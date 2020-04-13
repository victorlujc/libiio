// Based on the example provided here: https://github.com/mjansson/mdns

#ifdef _WIN32
#  define _CRT_SECURE_NO_WARNINGS 1
#endif

#include <stdio.h>
#include <errno.h>
#include "iio-private.h"
#include "mdns.h"
#include "network.h"
#include "debug.h"

#ifdef _WIN32
#  include <iphlpapi.h>
#else
#  include <netdb.h>
#endif

static int new_discovery_data(struct dns_sd_discovery_data** data)
{
	struct dns_sd_discovery_data* d;

	d = zalloc(sizeof(struct dns_sd_discovery_data));
	if (!d)
		return -ENOMEM;

	*data = d;
	return 0;
}

void dnssd_free_discovery_data(struct dns_sd_discovery_data* d)
{
	free(d->hostname);
	free(d);
}

static int
query_callback(int sock, const struct sockaddr* from, size_t addrlen,
	mdns_entry_type_t entry, uint16_t transaction_id,
	uint16_t rtype, uint16_t rclass, uint32_t ttl,
	const void* data, size_t size, size_t offset, size_t length,
	void* user_data) {


	char addrbuffer[64];
	char servicebuffer[64];
	char namebuffer[256];

	struct dns_sd_discovery_data* dd = (struct dns_sd_discovery_data*)user_data;
	if (dd == NULL) {
		ERROR("DNS SD: Missing info structure. Stop browsing.\n");
		goto quit;
	}

	if (rtype != MDNS_RECORDTYPE_SRV)
		goto quit;

	getnameinfo((const struct sockaddr*)from, addrlen,
		addrbuffer, NI_MAXHOST, servicebuffer, NI_MAXSERV,
		NI_NUMERICSERV | NI_NUMERICHOST);

	mdns_record_srv_t srv = mdns_record_parse_srv(data, size, offset, length,
		namebuffer, sizeof(namebuffer));
	DEBUG("%s : %s SRV %.*s priority %d weight %d port %d\n",
		addrbuffer, entrytype,
		MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);

	if (srv.name.length > 1)
	{
		dd->hostname = malloc(srv.name.length);
		strncpy(dd->hostname, srv.name.str, srv.name.length);
		dd->hostname[srv.name.length - 1] = 0;
	}
	strcpy(dd->addr_str, addrbuffer);
	dd->port = srv.port;


	DEBUG("DNS SD: added %s (%s:%d)\n", dd->hostname, dd->addr_str, dd->port);

	// A list entry was filled, prepare new item on the list.
	if (new_discovery_data(&dd->next)) {
		ERROR("DNS SD mDNS Resolver : memory failure\n");
	}

quit:
	return 0;
}

int dnssd_find_hosts(struct dns_sd_discovery_data** ddata)
{
#ifdef _WIN32
	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	if (WSAStartup(versionWanted, &wsaData)) {
		ERROR("Failed to initialize WinSock\n");
		return -1;
	}
#endif

	int ret = 0;
	struct dns_sd_discovery_data* d;

	DEBUG("DNS SD: Start service discovery.\n");

	if (new_discovery_data(&d) < 0) {
		return -ENOMEM;
	}

	size_t capacity = 2048;
	void* buffer = malloc(capacity);
	size_t records;
	DEBUG("Sending DNS-SD discovery\n");

	int port = 0;
	int sock = mdns_socket_open_ipv4(port);
	if (sock < 0) {
		ERROR("Failed to open socket: %s\n", strerror(errno));
		return -1;
	}
	DEBUG("Opened IPv4 socket for mDNS/DNS-SD\n");

	const char service[] = "_iio._tcp.local.";

	DEBUG("Sending mDNS query: %s\n", service);
	if (mdns_query_send(sock, MDNS_RECORDTYPE_PTR,
		service, strlen(service),
		buffer, capacity)) {
		ERROR("Failed to send mDNS query: %s\n", strerror(errno));
		goto quit;
	}

	DEBUG("Reading mDNS replies\n");
	for (int i = 0; i < 5; ++i) {
		do {
			records = mdns_query_recv(sock, buffer, capacity, query_callback, d, 1);
		} while (records);
		if (records)
			i = 0;
		Sleep(100);
	}

	*ddata = d;
quit:
	free(buffer);

	mdns_socket_close(sock);
	DEBUG("Closed socket\n");

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}
