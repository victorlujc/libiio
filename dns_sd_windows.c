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

static char addrbuffer[64];
static char namebuffer[256];

static mdns_string_t
ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr, size_t addrlen) {
    char host[NI_MAXHOST] = { 0 };
    char service[NI_MAXSERV] = { 0 };
    int ret = getnameinfo((const struct sockaddr*)addr, addrlen,
        host, NI_MAXHOST, service, NI_MAXSERV,
        NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if (ret == 0) {
        if (addr->sin_port != 0)
            len = snprintf(buffer, capacity, "%s:%s", host, service);
        else
            len = snprintf(buffer, capacity, "%s", host);
    }
    if (len >= (int)capacity)
        len = (int)capacity - 1;
    mdns_string_t str = { buffer, len };
    return str;
}

static mdns_string_t
ipv6_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in6* addr, size_t addrlen) {
    char host[NI_MAXHOST] = { 0 };
    char service[NI_MAXSERV] = { 0 };
    int ret = getnameinfo((const struct sockaddr*)addr, addrlen,
        host, NI_MAXHOST, service, NI_MAXSERV,
        NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if (ret == 0) {
        if (addr->sin6_port != 0)
            len = snprintf(buffer, capacity, "[%s]:%s", host, service);
        else
            len = snprintf(buffer, capacity, "%s", host);
    }
    if (len >= (int)capacity)
        len = (int)capacity - 1;
    mdns_string_t str = { buffer, len };
    return str;
}

static mdns_string_t
ip_address_to_string(char* buffer, size_t capacity, const struct sockaddr* addr, size_t addrlen) {
    if (addr->sa_family == AF_INET6)
        return ipv6_address_to_string(buffer, capacity, (const struct sockaddr_in6*)addr, addrlen);
    return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in*)addr, addrlen);
}

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

    struct dns_sd_discovery_data* dd = (struct dns_sd_discovery_data*)user_data;
    if (dd == NULL) {
        ERROR("DNS SD: Missing info structure. Stop browsing.\n");
        goto quit;
    }

    mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
    const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" :
        ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
    if (rtype != MDNS_RECORDTYPE_PTR)
        goto quit;
    mdns_string_t namestr = mdns_record_parse_ptr(data, size, offset, length,
        namebuffer, sizeof(namebuffer));
    DEBUG("%.*s : %s PTR %.*s rclass 0x%x ttl %u length %d\n",
        MDNS_STRING_FORMAT(fromaddrstr), entrytype,
        MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)length);

    const char* found = strstr(namestr.str, "iio");
    if (found == NULL)
        goto quit;

    DEBUG("Found IIO in DNS-SD response");

    /* Set properties on the last element on the list. */
    while (dd->next)
        dd = dd->next;

    const char* port_str = strchr(fromaddrstr.str, ':');
    size_t ip_addr_len = port_str - fromaddrstr.str;

    dd->port = atoi(port_str + 1);
    strncpy(dd->addr_str, fromaddrstr.str, ip_addr_len);

    // no hostname given by this library ?
    dd->hostname = strdup("");

    DEBUG("DNS SD: added %s (%s:%d)\n", hostname, dd->addr_str, port);

    // A list entry was filled, prepare new item on the list.
    if(new_discovery_data(&dd->next)) {
        ERROR("DNS SD Bonjour Resolver : memory failure\n");
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

    if (mdns_discovery_send(sock)) {
        ERROR("Failed to send DNS-DS discovery: %s\n", strerror(errno));
        goto quit;
    }

    DEBUG("Reading DNS-SD replies\n");
    for (int i = 0; i < 10; ++i) {
        do {
            records = mdns_discovery_recv(sock, buffer, capacity, query_callback, d);
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