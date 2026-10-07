// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra stateful NAT - detection of local services using a port.
 *
 * Used both by the CLI (to refuse a port forward that would take traffic
 * away from a service running on the router) and by zebra (to flag such a
 * collision at runtime). Only sockets of the calling process's network
 * namespace are visible.
 */

#ifndef _ZEBRA_NAT_PORT_H
#define _ZEBRA_NAT_PORT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>

#include "printfrr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NAT_PORT_TCP_LISTEN 0x0a

/*
 * Scan one /proc/net/{tcp,udp}[6] table. For IPv4 tables 'addr' is the
 * kernel's %08X rendering of the address; for IPv6 tables only the
 * wildcard and IPv4-mapped addresses can accept IPv4 traffic.
 */
static inline bool nat_port_scan(const char *path, bool v6, bool tcp, const struct in_addr *addr,
				 uint16_t port)
{
	char line[512];
	bool found = false;
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return false;

	/* Skip the header */
	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return false;
	}

	while (!found && fgets(line, sizeof(line), fp)) {
		char laddr[64], raddr[64];
		unsigned int lport, rport, state;
		bool addr_match;

		if (sscanf(line, " %*d: %63[0-9A-Fa-f]:%x %63[0-9A-Fa-f]:%x %x", laddr, &lport,
			   raddr, &rport, &state) != 5)
			continue;

		if (lport != port)
			continue;

		if (tcp) {
			if (state != NAT_PORT_TCP_LISTEN)
				continue;
		} else if (rport != 0) {
			/* connected UDP socket, not a service */
			continue;
		}

		if (!v6) {
			unsigned int a;

			if (sscanf(laddr, "%x", &a) != 1)
				continue;
			addr_match = (a == 0) || (addr && a == addr->s_addr);
		} else {
			char mapped[33];

			if (strlen(laddr) != 32)
				continue;
			addr_match = !strcmp(laddr, "00000000000000000000000000000000");
			if (!addr_match && addr) {
				/* ::ffff:a.b.c.d, words printed in host order */
				snprintfrr(mapped, sizeof(mapped), "0000000000000000%08X%08X",
					   (unsigned int)htonl(0x0000ffff),
					   (unsigned int)addr->s_addr);
				addr_match = !strcasecmp(laddr, mapped);
			}
		}

		if (addr_match)
			found = true;
	}

	fclose(fp);

	return found;
}

/*
 * Is a local service using 'port' for protocol 'proto' (IPPROTO_TCP or
 * IPPROTO_UDP) on 'addr'? With 'addr' NULL only services listening on all
 * addresses count.
 */
static inline bool nat_local_port_in_use(uint8_t proto, const struct in_addr *addr, uint16_t port)
{
#ifdef __linux__
	bool tcp = (proto == IPPROTO_TCP);

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return false;

	return nat_port_scan(tcp ? "/proc/net/tcp" : "/proc/net/udp", false, tcp, addr, port) ||
	       nat_port_scan(tcp ? "/proc/net/tcp6" : "/proc/net/udp6", true, tcp, addr, port);
#else
	return false;
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_NAT_PORT_H */
