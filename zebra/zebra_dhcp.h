// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra DHCPv4 client ("ip address dhcp").
 *
 * Obtains an IPv4 address, subnet mask, default gateway and DNS servers
 * for an interface using DHCP (RFC 2131 / RFC 2132).
 */

#ifndef _ZEBRA_DHCP_H
#define _ZEBRA_DHCP_H

#include "if.h"

#ifdef __cplusplus
extern "C" {
#endif

struct zebra_if;
struct zebra_dhcp_if;

/* Path of the resolver configuration rewritten with DHCP DNS servers. */
#ifndef ZEBRA_DHCP_RESOLV_CONF
#define ZEBRA_DHCP_RESOLV_CONF "/etc/resolv.conf"
#endif

/* True when the DHCP client is available on this platform. */
extern bool zebra_dhcp_supported(void);

/* Configuration: "ip address dhcp" / "no ip address dhcp". */
extern void zebra_dhcp_if_enable(struct interface *ifp);
extern void zebra_dhcp_if_disable(struct interface *ifp);

/*
 * Configuration: "ip dhcp dns-server A.B.C.D [A.B.C.D [A.B.C.D]]".
 *
 * zebra_dhcp_if_dns_static_set
 *    Store static DNS server number idx (0 = primary) of ifp; a NULL addr
 *    clears it.  Takes effect on the next zebra_dhcp_dns_static_apply().
 *
 * zebra_dhcp_if_dns_static_clear
 *    Remove all static DNS servers of ifp.
 *
 * zebra_dhcp_dns_static_apply
 *    Rewrite the resolver configuration after static servers changed.
 *    While an interface holds a DHCP lease, its static servers (if any)
 *    are used instead of the servers offered by DHCP.
 */
extern void zebra_dhcp_if_dns_static_set(struct interface *ifp, unsigned int idx,
					 const struct in_addr *addr);
extern void zebra_dhcp_if_dns_static_clear(struct interface *ifp);
extern void zebra_dhcp_dns_static_apply(void);

/* Interface state notifications from zebra/interface.c. */
extern void zebra_dhcp_if_up(struct interface *ifp);
extern void zebra_dhcp_if_down(struct interface *ifp);
extern void zebra_dhcp_if_delete(struct interface *ifp);
extern void zebra_dhcp_if_free(struct zebra_if *zif);

extern void zebra_dhcp_init(void);
extern void zebra_dhcp_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_DHCP_H */
