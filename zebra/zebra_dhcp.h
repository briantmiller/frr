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
