// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra stateful NAT - Linux kernel interaction.
 *
 * Programs clsact/flower/act_ct traffic control objects through the
 * dataplane, and reads the conntrack table through NETLINK_NETFILTER for
 * the "show ip nat ..." commands.
 */

#ifndef _ZEBRA_NAT_NETLINK_H
#define _ZEBRA_NAT_NETLINK_H

#ifdef HAVE_NETLINK

#include "zebra/kernel_netlink.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Add the netlink message for one NAT tc object to the batch. */
extern enum netlink_msg_status netlink_put_nat_tc_update_msg(struct nl_batch *bth,
							     struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_NAT_NETLINK_H */
