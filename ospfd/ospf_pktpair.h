// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF packet-pair link speed estimation.
 *
 * Runs a lib/pktpair session on every OSPF interface with
 * "ip ospf packet-pair" configured, probing each neighbor in state 2-Way
 * or better.  No protocol extension or neighbor-side configuration is
 * required; the neighbor only needs to answer ICMP echo requests.
 *
 * On Ethernet interfaces probes are written to an AF_PACKET socket with
 * PACKET_QDISC_BYPASS set, addressed to the neighbor's MAC, so they skip
 * the local egress qdisc and the estimate reflects the link rather than
 * a QoS policy configured on it.  When that is not possible (non-Ethernet
 * interface, kernel without the option, neighbor MAC not resolved) the
 * IP stack is used and this is reported in the show output.
 */

#ifndef _ZEBRA_OSPF_PKTPAIR_H
#define _ZEBRA_OSPF_PKTPAIR_H

#include "pktpair.h"

struct ospf_interface;
struct ospf_neighbor;
struct vty;
struct json_object;

/* Configuration defaults and limits. */
#define OSPF_PP_INTERVAL_DEFAULT PKTPAIR_INTERVAL_DEFAULT
#define OSPF_PP_PROBES_DEFAULT	 PKTPAIR_PROBES_DEFAULT
#define OSPF_PP_DSCP_DEFAULT	 PKTPAIR_DSCP_DEFAULT

/* Lifecycle hooks. */
extern void ospf_pp_if_up(struct ospf_interface *oi);
extern void ospf_pp_if_down(struct ospf_interface *oi);
extern void ospf_pp_if_config_changed(struct interface *ifp);

/* Display. */
extern void ospf_pp_show_nbr(struct vty *vty, struct ospf_neighbor *nbr,
			     struct json_object *json_neigh);
extern void ospf_pp_show_if(struct vty *vty, struct ospf_interface *oi,
			    struct json_object *json_iface);

#endif /* _ZEBRA_OSPF_PKTPAIR_H */
