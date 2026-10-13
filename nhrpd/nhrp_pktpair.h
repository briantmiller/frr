// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NHRP packet-pair link speed estimation.
 *
 * With "ip nhrp packet-pair" configured on a DMVPN tunnel interface, a
 * lib/pktpair session probes, over the tunnel:
 *
 *   - every NHS this router is registered with (client role), and
 *   - every client registered with this router (NHS role).
 *
 * Spoke-to-spoke shortcut peers are not probed.  Probes are ICMP echo
 * requests to the peer's tunnel (protocol) address; the peer only has to
 * answer them.
 *
 * Probes skip the local egress qdiscs (PACKET_QDISC_BYPASS):
 *
 *   underlay-bypass: nhrpd builds the complete frame (outer IPv4 +
 *     GRE + inner probe) and writes it to the underlay Ethernet
 *     interface, addressed to the next hop's MAC.  Neither the tunnel's
 *     nor the underlay's qdisc is traversed.
 *
 *   tunnel-bypass: when the frame can't be built safely (IPsec, GRE
 *     checksums/sequence numbers, FOU/GUE, non-Ethernet underlay,
 *     unresolved next hop, ...) the probe is written to the GRE device
 *     with the peer's NBMA address as link-layer destination, like NHRP
 *     packets themselves.  The tunnel's qdisc is skipped, the kernel
 *     encapsulates, and the underlay qdisc applies.
 *
 *   ip-stack: when PACKET_QDISC_BYPASS is unavailable.
 */

#ifndef _NHRP_PKTPAIR_H
#define _NHRP_PKTPAIR_H

struct interface;
struct vty;
struct json_object;

/* Start, reconfigure or stop probing to match config and state. */
extern void nhrp_pp_update(struct interface *ifp);
extern void nhrp_pp_stop(struct interface *ifp);

extern void nhrp_pp_config_write(struct vty *vty, struct interface *ifp);
extern void nhrp_pp_show(struct vty *vty, struct interface *ifp,
			 struct json_object *json);

#endif /* _NHRP_PKTPAIR_H */
