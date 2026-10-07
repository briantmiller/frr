// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra stateful NAT (NAPT) using TC flower and act_ct.
 *
 * Interfaces are configured as "ip nat inside" or "ip nat outside". For
 * every outside interface zebra programs a clsact qdisc and a handful of
 * flower filters:
 *
 *  egress, chain 0:
 *    - src <outside address>             -> ct commit zone Z       (pass)
 *    - indev <inside if> (one per inside) -> ct zone Z nat          (goto chain C)
 *  egress, chain C:
 *    - (one-to-one statics) ct_state +trk+new, src <local>
 *                         -> ct commit zone Z nat src <global>      (pass)
 *    - ct_state +trk+new  -> ct commit zone Z nat src <outside address> (pass)
 *    - ct_state +trk+inv  -> drop
 *  ingress, chain 0:
 *    - dst <outside address>             -> ct zone Z nat          (goto chain I)
 *    - dst <other static global address> -> ct zone Z nat          (goto chain I)
 *  ingress, chain I (one per static translation):
 *    - ct_state +trk+new, dst <global>[, proto, dst_port <global port>]
 *                         -> ct commit zone Z nat dst <local>[:<local port>] (pass)
 *
 * so traffic forwarded from an inside interface out of the outside
 * interface is source-NATed (with port translation) to the outside
 * interface's primary IPv4 address, and replies are translated back on
 * ingress before the routing decision.
 */

#ifndef _ZEBRA_NAT_H
#define _ZEBRA_NAT_H

#include "if.h"
#include "vty.h"
#include "json.h"
#include "ns.h"

#ifdef __cplusplus
extern "C" {
#endif

struct zebra_dplane_ctx;
struct zebra_ns;

/* Interface NAT role (zebra_if->nat_role) */
enum zebra_nat_role {
	ZEBRA_NAT_ROLE_NONE = 0,
	ZEBRA_NAT_ROLE_INSIDE,
	ZEBRA_NAT_ROLE_OUTSIDE,
};

/*
 * Traffic control layout. Priorities and the chain index are chosen to be
 * distinctive so that zebra only ever touches objects it created.
 */
#define ZEBRA_NAT_TC_PRIO_LOCAL	  0xbee1 /* egress chain 0: router's own traffic */
#define ZEBRA_NAT_TC_PRIO_INSIDE  0xbee2 /* egress chain 0: per inside if */
#define ZEBRA_NAT_TC_PRIO_CT_NEW  0xbee1 /* egress chain C: new connections */
#define ZEBRA_NAT_TC_PRIO_CT_INV  0xbee2 /* egress chain C: invalid packets */
#define ZEBRA_NAT_TC_PRIO_INGRESS 0xbee1 /* ingress chain 0: de-NAT */
#define ZEBRA_NAT_TC_CHAIN	  0xbee0 /* egress second stage chain */
#define ZEBRA_NAT_TC_CHAIN_IN	      0xbee1 /* ingress second stage chain */
#define ZEBRA_NAT_TC_PRIO_STATIC_SNAT 0xbed0 /* egress chain C: one-to-one statics */
#define ZEBRA_NAT_TC_PRIO_STATIC_DNAT 0xbee1 /* ingress chain I: static translations */
#define ZEBRA_NAT_TC_HANDLE	  1

/* Major handle of the clsact (and ingress) qdisc, TC_H_CLSACT */
#define ZEBRA_NAT_CLSACT_MAJOR 0xffff0000u

/*
 * Conntrack zone used for an outside interface. Every outside interface
 * gets its own zone, derived from its ifindex so that it is stable across
 * zebra restarts.
 */
#define ZEBRA_NAT_CT_ZONE_BASE 0x8000
#define ZEBRA_NAT_CT_ZONE_MASK 0x7fff
#define ZEBRA_NAT_CT_ZONE(ifindex)                                                                \
	((uint16_t)(ZEBRA_NAT_CT_ZONE_BASE | ((uint32_t)(ifindex) & ZEBRA_NAT_CT_ZONE_MASK)))

/* One conntrack tuple (one direction of a connection) */
struct zebra_nat_ct_tuple {
	uint8_t proto;
	struct in_addr src;
	struct in_addr dst;
	uint16_t sport; /* host order; ICMP: id */
	uint16_t dport; /* host order */
	uint8_t icmp_type;
	uint8_t icmp_code;
};

/* One conntrack entry, as read from the kernel */
struct zebra_nat_ct_entry {
	uint16_t zone;
	uint32_t id;
	uint32_t status;  /* IPS_* bits */
	uint32_t timeout; /* seconds */
	uint32_t mark;
	bool has_tcp_state;
	uint8_t tcp_state;
	bool has_counters;
	uint64_t pkts_orig, bytes_orig;
	uint64_t pkts_reply, bytes_reply;
	struct zebra_nat_ct_tuple orig;
	struct zebra_nat_ct_tuple reply;

	/* Raw CTA_TUPLE_ORIG attribute, used to delete the entry */
	uint16_t raw_orig_len;
	uint8_t raw_orig[256];
};

/* Conntrack statistics, summed over all cpus */
struct zebra_nat_ct_stats {
	uint32_t cpus;
	uint64_t found;
	uint64_t invalid;
	uint64_t insert;
	uint64_t insert_failed;
	uint64_t drop;
	uint64_t early_drop;
	uint64_t error;
	uint64_t search_restart;
	uint64_t clash_resolve;
	uint64_t chain_toolong;

	bool has_global;
	uint32_t entries;
	uint32_t max_entries;
};

/* Return non-zero from the callback to stop the walk */
typedef int (*zebra_nat_ct_walk_cb)(const struct zebra_nat_ct_entry *entry, void *arg);

/*
 * Kernel interface (nat_netlink.c). All functions are synchronous and use a
 * private socket in namespace 'ns_id'. 'zone' of 0 means "every zone".
 * They return 0 on success or a negative errno.
 */
extern int kernel_nat_ct_walk(ns_id_t ns_id, uint16_t zone, zebra_nat_ct_walk_cb cb, void *arg);
extern int kernel_nat_ct_stats(ns_id_t ns_id, struct zebra_nat_ct_stats *st);
extern int kernel_nat_ct_delete(ns_id_t ns_id, const struct zebra_nat_ct_entry *entry);

/* Configuration (northbound) */
extern void zebra_nat_if_set_role(struct interface *ifp, enum zebra_nat_role role);
extern const char *zebra_nat_role2str(enum zebra_nat_role role);

/*
 * Static translations. 'proto' is 0 (one-to-one), IPPROTO_TCP or
 * IPPROTO_UDP; ports are 0 for one-to-one translations. The global side is
 * either an address or an outside interface (whose primary address is used).
 */
struct zebra_nat_static;
extern struct zebra_nat_static *zebra_nat_static_create(const char *vrf_name, uint8_t proto,
							struct in_addr local, uint16_t local_port);
extern void zebra_nat_static_set_global(struct zebra_nat_static *st,
					const struct in_addr *global_addr,
					const char *global_ifname, uint16_t global_port);
extern void zebra_nat_static_delete(struct zebra_nat_static *st);

/* Events */
extern void zebra_nat_if_addr_update(struct interface *ifp);
extern void zebra_nat_startup_complete(struct zebra_ns *zns);
extern void zebra_nat_startup_cleanup(ns_id_t ns_id, ifindex_t ifindex);
extern void zebra_nat_dplane_result(struct zebra_dplane_ctx *ctx);

extern void zebra_nat_init(void);
extern void zebra_nat_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_NAT_H */
