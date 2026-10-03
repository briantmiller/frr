// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra - description of the settings of Linux bridges and bridge ports.
 *
 * One table drives everything: the northbound callbacks, the CLI, the
 * stored configuration and the netlink encoding.  To support another
 * setting, add a line to the right list below and a matching leaf to
 * yang/frr-zebra.yang.
 *
 * X(SYM, "name", kind, wire width, min, max, default, kernel attribute, enum names,
 *   cli value syntax, cli value help, cli help)
 *
 * The kernel attribute numbers are IFLA_BR_* (bridge) and IFLA_BRPORT_*
 * (port) from linux/if_link.h; they are part of the stable kernel ABI and are
 * spelled out so this file does not depend on the kernel headers.
 */

#ifndef _ZEBRA_LINK_OPTS_H
#define _ZEBRA_LINK_OPTS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum zebra_link_opt_kind {
	ZLO_BOOL,      /* on/off */
	ZLO_UINT,      /* unsigned number */
	ZLO_SECS,      /* seconds, sent to the kernel in centiseconds (u32) */
	ZLO_ENUM,      /* one of a list of names; the index is the kernel value */
	ZLO_MAC,       /* ethernet address */
	ZLO_VLANPROTO, /* "dot1q" or "dot1ad"; sent as the big-endian ethertype */
};

enum zebra_link_opt_scope {
	ZLO_SCOPE_BRIDGE, /* settings of the bridge device */
	ZLO_SCOPE_PORT,	  /* settings of a bridge port */
	ZLO_SCOPE_MAX,
};

/* Maximum number of settings per scope (the configuration keeps a bitmap) */
#define ZLO_MAX 64

/* No kernel default known: removing the option leaves the kernel as it is */
#define ZLO_NODEFAULT UINT64_MAX

#define ZEBRA_BRIDGE_OPT_LIST(X) \
	X(STP, "stp", ZLO_BOOL, 4, 0, 1, 0ULL, 5, NULL, "<on|off>", "on\n" "off\n", "Spanning tree protocol (kernel STP)") \
	X(AGEING_TIME, "ageing-time", ZLO_SECS, 4, 0, 10000, 300ULL, 4, NULL, "(0-10000)", "Value\n", "FDB ageing time in seconds (kernel default 300)") \
	X(FORWARD_DELAY, "forward-delay", ZLO_SECS, 4, 2, 30, 15ULL, 1, NULL, "(2-30)", "Value\n", "STP forward delay in seconds (kernel default 15)") \
	X(HELLO_TIME, "hello-time", ZLO_SECS, 4, 1, 10, 2ULL, 2, NULL, "(1-10)", "Value\n", "STP hello time in seconds (kernel default 2)") \
	X(MAX_AGE, "max-age", ZLO_SECS, 4, 6, 40, 20ULL, 3, NULL, "(6-40)", "Value\n", "STP max age in seconds (kernel default 20)") \
	X(PRIORITY, "priority", ZLO_UINT, 2, 0, 65535, 32768ULL, 6, NULL, "(0-65535)", "Value\n", "STP bridge priority (kernel default 32768)") \
	X(VLAN_FILTERING, "vlan-filtering", ZLO_BOOL, 1, 0, 1, 0ULL, 7, NULL, "<on|off>", "on\n" "off\n", "VLAN filtering") \
	X(VLAN_PROTOCOL, "vlan-protocol", ZLO_VLANPROTO, 2, 0, 1, 0ULL, 8, zlo_enum_br_vlan_protocol, "<dot1q|dot1ad>", "dot1q\n" "dot1ad\n" , "VLAN ethertype used by the bridge") \
	X(VLAN_DEFAULT_PVID, "vlan-default-pvid", ZLO_UINT, 2, 0, 4094, 1ULL, 39, NULL, "(0-4094)", "Value\n", "Default PVID given to new ports, 0 for none (kernel default 1)") \
	X(VLAN_STATS, "vlan-stats", ZLO_BOOL, 1, 0, 1, 0ULL, 41, NULL, "<on|off>", "on\n" "off\n", "Per-VLAN statistics") \
	X(VLAN_STATS_PER_PORT, "vlan-stats-per-port", ZLO_BOOL, 1, 0, 1, 0ULL, 45, NULL, "<on|off>", "on\n" "off\n", "Per-VLAN per-port statistics") \
	X(GROUP_FWD_MASK, "group-fwd-mask", ZLO_UINT, 2, 0, 65535, 0ULL, 9, NULL, "(0-65535)", "Value\n", "Bitmask of link-local group addresses (01-80-C2-00-00-0X) the bridge forwards") \
	X(GROUP_ADDRESS, "group-address", ZLO_MAC, 6, 0, 0, 1652522221568ULL, 20, NULL, "X:X:X:X:X:X", "MAC address\n", "Destination address of STP frames") \
	X(MULTICAST_SNOOPING, "multicast-snooping", ZLO_BOOL, 1, 0, 1, 1ULL, 23, NULL, "<on|off>", "on\n" "off\n", "IGMP/MLD snooping") \
	X(MULTICAST_ROUTER, "multicast-router", ZLO_ENUM, 1, 0, 2, 1ULL, 22, zlo_enum_br_multicast_router, "<disabled|auto|enabled>", "disabled\n" "auto\n" "enabled\n" , "Whether the bridge itself is a multicast router") \
	X(MULTICAST_QUERIER, "multicast-querier", ZLO_BOOL, 1, 0, 1, 0ULL, 25, NULL, "<on|off>", "on\n" "off\n", "Act as IGMP/MLD querier") \
	X(MULTICAST_QUERY_USE_IFADDR, "multicast-query-use-ifaddr", ZLO_BOOL, 1, 0, 1, 0ULL, 24, NULL, "<on|off>", "on\n" "off\n", "Use the bridge address as source of IGMP queries") \
	X(MULTICAST_STATS, "multicast-stats", ZLO_BOOL, 1, 0, 1, 0ULL, 42, NULL, "<on|off>", "on\n" "off\n", "Multicast statistics") \
	X(MULTICAST_IGMP_VERSION, "multicast-igmp-version", ZLO_UINT, 1, 2, 3, 2ULL, 43, NULL, "(2-3)", "Value\n", "IGMP version") \
	X(MULTICAST_MLD_VERSION, "multicast-mld-version", ZLO_UINT, 1, 1, 2, 1ULL, 44, NULL, "(1-2)", "Value\n", "MLD version") \
	X(MULTICAST_HASH_MAX, "multicast-hash-max", ZLO_UINT, 4, 1, 4294967295, 4096ULL, 27, NULL, "(1-4294967295)", "Value\n", "Maximum multicast group hash table size") \
	X(MULTICAST_LAST_MEMBER_COUNT, "multicast-last-member-count", ZLO_UINT, 4, 1, 4294967295, 2ULL, 28, NULL, "(1-4294967295)", "Value\n", "Last member query count (kernel default 2)") \
	X(MULTICAST_STARTUP_QUERY_COUNT, "multicast-startup-query-count", ZLO_UINT, 4, 1, 4294967295, 2ULL, 29, NULL, "(1-4294967295)", "Value\n", "Startup query count (kernel default 2)") \
	X(MULTICAST_LAST_MEMBER_INTERVAL, "multicast-last-member-interval", ZLO_UINT, 8, 0, 4294967295, 100ULL, 30, NULL, "(0-4294967295)", "Value\n", "Last member query interval, centiseconds (kernel default 100)") \
	X(MULTICAST_MEMBERSHIP_INTERVAL, "multicast-membership-interval", ZLO_UINT, 8, 0, 4294967295, 26000ULL, 31, NULL, "(0-4294967295)", "Value\n", "Group membership interval, centiseconds (kernel default 26000)") \
	X(MULTICAST_QUERIER_INTERVAL, "multicast-querier-interval", ZLO_UINT, 8, 0, 4294967295, 25500ULL, 32, NULL, "(0-4294967295)", "Value\n", "Other querier present interval, centiseconds (kernel default 25500)") \
	X(MULTICAST_QUERY_INTERVAL, "multicast-query-interval", ZLO_UINT, 8, 0, 4294967295, 12500ULL, 33, NULL, "(0-4294967295)", "Value\n", "Query interval, centiseconds (kernel default 12500)") \
	X(MULTICAST_QUERY_RESPONSE_INTERVAL, "multicast-query-response-interval", ZLO_UINT, 8, 0, 4294967295, 1000ULL, 34, NULL, "(0-4294967295)", "Value\n", "Query response interval, centiseconds (kernel default 1000)") \
	X(MULTICAST_STARTUP_QUERY_INTERVAL, "multicast-startup-query-interval", ZLO_UINT, 8, 0, 4294967295, 3125ULL, 35, NULL, "(0-4294967295)", "Value\n", "Startup query interval, centiseconds (kernel default 3125)") \
	X(FDB_MAX_LEARNED, "fdb-max-learned", ZLO_UINT, 4, 0, 4294967295, 0ULL, 49, NULL, "(0-4294967295)", "Value\n", "Maximum number of learned FDB entries, 0 for no limit")

#define ZEBRA_BRPORT_OPT_LIST(X) \
	X(STATE, "state", ZLO_ENUM, 1, 0, 4, ZLO_NODEFAULT, 1, zlo_enum_port_state, "<disabled|listening|learning|forwarding|blocking>", "disabled\n" "listening\n" "learning\n" "forwarding\n" "blocking\n" , "STP state of the port") \
	X(PRIORITY, "priority", ZLO_UINT, 2, 0, 255, 32ULL, 2, NULL, "(0-255)", "Value\n", "STP port priority (kernel default 32)") \
	X(COST, "cost", ZLO_UINT, 4, 0, 4294967295, 0ULL, 3, NULL, "(0-4294967295)", "Value\n", "STP path cost, 0 for automatic") \
	X(HAIRPIN, "hairpin", ZLO_BOOL, 1, 0, 1, 0ULL, 4, NULL, "<on|off>", "on\n" "off\n", "Hairpin mode: reflect frames back out of the port they came in on") \
	X(BPDU_GUARD, "bpdu-guard", ZLO_BOOL, 1, 0, 1, 0ULL, 5, NULL, "<on|off>", "on\n" "off\n", "Disable the port if it receives a BPDU") \
	X(ROOT_BLOCK, "root-block", ZLO_BOOL, 1, 0, 1, 0ULL, 6, NULL, "<on|off>", "on\n" "off\n", "Do not let the port become a root port") \
	X(FAST_LEAVE, "fast-leave", ZLO_BOOL, 1, 0, 1, 0ULL, 7, NULL, "<on|off>", "on\n" "off\n", "Multicast fast leave") \
	X(LEARNING, "learning", ZLO_BOOL, 1, 0, 1, 1ULL, 8, NULL, "<on|off>", "on\n" "off\n", "Learn MAC addresses on the port (kernel default on)") \
	X(UNICAST_FLOOD, "unicast-flood", ZLO_BOOL, 1, 0, 1, 1ULL, 9, NULL, "<on|off>", "on\n" "off\n", "Flood unknown unicast to the port (kernel default on)") \
	X(MULTICAST_FLOOD, "multicast-flood", ZLO_BOOL, 1, 0, 1, 1ULL, 27, NULL, "<on|off>", "on\n" "off\n", "Flood unknown multicast to the port (kernel default on)") \
	X(BROADCAST_FLOOD, "broadcast-flood", ZLO_BOOL, 1, 0, 1, 1ULL, 30, NULL, "<on|off>", "on\n" "off\n", "Flood broadcast to the port (kernel default on)") \
	X(MULTICAST_TO_UNICAST, "multicast-to-unicast", ZLO_BOOL, 1, 0, 1, 0ULL, 28, NULL, "<on|off>", "on\n" "off\n", "Send multicast as unicast to the port") \
	X(PROXY_ARP, "proxy-arp", ZLO_BOOL, 1, 0, 1, 0ULL, 10, NULL, "<on|off>", "on\n" "off\n", "Proxy ARP") \
	X(PROXY_ARP_WIFI, "proxy-arp-wifi", ZLO_BOOL, 1, 0, 1, 0ULL, 12, NULL, "<on|off>", "on\n" "off\n", "Proxy ARP for wireless clients") \
	X(NEIGH_SUPPRESS, "neigh-suppress", ZLO_BOOL, 1, 0, 1, 0ULL, 32, NULL, "<on|off>", "on\n" "off\n", "ARP/ND suppression") \
	X(NEIGH_VLAN_SUPPRESS, "neigh-vlan-suppress", ZLO_BOOL, 1, 0, 1, 0ULL, 43, NULL, "<on|off>", "on\n" "off\n", "Per-VLAN ARP/ND suppression") \
	X(VLAN_TUNNEL, "vlan-tunnel", ZLO_BOOL, 1, 0, 1, 0ULL, 29, NULL, "<on|off>", "on\n" "off\n", "VLAN to tunnel id mapping") \
	X(ISOLATED, "isolated", ZLO_BOOL, 1, 0, 1, 0ULL, 33, NULL, "<on|off>", "on\n" "off\n", "Isolate the port from other isolated ports (overrides private VLANs)") \
	X(LOCKED, "locked", ZLO_BOOL, 1, 0, 1, 0ULL, 39, NULL, "<on|off>", "on\n" "off\n", "Locked port: drop traffic from addresses not in the FDB") \
	X(MAB, "mab", ZLO_BOOL, 1, 0, 1, 0ULL, 40, NULL, "<on|off>", "on\n" "off\n", "MAC authentication bypass on a locked port") \
	X(MULTICAST_ROUTER, "multicast-router", ZLO_ENUM, 1, 0, 3, 1ULL, 25, zlo_enum_port_multicast_router, "<disabled|learning|permanent|temp>", "disabled\n" "learning\n" "permanent\n" "temp\n" , "Multicast router state of the port") \
	X(GROUP_FWD_MASK, "group-fwd-mask", ZLO_UINT, 2, 0, 65535, 0ULL, 31, NULL, "(0-65535)", "Value\n", "Link-local group addresses forwarded through this port") \
	X(MULTICAST_MAX_GROUPS, "multicast-max-groups", ZLO_UINT, 4, 0, 4294967295, 0ULL, 42, NULL, "(0-4294967295)", "Value\n", "Maximum multicast groups learned on the port, 0 for no limit") \
	X(MULTICAST_EHT_HOSTS_LIMIT, "multicast-eht-hosts-limit", ZLO_UINT, 4, 0, 4294967295, 512ULL, 37, NULL, "(0-4294967295)", "Value\n", "Maximum explicit-host-tracking hosts per port")

/* Indexes into the tables */
enum zebra_bridge_opt {
#define X(sym, ...) ZBO_##sym,
	ZEBRA_BRIDGE_OPT_LIST(X)
#undef X
	ZBO_COUNT
};

enum zebra_brport_opt {
#define X(sym, ...) ZPO_##sym,
	ZEBRA_BRPORT_OPT_LIST(X)
#undef X
	ZPO_COUNT
};

struct zebra_link_opt_def {
	const char *name; /* also the yang leaf name and the CLI keyword */
	enum zebra_link_opt_kind kind;
	uint8_t width; /* bytes on the wire: 1, 2, 4, 8, or 6 for a MAC */
	uint64_t min, max;
	uint64_t def; /* kernel default, sent when the option is removed */
	unsigned int attr;
	const char *const *enums; /* NULL terminated */
};

/* The values of a set of options; MACs are held in the low 48 bits */
struct zebra_link_optset {
	uint64_t mask; /* options that are set, bit per index */
	uint64_t val[ZLO_MAX];
};

extern const struct zebra_link_opt_def *zebra_link_opt_table(enum zebra_link_opt_scope scope,
							      unsigned int *count);

/* Index of the option called 'name', or -1 */
extern int zebra_link_opt_find(enum zebra_link_opt_scope scope, const char *name);

/*
 * Convert the text form of a value (as in the northbound tree and on the
 * command line) to the stored form; false if it is not valid for the option.
 */
extern bool zebra_link_opt_parse(const struct zebra_link_opt_def *def, const char *str,
				 uint64_t *val);

/* And back, for configuration output.  Returns 'buf'. */
extern const char *zebra_link_opt_format(const struct zebra_link_opt_def *def, uint64_t val,
					 char *buf, size_t buflen);

/* Settings to be sent to the kernel in one request */
struct zebra_link_opts_req {
	enum zebra_link_opt_scope scope;
	unsigned int count;
	struct {
		uint8_t idx;
		uint64_t val;
	} item[ZLO_MAX];
};

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_LINK_OPTS_H */
