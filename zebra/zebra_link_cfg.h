// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra - configured (zebra-created) Linux link types.
 *
 * Describes links that zebra is asked to create in the kernel through
 * configuration: bridge, veth, vlan, (standard) gre, dummy and vxlan.  The parameter
 * structures in this file are intentionally free of zebra/lib types so that
 * they can be carried inside a dataplane context and consumed by the netlink
 * encoder (zebra_link_netlink.c) without any additional dependencies.
 *
 * Extending with a new link type (gretap, ip6gre, vxlan, macvlan, ...):
 *   1. add an enum zebra_link_kind value and a parameter struct below,
 *   2. add the member to the union in struct zebra_link_params,
 *   3. add a validator, encoder and one table entry in zebra_link_netlink.c,
 *   4. add a case to the yang model + northbound/CLI code.
 */

#ifndef _ZEBRA_LINK_CFG_H
#define _ZEBRA_LINK_CFG_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

enum zebra_link_kind {
	ZEBRA_LINK_NONE = 0,
	ZEBRA_LINK_BRIDGE,
	ZEBRA_LINK_VETH,
	ZEBRA_LINK_VLAN,
	ZEBRA_LINK_GRE,
	ZEBRA_LINK_DUMMY,
	ZEBRA_LINK_VXLAN,
	/* Future: GRETAP, IP6GRE, IP6GRETAP, VXLAN, ... */
	ZEBRA_LINK_KIND_MAX,
};

enum zebra_link_vlan_encap {
	ZEBRA_LINK_VLAN_DOT1Q = 0, /* 802.1Q, the default */
	ZEBRA_LINK_VLAN_QINQ,	   /* 802.1ad (q-in-q) */
};

struct zebra_link_bridge {
	/* No creation parameters; the settings are in the bridge options */
	uint8_t reserved;
};

struct zebra_link_veth {
	char peer_name[IFNAMSIZ];
};

struct zebra_link_vlan {
	char parent[IFNAMSIZ];
	uint16_t vid;
	enum zebra_link_vlan_encap encap;
};

/* Standard (IPv4, L3) GRE.  Local or dev is required, remote may be "any". */
struct zebra_link_gre {
	bool has_local;
	struct in_addr local;

	char dev[IFNAMSIZ]; /* empty string if not configured */

	/* has_remote == false means "any" (multipoint GRE) */
	bool has_remote;
	struct in_addr remote;

	bool has_key;
	uint32_t key;

	bool has_ttl;
	uint8_t ttl;

	bool has_tos;
	uint8_t tos;
};

/*
 * Per-VLAN configuration of an interface that is a bridge port.
 *
 *  ON       tagged member of the VLAN
 *  UNTAGGED member of the VLAN, frames leave the port untagged
 *  PRIVATE  tagged member; additionally the port is isolated (the kernel's
 *           per-port IFLA_BRPORT_ISOLATED), so it only talks to
 *           non-isolated ports.  The kernel has no per-VLAN isolation: any
 *           PRIVATE VLAN isolates the whole port.
 *  OFF      not a member (an explicit removal, e.g. of the default VLAN 1)
 */
enum zebra_link_vlan_mode {
	ZEBRA_LINK_VLAN_UNSET = 0,
	ZEBRA_LINK_VLAN_OFF,
	ZEBRA_LINK_VLAN_ON,
	ZEBRA_LINK_VLAN_UNTAGGED,
	ZEBRA_LINK_VLAN_PRIVATE,
};

#define ZEBRA_LINK_VID_MIN 1
#define ZEBRA_LINK_VID_MAX 4094

static inline const char *zebra_link_vlan_mode2str(enum zebra_link_vlan_mode m)
{
	switch (m) {
	case ZEBRA_LINK_VLAN_OFF:
		return "off";
	case ZEBRA_LINK_VLAN_ON:
		return "on";
	case ZEBRA_LINK_VLAN_UNTAGGED:
		return "untagged";
	case ZEBRA_LINK_VLAN_PRIVATE:
		return "private";
	case ZEBRA_LINK_VLAN_UNSET:
		break;
	}
	return "unset";
}

/* One bridge-port request handed to the dataplane */
enum zebra_link_brport_type {
	ZEBRA_LINK_BRPORT_VLAN_ADD, /* [vid_begin, vid_end] with 'untagged'/'pvid' */
	ZEBRA_LINK_BRPORT_VLAN_DEL, /* [vid_begin, vid_end] */
	ZEBRA_LINK_BRPORT_ISOLATED, /* set the port isolated flag to 'isolated' */
};

struct zebra_link_brport_req {
	enum zebra_link_brport_type type;
	uint16_t vid_begin;
	uint16_t vid_end;
	bool untagged;
	bool pvid; /* single vid only */
	bool isolated;
};

/*
 * VXLAN (IPv4 underlay).  A multicast 'remote' requires 'dev'.  The UDP port
 * is always sent: the kernel's own default (8472) is not the IANA port.
 */
#define ZEBRA_LINK_VXLAN_DEFAULT_PORT 4789
#define ZEBRA_LINK_VNI_MAX 16777215

struct zebra_link_vxlan {
	uint32_t vni;

	bool has_local;
	struct in_addr local;

	/* Unicast peer, or multicast group (needs dev) */
	bool has_remote;
	struct in_addr remote;

	char dev[IFNAMSIZ]; /* underlay device, empty string if not configured */

	uint16_t dstport; /* host order; 0 means the default */

	bool has_ttl;
	uint8_t ttl;

	bool has_tos;
	uint8_t tos;

	bool has_learning;
	bool learning;
};

/*
 * Always memset() to zero before filling in: the struct is compared with
 * memcmp() to detect configuration changes.
 */
struct zebra_link_params {
	enum zebra_link_kind kind;
	union {
		struct zebra_link_bridge bridge;
		struct zebra_link_veth veth;
		struct zebra_link_vlan vlan;
		struct zebra_link_gre gre;
		struct zebra_link_vxlan vxlan;
	} u;
};

static inline const char *zebra_link_kind2str(enum zebra_link_kind kind)
{
	switch (kind) {
	case ZEBRA_LINK_BRIDGE:
		return "bridge";
	case ZEBRA_LINK_VETH:
		return "veth";
	case ZEBRA_LINK_VLAN:
		return "vlan";
	case ZEBRA_LINK_GRE:
		return "gre";
	case ZEBRA_LINK_DUMMY:
		return "dummy";
	case ZEBRA_LINK_VXLAN:
		return "vxlan";
	case ZEBRA_LINK_NONE:
	case ZEBRA_LINK_KIND_MAX:
		break;
	}
	return "none";
}

/*
 * Name of the existing interface this link is stacked on (vlan parent or gre
 * dev), or NULL if the link has no such dependency.  The interface must
 * exist (and have an ifindex) before the link can be created.
 */
static inline const char *
zebra_link_params_dependency(const struct zebra_link_params *p)
{
	if (p->kind == ZEBRA_LINK_VLAN)
		return p->u.vlan.parent[0] ? p->u.vlan.parent : NULL;
	if (p->kind == ZEBRA_LINK_GRE)
		return p->u.gre.dev[0] ? p->u.gre.dev : NULL;
	if (p->kind == ZEBRA_LINK_VXLAN)
		return p->u.vxlan.dev[0] ? p->u.vxlan.dev : NULL;
	return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_LINK_CFG_H */
