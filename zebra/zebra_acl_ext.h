// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Extended access-lists ("ip access-list extended NAME"): Cisco style
 * entries extended with every tc-flower match key.
 *
 * This file only knows the syntax and the parsed representation; it is
 * shared by mgmtd (CLI validation and canonical form) and zebra.  The
 * translation into tc-flower netlink attributes lives in
 * zebra_acl_flower.c.
 *
 * Copyright (C) 2026 FRRouting
 */

#ifndef _ZEBRA_ACL_EXT_H
#define _ZEBRA_ACL_EXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ethertypes, host byte order */
#define ACLX_ETH_P_IP	   0x0800
#define ACLX_ETH_P_ARP	   0x0806
#define ACLX_ETH_P_RARP	   0x8035
#define ACLX_ETH_P_8021Q   0x8100
#define ACLX_ETH_P_8021AD  0x88A8
#define ACLX_ETH_P_IPV6	   0x86DD
#define ACLX_ETH_P_MPLS_UC 0x8847
#define ACLX_ETH_P_MPLS_MC 0x8848
#define ACLX_ETH_P_PPP_SES 0x8864
#define ACLX_ETH_P_CFM	   0x8902
#define ACLX_ETH_P_ALL	   0x0003

/* IP protocols */
#define ACLX_IPPROTO_ICMP   1
#define ACLX_IPPROTO_TCP    6
#define ACLX_IPPROTO_UDP    17
#define ACLX_IPPROTO_ESP    50
#define ACLX_IPPROTO_AH	    51
#define ACLX_IPPROTO_ICMPV6 58
#define ACLX_IPPROTO_L2TP   115
#define ACLX_IPPROTO_SCTP   132

/* TCP flag bits */
#define ACLX_TCP_FIN   0x001
#define ACLX_TCP_SYN   0x002
#define ACLX_TCP_RST   0x004
#define ACLX_TCP_PSH   0x008
#define ACLX_TCP_ACK   0x010
#define ACLX_TCP_URG   0x020
#define ACLX_TCP_ECE   0x040
#define ACLX_TCP_CWR   0x080
#define ACLX_TCP_NS    0x100
#define ACLX_TCP_NAMED 0x1ff

/* ip-flags bits (TCA_FLOWER_KEY_FLAGS_*) */
#define ACLX_IPF_FRAG	   0x01
#define ACLX_IPF_FIRSTFRAG 0x02

/* enc-flags bits (TCA_FLOWER_KEY_FLAGS_TUNNEL_*) */
#define ACLX_ENCF_CSUM 0x04
#define ACLX_ENCF_DF   0x08
#define ACLX_ENCF_OAM  0x10
#define ACLX_ENCF_CRIT 0x20

/* ct-state bits (TCA_FLOWER_KEY_CT_FLAGS_*) */
#define ACLX_CT_NEW 0x01
#define ACLX_CT_EST 0x02
#define ACLX_CT_REL 0x04
#define ACLX_CT_TRK 0x08
#define ACLX_CT_INV 0x10
#define ACLX_CT_RPL 0x20

#define ACLX_MAX_LSE	     7
#define ACLX_MAX_GENEVE	     8
#define ACLX_GENEVE_DATA_MAX 124
#define ACLX_IFNAME_LEN	     16
#define ACLX_TEXT_MAX	     1024

/* What follows the action: the protocol of the entry */
enum aclx_l3 {
	ACLX_L3_IPV4 = 1, /* ip, or an IP protocol with IPv4 addresses */
	ACLX_L3_IPV6,	  /* ipv6, icmpv6, or an IP protocol with IPv6 addresses */
	ACLX_L3_ARP,
	ACLX_L3_RARP,
	ACLX_L3_MPLS,	   /* unicast */
	ACLX_L3_MPLS_MC,   /* multicast */
	ACLX_L3_PPPOE,	   /* PPPoE session */
	ACLX_L3_CFM,	   /* 802.1ag connectivity fault management */
	ACLX_L3_ETHERTYPE, /* "ethertype 0xHHHH" */
	ACLX_L3_ANY,	   /* "ethertype any" */
};

/* A field matched with value and mask */
struct aclx_u8m {
	bool set;
	uint8_t v, m;
};

struct aclx_u16m {
	bool set;
	uint16_t v, m;
};

struct aclx_u32m {
	bool set;
	uint32_t v, m;
};

struct aclx_u64m {
	bool set;
	uint64_t v, m;
};

struct aclx_mac {
	bool set;
	uint8_t v[6], m[6];
};

/* Address (network byte order); m holds the bits that are compared */
struct aclx_addr {
	bool set;   /* false: any */
	int family; /* AF_INET or AF_INET6 when set */
	uint8_t v[16], m[16];
};

/* Cisco port operators */
enum aclx_op {
	ACLX_OP_NONE = 0,
	ACLX_OP_EQ,    /* lo (and mask) */
	ACLX_OP_NEQ,   /* lo */
	ACLX_OP_LT,    /* lo */
	ACLX_OP_GT,    /* lo */
	ACLX_OP_RANGE, /* lo .. hi */
};

struct aclx_range {
	enum aclx_op op;
	uint32_t lo, hi;
	uint32_t mask; /* EQ only; all ones when not given */
};

/* One MPLS label stack entry match, "lse depth N ..." */
struct aclx_lse {
	uint8_t depth; /* 0: unused */
	bool label_set, tc_set, bos_set, ttl_set;
	uint32_t label;
	uint8_t tc, bos, ttl;
};

struct aclx_geneve {
	uint16_t class, class_m;
	uint8_t type, type_m;
	uint8_t len; /* data length, multiple of 4 */
	uint8_t data[ACLX_GENEVE_DATA_MAX], data_m[ACLX_GENEVE_DATA_MAX];
};

struct aclx_rule {
	enum aclx_l3 l3;
	uint16_t ethertype; /* ACLX_L3_ETHERTYPE */

	/* IP */
	bool ip_proto_set;
	uint8_t ip_proto;
	struct aclx_addr src, dst;
	struct aclx_range sport, dport;
	struct aclx_u8m icmp_type, icmp_code;
	/* TOS byte matches; merged by aclx_rule_tos() */
	struct aclx_u8m dscp, precedence, ecn, ip_tos;
	struct aclx_range ttl; /* EQ with mask, or a range expanded later */
	/* TCP flags: value/mask; established is (ack or rst) */
	struct aclx_u16m tcp_flags;
	bool established;
	struct aclx_u32m ip_flags;
	struct aclx_u32m spi;
	struct aclx_u32m l2tpv3_sid;

	/* Ethernet / VLAN */
	struct aclx_mac smac, dmac;
	bool vlan_id_set, vlan_prio_set, cvlan_id_set, cvlan_prio_set;
	uint16_t vlan_id, cvlan_id;
	uint8_t vlan_prio, cvlan_prio;
	uint16_t vlan_tpid; /* 0: default */
	struct aclx_u8m num_of_vlans;

	/* MPLS */
	bool mpls_label_set, mpls_tc_set, mpls_bos_set, mpls_ttl_set;
	uint32_t mpls_label;
	uint8_t mpls_tc, mpls_bos, mpls_ttl;
	struct aclx_lse lse[ACLX_MAX_LSE];

	/* PPPoE */
	struct aclx_u16m pppoe_sid;
	struct aclx_u16m ppp_proto;

	/* ARP / RARP */
	struct aclx_u8m arpop;
	struct aclx_addr arp_sip, arp_tip;
	struct aclx_mac arp_sha, arp_tha;

	/* CFM */
	struct aclx_u8m cfm_mdl, cfm_op;

	/* Tunnel metadata */
	struct aclx_u32m enc_key_id;
	struct aclx_addr enc_src, enc_dst;
	struct aclx_u16m enc_dst_port;
	struct aclx_u8m enc_tos, enc_ttl;
	struct aclx_u32m enc_flags;
	uint8_t n_geneve;
	struct aclx_geneve geneve[ACLX_MAX_GENEVE];
	struct aclx_u32m vxlan_gbp;
	bool erspan_set;
	uint8_t erspan_ver, erspan_ver_m, erspan_dir, erspan_dir_m, erspan_hwid, erspan_hwid_m;
	uint32_t erspan_index, erspan_index_m;
	bool gtp_set;
	uint8_t gtp_pdu, gtp_pdu_m, gtp_qfi, gtp_qfi_m;
	bool pfcp_set;
	uint8_t pfcp_type, pfcp_type_m;
	uint64_t pfcp_seid, pfcp_seid_m;

	/* Connection tracking */
	struct aclx_u16m ct_state;
	struct aclx_u16m ct_zone;
	struct aclx_u32m ct_mark;
	bool ct_label_set;
	uint8_t ct_label[16], ct_label_m[16];

	/* Others */
	char indev[ACLX_IFNAME_LEN];
	struct aclx_u8m l2_miss;
};

/*
 * Parse the match part of an entry (everything after permit/deny), e.g.
 * "tcp 10.0.0.0 0.0.0.255 any eq www dscp ef vlan-id 10".  Returns 0 on
 * success, -1 with a message in err otherwise.
 */
extern int aclx_rule_parse(const char *text, struct aclx_rule *rule, char *err, size_t errlen);

/* Canonical text of a rule, parses back into the same rule */
extern const char *aclx_rule_print(const struct aclx_rule *rule, char *buf, size_t len);

/* Outer ethertype of the frames the rule matches (VLAN TPID when tagged) */
extern uint16_t aclx_rule_eth_proto(const struct aclx_rule *rule);

/* The rule matches IP packets, so a DSCP can be added to it */
extern bool aclx_rule_is_ip(const struct aclx_rule *rule);

/*
 * Combined TOS byte value/mask from dscp, precedence, ecn and ip-tos.
 * Returns false when they ask for conflicting bits.  *m is 0 when none is set.
 */
extern bool aclx_rule_tos(const struct aclx_rule *rule, uint8_t *v, uint8_t *m);

/* Ethertype of the payload (inside any VLAN tags) */
extern uint16_t aclx_rule_inner_ethertype(const struct aclx_rule *rule);

/* The rule matches an outer VLAN tag / a second (customer) tag */
extern bool aclx_rule_has_vlan(const struct aclx_rule *rule);
extern bool aclx_rule_has_cvlan(const struct aclx_rule *rule);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_ACL_EXT_H */
