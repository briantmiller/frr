// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Extended access-list entries translated into tc-flower match keys.
 *
 * The attributes follow what iproute2's "tc filter add ... flower" sends
 * for the same match, so that the kernel sees exactly what an
 * administrator would have configured by hand:
 *
 *  - keys that take a mask are sent with one (all ones when no mask was
 *    given), except the transport ports that tc sends without a mask;
 *  - the IP ethertype comes from the filter protocol (TCA_FLOWER_KEY_ETH_TYPE
 *    is added by the netlink encoder, not here);
 *  - VLAN tags: the filter protocol is the outer TPID and
 *    TCA_FLOWER_KEY_[C]VLAN_ETH_TYPE carries the next ethertype.
 *
 * Cisco operators that one flower key cannot express are expanded:
 *
 *  - port "neq", "lt" and "gt" become one or two port ranges;
 *  - "ttl" with neq/lt/gt/range becomes a set of masked values;
 *  - "established" (ACK or RST set) becomes one filter per flag.
 *
 * Copyright (C) 2026 FRRouting
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "zebra/zebra_acl_flower.h"

#if defined(HAVE_NETLINK) || defined(ACLX_STANDALONE)

#include <linux/pkt_cls.h>

#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif

#define ALIGN4(x) (((x) + 3U) & ~3U)

/* Attribute writer over a fixed buffer */
struct nlbuf {
	uint8_t *b;
	size_t len, cap;
	bool overflow;
};

static void *nb_attr(struct nlbuf *nb, uint16_t type, const void *data, size_t dlen)
{
	size_t total = ALIGN4(4 + dlen);
	uint16_t hdr[2];
	uint8_t *p;

	if (nb->overflow || nb->len + total > nb->cap) {
		nb->overflow = true;
		return NULL;
	}
	p = nb->b + nb->len;
	hdr[0] = 4 + dlen;
	hdr[1] = type;
	memcpy(p, hdr, 4);
	if (dlen)
		memcpy(p + 4, data, dlen);
	memset(p + 4 + dlen, 0, total - 4 - dlen);
	nb->len += total;
	return p;
}

static void nb_u8(struct nlbuf *nb, uint16_t type, uint8_t v)
{
	nb_attr(nb, type, &v, 1);
}

static void nb_u16(struct nlbuf *nb, uint16_t type, uint16_t v)
{
	nb_attr(nb, type, &v, 2);
}

static void nb_be16(struct nlbuf *nb, uint16_t type, uint16_t v)
{
	nb_u16(nb, type, htons(v));
}

static void nb_u32(struct nlbuf *nb, uint16_t type, uint32_t v)
{
	nb_attr(nb, type, &v, 4);
}

static void nb_be32(struct nlbuf *nb, uint16_t type, uint32_t v)
{
	nb_u32(nb, type, htonl(v));
}

static void nb_be64(struct nlbuf *nb, uint16_t type, uint64_t v)
{
	uint8_t b[8];

	for (int i = 0; i < 8; i++)
		b[i] = v >> (56 - 8 * i);
	nb_attr(nb, type, b, 8);
}

/* Start a nested attribute; returns its offset, closed by nb_nest_end() */
static size_t nb_nest(struct nlbuf *nb, uint16_t type)
{
	size_t off = nb->len;

	nb_attr(nb, type, NULL, 0);
	return off;
}

static void nb_nest_end(struct nlbuf *nb, size_t off)
{
	uint16_t len;

	if (nb->overflow)
		return;
	len = nb->len - off;
	memcpy(nb->b + off, &len, 2);
}

/*
 * ----------------------------------------------------------------------
 * Expansion of the operators flower has no key for
 * ----------------------------------------------------------------------
 */

/* A port match flower can do: one value (and mask) or one range */
struct port_match {
	bool set;
	bool range;
	uint16_t lo, hi, mask;
};

static void port_add(struct port_match *out, int *n, uint32_t lo, uint32_t hi)
{
	struct port_match *pm = &out[(*n)++];

	pm->set = true;
	pm->lo = lo;
	pm->hi = hi;
	pm->range = lo != hi;
	pm->mask = 0xffff;
}

/* Returns the number of alternatives (0: matches no port) */
static int port_expand(const struct aclx_range *r, struct port_match out[2])
{
	int n = 0;

	memset(out, 0, 2 * sizeof(out[0]));

	switch (r->op) {
	case ACLX_OP_NONE:
		return 1; /* out[0] unset: any port */
	case ACLX_OP_EQ:
		out[0].set = true;
		out[0].lo = out[0].hi = r->lo;
		out[0].mask = r->mask;
		return 1;
	case ACLX_OP_NEQ:
		if (r->lo > 0)
			port_add(out, &n, 0, r->lo - 1);
		if (r->lo < 65535)
			port_add(out, &n, r->lo + 1, 65535);
		return n;
	case ACLX_OP_LT:
		if (r->lo > 0)
			port_add(out, &n, 0, r->lo - 1);
		return n;
	case ACLX_OP_GT:
		if (r->lo < 65535)
			port_add(out, &n, r->lo + 1, 65535);
		return n;
	case ACLX_OP_RANGE:
		if (r->lo <= r->hi)
			port_add(out, &n, r->lo, r->hi);
		return n;
	}
	return 0;
}

struct u8_match {
	bool set;
	uint8_t v, m;
};

/* Cover [lo, hi] of an 8 bit field with value/mask pairs */
static int u8_range_to_masks(unsigned int lo, unsigned int hi, struct u8_match *out, int n)
{
	while (lo <= hi) {
		unsigned int size = 1;

		/* largest aligned block starting at lo that fits */
		while (size < 256 && !(lo & size) && lo + 2 * size - 1 <= hi)
			size *= 2;
		out[n].set = true;
		out[n].v = lo;
		out[n].m = (uint8_t) ~(size - 1);
		n++;
		lo += size;
	}
	return n;
}

static int ttl_expand(const struct aclx_range *r, struct u8_match out[16])
{
	memset(out, 0, 16 * sizeof(out[0]));

	switch (r->op) {
	case ACLX_OP_NONE:
		return 1;
	case ACLX_OP_EQ:
		out[0].set = true;
		out[0].v = r->lo & r->mask;
		out[0].m = r->mask;
		return 1;
	case ACLX_OP_NEQ: {
		int n = 0;

		if (r->lo > 0)
			n = u8_range_to_masks(0, r->lo - 1, out, n);
		if (r->lo < 255)
			n = u8_range_to_masks(r->lo + 1, 255, out, n);
		return n;
	}
	case ACLX_OP_LT:
		return r->lo > 0 ? u8_range_to_masks(0, r->lo - 1, out, 0) : 0;
	case ACLX_OP_GT:
		return r->lo < 255 ? u8_range_to_masks(r->lo + 1, 255, out, 0) : 0;
	case ACLX_OP_RANGE:
		return r->lo <= r->hi ? u8_range_to_masks(r->lo, r->hi, out, 0) : 0;
	}
	return 0;
}

struct u16_match {
	bool set;
	uint16_t v, m;
};

/* TCP flags, with "established" meaning ACK or RST */
static int tcp_expand(const struct aclx_rule *r, struct u16_match out[2])
{
	static const uint16_t est[] = { ACLX_TCP_ACK, ACLX_TCP_RST };
	int n = 0;

	memset(out, 0, 2 * sizeof(out[0]));

	if (!r->established) {
		if (r->tcp_flags.set) {
			out[0].set = true;
			out[0].v = r->tcp_flags.v;
			out[0].m = r->tcp_flags.m;
		}
		return 1;
	}

	for (size_t i = 0; i < sizeof(est) / sizeof(est[0]); i++) {
		uint16_t v = r->tcp_flags.set ? r->tcp_flags.v : 0;
		uint16_t m = r->tcp_flags.set ? r->tcp_flags.m : 0;

		/* the flag is required clear: this alternative never matches */
		if ((m & est[i]) && !(v & est[i]))
			continue;
		out[n].set = true;
		out[n].v = v | est[i];
		out[n].m = m | est[i];
		n++;
	}
	return n;
}

/*
 * ----------------------------------------------------------------------
 * Keys
 * ----------------------------------------------------------------------
 */

static void put_addr(struct nlbuf *nb, const struct aclx_addr *a, uint16_t t4, uint16_t m4,
		     uint16_t t6, uint16_t m6)
{
	int len = a->family == AF_INET ? 4 : 16;

	if (!a->set)
		return;
	nb_attr(nb, a->family == AF_INET ? t4 : t6, a->v, len);
	nb_attr(nb, a->family == AF_INET ? m4 : m6, a->m, len);
}

static void put_mac(struct nlbuf *nb, const struct aclx_mac *m, uint16_t t, uint16_t tm)
{
	if (!m->set)
		return;
	nb_attr(nb, t, m->v, 6);
	nb_attr(nb, tm, m->m, 6);
}

static void put_u8m(struct nlbuf *nb, const struct aclx_u8m *f, uint16_t t, uint16_t tm)
{
	if (!f->set)
		return;
	nb_u8(nb, t, f->v);
	nb_u8(nb, tm, f->m);
}

static void put_port(struct nlbuf *nb, const struct port_match *pm, uint8_t proto, bool src)
{
	uint16_t t, tm;

	if (!pm->set)
		return;

	if (pm->range) {
		nb_be16(nb, src ? TCA_FLOWER_KEY_PORT_SRC_MIN : TCA_FLOWER_KEY_PORT_DST_MIN,
			pm->lo);
		nb_be16(nb, src ? TCA_FLOWER_KEY_PORT_SRC_MAX : TCA_FLOWER_KEY_PORT_DST_MAX,
			pm->hi);
		return;
	}

	switch (proto) {
	case ACLX_IPPROTO_TCP:
		t = src ? TCA_FLOWER_KEY_TCP_SRC : TCA_FLOWER_KEY_TCP_DST;
		tm = src ? TCA_FLOWER_KEY_TCP_SRC_MASK : TCA_FLOWER_KEY_TCP_DST_MASK;
		break;
	case ACLX_IPPROTO_UDP:
		t = src ? TCA_FLOWER_KEY_UDP_SRC : TCA_FLOWER_KEY_UDP_DST;
		tm = src ? TCA_FLOWER_KEY_UDP_SRC_MASK : TCA_FLOWER_KEY_UDP_DST_MASK;
		break;
	default:
		t = src ? TCA_FLOWER_KEY_SCTP_SRC : TCA_FLOWER_KEY_SCTP_DST;
		tm = src ? TCA_FLOWER_KEY_SCTP_SRC_MASK : TCA_FLOWER_KEY_SCTP_DST_MASK;
		break;
	}
	nb_be16(nb, t, pm->lo);
	if (pm->mask != 0xffff)
		nb_be16(nb, tm, pm->mask);
}

static void put_ip(struct nlbuf *nb, const struct aclx_rule *r, uint8_t tos, uint8_t tos_m,
		   const struct port_match *sp, const struct port_match *dp,
		   const struct u8_match *ttl, const struct u16_match *tcp)
{
	bool v6 = r->l3 == ACLX_L3_IPV6;

	if (r->ip_proto_set)
		nb_u8(nb, TCA_FLOWER_KEY_IP_PROTO, r->ip_proto);

	put_addr(nb, &r->src, TCA_FLOWER_KEY_IPV4_SRC, TCA_FLOWER_KEY_IPV4_SRC_MASK,
		 TCA_FLOWER_KEY_IPV6_SRC, TCA_FLOWER_KEY_IPV6_SRC_MASK);
	put_addr(nb, &r->dst, TCA_FLOWER_KEY_IPV4_DST, TCA_FLOWER_KEY_IPV4_DST_MASK,
		 TCA_FLOWER_KEY_IPV6_DST, TCA_FLOWER_KEY_IPV6_DST_MASK);

	if (tos_m) {
		nb_u8(nb, TCA_FLOWER_KEY_IP_TOS, tos);
		nb_u8(nb, TCA_FLOWER_KEY_IP_TOS_MASK, tos_m);
	}
	if (ttl->set) {
		nb_u8(nb, TCA_FLOWER_KEY_IP_TTL, ttl->v);
		nb_u8(nb, TCA_FLOWER_KEY_IP_TTL_MASK, ttl->m);
	}

	put_port(nb, sp, r->ip_proto, true);
	put_port(nb, dp, r->ip_proto, false);

	if (tcp->set) {
		nb_be16(nb, TCA_FLOWER_KEY_TCP_FLAGS, tcp->v);
		nb_be16(nb, TCA_FLOWER_KEY_TCP_FLAGS_MASK, tcp->m);
	}

	if (v6) {
		put_u8m(nb, &r->icmp_type, TCA_FLOWER_KEY_ICMPV6_TYPE,
			TCA_FLOWER_KEY_ICMPV6_TYPE_MASK);
		put_u8m(nb, &r->icmp_code, TCA_FLOWER_KEY_ICMPV6_CODE,
			TCA_FLOWER_KEY_ICMPV6_CODE_MASK);
	} else {
		put_u8m(nb, &r->icmp_type, TCA_FLOWER_KEY_ICMPV4_TYPE,
			TCA_FLOWER_KEY_ICMPV4_TYPE_MASK);
		put_u8m(nb, &r->icmp_code, TCA_FLOWER_KEY_ICMPV4_CODE,
			TCA_FLOWER_KEY_ICMPV4_CODE_MASK);
	}

	if (r->spi.set) {
		nb_be32(nb, TCA_FLOWER_KEY_SPI, r->spi.v);
		nb_be32(nb, TCA_FLOWER_KEY_SPI_MASK, r->spi.m);
	}
	if (r->l2tpv3_sid.set)
		nb_be32(nb, TCA_FLOWER_KEY_L2TPV3_SID, r->l2tpv3_sid.v);

	if (r->ip_flags.set) {
		nb_be32(nb, TCA_FLOWER_KEY_FLAGS, r->ip_flags.v);
		nb_be32(nb, TCA_FLOWER_KEY_FLAGS_MASK, r->ip_flags.m);
	}
}

static void put_vlan(struct nlbuf *nb, const struct aclx_rule *r)
{
	uint16_t inner = aclx_rule_inner_ethertype(r);

	if (!aclx_rule_has_vlan(r))
		return;

	if (r->vlan_id_set)
		nb_u16(nb, TCA_FLOWER_KEY_VLAN_ID, r->vlan_id);
	if (r->vlan_prio_set)
		nb_u8(nb, TCA_FLOWER_KEY_VLAN_PRIO, r->vlan_prio);

	if (aclx_rule_has_cvlan(r)) {
		/* the outer tag is followed by an 802.1Q customer tag */
		nb_be16(nb, TCA_FLOWER_KEY_VLAN_ETH_TYPE, ACLX_ETH_P_8021Q);
		if (r->cvlan_id_set)
			nb_u16(nb, TCA_FLOWER_KEY_CVLAN_ID, r->cvlan_id);
		if (r->cvlan_prio_set)
			nb_u8(nb, TCA_FLOWER_KEY_CVLAN_PRIO, r->cvlan_prio);
		if (inner != ACLX_ETH_P_ALL)
			nb_be16(nb, TCA_FLOWER_KEY_CVLAN_ETH_TYPE, inner);
	} else if (inner != ACLX_ETH_P_ALL) {
		nb_be16(nb, TCA_FLOWER_KEY_VLAN_ETH_TYPE, inner);
	}
}

static void put_mpls(struct nlbuf *nb, const struct aclx_rule *r)
{
	size_t opts;

	if (r->mpls_label_set)
		nb_u32(nb, TCA_FLOWER_KEY_MPLS_LABEL, r->mpls_label);
	if (r->mpls_tc_set)
		nb_u8(nb, TCA_FLOWER_KEY_MPLS_TC, r->mpls_tc);
	if (r->mpls_bos_set)
		nb_u8(nb, TCA_FLOWER_KEY_MPLS_BOS, r->mpls_bos);
	if (r->mpls_ttl_set)
		nb_u8(nb, TCA_FLOWER_KEY_MPLS_TTL, r->mpls_ttl);

	if (!r->lse[0].depth)
		return;

	opts = nb_nest(nb, TCA_FLOWER_KEY_MPLS_OPTS | NLA_F_NESTED);
	for (int i = 0; i < ACLX_MAX_LSE && r->lse[i].depth; i++) {
		const struct aclx_lse *l = &r->lse[i];
		size_t lse = nb_nest(nb, TCA_FLOWER_KEY_MPLS_OPTS_LSE | NLA_F_NESTED);

		nb_u8(nb, TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH, l->depth);
		if (l->label_set)
			nb_u32(nb, TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL, l->label);
		if (l->tc_set)
			nb_u8(nb, TCA_FLOWER_KEY_MPLS_OPT_LSE_TC, l->tc);
		if (l->bos_set)
			nb_u8(nb, TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS, l->bos);
		if (l->ttl_set)
			nb_u8(nb, TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL, l->ttl);
		nb_nest_end(nb, lse);
	}
	nb_nest_end(nb, opts);
}

static void put_arp(struct nlbuf *nb, const struct aclx_rule *r)
{
	put_addr(nb, &r->arp_sip, TCA_FLOWER_KEY_ARP_SIP, TCA_FLOWER_KEY_ARP_SIP_MASK, 0, 0);
	put_addr(nb, &r->arp_tip, TCA_FLOWER_KEY_ARP_TIP, TCA_FLOWER_KEY_ARP_TIP_MASK, 0, 0);
	put_u8m(nb, &r->arpop, TCA_FLOWER_KEY_ARP_OP, TCA_FLOWER_KEY_ARP_OP_MASK);
	put_mac(nb, &r->arp_sha, TCA_FLOWER_KEY_ARP_SHA, TCA_FLOWER_KEY_ARP_SHA_MASK);
	put_mac(nb, &r->arp_tha, TCA_FLOWER_KEY_ARP_THA, TCA_FLOWER_KEY_ARP_THA_MASK);
}

/* key and mask nests of the tunnel options; @mask selects which */
static void put_enc_opts_one(struct nlbuf *nb, const struct aclx_rule *r, bool mask)
{
	size_t outer, inner;

	if (r->n_geneve) {
		/* tc sends geneve options without NLA_F_NESTED */
		outer = nb_nest(nb, mask ? TCA_FLOWER_KEY_ENC_OPTS_MASK : TCA_FLOWER_KEY_ENC_OPTS);
		for (int i = 0; i < r->n_geneve; i++) {
			const struct aclx_geneve *g = &r->geneve[i];

			inner = nb_nest(nb, TCA_FLOWER_KEY_ENC_OPTS_GENEVE);
			nb_be16(nb, TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS,
				mask ? g->class_m : g->class);
			nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE, mask ? g->type_m : g->type);
			nb_attr(nb, TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA, mask ? g->data_m : g->data,
				g->len);
			nb_nest_end(nb, inner);
		}
		nb_nest_end(nb, outer);
		return;
	}

	if (!r->vxlan_gbp.set && !r->erspan_set && !r->gtp_set && !r->pfcp_set)
		return;

	outer = nb_nest(nb, (mask ? TCA_FLOWER_KEY_ENC_OPTS_MASK : TCA_FLOWER_KEY_ENC_OPTS) |
				    NLA_F_NESTED);
	if (r->vxlan_gbp.set) {
		inner = nb_nest(nb, TCA_FLOWER_KEY_ENC_OPTS_VXLAN | NLA_F_NESTED);
		nb_u32(nb, TCA_FLOWER_KEY_ENC_OPT_VXLAN_GBP,
		       mask ? r->vxlan_gbp.m : r->vxlan_gbp.v);
		nb_nest_end(nb, inner);
	} else if (r->erspan_set) {
		inner = nb_nest(nb, TCA_FLOWER_KEY_ENC_OPTS_ERSPAN | NLA_F_NESTED);
		if (!mask) {
			nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER, r->erspan_ver);
			if (r->erspan_ver == 1) {
				nb_be32(nb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX, r->erspan_index);
			} else {
				nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR, r->erspan_dir);
				nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID, r->erspan_hwid);
			}
		} else {
			/*
			 * Like tc, the mask carries the version itself and
			 * all fields; the kernel only looks at those of the
			 * version.
			 */
			bool v1 = r->erspan_ver == 1;

			nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER, r->erspan_ver_m);
			nb_be32(nb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX,
				v1 ? r->erspan_index_m : 0xffffffff);
			nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR, v1 ? 0xff : r->erspan_dir_m);
			nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID, v1 ? 0xff : r->erspan_hwid_m);
		}
		nb_nest_end(nb, inner);
	} else if (r->gtp_set) {
		inner = nb_nest(nb, TCA_FLOWER_KEY_ENC_OPTS_GTP | NLA_F_NESTED);
		nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_GTP_PDU_TYPE, mask ? r->gtp_pdu_m : r->gtp_pdu);
		nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_GTP_QFI, mask ? r->gtp_qfi_m : r->gtp_qfi);
		nb_nest_end(nb, inner);
	} else {
		inner = nb_nest(nb, TCA_FLOWER_KEY_ENC_OPTS_PFCP | NLA_F_NESTED);
		nb_u8(nb, TCA_FLOWER_KEY_ENC_OPT_PFCP_TYPE, mask ? r->pfcp_type_m : r->pfcp_type);
		nb_be64(nb, TCA_FLOWER_KEY_ENC_OPT_PFCP_SEID, mask ? r->pfcp_seid_m : r->pfcp_seid);
		nb_nest_end(nb, inner);
	}
	nb_nest_end(nb, outer);
}

static void put_tunnel(struct nlbuf *nb, const struct aclx_rule *r)
{
	if (r->enc_key_id.set)
		nb_be32(nb, TCA_FLOWER_KEY_ENC_KEY_ID, r->enc_key_id.v);
	put_addr(nb, &r->enc_src, TCA_FLOWER_KEY_ENC_IPV4_SRC, TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,
		 TCA_FLOWER_KEY_ENC_IPV6_SRC, TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK);
	put_addr(nb, &r->enc_dst, TCA_FLOWER_KEY_ENC_IPV4_DST, TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,
		 TCA_FLOWER_KEY_ENC_IPV6_DST, TCA_FLOWER_KEY_ENC_IPV6_DST_MASK);
	if (r->enc_dst_port.set)
		nb_be16(nb, TCA_FLOWER_KEY_ENC_UDP_DST_PORT, r->enc_dst_port.v);
	put_u8m(nb, &r->enc_tos, TCA_FLOWER_KEY_ENC_IP_TOS, TCA_FLOWER_KEY_ENC_IP_TOS_MASK);
	put_u8m(nb, &r->enc_ttl, TCA_FLOWER_KEY_ENC_IP_TTL, TCA_FLOWER_KEY_ENC_IP_TTL_MASK);
	put_enc_opts_one(nb, r, false);
	put_enc_opts_one(nb, r, true);
	if (r->enc_flags.set) {
		nb_be32(nb, TCA_FLOWER_KEY_ENC_FLAGS, r->enc_flags.v);
		nb_be32(nb, TCA_FLOWER_KEY_ENC_FLAGS_MASK, r->enc_flags.m);
	}
}

static void put_ct(struct nlbuf *nb, const struct aclx_rule *r)
{
	if (r->ct_state.set) {
		nb_u16(nb, TCA_FLOWER_KEY_CT_STATE, r->ct_state.v);
		nb_u16(nb, TCA_FLOWER_KEY_CT_STATE_MASK, r->ct_state.m);
	}
	if (r->ct_zone.set) {
		nb_u16(nb, TCA_FLOWER_KEY_CT_ZONE, r->ct_zone.v);
		nb_u16(nb, TCA_FLOWER_KEY_CT_ZONE_MASK, r->ct_zone.m);
	}
	if (r->ct_mark.set) {
		nb_u32(nb, TCA_FLOWER_KEY_CT_MARK, r->ct_mark.v);
		nb_u32(nb, TCA_FLOWER_KEY_CT_MARK_MASK, r->ct_mark.m);
	}
	if (r->ct_label_set) {
		nb_attr(nb, TCA_FLOWER_KEY_CT_LABELS, r->ct_label, 16);
		nb_attr(nb, TCA_FLOWER_KEY_CT_LABELS_MASK, r->ct_label_m, 16);
	}
}

static void desc_port(char *buf, size_t len, const char *kw, const struct aclx_range *op,
		      const struct port_match *pm)
{
	size_t n = strlen(buf);

	if (op->op == ACLX_OP_NONE || op->op == ACLX_OP_EQ || !pm->set)
		return;
	if (pm->range)
		snprintf(buf + n, len - n, "%s%s %u-%u", n ? " " : "", kw, pm->lo, pm->hi);
	else
		snprintf(buf + n, len - n, "%s%s %u", n ? " " : "", kw, pm->lo);
}

/* The parts of a filter that differ from the entry's own text */
static void describe(struct aclx_flower *f, const struct aclx_rule *r, const struct port_match *sp,
		     const struct port_match *dp, const struct u8_match *ttl,
		     const struct u16_match *tcp)
{
	size_t n;

	f->desc[0] = '\0';
	desc_port(f->desc, sizeof(f->desc), "src-port", &r->sport, sp);
	desc_port(f->desc, sizeof(f->desc), "dst-port", &r->dport, dp);
	n = strlen(f->desc);
	if (r->ttl.op != ACLX_OP_NONE && r->ttl.op != ACLX_OP_EQ && ttl->set)
		snprintf(f->desc + n, sizeof(f->desc) - n, "%sttl %u/0x%02x", n ? " " : "", ttl->v,
			 ttl->m);
	n = strlen(f->desc);
	if (r->established && tcp->set)
		snprintf(f->desc + n, sizeof(f->desc) - n, "%stcp-flags 0x%x/0x%x", n ? " " : "",
			 tcp->v, tcp->m);
}

static int fail(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
	return -1;
}

int aclx_flower_encode(const struct aclx_rule *r, uint8_t xtos, uint8_t xtos_m,
		       struct aclx_flower *out, int max, char *err, size_t errlen)
{
	struct port_match sp[2], dp[2];
	struct u8_match ttl[16];
	struct u16_match tcp[2];
	int nsp, ndp, nttl, ntcp, total, n = 0;
	uint8_t tos, tos_m;
	bool ip = aclx_rule_is_ip(r);

	err[0] = '\0';

	/* TOS from the entry, plus the class-map's */
	if (ip) {
		if (!aclx_rule_tos(r, &tos, &tos_m))
			return fail(err, errlen, "conflicting dscp, precedence, ecn and ip-tos");
		if ((tos ^ xtos) & tos_m & xtos_m)
			return 0;
		tos = (tos & ~xtos_m) | (xtos & xtos_m);
		tos_m |= xtos_m;
	} else {
		/* a TOS constraint can never match a non-IP packet */
		if (xtos_m)
			return 0;
		tos = tos_m = 0;
	}

	nsp = port_expand(&r->sport, sp);
	ndp = port_expand(&r->dport, dp);
	nttl = ip ? ttl_expand(&r->ttl, ttl) : (memset(ttl, 0, sizeof(ttl)), 1);
	ntcp = tcp_expand(r, tcp);

	total = nsp * ndp * nttl * ntcp;
	if (total > max)
		return fail(err, errlen, "entry needs %d filters, at most %d are allowed", total,
			    max);

	for (int a = 0; a < nsp; a++)
		for (int b = 0; b < ndp; b++)
			for (int c = 0; c < nttl; c++)
				for (int d = 0; d < ntcp; d++) {
					struct aclx_flower *f = &out[n++];
					struct nlbuf nb = {
						.b = f->raw,
						.cap = sizeof(f->raw),
					};

					f->eth_proto = aclx_rule_eth_proto(r);

					put_mac(&nb, &r->dmac, TCA_FLOWER_KEY_ETH_DST,
						TCA_FLOWER_KEY_ETH_DST_MASK);
					put_mac(&nb, &r->smac, TCA_FLOWER_KEY_ETH_SRC,
						TCA_FLOWER_KEY_ETH_SRC_MASK);
					put_vlan(&nb, r);
					if (r->num_of_vlans.set)
						nb_u8(&nb, TCA_FLOWER_KEY_NUM_OF_VLANS,
						      r->num_of_vlans.v);

					if (ip)
						put_ip(&nb, r, tos, tos_m, &sp[a], &dp[b], &ttl[c],
						       &tcp[d]);
					put_mpls(&nb, r);
					if (r->pppoe_sid.set)
						nb_be16(&nb, TCA_FLOWER_KEY_PPPOE_SID,
							r->pppoe_sid.v);
					if (r->ppp_proto.set)
						nb_be16(&nb, TCA_FLOWER_KEY_PPP_PROTO,
							r->ppp_proto.v);
					put_arp(&nb, r);
					if (r->cfm_mdl.set || r->cfm_op.set) {
						size_t cfm = nb_nest(&nb, TCA_FLOWER_KEY_CFM |
										  NLA_F_NESTED);

						if (r->cfm_mdl.set)
							nb_u8(&nb, TCA_FLOWER_KEY_CFM_MD_LEVEL,
							      r->cfm_mdl.v);
						if (r->cfm_op.set)
							nb_u8(&nb, TCA_FLOWER_KEY_CFM_OPCODE,
							      r->cfm_op.v);
						nb_nest_end(&nb, cfm);
					}
					put_tunnel(&nb, r);
					put_ct(&nb, r);
					if (r->indev[0])
						nb_attr(&nb, TCA_FLOWER_INDEV, r->indev,
							strlen(r->indev) + 1);
					if (r->l2_miss.set)
						nb_u8(&nb, TCA_FLOWER_L2_MISS, r->l2_miss.v);

					if (nb.overflow)
						return fail(err, errlen,
							    "entry has too many match keys");
					f->len = nb.len;
					describe(f, r, &sp[a], &dp[b], &ttl[c], &tcp[d]);
				}

	return n;
}

#else /* !HAVE_NETLINK */

int aclx_flower_encode(const struct aclx_rule *r, uint8_t xtos, uint8_t xtos_m,
		       struct aclx_flower *out, int max, char *err, size_t errlen)
{
	snprintf(err, errlen, "tc-flower is not available on this platform");
	return -1;
}

#endif /* HAVE_NETLINK */
