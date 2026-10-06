// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Extended access-lists ("ip access-list extended NAME"): syntax.
 *
 * An entry is "permit|deny" followed by a match specification:
 *
 *   PROTOCOL SOURCE [PORTS] DESTINATION [PORTS] [ICMP-MESSAGE] [OPTION...]
 *   arp|rarp|mpls|mpls-multicast|pppoe|cfm [OPTION...]
 *   ethertype <any|0xHHHH> [OPTION...]
 *
 * The IP part follows Cisco extended access-lists; every other tc-flower
 * match key is available as an option named after the flower key with
 * dashes instead of underscores (vlan-id, mpls-label, arp-op, ...).
 *
 * Copyright (C) 2026 FRRouting
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "zebra/zebra_acl_ext.h"

#define MAX_TOKENS 160

/*
 * ----------------------------------------------------------------------
 * Name tables
 * ----------------------------------------------------------------------
 */

struct name_value {
	const char *name;
	uint32_t value;
};

static const struct name_value ip_protocols[] = {
	{ "icmp", 1 },	 { "igmp", 2 },	  { "ipinip", 4 }, { "tcp", 6 },     { "udp", 17 },
	{ "gre", 47 },	 { "esp", 50 },	  { "ahp", 51 },   { "icmpv6", 58 }, { "eigrp", 88 },
	{ "ospf", 89 },	 { "nos", 94 },	  { "pim", 103 },  { "pcp", 108 },   { "vrrp", 112 },
	{ "l2tp", 115 }, { "sctp", 132 }, { NULL, 0 },
};

/* also accepted on input */
static const struct name_value ip_protocol_aliases[] = {
	{ "ah", 51 },
	{ NULL, 0 },
};

/* Cisco port names (TCP and UDP) */
static const struct name_value port_names[] = {
	{ "echo", 7 },		{ "discard", 9 },      { "daytime", 13 },
	{ "chargen", 19 },	{ "ftp-data", 20 },    { "ftp", 21 },
	{ "ssh", 22 },		{ "telnet", 23 },      { "smtp", 25 },
	{ "time", 37 },		{ "nameserver", 42 },  { "whois", 43 },
	{ "tacacs", 49 },	{ "domain", 53 },      { "bootps", 67 },
	{ "bootpc", 68 },	{ "tftp", 69 },	       { "gopher", 70 },
	{ "finger", 79 },	{ "www", 80 },	       { "http", 80 },
	{ "hostname", 101 },	{ "pop2", 109 },       { "pop3", 110 },
	{ "sunrpc", 111 },	{ "ident", 113 },      { "nntp", 119 },
	{ "ntp", 123 },		{ "netbios-ns", 137 }, { "netbios-dgm", 138 },
	{ "netbios-ss", 139 },	{ "snmp", 161 },       { "snmptrap", 162 },
	{ "xdmcp", 177 },	{ "bgp", 179 },	       { "irc", 194 },
	{ "dnsix", 195 },	{ "mobile-ip", 434 },  { "https", 443 },
	{ "pim-auto-rp", 496 }, { "isakmp", 500 },     { "biff", 512 },
	{ "exec", 512 },	{ "login", 513 },      { "who", 513 },
	{ "cmd", 514 },		{ "syslog", 514 },     { "lpd", 515 },
	{ "talk", 517 },	{ "rip", 520 },	       { "uucp", 540 },
	{ "klogin", 543 },	{ "kshell", 544 },     { "ldp", 646 },
	{ "bfd", 3784 },	{ "bfd-echo", 3785 },  { NULL, 0 },
};

static const struct name_value dscp_names[] = {
	{ "default", 0 }, { "cs0", 0 },	  { "cs1", 8 },	  { "af11", 10 }, { "af12", 12 },
	{ "af13", 14 },	  { "cs2", 16 },  { "af21", 18 }, { "af22", 20 }, { "af23", 22 },
	{ "cs3", 24 },	  { "af31", 26 }, { "af32", 28 }, { "af33", 30 }, { "cs4", 32 },
	{ "af41", 34 },	  { "af42", 36 }, { "af43", 38 }, { "cs5", 40 },  { "va", 44 },
	{ "ef", 46 },	  { "cs6", 48 },  { "cs7", 56 },  { NULL, 0 },
};

static const struct name_value precedence_names[] = {
	{ "routine", 0 },  { "priority", 1 },	    { "immediate", 2 },
	{ "flash", 3 },	   { "flash-override", 4 }, { "critical", 5 },
	{ "internet", 6 }, { "network", 7 },	    { NULL, 0 },
};

static const struct name_value ecn_names[] = {
	{ "not-ect", 0 }, { "ect1", 1 }, { "ect0", 2 }, { "ce", 3 }, { NULL, 0 },
};

static const struct name_value tcp_flag_names[] = {
	{ "fin", ACLX_TCP_FIN }, { "syn", ACLX_TCP_SYN },
	{ "rst", ACLX_TCP_RST }, { "psh", ACLX_TCP_PSH },
	{ "ack", ACLX_TCP_ACK }, { "urg", ACLX_TCP_URG },
	{ "ece", ACLX_TCP_ECE }, { "cwr", ACLX_TCP_CWR },
	{ "ns", ACLX_TCP_NS },	 { NULL, 0 },
};

static const struct name_value ct_state_names[] = {
	{ "trk", ACLX_CT_TRK },
	{ "new", ACLX_CT_NEW },
	{ "est", ACLX_CT_EST },
	{ "rel", ACLX_CT_REL },
	{ "inv", ACLX_CT_INV },
	{ "rpl", ACLX_CT_RPL },
	{ NULL, 0 },
};

static const struct name_value ip_flag_names[] = {
	{ "frag", ACLX_IPF_FRAG },
	{ "firstfrag", ACLX_IPF_FIRSTFRAG },
	{ NULL, 0 },
};

static const struct name_value enc_flag_names[] = {
	{ "tuncsum", ACLX_ENCF_CSUM },
	{ "tundf", ACLX_ENCF_DF },
	{ "tunoam", ACLX_ENCF_OAM },
	{ "tuncrit", ACLX_ENCF_CRIT },
	{ NULL, 0 },
};

static const struct name_value ppp_proto_names[] = {
	{ "ip", 0x0021 },      { "ipv6", 0x0057 }, { "mpls-uc", 0x0281 },
	{ "mpls-mc", 0x0283 }, { NULL, 0 },
};

static const struct name_value ethertype_names[] = {
	{ "ipv4", ACLX_ETH_P_IP },
	{ "arp", ACLX_ETH_P_ARP },
	{ "rarp", ACLX_ETH_P_RARP },
	{ "ipv6", ACLX_ETH_P_IPV6 },
	{ "mpls", ACLX_ETH_P_MPLS_UC },
	{ "mpls-multicast", ACLX_ETH_P_MPLS_MC },
	{ "pppoe", ACLX_ETH_P_PPP_SES },
	{ "cfm", ACLX_ETH_P_CFM },
	{ "lldp", 0x88CC },
	{ NULL, 0 },
};

/* ICMP messages: type and code (-1: any code) */
struct icmp_msg {
	const char *name;
	int type, code;
};

static const struct icmp_msg icmp4_msgs[] = {
	{ "echo-reply", 0, -1 },
	{ "unreachable", 3, -1 },
	{ "net-unreachable", 3, 0 },
	{ "host-unreachable", 3, 1 },
	{ "protocol-unreachable", 3, 2 },
	{ "port-unreachable", 3, 3 },
	{ "packet-too-big", 3, 4 },
	{ "source-route-failed", 3, 5 },
	{ "administratively-prohibited", 3, 13 },
	{ "source-quench", 4, -1 },
	{ "redirect", 5, -1 },
	{ "alternate-address", 6, -1 },
	{ "echo", 8, -1 },
	{ "router-advertisement", 9, -1 },
	{ "router-solicitation", 10, -1 },
	{ "time-exceeded", 11, -1 },
	{ "ttl-exceeded", 11, 0 },
	{ "reassembly-timeout", 11, 1 },
	{ "parameter-problem", 12, -1 },
	{ "timestamp-request", 13, -1 },
	{ "timestamp-reply", 14, -1 },
	{ "information-request", 15, -1 },
	{ "information-reply", 16, -1 },
	{ "mask-request", 17, -1 },
	{ "mask-reply", 18, -1 },
	{ "traceroute", 30, -1 },
	{ NULL, 0, 0 },
};

static const struct icmp_msg icmp6_msgs[] = {
	{ "destination-unreachable", 1, -1 },
	{ "no-route", 1, 0 },
	{ "admin-prohibited", 1, 1 },
	{ "beyond-scope", 1, 2 },
	{ "address-unreachable", 1, 3 },
	{ "port-unreachable", 1, 4 },
	{ "packet-too-big", 2, -1 },
	{ "time-exceeded", 3, -1 },
	{ "hop-limit", 3, 0 },
	{ "reassembly-timeout", 3, 1 },
	{ "parameter-problem", 4, -1 },
	{ "echo-request", 128, -1 },
	{ "echo-reply", 129, -1 },
	{ "mld-query", 130, -1 },
	{ "mld-report", 131, -1 },
	{ "mld-reduction", 132, -1 },
	{ "router-solicitation", 133, -1 },
	{ "router-advertisement", 134, -1 },
	{ "nd-ns", 135, -1 },
	{ "nd-na", 136, -1 },
	{ "redirect", 137, -1 },
	{ "mldv2-report", 143, -1 },
	{ NULL, 0, 0 },
};

static bool name_lookup(const struct name_value *t, const char *name, uint32_t *v)
{
	for (; t->name; t++) {
		if (strcmp(t->name, name) == 0) {
			*v = t->value;
			return true;
		}
	}
	return false;
}

static const char *name_of(const struct name_value *t, uint32_t v)
{
	for (; t->name; t++)
		if (t->value == v)
			return t->name;
	return NULL;
}

/*
 * ----------------------------------------------------------------------
 * Parser
 * ----------------------------------------------------------------------
 */

struct parser {
	char *tok[MAX_TOKENS];
	int n, i;
	char *err;
	size_t errlen;
	struct aclx_rule *r;
	/* options seen, to reject duplicates (each takes at least one token) */
	char seen[MAX_TOKENS][24];
	int nseen;
};

static int fail(struct parser *p, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(p->err, p->errlen, fmt, ap);
	va_end(ap);
	return -1;
}

static const char *peek(struct parser *p)
{
	return p->i < p->n ? p->tok[p->i] : NULL;
}

static const char *next_arg(struct parser *p, const char *what)
{
	if (p->i >= p->n) {
		fail(p, "%s needs a value", what);
		return NULL;
	}
	return p->tok[p->i++];
}

/* unsigned number, decimal or 0x hex */
static bool parse_num(const char *s, uint64_t max, uint64_t *out)
{
	char *end;
	unsigned long long v;

	if (!s || !*s || *s == '-' || *s == '+')
		return false;
	errno = 0;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		v = strtoull(s + 2, &end, 16);
	else
		v = strtoull(s, &end, 10);
	if (errno || *end || end == s || v > max)
		return false;
	*out = v;
	return true;
}

/* "V" or "V/M"; mask defaults to full */
static bool parse_vm(const char *s, uint64_t max, uint64_t *v, uint64_t *m)
{
	char buf[64];
	char *slash;

	if (strlen(s) >= sizeof(buf))
		return false;
	strcpy(buf, s);
	slash = strchr(buf, '/');
	if (slash)
		*slash++ = '\0';
	if (!parse_num(buf, max, v))
		return false;
	*m = max;
	if (slash && !parse_num(slash, max, m))
		return false;
	return true;
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	c = tolower(c);
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/* hex string (optional 0x) into bytes; returns number of bytes or -1 */
static int parse_hex_bytes(const char *s, uint8_t *out, size_t max)
{
	size_t len, n = 0;

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	len = strlen(s);
	if (len == 0 || len % 2 || len / 2 > max)
		return -1;
	for (size_t i = 0; i < len; i += 2) {
		int hi = hexval(s[i]), lo = hexval(s[i + 1]);

		if (hi < 0 || lo < 0)
			return -1;
		out[n++] = hi << 4 | lo;
	}
	return n;
}

/* aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff or aabb.ccdd.eeff */
static bool parse_mac(const char *s, uint8_t mac[6])
{
	unsigned int b[6];
	char c;

	if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &c) ==
		    6 ||
	    sscanf(s, "%2x-%2x-%2x-%2x-%2x-%2x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &c) ==
		    6) {
		for (int i = 0; i < 6; i++)
			mac[i] = b[i];
		return true;
	}

	unsigned int w[3];

	if (sscanf(s, "%4x.%4x.%4x%c", &w[0], &w[1], &w[2], &c) == 3) {
		for (int i = 0; i < 3; i++) {
			mac[2 * i] = w[i] >> 8;
			mac[2 * i + 1] = w[i] & 0xff;
		}
		return true;
	}

	return false;
}

/* MAC[/MAC|/BITS] */
static bool parse_mac_masked(const char *s, struct aclx_mac *mac)
{
	char buf[64];
	char *slash;
	uint64_t bits;

	if (strlen(s) >= sizeof(buf))
		return false;
	strcpy(buf, s);
	slash = strchr(buf, '/');
	if (slash)
		*slash++ = '\0';
	if (!parse_mac(buf, mac->v))
		return false;
	memset(mac->m, 0xff, 6);
	if (slash) {
		if (parse_num(slash, 48, &bits)) {
			for (int i = 0; i < 6; i++) {
				int b = (int)bits - 8 * i;

				mac->m[i] = b >= 8   ? 0xff
					    : b <= 0 ? 0
						     : (uint8_t)(0xff << (8 - b));
			}
		} else if (!parse_mac(slash, mac->m)) {
			return false;
		}
	}
	for (int i = 0; i < 6; i++)
		mac->v[i] &= mac->m[i];
	mac->set = true;
	return true;
}

static int family_len(int family)
{
	return family == AF_INET ? 4 : 16;
}

static void prefix_mask(int family, unsigned int plen, uint8_t *m)
{
	int len = family_len(family);

	for (int i = 0; i < len; i++) {
		int b = (int)plen - 8 * i;

		m[i] = b >= 8 ? 0xff : b <= 0 ? 0 : (uint8_t)(0xff << (8 - b));
	}
}

static bool mask_is_zero(const uint8_t *m, int len)
{
	for (int i = 0; i < len; i++)
		if (m[i])
			return false;
	return true;
}

static bool mask_is_full(const uint8_t *m, int len)
{
	for (int i = 0; i < len; i++)
		if (m[i] != 0xff)
			return false;
	return true;
}

/* prefix length of a contiguous mask, -1 otherwise */
static int mask_plen(const uint8_t *m, int len)
{
	int plen = 0;
	bool ended = false;

	for (int i = 0; i < len; i++) {
		for (int b = 7; b >= 0; b--) {
			if (m[i] & (1 << b)) {
				if (ended)
					return -1;
				plen++;
			} else {
				ended = true;
			}
		}
	}
	return plen;
}

/* ADDR or ADDR/PLEN, IPv4 or IPv6 */
static bool parse_prefix(const char *s, struct aclx_addr *a, int want_family)
{
	char buf[INET6_ADDRSTRLEN + 8];
	char *slash;
	uint64_t plen;

	if (strlen(s) >= sizeof(buf))
		return false;
	strcpy(buf, s);
	slash = strchr(buf, '/');
	if (slash)
		*slash++ = '\0';

	memset(a, 0, sizeof(*a));
	if (inet_pton(AF_INET, buf, a->v) == 1)
		a->family = AF_INET;
	else if (inet_pton(AF_INET6, buf, a->v) == 1)
		a->family = AF_INET6;
	else
		return false;

	if (want_family && a->family != want_family)
		return false;

	plen = a->family == AF_INET ? 32 : 128;
	if (slash && !parse_num(slash, plen, &plen))
		return false;
	prefix_mask(a->family, plen, a->m);
	for (int i = 0; i < 16; i++)
		a->v[i] &= a->m[i];
	a->set = true;
	return true;
}

/* positional address: any | host ADDR | ADDR/PLEN | ADDR WILDCARD */
static int parse_addr(struct parser *p, const char *what, struct aclx_addr *a)
{
	const char *t = next_arg(p, what);
	uint8_t wild[16];

	if (!t)
		return -1;

	memset(a, 0, sizeof(*a));
	if (strcmp(t, "any") == 0)
		return 0;

	if (strcmp(t, "host") == 0) {
		t = next_arg(p, "host");
		if (!t)
			return -1;
		if (strchr(t, '/') || !parse_prefix(t, a, 0))
			return fail(p, "invalid host address '%s'", t);
		return 0;
	}

	if (strchr(t, '/')) {
		if (!parse_prefix(t, a, 0))
			return fail(p, "invalid %s prefix '%s'", what, t);
		return 0;
	}

	if (!parse_prefix(t, a, 0))
		return fail(p,
			    "invalid %s '%s' (expected any, host ADDRESS, ADDRESS WILDCARD or PREFIX/LEN)",
			    what, t);

	/* ADDRESS WILDCARD */
	t = next_arg(p, "address wildcard");
	if (!t)
		return fail(p, "%s address needs a wildcard mask (or use host or PREFIX/LEN)",
			    what);
	if (inet_pton(a->family, t, wild) != 1)
		return fail(p, "invalid wildcard mask '%s'", t);
	for (int i = 0; i < family_len(a->family); i++) {
		a->m[i] = ~wild[i];
		a->v[i] &= a->m[i];
	}
	return 0;
}

static int parse_port_value(struct parser *p, const char *t, uint32_t *port, uint32_t *mask)
{
	char buf[64];
	char *slash;
	uint64_t v;

	if (strlen(t) >= sizeof(buf))
		return fail(p, "invalid port '%s'", t);
	strcpy(buf, t);
	slash = strchr(buf, '/');
	if (slash) {
		if (!mask)
			return fail(p, "a port mask is only allowed with eq");
		*slash++ = '\0';
	}
	if (!name_lookup(port_names, buf, port)) {
		if (!parse_num(buf, 65535, &v))
			return fail(p, "invalid port '%s'", buf);
		*port = v;
	}
	if (mask) {
		*mask = 0xffff;
		if (slash) {
			if (!parse_num(slash, 65535, &v))
				return fail(p, "invalid port mask '%s'", slash);
			*mask = v;
		}
	}
	return 0;
}

static bool is_op(const char *t)
{
	return t && (!strcmp(t, "eq") || !strcmp(t, "neq") || !strcmp(t, "lt") ||
		     !strcmp(t, "gt") || !strcmp(t, "range"));
}

/* eq P[/M] | neq P | lt P | gt P | range P P (ports or ttl) */
static int parse_range_op(struct parser *p, struct aclx_range *r, uint32_t maxv, bool is_port,
			  const char *what)
{
	const char *op = next_arg(p, what);
	const char *t;
	uint64_t v, m;

	memset(r, 0, sizeof(*r));
	if (!strcmp(op, "eq"))
		r->op = ACLX_OP_EQ;
	else if (!strcmp(op, "neq"))
		r->op = ACLX_OP_NEQ;
	else if (!strcmp(op, "lt"))
		r->op = ACLX_OP_LT;
	else if (!strcmp(op, "gt"))
		r->op = ACLX_OP_GT;
	else if (!strcmp(op, "range"))
		r->op = ACLX_OP_RANGE;
	else
		return fail(p, "invalid %s operator '%s' (eq, neq, lt, gt or range)", what, op);

	t = next_arg(p, op);
	if (!t)
		return -1;

	if (is_port) {
		if (parse_port_value(p, t, &r->lo, r->op == ACLX_OP_EQ ? &r->mask : NULL))
			return -1;
		if (r->op == ACLX_OP_RANGE) {
			t = next_arg(p, "range");
			if (!t || parse_port_value(p, t, &r->hi, NULL))
				return -1;
		}
	} else {
		if (r->op == ACLX_OP_EQ) {
			if (!parse_vm(t, maxv, &v, &m))
				return fail(p, "invalid %s '%s'", what, t);
			r->lo = v;
			r->mask = m;
		} else {
			if (!parse_num(t, maxv, &v))
				return fail(p, "invalid %s '%s'", what, t);
			r->lo = v;
			if (r->op == ACLX_OP_RANGE) {
				t = next_arg(p, "range");
				if (!t || !parse_num(t, maxv, &v))
					return fail(p, "invalid %s range", what);
				r->hi = v;
			}
		}
	}

	if (r->op == ACLX_OP_RANGE && r->hi < r->lo)
		return fail(p, "invalid %s range %u %u: the end is below the start", what, r->lo,
			    r->hi);
	if (r->op == ACLX_OP_EQ) {
		if (!is_port && !r->mask)
			return fail(p, "%s mask 0 matches every packet", what);
		r->lo &= r->mask;
	}
	return 0;
}

/* "+trk+est-new" style flag lists (ct-state) */
static bool parse_plus_minus(const char *s, const struct name_value *names, uint16_t *v,
			     uint16_t *m)
{
	*v = *m = 0;
	if (!*s)
		return false;
	while (*s) {
		bool plus;
		const struct name_value *n;

		if (*s == '+')
			plus = true;
		else if (*s == '-')
			plus = false;
		else
			return false;
		s++;
		for (n = names; n->name; n++) {
			size_t len = strlen(n->name);

			if (!strncmp(s, n->name, len)) {
				if (plus)
					*v |= n->value;
				*m |= n->value;
				s += len;
				break;
			}
		}
		if (!n->name)
			return false;
	}
	return true;
}

/* "frag/nofirstfrag" style flag lists (ip-flags, enc-flags) */
static bool parse_slash_flags(const char *s, const struct name_value *names, uint32_t *v,
			      uint32_t *m)
{
	char buf[128];
	char *tok, *save = NULL;

	if (strlen(s) >= sizeof(buf))
		return false;
	strcpy(buf, s);
	*v = *m = 0;
	for (tok = strtok_r(buf, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
		bool no = !strncmp(tok, "no", 2);
		uint32_t f;

		if (!name_lookup(names, no ? tok + 2 : tok, &f))
			return false;
		if (no)
			*v &= ~f;
		else
			*v |= f;
		*m |= f;
	}
	return *m != 0;
}

static int merge_tcp_flags(struct parser *p, uint16_t v, uint16_t m)
{
	struct aclx_u16m *f = &p->r->tcp_flags;

	if (f->set && ((f->v ^ v) & f->m & m))
		return fail(p, "conflicting TCP flag conditions");
	f->v = (f->v & ~m) | (v & m);
	f->m |= m;
	f->set = true;
	return 0;
}

/* Hexadecimal number with optional 0x prefix */
static bool parse_hexnum(const char *s, uint64_t max, uint64_t *out)
{
	uint64_t v = 0;

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	if (!*s || strlen(s) > 16)
		return false;
	for (; *s; s++) {
		int h = hexval(*s);

		if (h < 0)
			return false;
		v = (v << 4) | h;
	}
	if (v > max)
		return false;
	*out = v;
	return true;
}

static int parse_geneve(struct parser *p, const char *s)
{
	struct aclx_rule *r = p->r;
	char buf[1024];
	char *opt, *save = NULL;

	if (strlen(s) >= sizeof(buf))
		return fail(p, "geneve-opts too long");
	strcpy(buf, s);

	for (opt = strtok_r(buf, ",", &save); opt; opt = strtok_r(NULL, ",", &save)) {
		struct aclx_geneve *g;
		char *slash = strchr(opt, '/');
		char *f[3], *fm[3] = {};
		uint64_t v;
		int n;

		if (r->n_geneve >= ACLX_MAX_GENEVE)
			return fail(p, "at most %d geneve options", ACLX_MAX_GENEVE);
		g = &r->geneve[r->n_geneve++];

		if (slash)
			*slash++ = '\0';
		f[0] = strsep(&opt, ":");
		f[1] = strsep(&opt, ":");
		f[2] = opt;
		if (!f[0] || !f[1] || !f[2] || !*f[0] || !*f[1] || !*f[2])
			return fail(p,
				    "geneve option must be CLASS:TYPE:DATA[/CLASS_MASK:TYPE_MASK:DATA_MASK]");
		if (slash) {
			fm[0] = strsep(&slash, ":");
			fm[1] = strsep(&slash, ":");
			fm[2] = slash;
			if (!fm[0] || !fm[1] || !fm[2])
				return fail(p, "invalid geneve option mask");
		}

		/* hex values, like tc */
		if (!parse_hexnum(f[0], 0xffff, &v))
			return fail(p, "invalid geneve class '%s'", f[0]);
		g->class = v;
		if (!parse_hexnum(f[1], 0xff, &v))
			return fail(p, "invalid geneve type '%s'", f[1]);
		g->type = v;
		n = parse_hex_bytes(f[2], g->data, ACLX_GENEVE_DATA_MAX);
		if (n < 4 || n % 4)
			return fail(p, "geneve data must be 4 to %d bytes in multiples of 4",
				    ACLX_GENEVE_DATA_MAX);
		g->len = n;

		g->class_m = 0xffff;
		g->type_m = 0xff;
		memset(g->data_m, 0xff, g->len);
		if (fm[0]) {
			if (!parse_hexnum(fm[0], 0xffff, &v))
				return fail(p, "invalid geneve class mask");
			g->class_m = v;
			if (!parse_hexnum(fm[1], 0xff, &v))
				return fail(p, "invalid geneve type mask");
			g->type_m = v;
			if (parse_hex_bytes(fm[2], g->data_m, ACLX_GENEVE_DATA_MAX) != n)
				return fail(p, "geneve data mask must be as long as the data");
		}
	}
	return 0;
}

/* split "a:b:c[/x:y:z]" into fields; returns number of value fields */
static int split_colon(char *s, char **v, char **m, int max)
{
	char *slash = strchr(s, '/');
	int n = 0;

	if (slash)
		*slash++ = '\0';
	for (int i = 0; i < max; i++) {
		v[i] = strsep(&s, ":");
		m[i] = slash ? strsep(&slash, ":") : NULL;
		if (v[i])
			n++;
	}
	if (s)
		return -1;
	return n;
}

static bool hex_or_dec(const char *s, uint64_t max, uint64_t *v, bool hex_default)
{
	char *end;

	if (!s || !*s)
		return false;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		return parse_num(s, max, v);
	if (!hex_default)
		return parse_num(s, max, v);
	errno = 0;
	*v = strtoull(s, &end, 16);
	return !errno && !*end && *v <= max;
}

static int parse_option(struct parser *p, const char *kw);

static bool option_seen(struct parser *p, const char *kw)
{
	for (int i = 0; i < p->nseen; i++)
		if (!strcmp(p->seen[i], kw))
			return true;
	if (p->nseen < MAX_TOKENS) {
		strncpy(p->seen[p->nseen], kw, sizeof(p->seen[0]) - 1);
		p->nseen++;
	}
	return false;
}

static bool l3_is_ip(enum aclx_l3 l3)
{
	return l3 == ACLX_L3_IPV4 || l3 == ACLX_L3_IPV6;
}

static int need_ip(struct parser *p, const char *kw)
{
	if (!l3_is_ip(p->r->l3))
		return fail(p, "%s needs an IP protocol (ip, ipv6, tcp, ...)", kw);
	return 0;
}

static int need_proto(struct parser *p, const char *kw, int proto1, int proto2, int proto3)
{
	struct aclx_rule *r = p->r;

	if (need_ip(p, kw))
		return -1;
	if (!r->ip_proto_set ||
	    (r->ip_proto != proto1 && r->ip_proto != proto2 && r->ip_proto != proto3))
		return fail(p, "%s is not valid for this protocol", kw);
	return 0;
}

static int need_l3(struct parser *p, const char *kw, enum aclx_l3 a, enum aclx_l3 b)
{
	if (p->r->l3 != a && p->r->l3 != b)
		return fail(p, "%s is not valid for this protocol", kw);
	return 0;
}

static int parse_u8_vm(struct parser *p, const char *kw, struct aclx_u8m *f, uint8_t maxv)
{
	const char *t = next_arg(p, kw);
	uint64_t v, m;

	if (!t)
		return -1;
	if (!parse_vm(t, maxv, &v, &m))
		return fail(p, "invalid %s '%s'", kw, t);
	f->set = true;
	f->v = v & m;
	f->m = m;
	return 0;
}

static int parse_option(struct parser *p, const char *kw)
{
	struct aclx_rule *r = p->r;
	const char *t;
	uint64_t v, m;
	uint32_t u;

	if (strcmp(kw, "lse") && option_seen(p, kw))
		return fail(p, "%s given more than once", kw);

	/* --- IP header ------------------------------------------------- */
	if (!strcmp(kw, "dscp")) {
		if (need_ip(p, kw) || !(t = next_arg(p, kw)))
			return -1;
		if (!name_lookup(dscp_names, t, &u)) {
			if (!parse_num(t, 63, &v))
				return fail(p, "invalid dscp '%s'", t);
			u = v;
		}
		r->dscp.set = true;
		r->dscp.v = u;
		r->dscp.m = 0x3f;
		return 0;
	}
	if (!strcmp(kw, "precedence")) {
		if (need_ip(p, kw) || !(t = next_arg(p, kw)))
			return -1;
		if (!name_lookup(precedence_names, t, &u)) {
			if (!parse_num(t, 7, &v))
				return fail(p, "invalid precedence '%s'", t);
			u = v;
		}
		r->precedence.set = true;
		r->precedence.v = u;
		r->precedence.m = 0x7;
		return 0;
	}
	if (!strcmp(kw, "ecn")) {
		if (need_ip(p, kw) || !(t = next_arg(p, kw)))
			return -1;
		if (!name_lookup(ecn_names, t, &u)) {
			if (!parse_num(t, 3, &v))
				return fail(p, "invalid ecn '%s'", t);
			u = v;
		}
		r->ecn.set = true;
		r->ecn.v = u;
		r->ecn.m = 0x3;
		return 0;
	}
	if (!strcmp(kw, "ip-tos")) {
		if (need_ip(p, kw))
			return -1;
		return parse_u8_vm(p, kw, &r->ip_tos, 0xff);
	}
	if (!strcmp(kw, "ttl") || !strcmp(kw, "hop-limit")) {
		if (need_ip(p, kw))
			return -1;
		if (option_seen(p, !strcmp(kw, "ttl") ? "hop-limit" : "ttl"))
			return fail(p, "ttl given more than once");
		if (!is_op(peek(p)))
			return fail(p, "%s needs eq, neq, lt, gt or range", kw);
		return parse_range_op(p, &r->ttl, 255, false, kw);
	}
	if (!strcmp(kw, "fragments")) {
		if (need_ip(p, kw))
			return -1;
		/* Cisco: non-initial fragments */
		if (r->ip_flags.set && ((r->ip_flags.v ^ ACLX_IPF_FRAG) & r->ip_flags.m))
			return fail(p, "fragments conflicts with ip-flags");
		r->ip_flags.set = true;
		r->ip_flags.v = (r->ip_flags.v & ~(ACLX_IPF_FRAG | ACLX_IPF_FIRSTFRAG)) |
				ACLX_IPF_FRAG;
		r->ip_flags.m |= ACLX_IPF_FRAG | ACLX_IPF_FIRSTFRAG;
		return 0;
	}
	if (!strcmp(kw, "ip-flags")) {
		uint32_t fv, fm;

		if (need_ip(p, kw) || !(t = next_arg(p, kw)))
			return -1;
		if (!parse_slash_flags(t, ip_flag_names, &fv, &fm))
			return fail(p, "invalid ip-flags '%s' ([no]frag/[no]firstfrag)", t);
		if (r->ip_flags.set && ((r->ip_flags.v ^ fv) & r->ip_flags.m & fm))
			return fail(p, "ip-flags conflicts with fragments");
		r->ip_flags.set = true;
		r->ip_flags.v = (r->ip_flags.v & ~fm) | fv;
		r->ip_flags.m |= fm;
		return 0;
	}

	/* --- TCP flags ------------------------------------------------- */
	if (name_lookup(tcp_flag_names, kw, &u)) {
		if (need_proto(p, kw, ACLX_IPPROTO_TCP, -1, -1))
			return -1;
		return merge_tcp_flags(p, u, u);
	}
	if (!strcmp(kw, "established")) {
		if (need_proto(p, kw, ACLX_IPPROTO_TCP, -1, -1))
			return -1;
		r->established = true;
		return 0;
	}
	if (!strcmp(kw, "match-all")) {
		uint16_t fv = 0, fm = 0;
		int n = 0;

		if (need_proto(p, kw, ACLX_IPPROTO_TCP, -1, -1))
			return -1;
		while ((t = peek(p)) && (t[0] == '+' || t[0] == '-') &&
		       name_lookup(tcp_flag_names, t + 1, &u)) {
			if (t[0] == '+')
				fv |= u;
			fm |= u;
			p->i++;
			n++;
		}
		if (!n)
			return fail(p, "match-all needs +FLAG or -FLAG arguments");
		return merge_tcp_flags(p, fv, fm);
	}
	if (!strcmp(kw, "tcp-flags")) {
		if (need_proto(p, kw, ACLX_IPPROTO_TCP, -1, -1) || !(t = next_arg(p, kw)))
			return -1;
		if (!parse_vm(t, 0xfff, &v, &m))
			return fail(p, "invalid tcp-flags '%s'", t);
		if (!m)
			return fail(p, "tcp-flags mask 0 matches every packet");
		return merge_tcp_flags(p, v & m, m);
	}

	/* --- ICMP, SPI, L2TPv3 ----------------------------------------- */
	if (!strcmp(kw, "icmp-type") || !strcmp(kw, "icmp-code")) {
		if (need_proto(p, kw, ACLX_IPPROTO_ICMP, ACLX_IPPROTO_ICMPV6, -1))
			return -1;
		return parse_u8_vm(p, kw, kw[5] == 't' ? &r->icmp_type : &r->icmp_code, 0xff);
	}
	if (!strcmp(kw, "spi")) {
		if (need_proto(p, kw, ACLX_IPPROTO_ESP, ACLX_IPPROTO_AH, -1) ||
		    !(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, 0xffffffff, &v))
			return fail(p, "invalid spi '%s'", t);
		r->spi.set = true;
		r->spi.v = v;
		r->spi.m = 0xffffffff;
		return 0;
	}
	if (!strcmp(kw, "l2tpv3-sid")) {
		if (need_proto(p, kw, ACLX_IPPROTO_L2TP, -1, -1) || !(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, 0xffffffff, &v))
			return fail(p, "invalid l2tpv3-sid '%s'", t);
		r->l2tpv3_sid.set = true;
		r->l2tpv3_sid.v = v;
		r->l2tpv3_sid.m = 0xffffffff;
		return 0;
	}

	/* --- Ethernet, VLAN -------------------------------------------- */
	if (!strcmp(kw, "src-mac") || !strcmp(kw, "dst-mac")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_mac_masked(t, kw[0] == 's' ? &r->smac : &r->dmac))
			return fail(p, "invalid %s '%s'", kw, t);
		return 0;
	}
	if (!strcmp(kw, "vlan-id") || !strcmp(kw, "cvlan-id")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, 4095, &v))
			return fail(p, "invalid %s '%s' (0-4095)", kw, t);
		if (kw[0] == 'c') {
			r->cvlan_id_set = true;
			r->cvlan_id = v;
		} else {
			r->vlan_id_set = true;
			r->vlan_id = v;
		}
		return 0;
	}
	if (!strcmp(kw, "vlan-prio") || !strcmp(kw, "cvlan-prio")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, 7, &v))
			return fail(p, "invalid %s '%s' (0-7)", kw, t);
		if (kw[0] == 'c') {
			r->cvlan_prio_set = true;
			r->cvlan_prio = v;
		} else {
			r->vlan_prio_set = true;
			r->vlan_prio = v;
		}
		return 0;
	}
	if (!strcmp(kw, "vlan-tpid")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!strcmp(t, "802.1q"))
			r->vlan_tpid = ACLX_ETH_P_8021Q;
		else if (!strcmp(t, "802.1ad"))
			r->vlan_tpid = ACLX_ETH_P_8021AD;
		else
			return fail(p, "invalid vlan-tpid '%s' (802.1q or 802.1ad)", t);
		return 0;
	}
	if (!strcmp(kw, "num-of-vlans")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, 255, &v))
			return fail(p, "invalid num-of-vlans '%s'", t);
		r->num_of_vlans.set = true;
		r->num_of_vlans.v = v;
		return 0;
	}

	/* --- MPLS ------------------------------------------------------ */
	if (!strcmp(kw, "mpls-label") || !strcmp(kw, "mpls-tc") || !strcmp(kw, "mpls-bos") ||
	    !strcmp(kw, "mpls-ttl")) {
		if (need_l3(p, kw, ACLX_L3_MPLS, ACLX_L3_MPLS_MC) || !(t = next_arg(p, kw)))
			return -1;
		if (r->lse[0].depth)
			return fail(p, "%s cannot be combined with lse", kw);
		switch (kw[5]) {
		case 'l':
			if (!parse_num(t, 0xfffff, &v))
				return fail(p, "invalid mpls-label '%s'", t);
			r->mpls_label_set = true;
			r->mpls_label = v;
			break;
		case 't':
			if (kw[6] == 'c') {
				if (!parse_num(t, 7, &v))
					return fail(p, "invalid mpls-tc '%s'", t);
				r->mpls_tc_set = true;
				r->mpls_tc = v;
			} else {
				if (!parse_num(t, 255, &v))
					return fail(p, "invalid mpls-ttl '%s'", t);
				r->mpls_ttl_set = true;
				r->mpls_ttl = v;
			}
			break;
		default:
			if (!parse_num(t, 1, &v))
				return fail(p, "invalid mpls-bos '%s'", t);
			r->mpls_bos_set = true;
			r->mpls_bos = v;
			break;
		}
		return 0;
	}
	if (!strcmp(kw, "lse")) {
		struct aclx_lse *l;
		int k;

		if (need_l3(p, kw, ACLX_L3_MPLS, ACLX_L3_MPLS_MC))
			return -1;
		if (r->mpls_label_set || r->mpls_tc_set || r->mpls_bos_set || r->mpls_ttl_set)
			return fail(p, "lse cannot be combined with mpls-label/tc/bos/ttl");
		for (k = 0; k < ACLX_MAX_LSE && r->lse[k].depth; k++)
			;
		if (k == ACLX_MAX_LSE)
			return fail(p, "at most %d lse", ACLX_MAX_LSE);
		l = &r->lse[k];
		t = next_arg(p, "lse");
		if (!t || strcmp(t, "depth"))
			return fail(p,
				    "lse needs depth (lse depth N [label L] [tc T] [bos B] [ttl T])");
		t = next_arg(p, "depth");
		if (!t || !parse_num(t, ACLX_MAX_LSE, &v) || !v)
			return fail(p, "invalid lse depth (1-%d)", ACLX_MAX_LSE);
		for (int j = 0; j < k; j++)
			if (r->lse[j].depth == v)
				return fail(p, "lse depth %u given twice", (unsigned int)v);
		l->depth = v;
		while ((t = peek(p))) {
			if (!strcmp(t, "label")) {
				p->i++;
				t = next_arg(p, "label");
				if (!t || !parse_num(t, 0xfffff, &v))
					return fail(p, "invalid lse label");
				l->label_set = true;
				l->label = v;
			} else if (!strcmp(t, "tc")) {
				p->i++;
				t = next_arg(p, "tc");
				if (!t || !parse_num(t, 7, &v))
					return fail(p, "invalid lse tc");
				l->tc_set = true;
				l->tc = v;
			} else if (!strcmp(t, "bos")) {
				p->i++;
				t = next_arg(p, "bos");
				if (!t || !parse_num(t, 1, &v))
					return fail(p, "invalid lse bos");
				l->bos_set = true;
				l->bos = v;
			} else if (!strcmp(t, "ttl")) {
				p->i++;
				t = next_arg(p, "ttl");
				if (!t || !parse_num(t, 255, &v))
					return fail(p, "invalid lse ttl");
				l->ttl_set = true;
				l->ttl = v;
			} else {
				break;
			}
		}
		return 0;
	}

	/* --- PPPoE ----------------------------------------------------- */
	if (!strcmp(kw, "pppoe-sid")) {
		if (need_l3(p, kw, ACLX_L3_PPPOE, ACLX_L3_PPPOE) || !(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, 0xffff, &v))
			return fail(p, "invalid pppoe-sid '%s'", t);
		r->pppoe_sid.set = true;
		r->pppoe_sid.v = v;
		return 0;
	}
	if (!strcmp(kw, "ppp-proto")) {
		if (need_l3(p, kw, ACLX_L3_PPPOE, ACLX_L3_PPPOE) || !(t = next_arg(p, kw)))
			return -1;
		if (!name_lookup(ppp_proto_names, t, &u)) {
			if (!parse_num(t, 0xffff, &v))
				return fail(p, "invalid ppp-proto '%s'", t);
			u = v;
		}
		r->ppp_proto.set = true;
		r->ppp_proto.v = u;
		return 0;
	}

	/* --- ARP ------------------------------------------------------- */
	if (!strcmp(kw, "arp-op")) {
		char buf[32];
		char *slash;

		if (need_l3(p, kw, ACLX_L3_ARP, ACLX_L3_RARP) || !(t = next_arg(p, kw)))
			return -1;
		if (strlen(t) >= sizeof(buf))
			return fail(p, "invalid arp-op");
		strcpy(buf, t);
		slash = strchr(buf, '/');
		if (slash)
			*slash++ = '\0';
		if (!strcmp(buf, "request"))
			v = 1;
		else if (!strcmp(buf, "reply"))
			v = 2;
		else if (!parse_num(buf, 2, &v))
			return fail(p, "invalid arp-op '%s' (request, reply, 0, 1 or 2)", buf);
		m = 0xff;
		if (slash && !parse_num(slash, 0xff, &m))
			return fail(p, "invalid arp-op mask");
		r->arpop.set = true;
		r->arpop.v = v & m;
		r->arpop.m = m;
		return 0;
	}
	if (!strcmp(kw, "arp-sip") || !strcmp(kw, "arp-tip")) {
		if (need_l3(p, kw, ACLX_L3_ARP, ACLX_L3_RARP) || !(t = next_arg(p, kw)))
			return -1;
		if (!parse_prefix(t, kw[4] == 's' ? &r->arp_sip : &r->arp_tip, AF_INET))
			return fail(p, "invalid %s '%s' (IPv4 prefix)", kw, t);
		return 0;
	}
	if (!strcmp(kw, "arp-sha") || !strcmp(kw, "arp-tha")) {
		if (need_l3(p, kw, ACLX_L3_ARP, ACLX_L3_RARP) || !(t = next_arg(p, kw)))
			return -1;
		if (!parse_mac_masked(t, kw[4] == 's' ? &r->arp_sha : &r->arp_tha))
			return fail(p, "invalid %s '%s'", kw, t);
		return 0;
	}

	/* --- CFM ------------------------------------------------------- */
	if (!strcmp(kw, "cfm-mdl") || !strcmp(kw, "cfm-op")) {
		bool mdl = kw[4] == 'm';

		if (need_l3(p, kw, ACLX_L3_CFM, ACLX_L3_CFM) || !(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, mdl ? 7 : 255, &v))
			return fail(p, "invalid %s '%s'", kw, t);
		if (mdl) {
			r->cfm_mdl.set = true;
			r->cfm_mdl.v = v;
		} else {
			r->cfm_op.set = true;
			r->cfm_op.v = v;
		}
		return 0;
	}

	/* --- Tunnel metadata ------------------------------------------- */
	if (!strcmp(kw, "enc-key-id")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, 0xffffffff, &v))
			return fail(p, "invalid enc-key-id '%s'", t);
		r->enc_key_id.set = true;
		r->enc_key_id.v = v;
		return 0;
	}
	if (!strcmp(kw, "enc-src-ip") || !strcmp(kw, "enc-dst-ip")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_prefix(t, kw[4] == 's' ? &r->enc_src : &r->enc_dst, 0))
			return fail(p, "invalid %s '%s'", kw, t);
		return 0;
	}
	if (!strcmp(kw, "enc-dst-port")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, 65535, &v))
			return fail(p, "invalid enc-dst-port '%s'", t);
		r->enc_dst_port.set = true;
		r->enc_dst_port.v = v;
		return 0;
	}
	if (!strcmp(kw, "enc-tos"))
		return parse_u8_vm(p, kw, &r->enc_tos, 0xff);
	if (!strcmp(kw, "enc-ttl"))
		return parse_u8_vm(p, kw, &r->enc_ttl, 0xff);
	if (!strcmp(kw, "enc-flags")) {
		uint32_t fv, fm;

		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_slash_flags(t, enc_flag_names, &fv, &fm))
			return fail(p,
				    "invalid enc-flags '%s' ([no]tuncsum/[no]tundf/[no]tunoam/[no]tuncrit)",
				    t);
		r->enc_flags.set = true;
		r->enc_flags.v = fv;
		r->enc_flags.m = fm;
		return 0;
	}
	if (!strcmp(kw, "geneve-opts") || !strcmp(kw, "vxlan-opts") ||
	    !strcmp(kw, "erspan-opts") || !strcmp(kw, "gtp-opts") || !strcmp(kw, "pfcp-opts")) {
		int kinds = !!r->n_geneve + r->vxlan_gbp.set + r->erspan_set + r->gtp_set +
			    r->pfcp_set;
		char buf[256], *f[4], *fm[4];

		if (kinds)
			return fail(p, "only one kind of tunnel options can be matched");
		if (!(t = next_arg(p, kw)))
			return -1;
		if (kw[0] == 'g' && kw[1] == 'e')
			return parse_geneve(p, t);
		if (strlen(t) >= sizeof(buf))
			return fail(p, "%s too long", kw);
		strcpy(buf, t);

		if (kw[0] == 'v') {
			char *slash = strchr(buf, '/');

			if (slash)
				*slash++ = '\0';
			if (!parse_num(buf, 0xffffffff, &v))
				return fail(p, "invalid vxlan-opts '%s' (GBP[/MASK])", t);
			m = 0xffffffff;
			if (slash && !parse_num(slash, 0xffffffff, &m))
				return fail(p, "invalid vxlan-opts mask");
			r->vxlan_gbp.set = true;
			r->vxlan_gbp.v = v;
			r->vxlan_gbp.m = m;
			return 0;
		}
		if (kw[0] == 'e') {
			/* VERSION:INDEX:DIR:HWID[/VERSION:INDEX:DIR:HWID] */
			if (split_colon(buf, f, fm, 4) != 4 || !hex_or_dec(f[0], 2, &v, false) ||
			    v < 1)
				return fail(p, "invalid erspan-opts '%s' (VERSION:INDEX:DIR:HWID)",
					    t);
			r->erspan_set = true;
			r->erspan_ver = v;
			r->erspan_ver_m = fm[0] && *fm[0] && hex_or_dec(fm[0], 0xff, &m, false)
						  ? (uint8_t)m
						  : (uint8_t)v;
			if (v == 1) {
				if (!hex_or_dec(f[1], 0xffffffff, &v, false) || *f[2] || *f[3])
					return fail(p, "erspan version 1 takes 1:INDEX::");
				r->erspan_index = v;
				r->erspan_index_m = 0xffffffff;
				if (fm[1] && *fm[1]) {
					if (!hex_or_dec(fm[1], 0xffffffff, &m, false))
						return fail(p, "invalid erspan index mask");
					r->erspan_index_m = m;
				}
			} else {
				if (*f[1] || !hex_or_dec(f[2], 1, &v, false))
					return fail(p, "erspan version 2 takes 2::DIR:HWID");
				r->erspan_dir = v;
				if (!hex_or_dec(f[3], 0x3f, &v, false))
					return fail(p, "invalid erspan hwid");
				r->erspan_hwid = v;
				r->erspan_dir_m = r->erspan_hwid_m = 0xff;
				if (fm[2] && *fm[2]) {
					if (!hex_or_dec(fm[2], 0xff, &m, false))
						return fail(p, "invalid erspan dir mask");
					r->erspan_dir_m = m;
				}
				if (fm[3] && *fm[3]) {
					if (!hex_or_dec(fm[3], 0xff, &m, false))
						return fail(p, "invalid erspan hwid mask");
					r->erspan_hwid_m = m;
				}
			}
			return 0;
		}
		if (kw[0] == 'g') {
			/* PDU_TYPE:QFI[/PDU_TYPE_MASK:QFI_MASK], hex */
			if (split_colon(buf, f, fm, 2) != 2 || !hex_or_dec(f[0], 0xff, &v, true))
				return fail(p, "invalid gtp-opts '%s' (PDU_TYPE:QFI)", t);
			r->gtp_set = true;
			r->gtp_pdu = v;
			if (!hex_or_dec(f[1], 0xff, &v, true))
				return fail(p, "invalid gtp-opts qfi");
			r->gtp_qfi = v;
			r->gtp_pdu_m = r->gtp_qfi_m = 0xff;
			if (fm[0] && (!hex_or_dec(fm[0], 0xff, &m, true) || !fm[1]))
				return fail(p, "invalid gtp-opts mask");
			if (fm[0])
				r->gtp_pdu_m = m;
			if (fm[1]) {
				if (!hex_or_dec(fm[1], 0xff, &m, true))
					return fail(p, "invalid gtp-opts mask");
				r->gtp_qfi_m = m;
			}
			return 0;
		}
		/* pfcp: TYPE:SEID[/TYPE_MASK:SEID_MASK], hex */
		if (split_colon(buf, f, fm, 2) != 2 || !hex_or_dec(f[0], 0xff, &v, true))
			return fail(p, "invalid pfcp-opts '%s' (TYPE:SEID)", t);
		r->pfcp_set = true;
		r->pfcp_type = v;
		if (!hex_or_dec(f[1], UINT64_MAX, &v, true))
			return fail(p, "invalid pfcp-opts seid");
		r->pfcp_seid = v;
		r->pfcp_type_m = 0xff;
		r->pfcp_seid_m = UINT64_MAX;
		if (fm[0]) {
			if (!hex_or_dec(fm[0], 0xff, &m, true) || !fm[1] ||
			    !hex_or_dec(fm[1], UINT64_MAX, &v, true))
				return fail(p, "invalid pfcp-opts mask");
			r->pfcp_type_m = m;
			r->pfcp_seid_m = v;
		}
		return 0;
	}

	/* --- Connection tracking --------------------------------------- */
	if (!strcmp(kw, "ct-state")) {
		uint16_t fv, fm;

		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_plus_minus(t, ct_state_names, &fv, &fm))
			return fail(p, "invalid ct-state '%s' (e.g. +trk+est)", t);
		r->ct_state.set = true;
		r->ct_state.v = fv;
		r->ct_state.m = fm;
		return 0;
	}
	if (!strcmp(kw, "ct-zone")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_vm(t, 0xffff, &v, &m))
			return fail(p, "invalid ct-zone '%s'", t);
		r->ct_zone.set = true;
		r->ct_zone.v = v & m;
		r->ct_zone.m = m;
		return 0;
	}
	if (!strcmp(kw, "ct-mark")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_vm(t, 0xffffffff, &v, &m))
			return fail(p, "invalid ct-mark '%s'", t);
		r->ct_mark.set = true;
		r->ct_mark.v = v & m;
		r->ct_mark.m = m;
		return 0;
	}
	if (!strcmp(kw, "ct-label")) {
		char buf[80];
		char *slash;

		if (!(t = next_arg(p, kw)))
			return -1;
		if (strlen(t) >= sizeof(buf))
			return fail(p, "invalid ct-label");
		strcpy(buf, t);
		slash = strchr(buf, '/');
		if (slash)
			*slash++ = '\0';
		memset(r->ct_label, 0, 16);
		memset(r->ct_label_m, 0xff, 16);
		if (parse_hex_bytes(buf, r->ct_label, 16) != 16)
			return fail(p, "ct-label must be 32 hex digits");
		if (slash && parse_hex_bytes(slash, r->ct_label_m, 16) != 16)
			return fail(p, "ct-label mask must be 32 hex digits");
		for (int i = 0; i < 16; i++)
			r->ct_label[i] &= r->ct_label_m[i];
		r->ct_label_set = true;
		return 0;
	}

	/* --- Others ---------------------------------------------------- */
	if (!strcmp(kw, "indev")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (strlen(t) >= ACLX_IFNAME_LEN || strchr(t, '/'))
			return fail(p, "invalid indev '%s'", t);
		strcpy(r->indev, t);
		return 0;
	}
	if (!strcmp(kw, "l2-miss")) {
		if (!(t = next_arg(p, kw)))
			return -1;
		if (!parse_num(t, 1, &v))
			return fail(p, "invalid l2-miss '%s' (0 or 1)", t);
		r->l2_miss.set = true;
		r->l2_miss.v = v;
		return 0;
	}

	if (!strcmp(kw, "log") || !strcmp(kw, "log-input") || !strcmp(kw, "time-range"))
		return fail(p, "%s is not supported", kw);

	return fail(p, "unknown keyword '%s'", kw);
}

/* protocol keyword, sets l3 / ip_proto / ethertype */
static int parse_protocol(struct parser *p)
{
	struct aclx_rule *r = p->r;
	const char *t = next_arg(p, "protocol");
	uint32_t u;
	uint64_t v;

	if (!t)
		return fail(p, "missing protocol");

	if (!strcmp(t, "ip")) {
		r->l3 = ACLX_L3_IPV4;
	} else if (!strcmp(t, "ipv6")) {
		r->l3 = ACLX_L3_IPV6;
	} else if (!strcmp(t, "arp")) {
		r->l3 = ACLX_L3_ARP;
	} else if (!strcmp(t, "rarp")) {
		r->l3 = ACLX_L3_RARP;
	} else if (!strcmp(t, "mpls")) {
		r->l3 = ACLX_L3_MPLS;
	} else if (!strcmp(t, "mpls-multicast")) {
		r->l3 = ACLX_L3_MPLS_MC;
	} else if (!strcmp(t, "pppoe")) {
		r->l3 = ACLX_L3_PPPOE;
	} else if (!strcmp(t, "cfm")) {
		r->l3 = ACLX_L3_CFM;
	} else if (!strcmp(t, "ethertype")) {
		t = next_arg(p, "ethertype");
		if (!t)
			return -1;
		if (!strcmp(t, "any")) {
			r->l3 = ACLX_L3_ANY;
		} else {
			if (!name_lookup(ethertype_names, t, &u)) {
				if (!parse_num(t, 0xffff, &v) || v < 0x0600)
					return fail(p,
						    "invalid ethertype '%s' (any, a name or 0x0600-0xffff)",
						    t);
				u = v;
			}
			/* well known ethertypes use their own protocol keyword */
			switch (u) {
			case ACLX_ETH_P_IP:
				r->l3 = ACLX_L3_IPV4;
				break;
			case ACLX_ETH_P_IPV6:
				r->l3 = ACLX_L3_IPV6;
				break;
			case ACLX_ETH_P_ARP:
				r->l3 = ACLX_L3_ARP;
				break;
			case ACLX_ETH_P_RARP:
				r->l3 = ACLX_L3_RARP;
				break;
			case ACLX_ETH_P_MPLS_UC:
				r->l3 = ACLX_L3_MPLS;
				break;
			case ACLX_ETH_P_MPLS_MC:
				r->l3 = ACLX_L3_MPLS_MC;
				break;
			case ACLX_ETH_P_PPP_SES:
				r->l3 = ACLX_L3_PPPOE;
				break;
			case ACLX_ETH_P_CFM:
				r->l3 = ACLX_L3_CFM;
				break;
			case ACLX_ETH_P_8021Q:
			case ACLX_ETH_P_8021AD:
				return fail(p,
					    "use vlan-id/vlan-prio/vlan-tpid to match VLAN tags");
			default:
				r->l3 = ACLX_L3_ETHERTYPE;
				r->ethertype = u;
			}
			if (l3_is_ip(r->l3))
				return fail(p, "use the ip or ipv6 protocol keyword for IP");
		}
	} else {
		if (!name_lookup(ip_protocols, t, &u) && !name_lookup(ip_protocol_aliases, t, &u)) {
			if (!parse_num(t, 255, &v))
				return fail(p, "unknown protocol '%s'", t);
			u = v;
		}
		r->ip_proto_set = true;
		r->ip_proto = u;
		r->l3 = u == ACLX_IPPROTO_ICMPV6 ? ACLX_L3_IPV6 : ACLX_L3_IPV4;
	}
	return 0;
}

static bool proto_has_ports(const struct aclx_rule *r)
{
	return r->ip_proto_set &&
	       (r->ip_proto == ACLX_IPPROTO_TCP || r->ip_proto == ACLX_IPPROTO_UDP ||
		r->ip_proto == ACLX_IPPROTO_SCTP);
}

static bool proto_is_icmp(const struct aclx_rule *r)
{
	return r->ip_proto_set &&
	       (r->ip_proto == ACLX_IPPROTO_ICMP || r->ip_proto == ACLX_IPPROTO_ICMPV6);
}

/* "echo", "8", "3 1" after the destination of an icmp entry */
static int parse_icmp_positional(struct parser *p)
{
	struct aclx_rule *r = p->r;
	const struct icmp_msg *msgs = r->ip_proto == ACLX_IPPROTO_ICMP ? icmp4_msgs : icmp6_msgs;
	const char *t = peek(p);
	uint64_t v;

	if (!t)
		return 0;

	for (const struct icmp_msg *m = msgs; m->name; m++) {
		if (strcmp(m->name, t))
			continue;
		p->i++;
		r->icmp_type.set = true;
		r->icmp_type.v = m->type;
		r->icmp_type.m = 0xff;
		if (m->code >= 0) {
			r->icmp_code.set = true;
			r->icmp_code.v = m->code;
			r->icmp_code.m = 0xff;
		}
		option_seen(p, "icmp-type");
		if (m->code >= 0)
			option_seen(p, "icmp-code");
		return 0;
	}

	if (!parse_num(t, 255, &v))
		return 0;
	p->i++;
	r->icmp_type.set = true;
	r->icmp_type.v = v;
	r->icmp_type.m = 0xff;
	option_seen(p, "icmp-type");
	t = peek(p);
	if (t && parse_num(t, 255, &v)) {
		p->i++;
		r->icmp_code.set = true;
		r->icmp_code.v = v;
		r->icmp_code.m = 0xff;
		option_seen(p, "icmp-code");
	}
	return 0;
}

/* the address family of an IP entry, from the protocol and the addresses */
static int resolve_family(struct parser *p)
{
	struct aclx_rule *r = p->r;
	int fam = 0;
	struct aclx_addr *addrs[] = { &r->src, &r->dst };
	bool v6_keyword = (!r->ip_proto_set && r->l3 == ACLX_L3_IPV6) ||
			  (r->ip_proto_set && r->ip_proto == ACLX_IPPROTO_ICMPV6);
	bool v4_keyword = (!r->ip_proto_set && r->l3 == ACLX_L3_IPV4) ||
			  (r->ip_proto_set && r->ip_proto == ACLX_IPPROTO_ICMP);

	for (int i = 0; i < 2; i++) {
		if (!addrs[i]->set)
			continue;
		if (fam && fam != addrs[i]->family)
			return fail(p, "source and destination must be of the same address family");
		fam = addrs[i]->family;
	}

	if (fam == AF_INET6 && v4_keyword)
		return fail(p,
			    "IPv6 addresses cannot be used with this protocol (use ipv6 or icmpv6)");
	if (fam == AF_INET && v6_keyword)
		return fail(p, "IPv4 addresses cannot be used with this protocol");

	if (fam == AF_INET6)
		r->l3 = ACLX_L3_IPV6;
	else if (fam == AF_INET)
		r->l3 = ACLX_L3_IPV4;

	/* ::/0 and 0.0.0.0/0 only select the family */
	for (int i = 0; i < 2; i++)
		if (addrs[i]->set && mask_is_zero(addrs[i]->m, 16))
			memset(addrs[i], 0, sizeof(*addrs[i]));

	return 0;
}

static int check_rule(struct parser *p)
{
	struct aclx_rule *r = p->r;
	uint8_t v, m;

	if ((r->cvlan_id_set || r->cvlan_prio_set) && r->vlan_tpid == ACLX_ETH_P_8021Q)
		return fail(p, "cvlan-id/cvlan-prio need an 802.1ad outer tag");
	if (r->vlan_tpid &&
	    !(r->vlan_id_set || r->vlan_prio_set || r->cvlan_id_set || r->cvlan_prio_set))
		return fail(p, "vlan-tpid needs vlan-id, vlan-prio, cvlan-id or cvlan-prio");
	if (l3_is_ip(r->l3) && !aclx_rule_tos(r, &v, &m))
		return fail(p, "dscp, precedence, ecn and ip-tos conflict");
	if (r->ct_state.set) {
		/* the checks of the kernel (fl_validate_ct_state) */
		uint16_t st = r->ct_state.v;

		if (st && !(st & ACLX_CT_TRK))
			return fail(p, "ct-state flags other than -trk need +trk");
		if ((st & ACLX_CT_NEW) && (st & ACLX_CT_EST))
			return fail(p, "ct-state +new and +est are mutually exclusive");
		if ((st & ACLX_CT_NEW) && (st & ACLX_CT_RPL))
			return fail(p, "ct-state +new and +rpl are mutually exclusive");
		if ((st & ACLX_CT_INV) && (st & ~(ACLX_CT_TRK | ACLX_CT_INV)))
			return fail(p, "ct-state +inv can only be combined with +trk");
	}
	if (r->established && r->tcp_flags.set &&
	    (r->tcp_flags.m & (ACLX_TCP_ACK | ACLX_TCP_RST)) == (ACLX_TCP_ACK | ACLX_TCP_RST) &&
	    !(r->tcp_flags.v & (ACLX_TCP_ACK | ACLX_TCP_RST)))
		return fail(p, "established conflicts with the TCP flags");
	return 0;
}

int aclx_rule_parse(const char *text, struct aclx_rule *rule, char *err, size_t errlen)
{
	struct parser p = { .err = err, .errlen = errlen, .r = rule };
	char *buf, *save = NULL, *tok;
	int ret = -1;

	memset(rule, 0, sizeof(*rule));
	err[0] = '\0';

	if (strlen(text) >= ACLX_TEXT_MAX)
		return fail(&p, "entry too long");
	buf = strdup(text);
	if (!buf)
		return fail(&p, "out of memory");

	for (tok = strtok_r(buf, " \t\r\n", &save); tok; tok = strtok_r(NULL, " \t\r\n", &save)) {
		if (p.n == MAX_TOKENS) {
			fail(&p, "entry too long");
			goto out;
		}
		p.tok[p.n++] = tok;
	}

	if (parse_protocol(&p))
		goto out;

	if (l3_is_ip(rule->l3)) {
		if (parse_addr(&p, "source", &rule->src))
			goto out;
		if (is_op(peek(&p))) {
			if (!proto_has_ports(rule)) {
				fail(&p, "ports need tcp, udp or sctp");
				goto out;
			}
			if (parse_range_op(&p, &rule->sport, 65535, true, "source port"))
				goto out;
		}
		if (!peek(&p)) {
			fail(&p, "missing destination address");
			goto out;
		}
		if (parse_addr(&p, "destination", &rule->dst))
			goto out;
		if (is_op(peek(&p))) {
			if (!proto_has_ports(rule)) {
				fail(&p, "ports need tcp, udp or sctp");
				goto out;
			}
			if (parse_range_op(&p, &rule->dport, 65535, true, "destination port"))
				goto out;
		}
		if (resolve_family(&p))
			goto out;
		if (proto_is_icmp(rule) && parse_icmp_positional(&p))
			goto out;
	}

	while (p.i < p.n) {
		const char *kw = p.tok[p.i++];

		if (parse_option(&p, kw))
			goto out;
	}

	if (check_rule(&p))
		goto out;

	ret = 0;
out:
	free(buf);
	return ret;
}

/*
 * ----------------------------------------------------------------------
 * Helpers used by the encoder
 * ----------------------------------------------------------------------
 */

bool aclx_rule_tos(const struct aclx_rule *r, uint8_t *v, uint8_t *m)
{
	struct {
		const struct aclx_u8m *f;
		int shift;
	} parts[] = {
		{ &r->dscp, 2 },
		{ &r->precedence, 5 },
		{ &r->ecn, 0 },
		{ &r->ip_tos, 0 },
	};

	*v = *m = 0;
	for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
		uint8_t pv, pm;

		if (!parts[i].f->set)
			continue;
		pv = parts[i].f->v << parts[i].shift;
		pm = parts[i].f->m << parts[i].shift;
		if ((*v ^ pv) & *m & pm)
			return false;
		*v = (*v & ~pm) | (pv & pm);
		*m |= pm;
	}
	return true;
}

bool aclx_rule_is_ip(const struct aclx_rule *r)
{
	return l3_is_ip(r->l3);
}

static uint16_t l3_ethertype(const struct aclx_rule *r)
{
	switch (r->l3) {
	case ACLX_L3_IPV4:
		return ACLX_ETH_P_IP;
	case ACLX_L3_IPV6:
		return ACLX_ETH_P_IPV6;
	case ACLX_L3_ARP:
		return ACLX_ETH_P_ARP;
	case ACLX_L3_RARP:
		return ACLX_ETH_P_RARP;
	case ACLX_L3_MPLS:
		return ACLX_ETH_P_MPLS_UC;
	case ACLX_L3_MPLS_MC:
		return ACLX_ETH_P_MPLS_MC;
	case ACLX_L3_PPPOE:
		return ACLX_ETH_P_PPP_SES;
	case ACLX_L3_CFM:
		return ACLX_ETH_P_CFM;
	case ACLX_L3_ETHERTYPE:
		return r->ethertype;
	case ACLX_L3_ANY:
		return ACLX_ETH_P_ALL;
	}
	return ACLX_ETH_P_ALL;
}

uint16_t aclx_rule_inner_ethertype(const struct aclx_rule *r)
{
	return l3_ethertype(r);
}

bool aclx_rule_has_vlan(const struct aclx_rule *r)
{
	return r->vlan_id_set || r->vlan_prio_set || r->cvlan_id_set || r->cvlan_prio_set;
}

bool aclx_rule_has_cvlan(const struct aclx_rule *r)
{
	return r->cvlan_id_set || r->cvlan_prio_set;
}

uint16_t aclx_rule_eth_proto(const struct aclx_rule *r)
{
	if (aclx_rule_has_vlan(r)) {
		if (r->vlan_tpid)
			return r->vlan_tpid;
		return aclx_rule_has_cvlan(r) ? ACLX_ETH_P_8021AD : ACLX_ETH_P_8021Q;
	}
	return l3_ethertype(r);
}

/*
 * ----------------------------------------------------------------------
 * Printer
 * ----------------------------------------------------------------------
 */

struct out {
	char *buf;
	size_t len, pos;
	/* the text did not fit */
	bool truncated;
};

/* Append a space separated item; buf stays NUL terminated */
static void put(struct out *o, const char *fmt, ...)
{
	va_list ap;
	size_t start = o->pos;
	int n;

	if (o->truncated)
		return;
	if (start) {
		if (start + 1 >= o->len)
			goto truncated;
		o->buf[start++] = ' ';
	}
	va_start(ap, fmt);
	n = vsnprintf(o->buf + start, o->len - start, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= o->len - start)
		goto truncated;
	o->pos = start + n;
	return;

truncated:
	o->truncated = true;
	o->buf[o->pos] = '\0';
}

static void put_addr(struct out *o, const struct aclx_addr *a, bool show_family_any, int family)
{
	char s[INET6_ADDRSTRLEN], w[INET6_ADDRSTRLEN];
	uint8_t wild[16];
	int len, plen;

	if (!a->set) {
		put(o, show_family_any ? (family == AF_INET6 ? "::/0" : "0.0.0.0/0") : "any");
		return;
	}
	len = family_len(a->family);
	inet_ntop(a->family, a->v, s, sizeof(s));
	if (mask_is_full(a->m, len)) {
		put(o, "host %s", s);
		return;
	}
	plen = mask_plen(a->m, len);
	if (a->family == AF_INET6 && plen >= 0) {
		put(o, "%s/%d", s, plen);
		return;
	}
	for (int i = 0; i < len; i++)
		wild[i] = ~a->m[i];
	inet_ntop(a->family, wild, w, sizeof(w));
	put(o, "%s %s", s, w);
}

static void put_prefix(struct out *o, const char *kw, const struct aclx_addr *a)
{
	char s[INET6_ADDRSTRLEN], w[INET6_ADDRSTRLEN];
	int plen = mask_plen(a->m, family_len(a->family));

	inet_ntop(a->family, a->v, s, sizeof(s));
	if (plen == family_len(a->family) * 8) {
		put(o, "%s %s", kw, s);
	} else if (plen >= 0) {
		put(o, "%s %s/%d", kw, s, plen);
	} else {
		/* non-contiguous: only from a positional address, keep ADDR/PLEN */
		inet_ntop(a->family, a->m, w, sizeof(w));
		put(o, "%s %s/%d", kw, s, mask_plen(a->m, family_len(a->family)));
	}
}

static void put_mac(struct out *o, const char *kw, const struct aclx_mac *m)
{
	const uint8_t *v = m->v, *k = m->m;

	if (mask_is_full(k, 6))
		put(o, "%s %02x:%02x:%02x:%02x:%02x:%02x", kw, v[0], v[1], v[2], v[3], v[4], v[5]);
	else
		put(o, "%s %02x:%02x:%02x:%02x:%02x:%02x/%02x:%02x:%02x:%02x:%02x:%02x", kw, v[0],
		    v[1], v[2], v[3], v[4], v[5], k[0], k[1], k[2], k[3], k[4], k[5]);
}

static void put_port_value(struct out *o, uint32_t port)
{
	put(o, "%u", port);
}

static void put_range(struct out *o, const struct aclx_range *r, uint32_t full)
{
	switch (r->op) {
	case ACLX_OP_NONE:
		return;
	case ACLX_OP_EQ:
		if (r->mask != full)
			put(o, "eq %u/0x%x", r->lo, r->mask);
		else
			put(o, "eq %u", r->lo);
		return;
	case ACLX_OP_NEQ:
		put(o, "neq");
		break;
	case ACLX_OP_LT:
		put(o, "lt");
		break;
	case ACLX_OP_GT:
		put(o, "gt");
		break;
	case ACLX_OP_RANGE:
		put(o, "range %u %u", r->lo, r->hi);
		return;
	}
	put_port_value(o, r->lo);
}

static void put_u8m(struct out *o, const char *kw, const struct aclx_u8m *f)
{
	if (!f->set)
		return;
	if (f->m == 0xff)
		put(o, "%s %u", kw, f->v);
	else
		put(o, "%s %u/0x%x", kw, f->v, f->m);
}

static void put_u8x(struct out *o, const char *kw, const struct aclx_u8m *f)
{
	if (!f->set)
		return;
	if (f->m == 0xff)
		put(o, "%s 0x%02x", kw, f->v);
	else
		put(o, "%s 0x%02x/0x%02x", kw, f->v, f->m);
}

static void put_flags(struct out *o, const char *kw, const struct name_value *names, uint32_t v,
		      uint32_t m)
{
	char buf[160] = "";

	for (; names->name; names++) {
		if (!(m & names->value))
			continue;
		if (buf[0])
			strncat(buf, "/", sizeof(buf) - strlen(buf) - 1);
		if (!(v & names->value))
			strncat(buf, "no", sizeof(buf) - strlen(buf) - 1);
		strncat(buf, names->name, sizeof(buf) - strlen(buf) - 1);
	}
	put(o, "%s %s", kw, buf);
}

static void put_hex(char *buf, const uint8_t *b, int n)
{
	for (int i = 0; i < n; i++)
		sprintf(buf + 2 * i, "%02x", b[i]);
	buf[2 * n] = '\0';
}

static void put_icmp(struct out *o, const struct aclx_rule *r)
{
	const struct icmp_msg *msgs = r->ip_proto == ACLX_IPPROTO_ICMP ? icmp4_msgs : icmp6_msgs;
	bool type_full = r->icmp_type.set && r->icmp_type.m == 0xff;
	bool code_ok = !r->icmp_code.set || r->icmp_code.m == 0xff;

	if (!r->icmp_type.set && !r->icmp_code.set)
		return;

	if (type_full && code_ok) {
		int code = r->icmp_code.set ? r->icmp_code.v : -1;

		for (const struct icmp_msg *m = msgs; m->name; m++) {
			if (m->type == r->icmp_type.v && m->code == code) {
				put(o, "%s", m->name);
				return;
			}
		}
		if (code >= 0)
			put(o, "%u %u", r->icmp_type.v, code);
		else
			put(o, "%u", r->icmp_type.v);
		return;
	}

	put_u8m(o, "icmp-type", &r->icmp_type);
	put_u8m(o, "icmp-code", &r->icmp_code);
}

static void put_tcp_flags(struct out *o, const struct aclx_rule *r)
{
	const struct aclx_u16m *f = &r->tcp_flags;
	const struct name_value *n;
	char buf[160] = "match-all";

	if (r->established)
		put(o, "established");
	if (!f->set)
		return;

	/* bits without a name (the reserved bits of the header) */
	if ((f->v | f->m) & ~ACLX_TCP_NAMED) {
		put(o, "tcp-flags 0x%x/0x%x", f->v, f->m);
		return;
	}

	if (f->v == f->m) {
		/* only "flag set" conditions, Cisco keywords */
		for (n = tcp_flag_names; n->name; n++)
			if (f->m & n->value)
				put(o, "%s", n->name);
		return;
	}
	for (n = tcp_flag_names; n->name; n++) {
		if (!(f->m & n->value))
			continue;
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " %c%s",
			 (f->v & n->value) ? '+' : '-', n->name);
	}
	put(o, "%s", buf);
}

const char *aclx_rule_print(const struct aclx_rule *r, char *buf, size_t len)
{
	struct out o = { .buf = buf, .len = len };
	const char *name;
	char hex[2 * ACLX_GENEVE_DATA_MAX + 1], hexm[2 * ACLX_GENEVE_DATA_MAX + 1];

	buf[0] = '\0';

	/* protocol */
	switch (r->l3) {
	case ACLX_L3_IPV4:
	case ACLX_L3_IPV6:
		if (!r->ip_proto_set)
			put(&o, r->l3 == ACLX_L3_IPV4 ? "ip" : "ipv6");
		else if ((name = name_of(ip_protocols, r->ip_proto)))
			put(&o, "%s", name);
		else
			put(&o, "%u", r->ip_proto);
		break;
	case ACLX_L3_ARP:
		put(&o, "arp");
		break;
	case ACLX_L3_RARP:
		put(&o, "rarp");
		break;
	case ACLX_L3_MPLS:
		put(&o, "mpls");
		break;
	case ACLX_L3_MPLS_MC:
		put(&o, "mpls-multicast");
		break;
	case ACLX_L3_PPPOE:
		put(&o, "pppoe");
		break;
	case ACLX_L3_CFM:
		put(&o, "cfm");
		break;
	case ACLX_L3_ETHERTYPE:
		put(&o, "ethertype 0x%04x", r->ethertype);
		break;
	case ACLX_L3_ANY:
		put(&o, "ethertype any");
		break;
	}

	if (l3_is_ip(r->l3)) {
		int fam = r->l3 == ACLX_L3_IPV4 ? AF_INET : AF_INET6;
		/* the family is implied by the protocol or an address */
		bool implied = (!r->ip_proto_set) || (r->ip_proto == ACLX_IPPROTO_ICMP) ||
			       (r->ip_proto == ACLX_IPPROTO_ICMPV6) || r->src.set || r->dst.set ||
			       fam == AF_INET;

		put_addr(&o, &r->src, !implied, fam);
		put_range(&o, &r->sport, 0xffff);
		put_addr(&o, &r->dst, false, fam);
		put_range(&o, &r->dport, 0xffff);
		if (proto_is_icmp(r))
			put_icmp(&o, r);

		if (r->dscp.set) {
			if ((name = name_of(dscp_names, r->dscp.v)) && strcmp(name, "cs0"))
				put(&o, "dscp %s", name);
			else
				put(&o, "dscp %u", r->dscp.v);
		}
		if (r->precedence.set)
			put(&o, "precedence %s", name_of(precedence_names, r->precedence.v));
		if (r->ecn.set)
			put(&o, "ecn %s", name_of(ecn_names, r->ecn.v));
		put_u8x(&o, "ip-tos", &r->ip_tos);
		if (r->ttl.op != ACLX_OP_NONE) {
			put(&o, r->l3 == ACLX_L3_IPV6 ? "hop-limit" : "ttl");
			put_range(&o, &r->ttl, 0xff);
		}
		if (r->ip_flags.set) {
			if (r->ip_flags.v == ACLX_IPF_FRAG &&
			    r->ip_flags.m == (ACLX_IPF_FRAG | ACLX_IPF_FIRSTFRAG))
				put(&o, "fragments");
			else
				put_flags(&o, "ip-flags", ip_flag_names, r->ip_flags.v,
					  r->ip_flags.m);
		}
		put_tcp_flags(&o, r);
		if (r->spi.set)
			put(&o, "spi 0x%x", r->spi.v);
		if (r->l2tpv3_sid.set)
			put(&o, "l2tpv3-sid %u", r->l2tpv3_sid.v);
	}

	/* Ethernet, VLAN */
	if (r->smac.set)
		put_mac(&o, "src-mac", &r->smac);
	if (r->dmac.set)
		put_mac(&o, "dst-mac", &r->dmac);
	if (r->vlan_tpid)
		put(&o, "vlan-tpid %s", r->vlan_tpid == ACLX_ETH_P_8021AD ? "802.1ad" : "802.1q");
	if (r->vlan_id_set)
		put(&o, "vlan-id %u", r->vlan_id);
	if (r->vlan_prio_set)
		put(&o, "vlan-prio %u", r->vlan_prio);
	if (r->cvlan_id_set)
		put(&o, "cvlan-id %u", r->cvlan_id);
	if (r->cvlan_prio_set)
		put(&o, "cvlan-prio %u", r->cvlan_prio);
	if (r->num_of_vlans.set)
		put(&o, "num-of-vlans %u", r->num_of_vlans.v);

	/* MPLS */
	if (r->mpls_label_set)
		put(&o, "mpls-label %u", r->mpls_label);
	if (r->mpls_tc_set)
		put(&o, "mpls-tc %u", r->mpls_tc);
	if (r->mpls_bos_set)
		put(&o, "mpls-bos %u", r->mpls_bos);
	if (r->mpls_ttl_set)
		put(&o, "mpls-ttl %u", r->mpls_ttl);
	for (int i = 0; i < ACLX_MAX_LSE && r->lse[i].depth; i++) {
		const struct aclx_lse *l = &r->lse[i];

		put(&o, "lse depth %u", l->depth);
		if (l->label_set)
			put(&o, "label %u", l->label);
		if (l->tc_set)
			put(&o, "tc %u", l->tc);
		if (l->bos_set)
			put(&o, "bos %u", l->bos);
		if (l->ttl_set)
			put(&o, "ttl %u", l->ttl);
	}

	/* PPPoE */
	if (r->pppoe_sid.set)
		put(&o, "pppoe-sid %u", r->pppoe_sid.v);
	if (r->ppp_proto.set) {
		if ((name = name_of(ppp_proto_names, r->ppp_proto.v)))
			put(&o, "ppp-proto %s", name);
		else
			put(&o, "ppp-proto 0x%04x", r->ppp_proto.v);
	}

	/* ARP */
	if (r->arpop.set) {
		const char *op = r->arpop.v == 1 ? "request" : r->arpop.v == 2 ? "reply" : NULL;

		if (r->arpop.m != 0xff)
			put(&o, "arp-op %u/0x%x", r->arpop.v, r->arpop.m);
		else if (op)
			put(&o, "arp-op %s", op);
		else
			put(&o, "arp-op %u", r->arpop.v);
	}
	if (r->arp_sip.set)
		put_prefix(&o, "arp-sip", &r->arp_sip);
	if (r->arp_tip.set)
		put_prefix(&o, "arp-tip", &r->arp_tip);
	if (r->arp_sha.set)
		put_mac(&o, "arp-sha", &r->arp_sha);
	if (r->arp_tha.set)
		put_mac(&o, "arp-tha", &r->arp_tha);

	/* CFM */
	if (r->cfm_mdl.set)
		put(&o, "cfm-mdl %u", r->cfm_mdl.v);
	if (r->cfm_op.set)
		put(&o, "cfm-op %u", r->cfm_op.v);

	/* Tunnel */
	if (r->enc_key_id.set)
		put(&o, "enc-key-id %u", r->enc_key_id.v);
	if (r->enc_src.set)
		put_prefix(&o, "enc-src-ip", &r->enc_src);
	if (r->enc_dst.set)
		put_prefix(&o, "enc-dst-ip", &r->enc_dst);
	if (r->enc_dst_port.set)
		put(&o, "enc-dst-port %u", r->enc_dst_port.v);
	put_u8x(&o, "enc-tos", &r->enc_tos);
	put_u8m(&o, "enc-ttl", &r->enc_ttl);
	if (r->enc_flags.set)
		put_flags(&o, "enc-flags", enc_flag_names, r->enc_flags.v, r->enc_flags.m);
	if (r->n_geneve) {
		char opts[1024] = "";

		for (int i = 0; i < r->n_geneve; i++) {
			const struct aclx_geneve *g = &r->geneve[i];
			bool full = g->class_m == 0xffff && g->type_m == 0xff &&
				    mask_is_full(g->data_m, g->len);

			put_hex(hex, g->data, g->len);
			snprintf(opts + strlen(opts), sizeof(opts) - strlen(opts),
				 "%s%04x:%02x:%s", i ? "," : "", g->class, g->type, hex);
			if (!full) {
				put_hex(hexm, g->data_m, g->len);
				snprintf(opts + strlen(opts), sizeof(opts) - strlen(opts),
					 "/%04x:%02x:%s", g->class_m, g->type_m, hexm);
			}
		}
		put(&o, "geneve-opts %s", opts);
	}
	if (r->vxlan_gbp.set) {
		if (r->vxlan_gbp.m == 0xffffffff)
			put(&o, "vxlan-opts 0x%x", r->vxlan_gbp.v);
		else
			put(&o, "vxlan-opts 0x%x/0x%x", r->vxlan_gbp.v, r->vxlan_gbp.m);
	}
	if (r->erspan_set) {
		if (r->erspan_ver == 1 && r->erspan_ver_m == 1 && r->erspan_index_m == UINT32_MAX)
			put(&o, "erspan-opts 1:%u::", r->erspan_index);
		else if (r->erspan_ver != 1 && r->erspan_ver_m == r->erspan_ver &&
			 r->erspan_dir_m == 0xff && r->erspan_hwid_m == 0xff)
			put(&o, "erspan-opts %u::%u:%u", r->erspan_ver, r->erspan_dir,
			    r->erspan_hwid);
		else if (r->erspan_ver == 1)
			put(&o, "erspan-opts 1:%u::/%u:0x%x::", r->erspan_index, r->erspan_ver_m,
			    r->erspan_index_m);
		else
			put(&o, "erspan-opts %u::%u:%u/%u::0x%x:0x%x", r->erspan_ver, r->erspan_dir,
			    r->erspan_hwid, r->erspan_ver_m, r->erspan_dir_m, r->erspan_hwid_m);
	}
	if (r->gtp_set) {
		if (r->gtp_pdu_m == 0xff && r->gtp_qfi_m == 0xff)
			put(&o, "gtp-opts %02x:%02x", r->gtp_pdu, r->gtp_qfi);
		else
			put(&o, "gtp-opts %02x:%02x/%02x:%02x", r->gtp_pdu, r->gtp_qfi,
			    r->gtp_pdu_m, r->gtp_qfi_m);
	}
	if (r->pfcp_set) {
		if (r->pfcp_type_m == 0xff && r->pfcp_seid_m == UINT64_MAX)
			put(&o, "pfcp-opts %02x:%016" PRIx64, r->pfcp_type, r->pfcp_seid);
		else
			put(&o, "pfcp-opts %02x:%016" PRIx64 "/%02x:%016" PRIx64, r->pfcp_type,
			    r->pfcp_seid, r->pfcp_type_m, r->pfcp_seid_m);
	}

	/* Conntrack */
	if (r->ct_state.set) {
		char s[64] = "";

		for (const struct name_value *n = ct_state_names; n->name; n++)
			if (r->ct_state.m & n->value)
				snprintf(s + strlen(s), sizeof(s) - strlen(s), "%c%s",
					 (r->ct_state.v & n->value) ? '+' : '-', n->name);
		put(&o, "ct-state %s", s);
	}
	if (r->ct_zone.set) {
		if (r->ct_zone.m == 0xffff)
			put(&o, "ct-zone %u", r->ct_zone.v);
		else
			put(&o, "ct-zone %u/0x%x", r->ct_zone.v, r->ct_zone.m);
	}
	if (r->ct_mark.set) {
		if (r->ct_mark.m == 0xffffffff)
			put(&o, "ct-mark 0x%x", r->ct_mark.v);
		else
			put(&o, "ct-mark 0x%x/0x%x", r->ct_mark.v, r->ct_mark.m);
	}
	if (r->ct_label_set) {
		put_hex(hex, r->ct_label, 16);
		if (mask_is_full(r->ct_label_m, 16)) {
			put(&o, "ct-label %s", hex);
		} else {
			put_hex(hexm, r->ct_label_m, 16);
			put(&o, "ct-label %s/%s", hex, hexm);
		}
	}

	if (r->indev[0])
		put(&o, "indev %s", r->indev);
	if (r->l2_miss.set)
		put(&o, "l2-miss %u", r->l2_miss.v);

	return o.truncated ? NULL : buf;
}
