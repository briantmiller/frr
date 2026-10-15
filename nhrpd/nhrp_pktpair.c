// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NHRP packet-pair link speed estimation.
 *
 * See nhrp_pktpair.h for an overview and lib/pktpair.c for the
 * measurement method.
 */

#include "zebra.h"

#include <net/if_arp.h>
#include <sys/ioctl.h>

/* As in zebra/if_netlink.c: keep the kernel headers from redefining what
 * the libc headers pulled in by zebra.h already declare. */
#define _LINUX_IN6_H
#define _LINUX_IF_H
#define _LINUX_IP_H
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_tunnel.h>

#include "checksum.h"
#include "if.h"
#include "json.h"
#include "log.h"
#include "monotime.h"
#include "pktpair.h"
#include "privs.h"
#include "sockunion.h"
#include "vty.h"
#include "zclient.h"

#include "nhrpd.h"
#include "debug.h"
#include "nhrp_pktpair.h"

#define PP_IP_HDR_LEN 20

/* ------------------------------------------------------------------ */
/* Kernel queries                                                     */
/* ------------------------------------------------------------------ */

/* Egress parameters of a GRE device, as the kernel uses them. */
struct pp_gre_params {
	bool is_gre;	     /* IFLA_INFO_KIND "gre"               */
	uint16_t oflags;     /* GRE_* flags, network byte order    */
	uint32_t okey;	     /* network byte order                 */
	uint8_t ttl;	     /* 0 = inherit from inner packet      */
	uint8_t tos;	     /* 1 = inherit from inner packet      */
	uint8_t pmtudisc;
	uint8_t ignore_df;
	uint16_t encap_type; /* FOU/GUE, 0 = none                  */
	struct in_addr local;
	ifindex_t link;
};

static int pp_nl_fd = -1;
static uint32_t pp_nl_seq;
static uint8_t pp_nl_buf[32768];

static void pp_nl_addattr(struct nlmsghdr *n, int type, const void *data,
			  size_t len)
{
	struct rtattr *rta =
		(struct rtattr *)((uint8_t *)n + NLMSG_ALIGN(n->nlmsg_len));

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

/*
 * Send a request and return the reply message with the same sequence
 * number (in pp_nl_buf), or NULL on error or timeout.
 */
static struct nlmsghdr *pp_nl_request(struct nlmsghdr *req)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
	uint32_t seq;

	if (pp_nl_fd < 0) {
		pp_nl_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
				  NETLINK_ROUTE);
		if (pp_nl_fd < 0)
			return NULL;
		setsockopt(pp_nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	seq = ++pp_nl_seq;
	req->nlmsg_seq = seq;
	req->nlmsg_flags |= NLM_F_REQUEST;
	if (sendto(pp_nl_fd, req, req->nlmsg_len, 0, (struct sockaddr *)&sa,
		   sizeof(sa)) < 0)
		return NULL;

	for (;;) {
		ssize_t len = recv(pp_nl_fd, pp_nl_buf, sizeof(pp_nl_buf), 0);
		struct nlmsghdr *h;

		if (len < 0)
			return NULL;
		for (h = (struct nlmsghdr *)pp_nl_buf; NLMSG_OK(h, len);
		     h = NLMSG_NEXT(h, len)) {
			/* Skip replies to earlier, timed-out requests. */
			if (h->nlmsg_seq != seq)
				continue;
			if (h->nlmsg_type == NLMSG_ERROR)
				return NULL;
			return h;
		}
	}
}

static void pp_parse_rta(struct rtattr **tb, int max, struct rtattr *rta,
			 int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
}

static int pp_gre_params_get(ifindex_t ifindex, struct pp_gre_params *gp)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
	} req = {};
	struct nlmsghdr *h;
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1], *li[IFLA_INFO_MAX + 1];
	struct rtattr *gre[IFLA_GRE_MAX + 1];

	memset(gp, 0, sizeof(*gp));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.i));
	req.n.nlmsg_type = RTM_GETLINK;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_index = ifindex;

	h = pp_nl_request(&req.n);
	if (!h || h->nlmsg_type != RTM_NEWLINK)
		return -1;

	ifi = NLMSG_DATA(h);
	pp_parse_rta(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(h));
	if (!tb[IFLA_LINKINFO])
		return 0;
	pp_parse_rta(li, IFLA_INFO_MAX, RTA_DATA(tb[IFLA_LINKINFO]),
		     RTA_PAYLOAD(tb[IFLA_LINKINFO]));
	if (!li[IFLA_INFO_KIND] ||
	    strcmp(RTA_DATA(li[IFLA_INFO_KIND]), "gre") != 0)
		return 0;
	gp->is_gre = true;
	if (!li[IFLA_INFO_DATA])
		return 0;

	pp_parse_rta(gre, IFLA_GRE_MAX, RTA_DATA(li[IFLA_INFO_DATA]),
		     RTA_PAYLOAD(li[IFLA_INFO_DATA]));
	if (gre[IFLA_GRE_OFLAGS])
		memcpy(&gp->oflags, RTA_DATA(gre[IFLA_GRE_OFLAGS]),
		       sizeof(gp->oflags));
	if (gre[IFLA_GRE_OKEY])
		memcpy(&gp->okey, RTA_DATA(gre[IFLA_GRE_OKEY]),
		       sizeof(gp->okey));
	if (gre[IFLA_GRE_TTL])
		gp->ttl = *(uint8_t *)RTA_DATA(gre[IFLA_GRE_TTL]);
	if (gre[IFLA_GRE_TOS])
		gp->tos = *(uint8_t *)RTA_DATA(gre[IFLA_GRE_TOS]);
	if (gre[IFLA_GRE_PMTUDISC])
		gp->pmtudisc = *(uint8_t *)RTA_DATA(gre[IFLA_GRE_PMTUDISC]);
	if (gre[IFLA_GRE_IGNORE_DF])
		gp->ignore_df = *(uint8_t *)RTA_DATA(gre[IFLA_GRE_IGNORE_DF]);
	if (gre[IFLA_GRE_ENCAP_TYPE])
		memcpy(&gp->encap_type, RTA_DATA(gre[IFLA_GRE_ENCAP_TYPE]),
		       sizeof(gp->encap_type));
	if (gre[IFLA_GRE_LOCAL])
		memcpy(&gp->local, RTA_DATA(gre[IFLA_GRE_LOCAL]),
		       sizeof(gp->local));
	if (gre[IFLA_GRE_LINK])
		memcpy(&gp->link, RTA_DATA(gre[IFLA_GRE_LINK]),
		       sizeof(gp->link));
	return 0;
}

/*
 * Kernel route lookup for an underlay destination, as the tunnel would
 * do it (restricted to the tunnel's link device when it has one).
 */
static int pp_route_get(struct in_addr dst, ifindex_t oif,
			struct in_addr *gw, ifindex_t *out,
			struct in_addr *prefsrc)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		uint8_t attrs[64];
	} req = {};
	struct nlmsghdr *h;
	struct rtmsg *r;
	struct rtattr *tb[RTA_MAX + 1];

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.r));
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = AF_INET;
	req.r.rtm_dst_len = IPV4_MAX_BITLEN;
	pp_nl_addattr(&req.n, RTA_DST, &dst, sizeof(dst));
	if (oif != IFINDEX_INTERNAL) {
		uint32_t o = oif;

		pp_nl_addattr(&req.n, RTA_OIF, &o, sizeof(o));
	}

	h = pp_nl_request(&req.n);
	if (!h || h->nlmsg_type != RTM_NEWROUTE)
		return -1;

	r = NLMSG_DATA(h);
	if (r->rtm_type != RTN_UNICAST)
		return -1;
	pp_parse_rta(tb, RTA_MAX, RTM_RTA(r), RTM_PAYLOAD(h));
	if (!tb[RTA_OIF])
		return -1;

	gw->s_addr = INADDR_ANY;
	prefsrc->s_addr = INADDR_ANY;
	memcpy(out, RTA_DATA(tb[RTA_OIF]), sizeof(*out));
	if (tb[RTA_GATEWAY])
		memcpy(gw, RTA_DATA(tb[RTA_GATEWAY]), sizeof(*gw));
	if (tb[RTA_PREFSRC])
		memcpy(prefsrc, RTA_DATA(tb[RTA_PREFSRC]), sizeof(*prefsrc));
	return 0;
}

static bool pp_arp_lookup(int fd, const char *ifname, struct in_addr addr,
			  uint8_t *mac)
{
	struct arpreq req = {};
	struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;

	sin->sin_family = AF_INET;
	sin->sin_addr = addr;
	strlcpy(req.arp_dev, ifname, sizeof(req.arp_dev));
	if (ioctl(fd, SIOCGARP, &req) < 0 || !(req.arp_flags & ATF_COM))
		return false;
	memcpy(mac, req.arp_ha.sa_data, ETH_ALEN);
	return true;
}

/* ------------------------------------------------------------------ */
/* Peers                                                              */
/* ------------------------------------------------------------------ */

/*
 * The peers to probe: NHSes we are registered with, and clients
 * registered with us.  Returns "nhs", "client" or NULL.
 */
static const char *pp_peer_role(struct nhrp_cache *c)
{
	if (sockunion_family(&c->remote_addr) != AF_INET || !c->cur.peer ||
	    !c->cur.peer->online ||
	    sockunion_family(&c->cur.peer->vc->remote.nbma) != AF_INET)
		return NULL;
	if (c->cur.type == NHRP_CACHE_NHS)
		return "nhs";
	if (c->cur.type == NHRP_CACHE_DYNAMIC && c->cur.registered)
		return "client";
	return NULL;
}

static void pp_collect_cb(struct nhrp_cache *c, void *arg)
{
	struct pktpair_session *s = arg;

	if (pp_peer_role(c))
		pktpair_target_add(s, c->remote_addr.sin.sin_addr);
}

static void pp_collect(struct pktpair_session *s, void *arg)
{
	struct interface *ifp = arg;

	nhrp_cache_foreach(ifp, pp_collect_cb, s);
}

/* ------------------------------------------------------------------ */
/* Transmit path selection                                            */
/* ------------------------------------------------------------------ */

/*
 * Build the outer IPv4 and GRE headers the GRE device would put in front
 * of an inner IPv4 packet of ip_len bytes with TOS inner_tos.  Returns
 * the header length.
 */
static uint16_t pp_build_encap(uint8_t *buf, const struct pp_gre_params *gp,
			       struct in_addr src, struct in_addr dst,
			       uint8_t inner_tos, uint16_t ip_len)
{
	struct ip *oip = (struct ip *)buf;
	uint8_t *gre = buf + PP_IP_HDR_LEN;
	uint16_t grelen = 4 + ((gp->oflags & GRE_KEY) ? 4 : 0);
	uint16_t flags = gp->oflags & GRE_KEY;
	uint16_t proto = htons(ETH_P_IP);

	memset(oip, 0, PP_IP_HDR_LEN);
	oip->ip_v = IPVERSION;
	oip->ip_hl = PP_IP_HDR_LEN >> 2;
	oip->ip_tos = (gp->tos & 0x1) ? inner_tos : gp->tos;
	oip->ip_len = htons(PP_IP_HDR_LEN + grelen + ip_len);
	/* The inner probe has DF set, which the kernel copies outward. */
	oip->ip_off = (gp->ignore_df && !gp->pmtudisc) ? 0 : htons(IP_DF);
	oip->ip_ttl = gp->ttl ? gp->ttl : IPDEFTTL;
	oip->ip_p = IPPROTO_GRE;
	oip->ip_src = src;
	oip->ip_dst = dst;
	oip->ip_sum = in_cksum(oip, PP_IP_HDR_LEN);

	memcpy(gre, &flags, 2);
	memcpy(gre + 2, &proto, 2);
	if (flags)
		memcpy(gre + 4, &gp->okey, 4);

	return PP_IP_HDR_LEN + grelen;
}

/*
 * Try to set up the full bypass: outer IPv4 + GRE built here and written
 * to the underlay Ethernet device.  Returns NULL on success, otherwise
 * why it isn't possible.
 */
static const char *pp_prepare_underlay(struct pktpair_session *s,
				       struct nhrp_interface *nifp,
				       struct nhrp_peer *peer,
				       struct in_addr nbma,
				       struct pktpair_tx *tx, uint16_t ip_len)
{
	struct interface *ifp = nifp->ifp, *oifp;
	struct pp_gre_params gp;
	struct in_addr gw, prefsrc, src, nh;
	ifindex_t oif;
	uint16_t grelen;

	/*
	 * IPsec policies are applied by the IP stack after encapsulation.
	 * A frame written straight to the underlay would skip them and go
	 * out in clear text, so leave encapsulation to the kernel.
	 */
	if (nifp->ipsec_profile)
		return "tunnel protected by IPsec";
	if (peer->vc->ipsec)
		return "IPsec SA to peer";

	if (pp_gre_params_get(ifp->ifindex, &gp) < 0)
		return "can't read GRE parameters";
	if (!gp.is_gre)
		return "not a GRE tunnel";
	if (gp.encap_type)
		return "tunnel uses FOU/GUE encapsulation";
	if (gp.oflags & ~GRE_KEY)
		return "GRE checksum or sequence numbers enabled";

	if (pp_route_get(nbma, gp.link, &gw, &oif, &prefsrc) < 0)
		return "no underlay route to peer";
	oifp = if_lookup_by_index(oif, nifp->link_vrf_id);
	if (!oifp && nifp->link_vrf_id != VRF_DEFAULT)
		oifp = if_lookup_by_index(oif, VRF_DEFAULT);
	if (!oifp || oifp->ll_type != ZEBRA_LLT_ETHER)
		return "underlay interface is not Ethernet";

	src = gp.local.s_addr != INADDR_ANY ? gp.local : prefsrc;
	if (src.s_addr == INADDR_ANY)
		return "no underlay source address";

	grelen = 4 + ((gp.oflags & GRE_KEY) ? 4 : 0);
	if ((unsigned int)(PP_IP_HDR_LEN + grelen + ip_len) > oifp->mtu)
		return "probe exceeds underlay MTU";

	nh = gw.s_addr != INADDR_ANY ? gw : nbma;
	if (!pp_arp_lookup(pktpair_session_fd(s), oifp->name, nh, tx->lladdr))
		return "underlay next-hop MAC not resolved";

	tx->encap_len = pp_build_encap(tx->encap, &gp, src, nbma,
				       nifp->pp_cfg.dscp << 2, ip_len);
	tx->mode = PKTPAIR_TX_BYPASS;
	tx->path = "underlay-bypass";
	tx->reason = NULL;
	snprintf(tx->desc, sizeof(tx->desc),
		 "tunnel and underlay qdisc bypass via %s", oifp->name);
	tx->ifindex = oif;
	tx->protocol = ETH_P_IP;
	tx->halen = ETH_ALEN;
	return NULL;
}

static bool pp_prepare(struct pktpair_session *s, struct pktpair_target *t,
		       struct pktpair_tx *tx, uint16_t ip_len, void *arg)
{
	struct interface *ifp = arg;
	struct nhrp_interface *nifp = ifp->info;
	union sockunion su;
	struct nhrp_cache *c;
	struct nhrp_peer *peer;
	struct in_addr nbma;
	const char *reason;

	sockunion_set(&su, AF_INET, (uint8_t *)&t->dst, sizeof(t->dst));
	c = nhrp_cache_get(ifp, &su, 0);
	if (!c || !pp_peer_role(c))
		return false;
	if (sockunion_family(&nifp->afi[AFI_IP].addr) != AF_INET)
		return false;

	peer = c->cur.peer;
	nbma = peer->vc->remote.nbma.sin.sin_addr;
	tx->src = nifp->afi[AFI_IP].addr.sin.sin_addr;

	if (!pktpair_session_bypass_ok(s, &reason)) {
		tx->mode = PKTPAIR_TX_STACK;
		tx->path = "ip-stack";
		tx->reason = reason;
		strlcpy(tx->desc, "IP stack, tunnel and underlay qdiscs apply",
			sizeof(tx->desc));
		return true;
	}

	reason = pp_prepare_underlay(s, nifp, peer, nbma, tx, ip_len);
	if (!reason)
		return true;

	/*
	 * Tunnel-only bypass: the GRE device's header_ops build the outer
	 * header from the NBMA address, as for NHRP packets themselves.
	 */
	tx->mode = PKTPAIR_TX_BYPASS;
	tx->path = "tunnel-bypass";
	tx->reason = reason;
	strlcpy(tx->desc, "tunnel qdisc bypass, underlay qdisc applies",
		sizeof(tx->desc));
	tx->ifindex = ifp->ifindex;
	tx->protocol = ETH_P_IP;
	tx->halen = sizeof(nbma);
	memcpy(tx->lladdr, &nbma, sizeof(nbma));
	tx->encap_len = 0;
	return true;
}

/* Measure and report probes only from our NHSes and registered clients. */
static bool pp_accept(struct pktpair_session *s, struct in_addr src,
		      void *arg)
{
	struct interface *ifp = arg;
	struct nhrp_cache *c;
	union sockunion su;

	sockunion_set(&su, AF_INET, (uint8_t *)&src, sizeof(src));
	c = nhrp_cache_get(ifp, &su, 0);
	return c && pp_peer_role(c);
}

/* Report a peer's detected bandwidth to zebra (or withdraw it). */
static void pp_zebra_send(struct pktpair_session *s, struct in_addr peer,
			  struct interface *ifp, bool withdraw)
{
	struct zapi_detected_bw bw = { .ifindex = ifp->ifindex };

	bw.nexthop.ipa_type = IPADDR_V4;
	bw.nexthop.ipaddr_v4 = peer;
	if (!withdraw)
		pktpair_peer_bw(s, peer, &bw.rtt_kbps, &bw.out_kbps,
				&bw.in_kbps);
	if (!bw.rtt_kbps && !bw.out_kbps && !bw.in_kbps)
		SET_FLAG(bw.flags, ZAPI_DETECTED_BW_DELETE);
	nhrp_zebra_detected_bw_send(ifp->vrf->vrf_id, &bw);
}

static void pp_changed(struct pktpair_session *s, struct in_addr peer,
		       void *arg)
{
	pp_zebra_send(s, peer, arg, false);
}

static void pp_withdraw(struct pktpair_session *s, struct in_addr peer,
			void *arg)
{
	pp_zebra_send(s, peer, arg, true);
}

static bool pp_debug(void *arg)
{
	return debug_flags & NHRP_DEBUG_COMMON;
}

static const struct pktpair_ops nhrp_pp_ops = {
	.collect = pp_collect,
	.prepare = pp_prepare,
	.accept = pp_accept,
	.changed = pp_changed,
	.debug = pp_debug,
};

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

void nhrp_pp_update(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;
	bool run;

	if (!nifp)
		return;

	run = nifp->pp_enabled && nifp->enabled &&
	      ifp->ifindex != IFINDEX_INTERNAL &&
	      ifp->ll_type == ZEBRA_LLT_IPGRE &&
	      nifp->afi[AFI_IP].configured;

	if (!run) {
		nhrp_pp_stop(ifp);
		return;
	}

	if (nifp->pp)
		pktpair_session_set_cfg(nifp->pp, &nifp->pp_cfg);
	else
		nifp->pp = pktpair_session_new(master, &nhrpd_privs, ifp,
					       ifp->vrf->vrf_id, &nifp->pp_cfg,
					       &nhrp_pp_ops, ifp);
}

void nhrp_pp_stop(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;

	if (!nifp || !nifp->pp)
		return;
	pktpair_session_foreach_peer(nifp->pp, pp_withdraw, ifp);
	pktpair_session_free(&nifp->pp);
}

/* ------------------------------------------------------------------ */
/* Configuration and display                                          */
/* ------------------------------------------------------------------ */

static void pp_smoothing_config_write(struct vty *vty,
				      const struct pktpair_smooth_cfg *sm)
{
	if (sm->weight == PKTPAIR_SMOOTH_WEIGHT_DEFAULT &&
	    sm->step_threshold == PKTPAIR_STEP_THRESHOLD_DEFAULT &&
	    sm->step_samples == PKTPAIR_STEP_SAMPLES_DEFAULT)
		return;

	vty_out(vty, " ip nhrp packet-pair smoothing");
	if (sm->weight != PKTPAIR_SMOOTH_WEIGHT_DEFAULT)
		vty_out(vty, " weight %u", sm->weight);
	if (sm->step_threshold != PKTPAIR_STEP_THRESHOLD_DEFAULT)
		vty_out(vty, " step-threshold %u", sm->step_threshold);
	if (sm->step_samples != PKTPAIR_STEP_SAMPLES_DEFAULT)
		vty_out(vty, " step-samples %u", sm->step_samples);
	vty_out(vty, "\n");
}

void nhrp_pp_config_write(struct vty *vty, struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;

	pp_smoothing_config_write(vty, &nifp->pp_cfg.smooth);
	if (!nifp->pp_enabled)
		return;

	if (nifp->pp_cfg.respond_only) {
		vty_out(vty, " ip nhrp packet-pair responder\n");
		return;
	}
	vty_out(vty, " ip nhrp packet-pair");
	if (nifp->pp_interval_set)
		vty_out(vty, " interval %u", nifp->pp_cfg.interval);
	if (nifp->pp_probes_set)
		vty_out(vty, " probes %u", nifp->pp_cfg.probes);
	if (nifp->pp_dscp_set)
		vty_out(vty, " dscp %u", nifp->pp_cfg.dscp);
	vty_out(vty, "\n");
}

struct pp_show_ctx {
	struct vty *vty;
	struct json_object *json_peers;
	struct pktpair_session *s;
};

static void pp_show_peer(struct nhrp_cache *c, void *arg)
{
	struct pp_show_ctx *ctx = arg;
	const char *role = pp_peer_role(c);
	struct in_addr addr;

	if (!role)
		return;
	addr = c->remote_addr.sin.sin_addr;

	if (ctx->json_peers) {
		struct json_object *jp = json_object_new_object();

		json_object_string_add(jp, "role", role);
		json_object_string_addf(jp, "nbma", "%pSU",
					&c->cur.peer->vc->remote.nbma);
		pktpair_show_peer(ctx->vty, jp, NULL, ctx->s, addr, NULL);
		json_object_object_addf(ctx->json_peers, jp, "%pSU",
					&c->remote_addr);
	} else {
		vty_out(ctx->vty, "  Peer %pSU (%s), NBMA %pSU\n",
			&c->remote_addr, strcmp(role, "nhs") ? "client" : "NHS",
			&c->cur.peer->vc->remote.nbma);
		pktpair_show_peer(ctx->vty, NULL, NULL, ctx->s, addr, "  ");
	}
}

static const char *pp_not_running_reason(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;

	if (ifp->ll_type != ZEBRA_LLT_IPGRE)
		return "not a GRE tunnel";
	if (!nifp->enabled || !nifp->afi[AFI_IP].configured)
		return "NHRP not active for IPv4 on this interface";
	return "probe socket unavailable";
}

void nhrp_pp_show(struct vty *vty, struct interface *ifp,
		  struct json_object *json)
{
	struct nhrp_interface *nifp = ifp->info;
	struct pp_show_ctx ctx = { .vty = vty, .s = nifp->pp };
	const char *reason = NULL;
	bool bypass = false;

	if (!nifp->pp_enabled)
		return;
	if (nifp->pp)
		bypass = pktpair_session_bypass_ok(nifp->pp, &reason);

	if (json) {
		struct json_object *ji = json_object_new_object();

		json_object_boolean_true_add(ji, "enabled");
		json_object_boolean_add(ji, "running", nifp->pp != NULL);
		json_object_boolean_add(ji, "responder",
					nifp->pp_cfg.respond_only);
		if (!nifp->pp)
			json_object_string_add(ji, "notRunningReason",
					       pp_not_running_reason(ifp));
		if (nifp->pp) {
			json_object_boolean_add(ji, "qdiscBypass", bypass);
			if (!bypass && reason)
				json_object_string_add(ji, "qdiscBypassReason",
						       reason);
		}
		json_object_int_add(ji, "intervalSec", nifp->pp_cfg.interval);
		json_object_int_add(ji, "pairsPerSample", nifp->pp_cfg.probes);
		json_object_int_add(ji, "dscp", nifp->pp_cfg.dscp);
		pktpair_show_smoothing(vty, ji, &nifp->pp_cfg.smooth, NULL);
		pktpair_show_session(vty, ji, nifp->pp, NULL);
		ctx.json_peers = json_object_new_object();
		nhrp_cache_foreach(ifp, pp_show_peer, &ctx);
		json_object_object_add(ji, "peers", ctx.json_peers);
		json_object_object_add(json, ifp->name, ji);
		return;
	}

	if (nifp->pp_cfg.respond_only)
		vty_out(vty,
			"Interface %s: packet-pair responder %s, measures peers' probes and reports back\n",
			ifp->name, nifp->pp ? "active" : "configured");
	else
		vty_out(vty,
			"Interface %s: packet-pair probing %s, interval %us, %u pairs per sample, DSCP %u\n",
			ifp->name, nifp->pp ? "active" : "configured",
			nifp->pp_cfg.interval, nifp->pp_cfg.probes,
			nifp->pp_cfg.dscp);
	if (!nifp->pp)
		vty_out(vty, "  Not running: %s\n", pp_not_running_reason(ifp));
	else if (nifp->pp_cfg.respond_only)
		;
	else if (bypass)
		vty_out(vty,
			"  Probes bypass egress qdiscs (PACKET_QDISC_BYPASS), path chosen per peer\n");
	else
		vty_out(vty,
			"  Probes use the IP stack, egress qdiscs apply (%s)\n",
			reason ? reason : "unknown");
	pktpair_show_smoothing(vty, NULL, &nifp->pp_cfg.smooth, "  ");
	pktpair_show_session(vty, NULL, nifp->pp, "  ");
	nhrp_cache_foreach(ifp, pp_show_peer, &ctx);
	vty_out(vty, "\n");
}
