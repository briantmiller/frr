// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SAND v2 - zebra client and permanent neighbor entries
 */

#include <zebra.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>

#include "log.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"

#include "sandd/sandd.h"

DEFINE_MTYPE_STATIC(SANDD, SAND_XPFX, "SAND local prefix");

static struct zclient *sand_zclient;
static int sand_nl_sock = -1;

int sand_xpfx_cmp(const struct sand_xpfx *a, const struct sand_xpfx *b)
{
	return prefix_cmp(&a->p, &b->p);
}

/* ------------------------------------------------------------------ */
/* Routes                                                               */
/* ------------------------------------------------------------------ */

void sand_zebra_route(bool add, struct sand_route *rt)
{
	struct zapi_route api;
	uint8_t i;

	if (!sand_zclient || sand_zclient->sock < 0)
		return;

	zapi_route_init(&api);
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_SAND;
	api.safi = SAFI_UNICAST;
	api.prefix = rt->p;

	if (add) {
		SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
		SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
		api.metric = rt->cost;
		for (i = 0; i < rt->n_nh; i++) {
			struct zapi_nexthop *nh = &api.nexthops[i];

			zapi_nexthop_init(nh);
			nh->vrf_id = VRF_DEFAULT;
			nh->ifindex = rt->nh[i].ifindex;
			nh->gate = rt->nh[i].gate;
			nh->type = rt->p.family == AF_INET
					   ? NEXTHOP_TYPE_IPV4_IFINDEX
					   : NEXTHOP_TYPE_IPV6_IFINDEX;
			/* one-way links: the next hop never answers ARP/ND,
			 * so it is reachable only "onlink" (11.3) */
			SET_FLAG(nh->flags, ZAPI_NEXTHOP_FLAG_ONLINK);
		}
		api.nexthop_num = rt->n_nh;
	}

	zclient_route_send(add ? ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE,
			   sand_zclient, &api);
}

/* ------------------------------------------------------------------ */
/* Permanent neighbor entries (zebra's neighbor API carries no MAC)    */
/* ------------------------------------------------------------------ */

static void nl_addattr(struct nlmsghdr *n, size_t max, int type,
		       const void *data, size_t len)
{
	struct rtattr *rta;
	size_t rlen = RTA_LENGTH(len);

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(rlen) > max)
		return;
	rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = rlen;
	memcpy(RTA_DATA(rta), data, len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(rlen);
}

int sand_neigh_set(bool add, struct sand_neigh *ne)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg ndm;
		char buf[256];
	} req = {};
	struct sockaddr_nl snl = { .nl_family = AF_NETLINK };
	int ret;

	if (sand_nl_sock < 0) {
		frr_with_privs (&sandd_privs) {
			sand_nl_sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
					      NETLINK_ROUTE);
		}
		if (sand_nl_sock < 0) {
			zlog_err("SAND: netlink socket: %s",
				 safe_strerror(errno));
			return -1;
		}
	}

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_type = add ? RTM_NEWNEIGH : RTM_DELNEIGH;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	if (add)
		req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
	req.ndm.ndm_family = ne->family;
	req.ndm.ndm_ifindex = ne->ifindex;
	req.ndm.ndm_state = NUD_PERMANENT;
	req.ndm.ndm_type = RTN_UNICAST;
	nl_addattr(&req.n, sizeof(req), NDA_DST, &ne->addr,
		   ne->family == AF_INET ? 4 : 16);
	if (add && ne->mac_len)
		nl_addattr(&req.n, sizeof(req), NDA_LLADDR, ne->mac,
			   ne->mac_len);

	frr_with_privs (&sandd_privs) {
		ret = sendto(sand_nl_sock, &req, req.n.nlmsg_len, 0,
			     (struct sockaddr *)&snl, sizeof(snl));
	}
	if (ret < 0)
		zlog_warn("SAND: neighbor %s: %s", add ? "add" : "delete",
			  safe_strerror(errno));

	/* drain any error replies */
	{
		char junk[1024];

		while (recv(sand_nl_sock, junk, sizeof(junk), MSG_DONTWAIT) > 0)
			;
	}
	SAND_DBG(SAND_DEBUG_ZEBRA, "%s neighbor %s on ifindex %d",
		 add ? "set" : "removed",
		 ne->family == AF_INET ? "v4" : "v6", ne->ifindex);
	return ret < 0 ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* Locally originated prefixes: redistribution                          */
/* ------------------------------------------------------------------ */

static void sand_xpfx_set(const struct prefix *p, uint8_t src, bool on,
			  uint16_t metric)
{
	struct sand_xpfx ref = {}, *x;

	ref.p = *p;
	apply_mask(&ref.p);
	x = sand_xpfx_find(&sand->xpfx, &ref);
	if (on) {
		if (!x) {
			x = XCALLOC(MTYPE_SAND_XPFX, sizeof(*x));
			x->p = ref.p;
			sand_xpfx_add(&sand->xpfx, x);
		}
		x->src |= src;
		if (src == SAND_XP_NETWORK || !(x->src & SAND_XP_NETWORK))
			x->metric = metric;
	} else if (x) {
		x->src &= ~src;
		if (!x->src) {
			sand_xpfx_del(&sand->xpfx, x);
			XFREE(MTYPE_SAND_XPFX, x);
		}
	}
	sand_schedule_orig();
}

void sand_network_set(const struct prefix *p, bool on, uint16_t metric)
{
	sand_xpfx_set(p, SAND_XP_NETWORK, on, metric);
}

void sand_xpfx_flush(void)
{
	struct sand_xpfx *x;

	while ((x = sand_xpfx_pop(&sand->xpfx)))
		XFREE(MTYPE_SAND_XPFX, x);
}

static int sand_zebra_read_route(ZAPI_CALLBACK_ARGS)
{
	struct zapi_route api;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;
	if (CHECK_FLAG(api.message, ZAPI_MESSAGE_SRCPFX))
		return 0;
	if (api.prefix.family == AF_INET6 &&
	    IN6_IS_ADDR_LINKLOCAL(&api.prefix.u.prefix6))
		return 0;
	sand_xpfx_set(&api.prefix, SAND_XP_REDIST,
		      cmd == ZEBRA_REDISTRIBUTE_ROUTE_ADD, 0);
	return 0;
}

static bool sand_redist[AFI_MAX][ZEBRA_ROUTE_MAX];

bool sand_redist_get(afi_t afi, int type)
{
	return sand_redist[afi][type];
}

void sand_zebra_redistribute(afi_t afi, int type, bool on)
{
	struct sand_xpfx *x;

	sand_redist[afi][type] = on;
	if (!on) {
		/* drop everything we had from redistribution; zebra will
		 * resend the remaining types */
		frr_each_safe (sand_xpfx, &sand->xpfx, x) {
			if (!(x->src & SAND_XP_REDIST))
				continue;
			if (family2afi(x->p.family) != afi)
				continue;
			x->src &= ~SAND_XP_REDIST;
			if (!x->src) {
				sand_xpfx_del(&sand->xpfx, x);
				XFREE(MTYPE_SAND_XPFX, x);
			}
		}
		sand_schedule_orig();
	}
	if (sand_zclient)
		zclient_redistribute(on ? ZEBRA_REDISTRIBUTE_ADD
					: ZEBRA_REDISTRIBUTE_DELETE,
				     sand_zclient, afi, type, 0, VRF_DEFAULT);
	if (!on) {
		/* re-request the types still configured */
		int t;

		for (t = 0; t < ZEBRA_ROUTE_MAX; t++)
			if (sand_redist[afi][t] && sand_zclient) {
				zclient_redistribute(ZEBRA_REDISTRIBUTE_DELETE,
						     sand_zclient, afi, t, 0,
						     VRF_DEFAULT);
				zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD,
						     sand_zclient, afi, t, 0,
						     VRF_DEFAULT);
			}
	}
}

/* ------------------------------------------------------------------ */
/* Interfaces, addresses, router-id                                     */
/* ------------------------------------------------------------------ */

static int sand_zebra_if_addr(ZAPI_CALLBACK_ARGS)
{
	struct connected *ifc;

	ifc = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);
	if (!ifc)
		return 0;
	sand_if_update(ifc->ifp);
	if (cmd == ZEBRA_INTERFACE_ADDRESS_DELETE)
		connected_free(&ifc);
	return 0;
}

static int sand_zebra_router_id(ZAPI_CALLBACK_ARGS)
{
	struct prefix p;

	if (zebra_router_id_update_read(zclient->ibuf, &p) < 0)
		return -1;
	if (p.family != AF_INET)
		return 0;
	sand->rid_zebra = p.u.prefix4;
	sand_rid_update();
	return 0;
}

static void sand_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
	zclient_send_router_id_update(zclient, ZEBRA_ROUTER_ID_ADD, AFI_IP,
				      VRF_DEFAULT);
	/* routes and redistribution are resent on (re)connect */
	if (sand && sand->running) {
		struct sand_route *rt;

		frr_each (sand_rt, &sand->routes, rt)
			sand_zebra_route(true, rt);
	}
}

static zclient_handler *const sand_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = sand_zebra_if_addr,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = sand_zebra_if_addr,
	[ZEBRA_ROUTER_ID_UPDATE] = sand_zebra_router_id,
	[ZEBRA_REDISTRIBUTE_ROUTE_ADD] = sand_zebra_read_route,
	[ZEBRA_REDISTRIBUTE_ROUTE_DEL] = sand_zebra_read_route,
};

void sand_zebra_init(void)
{
	sand_zclient = zclient_new(master, &zclient_options_default,
				   sand_handlers, array_size(sand_handlers));
	zclient_init(sand_zclient, ZEBRA_ROUTE_SAND, 0, &sandd_privs);
	sand_zclient->zebra_connected = sand_zebra_connected;
}

void sand_zebra_stop(void)
{
	if (sand_zclient) {
		zclient_stop(sand_zclient);
		zclient_free(sand_zclient);
		sand_zclient = NULL;
	}
	if (sand_nl_sock >= 0)
		close(sand_nl_sock);
	sand_nl_sock = -1;
}
