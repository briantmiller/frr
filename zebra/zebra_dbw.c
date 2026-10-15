// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra detected bandwidth.  See zebra_dbw.h.
 */

#include <zebra.h>

#include "command.h"
#include "if.h"
#include "ipaddr.h"
#include "json.h"
#include "log.h"
#include "memory.h"
#include "monotime.h"
#include "typesafe.h"
#include "vrf.h"
#include "vty.h"
#include "zclient.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/zebra_dbw.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zserv.h"

DEFINE_MTYPE_STATIC(ZEBRA, DBW_IF, "Detected bandwidth interface");
DEFINE_MTYPE_STATIC(ZEBRA, DBW_SRC, "Detected bandwidth source");
DEFINE_MTYPE_STATIC(ZEBRA, DBW_NH, "Detected bandwidth next hop");

/* One next hop, as reported by one daemon. */
PREDECL_RBTREE_UNIQ(dbw_nhs);
struct dbw_nh {
	struct dbw_nhs_item item;
	struct ipaddr addr;
	uint64_t rtt_kbps;
	uint64_t out_kbps;
	uint64_t in_kbps;
	time_t updated; /* monotime() */
};

static int dbw_nh_cmp(const struct dbw_nh *a, const struct dbw_nh *b)
{
	return ipaddr_cmp(&a->addr, &b->addr);
}

DECLARE_RBTREE_UNIQ(dbw_nhs, struct dbw_nh, item, dbw_nh_cmp);

/* Everything one daemon reported for one interface. */
PREDECL_DLIST(dbw_srcs);
struct dbw_src {
	struct dbw_srcs_item item;
	uint8_t proto;
	unsigned short instance;
	struct dbw_nhs_head nhs;
};

DECLARE_DLIST(dbw_srcs, struct dbw_src, item);

struct zebra_dbw_if {
	struct dbw_srcs_head srcs;
};

/* ------------------------------------------------------------------ */
/* Storage                                                            */
/* ------------------------------------------------------------------ */

static uint64_t dbw_nh_out(const struct dbw_nh *nh)
{
	return nh->out_kbps ? nh->out_kbps : nh->rtt_kbps;
}

static uint64_t dbw_nh_in(const struct dbw_nh *nh)
{
	return nh->in_kbps ? nh->in_kbps : nh->rtt_kbps;
}

/* Where a next hop's effective value comes from. */
static const char *dbw_nh_source(uint64_t oneway, uint64_t rtt)
{
	if (oneway)
		return "one-way";
	return rtt ? "round-trip" : "none";
}

static struct dbw_src *dbw_src_find(struct zebra_if *zif, uint8_t proto,
				    unsigned short instance, bool create)
{
	struct dbw_src *src;

	if (!zif->dbw) {
		if (!create)
			return NULL;
		zif->dbw = XCALLOC(MTYPE_DBW_IF, sizeof(*zif->dbw));
		dbw_srcs_init(&zif->dbw->srcs);
	}

	frr_each (dbw_srcs, &zif->dbw->srcs, src)
		if (src->proto == proto && src->instance == instance)
			return src;
	if (!create)
		return NULL;

	src = XCALLOC(MTYPE_DBW_SRC, sizeof(*src));
	src->proto = proto;
	src->instance = instance;
	dbw_nhs_init(&src->nhs);
	dbw_srcs_add_tail(&zif->dbw->srcs, src);
	return src;
}

static void dbw_src_free(struct zebra_if *zif, struct dbw_src *src)
{
	struct dbw_nh *nh;

	while ((nh = dbw_nhs_pop(&src->nhs)))
		XFREE(MTYPE_DBW_NH, nh);
	dbw_nhs_fini(&src->nhs);
	dbw_srcs_del(&zif->dbw->srcs, src);
	XFREE(MTYPE_DBW_SRC, src);

	if (dbw_srcs_count(&zif->dbw->srcs) == 0) {
		dbw_srcs_fini(&zif->dbw->srcs);
		XFREE(MTYPE_DBW_IF, zif->dbw);
	}
}

void zebra_dbw_if_free(struct zebra_if *zif)
{
	struct dbw_src *src;

	while (zif->dbw && (src = dbw_srcs_first(&zif->dbw->srcs)))
		dbw_src_free(zif, src);
}

static void dbw_update(struct interface *ifp, uint8_t proto,
		       unsigned short instance,
		       const struct zapi_detected_bw *bw)
{
	struct zebra_if *zif = ifp->info;
	struct dbw_src *src;
	struct dbw_nh key = {}, *nh;
	bool remove;

	if (!zif)
		return;

	if (CHECK_FLAG(bw->flags, ZAPI_DETECTED_BW_CLEAR)) {
		src = dbw_src_find(zif, proto, instance, false);
		if (src)
			dbw_src_free(zif, src);
		return;
	}

	remove = CHECK_FLAG(bw->flags, ZAPI_DETECTED_BW_DELETE) ||
		 (!bw->rtt_kbps && !bw->out_kbps && !bw->in_kbps);
	src = dbw_src_find(zif, proto, instance, !remove);
	if (!src)
		return;

	key.addr = bw->nexthop;
	nh = dbw_nhs_find(&src->nhs, &key);
	if (remove) {
		if (nh) {
			dbw_nhs_del(&src->nhs, nh);
			XFREE(MTYPE_DBW_NH, nh);
		}
		if (dbw_nhs_count(&src->nhs) == 0)
			dbw_src_free(zif, src);
		return;
	}

	if (!nh) {
		nh = XCALLOC(MTYPE_DBW_NH, sizeof(*nh));
		nh->addr = bw->nexthop;
		dbw_nhs_add(&src->nhs, nh);
	}
	nh->rtt_kbps = bw->rtt_kbps;
	nh->out_kbps = bw->out_kbps;
	nh->in_kbps = bw->in_kbps;
	nh->updated = monotime(NULL);
}

static void dbw_compute(const struct dbw_src *src, enum zebra_dbw_aggregate agg,
			struct zebra_dbw_result *res)
{
	const struct dbw_nh *nh;

	memset(res, 0, sizeof(*res));
	frr_each (dbw_nhs_const, &src->nhs, nh) {
		uint64_t out = dbw_nh_out(nh), in = dbw_nh_in(nh);

		res->nexthops++;
		if (agg == ZEBRA_DBW_AGG_SUM) {
			res->out_kbps += out;
			res->in_kbps += in;
		} else {
			res->out_kbps = MAX(res->out_kbps, out);
			res->in_kbps = MAX(res->in_kbps, in);
		}
	}
}

bool zebra_dbw_get(struct interface *ifp, uint8_t proto,
		   unsigned short instance, struct zebra_dbw_result *res)
{
	struct zebra_if *zif = ifp->info;
	struct dbw_src *src;

	if (!zif)
		return false;
	src = dbw_src_find(zif, proto, instance, false);
	if (!src)
		return false;
	dbw_compute(src, zif->dbw_aggregate, res);
	return true;
}

void zebra_dbw_set_aggregate(struct interface *ifp,
			     enum zebra_dbw_aggregate agg)
{
	struct zebra_if *zif = ifp->info;

	if (zif)
		zif->dbw_aggregate = agg;
}

/* ------------------------------------------------------------------ */
/* ZAPI                                                               */
/* ------------------------------------------------------------------ */

void zread_detected_bw(ZAPI_HANDLER_ARGS)
{
	struct zapi_detected_bw bw;
	struct interface *ifp;

	if (zapi_detected_bw_decode(msg, &bw) < 0) {
		if (IS_ZEBRA_DEBUG_PACKET)
			zlog_debug("%s: malformed message from %s", __func__,
				   zebra_route_string(client->proto));
		return;
	}

	ifp = if_lookup_by_index(bw.ifindex, zvrf_id(zvrf));
	if (!ifp)
		return;

	if (IS_ZEBRA_DEBUG_EVENT) {
		if (CHECK_FLAG(bw.flags, ZAPI_DETECTED_BW_CLEAR))
			zlog_debug("detected bandwidth: %s[%u] clears %s",
				   zebra_route_string(client->proto),
				   client->instance, ifp->name);
		else
			zlog_debug("detected bandwidth: %s[%u] %s %pIA: rtt %" PRIu64
				   " out %" PRIu64 " in %" PRIu64 " kbps%s",
				   zebra_route_string(client->proto),
				   client->instance, ifp->name, &bw.nexthop,
				   bw.rtt_kbps, bw.out_kbps, bw.in_kbps,
				   CHECK_FLAG(bw.flags, ZAPI_DETECTED_BW_DELETE)
					   ? " (delete)"
					   : "");
	}

	dbw_update(ifp, client->proto, client->instance, &bw);
}

/* A daemon went away: its measurements go with it. */
static int dbw_client_close(struct zserv *client)
{
	struct vrf *vrf;
	struct interface *ifp;

	/* Synchronous helper sessions don't report bandwidth. */
	if (client->session_id)
		return 0;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			struct zebra_if *zif = ifp->info;
			struct dbw_src *src;

			if (!zif)
				continue;
			src = dbw_src_find(zif, client->proto, client->instance,
					   false);
			if (src)
				dbw_src_free(zif, src);
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Display                                                            */
/* ------------------------------------------------------------------ */

static const char *dbw_agg_str(enum zebra_dbw_aggregate agg)
{
	return agg == ZEBRA_DBW_AGG_SUM ? "sum" : "max";
}

static const char *dbw_speed_str(uint64_t kbps, char *buf, size_t len)
{
	if (kbps == 0)
		snprintf(buf, len, "unknown");
	else if (kbps >= 1000000)
		snprintf(buf, len, "%.2f Gbps", kbps / 1000000.0);
	else if (kbps >= 1000)
		snprintf(buf, len, "%.2f Mbps", kbps / 1000.0);
	else
		snprintf(buf, len, "%" PRIu64 " kbps", kbps);
	return buf;
}

static void dbw_src_name(const struct dbw_src *src, char *buf, size_t len)
{
	if (src->instance)
		snprintf(buf, len, "%s[%u]", zebra_route_string(src->proto),
			 src->instance);
	else
		snprintf(buf, len, "%s", zebra_route_string(src->proto));
}

void zebra_dbw_show_if(struct vty *vty, struct interface *ifp,
		       json_object *json_if)
{
	struct zebra_if *zif = ifp->info;
	struct dbw_src *src;
	json_object *json = NULL, *json_srcs = NULL;
	char name[64], b1[32], b2[32];

	if (!zif || !zif->dbw)
		return;

	if (json_if) {
		json = json_object_new_object();
		json_srcs = json_object_new_object();
		json_object_string_add(json, "aggregate",
				       dbw_agg_str(zif->dbw_aggregate));
		json_object_object_add(json, "sources", json_srcs);
		json_object_object_add(json_if, "detectedBandwidth", json);
	} else {
		vty_out(vty, "  Detected bandwidth (aggregate %s):\n",
			dbw_agg_str(zif->dbw_aggregate));
	}

	frr_each (dbw_srcs, &zif->dbw->srcs, src) {
		struct zebra_dbw_result res;

		dbw_compute(src, zif->dbw_aggregate, &res);
		dbw_src_name(src, name, sizeof(name));
		if (json) {
			json_object *js = json_object_new_object();

			json_object_int_add(js, "outKbps", res.out_kbps);
			json_object_int_add(js, "inKbps", res.in_kbps);
			json_object_int_add(js, "nexthopCount", res.nexthops);
			json_object_object_add(json_srcs, name, js);
		} else {
			vty_out(vty, "    %s: out %s, in %s, %u next hop%s\n",
				name, dbw_speed_str(res.out_kbps, b1, sizeof(b1)),
				dbw_speed_str(res.in_kbps, b2, sizeof(b2)),
				res.nexthops, res.nexthops == 1 ? "" : "s");
		}
	}
}

static void dbw_show_detail(struct vty *vty, struct interface *ifp,
			    json_object *json)
{
	struct zebra_if *zif = ifp->info;
	struct dbw_src *src;
	json_object *json_if = NULL, *json_srcs = NULL;
	time_t now = monotime(NULL);
	char name[64], b1[32], b2[32], b3[32];

	if (!zif || !zif->dbw)
		return;

	if (json) {
		json_if = json_object_new_object();
		json_srcs = json_object_new_object();
		json_object_string_add(json_if, "vrf", ifp->vrf->name);
		json_object_string_add(json_if, "aggregate",
				       dbw_agg_str(zif->dbw_aggregate));
		json_object_object_add(json_if, "sources", json_srcs);
		json_object_object_add(json, ifp->name, json_if);
	} else {
		vty_out(vty, "Interface %s (vrf %s), aggregate %s\n", ifp->name,
			ifp->vrf->name, dbw_agg_str(zif->dbw_aggregate));
	}

	frr_each (dbw_srcs, &zif->dbw->srcs, src) {
		struct zebra_dbw_result res;
		json_object *js = NULL, *jnhs = NULL;
		const struct dbw_nh *nh;

		dbw_compute(src, zif->dbw_aggregate, &res);
		dbw_src_name(src, name, sizeof(name));
		if (json) {
			js = json_object_new_object();
			jnhs = json_object_new_object();
			json_object_int_add(js, "outKbps", res.out_kbps);
			json_object_int_add(js, "inKbps", res.in_kbps);
			json_object_int_add(js, "nexthopCount", res.nexthops);
			json_object_object_add(js, "nexthops", jnhs);
			json_object_object_add(json_srcs, name, js);
		} else {
			vty_out(vty, "  %s: out %s, in %s, from %u next hop%s\n",
				name, dbw_speed_str(res.out_kbps, b1, sizeof(b1)),
				dbw_speed_str(res.in_kbps, b2, sizeof(b2)),
				res.nexthops, res.nexthops == 1 ? "" : "s");
		}

		frr_each (dbw_nhs_const, &src->nhs, nh) {
			if (json) {
				json_object *jn = json_object_new_object();

				json_object_int_add(jn, "rttKbps", nh->rtt_kbps);
				json_object_int_add(jn, "outKbps", dbw_nh_out(nh));
				json_object_string_add(jn, "outSource",
						       dbw_nh_source(nh->out_kbps,
								     nh->rtt_kbps));
				json_object_int_add(jn, "inKbps", dbw_nh_in(nh));
				json_object_string_add(jn, "inSource",
						       dbw_nh_source(nh->in_kbps,
								     nh->rtt_kbps));
				json_object_int_add(jn, "updatedSecAgo",
						    now - nh->updated);
				json_object_object_addf(jnhs, jn, "%pIA",
							&nh->addr);
			} else {
				vty_out(vty,
					"    %pIA: out %s (%s), in %s (%s), round trip %s, updated %llds ago\n",
					&nh->addr,
					dbw_speed_str(dbw_nh_out(nh), b1,
						      sizeof(b1)),
					dbw_nh_source(nh->out_kbps,
						      nh->rtt_kbps),
					dbw_speed_str(dbw_nh_in(nh), b2,
						      sizeof(b2)),
					dbw_nh_source(nh->in_kbps,
						      nh->rtt_kbps),
					dbw_speed_str(nh->rtt_kbps, b3,
						      sizeof(b3)),
					(long long)(now - nh->updated));
			}
		}
	}
}

#include "zebra/zebra_dbw_clippy.c"

DEFPY (show_zebra_detected_bw,
       show_zebra_detected_bw_cmd,
       "show zebra detected-bandwidth [interface IFNAME$ifname] [json$json]",
       SHOW_STR
       ZEBRA_STR
       "Bandwidth detected by protocols towards next hops\n"
       "Interface\n"
       "Interface name\n"
       JSON_STR)
{
	struct vrf *vrf;
	struct interface *ifp;
	json_object *json_top = json ? json_object_new_object() : NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifname && strcmp(ifname, ifp->name))
				continue;
			dbw_show_detail(vty, ifp, json_top);
		}
	}

	if (json)
		vty_json(vty, json_top);
	return CMD_SUCCESS;
}

void zebra_dbw_init(void)
{
	hook_register(zserv_client_close, dbw_client_close);
	install_element(VIEW_NODE, &show_zebra_detected_bw_cmd);
}
