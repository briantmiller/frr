// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv2 Multi-Topology Routing (RFC 4915).
 *
 * Overview
 * --------
 * - Interfaces may be given a per MT-ID output cost ("ip ospf mt-id N cost
 *   C").  These are advertised in the Router-LSA as MT-ID metrics, i.e. in
 *   the formerly-TOS fields of each link (RFC 4915 A.4.2).  Routers that do
 *   not implement RFC 4915 ignore those fields (RFC 2328 A.4.2), so the
 *   default topology is unaffected and the extension is backward
 *   compatible.
 *
 * - A separate route calculation (intra-area SPF, inter-area and AS
 *   external) is run for every topology (MT-ID 1-255) that appears in the
 *   LSDB or is configured locally.  During the calculation only the links
 *   that carry a metric for that MT-ID are used (RFC 4915 3.6).  Network-LSAs
 *   are shared by all topologies.
 *
 * - "mtr copy-base-topology" (router ospf) relaxes that rule: a link (or a
 *   Summary/AS-external LSA) without an explicit MT-ID metric takes part in
 *   the topology with its base (TOS 0) metric.  This lets a full topology be
 *   built without every link declaring every MT-ID and lets non-MT routers
 *   participate in every topology.
 *
 * - The routes of topology N are installed into kernel routing table
 *   "mtr-route-table-offset + N".
 */

#include <zebra.h>

#include "monotime.h"
#include "frrevent.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "log.h"
#include "command.h"
#include "vty.h"
#include "json.h"
#include "vrf.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ia.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_memory.h"
#include "ospfd/ospf_mtr.h"

#include "ospfd/ospf_mtr_clippy.c"

/* Delay before recomputing MT external routes after an external LSA
 * change (milliseconds); coalesces bursts of updates.
 */
#define OSPF_MTR_EXT_CALC_DELAY 200

/* ======================================================================
 * Interface configuration
 */

bool ospf_if_mt_cost_get(struct interface *ifp, uint8_t mtid, uint16_t *cost)
{
	struct ospf_if_params *params;

	if (!ifp || !ifp->info || mtid == OSPF_MTR_MTID_DEFAULT)
		return false;

	params = IF_DEF_PARAMS(ifp);
	if (!params || !params->mt_cost || !params->mt_cost[mtid])
		return false;

	if (cost)
		*cost = params->mt_cost[mtid];
	return true;
}

bool ospf_if_has_mt_cost(struct interface *ifp)
{
	int mtid;

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++)
		if (ospf_if_mt_cost_get(ifp, mtid, NULL))
			return true;
	return false;
}

/* ======================================================================
 * LSA encoding / decoding
 */

int ospf_mtr_if_link_metrics(struct ospf_interface *oi, int fixed, struct ospf_mt_metric *out)
{
	int mtid, count = 0;
	uint16_t cost;

	if (!oi || !oi->ifp)
		return 0;

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++) {
		if (!ospf_if_mt_cost_get(oi->ifp, mtid, &cost))
			continue;
		out[count].mtid = mtid;
		out[count].metric = fixed >= 0 ? (uint32_t)fixed : cost;
		count++;
	}

	return count;
}

bool ospf_mtr_link_metric(struct ospf *ospf, const struct router_lsa_link *l, uint8_t mtid,
			  uint16_t *metric)
{
	const uint8_t *p;
	int i;

	if (mtid == OSPF_MTR_MTID_DEFAULT) {
		*metric = ntohs(l->m[0].metric);
		return true;
	}

	/*
	 * RFC 4915 3.4: if an MT-ID appears multiple times the metric of the
	 * first instance is used.  The link length has been validated when
	 * the LSA was received (ospf_router_lsa_links_examin()).
	 */
	p = (const uint8_t *)l + OSPF_ROUTER_LSA_LINK_SIZE;
	for (i = 0; i < l->m[0].tos_count; i++, p += OSPF_ROUTER_LSA_TOS_SIZE) {
		if (p[0] == mtid) {
			*metric = (p[2] << 8) | p[3];
			return true;
		}
	}

	if (ospf && ospf->mtr_copy_base) {
		*metric = ntohs(l->m[0].metric);
		return true;
	}

	return false;
}

bool ospf_mtr_summary_metric(struct ospf *ospf, const struct lsa_header *lsah, uint32_t *metric)
{
	const struct summary_lsa *sl = (const struct summary_lsa *)lsah;
	const uint8_t *p, *lim;
	uint8_t mtid = ospf->mtr_cur_mtid;

	if (mtid == OSPF_MTR_MTID_DEFAULT) {
		*metric = GET_METRIC((uint8_t *)sl->metric);
		return true;
	}

	/* RFC 4915 A.4.4: MT-ID (1 octet) + metric (3 octets) entries. */
	p = (const uint8_t *)lsah + OSPF_LSA_HEADER_SIZE + 8;
	lim = (const uint8_t *)lsah + ntohs(lsah->length);
	for (; p + 4 <= lim; p += 4) {
		if (p[0] == mtid) {
			*metric = (p[1] << 16) | (p[2] << 8) | p[3];
			return true;
		}
	}

	if (ospf->mtr_copy_base) {
		*metric = GET_METRIC((uint8_t *)sl->metric);
		return true;
	}

	return false;
}

const struct as_route *ospf_mtr_external_entry(struct ospf *ospf, const struct as_external_lsa *al)
{
	uint8_t mtid = ospf->mtr_cur_mtid;
	const uint8_t *p, *lim;

	if (mtid == OSPF_MTR_MTID_DEFAULT)
		return &al->e[0];

	/*
	 * RFC 4915 A.4.5: each additional entry is E-bit + 7-bit MT-ID,
	 * metric, forwarding address and external route tag (12 octets).
	 * MT-IDs above 127 cannot be represented here.
	 */
	if (mtid <= OSPF_MTR_EXT_MTID_MAX) {
		p = (const uint8_t *)&al->e[1];
		lim = (const uint8_t *)al + ntohs(al->header.length);
		for (; p + sizeof(struct as_route) <= lim; p += sizeof(struct as_route)) {
			const struct as_route *er = (const struct as_route *)p;

			if ((er->tos & 0x7f) == mtid)
				return er;
		}
	}

	if (ospf->mtr_copy_base)
		return &al->e[0];

	return NULL;
}

int ospf_mtr_summary_metrics(struct ospf_area *area, struct prefix_ipv4 *p, bool asbr,
			     struct ospf_mt_metric *out)
{
	struct ospf *ospf = area->ospf;
	struct ospf_mtr_topo *topo;
	struct ospf_route *route;
	struct route_node *rn;
	uint32_t cost;
	int mtid, count = 0;

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++) {
		topo = ospf->mtr[mtid];
		if (!topo || !topo->rt || !topo->rtrs || !topo->grounded)
			continue;

		if (!asbr) {
			rn = route_node_lookup(topo->rt, (struct prefix *)p);
			if (!rn)
				continue;
			route_unlock_node(rn);
			route = rn->info;
			if (!route || route->type != OSPF_DESTINATION_NETWORK)
				continue;
		} else {
			route = ospf_find_asbr_route(ospf, topo->rtrs, p);
			if (!route)
				continue;
		}

		/* Never announce a route back into its own area, and only
		 * announce inter-area routes from the backbone outwards
		 * (RFC 2328 12.4.3).
		 */
		if (IPV4_ADDR_SAME(&route->u.std.area_id, &area->area_id))
			continue;
		if (route->path_type == OSPF_PATH_INTER_AREA && OSPF_IS_AREA_BACKBONE(area))
			continue;
		if (route->path_type != OSPF_PATH_INTRA_AREA &&
		    route->path_type != OSPF_PATH_INTER_AREA)
			continue;

		cost = route->cost;
		if (CHECK_FLAG(area->stub_router_state, OSPF_AREA_IS_STUB_ROUTED))
			cost = OSPF_STUB_MAX_METRIC_SUMMARY_COST;
		if (cost >= OSPF_LS_INFINITY)
			continue;

		out[count].mtid = mtid;
		out[count].metric = cost;
		count++;
	}

	return count;
}

bool ospf_mtr_summary_lsa_mt_same(const struct lsa_header *lsah, const struct ospf_mt_metric *mt,
				  int count)
{
	const uint8_t *p, *lim;
	int i = 0;

	p = (const uint8_t *)lsah + OSPF_LSA_HEADER_SIZE + 8;
	lim = (const uint8_t *)lsah + ntohs(lsah->length);
	for (; p + 4 <= lim; p += 4, i++) {
		if (i >= count)
			return false;
		if (p[0] != mt[i].mtid ||
		    ((uint32_t)(p[1] << 16) | (p[2] << 8) | p[3]) != mt[i].metric)
			return false;
	}

	return i == count;
}

/* ======================================================================
 * Topology management
 */

uint32_t ospf_mtr_table_id(struct ospf *ospf, uint8_t mtid)
{
	return ospf->mtr_table_offset + mtid;
}

/* Return true if routes may be installed into kernel table `table_id`. */
static bool ospf_mtr_table_valid(struct ospf *ospf, uint32_t table_id)
{
	/* Never clobber the unspec(0)/default(253)/main(254)/local(255)
	 * kernel tables.
	 */
	if (table_id == 0 || (table_id >= 253 && table_id <= 255))
		return false;
	return true;
}

bool ospf_mtr_active(struct ospf *ospf)
{
	int mtid;

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++)
		if (ospf->mtr[mtid])
			return true;
	return false;
}

static struct ospf_mtr_topo *ospf_mtr_topo_get(struct ospf *ospf, uint8_t mtid)
{
	struct ospf_mtr_topo *topo = ospf->mtr[mtid];

	if (topo)
		return topo;

	topo = XCALLOC(MTYPE_OSPF_MTR_TOPO, sizeof(*topo));
	topo->mtid = mtid;
	ospf->mtr[mtid] = topo;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("MTR: topology %u created (table %u)", mtid,
			   ospf_mtr_table_id(ospf, mtid));

	return topo;
}

/* Lookup the route installed/to install for prefix `p`: intra/inter-area
 * routes take precedence over AS external routes (RFC 2328 16.4 (6a)).
 */
static struct ospf_route *mtr_view_lookup(struct route_table *rt, struct route_table *ext,
					  const struct prefix *p)
{
	struct route_node *rn;
	struct ospf_route *route;

	if (rt) {
		rn = route_node_lookup(rt, p);
		if (rn) {
			route_unlock_node(rn);
			route = rn->info;
			if (route)
				return route;
		}
	}
	if (ext) {
		rn = route_node_lookup(ext, p);
		if (rn) {
			route_unlock_node(rn);
			return rn->info;
		}
	}
	return NULL;
}

/* Is this a route we hand to zebra? */
static bool mtr_route_installable(struct ospf_route *route)
{
	return route && route->type == OSPF_DESTINATION_NETWORK && !route->connected &&
	       route->paths && listcount(route->paths) > 0;
}

static bool mtr_route_same(struct ospf_route *a, struct ospf_route *b)
{
	struct listnode *n1, *n2;
	struct ospf_path *pa, *pb;

	if (a->path_type != b->path_type || a->cost != b->cost)
		return false;

	if (a->path_type == OSPF_PATH_TYPE1_EXTERNAL || a->path_type == OSPF_PATH_TYPE2_EXTERNAL) {
		if (a->u.ext.type2_cost != b->u.ext.type2_cost || a->u.ext.tag != b->u.ext.tag)
			return false;
	}

	if (listcount(a->paths) != listcount(b->paths))
		return false;

	for (n1 = listhead(a->paths), n2 = listhead(b->paths); n1 && n2;
	     n1 = listnextnode(n1), n2 = listnextnode(n2)) {
		pa = listgetdata(n1);
		pb = listgetdata(n2);
		if (!IPV4_ADDR_SAME(&pa->nexthop, &pb->nexthop) || pa->ifindex != pb->ifindex)
			return false;
	}

	return true;
}

/*
 * Synchronise zebra with a topology's new routing state.
 *
 * Old state: routes of (old_rt, old_ext) installed in topo->installed_table.
 * New state: routes of (new_rt, new_ext) to be installed in `new_table`
 * (0 = install nothing).
 */
static void mtr_install(struct ospf *ospf, struct ospf_mtr_topo *topo, struct route_table *old_rt,
			struct route_table *old_ext, struct route_table *new_rt,
			struct route_table *new_ext, uint32_t new_table)
{
	uint32_t old_table = topo->installed_table;
	struct route_table *tables[2];
	struct route_node *rn;
	struct ospf_route *route, *nroute;
	int i;

	/* Routes are not installed while a graceful restart is ongoing; do
	 * a full installation once it has finished.
	 */
	if (ospf->gr_info.restart_in_progress) {
		topo->installed_table = 0;
		return;
	}

	/* Withdraw routes that disappeared or moved to another table. */
	if (old_table) {
		tables[0] = old_rt;
		tables[1] = old_ext;
		for (i = 0; i < 2; i++) {
			if (!tables[i])
				continue;
			for (rn = route_top(tables[i]); rn; rn = route_next(rn)) {
				route = rn->info;
				if (!route)
					continue;
				/* external shadowed by intra/inter route */
				if (i == 1 && mtr_view_lookup(old_rt, NULL, &rn->p))
					continue;
				if (!mtr_route_installable(route))
					continue;

				nroute = mtr_view_lookup(new_rt, new_ext, &rn->p);
				if (new_table == old_table && mtr_route_installable(nroute))
					continue; /* replaced by add below */

				ospf_zebra_delete_table(ospf, (struct prefix_ipv4 *)&rn->p, route,
							old_table);
			}
		}
	}

	topo->installed_table = new_table;
	if (!new_table)
		return;

	/* Install new or changed routes. */
	tables[0] = new_rt;
	tables[1] = new_ext;
	for (i = 0; i < 2; i++) {
		if (!tables[i])
			continue;
		for (rn = route_top(tables[i]); rn; rn = route_next(rn)) {
			nroute = rn->info;
			if (!nroute)
				continue;
			if (i == 1 && mtr_view_lookup(new_rt, NULL, &rn->p))
				continue;
			/* (an installed route that became e.g. connected has
			 * been withdrawn above)
			 */
			if (!mtr_route_installable(nroute))
				continue;

			if (old_table == new_table) {
				route = mtr_view_lookup(old_rt, old_ext, &rn->p);
				if (mtr_route_installable(route) && mtr_route_same(route, nroute))
					continue;
			}

			ospf_zebra_add_table(ospf, (struct prefix_ipv4 *)&rn->p, nroute, new_table);
		}
	}
}

static uint32_t mtr_target_table(struct ospf *ospf, struct ospf_mtr_topo *topo)
{
	uint32_t table_id = ospf_mtr_table_id(ospf, topo->mtid);

	if (!ospf_mtr_table_valid(ospf, table_id)) {
		zlog_warn("MTR: not installing MT-ID %u routes: table %u is reserved, adjust mtr-route-table-offset",
			  topo->mtid, table_id);
		return 0;
	}
	return table_id;
}

static void ospf_mtr_topo_free_tables(struct ospf_mtr_topo *topo)
{
	/* External routes reference router routes: free them first. */
	if (topo->ext)
		ospf_route_table_free(topo->ext);
	if (topo->rt)
		ospf_route_table_free(topo->rt);
	if (topo->rtrs)
		ospf_rtrs_free(topo->rtrs);
	topo->ext = topo->rt = topo->rtrs = NULL;
}

static void ospf_mtr_topo_delete(struct ospf *ospf, uint8_t mtid, bool withdraw)
{
	struct ospf_mtr_topo *topo = ospf->mtr[mtid];

	if (!topo)
		return;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("MTR: topology %u removed", mtid);

	if (withdraw)
		mtr_install(ospf, topo, topo->rt, topo->ext, NULL, NULL, 0);
	ospf_mtr_topo_free_tables(topo);
	XFREE(MTYPE_OSPF_MTR_TOPO, topo);
	ospf->mtr[mtid] = NULL;
}

/* ======================================================================
 * Discovery of the topologies present in the LSDB
 */

static void mtr_scan_router_lsa(struct ospf_lsa *lsa, bool *seen)
{
	uint8_t *p, *lim, *mt;
	struct router_lsa_link *l;
	int i;

	if (IS_LSA_MAXAGE(lsa))
		return;

	p = (uint8_t *)lsa->data + OSPF_LSA_HEADER_SIZE + 4;
	lim = (uint8_t *)lsa->data + ntohs(lsa->data->length);
	while (p + OSPF_ROUTER_LSA_LINK_SIZE <= lim) {
		l = (struct router_lsa_link *)p;
		mt = p + OSPF_ROUTER_LSA_LINK_SIZE;
		for (i = 0; i < l->m[0].tos_count && mt + OSPF_ROUTER_LSA_TOS_SIZE <= lim;
		     i++, mt += OSPF_ROUTER_LSA_TOS_SIZE)
			seen[mt[0]] = true;
		p += OSPF_ROUTER_LSA_LINK_SIZE + l->m[0].tos_count * OSPF_ROUTER_LSA_TOS_SIZE;
	}
}

static void mtr_scan_summary_lsa(struct ospf_lsa *lsa, bool *seen)
{
	uint8_t *p, *lim;

	/* Our own Summary-LSAs merely reflect topologies known otherwise. */
	if (IS_LSA_MAXAGE(lsa) || IS_LSA_SELF(lsa))
		return;

	p = (uint8_t *)lsa->data + OSPF_LSA_HEADER_SIZE + 8;
	lim = (uint8_t *)lsa->data + ntohs(lsa->data->length);
	for (; p + 4 <= lim; p += 4)
		seen[p[0]] = true;
}

static void mtr_scan_external_lsa(struct ospf_lsa *lsa, bool *seen)
{
	struct as_external_lsa *al = (struct as_external_lsa *)lsa->data;
	uint8_t *p, *lim;

	if (IS_LSA_MAXAGE(lsa) || IS_LSA_SELF(lsa))
		return;

	p = (uint8_t *)&al->e[1];
	lim = (uint8_t *)al + ntohs(al->header.length);
	for (; p + sizeof(struct as_route) <= lim; p += sizeof(struct as_route))
		seen[((struct as_route *)p)->tos & 0x7f] = true;
}

/*
 * Collect the topologies present in the LSDB and in the local configuration.
 * A topology is "grounded" if it appears in a Router-LSA or is configured
 * locally; only grounded topologies are re-advertised in Summary-LSAs, which
 * prevents ABRs from keeping a topology alive between themselves after it
 * has been removed from every link.
 */
static void mtr_collect_topologies(struct ospf *ospf, bool *advertised, bool *grounded,
				   bool *configured)
{
	struct ospf_area *area;
	struct ospf_interface *oi;
	struct listnode *node, *inode;
	struct route_node *rn;
	struct ospf_lsa *lsa;
	int mtid;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		LSDB_LOOP (ROUTER_LSDB(area), rn, lsa)
			mtr_scan_router_lsa(lsa, grounded);
		LSDB_LOOP (SUMMARY_LSDB(area), rn, lsa)
			mtr_scan_summary_lsa(lsa, advertised);
		LSDB_LOOP (ASBR_SUMMARY_LSDB(area), rn, lsa)
			mtr_scan_summary_lsa(lsa, advertised);
		LSDB_LOOP (NSSA_LSDB(area), rn, lsa)
			mtr_scan_external_lsa(lsa, advertised);

		for (ALL_LIST_ELEMENTS_RO(area->oiflist, inode, oi))
			for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++)
				if (ospf_if_mt_cost_get(oi->ifp, mtid, NULL))
					configured[mtid] = true;
	}
	LSDB_LOOP (EXTERNAL_LSDB(ospf), rn, lsa)
		mtr_scan_external_lsa(lsa, advertised);

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++) {
		if (configured[mtid])
			grounded[mtid] = true;
		if (grounded[mtid])
			advertised[mtid] = true;
	}

	advertised[OSPF_MTR_MTID_DEFAULT] = false;
	grounded[OSPF_MTR_MTID_DEFAULT] = false;
	configured[OSPF_MTR_MTID_DEFAULT] = false;
}

/* ======================================================================
 * Route calculation
 */

/* Area state the default-topology SPF owns and MT runs must not alter. */
struct mtr_area_state {
	uint8_t transit;
	uint8_t shortcut_capability;
	int abr_count;
	int asbr_count;
	uint32_t spf_calculation;
	struct timeval ts_spf;
	bool spf_dry_run;
	bool spf_root_node;
};

static void mtr_area_save(struct ospf_area *area, struct mtr_area_state *st)
{
	st->transit = area->transit;
	st->shortcut_capability = area->shortcut_capability;
	st->abr_count = area->abr_count;
	st->asbr_count = area->asbr_count;
	st->spf_calculation = area->spf_calculation;
	st->ts_spf = area->ts_spf;
	st->spf_dry_run = area->spf_dry_run;
	st->spf_root_node = area->spf_root_node;
}

static void mtr_area_restore(struct ospf_area *area, const struct mtr_area_state *st)
{
	area->transit = st->transit;
	area->shortcut_capability = st->shortcut_capability;
	area->abr_count = st->abr_count;
	area->asbr_count = st->asbr_count;
	area->spf_calculation = st->spf_calculation;
	area->ts_spf = st->ts_spf;
	area->spf_dry_run = st->spf_dry_run;
	area->spf_root_node = st->spf_root_node;
}

static void mtr_spf_area(struct ospf_area *area, struct route_table *rt, struct route_table *rtrs)
{
	struct mtr_area_state st;

	mtr_area_save(area, &st);

	ospf_spf_calculate(area, area->router_lsa_self, rt, NULL, rtrs, false, true);
	ospf_spf_cleanup(area->spf, area->spf_vertex_list);
	area->spf = NULL;
	area->spf_vertex_list = NULL;

	mtr_area_restore(area, &st);
}

/* AS external routes for the current topology (RFC 2328 16.4). */
static void mtr_ase_calculate(struct ospf *ospf, struct route_table *rt, struct route_table *rtrs,
			      struct route_table *ext)
{
	struct ospf_area *area;
	struct listnode *node;
	struct route_node *rn;
	struct ospf_lsa *lsa;

	LSDB_LOOP (EXTERNAL_LSDB(ospf), rn, lsa)
		ospf_ase_calculate_route_tables(ospf, lsa, rt, rtrs, ext);

	if (ospf->anyNSSA)
		for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
			if (area->external_routing == OSPF_AREA_NSSA)
				LSDB_LOOP (NSSA_LSDB(area), rn, lsa)
					ospf_ase_calculate_route_tables(ospf, lsa, rt, rtrs, ext);

	LSDB_LOOP (NSSA_LSDB(ospf), rn, lsa)
		ospf_ase_calculate_route_tables(ospf, lsa, rt, rtrs, ext);
}

/* Full route calculation for one topology. */
static void mtr_calculate_topo(struct ospf *ospf, struct ospf_mtr_topo *topo)
{
	struct route_table *new_rt, *new_rtrs, *new_ext;
	struct ospf_area *area;
	struct listnode *node;
	struct timeval saved_ts_spf = ospf->ts_spf;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("MTR: calculating topology %u", topo->mtid);

	new_rt = route_table_init();
	new_rtrs = route_table_init();
	new_ext = route_table_init();

	ospf->mtr_cur_mtid = topo->mtid;

	/* Intra-area routes: backbone last, as for the default topology. */
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (area != ospf->backbone)
			mtr_spf_area(area, new_rt, new_rtrs);
	if (ospf->backbone)
		mtr_spf_area(ospf->backbone, new_rt, new_rtrs);

	/* Inter-area routes. */
	ospf_ia_routing(ospf, new_rt, new_rtrs);

	ospf_prune_unreachable_networks(new_rt);
	ospf_prune_unreachable_routers(new_rtrs);

	/* AS external routes. */
	mtr_ase_calculate(ospf, new_rt, new_rtrs, new_ext);

	ospf->mtr_cur_mtid = OSPF_MTR_MTID_DEFAULT;
	ospf->ts_spf = saved_ts_spf;

	/* Program zebra, then replace the tables. */
	mtr_install(ospf, topo, topo->rt, topo->ext, new_rt, new_ext, mtr_target_table(ospf, topo));

	ospf_mtr_topo_free_tables(topo);
	topo->rt = new_rt;
	topo->rtrs = new_rtrs;
	topo->ext = new_ext;

	topo->spf_runs++;
	monotime(&topo->ts_spf);
}

/*
 * MTR processing is enabled once any MTR configuration exists in this
 * instance.  Otherwise the router behaves as an RFC 2328 router and ignores
 * MT-ID metrics advertised by others.
 */
static bool ospf_mtr_enabled(struct ospf *ospf)
{
	struct ospf_interface *oi;
	struct listnode *node;

	if (ospf->mtr_copy_base || ospf->mtr_table_offset_configured)
		return true;

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
		if (oi->ifp && ospf_if_has_mt_cost(oi->ifp))
			return true;

	return false;
}

void ospf_mtr_calculate(struct ospf *ospf)
{
	bool advertised[OSPF_MTR_MTID_COUNT] = {};
	bool grounded[OSPF_MTR_MTID_COUNT] = {};
	bool configured[OSPF_MTR_MTID_COUNT] = {};
	struct ospf_mtr_topo *topo;
	int mtid;

	if (ospf_mtr_enabled(ospf))
		mtr_collect_topologies(ospf, advertised, grounded, configured);

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++) {
		if (!advertised[mtid]) {
			ospf_mtr_topo_delete(ospf, mtid, true);
			continue;
		}

		topo = ospf_mtr_topo_get(ospf, mtid);
		topo->advertised = advertised[mtid];
		topo->grounded = grounded[mtid];
		topo->configured = configured[mtid];
		mtr_calculate_topo(ospf, topo);
	}
}

void ospf_mtr_external_recalculate(struct ospf *ospf)
{
	struct ospf_mtr_topo *topo;
	struct route_table *new_ext;
	int mtid;

	event_cancel(&ospf->t_mtr_ext_calc);

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++) {
		topo = ospf->mtr[mtid];
		if (!topo || !topo->rt || !topo->rtrs)
			continue;

		new_ext = route_table_init();

		ospf->mtr_cur_mtid = mtid;
		mtr_ase_calculate(ospf, topo->rt, topo->rtrs, new_ext);
		ospf->mtr_cur_mtid = OSPF_MTR_MTID_DEFAULT;

		mtr_install(ospf, topo, topo->rt, topo->ext, topo->rt, new_ext,
			    mtr_target_table(ospf, topo));

		if (topo->ext)
			ospf_route_table_free(topo->ext);
		topo->ext = new_ext;
	}
}

static void ospf_mtr_external_timer(struct event *t)
{
	struct ospf *ospf = EVENT_ARG(t);

	ospf_mtr_external_recalculate(ospf);
}

void ospf_mtr_external_schedule(struct ospf *ospf)
{
	if (!ospf || !ospf_mtr_active(ospf))
		return;
	if (event_is_scheduled(ospf->t_mtr_ext_calc))
		return;

	event_add_timer_msec(master, ospf_mtr_external_timer, ospf, OSPF_MTR_EXT_CALC_DELAY,
			     &ospf->t_mtr_ext_calc);
}

void ospf_mtr_finish(struct ospf *ospf)
{
	int mtid;

	event_cancel(&ospf->t_mtr_ext_calc);

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++)
		ospf_mtr_topo_delete(ospf, mtid, !ospf->gr_info.prepare_in_progress);
}

void ospf_mtr_reinstall(struct ospf *ospf)
{
	struct ospf_mtr_topo *topo;
	int mtid;

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++) {
		topo = ospf->mtr[mtid];
		if (!topo)
			continue;
		mtr_install(ospf, topo, topo->rt, topo->ext, topo->rt, topo->ext,
			    mtr_target_table(ospf, topo));
	}
}

/* ======================================================================
 * CLI
 */

/* Re-originate the Router-LSAs of the areas `ifp` belongs to. */
static void mtr_if_update(struct interface *ifp)
{
	struct route_node *rn;
	struct ospf_interface *oi;

	if (!ifp->info)
		return;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		oi = rn->info;
		if (oi && oi->area)
			ospf_router_lsa_update_area(oi->area);
	}
}

DEFPY (ip_ospf_mt_cost,
       ip_ospf_mt_cost_cmd,
       "ip ospf mt-id (1-255)$mtid cost (1-65535)$cost",
       "IP Information\n"
       "OSPF interface commands\n"
       "Multi-topology (RFC 4915)\n"
       "MT-ID\n"
       "MT-ID specific interface cost\n"
       "Cost\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params = IF_DEF_PARAMS(ifp);

	if (!params->mt_cost)
		params->mt_cost = XCALLOC(MTYPE_OSPF_IF_PARAMS,
					  sizeof(uint16_t) * OSPF_MTR_MTID_COUNT);

	if (params->mt_cost[mtid] == cost)
		return CMD_SUCCESS;

	params->mt_cost[mtid] = cost;
	mtr_if_update(ifp);

	return CMD_SUCCESS;
}

DEFPY (no_ip_ospf_mt_cost,
       no_ip_ospf_mt_cost_cmd,
       "no ip ospf mt-id (1-255)$mtid [cost [(1-65535)]]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Multi-topology (RFC 4915)\n"
       "MT-ID\n"
       "MT-ID specific interface cost\n"
       "Cost\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params = IF_DEF_PARAMS(ifp);

	if (!params->mt_cost || !params->mt_cost[mtid])
		return CMD_SUCCESS;

	params->mt_cost[mtid] = 0;
	if (!ospf_if_has_mt_cost(ifp))
		XFREE(MTYPE_OSPF_IF_PARAMS, params->mt_cost);

	mtr_if_update(ifp);

	return CMD_SUCCESS;
}

DEFPY (ospf_mtr_copy_base,
       ospf_mtr_copy_base_cmd,
       "[no$no] mtr copy-base-topology",
       NO_STR
       "Multi-topology routing (RFC 4915)\n"
       "Links/prefixes without an MT-ID metric use the base topology metric\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	bool value = !no;

	if (ospf->mtr_copy_base == value)
		return CMD_SUCCESS;

	ospf->mtr_copy_base = value;
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);

	return CMD_SUCCESS;
}

DEFPY (ospf_mtr_table_offset,
       ospf_mtr_table_offset_cmd,
       "mtr-route-table-offset (0-4294967040)$offset",
       "Kernel routing table offset for multi-topology routes (table = offset + MT-ID)\n"
       "Offset\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (!ospf->mtr_table_offset_configured) {
		ospf->mtr_table_offset_configured = true;
		ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
	}

	if (ospf->mtr_table_offset == offset)
		return CMD_SUCCESS;

	ospf->mtr_table_offset = offset;
	ospf_mtr_reinstall(ospf);

	return CMD_SUCCESS;
}

DEFPY (no_ospf_mtr_table_offset,
       no_ospf_mtr_table_offset_cmd,
       "no mtr-route-table-offset [(0-4294967040)]",
       NO_STR
       "Kernel routing table offset for multi-topology routes (table = offset + MT-ID)\n"
       "Offset\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (ospf->mtr_table_offset_configured) {
		ospf->mtr_table_offset_configured = false;
		ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
	}

	if (ospf->mtr_table_offset == OSPF_MTR_TABLE_OFFSET_DEFAULT)
		return CMD_SUCCESS;

	ospf->mtr_table_offset = OSPF_MTR_TABLE_OFFSET_DEFAULT;
	ospf_mtr_reinstall(ospf);

	return CMD_SUCCESS;
}

void ospf_mtr_config_write_router(struct vty *vty, struct ospf *ospf)
{
	if (ospf->mtr_copy_base)
		vty_out(vty, " mtr copy-base-topology\n");
	if (ospf->mtr_table_offset_configured)
		vty_out(vty, " mtr-route-table-offset %u\n", ospf->mtr_table_offset);
}

void ospf_mtr_config_write_if(struct vty *vty, struct interface *ifp)
{
	uint16_t cost;
	int mtid;

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++)
		if (ospf_if_mt_cost_get(ifp, mtid, &cost))
			vty_out(vty, " ip ospf mt-id %d cost %u\n", mtid, cost);
}

void ospf_mtr_show_if(struct vty *vty, struct interface *ifp, json_object *json)
{
	json_object *json_mt = NULL;
	uint16_t cost;
	int mtid;
	bool first = true;

	for (mtid = OSPF_MTR_MTID_MIN; mtid <= OSPF_MTR_MTID_MAX; mtid++) {
		if (!ospf_if_mt_cost_get(ifp, mtid, &cost))
			continue;
		if (json) {
			char key[8];

			if (!json_mt)
				json_mt = json_object_new_object();
			snprintf(key, sizeof(key), "%d", mtid);
			json_object_int_add(json_mt, key, cost);
		} else {
			vty_out(vty, "%s%d:%u", first ? "  MT-ID costs: " : ", ", mtid, cost);
			first = false;
		}
	}
	if (json_mt)
		json_object_object_add(json, "mtIdCosts", json_mt);
	else if (!json && !first)
		vty_out(vty, "\n");
}

static const char *mtr_path_code(struct ospf_route *route)
{
	switch (route->path_type) {
	case OSPF_PATH_INTRA_AREA:
		return "N   ";
	case OSPF_PATH_INTER_AREA:
		return "N IA";
	case OSPF_PATH_TYPE1_EXTERNAL:
		return "N E1";
	case OSPF_PATH_TYPE2_EXTERNAL:
		return "N E2";
	default:
		return "N ? ";
	}
}

static void mtr_show_route(struct vty *vty, struct ospf *ospf, const struct prefix *p,
			   struct ospf_route *route, json_object *json_routes)
{
	struct listnode *node;
	struct ospf_path *path;
	json_object *json_route = NULL, *json_nhs = NULL, *json_nh;
	char buf[PREFIX_STRLEN];

	if (json_routes) {
		json_route = json_object_new_object();
		json_object_string_add(json_route, "routeType",
				       ospf_path_type_name(route->path_type));
		json_object_int_add(json_route, "cost", route->cost);
		if (route->path_type == OSPF_PATH_TYPE2_EXTERNAL)
			json_object_int_add(json_route, "type2cost", route->u.ext.type2_cost);
		if (route->path_type == OSPF_PATH_INTRA_AREA ||
		    route->path_type == OSPF_PATH_INTER_AREA)
			json_object_string_addf(json_route, "area", "%pI4", &route->u.std.area_id);
		json_nhs = json_object_new_array();
		json_object_object_add(json_route, "nexthops", json_nhs);
		json_object_object_add(json_routes, prefix2str(p, buf, sizeof(buf)), json_route);
	} else {
		if (route->path_type == OSPF_PATH_TYPE2_EXTERNAL)
			vty_out(vty, "%s %-18pFX [%u/%u]%s", mtr_path_code(route), p, route->cost,
				route->u.ext.type2_cost, route->u.ext.tag ? "" : "\n");
		else
			vty_out(vty, "%s %-18pFX [%u]%s", mtr_path_code(route), p, route->cost,
				route->path_type == OSPF_PATH_INTRA_AREA ||
						route->path_type == OSPF_PATH_INTER_AREA
					? ""
					: "\n");
		if (route->path_type == OSPF_PATH_INTRA_AREA ||
		    route->path_type == OSPF_PATH_INTER_AREA)
			vty_out(vty, " area: %pI4\n", &route->u.std.area_id);
		else if (route->path_type == OSPF_PATH_TYPE2_EXTERNAL && route->u.ext.tag)
			vty_out(vty, " tag: %u\n", route->u.ext.tag);
	}

	for (ALL_LIST_ELEMENTS_RO(route->paths, node, path)) {
		const char *ifname = ifindex2ifname(path->ifindex, ospf->vrf_id);

		if (json_nhs) {
			json_nh = json_object_new_object();
			if (path->nexthop.s_addr == INADDR_ANY)
				json_object_boolean_true_add(json_nh, "directlyAttached");
			else
				json_object_string_addf(json_nh, "ip", "%pI4", &path->nexthop);
			json_object_string_add(json_nh, "via", ifname);
			json_object_array_add(json_nhs, json_nh);
		} else if (path->nexthop.s_addr == INADDR_ANY)
			vty_out(vty, "%24s   directly attached to %s\n", "", ifname);
		else
			vty_out(vty, "%24s   via %pI4, %s\n", "", &path->nexthop, ifname);
	}
}

static void mtr_show_topo_routes(struct vty *vty, struct ospf *ospf, struct ospf_mtr_topo *topo,
				 json_object *json)
{
	struct route_node *rn;
	struct ospf_route *route;
	json_object *json_routes = NULL;

	if (json) {
		json_routes = json_object_new_object();
		json_object_object_add(json, "routes", json_routes);
	} else
		vty_out(vty, "\n  ============ MT-ID %u routing table ============\n", topo->mtid);

	if (topo->rt)
		for (rn = route_top(topo->rt); rn; rn = route_next(rn)) {
			route = rn->info;
			if (route && route->type == OSPF_DESTINATION_NETWORK)
				mtr_show_route(vty, ospf, &rn->p, route, json_routes);
		}

	if (topo->ext)
		for (rn = route_top(topo->ext); rn; rn = route_next(rn)) {
			route = rn->info;
			if (!route || route->type != OSPF_DESTINATION_NETWORK)
				continue;
			if (mtr_view_lookup(topo->rt, NULL, &rn->p))
				continue;
			mtr_show_route(vty, ospf, &rn->p, route, json_routes);
		}

	if (!json)
		vty_out(vty, "\n");
}

static void mtr_show_topo(struct vty *vty, struct ospf *ospf, struct ospf_mtr_topo *topo,
			  bool routes, json_object *json_topos)
{
	json_object *json = NULL;
	uint32_t table_id = ospf_mtr_table_id(ospf, topo->mtid);
	unsigned long nroutes = 0, next = 0;
	struct route_node *rn;
	char timebuf[OSPF_TIME_DUMP_SIZE];
	struct timeval now, elapsed;

	monotime(&now);
	timersub(&now, &topo->ts_spf, &elapsed);

	if (topo->rt)
		for (rn = route_top(topo->rt); rn; rn = route_next(rn))
			if (rn->info &&
			    ((struct ospf_route *)rn->info)->type == OSPF_DESTINATION_NETWORK)
				nroutes++;
	if (topo->ext)
		for (rn = route_top(topo->ext); rn; rn = route_next(rn))
			if (rn->info)
				next++;

	if (json_topos) {
		char key[8];

		json = json_object_new_object();
		snprintf(key, sizeof(key), "%u", topo->mtid);
		json_object_object_add(json_topos, key, json);
		json_object_int_add(json, "mtId", topo->mtid);
		json_object_int_add(json, "routeTable", table_id);
		json_object_boolean_add(json, "installed", topo->installed_table != 0);
		json_object_boolean_add(json, "advertised", topo->advertised);
		json_object_boolean_add(json, "configured", topo->configured);
		json_object_boolean_add(json, "inRouterLsas", topo->grounded);
		json_object_int_add(json, "spfRuns", topo->spf_runs);
		json_object_int_add(json, "intraInterAreaRoutes", nroutes);
		json_object_int_add(json, "externalRoutes", next);
	} else {
		vty_out(vty,
			" MT-ID %-3u table %-10u %-10s %s%s  SPF runs %u, last %s ago, %lu intra/inter-area, %lu external routes\n",
			topo->mtid, table_id, topo->installed_table ? "installed" : "(not inst)",
			topo->configured ? "C" : "-", topo->grounded ? "L" : "-", topo->spf_runs,
			ospf_timeval_dump(&elapsed, timebuf, sizeof(timebuf)), nroutes, next);
	}

	if (routes)
		mtr_show_topo_routes(vty, ospf, topo, json);
}

static int mtr_show_common(struct vty *vty, struct ospf *ospf, long mtid, bool routes,
			   json_object *json)
{
	json_object *json_vrf = NULL, *json_topos = NULL;
	struct ospf_mtr_topo *topo;
	int i;

	if (json) {
		json_vrf = json_object_new_object();
		json_object_object_add(json, ospf_vrf_id_to_name(ospf->vrf_id), json_vrf);
		json_object_boolean_add(json_vrf, "copyBaseTopology", ospf->mtr_copy_base);
		json_object_int_add(json_vrf, "routeTableOffset", ospf->mtr_table_offset);
		json_topos = json_object_new_object();
		json_object_object_add(json_vrf, "topologies", json_topos);
	} else {
		vty_out(vty, "\n OSPF Multi-Topology Routing (RFC 4915), VRF %s\n",
			ospf_vrf_id_to_name(ospf->vrf_id));
		vty_out(vty, " Copy base topology: %s, route table offset: %u\n",
			ospf->mtr_copy_base ? "enabled" : "disabled", ospf->mtr_table_offset);
		vty_out(vty, " Flags: C - configured locally, L - present in Router-LSA links\n\n");
	}

	for (i = OSPF_MTR_MTID_MIN; i <= OSPF_MTR_MTID_MAX; i++) {
		if (mtid && mtid != i)
			continue;
		topo = ospf->mtr[i];
		if (!topo) {
			if (mtid && !json)
				vty_out(vty, " MT-ID %ld: topology not present\n", mtid);
			continue;
		}
		mtr_show_topo(vty, ospf, topo, routes, json_topos);
	}

	return CMD_SUCCESS;
}

DEFPY (show_ip_ospf_mt,
       show_ip_ospf_mt_cmd,
       "show ip ospf [vrf NAME$vrf_name] mt-topology [(1-255)$mtid] [route$route] [json$uj]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "Multi-topology routing (RFC 4915)\n"
       "MT-ID\n"
       "Topology routing table\n"
       JSON_STR)
{
	struct ospf *ospf;
	json_object *json = NULL;

	if (vrf_name)
		ospf = ospf_lookup_by_inst_name(0, vrf_name);
	else
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	if (uj)
		json = json_object_new_object();

	if (ospf == NULL || !ospf->oi_running) {
		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty, "%% OSPF is not enabled in vrf %s\n",
				vrf_name ? vrf_name : VRF_DEFAULT_NAME);
		return CMD_SUCCESS;
	}

	mtr_show_common(vty, ospf, mtid, !!route, json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

void ospf_mtr_vty_if_init(void)
{
	install_element(INTERFACE_NODE, &ip_ospf_mt_cost_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_mt_cost_cmd);
}

void ospf_mtr_vty_init(void)
{
	install_element(OSPF_NODE, &ospf_mtr_copy_base_cmd);
	install_element(OSPF_NODE, &ospf_mtr_table_offset_cmd);
	install_element(OSPF_NODE, &no_ospf_mtr_table_offset_cmd);

	install_element(VIEW_NODE, &show_ip_ospf_mt_cmd);
}
