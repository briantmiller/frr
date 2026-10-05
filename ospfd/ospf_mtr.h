// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv2 Multi-Topology Routing (RFC 4915).
 *
 * The TOS fields of Router-LSAs, Summary-LSAs and AS-external-LSAs are
 * reinterpreted as MT-IDs.  A separate SPF (intra-area, inter-area and
 * external route calculation) is run for every topology that is advertised
 * in the LSDB or configured locally, and the resulting routes are installed
 * into a dedicated kernel routing table:
 *
 *      table-id = mtr-route-table-offset + MT-ID
 *
 * MT-ID 0 is the default topology and is handled by the regular OSPF code.
 */

#ifndef _ZEBRA_OSPF_MTR_H
#define _ZEBRA_OSPF_MTR_H

#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "json.h"

struct ospf;
struct ospf_area;
struct ospf_interface;
struct interface;
struct lsa_header;
struct router_lsa_link;
struct as_external_lsa;
struct as_route;

/*
 * MT-ID 0 is the default topology; 1..127 are additional topologies.
 * RFC 4915 3.7: the MT-ID space is 0-127 because AS-external-LSAs carry the
 * MT-ID in 7 bits; MT-IDs 128-255 are invalid and SHOULD be ignored.
 */
#define OSPF_MTR_MTID_DEFAULT 0
#define OSPF_MTR_MTID_MIN     1
#define OSPF_MTR_MTID_MAX     127
#define OSPF_MTR_MTID_COUNT   (OSPF_MTR_MTID_MAX + 1)

/* Is `mtid` a valid non-default MT-ID (RFC 4915 3.7)? */
#define OSPF_MTR_MTID_VALID(mtid) ((mtid) >= OSPF_MTR_MTID_MIN && (mtid) <= OSPF_MTR_MTID_MAX)

#define OSPF_MTR_TABLE_OFFSET_DEFAULT 0
#define OSPF_MTR_TABLE_OFFSET_MAX     (UINT32_MAX - OSPF_MTR_MTID_MAX)

/* One MT-ID/metric pair as carried in an LSA. */
struct ospf_mt_metric {
	uint8_t mtid;
	uint32_t metric;
};

/* Per-topology routing state. */
struct ospf_mtr_topo {
	uint8_t mtid;

	/* Intra- and inter-area routes (prefix -> struct ospf_route). */
	struct route_table *rt;
	/* ABR/ASBR routes (prefix -> list of struct ospf_route). */
	struct route_table *rtrs;
	/* AS-external routes (prefix -> struct ospf_route). */
	struct route_table *ext;

	/* Kernel table the routes above are currently installed into
	 * (0 = nothing installed).
	 */
	uint32_t installed_table;

	/* Topology was seen in the LSDB or local config on last run. */
	bool advertised;
	bool grounded; /* in a Router-LSA or configured locally */
	bool configured;

	/* Statistics. */
	uint32_t spf_runs;
	struct timeval ts_spf;
};

/* ---------------------------------------------------------------------
 * Interface configuration
 */
extern bool ospf_if_mt_cost_get(struct interface *ifp, uint8_t mtid, uint16_t *cost);
extern bool ospf_if_has_mt_cost(struct interface *ifp);

/* ---------------------------------------------------------------------
 * LSA encoding / decoding helpers
 */

/*
 * Build the list of MT-ID metrics advertised for a Router-LSA link
 * describing interface `oi`.  If `fixed` is >= 0 that metric is used for
 * every configured topology (stub-router max-metric, PtMP host routes).
 * Returns the number of entries written to `out` (ascending MT-ID order).
 */
extern int ospf_mtr_if_link_metrics(struct ospf_interface *oi, int fixed,
				    struct ospf_mt_metric *out);

/*
 * Return true if the Router-LSA link participates in topology `mtid`
 * and store its metric.  With "mtr copy-base-topology" a link lacking an
 * explicit MT-ID metric inherits its TOS 0 (base) metric.
 */
extern bool ospf_mtr_link_metric(struct ospf *ospf, const struct router_lsa_link *l, uint8_t mtid,
				 uint16_t *metric);

/*
 * Summary-LSA (type 3/4) metric for the topology currently being computed
 * (ospf->mtr_cur_mtid).  Returns false if the LSA does not belong to that
 * topology.
 */
extern bool ospf_mtr_summary_metric(struct ospf *ospf, const struct lsa_header *lsah,
				    uint32_t *metric);

/*
 * AS-external/NSSA-LSA entry for the topology currently being computed
 * (ospf->mtr_cur_mtid).  Returns NULL if the LSA does not belong to that
 * topology.
 */
extern const struct as_route *ospf_mtr_external_entry(struct ospf *ospf,
						      const struct as_external_lsa *al);

/*
 * MT-ID metrics an ABR advertises in a Summary-LSA for prefix `p` into
 * `area`, derived from the per-topology routing tables.
 */
extern int ospf_mtr_summary_metrics(struct ospf_area *area, struct prefix_ipv4 *p, bool asbr,
				    struct ospf_mt_metric *out);

/* Compare MT entries of an existing Summary-LSA with a computed set. */
extern bool ospf_mtr_summary_lsa_mt_same(const struct lsa_header *lsah,
					 const struct ospf_mt_metric *mt, int count);

/* ---------------------------------------------------------------------
 * Route calculation / installation
 */
extern void ospf_mtr_calculate(struct ospf *ospf);
extern void ospf_mtr_external_recalculate(struct ospf *ospf);
extern void ospf_mtr_external_schedule(struct ospf *ospf);
extern void ospf_mtr_finish(struct ospf *ospf);
extern void ospf_mtr_reinstall(struct ospf *ospf);
extern uint32_t ospf_mtr_table_id(struct ospf *ospf, uint8_t mtid);
extern bool ospf_mtr_active(struct ospf *ospf);

/* ---------------------------------------------------------------------
 * CLI
 */
extern void ospf_mtr_vty_init(void);
extern void ospf_mtr_vty_if_init(void);
extern void ospf_mtr_config_write_router(struct vty *vty, struct ospf *ospf);
extern void ospf_mtr_config_write_if(struct vty *vty, struct interface *ifp);
extern void ospf_mtr_show_if(struct vty *vty, struct interface *ifp, json_object *json);

#endif /* _ZEBRA_OSPF_MTR_H */
