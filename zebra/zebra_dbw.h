// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra detected bandwidth.
 *
 * Protocol daemons that measure bandwidth towards their neighbors (for
 * example packet-pair probing in ospfd and nhrpd) report it with
 * ZEBRA_DETECTED_BW_UPDATE, per interface and next hop.  zebra keeps the
 * values separately for every sending daemon (protocol and instance), so
 * several daemons can report for the same interface and next hop without
 * overwriting each other, and derives a per-interface bandwidth for each
 * daemon by combining that daemon's next hops on the interface according
 * to "detected-bandwidth aggregate <max|sum>".
 *
 * Per next hop, the outbound bandwidth used is the one-way measurement
 * when the daemon has one, otherwise the round-trip estimate (which is a
 * lower bound for both directions); likewise for inbound.
 */

#ifndef _ZEBRA_DBW_H
#define _ZEBRA_DBW_H

#include "hook.h"
#include "zebra/zserv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct interface;
struct zebra_if;
struct vty;
struct json_object;

enum zebra_dbw_aggregate {
	ZEBRA_DBW_AGG_MAX = 0, /* highest next hop (default) */
	ZEBRA_DBW_AGG_SUM = 1, /* sum over next hops         */
};

/* Interface bandwidth derived from one daemon's next hops. */
struct zebra_dbw_result {
	uint64_t out_kbps;
	uint64_t in_kbps;
	unsigned int nexthops;
};

extern void zebra_dbw_init(void);

/* Free all detected bandwidth state of an interface. */
extern void zebra_dbw_if_free(struct zebra_if *zif);

extern void zebra_dbw_set_aggregate(struct interface *ifp,
				    enum zebra_dbw_aggregate agg);

/*
 * Interface bandwidth as detected by daemon proto/instance on ifp.
 * Returns false if that daemon reported nothing for ifp.
 */
extern bool zebra_dbw_get(struct interface *ifp, uint8_t proto,
			  unsigned short instance,
			  struct zebra_dbw_result *res);

/*
 * Interface bandwidth as detected by any instance of daemon proto on ifp,
 * the highest one when several instances report.  Returns false if no
 * instance reported anything for ifp.
 */
extern bool zebra_dbw_get_proto(struct interface *ifp, uint8_t proto,
				struct zebra_dbw_result *res);

/*
 * Called whenever the detected bandwidth of an interface may have changed:
 * a report, a withdrawal, a daemon going away, or a new aggregate mode.
 */
DECLARE_HOOK(zebra_dbw_changed, (struct interface *ifp), (ifp));

/* Summary for "show interface". */
extern void zebra_dbw_show_if(struct vty *vty, struct interface *ifp,
			      struct json_object *json_if);

extern void zread_detected_bw(ZAPI_HANDLER_ARGS);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_DBW_H */
