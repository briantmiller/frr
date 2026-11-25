// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SAND v2 - Stateful Asymmetric Network Discovery
 *
 * A link-state routing protocol for networks with unidirectional links.
 * Every record has exactly one writer (its originator), and every
 * directed link is reported by its receiver.  See the SAND v2 design
 * document for the protocol specification.
 */

#ifndef _SANDD_H
#define _SANDD_H

#include <zebra.h>

#include "if.h"
#include "prefix.h"
#include "frrevent.h"
#include "typesafe.h"
#include "memory.h"
#include "privs.h"
#include "vty.h"
#include "vrf.h"
#include "nexthop.h"

DECLARE_MGROUP(SANDD);

/* ------------------------------------------------------------------ */
/* Protocol constants (design doc sections 4, 6, 12)                    */
/* ------------------------------------------------------------------ */

#define SAND_VERSION 2

#define SAND_DEFAULT_PORT  1000
#define SAND_DEFAULT_GROUP "224.0.0.69"

/* Packet types */
#define SAND_PKT_HELLO	 1
#define SAND_PKT_UPDATE	 2
#define SAND_PKT_SUMMARY 3
#define SAND_PKT_REQUEST 4

/* Record types */
#define SAND_REC_ROUTER	 1
#define SAND_REC_IFACE	 2
#define SAND_REC_PFX4	 3
#define SAND_REC_PFX6	 4
#define SAND_REC_MAX	 4

/* Record flags */
#define SAND_RFLAG_SILENT 0x01

#define SAND_HDR_LEN	   16
#define SAND_REC_HDR_LEN   20
#define SAND_KEY_LEN	   8
#define SAND_SUM_ENTRY_LEN 16
#define SAND_REQ_ENTRY_LEN 12
#define SAND_HELLO_LEN	   12
#define SAND_RTR_ENTRY_LEN 12
#define SAND_REQ_HDR_LEN   16

#define SAND_MAX_REC_LEN 1200
#define SAND_MAX_PKT	 65535

/* Timers, seconds unless noted */
#define SAND_DEFAULT_HELLO	   10
#define SAND_DEFAULT_HOLD	   40
#define SAND_DEFAULT_COST	   10
#define SAND_DEFAULT_LIFETIME	   3600
#define SAND_DEFAULT_SUMMARY	   60
#define SAND_ORIG_DELAY_MSEC	   500
#define SAND_MIN_ORIG_INTERVAL	   1
#define SAND_ZERO_AGE_HOLD	   60
#define SAND_FLOOD_DELAY_MSEC	   200
#define SAND_SPF_DELAY_MSEC	   100
#define SAND_SPF_HOLD_MSEC	   1000
#define SAND_REQ_HOPS		   8
#define SAND_REQ_DELAY_MSEC	   2000
#define SAND_REQ_MAX_ENTRIES	   100
#define SAND_REQ_MEMORY		   60
#define SAND_REQ_CACHE		   256
#define SAND_MAX_ECMP		   8
#define SAND_METRIC_THRESH_PCT	   25
#define SAND_DUPRID_LIMIT	   3
#define SAND_DUPRID_WINDOW	   300
#define SAND_MAX_IFACES		   256
#define SAND_METRIC_MAX		   65535

/* Delivery ratio is kept as fixed point, 0..SAND_RATIO_ONE */
#define SAND_RATIO_ONE 65536

/* ------------------------------------------------------------------ */
/* Records and the LSDB                                                 */
/* ------------------------------------------------------------------ */

struct sand_key {
	uint32_t orig;
	uint8_t type;
	uint16_t frag;
};

PREDECL_RBTREE_UNIQ(sand_lsdb);

struct sand_rec {
	struct sand_lsdb_item item;
	struct sand_key key;

	uint8_t flags;
	uint32_t seq;
	uint16_t cksum;
	uint16_t lifetime; /* lifetime when received/originated */
	time_t rcvd;	   /* monotime() when installed */
	time_t expired_at; /* 0 while live */

	uint8_t *data; /* whole record, network order */
	uint16_t len;

	time_t last_push; /* rate-limit for pushing our newer copy */

	bool purge;	   /* lifetime was 0: originator withdrew it */
	bool force_new;	   /* own record: originate a new version */
	time_t refresh_at; /* own record: when to refresh */
	bool placeholder;  /* own: holds a sequence floor only, never sent */
};

extern int sand_key_cmp(const struct sand_key *a, const struct sand_key *b);

static inline int sand_rec_cmp(const struct sand_rec *a,
			       const struct sand_rec *b)
{
	return sand_key_cmp(&a->key, &b->key);
}

DECLARE_RBTREE_UNIQ(sand_lsdb, struct sand_rec, item, sand_rec_cmp);

/* ------------------------------------------------------------------ */
/* Interfaces and heard links                                           */
/* ------------------------------------------------------------------ */

/* A directed link we hear: (rid, ifidx) -> (us, this interface) */
struct sand_nbr {
	struct sand_nbr *next;
	uint32_t rid;
	uint16_t ifidx;
	uint32_t boot_id;
	uint32_t last_pkt_seq;
	uint32_t ratio; /* delivery ratio, SAND_RATIO_ONE = 100% */
	uint16_t hold;	/* sender's hold time, seconds */
	uint16_t adv_metric;
	time_t last_heard;
	struct event *t_expire;
	struct sand_if *sif;
};

/* Flood queue entry: a key, looked up at send time */
struct sand_fq {
	struct sand_fq *next;
	struct sand_key key;
};

struct sand_if {
	struct interface *ifp;
	bool enabled;  /* "sand" configured */
	bool running;  /* enabled, up, has IPv4 and router is running */
	int16_t idx;   /* SAND interface index, -1 if none */
	uint16_t cost;
	uint16_t hello_interval;
	uint16_t hold_time;

	struct in_addr ipv4;
	struct in6_addr ipv6ll;

	uint32_t tx_seq;
	time_t last_tx;
	time_t last_summary_trigger;

	struct sand_nbr *nbrs;
	struct sand_fq *fq_head, *fq_tail;

	/* routers known (from their Router records) to hear this interface,
	 * refreshed by every route computation */
	uint32_t listeners[SAND_MAX_ECMP];
	uint8_t n_listeners; /* 0xff: more than fit */

	struct event *t_hello;
	struct event *t_flood;
	struct event *t_summary;

	/* stats */
	uint64_t tx_pkts, rx_pkts, tx_bytes, rx_bytes;
};

/* ------------------------------------------------------------------ */
/* Locally advertised prefixes                                          */
/* ------------------------------------------------------------------ */

#define SAND_XP_NETWORK	 0x01
#define SAND_XP_REDIST	 0x02

PREDECL_RBTREE_UNIQ(sand_xpfx);

struct sand_xpfx {
	struct sand_xpfx_item item;
	struct prefix p;
	uint16_t metric;
	uint8_t src; /* SAND_XP_* bitmask */
};

extern int sand_xpfx_cmp(const struct sand_xpfx *a, const struct sand_xpfx *b);
DECLARE_RBTREE_UNIQ(sand_xpfx, struct sand_xpfx, item, sand_xpfx_cmp);

/* ------------------------------------------------------------------ */
/* Route computation results                                            */
/* ------------------------------------------------------------------ */

/* One first hop: out our interface idx, to nbr's interface nbr_if */
struct sand_nh {
	int16_t local_if;
	uint32_t nbr;
	uint16_t nbr_if;
};

struct sand_spf_node {
	uint32_t rid;
	uint32_t cost; /* UINT32_MAX = unreachable */
	uint8_t n_nh;
	struct sand_nh nh[SAND_MAX_ECMP];
	bool live;
	bool silent;
	bool done;
};

/* Installed route, for diffing */
PREDECL_RBTREE_UNIQ(sand_rt);

struct sand_zebra_nh {
	ifindex_t ifindex;
	union g_addr gate;
	uint8_t mac[INTERFACE_HWADDR_MAX];
	uint8_t mac_len;
};

struct sand_route {
	struct sand_rt_item item;
	struct prefix p;
	uint32_t cost;
	uint8_t n_nh;
	struct sand_zebra_nh nh[SAND_MAX_ECMP];
	bool mark;
};

extern int sand_route_cmp(const struct sand_route *a,
			  const struct sand_route *b);
DECLARE_RBTREE_UNIQ(sand_rt, struct sand_route, item, sand_route_cmp);

/* Installed permanent neighbor entry */
struct sand_neigh {
	struct sand_neigh *next;
	ifindex_t ifindex;
	int family;
	union g_addr addr;
	uint8_t mac[INTERFACE_HWADDR_MAX];
	uint8_t mac_len;
	bool mark;
};

/* ------------------------------------------------------------------ */
/* The router instance                                                  */
/* ------------------------------------------------------------------ */

struct sand_reqcache {
	uint32_t requester;
	uint32_t nonce;
	time_t when;
};

struct sand {
	bool configured; /* "router sand" present */
	bool running;	 /* started (configured and has a router-id) */
	bool silent_announcing;
	uint32_t rid;
	struct in_addr rid_cfg;	   /* configured router-id, 0 if none */
	struct in_addr rid_zebra;  /* router-id from zebra */
	uint32_t boot_id;
	uint16_t lifetime;
	uint16_t summary_interval;
	uint16_t port;
	struct in_addr group;

	bool silent;
	uint16_t silent_hold;

	int sock;
	struct event *t_read;

	struct sand_lsdb_head lsdb;
	struct sand_xpfx_head xpfx;
	struct sand_rt_head routes;
	struct sand_neigh *neighs;

	struct event *t_orig;
	struct event *t_ager;
	struct event *t_spf;
	time_t last_spf_msec;
	bool orig_pending;

	/* SPF result */
	struct sand_spf_node *spf;
	size_t spf_n;

	struct sand_reqcache reqcache[SAND_REQ_CACHE];
	unsigned int reqcache_next;

	/* duplicate router-id detection */
	time_t duprid_window_start;
	unsigned int duprid_count;
	time_t duprid_block_until;

	/* stats */
	uint64_t spf_runs;
	uint64_t originations;
	uint64_t tx_type_pkts[5], tx_type_bytes[5];
};

extern struct sand *sand;
extern struct event_loop *master;
extern struct zebra_privs_t sandd_privs;

/* debug flags */
extern unsigned long sand_debug;
#define SAND_DEBUG_PACKET 0x01
#define SAND_DEBUG_FLOOD  0x02
#define SAND_DEBUG_SPF	  0x04
#define SAND_DEBUG_ZEBRA  0x08
#define SAND_DEBUG_EVENTS 0x10
#define SAND_DEBUG_ALL	  0x1f

#define SAND_DBG(flag, fmt, ...)                                               \
	do {                                                                   \
		if (sand_debug & (flag))                                       \
			zlog_debug("SAND: " fmt, ##__VA_ARGS__);               \
	} while (0)

/* ------------------------------------------------------------------ */
/* Function prototypes                                                  */
/* ------------------------------------------------------------------ */

/* sandd.c - instance */
extern void sand_init(void);
extern int sand_start(void);
extern void sand_stop(bool purge);
extern void sand_terminate(void);
extern void sand_rid_update(void);
extern void sand_set_silent(bool on, uint16_t hold);
extern uint32_t sand_load_boot_id(void);
extern const char *sand_rid2str(uint32_t rid, char *buf, size_t len);

/* sand_if.c - interfaces, sockets, heard links */
extern void sand_if_init(void);
extern struct sand_if *sand_if_get(struct interface *ifp);
extern struct sand_if *sand_if_by_idx(int idx);
extern void sand_if_update(struct interface *ifp);
extern void sand_if_update_all(void);
extern void sand_if_stop(struct sand_if *sif);
extern int sand_if_count(void);
extern int sand_sock_open(void);
extern void sand_sock_close(void);
extern void sand_if_heard(struct sand_if *sif, uint32_t rid, uint16_t ifidx,
			  uint32_t pkt_seq);
extern void sand_if_hello_rx(struct sand_if *sif, uint32_t rid, uint16_t ifidx,
			     uint32_t boot_id, uint16_t hold_ds);
extern void sand_if_trigger_summary(struct sand_if *sif);
extern void sand_if_trigger_summary_all(void);
extern uint16_t sand_nbr_metric(struct sand_nbr *n);
extern bool sand_flood_pop(struct sand_if *sif, struct sand_key *k);
extern int sand_if_config_write(struct vty *vty);

/* sand_pkt.c - encoding and I/O */
extern void sand_pkt_read(struct event *t);
extern int sand_pkt_send(struct sand_if *sif, uint8_t type,
			 const uint8_t *body, size_t blen);
extern void sand_send_hello(struct sand_if *sif);
extern size_t sand_if_payload_max(struct sand_if *sif);
extern void sand_put16(uint8_t *p, uint16_t v);
extern void sand_put32(uint8_t *p, uint32_t v);
extern uint16_t sand_get16(const uint8_t *p);
extern uint32_t sand_get32(const uint8_t *p);
extern void sand_key_put(uint8_t *p, const struct sand_key *k);
extern void sand_key_get(const uint8_t *p, struct sand_key *k);

/* sand_lsdb.c - records, origination, flooding, repair */
extern void sand_lsdb_init_all(void);
extern void sand_lsdb_flush(void);
extern struct sand_rec *sand_rec_lookup(const struct sand_key *k);
extern uint16_t sand_rec_remaining(const struct sand_rec *r);
extern bool sand_rec_usable(const struct sand_rec *r);
extern uint16_t sand_fletcher16(const uint8_t *data, size_t len);
extern void sand_rx_update(struct sand_if *sif, uint32_t sender,
			   const uint8_t *body, size_t len);
extern void sand_rx_summary(struct sand_if *sif, uint32_t sender,
			    const uint8_t *body, size_t len);
extern void sand_rx_request(struct sand_if *sif, uint32_t sender,
			    const uint8_t *body, size_t len);
extern void sand_send_summary(struct sand_if *sif);
extern void sand_flood_queue(struct sand_if *sif, const struct sand_key *k);
extern void sand_flood_all(const struct sand_key *k);
extern void sand_flood_except(const struct sand_key *k, uint32_t from);
extern void sand_flood_run(struct event *t);
extern void sand_flood_flush_all(void);
extern void sand_send_request(uint32_t target, const uint8_t *entries,
			      size_t n_entries);
extern void sand_schedule_orig(void);
extern void sand_originate_now(void);
extern void sand_purge_own(void);
extern uint32_t sand_lsdb_digest(void);
extern void sand_ager(struct event *t);
extern const char *sand_rec_type2str(uint8_t type);

/* sand_spf.c - route computation */
extern void sand_spf_schedule(void);
extern void sand_spf_run(void);
extern struct sand_spf_node *sand_spf_lookup(uint32_t rid);
extern void sand_routes_flush(void);
extern int sand_rtr_hears(uint32_t listener, uint32_t sender,
			  int16_t *sender_ifs, int max);

/* sand_zebra.c - zebra and kernel neighbor table */
extern void sand_zebra_init(void);
extern void sand_zebra_stop(void);
extern void sand_zebra_route(bool add, struct sand_route *rt);
extern void sand_zebra_redistribute(afi_t afi, int type, bool on);
extern bool sand_redist_get(afi_t afi, int type);
extern int sand_neigh_set(bool add, struct sand_neigh *n);
extern void sand_xpfx_flush(void);
extern void sand_network_set(const struct prefix *p, bool on, uint16_t metric);

/* sand_vty.c */
extern void sand_vty_init(void);

#endif /* _SANDD_H */
