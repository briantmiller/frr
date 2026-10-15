// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Packet-pair link speed estimation.
 *
 * A session runs on one interface and periodically sends back-to-back
 * pairs of MTU-sized ICMP echo requests to a set of IPv4 targets supplied
 * by the daemon (OSPF neighbors, NHRP peers, ...).  The targets' IP stacks
 * echo them back; from the replies the session derives, per target:
 *
 *   - round trip time (RTT) per probe pair,
 *   - jitter (mean absolute difference between consecutive RTTs),
 *   - inter-packet delay (dispersion) between the two replies of a pair,
 *   - estimated bottleneck bandwidth = packet_bits / dispersion
 *     (median over all pairs in a sample, to reject cross-traffic noise),
 *     plus an EWMA of that across samples.
 *
 * The daemon decides, per target and per sample, how probes are sent
 * (struct pktpair_tx):
 *
 *   PKTPAIR_TX_BYPASS: the probe is written to an AF_PACKET socket with
 *     PACKET_QDISC_BYPASS set, on tx.ifindex with link-layer destination
 *     tx.lladdr.  Optional pre-built headers (tx.encap, e.g. an outer IPv4
 *     and GRE header) are prepended to the inner probe.  The frame goes
 *     straight to the driver of tx.ifindex, skipping its egress qdisc.
 *
 *   PKTPAIR_TX_STACK: the probe goes through the IP stack (raw socket with
 *     IP_HDRINCL, bound to the session interface), and therefore through
 *     every qdisc on the way.
 *
 * Replies are always received on a raw ICMP socket bound to the session
 * interface, with kernel receive timestamps (SO_TIMESTAMPNS).
 *
 * One-way measurement
 * -------------------
 * The round-trip estimate is limited by the slower of the two directions.
 * To measure each direction separately, a session also recognizes probe
 * pairs arriving from peers (accepted by ops->accept), times their arrival
 * and computes the peer -> local ("inbound") bandwidth and one-way jitter.
 * When the peer's sample ends, the result is sent back to it in a report
 * (an ICMP echo reply carrying the prober's ICMP identifier), where it
 * becomes that target's local -> peer ("outbound") result.  Both sides
 * need a session for this; a session in respond_only mode measures and
 * reports without sending probes of its own.
 */

#ifndef _FRR_PKTPAIR_H
#define _FRR_PKTPAIR_H

#include <netinet/in.h>
#include <time.h>

#include "typesafe.h"
#include "vrf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct event_loop;
struct interface;
struct json_object;
struct vty;
struct zebra_privs_t;

/*
 * Version of the probe and report payload formats.  Both carry it right
 * after the magic number; a receiver ignores messages of any other
 * version (no measurement, no report) and counts them.  Increase only for
 * incompatible format changes.
 */
#define PKTPAIR_VERSION 1

/* Configuration defaults and limits. */
#define PKTPAIR_INTERVAL_DEFAULT 60 /* seconds between samples */
#define PKTPAIR_INTERVAL_MIN	 1
#define PKTPAIR_INTERVAL_MAX	 3600
#define PKTPAIR_PROBES_DEFAULT	 10 /* packet pairs per sample */
#define PKTPAIR_PROBES_MIN	 2
#define PKTPAIR_PROBES_MAX	 64
#define PKTPAIR_DSCP_DEFAULT	 0

/* Probe sizes (IP total length of the inner probe). */
#define PKTPAIR_PKT_MIN	    128
#define PKTPAIR_PKT_MAX	    9000
#define PKTPAIR_PKT_DEFAULT 1500

/* Room for headers a daemon prepends on the bypass path. */
#define PKTPAIR_ENCAP_MAX 64

/*
 * Smoothing of per-sample estimates across samples.
 *
 * Each sample's estimate (median over its pairs) is folded into an
 * exponentially weighted moving average of the inverse bandwidth, i.e. of
 * the time per bit, which is what packet pairs actually measure.  Averaging
 * times rather than rates keeps a single too-fast outlier from dragging
 * the average up: the result is a weighted harmonic mean.
 *
 * A sustained change in link speed would only fade in slowly, so when
 * step_samples consecutive samples all deviate from the smoothed value by
 * more than step_threshold percent in the same direction, the smoothed
 * value is reset to their (harmonic) mean.  A step_threshold of 0
 * disables this.
 */
#define PKTPAIR_SMOOTH_WEIGHT_DEFAULT  25 /* % weight of a new sample */
#define PKTPAIR_SMOOTH_WEIGHT_MIN      1
#define PKTPAIR_SMOOTH_WEIGHT_MAX      100
#define PKTPAIR_STEP_THRESHOLD_DEFAULT 30 /* %, 0 = no step detection */
#define PKTPAIR_STEP_THRESHOLD_MAX     1000
#define PKTPAIR_STEP_SAMPLES_DEFAULT   2
#define PKTPAIR_STEP_SAMPLES_MIN       1
#define PKTPAIR_STEP_SAMPLES_MAX       16

struct pktpair_smooth_cfg {
	uint8_t weight;		 /* 1-100 %; 100 = latest sample only */
	uint16_t step_threshold; /* 0-1000 %                          */
	uint8_t step_samples;	 /* 1-16                              */
};

#define PKTPAIR_SMOOTH_CFG_DEFAULT                                             \
	{                                                                      \
		.weight = PKTPAIR_SMOOTH_WEIGHT_DEFAULT,                       \
		.step_threshold = PKTPAIR_STEP_THRESHOLD_DEFAULT,              \
		.step_samples = PKTPAIR_STEP_SAMPLES_DEFAULT,                  \
	}

struct pktpair_smoother {
	double inv;	     /* EWMA of 1/kbps, 0 before the first sample */
	double step_inv_sum; /* 1/kbps summed over the pending step       */
	uint8_t step_count;  /* consecutive deviating samples            */
	int8_t step_dir;     /* +1 faster, -1 slower                     */
	uint32_t resets;     /* step resets so far                       */
};

/*
 * Fold a sample (kbit/s, > 0) into sm and return the smoothed value in
 * kbit/s.
 */
extern uint64_t pktpair_smooth_update(struct pktpair_smoother *sm,
				      const struct pktpair_smooth_cfg *cfg,
				      uint64_t sample_kbps);

struct pktpair_cfg {
	uint16_t interval; /* seconds */
	uint8_t probes;	   /* pairs per sample */
	uint8_t dscp;	   /* 0-63, inner IP header */
	bool respond_only; /* measure and report peers' probes only */
	struct pktpair_smooth_cfg smooth;
};

enum pktpair_tx_mode {
	PKTPAIR_TX_STACK = 0,
	PKTPAIR_TX_BYPASS,
};

/* How probes towards one target are sent during one sample. */
struct pktpair_tx {
	enum pktpair_tx_mode mode;
	const char *path;   /* short machine-readable id, for JSON  */
	const char *reason; /* why bypass is partial/absent, or NULL */
	char desc[96];	    /* human-readable description           */

	struct in_addr src; /* inner IPv4 source address           */

	/* PKTPAIR_TX_BYPASS only. */
	ifindex_t ifindex;
	uint16_t protocol; /* ethertype, host order (ETH_P_IP)    */
	uint8_t halen;
	uint8_t lladdr[16];
	uint16_t encap_len;
	uint8_t encap[PKTPAIR_ENCAP_MAX];
};

/* Results of the most recent completed sample for one target. */
struct pktpair_stats {
	uint32_t rtt_min_usec; /* over the first packet of each pair */
	uint32_t rtt_avg_usec;
	uint32_t rtt_max_usec;
	uint32_t jitter_usec;	 /* mean |RTT(i) - RTT(i-1)|          */
	uint32_t ipd_avg_usec;	 /* mean reply dispersion             */
	uint64_t bw_kbps;	 /* median packet-pair estimate       */
	uint64_t bw_smooth_kbps; /* smoothed over samples             */
	struct pktpair_smoother smoother;
	uint16_t pkt_size;	 /* IP length of each inner probe     */
	uint16_t pairs_sent;
	uint16_t pairs_valid; /* both replies, positive gap        */
	uint16_t pkts_lost;
	struct pktpair_tx tx; /* how this sample was sent          */
	struct timeval last_update; /* monotonic */
};

/* One-way results for one direction, measured at the receiving end. */
struct pktpair_oneway {
	uint64_t bw_kbps;	 /* median over the sample's pairs   */
	uint64_t bw_smooth_kbps; /* smoothed over samples            */
	struct pktpair_smoother smoother;
	uint32_t ipd_avg_usec;	 /* mean arrival gap within pairs    */
	uint32_t jitter_usec;	 /* mean |OWD(i) - OWD(i-1)|         */
	uint16_t pkt_size;
	uint8_t npairs;	     /* pairs the sender sent            */
	uint8_t pairs_seen;  /* pairs with at least one arrival  */
	uint8_t pairs_valid; /* both arrived, positive gap       */
	uint8_t pkts_rcvd;
	uint64_t samples;
	struct timeval last_update; /* monotonic */
};

struct pktpair_pair {
	struct timespec tx[2];
	struct timespec rx[2];
	uint8_t sent; /* bitmask of packets sent    */
	uint8_t rcvd; /* bitmask of replies received */
};

PREDECL_HASH(pktpair_targets);

struct pktpair_target {
	struct pktpair_targets_item item;
	struct in_addr dst;

	/* Current sample. */
	uint32_t sample_id;
	uint8_t npairs;
	uint16_t pkt_size;
	bool seen; /* re-added by the daemon this round */
	struct pktpair_tx tx;
	struct pktpair_pair pairs[PKTPAIR_PROBES_MAX];

	/* Results. */
	uint64_t samples;
	struct pktpair_stats stats;

	/* Local -> target, as reported back by the target. */
	uint32_t outbound_sample_id;
	struct pktpair_oneway outbound;
};

struct pktpair_session;

struct pktpair_ops {
	/*
	 * Called at the start of every sample.  The daemon calls
	 * pktpair_target_add() once for every target to probe now; targets
	 * not added are dropped together with their statistics.
	 */
	void (*collect)(struct pktpair_session *s, void *arg);

	/*
	 * Choose how to reach target t during this sample.  tx is zeroed
	 * and must at least get mode and src; ip_len is the total length of
	 * the inner probe (for building encap headers).  Return false to
	 * skip the target this round.
	 */
	bool (*prepare)(struct pktpair_session *s, struct pktpair_target *t,
			struct pktpair_tx *tx, uint16_t ip_len, void *arg);

	/*
	 * Optional: whether probes arriving from src should be measured and
	 * reported (e.g. src is a neighbor on this interface).  Without it,
	 * any sender is accepted, up to a fixed number of senders.
	 */
	bool (*accept)(struct pktpair_session *s, struct in_addr src,
		       void *arg);

	/*
	 * Optional: results for peer changed (new sample, report, inbound
	 * measurement) or went away.  Use pktpair_peer_bw() for the values.
	 */
	void (*changed)(struct pktpair_session *s, struct in_addr peer,
			void *arg);

	/* Optional: return true to log debug messages. */
	bool (*debug)(void *arg);
};

/*
 * Start a session on ifp.  Returns NULL if the receive socket can't be
 * opened.  The caller must free the session before ifp goes away.
 */
extern struct pktpair_session *
pktpair_session_new(struct event_loop *loop, struct zebra_privs_t *privs,
		    struct interface *ifp, vrf_id_t vrf_id,
		    const struct pktpair_cfg *cfg,
		    const struct pktpair_ops *ops, void *arg);
extern void pktpair_session_free(struct pktpair_session **s);

/* Apply changed configuration to a running session. */
extern void pktpair_session_set_cfg(struct pktpair_session *s,
				    const struct pktpair_cfg *cfg);

/* Whether the AF_PACKET bypass socket could be opened, and if not why. */
extern bool pktpair_session_bypass_ok(const struct pktpair_session *s,
				      const char **reason);

/* A socket usable for ioctls (SIOCGARP) in the session's VRF. */
extern int pktpair_session_fd(const struct pktpair_session *s);

extern struct interface *pktpair_session_ifp(const struct pktpair_session *s);

/* For use from ops->collect only. */
extern void pktpair_target_add(struct pktpair_session *s, struct in_addr dst);

extern struct pktpair_target *
pktpair_target_lookup(struct pktpair_session *s, struct in_addr dst);

/*
 * Current smoothed bandwidths for a peer, in kbit/s, 0 when unknown or
 * when the latest sample produced no valid pairs: the round-trip estimate
 * from probing it, the outbound one-way result it reported, and the
 * inbound one-way result measured from its probes.
 */
extern void pktpair_peer_bw(struct pktpair_session *s, struct in_addr peer,
			    uint64_t *rtt_kbps, uint64_t *out_kbps,
			    uint64_t *in_kbps);

/* Call cb for every peer the session has results or state for. */
extern void pktpair_session_foreach_peer(
	struct pktpair_session *s,
	void (*cb)(struct pktpair_session *s, struct in_addr peer, void *arg),
	void *arg);

/* Peer -> local results measured from peer's probes, or NULL. */
extern const struct pktpair_oneway *
pktpair_inbound_lookup(struct pktpair_session *s, struct in_addr peer);

/*
 * Display everything known about one peer: the configuration line
 * (unless cfg is NULL), the round-trip results of probing it, the
 * outbound result it reported, and the inbound result measured from its
 * probes.  s may be NULL (session not running).  Text output starts at
 * the given indent, details are indented two more columns.  With json
 * non-NULL, keys are added to json instead ("outbound" and "inbound" as
 * nested objects).
 */
extern void pktpair_show_peer(struct vty *vty, struct json_object *json,
			      const struct pktpair_cfg *cfg,
			      struct pktpair_session *s, struct in_addr peer,
			      const char *indent);

/*
 * Session-wide information: the payload version in use and messages
 * ignored because peers use another version.  Text output is printed
 * only when there were such messages.
 */
/* The smoothing configuration, as a text line or JSON keys. */
extern void pktpair_show_smoothing(struct vty *vty, struct json_object *json,
				   const struct pktpair_smooth_cfg *smooth,
				   const char *indent);

extern void pktpair_show_session(struct vty *vty, struct json_object *json,
				 struct pktpair_session *s,
				 const char *indent);

extern const char *pktpair_speed_str(uint64_t kbps, char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_PKTPAIR_H */
