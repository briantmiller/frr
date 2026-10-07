// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra DHCPv4 client ("ip address dhcp").
 *
 * A small RFC 2131 DHCP client that runs inside zebra's main event loop.
 * For every interface configured with "ip address dhcp" it:
 *
 *  - broadcasts DHCPDISCOVER / DHCPREQUEST with exponential back-off,
 *  - accepts the first DHCPOFFER and requests it,
 *  - on DHCPACK installs the leased address/prefix on the interface,
 *    a default route (route type "dhcp", distance 254) towards the
 *    offered router, and rewrites the resolver configuration with the
 *    offered DNS servers,
 *  - renews (unicast, T1) and rebinds (broadcast, T2) the lease and
 *    removes everything again when the lease expires, a DHCPNAK is
 *    received or the configuration is removed (sending DHCPRELEASE).
 *
 * Packets are sent and received through an AF_PACKET socket while the
 * interface has no usable address; renewals are unicast through a raw
 * IP socket so the kernel takes care of routing and ARP.  This keeps the
 * implementation within the capabilities zebra already holds
 * (CAP_NET_RAW / CAP_NET_ADMIN).
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/frrdistance.h"
#include "lib/frrevent.h"
#include "lib/if.h"
#include "lib/json.h"
#include "lib/lib_errors.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/monotime.h"
#include "lib/network.h"
#include "lib/prefix.h"
#include "lib/privs.h"
#include "lib/vrf.h"

#include "zebra/zebra_dhcp.h"
#include "zebra/connected.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_vrf.h"

#ifdef GNU_LINUX
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

extern struct zebra_privs_t zserv_privs;

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_DHCP_IF, "Zebra DHCP client interface");
DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_DHCP_RESOLV, "Zebra DHCP saved resolv.conf");

/* Protocol constants (RFC 2131 / RFC 2132) */
#define DHCP_SERVER_PORT     67
#define DHCP_CLIENT_PORT     68
#define DHCP_MAGIC_COOKIE    0x63825363
#define BOOTP_REQUEST	     1
#define BOOTP_REPLY	     2
#define BOOTP_FLAG_BROADCAST 0x8000
#define BOOTP_MIN_LEN	     300
#define DHCP_OPTIONS_LEN     308 /* 576 - IP(20) - UDP(8) - fixed BOOTP(240) */

#define DHCP_OPT_PAD	      0
#define DHCP_OPT_SUBNET_MASK  1
#define DHCP_OPT_ROUTER	      3
#define DHCP_OPT_DNS	      6
#define DHCP_OPT_HOSTNAME     12
#define DHCP_OPT_DOMAIN_NAME  15
#define DHCP_OPT_REQUESTED_IP 50
#define DHCP_OPT_LEASE_TIME   51
#define DHCP_OPT_OVERLOAD     52
#define DHCP_OPT_MSG_TYPE     53
#define DHCP_OPT_SERVER_ID    54
#define DHCP_OPT_PARAM_REQ    55
#define DHCP_OPT_MESSAGE      56
#define DHCP_OPT_MAX_SIZE     57
#define DHCP_OPT_T1	      58
#define DHCP_OPT_T2	      59
#define DHCP_OPT_CLIENT_ID    61
#define DHCP_OPT_END	      255

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK	     5
#define DHCPNAK	     6
#define DHCPRELEASE  7

#define DHCP_LEASE_INFINITE 0xffffffffU
#define DHCP_MAX_DNS	    8

/* Retransmission policy */
#define DHCP_BACKOFF_MIN	4  /* seconds, RFC 2131 4.1 */
#define DHCP_BACKOFF_MAX	64 /* seconds */
#define DHCP_REQUEST_RETRIES	4  /* REQUESTING -> back to INIT */
#define DHCP_REBOOT_RETRIES	2  /* INIT-REBOOT -> keep old lease */
#define DHCP_RENEW_MIN_INTERVAL 60 /* seconds, RFC 2131 4.4.5 */
#define DHCP_SOCKET_RETRY	10 /* seconds */

struct dhcp_iphdr {
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
} __attribute__((packed));

struct dhcp_udphdr {
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t check;
} __attribute__((packed));

struct dhcp_msg {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t cookie;
	uint8_t options[DHCP_OPTIONS_LEN];
} __attribute__((packed));

#define DHCP_FIXED_LEN (sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN)

struct dhcp_packet {
	struct dhcp_iphdr ip;
	struct dhcp_udphdr udp;
	struct dhcp_msg dhcp;
} __attribute__((packed));

enum dhcp_state {
	DHCP_STATE_STOPPED = 0, /* interface not operational */
	DHCP_STATE_INIT,
	DHCP_STATE_SELECTING,
	DHCP_STATE_REQUESTING,
	DHCP_STATE_REBOOTING,
	DHCP_STATE_BOUND,
	DHCP_STATE_RENEWING,
	DHCP_STATE_REBINDING,
};

static const char *const dhcp_state_names[] = {
	[DHCP_STATE_STOPPED] = "Stopped (interface down)",
	[DHCP_STATE_INIT] = "Init",
	[DHCP_STATE_SELECTING] = "Selecting",
	[DHCP_STATE_REQUESTING] = "Requesting",
	[DHCP_STATE_REBOOTING] = "Rebooting",
	[DHCP_STATE_BOUND] = "Bound",
	[DHCP_STATE_RENEWING] = "Renewing",
	[DHCP_STATE_REBINDING] = "Rebinding",
};

/* Information carried by a DHCP reply. */
struct dhcp_reply {
	uint8_t msg_type;
	struct in_addr yiaddr;
	struct in_addr server_id;
	struct in_addr mask;
	struct in_addr router;
	struct in_addr dns[DHCP_MAX_DNS];
	uint8_t dns_count;
	char domain[256];
	uint32_t lease_time;
	uint32_t t1;
	uint32_t t2;
	bool has_mask;
	bool has_router;
	bool has_lease;
	bool has_t1;
	bool has_t2;
	char message[128];
};

struct dhcp_lease {
	bool valid;
	struct in_addr addr;
	uint8_t prefixlen;
	struct in_addr router; /* 0.0.0.0 when none offered */
	struct in_addr server_id;
	struct in_addr dns[DHCP_MAX_DNS];
	uint8_t dns_count;
	char domain[256];
	uint32_t lease_time; /* seconds or DHCP_LEASE_INFINITE */
	uint32_t t1;
	uint32_t t2;
	time_t start;	 /* monotonic: when the REQUEST was sent */
	time_t obtained; /* wall clock, for display */
};

struct zebra_dhcp_if {
	struct interface *ifp;
	enum dhcp_state state;

	uint32_t xid;
	time_t xact_start; /* monotonic start of the current exchange */
	time_t req_sent;   /* monotonic time of the last REQUEST */
	unsigned int retries;

	int sock; /* AF_PACKET socket, -1 when closed */
	struct event *t_read;
	struct event *t_timer;

	/* Offer being requested (REQUESTING state) */
	struct in_addr offer_addr;
	struct in_addr offer_server;

	struct dhcp_lease lease;

	/* What is currently programmed on the system */
	bool addr_installed;
	struct prefix installed_addr;
	bool route_installed;
	struct in_addr installed_gw;
	ifindex_t installed_ifindex;
	vrf_id_t installed_vrf;
	uint32_t installed_table;

	uint16_t instance; /* route instance, unique per interface */

	/* Statistics */
	uint32_t tx_discover, tx_request, tx_release;
	uint32_t rx_offer, rx_ack, rx_nak;
	char last_nak[128];
};

/* Route instances already handed out (instance 0 is never used). */
static uint8_t dhcp_instance_map[(UINT16_MAX + 1) / 8];

/* resolv.conf ownership */
static struct {
	bool owned;	   /* we have written the file */
	bool saved_exists; /* the original file existed */
	char *saved;	   /* original contents */
	size_t saved_len;
	char last[2048]; /* contents last written by us */
} dhcp_resolv;

static void dhcp_timer_cb(struct event *ev);
static void dhcp_read_cb(struct event *ev);
static void dhcp_send_discover(struct zebra_dhcp_if *dif);
static void dhcp_send_request(struct zebra_dhcp_if *dif);
static void dhcp_enter_init(struct zebra_dhcp_if *dif, unsigned int delay_ms);
static void dhcp_dns_update(void);

#define DHCP_DEBUG(dif, fmt, ...)                                                                 \
	do {                                                                                      \
		if (IS_ZEBRA_DEBUG_DHCP)                                                          \
			zlog_debug("DHCP %s: " fmt, (dif)->ifp->name, ##__VA_ARGS__);             \
	} while (0)

bool zebra_dhcp_supported(void)
{
#ifdef GNU_LINUX
	return true;
#else
	return false;
#endif
}

static inline struct zebra_dhcp_if *dhcp_if_get(const struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	return zif ? zif->dhcp : NULL;
}

static uint16_t dhcp_instance_alloc(void)
{
	for (uint32_t i = 1; i <= UINT16_MAX; i++) {
		if (!(dhcp_instance_map[i / 8] & (1 << (i % 8)))) {
			dhcp_instance_map[i / 8] |= (1 << (i % 8));
			return i;
		}
	}
	return 0;
}

static void dhcp_instance_free(uint16_t instance)
{
	if (instance)
		dhcp_instance_map[instance / 8] &= ~(1 << (instance % 8));
}

static time_t dhcp_now(void)
{
	return monotime(NULL);
}

static void dhcp_set_state(struct zebra_dhcp_if *dif, enum dhcp_state state)
{
	if (dif->state != state)
		DHCP_DEBUG(dif, "state %s -> %s", dhcp_state_names[dif->state],
			   dhcp_state_names[state]);
	dif->state = state;
}

static void dhcp_timer_msec(struct zebra_dhcp_if *dif, long msec)
{
	event_cancel(&dif->t_timer);
	if (msec < 0)
		msec = 0;
	event_add_timer_msec(zrouter.master, dhcp_timer_cb, dif, msec, &dif->t_timer);
}

/* Exponential back-off with +/- 1 second of jitter (RFC 2131 4.1). */
static long dhcp_backoff_msec(unsigned int retries)
{
	unsigned int base = DHCP_BACKOFF_MIN;

	while (retries-- && base < DHCP_BACKOFF_MAX)
		base *= 2;
	if (base > DHCP_BACKOFF_MAX)
		base = DHCP_BACKOFF_MAX;

	return (long)base * 1000 + (long)(frr_weak_random() % 2001) - 1000;
}

static bool dhcp_if_operative(const struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	if (ifp->ifindex == IFINDEX_INTERNAL)
		return false;
	if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE))
		return false;
	if (zif && zif->shutdown == IF_ZEBRA_DATA_ON)
		return false;
	return if_is_operative(ifp);
}

/* ------------------------------------------------------------------ */
/* Lease bookkeeping                                                   */
/* ------------------------------------------------------------------ */

static bool dhcp_lease_finite(const struct dhcp_lease *l)
{
	return l->lease_time != DHCP_LEASE_INFINITE;
}

static time_t dhcp_lease_t1(const struct dhcp_lease *l)
{
	return l->start + l->t1;
}

static time_t dhcp_lease_t2(const struct dhcp_lease *l)
{
	return l->start + l->t2;
}

static time_t dhcp_lease_expiry(const struct dhcp_lease *l)
{
	return l->start + l->lease_time;
}

static bool dhcp_lease_expired(const struct dhcp_lease *l)
{
	if (!l->valid)
		return true;
	if (!dhcp_lease_finite(l))
		return false;
	return dhcp_now() >= dhcp_lease_expiry(l);
}

static void dhcp_addr_install(struct zebra_dhcp_if *dif, struct prefix *p)
{
	struct interface *ifp = dif->ifp;
	struct connected *ifc;

	ifc = connected_check_ptp(ifp, p, NULL);
	if (ifc && CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED)) {
		/* Statically configured as well: leave it alone. */
		DHCP_DEBUG(dif, "address %pFX already configured", p);
		return;
	}

	if (ifc && CHECK_FLAG(ifc->conf, ZEBRA_IFC_REAL)) {
		/*
		 * Already present in the kernel (e.g. left over by a
		 * previous zebra run): adopt it instead of re-adding it.
		 */
		SET_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED);
		SET_FLAG(ifc->conf, ZEBRA_IFC_QUEUED);
	} else {
		if_ip_address_install(ifp, p, NULL, NULL);
	}

	dif->addr_installed = true;
	prefix_copy(&dif->installed_addr, p);
	DHCP_DEBUG(dif, "installed address %pFX", p);
}

static void dhcp_addr_uninstall(struct zebra_dhcp_if *dif)
{
	struct interface *ifp = dif->ifp;
	struct connected *ifc;

	if (!dif->addr_installed)
		return;

	dif->addr_installed = false;
	ifc = connected_check_ptp(ifp, &dif->installed_addr, NULL);
	if (ifc && CHECK_FLAG(ifc->conf, ZEBRA_IFC_CONFIGURED))
		if_ip_address_uninstall(ifp, &dif->installed_addr, NULL);

	DHCP_DEBUG(dif, "removed address %pFX", &dif->installed_addr);
}

static void dhcp_route_uninstall(struct zebra_dhcp_if *dif)
{
	struct prefix p = { .family = AF_INET, .prefixlen = 0 };

	if (!dif->route_installed)
		return;

	dif->route_installed = false;
	rib_delete(AFI_IP, SAFI_UNICAST, dif->installed_vrf, ZEBRA_ROUTE_DHCP, dif->instance, 0,
		   &p, NULL, NULL, 0, dif->installed_table, 0, ZEBRA_DHCP_DISTANCE_DEFAULT, false);

	DHCP_DEBUG(dif, "removed default route via %pI4", &dif->installed_gw);
}

static void dhcp_route_install(struct zebra_dhcp_if *dif)
{
	struct interface *ifp = dif->ifp;
	struct zebra_vrf *zvrf = ifp->vrf->info;
	struct prefix p = { .family = AF_INET, .prefixlen = 0 };
	struct prefix gw = { .family = AF_INET, .prefixlen = IPV4_MAX_BITLEN };
	struct prefix subnet = { .family = AF_INET };
	struct nexthop nh = {};

	if (!zvrf || !dif->lease.router.s_addr)
		return;

	nh.type = NEXTHOP_TYPE_IPV4_IFINDEX;
	nh.gate.ipv4 = dif->lease.router;
	nh.ifindex = ifp->ifindex;
	nh.vrf_id = ifp->vrf->vrf_id;

	/*
	 * A router outside of the leased subnet is legal (RFC 2132 only says
	 * routers "should" be on the client's subnet); reach it on-link.
	 */
	gw.u.prefix4 = dif->lease.router;
	subnet.u.prefix4 = dif->lease.addr;
	subnet.prefixlen = dif->lease.prefixlen;
	if (!prefix_match(&subnet, &gw))
		SET_FLAG(nh.flags, NEXTHOP_FLAG_ONLINK);

	rib_add(AFI_IP, SAFI_UNICAST, ifp->vrf->vrf_id, ZEBRA_ROUTE_DHCP, dif->instance, 0, &p,
		NULL, &nh, 0, zvrf->table_id, 0, 0, ZEBRA_DHCP_DISTANCE_DEFAULT, 0, false, false);

	dif->route_installed = true;
	dif->installed_gw = dif->lease.router;
	dif->installed_ifindex = ifp->ifindex;
	dif->installed_vrf = ifp->vrf->vrf_id;
	dif->installed_table = zvrf->table_id;

	DHCP_DEBUG(dif, "installed default route via %pI4", &dif->lease.router);
}

/* Remove everything a lease programmed and forget the lease. */
static void dhcp_lease_drop(struct zebra_dhcp_if *dif, const char *reason)
{
	if (dif->lease.valid)
		zlog_info("DHCP %s: lease for %pI4/%u released (%s)", dif->ifp->name,
			  &dif->lease.addr, dif->lease.prefixlen, reason);

	dhcp_route_uninstall(dif);
	dhcp_addr_uninstall(dif);
	memset(&dif->lease, 0, sizeof(dif->lease));
	dhcp_dns_update();
}

/* ------------------------------------------------------------------ */
/* Resolver configuration                                              */
/* ------------------------------------------------------------------ */

#define DHCP_RESOLV_HEADER "# Generated by FRR zebra DHCP client (ip address dhcp).\n"
#define DHCP_RESOLV_BACKUP ZEBRA_DHCP_RESOLV_CONF ".frr-dhcp-orig"

/* Read a whole (small) file.  Returns false if it cannot be opened. */
static bool dhcp_file_read(const char *path, char **data, size_t *len)
{
	FILE *fp;
	char buf[4096];
	size_t n;

	*data = NULL;
	*len = 0;

	frr_with_privs (&zserv_privs) {
		fp = fopen(path, "r");
	}
	if (!fp)
		return false;

	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0 && *len < 65536) {
		*data = XREALLOC(MTYPE_ZEBRA_DHCP_RESOLV, *data, *len + n);
		memcpy(*data + *len, buf, n);
		*len += n;
	}
	fclose(fp);
	return true;
}

static bool dhcp_file_write(const char *path, const char *data, size_t len)
{
	FILE *fp;
	bool ok = false;

	frr_with_privs (&zserv_privs) {
		fp = fopen(path, "w");
		if (fp) {
			ok = (fwrite(data, 1, len, fp) == len);
			if (fclose(fp) != 0)
				ok = false;
		}
	}

	if (!ok)
		flog_err_sys(EC_LIB_SYSTEM_CALL, "DHCP: unable to write %s: %s", path,
			     safe_strerror(errno));
	return ok;
}

static bool dhcp_resolv_is_ours(const char *data, size_t len)
{
	size_t hlen = strlen(DHCP_RESOLV_HEADER);

	return data && len >= hlen && memcmp(data, DHCP_RESOLV_HEADER, hlen) == 0;
}

/*
 * Remember the resolver configuration that was in place before we took
 * it over.  A copy is kept on disk so that it can still be restored after
 * zebra has been restarted while it owned the file.
 */
static void dhcp_resolv_save(void)
{
	char *data, *backup;
	size_t len, blen;

	XFREE(MTYPE_ZEBRA_DHCP_RESOLV, dhcp_resolv.saved);
	dhcp_resolv.saved_len = 0;
	dhcp_resolv.saved_exists = dhcp_file_read(ZEBRA_DHCP_RESOLV_CONF, &data, &len);

	if (dhcp_resolv_is_ours(data, len)) {
		/* Written by a previous zebra instance: use its backup. */
		XFREE(MTYPE_ZEBRA_DHCP_RESOLV, data);
		if (dhcp_file_read(DHCP_RESOLV_BACKUP, &backup, &blen)) {
			dhcp_resolv.saved = backup;
			dhcp_resolv.saved_len = blen;
		} else {
			dhcp_resolv.saved_exists = false;
		}
		return;
	}

	dhcp_resolv.saved = data;
	dhcp_resolv.saved_len = len;
	if (dhcp_resolv.saved_exists)
		dhcp_file_write(DHCP_RESOLV_BACKUP, data ? data : "", len);
}

static bool dhcp_resolv_write(const char *data, size_t len)
{
	return dhcp_file_write(ZEBRA_DHCP_RESOLV_CONF, data, len);
}

static void dhcp_resolv_restore(void)
{
	if (!dhcp_resolv.owned)
		return;

	if (dhcp_resolv.saved_exists)
		dhcp_resolv_write(dhcp_resolv.saved ? dhcp_resolv.saved : "",
				  dhcp_resolv.saved_len);
	else
		frr_with_privs (&zserv_privs) {
			unlink(ZEBRA_DHCP_RESOLV_CONF);
		}
	frr_with_privs (&zserv_privs) {
		unlink(DHCP_RESOLV_BACKUP);
	}

	XFREE(MTYPE_ZEBRA_DHCP_RESOLV, dhcp_resolv.saved);
	dhcp_resolv.saved_len = 0;
	dhcp_resolv.owned = false;
	dhcp_resolv.last[0] = '\0';
	zlog_info("DHCP: restored original %s", ZEBRA_DHCP_RESOLV_CONF);
}

static bool dhcp_if_has_lease(const struct zebra_dhcp_if *dif)
{
	return dif->lease.valid && dif->addr_installed;
}

/*
 * Rebuild the resolver configuration from the DNS servers of every bound
 * interface in the default VRF (the system resolver is not VRF aware).
 */
static void dhcp_dns_update(void)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	struct in_addr servers[DHCP_MAX_DNS * 2];
	unsigned int nservers = 0;
	char search[512] = "";
	char buf[sizeof(dhcp_resolv.last)];
	int len;

	if (!vrf)
		return;

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct zebra_dhcp_if *dif = dhcp_if_get(ifp);

		if (!dif || !dhcp_if_has_lease(dif))
			continue;

		for (unsigned int i = 0; i < dif->lease.dns_count; i++) {
			unsigned int j;

			for (j = 0; j < nservers; j++)
				if (servers[j].s_addr == dif->lease.dns[i].s_addr)
					break;
			if (j == nservers && nservers < array_size(servers))
				servers[nservers++] = dif->lease.dns[i];
		}
		if (dif->lease.domain[0] && dif->lease.dns_count &&
		    !strstr(search, dif->lease.domain)) {
			if (search[0])
				strlcat(search, " ", sizeof(search));
			strlcat(search, dif->lease.domain, sizeof(search));
		}
	}

	if (!nservers) {
		dhcp_resolv_restore();
		return;
	}

	len = snprintf(buf, sizeof(buf),
		       DHCP_RESOLV_HEADER "# Changes to this file will be overwritten.\n");
	if (search[0])
		len += snprintf(buf + len, sizeof(buf) - len, "search %s\n", search);
	for (unsigned int i = 0; i < nservers && (size_t)len < sizeof(buf); i++)
		len += snprintfrr(buf + len, sizeof(buf) - len, "nameserver %pI4\n", &servers[i]);
	if ((size_t)len >= sizeof(buf))
		len = sizeof(buf) - 1;

	if (dhcp_resolv.owned && strcmp(buf, dhcp_resolv.last) == 0)
		return;

	if (!dhcp_resolv.owned)
		dhcp_resolv_save();

	if (dhcp_resolv_write(buf, len)) {
		dhcp_resolv.owned = true;
		strlcpy(dhcp_resolv.last, buf, sizeof(dhcp_resolv.last));
		zlog_info("DHCP: updated %s with %u DNS server(s)", ZEBRA_DHCP_RESOLV_CONF,
			  nservers);
	}
}

/* ------------------------------------------------------------------ */
/* Packet I/O                                                          */
/* ------------------------------------------------------------------ */

static uint32_t dhcp_csum_add(uint32_t sum, const void *data, size_t len)
{
	const uint8_t *p = data;

	while (len > 1) {
		sum += (uint32_t)(p[0] << 8 | p[1]);
		p += 2;
		len -= 2;
	}
	if (len)
		sum += (uint32_t)(p[0] << 8);
	return sum;
}

static uint16_t dhcp_csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons((uint16_t)~sum);
}

static void dhcp_sock_close(struct zebra_dhcp_if *dif)
{
	event_cancel(&dif->t_read);
	if (dif->sock >= 0) {
		close(dif->sock);
		dif->sock = -1;
	}
}

static int dhcp_sock_open(struct zebra_dhcp_if *dif)
{
#ifdef GNU_LINUX
	struct interface *ifp = dif->ifp;
	struct sockaddr_ll sll = {};
	/* Accept only unfragmented UDP datagrams to port 68. */
	struct sock_filter code[] = {
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 6),
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 6),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x1fff, 4, 0),
		BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
		BPF_STMT(BPF_LD | BPF_H | BPF_IND, 2),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, DHCP_CLIENT_PORT, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0x0fffffff),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	struct sock_fprog prog = {
		.len = array_size(code),
		.filter = code,
	};
	int fd;

	if (dif->sock >= 0)
		return 0;

	frr_with_privs (&zserv_privs) {
		fd = vrf_socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP), ifp->vrf->vrf_id,
				ifp->name);
	}
	if (fd < 0) {
		flog_err_sys(EC_LIB_SOCKET, "DHCP %s: cannot open packet socket: %s", ifp->name,
			     safe_strerror(errno));
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
		zlog_warn("DHCP %s: cannot attach socket filter: %s", ifp->name,
			  safe_strerror(errno));

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = ifp->ifindex;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		flog_err_sys(EC_LIB_SOCKET, "DHCP %s: cannot bind socket: %s", ifp->name,
			     safe_strerror(errno));
		close(fd);
		return -1;
	}

	set_nonblocking(fd);
	dif->sock = fd;
	event_add_read(zrouter.master, dhcp_read_cb, dif, fd, &dif->t_read);
	return 0;
#else
	return -1;
#endif
}

/* Build the UDP/IP headers in front of a DHCP message. */
static size_t dhcp_packet_finish(struct dhcp_packet *pkt, size_t dhcp_len, struct in_addr src,
				 struct in_addr dst)
{
	size_t udp_len = sizeof(pkt->udp) + dhcp_len;
	size_t tot_len = sizeof(pkt->ip) + udp_len;
	uint32_t sum;

	pkt->ip.ver_ihl = 0x45;
	pkt->ip.tos = 0;
	pkt->ip.tot_len = htons(tot_len);
	pkt->ip.id = 0;
	pkt->ip.frag_off = 0;
	pkt->ip.ttl = 64;
	pkt->ip.protocol = IPPROTO_UDP;
	pkt->ip.check = 0;
	pkt->ip.saddr = src.s_addr;
	pkt->ip.daddr = dst.s_addr;
	pkt->ip.check = dhcp_csum_fold(dhcp_csum_add(0, &pkt->ip, sizeof(pkt->ip)));

	pkt->udp.sport = htons(DHCP_CLIENT_PORT);
	pkt->udp.dport = htons(DHCP_SERVER_PORT);
	pkt->udp.len = htons(udp_len);
	pkt->udp.check = 0;

	/* UDP checksum over the pseudo header + UDP header + payload */
	sum = dhcp_csum_add(0, &pkt->ip.saddr, 8);
	sum += IPPROTO_UDP;
	sum += udp_len;
	sum = dhcp_csum_add(sum, &pkt->udp, udp_len);
	pkt->udp.check = dhcp_csum_fold(sum);
	if (pkt->udp.check == 0)
		pkt->udp.check = 0xffff;

	return tot_len;
}

static int dhcp_send_broadcast(struct zebra_dhcp_if *dif, struct dhcp_packet *pkt, size_t dhcp_len,
			       struct in_addr src)
{
#ifdef GNU_LINUX
	struct interface *ifp = dif->ifp;
	struct sockaddr_ll sll = {};
	struct in_addr bcast = { .s_addr = INADDR_BROADCAST };
	size_t len;

	if (dhcp_sock_open(dif) < 0)
		return -1;

	len = dhcp_packet_finish(pkt, dhcp_len, src, bcast);

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = ifp->ifindex;
	if (ifp->hw_addr_len > 0 && ifp->hw_addr_len <= (int)sizeof(sll.sll_addr)) {
		sll.sll_halen = ifp->hw_addr_len;
		memset(sll.sll_addr, 0xff, ifp->hw_addr_len);
	}

	if (sendto(dif->sock, pkt, len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		zlog_warn("DHCP %s: send failed: %s", ifp->name, safe_strerror(errno));
		return -1;
	}
	return 0;
#else
	return -1;
#endif
}

/* Unicast through the IP stack (kernel routes and resolves ARP). */
static int dhcp_send_unicast(struct zebra_dhcp_if *dif, struct dhcp_packet *pkt, size_t dhcp_len,
			     struct in_addr src, struct in_addr dst)
{
	struct interface *ifp = dif->ifp;
	struct sockaddr_in sin = {};
	size_t len;
	int fd, ret;

	frr_with_privs (&zserv_privs) {
		fd = vrf_socket(AF_INET, SOCK_RAW, IPPROTO_RAW, ifp->vrf->vrf_id, ifp->name);
	}
	if (fd < 0) {
		zlog_warn("DHCP %s: cannot open raw socket: %s", ifp->name, safe_strerror(errno));
		return -1;
	}

	len = dhcp_packet_finish(pkt, dhcp_len, src, dst);
	sin.sin_family = AF_INET;
	sin.sin_addr = dst;
	ret = sendto(fd, pkt, len, 0, (struct sockaddr *)&sin, sizeof(sin));
	if (ret < 0)
		zlog_warn("DHCP %s: unicast to %pI4 failed: %s", ifp->name, &dst,
			  safe_strerror(errno));
	close(fd);
	return ret < 0 ? -1 : 0;
}

static uint8_t *dhcp_opt_put(uint8_t *p, const uint8_t *end, uint8_t code, uint8_t len,
			     const void *data)
{
	if (p + 2 + len >= end) /* keep room for the END option */
		return p;
	*p++ = code;
	*p++ = len;
	memcpy(p, data, len);
	return p + len;
}

/*
 * Fill in a DHCP message.  Returns the length of the BOOTP payload.
 */
static size_t dhcp_build_msg(struct zebra_dhcp_if *dif, struct dhcp_msg *m, uint8_t type,
			     struct in_addr ciaddr, const struct in_addr *requested,
			     const struct in_addr *server_id)
{
	struct interface *ifp = dif->ifp;
	uint8_t *p = m->options;
	const uint8_t *end = m->options + sizeof(m->options);
	time_t elapsed = dhcp_now() - dif->xact_start;
	uint8_t client_id[1 + INTERFACE_HWADDR_MAX];
	uint8_t client_id_len;
	const char *hostname;
	size_t len;

	memset(m, 0, sizeof(*m));
	m->op = BOOTP_REQUEST;
	if (ifp->hw_addr_len == ETH_ALEN) {
		m->htype = 1; /* Ethernet */
		m->hlen = ETH_ALEN;
		memcpy(m->chaddr, ifp->hw_addr, ETH_ALEN);
	} else {
		/* No usable link-layer address: ask for broadcast replies. */
		m->flags = htons(BOOTP_FLAG_BROADCAST);
	}
	m->xid = dif->xid;
	m->secs = htons(elapsed > UINT16_MAX ? UINT16_MAX : (uint16_t)elapsed);
	m->ciaddr = ciaddr.s_addr;
	m->cookie = htonl(DHCP_MAGIC_COOKIE);

	p = dhcp_opt_put(p, end, DHCP_OPT_MSG_TYPE, 1, &type);

	/* Client identifier (RFC 2132 9.14) */
	if (ifp->hw_addr_len == ETH_ALEN) {
		client_id[0] = 1;
		memcpy(client_id + 1, ifp->hw_addr, ETH_ALEN);
		client_id_len = 1 + ETH_ALEN;
	} else {
		client_id[0] = 0;
		client_id_len = 1 +
				strlcpy((char *)client_id + 1, ifp->name, sizeof(client_id) - 1);
		if (client_id_len > sizeof(client_id))
			client_id_len = sizeof(client_id);
	}
	p = dhcp_opt_put(p, end, DHCP_OPT_CLIENT_ID, client_id_len, client_id);

	if (requested)
		p = dhcp_opt_put(p, end, DHCP_OPT_REQUESTED_IP, 4, requested);
	if (server_id)
		p = dhcp_opt_put(p, end, DHCP_OPT_SERVER_ID, 4, server_id);

	if (type == DHCPDISCOVER || type == DHCPREQUEST) {
		static const uint8_t prl[] = {
			DHCP_OPT_SUBNET_MASK, DHCP_OPT_ROUTER, DHCP_OPT_DNS, DHCP_OPT_DOMAIN_NAME,
			DHCP_OPT_LEASE_TIME,  DHCP_OPT_T1,     DHCP_OPT_T2,
		};
		uint16_t maxsize;
		unsigned int mtu = ifp->mtu ? ifp->mtu : 576;

		if (mtu > 1500)
			mtu = 1500;
		if (mtu < 576)
			mtu = 576;
		maxsize = htons(mtu);
		p = dhcp_opt_put(p, end, DHCP_OPT_MAX_SIZE, 2, &maxsize);
		p = dhcp_opt_put(p, end, DHCP_OPT_PARAM_REQ, sizeof(prl), prl);

		hostname = cmd_hostname_get();
		if (hostname && hostname[0]) {
			size_t hlen = strlen(hostname);

			if (hlen > 63)
				hlen = 63;
			p = dhcp_opt_put(p, end, DHCP_OPT_HOSTNAME, hlen, hostname);
		}
	}

	*p++ = DHCP_OPT_END;

	len = DHCP_FIXED_LEN + (size_t)(p - m->options);
	if (len < BOOTP_MIN_LEN)
		len = BOOTP_MIN_LEN; /* already zero padded */
	return len;
}

static void dhcp_new_xid(struct zebra_dhcp_if *dif)
{
	dif->xid = (uint32_t)frr_weak_random();
	dif->xact_start = dhcp_now();
	dif->retries = 0;
}

static void dhcp_send_discover(struct zebra_dhcp_if *dif)
{
	struct dhcp_packet pkt;
	struct in_addr any = {};
	size_t len;

	len = dhcp_build_msg(dif, &pkt.dhcp, DHCPDISCOVER, any, NULL, NULL);
	DHCP_DEBUG(dif, "sending DHCPDISCOVER xid 0x%08x", ntohl(dif->xid));
	if (dhcp_send_broadcast(dif, &pkt, len, any) == 0)
		dif->tx_discover++;
}

/* Send a DHCPREQUEST appropriate for the current state. */
static void dhcp_send_request(struct zebra_dhcp_if *dif)
{
	struct dhcp_packet pkt;
	struct in_addr any = {};
	size_t len;
	int ret;

	switch (dif->state) {
	case DHCP_STATE_REQUESTING:
		len = dhcp_build_msg(dif, &pkt.dhcp, DHCPREQUEST, any, &dif->offer_addr,
				     &dif->offer_server);
		ret = dhcp_send_broadcast(dif, &pkt, len, any);
		break;
	case DHCP_STATE_REBOOTING:
		len = dhcp_build_msg(dif, &pkt.dhcp, DHCPREQUEST, any, &dif->lease.addr, NULL);
		ret = dhcp_send_broadcast(dif, &pkt, len, any);
		break;
	case DHCP_STATE_RENEWING:
		len = dhcp_build_msg(dif, &pkt.dhcp, DHCPREQUEST, dif->lease.addr, NULL, NULL);
		ret = dhcp_send_unicast(dif, &pkt, len, dif->lease.addr, dif->lease.server_id);
		break;
	case DHCP_STATE_REBINDING:
		len = dhcp_build_msg(dif, &pkt.dhcp, DHCPREQUEST, dif->lease.addr, NULL, NULL);
		ret = dhcp_send_broadcast(dif, &pkt, len, dif->lease.addr);
		break;
	case DHCP_STATE_STOPPED:
	case DHCP_STATE_INIT:
	case DHCP_STATE_SELECTING:
	case DHCP_STATE_BOUND:
	default:
		return;
	}

	DHCP_DEBUG(dif, "sending DHCPREQUEST (%s) xid 0x%08x", dhcp_state_names[dif->state],
		   ntohl(dif->xid));
	if (ret == 0) {
		dif->tx_request++;
		if (dif->retries == 0)
			dif->req_sent = dhcp_now();
	}
}

static void dhcp_send_release(struct zebra_dhcp_if *dif)
{
	struct dhcp_packet pkt;
	size_t len;

	if (!dif->lease.valid || !dif->lease.server_id.s_addr || !dhcp_if_operative(dif->ifp))
		return;

	dhcp_new_xid(dif);
	len = dhcp_build_msg(dif, &pkt.dhcp, DHCPRELEASE, dif->lease.addr, NULL,
			     &dif->lease.server_id);
	DHCP_DEBUG(dif, "sending DHCPRELEASE for %pI4 to %pI4", &dif->lease.addr,
		   &dif->lease.server_id);
	if (dhcp_send_unicast(dif, &pkt, len, dif->lease.addr, dif->lease.server_id) == 0)
		dif->tx_release++;
}

/* ------------------------------------------------------------------ */
/* Reply parsing                                                       */
/* ------------------------------------------------------------------ */

static void dhcp_copy_domain(char *dst, size_t dstlen, const uint8_t *src, size_t len)
{
	size_t j = 0;

	/* Keep only characters that are valid in a resolv.conf domain. */
	for (size_t i = 0; i < len && j + 1 < dstlen; i++) {
		char c = (char)src[i];

		if (isalnum((unsigned char)c) || c == '-' || c == '.' || c == '_')
			dst[j++] = c;
		else if (c == ' ' && j > 0 && dst[j - 1] != ' ')
			dst[j++] = ' ';
		else if (c == '\0')
			break;
	}
	while (j > 0 && (dst[j - 1] == ' ' || dst[j - 1] == '.'))
		j--;
	dst[j] = '\0';
}

/* Returns the option-overload value seen, or -1 on malformed options. */
static int dhcp_parse_options(const uint8_t *p, size_t len, struct dhcp_reply *r)
{
	const uint8_t *end = p + len;
	int overload = 0;

	while (p < end) {
		uint8_t code = *p++;
		uint8_t olen;

		if (code == DHCP_OPT_PAD)
			continue;
		if (code == DHCP_OPT_END)
			break;
		if (p >= end)
			return -1;
		olen = *p++;
		if (p + olen > end)
			return -1;

		switch (code) {
		case DHCP_OPT_MSG_TYPE:
			if (olen >= 1)
				r->msg_type = p[0];
			break;
		case DHCP_OPT_SERVER_ID:
			if (olen >= 4)
				memcpy(&r->server_id, p, 4);
			break;
		case DHCP_OPT_SUBNET_MASK:
			if (olen >= 4) {
				memcpy(&r->mask, p, 4);
				r->has_mask = true;
			}
			break;
		case DHCP_OPT_ROUTER:
			if (olen >= 4 && !r->has_router) {
				memcpy(&r->router, p, 4);
				r->has_router = true;
			}
			break;
		case DHCP_OPT_DNS:
			for (unsigned int i = 0; i + 4 <= olen && r->dns_count < DHCP_MAX_DNS;
			     i += 4)
				memcpy(&r->dns[r->dns_count++], p + i, 4);
			break;
		case DHCP_OPT_DOMAIN_NAME:
			dhcp_copy_domain(r->domain, sizeof(r->domain), p, olen);
			break;
		case DHCP_OPT_LEASE_TIME:
			if (olen >= 4) {
				memcpy(&r->lease_time, p, 4);
				r->lease_time = ntohl(r->lease_time);
				r->has_lease = true;
			}
			break;
		case DHCP_OPT_T1:
			if (olen >= 4) {
				memcpy(&r->t1, p, 4);
				r->t1 = ntohl(r->t1);
				r->has_t1 = true;
			}
			break;
		case DHCP_OPT_T2:
			if (olen >= 4) {
				memcpy(&r->t2, p, 4);
				r->t2 = ntohl(r->t2);
				r->has_t2 = true;
			}
			break;
		case DHCP_OPT_OVERLOAD:
			if (olen >= 1)
				overload = p[0];
			break;
		case DHCP_OPT_MESSAGE: {
			size_t n = MIN((size_t)olen, sizeof(r->message) - 1);

			for (size_t i = 0; i < n; i++)
				r->message[i] = isprint(p[i]) ? (char)p[i] : '.';
			r->message[n] = '\0';
			break;
		}
		default:
			break;
		}
		p += olen;
	}

	return overload;
}

/*
 * Validate a received IPv4/UDP/BOOTP datagram for this interface and
 * extract the DHCP reply.  Returns false if the packet is not for us.
 */
static bool dhcp_parse_packet(struct zebra_dhcp_if *dif, const uint8_t *buf, size_t len,
			      struct dhcp_reply *r)
{
	const struct dhcp_iphdr *ip = (const struct dhcp_iphdr *)buf;
	const struct dhcp_udphdr *udp;
	const struct dhcp_msg *m;
	size_t ihl, tot_len, udp_len, dhcp_len;
	int overload;

	if (len < sizeof(*ip))
		return false;
	if ((ip->ver_ihl >> 4) != 4)
		return false;
	ihl = (size_t)(ip->ver_ihl & 0x0f) * 4;
	tot_len = ntohs(ip->tot_len);
	if (ihl < sizeof(*ip) || tot_len < ihl || tot_len > len)
		return false;
	if (ip->protocol != IPPROTO_UDP)
		return false;
	if (ntohs(ip->frag_off) & 0x3fff)
		return false;
	if (dhcp_csum_fold(dhcp_csum_add(0, buf, ihl)) != 0)
		return false;

	if (tot_len - ihl < sizeof(*udp))
		return false;
	udp = (const struct dhcp_udphdr *)(buf + ihl);
	if (ntohs(udp->dport) != DHCP_CLIENT_PORT || ntohs(udp->sport) != DHCP_SERVER_PORT)
		return false;
	udp_len = ntohs(udp->len);
	if (udp_len < sizeof(*udp) || udp_len > tot_len - ihl)
		return false;

	/*
	 * The UDP checksum is not verified: with checksum offload on virtual
	 * interfaces it is frequently not filled in yet when the frame
	 * reaches a packet socket.
	 */

	dhcp_len = udp_len - sizeof(*udp);
	if (dhcp_len < DHCP_FIXED_LEN)
		return false;
	m = (const struct dhcp_msg *)((const uint8_t *)udp + sizeof(*udp));

	if (m->op != BOOTP_REPLY || m->xid != dif->xid || ntohl(m->cookie) != DHCP_MAGIC_COOKIE)
		return false;
	if (dif->ifp->hw_addr_len == ETH_ALEN &&
	    (m->hlen != ETH_ALEN || memcmp(m->chaddr, dif->ifp->hw_addr, ETH_ALEN) != 0))
		return false;

	memset(r, 0, sizeof(*r));
	r->yiaddr.s_addr = m->yiaddr;

	overload = dhcp_parse_options(m->options, dhcp_len - DHCP_FIXED_LEN, r);
	if (overload < 0)
		return false;
	if (overload & 1)
		dhcp_parse_options(m->file, sizeof(m->file), r);
	if (overload & 2)
		dhcp_parse_options(m->sname, sizeof(m->sname), r);

	return r->msg_type != 0;
}

/* ------------------------------------------------------------------ */
/* State machine                                                       */
/* ------------------------------------------------------------------ */

static uint8_t dhcp_classful_len(struct in_addr addr)
{
	uint32_t a = ntohl(addr.s_addr);

	if (IN_CLASSA(a))
		return 8;
	if (IN_CLASSB(a))
		return 16;
	return 24;
}

static bool dhcp_addr_usable(struct in_addr addr)
{
	uint32_t a = ntohl(addr.s_addr);

	return a != 0 && a != INADDR_BROADCAST && !IN_MULTICAST(a) && !IN_EXPERIMENTAL(a) &&
	       (a >> 24) != IN_LOOPBACKNET;
}

/* Arm the timer for the next lease event (T1, T2 or expiry). */
static void dhcp_schedule_bound(struct zebra_dhcp_if *dif)
{
	const struct dhcp_lease *l = &dif->lease;
	time_t now = dhcp_now();

	if (!dhcp_lease_finite(l)) {
		event_cancel(&dif->t_timer);
		return;
	}

	switch (dif->state) {
	case DHCP_STATE_BOUND:
		dhcp_timer_msec(dif, (long)(dhcp_lease_t1(l) - now) * 1000);
		break;
	case DHCP_STATE_STOPPED:
		dhcp_timer_msec(dif, (long)(dhcp_lease_expiry(l) - now) * 1000);
		break;
	case DHCP_STATE_INIT:
	case DHCP_STATE_SELECTING:
	case DHCP_STATE_REQUESTING:
	case DHCP_STATE_REBOOTING:
	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REBINDING:
	default:
		break;
	}
}

static void dhcp_enter_bound(struct zebra_dhcp_if *dif)
{
	dhcp_set_state(dif, DHCP_STATE_BOUND);
	dhcp_sock_close(dif);
	dhcp_schedule_bound(dif);
}

/* A DHCPACK was received: (re)program the lease. */
static void dhcp_handle_ack(struct zebra_dhcp_if *dif, const struct dhcp_reply *r)
{
	struct dhcp_lease nl = {};
	struct in_addr mask;
	struct prefix p = { .family = AF_INET };
	bool addr_changed, gw_changed, was_valid = dif->lease.valid;

	if (!dhcp_addr_usable(r->yiaddr)) {
		zlog_warn("DHCP %s: ignoring DHCPACK with unusable address %pI4", dif->ifp->name,
			  &r->yiaddr);
		return;
	}

	nl.valid = true;
	nl.addr = r->yiaddr;
	if (r->has_mask) {
		nl.prefixlen = ip_masklen(r->mask);
		masklen2ip(nl.prefixlen, &mask);
		if (mask.s_addr != r->mask.s_addr || nl.prefixlen > 30) {
			zlog_warn("DHCP %s: invalid subnet mask %pI4 in DHCPACK, using classful mask",
				  dif->ifp->name, &r->mask);
			nl.prefixlen = dhcp_classful_len(nl.addr);
		}
	} else {
		nl.prefixlen = dhcp_classful_len(nl.addr);
	}

	if (r->has_router && dhcp_addr_usable(r->router) && r->router.s_addr != r->yiaddr.s_addr)
		nl.router = r->router;

	nl.server_id = r->server_id;
	if (!nl.server_id.s_addr && dif->state == DHCP_STATE_REQUESTING)
		nl.server_id = dif->offer_server;
	if (!nl.server_id.s_addr)
		nl.server_id = dif->lease.server_id;

	for (unsigned int i = 0; i < r->dns_count; i++)
		if (dhcp_addr_usable(r->dns[i]))
			nl.dns[nl.dns_count++] = r->dns[i];
	strlcpy(nl.domain, r->domain, sizeof(nl.domain));

	/* Lease timing (RFC 2131 4.4.5) */
	nl.lease_time = r->has_lease ? r->lease_time : 3600;
	if (nl.lease_time == 0)
		nl.lease_time = 60;
	if (dhcp_lease_finite(&nl)) {
		nl.t1 = (r->has_t1 && r->t1 && r->t1 < nl.lease_time) ? r->t1 : nl.lease_time / 2;
		nl.t2 = (r->has_t2 && r->t2 > nl.t1 && r->t2 < nl.lease_time)
				? r->t2
				: (uint32_t)((uint64_t)nl.lease_time * 7 / 8);
		if (nl.t2 <= nl.t1)
			nl.t2 = nl.t1 + (nl.lease_time - nl.t1) / 2;
	}
	nl.start = dif->req_sent ? dif->req_sent : dhcp_now();
	nl.obtained = time(NULL);

	addr_changed = !was_valid || nl.addr.s_addr != dif->lease.addr.s_addr ||
		       nl.prefixlen != dif->lease.prefixlen || !dif->addr_installed;
	gw_changed = !was_valid || nl.router.s_addr != dif->lease.router.s_addr ||
		     !dif->route_installed || dif->installed_ifindex != dif->ifp->ifindex;

	if (addr_changed) {
		dhcp_route_uninstall(dif);
		dhcp_addr_uninstall(dif);
		gw_changed = true;
	} else if (gw_changed) {
		dhcp_route_uninstall(dif);
	}

	dif->lease = nl;

	if (addr_changed) {
		p.u.prefix4 = nl.addr;
		p.prefixlen = nl.prefixlen;
		dhcp_addr_install(dif, &p);
	}
	if (gw_changed && nl.router.s_addr)
		dhcp_route_install(dif);

	if (addr_changed || gw_changed || dif->state != DHCP_STATE_RENEWING)
		zlog_info("DHCP %s: bound to %pI4/%u, gateway %pI4, lease %us (server %pI4)",
			  dif->ifp->name, &nl.addr, nl.prefixlen, &nl.router, nl.lease_time,
			  &nl.server_id);
	else
		DHCP_DEBUG(dif, "lease for %pI4 renewed for %us", &nl.addr, nl.lease_time);

	dhcp_dns_update();
	dhcp_enter_bound(dif);
}

static void dhcp_handle_reply(struct zebra_dhcp_if *dif, const struct dhcp_reply *r)
{
	switch (r->msg_type) {
	case DHCPOFFER:
		dif->rx_offer++;
		if (dif->state != DHCP_STATE_SELECTING)
			return;
		if (!dhcp_addr_usable(r->yiaddr) || !r->server_id.s_addr) {
			DHCP_DEBUG(dif, "ignoring invalid DHCPOFFER");
			return;
		}
		DHCP_DEBUG(dif, "DHCPOFFER of %pI4 from %pI4", &r->yiaddr, &r->server_id);
		dif->offer_addr = r->yiaddr;
		dif->offer_server = r->server_id;
		dhcp_set_state(dif, DHCP_STATE_REQUESTING);
		dif->retries = 0;
		dhcp_send_request(dif);
		dhcp_timer_msec(dif, dhcp_backoff_msec(0));
		break;

	case DHCPACK:
		dif->rx_ack++;
		if (dif->state != DHCP_STATE_REQUESTING && dif->state != DHCP_STATE_REBOOTING &&
		    dif->state != DHCP_STATE_RENEWING && dif->state != DHCP_STATE_REBINDING)
			return;
		if (dif->state == DHCP_STATE_REQUESTING && r->server_id.s_addr &&
		    r->server_id.s_addr != dif->offer_server.s_addr)
			return;
		DHCP_DEBUG(dif, "DHCPACK for %pI4 from %pI4", &r->yiaddr, &r->server_id);
		dhcp_handle_ack(dif, r);
		break;

	case DHCPNAK:
		dif->rx_nak++;
		if (dif->state != DHCP_STATE_REQUESTING && dif->state != DHCP_STATE_REBOOTING &&
		    dif->state != DHCP_STATE_RENEWING && dif->state != DHCP_STATE_REBINDING)
			return;
		if (dif->state == DHCP_STATE_REQUESTING && r->server_id.s_addr &&
		    r->server_id.s_addr != dif->offer_server.s_addr)
			return;
		strlcpy(dif->last_nak, r->message, sizeof(dif->last_nak));
		zlog_warn("DHCP %s: DHCPNAK received from %pI4%s%s", dif->ifp->name, &r->server_id,
			  r->message[0] ? ": " : "", r->message);
		dhcp_lease_drop(dif, "DHCPNAK");
		/* RFC 2131 3.1.5: restart after a short delay */
		dhcp_enter_init(dif, 1000 + frr_weak_random() % 2000);
		break;

	default:
		break;
	}
}

static void dhcp_read_cb(struct event *ev)
{
	struct zebra_dhcp_if *dif = EVENT_ARG(ev);
	uint8_t buf[2048];
	struct dhcp_reply r;

#ifdef GNU_LINUX
	for (int i = 0; i < 32 && dif->sock >= 0; i++) {
		struct sockaddr_ll sll;
		socklen_t slen = sizeof(sll);
		ssize_t n;

		n = recvfrom(dif->sock, buf, sizeof(buf), 0, (struct sockaddr *)&sll, &slen);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
				zlog_warn("DHCP %s: receive failed: %s", dif->ifp->name,
					  safe_strerror(errno));
			break;
		}
		if (sll.sll_pkttype == PACKET_OUTGOING)
			continue;
		if (dhcp_parse_packet(dif, buf, (size_t)n, &r))
			dhcp_handle_reply(dif, &r);
	}
#endif

	/* The handlers may have closed the socket (e.g. on entering BOUND) */
	if (dif->sock >= 0)
		event_add_read(zrouter.master, dhcp_read_cb, dif, dif->sock, &dif->t_read);
}

/* Start a fresh DHCPDISCOVER cycle after delay_ms. */
static void dhcp_enter_init(struct zebra_dhcp_if *dif, unsigned int delay_ms)
{
	dhcp_set_state(dif, DHCP_STATE_INIT);
	dhcp_timer_msec(dif, delay_ms);
}

static void dhcp_timer_cb(struct event *ev)
{
	struct zebra_dhcp_if *dif = EVENT_ARG(ev);
	struct dhcp_lease *l = &dif->lease;
	time_t now = dhcp_now();
	time_t remaining;
	long next;

	switch (dif->state) {
	case DHCP_STATE_STOPPED:
		/* Lease ran out while the interface was down. */
		if (l->valid && dhcp_lease_expired(l))
			dhcp_lease_drop(dif, "lease expired");
		break;

	case DHCP_STATE_INIT:
		if (dhcp_sock_open(dif) < 0) {
			dhcp_timer_msec(dif, DHCP_SOCKET_RETRY * 1000);
			break;
		}
		dhcp_new_xid(dif);
		dhcp_set_state(dif, DHCP_STATE_SELECTING);
		dhcp_send_discover(dif);
		dhcp_timer_msec(dif, dhcp_backoff_msec(0));
		break;

	case DHCP_STATE_SELECTING:
		dif->retries++;
		dhcp_send_discover(dif);
		dhcp_timer_msec(dif, dhcp_backoff_msec(dif->retries));
		break;

	case DHCP_STATE_REQUESTING:
		if (++dif->retries > DHCP_REQUEST_RETRIES) {
			DHCP_DEBUG(dif, "no DHCPACK received, restarting");
			dhcp_enter_init(dif, 0);
			break;
		}
		dhcp_send_request(dif);
		dhcp_timer_msec(dif, dhcp_backoff_msec(dif->retries));
		break;

	case DHCP_STATE_REBOOTING:
		if (++dif->retries > DHCP_REBOOT_RETRIES) {
			/*
			 * RFC 2131 3.2: with no answer the client may keep
			 * using its unexpired lease.
			 */
			if (dhcp_lease_expired(l)) {
				dhcp_lease_drop(dif, "lease expired");
				dhcp_enter_init(dif, 0);
			} else {
				DHCP_DEBUG(dif, "no answer to INIT-REBOOT, keeping lease");
				dhcp_enter_bound(dif);
				if (dhcp_lease_finite(l) && now >= dhcp_lease_t1(l))
					dhcp_timer_msec(dif, 0);
			}
			break;
		}
		dhcp_send_request(dif);
		dhcp_timer_msec(dif, dhcp_backoff_msec(dif->retries));
		break;

	case DHCP_STATE_BOUND:
		/* T1 expired: try to renew with the leasing server. */
		if (dhcp_sock_open(dif) < 0) {
			dhcp_timer_msec(dif, DHCP_SOCKET_RETRY * 1000);
			break;
		}
		dhcp_new_xid(dif);
		dhcp_set_state(dif, now >= dhcp_lease_t2(l) ? DHCP_STATE_REBINDING
							    : DHCP_STATE_RENEWING);
		/* fallthrough */
	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REBINDING:
		if (dhcp_lease_expired(l)) {
			dhcp_lease_drop(dif, "lease expired");
			dhcp_enter_init(dif, 0);
			break;
		}
		if (dif->state == DHCP_STATE_RENEWING && now >= dhcp_lease_t2(l)) {
			/* T2 expired: broadcast to any server. */
			dhcp_set_state(dif, DHCP_STATE_REBINDING);
			dif->retries = 0;
		}

		dhcp_send_request(dif);
		dif->retries++;

		/* RFC 2131 4.4.5: half the remaining time, at least 60s */
		remaining = (dif->state == DHCP_STATE_RENEWING) ? dhcp_lease_t2(l) - now
								: dhcp_lease_expiry(l) - now;
		next = MAX(remaining / 2, DHCP_RENEW_MIN_INTERVAL);
		if (next > remaining)
			next = remaining;
		dhcp_timer_msec(dif, next * 1000);
		break;
	}
}

/* Interface became usable: start (or resume) acquiring a lease. */
static void dhcp_start(struct zebra_dhcp_if *dif)
{
	if (!dhcp_if_operative(dif->ifp))
		return;

	if (dif->lease.valid && !dhcp_lease_expired(&dif->lease)) {
		/* INIT-REBOOT: verify the lease we already hold. */
		if (dhcp_sock_open(dif) < 0) {
			dhcp_enter_init(dif, DHCP_SOCKET_RETRY * 1000);
			return;
		}
		dhcp_new_xid(dif);
		dhcp_set_state(dif, DHCP_STATE_REBOOTING);
		dhcp_send_request(dif);
		dhcp_timer_msec(dif, dhcp_backoff_msec(0));
		return;
	}

	if (dif->lease.valid)
		dhcp_lease_drop(dif, "lease expired");

	/* RFC 2131 4.4.1: wait a random time before the first DISCOVER */
	dhcp_enter_init(dif, frr_weak_random() % 1000);
}

static void dhcp_stop(struct zebra_dhcp_if *dif)
{
	dhcp_sock_close(dif);
	event_cancel(&dif->t_timer);
	dhcp_set_state(dif, DHCP_STATE_STOPPED);
	dif->retries = 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void zebra_dhcp_if_enable(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_dhcp_if *dif;

	if (!zif || zif->dhcp)
		return;

	dif = XCALLOC(MTYPE_ZEBRA_DHCP_IF, sizeof(*dif));
	dif->ifp = ifp;
	dif->sock = -1;
	dif->state = DHCP_STATE_STOPPED;
	dif->instance = dhcp_instance_alloc();
	zif->dhcp = dif;

	DHCP_DEBUG(dif, "DHCP client enabled");
	dhcp_start(dif);
}

void zebra_dhcp_if_disable(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;
	struct zebra_dhcp_if *dif = zif ? zif->dhcp : NULL;

	if (!dif)
		return;

	DHCP_DEBUG(dif, "DHCP client disabled");
	dhcp_send_release(dif);
	dhcp_stop(dif);
	dhcp_lease_drop(dif, "DHCP disabled");
	zebra_dhcp_if_free(zif);
}

void zebra_dhcp_if_up(struct interface *ifp)
{
	struct zebra_dhcp_if *dif = dhcp_if_get(ifp);

	if (!dif || dif->state != DHCP_STATE_STOPPED)
		return;

	DHCP_DEBUG(dif, "interface up");
	event_cancel(&dif->t_timer);
	dhcp_start(dif);
}

void zebra_dhcp_if_down(struct interface *ifp)
{
	struct zebra_dhcp_if *dif = dhcp_if_get(ifp);

	if (!dif || dif->state == DHCP_STATE_STOPPED)
		return;

	DHCP_DEBUG(dif, "interface down");
	dhcp_stop(dif);
	/* Keep the lease; it is re-verified (INIT-REBOOT) on link up. */
	if (dif->lease.valid)
		dhcp_schedule_bound(dif);
}

void zebra_dhcp_if_delete(struct interface *ifp)
{
	struct zebra_dhcp_if *dif = dhcp_if_get(ifp);

	if (!dif)
		return;

	/* The kernel removed the address together with the device. */
	dhcp_stop(dif);
	dhcp_lease_drop(dif, "interface deleted");
}

void zebra_dhcp_if_free(struct zebra_if *zif)
{
	struct zebra_dhcp_if *dif = zif->dhcp;

	if (!dif)
		return;

	dhcp_sock_close(dif);
	event_cancel(&dif->t_timer);
	dhcp_instance_free(dif->instance);
	XFREE(MTYPE_ZEBRA_DHCP_IF, zif->dhcp);
}

/* ------------------------------------------------------------------ */
/* show dhcp lease                                                     */
/* ------------------------------------------------------------------ */

static const char *dhcp_fmt_duration(time_t secs, char *buf, size_t len)
{
	unsigned long s = secs < 0 ? 0 : (unsigned long)secs;
	unsigned long d = s / 86400, h = (s / 3600) % 24, m = (s / 60) % 60;

	if (d)
		snprintf(buf, len, "%lud%02luh%02lum%02lus", d, h, m, s % 60);
	else
		snprintf(buf, len, "%02lu:%02lu:%02lu", h, m, s % 60);
	return buf;
}

static void dhcp_show_if(struct vty *vty, struct zebra_dhcp_if *dif, json_object *json)
{
	struct interface *ifp = dif->ifp;
	const struct dhcp_lease *l = &dif->lease;
	bool have = l->valid;
	time_t now = dhcp_now();
	struct in_addr mask = {};
	char buf[64], tbuf[64];
	json_object *jif = NULL, *jdns;
	struct tm tm;

	if (have)
		masklen2ip(l->prefixlen, &mask);

	if (json) {
		jif = json_object_new_object();
		json_object_string_add(jif, "vrf", ifp->vrf->name);
		json_object_string_add(jif, "state", dhcp_state_names[dif->state]);
		json_object_boolean_add(jif, "leaseValid", have);
		if (have) {
			json_object_string_addf(jif, "address", "%pI4", &l->addr);
			json_object_int_add(jif, "prefixLength", l->prefixlen);
			json_object_string_addf(jif, "subnetMask", "%pI4", &mask);
			if (l->router.s_addr)
				json_object_string_addf(jif, "gateway", "%pI4", &l->router);
			jdns = json_object_new_array();
			for (unsigned int i = 0; i < l->dns_count; i++)
				json_array_string_addf(jdns, "%pI4", &l->dns[i]);
			json_object_object_add(jif, "dnsServers", jdns);
			if (l->domain[0])
				json_object_string_add(jif, "domainName", l->domain);
			json_object_string_addf(jif, "dhcpServer", "%pI4", &l->server_id);
			json_object_int_add(jif, "leaseObtainedEpoch", (int64_t)l->obtained);
			if (dhcp_lease_finite(l)) {
				json_object_int_add(jif, "leaseTime", l->lease_time);
				json_object_int_add(jif, "renewInSecs",
						    MAX(dhcp_lease_t1(l) - now, 0));
				json_object_int_add(jif, "rebindInSecs",
						    MAX(dhcp_lease_t2(l) - now, 0));
				json_object_int_add(jif, "expiresInSecs",
						    MAX(dhcp_lease_expiry(l) - now, 0));
			} else {
				json_object_string_add(jif, "leaseTime", "infinite");
			}
		}
		json_object_int_add(jif, "discoverSent", dif->tx_discover);
		json_object_int_add(jif, "requestSent", dif->tx_request);
		json_object_int_add(jif, "releaseSent", dif->tx_release);
		json_object_int_add(jif, "offerReceived", dif->rx_offer);
		json_object_int_add(jif, "ackReceived", dif->rx_ack);
		json_object_int_add(jif, "nakReceived", dif->rx_nak);
		json_object_object_add(json, ifp->name, jif);
		return;
	}

	vty_out(vty, "Interface %s", ifp->name);
	if (ifp->vrf->vrf_id != VRF_DEFAULT)
		vty_out(vty, " (vrf %s)", ifp->vrf->name);
	vty_out(vty, "\n");
	vty_out(vty, "  State:             %s\n", dhcp_state_names[dif->state]);

	if (!have) {
		vty_out(vty, "  No lease\n");
	} else {
		vty_out(vty, "  IP address:        %pI4/%u\n", &l->addr, l->prefixlen);
		vty_out(vty, "  Subnet mask:       %pI4\n", &mask);
		if (l->router.s_addr)
			vty_out(vty, "  Default gateway:   %pI4\n", &l->router);
		else
			vty_out(vty, "  Default gateway:   (none)\n");
		vty_out(vty, "  DNS servers:      ");
		if (!l->dns_count)
			vty_out(vty, " (none)");
		for (unsigned int i = 0; i < l->dns_count; i++)
			vty_out(vty, " %pI4", &l->dns[i]);
		vty_out(vty, "\n");
		if (l->domain[0])
			vty_out(vty, "  Domain name:       %s\n", l->domain);
		vty_out(vty, "  DHCP server:       %pI4\n", &l->server_id);
		localtime_r(&l->obtained, &tm);
		strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);
		vty_out(vty, "  Lease obtained:    %s\n", tbuf);
		if (dhcp_lease_finite(l)) {
			vty_out(vty, "  Lease time:        %s\n",
				dhcp_fmt_duration(l->lease_time, buf, sizeof(buf)));
			vty_out(vty, "  Renewal (T1) in:   %s\n",
				dhcp_fmt_duration(dhcp_lease_t1(l) - now, buf, sizeof(buf)));
			vty_out(vty, "  Rebinding (T2) in: %s\n",
				dhcp_fmt_duration(dhcp_lease_t2(l) - now, buf, sizeof(buf)));
			vty_out(vty, "  Lease expires in:  %s\n",
				dhcp_fmt_duration(dhcp_lease_expiry(l) - now, buf, sizeof(buf)));
		} else {
			vty_out(vty, "  Lease time:        infinite\n");
		}
	}
	vty_out(vty,
		"  Messages:          %u discover, %u request, %u release sent; %u offer, %u ack, %u nak received\n",
		dif->tx_discover, dif->tx_request, dif->tx_release, dif->rx_offer, dif->rx_ack,
		dif->rx_nak);
	if (dif->last_nak[0])
		vty_out(vty, "  Last NAK message:  %s\n", dif->last_nak);
	vty_out(vty, "\n");
}

#include "zebra/zebra_dhcp_clippy.c"

DEFPY (show_dhcp_lease,
       show_dhcp_lease_cmd,
       "show dhcp lease [json]$json",
       SHOW_STR
       "DHCP client information\n"
       "Current DHCP lease of every DHCP configured interface\n"
       JSON_STR)
{
	struct vrf *vrf;
	struct interface *ifp;
	json_object *jo = json ? json_object_new_object() : NULL;
	unsigned int count = 0;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			struct zebra_dhcp_if *dif = dhcp_if_get(ifp);

			if (!dif)
				continue;
			dhcp_show_if(vty, dif, jo);
			count++;
		}
	}

	if (jo)
		vty_json(vty, jo);
	else if (!count)
		vty_out(vty, "No interfaces are configured with \"ip address dhcp\"\n");

	return CMD_SUCCESS;
}

void zebra_dhcp_init(void)
{
	install_element(VIEW_NODE, &show_dhcp_lease_cmd);
}

/*
 * zebra is shutting down: stop all protocol activity.  Addresses and the
 * resolver configuration are left in place, like any other configured
 * address; the default route is withdrawn together with all of zebra's
 * routes.
 */
void zebra_dhcp_terminate(void)
{
	struct vrf *vrf;
	struct interface *ifp;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			struct zebra_dhcp_if *dif = dhcp_if_get(ifp);

			if (dif)
				dhcp_stop(dif);
		}
	}

	XFREE(MTYPE_ZEBRA_DHCP_RESOLV, dhcp_resolv.saved);
}
