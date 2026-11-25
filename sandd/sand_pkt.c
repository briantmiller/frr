// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SAND v2 - packet encoding, socket I/O and dispatch
 */

#include <zebra.h>

#include <netinet/ip.h>

#include "log.h"
#include "network.h"
#include "sockopt.h"

#include "sandd/sandd.h"

void sand_put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

void sand_put32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = (v >> 16) & 0xff;
	p[2] = (v >> 8) & 0xff;
	p[3] = v & 0xff;
}

uint16_t sand_get16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

uint32_t sand_get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

void sand_key_put(uint8_t *p, const struct sand_key *k)
{
	p[0] = k->type;
	p[1] = 0;
	sand_put16(p + 2, k->frag);
	sand_put32(p + 4, k->orig);
}

void sand_key_get(const uint8_t *p, struct sand_key *k)
{
	k->type = p[0];
	k->frag = sand_get16(p + 2);
	k->orig = sand_get32(p + 4);
}

/* Room for a SAND packet body on this interface (MTU - IP - UDP - header) */
size_t sand_if_payload_max(struct sand_if *sif)
{
	unsigned int mtu = sif->ifp->mtu;

	if (mtu < 576 || mtu > 65535)
		mtu = 1500;
	return mtu - 20 - 8 - SAND_HDR_LEN;
}

int sand_pkt_send(struct sand_if *sif, uint8_t type, const uint8_t *body,
		  size_t blen)
{
	uint8_t buf[SAND_MAX_PKT];
	struct sockaddr_in dst = {};
	struct ip_mreqn mreqn = {};
	ssize_t n;
	size_t len = SAND_HDR_LEN + blen;

	if (!sand || !sand->running || sand->sock < 0 || !sif->running)
		return -1;
	if (sand->silent && !sand->silent_announcing)
		return 0;
	if (len > sizeof(buf))
		return -1;

	buf[0] = SAND_VERSION;
	buf[1] = type;
	sand_put16(buf + 2, len);
	sand_put32(buf + 4, sand->rid);
	sand_put16(buf + 8, sif->idx);
	buf[10] = 0; /* auth type: none */
	buf[11] = 0; /* flags */
	sand_put32(buf + 12, ++sif->tx_seq);
	if (blen)
		memcpy(buf + SAND_HDR_LEN, body, blen);

	mreqn.imr_ifindex = sif->ifp->ifindex;
	mreqn.imr_address = sif->ipv4;
	if (setsockopt(sand->sock, IPPROTO_IP, IP_MULTICAST_IF, &mreqn,
		       sizeof(mreqn)) < 0) {
		zlog_warn("SAND: IP_MULTICAST_IF on %s: %s", sif->ifp->name,
			  safe_strerror(errno));
		return -1;
	}

	dst.sin_family = AF_INET;
	dst.sin_port = htons(sand->port);
	dst.sin_addr = sand->group;

	n = sendto(sand->sock, buf, len, 0, (struct sockaddr *)&dst,
		   sizeof(dst));
	if (n < 0) {
		/* EPERM: a firewall drops this direction - that is a
		 * one-way link, not an error */
		if (errno != EPERM)
			SAND_DBG(SAND_DEBUG_PACKET, "send on %s failed: %s",
				 sif->ifp->name, safe_strerror(errno));
		return -1;
	}

	sif->tx_pkts++;
	sif->tx_bytes += len;
	if (type < 5) {
		sand->tx_type_pkts[type]++;
		sand->tx_type_bytes[type] += len;
	}
	sif->last_tx = monotime(NULL);

	SAND_DBG(SAND_DEBUG_PACKET, "tx type %u len %zu on %s seq %u", type,
		 len, sif->ifp->name, sif->tx_seq);
	return 0;
}

void sand_send_hello(struct sand_if *sif)
{
	uint8_t b[SAND_HELLO_LEN];

	sand_put32(b, sand->boot_id);
	sand_put16(b + 4, sif->hello_interval * 10);
	sand_put16(b + 6, sif->hold_time * 10);
	sand_put32(b + 8, sand_lsdb_digest());
	sand_pkt_send(sif, SAND_PKT_HELLO, b, sizeof(b));
}

static void sand_pkt_dispatch(struct sand_if *sif, const uint8_t *buf,
			      size_t len)
{
	uint8_t type;
	uint16_t plen, sifidx;
	uint32_t sender, pseq;
	const uint8_t *body;
	size_t blen;

	if (len < SAND_HDR_LEN)
		return;
	if (buf[0] != SAND_VERSION)
		return;
	type = buf[1];
	plen = sand_get16(buf + 2);
	if (plen < SAND_HDR_LEN || plen > len)
		return;
	sender = sand_get32(buf + 4);
	sifidx = sand_get16(buf + 8);
	if (buf[10] != 0) /* authentication not implemented yet */
		return;
	pseq = sand_get32(buf + 12);
	if (sender == 0)
		return;
	if (sender == sand->rid) {
		/* Our own RID.  Two of our interfaces on one segment can loop
		 * our packets back legitimately, but a Hello with someone
		 * else's boot id means another router uses our RID (10.4). */
		if (type == SAND_PKT_HELLO && plen >= SAND_HDR_LEN + SAND_HELLO_LEN &&
		    sand_get32(buf + SAND_HDR_LEN) != sand->boot_id) {
			static time_t last_log;
			time_t now = monotime(NULL);
			char rb[INET_ADDRSTRLEN];

			if (now - last_log >= 10) {
				last_log = now;
				zlog_err("SAND: router-id %s appears to be in use by another router (Hello with our id received on %s)",
					 sand_rid2str(sand->rid, rb, sizeof(rb)),
					 sif->ifp->name);
			}
		}
		return;
	}

	body = buf + SAND_HDR_LEN;
	blen = plen - SAND_HDR_LEN;

	sif->rx_pkts++;
	sif->rx_bytes += plen;

	SAND_DBG(SAND_DEBUG_PACKET, "rx type %u len %u on %s from %pI4/%u",
		 type, plen, sif->ifp->name, &(struct in_addr){htonl(sender)},
		 sifidx);

	/* Any valid packet proves the directed link sender -> us */
	sand_if_heard(sif, sender, sifidx, pseq);

	switch (type) {
	case SAND_PKT_HELLO:
		if (blen >= SAND_HELLO_LEN)
			sand_if_hello_rx(sif, sender, sifidx,
					 sand_get32(body),
					 sand_get16(body + 6));
		break;
	case SAND_PKT_UPDATE:
		sand_rx_update(sif, sender, body, blen);
		break;
	case SAND_PKT_SUMMARY:
		sand_rx_summary(sif, sender, body, blen);
		break;
	case SAND_PKT_REQUEST:
		sand_rx_request(sif, sender, body, blen);
		break;
	default:
		break;
	}
}

void sand_pkt_read(struct event *t)
{
	static uint8_t buf[SAND_MAX_PKT];
	uint8_t cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct sockaddr_in from;
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	struct msghdr msg = {};
	struct cmsghdr *cm;
	ifindex_t ifindex = 0;
	struct interface *ifp;
	struct sand_if *sif;
	ssize_t n;

	event_add_read(master, sand_pkt_read, NULL, sand->sock, &sand->t_read);

	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	n = recvmsg(sand->sock, &msg, 0);
	if (n <= 0)
		return;

	for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level == IPPROTO_IP &&
		    cm->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *pi =
				(struct in_pktinfo *)CMSG_DATA(cm);
			ifindex = pi->ipi_ifindex;
		}
	}
	if (!ifindex)
		return;

	ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);
	if (!ifp || !ifp->info)
		return;
	sif = ifp->info;
	if (!sif->running)
		return;

	sand_pkt_dispatch(sif, buf, n);
}
