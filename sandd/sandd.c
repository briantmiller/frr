// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SAND v2 - router instance: start, stop, router-id, silence
 */

#include <zebra.h>

#include "log.h"
#include "libfrr.h"
#include "network.h"

#include "sandd/sandd.h"

DEFINE_MGROUP(SANDD, "sandd");
DEFINE_MTYPE_STATIC(SANDD, SAND_TOP, "SAND instance");

struct sand *sand;
unsigned long sand_debug;

const char *sand_rid2str(uint32_t rid, char *buf, size_t len)
{
	struct in_addr a = { .s_addr = htonl(rid) };

	inet_ntop(AF_INET, &a, buf, len);
	return buf;
}

/* A value that changes on every restart (design doc 9.1) */
uint32_t sand_load_boot_id(void)
{
	char path[512];
	uint32_t id = 0;
	FILE *f;

	snprintf(path, sizeof(path), "%s/sandd.bootid", frr_libstatedir);
	f = fopen(path, "r");
	if (f) {
		if (fscanf(f, "%u", &id) != 1)
			id = 0;
		fclose(f);
	}
	id++;
	if (id == 0)
		id = 1;
	f = fopen(path, "w");
	if (f) {
		fprintf(f, "%u\n", id);
		fclose(f);
	} else {
		/* no storage: fall back to the time in seconds */
		id = (uint32_t)time(NULL);
	}
	return id;
}

void sand_init(void)
{
	sand = XCALLOC(MTYPE_SAND_TOP, sizeof(*sand));
	sand->sock = -1;
	sand->lifetime = SAND_DEFAULT_LIFETIME;
	sand->summary_interval = SAND_DEFAULT_SUMMARY;
	sand->port = SAND_DEFAULT_PORT;
	sand->silent_hold = 3600;
	inet_pton(AF_INET, SAND_DEFAULT_GROUP, &sand->group);
	sand_lsdb_init_all();
	sand_xpfx_init(&sand->xpfx);
	sand_rt_init(&sand->routes);
}

int sand_start(void)
{
	uint32_t rid;
	char buf[INET_ADDRSTRLEN];

	if (sand->running || !sand->configured)
		return 0;
	rid = ntohl(sand->rid_cfg.s_addr ? sand->rid_cfg.s_addr
					 : sand->rid_zebra.s_addr);
	if (!rid)
		return 0; /* wait for a router-id */

	sand->rid = rid;
	sand->boot_id = sand_load_boot_id();
	if (sand_sock_open() < 0)
		return -1;
	sand->running = true;
	zlog_notice("SAND: starting, router-id %s, boot id %u",
		    sand_rid2str(rid, buf, sizeof(buf)), sand->boot_id);

	event_add_timer(master, sand_ager, NULL, 1, &sand->t_ager);
	sand_if_update_all();
	sand_schedule_orig();
	return 0;
}

void sand_stop(bool purge)
{
	int i;

	if (!sand->running)
		return;
	zlog_notice("SAND: stopping%s", purge ? ", withdrawing records" : "");
	if (purge && !sand->silent)
		sand_purge_own();

	sand_routes_flush();
	for (i = 0; i < SAND_MAX_IFACES; i++) {
		struct sand_if *sif = sand_if_by_idx(i);

		if (sif)
			sand_if_stop(sif);
	}
	event_cancel(&sand->t_orig);
	event_cancel(&sand->t_ager);
	event_cancel(&sand->t_spf);
	sand_lsdb_flush();
	sand_sock_close();
	sand->running = false;
	sand->rid = 0;
}

/* Free everything at exit (after sand_stop) */
void sand_terminate(void)
{
	sand_xpfx_flush();
	sand_xpfx_fini(&sand->xpfx);
	sand_rt_fini(&sand->routes);
	sand_lsdb_fini(&sand->lsdb);
	XFREE(MTYPE_SAND_TOP, sand);
}

void sand_rid_update(void)
{
	uint32_t want = ntohl(sand->rid_cfg.s_addr ? sand->rid_cfg.s_addr
						   : sand->rid_zebra.s_addr);

	if (sand->running && want == sand->rid)
		return;
	if (sand->running)
		sand_stop(true);
	if (sand->configured)
		sand_start();
}

/* Emissions control (9.4) */
void sand_set_silent(bool on, uint16_t hold)
{
	struct sand_rec *r;

	sand->silent_hold = hold;
	if (on == sand->silent)
		return;

	sand->silent = on;
	if (!sand->running)
		return;

	frr_each (sand_lsdb, &sand->lsdb, r)
		if (r->key.orig == sand->rid && !r->purge)
			r->force_new = true;

	if (on) {
		zlog_notice("SAND: going silent for up to %u seconds", hold);
		sand->silent_announcing = true;
		sand_originate_now();
		sand_flood_flush_all();
		sand->silent_announcing = false;
	} else {
		zlog_notice("SAND: transmitting again");
		sand_originate_now();
		sand_if_trigger_summary_all();
	}
}
