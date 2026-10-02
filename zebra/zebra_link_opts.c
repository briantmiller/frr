// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra - tables and value conversion for bridge and bridge port settings.
 */

#include <zebra.h>

#include "lib/prefix.h"
#include "zebra/zebra_link_opts.h"

static const char *const zlo_enum_br_vlan_protocol[] = { "dot1q", "dot1ad", NULL };
static const char *const zlo_enum_br_multicast_router[] = { "disabled", "auto", "enabled", NULL };
static const char *const zlo_enum_port_state[] = { "disabled", "listening", "learning", "forwarding", "blocking", NULL };
static const char *const zlo_enum_port_multicast_router[] = { "disabled", "learning", "permanent", "temp", NULL };

static const struct zebra_link_opt_def bridge_opts[] = {
#define X(sym, name, kind, width, min, max, def, attr, enums, vs, vh, hlp) \
	{ name, kind, width, min, max, def, attr, enums },
	ZEBRA_BRIDGE_OPT_LIST(X)
#undef X
};

static const struct zebra_link_opt_def brport_opts[] = {
#define X(sym, name, kind, width, min, max, def, attr, enums, vs, vh, hlp) \
	{ name, kind, width, min, max, def, attr, enums },
	ZEBRA_BRPORT_OPT_LIST(X)
#undef X
};

const struct zebra_link_opt_def *zebra_link_opt_table(enum zebra_link_opt_scope scope,
						      unsigned int *count)
{
	if (scope == ZLO_SCOPE_BRIDGE) {
		*count = array_size(bridge_opts);
		return bridge_opts;
	}
	*count = array_size(brport_opts);
	return brport_opts;
}

int zebra_link_opt_find(enum zebra_link_opt_scope scope, const char *name)
{
	unsigned int i, count;
	const struct zebra_link_opt_def *t = zebra_link_opt_table(scope, &count);

	for (i = 0; i < count; i++)
		if (strcmp(t[i].name, name) == 0)
			return i;
	return -1;
}

bool zebra_link_opt_parse(const struct zebra_link_opt_def *def, const char *str,
			  uint64_t *val)
{
	unsigned int i, b[6];
	char *end;
	uint64_t v;

	switch (def->kind) {
	case ZLO_BOOL:
		if (!strcmp(str, "true") || !strcmp(str, "on"))
			*val = 1;
		else if (!strcmp(str, "false") || !strcmp(str, "off"))
			*val = 0;
		else
			return false;
		return true;

	case ZLO_UINT:
	case ZLO_SECS:
		errno = 0;
		v = strtoull(str, &end, 10);
		if (errno || end == str || *end != '\0' || v < def->min || v > def->max)
			return false;
		*val = v;
		return true;

	case ZLO_ENUM:
	case ZLO_VLANPROTO:
		for (i = 0; def->enums && def->enums[i]; i++) {
			if (!strcmp(def->enums[i], str)) {
				*val = i;
				return true;
			}
		}
		return false;

	case ZLO_MAC:
		if (sscanf(str, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
			return false;
		v = 0;
		for (i = 0; i < 6; i++) {
			if (b[i] > 255)
				return false;
			v = (v << 8) | b[i];
		}
		*val = v;
		return true;
	}
	return false;
}

const char *zebra_link_opt_format(const struct zebra_link_opt_def *def, uint64_t val, char *buf,
				  size_t buflen)
{
	unsigned int i;

	switch (def->kind) {
	case ZLO_BOOL:
		snprintf(buf, buflen, "%s", val ? "on" : "off");
		break;
	case ZLO_UINT:
	case ZLO_SECS:
		snprintf(buf, buflen, "%lu", val);
		break;
	case ZLO_ENUM:
	case ZLO_VLANPROTO:
		for (i = 0; def->enums && def->enums[i]; i++)
			if (i == val)
				break;
		snprintf(buf, buflen, "%s", def->enums && def->enums[i] ? def->enums[i] : "?");
		break;
	case ZLO_MAC:
		snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned int)(val >> 40) & 0xff,
			 (unsigned int)(val >> 32) & 0xff, (unsigned int)(val >> 24) & 0xff,
			 (unsigned int)(val >> 16) & 0xff, (unsigned int)(val >> 8) & 0xff,
			 (unsigned int)val & 0xff);
		break;
	}
	return buf;
}
