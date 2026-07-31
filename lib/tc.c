// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Traffic Control (TC) main library
 * Copyright (C) 2022  Shichu Yang
 */

#include "tc.h"

int tc_getrate(const char *str, uint64_t *rate)
{
	char *endp;
	uint64_t raw = strtoull(str, &endp, 10);

	if (endp == str)
		return -1;

	/* if the string only contains a number, it must be valid rate (bps) */
	bool valid = (*endp == '\0');

	const char *p = endp;
	bool bytes = false, binary_base = false;
	int power = 0;

	while (*p) {
		if (strcmp(p, "Bps") == 0) {
			bytes = true;
			valid = true;
			break;
		} else if (strcmp(p, "bit") == 0) {
			valid = true;
			break;
		}
		switch (*p) {
		case 'k':
		case 'K':
			power = 1;
			break;
		case 'm':
		case 'M':
			power = 2;
			break;
		case 'g':
		case 'G':
			power = 3;
			break;
		case 't':
		case 'T':
			power = 4;
			break;
		case 'i':
		case 'I':
			if (power != 0)
				binary_base = true;
			else
				return -1;
			break;
		default:
			return -1;
		}
		p++;
	}

	if (!valid)
		return -1;

	for (int i = 0; i < power; i++)
		raw *= binary_base ? 1024ULL : 1000ULL;

	if (bytes)
		*rate = raw;
	else
		*rate = raw / 8ULL;

	return 0;
}

static int tc_action_mpls_cmp(const struct tc_act_mpls *a1, 
			      const struct tc_act_mpls *a2)
{
	if(a1->mode != a2->mode)
		return false;
	switch(a1->mode) {
	case TC_MPLS_PUSH:
		if(a1->protocol != a2->protocol)
			return false;
		if(a1->label != a2->label)
			return false;
		return true;
	case TC_MPLS_PUSH_MAC:
		if(a1->label != a2->label)
			return false;
		if(a1->ttl != a2->ttl)
			return false;
		if(a1->bos != a2->bos)
			return false;
		return true;
	case TC_MPLS_DEC_TTL:
	case TC_MPLS_POP:
	default:
		return true;
	};
	return true;
}

static int tc_action_vlan_cmp(const struct tc_act_vlan *a1, 
			      const struct tc_act_vlan *a2)
{
	if (a1->mode != a2->mode)
		return false;
	switch(a1->mode){
	case TC_VLAN_PUSH_ETH:
		if (!memcmp(a1->dst.octet,a2->dst.octet,ETH_ALEN))
			return false;
		if (!memcmp(a1->src.octet,a2->src.octet,ETH_ALEN))
			return false;
		return true;
	case TC_VLAN_REPLACE:
		if (a1->id != a2->id)
			return false;
		fallthrough;
	case TC_VLAN_POP:
	case TC_VLAN_POP_ETH:
	case TC_VLAN_PUSH:
	default:
		return true;
	};
}

int tc_action_cmp(const struct tc_action *a1, 
		  const struct tc_action *a2)
{
	if (a1->kind != a2->kind)
		return false;
	switch(a1->kind) {
	case TC_ACTION_MPLS:
		return tc_action_mpls_cmp(&a1->u.mpls,&a2->u.mpls);
	case TC_ACTION_VLAN:
		return tc_action_vlan_cmp(&a1->u.vlan,&a2->u.vlan);
	case TC_ACTION_MIRRED:
		if (a1->u.mirred.ifindex != a2->u.mirred.ifindex)
			return false;
		if (a1->u.mirred.direction != a2->u.mirred.direction)
			return false;
		if (a1->u.mirred.mode != a2->u.mirred.mode)
			return false;
		fallthrough;
	case TC_ACTION_UNSPEC:
	default:
		return true;
	};
}
