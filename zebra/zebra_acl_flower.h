// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Extended access-list entries translated into tc-flower match keys.
 *
 * Copyright (C) 2026 FRRouting
 */

#ifndef _ZEBRA_ACL_FLOWER_H
#define _ZEBRA_ACL_FLOWER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zebra/zebra_acl_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Room for the netlink attributes of one filter's match keys */
#define ACLX_FLOWER_RAW_MAX 768

/*
 * Cisco operators that flower cannot express with one key (neq, lt and gt
 * on ports, ttl ranges, "established") expand into several filters.
 */
#define ACLX_FLOWER_MAX_FILTERS 32

struct aclx_flower {
	/* tc filter protocol, host byte order (ETH_P_ALL for any) */
	uint16_t eth_proto;
	/*
	 * TCA_FLOWER_KEY_* attributes, each padded to 4 bytes.  The
	 * ethertype key (TCA_FLOWER_KEY_ETH_TYPE) is not included: it
	 * follows from the filter protocol.
	 */
	uint16_t len;
	uint8_t raw[ACLX_FLOWER_RAW_MAX];
	/*
	 * For entries expanded into several filters: what this one
	 * matches of the expanded operators, e.g. "dst-port 81-65535
	 * tcp-flags 0x10/0x10".  Empty otherwise.
	 */
	char desc[96];
};

/*
 * Translate @rule into flower match keys, additionally requiring the IP
 * TOS byte to match @tos under @tos_mask (0 for no extra constraint).
 *
 * Writes up to @max filters to @out; their union matches what the rule
 * matches.  Returns the number of filters (0 when the rule can never
 * match, e.g. "lt 0" or a TOS constraint on a non-IP rule), or -1 with a
 * message in @err.
 */
extern int aclx_flower_encode(const struct aclx_rule *rule, uint8_t tos, uint8_t tos_mask,
			      struct aclx_flower *out, int max, char *err, size_t errlen);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_ACL_FLOWER_H */
