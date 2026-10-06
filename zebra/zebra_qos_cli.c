// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QoS (class-map / policy-map / service-policy) CLI, runs in mgmtd.
 *
 * Copyright (C) 2026 FRRouting
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "command.h"
#include "northbound_cli.h"
#include "yang.h"

#include "zebra/zebra_acl_ext.h"
#include "zebra/zebra_qos_cli.h"
#include "zebra/zebra_qos_cli_clippy.c"

#define QOS_STR		   "Quality of Service\n"
#define CLASS_MAP_STR	   "Configure a QoS class-map\n"
#define POLICY_MAP_STR	   "Configure a QoS policy-map\n"
#define SERVICE_POLICY_STR "Apply a QoS policy-map\n"
#define RATE_STR                                                                                  \
	"Rate in bits/sec, optionally with a k, m or g SI suffix and bps, e.g. 512k, 20mbps, 1.5g\n"

#define QOS_XPATH	     "/frr-qos:qos"
#define QOS_CLASS_MAP_XPATH  QOS_XPATH "/class-map[name='%s']"
#define QOS_POLICY_MAP_XPATH QOS_XPATH "/policy-map[name='%s']"
#define QOS_ACLX_XPATH	     QOS_XPATH "/extended-access-list[name='%s']"

#define ACLX_STR     "Extended access-list (all tc-flower match keys)\n"
#define ACLX_SEQ_STR "Sequence number\n"
#define ACLX_LINE_STR                                                                             \
	"PROTOCOL SOURCE [PORTS] DESTINATION [PORTS] [OPTIONS], see the documentation\n"

/*
 * ----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------
 */

/*
 * Parse a rate such as "20000000", "512k", "20m", "20mbps", "1.5g" or
 * "100kbit" into bits per second.  SI (power of 10) prefixes are used.
 */
static int qos_parse_rate(const char *str, uint64_t *bps)
{
	char *end;
	double value;
	double mult = 1;

	errno = 0;
	value = strtod(str, &end);
	if (end == str || errno || value <= 0)
		return -1;

	switch (*end) {
	case 'k':
	case 'K':
		mult = 1e3;
		end++;
		break;
	case 'm':
	case 'M':
		mult = 1e6;
		end++;
		break;
	case 'g':
	case 'G':
		mult = 1e9;
		end++;
		break;
	default:
		break;
	}

	if (*end && strcasecmp(end, "bps") && strcasecmp(end, "bit") && strcasecmp(end, "b"))
		return -1;

	value *= mult;
	if (value < 1 || value > 1e15)
		return -1;

	*bps = (uint64_t)(value + 0.5);
	return 0;
}

static const char *qos_rate2str(uint64_t bps, char *buf, size_t len)
{
	if (bps % 1000000000ULL == 0)
		snprintf(buf, len, "%" PRIu64 "gbps", bps / 1000000000ULL);
	else if (bps % 1000000ULL == 0)
		snprintf(buf, len, "%" PRIu64 "mbps", bps / 1000000ULL);
	else if (bps % 1000ULL == 0)
		snprintf(buf, len, "%" PRIu64 "kbps", bps / 1000ULL);
	else
		snprintf(buf, len, "%lubps", bps);

	return buf;
}

static const struct {
	const char *name;
	uint8_t value;
} qos_dscp_names[] = {
	{ "default", 0 }, { "cs1", 8 },	  { "af11", 10 }, { "af12", 12 }, { "af13", 14 },
	{ "cs2", 16 },	  { "af21", 18 }, { "af22", 20 }, { "af23", 22 }, { "cs3", 24 },
	{ "af31", 26 },	  { "af32", 28 }, { "af33", 30 }, { "cs4", 32 },  { "af41", 34 },
	{ "af42", 36 },	  { "af43", 38 }, { "cs5", 40 },  { "ef", 46 },	  { "cs6", 48 },
	{ "cs7", 56 },
};

static int qos_parse_dscp(const char *str, uint8_t *dscp)
{
	char *end;
	unsigned long val;

	for (size_t i = 0; i < array_size(qos_dscp_names); i++) {
		if (strcasecmp(str, qos_dscp_names[i].name) == 0) {
			*dscp = qos_dscp_names[i].value;
			return 0;
		}
	}

	if (strcasecmp(str, "cs0") == 0) {
		*dscp = 0;
		return 0;
	}

	errno = 0;
	val = strtoul(str, &end, 10);
	if (end == str || *end || errno || val > 63)
		return -1;

	*dscp = val;
	return 0;
}

static const char *qos_dscp2str(uint8_t dscp, char *buf, size_t len)
{
	for (size_t i = 0; i < array_size(qos_dscp_names); i++) {
		if (qos_dscp_names[i].value == dscp) {
			snprintf(buf, len, "%s", qos_dscp_names[i].name);
			return buf;
		}
	}

	snprintf(buf, len, "%u", dscp);
	return buf;
}

/*
 * ----------------------------------------------------------------------
 * ip access-list extended
 * ----------------------------------------------------------------------
 */

DEFPY_YANG_NOSH (ip_access_list_extended,
		 ip_access_list_extended_cmd,
		 "ip access-list extended QOS_ACLX_NAME$name",
		 IP_STR
		 "Add an access list entry\n"
		 ACLX_STR
		 "Access-list name\n")
{
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath, sizeof(xpath), QOS_ACLX_XPATH, name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(ACL_EXT_NODE, xpath);

	return ret;
}

DEFPY_YANG (no_ip_access_list_extended,
	    no_ip_access_list_extended_cmd,
	    "no ip access-list extended QOS_ACLX_NAME$name",
	    NO_STR
	    IP_STR
	    "Add an access list entry\n"
	    ACLX_STR
	    "Access-list name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), QOS_ACLX_XPATH, name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

/* Search the candidate entries of the current access-list */
struct aclx_cli_find {
	/* in: entry to look for (action NULL: remark) */
	const char *action;
	const char *text;
	uint32_t skip_seq;
	/* out */
	uint32_t found_seq;
	uint32_t max_seq;
};

static int aclx_cli_find_cb(const struct lyd_node *dnode, void *arg)
{
	struct aclx_cli_find *f = arg;
	uint32_t seq = yang_dnode_get_uint32(dnode, "sequence");

	if (seq > f->max_seq)
		f->max_seq = seq;
	if (f->found_seq || seq == f->skip_seq || !f->text)
		return YANG_ITER_CONTINUE;

	if (f->action) {
		if (yang_dnode_exists(dnode, "action") &&
		    strcmp(yang_dnode_get_string(dnode, "action"), f->action) == 0 &&
		    yang_dnode_exists(dnode, "match") &&
		    strcmp(yang_dnode_get_string(dnode, "match"), f->text) == 0)
			f->found_seq = seq;
	} else if (yang_dnode_exists(dnode, "remark") &&
		   strcmp(yang_dnode_get_string(dnode, "remark"), f->text) == 0) {
		f->found_seq = seq;
	}

	return YANG_ITER_CONTINUE;
}

static void aclx_cli_find(struct vty *vty, struct aclx_cli_find *f)
{
	yang_dnode_iterate(aclx_cli_find_cb, f, vty->candidate_config->dnode, "%s/entry",
			   VTY_CURR_XPATH);
}

/* Canonical form of the match text, or NULL after printing the error */
static const char *aclx_cli_canonical(struct vty *vty, const char *text, char *buf, size_t len)
{
	struct aclx_rule *rule = XCALLOC(MTYPE_TMP, sizeof(*rule));
	char err[256];
	const char *ret = buf;

	if (aclx_rule_parse(text, rule, err, sizeof(err)) < 0) {
		vty_out(vty, "%% Invalid access-list entry: %s\n", err);
		ret = NULL;
	} else if (!aclx_rule_print(rule, buf, len)) {
		vty_out(vty, "%% Invalid access-list entry: too long in canonical form\n");
		ret = NULL;
	}
	XFREE(MTYPE_TMP, rule);

	return ret;
}

/* Sequence number given as the first argument, or the next free one */
static int64_t aclx_cli_seq(struct vty *vty, struct cmd_token **argv, int *idx)
{
	struct aclx_cli_find f = {};

	if (argv[0]->type == RANGE_TKN) {
		*idx = 1;
		return strtoul(argv[0]->arg, NULL, 10);
	}

	*idx = 0;
	aclx_cli_find(vty, &f);
	if ((uint64_t)f.max_seq + 10 > UINT32_MAX) {
		vty_out(vty, "%% No sequence number left, renumber the access-list\n");
		return -1;
	}
	/* like Cisco: 10, 20, 30... */
	return f.max_seq + 10;
}

DEFUN_YANG (aclx_entry,
	    aclx_entry_cmd,
	    "[(1-4294967295)] <permit|deny> LINE...",
	    ACLX_SEQ_STR
	    "Specify packets to forward (select)\n"
	    "Specify packets to reject (not select)\n"
	    ACLX_LINE_STR)
{
	char xpath[XPATH_MAXLEN], axpath[XPATH_MAXLEN + 16], mxpath[XPATH_MAXLEN + 16];
	char canon[ACLX_TEXT_MAX];
	struct aclx_cli_find f = {};
	const char *action;
	char *text;
	int64_t seq;
	int idx;

	seq = aclx_cli_seq(vty, argv, &idx);
	if (seq < 0)
		return CMD_WARNING_CONFIG_FAILED;
	action = argv[idx]->text;

	text = argv_concat(argv, argc, idx + 1);
	if (!aclx_cli_canonical(vty, text, canon, sizeof(canon))) {
		XFREE(MTYPE_TMP, text);
		return CMD_WARNING_CONFIG_FAILED;
	}
	XFREE(MTYPE_TMP, text);

	f.action = action;
	f.text = canon;
	f.skip_seq = seq;
	aclx_cli_find(vty, &f);
	if (f.found_seq) {
		vty_out(vty, "%% Duplicate access-list entry (sequence %u)\n", f.found_seq);
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath, sizeof(xpath), "./entry[sequence='%" PRId64 "']", seq);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(axpath, sizeof(axpath), "%s/remark", xpath);
	nb_cli_enqueue_change(vty, axpath, NB_OP_DESTROY, NULL);
	snprintf(axpath, sizeof(axpath), "%s/action", xpath);
	nb_cli_enqueue_change(vty, axpath, NB_OP_MODIFY, action);
	snprintf(mxpath, sizeof(mxpath), "%s/match", xpath);
	nb_cli_enqueue_change(vty, mxpath, NB_OP_MODIFY, canon);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (aclx_remark,
	    aclx_remark_cmd,
	    "[(1-4294967295)] remark LINE...",
	    ACLX_SEQ_STR
	    "Access list entry comment\n"
	    "Comment up to 100 characters\n")
{
	char xpath[XPATH_MAXLEN], axpath[XPATH_MAXLEN + 16], mxpath[XPATH_MAXLEN + 16];
	char rxpath[XPATH_MAXLEN + 16];
	char *text;
	int64_t seq;
	int idx, ret;

	seq = aclx_cli_seq(vty, argv, &idx);
	if (seq < 0)
		return CMD_WARNING_CONFIG_FAILED;

	text = argv_concat(argv, argc, idx + 1);
	if (strlen(text) > 100) {
		vty_out(vty, "%% Remark too long (at most 100 characters)\n");
		XFREE(MTYPE_TMP, text);
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath, sizeof(xpath), "./entry[sequence='%" PRId64 "']", seq);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(axpath, sizeof(axpath), "%s/action", xpath);
	nb_cli_enqueue_change(vty, axpath, NB_OP_DESTROY, NULL);
	snprintf(mxpath, sizeof(mxpath), "%s/match", xpath);
	nb_cli_enqueue_change(vty, mxpath, NB_OP_DESTROY, NULL);
	snprintf(rxpath, sizeof(rxpath), "%s/remark", xpath);
	nb_cli_enqueue_change(vty, rxpath, NB_OP_MODIFY, text);

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, text);

	return ret;
}

static int aclx_cli_delete_seq(struct vty *vty, const char *seq)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./entry[sequence='%s']", seq);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_aclx_seq,
	    no_aclx_seq_cmd,
	    "no (1-4294967295)",
	    NO_STR
	    ACLX_SEQ_STR)
{
	return aclx_cli_delete_seq(vty, argv[1]->arg);
}

/* "no 10 permit ...", the rest of the entry is not checked */
DEFUN_YANG (no_aclx_seq_entry,
	    no_aclx_seq_entry_cmd,
	    "no (1-4294967295) <permit|deny|remark> LINE...",
	    NO_STR
	    ACLX_SEQ_STR
	    "Specify packets to forward (select)\n"
	    "Specify packets to reject (not select)\n"
	    "Access list entry comment\n"
	    "Ignored\n")
{
	return aclx_cli_delete_seq(vty, argv[1]->arg);
}

DEFUN_YANG (no_aclx_entry,
	    no_aclx_entry_cmd,
	    "no <permit|deny|remark> LINE...",
	    NO_STR
	    "Specify packets to forward (select)\n"
	    "Specify packets to reject (not select)\n"
	    "Access list entry comment\n"
	    "The entry to remove\n")
{
	char xpath[XPATH_MAXLEN];
	char canon[ACLX_TEXT_MAX];
	struct aclx_cli_find f = {};
	bool remark = strcmp(argv[1]->text, "remark") == 0;
	char *text;

	text = argv_concat(argv, argc, 2);
	if (remark) {
		strlcpy(canon, text, sizeof(canon));
	} else if (!aclx_cli_canonical(vty, text, canon, sizeof(canon))) {
		XFREE(MTYPE_TMP, text);
		return CMD_WARNING_CONFIG_FAILED;
	}
	XFREE(MTYPE_TMP, text);

	f.action = remark ? NULL : argv[1]->text;
	f.text = canon;
	aclx_cli_find(vty, &f);
	if (!f.found_seq) {
		vty_out(vty, "%% No such access-list entry\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath, sizeof(xpath), "./entry[sequence='%u']", f.found_seq);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void cli_show_aclx(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "ip access-list extended %s\n", yang_dnode_get_string(dnode, "name"));
}

static void cli_show_aclx_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

/* entries are shown in sequence order */
static int cli_cmp_aclx_entry(const struct lyd_node *dnode1, const struct lyd_node *dnode2)
{
	uint32_t seq1 = yang_dnode_get_uint32(dnode1, "sequence");
	uint32_t seq2 = yang_dnode_get_uint32(dnode2, "sequence");

	return seq1 < seq2 ? -1 : seq1 > seq2;
}

static void cli_show_aclx_entry(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	uint32_t seq = yang_dnode_get_uint32(dnode, "sequence");

	if (yang_dnode_exists(dnode, "remark"))
		vty_out(vty, " %u remark %s\n", seq, yang_dnode_get_string(dnode, "remark"));
	else if (yang_dnode_exists(dnode, "action") && yang_dnode_exists(dnode, "match"))
		vty_out(vty, " %u %s %s\n", seq, yang_dnode_get_string(dnode, "action"),
			yang_dnode_get_string(dnode, "match"));
}

/*
 * ----------------------------------------------------------------------
 * class-map
 * ----------------------------------------------------------------------
 */

DEFPY_YANG_NOSH (class_map,
		 class_map_cmd,
		 "class-map [<match-any|match-all>$mtype] QOS_CMAP_NAME$name",
		 CLASS_MAP_STR
		 "Packets must match at least one match statement\n"
		 "Packets must match all match statements (default)\n"
		 "Class-map name\n")
{
	char xpath[XPATH_MAXLEN];
	int ret;

	if (strcmp(name, "class-default") == 0) {
		vty_out(vty, "%% class-default is reserved\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath, sizeof(xpath), QOS_CLASS_MAP_XPATH, name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (mtype) {
		char mxpath[XPATH_MAXLEN + 16];

		snprintf(mxpath, sizeof(mxpath), "%s/match-type", xpath);
		nb_cli_enqueue_change(vty, mxpath, NB_OP_MODIFY, mtype);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(CLASS_MAP_NODE, xpath);

	return ret;
}

DEFPY_YANG (no_class_map,
	    no_class_map_cmd,
	    "no class-map [<match-any|match-all>] QOS_CMAP_NAME$name",
	    NO_STR
	    CLASS_MAP_STR
	    "Packets must match at least one match statement\n"
	    "Packets must match all match statements\n"
	    "Class-map name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), QOS_CLASS_MAP_XPATH, name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

DEFPY_YANG (class_map_match_acl,
	    class_map_match_acl_cmd,
	    "[no] match access-group name ACCESSLIST_NAME$acl",
	    NO_STR
	    "Classification criteria\n"
	    "Access group\n"
	    "Named access list\n"
	    "Access list name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./access-group[.='%s']", acl);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (class_map_match_dscp,
	    class_map_match_dscp_cmd,
	    "[no] match ip dscp DSCP...",
	    NO_STR
	    "Classification criteria\n"
	    "IP specific values\n"
	    "Match IP DSCP (DiffServ CodePoints)\n"
	    "DSCP value (0-63) or name: default, cs0-cs7, af11-af43, ef\n")
{
	bool no = strcmp(argv[0]->text, "no") == 0;
	int idx = no ? 4 : 3;
	char xpath[XPATH_MAXLEN];

	for (int i = idx; i < argc; i++) {
		uint8_t dscp;

		if (qos_parse_dscp(argv[i]->arg, &dscp)) {
			vty_out(vty, "%% Invalid DSCP value: %s\n", argv[i]->arg);
			return CMD_WARNING_CONFIG_FAILED;
		}

		snprintf(xpath, sizeof(xpath), "./dscp[.='%u']", dscp);
		nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (class_map_match_any,
	    class_map_match_any_cmd,
	    "[no] match any",
	    NO_STR
	    "Classification criteria\n"
	    "Match any packet\n")
{
	nb_cli_enqueue_change(vty, "./any", no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void cli_show_class_map(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "class-map %s %s\n", yang_dnode_get_string(dnode, "match-type"),
		yang_dnode_get_string(dnode, "name"));
}

static void cli_show_class_map_end(struct vty *vty, const struct lyd_node *dnode)
{
	const struct lyd_node *child;
	bool first = true;
	char buf[16];

	/* all DSCP values are shown as a single match statement */
	LY_LIST_FOR (lyd_child(dnode), child) {
		if (strcmp(child->schema->name, "dscp"))
			continue;

		if (first)
			vty_out(vty, " match ip dscp");
		vty_out(vty, " %s",
			qos_dscp2str(yang_dnode_get_uint8(child, NULL), buf, sizeof(buf)));
		first = false;
	}
	if (!first)
		vty_out(vty, "\n");

	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

static void cli_show_class_map_access_group(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " match access-group name %s\n", yang_dnode_get_string(dnode, NULL));
}

static void cli_show_class_map_any(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	vty_out(vty, " match any\n");
}

/*
 * ----------------------------------------------------------------------
 * policy-map
 * ----------------------------------------------------------------------
 */

DEFPY_YANG_NOSH (policy_map,
		 policy_map_cmd,
		 "policy-map QOS_PMAP_NAME$name [<hfsc|htb>$type]",
		 POLICY_MAP_STR
		 "Policy-map name\n"
		 "HFSC policy-map: classes are configured with service curves\n"
		 "HTB policy-map (default): classes are configured with rates\n")
{
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath, sizeof(xpath), QOS_POLICY_MAP_XPATH, name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	/* without a type an existing policy-map keeps its type */
	if (type) {
		char txpath[XPATH_MAXLEN + 8];

		snprintf(txpath, sizeof(txpath), "%s/type", xpath);
		nb_cli_enqueue_change(vty, txpath, NB_OP_MODIFY, type);
	}

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(POLICY_MAP_NODE, xpath);

	return ret;
}

DEFPY_YANG (no_policy_map,
	    no_policy_map_cmd,
	    "no policy-map QOS_PMAP_NAME$name [<hfsc|htb>]",
	    NO_STR
	    POLICY_MAP_STR
	    "Policy-map name\n"
	    "HFSC policy-map\n"
	    "HTB policy-map\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), QOS_POLICY_MAP_XPATH, name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes_clear_pending(vty, NULL);
}

DEFPY_YANG_NOSH (policy_map_class,
		 policy_map_class_cmd,
		 "class QOS_CMAP_NAME$name",
		 "Configure a class of the policy-map\n"
		 "Class-map name, or class-default\n")
{
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath, sizeof(xpath), "%s/class[name='%s']", VTY_CURR_XPATH, name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(POLICY_MAP_CLASS_NODE, xpath);

	return ret;
}

DEFPY_YANG (no_policy_map_class,
	    no_policy_map_class_cmd,
	    "no class QOS_CMAP_NAME$name",
	    NO_STR
	    "Remove a class from the policy-map\n"
	    "Class-map name, or class-default\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "%s/class[name='%s']", VTY_CURR_XPATH, name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static int qos_class_rate_set(struct vty *vty, const char *container, const char *percent,
			      const char *rate)
{
	char xpath[XPATH_MAXLEN];
	char value[32];
	uint64_t bps;

	if (percent) {
		snprintf(xpath, sizeof(xpath), "./%s/percent", container);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, percent);
	} else {
		if (qos_parse_rate(rate, &bps)) {
			vty_out(vty, "%% Invalid rate: %s\n", rate);
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintf(value, sizeof(value), "%lu", bps);
		snprintf(xpath, sizeof(xpath), "./%s/bps", container);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, value);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static int qos_class_rate_unset(struct vty *vty, const char *container)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "./%s/percent", container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	snprintf(xpath, sizeof(xpath), "./%s/bps", container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (policy_class_bandwidth,
	    policy_class_bandwidth_cmd,
	    "bandwidth <percent (1-100)$percent|RATE$rate>",
	    "Guaranteed bandwidth (HTB rate) of the class\n"
	    "Percentage of the parent bandwidth\n"
	    "Percentage\n"
	    RATE_STR)
{
	return qos_class_rate_set(vty, "bandwidth", percent_str, rate);
}

DEFPY_YANG (no_policy_class_bandwidth,
	    no_policy_class_bandwidth_cmd,
	    "no bandwidth [<percent (1-100)|RATE>]",
	    NO_STR
	    "Guaranteed bandwidth (HTB rate) of the class\n"
	    "Percentage of the parent bandwidth\n"
	    "Percentage\n"
	    RATE_STR)
{
	return qos_class_rate_unset(vty, "bandwidth");
}

DEFPY_YANG (policy_class_max_bandwidth,
	    policy_class_max_bandwidth_cmd,
	    "max-bandwidth <percent (1-100)$percent|RATE$rate>",
	    "Maximum bandwidth (HTB ceil) of the class\n"
	    "Percentage of the interface QoS bandwidth\n"
	    "Percentage\n"
	    RATE_STR)
{
	return qos_class_rate_set(vty, "max-bandwidth", percent_str, rate);
}

DEFPY_YANG (no_policy_class_max_bandwidth,
	    no_policy_class_max_bandwidth_cmd,
	    "no max-bandwidth [<percent (1-100)|RATE>]",
	    NO_STR
	    "Maximum bandwidth (HTB ceil) of the class\n"
	    "Percentage of the interface QoS bandwidth\n"
	    "Percentage\n"
	    RATE_STR)
{
	return qos_class_rate_unset(vty, "max-bandwidth");
}

DEFPY_YANG (policy_class_priority,
	    policy_class_priority_cmd,
	    "[no] priority ![(0-7)$prio]",
	    NO_STR
	    "Class priority, used to share excess bandwidth\n"
	    "Priority, 0 is the highest\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./priority", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./priority", NB_OP_MODIFY, prio_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (policy_class_queue_limit,
	    policy_class_queue_limit_cmd,
	    "[no] queue-limit ![(1-4294967295)$limit [packets]]",
	    NO_STR
	    "Queue length of the class\n"
	    "Queue length\n"
	    "Queue length is in packets\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./queue-limit", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./queue-limit", NB_OP_MODIFY, limit_str);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (policy_class_service_policy,
	    policy_class_service_policy_cmd,
	    "[no] service-policy ![QOS_PMAP_NAME$name]",
	    NO_STR
	    "Apply a child policy-map to the traffic of this class\n"
	    "Child policy-map name\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./service-policy", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./service-policy", NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Parse a delay such as "10ms", "500us", "1s" or "20" (milliseconds) into
 * microseconds.
 */
static int qos_parse_delay(const char *str, uint32_t *usec)
{
	char *end;
	double value, mult = 1000;

	errno = 0;
	value = strtod(str, &end);
	if (end == str || errno || value <= 0)
		return -1;

	if (*end == '\0' || !strcasecmp(end, "ms") || !strcasecmp(end, "msec"))
		mult = 1000;
	else if (!strcasecmp(end, "us") || !strcasecmp(end, "usec"))
		mult = 1;
	else if (!strcasecmp(end, "s") || !strcasecmp(end, "sec"))
		mult = 1000000;
	else
		return -1;

	value *= mult;
	if (value < 1 || value > UINT32_MAX)
		return -1;

	*usec = (uint32_t)(value + 0.5);
	return 0;
}

static const char *qos_delay2str(uint32_t usec, char *buf, size_t len)
{
	if (usec % 1000000 == 0)
		snprintf(buf, len, "%us", usec / 1000000);
	else if (usec % 1000 == 0)
		snprintf(buf, len, "%ums", usec / 1000);
	else
		snprintf(buf, len, "%uus", usec);

	return buf;
}

/*
 * Enqueue m1 or m2 of a service curve: a percentage or a rate.  The change
 * keeps pointing at @value, which must stay valid until it is applied.
 */
static int qos_curve_rate_enqueue(struct vty *vty, const char *base, const char *which,
				  const char *percent, const char *rate, char *value,
				  size_t value_len)
{
	char xpath[XPATH_MAXLEN];
	uint64_t bps;

	if (percent) {
		snprintf(xpath, sizeof(xpath), "%s/%s/percent", base, which);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, percent);
		return CMD_SUCCESS;
	}

	if (qos_parse_rate(rate, &bps)) {
		vty_out(vty, "%% Invalid rate: %s\n", rate);
		return CMD_WARNING_CONFIG_FAILED;
	}
	snprintf(value, value_len, "%" PRIu64, bps);
	snprintf(xpath, sizeof(xpath), "%s/%s/bps", base, which);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, value);

	return CMD_SUCCESS;
}

DEFPY_YANG (policy_class_curve,
	    policy_class_curve_cmd,
	    "<rt|ls|sc|ul>$curve [m1 <percent (1-100)$m1_pct|RATE$m1_rate> d DELAY$delay] m2 <percent (1-100)$m2_pct|RATE$m2_rate>",
	    "HFSC real-time service curve (guaranteed rate and delay)\n"
	    "HFSC link-share service curve (share of the excess bandwidth)\n"
	    "HFSC real-time and link-share service curve\n"
	    "HFSC upper-limit service curve (maximum link-share rate)\n"
	    "Rate of the first segment of the curve\n"
	    "Percentage of the interface QoS bandwidth\n"
	    "Percentage\n"
	    RATE_STR
	    "Length of the first segment\n"
	    "Delay, optionally with a us, ms (default) or s suffix\n"
	    "Rate of the second segment of the curve (long term rate)\n"
	    "Percentage of the interface QoS bandwidth\n"
	    "Percentage\n"
	    RATE_STR)
{
	char base[32], xpath[XPATH_MAXLEN], value[16], m1_value[32], m2_value[32];
	uint32_t usec;
	int ret;

	snprintf(base, sizeof(base), "./%s", curve);

	/* replace the whole curve: drop a previous first segment */
	if (!delay) {
		snprintf(xpath, sizeof(xpath), "%s/m1", base);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		snprintf(xpath, sizeof(xpath), "%s/d", base);
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	}

	nb_cli_enqueue_change(vty, base, NB_OP_CREATE, NULL);

	if (delay) {
		if (qos_parse_delay(delay, &usec)) {
			vty_out(vty, "%% Invalid delay: %s\n", delay);
			return CMD_WARNING_CONFIG_FAILED;
		}
		snprintf(value, sizeof(value), "%u", usec);
		snprintf(xpath, sizeof(xpath), "%s/d", base);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, value);

		ret = qos_curve_rate_enqueue(vty, base, "m1", m1_pct_str, m1_rate, m1_value,
					     sizeof(m1_value));
		if (ret != CMD_SUCCESS)
			return ret;
	}

	ret = qos_curve_rate_enqueue(vty, base, "m2", m2_pct_str, m2_rate, m2_value,
				     sizeof(m2_value));
	if (ret != CMD_SUCCESS)
		return ret;

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_policy_class_curve,
	    no_policy_class_curve_cmd,
	    "no <rt|ls|sc|ul>$curve [m1 <percent (1-100)|RATE> d DELAY] [m2 <percent (1-100)|RATE>]",
	    NO_STR
	    "HFSC real-time service curve\n"
	    "HFSC link-share service curve\n"
	    "HFSC real-time and link-share service curve\n"
	    "HFSC upper-limit service curve\n"
	    "Rate of the first segment of the curve\n"
	    "Percentage of the interface QoS bandwidth\n"
	    "Percentage\n"
	    RATE_STR
	    "Length of the first segment\n"
	    "Delay\n"
	    "Rate of the second segment of the curve\n"
	    "Percentage of the interface QoS bandwidth\n"
	    "Percentage\n"
	    RATE_STR)
{
	char xpath[32];

	snprintf(xpath, sizeof(xpath), "./%s", curve);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* "percent N" or "20mbps" for a rate-spec container */
static const char *qos_rate_spec2str(const struct lyd_node *dnode, char *buf, size_t len)
{
	char rate[32];

	if (yang_dnode_exists(dnode, "percent"))
		snprintf(buf, len, "percent %u", yang_dnode_get_uint8(dnode, "percent"));
	else
		snprintf(buf, len, "%s",
			 qos_rate2str(yang_dnode_get_uint64(dnode, "bps"), rate, sizeof(rate)));

	return buf;
}

static void cli_show_policy_class_curve(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults)
{
	char m1[32], m2[32], d[16];

	vty_out(vty, "  %s", dnode->schema->name);
	if (yang_dnode_exists(dnode, "d"))
		vty_out(vty, " m1 %s d %s",
			qos_rate_spec2str(yang_dnode_get(dnode, "m1"), m1, sizeof(m1)),
			qos_delay2str(yang_dnode_get_uint32(dnode, "d"), d, sizeof(d)));
	vty_out(vty, " m2 %s\n", qos_rate_spec2str(yang_dnode_get(dnode, "m2"), m2, sizeof(m2)));
}

static void cli_show_policy_map(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "policy-map %s%s\n", yang_dnode_get_string(dnode, "name"),
		strcmp(yang_dnode_get_string(dnode, "type"), "hfsc") == 0 ? " hfsc" : "");
}

static void cli_show_policy_map_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, "exit\n");
	vty_out(vty, "!\n");
}

static void cli_show_policy_class(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " class %s\n", yang_dnode_get_string(dnode, "name"));
}

static void cli_show_policy_class_end(struct vty *vty, const struct lyd_node *dnode)
{
	vty_out(vty, " exit\n");
}

static void cli_show_policy_class_rate(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults)
{
	/* dnode is .../<bandwidth|max-bandwidth>/<percent|bps> */
	const char *container = lyd_parent(dnode)->schema->name;
	char buf[32];

	if (strcmp(dnode->schema->name, "percent") == 0)
		vty_out(vty, "  %s percent %u\n", container, yang_dnode_get_uint8(dnode, NULL));
	else
		vty_out(vty, "  %s %s\n", container,
			qos_rate2str(yang_dnode_get_uint64(dnode, NULL), buf, sizeof(buf)));
}

static void cli_show_policy_class_priority(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	vty_out(vty, "  priority %u\n", yang_dnode_get_uint8(dnode, NULL));
}

static void cli_show_policy_class_queue_limit(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, "  queue-limit %u packets\n", yang_dnode_get_uint32(dnode, NULL));
}

static void cli_show_policy_class_service_policy(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	vty_out(vty, "  service-policy %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * ----------------------------------------------------------------------
 * interface
 * ----------------------------------------------------------------------
 */

DEFPY_YANG (interface_qos_bandwidth,
	    interface_qos_bandwidth_cmd,
	    "qos bandwidth RATE$rate",
	    QOS_STR
	    "Bandwidth available to the output service-policy\n"
	    RATE_STR)
{
	char value[32];
	uint64_t bps;

	if (qos_parse_rate(rate, &bps)) {
		vty_out(vty, "%% Invalid rate: %s\n", rate);
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(value, sizeof(value), "%lu", bps);
	nb_cli_enqueue_change(vty, "./frr-qos:qos/bandwidth", NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_interface_qos_bandwidth,
	    no_interface_qos_bandwidth_cmd,
	    "no qos bandwidth [RATE]",
	    NO_STR
	    QOS_STR
	    "Bandwidth available to the output service-policy\n"
	    RATE_STR)
{
	nb_cli_enqueue_change(vty, "./frr-qos:qos/bandwidth", NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (interface_service_policy,
	    interface_service_policy_cmd,
	    "[no] service-policy [output] ![QOS_PMAP_NAME$name]",
	    NO_STR
	    SERVICE_POLICY_STR
	    "Apply to traffic leaving the interface (default)\n"
	    "Policy-map name\n")
{
	if (no)
		nb_cli_enqueue_change(vty, "./frr-qos:qos/service-policy-output", NB_OP_DESTROY,
				      NULL);
	else
		nb_cli_enqueue_change(vty, "./frr-qos:qos/service-policy-output", NB_OP_MODIFY,
				      name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (interface_ip_access_group,
	    interface_ip_access_group_cmd,
	    "ip access-group QOS_ACLX_NAME$name <in|out>$dir",
	    IP_STR
	    "Apply an extended access-list to the interface\n"
	    "Access-list name\n"
	    "Filter traffic received on the interface\n"
	    "Filter traffic sent on the interface\n")
{
	char xpath[64];

	snprintf(xpath, sizeof(xpath), "./frr-qos:access-group/%s", dir);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_interface_ip_access_group,
	    no_interface_ip_access_group_cmd,
	    "no ip access-group [QOS_ACLX_NAME$name] <in|out>$dir",
	    NO_STR
	    IP_STR
	    "Apply an extended access-list to the interface\n"
	    "Access-list name\n"
	    "Filter traffic received on the interface\n"
	    "Filter traffic sent on the interface\n")
{
	char xpath[64];

	snprintf(xpath, sizeof(xpath), "./frr-qos:access-group/%s", dir);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

static void cli_show_interface_access_group(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults)
{
	vty_out(vty, " ip access-group %s %s\n", yang_dnode_get_string(dnode, NULL),
		dnode->schema->name);
}

static void cli_show_interface_qos_bandwidth(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults)
{
	char buf[32];

	vty_out(vty, " qos bandwidth %s\n",
		qos_rate2str(yang_dnode_get_uint64(dnode, NULL), buf, sizeof(buf)));
}

static void cli_show_interface_service_policy(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	vty_out(vty, " service-policy output %s\n", yang_dnode_get_string(dnode, NULL));
}

/*
 * ----------------------------------------------------------------------
 * Nodes and init
 * ----------------------------------------------------------------------
 */

/*
 * Note: mgmtd writes the running configuration of all YANG modules itself
 * (mgmtd_config_write()), so these nodes have no config_write callback.
 */
static struct cmd_node class_map_node = {
	.name = "class-map",
	.node = CLASS_MAP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-cmap)# ",
};

static struct cmd_node policy_map_node = {
	.name = "policy-map",
	.node = POLICY_MAP_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-pmap)# ",
};

static struct cmd_node policy_map_class_node = {
	.name = "policy-map class",
	.node = POLICY_MAP_CLASS_NODE,
	.parent_node = POLICY_MAP_NODE,
	.prompt = "%s(config-pmap-c)# ",
};

static struct cmd_node acl_ext_node = {
	.name = "ip access-list extended",
	.node = ACL_EXT_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-ext-nacl)# ",
};

static const struct cmd_variable_handler qos_var_handlers[] = {
	{ .tokenname = "QOS_ACLX_NAME", .xpath = QOS_XPATH "/extended-access-list/name" },
	{ .tokenname = "QOS_CMAP_NAME", .xpath = QOS_XPATH "/class-map/name" },
	{ .tokenname = "QOS_PMAP_NAME", .xpath = QOS_XPATH "/policy-map/name" },
	{ .completions = NULL },
};

/* clang-format off */
const struct frr_yang_module_info frr_qos_cli_info = {
	.name = "frr-qos",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-qos:qos/extended-access-list",
			.cbs = {
				.cli_show = cli_show_aclx,
				.cli_show_end = cli_show_aclx_end,
			}
		},
		{
			.xpath = "/frr-qos:qos/extended-access-list/entry",
			.cbs = {
				.cli_cmp = cli_cmp_aclx_entry,
				.cli_show = cli_show_aclx_entry,
			}
		},
		{
			.xpath = "/frr-qos:qos/class-map",
			.cbs = {
				.cli_show = cli_show_class_map,
				.cli_show_end = cli_show_class_map_end,
			}
		},
		{
			.xpath = "/frr-qos:qos/class-map/access-group",
			.cbs.cli_show = cli_show_class_map_access_group,
		},
		{
			.xpath = "/frr-qos:qos/class-map/any",
			.cbs.cli_show = cli_show_class_map_any,
		},
		{
			.xpath = "/frr-qos:qos/policy-map",
			.cbs = {
				.cli_show = cli_show_policy_map,
				.cli_show_end = cli_show_policy_map_end,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class",
			.cbs = {
				.cli_show = cli_show_policy_class,
				.cli_show_end = cli_show_policy_class_end,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/bandwidth/percent",
			.cbs.cli_show = cli_show_policy_class_rate,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/bandwidth/bps",
			.cbs.cli_show = cli_show_policy_class_rate,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/max-bandwidth/percent",
			.cbs.cli_show = cli_show_policy_class_rate,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/max-bandwidth/bps",
			.cbs.cli_show = cli_show_policy_class_rate,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/priority",
			.cbs.cli_show = cli_show_policy_class_priority,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/rt",
			.cbs.cli_show = cli_show_policy_class_curve,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ls",
			.cbs.cli_show = cli_show_policy_class_curve,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/sc",
			.cbs.cli_show = cli_show_policy_class_curve,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ul",
			.cbs.cli_show = cli_show_policy_class_curve,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/queue-limit",
			.cbs.cli_show = cli_show_policy_class_queue_limit,
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/service-policy",
			.cbs.cli_show = cli_show_policy_class_service_policy,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-qos:qos/bandwidth",
			.cbs.cli_show = cli_show_interface_qos_bandwidth,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-qos:access-group/in",
			.cbs.cli_show = cli_show_interface_access_group,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-qos:access-group/out",
			.cbs.cli_show = cli_show_interface_access_group,
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-qos:qos/service-policy-output",
			.cbs.cli_show = cli_show_interface_service_policy,
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

void zebra_qos_cli_init(void)
{
	cmd_variable_handler_register(qos_var_handlers);

	install_node(&acl_ext_node);
	install_node(&class_map_node);
	install_node(&policy_map_node);
	install_node(&policy_map_class_node);

	install_default(ACL_EXT_NODE);
	install_default(CLASS_MAP_NODE);
	install_default(POLICY_MAP_NODE);
	install_default(POLICY_MAP_CLASS_NODE);

	install_element(CONFIG_NODE, &ip_access_list_extended_cmd);
	install_element(CONFIG_NODE, &no_ip_access_list_extended_cmd);
	install_element(ACL_EXT_NODE, &aclx_entry_cmd);
	install_element(ACL_EXT_NODE, &aclx_remark_cmd);
	install_element(ACL_EXT_NODE, &no_aclx_seq_cmd);
	install_element(ACL_EXT_NODE, &no_aclx_seq_entry_cmd);
	install_element(ACL_EXT_NODE, &no_aclx_entry_cmd);

	install_element(CONFIG_NODE, &class_map_cmd);
	install_element(CONFIG_NODE, &no_class_map_cmd);
	install_element(CLASS_MAP_NODE, &class_map_match_acl_cmd);
	install_element(CLASS_MAP_NODE, &class_map_match_dscp_cmd);
	install_element(CLASS_MAP_NODE, &class_map_match_any_cmd);

	install_element(CONFIG_NODE, &policy_map_cmd);
	install_element(CONFIG_NODE, &no_policy_map_cmd);
	install_element(POLICY_MAP_NODE, &policy_map_class_cmd);
	install_element(POLICY_MAP_NODE, &no_policy_map_class_cmd);

	install_element(POLICY_MAP_CLASS_NODE, &policy_class_bandwidth_cmd);
	install_element(POLICY_MAP_CLASS_NODE, &no_policy_class_bandwidth_cmd);
	install_element(POLICY_MAP_CLASS_NODE, &policy_class_max_bandwidth_cmd);
	install_element(POLICY_MAP_CLASS_NODE, &no_policy_class_max_bandwidth_cmd);
	install_element(POLICY_MAP_CLASS_NODE, &policy_class_priority_cmd);
	install_element(POLICY_MAP_CLASS_NODE, &policy_class_curve_cmd);
	install_element(POLICY_MAP_CLASS_NODE, &no_policy_class_curve_cmd);
	install_element(POLICY_MAP_CLASS_NODE, &policy_class_queue_limit_cmd);
	install_element(POLICY_MAP_CLASS_NODE, &policy_class_service_policy_cmd);

	install_element(INTERFACE_NODE, &interface_qos_bandwidth_cmd);
	install_element(INTERFACE_NODE, &no_interface_qos_bandwidth_cmd);
	install_element(INTERFACE_NODE, &interface_service_policy_cmd);
	install_element(INTERFACE_NODE, &interface_ip_access_group_cmd);
	install_element(INTERFACE_NODE, &no_interface_ip_access_group_cmd);
}
