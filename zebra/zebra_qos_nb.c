// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra QoS northbound callbacks (frr-qos YANG module).
 *
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "memory.h"
#include "northbound.h"
#include "yang.h"

#include "zebra/interface.h"
#include "zebra/zebra_qos.h"
#include "zebra/zebra_acl_ext.h"

/*
 * ----------------------------------------------------------------------
 * /frr-qos:qos/extended-access-list
 * ----------------------------------------------------------------------
 */
static int qos_acl_ext_create(struct nb_cb_create_args *args)
{
	struct qos_acl_ext *acl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl = zebra_qos_acl_ext_get(yang_dnode_get_string(args->dnode, "name"));
	nb_running_set_entry(args->dnode, acl);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_acl_ext_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_acl_ext *acl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_unset_entry(args->dnode);
	zebra_qos_acl_ext_del(acl);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_acl_ext_entry_create(struct nb_cb_create_args *args)
{
	struct qos_acl_ext *acl;
	struct qos_acl_ext_entry *entry;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl = nb_running_get_entry(args->dnode, NULL, true);
	entry = zebra_qos_acl_ext_entry_add(acl, yang_dnode_get_uint32(args->dnode, "sequence"));
	nb_running_set_entry(args->dnode, entry);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_acl_ext_entry_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_acl_ext_entry *entry;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry = nb_running_unset_entry(args->dnode);
	zebra_qos_acl_ext_entry_del(entry);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_acl_ext_entry_action_modify(struct nb_cb_modify_args *args)
{
	struct qos_acl_ext_entry *entry;
	bool deny;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry = nb_running_get_entry(args->dnode, NULL, true);
	/* enum deny has value 1 */
	deny = yang_dnode_get_enum(args->dnode, NULL) == 1;
	entry->permit = !deny;
	entry->deny = deny;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_acl_ext_entry_action_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_acl_ext_entry *entry;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry = nb_running_get_entry(args->dnode, NULL, true);
	entry->permit = entry->deny = false;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_acl_ext_entry_match_modify(struct nb_cb_modify_args *args)
{
	struct qos_acl_ext_entry *entry;
	const char *text = yang_dnode_get_string(args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE: {
		struct aclx_rule *rule = XCALLOC(MTYPE_TMP, sizeof(*rule));
		char *buf = XCALLOC(MTYPE_TMP, ACLX_TEXT_MAX);
		int ret = aclx_rule_parse(text, rule, args->errmsg, args->errmsg_len);

		/* zebra keeps the canonical form, it must fit */
		if (ret == 0 && !aclx_rule_print(rule, buf, ACLX_TEXT_MAX)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "entry too long in canonical form");
			ret = -1;
		}
		XFREE(MTYPE_TMP, buf);
		XFREE(MTYPE_TMP, rule);
		return ret < 0 ? NB_ERR_VALIDATION : NB_OK;
	}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	entry = nb_running_get_entry(args->dnode, NULL, true);
	if (zebra_qos_acl_ext_entry_set_match(entry, text, args->errmsg, args->errmsg_len) < 0)
		/* validated above, cannot happen */
		return NB_ERR_INCONSISTENCY;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_acl_ext_entry_match_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_acl_ext_entry *entry;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry = nb_running_get_entry(args->dnode, NULL, true);
	zebra_qos_acl_ext_entry_unset_match(entry);
	zebra_qos_config_changed();

	return NB_OK;
}

/* Remarks are only kept in the configuration */
static int qos_acl_ext_entry_remark_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

static int qos_acl_ext_entry_remark_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * ----------------------------------------------------------------------
 * /frr-qos:qos/class-map
 * ----------------------------------------------------------------------
 */
static int qos_class_map_create(struct nb_cb_create_args *args)
{
	struct qos_class_map *cmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cmap = zebra_qos_class_map_get(yang_dnode_get_string(args->dnode, "name"));
	nb_running_set_entry(args->dnode, cmap);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_class_map_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_class_map *cmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cmap = nb_running_unset_entry(args->dnode);
	zebra_qos_class_map_del(cmap);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_class_map_match_type_modify(struct nb_cb_modify_args *args)
{
	struct qos_class_map *cmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cmap = nb_running_get_entry(args->dnode, NULL, true);
	/* enum match-any has value 1 */
	cmap->match_any = yang_dnode_get_enum(args->dnode, NULL) == 1;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_class_map_access_group_create(struct nb_cb_create_args *args)
{
	struct qos_class_map *cmap;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cmap = nb_running_get_entry(args->dnode, NULL, true);
	name = yang_dnode_get_string(args->dnode, NULL);
	zebra_qos_class_map_acl_add(cmap, name);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_class_map_access_group_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_class_map *cmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cmap = nb_running_get_entry(args->dnode, NULL, true);
	zebra_qos_class_map_acl_del(cmap, yang_dnode_get_string(args->dnode, NULL));
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_class_map_dscp_create(struct nb_cb_create_args *args)
{
	struct qos_class_map *cmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cmap = nb_running_get_entry(args->dnode, NULL, true);
	SET_FLAG(cmap->dscp, (uint64_t)1 << yang_dnode_get_uint8(args->dnode, NULL));
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_class_map_dscp_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_class_map *cmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cmap = nb_running_get_entry(args->dnode, NULL, true);
	UNSET_FLAG(cmap->dscp, (uint64_t)1 << yang_dnode_get_uint8(args->dnode, NULL));
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_class_map_any_create(struct nb_cb_create_args *args)
{
	struct qos_class_map *cmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cmap = nb_running_get_entry(args->dnode, NULL, true);
	cmap->match_all_packets = true;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_class_map_any_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_class_map *cmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	cmap = nb_running_get_entry(args->dnode, NULL, true);
	cmap->match_all_packets = false;
	zebra_qos_config_changed();

	return NB_OK;
}

/*
 * ----------------------------------------------------------------------
 * /frr-qos:qos/policy-map
 * ----------------------------------------------------------------------
 */
static int qos_policy_map_create(struct nb_cb_create_args *args)
{
	struct qos_policy_map *pmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pmap = zebra_qos_policy_map_get(yang_dnode_get_string(args->dnode, "name"));
	nb_running_set_entry(args->dnode, pmap);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_map_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_policy_map *pmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pmap = nb_running_unset_entry(args->dnode);
	zebra_qos_policy_map_del(pmap);
	zebra_qos_config_changed();

	return NB_OK;
}

/*
 * The class list is "ordered-by user": find the class configured right
 * before @dnode so the internal list follows the configuration order.
 */
static struct qos_policy_class *qos_policy_class_prev(const struct lyd_node *dnode)
{
	const struct lyd_node *first = lyd_first_sibling(dnode);
	const struct lyd_node *node = dnode;

	while (node != first) {
		node = node->prev;
		if (node->schema == dnode->schema)
			return nb_running_get_entry_non_rec(node, NULL, false);
	}

	return NULL;
}

static int qos_policy_class_create(struct nb_cb_create_args *args)
{
	struct qos_policy_map *pmap;
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pmap = nb_running_get_entry(args->dnode, NULL, true);
	pclass = zebra_qos_policy_class_add(pmap, yang_dnode_get_string(args->dnode, "name"),
					    qos_policy_class_prev(args->dnode));
	nb_running_set_entry(args->dnode, pclass);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_unset_entry(args->dnode);
	zebra_qos_policy_class_del(pclass);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_move(struct nb_cb_move_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	zebra_qos_policy_class_move(pclass, qos_policy_class_prev(args->dnode));
	zebra_qos_config_changed();

	return NB_OK;
}

/* HFSC curve a node below .../class/<rt|ls|sc|ul> belongs to, NULL otherwise */
static struct qos_curve *qos_policy_class_curve(const struct lyd_node *dnode,
						struct qos_policy_class *pclass)
{
	for (; dnode; dnode = lyd_parent(dnode)) {
		const char *name = dnode->schema->name;

		if (strcmp(name, "class") == 0)
			return NULL;
		if (strcmp(name, "rt") == 0)
			return &pclass->rt;
		if (strcmp(name, "ls") == 0)
			return &pclass->ls;
		if (strcmp(name, "sc") == 0)
			return &pclass->sc;
		if (strcmp(name, "ul") == 0)
			return &pclass->ul;
	}

	return NULL;
}

static struct qos_rate *qos_policy_class_rate(const struct lyd_node *dnode,
					      struct qos_policy_class *pclass)
{
	/*
	 * dnode is .../<bandwidth|max-bandwidth>/<percent|bps> or
	 * .../<rt|ls|sc|ul>/<m1|m2>/<percent|bps>
	 */
	const char *container = lyd_parent(dnode)->schema->name;
	struct qos_curve *curve = qos_policy_class_curve(dnode, pclass);

	if (curve)
		return strcmp(container, "m1") == 0 ? &curve->m1 : &curve->m2;

	if (strcmp(container, "max-bandwidth") == 0)
		return &pclass->max_bandwidth;

	return &pclass->bandwidth;
}

static int qos_policy_class_rate_percent_modify(struct nb_cb_modify_args *args)
{
	struct qos_policy_class *pclass;
	struct qos_rate *rate;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	rate = qos_policy_class_rate(args->dnode, pclass);
	rate->type = QOS_RATE_PERCENT;
	rate->value = yang_dnode_get_uint8(args->dnode, NULL);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_rate_bps_modify(struct nb_cb_modify_args *args)
{
	struct qos_policy_class *pclass;
	struct qos_rate *rate;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	rate = qos_policy_class_rate(args->dnode, pclass);
	rate->type = QOS_RATE_BPS;
	rate->value = yang_dnode_get_uint64(args->dnode, NULL);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_rate_destroy(struct nb_cb_destroy_args *args, enum qos_rate_type type)
{
	struct qos_policy_class *pclass;
	struct qos_rate *rate;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	rate = qos_policy_class_rate(args->dnode, pclass);
	/* switching between percent and bps destroys the other case */
	if (rate->type == type) {
		rate->type = QOS_RATE_NONE;
		rate->value = 0;
	}
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_rate_percent_destroy(struct nb_cb_destroy_args *args)
{
	return qos_policy_class_rate_destroy(args, QOS_RATE_PERCENT);
}

static int qos_policy_class_rate_bps_destroy(struct nb_cb_destroy_args *args)
{
	return qos_policy_class_rate_destroy(args, QOS_RATE_BPS);
}

static int qos_policy_class_curve_create(struct nb_cb_create_args *args)
{
	struct qos_policy_class *pclass;
	struct qos_curve *curve;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	curve = qos_policy_class_curve(args->dnode, pclass);
	/* m1, d and m2 follow in the same transaction */
	memset(curve, 0, sizeof(*curve));
	curve->set = true;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_curve_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	/* only the container gets a destroy callback, clear all of it */
	memset(qos_policy_class_curve(args->dnode, pclass), 0, sizeof(struct qos_curve));
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_curve_d_modify(struct nb_cb_modify_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	qos_policy_class_curve(args->dnode, pclass)->d = yang_dnode_get_uint32(args->dnode, NULL);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_curve_d_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	qos_policy_class_curve(args->dnode, pclass)->d = 0;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_map_type_modify(struct nb_cb_modify_args *args)
{
	struct qos_policy_map *pmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pmap = nb_running_get_entry(args->dnode, NULL, true);
	/* enum hfsc has value 1 */
	pmap->hfsc = yang_dnode_get_enum(args->dnode, NULL) == 1;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_priority_modify(struct nb_cb_modify_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	pclass->priority = yang_dnode_get_uint8(args->dnode, NULL);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_priority_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	pclass->priority = -1;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_queue_limit_modify(struct nb_cb_modify_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	pclass->queue_limit = yang_dnode_get_uint32(args->dnode, NULL);
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_queue_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	pclass->queue_limit = 0;
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_service_policy_modify(struct nb_cb_modify_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	strlcpy(pclass->service_policy, yang_dnode_get_string(args->dnode, NULL),
		sizeof(pclass->service_policy));
	zebra_qos_config_changed();

	return NB_OK;
}

static int qos_policy_class_service_policy_destroy(struct nb_cb_destroy_args *args)
{
	struct qos_policy_class *pclass;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	pclass = nb_running_get_entry(args->dnode, NULL, true);
	pclass->service_policy[0] = '\0';
	zebra_qos_config_changed();

	return NB_OK;
}

/*
 * ----------------------------------------------------------------------
 * /frr-interface:lib/interface/frr-qos:qos
 * ----------------------------------------------------------------------
 */
static struct zebra_if_qos *qos_nb_if(const struct lyd_node *dnode)
{
	struct interface *ifp = nb_running_get_entry(dnode, NULL, true);

	return zebra_qos_if_get(ifp);
}

static int lib_interface_qos_bandwidth_modify(struct nb_cb_modify_args *args)
{
	struct zebra_if_qos *qos;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	qos = qos_nb_if(args->dnode);
	if (!qos)
		return NB_ERR_INCONSISTENCY;

	qos->bandwidth = yang_dnode_get_uint64(args->dnode, NULL);
	zebra_qos_config_changed();

	return NB_OK;
}

static int lib_interface_qos_bandwidth_destroy(struct nb_cb_destroy_args *args)
{
	struct zebra_if_qos *qos;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	qos = qos_nb_if(args->dnode);
	if (qos)
		qos->bandwidth = 0;
	zebra_qos_config_changed();

	return NB_OK;
}

static int lib_interface_qos_service_policy_modify(struct nb_cb_modify_args *args)
{
	struct zebra_if_qos *qos;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	qos = qos_nb_if(args->dnode);
	if (!qos)
		return NB_ERR_INCONSISTENCY;

	strlcpy(qos->service_policy, yang_dnode_get_string(args->dnode, NULL),
		sizeof(qos->service_policy));
	zebra_qos_config_changed();

	return NB_OK;
}

static int lib_interface_qos_service_policy_destroy(struct nb_cb_destroy_args *args)
{
	struct zebra_if_qos *qos;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	qos = qos_nb_if(args->dnode);
	if (qos)
		qos->service_policy[0] = '\0';
	zebra_qos_config_changed();

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_qos_info = {
	.name = "frr-qos",
	.nodes = {
		{
			.xpath = "/frr-qos:qos/extended-access-list",
			.cbs = {
				.create = qos_acl_ext_create,
				.destroy = qos_acl_ext_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/extended-access-list/entry",
			.cbs = {
				.create = qos_acl_ext_entry_create,
				.destroy = qos_acl_ext_entry_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/extended-access-list/entry/action",
			.cbs = {
				.modify = qos_acl_ext_entry_action_modify,
				.destroy = qos_acl_ext_entry_action_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/extended-access-list/entry/match",
			.cbs = {
				.modify = qos_acl_ext_entry_match_modify,
				.destroy = qos_acl_ext_entry_match_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/extended-access-list/entry/remark",
			.cbs = {
				.modify = qos_acl_ext_entry_remark_modify,
				.destroy = qos_acl_ext_entry_remark_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/class-map",
			.cbs = {
				.create = qos_class_map_create,
				.destroy = qos_class_map_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/class-map/match-type",
			.cbs = {
				.modify = qos_class_map_match_type_modify,
			}
		},
		{
			.xpath = "/frr-qos:qos/class-map/access-group",
			.cbs = {
				.create = qos_class_map_access_group_create,
				.destroy = qos_class_map_access_group_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/class-map/dscp",
			.cbs = {
				.create = qos_class_map_dscp_create,
				.destroy = qos_class_map_dscp_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/class-map/any",
			.cbs = {
				.create = qos_class_map_any_create,
				.destroy = qos_class_map_any_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map",
			.cbs = {
				.create = qos_policy_map_create,
				.destroy = qos_policy_map_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/type",
			.cbs = {
				.modify = qos_policy_map_type_modify,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class",
			.cbs = {
				.create = qos_policy_class_create,
				.destroy = qos_policy_class_destroy,
				.move = qos_policy_class_move,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/bandwidth/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/bandwidth/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/max-bandwidth/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/max-bandwidth/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/priority",
			.cbs = {
				.modify = qos_policy_class_priority_modify,
				.destroy = qos_policy_class_priority_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/rt",
			.cbs = {
				.create = qos_policy_class_curve_create,
				.destroy = qos_policy_class_curve_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/rt/d",
			.cbs = {
				.modify = qos_policy_class_curve_d_modify,
				.destroy = qos_policy_class_curve_d_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/rt/m1/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/rt/m1/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/rt/m2/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/rt/m2/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ls",
			.cbs = {
				.create = qos_policy_class_curve_create,
				.destroy = qos_policy_class_curve_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ls/d",
			.cbs = {
				.modify = qos_policy_class_curve_d_modify,
				.destroy = qos_policy_class_curve_d_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ls/m1/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ls/m1/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ls/m2/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ls/m2/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/sc",
			.cbs = {
				.create = qos_policy_class_curve_create,
				.destroy = qos_policy_class_curve_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/sc/d",
			.cbs = {
				.modify = qos_policy_class_curve_d_modify,
				.destroy = qos_policy_class_curve_d_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/sc/m1/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/sc/m1/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/sc/m2/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/sc/m2/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ul",
			.cbs = {
				.create = qos_policy_class_curve_create,
				.destroy = qos_policy_class_curve_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ul/d",
			.cbs = {
				.modify = qos_policy_class_curve_d_modify,
				.destroy = qos_policy_class_curve_d_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ul/m1/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ul/m1/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ul/m2/percent",
			.cbs = {
				.modify = qos_policy_class_rate_percent_modify,
				.destroy = qos_policy_class_rate_percent_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/ul/m2/bps",
			.cbs = {
				.modify = qos_policy_class_rate_bps_modify,
				.destroy = qos_policy_class_rate_bps_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/queue-limit",
			.cbs = {
				.modify = qos_policy_class_queue_limit_modify,
				.destroy = qos_policy_class_queue_limit_destroy,
			}
		},
		{
			.xpath = "/frr-qos:qos/policy-map/class/service-policy",
			.cbs = {
				.modify = qos_policy_class_service_policy_modify,
				.destroy = qos_policy_class_service_policy_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-qos:qos/bandwidth",
			.cbs = {
				.modify = lib_interface_qos_bandwidth_modify,
				.destroy = lib_interface_qos_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-qos:qos/service-policy-output",
			.cbs = {
				.modify = lib_interface_qos_service_policy_modify,
				.destroy = lib_interface_qos_service_policy_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */
