// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * frr-confjson: convert FRR configuration between frr.conf text and JSON,
 * driven by the frr.xref command catalog produced by the FRR build.
 *
 *   frr-confjson [-x frr.xref] to-json [FILE|-]    running config -> JSON
 *   frr-confjson [-x frr.xref] to-conf [FILE|-]    JSON -> FRR config commands
 *
 * JSON format
 * -----------
 * The JSON follows the command line: every word of a command is one level
 * of nesting, and the last word is the value.  Commands that enter a
 * sub-mode (interface, router bgp, address-family, ...) hold the commands
 * of that mode:
 *
 *   interface eth0                    {"config": {
 *    ip address 192.0.2.1/24            "interface": {"eth0": {
 *    description uplink to core           "ip": {"address": "192.0.2.1/24"},
 *   exit                                  "description": "uplink to core"}},
 *   router bgp 65001                    "router": {"bgp": {"65001": {
 *    no bgp ebgp-requires-policy          "no": {"bgp": {"ebgp-requires-policy": true}},
 *    neighbor 192.0.2.2 remote-as 2       "neighbor": {"192.0.2.2": {"remote-as": 2}}}}}}}
 *   exit
 *
 * - a command that ends in a keyword has the value true
 * - free text ("description uplink to core") stays one string value
 * - several commands with the same words up to the value give a list:
 *   "ip route 10.0.0.0/8 192.0.2.1" + "... 192.0.2.2" ->
 *   {"ip": {"route": {"10.0.0.0/8": ["192.0.2.1", "192.0.2.2"]}}}
 * - "no" is the first word like on the command line: {"no": {...}}; a "no"
 *   command may carry arguments the negated command doesn't take (e.g. a
 *   description's text): they are dropped, never keywords of the command
 * - a key or value may hold several words ("timers": "10 30"), and a string
 *   in a list is a literal command line
 *
 * How it works
 * ------------
 * - Every DEFUN/DEFPY compiled into a daemon is listed in frr.xref
 *   (python/xrelfo.py) with the CLI node(s) it is installed into.  They are
 *   loaded at runtime, de-duplicated like python/xref2vtysh.py does for
 *   vtysh, and installed into libfrr's command graphs.
 * - The node hierarchy (which command enters which mode) is not in
 *   frr.xref; it comes from vtysh's node table and DEFUNSH handlers, which
 *   this tool links (but not vtysh's compiled-in copy of the commands).
 * - Lines are matched with libfrr's command_match(): FRR's own grammar
 *   decides which words are keywords and values (text -> JSON) and where a
 *   sub-mode command ends and the commands inside it begin (JSON -> text).
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <zebra.h>

#include <getopt.h>

#include "command.h"
#include "command_graph.h"
#include "command_match.h"
#include "graph.h"
#include "linklist.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "json.h"

#include "vtysh/vtysh.h"

#ifndef FRR_XREF_DEFAULT
#define FRR_XREF_DEFAULT "/usr/share/frr/frr.xref"
#endif
#ifndef FRR_VTYSH_DEFAULT
#define FRR_VTYSH_DEFAULT "vtysh"
#endif


/* ------------------------------------------------------------------------
 * symbols vtysh.c expects from vtysh_main.c
 * ------------------------------------------------------------------------
 */
struct event_loop *master;
char frr_config[MAXPATHLEN];
char vtydir[MAXPATHLEN];
char history_file[MAXPATHLEN];
bool vtysh_loop_exited;
int execute_flag;
int user_mode;
struct event *vtysh_rl_read_thread;

void vtysh_exec_timeout_config(uint32_t tsecs)
{
}

uint32_t vtysh_get_exec_timeout(void)
{
	return 0;
}

/* vtysh's compiled-in copy of the daemon commands (vtysh_cmd.c, generated
 * from frr.xref at build time) is deliberately not linked: the commands come
 * from the frr.xref given at runtime instead.
 */
void vtysh_init_cmd(void)
{
}


/* ------------------------------------------------------------------------
 * small helpers
 * ------------------------------------------------------------------------
 */
#define TOKMAX	 256
#define STACKMAX 32
#define WORDMAX	 256

struct bits {
	uint64_t w[TOKMAX / 64];
};

static inline void bset(struct bits *b, int i)
{
	b->w[i >> 6] |= 1ULL << (i & 63);
}

static inline bool bget(const struct bits *b, int i)
{
	return (b->w[i >> 6] >> (i & 63)) & 1;
}

struct sbuf {
	char *s;
	size_t len, size;
};

static void sb_add(struct sbuf *b, const char *fmt, ...) PRINTFRR(2, 3);

static void sb_add(struct sbuf *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	for (;;) {
		size_t room = b->size - b->len;

		va_start(ap, fmt);
		n = vsnprintf(b->s ? b->s + b->len : NULL, room, fmt, ap);
		va_end(ap);
		if (n >= 0 && (size_t)n < room) {
			b->len += n;
			return;
		}
		b->size = (b->size + n + 1) * 2;
		b->s = realloc(b->s, b->size);
		if (!b->s)
			abort();
	}
}

static char *xstrdup(const char *s)
{
	char *r = strdup(s ? s : "");

	if (!r)
		abort();
	return r;
}

static void *xcalloc(size_t n, size_t sz)
{
	void *p = calloc(n ? n : 1, sz ? sz : 1);

	if (!p)
		abort();
	return p;
}

/* xref2vtysh's normalization: drop $varnames, squash whitespace */
static char *normalize_cmd(const char *cmd)
{
	struct sbuf b = {};
	bool ws = false;

	while (isspace((unsigned char)*cmd))
		cmd++;
	for (const char *p = cmd; *p; p++) {
		if (*p == '$' && islower((unsigned char)p[1])) {
			p++;
			while (isalnum((unsigned char)p[1]) || p[1] == '_')
				p++;
			continue;
		}
		if (isspace((unsigned char)*p)) {
			ws = true;
			continue;
		}
		if (ws && b.len)
			sb_add(&b, " ");
		ws = false;
		sb_add(&b, "%c", *p);
	}
	return b.s ? b.s : xstrdup("");
}

/* simple string set */
struct strset {
	char **slot;
	size_t size, count;
};

static uint32_t str_hash(const char *s)
{
	uint32_t h = 2166136261u;

	while (*s)
		h = (h ^ (uint8_t)*s++) * 16777619u;
	return h;
}

static bool strset_add(struct strset *set, const char *s)
{
	if ((set->count + 1) * 2 >= set->size) {
		struct strset n = { .size = set->size ? set->size * 2 : 1024 };

		n.slot = xcalloc(n.size, sizeof(char *));
		for (size_t i = 0; i < set->size; i++)
			if (set->slot[i])
				strset_add(&n, set->slot[i]);
		free(set->slot);
		*set = n;
	}
	size_t i = str_hash(s) & (set->size - 1);

	while (set->slot[i]) {
		if (!strcmp(set->slot[i], s))
			return false;
		i = (i + 1) & (set->size - 1);
	}
	set->slot[i] = xstrdup(s);
	set->count++;
	return true;
}

/* ------------------------------------------------------------------------
 * per-command analysis (standalone graph of one cmd_element)
 * ------------------------------------------------------------------------
 */
struct tok {
	enum cmd_token_type type;
	const char *text;
	long long min, max;
	bool repeat, mandatory;
	int *next, nnext;
	int *prev, nprev;
};

struct cmdinfo {
	const struct cmd_element *el;
	int ntok, start, end;
	struct tok *t;
	char *sig;    /* mandatory keywords, leading "no" removed */
	bool mand_no; /* "no ..." only command */
	int opt_no;   /* optional leading "no" keyword token, or -1 */
	struct bits loopfork;
	bool usable;
};

static bool is_varying(enum cmd_token_type t)
{
	return t >= VARIABLE_TKN && t < FORK_TKN;
}

static bool reach(struct cmdinfo *ci, int from, const struct bits *removed, int target)
{
	int stack[TOKMAX * 4], sp = 0;
	struct bits seen = {};

	stack[sp++] = from;
	while (sp) {
		int i = stack[--sp];

		if (bget(&seen, i) || (removed && bget(removed, i)))
			continue;
		if (i == target)
			return true;
		bset(&seen, i);
		for (int k = 0; k < ci->t[i].nnext && sp < TOKMAX * 4; k++)
			stack[sp++] = ci->t[i].next[k];
	}
	return false;
}

static void descendants(struct cmdinfo *ci, int from, struct bits *out)
{
	int stack[TOKMAX * 4], sp = 0;

	memset(out, 0, sizeof(*out));
	for (int k = 0; k < ci->t[from].nnext; k++)
		stack[sp++] = ci->t[from].next[k];
	while (sp) {
		int i = stack[--sp];

		if (bget(out, i))
			continue;
		bset(out, i);
		for (int k = 0; k < ci->t[i].nnext && sp < TOKMAX * 4; k++)
			stack[sp++] = ci->t[i].next[k];
	}
}

static bool is_loop_fork(struct cmdinfo *ci, int f)
{
	struct bits below;
	bool have = false;

	for (int k = 0; k < ci->t[f].nprev; k++) {
		int p = ci->t[f].prev[k];

		if (ci->t[p].type != JOIN_TKN)
			continue;
		if (!have) {
			descendants(ci, f, &below);
			have = true;
		}
		if (bget(&below, p))
			return true;
	}
	return false;
}

static void topo(struct cmdinfo *ci, int i, struct bits *seen, int *order, int *n)
{
	if (bget(seen, i))
		return;
	bset(seen, i);
	order[(*n)++] = i;
	for (int k = 0; k < ci->t[i].nnext; k++) {
		int x = ci->t[i].next[k];

		/* every edge: FRR's parser numbers a <...> group's members
		 * before its FORK, and the seen set stops keyword-set loops
		 */
		topo(ci, x, seen, order, n);
	}
}

static struct cmdinfo *cmdinfo_build(const struct cmd_element *el)
{
	struct cmdinfo *ci = xcalloc(1, sizeof(*ci));
	struct graph *g = graph_new();
	struct graph_node *gnodes[TOKMAX];
	int n = 0;

	ci->el = el;
	ci->opt_no = -1;
	graph_new_node(g, cmd_token_new(START_TKN, el->attr, NULL, NULL),
		       (void (*)(void *))cmd_token_del);
	cmd_graph_parse(g, el);

	for (unsigned int i = 0; i < vector_active(g->nodes); i++) {
		struct graph_node *gn = vector_slot(g->nodes, i);

		if (!gn || gn->data == (void *)el)
			continue;
		if (n >= TOKMAX)
			return ci; /* unusable */
		gnodes[n++] = gn;
	}
	ci->ntok = n;
	ci->t = xcalloc(n, sizeof(struct tok));

	for (int i = 0; i < n; i++) {
		struct cmd_token *ct = gnodes[i]->data;
		struct tok *t = &ci->t[i];

		t->type = ct->type;
		t->text = ct->text;
		t->min = ct->min;
		t->max = ct->max;
		t->repeat = ct->allowrepeat;
		t->next = xcalloc(vector_active(gnodes[i]->to) + 1, sizeof(int));
		for (unsigned int k = 0; k < vector_active(gnodes[i]->to); k++) {
			struct graph_node *to = vector_slot(gnodes[i]->to, k);

			for (int j = 0; j < n; j++)
				if (gnodes[j] == to) {
					t->next[t->nnext++] = j;
					break;
				}
		}
		if (t->type == START_TKN)
			ci->start = i;
		if (t->type == END_TKN)
			ci->end = i;
	}
	for (int i = 0; i < n; i++)
		ci->t[i].prev = xcalloc(n + 1, sizeof(int));
	for (int i = 0; i < n; i++)
		for (int k = 0; k < ci->t[i].nnext; k++) {
			struct tok *x = &ci->t[ci->t[i].next[k]];

			x->prev[x->nprev++] = i;
		}

	/* mandatory tokens: every path from START to END passes them */
	for (int i = 0; i < n; i++) {
		struct bits rm = {};

		if (ci->t[i].type != WORD_TKN && !is_varying(ci->t[i].type))
			continue;
		bset(&rm, i);
		ci->t[i].mandatory = !reach(ci, ci->start, &rm, ci->end);
	}
	for (int i = 0; i < n; i++)
		if (ci->t[i].type == FORK_TKN && is_loop_fork(ci, i))
			bset(&ci->loopfork, i);

	/* optional leading "no" ("[no] ...") */
	for (int i = 0; i < n && ci->opt_no < 0; i++) {
		struct tok *t = &ci->t[i];
		bool first = true;

		if (t->type != WORD_TKN || t->mandatory || strcmp(t->text, "no"))
			continue;
		for (int k = 0; k < t->nprev; k++) {
			int p = t->prev[k];

			if (p != ci->start && !(ci->t[p].type == FORK_TKN && ci->t[p].nprev == 1 &&
						ci->t[p].prev[0] == ci->start))
				first = false;
		}
		if (first)
			ci->opt_no = i;
	}

	/* signature: the fixed keywords */
	int order[TOKMAX], no = 0;
	struct bits seen = {};
	struct sbuf sig = {};

	topo(ci, ci->start, &seen, order, &no);
	for (int k = 0; k < no; k++) {
		struct tok *t = &ci->t[order[k]];

		if (t->type != WORD_TKN || !t->mandatory)
			continue;
		if (!sig.len && !ci->mand_no && !strcmp(t->text, "no")) {
			ci->mand_no = true;
			continue;
		}
		sb_add(&sig, "%s%s", sig.len ? " " : "", t->text);
	}
	ci->sig = sig.s ? sig.s : xstrdup("");
	ci->usable = true;
	return ci;
}

/* pointer -> cmdinfo cache */
static struct {
	const struct cmd_element **key;
	struct cmdinfo **val;
	size_t size, count;
} infos;

static struct cmdinfo *cmdinfo_get(const struct cmd_element *el)
{
	size_t i;

	if ((infos.count + 1) * 2 >= infos.size) {
		size_t osize = infos.size;
		const struct cmd_element **okey = infos.key;
		struct cmdinfo **oval = infos.val;

		infos.size = osize ? osize * 2 : 4096;
		infos.key = xcalloc(infos.size, sizeof(*infos.key));
		infos.val = xcalloc(infos.size, sizeof(*infos.val));
		infos.count = 0;
		for (size_t k = 0; k < osize; k++)
			if (okey[k]) {
				i = ((uintptr_t)okey[k] >> 4) & (infos.size - 1);
				while (infos.key[i])
					i = (i + 1) & (infos.size - 1);
				infos.key[i] = okey[k];
				infos.val[i] = oval[k];
				infos.count++;
			}
		free(okey);
		free(oval);
	}
	i = ((uintptr_t)el >> 4) & (infos.size - 1);
	while (infos.key[i]) {
		if (infos.key[i] == el)
			return infos.val[i];
		i = (i + 1) & (infos.size - 1);
	}
	infos.key[i] = el;
	infos.val[i] = cmdinfo_build(el);
	infos.count++;
	return infos.val[i];
}

/* ------------------------------------------------------------------------
 * loading frr.xref
 * ------------------------------------------------------------------------
 */
static struct {
	unsigned int loaded, installed, merged, nosh, no_node, not_config, not_routed;
} stats;

static bool node_is_config(enum node_type n)
{
	return n >= CONFIG_NODE && vector_lookup(cmdvec, n) != NULL;
}

static bool json_has_str(json_object *arr, const char *s)
{
	if (!arr || json_object_get_type(arr) != json_type_array)
		return false;
	for (size_t i = 0; i < json_object_array_length(arr); i++) {
		const char *v = json_object_get_string(json_object_array_get_idx(arr, i));

		if (v && !strcmp(v, s))
			return true;
	}
	return false;
}

/*
 * lib/ commands vtysh routes to daemons; others never reach vtysh (and so
 * can't appear in an integrated config).  Same list as daemon_flags in
 * python/xref2vtysh.py, plus the files it special-cases.
 */
static const char *const vtysh_lib_files[] = {
	"lib/libagentx.c",
	"lib/filter.c",
	"lib/filter_cli.c",
	"lib/host_cli.c",
	"lib/if.c",
	"lib/keychain_cli.c",
	"lib/mgmt_be_client.c",
	"lib/mgmt_fe_client.c",
	"lib/lib_vty.c",
	"lib/log_cli.c",
	"lib/log_vty.c",
	"lib/nexthop_group.c",
	"lib/resolver.c",
	"lib/routemap.c",
	"lib/routemap_cli.c",
	"lib/spf_backoff.c",
	"lib/event.c",
	"lib/vrf.c",
	"lib/vty.c",
	"lib/plist.c",
	"lib/if_rmap.c",
};

static bool reaches_vtysh(json_object *spec)
{
	json_object *jdefun, *jfile;
	const char *file;

	if (!json_object_object_get_ex(spec, "defun", &jdefun) ||
	    !json_object_object_get_ex(jdefun, "file", &jfile))
		return true;
	file = json_object_get_string(jfile);
	if (strncmp(file, "lib/", 4))
		return true;
	for (size_t i = 0; i < array_size(vtysh_lib_files); i++)
		if (!strcmp(file, vtysh_lib_files[i]))
			return true;
	return false;
}

static int load_xref(const char *path)
{
	json_object *root = json_object_from_file(path), *cli;
	struct strset seen = {};
	char key[64];

	if (!root) {
		fprintf(stderr, "frr-confjson: cannot read %s: %s\n", path,
			json_util_get_last_err());
		return -1;
	}
	if (!json_object_object_get_ex(root, "cli", &cli)) {
		fprintf(stderr, "frr-confjson: %s has no \"cli\" section\n", path);
		return -1;
	}

	/* commands vtysh itself defines win, like in vtysh */
	for (unsigned int n = 0; n < vector_active(cmdvec); n++) {
		struct cmd_node *cnode = vector_slot(cmdvec, n);

		if (!cnode)
			continue;
		for (unsigned int i = 0; i < vector_active(cnode->cmd_vector); i++) {
			const struct cmd_element *el = vector_slot(cnode->cmd_vector, i);
			char *nc;
			struct sbuf b = {};

			if (!el)
				continue;
			nc = normalize_cmd(el->string);
			sb_add(&b, "%u\x1f%s", n, nc);
			strset_add(&seen, b.s);
			free(nc);
			free(b.s);
		}
	}

	json_object_object_foreach(cli, name, origins)
	{
		json_object_object_foreach(origins, origin, spec)
		{
			json_object *jstr, *jdoc, *jattrs = NULL, *jnodes;
			struct cmd_element *el = NULL;

			if (!strncmp(origin, "vtysh/", 6))
				continue;
			if (!json_object_object_get_ex(spec, "string", &jstr) ||
			    !json_object_object_get_ex(spec, "nodes", &jnodes))
				continue;
			stats.loaded++;
			json_object_object_get_ex(spec, "attrs", &jattrs);
			if (!reaches_vtysh(spec)) {
				stats.not_routed++;
				continue;
			}
			if (json_has_str(jattrs, "nosh")) {
				stats.nosh++;
				continue;
			}
			for (size_t k = 0; k < json_object_array_length(jnodes); k++) {
				json_object *jn = json_object_array_get_idx(jnodes, k), *jid;
				int node;
				char *nc;
				struct sbuf b = {};

				if (!json_object_object_get_ex(jn, "node", &jid))
					continue;
				node = json_object_get_int(jid);
				if (node < CONFIG_NODE) {
					stats.not_config++;
					continue;
				}
				if (!node_is_config(node)) {
					stats.no_node++;
					continue;
				}
				nc = normalize_cmd(json_object_get_string(jstr));
				sb_add(&b, "%d\x1f%s", node, nc);
				free(nc);
				if (!strset_add(&seen, b.s)) {
					free(b.s);
					stats.merged++;
					continue;
				}
				free(b.s);
				if (!el) {
					el = xcalloc(1, sizeof(*el));
					el->string = xstrdup(json_object_get_string(jstr));
					el->doc = json_object_object_get_ex(spec, "doc", &jdoc)
							  ? xstrdup(json_object_get_string(jdoc))
							  : xstrdup("");
					snprintfrr(key, sizeof(key), "%s", name);
					el->name = xstrdup(key);
					if (json_has_str(jattrs, "hidden"))
						el->attr |= CMD_ATTR_HIDDEN;
					if (json_has_str(jattrs, "deprecated"))
						el->attr |= CMD_ATTR_DEPRECATED;
				}
				/* not install_element(): that macro also emits a
				 * static xref record for compile-time commands
				 */
				_install_element(node, el);
				stats.installed++;
			}
		}
	}

	for (unsigned int n = 0; n < vector_active(cmdvec); n++) {
		struct cmd_node *cnode = vector_slot(cmdvec, n);

		if (cnode)
			cmd_finalize_node(cnode);
	}
	json_object_put(root);
	return 0;
}

/* ------------------------------------------------------------------------
 * matching a line in a node
 * ------------------------------------------------------------------------
 */
struct match {
	const struct cmd_element *el;
	struct cmdinfo *ci;
	int n;		   /* tokens consumed */
	int path[TOKMAX];  /* standalone-graph token per consumed word */
	char *arg[TOKMAX]; /* input value per consumed word */
	struct list *argv; /* command_match() result */
};

static void match_free(struct match *m)
{
	for (int i = 0; i < m->n; i++)
		free(m->arg[i]);
	if (m->argv)
		list_delete(&m->argv);
	m->n = 0;
}

static const char *matcher_err(enum matcher_rv rv)
{
	switch (rv) {
	case MATCHER_NO_MATCH:
		return "unknown command";
	case MATCHER_INCOMPLETE:
		return "incomplete command";
	case MATCHER_AMBIGUOUS:
		return "ambiguous command";
	case MATCHER_OK:
		return "ok";
	}
	return "?";
}

/* follow the tokens command_match() consumed through the command's own graph */
static bool map_path(struct cmdinfo *ci, struct cmd_token **av, int nav, int idx, int k,
		     struct match *m, bool *seen)
{
	for (int e = 0; e < ci->t[idx].nnext; e++) {
		int nx = ci->t[idx].next[e];
		struct tok *t = &ci->t[nx];

		if (t->type == FORK_TKN || t->type == JOIN_TKN || t->type == NEG_ONLY_TKN) {
			if (seen[nx * (nav + 1) + k])
				continue;
			seen[nx * (nav + 1) + k] = true;
			if (map_path(ci, av, nav, nx, k, m, seen))
				return true;
			continue;
		}
		if (t->type == END_TKN) {
			if (k == nav)
				return true;
			continue;
		}
		if (t->type == START_TKN)
			continue;
		if (k >= nav || t->type != av[k]->type ||
		    strcmp(t->text ? t->text : "", av[k]->text ? av[k]->text : ""))
			continue;
		m->path[k] = nx;
		if (map_path(ci, av, nav, nx, k + 1, m, seen))
			return true;
	}
	return false;
}

static enum matcher_rv match_line(enum node_type node, const char *line, struct match *m)
{
	struct cmd_node *cnode = vector_lookup(cmdvec, node);
	vector vline;
	enum matcher_rv rv;
	struct cmd_token *av[TOKMAX];
	int nav = 0;
	struct listnode *ln;
	struct cmd_token *tk;

	memset(m, 0, sizeof(*m));
	if (!cnode)
		return MATCHER_NO_MATCH;
	vline = cmd_make_strvec(line);
	if (!vline)
		return MATCHER_NO_MATCH;
	rv = command_match(cnode->cmdgraph, vline, &m->argv, &m->el);
	cmd_free_strvec(vline);
	if (rv != MATCHER_OK)
		return rv;

	for (ALL_LIST_ELEMENTS_RO(m->argv, ln, tk))
		if (nav < TOKMAX)
			av[nav++] = tk;
	m->ci = cmdinfo_get(m->el);
	if (m->ci->usable) {
		bool *seen = xcalloc((size_t)m->ci->ntok * (nav + 1), 1);
		bool ok = map_path(m->ci, av, nav, m->ci->start, 0, m, seen);

		free(seen);
		if (!ok)
			m->ci = NULL;
	} else {
		m->ci = NULL;
	}
	for (int i = 0; i < nav; i++)
		m->arg[i] = xstrdup(av[i]->arg ? av[i]->arg : av[i]->text);
	m->n = nav;
	return MATCHER_OK;
}

/* canonical text of a matched line (full keywords, single spaces) */
static char *match_text(struct match *m)
{
	struct sbuf b = {};
	struct listnode *ln;
	struct cmd_token *tk;

	for (ALL_LIST_ELEMENTS_RO(m->argv, ln, tk))
		sb_add(&b, "%s%s", b.len ? " " : "", tk->type == WORD_TKN ? tk->text : tk->arg);
	return b.s ? b.s : xstrdup("");
}

/* run vtysh's handler for a matched line to learn the resulting node */
static enum node_type node_after(enum node_type node, struct match *m)
{
	static struct vty *svty;
	struct cmd_token *av[TOKMAX];
	int argc = 0;
	struct listnode *ln;
	struct cmd_token *tk;

	/* only vtysh's own DEFUNSH handlers; they just switch vty->node */
	if (!m->el->func || !m->el->daemon)
		return node;
	if (!svty) {
		/* VTY_SHELL without an output stream: messages a handler
		 * prints ("removing the password ...") are dropped
		 */
		svty = vty_new();
		svty->type = VTY_SHELL;
		svty->of = NULL;
		svty->of_saved = NULL;
	}
	for (ALL_LIST_ELEMENTS_RO(m->argv, ln, tk))
		if (argc < TOKMAX)
			av[argc++] = tk;
	svty->node = node;
	m->el->func(m->el, svty, argc, av);
	return svty->node;
}

/* is a an enclosing node of n (per vtysh's node table)? */
static bool is_ancestor(enum node_type a, enum node_type n)
{
	for (int guard = 0; guard < 32; guard++) {
		struct cmd_node *cnode = vector_lookup(cmdvec, n);

		if (!cnode || !cnode->parent_node || cnode->parent_node == n)
			return false;
		n = cnode->parent_node;
		if (n == a)
			return true;
	}
	return false;
}

static const char *node_name(enum node_type n)
{
	struct cmd_node *cnode = vector_lookup(cmdvec, n);
	static char buf[32];

	if (cnode && cnode->name)
		return cnode->name;
	snprintfrr(buf, sizeof(buf), "node %d", n);
	return buf;
}

/* "exit-address-family", "exit-vrf", ... or "exit" */
static const char *node_exit_cmd(enum node_type n)
{
	struct cmd_node *cnode = vector_lookup(cmdvec, n);

	if (!cnode)
		return "exit";
	for (unsigned int i = 0; i < vector_active(cnode->cmd_vector); i++) {
		const struct cmd_element *el = vector_slot(cnode->cmd_vector, i);

		if (el && el->func && !strncmp(el->string, "exit-", 5) && !strchr(el->string, ' '))
			return el->string;
	}
	return "exit";
}

/* ------------------------------------------------------------------------
 * matched line -> JSON statement
 * ------------------------------------------------------------------------
 */
static bool all_digits(const char *s)
{
	if (!*s)
		return false;
	for (; *s; s++)
		if (!isdigit((unsigned char)*s))
			return false;
	return true;
}

/* ------------------------------------------------------------------------
 * errors
 * ------------------------------------------------------------------------
 */
static json_object *errors;


static void add_error(const char *path, enum node_type node, const char *fmt, ...)
{
	json_object *e = json_object_new_object();
	char *msg;
	va_list ap;

	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) < 0)
		abort();
	va_end(ap);
	json_object_object_add(e, "path", json_object_new_string(path));
	json_object_object_add(e, "node", json_object_new_string(node_name(node)));
	json_object_object_add(e, "error", json_object_new_string(msg));
	json_object_array_add(errors, e);
	free(msg);
}

/* is m a negated command with signature sig? */
static bool is_negation_of(struct match *m, const char *sig)
{
	bool no = false;

	if (!m->ci || strcmp(m->ci->sig, sig))
		return false;
	if (m->ci->mand_no)
		return true;
	for (int k = 0; k < m->n && !no; k++)
		no = m->path[k] == m->ci->opt_no;
	return no;
}

/*
 * "no " + positive line; "no" commands often take fewer arguments, so drop
 * trailing words until FRR accepts it -- but never below the command's own
 * keywords ("no neighbor X timers 10 30" may become "no neighbor X timers",
 * never "no neighbor X").
 */
static bool negate_line(enum node_type node, const char *pos, const char *sig, struct match *m)
{
	char *line;

	if (asprintf(&line, "no %s", pos) < 0)
		abort();
	for (bool full = true;; full = false) {
		/* "no" + the whole line keeps every keyword, so its meaning is
		 * exact even when the "no" command's signature differs
		 * ("pbr-map P seq 1" vs "no pbr-map PBRMAP [seq (1-700)]")
		 */
		if (match_line(node, line, m) == MATCHER_OK &&
		    (full ? is_negation_of(m, m->ci ? m->ci->sig : "") : is_negation_of(m, sig))) {
			free(line);
			return true;
		}
		match_free(m);

		char *sp = strrchr(line, ' ');

		if (!sp || sp - line <= 2)
			break;
		*sp = '\0';
	}
	free(line);
	return false;
}

/* ------------------------------------------------------------------------
 * one command line: FRR grammar, plus negated forms
 * ------------------------------------------------------------------------
 */

/* "exit", "end", "exit-address-family", ...: these only move between modes */
static bool is_exit_word(const char *line)
{
	return !strcmp(line, "end") || !strcmp(line, "exit") || !strcmp(line, "quit") ||
	       !strncmp(line, "exit-", 5);
}

/*
 * Match a statement in node.  A "no" command that FRR doesn't accept as
 * written is retried with trailing words dropped (see negate_line()).
 */
static enum matcher_rv resolve_line(enum node_type node, const char *line, struct match *m)
{
	enum matcher_rv rv = match_line(node, line, m);
	struct match pm;

	if (rv == MATCHER_OK || strncmp(line, "no ", 3))
		return rv;
	if (match_line(node, line + 3, &pm) == MATCHER_OK && pm.ci) {
		char *pos = match_text(&pm);
		bool ok;

		match_free(&pm);
		match_free(m);
		ok = negate_line(node, pos, pm.ci->sig, m);
		free(pos);
		if (ok)
			return MATCHER_OK;
	} else {
		match_free(&pm);
	}
	return match_line(node, line, m);
}

/* the sub-mode a matched line enters, or node itself */
static enum node_type entered_node(enum node_type node, struct match *m)
{
	enum node_type next = node_after(node, m);

	if (next == node || next < CONFIG_NODE || !vector_lookup(cmdvec, next) ||
	    is_ancestor(next, node))
		return node;
	return next;
}

/* ------------------------------------------------------------------------
 * text -> JSON
 * ------------------------------------------------------------------------
 */

/* one word of a command: keyword, or a value (repeat runs joined) */
struct seg {
	char *text;
	bool keyword;
	bool choice; /* keyword picked from alternatives: <in|out> */
	bool number;
};

/* is keyword token i one of several alternatives ("<in|out>")? */
static bool in_choice(struct cmdinfo *ci, int i)
{
	for (int k = 0; k < ci->t[i].nprev; k++) {
		int f = ci->t[i].prev[k], alts = 0;

		if (ci->t[f].type != FORK_TKN || bget(&ci->loopfork, f))
			continue;
		for (int e = 0; e < ci->t[f].nnext; e++)
			if (ci->t[ci->t[f].next[e]].type != JOIN_TKN)
				alts++;
		if (alts >= 2)
			return true;
	}
	return false;
}

static int match_segs(struct match *m, struct seg *s, int max)
{
	int n = 0;

	for (int k = 0; k < m->n && n < max; k++) {
		struct tok *t = m->ci ? &m->ci->t[m->path[k]] : NULL;
		const char *arg = m->arg[k];

		if (t && t->repeat && k > 0 && m->path[k - 1] == m->path[k]) {
			/* "WORD...": one value */
			char *j;

			if (asprintf(&j, "%s %s", s[n - 1].text, arg) < 0)
				abort();
			free(s[n - 1].text);
			s[n - 1].text = j;
			s[n - 1].number = false;
			continue;
		}
		s[n].keyword = t ? t->type == WORD_TKN : false;
		s[n].choice = s[n].keyword && in_choice(m->ci, m->path[k]);
		s[n].text = xstrdup(s[n].keyword ? t->text : arg);
		s[n].number = t &&
			      (t->type == RANGE_TKN || (t->type == ASNUM_TKN && all_digits(arg)));
		n++;
	}
	return n;
}

static void segs_free(struct seg *s, int n)
{
	for (int i = 0; i < n; i++)
		free(s[i].text);
}

static json_object *seg_value(struct seg *s)
{
	if (s->number)
		return json_object_new_int64(strtoll(s->text, NULL, 10));
	return json_object_new_string(s->text);
}

/* add a leaf value under key; a different existing value makes a list */
static void add_leaf(json_object *obj, const char *key, json_object *val)
{
	json_object *cur;

	if (!json_object_object_get_ex(obj, key, &cur)) {
		json_object_object_add(obj, key, val);
		return;
	}
	if (json_object_get_type(cur) == json_type_array) {
		for (size_t i = 0; i < json_object_array_length(cur); i++)
			if (json_object_equal(json_object_array_get_idx(cur, i), val)) {
				json_object_put(val);
				return;
			}
		json_object_array_add(cur, val);
		return;
	}
	if (json_object_equal(cur, val)) {
		json_object_put(val);
		return;
	}

	json_object *arr = json_object_new_array();

	json_object_array_add(arr, json_object_get(cur));
	json_object_array_add(arr, val);
	json_object_object_add(obj, key, arr);
}

/* the object under key, created (or added to a list) when needed */
static json_object *descend(json_object *obj, const char *key)
{
	json_object *cur, *o;

	if (!json_object_object_get_ex(obj, key, &cur)) {
		o = json_object_new_object();
		json_object_object_add(obj, key, o);
		return o;
	}
	if (json_object_get_type(cur) == json_type_object)
		return cur;
	if (json_object_get_type(cur) == json_type_array) {
		for (size_t i = json_object_array_length(cur); i > 0; i--) {
			o = json_object_array_get_idx(cur, i - 1);
			if (json_object_get_type(o) == json_type_object)
				return o;
		}
		o = json_object_new_object();
		json_object_array_add(cur, o);
		return o;
	}

	json_object *arr = json_object_new_array();

	o = json_object_new_object();
	json_object_array_add(arr, json_object_get(cur));
	json_object_array_add(arr, o);
	json_object_object_add(obj, key, arr);
	return o;
}

/*
 * Put one command into obj.  For a sub-mode command every word is a key
 * and the object for the commands inside the mode is returned.
 */
static json_object *insert_segs(json_object *obj, struct seg *s, int n, bool block)
{
	if (!n)
		return obj;
	if (block) {
		for (int i = 0; i < n; i++)
			obj = descend(obj, s[i].text);
		return obj;
	}
	/* "timers 10 30": trailing numbers stay together, as one value */
	int nums = 0;

	while (nums < n - 1 && s[n - 1 - nums].number)
		nums++;
	if (nums >= 2) {
		struct sbuf v = {};

		for (int i = n - nums; i < n; i++)
			sb_add(&v, "%s%s", v.len ? " " : "", s[i].text);
		for (int i = 0; i < n - nums - 1; i++)
			obj = descend(obj, s[i].text);
		add_leaf(obj, s[n - nums - 1].text, json_object_new_string(v.s));
		free(v.s);
		return NULL;
	}
	/* a keyword chosen from alternatives reads as a value */
	if ((s[n - 1].keyword && !s[n - 1].choice) || n == 1) {
		for (int i = 0; i < n - 1; i++)
			obj = descend(obj, s[i].text);
		add_leaf(obj, s[n - 1].text,
			 s[n - 1].keyword ? json_object_new_boolean(true) : seg_value(&s[n - 1]));
		return NULL;
	}
	for (int i = 0; i < n - 2; i++)
		obj = descend(obj, s[i].text);
	add_leaf(obj, s[n - 2].text, seg_value(&s[n - 1]));
	return NULL;
}

static json_object *text_to_json(FILE *in)
{
	enum node_type nodes[STACKMAX];
	json_object *objs[STACKMAX];
	int depth = 0, lineno = 0;
	char *buf = NULL;
	size_t bsz = 0;
	ssize_t len;
	json_object *root = json_object_new_object();
	json_object *config = json_object_new_object();

	nodes[0] = CONFIG_NODE;
	objs[0] = config;

	while ((len = getline(&buf, &bsz, in)) >= 0) {
		char *line = buf, *end;
		struct match m;
		enum matcher_rv rv = MATCHER_NO_MATCH, first = MATCHER_NO_MATCH;
		struct seg segs[WORDMAX];
		int lvl, nseg;
		char path[32];

		lineno++;
		while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
			buf[--len] = '\0';
		while (isspace((unsigned char)*line))
			line++;
		end = line + strlen(line);
		while (end > line && isspace((unsigned char)end[-1]))
			*--end = '\0';
		if (!*line || *line == '!' || *line == '#' || !strcmp(line, "end") ||
		    !strcmp(line, "Building configuration...") ||
		    !strcmp(line, "Current configuration:"))
			continue;
		snprintfrr(path, sizeof(path), "line %d", lineno);
		if (is_exit_word(line)) {
			/* like vtysh: exit at the top ends the config file */
			if (!depth && (!strcmp(line, "exit") || !strcmp(line, "quit"))) {
				add_error(path, CONFIG_NODE,
					  "early exit from config file; the remaining lines are ignored");
				break;
			}
			/* leave the mode only if the command exists in it
			 * ("exit-address-family" outside an address-family
			 * is an unknown command for vtysh too)
			 */
			rv = match_line(nodes[depth], line, &m);
			if (rv != MATCHER_OK || !depth) {
				add_error(path, nodes[depth], "'%s': %s in %s", line,
					  matcher_err(rv), node_name(nodes[depth]));
				match_free(&m);
				continue;
			}

			enum node_type to = node_after(nodes[depth], &m);

			match_free(&m);
			depth--;
			for (int k = depth; k >= 0; k--)
				if (nodes[k] == to) {
					depth = k;
					break;
				}
			continue;
		}

		/* current node first, then implicit exits (like vtysh) */
		for (lvl = depth; lvl >= 0; lvl--) {
			rv = match_line(nodes[lvl], line, &m);
			if (lvl == depth)
				first = rv;
			if (rv == MATCHER_OK)
				break;
			match_free(&m);
		}
		if (rv != MATCHER_OK) {
			/* keep the words, without grammar: last one is the value */
			char *dup = xstrdup(line), *sp, *w;

			add_error(path, nodes[depth], "'%s': %s in %s", line, matcher_err(first),
				  node_name(nodes[depth]));
			nseg = 0;
			for (w = strtok_r(dup, " \t", &sp); w && nseg < WORDMAX;
			     w = strtok_r(NULL, " \t", &sp)) {
				segs[nseg].text = xstrdup(w);
				segs[nseg].keyword = false;
				segs[nseg].choice = false;
				segs[nseg++].number = false;
			}
			free(dup);
			insert_segs(objs[depth], segs, nseg, false);
			segs_free(segs, nseg);
			continue;
		}
		depth = lvl;

		enum node_type next = entered_node(nodes[depth], &m);
		enum node_type after = node_after(nodes[depth], &m);

		nseg = match_segs(&m, segs, WORDMAX);
		match_free(&m);

		if (next != nodes[depth] && depth + 1 < STACKMAX) {
			objs[depth + 1] = insert_segs(objs[depth], segs, nseg, true);
			nodes[++depth] = next;
		} else {
			insert_segs(objs[depth], segs, nseg, false);
			/* a command that leaves to an enclosing mode */
			for (int k = depth - 1; k >= 0 && after != nodes[depth]; k--)
				if (nodes[k] == after) {
					depth = k;
					break;
				}
		}
		segs_free(segs, nseg);
	}
	free(buf);
	json_object_object_add(root, "config", config);
	return root;
}

/* ------------------------------------------------------------------------
 * JSON -> config commands
 * ------------------------------------------------------------------------
 */

/* a word path from the document root to a value */
struct jpath {
	char **w;
	int n;
	char *ptr; /* JSON pointer, for error messages */
};

struct jpaths {
	struct jpath *p;
	int n, size;
};

static void ptr_add(struct sbuf *b, const char *key)
{
	sb_add(b, "/");
	for (const char *c = key; *c; c++) {
		if (*c == '~')
			sb_add(b, "~0");
		else if (*c == '/')
			sb_add(b, "~1");
		else
			sb_add(b, "%c", *c);
	}
}

static void paths_add(struct jpaths *ps, char **w, int n, const char *ptr)
{
	struct jpath *p;

	if (ps->n == ps->size) {
		ps->size = ps->size ? ps->size * 2 : 256;
		ps->p = realloc(ps->p, ps->size * sizeof(*ps->p));
		if (!ps->p)
			abort();
	}
	p = &ps->p[ps->n++];
	p->w = xcalloc(n + 1, sizeof(char *));
	for (int i = 0; i < n; i++)
		p->w[i] = xstrdup(w[i]);
	p->n = n;
	p->ptr = xstrdup(ptr);
}

static void flatten(json_object *v, char **w, int n, const char *ptr, struct jpaths *ps)
{
	char num[64];
	struct sbuf sub = {};

	if (n >= WORDMAX - 1) {
		add_error(ptr, CONFIG_NODE, "nested too deeply");
		return;
	}
	switch (json_object_get_type(v)) {
	case json_type_object:
		if (!json_object_object_length(v)) {
			paths_add(ps, w, n, ptr); /* "router ospf": {} */
			return;
		}
		json_object_object_foreach(v, key, val)
		{
			sb_add(&sub, "%s", ptr);
			ptr_add(&sub, key);
			w[n] = key;
			flatten(val, w, n + 1, sub.s, ps);
			sub.len = 0;
		}
		free(sub.s);
		return;
	case json_type_array:
		for (size_t i = 0; i < json_object_array_length(v); i++) {
			sb_add(&sub, "%s/%zu", ptr, i);
			flatten(json_object_array_get_idx(v, i), w, n, sub.s, ps);
			sub.len = 0;
		}
		free(sub.s);
		return;
	case json_type_boolean:
		if (json_object_get_boolean(v))
			paths_add(ps, w, n, ptr);
		return; /* false: left out */
	case json_type_int:
		snprintfrr(num, sizeof(num), "%" PRId64, json_object_get_int64(v));
		w[n] = num;
		paths_add(ps, w, n + 1, ptr);
		return;
	case json_type_double: {
		double d = json_object_get_double(v);
		long long ll = (long long)d;

		if (d != (double)ll) {
			add_error(ptr, CONFIG_NODE, "numbers must be integers");
			return;
		}
		snprintfrr(num, sizeof(num), "%lld", ll);
	}
		w[n] = num;
		paths_add(ps, w, n + 1, ptr);
		return;
	case json_type_string:
		w[n] = (char *)json_object_get_string(v);
		paths_add(ps, w, n + 1, ptr);
		return;
	case json_type_null:
		return;
	}
}

static char *join_words(char **w, int from, int to)
{
	struct sbuf b = {};

	for (int i = from; i < to; i++)
		sb_add(&b, "%s%s", b.len ? " " : "", w[i]);
	return b.s ? b.s : xstrdup("");
}

/* sub-mode commands, cached: node|line -> entered node + canonical text */
static struct {
	char **key, **text;
	int *child;
	size_t size, count;
} ocache;

static bool opener_lookup(enum node_type node, const char *line, enum node_type *child, char **text)
{
	char *key;
	size_t i;
	struct match m;

	if (asprintf(&key, "%u\x1f%s", node, line) < 0)
		abort();
	if ((ocache.count + 1) * 2 >= ocache.size) {
		size_t osize = ocache.size;
		char **ok = ocache.key, **ot = ocache.text;
		int *oc = ocache.child;

		ocache.size = osize ? osize * 2 : 1024;
		ocache.key = xcalloc(ocache.size, sizeof(char *));
		ocache.text = xcalloc(ocache.size, sizeof(char *));
		ocache.child = xcalloc(ocache.size, sizeof(int));
		for (size_t k = 0; k < osize; k++)
			if (ok[k]) {
				i = str_hash(ok[k]) & (ocache.size - 1);
				while (ocache.key[i])
					i = (i + 1) & (ocache.size - 1);
				ocache.key[i] = ok[k];
				ocache.text[i] = ot[k];
				ocache.child[i] = oc[k];
			}
		free(ok);
		free(ot);
		free(oc);
	}
	i = str_hash(key) & (ocache.size - 1);
	while (ocache.key[i]) {
		if (!strcmp(ocache.key[i], key)) {
			free(key);
			*child = ocache.child[i];
			*text = ocache.text[i];
			return ocache.child[i] >= 0;
		}
		i = (i + 1) & (ocache.size - 1);
	}
	ocache.key[i] = key;
	ocache.child[i] = -1;
	ocache.count++;
	if (match_line(node, line, &m) == MATCHER_OK) {
		enum node_type next = entered_node(node, &m);

		if (next != node) {
			ocache.child[i] = next;
			ocache.text[i] = match_text(&m);
		}
	}
	match_free(&m);
	*child = ocache.child[i];
	*text = ocache.text[i];
	return ocache.child[i] >= 0;
}

/* a path cut into sub-mode commands plus a final command */
struct split {
	int nop;
	char *op[STACKMAX];		   /* canonical sub-mode command lines */
	enum node_type op_node[STACKMAX];  /* mode each one is given in */
	enum node_type op_child[STACKMAX]; /* mode it enters */
	char *stmt;			   /* final command, NULL if none */
	enum node_type stmt_node;
	/* deepest failure, for the error message */
	int fail_from;
	enum node_type fail_node;
	char *fail_line;
	enum matcher_rv fail_rv;
};

/*
 * Cut words[from..n) given in node into commands: the whole rest as one
 * command, else the longest leading sub-mode command followed by commands
 * inside that mode.
 */
static bool split_path(char **w, int n, int from, enum node_type node, struct split *r)
{
	char *line;
	struct match m;
	enum matcher_rv rv;

	if (from == n)
		return true; /* ends with a sub-mode command */

	line = join_words(w, from, n);
	rv = is_exit_word(line) ? MATCHER_NO_MATCH : resolve_line(node, line, &m);
	if (rv == MATCHER_OK) {
		enum node_type next = entered_node(node, &m);
		char *text = match_text(&m);

		match_free(&m);
		free(line);
		if (next != node && r->nop < STACKMAX) {
			r->op[r->nop] = text;
			r->op_node[r->nop] = node;
			r->op_child[r->nop++] = next;
		} else {
			r->stmt = text;
			r->stmt_node = node;
		}
		return true;
	}
	match_free(&m);
	if (from >= r->fail_from) {
		r->fail_from = from;
		r->fail_node = node;
		r->fail_rv = rv;
		free(r->fail_line);
		r->fail_line = xstrdup(line);
	}
	free(line);

	for (int i = n - 1; i > from && r->nop < STACKMAX; i--) {
		enum node_type child;
		char *text, *op = join_words(w, from, i);
		bool ok = opener_lookup(node, op, &child, &text);

		free(op);
		if (!ok)
			continue;
		r->op[r->nop] = text;
		r->op_node[r->nop] = node;
		r->op_child[r->nop++] = child;
		if (split_path(w, n, i, child, r))
			return true;
		r->nop--;
	}
	return false;
}

/* open sub-mode commands while emitting */
struct emitter {
	struct sbuf out;
	int depth;
	char *op[STACKMAX];
	enum node_type op_node[STACKMAX], op_child[STACKMAX];
};

static void emit_close(struct emitter *e, int keep)
{
	while (e->depth > keep) {
		e->depth--;
		sb_add(&e->out, "%*s%s\n", e->depth, "", node_exit_cmd(e->op_child[e->depth]));
		if (!e->depth)
			sb_add(&e->out, "!\n");
	}
}

static void emit_split(struct emitter *e, struct split *r)
{
	int k = 0;

	while (k < e->depth && k < r->nop && !strcmp(e->op[k], r->op[k]) &&
	       e->op_node[k] == r->op_node[k])
		k++;
	emit_close(e, k);
	for (; k < r->nop; k++) {
		sb_add(&e->out, "%*s%s\n", k, "", r->op[k]);
		e->op[k] = r->op[k];
		e->op_node[k] = r->op_node[k];
		e->op_child[k] = r->op_child[k];
		e->depth = k + 1;
	}
	if (r->stmt)
		sb_add(&e->out, "%*s%s\n", r->nop, "", r->stmt);
}

/* ", valid in: bgp, ..." for a command given in the wrong mode */
static char *valid_elsewhere(enum node_type node, const char *line)
{
	struct sbuf b = {};
	int found = 0;

	for (unsigned int n = CONFIG_NODE; n < vector_active(cmdvec) && found < 4; n++) {
		struct match m;

		if (n == node || !vector_lookup(cmdvec, n))
			continue;
		if (match_line(n, line, &m) == MATCHER_OK)
			sb_add(&b, "%s%s", found++ ? ", " : "; valid in: ", node_name(n));
		match_free(&m);
	}
	return b.s ? b.s : xstrdup("");
}

static void path_error(struct jpath *p, struct split *r)
{
	char *before, *hint;

	if (!r->fail_line) {
		add_error(p->ptr, CONFIG_NODE, "empty command");
		return;
	}
	before = r->fail_from > 0 ? join_words(p->w, 0, r->fail_from) : NULL;
	if (is_exit_word(r->fail_line)) {
		add_error(p->ptr, r->fail_node,
			  "'%s': modes are left by nesting in JSON, not with exit", r->fail_line);
	} else {
		hint = r->fail_rv == MATCHER_NO_MATCH ? valid_elsewhere(r->fail_node, r->fail_line)
						      : xstrdup("");
		add_error(p->ptr, r->fail_node, "'%s': %s in %s%s%s%s%s", r->fail_line,
			  matcher_err(r->fail_rv), node_name(r->fail_node),
			  before ? " (after '" : "", before ? before : "", before ? "')" : "",
			  hint);
		free(hint);
	}
	free(before);
}

/* JSON document -> config text; NULL (and errors) if anything is invalid */
static char *json_to_text(json_object *cfg)
{
	struct jpaths ps = {};
	char *w[WORDMAX];
	struct emitter e = {};

	flatten(cfg, w, 0, "/config", &ps);
	for (int i = 0; i < ps.n; i++) {
		struct split r = { .fail_from = -1 };

		if (!split_path(ps.p[i].w, ps.p[i].n, 0, CONFIG_NODE, &r)) {
			path_error(&ps.p[i], &r);
			free(r.fail_line);
			continue;
		}
		emit_split(&e, &r);
		free(r.stmt);
		free(r.fail_line);
	}
	emit_close(&e, 0);
	for (int i = 0; i < ps.n; i++) {
		for (int k = 0; k < ps.p[i].n; k++)
			free(ps.p[i].w[k]);
		free(ps.p[i].w);
		free(ps.p[i].ptr);
	}
	free(ps.p);
	if (json_object_array_length(errors)) {
		free(e.out.s);
		return NULL;
	}
	return e.out.s ? e.out.s : xstrdup("");
}

/* ------------------------------------------------------------------------
 * --self-test: random valid line per command -> JSON -> line, every node
 * ------------------------------------------------------------------------
 */
static const char *sample_value(struct tok *t, unsigned int r, char *buf, size_t sz)
{
	static const char *const v4[] = { "10.1.2.3", "192.0.2.1" };
	static const char *const v4p[] = { "10.1.0.0/16", "192.0.2.0/24" };
	static const char *const v6[] = { "2001:db8::1", "fe80::1" };
	static const char *const v6p[] = { "2001:db8::/32", "fd00::/8" };
	static const char *const asn[] = { "65001", "1.10" };
	static const char *const var[] = { "foo1", "BAR-2", "x_3" };

	if (t->type == RANGE_TKN) {
		long long v = r % 3 == 0   ? t->min
			      : r % 3 == 1 ? t->max
					   : t->min + (t->max - t->min) / 2;

		snprintfrr(buf, sz, "%lld", v);
		return buf;
	}
	if (t->type == IPV4_TKN)
		return v4[r % 2];
	if (t->type == IPV4_PREFIX_TKN)
		return v4p[r % 2];
	if (t->type == IPV6_TKN)
		return v6[r % 2];
	if (t->type == IPV6_PREFIX_TKN)
		return v6p[r % 2];
	if (t->type == MAC_TKN)
		return "00:11:22:33:44:55";
	if (t->type == MAC_PREFIX_TKN)
		return "00:11:22:33:44:55/48";
	if (t->type == ASNUM_TKN)
		return asn[r % 2];
	return var[r % 3];
}

static char *random_line(struct cmdinfo *ci, unsigned int *seed)
{
	struct sbuf b = {};
	struct bits used = {};
	int i = ci->start, steps = 0;
	char vbuf[64];

	for (;;) {
		int cand[TOKMAX], nc = 0;

		if (++steps > 400)
			goto fail;
		for (int e = 0; e < ci->t[i].nnext; e++) {
			int n = ci->t[i].next[e];
			struct tok *t = &ci->t[n];

			if (n == i)
				continue;
			if (bget(&used, n) && t->type != FORK_TKN && t->type != JOIN_TKN &&
			    t->type != END_TKN)
				continue;
			cand[nc++] = n;
		}
		if (bget(&ci->loopfork, i) && rand_r(seed) % 10 < 4)
			for (int e = 0; e < nc; e++)
				if (ci->t[cand[e]].type == JOIN_TKN) {
					cand[0] = cand[e];
					nc = 1;
					break;
				}
		if (!nc)
			goto fail;
		i = cand[rand_r(seed) % nc];

		struct tok *t = &ci->t[i];

		if (t->type == END_TKN)
			return b.s;
		if (t->type == NEG_ONLY_TKN) {
			if (!b.s || strncmp(b.s, "no ", 3))
				goto fail;
		} else if (t->type == WORD_TKN) {
			sb_add(&b, "%s%s", b.len ? " " : "", t->text);
			bset(&used, i);
		} else if (is_varying(t->type)) {
			sb_add(&b, "%s%s", b.len ? " " : "",
			       sample_value(t, rand_r(seed), vbuf, sizeof(vbuf)));
			if (t->repeat && rand_r(seed) % 2)
				sb_add(&b, " %s",
				       sample_value(t, rand_r(seed), vbuf, sizeof(vbuf)));
			bset(&used, i);
		}
	}
fail:
	free(b.s);
	return NULL;
}

/* ------------------------------------------------------------------------
 * --self-test: random valid lines of every command, through JSON and back
 * ------------------------------------------------------------------------
 */

/* a way into every mode: the sub-mode commands from the top */
static char *chain[STACKMAX][TOKMAX * 4];
static int chain_len[TOKMAX * 4];
static bool chain_known[TOKMAX * 4];

static void build_chains(unsigned int *seed)
{
	int queue[TOKMAX * 4], qh = 0, qt = 0;

	chain_known[CONFIG_NODE] = true;
	queue[qt++] = CONFIG_NODE;
	while (qh < qt) {
		enum node_type n = queue[qh++];
		struct cmd_node *cnode = vector_lookup(cmdvec, n);

		for (unsigned int c = 0; cnode && c < vector_active(cnode->cmd_vector); c++) {
			const struct cmd_element *el = vector_slot(cnode->cmd_vector, c);
			struct cmdinfo *ci;

			if (!el || !el->func || !el->daemon)
				continue;
			ci = cmdinfo_get(el);
			for (int k = 0; ci->usable && k < 8; k++) {
				char *line = random_line(ci, seed);
				struct match m;
				enum node_type next;

				if (!line)
					continue;
				if (match_line(n, line, &m) != MATCHER_OK) {
					match_free(&m);
					free(line);
					continue;
				}
				next = entered_node(n, &m);
				match_free(&m);
				if (next == n || chain_known[next] ||
				    chain_len[n] + 1 >= STACKMAX) {
					free(line);
					continue;
				}
				for (int j = 0; j < chain_len[n]; j++)
					chain[j][next] = chain[j][n];
				chain[chain_len[n]][next] = line;
				chain_len[next] = chain_len[n] + 1;
				chain_known[next] = true;
				queue[qt++] = next;
			}
		}
	}
}

/* line (valid in node) -> JSON document -> config text, in its context */
static char *doc_round_trip(enum node_type node, const char *line, bool neg)
{
	json_object *cfg = json_object_new_object(), *obj = cfg;
	struct seg s[WORDMAX];
	struct match m;
	char *text;
	int n;

	/* sub-mode commands, each in the mode before it */
	enum node_type cur = CONFIG_NODE;

	for (int j = 0; j < chain_len[node]; j++) {
		match_line(cur, chain[j][node], &m);
		n = match_segs(&m, s, WORDMAX);
		obj = insert_segs(obj, s, n, true);
		segs_free(s, n);
		cur = entered_node(cur, &m);
		match_free(&m);
	}
	match_line(node, line, &m);
	n = match_segs(&m, s, WORDMAX);
	if (neg)
		obj = descend(obj, "no");
	insert_segs(obj, s, n, entered_node(node, &m) != node);
	segs_free(s, n);
	match_free(&m);
	text = json_to_text(cfg);
	json_object_put(cfg);
	return text;
}

/* the command at the given depth in config text produced above */
static char *text_line_at(const char *text, int depth)
{
	char *dup = xstrdup(text), *sp, *l, *res = NULL;

	for (l = strtok_r(dup, "\n", &sp); l; l = strtok_r(NULL, "\n", &sp)) {
		int ind = 0;

		while (l[ind] == ' ')
			ind++;
		if (ind == depth && !is_exit_word(l + ind) && l[ind] != '!') {
			free(res);
			res = xstrdup(l + ind);
		}
	}
	free(dup);
	return res;
}

static int self_test(int per_cmd)
{
	unsigned int seed = 1;
	unsigned long total = 0, ok = 0, other = 0, amb = 0, exits = 0;
	unsigned long unreachable = 0;
	unsigned long pos = 0, negated = 0;
	int shown = 0;

	build_chains(&seed);
	for (unsigned int n = CONFIG_NODE; n < vector_active(cmdvec); n++) {
		struct cmd_node *cnode = vector_slot(cmdvec, n);

		if (!cnode)
			continue;
		if (!chain_known[n]) {
			/* only a problem if the mode has commands from frr.xref
			 * (vtysh-internal modes have just exit/end)
			 */
			for (unsigned int c = 0; c < vector_active(cnode->cmd_vector); c++) {
				const struct cmd_element *el = vector_slot(cnode->cmd_vector, c);

				if (el && !el->func) {
					fprintf(stderr, "self-test: no way found into mode %s\n",
						node_name(n));
					unreachable++;
					break;
				}
			}
			continue;
		}
		for (unsigned int c = 0; c < vector_active(cnode->cmd_vector); c++) {
			const struct cmd_element *el = vector_slot(cnode->cmd_vector, c);
			struct cmdinfo *ci;

			if (!el)
				continue;
			ci = cmdinfo_get(el);
			if (!ci->usable)
				continue;
			for (int k = 0; k < per_cmd; k++) {
				char *line = random_line(ci, &seed), *canon, *text, *got;
				struct match m;
				enum matcher_rv rv;
				bool good;

				if (!line)
					continue;
				rv = match_line(n, line, &m);
				if (rv == MATCHER_AMBIGUOUS) {
					/* FRR's own grammar is ambiguous here;
					 * vtysh rejects the line as well
					 */
					amb++;
					match_free(&m);
					free(line);
					continue;
				}
				if (rv == MATCHER_OK && is_exit_word(line)) {
					exits++; /* not configuration */
					match_free(&m);
					free(line);
					continue;
				}
				if (rv != MATCHER_OK || m.el != el) {
					other++;
					match_free(&m);
					free(line);
					continue;
				}
				canon = match_text(&m);
				match_free(&m);
				total++;

				json_object *saved = errors;

				errors = json_object_new_array();
				text = doc_round_trip(n, line, false);
				got = text ? text_line_at(text, chain_len[n]) : NULL;
				good = got && !strcmp(got, canon);
				if (!good && shown++ < 40)
					fprintf(stderr, "FAIL [%s] '%s' -> %s%s\n", node_name(n),
						canon, got ? got : "error: ",
						got ? ""
						    : json_object_to_json_string_ext(
							      errors,
							      JSON_C_TO_STRING_PLAIN |
								      JSON_C_TO_STRING_NOSLASHESCAPE));
				ok += good;
				free(text);
				free(got);

				/* "no" + the command */
				if (good && strncmp(canon, "no ", 3)) {
					json_object_put(errors);
					errors = json_object_new_array();
					pos++;
					text = doc_round_trip(n, line, true);
					got = text ? text_line_at(text, chain_len[n]) : NULL;
					if (got && !strncmp(got, "no ", 3))
						negated++;
					free(text);
					free(got);
				}
				json_object_put(errors);
				errors = saved;
				free(canon);
				free(line);
			}
		}
	}
	fprintf(stderr,
		"self-test: %lu/%lu random commands round-tripped through JSON in their mode "
		"(skipped: %lu ambiguous in FRR's own grammar, %lu taken by another command, "
		"%lu exit/end)\n",
		ok, total, amb, other, exits);
	fprintf(stderr,
		"self-test: \"no\": %lu/%lu commands negated (the rest have no \"no\" form)\n",
		negated, pos);
	return ok == total && !unreachable ? 0 : 1;
}

/* ------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------
 */
static void usage(int rc)
{
	fprintf(rc ? stderr : stdout,
		"usage: frr-confjson [options] to-json [FILE|-]\n"
		"       frr-confjson [options] to-conf [FILE|-]\n"
		"\n"
		"  to-json   FRR config text -> JSON.  Without FILE the running\n"
		"            config is read with 'vtysh -c \"show running-config\"'.\n"
		"  to-conf   JSON -> FRR config commands (frr.conf syntax).\n"
		"\n"
		"options:\n"
		"  -x, --xref FILE     command catalog (default $FRR_XREF or %s)\n"
		"      --vtysh PATH    vtysh binary (default %s)\n"
		"  -N, --pathspace NS  pass -N NS to vtysh\n"
		"  -c, --compact       to-json: compact JSON\n"
		"  -s, --stats         print catalog statistics to stderr\n"
		"      --self-test[=N] round-trip N random lines of every command\n"
		"  -h, --help\n",
		FRR_XREF_DEFAULT, FRR_VTYSH_DEFAULT);
	exit(rc);
}

static char *read_all(FILE *f)
{
	struct sbuf b = {};
	char chunk[65536];
	size_t n;

	while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
		sb_add(&b, "%.*s", (int)n, chunk);
	return b.s ? b.s : xstrdup("");
}

static FILE *open_input(const char *file)
{
	FILE *f;

	if (!file || !strcmp(file, "-"))
		return stdin;
	f = fopen(file, "r");
	if (!f) {
		fprintf(stderr, "frr-confjson: %s: %s\n", file, safe_strerror(errno));
		exit(2);
	}
	return f;
}

static void print_errors(void)
{
	if (!json_object_array_length(errors))
		return;
	fprintf(stderr, "%s\n",
		json_object_to_json_string_ext(errors, JSON_C_TO_STRING_PRETTY |
							       JSON_C_TO_STRING_NOSLASHESCAPE));
}

int main(int argc, char **argv)
{
	static const struct option longopts[] = { { "xref", required_argument, NULL, 'x' },
						  { "vtysh", required_argument, NULL, 'V' },
						  { "pathspace", required_argument, NULL, 'N' },
						  { "compact", no_argument, NULL, 'c' },
						  { "stats", no_argument, NULL, 's' },
						  { "help", no_argument, NULL, 'h' },
						  { "self-test", optional_argument, NULL, 'T' },
						  {} };
	const char *xref = getenv("FRR_XREF");
	const char *vtysh_bin = FRR_VTYSH_DEFAULT, *pathspace = NULL;
	bool compact = false, show_stats = false;
	int opt, rc = 0, selftest = 0;

	if (!xref || !*xref)
		xref = FRR_XREF_DEFAULT;
	while ((opt = getopt_long(argc, argv, "x:N:csh", longopts, NULL)) != -1) {
		switch (opt) {
		case 'x':
			xref = optarg;
			break;
		case 'V':
			vtysh_bin = optarg;
			break;
		case 'N':
			pathspace = optarg;
			break;
		case 'c':
			compact = true;
			break;
		case 's':
			show_stats = true;
			break;
		case 'T':
			selftest = optarg ? atoi(optarg) : 4;
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(2);
		}
	}
	if (optind >= argc && !selftest)
		usage(2);

	const char *mode = optind < argc ? argv[optind] : "self-test";
	const char *file = optind + 1 < argc ? argv[optind + 1] : NULL;

	if (!selftest && strcmp(mode, "to-json") && strcmp(mode, "to-conf"))
		usage(2);

	/* vtysh's modes and mode-switching commands, then frr.xref */
	vtysh_init_vty();
	if (load_xref(xref) < 0)
		return 2;
	errors = json_object_new_array();
	if (show_stats)
		fprintf(stderr,
			"frr-confjson: %s: %u command definitions, %u installed "
			"(%u merged duplicates, %u nosh, %u non-config, %u unknown node, "
			"%u lib commands vtysh doesn't route)\n",
			xref, stats.loaded, stats.installed, stats.merged, stats.nosh,
			stats.not_config, stats.no_node, stats.not_routed);
	if (selftest)
		return self_test(selftest);

	if (!strcmp(mode, "to-json")) {
		FILE *in;
		bool piped = false;
		json_object *doc;

		if (file) {
			in = open_input(file);
		} else {
			char *cmd;

			if (asprintf(&cmd, "%s%s%s -c 'show running-config'", vtysh_bin,
				     pathspace ? " -N " : "", pathspace ? pathspace : "") < 0)
				abort();
			in = popen(cmd, "r");
			free(cmd);
			if (!in) {
				fprintf(stderr, "frr-confjson: cannot run %s\n", vtysh_bin);
				return 2;
			}
			piped = true;
		}
		doc = text_to_json(in);
		if (piped) {
			int st = pclose(in);

			if (st != 0) {
				fprintf(stderr,
					"frr-confjson: '%s -c \"show running-config\"' failed (status %d)\n",
					vtysh_bin, st);
				rc = 2;
			}
		} else if (in != stdin) {
			fclose(in);
		}
		printf("%s\n",
		       json_object_to_json_string_ext(doc, (compact ? JSON_C_TO_STRING_PLAIN
								    : JSON_C_TO_STRING_PRETTY) |
								   JSON_C_TO_STRING_NOSLASHESCAPE));
		json_object_put(doc);
	} else {
		FILE *in = open_input(file);
		char *text = read_all(in), *out;
		enum json_tokener_error jerr;
		json_object *doc = json_tokener_parse_verbose(text, &jerr), *cfg;

		if (in != stdin)
			fclose(in);
		free(text);
		if (!doc) {
			fprintf(stderr, "frr-confjson: invalid JSON: %s\n",
				json_tokener_error_desc(jerr));
			return 2;
		}
		if (json_object_get_type(doc) != json_type_object ||
		    !json_object_object_get_ex(doc, "config", &cfg)) {
			fprintf(stderr, "frr-confjson: expected {\"config\": {...}}\n");
			return 2;
		}
		out = json_to_text(cfg);
		if (out)
			fputs(out, stdout);
		free(out);
		json_object_put(doc);
	}

	if (json_object_array_length(errors)) {
		print_errors();
		if (!rc)
			rc = 1;
	}
	return rc;
}
