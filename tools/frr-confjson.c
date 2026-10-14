// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * frr-confjson: convert FRR configuration between frr.conf text and JSON,
 * driven by the frr.xref command catalog produced by the FRR build.
 *
 *   frr-confjson [-x frr.xref] to-json [FILE|-]    running config -> JSON
 *   frr-confjson [-x frr.xref] to-conf [FILE|-]    JSON -> FRR config commands
 *
 * How it works
 * ------------
 * - Every DEFUN/DEFPY that was compiled into a daemon is listed in frr.xref
 *   (written by python/xrelfo.py at link time) together with the CLI node(s)
 *   it was installed into.  Those commands are loaded at runtime, de-duplicated
 *   exactly like python/xref2vtysh.py does for vtysh ("nosh" commands are
 *   skipped, identical strings in a node are merged), and installed into
 *   libfrr's real command graphs.
 * - The node hierarchy -- which command enters which node, which command
 *   leaves it -- is not part of frr.xref.  It is taken from vtysh itself: this
 *   tool links vtysh's node table and its DEFUNSH handlers (the same code
 *   vtysh uses to track the node while reading frr.conf), but not vtysh's
 *   compiled-in copy of the daemon commands.
 * - Lines are matched with libfrr's command_match(), so abbreviations, token
 *   precedence, value validation and ambiguity follow FRR exactly.
 *
 * JSON format
 * -----------
 *   { "config": [ <statement>, ... ] }
 *
 *   statement:  "literal config line"
 *            |  { "cmd":    "<signature>",          e.g. "neighbor remote-as"
 *                 "params": { "<name>": <value> },  e.g. {"neighbor": "192.0.2.1",
 *                                                         "remote_as": 65001}
 *                 "no":     true,                   negated form
 *                 "id":     "<xref command name>",  only when "cmd" is ambiguous
 *                 "config": [ <statement>, ... ] }  statements inside the node
 *                                                   this command enters
 *
 * A command's signature is its fixed keywords (without a leading "no").
 * Parameter names come from the command definition: DEFPY "$name"s, else the
 * keyword in front of a value ("router-id A.B.C.D" -> router_id).  Optional
 * keywords are booleans, keyword choices take the keyword as value
 * ("<deny|permit>$action" -> "action": "permit"), "WORD..." takes a list.
 *
 * "no": true works for every command: the "[no] ..." form or the separate
 * "no ..." command is used, and parameters the negated form does not take
 * (e.g. the timer values of "no neighbor X timers") are dropped.
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
#define TOKMAX	256
#define NAMEMAX 64

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

/* "router-id" -> "router_id", "dot+" -> "dot_plus" */
static char *norm_name(const char *text)
{
	struct sbuf b = {};
	bool us = false;

	for (const char *p = text; *p; p++) {
		if (*p == '+') {
			sb_add(&b, "%s", (b.len && !us) ? "_plus" : "plus");
			us = false;
		} else if (isalnum((unsigned char)*p)) {
			sb_add(&b, "%c", tolower((unsigned char)*p));
			us = false;
		} else if (b.len && !us) {
			sb_add(&b, "_");
			us = true;
		}
	}
	while (b.len && b.s[b.len - 1] == '_')
		b.s[--b.len] = '\0';
	if (!b.len)
		sb_add(&b, "arg");
	if (isdigit((unsigned char)b.s[0])) {
		char *r = xcalloc(1, b.len + 2);

		r[0] = '_';
		memcpy(r + 1, b.s, b.len + 1);
		free(b.s);
		return r;
	}
	return b.s;
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
	const char *text, *desc, *varname;
	long long min, max;
	bool repeat, mandatory;
	int *next, nnext;
	int *prev, nprev;
	int param, flag, group; /* name index or -1 */
};

struct cmdinfo {
	const struct cmd_element *el;
	struct graph *graph;
	int ntok, start, end;
	struct tok *t;
	char *sig;    /* mandatory keywords, leading "no" removed */
	bool mand_no; /* "no ..." only command */
	int opt_no;   /* optional leading "no" keyword token, or -1 */
	struct bits loopfork;
	char *names[NAMEMAX];
	bool required[NAMEMAX];
	int nnames;
	bool usable;
};

static bool is_varying(enum cmd_token_type t)
{
	return t >= VARIABLE_TKN && t < FORK_TKN;
}

static int name_idx(struct cmdinfo *ci, const char *name, bool create)
{
	for (int i = 0; i < ci->nnames; i++)
		if (!strcmp(ci->names[i], name))
			return i;
	if (!create || ci->nnames >= NAMEMAX)
		return -1;
	ci->names[ci->nnames] = xstrdup(name);
	return ci->nnames++;
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

static const char *prev_word(struct cmdinfo *ci, int i, int depth)
{
	const char *found = NULL;

	if (depth > 8)
		return NULL;
	for (int k = 0; k < ci->t[i].nprev; k++) {
		struct tok *p = &ci->t[ci->t[i].prev[k]];
		const char *w = NULL;

		if (p->type == WORD_TKN)
			w = p->text;
		else if (p->type == FORK_TKN || p->type == JOIN_TKN)
			w = prev_word(ci, ci->t[i].prev[k], depth + 1);
		else
			return NULL;
		if (!w)
			return NULL;
		if (found && strcmp(found, w))
			return NULL;
		found = w;
	}
	return found;
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

static int fork_words(struct cmdinfo *ci, int f)
{
	int n = 0;

	for (int k = 0; k < ci->t[f].nnext; k++)
		if (ci->t[ci->t[f].next[k]].type == WORD_TKN)
			n++;
	return n;
}

static int fork_join(struct cmdinfo *ci, int f)
{
	int queue[TOKMAX * 4], qh = 0, qt = 0;
	struct bits seen = {}, rm = {};

	bset(&seen, f);
	bset(&rm, f);
	for (int k = 0; k < ci->t[f].nnext; k++)
		queue[qt++] = ci->t[f].next[k];
	while (qh < qt) {
		int j = queue[qh++];

		if (bget(&seen, j))
			continue;
		bset(&seen, j);
		if (ci->t[j].type == JOIN_TKN) {
			bool all = true;

			for (int k = 0; k < ci->t[f].nnext && all; k++) {
				int b = ci->t[f].next[k];

				if (b != j && !reach(ci, b, &rm, j))
					all = false;
			}
			if (all)
				return j;
		}
		for (int k = 0; k < ci->t[j].nnext && qt < TOKMAX * 4; k++)
			queue[qt++] = ci->t[j].next[k];
	}
	return -1;
}

static bool branch_uses(struct cmdinfo *ci, int f, int i, int name)
{
	int j = fork_join(ci, f);
	int stack[TOKMAX * 4], sp = 0;
	struct bits seen = {};

	for (int k = 0; k < ci->t[i].nnext; k++)
		stack[sp++] = ci->t[i].next[k];
	while (sp) {
		int x = stack[--sp];

		if (bget(&seen, x) || x == j || x == f)
			continue;
		bset(&seen, x);
		if (ci->t[x].param == name || ci->t[x].flag == name)
			return true;
		for (int k = 0; k < ci->t[x].nnext && sp < TOKMAX * 4; k++)
			stack[sp++] = ci->t[x].next[k];
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

static const char *type_fallback(enum cmd_token_type t)
{
	if (t == IPV4_TKN)
		return "ipv4";
	if (t == IPV4_PREFIX_TKN)
		return "prefix";
	if (t == IPV6_TKN)
		return "ipv6";
	if (t == IPV6_PREFIX_TKN)
		return "ipv6_prefix";
	if (t == MAC_TKN)
		return "mac";
	if (t == MAC_PREFIX_TKN)
		return "mac_prefix";
	if (t == ASNUM_TKN)
		return "asn";
	if (t == RANGE_TKN)
		return "value";
	return NULL;
}

static struct cmdinfo *cmdinfo_build(const struct cmd_element *el)
{
	struct cmdinfo *ci = xcalloc(1, sizeof(*ci));
	struct graph *g = graph_new();
	struct graph_node *gnodes[TOKMAX];
	int n = 0;

	ci->el = el;
	ci->graph = g;
	ci->opt_no = -1;
	graph_new_node(g, cmd_token_new(START_TKN, el->attr, NULL, NULL),
		       (void (*)(void *))cmd_token_del);
	cmd_graph_parse(g, el);
	cmd_graph_names(g);

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
		t->desc = ct->desc;
		t->varname = ct->varname;
		t->min = ct->min;
		t->max = ct->max;
		t->repeat = ct->allowrepeat;
		t->param = t->flag = t->group = -1;
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

	/* 1. parameter names for value tokens */
	int vname[TOKMAX];

	for (int i = 0; i < n; i++) {
		struct tok *t = &ci->t[i];
		const char *nm;
		char *norm;

		vname[i] = -1;
		if (!is_varying(t->type))
			continue;
		nm = t->varname;
		if (!nm) {
			const char *pw = prev_word(ci, i, 0);
			int words = 0;

			if (t->desc)
				for (const char *p = t->desc; *p; p++)
					if (!isspace((unsigned char)*p) &&
					    (p == t->desc || isspace((unsigned char)p[-1])))
						words++;
			if (pw)
				nm = pw;
			else if (t->desc && words > 0 && words <= 2 && strlen(t->desc) <= 24)
				nm = t->desc;
			else
				nm = type_fallback(t->type);
			if (!nm)
				nm = t->text ? t->text : "arg";
		}
		norm = norm_name(nm);

		/* names of tokens that can appear on one path must differ */
		struct bits di;
		char cand[256];
		int k = 1;

		descendants(ci, i, &di);
		snprintfrr(cand, sizeof(cand), "%s", norm);
		for (;;) {
			int idx = name_idx(ci, cand, false);
			bool clash = false;

			for (int j = 0; j < i && idx >= 0; j++) {
				struct bits dj;

				if (vname[j] != idx)
					continue;
				descendants(ci, j, &dj);
				if (bget(&di, j) || bget(&dj, i)) {
					clash = true;
					break;
				}
			}
			if (!clash)
				break;
			snprintfrr(cand, sizeof(cand), "%s_%d", norm, ++k);
		}
		free(norm);
		vname[i] = name_idx(ci, cand, true);
		t->param = vname[i];
	}

	/* 2. optional keywords: boolean flags or keyword choices */
	for (int i = 0; i < n; i++) {
		struct tok *t = &ci->t[i];
		const char *vn;
		char *nvn = NULL;

		if (t->type != WORD_TKN || t->mandatory)
			continue;
		if (!strcmp(t->text, "no") && ci->opt_no < 0 && reach(ci, ci->start, NULL, i)) {
			bool first = true;

			for (int k = 0; k < t->nprev; k++) {
				int p = t->prev[k];

				if (p != ci->start &&
				    !(ci->t[p].type == FORK_TKN && ci->t[p].nprev == 1 &&
				      ci->t[p].prev[0] == ci->start))
					first = false;
			}
			if (first) {
				ci->opt_no = i;
				continue;
			}
		}
		{
			char *f = norm_name(t->text);

			t->flag = name_idx(ci, f, true);
			free(f);
		}
		vn = (t->varname && strcmp(t->varname, "no")) ? t->varname : NULL;
		if (vn)
			nvn = norm_name(vn);
		for (int k = 0; k < t->nprev; k++) {
			int p = t->prev[k];
			struct tok *pt = &ci->t[p];
			bool shared = false;
			int cand = -1;

			if (pt->type != FORK_TKN)
				continue;
			if (vn) {
				int nidx = name_idx(ci, nvn, false);

				for (int s = 0; s < pt->nnext; s++) {
					struct tok *st = &ci->t[pt->next[s]];

					if (pt->next[s] == i)
						continue;
					if ((st->type == WORD_TKN && st->varname &&
					     !strcmp(st->varname, vn)) ||
					    (nidx >= 0 && st->param == nidx))
						shared = true;
				}
			}
			if (bget(&ci->loopfork, p)) {
				if (shared)
					cand = name_idx(ci, nvn, true);
				else if (vn)
					t->flag = name_idx(ci, nvn, true);
			} else if (vn) {
				if (shared)
					cand = name_idx(ci, nvn, true);
				else
					t->flag = name_idx(ci, nvn, true);
			} else {
				int sv = -1, nsv = 0;

				for (int s = 0; s < pt->nnext; s++) {
					int pp = ci->t[pt->next[s]].param;

					if (pp >= 0 && pp != sv) {
						sv = pp;
						nsv++;
					}
				}
				if (nsv == 1) {
					cand = sv;
				} else if (pt->nprev == 1 && ci->t[pt->prev[0]].type == WORD_TKN &&
					   fork_words(ci, p) >= 2) {
					char *gname = norm_name(ci->t[pt->prev[0]].text);

					cand = name_idx(ci, gname, true);
					free(gname);
				}
			}
			if (cand >= 0 && !branch_uses(ci, p, i, cand))
				t->group = cand;
			break;
		}
		free(nvn);
	}

	/* 3. which names every rendering needs */
	for (int nm = 0; nm < ci->nnames; nm++) {
		struct bits rm = {};

		for (int i = 0; i < n; i++)
			if (ci->t[i].param == nm || ci->t[i].flag == nm || ci->t[i].group == nm)
				bset(&rm, i);
		ci->required[nm] = !reach(ci, ci->start, &rm, ci->end);
	}

	/* 4. signature: the fixed keywords */
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

/*
 * vtysh defines its own copy of node-entering commands ("router bgp ...")
 * without DEFPY $names; the daemon's "nosh" original in frr.xref has the
 * same grammar with FRR's parameter names.  node|normalized -> xref string.
 */
static struct {
	char **key, **val;
	size_t size, count;
} twins;

static void twin_add(const char *key, const char *val)
{
	size_t i;

	if ((twins.count + 1) * 2 >= twins.size) {
		size_t osize = twins.size;
		char **ok = twins.key, **ov = twins.val;

		twins.size = osize ? osize * 2 : 512;
		twins.key = xcalloc(twins.size, sizeof(char *));
		twins.val = xcalloc(twins.size, sizeof(char *));
		twins.count = 0;
		for (size_t k = 0; k < osize; k++)
			if (ok[k])
				twin_add(ok[k], ov[k]);
		free(ok);
		free(ov);
	}
	i = str_hash(key) & (twins.size - 1);
	while (twins.key[i]) {
		if (!strcmp(twins.key[i], key))
			return;
		i = (i + 1) & (twins.size - 1);
	}
	twins.key[i] = xstrdup(key);
	twins.val[i] = xstrdup(val);
	twins.count++;
}

static const char *twin_get(const char *key)
{
	size_t i;

	if (!twins.size)
		return NULL;
	i = str_hash(key) & (twins.size - 1);
	while (twins.key[i]) {
		if (!strcmp(twins.key[i], key))
			return twins.val[i];
		i = (i + 1) & (twins.size - 1);
	}
	return NULL;
}

/* string to analyze for el: its xref twin if it has one */
static const struct cmd_element *naming_source(const struct cmd_element *el)
{
	struct cmd_element *tw;
	char *nc;
	const char *tstr = NULL;
	struct sbuf b = {};

	if (!el->func)
		return el;
	nc = normalize_cmd(el->string);
	for (unsigned int n = 0; n < vector_active(cmdvec) && !tstr; n++) {
		struct cmd_node *cnode = vector_slot(cmdvec, n);

		if (!cnode)
			continue;
		for (unsigned int i = 0; i < vector_active(cnode->cmd_vector); i++)
			if (vector_slot(cnode->cmd_vector, i) == el) {
				sb_add(&b, "%u\x1f%s", n, nc);
				tstr = twin_get(b.s);
				break;
			}
	}
	free(nc);
	free(b.s);
	if (!tstr)
		return el;
	tw = xcalloc(1, sizeof(*tw));
	*tw = *el;
	tw->string = tstr;
	tw->doc = el->doc;
	return tw;
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
	infos.val[i] = cmdinfo_build(naming_source(el));
	infos.val[i]->el = el;
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
				for (size_t k = 0; k < json_object_array_length(jnodes); k++) {
					json_object *jid;
					char *nc;
					struct sbuf b = {};

					if (!json_object_object_get_ex(json_object_array_get_idx(jnodes,
												 k),
								       "node", &jid))
						continue;
					nc = normalize_cmd(json_object_get_string(jstr));
					sb_add(&b, "%d\x1f%s", json_object_get_int(jid), nc);
					twin_add(b.s, json_object_get_string(jstr));
					free(nc);
					free(b.s);
				}
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
				/* names for vtysh's own copy of this command */
				twin_add(b.s, json_object_get_string(jstr));
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
		svty = vty_new();
		svty->type = VTY_FILE;
		svty->of = NULL;
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

static json_object *match_params(struct match *m, bool *no)
{
	struct cmdinfo *ci = m->ci;
	json_object *p = json_object_new_object();

	*no = ci->mand_no;
	for (int k = 0; k < m->n; k++) {
		struct tok *t = &ci->t[m->path[k]];
		const char *arg = m->arg[k];

		if (t->type == WORD_TKN) {
			if (t->mandatory)
				continue;
			if (m->path[k] == ci->opt_no) {
				*no = true;
			} else if (t->group >= 0) {
				json_object_object_add(p, ci->names[t->group],
						       json_object_new_string(t->text));
			} else if (t->flag >= 0 &&
				   !json_object_object_get_ex(p, ci->names[t->flag], NULL)) {
				json_object_object_add(p, ci->names[t->flag],
						       json_object_new_boolean(true));
			}
			continue;
		}
		if (t->param < 0)
			continue;

		const char *nm = ci->names[t->param];
		json_object *v;
		bool num = t->type == RANGE_TKN || (t->type == ASNUM_TKN && all_digits(arg));

		v = num ? json_object_new_int64(strtoll(arg, NULL, 10))
			: json_object_new_string(arg);
		if (t->repeat) {
			json_object *prev;

			if (json_object_object_get_ex(p, nm, &prev)) {
				if (t->type == VARIABLE_TKN) {
					char *s;

					if (asprintf(&s, "%s %s", json_object_get_string(prev),
						     arg) < 0)
						abort();
					json_object_object_add(p, nm, json_object_new_string(s));
					free(s);
					json_object_put(v);
				} else {
					json_object_array_add(prev, v);
				}
				continue;
			}
			if (t->type != VARIABLE_TKN) {
				json_object *arr = json_object_new_array();

				json_object_array_add(arr, v);
				v = arr;
			}
		}
		json_object_object_add(p, nm, v);
	}
	return p;
}

/* ------------------------------------------------------------------------
 * JSON params -> line
 * ------------------------------------------------------------------------
 */
struct rstate {
	struct cmdinfo *ci;
	json_object *pv[NAMEMAX]; /* value per name (NULL = not given) */
	uint64_t all, values;	  /* names given; names given a value */
	bool no;
	const char *words[TOKMAX * 2];
	int nw;
	char *out[16];
	int nout;
	int budget;
};

static bool value_true(json_object *v)
{
	return v && json_object_get_type(v) == json_type_boolean && json_object_get_boolean(v);
}

static bool choice_eq(struct cmdinfo *ci, struct tok *t, json_object *v)
{
	const char *s;

	if (!v || json_object_get_type(v) != json_type_string)
		return false;
	s = json_object_get_string(v);
	return !strcmp(s, t->text) || (t->flag >= 0 && !strcmp(s, ci->names[t->flag]));
}

/* one scalar value as CLI word, NULL if it can't be one */
static char *scalar_word(struct tok *t, json_object *v)
{
	char buf[64];
	const char *s;

	if (json_object_get_type(v) == json_type_int) {
		snprintfrr(buf, sizeof(buf), "%" PRId64, json_object_get_int64(v));
		s = buf;
	} else if (json_object_get_type(v) == json_type_double) {
		double d = json_object_get_double(v);

		if (d != (double)(long long)d)
			return NULL;
		snprintfrr(buf, sizeof(buf), "%lld", (long long)d);
		s = buf;
	} else if (json_object_get_type(v) == json_type_string) {
		s = json_object_get_string(v);
	} else {
		return NULL;
	}
	if (!*s)
		return NULL;
	for (const char *p = s; *p; p++)
		if (isspace((unsigned char)*p))
			return NULL;
	if (t->type == RANGE_TKN) {
		char *end;
		long long x = strtoll(s, &end, 10);

		if (*end || x < t->min || x > t->max)
			return NULL;
	}
	return xstrdup(s);
}

static char *value_words(struct tok *t, json_object *v)
{
	struct sbuf b = {};

	if (!v || json_object_get_type(v) == json_type_boolean)
		return NULL;
	if (t->repeat) {
		if (json_object_get_type(v) == json_type_array) {
			size_t n = json_object_array_length(v);

			for (size_t i = 0; i < n; i++) {
				char *w = scalar_word(t, json_object_array_get_idx(v, i));

				if (!w) {
					free(b.s);
					return NULL;
				}
				sb_add(&b, "%s%s", b.len ? " " : "", w);
				free(w);
			}
			return b.s;
		}
		if (json_object_get_type(v) == json_type_string) {
			char *dup = xstrdup(json_object_get_string(v)), *sp, *w;

			for (w = strtok_r(dup, " \t", &sp); w; w = strtok_r(NULL, " \t", &sp)) {
				json_object *jw = json_object_new_string(w);
				char *x = scalar_word(t, jw);

				json_object_put(jw);
				if (!x) {
					free(dup);
					free(b.s);
					return NULL;
				}
				sb_add(&b, "%s%s", b.len ? " " : "", x);
				free(x);
			}
			free(dup);
			return b.s;
		}
	}
	if (json_object_get_type(v) == json_type_array)
		return NULL;
	return scalar_word(t, v);
}

static void render_walk(struct rstate *st, int idx, uint64_t touched, uint64_t valued,
			struct bits used, bool no_taken)
{
	struct cmdinfo *ci = st->ci;
	struct tok *cur = &ci->t[idx];
	int maxused = -1;

	if (st->nout >= 16 || --st->budget <= 0)
		return;
	if (bget(&ci->loopfork, idx))
		for (int e = 0; e < cur->nnext; e++)
			if (bget(&used, cur->next[e]) && cur->next[e] > maxused)
				maxused = cur->next[e];

	for (int e = 0; e < cur->nnext; e++) {
		int nx = cur->next[e];
		struct tok *t = &ci->t[nx];
		struct bits u2 = used;

		if (nx == idx)
			continue;
		if (maxused >= 0 && nx <= maxused && t->type != JOIN_TKN)
			continue;
		if (t->type == FORK_TKN || t->type == JOIN_TKN) {
			render_walk(st, nx, touched, valued, used, no_taken);
			continue;
		}
		if (t->type == NEG_ONLY_TKN) {
			if (st->no)
				render_walk(st, nx, touched, valued, used, no_taken);
			continue;
		}
		if (t->type == END_TKN) {
			if (touched == st->all && (st->values & ~valued) == 0 &&
			    (no_taken || !st->no || ci->mand_no)) {
				struct sbuf b = {};

				for (int i = 0; i < st->nw; i++)
					sb_add(&b, "%s%s", i ? " " : "", st->words[i]);
				for (int i = 0; i < st->nout; i++)
					if (!strcmp(st->out[i], b.s)) {
						free(b.s);
						b.s = NULL;
						break;
					}
				if (b.s)
					st->out[st->nout++] = b.s;
			}
			continue;
		}
		if (t->type == START_TKN)
			continue;
		if (bget(&used, nx) && !t->repeat)
			continue;
		bset(&u2, nx);

		if (t->type == WORD_TKN) {
			uint64_t nt = touched, nv = valued;
			bool sel = false, nno = no_taken;

			if (t->mandatory) {
				sel = true;
			} else if (nx == ci->opt_no) {
				sel = st->no;
				nno = true;
			} else {
				if (t->group >= 0 && st->pv[t->group] &&
				    choice_eq(ci, t, st->pv[t->group])) {
					sel = true;
					nt |= 1ULL << t->group;
					nv |= 1ULL << t->group;
				}
				if (t->flag >= 0 && st->pv[t->flag]) {
					sel = true;
					nt |= 1ULL << t->flag;
					if (choice_eq(ci, t, st->pv[t->flag]))
						nv |= 1ULL << t->flag;
				}
			}
			if (!sel)
				continue;
			st->words[st->nw++] = t->text;
			render_walk(st, nx, nt, nv, u2, nno);
			st->nw--;
			continue;
		}
		if (t->param < 0 || !st->pv[t->param])
			continue;

		char *w = value_words(t, st->pv[t->param]);

		if (!w)
			continue;
		st->words[st->nw++] = w;
		render_walk(st, nx, touched | (1ULL << t->param), valued | (1ULL << t->param), u2,
			    no_taken);
		st->nw--;
		free(w);
	}
}

/*
 * Render the command with params.  Returns candidate lines (shortest first),
 * or sets *bad to the first parameter name the command doesn't have.
 */
static int render(struct cmdinfo *ci, json_object *params, bool no, bool lenient, char **out,
		  int maxout, const char **bad)
{
	struct rstate st = { .ci = ci, .no = no, .budget = 200000 };
	struct bits used = {};

	*bad = NULL;
	if (!ci || !ci->usable)
		return 0;
	if (ci->mand_no && !no)
		return 0;
	if (no && !ci->mand_no && ci->opt_no < 0)
		return 0;
	if (params) {
		json_object_object_foreach(params, key, val)
		{
			int i = name_idx(ci, key, false);

			if (json_object_get_type(val) == json_type_null ||
			    (json_object_get_type(val) == json_type_boolean &&
			     !json_object_get_boolean(val)))
				continue;
			if (i < 0) {
				if (lenient)
					continue;
				*bad = key;
				return 0;
			}
			st.pv[i] = val;
			st.all |= 1ULL << i;
			if (!value_true(val))
				st.values |= 1ULL << i;
		}
	}
	render_walk(&st, ci->start, 0, 0, used, false);

	/* shortest spelling first ("A.B.C.D" before "host A.B.C.D") */
	for (int i = 1; i < st.nout; i++)
		for (int j = i; j > 0 && strlen(st.out[j]) < strlen(st.out[j - 1]); j--) {
			char *x = st.out[j];

			st.out[j] = st.out[j - 1];
			st.out[j - 1] = x;
		}
	int n = 0;

	for (int i = 0; i < st.nout; i++) {
		if (n < maxout)
			out[n++] = st.out[i];
		else
			free(st.out[i]);
	}
	return n;
}

/* ------------------------------------------------------------------------
 * errors
 * ------------------------------------------------------------------------
 */
static json_object *errors;

static void add_error(const char *path, enum node_type node, const char *fmt, ...) PRINTFRR(3, 4);
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

/* ------------------------------------------------------------------------
 * JSON statement -> config line
 * ------------------------------------------------------------------------
 */
static bool verify_line(enum node_type node, const char *line, struct match *m)
{
	if (match_line(node, line, m) == MATCHER_OK)
		return true;
	match_free(m);
	return false;
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

static void free_lines(char **l, int n)
{
	for (int i = 0; i < n; i++)
		free(l[i]);
}

/* render each candidate, keep the first spelling FRR accepts */
static int render_cands(enum node_type node, struct cmdinfo **cands, int ncand,
			json_object *params, bool no, bool lenient, char **lines,
			struct cmdinfo **owner, int max, const char **firstbad)
{
	int nl = 0;

	for (int c = 0; c < ncand; c++) {
		char *out[8];
		const char *bad = NULL;
		int n = render(cands[c], params, no, lenient, out, 8, &bad);

		if (bad && !*firstbad)
			*firstbad = bad;
		for (int i = 0; i < n; i++) {
			struct match t;

			if (nl < max && verify_line(node, out[i], &t)) {
				match_free(&t);
				lines[nl] = out[i];
				owner[nl++] = cands[c];
				free_lines(out + i + 1, n - i - 1);
				break;
			}
			free(out[i]);
		}
	}
	return nl;
}

/* all lines equal -> pick it; different -> ambiguous */
static int pick_line(char **lines, struct cmdinfo **owner, int nl, const char *path,
		     enum node_type node)
{
	for (int i = 1; i < nl; i++)
		if (strcmp(lines[i], lines[0])) {
			struct sbuf b = {};

			for (int k = 0; k < nl; k++)
				sb_add(&b, "%s%s -> '%s'", k ? "; " : "", owner[k]->el->name,
				       lines[k]);
			add_error(path, node, "ambiguous: %s; add \"id\" to choose", b.s);
			free(b.s);
			return -1;
		}
	return 0;
}

static void explain_failure(enum node_type node, const char *path, struct cmdinfo **cands,
			    int ncand, json_object *params, const char *what, const char *firstbad)
{
	struct cmdinfo *ci = cands[0];
	struct sbuf b = {};

	if (ncand == 1 && firstbad) {
		for (int i = 0; i < ci->nnames; i++)
			sb_add(&b, "%s%s", i ? ", " : "", ci->names[i]);
		add_error(path, node, "unknown parameter '%s' for '%s' (valid: %s)", firstbad,
			  ci->el->string, b.len ? b.s : "none");
	} else if (ncand == 1) {
		for (int i = 0; i < ci->nnames; i++)
			if (ci->required[i] &&
			    !(params && json_object_object_get_ex(params, ci->names[i], NULL)))
				sb_add(&b, "%s%s", b.len ? ", " : "", ci->names[i]);
		if (b.len)
			add_error(path, node, "missing parameter(s) %s for '%s'", b.s,
				  ci->el->string);
		else
			add_error(path, node, "parameter values/combination not accepted by '%s'",
				  ci->el->string);
	} else {
		for (int c = 0; c < ncand && c < 8; c++)
			sb_add(&b, "%s%s: %s", c ? " | " : "", cands[c]->el->name,
			       cands[c]->el->string);
		add_error(path, node, "no '%s' command in %s accepts these params; candidates: %s",
			  what, node_name(node), b.s);
	}
	free(b.s);
}

/*
 * Resolve {"cmd", "params", "no", "id"} in node into a matched line.
 * On failure, records an error and returns false.
 */
static bool resolve_obj(enum node_type node, json_object *stmt, const char *path, struct match *m)
{
	struct cmd_node *cnode = vector_lookup(cmdvec, node);
	json_object *jcmd = NULL, *jparams = NULL, *jno = NULL, *jid = NULL;
	const char *cmd = NULL, *id = NULL, *firstbad = NULL;
	bool no = false, has_params = false, ok = false;
	char *want = NULL, *lines[64];
	struct cmdinfo *cands[512], *owner[64];
	int ncand = 0, nl;

	json_object_object_get_ex(stmt, "cmd", &jcmd);
	json_object_object_get_ex(stmt, "params", &jparams);
	json_object_object_get_ex(stmt, "no", &jno);
	json_object_object_get_ex(stmt, "id", &jid);
	if (jcmd)
		cmd = json_object_get_string(jcmd);
	if (jid)
		id = json_object_get_string(jid);
	if (jno)
		no = json_object_get_boolean(jno);
	if (jparams && json_object_get_type(jparams) != json_type_object) {
		add_error(path, node, "\"params\" must be an object");
		return false;
	}
	if (jparams && json_object_object_length(jparams) > 0)
		has_params = true;
	if (!cmd && !id) {
		add_error(path, node, "statement needs \"cmd\" or \"id\"");
		return false;
	}

	/* 1. "cmd" is a complete line */
	if (cmd && !id && !has_params) {
		struct match pm;
		char *line;

		if (asprintf(&line, "%s%s", no ? "no " : "", cmd) < 0)
			abort();
		ok = verify_line(node, line, m);
		free(line);
		if (ok)
			return true;
		if (no && verify_line(node, cmd, &pm)) {
			char *pos = match_text(&pm);
			bool done = pm.ci && negate_line(node, pos, pm.ci->sig, m);

			free(pos);
			match_free(&pm);
			if (done)
				return true;
		}
	}

	/* 2. signature (or id) + params */
	if (id) {
		for (unsigned int i = 0; i < vector_active(cnode->cmd_vector); i++) {
			const struct cmd_element *el = vector_slot(cnode->cmd_vector, i);

			if (el && el->name && !strcmp(el->name, id)) {
				want = xstrdup(cmdinfo_get(el)->sig);
				if (cmdinfo_get(el)->usable)
					cands[ncand++] = cmdinfo_get(el);
				break;
			}
		}
		if (!ncand) {
			add_error(path, node, "no command with id '%s' in %s", id, node_name(node));
			free(want);
			return false;
		}
	} else {
		want = normalize_cmd(cmd);
	}
	/* every command with this signature; with "id", only when that
	 * command has no "no" form of its own
	 */
	if (!id || (no && !(cands[0]->mand_no || cands[0]->opt_no >= 0)))
		for (unsigned int i = 0; i < vector_active(cnode->cmd_vector); i++) {
			const struct cmd_element *el = vector_slot(cnode->cmd_vector, i);
			struct cmdinfo *ci;

			if (!el)
				continue;
			ci = cmdinfo_get(el);
			if (!ci->usable || strcmp(ci->sig, want) || (ncand && ci == cands[0]) ||
			    ncand >= 512)
				continue;
			if (id && !(ci->mand_no || ci->opt_no >= 0))
				continue;
			cands[ncand++] = ci;
		}
	if (!ncand) {
		add_error(path, node, "'%s' is not a command in %s (as a line or a signature)",
			  cmd, node_name(node));
		free(want);
		return false;
	}

	/* "id" names a positive command: negate exactly its spelling first */
	if (id && no && !cands[0]->mand_no && cands[0]->opt_no < 0) {
		const char *ignore = NULL;

		nl = render_cands(node, cands, 1, jparams, false, false, lines, owner, 64, &ignore);
		for (int i = 0; i < nl && !ok; i++)
			ok = negate_line(node, lines[i], owner[i]->sig, m);
		free_lines(lines, nl);
		if (ok) {
			free(want);
			return true;
		}
	}

	/* a. render as asked */
	nl = render_cands(node, cands, ncand, jparams, no, false, lines, owner, 64, &firstbad);
	if (nl) {
		int pick = pick_line(lines, owner, nl, path, node);

		ok = pick >= 0 && verify_line(node, lines[pick], m);
		free_lines(lines, nl);
		free(want);
		return ok;
	}

	if (no) {
		bool negatable = false;

		for (int c = 0; c < ncand; c++)
			negatable |= cands[c]->mand_no || cands[c]->opt_no >= 0;

		/* b. "no" + the positive line, trimmed to what "no" takes */
		struct cmdinfo *pos[512];
		int npos = 0;
		const char *ignore = NULL;

		for (int c = 0; c < ncand; c++)
			if (!cands[c]->mand_no)
				pos[npos++] = cands[c];
		nl = render_cands(node, pos, npos, jparams, false, false, lines, owner, 64,
				  &ignore);
		for (int i = 0; i < nl && !ok; i++)
			ok = negate_line(node, lines[i], owner[i]->sig, m);
		free_lines(lines, nl);
		if (ok) {
			free(want);
			return true;
		}

		/* c. drop parameters the "no" form doesn't have */
		nl = render_cands(node, cands, ncand, jparams, true, true, lines, owner, 64,
				  &ignore);
		if (nl) {
			int pick = pick_line(lines, owner, nl, path, node);

			ok = pick >= 0 && verify_line(node, lines[pick], m);
			free_lines(lines, nl);
			free(want);
			return ok;
		}
		if (!negatable) {
			add_error(path, node, "'%s' has no \"no\" form in %s", want,
				  node_name(node));
			free(want);
			return false;
		}
	}
	/* explain against the commands that could apply */
	int nap = 0;

	for (int c = 0; c < ncand; c++)
		if (no || !cands[c]->mand_no)
			cands[nap++] = cands[c];
	if (!nap)
		nap = ncand;
	firstbad = NULL;
	if (nap == 1) {
		char *out[8];
		int n = render(cands[0], jparams, no, false, out, 8, &firstbad);

		free_lines(out, n);
	}
	explain_failure(node, path, cands, nap, jparams, cmd ? cmd : id, firstbad);
	free(want);
	return false;
}

static void emit_list(json_object *arr, enum node_type node, int depth, const char *path,
		      struct sbuf *out);

static void emit_stmt(json_object *stmt, enum node_type node, int depth, const char *path,
		      struct sbuf *out)
{
	struct match m;
	json_object *children = NULL;
	enum node_type next;
	char *text;

	if (json_object_get_type(stmt) == json_type_string) {
		const char *line = json_object_get_string(stmt);
		enum matcher_rv rv;

		while (isspace((unsigned char)*line))
			line++;
		if (!*line || *line == '!')
			return;
		rv = match_line(node, line, &m);
		if (rv != MATCHER_OK) {
			add_error(path, node, "'%s': %s in %s", line, matcher_err(rv),
				  node_name(node));
			return;
		}
	} else if (json_object_get_type(stmt) == json_type_object) {
		json_object_object_foreach(stmt, key, val)
		{
			(void)val;
			if (strcmp(key, "cmd") && strcmp(key, "params") && strcmp(key, "no") &&
			    strcmp(key, "id") && strcmp(key, "config") && strcmp(key, "comment")) {
				add_error(path, node, "unknown key '%s'", key);
				return;
			}
		}
		json_object_object_get_ex(stmt, "config", &children);
		if (!resolve_obj(node, stmt, path, &m))
			return;
	} else {
		add_error(path, node, "statement must be a string or an object");
		return;
	}

	text = match_text(&m);
	next = node_after(node, &m);
	match_free(&m);

	/* "exit", "end", "exit-address-family"...: implied by nesting */
	if (!strcmp(text, "end") || !strcmp(text, "exit") || !strcmp(text, "quit") ||
	    !strncmp(text, "exit-", 5) ||
	    (next != node && (next < CONFIG_NODE || is_ancestor(next, node)))) {
		add_error(path, node,
			  "'%s' leaves the current mode; blocks are closed by "
			  "nesting statements in \"config\"",
			  text);
		free(text);
		return;
	}

	sb_add(out, "%*s%s\n", depth, "", text);
	if (next != node && next >= CONFIG_NODE && vector_lookup(cmdvec, next)) {
		char sub[1024];

		snprintfrr(sub, sizeof(sub), "%.1000s/config", path);
		if (children)
			emit_list(children, next, depth + 1, sub, out);
		sb_add(out, "%*s%s\n", depth, "", node_exit_cmd(next));
		if (depth == 0)
			sb_add(out, "!\n");
	} else if (children && json_object_array_length(children)) {
		add_error(path, node, "'%s' does not enter a sub-mode; \"config\" is not allowed",
			  text);
	}
	free(text);
}

static void emit_list(json_object *arr, enum node_type node, int depth, const char *path,
		      struct sbuf *out)
{
	char sub[1024];

	if (json_object_get_type(arr) != json_type_array) {
		add_error(path, node, "\"config\" must be an array");
		return;
	}
	for (size_t i = 0; i < json_object_array_length(arr); i++) {
		snprintfrr(sub, sizeof(sub), "%.1000s/%zu", path, i);
		emit_stmt(json_object_array_get_idx(arr, i), node, depth, sub, out);
	}
}

/* ------------------------------------------------------------------------
 * config text -> JSON
 * ------------------------------------------------------------------------
 */
static bool opt_lines;

static bool stmt_reproduces(enum node_type node, json_object *o, struct match *m)
{
	json_object *saved = errors, *p1, *p2;
	struct match back;
	bool same = false, no1, no2;

	errors = json_object_new_array();
	if (resolve_obj(node, o, "", &back)) {
		if (back.el == m->el && back.ci && m->ci) {
			p1 = match_params(m, &no1);
			p2 = match_params(&back, &no2);
			same = no1 == no2 && json_object_equal(p1, p2);
			json_object_put(p1);
			json_object_put(p2);
		}
		match_free(&back);
	}
	json_object_put(errors);
	errors = saved;
	return same;
}

static json_object *stmt_from_match(enum node_type node, struct match *m)
{
	json_object *o, *params;
	bool no;
	char *line = match_text(m);

	if (opt_lines || !m->ci || !m->ci->sig[0])
		goto literal;

	params = match_params(m, &no);
	o = json_object_new_object();
	json_object_object_add(o, "cmd", json_object_new_string(m->ci->sig));
	if (no)
		json_object_object_add(o, "no", json_object_new_boolean(true));
	if (json_object_object_length(params))
		json_object_object_add(o, "params", params);
	else
		json_object_put(params);

	/* does {cmd, params, no} lead back to this command and these params?
	 * (keyword sets may come back in canonical order)
	 */
	if (!stmt_reproduces(node, o, m)) {
		json_object_object_add(o, "id", json_object_new_string(m->el->name));
		if (!m->el->name || !stmt_reproduces(node, o, m)) {
			json_object_put(o);
			goto literal;
		}
	}
	free(line);
	return o;

literal:
	o = json_object_new_string(line);
	free(line);
	return o;
}

#define STACKMAX 32

static json_object *text_to_json(FILE *in)
{
	enum node_type nodes[STACKMAX];
	json_object *arrs[STACKMAX];
	int depth = 0, lineno = 0;
	char *buf = NULL;
	size_t bsz = 0;
	ssize_t len;
	json_object *root = json_object_new_object();
	json_object *config = json_object_new_array();

	nodes[0] = CONFIG_NODE;
	arrs[0] = config;

	while ((len = getline(&buf, &bsz, in)) >= 0) {
		char *line = buf, *end;
		struct match m;
		enum matcher_rv rv = MATCHER_NO_MATCH;
		int lvl;

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
		if (!strcmp(line, "exit") || !strncmp(line, "exit-", 5) || !strcmp(line, "quit")) {
			if (depth > 0) {
				depth--;
				continue;
			}
			/* like vtysh: exit at the top ends the config file */
			char path[32];

			snprintfrr(path, sizeof(path), "line %d", lineno);
			add_error(path, CONFIG_NODE,
				  "early exit from config file; the remaining lines are ignored");
			break;
		}

		/* current node first, then implicit exits (like vtysh) */
		enum matcher_rv first = MATCHER_NO_MATCH;

		for (lvl = depth; lvl >= 0; lvl--) {
			rv = match_line(nodes[lvl], line, &m);
			if (lvl == depth)
				first = rv;
			if (rv == MATCHER_OK)
				break;
			match_free(&m);
		}
		if (rv != MATCHER_OK) {
			char path[32];

			snprintfrr(path, sizeof(path), "line %d", lineno);
			add_error(path, nodes[depth], "'%s': %s in %s", line, matcher_err(first),
				  node_name(nodes[depth]));
			json_object_array_add(arrs[depth], json_object_new_string(line));
			continue;
		}
		depth = lvl;

		json_object *stmt = stmt_from_match(nodes[depth], &m);
		enum node_type next = node_after(nodes[depth], &m);

		match_free(&m);
		json_object_array_add(arrs[depth], stmt);

		if (next == nodes[depth] || next < CONFIG_NODE)
			continue;
		/* leaving to an enclosing node */
		bool up = false;

		for (int k = depth - 1; k >= 0; k--)
			if (nodes[k] == next) {
				depth = k;
				up = true;
				break;
			}
		if (up || depth + 1 >= STACKMAX)
			continue;

		json_object *kids = json_object_new_array();

		if (json_object_get_type(stmt) == json_type_string) {
			json_object *o = json_object_new_object();

			json_object_object_add(o, "cmd", json_object_get(stmt));
			json_object_array_put_idx(arrs[depth],
						  json_object_array_length(arrs[depth]) - 1, o);
			stmt = o;
		}
		json_object_object_add(stmt, "config", kids);
		depth++;
		nodes[depth] = next;
		arrs[depth] = kids;
	}
	free(buf);
	json_object_object_add(root, "config", config);
	return root;
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

static int self_test(int per_cmd)
{
	unsigned int seed = 1;
	unsigned long total = 0, ok = 0, other = 0, nocmds = 0, amb = 0;
	unsigned long pos = 0, negated = 0, no_form = 0;
	FILE *negf = getenv("FRR_CONFJSON_NEGATED") ? fopen(getenv("FRR_CONFJSON_NEGATED"), "w")
						    : NULL;
	FILE *unnegf = getenv("FRR_CONFJSON_UNNEGATED")
			       ? fopen(getenv("FRR_CONFJSON_UNNEGATED"), "w")
			       : NULL;
	int shown = 0;

	for (unsigned int n = CONFIG_NODE; n < vector_active(cmdvec); n++) {
		struct cmd_node *cnode = vector_slot(cmdvec, n);

		if (!cnode)
			continue;
		for (unsigned int c = 0; c < vector_active(cnode->cmd_vector); c++) {
			const struct cmd_element *el = vector_slot(cnode->cmd_vector, c);
			struct cmdinfo *ci;

			if (!el)
				continue;
			ci = cmdinfo_get(el);
			if (!ci->usable || !ci->sig[0]) {
				nocmds++;
				continue;
			}
			for (int k = 0; k < per_cmd; k++) {
				char *line = random_line(ci, &seed), *l2 = NULL;
				struct match m, m2;
				json_object *stmt = NULL, *p1, *p2;
				bool no1, no2, good = false;
				const char *why = "no match";

				if (!line)
					continue;
				total++;
				enum matcher_rv rv = match_line(n, line, &m);

				if (rv == MATCHER_AMBIGUOUS) {
					/* FRR's grammar itself is ambiguous here;
					 * vtysh rejects the line as well
					 */
					amb++;
					total--;
					match_free(&m);
					free(line);
					continue;
				}
				if (rv != MATCHER_OK) {
					match_free(&m);
					goto report;
				}
				if (m.el != el || !m.ci) {
					/* a more specific command took it */
					other++;
					match_free(&m);
					free(line);
					continue;
				}
				stmt = stmt_from_match(n, &m);
				p1 = match_params(&m, &no1);
				why = "JSON does not render";
				if (json_object_get_type(stmt) == json_type_object &&
				    resolve_obj(n, stmt, "", &m2)) {
					l2 = match_text(&m2);
					why = "different command";
					if (m2.el == el && m2.ci) {
						p2 = match_params(&m2, &no2);
						why = "different params";
						good = no1 == no2 && json_object_equal(p1, p2);
						json_object_put(p2);
					}
					match_free(&m2);
				} else if (json_object_get_type(stmt) == json_type_string) {
					why = "kept as literal line";
				}
				/* "no": true on a positive statement */
				if (good && !no1 && json_object_get_type(stmt) == json_type_object) {
					json_object *neg = NULL;
					struct match m3;
					bool has_no = false;

					json_object_deep_copy(stmt, &neg, NULL);
					json_object_object_add(neg, "no",
							       json_object_new_boolean(true));
					pos++;
					for (unsigned int q = 0;
					     q < vector_active(cnode->cmd_vector); q++) {
						const struct cmd_element *e2 =
							vector_slot(cnode->cmd_vector, q);
						struct cmdinfo *c2;

						if (!e2)
							continue;
						c2 = cmdinfo_get(e2);
						if (c2->usable && !strcmp(c2->sig, ci->sig) &&
						    (c2->mand_no || c2->opt_no >= 0))
							has_no = true;
					}
					if (has_no)
						no_form++;
					if (resolve_obj(n, neg, "", &m3)) {
						char *nl = match_text(&m3);

						if (!strncmp(nl, "no ", 3)) {
							negated++;
							if (negf)
								fprintf(negf, "%u\t%s\n", n, nl);
						}
						free(nl);
						match_free(&m3);
					} else {
						if (unnegf)
							fprintf(unnegf, "%u\t%s\n", n, line);
						if (has_no && shown++ < 40)
							fprintf(stderr, "NO-FAIL [%s] '%s'\n",
								node_name(n), line);
					}
					json_object_put(neg);
				}
				json_object_put(p1);
				match_free(&m);
report:
				if (good) {
					ok++;
				} else if (shown++ < 40) {
					fprintf(stderr, "FAIL [%s] %s: '%s' -> %s -> '%s' (%s)\n",
						node_name(n), el->name, line,
						stmt ? json_object_to_json_string_ext(
							       stmt,
							       JSON_C_TO_STRING_PLAIN |
								       JSON_C_TO_STRING_NOSLASHESCAPE)
						     : "-",
						l2 ? l2 : "-", why);
				}
				if (stmt)
					json_object_put(stmt);
				free(l2);
				free(line);
			}
		}
	}
	json_object_array_del_idx(errors, 0, json_object_array_length(errors));
	fprintf(stderr,
		"self-test: %lu/%lu random lines round-tripped "
		"(%lu taken by a more specific command, %lu ambiguous in FRR's own grammar, "
		"%lu commands without signature)\n",
		ok, total, other, amb, nocmds);
	fprintf(stderr,
		"self-test: \"no\": %lu/%lu positive statements negated "
		"(%lu have a \"no\" form with the same signature)\n",
		negated, pos, no_form);
	if (negf)
		fclose(negf);
	if (unnegf)
		fclose(unnegf);
	return ok == total ? 0 : 1;
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
		"  -l, --lines         to-json: plain config lines, no cmd/params\n"
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
						  { "lines", no_argument, NULL, 'l' },
						  { "compact", no_argument, NULL, 'c' },
						  { "stats", no_argument, NULL, 's' },
						  { "help", no_argument, NULL, 'h' },
						  { "self-test", optional_argument, NULL, 'T' },
						  {} };
	const char *xref = getenv("FRR_XREF");
	const char *vtysh_bin = FRR_VTYSH_DEFAULT, *pathspace = NULL;
	bool compact = false, show_stats = false;
	int selftest = 0;
	int opt, rc = 0;

	if (!xref || !*xref)
		xref = FRR_XREF_DEFAULT;
	while ((opt = getopt_long(argc, argv, "x:N:lcsh", longopts, NULL)) != -1) {
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
		case 'l':
			opt_lines = true;
			break;
		case 'c':
			compact = true;
			break;
		case 's':
			show_stats = true;
			break;
		case 'h':
			usage(0);
			break;
		case 'T':
			selftest = optarg ? atoi(optarg) : 4;
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

	/* vtysh's nodes and node-switching commands, then frr.xref */
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
		char *text = read_all(in);
		enum json_tokener_error jerr;
		json_object *doc = json_tokener_parse_verbose(text, &jerr), *cfg;
		struct sbuf out = {};

		if (in != stdin)
			fclose(in);
		free(text);
		if (!doc) {
			fprintf(stderr, "frr-confjson: invalid JSON: %s\n",
				json_tokener_error_desc(jerr));
			return 2;
		}
		if (json_object_get_type(doc) == json_type_array)
			cfg = doc;
		else if (!json_object_object_get_ex(doc, "config", &cfg)) {
			fprintf(stderr,
				"frr-confjson: expected {\"config\": [...]} or a list of statements\n");
			return 2;
		}
		emit_list(cfg, CONFIG_NODE, 0, "/config", &out);
		if (!json_object_array_length(errors))
			fputs(out.s ? out.s : "", stdout);
		free(out.s);
		json_object_put(doc);
	}

	if (json_object_array_length(errors)) {
		print_errors();
		if (!rc)
			rc = 1;
	}
	return rc;
}
