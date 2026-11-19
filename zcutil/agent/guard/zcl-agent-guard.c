/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Derived from Z23 tools/agent_guard.c@9a191ef7b, Apache-2.0, changed: zclassicd's rules, a
 * portable line reader and binary stdin for Windows, and a warning verdict. See
 * zcutil/tools/NOTICE.
 *
 * zcl-agent-guard: a Claude Code PreToolUse hook that refuses the never-do list AGENTS.md
 * already states (node datadirs, reindex, spend and key export, Python, git identity, git push to
 * master or forced, hosted CI, vendored code) and warns on an edit of the sealed consensus set.
 *
 *   zcl-agent-guard                       hook mode: PreToolUse JSON on stdin
 *   zcl-agent-guard --bash CMD            print ALLOW, WARN <rule> or REFUSE <rule> <text>
 *   zcl-agent-guard --ps CMD              the same for a PowerShell command
 *   zcl-agent-guard --path TOOL FILE [CONTENT]
 *   zcl-agent-guard --replay TRANSCRIPT   evaluate a transcript (JSONL) offline
 *
 * Hook contract: exit 2 plus one stderr line refuses the call; exit 0 allows it (a warning is a
 * stderr line plus a PreToolUse "ask" decision on stdout, exit 0). Malformed input fails open
 * with a warning: this is a safety net,
 * not the primary control. Precision matters as much as coverage, because a false refusal
 * stalls the worker.
 *
 * Shell scanning is documented in rules.c. Hook JSON is parsed with the vendored zjsonp. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "rules.h"
#include "zjsonp/zjsonp.h"

#define MAX_INPUT (32u * 1024u * 1024u)
#define MAX_CALLS 16

/* ---- tool call extraction from JSON ------------------------------ */

struct call {
    char *name, *cmd, *file, *nb, *content;
};

static void call_free(struct call *c)
{
    free(c->name);
    free(c->cmd);
    free(c->file);
    free(c->nb);
    free(c->content);
    memset(c, 0, sizeof *c);
}

static char *dec_str(const char *text, const zjsonp_event *ev)
{
    char *out = malloc(ev->len + 1); // raw-alloc-ok:build-tool
    size_t n;
    if (!out) return NULL;
    n = zjsonp_str_decode(text, ev, out, ev->len + 1);
    if (n == SIZE_MAX || n > ev->len) {
        free(out);
        return NULL;
    }
    out[n] = '\0';
    return out;
}

static bool skip_value(zjsonp *p, const zjsonp_event *v)
{
    int d = 0;
    if (v->kind != ZJRP_OBJ_OPEN && v->kind != ZJRP_ARR_OPEN) return true;
    d = 1;
    while (d > 0) {
        zjsonp_event ev;
        if (zjsonp_next(p, &ev) != ZJRP_OK) return false;
        if (ev.kind == ZJRP_OBJ_OPEN || ev.kind == ZJRP_ARR_OPEN) d++;
        if (ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE) d--;
    }
    return true;
}

/* Decode the key event into out; out[0] is NUL when it does not fit. */
static void key_str(const char *text, const zjsonp_event *ev, char *out, size_t cap)
{
    size_t n = zjsonp_str_decode(text, ev, out, cap);
    if (n == SIZE_MAX || n >= cap) out[0] = '\0';
    else out[n] = '\0';
}

static char **input_slot(struct call *c, const char *key)
{
    if (strcmp(key, "command") == 0) return &c->cmd;
    if (strcmp(key, "file_path") == 0) return &c->file;
    if (strcmp(key, "notebook_path") == 0) return &c->nb;
    if (strcmp(key, "content") == 0) return &c->content;
    return NULL;
}

/* Called after the tool_input OBJ_OPEN; consumes through its close. */
static bool parse_input(zjsonp *p, const char *text, struct call *call)
{
    for (;;) {
        zjsonp_event ev, v;
        char key[32];
        char **slot;
        if (zjsonp_next(p, &ev) != ZJRP_OK) return false;
        if (ev.kind == ZJRP_OBJ_CLOSE) return true;
        if (ev.kind != ZJRP_KEY || zjsonp_next(p, &v) != ZJRP_OK) return false;
        key_str(text, &ev, key, sizeof key);
        slot = input_slot(call, key);
        if (slot && v.kind == ZJRP_STR) {
            free(*slot);
            *slot = dec_str(text, &v);
        } else if (!skip_value(p, &v)) {
            return false;
        }
    }
}

static bool parse_hook(const char *text, size_t len, struct call *call)
{
    zjsonp p;
    zjsonp_event ev;
    zjsonp_init(&p, text, len);
    if (zjsonp_next(&p, &ev) != ZJRP_OK || ev.kind != ZJRP_OBJ_OPEN) return false;
    for (;;) {
        zjsonp_event v;
        char key[32];
        if (zjsonp_next(&p, &ev) != ZJRP_OK) return false;
        if (ev.kind == ZJRP_OBJ_CLOSE) return true;
        if (ev.kind != ZJRP_KEY || zjsonp_next(&p, &v) != ZJRP_OK) return false;
        key_str(text, &ev, key, sizeof key);
        if (strcmp(key, "tool_name") == 0 && v.kind == ZJRP_STR) {
            free(call->name);
            call->name = dec_str(text, &v);
        } else if (strcmp(key, "tool_input") == 0 && v.kind == ZJRP_OBJ_OPEN) {
            if (!parse_input(&p, text, call)) return false;
        } else if (!skip_value(&p, &v)) {
            return false;
        }
    }
}

static const char *eval_call(const struct call *c)
{
    if (!c->name) return NULL;
    if (strcmp(c->name, "Bash") == 0) return c->cmd ? ag_eval_bash(c->cmd) : NULL;
    if (strcmp(c->name, "PowerShell") == 0) return c->cmd ? ag_eval_ps(c->cmd) : NULL;
    if (strcmp(c->name, "NotebookEdit") == 0) return ag_eval_path(c->name, c->nb, NULL);
    if (strcmp(c->name, "Edit") == 0 || strcmp(c->name, "Write") == 0 ||
        strcmp(c->name, "MultiEdit") == 0)
        return ag_eval_path(c->name, c->file, c->content);
    return NULL;
}

static bool call_is_checked(const struct call *c)
{
    static const char *const tools[] = {"Bash", "PowerShell", "Edit", "Write", "MultiEdit",
                                        "NotebookEdit"};
    if (!c->name) return false;
    for (size_t i = 0; i < sizeof tools / sizeof tools[0]; i++)
        if (strcmp(c->name, tools[i]) == 0) return true;
    return false;
}

static const char *call_subject(const struct call *c)
{
    if (c->cmd) return c->cmd;
    if (c->file) return c->file;
    return c->nb ? c->nb : "";
}

/* ---- transcript replay ------------------------------------------- */

struct walker {
    zjsonp p;
    const char *text;
    struct call calls[MAX_CALLS];
    int ncalls;
    bool assistant;
};

struct objst {
    char type[24];
    char *name;
    struct call in;
    bool has_in;
};

static bool walk_value(struct walker *W, const zjsonp_event *v, int level);

static bool walk_array(struct walker *W, int level)
{
    for (;;) {
        zjsonp_event ev;
        if (zjsonp_next(&W->p, &ev) != ZJRP_OK) return false;
        if (ev.kind == ZJRP_ARR_CLOSE) return true;
        if (!walk_value(W, &ev, level + 1)) return false;
    }
}

static bool walk_member(struct walker *W, const zjsonp_event *kev, int level,
                        struct objst *st)
{
    zjsonp_event v;
    char key[16];
    if (zjsonp_next(&W->p, &v) != ZJRP_OK) return false;
    key_str(W->text, kev, key, sizeof key);
    if (strcmp(key, "type") == 0 && v.kind == ZJRP_STR) {
        key_str(W->text, &v, st->type, sizeof st->type);
        return true;
    }
    if (strcmp(key, "name") == 0 && v.kind == ZJRP_STR) {
        free(st->name);
        st->name = dec_str(W->text, &v);
        return true;
    }
    if (strcmp(key, "input") == 0 && v.kind == ZJRP_OBJ_OPEN) {
        st->has_in = true;
        return parse_input(&W->p, W->text, &st->in);
    }
    return walk_value(W, &v, level + 1);
}

static void finish_object(struct walker *W, struct objst *st, int level)
{
    if (level == 0) {
        W->assistant = strcmp(st->type, "assistant") == 0;
    } else if (strcmp(st->type, "tool_use") == 0 && st->name && st->has_in &&
               W->ncalls < MAX_CALLS) {
        W->calls[W->ncalls] = st->in;
        W->calls[W->ncalls].name = st->name;
        W->ncalls++;
        st->name = NULL;
        memset(&st->in, 0, sizeof st->in);
    }
}

static bool walk_object(struct walker *W, int level)
{
    struct objst st;
    bool ok = true;
    memset(&st, 0, sizeof st);
    for (;;) {
        zjsonp_event ev;
        if (zjsonp_next(&W->p, &ev) != ZJRP_OK) {
            ok = false;
            break;
        }
        if (ev.kind == ZJRP_OBJ_CLOSE) break;
        if (ev.kind != ZJRP_KEY || !walk_member(W, &ev, level, &st)) {
            ok = false;
            break;
        }
    }
    if (ok) finish_object(W, &st, level);
    free(st.name);
    call_free(&st.in);
    return ok;
}

static bool walk_value(struct walker *W, const zjsonp_event *v, int level)
{
    if (level > ZJRP_MAX_DEPTH) return false;
    if (v->kind == ZJRP_OBJ_OPEN) return walk_object(W, level);
    if (v->kind == ZJRP_ARR_OPEN) return walk_array(W, level);
    return true;
}

/* ---- output: text or JSON, paged to 16 KiB ----------------------- */

#define OUT_BUDGET 16384

struct out {
    bool json;
    long after, seen;
    size_t used;
    bool truncated;
};

static void json_str(FILE *f, const char *s, size_t max)
{
    fputc('"', f);
    for (size_t i = 0; s[i] && i < max; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch == '"' || ch == '\\') fprintf(f, "\\%c", ch);
        else if (ch < 0x20) fprintf(f, "\\u%04x", ch);
        else fputc(ch, f);
    }
    fputc('"', f);
}

/* One finding line; skipped before --after and dropped once the page is full. */
static void emit_finding(struct out *o, const char *rule, const char *subject)
{
    char buf[141];
    size_t n = 0;
    int w;
    if (o->seen++ < o->after) return;
    if (o->used >= OUT_BUDGET) {
        o->truncated = true;
        return;
    }
    for (; subject[n] && n < 140; n++)
        buf[n] = (subject[n] == '\n' || subject[n] == '\r') ? ' ' : subject[n];
    buf[n] = '\0';
    if (o->json) {
        printf("{\"rule\":\"%s\",\"subject\":", rule);
        json_str(stdout, buf, 140);
        printf("}\n");
        w = (int)(n + 40);
    } else {
        w = printf("%s %s %s\n", ag_rule_is_warning(rule) ? "WARN" : "REFUSE", rule, buf);
    }
    o->used += (size_t)w;
}

/* ---- transcript replay ------------------------------------------- */

static void replay_line(const char *line, size_t len, long *calls, long *refused, long *warned,
                        struct out *o)
{
    struct walker *W = calloc(1, sizeof *W); // raw-alloc-ok:build-tool
    zjsonp_event ev;
    if (!W) {
        fprintf(stderr, "zcl-agent-guard: out of memory in replay\n");
        return;
    }
    W->text = line;
    zjsonp_init(&W->p, line, len);
    if (zjsonp_next(&W->p, &ev) == ZJRP_OK && ev.kind == ZJRP_OBJ_OPEN &&
        walk_object(W, 0) && W->assistant) {
        for (int i = 0; i < W->ncalls; i++) {
            const char *r;
            if (!call_is_checked(&W->calls[i])) continue;
            (*calls)++;
            r = eval_call(&W->calls[i]);
            if (!r) continue;
            if (ag_rule_is_warning(r)) (*warned)++;
            else (*refused)++;
            emit_finding(o, r, call_subject(&W->calls[i]));
        }
    }
    for (int i = 0; i < W->ncalls; i++) call_free(&W->calls[i]);
    free(W);
}

/* One line of any length into *buf (NUL-terminated); returns its length or -1 at EOF. */
static long read_line(FILE *f, char **buf, size_t *cap)
{
    size_t n = 0;
    int ch;
    while ((ch = fgetc(f)) != EOF) {
        if (n + 2 > *cap) {
            size_t nc = *cap ? *cap * 2 : 4096;
            char *nb = realloc(*buf, nc); // raw-alloc-ok:build-tool
            if (!nb) return -1;
            *buf = nb;
            *cap = nc;
        }
        (*buf)[n++] = (char)ch;
        if (ch == '\n') break;
    }
    if (n == 0) return -1;
    (*buf)[n] = '\0';
    return (long)n;
}

/* Exit 0 clean, 1 a refusal was found, 2 unreadable or a hollow scan (no checked calls). */
static int cmd_replay(const char *file, struct out *o)
{
    FILE *f = fopen(file, "rb");
    char *line = NULL;
    size_t cap = 0;
    long n, calls = 0, refused = 0, warned = 0;
    if (!f) {
        fprintf(stderr, "zcl-agent-guard: cannot open %s\n", file);
        return 2;
    }
    while ((n = read_line(f, &line, &cap)) >= 0)
        replay_line(line, (size_t)n, &calls, &refused, &warned, o);
    free(line);
    fclose(f);
    if (o->json) {
        long shown = o->seen - o->after;
        printf("{\"calls\":%ld,\"refused\":%ld,\"warned\":%ld,\"next\":%ld}\n", calls, refused,
               warned, o->truncated ? o->after + (shown > 0 ? shown : 0) : -1L);
    } else {
        printf("replay: %ld calls, %ld refused, %ld warned\n", calls, refused, warned);
    }
    if (o->truncated)
        fprintf(stderr, "zcl-agent-guard: output truncated at 16 KiB; page with --after=N\n");
    if (calls == 0) {
        fprintf(stderr, "zcl-agent-guard: no Bash/Edit/Write calls in %s (hollow scan)\n", file);
        return 2;
    }
    return refused > 0 ? 1 : 0;
}

/* ---- hook mode and CLI ------------------------------------------- */

/* Reads stdin up to MAX_INPUT; *big is set when more input follows, which is then unread. */
static char *read_stdin(size_t *len, bool *big)
{
    size_t cap = 65536, n = 0;
    char *buf = malloc(cap); // raw-alloc-ok:build-tool
    *big = false;
    while (buf) {
        size_t got = fread(buf + n, 1, cap - n, stdin);
        n += got;
        if (n < cap) break;
        if (cap >= MAX_INPUT) {
            *big = fgetc(stdin) != EOF;
            break;
        }
        cap *= 2;
        char *nb = realloc(buf, cap); // raw-alloc-ok:build-tool
        if (!nb) {
            free(buf);
            return NULL;
        }
        buf = nb;
    }
    *len = n;
    return buf;
}

/* A warning reaches the model only as a PreToolUse decision on stdout (stderr of an exit-0 hook
 * goes to the debug log): ask puts the call in front of the human with the rule text. */
static void print_ask(const char *rule)
{
    char reason[700];
    snprintf(reason, sizeof reason, "%s: %s", rule, ag_rule_text(rule));
    printf("{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\","
           "\"permissionDecision\":\"ask\",\"permissionDecisionReason\":");
    json_str(stdout, reason, sizeof reason);
    printf("}}\n");
    fflush(stdout);
}

static int cmd_hook(void)
{
    size_t len = 0;
    bool big = false;
    char *in = read_stdin(&len, &big);
    struct call call;
    const char *r = NULL;
    bool ok;
    memset(&call, 0, sizeof call);
    if (big) {
        /* Input over the cap cannot be parsed, and the hook only runs for the checked tools, so
         * a Write of a huge body to a vendor or workflow path must not slip through. */
        free(in);
        fprintf(stderr,
                "zcl-agent-guard refused (%s): hook input over %u MiB. %s\n", R_COMPLEX,
                MAX_INPUT >> 20, ag_rule_text(R_COMPLEX));
        return 2;
    }
    if (!in) {
        fprintf(stderr, "zcl-agent-guard: warning: unreadable hook input; allowing\n");
        return 0;
    }
    ok = parse_hook(in, len, &call);
    if (ok) r = eval_call(&call);
    else fprintf(stderr, "zcl-agent-guard: warning: unexpected hook input; allowing\n");
    call_free(&call);
    free(in);
    if (!r) return 0;
    if (ag_rule_is_warning(r)) {
        fprintf(stderr, "zcl-agent-guard warning (%s): %s\n", r, ag_rule_text(r));
        print_ask(r);
        return 0;
    }
    fprintf(stderr,
            "zcl-agent-guard refused (%s): %s. If this is a false positive, "
            "report it in your result; do not work around it.\n",
            r, ag_rule_text(r));
    return 2;
}

/* ALLOW and WARN exit 0, REFUSE exits 1 (a finding). */
static int print_verdict(const char *r, bool json)
{
    const char *kind = !r ? "ALLOW" : ag_rule_is_warning(r) ? "WARN" : "REFUSE";
    if (json) {
        printf("{\"verdict\":\"%s\"", kind);
        if (r) {
            printf(",\"rule\":\"%s\",\"text\":", r);
            json_str(stdout, ag_rule_text(r), 400);
        }
        printf("}\n");
    } else if (r) {
        printf("%s %s %s\n", kind, r, ag_rule_text(r));
    } else {
        printf("ALLOW\n");
    }
    return r && !ag_rule_is_warning(r) ? 1 : 0;
}

static int usage(void)
{
    fprintf(stderr,
            "usage: zcl-agent-guard [--json] [--after=N] "
            "[--bash CMD | --ps CMD | --path TOOL FILE [CONTENT] | --replay FILE]\n"
            "       no arguments: PreToolUse hook on stdin (exit 2 refuses)\n");
    return 64;
}

int main(int argc, char **argv)
{
    struct out o = {false, 0, 0, 0, false};
    int n = 0;
    char *args[8];
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) o.json = true;
        else if (strncmp(argv[i], "--after=", 8) == 0) o.after = atol(argv[i] + 8);
        else if (n < 8) args[n++] = argv[i];
        else return usage();
    }
    if (n == 0) return cmd_hook();
    if (n == 2 && strcmp(args[0], "--ps") == 0) return print_verdict(ag_eval_ps(args[1]), o.json);
    if (n == 2 && strcmp(args[0], "--bash") == 0)
        return print_verdict(ag_eval_bash(args[1]), o.json);
    if ((n == 3 || n == 4) && strcmp(args[0], "--path") == 0)
        return print_verdict(ag_eval_path(args[1], args[2], n == 4 ? args[3] : NULL), o.json);
    if (n == 2 && strcmp(args[0], "--replay") == 0) return cmd_replay(args[1], &o);
    return usage();
}
