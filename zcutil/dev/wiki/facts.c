/* zcl-dev lessons and zcl-dev know: search the agent lessons, and answer from the closed FACTS table.
 * MIT, like the rest of zclassicd.
 *
 *   zcl-dev lessons find <query...> [--json]       case-insensitive, up to 8 hits, cites file:line
 *   zcl-dev lessons add OPEN <tracked-path> "<text>" [--json]
 *   zcl-dev know <term> [--json]                   rows where term is subject or object, else UNKNOWN
 *   zcl-dev know --check [--facts=FILE] [--json]   the validator of the FACTS table
 *
 * FACTS.tsv is one fact per line: subject, relation, object, context, confidence, why, separated by
 * tabs. The "#!relations", "#!contexts" and "#!terms" header lines declare the closed vocabularies;
 * a term containing '/' is a tracked repository path. There is no free text on either side of a
 * relation, so pasted prose cannot become a fact. Designed after Z23's `dev know` and its gate
 * (engine/composition/fleet_facts.def, tools/lint/lintc/gate_fleet_facts.c); no Z23 code is copied. */
#include "wikilib.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define LESSONS_FILE "doc/agent/LESSONS.md"
#define TRAPS_FILE "doc/agent/TRAPS.md"
#define FACTS_FILE "doc/agent/FACTS.tsv"
#define MAX_HITS 8
#define PER_FILE_FIRST 3 /* each file gets this many hits before any file takes more */
#define HIT_CLIP 300

/* ---- lessons ------------------------------------------------------------------------------ */

typedef struct { int file; size_t line; char *text; int taken; } Hit;

static int all_words(const char *line, const List *words)
{
    for (size_t i = 0; i < words->n; i++)
        if (!contains_ci(line, words->v[i])) return 0;
    return 1;
}

static int lessons_find(int argc, char **argv)
{
    static const char *const files[3] = {LESSONS_FILE, TRAPS_FILE, FACTS_FILE};
    List words = {0};
    Hit *hits = NULL;
    size_t nh = 0, caph = 0, per[3] = {0, 0, 0}, taken = 0;
    int readable = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) g_json = 1;
        else if (argv[i][0] == '-' && argv[i][1] == '-') return fail_reply("USAGE", "unknown option", argv[i]);
        else {
            char *w = xstrdup(argv[i]);
            for (char *t = strtok(w, " \t"); t; t = strtok(NULL, " \t")) list_push(&words, t);
            free(w);
        }
    }
    if (!words.n) return fail_reply("USAGE", "usage: zcl-dev lessons find <query...> [--json]", "");
    for (int f = 0; f < 3; f++) {
        List lines = {0};
        if (file_lines(files[f], &lines)) continue;
        readable++;
        for (size_t i = 0; i < lines.n; i++) {
            if (!lines.v[i][0] || (f == 2 && lines.v[i][0] == '#')) continue;
            if (!all_words(lines.v[i], &words)) continue;
            if (nh == caph) { caph = caph ? caph * 2 : 16; hits = xrealloc(hits, caph * sizeof *hits); }
            hits[nh].file = f;
            hits[nh].line = i + 1;
            hits[nh].text = xstrdup(lines.v[i]);
            hits[nh].taken = 0;
            nh++;
        }
        list_free(&lines);
    }
    if (!readable) return fail_reply("HOLLOW_SCAN", "none of LESSONS.md, TRAPS.md or FACTS.tsv could be read", "doc/agent");
    /* Pass 1: a few hits per file so one file cannot crowd out the others; pass 2 fills the rest. */
    for (size_t i = 0; i < nh && taken < MAX_HITS; i++)
        if (per[hits[i].file] < PER_FILE_FIRST) { hits[i].taken = 1; per[hits[i].file]++; taken++; }
    for (size_t i = 0; i < nh && taken < MAX_HITS; i++)
        if (!hits[i].taken) { hits[i].taken = 1; taken++; }

    Buf out = {0};
    if (g_json) {
        buf_add(&out, "{\"ok\":true,\"matches\":");
        buf_printf(&out, "%zu,\"results\":[", nh);
    } else {
        buf_printf(&out, "%zu match%s, showing %zu\n", nh, nh == 1 ? "" : "es", taken);
    }
    size_t shown = 0;
    for (size_t i = 0; i < nh; i++) {
        if (!hits[i].taken) continue;
        char text[8192];
        snprintf(text, sizeof text, "%s", hits[i].text);
        clip_text(text, HIT_CLIP);
        if (g_json) {
            if (shown) buf_add(&out, ",");
            buf_add(&out, "{\"file\":");
            buf_json(&out, files[hits[i].file]);
            buf_printf(&out, ",\"line\":%zu,\"text\":", hits[i].line);
            buf_json(&out, text);
            buf_add(&out, "}");
        } else {
            buf_printf(&out, "%s:%zu: %s\n", files[hits[i].file], hits[i].line, text);
        }
        shown++;
    }
    if (g_json) buf_add(&out, "]}\n");
    else if (nh > taken) buf_add(&out, "narrow the query to see the rest\n");
    fwrite(out.p, 1, out.n, stdout);
    buf_free(&out);
    for (size_t i = 0; i < nh; i++) free(hits[i].text);
    free(hits);
    list_free(&words);
    return 0;
}

static int safe_path_chars(const char *p)
{
    if (!*p || strlen(p) > 400 || *p == '/' || *p == '-') return 0;
    for (; *p; p++)
        if (!isalnum((unsigned char)*p) && !strchr("._/+@-", *p)) return 0;
    return 1;
}

/* Append "OPEN <path> — <text>" after the checks that doc check-docs enforces on a lesson line. */
static int lessons_add(int argc, char **argv)
{
    const char *pos[3];
    int np = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) g_json = 1;
        else if (np < 3) pos[np++] = argv[i];
        else return fail_reply("USAGE", "usage: zcl-dev lessons add OPEN <tracked-path> \"<text>\"", argv[i]);
    }
    if (np != 3) return fail_reply("USAGE", "usage: zcl-dev lessons add OPEN <tracked-path> \"<text>\"", "");
    if (strcmp(pos[0], "OPEN"))
        return fail_reply("BAD_STATE", "a new lesson starts OPEN; DONE needs a test or gate that holds it", pos[0]);
    if (!safe_path_chars(pos[1])) return fail_reply("BAD_PATH", "the path has characters a tracked path does not need", pos[1]);
    char text[1024];
    snprintf(text, sizeof text, "%s", pos[2]);
    char *t = trim(text);
    size_t n = strlen(t);
    if (n < 20) return fail_reply("BAD_TEXT", "state the measured failure and the invariant (at least 20 bytes)", "");
    if (strlen(pos[2]) >= sizeof text) return fail_reply("BAD_TEXT", "the lesson is a single line of at most 1000 bytes", "");
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)t[i] < 0x20 || t[i] == 0x7f)
            return fail_reply("BAD_TEXT", "the lesson is one line without control characters", "");
    List tracked = {0}, lines = {0};
    git_files(&tracked);
    if (!list_has(&tracked, pos[1])) {
        list_free(&tracked);
        return fail_reply("UNTRACKED_PATH", "the lesson must name a tracked path", pos[1]);
    }
    list_free(&tracked);
    if (file_lines(LESSONS_FILE, &lines)) return fail_reply("NO_LESSONS", "cannot read the lessons file", LESSONS_FILE);
    char line[1600];
    snprintf(line, sizeof line, "OPEN %s \xe2\x80\x94 %s", pos[1], t);
    for (size_t i = 0; i < lines.n; i++)
        if (!strcmp(lines.v[i], line)) {
            list_free(&lines);
            return fail_reply("DUPLICATE", "this lesson is already recorded", LESSONS_FILE);
        }
    size_t at = lines.n + 1;
    list_free(&lines);
    FILE *f = fopen(LESSONS_FILE, "rb+");
    if (!f) return fail_reply("NO_LESSONS", "cannot open the lessons file for writing", LESSONS_FILE);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    int need_nl = 0;
    if (sz > 0) {
        int last;
        fseek(f, sz - 1, SEEK_SET);
        last = fgetc(f);
        need_nl = last != '\n';
    }
    fseek(f, 0, SEEK_END);
    if (need_nl) { fputc('\n', f); at++; }
    if (fprintf(f, "%s\n", line) < 0 || fclose(f)) return fail_reply("WRITE_FAILED", "cannot append to the lessons file", LESSONS_FILE);
    Buf out = {0};
    if (g_json) {
        buf_add(&out, "{\"ok\":true,\"file\":");
        buf_json(&out, LESSONS_FILE);
        buf_printf(&out, ",\"line\":%zu,\"text\":", at);
        buf_json(&out, line);
        buf_add(&out, "}\n");
    } else {
        buf_printf(&out, "added %s:%zu: %s\n", LESSONS_FILE, at, line);
    }
    fwrite(out.p, 1, out.n, stdout);
    buf_free(&out);
    return 0;
}

int cmd_lessons(int argc, char **argv)
{
    if (argc >= 1 && !strcmp(argv[0], "find")) return lessons_find(argc - 1, argv + 1);
    if (argc >= 1 && !strcmp(argv[0], "add")) return lessons_add(argc - 1, argv + 1);
    return fail_reply("USAGE", "usage: zcl-dev lessons find <query...> | add OPEN <tracked-path> \"<text>\"", "");
}

/* ---- facts -------------------------------------------------------------------------------- */

enum { NF = 6 };
typedef struct { char *f[NF]; size_t line; } Row;
typedef struct {
    List relations, contexts, terms, term_line; /* term_line: declaration line of each term */
    Row *rows;
    size_t n, cap;
} Facts;

static void problem(List *probs, const char *file, size_t line, const char *fmt, const char *a, const char *b)
{
    char msg[1024], full[1400];
    snprintf(msg, sizeof msg, fmt, a ? a : "", b ? b : "");
    snprintf(full, sizeof full, "%s:%zu: %s", file, line, msg);
    list_push(probs, full);
}

static void declare(List *set, List *at, const char *rest, const char *what, const char *file, size_t line, List *probs)
{
    char *c = xstrdup(rest);
    for (char *t = strtok(c, " \t"); t; t = strtok(NULL, " \t")) {
        if (list_has(set, t)) problem(probs, file, line, "%s declared twice: %s", what, t);
        else {
            char num[32];
            list_push(set, t);
            snprintf(num, sizeof num, "%zu", line);
            if (at) list_push(at, num);
        }
    }
    free(c);
}

/* Parse the table. Structural problems (wrong field count, repeated declarations) go to probs. */
static int facts_load(const char *file, Facts *F, List *probs)
{
    List lines = {0};
    if (file_lines(file, &lines)) return 1;
    for (size_t i = 0; i < lines.n; i++) {
        char *l = lines.v[i];
        size_t ln = i + 1;
        if (!*l) continue;
        if (has_prefix(l, "#!relations")) { declare(&F->relations, NULL, l + 11, "relation", file, ln, probs); continue; }
        if (has_prefix(l, "#!contexts")) { declare(&F->contexts, NULL, l + 10, "context", file, ln, probs); continue; }
        if (has_prefix(l, "#!terms")) { declare(&F->terms, &F->term_line, l + 7, "term", file, ln, probs); continue; }
        if (*l == '#') continue;
        Row r = {{0}, ln};
        char *p = l;
        int k = 0;
        for (; k < NF; k++) {
            char *tab = strchr(p, '\t');
            if (k < NF - 1 && !tab) break;
            if (k == NF - 1 && tab) { k = NF + 1; break; }
            if (tab) *tab = 0;
            r.f[k] = xstrdup(p);
            p = tab ? tab + 1 : p;
        }
        if (k != NF) {
            problem(probs, file, ln, "expected %s tab-separated fields (subject relation object context confidence why)", "6", NULL);
            for (int j = 0; j < NF; j++) free(r.f[j]);
            continue;
        }
        if (F->n == F->cap) { F->cap = F->cap ? F->cap * 2 : 32; F->rows = xrealloc(F->rows, F->cap * sizeof *F->rows); }
        F->rows[F->n++] = r;
    }
    list_free(&lines);
    return 0;
}

static void facts_free(Facts *F)
{
    for (size_t i = 0; i < F->n; i++)
        for (int j = 0; j < NF; j++) free(F->rows[i].f[j]);
    free(F->rows);
    list_free(&F->relations);
    list_free(&F->contexts);
    list_free(&F->terms);
    list_free(&F->term_line);
}

static int token_ok(const char *t)
{
    if (!*t || !isalnum((unsigned char)*t)) return 0;
    for (; *t; t++)
        if (!isalnum((unsigned char)*t) && !strchr("._-", *t)) return 0;
    return 1;
}

/* The validator: closed vocabulary, tracked paths, no duplicate rows, no unused terms. */
static int facts_check(const char *file, int json)
{
    Facts F = {{0}, {0}, {0}, {0}, NULL, 0, 0};
    List probs = {0}, tracked = {0};
    if (facts_load(file, &F, &probs)) return fail_reply("NO_FACTS", "cannot read the facts table", file);
    git_files(&tracked);
    if (!F.n) { facts_free(&F); list_free(&tracked); return fail_reply("HOLLOW_SCAN", "the facts table has no rows", file); }
    if (!F.relations.n) problem(&probs, file, 1, "no %s%s declared", "#!relations", NULL);
    if (!F.contexts.n) problem(&probs, file, 1, "no %s%s declared", "#!contexts", NULL);
    if (!F.terms.n) problem(&probs, file, 1, "no %s%s declared", "#!terms", NULL);
    for (size_t i = 0; i < F.terms.n; i++) {
        const char *t = F.terms.v[i];
        if (strchr(t, '/')) {
            if (!list_has(&tracked, t)) problem(&probs, file, (size_t)atoi(F.term_line.v[i]), "term %s is not a tracked path%s", t, "");
        } else if (!token_ok(t)) {
            problem(&probs, file, (size_t)atoi(F.term_line.v[i]), "term %s is not a plain token (letters, digits, . _ -)%s", t, "");
        }
    }
    size_t *used = calloc(F.terms.n ? F.terms.n : 1, sizeof *used);
    if (!used) die("out of memory");
    List keys = {0};
    for (size_t i = 0; i < F.n; i++) {
        Row *r = &F.rows[i];
        for (int k = 0; k < NF; k++)
            if (!*trim(r->f[k])) problem(&probs, file, r->line, "field %s is empty%s", (const char *[]){"1", "2", "3", "4", "5", "6"}[k], "");
        if (!list_has(&F.relations, r->f[1])) problem(&probs, file, r->line, "relation %s is not declared%s", r->f[1], "");
        if (!list_has(&F.contexts, r->f[3])) problem(&probs, file, r->line, "context %s is not declared%s", r->f[3], "");
        if (strcmp(r->f[4], "DOCTRINE") && strcmp(r->f[4], "OBSERVED"))
            problem(&probs, file, r->line, "confidence %s must be DOCTRINE or OBSERVED (UNKNOWN is synthesized, never written)%s", r->f[4], "");
        for (int k = 0; k < 3; k += 2) {
            size_t at = 0;
            while (at < F.terms.n && strcmp(F.terms.v[at], r->f[k])) at++;
            if (at == F.terms.n) problem(&probs, file, r->line, "term %s is not declared%s", r->f[k], "");
            else used[at]++;
        }
        char key[2048];
        snprintf(key, sizeof key, "%s\t%s\t%s\t%s", r->f[0], r->f[1], r->f[2], r->f[3]);
        if (list_has(&keys, key)) problem(&probs, file, r->line, "duplicate row: %s", r->f[0], NULL);
        else list_push(&keys, key);
    }
    for (size_t i = 0; i < F.terms.n; i++)
        if (!used[i]) problem(&probs, file, (size_t)atoi(F.term_line.v[i]), "term %s is declared but no row uses it%s", F.terms.v[i], "");
    Buf out = {0};
    if (json) {
        buf_printf(&out, "{\"ok\":%s,\"rows\":%zu,\"terms\":%zu,\"problems\":[", probs.n ? "false" : "true", F.n, F.terms.n);
        for (size_t i = 0; i < probs.n; i++) { if (i) buf_add(&out, ","); buf_json(&out, probs.v[i]); }
        buf_add(&out, "]}\n");
        fwrite(out.p, 1, out.n, stdout);
    } else {
        for (size_t i = 0; i < probs.n; i++) fprintf(stderr, "FAIL: %s\n", probs.v[i]);
        if (probs.n) fprintf(stderr, "know --check: FAILED (%zu problems)\n", probs.n);
        else printf("know --check: OK (%zu rows, %zu terms, %zu relations, %zu contexts)\n", F.n, F.terms.n,
                    F.relations.n, F.contexts.n);
    }
    int bad = probs.n != 0;
    buf_free(&out);
    free(used);
    list_free(&keys);
    list_free(&probs);
    list_free(&tracked);
    facts_free(&F);
    return bad ? 1 : 0;
}

static int know_term(const char *file, const char *term)
{
    Facts F = {{0}, {0}, {0}, {0}, NULL, 0, 0};
    List probs = {0};
    if (facts_load(file, &F, &probs)) return fail_reply("NO_FACTS", "cannot read the facts table", file);
    Buf out = {0};
    size_t hits = 0;
    if (g_json) buf_printf(&out, "{\"ok\":true,\"term\":");
    if (g_json) { buf_json(&out, term); buf_add(&out, ",\"rows\":["); }
    for (size_t i = 0; i < F.n; i++) {
        Row *r = &F.rows[i];
        if (strcmp(r->f[0], term) && strcmp(r->f[2], term)) continue;
        if (g_json) {
            if (hits) buf_add(&out, ",");
            buf_add(&out, "{\"subject\":"); buf_json(&out, r->f[0]);
            buf_add(&out, ",\"relation\":"); buf_json(&out, r->f[1]);
            buf_add(&out, ",\"object\":"); buf_json(&out, r->f[2]);
            buf_add(&out, ",\"context\":"); buf_json(&out, r->f[3]);
            buf_add(&out, ",\"confidence\":"); buf_json(&out, r->f[4]);
            buf_add(&out, ",\"why\":"); buf_json(&out, r->f[5]);
            buf_add(&out, "}");
        } else {
            char why[TEXT_MAX * 2];
            snprintf(why, sizeof why, "%s", r->f[5]);
            clip_text(why, 360);
            buf_printf(&out, "%s %s %s  [%s, %s]  %s\n", r->f[0], r->f[1], r->f[2], r->f[3], r->f[4], why);
        }
        hits++;
        if (out.n > REPLY_MAX - 2048) break;
    }
    if (g_json) buf_printf(&out, "],\"confidence\":\"%s\"}\n", hits ? "KNOWN" : "UNKNOWN");
    else if (!hits) buf_printf(&out, "UNKNOWN: no row in %s names \"%s\" as subject or object\n", file, term);
    fwrite(out.p, 1, out.n, stdout);
    buf_free(&out);
    list_free(&probs);
    facts_free(&F);
    return 0;
}

int cmd_know(int argc, char **argv)
{
    const char *term = NULL, *file = FACTS_FILE;
    int check = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) g_json = 1;
        else if (!strcmp(argv[i], "--check")) check = 1;
        else if (has_prefix(argv[i], "--facts=")) file = argv[i] + 8;
        else if (argv[i][0] == '-' || term) return fail_reply("USAGE", "usage: zcl-dev know <term> | --check [--facts=FILE] [--json]", argv[i]);
        else term = argv[i];
    }
    if (check) {
        if (term) return fail_reply("USAGE", "--check takes no term", term);
        return facts_check(file, g_json);
    }
    if (!term) return fail_reply("USAGE", "usage: zcl-dev know <term> | --check [--facts=FILE] [--json]", "");
    return know_term(file, term);
}
