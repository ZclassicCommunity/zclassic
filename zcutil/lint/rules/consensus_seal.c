/* consensus-seal: the consensus tripwire, a seal by git blob id. It pins bytes, it does not review them.
 *
 * Copyright 2026 Rhett Creighton - MIT (zclassicd). Design from Z23 core/UNSEAL.md and tools/core_seal.c
 * @9a191ef7b (ideas only; no code copied): a sealed file is pinned by its git blob sha1, read from
 * `git ls-files -s`, so no hash code is needed. The sealed set is fixed in consensus_sealed() below.
 *
 * zcutil/consensus.seal holds one row per sealed file, "<path>TAB<40 lowercase hex blob>", sorted bytewise,
 * after '#' comment lines. A sealed tracked file whose index blob differs from its row, a sealed file with no
 * row, a sealed file edited or untracked on disk, or a row whose file is no longer sealed is a finding (exit 1) that points at doc/agent/UNSEAL.md.
 * Exit: 0 ok, 1 finding, 2 broken (missing or malformed seal, hollow scan, refused --reseal).
 *
 * --reseal --reason "<text>" (driver flags, lintlib.h) rewrites the seal from the index and appends one line
 * to doc/agent/SEAL_LOG.md. It is the owner's ritual; an agent never runs it on its own.
 */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* macOS hides mkdtemp, sysconf names and friends under a POSIX-only mask */
#endif
#include "../lintlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SEAL_REL "zcutil/consensus.seal"
#define SEAL_LOG_REL "doc/agent/SEAL_LOG.md"
#define BLOB_HEX 40
#define RITUAL "read doc/agent/UNSEAL.md: the ritual is a differential and golden pass, a non-author review, then zcl-lint consensus-seal --reseal --reason \"<why>\""

struct ent { char *path; char blob[BLOB_HEX + 1]; };
struct ents { struct ent *v; size_t n, cap; };
struct sbuf { char *s; size_t len, cap; };

static void ents_add(struct ents *e, const char *path, const char *blob)
{
    if (e->n == e->cap) {
        e->cap = e->cap ? e->cap * 2 : 256;
        e->v = lint_xrealloc(e->v, e->cap * sizeof *e->v);
    }
    e->v[e->n].path = lint_xstrdup(path);
    snprintf(e->v[e->n].blob, sizeof e->v[e->n].blob, "%s", blob);
    e->n++;
}

static void ents_free(struct ents *e)
{
    for (size_t i = 0; i < e->n; i++) free(e->v[i].path);
    free(e->v);
    e->v = NULL;
    e->n = e->cap = 0;
}

static int cmp_ent(const void *a, const void *b)
{
    return strcmp(((const struct ent *)a)->path, ((const struct ent *)b)->path);
}

static void sbuf_add(struct sbuf *b, const char *s)
{
    size_t sl = strlen(s), need = b->len + (b->len ? 1 : 0) + sl + 1;
    if (need > b->cap) {
        b->cap = need * 2;
        b->s = lint_xrealloc(b->s, b->cap);
    }
    if (b->len) b->s[b->len++] = ' ';
    memcpy(b->s + b->len, s, sl + 1);
    b->len += sl;
}

/* The sealed set. Changing this list is itself a consensus-surface change: it goes through the ritual. */
static bool consensus_sealed(const char *p)
{
    static const char *const zcash_names[] = {"JoinSplit", "Note", "NoteEncryption", "Proof", "Address",
                                              "IncrementalMerkleTree"};
    static const char *const exact[] = {
        "src/chainparams.cpp", "src/pow.cpp", "src/pow.h",
        "src/script/interpreter.cpp", "src/script/interpreter.h", "src/script/script.cpp", "src/script/script.h",
    };
    if (lint_has_prefix(p, "src/consensus/") || lint_has_prefix(p, "src/primitives/")) return true;
    if (lint_has_prefix(p, "src/pow/tromp/")) return false; /* excluded: the vendored equihash miner */
    if (lint_has_prefix(p, "src/pow/")) return true;
    for (size_t i = 0; i < sizeof exact / sizeof exact[0]; i++)
        if (!strcmp(p, exact[i])) return true;
    if (lint_has_prefix(p, "src/zcash/") && !strchr(p + strlen("src/zcash/"), '/')) {
        const char *base = p + strlen("src/zcash/");
        for (size_t i = 0; i < sizeof zcash_names / sizeof zcash_names[0]; i++) {
            size_t n = strlen(zcash_names[i]);
            if (!strncmp(base, zcash_names[i], n) && base[n] == '.') return true; /* Note.* but not NoteEncryption.* */
        }
    }
    return false;
}

static bool is_lower_hex(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}

static void die_git(void)
{
    fprintf(stderr, "zcl-lint: unexpected git output in %s\n", lint_root);
    exit(2);
}

/* Runs `git -C root <args>` without a shell and returns its whole stdout (NUL-terminated, length in *len); exits 2
 * on failure. */
static char *git_out(char *const args[], size_t *len)
{
    char *buf = lint_git_out(args, len);
    if (!buf) { fprintf(stderr, "zcl-lint: git %s failed in %s\n", args[0], lint_root); exit(2); }
    return buf;
}

/* Sealed tracked files with their index blob ids, from `git ls-files -s -z`. Stage 0 keeps its blob; an
 * unmerged path (stages 1 to 3) is recorded once as "unmerged", which can never equal a seal row. */
static void load_index_sealed(struct ents *out)
{
    size_t n, i = 0;
    char *buf = git_out((char *[]){"ls-files", "-s", "-z", NULL}, &n);
    while (i < n) {
        char *ent = buf + i; /* "<mode> <sha> <stage>\t<path>", NUL-terminated by -z */
        i += strlen(ent) + 1;
        char *tab = strchr(ent, '\t');
        if (!tab) die_git();
        *tab = '\0';
        char *sha = strchr(ent, ' ');
        if (!sha) die_git();
        *sha++ = '\0';
        char *stage = strchr(sha, ' ');
        if (!stage) die_git();
        *stage++ = '\0';
        if (!consensus_sealed(tab + 1)) continue;
        if (stage[0] != '0' && out->n && !strcmp(out->v[out->n - 1].path, tab + 1)) continue; /* ls-files sorts by path */
        ents_add(out, tab + 1, stage[0] == '0' ? sha : "unmerged");
    }
    free(buf);
    qsort(out->v, out->n, sizeof *out->v, cmp_ent);
}

/* Sealed paths that differ on disk from the index (edited, deleted) or are untracked, sorted and unique. */
static void load_worktree_dirty(struct ents *out)
{
    static char *const diff_args[] = {"diff", "--name-only", "-z", NULL};
    static char *const other_args[] = {"ls-files", "--others", "--exclude-standard", "-z", NULL};
    char *const *const cmds[] = {diff_args, other_args};
    for (size_t c = 0; c < 2; c++) {
        size_t n, i = 0;
        char *buf = git_out(cmds[c], &n);
        while (i < n) {
            char *path = buf + i;
            i += strlen(path) + 1;
            if (consensus_sealed(path)) ents_add(out, path, "");
        }
        free(buf);
    }
    qsort(out->v, out->n, sizeof *out->v, cmp_ent);
    size_t w = 0;
    for (size_t r = 0; r < out->n; r++) {
        if (w && !strcmp(out->v[w - 1].path, out->v[r].path)) { free(out->v[r].path); continue; }
        out->v[w++] = out->v[r];
    }
    out->n = w;
}

/* Parses zcutil/consensus.seal. *exists is false when the file is absent (allowed only for the first reseal).
 * Returns false on a malformed file; the message is printed here. */
static bool load_seal(struct ents *out, bool *exists)
{
    char *p = lint_rootpath(SEAL_REL);
    FILE *f = fopen(p, "rb");
    free(p);
    *exists = f != NULL;
    if (!f) return true;
    char line[4096];
    size_t lineno = 0;
    bool ok = true;
    while (ok && fgets(line, sizeof line, f)) {
        lineno++;
        size_t len = strlen(line);
        if (len == sizeof line - 1 && line[len - 1] != '\n') { ok = false; break; }
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        if (!len || line[0] == '#') continue;
        char *tab = strrchr(line, '\t');
        if (!tab || tab == line || strlen(tab + 1) != BLOB_HEX || !is_lower_hex(tab + 1, BLOB_HEX)) { ok = false; break; }
        *tab = '\0';
        ents_add(out, line, tab + 1);
    }
    if (ok && ferror(f)) ok = false;
    fclose(f);
    if (!ok) {
        printf("FAIL consensus-seal: %s line %zu is malformed (want <path>TAB<40 hex>)\n", SEAL_REL, lineno);
        return false;
    }
    qsort(out->v, out->n, sizeof *out->v, cmp_ent);
    for (size_t i = 1; i < out->n; i++)
        if (!strcmp(out->v[i - 1].path, out->v[i].path)) {
            printf("FAIL consensus-seal: %s lists %s twice\n", SEAL_REL, out->v[i].path);
            return false;
        }
    return true;
}

/* The short HEAD commit for the log line; "unborn" when there is none yet. */
static void git_head(char *out, size_t cap)
{
    char *argv[] = { "git", "-C", (char *)lint_root, "rev-parse", "--short=12", "HEAD", NULL };
    struct lint_proc p;
    int opened = lint_proc_open(&p, NULL, argv, 0) == 0;
    out[0] = '\0';
    if (opened) {
        if (!fgets(out, (int)cap, p.fp)) out[0] = '\0';
        if (lint_proc_close(&p) != 0) out[0] = '\0';
    }
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
    if (!n) snprintf(out, cap, "unborn");
}

static int write_seal(const struct ents *now)
{
    char *p = lint_rootpath(SEAL_REL);
    FILE *f = fopen(p, "wb");
    if (!f) { printf("FAIL consensus-seal: cannot write %s\n", SEAL_REL); free(p); return 2; }
    fputs("# zcutil/consensus.seal: consensus tripwire. One row per sealed file: <path>TAB<git blob sha1>.\n", f);
    fputs("# Written by zcl-lint consensus-seal --reseal --reason. Do not hand-edit. Ritual: doc/agent/UNSEAL.md\n", f);
    for (size_t i = 0; i < now->n; i++) fprintf(f, "%s\t%s\n", now->v[i].path, now->v[i].blob);
    int rc = fclose(f) == 0 ? 0 : 2;
    if (rc) printf("FAIL consensus-seal: cannot write %s\n", SEAL_REL);
    free(p);
    return rc;
}

/* The git blob id of the seal file as it is on disk. */
static void seal_blob(char out[BLOB_HEX + 1])
{
    size_t n;
    char *b = git_out((char *[]){"hash-object", "--", SEAL_REL, NULL}, &n);
    if (n < BLOB_HEX || !is_lower_hex(b, BLOB_HEX)) die_git();
    memcpy(out, b, BLOB_HEX);
    out[BLOB_HEX] = '\0';
    free(b);
}

/* The seal blob recorded on the last SEAL_LOG line ("- <time> <head> seal=<blob> ..."). False when the log
 * is absent or its last line carries none. */
static bool log_last_seal(char out[BLOB_HEX + 1])
{
    char *p = lint_rootpath(SEAL_LOG_REL);
    FILE *f = fopen(p, "rb");
    free(p);
    if (!f) return false;
    char line[8192], last[8192] = "";
    bool cut = false;
    while (fgets(line, sizeof line, f)) {
        size_t len = strlen(line);
        bool partial = len == sizeof line - 1 && line[len - 1] != '\n';
        if (!cut && !strncmp(line, "- ", 2)) snprintf(last, sizeof last, "%s", line);
        cut = partial; /* the rest of an overlong line is not a new entry */
    }
    fclose(f);
    const char *s = strstr(last, " seal=");
    if (!s || strlen(s + 6) < BLOB_HEX || !is_lower_hex(s + 6, BLOB_HEX)) return false;
    memcpy(out, s + 6, BLOB_HEX);
    out[BLOB_HEX] = '\0';
    return true;
}

static int append_log(const char *reason, const char *changes, size_t files)
{
    char blob[BLOB_HEX + 1];
    seal_blob(blob);
    char *p = lint_rootpath(SEAL_LOG_REL);
    FILE *f = fopen(p, "ab");
    if (!f) { printf("FAIL consensus-seal: cannot append %s\n", SEAL_LOG_REL); free(p); return 2; }
    char date[32], head[64];
    time_t t = time(NULL);
    strftime(date, sizeof date, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    git_head(head, sizeof head);
    fprintf(f, "- %s %s seal=%s %zu sealed files; changed: %s; reason: %s\n", date, head, blob, files,
            changes[0] ? changes : "(none)", reason);
    int rc = fclose(f) == 0 ? 0 : 2;
    if (rc) printf("FAIL consensus-seal: cannot append %s\n", SEAL_LOG_REL);
    free(p);
    return rc;
}

int lint_rule_consensus_seal(bool update)
{
    (void)update; /* no baseline; the driver refuses --update-baseline for this rule */
    if (lint_reseal && (!lint_reason || !*lint_reason)) {
        printf("FAIL consensus-seal: --reseal needs --reason \"<why this consensus change is needed>\"; nothing written\n");
        return 2;
    }
    if (lint_reseal && strpbrk(lint_reason, "\r\n")) {
        printf("FAIL consensus-seal: --reason must be one line; nothing written\n");
        return 2;
    }
    struct ents now = {0}, seal = {0}, dirty = {0};
    bool exists = false;
    load_index_sealed(&now);
    if (!now.n) {
        printf("FAIL consensus-seal: no consensus-sealed file is tracked, nothing scanned\n");
        ents_free(&now);
        return 2;
    }
    if (!load_seal(&seal, &exists) || (!exists && !lint_reseal)) {
        if (!exists && !lint_reseal) printf("FAIL consensus-seal: %s is missing; it has never been sealed\n", SEAL_REL);
        ents_free(&now);
        ents_free(&seal);
        return 2;
    }
    load_worktree_dirty(&dirty);

    if (lint_reseal) { /* the seal must pin a state that is merged, staged and equal to the files on disk */
        for (size_t i = 0; i < now.n; i++)
            if (!strcmp(now.v[i].blob, "unmerged")) {
                printf("FAIL consensus-seal: %s is unmerged; resolve the conflict first; nothing written\n", now.v[i].path);
                ents_free(&now); ents_free(&seal); ents_free(&dirty);
                return 2;
            }
        if (dirty.n) {
            printf("FAIL consensus-seal: %s is modified in the working tree (not staged), or untracked; "
                   "git add it first; nothing written\n", dirty.v[0].path);
            ents_free(&now); ents_free(&seal); ents_free(&dirty);
            return 2;
        }
    }

    /* Walk both sorted lists together: each path is unchanged, changed, newly sealed, or no longer sealed. */
    struct sbuf changes = {0};
    sbuf_add(&changes, ""); /* allocates; leaves the list empty */
    size_t a = 0, b = 0, drift = 0;
    while (a < now.n || b < seal.n) {
        int c = a == now.n ? 1 : b == seal.n ? -1 : strcmp(now.v[a].path, seal.v[b].path);
        const char *path = NULL, *what = NULL;
        if (c < 0) {
            path = now.v[a].path;
            what = !strcmp(now.v[a].blob, "unmerged") ? "is unmerged (resolve the conflict first)"
                 : "is consensus-sealed but has no row in the seal (a new sealed file needs the ritual)";
            a++;
        } else if (c > 0) {
            path = seal.v[b].path;
            what = "has a seal row but is no longer in the sealed set (removed or moved)";
            b++;
        } else {
            path = now.v[a].path;
            if (!strcmp(now.v[a].blob, "unmerged"))
                what = "is unmerged (resolve the conflict first)";
            else if (strcmp(now.v[a].blob, seal.v[b].blob))
                what = "changed (its git blob differs from the seal)";
            a++;
            b++;
        }
        if (!what) continue;
        drift++;
        if (!lint_reseal) printf("FAIL consensus-seal: %s %s\n", path, what);
        sbuf_add(&changes, path);
    }
    if (!lint_reseal)
        for (size_t i = 0; i < dirty.n; i++)
            printf("FAIL consensus-seal: %s is modified in the working tree (not staged), or untracked; "
                   "git add it, then follow the ritual in doc/agent/UNSEAL.md\n", dirty.v[i].path);

    /* The seal must be the one the last SEAL_LOG line wrote: a hand-edited seal has no matching log line. */
    char want[BLOB_HEX + 1], have[BLOB_HEX + 1];
    bool bound = exists && log_last_seal(want) && (seal_blob(have), !strcmp(want, have));

    int rc = 0;
    if (lint_reseal) {
        if (!drift && exists && bound) {
            printf("consensus-seal: seal already matches the index (%zu files); nothing resealed\n", now.n);
        } else if (write_seal(&now) || append_log(lint_reason, changes.s, now.n)) {
            rc = 2;
        } else {
            printf("consensus-seal: resealed %zu files (%zu changed); logged in %s\n", now.n, drift, SEAL_LOG_REL);
        }
    } else if (drift || dirty.n || !bound) {
        if (!bound)
            printf("FAIL consensus-seal: %s does not match the last %s line (hand-edited seal, or no seal= entry)\n",
                   SEAL_REL, SEAL_LOG_REL);
        printf("consensus-seal: %zu sealed change(s); %s\n", drift + dirty.n + (bound ? 0 : 1), RITUAL);
        rc = 1;
    } else {
        printf("consensus-seal: ok (%zu files sealed)\n", now.n);
    }
    free(changes.s);
    ents_free(&now);
    ents_free(&seal);
    ents_free(&dirty);
    return rc;
}
