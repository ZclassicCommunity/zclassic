/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Derived from Z23 tools/agent_guard_rules.c@9a191ef7b, Apache-2.0, changed (zclassicd's rules; see
 * zcutil/tools/NOTICE). zcl-agent-guard: the `git push` rule and the little git state it needs.
 *
 * Refused: a push to master or a release ref (also by a force or a delete), --all and --mirror. A
 * delete of any other branch (`:feature`, --delete) is ordinary. A force of a named branch other than
 * master or release (--force, -f, +ref) is allowed with a note on stderr: it is the agent's own
 * feature branch. A push that names no branch (a bare push, `origin`, HEAD) pushes the current
 * branch: it is refused only when that branch is master. The current branch is the one a
 * `git checkout -b X`, `git switch -c X`, `git checkout X` or `git switch X` earlier in the same
 * command put us on, else the one HEAD names in the repository at the working directory (found by
 * walking up to the root; `git -C dir` and `cd dir` move it). Where the branch cannot be read the
 * push is allowed, because most pushes are of a feature branch. --dry-run and --help only look. */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rules.h"
#include "rules_int.h"

#define PATH_CAP 1100

/* The git state along one command: the working directory as the user wrote it (case kept, for
 * reading .git/HEAD) and the branch a checkout or switch put us on. */
static char s_cwd[PATH_CAP];
static char s_branch[96];

static bool has_glob(const char *s)
{
    return strpbrk(s, "*?[") != NULL;
}

void ag_git_state_reset(const char *hook_cwd)
{
    snprintf(s_cwd, sizeof s_cwd, "%s", hook_cwd ? hook_cwd : "");
    s_branch[0] = '\0';
}

/* out = a "/" b "/" c, the middle part skipped when b is NULL; false when it does not fit. */
static bool join_path(char *out, size_t cap, const char *a, const char *b, const char *c)
{
    size_t la = strlen(a), lb = b ? strlen(b) : 0, lc = strlen(c);
    if (la + lb + lc + 3 > cap) return false;
    memcpy(out, a, la);
    out[la++] = '/';
    if (b) {
        memcpy(out + la, b, lb);
        la += lb;
        out[la++] = '/';
    }
    memcpy(out + la, c, lc + 1);
    return true;
}

static bool is_absolute(const char *w)
{
    return w[0] == '/' || w[0] == '\\' || (isalpha((unsigned char)w[0]) && w[1] == ':');
}

/* A directory word against base: absolute as it is, ~ as the home, relative below base. False for a
 * variable or substitution (the directory is not known) and for a relative word with no base. */
static bool resolve_dir(const char *base, const char *w, char *out, size_t cap)
{
    const char *home;
    if (!w[0] || strchr("$`%", w[0])) return false;
    if (w[0] == '~' && (w[1] == '\0' || w[1] == '/' || w[1] == '\\')) {
        home = getenv("HOME");
        if (!home) home = getenv("USERPROFILE");
        if (!home || strlen(home) + strlen(w) + 1 > cap) return false;
        snprintf(out, cap, "%s%s", home, w + 1);
        return true;
    }
    if (is_absolute(w)) {
        if (strlen(w) + 1 > cap) return false;
        memcpy(out, w, strlen(w) + 1);
        return true;
    }
    return base[0] && join_path(out, cap, base, NULL, w);
}

void ag_git_note_cd(char **a, int na)
{
    char tmp[PATH_CAP];
    int i = 0;
    while (i < na && a[i][0] == '-' && a[i][1]) i++;
    if (i >= na) { /* a bare cd goes home */
        s_cwd[0] = '\0';
        if (resolve_dir("", "~", tmp, sizeof tmp)) memcpy(s_cwd, tmp, strlen(tmp) + 1);
        return;
    }
    if (strcmp(a[i], "-") == 0 || !resolve_dir(s_cwd, a[i], tmp, sizeof tmp)) {
        s_cwd[0] = '\0';
        return;
    }
    memcpy(s_cwd, tmp, strlen(tmp) + 1);
}

/* The branch name an option or word of checkout/switch gives: after -b/-B (checkout) or
 * -c/-C/--create (switch), else the first plain word; NULL for none. A `--` ends it. */
static const char *branch_word(const char *sub, char **a, int na)
{
    bool is_switch = strcmp(sub, "switch") == 0;
    for (int i = 0; i < na; i++) {
        const char *w = a[i];
        if (strcmp(w, "--") == 0) return NULL;
        if (strcmp(w, is_switch ? "-c" : "-b") == 0 || strcmp(w, is_switch ? "-C" : "-B") == 0 ||
            (is_switch && strcmp(w, "--create") == 0))
            return i + 1 < na ? a[i + 1] : NULL;
        if (w[0] != '-') return strcmp(w, "-") == 0 ? NULL : w;
    }
    return NULL;
}

void ag_git_note_branch(const char *sub, char **a, int na)
{
    const char *b;
    if (strcmp(sub, "checkout") != 0 && strcmp(sub, "switch") != 0) return;
    b = branch_word(sub, a, na);
    if (b && strlen(b) < sizeof s_branch) memcpy(s_branch, b, strlen(b) + 1);
}

/* The first line of a small file into line (NUL-terminated, no newline); false when unreadable. */
static bool read_first_line(const char *path, char *line, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) return false;
    n = fread(line, 1, cap - 1, f);
    fclose(f);
    line[n] = '\0';
    line[strcspn(line, "\r\n")] = '\0';
    return true;
}

/* The HEAD file of the repository whose root is dir: <dir>/.git/HEAD, or <gitdir>/HEAD when .git
 * is a file (a worktree or submodule; a relative gitdir is relative to dir). */
static bool head_path_at(const char *dir, char *out, size_t cap)
{
    char dot[PATH_CAP], line[512];
    const char *gd;
    if (!join_path(dot, sizeof dot, dir, NULL, ".git")) return false;
    if (read_first_line(dot, line, sizeof line) && strncmp(line, "gitdir:", 7) == 0) {
        gd = line + 7;
        while (*gd == ' ') gd++;
        if (is_absolute(gd)) return join_path(out, cap, gd, NULL, "HEAD");
        return join_path(out, cap, dir, gd, "HEAD");
    }
    if (!join_path(out, cap, dot, NULL, "HEAD")) return false;
    return read_first_line(out, line, sizeof line) && line[0];
}

/* Walk up from dir to the repository root and give its HEAD file. */
static bool find_head(const char *dir, char *out, size_t cap)
{
    char cur[PATH_CAP];
    if (strlen(dir) >= sizeof cur) return false;
    memcpy(cur, dir, strlen(dir) + 1);
    for (int depth = 0; depth < 64 && cur[0]; depth++) {
        char *cut;
        if (head_path_at(cur, out, cap)) return true;
        cut = strrchr(cur, '/');
        if (!cut) cut = strrchr(cur, '\\');
        if (!cut || cut == cur || cut[-1] == ':') return false;
        *cut = '\0';
    }
    return false;
}

/* The current branch is master: by the checkout or switch seen earlier in the command, else by
 * HEAD of the repository at dir. */
static bool on_master(const char *dir)
{
    char path[2 * PATH_CAP], line[512];
    if (s_branch[0]) return strcmp(s_branch, "master") == 0;
    if (!dir[0] || !find_head(dir, path, sizeof path)) return false;
    if (!read_first_line(path, line, sizeof line)) return false;
    return strcmp(line, "ref: refs/heads/master") == 0;
}

/* True when w is a short option group of letters containing flag ch. */
static bool short_group_has(const char *w, char ch)
{
    if (w[0] != '-' || w[1] == '-' || w[1] == '\0') return false;
    for (const char *p = w + 1; *p; p++)
        if (!isalpha((unsigned char)*p)) return false;
    return strchr(w + 1, ch) != NULL;
}

/* The destination of a refspec is master or a release ref (or a wildcard that may be one). A
 * delete (":name") names its target after the colon, so it is judged the same way. */
static bool refspec_protected(const char *r)
{
    const char *dst = strchr(r, ':');
    dst = dst ? dst + 1 : r;
    if (dst[0] == '+') dst++;
    if (strncmp(dst, "refs/heads/", 11) == 0) dst += 11;
    return strcmp(dst, "master") == 0 || strcmp(dst, "release") == 0 ||
           strncmp(dst, "release/", 8) == 0 || has_glob(dst);
}

static bool push_opt_takes_arg(const char *a)
{
    static const char *const opts[] = {"--repo", "-o", "--push-option", "--receive-pack",
                                       "--exec", "--signed"};
    for (size_t i = 0; i < sizeof opts / sizeof opts[0]; i++)
        if (strcmp(a, opts[i]) == 0) return true;
    return false;
}

struct pushst {
    bool force, master, tags, head;
    int pos;
};

/* --help and --dry-run only look: nothing is pushed. */
static bool is_look_only(const char *w)
{
    return strcmp(w, "--help") == 0 || strcmp(w, "-h") == 0 || strcmp(w, "--dry-run") == 0 ||
           strcmp(w, "-n") == 0;
}

/* The safe forms of a force: they check the remote still holds what we last saw. */
static bool is_lease(const char *w)
{
    return strncmp(w, "--force-with-lease", 18) == 0 || strcmp(w, "--force-if-includes") == 0;
}

static bool is_plain_force(const char *w)
{
    return strncmp(w, "--force", 7) == 0 || short_group_has(w, 'f');
}

/* One option word: 1 when it only asks for help or a dry run (nothing is pushed), else 0. */
static int push_option(char **a, int na, int *i, struct pushst *s)
{
    const char *w = a[*i];
    if (is_look_only(w)) return 1;
    if (is_lease(w) || strcmp(w, "--delete") == 0 || short_group_has(w, 'd')) return 0;
    if (is_plain_force(w)) s->force = true;
    else if (strcmp(w, "--all") == 0 || strcmp(w, "--mirror") == 0) s->master = true;
    else if (strcmp(w, "--tags") == 0) s->tags = true;
    else if (push_opt_takes_arg(w) && *i + 1 < na) (*i)++;
    return 0;
}

/* A word after the remote: a refspec. */
static void push_refspec(const char *w, struct pushst *s)
{
    if (w[0] == '+') s->force = true;
    if (refspec_protected(w)) s->master = true;
    if (strcmp(w, "HEAD") == 0) s->head = true;
}

const char *ag_push_rule(char **a, int na, const char *dash_c)
{
    struct pushst s = {false, false, false, false, 0};
    char dir[PATH_CAP];
    if (!dash_c || !resolve_dir(s_cwd, dash_c, dir, sizeof dir))
        snprintf(dir, sizeof dir, "%s", dash_c ? "" : s_cwd);
    for (int i = 0; i < na; i++) {
        if (a[i][0] == '-' && a[i][1]) {
            if (push_option(a, na, &i, &s)) return NULL;
        } else if (++s.pos >= 2) {
            push_refspec(a[i], &s);
        }
    }
    if (s.master) return R_PUSH;
    if (((s.pos < 2 && !s.tags) || s.head) && on_master(dir)) return R_PUSH;
    if (s.force) ag_note_text("forced push of a branch other than master or release: allowed");
    return NULL;
}
