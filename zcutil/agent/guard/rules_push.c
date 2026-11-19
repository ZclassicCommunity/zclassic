/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Derived from Z23 tools/agent_guard_rules.c@9a191ef7b, Apache-2.0, changed (zclassicd's rules; see
 * zcutil/tools/NOTICE). zcl-agent-guard: the `git push` rule.
 *
 * Refused: a plain force (--force, -f, +ref), a branch delete, a push to master, --all and --mirror.
 * --force-with-lease to a named branch is the ordinary way to update a rebased feature branch, so it
 * is allowed. A push that names no branch (a bare push, `origin`, HEAD) pushes the current branch:
 * it is refused only when the repository at cwd is on master, and allowed where the branch cannot be
 * read, because most pushes are of a feature branch. --dry-run and --help only look. */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "rules.h"
#include "rules_int.h"

#define PATH_CAP 1100

static bool has_glob(const char *s)
{
    return strpbrk(s, "*?[") != NULL;
}

/* True when w is a short option group of letters containing flag ch. */
static bool short_group_has(const char *w, char ch)
{
    if (w[0] != '-' || w[1] == '-' || w[1] == '\0') return false;
    for (const char *p = w + 1; *p; p++)
        if (!isalpha((unsigned char)*p)) return false;
    return strchr(w + 1, ch) != NULL;
}

/* The destination master, src:master or refs/heads/master updates master; a wildcard may. */
static bool refspec_names_master(const char *r)
{
    const char *dst = strchr(r, ':');
    dst = dst ? dst + 1 : r;
    if (dst[0] == '+') dst++;
    if (strncmp(dst, "refs/heads/", 11) == 0) dst += 11;
    return strcmp(dst, "master") == 0 || has_glob(dst);
}

static bool push_opt_takes_arg(const char *a)
{
    static const char *const opts[] = {"--repo", "-o", "--push-option", "--receive-pack",
                                       "--exec", "--signed"};
    for (size_t i = 0; i < sizeof opts / sizeof opts[0]; i++)
        if (strcmp(a, opts[i]) == 0) return true;
    return false;
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

/* The path of HEAD for the repository at cwd: <cwd>/.git/HEAD, or <gitdir>/HEAD when .git is a file
 * (a worktree or submodule; a relative gitdir is relative to cwd). */
static bool head_path(const char *cwd, char *out, size_t cap)
{
    char dot[PATH_CAP], line[512];
    const char *dir;
    if (!join_path(dot, sizeof dot, cwd, NULL, ".git")) return false;
    if (!read_first_line(dot, line, sizeof line)) line[0] = '\0'; /* a directory: no pointer */
    if (strncmp(line, "gitdir:", 7) != 0) return join_path(out, cap, dot, NULL, "HEAD");
    dir = line + 7;
    while (*dir == ' ') dir++;
    if (dir[0] == '/' || dir[0] == '\\' || dir[1] == ':') /* absolute (a worktree) */
        return join_path(out, cap, dir, NULL, "HEAD");
    return join_path(out, cap, cwd, dir, "HEAD");
}

static bool on_master(const char *cwd)
{
    char path[2 * PATH_CAP], line[512];
    if (!cwd || !cwd[0] || !head_path(cwd, path, sizeof path)) return false;
    if (!read_first_line(path, line, sizeof line)) return false;
    return strcmp(line, "ref: refs/heads/master") == 0;
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

/* A plain force, or a branch delete. */
static bool is_force_or_delete(const char *w)
{
    return strncmp(w, "--force", 7) == 0 || short_group_has(w, 'f') || strcmp(w, "--delete") == 0 ||
           short_group_has(w, 'd');
}

/* One option word: 1 when it only asks for help or a dry run (nothing is pushed), else 0. */
static int push_option(char **a, int na, int *i, struct pushst *s)
{
    const char *w = a[*i];
    if (is_look_only(w)) return 1;
    if (is_lease(w)) return 0;
    if (is_force_or_delete(w)) s->force = true;
    else if (strcmp(w, "--all") == 0 || strcmp(w, "--mirror") == 0) s->master = true;
    else if (strcmp(w, "--tags") == 0) s->tags = true;
    else if (push_opt_takes_arg(w) && *i + 1 < na) (*i)++;
    return 0;
}

/* A word after the remote: a refspec. */
static void push_refspec(const char *w, struct pushst *s)
{
    if (w[0] == '+') s->force = true;
    if (refspec_names_master(w)) s->master = true;
    if (strcmp(w, "HEAD") == 0) s->head = true;
}

const char *ag_push_rule(char **a, int na, const char *cwd)
{
    struct pushst s = {false, false, false, false, 0};
    for (int i = 0; i < na; i++) {
        if (a[i][0] == '-' && a[i][1]) {
            if (push_option(a, na, &i, &s)) return NULL;
        } else if (++s.pos >= 2) {
            push_refspec(a[i], &s);
        }
    }
    if (s.force || s.master) return R_PUSH;
    if ((s.pos < 2 && !s.tags) || s.head) return on_master(cwd) ? R_PUSH : NULL;
    return NULL;
}
