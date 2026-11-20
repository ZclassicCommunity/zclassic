/* zcl-dev wiki and zcl-dev read: walk the docs tree and the source tree one topic at a time.
 * MIT, like the rest of zclassicd. One binary, four commands: it acts as wiki, read, lessons or
 * know by the name it is run under (zcl-dev-wiki, zcl-dev-read, zcl-dev-lessons, zcl-dev-know),
 * so the git-style dispatch of zcl-dev finds each one.
 *
 *   zcl-dev wiki [topic] [--after=N] [--json]   topic: a path under doc/, or code/<dir>
 *   zcl-dev read <path> [--offset=N] [--bytes=N] [--json]
 *
 * Designed after Z23's discover.wiki and discover.read (tools/command/native_wiki_*.c).
 * Every reply stays under 16 KiB; a long child list pages with --after. */
#include "wikilib.h"

#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#define chdir _chdir
#else
#include <unistd.h>
#endif

enum {
    CHILD_CAP = 64,       /* children per reply */
    CMD_CAP = 16,         /* resolved commands per topic */
    FOOTER_RESERVE = 700, /* room kept for the paging footer */
    READ_MAX = 15872,     /* bytes per read chunk; header and footer fit under 16 KiB */
    HEAD_MAX = 8192,      /* how much of a file a summary looks at */
    TOPIC_MAX = 480,
};

/* ---- path rules --------------------------------------------------------------------------- */

static const char *const excluded_names[] = {"vendor", "depends", "build", "obj", "node_modules",
                                             "autom4te.cache", "__pycache__", NULL};
static const char *const excluded_prefixes[] = {"src/leveldb", "src/secp256k1", "src/univalue",
                                                "zcutil/bin", "zcutil/gen", NULL};
static const char *const object_exts[] = {".o", ".a", ".lo", ".la", ".obj", ".exe", ".dll", ".so",
                                          ".dylib", ".pyc", NULL};

/* A syntactically safe relative path: no empty, "." or ".." component, no backslash, no control byte. */
static int safe_rel(const char *p)
{
    if (!*p || strlen(p) > TOPIC_MAX || *p == '/') return 0;
    size_t comp = 0;
    for (const char *c = p;; c++) {
        if (*c == '/' || !*c) {
            if (!comp) return 0;
            if (comp == 1 && c[-1] == '.') return 0;
            if (comp == 2 && c[-1] == '.' && c[-2] == '.') return 0;
            comp = 0;
            if (!*c) break;
        } else {
            if (*c == '\\' || (unsigned char)*c < 0x20) return 0;
            comp++;
        }
    }
    return 1;
}

/* The source tree does not serve dot directories, build outputs or vendored trees. */
static int code_excluded(const char *rel)
{
    for (const char *c = rel; *c;) {
        size_t n = strcspn(c, "/");
        if (*c == '.') return 1;
        for (int i = 0; excluded_names[i]; i++)
            if (strlen(excluded_names[i]) == n && !strncmp(c, excluded_names[i], n)) return 1;
        c += n + (c[n] ? 1 : 0);
    }
    for (int i = 0; excluded_prefixes[i]; i++) {
        size_t n = strlen(excluded_prefixes[i]);
        if (!strncmp(rel, excluded_prefixes[i], n) && (!rel[n] || rel[n] == '/')) return 1;
    }
    return 0;
}

static int dot_component(const char *rel)
{
    for (const char *c = rel; *c;) {
        if (*c == '.') return 1;
        c += strcspn(c, "/");
        if (*c) c++;
    }
    return 0;
}

static int is_dir(const char *p)
{
    struct stat st;
    return !stat(p, &st) && S_ISDIR(st.st_mode);
}

static int is_file(const char *p)
{
    struct stat st;
    return !stat(p, &st) && S_ISREG(st.st_mode);
}

/* Is the resolved path inside the resolved root? */
static int inside(const char *root, const char *real)
{
    size_t n = strlen(root);
    return !strncmp(real, root, n) && (!real[n] || real[n] == '/' || !strcmp(root, "/"));
}

/* ---- file summaries ----------------------------------------------------------------------- */

static int boilerplate(const char *t)
{
    static const char *const words[] = {"copyright", "license", "licence", "spdx", "distributed under",
                                        "all rights", "see the file", "permission", "copying", "-*-",
                                        "@file", NULL};
    for (int i = 0; words[i]; i++)
        if (contains_ci(t, words[i])) return 1;
    return 0;
}

static int substantive(const char *t)
{
    int letters = 0;
    for (const char *c = t; *c; c++) letters += isalpha((unsigned char)*c) ? 1 : 0;
    return strlen(t) >= 8 && letters >= 4 && !boilerplate(t);
}

/* Text of one comment line with the comment markers removed; "" when it carries none. */
static char *comment_text(char *line)
{
    char *t = trim(line);
    size_t n;
    while (*t == '/' || *t == '*' || *t == '!' || *t == '#') t++;
    t = trim(t);
    n = strlen(t);
    while (n && (t[n - 1] == '/' || t[n - 1] == '*' || t[n - 1] == ' ')) t[--n] = 0;
    return t;
}

/* The text after "purpose:" in a comment line (any case), or NULL. */
static const char *find_purpose(const char *c)
{
    for (; *c; c++)
        if (!strncmp(c, "purpose:", 8) || !strncmp(c, "Purpose:", 8) || !strncmp(c, "PURPOSE:", 8)) {
            c += 8;
            while (*c == ' ') c++;
            return c;
        }
    return NULL;
}

/* style 0: C comments, 1: '#' comments. The "purpose:" line of the leading comment, else its first
 * substantive line; out is "" when the file has no leading comment. */
static void source_summary(const char *head, int style, char *out, size_t cap)
{
    char first[TEXT_MAX + 1] = "", purpose[TEXT_MAX + 1] = "", line[1024];
    int in_block = 0, lines = 0;
    for (const char *p = head; *p && lines < 80; lines++) {
        size_t n = strcspn(p, "\n");
        size_t k = n < sizeof line - 1 ? n : sizeof line - 1;
        memcpy(line, p, k);
        line[k] = 0;
        p += n + (p[n] ? 1 : 0);
        char *t = trim(line);
        int comment = 0;
        if (!*t) continue;
        if (style == 0) {
            if (in_block) comment = 1;
            else if (has_prefix(t, "/*")) { comment = 1; in_block = 1; }
            else if (has_prefix(t, "//")) comment = 1;
            if (comment && in_block && strstr(t, "*/") && (!has_prefix(t, "/*") || strstr(t + 2, "*/")))
                in_block = 0; /* this line closes the block; its text still counts */
        } else {
            if (has_prefix(t, "#!")) continue;
            if (*t == '#') comment = 1;
        }
        if (!comment) break; /* code reached: the leading comment is over */
        char *c = comment_text(t);
        const char *pp = find_purpose(c);
        if (pp && !purpose[0]) snprintf(purpose, sizeof purpose, "%s", pp);
        else if (!pp && !first[0] && substantive(c)) snprintf(first, sizeof first, "%s", c);
    }
    snprintf(out, cap, "%s", purpose[0] ? purpose : first);
    clip_text(out, TEXT_MAX);
}

static int is_hash_style(const char *name)
{
    return has_suffix(name, ".sh") || has_suffix(name, ".am") || has_suffix(name, ".include") ||
           has_suffix(name, ".mk") || has_suffix(name, ".rules") || has_prefix(name, "Makefile");
}

static int is_c_style(const char *name)
{
    static const char *const exts[] = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".inc", ".def", NULL};
    for (int i = 0; exts[i]; i++)
        if (has_suffix(name, exts[i])) return 1;
    return 0;
}

/* One-line summary of a file; "" when it has none. */
static void file_summary(const char *fs, const char *name, char *out, size_t cap)
{
    out[0] = 0;
    char *head = read_file(fs, HEAD_MAX, NULL);
    if (!head) return;
    if (is_c_style(name)) source_summary(head, 0, out, cap);
    else if (is_hash_style(name)) source_summary(head, 1, out, cap);
    else if (has_suffix(name, ".md")) md_summary(head, out, cap);
    free(head);
}

/* ---- directory listing -------------------------------------------------------------------- */

typedef struct {
    int code;            /* the source tree rather than doc/ */
    char root[PATH_CAP]; /* resolved root: doc/ or the repository */
} Tree;

static int secret_name(const char *rel);

static int cmp_names(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static int object_file(const char *name)
{
    for (int i = 0; object_exts[i]; i++)
        if (has_suffix(name, object_exts[i])) return 1;
    return 0;
}

/* Visible children of directory fs (rel is its repo-relative path for code): subdirectories into
 * dirs, files into files, both sorted. Symlinks that leave the root, and symlinked directories, are
 * not listed. */
static void list_children(const Tree *tr, const char *fs, const char *rel, List *dirs, List *files)
{
    DIR *d = opendir(fs);
    struct dirent *e;
    if (!d) return;
    while ((e = readdir(d))) {
        char child[PATH_CAP], crel[PATH_CAP], real[PATH_CAP];
        struct stat st;
        if (e->d_name[0] == '.') continue;
        if (snprintf(child, sizeof child, "%s/%s", fs, e->d_name) >= (int)sizeof child) continue;
        if (tr->code) {
            snprintf(crel, sizeof crel, "%s%s%s", rel, *rel ? "/" : "", e->d_name);
            if (code_excluded(crel)) continue;
        }
        if (stat(child, &st)) continue;
        if (real_path(child, real, sizeof real) || !inside(tr->root, real)) continue;
#ifndef _WIN32
        struct stat ls;
        if (!lstat(child, &ls) && S_ISLNK(ls.st_mode) && S_ISDIR(st.st_mode)) continue;
#endif
        if (S_ISDIR(st.st_mode)) list_push(dirs, e->d_name);
        else if (S_ISREG(st.st_mode)) {
            if (tr->code ? (object_file(e->d_name) || secret_name(e->d_name)) : (!has_suffix(e->d_name, ".md") || !strcmp(e->d_name, "README.md")))
                continue;
            list_push(files, e->d_name);
        }
    }
    closedir(d);
    if (dirs->n > 1) qsort(dirs->v, dirs->n, sizeof *dirs->v, cmp_names);
    if (files->n > 1) qsort(files->v, files->n, sizeof *files->v, cmp_names);
}

/* Index document of a directory: README.md for doc/, AGENTS.md else README.md for code; "" if none. */
static void index_doc(const Tree *tr, const char *fs, char *out, size_t cap)
{
    const char *const names[2] = {tr->code ? "AGENTS.md" : "README.md", tr->code ? "README.md" : NULL};
    out[0] = 0;
    for (int i = 0; i < 2 && names[i]; i++) {
        char p[PATH_CAP];
        snprintf(p, sizeof p, "%s/%s", fs, names[i]);
        if (is_file(p)) { snprintf(out, cap, "%s", p); return; }
    }
}

/* Title and summary of a directory; the summary falls back to "N files". */
static void dir_summary(const Tree *tr, const char *fs, const char *rel, const char *name, char *title,
                        size_t tcap, char *sum, size_t scap)
{
    char idx[PATH_CAP];
    snprintf(title, tcap, "%.200s", name);
    sum[0] = 0;
    index_doc(tr, fs, idx, sizeof idx);
    if (idx[0]) {
        char *text = read_file(idx, HEAD_MAX, NULL);
        if (text) {
            char t[TEXT_MAX + 1];
            md_summary(text, sum, scap);
            if (!tr->code) {
                md_title(text, t, sizeof t);
                if (t[0]) snprintf(title, tcap, "%s", t);
            }
            free(text);
        }
    }
    if (!sum[0]) {
        List d = {0}, f = {0};
        list_children(tr, fs, rel, &d, &f);
        snprintf(sum, scap, "%zu file%s", d.n + f.n, d.n + f.n == 1 ? "" : "s");
        list_free(&d);
        list_free(&f);
    }
}

/* ---- commands named by a topic ------------------------------------------------------------ */

static int regular_exists(const char *p)
{
    if (!safe_rel(p)) return 0;
    return is_file(p);
}

/* Does a backticked command line resolve to something that exists in this tree? */
static int command_resolves(const char *cmd)
{
    char buf[512], *tok[24];
    size_t nt = 0;
    snprintf(buf, sizeof buf, "%s", cmd);
    for (char *c = strtok(buf, " "); c && nt < 24; c = strtok(NULL, " ")) tok[nt++] = c;
    if (!nt) return 0;
    if (!strcmp(tok[0], "zcl-dev") || !strcmp(tok[0], "zcutil/bin/zcl-dev")) {
        size_t i = 1;
        while (i + 1 < nt && !strcmp(tok[i], "-C")) i += 2;
        return i < nt && sub_resolves(tok[i]);
    }
    if (!strcmp(tok[0], "make")) {
        const char *dir = ".";
        char mk[PATH_CAP];
        for (size_t i = 1; i + 1 < nt; i++)
            if (!strcmp(tok[i], "-C")) dir = tok[i + 1];
        if (strcmp(dir, ".") && !safe_rel(dir)) return 0;
        snprintf(mk, sizeof mk, "%s/Makefile", dir);
        return is_file(mk);
    }
    if (!strcmp(tok[0], "sh")) {
        for (size_t i = 1; i < nt; i++)
            if (tok[i][0] != '-') return regular_exists(tok[i]);
        return 0;
    }
    if (strchr(tok[0], '/')) return regular_exists(has_prefix(tok[0], "./") ? tok[0] + 2 : tok[0]);
    return 0;
}

/* Backticked commands of the "Commands:" line of an index document, only those that resolve. */
static void topic_commands(const char *idx, List *cmds)
{
    if (!idx[0]) return;
    char *text = read_file(idx, 16384, NULL);
    if (!text) return;
    for (const char *p = text; *p;) {
        size_t n = strcspn(p, "\n");
        if (!strncmp(p, "Commands:", 9)) {
            const char *c = p + 9, *end = p + n;
            while (c < end && cmds->n < CMD_CAP) {
                const char *a = memchr(c, '`', (size_t)(end - c));
                if (!a) break;
                const char *b = memchr(a + 1, '`', (size_t)(end - a - 1));
                if (!b) break;
                char cmd[512];
                size_t k = (size_t)(b - a - 1);
                if (k && k < sizeof cmd) {
                    memcpy(cmd, a + 1, k);
                    cmd[k] = 0;
                    if (command_resolves(cmd)) list_push(cmds, cmd);
                }
                c = b + 1;
            }
            break; /* one Commands: line */
        }
        p += n + (p[n] ? 1 : 0);
    }
    free(text);
}

/* ---- topic resolution --------------------------------------------------------------------- */

/* The nearest existing topic at or above rel, as a topic path ("" for the root). */
static void nearest_topic(const Tree *tr, const char *rel, char *out, size_t cap)
{
    char cur[PATH_CAP], fs[PATH_CAP];
    snprintf(cur, sizeof cur, "%s", rel);
    for (;;) {
        snprintf(fs, sizeof fs, "%s%.4000s", tr->code ? "" : "doc/", cur);
        if (!*cur) snprintf(fs, sizeof fs, "%s", tr->code ? "." : "doc");
        if (is_dir(fs)) break;
        char *s = strrchr(cur, '/');
        if (!s) { cur[0] = 0; break; }
        *s = 0;
    }
    snprintf(out, cap, "%s%s%s", tr->code ? "code" : "", tr->code && *cur ? "/" : "", cur);
}

typedef struct {
    Tree tr;
    char topic[TOPIC_MAX + 8]; /* as the caller named it, normalised */
    char rel[TOPIC_MAX + 16];  /* inside the tree ("" for its root) */
    char fs[PATH_CAP];         /* path to open from the repository root */
    int leaf;                  /* a page (file), not a directory */
} Node;

static int resolve_topic(const char *arg, Node *nd, int *rc)
{
    char t[TOPIC_MAX + 8];
    size_t n = strlen(arg);
    memset(nd, 0, sizeof *nd);
    while (n > 1 && arg[n - 1] == '/') n--;
    if (n > TOPIC_MAX) { *rc = fail_reply("INVALID_TOPIC", "topic is too long", ""); return 0; }
    memcpy(t, arg, n);
    t[n] = 0;
    if (n && !safe_rel(t)) {
        *rc = fail_reply("INVALID_TOPIC", "topic must be a relative path without . or .. parts", t);
        return 0;
    }
    snprintf(nd->topic, sizeof nd->topic, "%s", t);
    if (!strcmp(t, "code") || has_prefix(t, "code/")) {
        nd->tr.code = 1;
        snprintf(nd->rel, sizeof nd->rel, "%s", t[4] ? t + 5 : "");
        if (code_excluded(nd->rel)) {
            *rc = fail_reply("EXCLUDED_PATH", "the source tree does not serve dot directories, build "
                             "outputs or vendored trees", t);
            return 0;
        }
        snprintf(nd->fs, sizeof nd->fs, "%s", nd->rel[0] ? nd->rel : ".");
        if (real_path(".", nd->tr.root, sizeof nd->tr.root)) die("cannot resolve the current directory");
    } else {
        snprintf(nd->rel, sizeof nd->rel, "%s", t);
        if (dot_component(t)) {
            *rc = fail_reply("EXCLUDED_PATH", "doc/ does not serve dot paths", t);
            return 0;
        }
        snprintf(nd->fs, sizeof nd->fs, "doc%s%s", t[0] ? "/" : "", t);
        if (real_path("doc", nd->tr.root, sizeof nd->tr.root)) {
            *rc = fail_reply("NO_DOCS", "no doc/ directory here; run from the repository root or pass -C", "doc");
            return 0;
        }
    }
    if (!is_dir(nd->fs) && !(is_file(nd->fs) && !nd->tr.code && has_suffix(nd->fs, ".md"))) {
        char nearest[PATH_CAP + 16]; /* "code/" plus the longest topic (PATH_CAP - 1) must fit whole */
        nearest_topic(&nd->tr, nd->rel, nearest, sizeof nearest);
        *rc = fail_reply("UNKNOWN_TOPIC", "no such topic; the nearest existing topic is the evidence",
                         nearest[0] ? nearest : "(root)");
        return 0;
    }
    char real[PATH_CAP];
    if (real_path(nd->fs, real, sizeof real) || !inside(nd->tr.root, real)) {
        *rc = fail_reply(nd->tr.code ? "OUTSIDE_CODE" : "OUTSIDE_DOCS",
                         nd->tr.code ? "path resolves outside the repository" : "path resolves outside doc/", t);
        return 0;
    }
    nd->leaf = !is_dir(nd->fs);
    return 1;
}

/* ---- the wiki reply ----------------------------------------------------------------------- */

typedef struct { char name[256], path[TOPIC_MAX + 300], title[TEXT_MAX + 1], sum[TEXT_MAX + 1]; int dir; } Child;

static void join_topic(const Node *nd, const char *name, char *out, size_t cap)
{
    if (nd->tr.code) snprintf(out, cap, "%s/%s", nd->topic[0] ? nd->topic : "code", name);
    else snprintf(out, cap, "%s%s%s", nd->topic, nd->topic[0] ? "/" : "", name);
}

/* Child number i of the node: the virtual code/ entry first at the docs root, then directories,
 * then files. */
static void make_child(const Node *nd, const List *dirs, const List *files, int has_code, size_t i, Child *c)
{
    char fs[PATH_CAP + 300], rel[PATH_CAP + 300];
    memset(c, 0, sizeof *c);
    if (has_code && i == 0) {
        snprintf(c->name, sizeof c->name, "code");
        snprintf(c->path, sizeof c->path, "code");
        snprintf(c->title, sizeof c->title, "code");
        snprintf(c->sum, sizeof c->sum, "the source tree: zcl-dev wiki code/<dir>");
        c->dir = 1;
        return;
    }
    if (has_code) i--;
    c->dir = i < dirs->n;
    snprintf(c->name, sizeof c->name, "%s", c->dir ? dirs->v[i] : files->v[i - dirs->n]);
    join_topic(nd, c->name, c->path, sizeof c->path);
    snprintf(fs, sizeof fs, "%s/%s", nd->fs, c->name);
    snprintf(rel, sizeof rel, "%s%s%s", nd->rel, nd->rel[0] ? "/" : "", c->name);
    if (c->dir) dir_summary(&nd->tr, fs, rel, c->name, c->title, sizeof c->title, c->sum, sizeof c->sum);
    else {
        snprintf(c->title, sizeof c->title, "%.200s", c->name);
        file_summary(fs, c->name, c->sum, sizeof c->sum);
        if (!nd->tr.code) {
            char *text = read_file(fs, HEAD_MAX, NULL);
            if (text) {
                char t[TEXT_MAX + 1];
                md_title(text, t, sizeof t);
                if (t[0]) snprintf(c->title, sizeof c->title, "%s", t);
                free(text);
            }
        }
    }
}

static void next_hint(const Node *nd, size_t after, char *out, size_t cap)
{
    snprintf(out, cap, "zcl-dev wiki%s%s --after=%zu", nd->topic[0] ? " " : "", nd->topic, after);
}

int cmd_wiki(int argc, char **argv)
{
    const char *topic = NULL;
    size_t after = 0;
    int rc = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) g_json = 1;
        else if (has_prefix(argv[i], "--after=")) {
            const char *v = argv[i] + 8;
            char *end;
            if (!*v || !isdigit((unsigned char)*v)) return fail_reply("USAGE", "--after takes a number", argv[i]);
            after = strtoul(v, &end, 10);
            if (*end) return fail_reply("USAGE", "--after takes a number", argv[i]);
        } else if (argv[i][0] == '-' || topic) return fail_reply("USAGE", "usage: zcl-dev wiki [topic] [--after=N] [--json]", argv[i]);
        else topic = argv[i];
    }
    Node nd;
    if (!resolve_topic(topic ? topic : "", &nd, &rc)) return rc;

    char title[TEXT_MAX + 1], sum[TEXT_MAX + 1], idx[PATH_CAP] = "";
    const char *tname = nd.topic[0] ? strrchr(nd.topic, '/') ? strrchr(nd.topic, '/') + 1 : nd.topic : "(root)";
    List dirs = {0}, files = {0}, cmds = {0};
    int has_code = !nd.tr.code && !nd.topic[0];
    if (nd.leaf) {
        char *text = read_file(nd.fs, HEAD_MAX, NULL);
        snprintf(title, sizeof title, "%.200s", tname);
        sum[0] = 0;
        if (text) {
            char t[TEXT_MAX + 1];
            md_summary(text, sum, sizeof sum);
            md_title(text, t, sizeof t);
            if (t[0]) snprintf(title, sizeof title, "%s", t);
            free(text);
        }
    } else {
        dir_summary(&nd.tr, nd.fs, nd.rel, nd.tr.code && !nd.rel[0] ? "code" : tname, title, sizeof title, sum, sizeof sum);
        index_doc(&nd.tr, nd.fs, idx, sizeof idx);
        topic_commands(idx, &cmds);
        list_children(&nd.tr, nd.fs, nd.rel, &dirs, &files);
    }
    size_t total = (nd.leaf ? 0 : dirs.n + files.n) + (has_code ? 1 : 0);

    /* Header, then as many children as fit under the budget. */
    Buf out = {0}, kids = {0};
    size_t shown = 0;
    if (g_json) {
        buf_add(&out, "{\"ok\":true,\"topic\":");
        buf_json(&out, nd.topic);
        buf_add(&out, ",\"title\":");
        buf_json(&out, title);
        buf_add(&out, ",\"summary\":");
        buf_json(&out, sum);
        buf_add(&out, ",\"commands\":[");
        for (size_t i = 0; i < cmds.n; i++) { if (i) buf_add(&out, ","); buf_json(&out, cmds.v[i]); }
        buf_printf(&out, "],\"total\":%zu,\"after\":%zu,\"children\":[", total, after);
    } else {
        buf_printf(&out, "topic: %s\n", nd.topic[0] ? nd.topic : "(root)");
        buf_printf(&out, "title: %s\n", title);
        buf_printf(&out, "summary: %s\n", sum);
        if (cmds.n) {
            buf_add(&out, "commands:\n");
            for (size_t i = 0; i < cmds.n; i++) buf_printf(&out, "  %s\n", cmds.v[i]);
        }
    }
    for (size_t i = after; i < total && shown < CHILD_CAP; i++) {
        Child c;
        Buf one = {0};
        make_child(&nd, &dirs, &files, has_code, i, &c);
        if (g_json) {
            buf_add(&one, shown ? "," : "");
            buf_add(&one, "{\"path\":");
            buf_json(&one, c.path);
            buf_add(&one, ",\"kind\":");
            buf_json(&one, c.dir ? "topic" : "page");
            buf_add(&one, ",\"title\":");
            buf_json(&one, c.title);
            buf_add(&one, ",\"summary\":");
            buf_json(&one, c.sum);
            buf_add(&one, "}");
        } else {
            buf_printf(&one, "  %s%s%s%s\n", c.name, c.dir ? "/" : "", c.sum[0] ? " - " : "", c.sum);
        }
        if (out.n + kids.n + one.n + FOOTER_RESERVE > REPLY_MAX && shown) { buf_free(&one); break; }
        buf_addn(&kids, one.p, one.n);
        buf_free(&one);
        shown++;
    }
    char hint[TOPIC_MAX + 64] = "";
    if (after + shown < total) next_hint(&nd, after + shown, hint, sizeof hint);
    if (g_json) {
        buf_addn(&out, kids.p ? kids.p : "", kids.n);
        buf_add(&out, "],\"next\":");
        if (hint[0]) buf_json(&out, hint); else buf_add(&out, "null");
        buf_add(&out, "}\n");
    } else {
        if (total) buf_printf(&out, "children: %zu (showing %zu-%zu)\n", total, shown ? after + 1 : after, after + shown);
        buf_addn(&out, kids.p ? kids.p : "", kids.n);
        if (nd.leaf) buf_printf(&out, "read: zcl-dev read doc/%s\n", nd.rel);
        if (hint[0]) buf_printf(&out, "next: %s\n", hint);
    }
    fwrite(out.p, 1, out.n, stdout);
    buf_free(&out);
    buf_free(&kids);
    list_free(&dirs);
    list_free(&files);
    list_free(&cmds);
    return 0;
}

/* ---- read --------------------------------------------------------------------------------- */

/* Bytes of escaped JSON that one source byte costs. */
static size_t json_cost(unsigned char c)
{
    if (c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t') return 2;
    return (c < 0x20 || c == 0x7f) ? 6 : 1;
}

static int secret_name(const char *rel)
{
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    return !strcmp(base, "wallet.dat") || has_prefix(base, ".env") || has_suffix(base, ".pem") ||
           has_suffix(base, ".key") || has_suffix(base, ".wallet");
}

int cmd_read(int argc, char **argv)
{
    const char *path = NULL;
    size_t offset = 0, want = READ_MAX;
    for (int i = 0; i < argc; i++) {
        const char *v = NULL;
        if (!strcmp(argv[i], "--json")) { g_json = 1; continue; }
        if (has_prefix(argv[i], "--offset=")) v = argv[i] + 9;
        else if (has_prefix(argv[i], "--bytes=")) v = argv[i] + 8;
        if (v) {
            char *end;
            if (!*v || !isdigit((unsigned char)*v)) return fail_reply("USAGE", "expected a number", argv[i]);
            unsigned long long n = strtoull(v, &end, 10);
            if (*end) return fail_reply("USAGE", "expected a number", argv[i]);
            if (argv[i][2] == 'o') offset = (size_t)n;
            else want = n > READ_MAX ? READ_MAX : (size_t)n;
        } else if (argv[i][0] == '-' || path) {
            return fail_reply("USAGE", "usage: zcl-dev read <path> [--offset=N] [--bytes=N] [--json]", argv[i]);
        } else path = argv[i];
    }
    if (!path) return fail_reply("USAGE", "usage: zcl-dev read <path> [--offset=N] [--bytes=N] [--json]", "");
    if (has_prefix(path, "./")) path += 2;
    if (!safe_rel(path)) return fail_reply("INVALID_PATH", "path must be relative, without . or .. parts", path);
    for (const char *c = path; *c;) {
        size_t n = strcspn(c, "/");
        if (n == 4 && !strncmp(c, ".git", 4)) return fail_reply("EXCLUDED_PATH", "the git directory is not served", path);
        c += n + (c[n] ? 1 : 0);
    }
    if (secret_name(path)) return fail_reply("EXCLUDED_PATH", "key and wallet files are not served", path);
    if (!is_file(path) && !is_dir(path)) return fail_reply("NO_SUCH_FILE", "no such file", path);
    char root[PATH_CAP], real[PATH_CAP];
    if (real_path(".", root, sizeof root)) die("cannot resolve the current directory");
    if (real_path(path, real, sizeof real) || !inside(root, real))
        return fail_reply("OUTSIDE_CODE", "path resolves outside the repository", path);
    if (is_dir(path)) return fail_reply("NOT_A_FILE", "a directory; list it with zcl-dev wiki code/<dir>", path);

    FILE *f = fopen(path, "rb");
    if (!f) return fail_reply("NO_SUCH_FILE", "cannot open the file", path);
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    if (fsz < 0) { fclose(f); return fail_reply("READ_FAILED", "cannot size the file", path); }
    size_t size = (size_t)fsz;
    if (offset > size) { fclose(f); return fail_reply("OFFSET_PAST_END", "offset is beyond the end of the file", path); }
    if (fseek(f, (long)offset, SEEK_SET)) { fclose(f); return fail_reply("READ_FAILED", "cannot seek", path); }
    unsigned char *buf = xrealloc(NULL, READ_MAX + 8);
    size_t avail = fread(buf, 1, want + 1, f), n = avail < want ? avail : want, got;
    fclose(f);
    if (memchr(buf, 0, avail)) { free(buf); return fail_reply("BINARY_FILE", "the chunk contains NUL bytes", path); }
    if (g_json) { /* the escaped chunk must fit the reply budget */
        size_t cost = 0, k = 0;
        while (k < n && cost + json_cost(buf[k]) <= REPLY_MAX - 1024) cost += json_cost(buf[k++]);
        n = k;
    }
    while (n > 1 && n < avail && (buf[n] & 0xc0) == 0x80) n--; /* do not end inside a UTF-8 sequence */
    got = n;
    buf[got] = 0;
    Buf out = {0};
    int more = offset + got < size;
    if (g_json) {
        buf_add(&out, "{\"ok\":true,\"path\":");
        buf_json(&out, path);
        buf_printf(&out, ",\"offset\":%zu,\"bytes\":%zu,\"size\":%zu,\"eof\":%s,\"content\":", offset, got, size,
                   more ? "false" : "true");
        buf_json(&out, (const char *)buf);
        if (more) buf_printf(&out, ",\"next\":\"zcl-dev read %s --offset=%zu\"}\n", path, offset + got);
        else buf_add(&out, ",\"next\":null}\n");
    } else {
        buf_printf(&out, "# zcl-dev read %s offset=%zu bytes=%zu of %zu\n", path, offset, got, size);
        buf_addn(&out, (const char *)buf, got);
        if (got && buf[got - 1] != '\n') buf_add(&out, "\n");
        if (more) buf_printf(&out, "# next: zcl-dev read %s --offset=%zu\n", path, offset + got);
    }
    fwrite(out.p, 1, out.n, stdout);
    buf_free(&out);
    free(buf);
    return 0;
}

/* ---- entry -------------------------------------------------------------------------------- */

typedef struct { const char *name, *purpose; int (*fn)(int, char **); } Sub;
static const Sub subs[] = {
    {"wiki", "walk the docs tree and the source tree one topic at a time", cmd_wiki},
    {"read", "read a repository file in chunks of at most 16 KiB", cmd_read},
    {"lessons", "search lessons, traps and facts; add a lesson", cmd_lessons},
    {"know", "answer from the closed FACTS table (UNKNOWN when no row); --check validates it", cmd_know},
    {NULL, NULL, NULL}};

int main(int argc, char **argv)
{
    char name[128];
    const char *base = strrchr(argv[0], '/');
    g_argv0 = argv[0];
    const char *bs = strrchr(argv[0], '\\');
    if (bs && (!base || bs > base)) base = bs;
    base = base ? base + 1 : argv[0];
    snprintf(name, sizeof name, "%s", base);
    if (has_suffix(name, ".exe")) name[strlen(name) - 4] = 0;
    const char *cmd = has_prefix(name, "zcl-dev-") ? name + 8 : name;
    const Sub *s = subs;
    while (s->name && strcmp(s->name, cmd)) s++;
    if (!s->name) die("run as zcl-dev-wiki, zcl-dev-read, zcl-dev-lessons or zcl-dev-know (not %s)", name);
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    argc--;
    argv++;
    if (argc && !strcmp(argv[0], "--purpose")) { puts(s->purpose); return 0; }
    if (argc >= 2 && !strcmp(argv[0], "-C")) {
        if (chdir(argv[1])) die("cannot enter %s", argv[1]);
        argc -= 2;
        argv += 2;
    }
    return s->fn(argc, argv);
}
