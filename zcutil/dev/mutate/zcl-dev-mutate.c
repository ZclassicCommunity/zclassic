/* zcl-dev mutate: a mutation-testing harness for one C or C++ file.
 *
 * Derived from Z23 tools/dev/mutation_campaign.c@9a191ef7b, Apache-2.0; changed. See zcutil/tools/NOTICE
 *
 * usage: zcl-dev mutate list <file> [--lines A-B] [--class c,...] [--json]
 *        zcl-dev mutate run <file> [--lines A-B] [--class c,...] [--max N] [--timeout SECS]
 *                               [--build "<cmd words>"] [--json] -- <test argv...>
 *        zcl-dev mutate restore <file>
 *        zcl-dev-mutate --selftest | --purpose
 * `list` enumerates the sites only. `run` applies one site at a time to the file, runs the build and
 * then the test, and reports the mutants the test let survive (mutate_run.c). Exit: 0 no survivors,
 * 1 survivors, 2 broken or refused. C, libc only; gnu17 that also compiles as c2x.
 */
#define _POSIX_C_SOURCE 200809L
#include "mutate_ops.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define USAGE \
    "usage: zcl-dev mutate list <file> [--lines A-B] [--class c,...] [--json]\n" \
    "       zcl-dev mutate run <file> [--lines A-B] [--class c,...] [--max N] [--timeout SECS]\n" \
    "                              [--build \"<cmd words>\"] [--json] -- <test argv...>\n" \
    "       zcl-dev mutate restore <file>\n" \
    "classes: relational logical boundary return statement\n"

static int usage(const char *why)
{
    if (why) fprintf(stderr, "zcl-dev mutate: %s\n", why);
    fputs(USAGE, stderr);
    return 2;
}

char *mut_read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    char *buf = malloc(cap + 1);
    while (buf) {
        size_t got = fread(buf + n, 1, cap - n, f);
        n += got;
        if (n < cap) break;
        char *nb = realloc(buf, cap * 2 + 1);
        if (!nb) { free(buf); buf = NULL; break; }
        buf = nb;
        cap *= 2;
    }
    bool bad = ferror(f) != 0;
    fclose(f);
    if (!buf || bad) { free(buf); return NULL; }
    buf[n] = 0;
    *len = n;
    return buf;
}

static bool is_absolute(const char *file)
{
#if defined(_WIN32)
    if (file[0] == '\\' || (file[0] && file[1] == ':')) return true;
#endif
    return file[0] == '/';
}

/* zcl-dev runs subcommands from the repository root and passes the caller's subdirectory in
 * ZCL_DEV_PREFIX; a relative file is relative to that. False when the joined path does not fit. */
bool mut_join_prefix(const char *file, char *joined, size_t cap)
{
    const char *prefix = getenv("ZCL_DEV_PREFIX");
    bool pre = prefix && prefix[0] && strcmp(prefix, ".") != 0 && !is_absolute(file);
    int n = snprintf(joined, cap, "%s%s%s", pre ? prefix : "", pre ? "/" : "", file);
    return n > 0 && (size_t)n < cap;
}

void mut_filter(struct mut_sites *s, const struct mut_opts *o)
{
    size_t k = 0;
    for (size_t i = 0; i < s->n; i++) {
        const struct mut_site *x = &s->v[i];
        if (x->line < o->lo || x->line > o->hi || !(o->classes & (1u << x->cls))) continue;
        s->v[k++] = *x;
    }
    s->n = k;
}

void mut_print_site(FILE *f, const struct mut_site *s)
{
    fprintf(f, "%zu:%zu %s '%s' -> '%s'\n", s->line, s->column, mut_class_name(s->cls), s->orig, s->repl);
}

void mut_json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}

void mut_json_site(FILE *f, const struct mut_site *s)
{
    fprintf(f, "{\"line\":%zu,\"col\":%zu,\"class\":\"%s\",\"orig\":", s->line, s->column, mut_class_name(s->cls));
    mut_json_str(f, s->orig);
    fputs(",\"repl\":", f);
    mut_json_str(f, s->repl);
    fputc('}', f);
}

/* ---- options ------------------------------------------------------------------------------- */
static bool parse_size(const char *s, size_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s || *end || s[0] == '-') return false;
    *out = (size_t)v;
    return true;
}

static bool parse_lines(const char *s, struct mut_opts *o)
{
    char buf[64];
    if (strlen(s) >= sizeof buf) return false;
    memcpy(buf, s, strlen(s) + 1);
    char *dash = strchr(buf, '-');
    if (!dash) return false;
    *dash = 0;
    return parse_size(buf, &o->lo) && parse_size(dash + 1, &o->hi) && o->lo >= 1 && o->lo <= o->hi;
}

/* The value of option `name` at argv[*i] (`--name v` or `--name=v`), or NULL when it is not that option. */
static const char *opt_value(int argc, char **argv, int *i, const char *name, bool *missing)
{
    size_t n = strlen(name);
    if (strncmp(argv[*i], name, n) != 0) return NULL;
    if (argv[*i][n] == '=') return argv[*i] + n + 1;
    if (argv[*i][n] != 0) return NULL;
    if (*i + 1 >= argc) { *missing = true; return NULL; }
    return argv[++*i];
}

static bool parse_number_opt(const char *v, size_t *out, size_t floor)
{
    return parse_size(v, out) && *out >= floor;
}

/* The options only `run` takes: 1 consumed, 0 not one of them, -1 a bad or missing value. */
static int parse_run_opt(int argc, char **argv, int *i, struct mut_opts *o)
{
    bool miss = false;
    const char *v;
    size_t n = 0;
    if ((v = opt_value(argc, argv, i, "--max", &miss))) return parse_number_opt(v, &o->max, 1) ? 1 : -1;
    if ((v = opt_value(argc, argv, i, "--timeout", &miss))) {
        if (!parse_number_opt(v, &n, 1) || n > 86400) return -1;
        o->timeout = (long)n;
        return 1;
    }
    if ((v = opt_value(argc, argv, i, "--build", &miss))) { o->build = v; return 1; }
    return miss ? -1 : 0;
}

/* One option at argv[*i]: 1 consumed, 0 not an option this command takes, -1 a bad value. */
static int parse_one(int argc, char **argv, int *i, bool run, struct mut_opts *o)
{
    bool miss = false;
    const char *v;
    if (strcmp(argv[*i], "--json") == 0) { o->json = true; return 1; }
    if ((v = opt_value(argc, argv, i, "--lines", &miss))) return parse_lines(v, o) ? 1 : -1;
    if ((v = opt_value(argc, argv, i, "--class", &miss))) return mut_class_parse(v, &o->classes) ? 1 : -1;
    if (miss) return -1;
    return run ? parse_run_opt(argc, argv, i, o) : 0;
}

static int parse_opts(int argc, char **argv, bool run, struct mut_opts *o)
{
    *o = (struct mut_opts){NULL, 0, SIZE_MAX, (1u << MUT_CLASS_COUNT) - 1, false, SIZE_MAX, 600, NULL, NULL};
    for (int i = 0; i < argc; i++) {
        if (run && strcmp(argv[i], "--") == 0) {
            o->test = argv + i + 1;
            break;
        }
        int r = parse_one(argc, argv, &i, run, o);
        if (r < 0) return usage("bad option value");
        if (r > 0) continue;
        if (argv[i][0] == '-' || o->file) return usage("unexpected argument");
        o->file = argv[i];
    }
    if (!o->file) return usage("no file");
    if (run && (!o->test || !o->test[0])) return usage("run needs a test command after --");
    return 0;
}

/* ---- list ---------------------------------------------------------------------------------- */
static int cmd_list(int argc, char **argv)
{
    struct mut_opts o;
    if (parse_opts(argc, argv, false, &o)) return 2;
    size_t len = 0;
    char path[4096];
    if (!mut_join_prefix(o.file, path, sizeof path)) { fprintf(stderr, "zcl-dev mutate: path too long: %s\n", o.file); return 2; }
    char *text = mut_read_file(path, &len);
    if (!text) { fprintf(stderr, "zcl-dev mutate: cannot read %s: %s\n", path, strerror(errno)); return 2; }
    struct mut_sites s = {0};
    if (!mut_enumerate(text, len, &s)) { free(text); fputs("zcl-dev mutate: out of memory\n", stderr); return 2; }
    mut_filter(&s, &o);
    if (o.json) {
        fputs("{\"file\":", stdout);
        mut_json_str(stdout, o.file);
        printf(",\"count\":%zu,\"sites\":[", s.n);
        for (size_t i = 0; i < s.n; i++) {
            if (i) fputc(',', stdout);
            mut_json_site(stdout, &s.v[i]);
        }
        puts("]}");
    } else {
        for (size_t i = 0; i < s.n; i++) mut_print_site(stdout, &s.v[i]);
        printf("sites %zu\n", s.n);
    }
    mut_sites_free(&s);
    free(text);
    return 0;
}

/* ---- selftest: the operators on inline text ------------------------------------------------ */
static int st_fail;
#define ST(cond) do { if (!(cond)) { fprintf(stderr, "selftest FAIL line %d: %s\n", __LINE__, #cond); st_fail++; } } while (0)

static size_t st_sites(const char *text, struct mut_sites *s)
{
    s->n = 0;
    ST(mut_enumerate(text, strlen(text), s));
    return s->n;
}

static bool st_has(const struct mut_sites *s, enum mut_class c, const char *orig, const char *repl)
{
    for (size_t i = 0; i < s->n; i++)
        if (s->v[i].cls == c && !strcmp(s->v[i].orig, orig) && !strcmp(s->v[i].repl, repl)) return true;
    return false;
}

static void selftest_masks(struct mut_sites *s)
{
    ST(st_sites("/* a < b && 1 */ // x == 2\n", s) == 0);
    ST(st_sites("const char *p = \"a < b 7\"; char c = '<';\n", s) == 0);
    ST(st_sites("#include <vector>\n#if X > 1\n#endif\n", s) == 0);
    ST(st_sites("auto r = R\"d(a < b; f(1);)d\";\n", s) == 0);
    ST(st_sites("std::vector<int> v; a<<1; b >> 2;\n", s) == 4); /* only the literals 1 and 2 */
    ST(st_sites("x[16]; int a[4];\n", s) == 0);
    ST(st_sites("double d = 1.5 + 0x10 + 0755 + 1e3;\n", s) == 0);
    ST(st_sites("long m = 1'000;\n", s) == 0);
    ST(st_sites("#define CAP 32\n", s) == 2);
    ST(st_sites("std::map<int, std::vector<int> > m;\n", s) == 0);
}

static void selftest_classes(struct mut_sites *s)
{
    st_sites("if (a < b && c >= d) x = n == 0;\n", s);
    ST(st_has(s, MUT_RELATIONAL, "<", "<=") && st_has(s, MUT_RELATIONAL, ">=", ">"));
    ST(st_has(s, MUT_RELATIONAL, "==", "!=") && st_has(s, MUT_LOGICAL, "&&", "||"));
    ST(st_has(s, MUT_BOUNDARY, "0", "1") && !st_has(s, MUT_BOUNDARY, "0", "-1"));
    st_sites("    return true;\n    return false;\n    return x;\n", s);
    ST(s->n == 2 && st_has(s, MUT_RETURN, "return true;", "return false;"));
    st_sites("    foo(a, b);\n    int x(3);\n    y = f(1);\n    return g();\n    obj.f(z); // c\n", s);
    ST(st_has(s, MUT_STATEMENT, "foo(a, b);", "(void)0;") && st_has(s, MUT_STATEMENT, "obj.f(z);", "(void)0;"));
    ST(!st_has(s, MUT_STATEMENT, "return g();", "(void)0;") && !st_has(s, MUT_STATEMENT, "y = f(1);", "(void)0;"));
    st_sites("    ::exit(1);\n    f(a,\n      b);\n", s);
    ST(st_has(s, MUT_STATEMENT, "::exit(1);", "(void)0;") && !st_has(s, MUT_STATEMENT, "f(a,", "(void)0;"));
}

static void selftest_apply(struct mut_sites *s)
{
    const char *t = "int f(int a) { return a > 9; }\n";
    st_sites(t, s);
    ST(s->n == 3 && s->v[0].line == 1 && s->v[0].column == 25 && s->v[1].offset == 26);
    size_t n = 0;
    char *img = mut_apply(t, strlen(t), &s->v[0], &n);
    ST(img && !strcmp(img, "int f(int a) { return a >= 9; }\n") && n == strlen(t) + 1);
    free(img);
    unsigned bits = 0;
    ST(mut_class_parse("return,boundary", &bits) && bits == ((1u << MUT_RETURN) | (1u << MUT_BOUNDARY)));
    ST(!mut_class_parse("arith", &bits) && !mut_class_parse("", &bits));
}

static int selftest(void)
{
    struct mut_sites s = {0};
    selftest_masks(&s);
    selftest_classes(&s);
    selftest_apply(&s);
    mut_sites_free(&s);
    if (st_fail) { fprintf(stderr, "zcl-dev-mutate selftest: %d failure(s)\n", st_fail); return 1; }
    puts("zcl-dev-mutate selftest: ok");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage(NULL);
    const char *cmd = argv[1];
    if (!strcmp(cmd, "--purpose")) {
        puts("mutation testing: apply one defect at a time to a C/C++ file, report mutants the tests miss");
        return 0;
    }
    if (!strcmp(cmd, "--selftest")) return selftest();
    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help")) { fputs(USAGE, stdout); return 0; }
    if (!strcmp(cmd, "list")) return cmd_list(argc - 2, argv + 2);
    if (!strcmp(cmd, "run")) {
        struct mut_opts o;
        if (parse_opts(argc - 2, argv + 2, true, &o)) return 2;
        return mut_run(&o);
    }
    if (!strcmp(cmd, "restore")) {
        if (argc != 3) return usage("restore takes one file");
        return mut_restore(argv[2]);
    }
    return usage("unknown command");
}
