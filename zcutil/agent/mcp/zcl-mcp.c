/* zcl-mcp: read-only MCP server for agents working on zclassicd. MIT, like the rest of zclassicd.
 *
 * Stdio, newline-delimited JSON-RPC 2.0, one request at a time, no threads, logs to stderr: the
 * same transport shape as `z23 mcp serve`. The protocol core is Z23's mcp_rpc.c, vendored verbatim
 * under zcutil/tools/vendor. Each tool maps validated arguments to a fixed argv of a zcutil/bin
 * tool and runs it through zcl-run (Z23's process_group_exec) under a 60 s rail: no shell, no
 * arbitrary command, nothing that spends, signs or pushes.
 *
 *   zcl-mcp --checkout=<toplevel> [--bindir=DIR] [--timeout=SECONDS]
 *
 * Plain C, libc only, gnu17 and C2x clean; also builds with x86_64-w64-mingw32-gcc.
 */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__MINGW32__) && !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#include "mcp/mcp_rpc.h"

#define SERVER_NAME "zcl-mcp"
#define SERVER_VERSION "0.1.0"
#define DEFAULT_TIMEOUT_S 60
#define MAX_FRAME (1u << 20)      /* one request line */
#define MAX_CAPTURE (256u * 1024) /* child output kept */
#define MAX_REPLY 32768u          /* one tools/call text, capped by mcp_reply_tool_text */
#define MAX_ARGV 48
#define MAX_TOKEN 200
#define MAX_PATHS 8

#ifdef _WIN32
#define EXE_SUFFIX ".exe"
#else
#define EXE_SUFFIX ""
#endif

struct argv_list {
    char *v[MAX_ARGV];
    int n;
};

struct ctx {
    const char *checkout;
    char bindir[1024];
    int timeout_s;
    struct argv_list av; /* built by the authority callback, run by the executor */
    char detail[512];
};

static void av_free(struct argv_list *a)
{
    for (int i = 0; i < a->n; i++) {
        free(a->v[i]);
        a->v[i] = NULL;
    }
    a->n = 0;
}

static bool av_add(struct argv_list *a, const char *s)
{
    if (a->n >= MAX_ARGV - 1) return false;
    char *d = strdup(s);
    if (!d) return false;
    a->v[a->n++] = d;
    a->v[a->n] = NULL; /* execv needs a NULL terminator, never a stale slot */
    return true;
}

static bool av_add_opt(struct argv_list *a, const char *name, long long n)
{
    char buf[64];
    snprintf(buf, sizeof buf, "--%s=%lld", name, n);
    return av_add(a, buf);
}

/* ---- argument validation -------------------------------------------------- */

static bool refuse(struct ctx *c, struct mcp_refusal *why, const char *code, const char *msg,
                   const char *what)
{
    snprintf(c->detail, sizeof c->detail, "%s", what ? what : "");
    why->code = code;
    why->message = msg;
    why->detail = what ? c->detail : NULL;
    why->did_you_mean_json = NULL;
    return false;
}

#define OOM(c, why) refuse((c), (why), "internal", "out of memory", NULL)

static bool charset_ok(unsigned char ch)
{
    return isalnum(ch) || ch == '_' || ch == '.' || ch == '/' || ch == ':' || ch == '=' || ch == ',' ||
           ch == '-';
}

/* A token is 1..MAX_TOKEN bytes of [A-Za-z0-9_./:=,-], never starting with '-' (option injection). */
static bool token_ok(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (!n || n > MAX_TOKEN || s[0] == '-') return false;
    for (size_t i = 0; i < n; i++)
        if (!charset_ok((unsigned char)s[i])) return false;
    return true;
}

/* A repository-relative path: a token, no ':' (drive letters), no leading '/', no "." or ".." part. */
static bool path_ok(const char *s)
{
    if (!token_ok(s) || s[0] == '/' || strchr(s, ':')) return false;
    const char *p = s;
    for (;;) {
        const char *e = strchr(p, '/');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n == 0 || (n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.')) return false;
        if (!e) return true;
        p = e + 1;
    }
}

static bool digits_ok(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (!n || n > 9) return false;
    for (size_t i = 0; i < n; i++)
        if (!isdigit((unsigned char)s[i])) return false;
    return true;
}

/* Optional string argument. 1 present and a string, 0 absent, -1 present with the wrong type. */
static int arg_str(const struct json_value *args, const char *key, const char **out)
{
    const struct json_value *v = json_get(args, key);
    if (!v || json_is_null(v)) return 0;
    if (v->type != JSON_STR || !v->val.s) return -1;
    *out = v->val.s;
    return 1;
}

static int arg_int(const struct json_value *args, const char *key, long long *out)
{
    const struct json_value *v = json_get(args, key);
    if (!v || json_is_null(v)) return 0;
    if (v->type != JSON_INT || v->val.i < 0 || v->val.i > 999999999) return -1;
    *out = v->val.i;
    return 1;
}

static bool paths_into(struct ctx *c, const struct json_value *args, struct mcp_refusal *why)
{
    const struct json_value *p = json_get(args, "paths");
    if (!p || p->type != JSON_ARR || json_size(p) < 1 || json_size(p) > MAX_PATHS)
        return refuse(c, why, "bad_argument", "paths must be an array of 1 to 8 strings", "paths");
    for (size_t i = 0; i < json_size(p); i++) {
        const struct json_value *e = json_at(p, i);
        if (!e || e->type != JSON_STR || !path_ok(e->val.s))
            return refuse(c, why, "bad_argument",
                          "a path must be repository-relative, [A-Za-z0-9_./=,-] only, no .. part",
                          e && e->type == JSON_STR ? e->val.s : "paths");
        if (!av_add(&c->av, e->val.s)) return OOM(c, why);
    }
    return true;
}

/* ---- tool builders ----------------------------------------------------------
 * Each fills c->av after the leading zcl-run slot with the tool and its arguments. */

static bool dev_base(struct ctx *c, struct mcp_refusal *why, const char *sub)
{
    char path[1100];
    snprintf(path, sizeof path, "%s/zcl-dev%s", c->bindir, EXE_SUFFIX);
    if (!av_add(&c->av, path) || !av_add(&c->av, "-C") || !av_add(&c->av, c->checkout) ||
        !av_add(&c->av, sub))
        return OOM(c, why);
    return true;
}

static bool dev_json(struct ctx *c, struct mcp_refusal *why, const char *sub)
{
    return dev_base(c, why, sub) && (av_add(&c->av, "--json") || OOM(c, why));
}

static bool build_guide(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    return dev_json(c, why, "guide") && paths_into(c, a, why);
}

static bool build_select(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    const char *base = NULL;
    int r = arg_str(a, "base", &base);
    if (r < 0 || (r == 1 && !token_ok(base)))
        return refuse(c, why, "bad_argument", "base must be a git ref, [A-Za-z0-9_./:=,-] only", "base");
    if (!dev_json(c, why, "select")) return false;
    return r != 1 || av_add(&c->av, base) ? true : OOM(c, why);
}

static bool build_tests(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    return dev_json(c, why, "tests") && paths_into(c, a, why);
}

static bool code_flag_ok(const char *s)
{
    if (!strcmp(s, "--tests")) return true;
    if (!strncmp(s, "--depth=", 8) || !strncmp(s, "--after=", 8)) return digits_ok(s + 8);
    if (!strncmp(s, "--since=", 8)) {
        size_t n = strlen(s + 8);
        if (!n || n > 6) return false;
        for (size_t i = 0; i + 1 < n; i++)
            if (!isdigit((unsigned char)s[8 + i])) return false;
        char last = s[8 + n - 1];
        return isdigit((unsigned char)last) || strchr("dhwm", last) != NULL;
    }
    return false;
}

/* positional arity and kind per sub: P path, N name (identifier-ish token) */
static const struct {
    const char *sub;
    const char *shape;
} code_subs[] = {
    {"map", ""},   {"owner", "P"}, {"impact", "P"}, {"file", "P"},   {"sym", "N"},
    {"refs", "N"}, {"cost", "P"},  {"recent", ""},  {"body", "PN"},
};

static bool build_code(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    const char *sub = NULL;
    if (arg_str(a, "sub", &sub) != 1) return refuse(c, why, "bad_argument", "sub is required", "sub");
    const char *shape = NULL;
    for (size_t i = 0; i < sizeof code_subs / sizeof *code_subs; i++)
        if (!strcmp(code_subs[i].sub, sub)) shape = code_subs[i].shape;
    if (!shape) return refuse(c, why, "bad_argument", "unknown sub", sub);
    const struct json_value *args = json_get(a, "args");
    if (args && (args->type != JSON_ARR || json_size(args) > 5))
        return refuse(c, why, "bad_argument", "args must be an array of at most 5 strings", "args");
    if (!dev_base(c, why, "code") || !av_add(&c->av, sub)) return false;
    size_t pos = 0, want = strlen(shape);
    for (size_t i = 0; args && i < json_size(args); i++) {
        const struct json_value *e = json_at(args, i);
        if (!e || e->type != JSON_STR || !e->val.s)
            return refuse(c, why, "bad_argument", "every arg must be a string", "args");
        const char *s = e->val.s;
        if (s[0] == '-') {
            if (!code_flag_ok(s))
                return refuse(c, why, "bad_argument", "allowed flags: --tests --depth=N --since=Nd --after=N", s);
        } else {
            if (pos >= want) return refuse(c, why, "bad_argument", "too many positional arguments", sub);
            if (!(shape[pos] == 'P' ? path_ok(s) : token_ok(s)))
                return refuse(c, why, "bad_argument", "argument must be [A-Za-z0-9_./:=,-] only, and a path has no .. part", s);
            pos++;
        }
        if (!av_add(&c->av, s)) return OOM(c, why);
    }
    if (pos != want) return refuse(c, why, "bad_argument", "missing positional argument", sub);
    return av_add(&c->av, "--json") ? true : OOM(c, why);
}

static bool build_wiki(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    const char *topic = NULL;
    long long after = 0;
    int rt = arg_str(a, "topic", &topic), ra = arg_int(a, "after", &after);
    if (rt < 0 || (rt == 1 && topic[0] && !path_ok(topic)))
        return refuse(c, why, "bad_argument", "topic must be a relative path, [A-Za-z0-9_./=,-] only", "topic");
    if (ra < 0) return refuse(c, why, "bad_argument", "after must be a non-negative integer", "after");
    if (!dev_base(c, why, "wiki")) return false;
    if (rt == 1 && topic[0] && !av_add(&c->av, topic)) return OOM(c, why);
    if (!av_add(&c->av, "--json")) return OOM(c, why);
    return ra != 1 || av_add_opt(&c->av, "after", after) ? true : OOM(c, why);
}

static bool build_read(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    const char *path = NULL;
    long long off = 0, bytes = 0;
    int rp = arg_str(a, "path", &path), ro = arg_int(a, "offset", &off), rb = arg_int(a, "bytes", &bytes);
    if (rp != 1 || !path_ok(path))
        return refuse(c, why, "bad_argument", "path must be repository-relative, no .. part", "path");
    if (ro < 0 || rb < 0 || (rb == 1 && bytes < 1))
        return refuse(c, why, "bad_argument", "offset must be >= 0 and bytes >= 1", "offset/bytes");
    if (!dev_base(c, why, "read") || !av_add(&c->av, path) || !av_add(&c->av, "--json")) return false;
    if (ro == 1 && !av_add_opt(&c->av, "offset", off)) return OOM(c, why);
    if (rb == 1 && !av_add_opt(&c->av, "bytes", bytes)) return OOM(c, why);
    return true;
}

static bool build_lessons(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    const char *q = NULL;
    if (arg_str(a, "q", &q) != 1 || !q[0] || strlen(q) > 400)
        return refuse(c, why, "bad_argument", "q must be 1 to 8 words", "q");
    if (!dev_base(c, why, "lessons") || !av_add(&c->av, "find")) return false;
    char words[404];
    snprintf(words, sizeof words, "%s", q);
    int n = 0;
    for (char *w = strtok(words, " \t"); w; w = strtok(NULL, " \t")) {
        if (++n > 8 || !token_ok(w))
            return refuse(c, why, "bad_argument",
                          "q is at most 8 words of [A-Za-z0-9_./:=,-], none starting with '-'", w);
        if (!av_add(&c->av, w)) return OOM(c, why);
    }
    return n ? true : refuse(c, why, "bad_argument", "q must hold a word", "q");
}

static bool build_know(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    const char *t = NULL;
    if (arg_str(a, "term", &t) != 1 || !token_ok(t))
        return refuse(c, why, "bad_argument", "term must be [A-Za-z0-9_./:=,-] only", "term");
    if (!dev_base(c, why, "know") || !av_add(&c->av, "--json") || !av_add(&c->av, t)) return false;
    return true;
}

static const char *const lint_rules[] = {
    "no-new-jq",  "no-new-bash",  "banned-str", "md-links",    "vendor",    "no-python",      "filesize",
    "complexity", "long-functions", "warnsupp", "doc-claims",  "doc-paths", "version-facts",  "victory",
    "secretlog",  "testiso",      "shellport",  "wallclock",   "consensus-seal", NULL,
};

static bool build_lint(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    const char *rule = NULL;
    bool known = false;
    if (arg_str(a, "rule", &rule) == 1)
        for (int i = 0; lint_rules[i]; i++) known |= !strcmp(lint_rules[i], rule);
    if (!known) return refuse(c, why, "bad_argument", "rule is not a read-only zcl-lint rule", rule);
    char path[1100];
    snprintf(path, sizeof path, "%s/zcl-lint%s", c->bindir, EXE_SUFFIX);
    if (!av_add(&c->av, path) || !av_add(&c->av, "--root") || !av_add(&c->av, c->checkout) ||
        !av_add(&c->av, rule))
        return OOM(c, why);
    return true;
}

static bool build_receipt(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    const char *step = NULL, *dir = NULL;
    int rs = arg_str(a, "step", &step), rd = arg_str(a, "dir", &dir);
    if (rs != 1 || !token_ok(step) || strchr(step, '/'))
        return refuse(c, why, "bad_argument", "step must be a ci step name", "step");
    if (rd < 0 || (rd == 1 && !path_ok(dir)))
        return refuse(c, why, "bad_argument", "dir must be repository-relative, no .. part", "dir");
    if (!dev_base(c, why, "receipt") || !av_add(&c->av, step)) return false;
    return rd != 1 || av_add(&c->av, dir) ? true : OOM(c, why);
}

static bool build_doctor(struct ctx *c, const struct json_value *a, struct mcp_refusal *why)
{
    (void)a;
    return dev_base(c, why, "doctor") && (av_add(&c->av, "--json") || OOM(c, why));
}

/* ---- tool table ------------------------------------------------------------- */

typedef bool (*builder_fn)(struct ctx *, const struct json_value *, struct mcp_refusal *);

static const struct mcp_tool tools[] = {
#define ZCL_TOOL(name, builder, desc, schema) {name, desc, schema, true},
#include "tools.def"
#undef ZCL_TOOL
};
static const builder_fn builders[] = {
#define ZCL_TOOL(name, builder, desc, schema) builder,
#include "tools.def"
#undef ZCL_TOOL
};

/* ---- bounded child execution -------------------------------------------------- */

struct run_result {
    int code;       /* exit status, -1 when not started, -2 on timeout */
    bool truncated; /* output capped at MAX_CAPTURE */
};

static bool cap_append(struct mcp_buf *out, const char *p, size_t n, struct run_result *r)
{
    if (out->len + n > MAX_CAPTURE) {
        n = MAX_CAPTURE - out->len;
        r->truncated = true;
    }
    mcp_buf_put(out, p, n);
    return !r->truncated;
}

#ifdef _WIN32
/* One command line; every token passed validation, so only spaces in bindir or checkout can need quotes. */
static bool win_cmdline(char *out, size_t cap, char *const *argv)
{
    size_t used = 0;
    for (int i = 0; argv[i]; i++) {
        bool q = !argv[i][0] || strpbrk(argv[i], " \t");
        int w = snprintf(out + used, cap - used, "%s%s%s%s", i ? " " : "", q ? "\"" : "", argv[i],
                         q ? "\"" : "");
        if (w < 0 || (size_t)w >= cap - used) return false;
        used += (size_t)w;
    }
    return true;
}

static void run_child(char *const *argv, int timeout_s, struct mcp_buf *out, struct run_result *r)
{
    char cmd[32768];
    r->code = -1;
    if (!win_cmdline(cmd, sizeof cmd, argv)) return;
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    STARTUPINFOA si = {0};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(wr);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) {
        CloseHandle(rd);
        return;
    }
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)timeout_s * 1000u;
    for (;;) {
        DWORD avail = 0;
        char buf[4096];
        if (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail) {
            DWORD got = 0;
            if (ReadFile(rd, buf, sizeof buf < avail ? (DWORD)sizeof buf : avail, &got, NULL) && got &&
                !cap_append(out, buf, got, r)) {
                TerminateProcess(pi.hProcess, 1);
                break;
            }
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break;
        if (GetTickCount64() >= deadline) {
            /* zcl-run holds a kill-on-close job object: ending it reaps the whole tree */
            TerminateProcess(pi.hProcess, 1);
            r->code = -2;
            break;
        }
        Sleep(10);
    }
    DWORD ec = 1;
    WaitForSingleObject(pi.hProcess, 5000);
    GetExitCodeProcess(pi.hProcess, &ec);
    if (r->code != -2) r->code = (int)ec;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(rd);
}
#else
static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void run_child(char *const *argv, int timeout_s, struct mcp_buf *out, struct run_result *r)
{
    int fd[2];
    r->code = -1;
    if (pipe(fd)) return;
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]);
        close(fd[1]);
        return;
    }
    if (pid == 0) {
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) dup2(nul, 0);
        dup2(fd[1], 1);
        dup2(fd[1], 2);
        close(fd[0]);
        close(fd[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(fd[1]);
    long long deadline = now_ms() + (long long)timeout_s * 1000;
    bool killed = false;
    for (;;) {
        long long left = deadline - now_ms();
        if (left <= 0) {
            r->code = -2;
            killed = true;
            break;
        }
        struct pollfd p = {fd[0], POLLIN, 0};
        int pr = poll(&p, 1, left > 1000 ? 1000 : (int)left);
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) break;
        if (pr == 0) continue;
        char buf[4096];
        ssize_t got = read(fd[0], buf, sizeof buf);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break; /* EOF: every holder of the pipe has exited */
        if (!cap_append(out, buf, (size_t)got, r)) {
            killed = true;
            break;
        }
    }
    if (killed) { /* zcl-run called setsid, so the group id is the child pid */
        kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
    }
    close(fd[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
    if (r->code != -2) r->code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
}
#endif

/* ---- endpoint callbacks ------------------------------------------------------- */

static bool authority(void *vctx, const struct mcp_tool *tool, const struct json_value *args,
                      struct mcp_refusal *why)
{
    struct ctx *c = vctx;
    av_free(&c->av);
    char run[1100];
    snprintf(run, sizeof run, "%s/zcl-run%s", c->bindir, EXE_SUFFIX);
    if (!av_add(&c->av, run)) return OOM(c, why);
    if (args->type != JSON_OBJ) {
        av_free(&c->av);
        return refuse(c, why, "bad_argument", "arguments must be an object", NULL);
    }
    (void)refuse(c, why, "internal", "could not build the command", NULL); /* default if a builder fails silently */
    if (!builders[tool - tools](c, args, why)) {
        av_free(&c->av);
        return false;
    }
    return true;
}

static void put_failure(struct mcp_buf *text, const struct run_result *r, int timeout_s, const struct mcp_buf *out)
{
    char msg[96];
    if (r->code == -2) snprintf(msg, sizeof msg, "the tool did not finish within %d s and was killed", timeout_s);
    else if (r->code == -1) snprintf(msg, sizeof msg, "the tool could not be started");
    else snprintf(msg, sizeof msg, "the tool exited with status %d", r->code);
    mcp_buf_str(text, "{\"ok\":false,\"error\":{\"code\":\"");
    mcp_buf_str(text, r->code == -2 ? "timeout" : r->code == -1 ? "not_started" : "tool_failed");
    mcp_buf_str(text, "\",\"message\":");
    mcp_buf_json_str(text, msg);
    mcp_buf_str(text, ",\"detail\":");
    mcp_buf_json_str_n(text, out->p ? out->p : "", out->len);
    mcp_buf_str(text, "}}");
}

static bool executor(void *vctx, const struct mcp_tool *tool, const struct json_value *args,
                     struct mcp_buf *text, bool *is_error)
{
    struct ctx *c = vctx;
    (void)tool;
    (void)args;
    struct mcp_buf out;
    struct run_result r = {0, false};
    mcp_buf_init(&out);
    if (!c->av.n) return false;
    run_child(c->av.v, c->timeout_s, &out, &r);
    av_free(&c->av);
    if (out.oom) {
        mcp_buf_free(&out);
        return false;
    }
    if (r.code == 0 || r.code == 1) { /* 1 is a finding, still a result */
        mcp_buf_put(text, out.p ? out.p : "", out.len);
        if (r.truncated) mcp_buf_str(text, "\n[output capped at 262144 bytes]");
        *is_error = false;
    } else {
        put_failure(text, &r, c->timeout_s, &out);
        *is_error = true;
    }
    mcp_buf_free(&out);
    return !text->oom;
}

/* ---- main --------------------------------------------------------------------- */

static void exe_dir(const char *argv0, char *out, size_t cap)
{
    char path[1024] = "";
#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, path, sizeof path);
    if (!n || n >= sizeof path) snprintf(path, sizeof path, "%s", argv0);
#else
    ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);
    if (n > 0) path[n] = 0;
    else snprintf(path, sizeof path, "%s", argv0);
#endif
    char *s = strrchr(path, '/');
#ifdef _WIN32
    char *b = strrchr(path, '\\');
    if (b && (!s || b > s)) s = b;
#endif
    if (s) *s = 0;
    else snprintf(path, sizeof path, ".");
    snprintf(out, cap, "%s", path);
}

static bool is_dir(const char *p)
{
    struct stat st;
    return !stat(p, &st) && S_ISDIR(st.st_mode);
}

/* Read one newline-terminated frame into line. 1 frame, 0 end of input, 2 frame over the cap (drained). */
static int read_frame(struct mcp_buf *line)
{
    line->len = 0;
    bool over = false;
    for (int ch; (ch = fgetc(stdin)) != EOF;) {
        if (ch == '\n') return over ? 2 : 1;
        if (over) continue;
        if (line->len >= MAX_FRAME) {
            over = true;
            continue;
        }
        char b = (char)ch;
        mcp_buf_put(line, &b, 1);
    }
    return over ? 2 : line->len ? 1 : 0;
}

static void send_frame(const struct mcp_buf *b)
{
    fwrite(b->p, 1, b->len, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static bool handle_frame(const struct mcp_endpoint *ep, struct mcp_buf *line, int got)
{
    struct mcp_buf reply;
    mcp_buf_init(&reply);
    if (got == 2) {
        mcp_reply_error(&reply, NULL, MCP_ERR_INVALID_REQUEST, "request frame exceeds 1 MiB");
        send_frame(&reply);
        mcp_buf_free(&reply);
        return true;
    }
    size_t n = line->len, s = 0;
    while (n && line->p[n - 1] == '\r') n--;
    while (s < n && (line->p[s] == ' ' || line->p[s] == '\t')) s++;
    bool alive = true;
    if (s < n) {
        enum mcp_dispatch_result d = mcp_dispatch(ep, line->p + s, n - s, &reply);
        if (d == MCP_FATAL || reply.oom) {
            fprintf(stderr, "zcl-mcp: out of memory, stopping\n");
            alive = false;
        } else if (d == MCP_REPLY) {
            send_frame(&reply);
        }
    }
    mcp_buf_free(&reply);
    return alive;
}

int main(int argc, char **argv)
{
    struct ctx c = {0};
    c.timeout_s = DEFAULT_TIMEOUT_S;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--checkout=", 11)) c.checkout = argv[i] + 11;
        else if (!strncmp(argv[i], "--bindir=", 9)) snprintf(c.bindir, sizeof c.bindir, "%s", argv[i] + 9);
        else if (!strncmp(argv[i], "--timeout=", 10) && digits_ok(argv[i] + 10) && atoi(argv[i] + 10) > 0)
            c.timeout_s = atoi(argv[i] + 10);
        else if (!strcmp(argv[i], "--purpose")) {
            puts("read-only MCP server for agents: guide, select, tests, code, wiki, read, lessons, know, lint, receipt, doctor");
            return 0;
        } else {
            fprintf(stderr, "usage: zcl-mcp --checkout=<toplevel> [--bindir=DIR] [--timeout=SECONDS]\n");
            return 2;
        }
    }
    if (!c.checkout || !c.checkout[0]) {
        fprintf(stderr, "zcl-mcp: --checkout=<toplevel> is required\n");
        return 2;
    }
    if (!is_dir(c.checkout)) {
        fprintf(stderr, "zcl-mcp: --checkout=%s is not a directory\n", c.checkout);
        return 2;
    }
    if (!c.bindir[0]) exe_dir(argv[0], c.bindir, sizeof c.bindir);
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    struct mcp_endpoint ep = {0};
    ep.server_name = SERVER_NAME;
    ep.server_version = SERVER_VERSION;
    ep.instructions =
        "Read-only tools for the zclassicd source tree. Start with zcl_guide on the paths you will edit, "
        "then zcl_code (map, owner, impact, body) instead of reading large files, and zcl_tests for the "
        "focused test set. Nothing here runs a command, spends, signs or pushes.";
    ep.tools = tools;
    ep.tool_count = sizeof tools / sizeof *tools;
    ep.authority = authority;
    ep.call = executor;
    ep.ctx = &c;
    ep.max_reply_bytes = MAX_REPLY;
    fprintf(stderr, "zcl-mcp: serving checkout=%s bindir=%s tools=%zu\n", c.checkout, c.bindir, ep.tool_count);

    struct mcp_buf line;
    mcp_buf_init(&line);
    int rc = 0, got;
    while ((got = read_frame(&line)) != 0)
        if (!handle_frame(&ep, &line, got)) {
            rc = 1;
            break;
        }
    mcp_buf_free(&line);
    av_free(&c.av);
    return rc;
}
