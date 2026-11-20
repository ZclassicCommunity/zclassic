/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * jsonq — path query over a JSON document on stdin.
 *
 * Python is banned in this repository. Shell scripts extract JSON with
 * grep/sed when the document is flat; nested RPC and native-command
 * envelopes need a real parser. This is that parser, built on the in-tree
 * zjsonp pull parser (allocation-free, depth-bounded). No jq, no Python.
 *
 *   printf '%s' "$json" | jsonq get data.plan_id
 *   printf '%s' "$json" | jsonq has result.ok
 *   printf '%s' "$json" | jsonq eq ok true
 *   printf '%s' "$json" | jsonq count result
 *   printf '%s' "$json" | jsonq raw data
 *   printf '%s' "$json" | jsonq type state.tracked
 *   printf '%s' "$json" | jsonq keys data
 *   printf '%s' "$json" | jsonq key-count data usage
 *   printf '%s' "$json" | jsonq unwrap
 *
 * PATH: dotted keys and [index] from the document root. Leading '.' is
 * optional. Example: result.items[1].id
 *
 * get/raw print the value and exit 0. Missing path exits 1. Malformed
 * JSON or usage exits 2. unwrap prints result when the envelope is a
 * JSON-RPC object with a null/absent error; a present error exits 2.
 * key-count counts direct decoded keys exactly matching the literal KEY
 * argument. Zero matches succeeds; a selected non-object exits 1.
 */
#include "multicall.h"
#include "zjsonp/zjsonp.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

enum {
    JSONQ_MAX_INPUT = 16 << 20,
    MAX_SEGS = 32,
    MAX_KEY = 256,
    DECODE_CAP = 1 << 16,
    MAX_LINE_PATHS = 32
};

typedef enum { SEG_KEY = 0, SEG_INDEX = 1 } seg_kind;

typedef struct {
    seg_kind kind;
    char key[MAX_KEY];
    size_t key_len;
    int index;
} path_seg;

typedef struct {
    bool is_array;
    int index;
    char key[MAX_KEY];
    size_t key_len;
    bool have_key;
} frame;

typedef enum {
    CMD_GET = 0,
    CMD_RAW,
    CMD_TYPE,
    CMD_HAS,
    CMD_EQ,
    CMD_COUNT,
    CMD_KEYS,
    CMD_KEY_COUNT,
    CMD_UNWRAP,
    CMD_LINES,
    CMD_LINES_CHECK
} cmd_kind;

static char g_input[JSONQ_MAX_INPUT];
static char g_decode[DECODE_CAP];
static path_seg g_segs[MAX_SEGS];
static int g_nsegs;
static frame g_stack[ZJRP_MAX_DEPTH];
static int g_depth;

static void usage(void)
{
    fputs("usage: jsonq get|raw|type|has|eq|count|keys PATH\n"
          "       jsonq key-count PATH KEY\n"
          "       jsonq unwrap\n"
          "       jsonq lines PATH [PATH ...] (1-32 strings without CR/LF/NUL)\n"
          "Read one JSON document from stdin.\n",
          stderr);
}

static int parse_array_index_digits(const char **cursor)
{
    const char *p = *cursor;
    int idx = 0;
    while (*p >= '0' && *p <= '9') {
        int digit = *p - '0';
        if (idx > (INT_MAX - digit) / 10) {
            fprintf(stderr, "jsonq: array index exceeds maximum %d\n", INT_MAX);
            return -1;
        }
        idx = idx * 10 + digit;
        p++;
    }
    *cursor = p;
    return idx;
}

static bool path_denotes_root(const char *p)
{
    return !p || !*p || (p[0] == '.' && p[1] == '\0');
}

/* Parses one "[index]" segment starting at '[', stores it in s and
 * advances the cursor past the ']' and any following '.'. Returns 0 on
 * success, 1 when no digit follows '[', 2 when ']' is missing, or -1
 * when parse_array_index_digits already reported the failure. */
static int parse_index_segment(const char **cursor, path_seg *s)
{
    const char *p = *cursor + 1;
    if (*p < '0' || *p > '9')
        return 1;
    int idx = parse_array_index_digits(&p);
    if (idx < 0)
        return -1;
    if (*p != ']')
        return 2;
    p++;
    s->kind = SEG_INDEX;
    s->index = idx;
    s->key_len = 0;
    if (*p == '.')
        p++;
    *cursor = p;
    return 0;
}

/* Parses one dotted key segment, stores it in s and advances the cursor
 * past the key and any following '.'. Returns 0 on success, or 1 when
 * the segment is empty or oversized. */
static int parse_key_segment(const char **cursor, path_seg *s)
{
    const char *p = *cursor;
    const char *start = p;
    while (*p && *p != '.' && *p != '[')
        p++;
    size_t n = (size_t)(p - start);
    if (n == 0 || n >= MAX_KEY)
        return 1;
    s->kind = SEG_KEY;
    memcpy(s->key, start, n);
    s->key[n] = '\0';
    s->key_len = n;
    s->index = 0;
    if (*p == '.')
        p++;
    *cursor = p;
    return 0;
}

static int parse_path(const char *path)
{
    const char *p = path;
    g_nsegs = 0;
    if (path_denotes_root(p))
        return 0;
    if (*p == '.')
        p++;
    while (*p) {
        if (g_nsegs >= MAX_SEGS) {
            fputs("jsonq: path too deep\n", stderr);
            return -1;
        }
        path_seg *s = &g_segs[g_nsegs];
        if (*p == '[') {
            int rc = parse_index_segment(&p, s);
            if (rc == 1) {
                fputs("jsonq: expected array index\n", stderr);
                return -1;
            }
            if (rc == 2) {
                fputs("jsonq: missing ]\n", stderr);
                return -1;
            }
            if (rc < 0)
                return -1;
            g_nsegs++;
            continue;
        }
        if (parse_key_segment(&p, s) != 0) {
            fputs("jsonq: empty or oversized path segment\n", stderr);
            return -1;
        }
        g_nsegs++;
    }
    return 0;
}

static bool decode_key(const char *text, const zjsonp_event *ev,
                       char *out, size_t cap, size_t *len_out)
{
    size_t n = zjsonp_str_decode(text, ev, out, cap);
    if (n == SIZE_MAX || n >= cap)
        return false;
    out[n] = '\0';
    *len_out = n;
    return true;
}

static bool selector_eq(const frame *fr, const path_seg *want)
{
    if (fr->is_array) {
        if (want->kind != SEG_INDEX)
            return false;
        return fr->index == want->index;
    }
    if (want->kind != SEG_KEY)
        return false;
    if (!fr->have_key)
        return false;
    return fr->key_len == want->key_len &&
           memcmp(fr->key, want->key, fr->key_len) == 0;
}

static int skip_container(zjsonp *p, unsigned open_depth)
{
    for (;;) {
        zjsonp_event ev;
        zjsonp_status st = zjsonp_next(p, &ev);
        if (st != ZJRP_OK)
            return -1;
        if ((ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE) &&
            p->depth < open_depth)
            return 0;
    }
}

static const char *kind_type(zjsonp_event_kind k)
{
    switch (k) {
    case ZJRP_OBJ_OPEN:
        return "object";
    case ZJRP_ARR_OPEN:
        return "array";
    case ZJRP_STR:
        return "string";
    case ZJRP_NUM:
        return "number";
    case ZJRP_BOOL:
        return "bool";
    case ZJRP_NULL:
        return "null";
    default:
        return "?";
    }
}

static bool decoded_text_equals(const char *text, size_t length, const char *expected)
{
    return length == strlen(expected) && memcmp(text, expected, length) == 0;
}

static int emit_scalar(const char *text, const zjsonp_event *ev, bool raw)
{
    if (ev->kind == ZJRP_STR) {
        if (raw) {
            if (ev->off == 0)
                return -1;
            fwrite(text + ev->off - 1, 1, ev->len + 2, stdout);
            fputc('\n', stdout);
            return 0;
        }
        size_t n = zjsonp_str_decode(text, ev, g_decode, sizeof g_decode);
        if (n == SIZE_MAX || n >= sizeof g_decode)
            return -1;
        fwrite(g_decode, 1, n, stdout);
        fputc('\n', stdout);
        return 0;
    }
    fwrite(text + ev->off, 1, ev->len, stdout);
    fputc('\n', stdout);
    return 0;
}

static int emit_raw_range(const char *text, size_t start, size_t end)
{
    if (end < start || end > JSONQ_MAX_INPUT)
        return -1;
    fwrite(text + start, 1, end - start, stdout);
    fputc('\n', stdout);
    return 0;
}

static bool is_close_event(const zjsonp *p, const zjsonp_event *ev,
                           unsigned open_depth)
{
    return (ev->kind == ZJRP_OBJ_CLOSE || ev->kind == ZJRP_ARR_CLOSE) &&
           p->depth < open_depth;
}

static bool is_scalar_event(const zjsonp_event *ev)
{
    return ev->kind == ZJRP_STR || ev->kind == ZJRP_NUM ||
           ev->kind == ZJRP_BOOL || ev->kind == ZJRP_NULL;
}

/* Prints the element count of an array or the key count of an object.
 * Only DIRECT members count: a nested container is one member for an
 * array, and its keys are never members of the surrounding object, so
 * every nested container is skipped whole. */
static int count_container(zjsonp *p, const zjsonp_event *open,
                           unsigned open_depth)
{
    int n = 0;
    if (open->kind != ZJRP_ARR_OPEN && open->kind != ZJRP_OBJ_OPEN)
        return 2;
    for (;;) {
        zjsonp_event ev;
        zjsonp_status st = zjsonp_next(p, &ev);
        if (st != ZJRP_OK)
            return 2;
        if (is_close_event(p, &ev, open_depth)) {
            printf("%d\n", n);
            return 0;
        }
        if (ev.kind == ZJRP_OBJ_OPEN || ev.kind == ZJRP_ARR_OPEN) {
            if (open->kind == ZJRP_ARR_OPEN)
                n++; /* the container itself is one array element */
            if (skip_container(p, p->depth) != 0)
                return 2;
        } else if (open->kind == ZJRP_OBJ_OPEN) {
            if (ev.kind == ZJRP_KEY)
                n++; /* a member key; its value events are not members */
        } else if (is_scalar_event(&ev)) {
            n++;
        }
    }
}

/* List direct decoded keys, or count exact byte matches when wanted is set.
 * Nested containers are skipped whole; key delimiters never affect counting. */
static int keys_container(zjsonp *p, const char *text,
                          const zjsonp_event *open, unsigned open_depth,
                          const char *wanted)
{
    if (open->kind != ZJRP_OBJ_OPEN)
        return 1;
    size_t matches = 0, wanted_len = wanted ? strlen(wanted) : 0;
    for (;;) {
        zjsonp_event ev;
        zjsonp_status st = zjsonp_next(p, &ev);
        if (st != ZJRP_OK)
            return 2;
        if (is_close_event(p, &ev, open_depth)) {
            if (wanted) printf("%zu\n", matches);
            return 0;
        }
        if (ev.kind == ZJRP_OBJ_OPEN || ev.kind == ZJRP_ARR_OPEN) {
            if (skip_container(p, p->depth) != 0)
                return 2;
            continue;
        }
        if (ev.kind == ZJRP_KEY) {
            size_t kn = 0;
            if (!decode_key(text, &ev, g_decode, sizeof g_decode, &kn))
                return 2;
            if (wanted) {
                if (kn == wanted_len && memcmp(g_decode, wanted, kn) == 0)
                    matches++;
            } else {
                fwrite(g_decode, 1, kn, stdout);
                fputc('\n', stdout);
            }
        }
    }
}

static int finish_matched_container(zjsonp *p, const char *text,
                                    const zjsonp_event *open, cmd_kind cmd,
                                    const char *eq)
{
    if (cmd == CMD_LINES || cmd == CMD_LINES_CHECK) return 1;
    unsigned open_depth = p->depth;
    size_t start = open->off;
    switch (cmd) {
    case CMD_HAS:
        return 0;
    case CMD_TYPE:
        puts(kind_type(open->kind));
        return 0;
    case CMD_EQ:
        return 1;
    case CMD_GET:
    case CMD_RAW:
        if (skip_container(p, open_depth) != 0)
            return 2;
        return emit_raw_range(text, start, p->pos);
    case CMD_COUNT:
        return count_container(p, open, open_depth);
    case CMD_KEYS:
        return keys_container(p, text, open, open_depth, NULL);
    case CMD_KEY_COUNT:
        return keys_container(p, text, open, open_depth, eq);
    default:
        return 2;
    }
}

static int scalar_equals(const char *text, const zjsonp_event *ev, const char *eq)
{
    if (!eq) return 2;
    if (ev->kind == ZJRP_STR) {
        size_t n = zjsonp_str_decode(text, ev, g_decode, sizeof g_decode);
        if (n == SIZE_MAX || n >= sizeof g_decode) return 2;
        g_decode[n] = 0;
        return decoded_text_equals(g_decode, n, eq) ? 0 : 1;
    }
    if (ev->len >= DECODE_CAP) return 2;
    memcpy(g_decode, text + ev->off, ev->len);
    g_decode[ev->len] = 0;
    return strcmp(g_decode, eq) == 0 ? 0 : 1;
}

static int string_line(const char *text, const zjsonp_event *ev, bool emit)
{
    if (ev->kind != ZJRP_STR) return 1;
    size_t n = zjsonp_str_decode(text, ev, g_decode, sizeof g_decode);
    if (n == SIZE_MAX || n >= sizeof g_decode) return 2;
    if (memchr(g_decode, '\0', n) || memchr(g_decode, '\r', n) ||
        memchr(g_decode, '\n', n)) return 2;
    if (emit && (fwrite(g_decode, 1, n, stdout) != n || fputc('\n', stdout) == EOF))
        return 2;
    return 0;
}

static int handle_matched_scalar(const char *text, const zjsonp_event *ev,
                                 cmd_kind cmd, const char *eq)
{
    if (cmd == CMD_LINES || cmd == CMD_LINES_CHECK)
        return string_line(text, ev, cmd == CMD_LINES);
    if (cmd == CMD_HAS)
        return 0;
    if (cmd == CMD_TYPE) {
        puts(kind_type(ev->kind));
        return 0;
    }
    if (cmd == CMD_COUNT || cmd == CMD_KEYS || cmd == CMD_KEY_COUNT)
        return 1;
    if (cmd == CMD_GET)
        return emit_scalar(text, ev, false);
    if (cmd == CMD_RAW)
        return emit_scalar(text, ev, true);
    if (cmd == CMD_EQ) return scalar_equals(text, ev, eq);
    return 2;
}

static bool value_is_prefix_or_exact(int matched, bool *exact)
{
    if (matched == g_nsegs) {
        *exact = true;
        return true;
    }
    if (matched < g_nsegs) {
        *exact = false;
        return true;
    }
    return false;
}

static int child_match_rank(const frame *parent, int matched, bool *exact)
{
    if (matched >= g_nsegs)
        return -1;
    if (!selector_eq(parent, &g_segs[matched]))
        return 0;
    return value_is_prefix_or_exact(matched + 1, exact) ? 1 : 0;
}

static void bump_array(void)
{
    if (g_depth <= 0)
        return;
    frame *fr = &g_stack[g_depth - 1];
    if (fr->is_array)
        fr->index++;
    else
        fr->have_key = false;
}

/* Sentinels for walk's helpers: WALK_CONTINUE means the walk must keep
 * consuming events, RANK_INVALID means the frame stack is corrupt. The
 * values cannot collide with walk's exit codes (-1, 0, 1, 2) or with the
 * rank values child_match_rank produces (-1, 0, 1). */
enum { WALK_CONTINUE = -2, RANK_INVALID = INT_MIN };

/* Consumes the events that only move the frame stack: a key names the
 * value the innermost frame awaits, and a close pops that frame. Returns
 * 0 when the event was consumed, 1 when it is not a stack event, and 2
 * on a structure error. */
static int handle_stack_event(const char *text, const zjsonp_event *ev,
                              int *matched)
{
    if (ev->kind == ZJRP_KEY) {
        if (g_depth <= 0)
            return 2;
        frame *fr = &g_stack[g_depth - 1];
        if (!decode_key(text, ev, fr->key, sizeof fr->key, &fr->key_len))
            return 2;
        fr->have_key = true;
        return 0;
    }
    if (ev->kind == ZJRP_OBJ_CLOSE || ev->kind == ZJRP_ARR_CLOSE) {
        if (g_depth <= 0)
            return 2;
        g_depth--;
        *matched = g_depth > 0 ? g_depth - 1 : 0;
        bump_array();
        return 0;
    }
    return 1;
}

static bool is_open_event(const zjsonp_event *ev)
{
    return ev->kind == ZJRP_OBJ_OPEN || ev->kind == ZJRP_ARR_OPEN;
}

/* Ranks a value event against the path: 1 when it lies on the path, 0 or
 * -1 when it does not, RANK_INVALID when the frame stack is corrupt. The
 * document's first event is the whole match when the path is empty, and a
 * descent point when it opens a container. */
static int rank_event(bool first, bool is_open, int matched, bool *exact)
{
    if (first) {
        if (g_nsegs == 0) {
            *exact = true;
            return 1;
        }
        if (is_open) {
            *exact = false;
            return 1;
        }
        return 0;
    }
    if (g_depth <= 0)
        return RANK_INVALID;
    return child_match_rank(&g_stack[g_depth - 1], matched, exact);
}

/* Steps past an event that is off the path: an open container is skipped
 * whole, then the sibling position advances. */
static int advance_unmatched(zjsonp *p, bool is_open)
{
    if (is_open) {
        if (skip_container(p, p->depth) != 0)
            return 2;
    }
    bump_array();
    return WALK_CONTINUE;
}

/* Applies the command to the exactly matched event: containers go through
 * finish_matched_container, scalars through handle_matched_scalar. */
static int finish_matched_value(zjsonp *p, const char *text,
                                const zjsonp_event *ev, bool is_open,
                                cmd_kind cmd, const char *eq)
{
    if (is_open)
        return finish_matched_container(p, text, ev, cmd, eq);
    return handle_matched_scalar(text, ev, cmd, eq);
}

/* Pushes an open container that is a path prefix onto the frame stack. */
static int descend_frame(const zjsonp_event *ev, bool at_root, int *matched)
{
    if (g_depth >= ZJRP_MAX_DEPTH)
        return 2;
    frame *fr = &g_stack[g_depth];
    memset(fr, 0, sizeof *fr);
    fr->is_array = ev->kind == ZJRP_ARR_OPEN;
    g_depth++;
    if (!at_root)
        (*matched)++;
    return WALK_CONTINUE;
}

static int walk(const char *text, size_t len, cmd_kind cmd, const char *eq)
{
    zjsonp p;
    zjsonp_init(&p, text, len);
    g_depth = 0;
    int matched = 0;
    bool first = true;

    for (;;) {
        zjsonp_event ev;
        zjsonp_status st = zjsonp_next(&p, &ev);
        if (st == ZJRP_DONE)
            return 1;
        if (st != ZJRP_OK) {
            fprintf(stderr, "jsonq: %s at byte %zu\n",
                    zjsonp_status_name(st), zjsonp_pos(&p));
            return 2;
        }
        int stacked = handle_stack_event(text, &ev, &matched);
        if (stacked == 2)
            return 2;
        if (stacked == 0)
            continue;

        bool exact = false;
        bool is_open = is_open_event(&ev);
        bool at_root = first;
        int rank = rank_event(first, is_open, matched, &exact);
        first = false;
        if (rank == RANK_INVALID)
            return 2;

        int rc = WALK_CONTINUE;
        if (rank <= 0)
            rc = advance_unmatched(&p, is_open);
        else if (exact)
            rc = finish_matched_value(&p, text, &ev, is_open, cmd, eq);
        else if (!is_open)
            rc = advance_unmatched(&p, is_open);
        else
            rc = descend_frame(&ev, at_root, &matched);
        if (rc != WALK_CONTINUE)
            return rc;
    }
}

static bool valid_document(const char *text, size_t len)
{
    zjsonp parser;
    zjsonp_event event;
    zjsonp_init(&parser, text, len);
    for (;;) {
        zjsonp_status status = zjsonp_next(&parser, &event);
        if (status == ZJRP_DONE)
            return true;
        if (status != ZJRP_OK)
            return false;
    }
}

static int cmd_unwrap(const char *text, size_t len)
{
    zjsonp parser;
    zjsonp_event selected;
    zjsonp_init(&parser, text, len);
    if (zjsonp_next(&parser, &selected) != ZJRP_OK)
        return 2;
    zjsonp selected_parser = parser;
    bool have_result = false, have_error = false;
    zjsonp_event event;
    while (zjsonp_next(&parser, &event) == ZJRP_OK) {
        if (event.kind != ZJRP_KEY || parser.depth != 1)
            continue;
        char key[6];
        size_t size = zjsonp_str_decode(text, &event, key, sizeof key);
        if (size == 5 && memcmp(key, "error", 5) == 0) {
            if (have_error || zjsonp_next(&parser, &event) != ZJRP_OK ||
                event.kind != ZJRP_NULL) {
                fputs("jsonq: invalid json-rpc error member\n", stderr);
                return 2;
            }
            have_error = true;
        } else if (size == 6 && memcmp(key, "result", 6) == 0) {
            if (have_result || zjsonp_next(&parser, &selected) != ZJRP_OK) {
                fputs("jsonq: ambiguous json-rpc result\n", stderr);
                return 2;
            }
            selected_parser = parser;
            have_result = true;
        }
    }
    return finish_matched_value(&selected_parser, text, &selected,
                                is_open_event(&selected), have_result ? CMD_GET : CMD_RAW, NULL);
}

static bool read_document(size_t *len)
{
#if defined(_WIN32)
    if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
        fputs("jsonq: cannot select binary stdin\n", stderr);
        return false;
    }
#endif
    *len = fread(g_input, 1, sizeof g_input, stdin);
    if (ferror(stdin) || !feof(stdin)) {
        fprintf(stderr, "jsonq: read error or input over %d bytes\n", JSONQ_MAX_INPUT);
        return false;
    }
    if (!valid_document(g_input, *len)) {
        fputs("jsonq: input is not exactly one JSON document\n", stderr);
        return false;
    }
    return true;
}

static bool parse_command(int argc, char **argv, cmd_kind *cmd)
{
    static const struct {
        const char *name;
        cmd_kind kind;
        int argc;
    } commands[] = {
        { "get", CMD_GET, 3 },
        { "raw", CMD_RAW, 3 },
        { "type", CMD_TYPE, 3 },
        { "has", CMD_HAS, 3 },
        { "eq", CMD_EQ, 4 },
        { "count", CMD_COUNT, 3 },
        { "keys", CMD_KEYS, 3 },
        { "key-count", CMD_KEY_COUNT, 4 },
        { "unwrap", CMD_UNWRAP, 2 }
    };
    if (argc < 2) return false;
    if (strcmp(argv[1], "lines") == 0) {
        if (argc < 3 || argc > MAX_LINE_PATHS + 2) return false;
        *cmd = CMD_LINES;
        return true;
    }
    for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++) {
        if (strcmp(argv[1], commands[i].name) != 0) continue;
        if (argc != commands[i].argc) return false;
        *cmd = commands[i].kind;
        return true;
    }
    return false;
}

static int finish_stdout(int rc)
{
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fputs("jsonq: stdout write failed\n", stderr);
        return 2;
    }
    return rc;
}

static int string_lines(size_t len, int count, char **paths)
{
    /* Two bounded passes over immutable input: semantic failures never emit a
     * valid-looking prefix. The second pass can fail only on output delivery. */
    for (int pass = 0; pass < 2; ++pass) {
        for (int i = 0; i < count; ++i) {
            if (parse_path(paths[i]) != 0) return 2;
            int rc = walk(g_input, len, pass ? CMD_LINES : CMD_LINES_CHECK, NULL);
            if (rc != 0) {
                fprintf(stderr, "jsonq: lines could not read string path %s\n", paths[i]);
                return rc;
            }
        }
    }
    return 0;
}

int jsonq_main(int argc, char **argv)
{
    cmd_kind cmd;
    if (!parse_command(argc, argv, &cmd)) {
        usage();
        return 2;
    }
    const char *path = argc > 2 ? argv[2] : NULL;
    const char *eq = argc > 3 ? argv[3] : NULL;

    size_t len = 0;
    if (!read_document(&len)) return 2;
    if (cmd == CMD_LINES)
        return finish_stdout(string_lines(len, argc - 2, argv + 2));
    if (cmd == CMD_UNWRAP)
        return finish_stdout(cmd_unwrap(g_input, len));
    if (parse_path(path) != 0)
        return 2;
    return finish_stdout(walk(g_input, len, cmd, eq));
}
