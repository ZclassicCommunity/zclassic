/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "json/json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <inttypes.h>
#include <errno.h>
#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "base/hex.h"

#ifdef ZCL_TESTING
#include <stdatomic.h>
/* Test-only accounting for module-owned heap blocks. Atomic accounting also
 * supports ownership transfer between threads. Snapshot assertions require
 * an isolated fixture with no unrelated JSON allocation in flight. */
static atomic_size_t json_test_blocks;

size_t json_test_live_blocks(void)
{
    return atomic_load_explicit(&json_test_blocks, memory_order_relaxed);
}

static void *json_heap_alloc(size_t n, const char *label)
{
    void *p = zcl_malloc(n, label);
    if (!p) return NULL; /* checked allocator logged allocation failure */
    atomic_fetch_add_explicit(&json_test_blocks, 1, memory_order_relaxed);
    return p;
}

static void *json_heap_resize(void *p, size_t n, const char *label)
{
    bool fresh = p == NULL; /* capture before realloc invalidates old pointer */
    void *q = zcl_realloc(p, n, label); /* module resize sizes are positive */
    if (!q) return NULL; /* checked allocator logged allocation failure */
    if (fresh) atomic_fetch_add_explicit(&json_test_blocks, 1, memory_order_relaxed);
    return q;
}

static char *json_heap_strdup(const char *s, const char *label)
{
    if (s && zcl_alloc_fault_should_fail(label)) {
        fprintf(stderr, "json_heap_strdup: injected allocation failure (%s)\n", label);
        return NULL;
    }
    char *p = zcl_strdup(s, label);
    if (!p) return NULL; /* NULL input is an absent object key, not a block */
    atomic_fetch_add_explicit(&json_test_blocks, 1, memory_order_relaxed);
    return p;
}

static void json_heap_release(void *p)
{
    if (!p) return;
    atomic_fetch_sub_explicit(&json_test_blocks, 1, memory_order_relaxed);
    free(p);
}
#else
#define json_heap_alloc zcl_malloc
#define json_heap_resize zcl_realloc
#define json_heap_strdup zcl_strdup
#define json_heap_release free
#endif

void json_init(struct json_value *v)
{
    memset(v, 0, sizeof(*v));
    v->type = JSON_NULL;
}

static void json_clear_children(struct json_value *v)
{
    for (size_t i = 0; i < v->num_children; i++) {
        json_free(&v->children[i]);
        json_heap_release(v->keys[i]);
    }
    json_heap_release(v->children);
    json_heap_release(v->keys);
    v->children = NULL;
    v->keys = NULL;
    v->num_children = 0;
    v->children_cap = 0;
}

void json_free(struct json_value *v)
{
    if (v->type == JSON_STR)
        json_heap_release(v->val.s);
    json_clear_children(v);
}

void json_set_null(struct json_value *v)
{
    json_free(v);
    v->type = JSON_NULL;
}

void json_set_bool(struct json_value *v, bool b)
{
    json_free(v);
    v->type = JSON_BOOL;
    v->val.b = b;
}

void json_set_int(struct json_value *v, int64_t i)
{
    json_free(v);
    v->type = JSON_INT;
    v->val.i = i;
}

void json_set_real(struct json_value *v, double d)
{
    json_free(v);
    v->type = JSON_REAL;
    v->val.d = d;
}

void json_set_str(struct json_value *v, const char *s)
{
    json_free(v);
    v->val.s = json_heap_strdup(s, "json_set_str");
    /* Under OOM we silently degrade to JSON_NULL rather than leaving a
     * JSON_STR with NULL val.s — every downstream consumer dereferences
     * val.s expecting a real string. Loud failure was logged inside
     * zcl_strdup; here we just stay type-safe. */
    v->type = v->val.s ? JSON_STR : JSON_NULL;
}

void json_set_array(struct json_value *v)
{
    json_free(v);
    v->type = JSON_ARR;
}

void json_set_object(struct json_value *v)
{
    json_free(v);
    v->type = JSON_OBJ;
}

static bool json_grow(struct json_value *v)
{
    if (v->num_children >= v->children_cap) {
        if (v->children_cap > SIZE_MAX / 2) {
            fprintf(stderr, "json_grow: capacity doubling overflow (cap=%zu)\n",
                    v->children_cap);
            return false;
        }
        size_t newcap = v->children_cap == 0 ? 8 : v->children_cap * 2;
        if (newcap > SIZE_MAX / sizeof(*v->children) ||
            newcap > SIZE_MAX / sizeof(*v->keys) ||
            v->num_children >= newcap) {
            fprintf(stderr, "json_grow: unrepresentable growth or no append slot "
                    "(count=%zu, cap=%zu, next=%zu)\n",
                    v->num_children, v->children_cap, newcap);
            return false;
        }
        struct json_value *nc = json_heap_resize(v->children,
                                        newcap * sizeof(*nc), "json_children");
        if (!nc) return false;
        v->children = nc;
        char **nk = json_heap_resize(v->keys, newcap * sizeof(*nk), "json_keys");
        if (!nk) return false;
        v->keys = nk;
        v->children_cap = newcap;
    }
    return true;
}

static bool json_copy_children_checked(struct json_value *dst,
    const struct json_value *src)
{
    if (!src->num_children) return true;
    if (src->num_children > SIZE_MAX / sizeof(*dst->children) ||
        src->num_children > SIZE_MAX / sizeof(*dst->keys)) {
        fprintf(stderr, "json_copy_checked: unrepresentable child count\n");
        return false;
    }
    dst->children_cap = src->num_children;
    dst->children = json_heap_alloc(dst->children_cap * sizeof(*dst->children), "json_copy_children");
    if (!dst->children) return false;
    dst->keys = json_heap_alloc(dst->children_cap * sizeof(*dst->keys), "json_copy_keys");
    if (!dst->keys) return false;
    memset(dst->keys, 0, dst->children_cap * sizeof(*dst->keys));
    for (size_t i = 0; i < src->num_children; i++) {
        if (!json_copy_checked(&dst->children[i], &src->children[i])) return false;
        dst->num_children++;
        if (src->keys[i]) {
            dst->keys[i] = json_heap_strdup(src->keys[i], "json_copy_key");
            if (!dst->keys[i]) return false;
        }
    }
    return true;
}

bool json_copy_checked(struct json_value *dst, const struct json_value *src)
{
    json_init(dst);
    dst->type = src->type;
    switch (src->type) {
    case JSON_BOOL: dst->val.b = src->val.b; break;
    case JSON_INT:  dst->val.i = src->val.i; break;
    case JSON_REAL: dst->val.d = src->val.d; break;
    case JSON_STR:
        dst->val.s = json_heap_strdup(src->val.s, "json_copy_str");
        if (!dst->val.s) {
            json_init(dst);
            return false;
        }
        break;
    default: break;
    }
    if (json_copy_children_checked(dst, src)) return true;
    json_free(dst);
    json_init(dst);
    return false;
}

void json_copy(struct json_value *dst, const struct json_value *src)
{
    (void)json_copy_checked(dst, src);
}

bool json_push_back(struct json_value *arr, const struct json_value *child)
{
    if (arr->type != JSON_ARR) {
        fprintf(stderr, "json_push_back: target type=%d; initialize an array "
                "with json_set_array before appending\n", (int)arr->type);
        return false;
    }
    if (!json_grow(arr)) return false;
    if (!json_copy_checked(&arr->children[arr->num_children], child)) return false;
    arr->keys[arr->num_children] = NULL;
    arr->num_children++;
    return true;
}

bool json_push_kv(struct json_value *obj, const char *key,
                  const struct json_value *child)
{
    if (obj->type != JSON_OBJ) {
        fprintf(stderr, "json_push_kv: target type=%d; initialize an object "
                "with json_set_object before appending\n", (int)obj->type);
        return false;
    }
    if (!json_grow(obj)) return false;
    /* Allocate the key first so an OOM here doesn't leave a copied
     * child stranded with a NULL key — json_get does
     * strcmp(obj->keys[i], key) and a NULL slot would crash. */
    char *kdup = json_heap_strdup(key, "json_push_kv_key");
    if (!kdup) return false;
    if (!json_copy_checked(&obj->children[obj->num_children], child)) {
        json_heap_release(kdup);
        return false;
    }
    obj->keys[obj->num_children] = kdup;
    obj->num_children++;
    return true;
}

/* Append a prepared scalar under key, then release its temporary storage.
 * Takes ownership of *v's resources (always frees v before returning). */
static bool json_push_kv_owned(struct json_value *obj, const char *key,
                               struct json_value *v)
{
    bool ok = json_push_kv(obj, key, v);
    json_free(v);
    return ok;
}

bool json_push_kv_str(struct json_value *obj, const char *key, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    if (s && v.type != JSON_STR) return false;
    return json_push_kv_owned(obj, key, &v);
}

bool json_push_kv_int(struct json_value *obj, const char *key, int64_t i)
{
    struct json_value v;
    json_init(&v);
    json_set_int(&v, i);
    return json_push_kv_owned(obj, key, &v);
}

bool json_push_kv_real(struct json_value *obj, const char *key, double d)
{
    struct json_value v;
    json_init(&v);
    json_set_real(&v, d);
    return json_push_kv_owned(obj, key, &v);
}

bool json_push_kv_bool(struct json_value *obj, const char *key, bool b)
{
    struct json_value v;
    json_init(&v);
    json_set_bool(&v, b);
    return json_push_kv_owned(obj, key, &v);
}

/* Read accessors are NULL-safe: passing NULL (e.g. json_at()/json_get() on an
 * absent element/key) yields the type's zero value rather than dereferencing.
 * This makes the idiom json_get_str(json_at(params, N)) safe when the optional
 * param N is missing — a missing RPC arg must never crash the node. */
size_t json_size(const struct json_value *v)
{
    return v ? v->num_children : 0;
}

bool json_empty(const struct json_value *v)
{
    return !v || v->num_children == 0;
}

const struct json_value *json_get(const struct json_value *obj, const char *key)
{
    if (!obj || !key || obj->type != JSON_OBJ) return NULL;
    for (size_t i = 0; i < obj->num_children; i++)
        if (obj->keys[i] && strcmp(obj->keys[i], key) == 0)
            return &obj->children[i];
    return NULL;
}

const struct json_value *json_at(const struct json_value *v, size_t index)
{
    if (!v || index >= v->num_children) return NULL;
    return &v->children[index];
}

bool json_is_null(const struct json_value *v)
{
    return !v || v->type == JSON_NULL;
}

bool json_get_bool(const struct json_value *v)
{
    return v && v->type == JSON_BOOL && v->val.b;
}

int64_t json_get_int(const struct json_value *v)
{
    if (!v) return 0;
    if (v->type == JSON_INT) return v->val.i;
    if (v->type == JSON_REAL) return (int64_t)v->val.d;
    return 0;
}

double json_get_real(const struct json_value *v)
{
    if (!v) return 0.0;
    if (v->type == JSON_REAL) return v->val.d;
    if (v->type == JSON_INT) return (double)v->val.i;
    return 0.0;
}

const char *json_get_str(const struct json_value *v)
{
    if (v && v->type == JSON_STR) return v->val.s;
    return "";
}

/* --- JSON writer --- */

static char json_short_escape(char c)
{
    switch (c) {
    case '"':  return '"';
    case '\\': return '\\';
    case '\b': return 'b';
    case '\f': return 'f';
    case '\n': return 'n';
    case '\r': return 'r';
    case '\t': return 't';
    default: return 0;
    }
}

static size_t json_escape_unicode(unsigned char c, char *buf, size_t buflen, size_t pos)
{
    char tmp[8];
    int n = snprintf(tmp, sizeof(tmp), "\\u%04x", c);
    for (int i = 0; i < n; i++) {
        if (pos < buflen) { buf[pos] = tmp[i]; } pos++;
    }
    return pos;
}

static size_t json_escape_str(const char *s, char *buf, size_t buflen)
{
    size_t pos = 0;
    if (pos < buflen) { buf[pos] = '"'; } pos++;
    for (const char *p = s; *p; p++) {
        char esc = json_short_escape(*p);
        if (esc) {
            if (pos < buflen) { buf[pos] = '\\'; } pos++;
            if (pos < buflen) { buf[pos] = esc; } pos++;
        } else if ((unsigned char)*p < 0x20) {
            pos = json_escape_unicode((unsigned char)*p, buf, buflen, pos);
        } else {
            if (pos < buflen) { buf[pos] = *p; } pos++;
        }
    }
    if (pos < buflen) { buf[pos] = '"'; } pos++;
    return pos;
}

static size_t json_write_literal(const char *s, size_t n, char *buf, size_t cap)
{
    if (n <= cap) memcpy(buf, s, n);
    return n;
}

static size_t json_write_number(const struct json_value *v, char *buf, size_t cap)
{
    char tmp[64];
    int n = v->type == JSON_INT ? snprintf(tmp, sizeof(tmp), "%" PRId64, v->val.i)
                                : snprintf(tmp, sizeof(tmp), "%.8g", v->val.d);
    return json_write_literal(tmp, (size_t)n, buf, cap);
}

/* The write cursor for a child. A sizing probe (buf == NULL, cap == 0) or a
 * position past cap yields NULL: forming buf + pos from a NULL buffer is UB
 * even though the callee never writes through it. */
static char *json_cursor(char *buf, size_t pos, size_t cap)
{
    return buf != NULL && pos < cap ? buf + pos : NULL;
}

static size_t json_write_array(const struct json_value *v, char *buf, size_t cap)
{
    size_t pos = 0;
    if (pos < cap) { buf[pos] = '['; } pos++;
    for (size_t i = 0; i < v->num_children; i++) {
        if (i > 0) { if (pos < cap) buf[pos] = ','; pos++; }
        pos += json_write(&v->children[i], json_cursor(buf, pos, cap), cap > pos ? cap - pos : 0);
    }
    if (pos < cap) { buf[pos] = ']'; } pos++;
    return pos;
}

static size_t json_write_object(const struct json_value *v, char *buf, size_t cap)
{
    size_t pos = 0;
    if (pos < cap) { buf[pos] = '{'; } pos++;
    for (size_t i = 0; i < v->num_children; i++) {
        if (i > 0) { if (pos < cap) buf[pos] = ','; pos++; }
        pos += json_escape_str(v->keys[i] ? v->keys[i] : "", json_cursor(buf, pos, cap),
                               cap > pos ? cap - pos : 0);
        if (pos < cap) { buf[pos] = ':'; } pos++;
        pos += json_write(&v->children[i], json_cursor(buf, pos, cap), cap > pos ? cap - pos : 0);
    }
    if (pos < cap) { buf[pos] = '}'; } pos++;
    return pos;
}

size_t json_write(const struct json_value *v, char *buf, size_t buflen)
{
    size_t pos = 0;
    switch (v->type) {
    case JSON_NULL: pos = json_write_literal("null", 4, buf, buflen); break;
    case JSON_BOOL:
        pos = v->val.b ? json_write_literal("true", 4, buf, buflen)
                       : json_write_literal("false", 5, buf, buflen); break;
    case JSON_INT: case JSON_REAL: pos = json_write_number(v, buf, buflen); break;
    case JSON_STR: pos = json_escape_str(v->val.s ? v->val.s : "", buf, buflen); break;
    case JSON_ARR: pos = json_write_array(v, buf, buflen); break;
    case JSON_OBJ: pos = json_write_object(v, buf, buflen); break;
    }
    if (pos < buflen) buf[pos] = '\0';
    else if (buflen) buf[buflen - 1] = '\0';
    return pos;
}

/* --- JSON reader --- */

/* Maximum nesting depth for arrays/objects.  Prevents stack overflow
 * under -O1+gcov where each recursive frame is larger due to
 * instrumentation overhead. 256 is generous for any real-world JSON. */
#define JSON_MAX_DEPTH 256

static const char *skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}

static bool parse_value_r(struct json_value *v, const char **pp,
                          const char *end, int depth);

static void json_discard_span(char *s, size_t len)
{
    if (s) {
        memory_cleanse(s, len);
        json_heap_release(s);
    }
}

static void json_discard_string(char *s)
{
    if (s)
        json_discard_span(s, strlen(s) + 1);
}

static void json_discard_value(struct json_value *v)
{
    json_cleanse_strings(v);
    json_free(v);
}

/* Append one decoded byte. A NULL string is the validate-only scan: the
 * grammar is walked exactly as for a kept string and nothing is stored. */
static bool str_put(char **s, size_t *cap, size_t *len, char c)
{
    if (!*s)
        return true;
    if (*len >= *cap - 1) {
        /* A new block, so the old one can be overwritten before it is freed: realloc would leave the
         * text of a long string in memory that is no longer owned. */
        char *ns = json_heap_alloc(*cap * 2, "json_string");
        if (!ns) return false;
        memcpy(ns, *s, *len);
        memory_cleanse(*s, *cap);
        json_heap_release(*s);
        *s = ns;
        *cap *= 2;
    }
    (*s)[(*len)++] = c;
    return true;
}

static bool str_hex4(const char **pp, const char *end, uint32_t *unit)
{
    const char *p = *pp;
    if ((size_t)(end - p) < 4) return false;
    uint32_t value = 0;
    for (size_t i = 0; i < 4; i++) {
        int digit = zcl_hex_nibble(p[i], true);
        if (digit < 0) return false;
        value = (value << 4) | (uint32_t)digit;
    }
    *unit = value;
    *pp = p + 4;
    return true;
}

static bool str_unicode_scalar(const char **pp, const char *end, uint32_t *cp)
{
    uint32_t first, second;
    if (!str_hex4(pp, end, &first)) return false;
    if (first >= 0xdc00 && first <= 0xdfff) return false;
    if (first >= 0xd800 && first <= 0xdbff) {
        if ((size_t)(end - *pp) < 6 || (*pp)[0] != '\\' || (*pp)[1] != 'u')
            return false;
        *pp += 2;
        if (!str_hex4(pp, end, &second)) return false;
        if (second < 0xdc00 || second > 0xdfff) return false;
        first = 0x10000 + ((first - 0xd800) << 10) + second - 0xdc00;
    }
    /* json_value strings/keys are C strings: NUL would discard identity. */
    if (first == 0) return false;
    *cp = first;
    return true;
}

static bool str_unicode_put(char **s, size_t *cap, size_t *len,
                             const char **pp, const char *end)
{
    uint32_t cp;
    if (!str_unicode_scalar(pp, end, &cp)) return false;
    char encoded[4];
    size_t n = cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    static const unsigned char prefix[] = {0, 0, 0xc0, 0xe0, 0xf0};
    if (n == 1) encoded[0] = (char)cp;
    else {
        encoded[0] = (char)(prefix[n] | (cp >> (6 * (n - 1))));
        for (size_t i = 1; i < n; i++)
            encoded[i] = (char)(0x80 | ((cp >> (6 * (n - 1 - i))) & 0x3f));
    }
    for (size_t i = 0; i < n; i++)
        if (!str_put(s, cap, len, encoded[i])) return false;
    return true;
}

/* pp points after the backslash; Unicode consumes its complete scalar. */
static bool str_escape(char **s, size_t *cap, size_t *len,
                        const char **pp, const char *end)
{
    if (*pp >= end) return false;
    char c = *(*pp)++;
    switch (c) {
    case '"': case '\\': case '/': break;
    case 'b': c = '\b'; break;
    case 'f': c = '\f'; break;
    case 'n': c = '\n'; break;
    case 'r': c = '\r'; break;
    case 't': c = '\t'; break;
    case 'u': return str_unicode_put(s, cap, len, pp, end);
    default: return false;
    }
    return str_put(s, cap, len, c);
}

/* out == NULL walks the same grammar without allocating (json_valid). */
static bool parse_string(char **out, const char **pp, const char *end)
{
    const char *p = *pp;
    if (p >= end || *p != '"') return false;
    p++;
    size_t cap = 64, len = 0;
    char *s = NULL;
    if (out) {
        s = json_heap_alloc(cap, "json_string");
        if (!s) return false;
    }
    while (p < end && *p != '"') {
        unsigned char c = (unsigned char)*p++;
        if (c < 0x20) { json_discard_span(s, len); return false; }
        bool ok = c == '\\' ? str_escape(&s, &cap, &len, &p, end)
                             : str_put(&s, &cap, &len, (char)c);
        if (!ok) { json_discard_span(s, len); return false; }
    }
    if (p >= end) { json_discard_span(s, len); return false; }
    p++;
    if (out) {
        s[len] = '\0';
        *out = s;
    }
    *pp = p;
    return true;
}

static bool json_number_digits(const char **pp, const char *end)
{
    const char *start = *pp;
    while (*pp < end && **pp >= '0' && **pp <= '9') (*pp)++;
    return *pp != start;
}

static bool json_number_tail(const char **pp, const char *end, bool *real)
{
    const char *p = *pp;
    if (p < end && *p == '.') {
        *real = true; p++;
        if (!json_number_digits(&p, end)) return false;
    }
    if (p < end && (*p == 'e' || *p == 'E')) {
        *real = true; p++;
        if (p < end && (*p == '+' || *p == '-')) p++;
        if (!json_number_digits(&p, end)) return false;
    }
    *pp = p;
    return true;
}

static bool json_number_span(const char **pp, const char *end, bool *real)
{
    const char *p = *pp;
    if (p < end && *p == '-') p++;
    if (p == end) return false;
    if (*p == '0') {
        p++;
        if (p < end && *p >= '0' && *p <= '9') return false;
    } else if (!json_number_digits(&p, end)) return false;
    if (!json_number_tail(&p, end, real)) return false;
    *pp = p;
    return true;
}

static bool parse_number(struct json_value *v, const char **pp, const char *end)
{
    const char *start = *pp, *p = start;
    bool is_real = false;
    if (!json_number_span(&p, end, &is_real)) return false;
    char tmp[64];
    size_t len = (size_t)(p - start);
    if (len >= sizeof(tmp)) return false;
    memcpy(tmp, start, len);
    tmp[len] = '\0';
    char *converted_end = NULL;
    errno = 0;
    if (is_real) {
        v->type = JSON_REAL;
        v->val.d = strtod(tmp, &converted_end);
        if (errno == ERANGE || !isfinite(v->val.d)) return false;
    } else {
        v->type = JSON_INT;
        v->val.i = strtoll(tmp, &converted_end, 10);
        if (errno == ERANGE) return false;
    }
    if (converted_end != tmp + len) return false;
    *pp = p;
    return true;
}

/* Take ownership of key and child as the next member of v; both are freed
 * when v cannot grow. */
static bool json_append(struct json_value *v, char *key,
                        struct json_value *child)
{
    if (!json_grow(v)) {
        json_discard_string(key);
        json_discard_value(child);
        return false;
    }
    v->keys[v->num_children] = key;
    v->children[v->num_children] = *child;
    v->num_children++;
    return true;
}

/* One member name and its ':', whitespace allowed around both. key NULL
 * is the validate-only walk. On failure nothing is left allocated. */
static bool parse_member_key(char **key, const char **pp, const char *end)
{
    const char *p = skip_ws(*pp, end);
    if (!parse_string(key, &p, end)) return false;
    p = skip_ws(p, end);
    if (p >= end || *p != ':') {
        if (key) { json_discard_string(*key); *key = NULL; }
        return false;
    }
    *pp = p + 1;
    return true;
}

/* The members of an object whose '{' has been consumed. v is the object
 * being filled, or NULL for json_valid (no key, no child, no growth). */
static bool parse_object_r(struct json_value *v, const char **pp,
                           const char *end, int depth)
{
    const char *p = skip_ws(*pp, end);
    if (p < end && *p == '}') { *pp = p + 1; return true; }
    while (p < end) {
        char *key = NULL;
        if (!parse_member_key(v ? &key : NULL, &p, end)) return false;
        struct json_value child;
        json_init(&child);
        if (!parse_value_r(v ? &child : NULL, &p, end, depth + 1)) {
            json_discard_string(key);
            if (v) json_discard_value(&child);
            return false;
        }
        if (v && !json_append(v, key, &child)) return false;
        p = skip_ws(p, end);
        if (p < end && *p == ',') { p++; continue; }
        if (p < end && *p == '}') { *pp = p + 1; return true; }
        return false;
    }
    return false;
}

/* The elements of an array whose '[' has been consumed; v as above. */
static bool parse_array_r(struct json_value *v, const char **pp,
                          const char *end, int depth)
{
    const char *p = skip_ws(*pp, end);
    if (p < end && *p == ']') { *pp = p + 1; return true; }
    while (p < end) {
        struct json_value child;
        json_init(&child);
        if (!parse_value_r(v ? &child : NULL, &p, end, depth + 1)) {
            if (v) json_discard_value(&child);
            return false;
        }
        if (v && !json_append(v, NULL, &child)) return false;
        p = skip_ws(p, end);
        if (p < end && *p == ',') { p++; continue; }
        if (p < end && *p == ']') { *pp = p + 1; return true; }
        return false;
    }
    return false;
}

static bool parse_value_string(struct json_value *v, bool keep, const char **pp,
                               const char *end)
{
    char *s = NULL;
    const char *p = *pp;
    if (!parse_string(keep ? &s : NULL, &p, end)) return false;
    v->type = JSON_STR;
    v->val.s = s;
    *pp = p;
    return true;
}

static bool parse_value_container(struct json_value *v, bool keep, const char **pp,
                                  const char *end, int depth)
{
    bool obj = **pp == '{';
    if (depth >= JSON_MAX_DEPTH) return false;
    (*pp)++;
    if (obj) json_set_object(v); else json_set_array(v);
    return obj ? parse_object_r(keep ? v : NULL, pp, end, depth)
               : parse_array_r(keep ? v : NULL, pp, end, depth);
}

static bool parse_value_literal(struct json_value *v, const char **pp,
                                const char *end)
{
    const char *p = *pp;
    if (end - p >= 4 && memcmp(p, "null", 4) == 0) {
        v->type = JSON_NULL; *pp = p + 4; return true;
    }
    if (end - p >= 4 && memcmp(p, "true", 4) == 0) {
        v->type = JSON_BOOL; v->val.b = true; *pp = p + 4; return true;
    }
    if (end - p >= 5 && memcmp(p, "false", 5) == 0) {
        v->type = JSON_BOOL; v->val.b = false; *pp = p + 5; return true;
    }
    return false;
}

static bool parse_value_r(struct json_value *v, const char **pp,
                          const char *end, int depth)
{
    const char *p = skip_ws(*pp, end);
    if (p >= end) return false;
    struct json_value sink;
    bool keep = v != NULL;
    if (!keep) v = &sink;
    json_init(v);
    if (*p == '"') {
        bool ok = parse_value_string(v, keep, &p, end);
        if (ok) *pp = p;
        return ok;
    }
    if (*p == '{' || *p == '[') {
        if (depth >= JSON_MAX_DEPTH) return false;
        *pp = p;
        return parse_value_container(v, keep, pp, end, depth);
    }
    if (parse_value_literal(v, &p, end)) { *pp = p; return true; }
    if (*p == '-' || (*p >= '0' && *p <= '9')) {
        *pp = p;
        return parse_number(v, pp, end);
    }
    return false;
}

bool json_read(struct json_value *v, const char *raw, size_t len)
{
    json_init(v);
    const char *p = raw;
    const char *end = raw + len;
    if (!parse_value_r(v, &p, end, 0) || skip_ws(p, end) != end) {
        json_discard_value(v);
        json_init(v);
        return false;
    }
    return true;
}

bool json_valid(const char *raw, size_t len)
{
    const char *p = raw;
    if (!raw)
        return false;
    const char *end = raw + len;
    return parse_value_r(NULL, &p, end, 0) && skip_ws(p, end) == end;
}

void diag_push_health(struct json_value *out, bool ok, const char *reason)
{
    struct json_value health = {0};
    json_set_object(&health);
    json_push_kv_bool(&health, "ok", ok);
    json_push_kv_str(&health, "reason", reason);
    json_push_kv(out, "_health", &health);
    json_free(&health);
}
