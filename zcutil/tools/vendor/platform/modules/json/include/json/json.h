/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_JSON_H
#define ZCL_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base/cleanse.h"

enum json_type {
    JSON_NULL,
    JSON_BOOL,
    JSON_INT,
    JSON_REAL,
    JSON_STR,
    JSON_ARR,
    JSON_OBJ
};

struct json_value {
    enum json_type type;
    union {
        bool b;
        int64_t i;
        double d;
        char *s;
    } val;
    char **keys;
    struct json_value *children;
    size_t num_children;
    size_t children_cap;
};

/* Lifecycle: json_value is not self-initializing. Stack values must be
 * zero-initialized or passed through json_init() before any json_set_*(),
 * json_push_*(), json_free(), or json_copy() call. Setters free any previous
 * contents before replacing the value, so calling them on uninitialized stack
 * memory is undefined and can crash. */
void json_init(struct json_value *v);
void json_free(struct json_value *v);

#ifdef ZCL_TESTING
/* Counts module-created blocks released through the JSON lifecycle. Test
 * fixtures must use module constructors and isolate snapshot comparisons.
 * No instrumentation or observation API exists in production builds. */
size_t json_test_live_blocks(void);
#endif

/* Overwrite every owned string value and object key in place without changing
 * the tree shape. Call immediately before json_free() for secret-bearing
 * documents whose storage has reached its last use. */
static inline void json_cleanse_strings(struct json_value *v)
{
    if (!v)
        return;
    if (v->type == JSON_STR && v->val.s)
        memory_cleanse(v->val.s, strlen(v->val.s) + 1);
    for (size_t i = 0; i < v->num_children; i++) {
        json_cleanse_strings(&v->children[i]);
        if (v->keys && v->keys[i])
            memory_cleanse(v->keys[i], strlen(v->keys[i]) + 1);
    }
}

void json_set_null(struct json_value *v);
void json_set_bool(struct json_value *v, bool b);
void json_set_int(struct json_value *v, int64_t i);
void json_set_real(struct json_value *v, double d);
void json_set_str(struct json_value *v, const char *s);
void json_set_array(struct json_value *v);
void json_set_object(struct json_value *v);

bool json_push_back(struct json_value *arr, const struct json_value *child);
bool json_push_kv(struct json_value *obj, const char *key,
                  const struct json_value *child);
bool json_push_kv_str(struct json_value *obj, const char *key, const char *s);
bool json_push_kv_int(struct json_value *obj, const char *key, int64_t i);
bool json_push_kv_real(struct json_value *obj, const char *key, double d);
bool json_push_kv_bool(struct json_value *obj, const char *key, bool b);

/* Push the reserved `_health` object — { "ok": <ok>, "reason": <reason> } —
 * onto `out` (see the "Adding state introspection" convention). Consolidates
 * the identical dumpstate `_health` tail used across the subsystem/projection
 * dumpers; `reason` is copied by json_push_kv_str, so a caller-owned stack
 * buffer is fine. */
void diag_push_health(struct json_value *out, bool ok, const char *reason);

void json_copy(struct json_value *dst, const struct json_value *src);
/* Deep-copy into a fresh destination (as for json_copy). On refusal, release
 * every partial allocation and leave dst initialized as JSON_NULL. Success
 * guarantees complete values and keys; dst and src must not alias. */
bool json_copy_checked(struct json_value *dst, const struct json_value *src);
size_t json_size(const struct json_value *v);
bool json_empty(const struct json_value *v);

const struct json_value *json_get(const struct json_value *obj, const char *key);
const struct json_value *json_at(const struct json_value *v, size_t index);

bool json_is_null(const struct json_value *v);
bool json_get_bool(const struct json_value *v);
int64_t json_get_int(const struct json_value *v);
double json_get_real(const struct json_value *v);
const char *json_get_str(const struct json_value *v);

/* Serialize v into buf. Returns the number of bytes the full output WOULD
 * occupy, excluding the NUL terminator. A return >= buflen means the output
 * was TRUNCATED. Pass buf=NULL/buflen=0 as a sizing probe to learn the
 * required length. The result is NUL-terminated iff it is < buflen. */
size_t json_write(const struct json_value *v, char *buf, size_t buflen);

/* Parse exactly one JSON value from raw[0..len). Trailing JSON whitespace is
 * accepted; any other suffix is rejected. On parse failure, returns false and
 * leaves v a fresh JSON_NULL (safe to json_free or reuse). */
bool json_read(struct json_value *v, const char *raw, size_t len);

/* Exactly json_read's grammar, depth limit included, with no allocation and
 * no tree: true iff json_read would accept raw[0..len) given the memory.
 * This is what lets a caller tell malformed input from exhausted memory: a
 * body json_valid accepts and json_read refuses could not be allocated. */
bool json_valid(const char *raw, size_t len);

#endif
