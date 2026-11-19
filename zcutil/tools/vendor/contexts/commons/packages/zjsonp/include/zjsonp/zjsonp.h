/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded JSON (RFC 8259) pull parser for C23, companion to
 *          the zjson writer. Allocation-free, depth-bounded, and
 *          total: the parser reads caller memory, produces one event
 *          per call, and every malformed input ends in a precise
 *          ZJR_SYNTAX at the offending byte (input length when truncated), never a crash or a read
 *          past the end.
 *
 * Rules enforced:
 *  - strict RFC 8259 grammar: whitespace is only SP/HT/LF/CR;
 *    numbers match -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?;
 *    strings reject raw control bytes and malformed escapes; input
 *    must be well-formed UTF-8 (validated via zutf8);
 *  - structure: one top-level value, containers nest at most
 *    ZJRP_MAX_DEPTH deep, object members are key:value pairs, and
 *    ZJR_DONE is produced only after the complete document and
 *    optional trailing whitespace;
 *  - string and number payloads are reported as raw slices of the
 *    input (escapes intact); decode with zjsonp_str_decode and parse
 *    numbers with zjsonp_num_i64 / zjsonp_num_f64.
 *
 * The parser struct is caller-owned plain data. The input must
 * outlive parsing; events point into it.
 */
#ifndef ZJSONP_H
#define ZJSONP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZJRP_MAX_DEPTH 32

typedef enum {
  ZJRP_OK = 0,  /* event produced */
  ZJRP_DONE,    /* document complete; no more events */
  ZJRP_SYNTAX,  /* malformed input; zjsonp_pos() is the offset */
  ZJRP_DEPTH    /* nesting beyond ZJRP_MAX_DEPTH */
} zjsonp_status;

typedef enum {
  ZJRP_OBJ_OPEN = 0,
  ZJRP_OBJ_CLOSE,
  ZJRP_ARR_OPEN,
  ZJRP_ARR_CLOSE,
  ZJRP_KEY,  /* object member name; raw escaped slice */
  ZJRP_STR,  /* string value; raw escaped slice */
  ZJRP_NUM,  /* number value; raw slice */
  ZJRP_BOOL, /* boolean value; slice is "true"/"false" */
  ZJRP_NULL  /* null value; slice is "null" */
} zjsonp_event_kind;

typedef struct {
  zjsonp_event_kind kind;
  size_t off; /* byte offset of the payload in the input */
  size_t len; /* payload length (0 for open/close events) */
} zjsonp_event;

typedef struct {
  const char *text;
  size_t len;
  size_t pos;
  uint32_t depth;
  uint32_t is_array;    /* bit i: container at level i is an array */
  uint32_t expect_key;  /* bit i: object at level i awaits a key */
  uint32_t first;       /* bit i: no element completed at level i yet */
  uint32_t after_comma; /* bit i: a separator was consumed but no
                           element followed (trailing-comma trap) */
  bool top_done;
  bool failed; /* sticky syntax failure; cleared only by init */
} zjsonp;

/* Initialize a parser over text[0..len). text may be NULL when len
 * is 0. NULL p is a no-op. */
void zjsonp_init(zjsonp *p, const char *text, size_t len);

/* Pull the next event. On ZJRP_OK *ev is filled. On ZJRP_SYNTAX the
 * parser is finished; zjsonp_pos() locates the offending byte. NULL
 * p or ev yields ZJRP_SYNTAX without touching anything. */
zjsonp_status zjsonp_next(zjsonp *p, zjsonp_event *ev);

/* Current input offset (end of the last consumed token, or the
 * offending byte after ZJRP_SYNTAX, or len when truncated). */
size_t zjsonp_pos(const zjsonp *p);

/* Decode a ZJRP_KEY/ZJRP_STR payload into out[0..cap): escapes are
 * resolved, \uXXXX pairs (including surrogate pairs) are encoded as
 * UTF-8 via zutf8. Returns the decoded length (even when it exceeds
 * cap; nothing is written beyond cap), or SIZE_MAX when the payload
 * is malformed. text is the parser input; ev is the event. */
size_t zjsonp_str_decode(const char *text, const zjsonp_event *ev,
                         char *out, size_t cap);

/* Parse a ZJRP_NUM payload. i64 fails (false) on overflow or a
 * fraction/exponent; f64 uses strtod semantics after grammar
 * validation (already guaranteed by the parser). */
bool zjsonp_num_i64(const char *text, const zjsonp_event *ev,
                    int64_t *out);
bool zjsonp_num_f64(const char *text, const zjsonp_event *ev,
                    double *out);

/* Static name for a status ("ok", "done", "syntax", "depth"). */
const char *zjsonp_status_name(zjsonp_status st);

#endif /* ZJSONP_H */
