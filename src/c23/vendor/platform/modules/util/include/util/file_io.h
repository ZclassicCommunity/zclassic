/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Whole-file read helpers: fopen/fseek/ftell/fread wrapped with full
 * error checking so callers stop hand-rolling the same read-to-buffer
 * pattern. */

#ifndef ZCL_UTIL_FILE_IO_H
#define ZCL_UTIL_FILE_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Read the entire contents of `path` into a freshly zcl_malloc'd buffer.
 *
 * Every step is checked: fopen, both fseeks, ftell (rejects a negative
 * result), the size-to-size_t conversion (rejects overflow), the
 * allocation, and the fread (rejects a short read). Every failure branch
 * logs via LOG_FAIL tagged with `log_ctx` and closes/frees whatever was
 * already open/allocated.
 *
 * `max_len`, if nonzero, caps the accepted on-disk size: a file larger
 * than `max_len` bytes is refused (logged, false returned) BEFORE any
 * allocation is attempted. Pass 0 for no cap.
 *
 * On success: `*out_buf`/`*out_len` are set (a zero-length file yields
 * `*out_buf == NULL`, `*out_len == 0`, true) and the caller owns
 * `*out_buf` (release with free()). On failure: `*out_buf` is NULL,
 * `*out_len` is 0, and false is returned. */
bool zcl_read_whole_file(const char *path, size_t max_len,
                          uint8_t **out_buf, size_t *out_len,
                          const char *log_ctx);

/* Same contract as zcl_read_whole_file(), but the buffer is allocated
 * one byte larger and NUL-terminated so it can be treated as a C
 * string. `*out_len` is the text length, excluding the terminator. For
 * a zero-length file, `*out_buf` is a freshly allocated empty string
 * ("\0"), not NULL, so callers can pass it straight to string
 * functions without a NULL check. */
bool zcl_read_whole_file_text(const char *path, size_t max_len,
                               char **out_buf, size_t *out_len,
                               const char *log_ctx);

#endif
