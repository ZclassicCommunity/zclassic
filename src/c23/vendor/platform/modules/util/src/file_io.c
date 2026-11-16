/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Implements zcl_read_whole_file() / zcl_read_whole_file_text(): read an
 * entire file into a fresh zcl_malloc'd buffer with every syscall/libc
 * return checked and every failure branch logged via LOG_FAIL. */

#include "util/file_io.h"

#include "platform/file_stream.h"
#include "base/cleanse.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>

static bool read_binary_size(FILE *f, const char *path, size_t max_len,
                              size_t *size, const char *log_ctx)
{
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file: fseek(SEEK_END) failed for %s", path);
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file: ftell failed for %s", path);
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file: fseek(SEEK_SET) failed for %s", path);
    }

    size_t n = (size_t)sz;
    if (max_len > 0 && n > max_len) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file: %s is %zu bytes, exceeds cap %zu",
                  path, n, max_len);
    }
    *size = n;
    return true;
}

bool zcl_read_whole_file(const char *path, size_t max_len,
                          uint8_t **out_buf, size_t *out_len,
                          const char *log_ctx)
{
    if (out_buf) *out_buf = NULL;
    if (out_len) *out_len = 0;
    if (!path || !out_buf || !out_len)
        LOG_FAIL(log_ctx ? log_ctx : "file_io", "read_whole_file: NULL argument");

    FILE *f = platform_file_stream_open_read(path);
    if (!f)
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file: read open failed for %s", path);
    size_t n;
    if (!read_binary_size(f, path, max_len, &n, log_ctx)) return false;

    uint8_t *buf = NULL;
    if (n > 0) {
        buf = zcl_malloc(n, "zcl_read_whole_file");
        if (!buf) {
            fclose(f);
            LOG_FAIL(log_ctx ? log_ctx : "file_io",
                      "read_whole_file: malloc failed (%zu bytes) for %s",
                      n, path);
        }
        size_t got = fread(buf, 1, n, f);
        if (got != n) {
            memory_cleanse(buf, n);
            free(buf);
            fclose(f);
            LOG_FAIL(log_ctx ? log_ctx : "file_io",
                      "read_whole_file: short fread for %s (got %zu, expected %zu)",
                      path, got, n);
        }
    }
    fclose(f);

    *out_buf = buf;
    *out_len = n;
    return true;
}

static bool read_text_size(FILE *f, const char *path, size_t max_len,
                            size_t *size, const char *log_ctx)
{
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file_text: fseek(SEEK_END) failed for %s", path);
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file_text: ftell failed for %s", path);
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file_text: fseek(SEEK_SET) failed for %s", path);
    }

    size_t n = (size_t)sz;
    if (max_len > 0 && n > max_len) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file_text: %s is %zu bytes, exceeds cap %zu",
                  path, n, max_len);
    }
    if (n == SIZE_MAX) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file_text: %s size overflows NUL-terminated buffer",
                  path);
    }
    *size = n;
    return true;
}

bool zcl_read_whole_file_text(const char *path, size_t max_len,
                               char **out_buf, size_t *out_len,
                               const char *log_ctx)
{
    if (out_buf) *out_buf = NULL;
    if (out_len) *out_len = 0;
    if (!path || !out_buf || !out_len)
        LOG_FAIL(log_ctx ? log_ctx : "file_io", "read_whole_file_text: NULL argument");

    FILE *f = platform_file_stream_open_read(path);
    if (!f)
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file_text: read open failed for %s", path);
    size_t n;
    if (!read_text_size(f, path, max_len, &n, log_ctx)) return false;

    char *buf = zcl_malloc(n + 1, "zcl_read_whole_file_text");
    if (!buf) {
        fclose(f);
        LOG_FAIL(log_ctx ? log_ctx : "file_io",
                  "read_whole_file_text: malloc failed (%zu bytes) for %s",
                  n + 1, path);
    }
    if (n > 0) {
        size_t got = fread(buf, 1, n, f);
        if (got != n) {
            memory_cleanse(buf, n + 1);
            free(buf);
            fclose(f);
            LOG_FAIL(log_ctx ? log_ctx : "file_io",
                      "read_whole_file_text: short fread for %s (got %zu, expected %zu)",
                      path, got, n);
        }
    }
    buf[n] = '\0';
    fclose(f);

    *out_buf = buf;
    *out_len = n;
    return true;
}
