/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 *
 * Owner-only secret files: atomic write, tighten, read, private directory.
 *
 * POSIX: files are 0600, directories 0700.
 * Windows: a protected DACL granting full control only to the current user.
 *
 * Every function returns 0 on success and a negative value on failure; on
 * failure `err` (if non-NULL) receives a one-line explanation that never
 * contains file contents.
 */
#ifndef ZCL_C23_TOR_KEYFILE_H
#define ZCL_C23_TOR_KEYFILE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Write `len` bytes to `path` atomically: temp file in the same directory
 * (created owner-only), write, fsync, rename over `path`, fsync directory.
 * A pre-existing `path` is replaced, so a looser old file never survives.
 * `path` is UTF-8. */
int zcl_keyfile_write(const char *path, const void *data, size_t len,
                      char *err, size_t errsz);

/* Make an existing file owner-only. Returns 0 if tightened or already tight,
 * 1 if the file does not exist, negative on error (not a regular file, not
 * owned by the caller, chmod/ACL failure). Never follows a symlink on POSIX. */
int zcl_keyfile_tighten(const char *path, char *err, size_t errsz);

/* Read a whole file of at most `cap` bytes into `buf`. Fails if larger.
 * Never follows a symlink on POSIX. */
int zcl_keyfile_read(const char *path, void *buf, size_t cap, size_t *len,
                     char *err, size_t errsz);

/* Create `path` as an owner-only directory (single level); an existing
 * directory owned by the caller is tightened. */
int zcl_keyfile_mkdir_private(const char *path, char *err, size_t errsz);

/* Remove a file. Returns 0 if removed or already absent, negative on error. */
int zcl_keyfile_remove(const char *path, char *err, size_t errsz);

#ifdef __cplusplus
}
#endif
#endif
