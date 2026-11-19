/* zclassicd-owned. Parameter-file reading shared by librustzcash_compat.c, and
 * the lazy proving-parameter mode (ZCL_PARAMS_VERIFY, doc/c23-build.md).
 * Internal to libzcl_c23.a: C only, never included from C++.
 *
 * Verifying keys are compiled in (sapling_install_embedded_vks), so the three
 * parameter files matter only for proving. In lazy mode (the default) init
 * hashes the Sapling spend and output files and keeps nothing, checks only the
 * size of the Sprout file, and records the paths here; the raw Sapling bytes
 * are read and re-verified against the init-time digest when a proof needs
 * them, and the Sprout file is hashed once before the first Sprout proof
 * (zcl_c23_sprout_params_ready). ZCL_PARAMS_VERIFY=boot keeps the old path:
 * all three files hashed at init and the Sapling bytes resident. */
#ifndef ZCL_PARAMS_LAZY_H
#define ZCL_PARAMS_LAZY_H

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
typedef wchar_t zcl_pchar; /* parameter path code unit (codeunit) */
typedef HANDLE zcl_fh;     /* an open parameter file */
#else
typedef char zcl_pchar;
typedef int zcl_fh;
#endif

/* Rust panic under panic = 'abort': message on stderr, then abort. */
__attribute__((noreturn, cold)) void zcl_c23_params_panic(const char *msg);

/* rustzcash.rs:218-220 File::open(..).expect(open_msg): panics on failure. */
zcl_fh zcl_c23_params_open(const zcl_pchar *path, const char *open_msg);
/* The same open without the panic: false when the file cannot be opened. */
bool zcl_c23_params_try_open(const zcl_pchar *path, zcl_fh *out);
void zcl_c23_params_close(zcl_fh h);

/* rustzcash.rs:222-250 plus hashreader.rs: every byte of the file goes
 * through BLAKE2b-512 (Blake2b::new(64), unkeyed), and into_hash renders the
 * digest as lowercase hex ("{:02x}"). keep_cap > 0 also keeps the first
 * keep_cap bytes in memory: for a file whose digest is the canonical one,
 * that is the whole file, and it becomes the proving key. */
struct zcl_c23_hash_job {
    zcl_fh fh;
    size_t keep_cap;
    uint8_t *kept; /* out: malloc'd, keep_cap bytes, NULL when keep_cap == 0 */
    uint64_t len;  /* out: bytes read */
    char hex[129]; /* out: lowercase hex digest */
    bool io_ok;    /* out: read to end of file without an I/O error */
};
void *zcl_c23_params_hash_run(void *job); /* pthread start routine shape */

#if defined(_WIN32)
/* UTF-16 -> UTF-8; NULL when the input is not valid UTF-16 (lone surrogate). */
char *zcl_c23_params_wide_to_utf8(const wchar_t *w);
#endif

/* Identity of an open file: device, inode (file index on Windows), size and
 * modification and change times. Two equal stamps mean the same bytes unless
 * someone rewrote the file in place within the clock granularity and also
 * restored both times, which the change time does not allow on POSIX. */
struct zcl_c23_file_stamp {
    uint64_t dev, ino, size;
    int64_t mtime_ns, ctime_ns;
};
bool zcl_c23_params_stamp(zcl_fh h, struct zcl_c23_file_stamp *out);

/* True unless ZCL_PARAMS_VERIFY is "boot". Read by init. */
bool zcl_c23_params_lazy_requested(void);

/* One verified parameter file as init saw it. hex points at a string that
 * lives for the process (the canonical digests). */
struct zcl_c23_param_file {
    const zcl_pchar *path;
    const char *hex;
    uint64_t size;
};

/* Called at the end of a successful init: records the mode and, in lazy mode,
 * copies spend, output and sprout (in that order). A second init replaces the
 * record (the old path copies are leaked, as init leaks the old key set). */
void zcl_c23_params_register(const struct zcl_c23_param_file files[3], bool lazy);
/* 0 before init, 1 boot mode, 2 lazy mode. */
int zcl_c23_params_mode(void);

/* Lazy mode: reads both Sapling files whole and checks each against its
 * init-time size and BLAKE2b-512 digest. On success the caller owns the two
 * malloc'd buffers; on any failure nothing is returned, the reason is logged
 * once, and false comes back. */
bool zcl_c23_params_load_sapling(uint8_t **spend, size_t *spend_len,
                                 uint8_t **output, size_t *output_len);

/* Raw parameter bytes this process holds right now (boot mode: the resident
 * Sapling pair; lazy mode: only while a load is being parsed). */
void zcl_c23_params_resident_add(int64_t delta);

#endif
