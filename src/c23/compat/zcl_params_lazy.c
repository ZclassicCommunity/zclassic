/* zclassicd-owned. See zcl_params_lazy.h. The file reading and hashing moved
 * here unchanged from librustzcash_compat.c; the lazy-mode registry, the
 * proof-time Sapling reload and the Sprout readiness check are new. The design
 * follows Z23 core/modules/sapling/src/params_init.c (nothing loaded for
 * proving at boot, pin check when proving starts, a same-file stamp keyed by
 * device, inode, size and times) on top of this shim's own key handling. */

/* POSIX declarations (open, fstat, O_CLOEXEC) under -std=c23 as well; the
 * same guard librustzcash_compat.c uses. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "zcl_params_lazy.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <wchar.h>
#endif

/* Exported ABI (librustzcash.h); visibility as librustzcash_compat.c does. */
#if !defined(_WIN32)
#pragma GCC visibility push(default)
#endif
#include "librustzcash.h"
#if !defined(_WIN32)
#pragma GCC visibility pop
#endif

#include "crypto/blake2b.h"
#include "zcl_c23_glue.h"

void zcl_c23_params_panic(const char *msg)
{
    fprintf(stderr, "librustzcash (C23): %s\n", msg);
    fflush(stderr);
    abort();
}

/* One line into the node's debug.log ("zc23: " prefix), whatever -debug says:
 * these lines report a mode choice or a refusal the operator must see. */
static void log_line(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    size_t len = strlen(buf);
    buf[len] = '\n';
    buf[len + 1] = 0;
    zcl_c23_log_sink(buf);
}

/* ------------------------------------------------------------------------ */
/* Files                                                                     */
/* ------------------------------------------------------------------------ */

/* Rust's std::fs::File::open opens with read access only; on Windows it
 * shares read, write and delete and passes FILE_FLAG_BACKUP_SEMANTICS, so a
 * directory opens there and the read that follows fails (as it does on
 * POSIX). */
bool zcl_c23_params_try_open(const zcl_pchar *path, zcl_fh *out)
{
#if defined(_WIN32)
    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    *out = h;
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    *out = fd;
#endif
    return true;
}

zcl_fh zcl_c23_params_open(const zcl_pchar *path, const char *open_msg)
{
    zcl_fh h;
    if (!zcl_c23_params_try_open(path, &h))
        zcl_c23_params_panic(open_msg);
    return h;
}

/* The file is only read; a failing close cannot change bytes already hashed,
 * and Rust's drop of a File ignores the close result as well. */
void zcl_c23_params_close(zcl_fh h)
{
#if defined(_WIN32)
    (void)CloseHandle(h);
#else
    (void)close(h);
#endif
}

/* One read: > 0 bytes read, 0 at end of file, -1 on an error. EINTR is
 * retried, as Rust's BufReader and io::copy do. */
static long long fh_read(zcl_fh h, uint8_t *buf, size_t cap)
{
#if defined(_WIN32)
    DWORD want = cap > (size_t)(1u << 30) ? (DWORD)(1u << 30) : (DWORD)cap;
    DWORD got = 0;
    if (!ReadFile(h, buf, want, &got, NULL))
        return -1;
    return (long long)got;
#else
    for (;;) {
        ssize_t n = read(h, buf, cap);
        if (n >= 0)
            return (long long)n;
        if (errno != EINTR)
            return -1;
    }
#endif
}

#define ZCL_READ_CHUNK ((size_t)1 << 20) /* Rust: BufReader::with_capacity(1 MiB) */

static void hex_digest(char hex[129], const uint8_t d[64])
{
    static const char HEX[] = "0123456789abcdef";
    for (size_t i = 0; i < 64; i++) {
        hex[2 * i] = HEX[d[i] >> 4];
        hex[2 * i + 1] = HEX[d[i] & 15];
    }
    hex[128] = 0;
}

/* Where the next read goes: the kept prefix while it lasts, else scratch. */
static uint8_t *read_dst(struct zcl_c23_hash_job *j, uint8_t *scratch, size_t *cap)
{
    *cap = ZCL_READ_CHUNK;
    if (j->len >= j->keep_cap)
        return scratch;
    size_t left = j->keep_cap - (size_t)j->len;
    if (left < *cap)
        *cap = left;
    return j->kept + j->len;
}

void *zcl_c23_params_hash_run(void *arg)
{
    struct zcl_c23_hash_job *j = arg;
    struct blake2b_ctx b;
    uint8_t d[64];
    j->io_ok = false;
    j->len = 0;
    j->hex[0] = 0;
    if (blake2b_init(&b, sizeof(d)) != 0)
        zcl_c23_params_panic("internal: BLAKE2b-512 initialisation failed");
    if (j->keep_cap) {
        j->kept = malloc(j->keep_cap);
        if (!j->kept)
            zcl_c23_params_panic("out of memory reading a Sapling parameter file");
    }
    uint8_t *scratch = malloc(ZCL_READ_CHUNK);
    if (!scratch)
        zcl_c23_params_panic("out of memory reading a parameter file");
    for (;;) {
        size_t cap;
        uint8_t *dst = read_dst(j, scratch, &cap);
        long long n = fh_read(j->fh, dst, cap);
        if (n < 0)
            goto out;
        if (n == 0)
            break;
        if (blake2b_update(&b, dst, (size_t)n) != 0)
            zcl_c23_params_panic("internal: BLAKE2b-512 update failed");
        j->len += (uint64_t)n;
    }
    if (blake2b_final(&b, d, sizeof(d)) != 0)
        zcl_c23_params_panic("internal: BLAKE2b-512 finalisation failed");
    hex_digest(j->hex, d);
    j->io_ok = true;
out:
    free(scratch);
    return NULL;
}

#if defined(_WIN32)
char *zcl_c23_params_wide_to_utf8(const wchar_t *w)
{
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, NULL, 0,
                                NULL, NULL);
    if (n <= 0)
        return NULL;
    char *out = malloc((size_t)n);
    if (!out)
        zcl_c23_params_panic("out of memory converting a parameter path");
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w, -1, out, n, NULL,
                            NULL) != n) {
        free(out);
        return NULL;
    }
    return out;
}
#endif

/* Nanoseconds of a stat time: st_mtim/st_ctim on Linux, whole seconds on the
 * other POSIX systems (the device, inode and size still change on a swap). */
#if defined(__linux__)
#define ZCL_ST_NS(st, f) ((int64_t)(st).f##tim.tv_sec * 1000000000 + (int64_t)(st).f##tim.tv_nsec)
#else
#define ZCL_ST_NS(st, f) ((int64_t)(st).f##time * 1000000000)
#endif

bool zcl_c23_params_stamp(zcl_fh h, struct zcl_c23_file_stamp *out)
{
    memset(out, 0, sizeof(*out));
#if defined(_WIN32)
    BY_HANDLE_FILE_INFORMATION bi;
    if (!GetFileInformationByHandle(h, &bi))
        return false;
    out->dev = bi.dwVolumeSerialNumber;
    out->ino = ((uint64_t)bi.nFileIndexHigh << 32) | bi.nFileIndexLow;
    out->size = ((uint64_t)bi.nFileSizeHigh << 32) | bi.nFileSizeLow;
    /* 100 ns units: the stamp is only ever compared with another stamp. */
    out->mtime_ns = (int64_t)(((uint64_t)bi.ftLastWriteTime.dwHighDateTime << 32) |
                              bi.ftLastWriteTime.dwLowDateTime);
#else
    struct stat st;
    if (fstat(h, &st) != 0)
        return false;
    out->dev = (uint64_t)st.st_dev;
    out->ino = (uint64_t)st.st_ino;
    out->size = (uint64_t)st.st_size;
    out->mtime_ns = ZCL_ST_NS(st, st_m);
    out->ctime_ns = ZCL_ST_NS(st, st_c);
#endif
    return true;
}

static bool stamp_eq(const struct zcl_c23_file_stamp *a,
                     const struct zcl_c23_file_stamp *b)
{
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size &&
           a->mtime_ns == b->mtime_ns && a->ctime_ns == b->ctime_ns;
}

/* ------------------------------------------------------------------------ */
/* Mode and registry                                                         */
/* ------------------------------------------------------------------------ */

bool zcl_c23_params_lazy_requested(void)
{
    const char *v = getenv("ZCL_PARAMS_VERIFY");
    return !(v && strcmp(v, "boot") == 0);
}

struct lazy_file {
    zcl_pchar *path;
    const char *hex;
    uint64_t size;
};
struct lazy_reg {
    struct lazy_file f[3]; /* spend, output, sprout */
};

static atomic_int g_mode;                   /* 0 none, 1 boot, 2 lazy */
static _Atomic(struct lazy_reg *) g_reg;    /* lazy mode; never freed */
static _Atomic(int64_t) g_resident;         /* raw parameter bytes held */

static zcl_pchar *pchar_dup(const zcl_pchar *s)
{
#if defined(_WIN32)
    size_t n = wcslen(s) + 1;
#else
    size_t n = strlen(s) + 1;
#endif
    zcl_pchar *d = malloc(n * sizeof(zcl_pchar));
    if (!d)
        zcl_c23_params_panic("out of memory copying a parameter path");
    memcpy(d, s, n * sizeof(zcl_pchar));
    return d;
}

void zcl_c23_params_register(const struct zcl_c23_param_file files[3], bool lazy)
{
    if (lazy) {
        struct lazy_reg *r = malloc(sizeof(*r));
        if (!r)
            zcl_c23_params_panic("out of memory recording the parameter files");
        for (int i = 0; i < 3; i++) {
            r->f[i].path = pchar_dup(files[i].path);
            r->f[i].hex = files[i].hex;
            r->f[i].size = files[i].size;
        }
        atomic_store_explicit(&g_reg, r, memory_order_release);
        log_line("zk params: verify mode lazy (Sprout and Sapling proving bytes "
                 "are verified at first proof)");
    }
    atomic_store_explicit(&g_mode, lazy ? 2 : 1, memory_order_release);
}

int zcl_c23_params_mode(void)
{
    return atomic_load_explicit(&g_mode, memory_order_acquire);
}

void zcl_c23_params_resident_add(int64_t delta)
{
    atomic_fetch_add_explicit(&g_resident, delta, memory_order_relaxed);
}

size_t zcl_c23_params_bytes_resident(void)
{
    int64_t v = atomic_load_explicit(&g_resident, memory_order_relaxed);
    return v > 0 ? (size_t)v : 0;
}

/* ------------------------------------------------------------------------ */
/* Proof-time loads                                                          */
/* ------------------------------------------------------------------------ */

/* Whole file into a new buffer, only if it still has its init-time size and
 * digest. */
static bool load_verified(const struct lazy_file *f, uint8_t **out)
{
    struct zcl_c23_hash_job j;
    memset(&j, 0, sizeof(j));
    *out = NULL;
    if (!zcl_c23_params_try_open(f->path, &j.fh))
        return false;
    j.keep_cap = (size_t)f->size;
    zcl_c23_params_hash_run(&j);
    zcl_c23_params_close(j.fh);
    if (!j.io_ok || j.len != f->size || strcmp(j.hex, f->hex) != 0) {
        free(j.kept);
        return false;
    }
    *out = j.kept;
    return true;
}

static atomic_bool g_sapling_refusal_logged;

bool zcl_c23_params_load_sapling(uint8_t **spend, size_t *spend_len,
                                 uint8_t **output, size_t *output_len)
{
    const struct lazy_reg *r = atomic_load_explicit(&g_reg, memory_order_acquire);
    *spend = *output = NULL;
    if (r && load_verified(&r->f[0], spend) && load_verified(&r->f[1], output)) {
        *spend_len = (size_t)r->f[0].size;
        *output_len = (size_t)r->f[1].size;
        zcl_c23_params_resident_add((int64_t)(r->f[0].size + r->f[1].size));
        return true;
    }
    free(*spend);
    *spend = NULL;
    if (!atomic_exchange(&g_sapling_refusal_logged, true))
        log_line("Sapling proving parameters changed on disk since start-up; "
                 "refusing to prove");
    return false;
}

/* The Sprout file is hashed once per process and again only when its stamp
 * changes. g_sprout_mu serialises the check, so racing first Sprout proofs
 * hash the 692 MiB file once. */
static pthread_mutex_t g_sprout_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_sprout_ok;                       /* g_sprout_mu */
static struct zcl_c23_file_stamp g_sprout_st;  /* g_sprout_mu */
static atomic_bool g_sprout_refusal_logged;

static void set_err(char *err, size_t errsz, const char *msg)
{
    if (err && errsz)
        snprintf(err, errsz, "%s", msg);
}

static const char SPROUT_CHANGED[] =
    "Sprout proving parameters (sprout-groth16.params) do not match the "
    "canonical BLAKE2b-512 digest; refusing to create a Sprout proof. Clean "
    "`~/.zcash-params/` and re-run `fetch-params`.";

/* Under g_sprout_mu: hashes the file behind h unless the last verified stamp
 * still matches. Closes h. */
static bool sprout_check_locked(const struct lazy_file *f, zcl_fh h)
{
    struct zcl_c23_file_stamp st;
    bool have = zcl_c23_params_stamp(h, &st);
    if (have && g_sprout_ok && stamp_eq(&st, &g_sprout_st)) {
        zcl_c23_params_close(h);
        return true;
    }
    struct zcl_c23_hash_job j;
    memset(&j, 0, sizeof(j));
    j.fh = h;
    zcl_c23_params_hash_run(&j);
    zcl_c23_params_close(h);
    g_sprout_ok = have && j.io_ok && j.len == f->size && strcmp(j.hex, f->hex) == 0;
    g_sprout_st = st;
    return g_sprout_ok;
}

bool zcl_c23_sprout_params_ready(char *err, size_t errsz)
{
    int mode = zcl_c23_params_mode();
    if (mode == 1)
        return true; /* boot mode: init hashed the file */
    const struct lazy_reg *r = atomic_load_explicit(&g_reg, memory_order_acquire);
    if (mode != 2 || !r) {
        set_err(err, errsz, "the zk-SNARK parameters are not loaded yet");
        return false;
    }
    zcl_fh h;
    if (!zcl_c23_params_try_open(r->f[2].path, &h)) {
        set_err(err, errsz, "could not open the Sprout proving parameters "
                            "(sprout-groth16.params)");
        return false;
    }
    pthread_mutex_lock(&g_sprout_mu);
    bool ok = sprout_check_locked(&r->f[2], h);
    pthread_mutex_unlock(&g_sprout_mu);
    if (!ok) {
        set_err(err, errsz, SPROUT_CHANGED);
        if (!atomic_exchange(&g_sprout_refusal_logged, true))
            log_line("%s", SPROUT_CHANGED);
    }
    return ok;
}
