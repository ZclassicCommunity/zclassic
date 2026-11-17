/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 *
 * In-process Tor: tor_run_main on a thread of the daemon, the way Z23 runs it
 * (core/modules/net/src/tor_integration.c). See zcl_tor_inproc.h.
 *
 * What Tor does to process-wide state when it runs here (checked against the
 * pinned fork, src/app/main/main.c, src/lib/evloop/compat_libevent.c,
 * src/lib/crypt_ops/crypto_openssl_mgt.c):
 *  - event_set_mem_functions(tor_malloc_, tor_realloc_, tor_free_): libevent's
 *    allocator hooks become Tor's wrappers. They call the C library heap, so
 *    blocks allocated before and freed after are compatible; the difference
 *    is that an allocation failure aborts.
 *  - event_set_log_callback: libevent warnings go to Tor's log until the
 *    daemon re-installs its own callback (after start and after stop).
 *  - signal handlers: turned off by the caller with __DisableSignalHandlers 1.
 *  - OpenSSL: OPENSSL_init_ssl (additive), CONF_modules_unload at exit. The
 *    daemon and Tor link the same libcrypto/libssl archive.
 * A failed assertion inside Tor aborts the whole process. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* strict _POSIX_C_SOURCE hides O_NOFOLLOW etc. on Darwin */
#endif
#endif

#include "zcl_tor_inproc.h"
#include "zcl_tor_proc.h"

#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
#else
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <event2/event.h>
#include <event2/thread.h>
#include <tor_api.h>

struct zcl_tor_inproc {
    tor_main_configuration_t *cfg;
    char **argv;
    int argc;
    atomic_int done;
    int rc;
    bool joined;
#ifdef _WIN32
    HANDLE th;
#else
    pthread_t th;
    int owner_fd; /* our end of the owner channel, -1 once closed */
    int tor_fd;   /* Tor's end; Tor closes it when it takes it */
    dev_t tor_dev;
    ino_t tor_ino;
#endif
};

/* One Tor per process (tor_api.h: concurrent tor_run_main is undefined). */
static atomic_bool g_running;

static void ie(char *err, size_t errsz, const char *fmt, ...)
{
    va_list ap;
    if (!err || errsz == 0)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

/* Carried patch depends/patches/tor/0002-dynhost-set-enabled.patch: the pinned
 * fork starts a second, random-key onion service (dynhost) on its own. The
 * daemon makes its onion service through the control port; switch dynhost off
 * before Tor runs. Not declared in tor_api.h. */
extern void dynhost_set_enabled(int enabled);

static void run(struct zcl_tor_inproc *p)
{
    dynhost_set_enabled(0);
    p->rc = tor_run_main(p->cfg);
    atomic_store(&p->done, 1);
}

#ifdef _WIN32
static unsigned __stdcall thread_main(void *arg)
{
    run((struct zcl_tor_inproc *)arg);
    return 0;
}
#else
static void *thread_main(void *arg)
{
    run((struct zcl_tor_inproc *)arg);
    return NULL;
}
#endif

static void free_argv(struct zcl_tor_inproc *p)
{
    int i;
    if (!p->argv)
        return;
    for (i = 0; i < p->argc; i++)
        free(p->argv[i]);
    free(p->argv);
    p->argv = NULL;
}

static bool push_arg(struct zcl_tor_inproc *p, const char *s)
{
    size_t n = strlen(s) + 1;
    char *c = (char *)malloc(n);
    if (!c)
        return false;
    memcpy(c, s, n);
    p->argv[p->argc++] = c;
    return true;
}

bool zcl_tor_inproc_busy(void)
{
    return atomic_load(&g_running);
}

int zcl_tor_inproc_start(struct zcl_tor_inproc **out,
                         const char *const *tor_args, size_t ntor_args,
                         char *err, size_t errsz)
{
    struct zcl_tor_inproc *p;
    bool idle = false;
    size_t i;

    *out = NULL;
    if (!atomic_compare_exchange_strong(&g_running, &idle, true)) {
        ie(err, errsz, "an in-process Tor is already running in this process");
        return -1;
    }
    p = (struct zcl_tor_inproc *)calloc(1, sizeof(*p));
    if (!p) {
        ie(err, errsz, "out of memory");
        goto fail_flag;
    }
#ifndef _WIN32
    p->owner_fd = -1;
    p->tor_fd = -1;
#endif
    p->argv = (char **)calloc(ntor_args + 5, sizeof(char *));
    /* --quiet: no console log before the torrc is read; stdout and stderr
     * belong to the daemon. */
    if (!p->argv || !push_arg(p, "tor") || !push_arg(p, "--quiet")) {
        ie(err, errsz, "out of memory");
        goto fail;
    }
    for (i = 0; i < ntor_args; i++) {
        if (!push_arg(p, tor_args[i])) {
            ie(err, errsz, "out of memory");
            goto fail;
        }
    }
#ifndef _WIN32
    {
        /* Our own socketpair rather than
         * tor_main_configuration_setup_control_socket: that API's free
         * function closes Tor's end a second time after Tor has closed it,
         * which in a threaded process can close an unrelated descriptor. */
        int sp[2];
        struct stat st;
        char num[16];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) != 0) {
            ie(err, errsz, "socketpair for the owner channel failed");
            goto fail;
        }
        p->owner_fd = sp[0];
        p->tor_fd = sp[1];
        if (fstat(sp[1], &st) == 0) {
            p->tor_dev = st.st_dev;
            p->tor_ino = st.st_ino;
        }
        (void)snprintf(num, sizeof(num), "%d", sp[1]);
        if (!push_arg(p, "__OwningControllerFD") || !push_arg(p, num)) {
            ie(err, errsz, "out of memory");
            goto fail;
        }
    }
    /* Make libevent thread-aware before Tor creates its event base; the
     * daemon makes the same call for its own bases. */
    (void)evthread_use_pthreads();
#else
    (void)evthread_use_windows_threads();
#endif
    p->cfg = tor_main_configuration_new();
    if (!p->cfg ||
        tor_main_configuration_set_command_line(p->cfg, p->argc, p->argv) != 0) {
        ie(err, errsz, "tor_main_configuration setup failed");
        goto fail;
    }
#ifdef _WIN32
    p->th = (HANDLE)_beginthreadex(NULL, 0, thread_main, p, 0, NULL);
    if (!p->th) {
        ie(err, errsz, "cannot create the Tor thread");
        goto fail;
    }
#else
    if (pthread_create(&p->th, NULL, thread_main, p) != 0) {
        ie(err, errsz, "cannot create the Tor thread");
        goto fail;
    }
#endif
    *out = p;
    return 0;
fail:
    if (p->cfg)
        tor_main_configuration_free(p->cfg);
#ifndef _WIN32
    if (p->owner_fd >= 0)
        (void)close(p->owner_fd);
    if (p->tor_fd >= 0)
        (void)close(p->tor_fd);
#endif
    free_argv(p);
    free(p);
fail_flag:
    atomic_store(&g_running, false);
    return -1;
}

bool zcl_tor_inproc_alive(struct zcl_tor_inproc *p)
{
    return p && !p->joined && atomic_load(&p->done) == 0;
}

void zcl_tor_inproc_release_owner(struct zcl_tor_inproc *p)
{
#ifndef _WIN32
    if (p && p->owner_fd >= 0) {
        (void)close(p->owner_fd);
        p->owner_fd = -1;
    }
#else
    (void)p;
#endif
}

bool zcl_tor_inproc_wait(struct zcl_tor_inproc *p, unsigned timeout_ms)
{
    uint64_t end;
    if (!p)
        return true;
    if (p->joined)
        return true;
    end = zcl_tor_now_ms() + timeout_ms;
    while (atomic_load(&p->done) == 0) {
        if (zcl_tor_now_ms() >= end)
            return false;
        zcl_tor_sleep_ms(10);
    }
#ifdef _WIN32
    (void)WaitForSingleObject(p->th, INFINITE);
    (void)CloseHandle(p->th);
#else
    (void)pthread_join(p->th, NULL);
#endif
    p->joined = true;
    return true;
}

void zcl_tor_inproc_close(struct zcl_tor_inproc *p)
{
    if (!p || !p->joined)
        return;
    zcl_tor_inproc_release_owner(p);
#ifndef _WIN32
    if (p->tor_fd >= 0) {
        /* Tor closes its end once it has taken it. If Tor failed before that
         * (bad configuration), the descriptor is still ours: close it only
         * when it is still the same socket. */
        struct stat st;
        if (fstat(p->tor_fd, &st) == 0 && S_ISSOCK(st.st_mode) &&
            st.st_dev == p->tor_dev && st.st_ino == p->tor_ino)
            (void)close(p->tor_fd);
        p->tor_fd = -1;
    }
#endif
    tor_main_configuration_free(p->cfg);
    free_argv(p);
    free(p);
    atomic_store(&g_running, false);
}
