/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 * POSIX child-process layer for zcl_tor_embed (posix_spawn, no shell).
 *
 * Owner channel: a socketpair. The child end is passed to Tor as
 * __OwningControllerFD 3 (Tor treats it as a pre-authenticated owning
 * control connection and exits when it sees EOF). The parent end is closed
 * on stop, and by the kernel if the parent dies by any means, including
 * kill -9. This is the same mechanism Z23 uses in-process. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include "zcl_tor_proc.h"
#include "zcl_tor_embed.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static void pe(char *err, size_t errsz, const char *fmt, ...)
{
    va_list ap;
    if (!err || errsz == 0)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

uint64_t zcl_tor_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

void zcl_tor_sleep_ms(unsigned ms)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

int zcl_tor_proc_tor_path(const char *utf8, char *out, size_t cap, char *err, size_t errsz)
{
    int n = snprintf(out, cap, "%s", utf8);
    if (n > 0 && (size_t)n < cap)
        return 0;
    if (err && errsz)
        (void)snprintf(err, errsz, "path too long");
    return -1;
}

int zcl_tor_proc_self_exe(char *out, size_t cap)
{
#ifdef __linux__
    /* Opening /proc/self/exe also works if the file was replaced by an
     * upgrade, so use it directly rather than resolving it. */
    int n = snprintf(out, cap, "/proc/self/exe");
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
#else
    (void)out;
    (void)cap;
    return -1; /* caller must pass exe_path */
#endif
}

/* Move fd to a descriptor >= 10 so the dup2 targets 0..3 cannot collide. */
static int high_fd(int fd)
{
    int n = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    int saved = errno;
    (void)close(fd);
    errno = saved;
    return n;
}

int zcl_tor_proc_spawn(struct zcl_tor_proc *p, const char *exe,
                       const char *const *tor_args, size_t ntor_args,
                       const char *stdio_log, char *err, size_t errsz)
{
    int sv[2] = {-1, -1};
    int nullfd = -1, logfd = -1;
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t at;
    sigset_t none, defs;
    char **av = NULL;
    size_t ac = 0, i;
    int rc, ret = -1;
    bool fa_init = false, at_init = false;
    pid_t pid;

    memset(p, 0, sizeof(*p));
    p->owner_fd = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) {
        pe(err, errsz, "socketpair: %s", strerror(errno));
        return -1;
    }
    if ((sv[0] = high_fd(sv[0])) < 0 || (sv[1] = high_fd(sv[1])) < 0) {
        pe(err, errsz, "fcntl(F_DUPFD_CLOEXEC): %s", strerror(errno));
        goto out;
    }
    nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (nullfd < 0 || (nullfd = high_fd(nullfd)) < 0) {
        pe(err, errsz, "open /dev/null: %s", strerror(errno));
        goto out;
    }
    logfd = open(stdio_log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (logfd < 0 || (logfd = high_fd(logfd)) < 0) {
        pe(err, errsz, "open %s: %s", stdio_log, strerror(errno));
        goto out;
    }

    av = (char **)calloc(ntor_args + 8, sizeof(char *));
    if (!av) {
        pe(err, errsz, "out of memory");
        goto out;
    }
    av[ac++] = (char *)exe;
    av[ac++] = (char *)ZCL_TOR_EMBED_ARG;
    av[ac++] = (char *)"3";
    for (i = 0; i < ntor_args; i++)
        av[ac++] = (char *)tor_args[i];
    av[ac++] = (char *)"__OwningControllerFD";
    av[ac++] = (char *)"3";
    av[ac] = NULL;

    if (posix_spawn_file_actions_init(&fa) != 0) {
        pe(err, errsz, "posix_spawn_file_actions_init failed");
        goto out;
    }
    fa_init = true;
    if (posix_spawnattr_init(&at) != 0) {
        pe(err, errsz, "posix_spawnattr_init failed");
        goto out;
    }
    at_init = true;
    sigemptyset(&none);
    sigemptyset(&defs);
    sigaddset(&defs, SIGPIPE);
    sigaddset(&defs, SIGHUP);
    sigaddset(&defs, SIGINT);
    sigaddset(&defs, SIGTERM);
    sigaddset(&defs, SIGCHLD);
    if (posix_spawn_file_actions_adddup2(&fa, nullfd, 0) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, logfd, 1) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, logfd, 2) != 0 ||
        posix_spawn_file_actions_adddup2(&fa, sv[1], 3) != 0 ||
        posix_spawnattr_setpgroup(&at, 0) != 0 ||
        posix_spawnattr_setsigmask(&at, &none) != 0 ||
        posix_spawnattr_setsigdefault(&at, &defs) != 0 ||
        posix_spawnattr_setflags(&at, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK |
                                          POSIX_SPAWN_SETSIGDEF) != 0) {
        pe(err, errsz, "posix_spawn setup failed");
        goto out;
    }
    rc = posix_spawn(&pid, exe, &fa, &at, av, environ);
    if (rc != 0) {
        pe(err, errsz, "posix_spawn %s: %s", exe, strerror(rc));
        goto out;
    }
    p->pid = (int)pid;
    p->owner_fd = sv[0];
    sv[0] = -1;
    ret = 0;
out:
    if (fa_init)
        (void)posix_spawn_file_actions_destroy(&fa);
    if (at_init)
        (void)posix_spawnattr_destroy(&at);
    free(av);
    if (sv[0] >= 0)
        (void)close(sv[0]);
    if (sv[1] >= 0)
        (void)close(sv[1]);
    if (nullfd >= 0)
        (void)close(nullfd);
    if (logfd >= 0)
        (void)close(logfd);
    return ret;
}

bool zcl_tor_proc_alive(struct zcl_tor_proc *p)
{
    int st = 0;
    pid_t r;
    if (p->reaped || p->pid <= 0)
        return false;
    do {
        r = waitpid((pid_t)p->pid, &st, WNOHANG);
    } while (r < 0 && errno == EINTR);
    if (r == 0)
        return true;
    p->reaped = true;
    p->exit_status = (r > 0) ? st : -1; /* ECHILD: already reaped elsewhere */
    return false;
}

void zcl_tor_proc_release_owner(struct zcl_tor_proc *p)
{
    if (p->owner_fd >= 0) {
        (void)close(p->owner_fd);
        p->owner_fd = -1;
    }
}

void zcl_tor_proc_terminate(struct zcl_tor_proc *p)
{
    if (!p->reaped && p->pid > 0)
        (void)kill((pid_t)p->pid, SIGTERM);
}

void zcl_tor_proc_kill(struct zcl_tor_proc *p)
{
    if (!p->reaped && p->pid > 0)
        (void)kill((pid_t)p->pid, SIGKILL);
}

bool zcl_tor_proc_wait(struct zcl_tor_proc *p, unsigned timeout_ms)
{
    uint64_t end = zcl_tor_now_ms() + timeout_ms;
    for (;;) {
        if (!zcl_tor_proc_alive(p))
            return true;
        if (zcl_tor_now_ms() >= end)
            return false;
        zcl_tor_sleep_ms(20);
    }
}

void zcl_tor_proc_close(struct zcl_tor_proc *p)
{
    zcl_tor_proc_release_owner(p);
}
#endif
