/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Start one command as the leader of a private process group. On POSIX this
 * is setsid(2)/setpgid(2) then execvp. On Windows the equivalent bounded
 * tree is a kill-on-close Job Object: this process stays the supervisor,
 * so the harness PID is the job owner, and closing it reaps descendants.
 */

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Append `count` copies of ch to out[*used..], never writing past cap-1
 * (the final NUL slot). Factored out of quote_arg() so its repeated
 * bounded-append loops do not each add to that function's own complexity. */
static void append_repeated(char *out, size_t cap, size_t *used, char ch,
                            size_t count)
{
    for (size_t i = 0; i < count && *used + 1 < cap; i++)
        out[(*used)++] = ch;
}

/* MS command-line quoting escapes a literal '"' as (2n+1) backslashes plus
 * a quote, where n is the run of backslashes immediately preceding it. */
static void quote_arg_emit_escaped_quote(char *out, size_t cap, size_t *used,
                                         size_t slashes)
{
    append_repeated(out, cap, used, '\\', slashes * 2u + 1u);
    append_repeated(out, cap, used, '"', 1);
}

static size_t quote_arg(char *out, size_t cap, const char *arg)
{
    size_t used = 0, slashes = 0;
    bool quote = !arg[0] || strpbrk(arg, " \t\n\v\"") != NULL;
    if (quote) append_repeated(out, cap, &used, '"', 1);
    for (const char *p = arg;; p++) {
        if (*p == '\\') { slashes++; continue; }
        if (*p == '"') {
            quote_arg_emit_escaped_quote(out, cap, &used, slashes);
        } else {
            if (*p == 0 && quote) slashes *= 2u;
            append_repeated(out, cap, &used, '\\', slashes);
            if (*p == 0) break;
            append_repeated(out, cap, &used, *p, 1);
        }
        slashes = 0;
    }
    if (quote) append_repeated(out, cap, &used, '"', 1);
    if (cap) out[used < cap ? used : cap - 1] = 0;
    return used;
}

static bool build_command(int argc, char **argv, char *out, size_t cap)
{
    size_t used = 0;
    if (!out || cap < 2) return false;
    out[0] = 0;
    for (int i = 1; i < argc; i++) {
        if (i > 1) {
            if (used + 1 >= cap) return false;
            out[used++] = ' ';
        }
        size_t wrote = quote_arg(out + used, cap - used, argv[i]);
        if (wrote + used + 1 >= cap) return false;
        used += wrote;
    }
    return true;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "process-group-exec: usage: process-group-exec COMMAND [ARG ...]\n");
        return 2;
    }

    char command[32768];
    if (!build_command(argc, argv, command, sizeof(command))) {
        fprintf(stderr, "process-group-exec: command line is too long\n");
        return 2;
    }

    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job ||
        !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) {
        if (job) CloseHandle(job);
        fprintf(stderr, "process-group-exec: cannot create job object (win32=%lu)\n",
                (unsigned long)GetLastError());
        return 126;
    }

    STARTUPINFOA startup = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION process = {0};
    BOOL started = CreateProcessA(
        NULL, command, NULL, NULL, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &process);
    if (!started) {
        fprintf(stderr, "process-group-exec: cannot execute %s (win32=%lu)\n",
                argv[1], (unsigned long)GetLastError());
        CloseHandle(job);
        return 127;
    }
    if (!AssignProcessToJobObject(job, process.hProcess)) {
        fprintf(stderr, "process-group-exec: cannot assign job (win32=%lu)\n",
                (unsigned long)GetLastError());
        (void)TerminateProcess(process.hProcess, 126);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(job);
        return 126;
    }
    if (ResumeThread(process.hThread) == (DWORD)-1) {
        fprintf(stderr, "process-group-exec: cannot resume child (win32=%lu)\n",
                (unsigned long)GetLastError());
        (void)TerminateProcess(process.hProcess, 126);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(job);
        return 126;
    }
    CloseHandle(process.hThread);

    DWORD wait = WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 1;
    if (wait == WAIT_OBJECT_0)
        (void)GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hProcess);
    CloseHandle(job);
    return (int)exit_code;
}

#else

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

/* Seconds a group gets to exit on TERM after its launching parent died. */
#define PARENT_DEATH_GRACE_S 5L

#define PGE_USAGE "process-group-exec [--die-with-parent | --die-with-lease FILE:STALE[:GRACE]] COMMAND [ARG ...]"

/* --die-with-lease supervision spec. The lease file's mtime is the driver's
 * proof of control: whoever launched this group keeps it fresh, and a file
 * that is missing or older than stale_s means that control is gone, so the
 * supervisor terminates the one process group it spawned. Ownership stays
 * exact — no PPID heuristic, no port claim, no pid that could be reused. */
struct lease_spec {
    char file[512];
    long stale_s;
    long grace_s;
};

/* Parse one whole-positive seconds field (the caller splits on colons
 * first, so the field must run to the NUL). Returns false on any
 * malformation, including strtol's out-of-range clamp (errno=ERANGE). */
static bool lease_field_seconds(const char *text, long *out)
{
    *out = 0;
    char *end = NULL;
    errno = 0;
    long v = strtol(text, &end, 10);
    if (errno == ERANGE || end == text || *end != 0 || v < 1)
        return false;
    *out = v;
    return true;
}

static int lease_parse(const char *spec, struct lease_spec *out)
{
    memset(out, 0, sizeof(*out));
    /* FILE:STALE[:GRACE], colon-separated; every field must be present and
     * whole-positive. The file path may not contain a colon: fail closed
     * instead of half-parsing a mangled spec. */
    const char *c1 = strchr(spec, ':');
    if (!c1)
        return 0;
    const char *c2 = strchr(c1 + 1, ':');
    char *end;
    errno = 0;
    long stale = strtol(c1 + 1, &end, 10);
    const char *field_end = c2 ? c2 : spec + strlen(spec);
    if (errno == ERANGE || end == c1 + 1 || end != field_end || stale < 1)
        return 0;
    long grace = 30;
    if (c2) {
        if (strchr(c2 + 1, ':'))
            return 0;
        /* reap_leased_group computes grace_s * 5; refuse values that
         * would overflow it. */
        if (!lease_field_seconds(c2 + 1, &grace) || grace > LONG_MAX / 5)
            return 0;
    }
    size_t file_len = (size_t)(c1 - spec);
    if (file_len == 0 || file_len >= sizeof(out->file))
        return 0;
    memcpy(out->file, spec, file_len);
    out->file[file_len] = 0;
    out->stale_s = stale;
    out->grace_s = grace;
    return 1;
}

static int lease_stale(const struct lease_spec *lease, char *why, size_t cap)
{
    struct stat st;
    if (stat(lease->file, &st) != 0) {
        snprintf(why, cap, "stat: %s", strerror(errno));
        return 1;
    }
    double age = difftime(time(NULL), st.st_mtime); // platform-ok: standalone supervision tool, no platform linkage; lease age is fixture-reap timing, not consensus timing
    if (age > (double)lease->stale_s) {
        snprintf(why, cap, "age %.0fs exceeds %lds", age, lease->stale_s);
        return 1;
    }
    return 0;
}

/* Map a reaped child's wait status to the launcher's pass-through exit
 * code: its own exit code, or 128+signal when a signal ended it. */
static int child_status_code(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 125;
}

/* The lease went stale: terminate the group this launcher created. TERM
 * first, then SIGKILL after grace_s. The SIGKILL takes the whole group
 * including this supervisor — SIGKILL cannot spare the leader — and a
 * supervisor that dies with its unreapable child still meets the contract
 * that the group is gone. */
static int reap_leased_group(pid_t child, long grace_s)
{
    int status = 0;
    pid_t rc;
    struct timespec ts;
    kill(-getpgrp(), SIGTERM);
    long slices = grace_s * 5; /* 200ms slices per second */
    long waited = 0;
    while (waited < slices) {
        rc = waitpid(child, &status, WNOHANG);
        if (rc == child)
            return child_status_code(status);
        ts.tv_sec = 0;
        ts.tv_nsec = 200L * 1000L * 1000L;
        nanosleep(&ts, NULL);
        waited++;
    }
    fprintf(stderr, "process-group-exec: group ignored TERM for %lds: SIGKILL\n",
            grace_s);
    kill(-getpgrp(), SIGKILL);
    /* unreachable in practice: the group kill includes us */
    for (;;)
        pause();
}

/* Stay resident as the group leader and supervise the command, by lease
 * file (lease != NULL) and/or by its launching parent (parent > 0).
 * Returns the child's pass-through exit status when the child ends (by
 * itself, by a group signal from the caller's cleanup, or by the lease
 * reap below). */
static int supervise_leased(const struct lease_spec *lease, pid_t parent,
                            char **child_argv)
{
    char why[256];
    struct timespec ts;
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "process-group-exec: cannot fork supervisor child: %s\n",
                strerror(errno));
        return 126;
    }
    if (child == 0) {
        execvp(child_argv[0], child_argv);
        fprintf(stderr, "process-group-exec: cannot execute %s: %s\n",
                child_argv[0], strerror(errno));
        _exit(127);
    }
    /* The supervisor must survive the group TERMs it issues and the ones
     * the caller's cleanup sends, so it can still reap the child and pass
     * the status through. Set only in the parent: a disposition set before
     * fork would cross execvp into the supervised command. */
    struct sigaction ign = {0};
    ign.sa_handler = SIG_IGN;
    sigaction(SIGTERM, &ign, NULL);
    sigaction(SIGHUP, &ign, NULL);

    /* Check cadence: at least four checks per stale window, bounded to
     * [1s, 5s] so both a 1s test window and a 180s journey window get
     * bounded detection latency. */
    long poll_s = lease ? lease->stale_s / 4 : 1;
    if (poll_s < 1 || parent > 0)
        poll_s = 1;
    if (poll_s > 5)
        poll_s = 5;

    for (;;) {
        int status = 0;
        pid_t rc = waitpid(child, &status, WNOHANG);
        if (rc == child)
            return child_status_code(status);
        if (rc < 0 && errno != EINTR) {
            fprintf(stderr, "process-group-exec: waitpid failed: %s\n",
                    strerror(errno));
            return 125;
        }
        if (parent > 0 && getppid() != parent) {
            fprintf(stderr,
                    "process-group-exec: launching parent exited: "
                    "terminating group\n");
            return reap_leased_group(child, PARENT_DEATH_GRACE_S);
        }
        if (lease && lease_stale(lease, why, sizeof(why))) {
            fprintf(stderr,
                    "process-group-exec: supervision lease %s is stale (%s): "
                    "terminating group\n",
                    lease->file, why);
            return reap_leased_group(child, lease->grace_s);
        }
        ts.tv_sec = poll_s;
        ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
    }
}

int main(int argc, char **argv)
{
    int die_with_parent = 0;
    struct lease_spec lease = {0};
    int have_lease = 0;
    int first = 1;
    if (argc < 2) {
        fprintf(stderr, "process-group-exec: usage: %s\n", PGE_USAGE);
        return 2;
    }
    /* Exactly one optional leading flag; anything else that starts with
     * '-' is a usage error rather than a silently executed filename, so
     * a misspelled flag fails closed instead of launching the wrong
     * thing. */
    if (argv[1][0] == '-') {
        if (strcmp(argv[1], "--die-with-parent") == 0) {
            die_with_parent = 1;
            first = 2;
        } else if (strncmp(argv[1], "--die-with-lease=", 17) == 0) {
            if (!lease_parse(argv[1] + 17, &lease)) {
                fprintf(stderr,
                        "process-group-exec: bad lease spec %s "
                        "(want FILE:STALE[:GRACE], whole seconds)\n",
                        argv[1] + 17);
                return 2;
            }
            have_lease = 1;
            first = 2;
        } else {
            fprintf(stderr,
                    "process-group-exec: unknown flag %s (usage: %s)\n",
                    argv[1], PGE_USAGE);
            return 2;
        }
        if (argc < 3) {
            fprintf(stderr,
                    "process-group-exec: %s needs COMMAND\n", argv[1]);
            return 2;
        }
    }

    if (setsid() < 0 && setpgid(0, 0) < 0) {
        fprintf(stderr, "process-group-exec: cannot create process group: %s\n",
                strerror(errno));
        return 126;
    }

    if (die_with_parent) {
#if defined(__linux__) && defined(PR_SET_PDEATHSIG)
        /* The kernel reaps this whole tree when the launching shell dies,
         * so a crashed driver cannot strand a fixture daemon on a shared
         * port. Deliberately NOT the default, and not for remote journey
         * legs: their parent is one short ssh session of many, so they
         * take --die-with-lease instead. Applied before exec and after
         * setsid; prctl survives both. */
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
            fprintf(stderr,
                    "process-group-exec: cannot request parent-death "
                    "signal: %s\n",
                    strerror(errno));
            return 126;
        }
        /* Race closure: if the parent died between fork and prctl, the
         * signal was never armed for that death. Check once now. */
        if (getppid() == 1) {
            fprintf(stderr,
                    "process-group-exec: parent already exited before "
                    "parent-death signal was armed\n");
            return 125;
        }
#else
        /* No kernel parent-death signal here: stay resident as the group
         * leader and reap the group within a second of the launching
         * process being reparented. */
        pid_t parent = getppid();
        if (parent == 1) {
            fprintf(stderr,
                    "process-group-exec: parent already exited before "
                    "parent-death supervision was armed\n");
            return 125;
        }
        return supervise_leased(NULL, parent, &argv[first]);
#endif
    }

    if (have_lease) {
        /* The remote-leg orphan counterpart of --die-with-parent: the
         * launching ssh session is gone by design, so the kernel cannot
         * watch a parent; the lease file is the driver's liveness instead.
         * Fully POSIX: stat, sleep, kill. */
        return supervise_leased(&lease, 0, &argv[first]);
    }

    execvp(argv[first], &argv[first]);
    fprintf(stderr, "process-group-exec: cannot execute %s: %s\n", argv[first],
            strerror(errno));
    return 127;
}

#endif
