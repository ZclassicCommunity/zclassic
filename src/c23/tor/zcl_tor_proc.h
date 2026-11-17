/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 * Internal: platform child-process layer for zcl_tor_embed. */
#ifndef ZCL_C23_TOR_PROC_H
#define ZCL_C23_TOR_PROC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

struct zcl_tor_proc {
#ifdef _WIN32
    HANDLE process;
    HANDLE job;
    unsigned long pid;
#else
    int pid;
    int owner_fd; /* parent end of the owner channel, -1 once closed */
#endif
    bool reaped;
    int exit_status;
};

uint64_t zcl_tor_now_ms(void);
void zcl_tor_sleep_ms(unsigned ms);

/* Start `exe` as: exe ZCL_TOR_EMBED_ARG <keep> <tor_args...> with the owner
 * channel arguments appended. `tor_args` are the Tor command-line arguments
 * after the program name. stdin is the null device; stdout and stderr are
 * appended to `stdio_log`. The child lives in its own process group (POSIX)
 * or job object that kills it when the parent handle closes (Windows). */
int zcl_tor_proc_spawn(struct zcl_tor_proc *p, const char *exe,
                       const char *const *tor_args, size_t ntor_args,
                       const char *stdio_log, char *err, size_t errsz);

/* The form of an existing directory `utf8` that Tor itself can open. POSIX:
 * a copy. Windows: Tor uses narrow ANSI file APIs, so unless the process has
 * a UTF-8 active code page the directory is returned as an ASCII 8.3 short
 * path; if that is impossible the call fails with a message in `err`. The
 * result uses backslashes. */
int zcl_tor_proc_tor_path(const char *utf8, char *out, size_t cap, char *err, size_t errsz);

/* Resolve this binary's path. */
int zcl_tor_proc_self_exe(char *out, size_t cap);

/* Non-blocking: true while running (and reaps the child when it has exited). */
bool zcl_tor_proc_alive(struct zcl_tor_proc *p);
/* Close the owner channel (POSIX: Tor sees EOF on its owning controller and
 * exits). No-op on Windows, where the job object does that. */
void zcl_tor_proc_release_owner(struct zcl_tor_proc *p);
/* Ask politely (SIGTERM / no-op on Windows) or kill (SIGKILL /
 * TerminateProcess). */
void zcl_tor_proc_terminate(struct zcl_tor_proc *p);
void zcl_tor_proc_kill(struct zcl_tor_proc *p);
/* Wait up to timeout_ms for exit; true when the child is gone. */
bool zcl_tor_proc_wait(struct zcl_tor_proc *p, unsigned timeout_ms);
/* Release OS handles after the child is gone. */
void zcl_tor_proc_close(struct zcl_tor_proc *p);

#endif
