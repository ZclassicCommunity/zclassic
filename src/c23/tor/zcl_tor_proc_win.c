/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 * Windows child-process layer for zcl_tor_embed (CreateProcessW, no shell).
 *
 * The child is assigned to a job object with KILL_ON_JOB_CLOSE, so Windows
 * kills it when the parent exits for any reason. It is also given
 * __OwningControllerProcess <parent pid> so Tor notices on its own.
 * Only the three standard handles are inherited (PROC_THREAD_ATTRIBUTE_
 * HANDLE_LIST). Not run on a Windows host in this unit; compile-checked
 * with the mingw cross compiler. */
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include "zcl_tor_proc.h"
#include "zcl_tor_embed.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

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
    return (uint64_t)GetTickCount64();
}

void zcl_tor_sleep_ms(unsigned ms)
{
    Sleep(ms);
}

static wchar_t *to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0)
        return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w)
        return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) != n) {
        free(w);
        return NULL;
    }
    return w;
}

int zcl_tor_proc_self_exe(char *out, size_t cap)
{
    wchar_t w[32768];
    DWORD n = GetModuleFileNameW(NULL, w, (DWORD)(sizeof(w) / sizeof(w[0])));
    int u;
    if (n == 0 || n >= sizeof(w) / sizeof(w[0]))
        return -1;
    u = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
    return u > 0 ? 0 : -1;
}

#define BSLASH ((wchar_t)0x5c)

/* Append one argument to a wide command line using the rules
 * CommandLineToArgvW inverts. Returns the new length or 0 on overflow. */
static size_t cmd_append(wchar_t *cmd, size_t cap, size_t len, const wchar_t *arg)
{
    int q = (*arg == 0) || wcspbrk(arg, L" \t\n\v\"") != NULL;
    size_t bs = 0, k, n;
    const wchar_t *c;
    /* worst case every character doubles, plus quotes, separator and NUL */
    if (len + wcslen(arg) * 2 + 5 >= cap)
        return 0;
    if (len)
        cmd[len++] = L' ';
    if (q)
        cmd[len++] = L'"';
    for (c = arg; *c; c++) {
        if (*c == BSLASH) {
            bs++;
            continue;
        }
        if (*c == L'"') {
            for (k = 0; k < bs * 2 + 1; k++)
                cmd[len++] = BSLASH;
            cmd[len++] = L'"';
        } else {
            for (k = 0; k < bs; k++)
                cmd[len++] = BSLASH;
            cmd[len++] = *c;
        }
        bs = 0;
    }
    n = q ? bs * 2 : bs;
    for (k = 0; k < n; k++)
        cmd[len++] = BSLASH;
    if (q)
        cmd[len++] = L'"';
    cmd[len] = 0;
    return len;
}

int zcl_tor_proc_spawn(struct zcl_tor_proc *p, const char *exe,
                       const char *const *tor_args, size_t ntor_args,
                       const char *stdio_log, char *err, size_t errsz)
{
    wchar_t *wexe = NULL, *wlog = NULL, *wcmd = NULL;
    const size_t cmdcap = 32768;
    size_t len, i;
    HANDLE hnull = INVALID_HANDLE_VALUE, hlog = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOEXW si;
    PROCESS_INFORMATION pi;
    SIZE_T asz = 0;
    HANDLE inherit[3];
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jl;
    char pidbuf[32];
    int ret = -1;
    int attr_init = 0;

    memset(p, 0, sizeof(*p));
    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));

    wexe = to_wide(exe);
    wlog = to_wide(stdio_log);
    wcmd = (wchar_t *)malloc(cmdcap * sizeof(wchar_t));
    if (!wexe || !wlog || !wcmd) {
        pe(err, errsz, "cannot convert paths to UTF-16 or out of memory");
        goto out;
    }
    wcmd[0] = 0;
    len = 0;
    {
        wchar_t *tmp;
        tmp = to_wide(exe);
        len = tmp ? cmd_append(wcmd, cmdcap, len, tmp) : 0;
        free(tmp);
        if (!len)
            goto toolong;
        tmp = to_wide(ZCL_TOR_EMBED_ARG);
        len = tmp ? cmd_append(wcmd, cmdcap, len, tmp) : 0;
        free(tmp);
        if (!len)
            goto toolong;
        tmp = to_wide("-");
        len = tmp ? cmd_append(wcmd, cmdcap, len, tmp) : 0;
        free(tmp);
        if (!len)
            goto toolong;
        for (i = 0; i < ntor_args; i++) {
            tmp = to_wide(tor_args[i]);
            len = tmp ? cmd_append(wcmd, cmdcap, len, tmp) : 0;
            free(tmp);
            if (!len)
                goto toolong;
        }
        (void)snprintf(pidbuf, sizeof(pidbuf), "%lu", (unsigned long)GetCurrentProcessId());
        tmp = to_wide("__OwningControllerProcess");
        len = tmp ? cmd_append(wcmd, cmdcap, len, tmp) : 0;
        free(tmp);
        if (!len)
            goto toolong;
        tmp = to_wide(pidbuf);
        len = tmp ? cmd_append(wcmd, cmdcap, len, tmp) : 0;
        free(tmp);
        if (!len)
            goto toolong;
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    hnull = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hnull == INVALID_HANDLE_VALUE) {
        pe(err, errsz, "open NUL failed (%lu)", GetLastError());
        goto out;
    }
    hlog = CreateFileW(wlog, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hlog == INVALID_HANDLE_VALUE) {
        pe(err, errsz, "open log failed (%lu)", GetLastError());
        goto out;
    }

    p->job = CreateJobObjectW(NULL, NULL);
    if (!p->job) {
        pe(err, errsz, "CreateJobObject failed (%lu)", GetLastError());
        goto out;
    }
    memset(&jl, 0, sizeof(jl));
    jl.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(p->job, JobObjectExtendedLimitInformation, &jl,
                                 sizeof(jl))) {
        pe(err, errsz, "SetInformationJobObject failed (%lu)", GetLastError());
        goto out;
    }

    inherit[0] = hnull;
    inherit[1] = hlog;
    inherit[2] = hlog;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(asz);
    if (!si.lpAttributeList ||
        !InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &asz)) {
        pe(err, errsz, "InitializeProcThreadAttributeList failed (%lu)", GetLastError());
        goto out;
    }
    attr_init = 1;
    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inherit, sizeof(inherit), NULL, NULL)) {
        pe(err, errsz, "UpdateProcThreadAttribute failed (%lu)", GetLastError());
        goto out;
    }
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = hnull;
    si.StartupInfo.hStdOutput = hlog;
    si.StartupInfo.hStdError = hlog;

    if (!CreateProcessW(wexe, wcmd, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP |
                            EXTENDED_STARTUPINFO_PRESENT,
                        NULL, NULL, &si.StartupInfo, &pi)) {
        pe(err, errsz, "CreateProcess failed (%lu)", GetLastError());
        goto out;
    }
    if (!AssignProcessToJobObject(p->job, pi.hProcess)) {
        pe(err, errsz, "AssignProcessToJobObject failed (%lu)", GetLastError());
        (void)TerminateProcess(pi.hProcess, 1);
        (void)CloseHandle(pi.hProcess);
        (void)CloseHandle(pi.hThread);
        goto out;
    }
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        pe(err, errsz, "ResumeThread failed (%lu)", GetLastError());
        (void)TerminateProcess(pi.hProcess, 1);
        (void)CloseHandle(pi.hProcess);
        (void)CloseHandle(pi.hThread);
        goto out;
    }
    (void)CloseHandle(pi.hThread);
    p->process = pi.hProcess;
    p->pid = pi.dwProcessId;
    ret = 0;
    goto out;
toolong:
    pe(err, errsz, "Tor command line too long or not valid UTF-8");
out:
    if (si.lpAttributeList) {
        if (attr_init)
            DeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
    }
    if (hnull != INVALID_HANDLE_VALUE)
        (void)CloseHandle(hnull);
    if (hlog != INVALID_HANDLE_VALUE)
        (void)CloseHandle(hlog);
    free(wexe);
    free(wlog);
    free(wcmd);
    if (ret != 0 && p->job) {
        (void)CloseHandle(p->job);
        p->job = NULL;
    }
    return ret;
}

bool zcl_tor_proc_alive(struct zcl_tor_proc *p)
{
    DWORD code;
    if (p->reaped || !p->process)
        return false;
    if (!GetExitCodeProcess(p->process, &code) || code == STILL_ACTIVE)
        return true;
    p->reaped = true;
    p->exit_status = (int)code;
    return false;
}

void zcl_tor_proc_release_owner(struct zcl_tor_proc *p)
{
    (void)p; /* the job object is the owner channel on Windows */
}

void zcl_tor_proc_terminate(struct zcl_tor_proc *p)
{
    (void)p; /* no polite signal for a console-less process; stop() sends
              * SIGNAL HALT on the control port first */
}

void zcl_tor_proc_kill(struct zcl_tor_proc *p)
{
    if (!p->reaped && p->process)
        (void)TerminateProcess(p->process, 1);
}

bool zcl_tor_proc_wait(struct zcl_tor_proc *p, unsigned timeout_ms)
{
    uint64_t end = zcl_tor_now_ms() + timeout_ms;
    for (;;) {
        if (!zcl_tor_proc_alive(p))
            return true;
        if (zcl_tor_now_ms() >= end)
            return false;
        Sleep(20);
    }
}

void zcl_tor_proc_close(struct zcl_tor_proc *p)
{
    if (p->process) {
        (void)CloseHandle(p->process);
        p->process = NULL;
    }
    if (p->job) {
        (void)CloseHandle(p->job); /* kills any survivor */
        p->job = NULL;
    }
}
#endif
