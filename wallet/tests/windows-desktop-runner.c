// Run native Qt GUI tests on a private desktop without switching the user's
// desktop. Build: gcc -std=c23 -municode -static windows-desktop-runner.c -o runner.exe
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t **argv)
{
    if (argc != 3) {
        fwprintf(stderr, L"usage: runner.exe executable \"complete command line\"\n");
        return 2;
    }
    wchar_t desktop_name[64];
    swprintf(desktop_name, 64, L"ZclWalletTest-%lu", GetCurrentProcessId());
    HDESK desktop = CreateDesktopW(desktop_name, NULL, NULL, 0,
        DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS |
        DESKTOP_ENUMERATE, NULL);
    if (!desktop) {
        fwprintf(stderr, L"CreateDesktop failed: %lu\n", GetLastError());
        return 2;
    }
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                         &limits, sizeof(limits))) {
        fwprintf(stderr, L"Test job setup failed: %lu\n", GetLastError());
        if (job) CloseHandle(job);
        CloseDesktop(desktop);
        return 2;
    }
    // Redirect standard handles so a GUI --help exits rather than opening a
    // native help message box. QtTest writes its requested -o result file.
    SECURITY_ATTRIBUTES inherit = {.nLength = sizeof(inherit), .bInheritHandle = TRUE};
    HANDLE null_io = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, NULL);
    if (null_io == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Test output redirection failed: %lu\n", GetLastError());
        CloseHandle(job);
        CloseDesktop(desktop);
        return 2;
    }
    STARTUPINFOW startup = {.cb = sizeof(startup), .lpDesktop = desktop_name,
        .dwFlags = STARTF_USESTDHANDLES, .hStdInput = null_io,
        .hStdOutput = null_io, .hStdError = null_io};
    PROCESS_INFORMATION process = {0};
    DWORD result = 2;
    if (!CreateProcessW(argv[1], argv[2], NULL, NULL, TRUE, CREATE_SUSPENDED,
                        NULL, NULL, &startup, &process)) {
        fwprintf(stderr, L"Test process creation failed: %lu\n", GetLastError());
    } else {
        if (!AssignProcessToJobObject(job, process.hProcess)) {
            fwprintf(stderr, L"Test job assignment failed: %lu\n", GetLastError());
            TerminateProcess(process.hProcess, 2);
        } else if (ResumeThread(process.hThread) == (DWORD)-1) {
            fwprintf(stderr, L"Test resume failed: %lu\n", GetLastError());
        } else if (WaitForSingleObject(process.hProcess, 120000) != WAIT_OBJECT_0) {
            fwprintf(stderr, L"Test exceeded 120 seconds or wait failed\n");
        } else if (!GetExitCodeProcess(process.hProcess, &result)) {
            fwprintf(stderr, L"Cannot read test exit code: %lu\n", GetLastError());
            result = 2;
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    CloseHandle(job); // Also terminates a timed-out process and its children.
    CloseHandle(null_io);
    CloseDesktop(desktop);
    return (int)result;
}
