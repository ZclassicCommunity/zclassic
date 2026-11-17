#ifndef DAEMONJOB_H
#define DAEMONJOB_H

// Last-resort parent-death backstop for the embedded daemon (Windows).
//
// The orderly path is unchanged and always preferred: window close / File->Exit /
// SIGINT / SIGTERM (POSIX) run RPC::shutdownZClassicd(), which sends the daemon an
// RPC `stop` and waits for it to flush and exit. This job object only matters when
// the wallet dies WITHOUT running any cleanup (taskkill /F, crash, kill from a
// debugger): Windows then closes the job handle and terminates the daemon instead
// of leaving it orphaned on its datadir and ports.
//
// To make sure the backstop can never cut short an orderly stop, shutdownZClassicd()
// calls disarm() as soon as `stop` has been sent; from then on, even if the wallet
// exits before the daemon has finished flushing, the daemon is left to finish on its
// own exactly as before. bind() re-arms for each (re)launched daemon.
//
// Non-Windows: no-ops (POSIX covers SIGINT/SIGTERM via the signal handler in main.cpp;
// SIGKILL cannot be intercepted and has no portable backstop).

#include <QProcess>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace DaemonJob {

inline HANDLE& handle() {
    static HANDLE job = nullptr;
    return job;
}

inline bool setLimit(bool killOnClose) {
    HANDLE job = handle();
    if (!job) return false;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
    ZeroMemory(&info, sizeof(info));
    info.BasicLimitInformation.LimitFlags = killOnClose ? JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE : 0;
    return SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info)) != 0;
}

// Put the freshly started daemon into the kill-on-close job. Returns false (and the
// daemon simply runs un-backstopped, as before) if any step fails.
inline bool bind(QProcess* p) {
    if (!p || !p->pid() || !p->pid()->hProcess) return false;
    HANDLE& job = handle();
    if (!job) {
        job = CreateJobObjectW(nullptr, nullptr);   // unnamed, inheritable by nobody
        if (!job) return false;
    }
    if (!setLimit(true)) return false;
    return AssignProcessToJobObject(job, p->pid()->hProcess) != 0;
}

// An orderly stop is under way: never kill the daemon because the wallet exits.
inline void disarm() { setLimit(false); }

} // namespace DaemonJob

#else

namespace DaemonJob {
inline bool bind(QProcess*) { return false; }
inline void disarm() {}
}

#endif

#endif // DAEMONJOB_H
