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
// EVERY daemon launch goes through DaemonJob::start() (connection.cpp first start and
// repair relaunches, rpc.cpp crash restart). It does not depend on any QProcess signal:
// the ConnectionLoader disconnects all of its handlers from the process when it hands
// the node over to RPC, which used to drop the old `started` hook, so a daemon
// restarted after an unexpected exit was never bound.
//
// Mechanics (Windows):
//  * The child is created CREATE_SUSPENDED (through QProcess's CreateProcess argument
//    modifier, only while start() is launching), assigned to a fresh kill-on-close job
//    BEFORE it runs a single instruction, then resumed. If assignment fails the child
//    is resumed anyway and simply runs un-backstopped, as it did before.
//  * One job per launch. The job handle is non-inheritable (QProcess launches with
//    bInheritHandles=TRUE, so an inheritable handle would be duplicated into the
//    child and keep the job alive after the wallet died).
//  * Nested jobs (Windows 8+) cover a wallet that is itself inside a job.
//
// To make sure the backstop can never cut short an orderly stop, shutdownZClassicd()
// calls disarm() as soon as `stop` has been sent; from then on, even if the wallet
// exits before the daemon has finished flushing, the daemon is left to finish on its
// own exactly as before. A later start() makes its own, armed, job and never re-arms a
// launch that is already shutting down.
//
// Non-Windows: start() is a plain QProcess::start(); POSIX covers SIGINT/SIGTERM via
// the signal handler in main.cpp, SIGKILL has no portable backstop.

#include <QProcess>
#include <QString>
#include <QStringList>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <QPointer>
#include <vector>

namespace DaemonJob {

struct Entry {
    QPointer<QProcess> process;
    HANDLE job;
    bool armed;
};

inline std::vector<Entry>& entries() {
    static std::vector<Entry> list;
    return list;
}

inline bool& launching() {
    static bool flag = false;
    return flag;
}

inline bool setLimit(HANDLE job, bool killOnClose) {
    if (!job) return false;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
    ZeroMemory(&info, sizeof(info));
    info.BasicLimitInformation.LimitFlags = killOnClose ? JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE : 0;
    return SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info)) != 0;
}

// Drop bookkeeping for processes that are gone (closing a job whose process already
// exited kills nothing).
inline void prune() {
    auto& list = entries();
    for (size_t i = 0; i < list.size();) {
        QProcess* p = list[i].process.data();
        if (!p || p->state() == QProcess::NotRunning) {
            if (list[i].job) CloseHandle(list[i].job);
            list.erase(list.begin() + static_cast<std::ptrdiff_t>(i));
        } else {
            ++i;
        }
    }
}

// Create a fresh unnamed, NON-inheritable kill-on-close job and put the (suspended)
// child into it. Returns 0 on success, else the Win32 error. On success the job is
// recorded in entries(); on failure no handle is leaked.
inline DWORD bind(QProcess* p, HANDLE* jobOut = nullptr) {
    if (!p || !p->pid() || !p->pid()->hProcess) return ERROR_INVALID_HANDLE;
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) return GetLastError();
    // Explicit: a child that inherited this handle would keep the job alive.
    if (!SetHandleInformation(job, HANDLE_FLAG_INHERIT, 0) || !setLimit(job, true)
            || !AssignProcessToJobObject(job, p->pid()->hProcess)) {
        const DWORD err = GetLastError();
        CloseHandle(job);
        return err ? err : ERROR_GEN_FAILURE;
    }
    entries().push_back(Entry{QPointer<QProcess>(p), job, true});
    if (jobOut) *jobOut = job;
    return 0;
}

// Start `program` under the backstop. Returns 0 when the child is bound to its job
// (or could not be started at all, in which case there is nothing to back-stop),
// otherwise the Win32 error that left it running un-backstopped.
inline DWORD start(QProcess* p, const QString& program, const QStringList& args) {
    if (!p) return ERROR_INVALID_HANDLE;
    prune();
    p->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* a) {
        if (launching()) a->flags |= CREATE_SUSPENDED;
    });
    launching() = true;
    p->start(program, args);
    launching() = false;
    if (!p->pid()) return 0;   // failed to start: errorOccurred() reports it
    const DWORD err = bind(p);
    // Resume regardless: a bind failure must never strand a suspended daemon.
    if (p->pid() && p->pid()->hThread) ResumeThread(p->pid()->hThread);
    return err;
}

// An orderly stop is under way: never kill the daemon because the wallet exits.
inline void disarm() {
    for (auto& e : entries()) {
        if (e.armed && setLimit(e.job, false)) e.armed = false;
    }
}

// Test seams.
inline bool isInJob(QProcess* p) {
    if (!p || !p->pid()) return false;
    for (const auto& e : entries()) {
        BOOL in = FALSE;
        if (e.process.data() == p && e.job
                && IsProcessInJob(p->pid()->hProcess, e.job, &in) && in)
            return true;
    }
    return false;
}

inline bool isArmed(QProcess* p) {
    if (!isInJob(p)) return false;
    for (const auto& e : entries()) {
        if (e.process.data() != p) continue;
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
        ZeroMemory(&info, sizeof(info));
        if (QueryInformationJobObject(e.job, JobObjectExtendedLimitInformation, &info,
                                      sizeof(info), nullptr)
                && (info.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE))
            return true;
    }
    return false;
}

} // namespace DaemonJob

#else

namespace DaemonJob {
inline unsigned long start(QProcess* p, const QString& program, const QStringList& args) {
    if (p) p->start(program, args);
    return 0;
}
inline void disarm() {}
inline bool isInJob(QProcess*) { return false; }
inline bool isArmed(QProcess*) { return false; }
}

#endif

#endif // DAEMONJOB_H
