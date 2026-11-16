#ifndef ZCL_REPAIRLOCK_H
#define ZCL_REPAIRLOCK_H

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMutex>
#include <QProcess>
#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Same OS lock and byte range as boost::interprocess::file_lock in zclassicd.
// QLockFile/flock are not compatible with that protocol. Never unlink .lock.
// Stack-owned on the repair thread, held across wallet backup and chain moves.
inline bool repairProcessIsStopped(const QProcess* process) {
    // Starting also counts as live. Never terminate a node to make repair
    // eligible: it may still be flushing wallet or database state.
    return !process || process->state() == QProcess::NotRunning;
}

class RepairLock {
public:
    explicit RepairLock(const QString& directory) {
        if (!processMutex().tryLock()) {
            message = QStringLiteral("Another repair is already running.");
            return;
        }
        ownsMutex = true;
        const QFileInfo info(QDir(directory).filePath(".lock"));
        if (directory.isEmpty() || !info.isFile() || info.isSymLink()) {
            message = QStringLiteral("The node lock file is unavailable; repair was stopped.");
            return;
        }
#ifdef Q_OS_WIN
        handle = CreateFileW(reinterpret_cast<LPCWSTR>(info.absoluteFilePath().utf16()),
            GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            BY_HANDLE_FILE_INFORMATION details{};
            if (GetFileInformationByHandle(handle, &details) &&
                !(details.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) {
                OVERLAPPED overlap{};
                locked = LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0, MAXDWORD, MAXDWORD, &overlap);
            }
        }
#else
        handle = ::open(QFile::encodeName(info.absoluteFilePath()).constData(),
            O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        if (handle >= 0) {
            struct stat details{};
            struct flock lock{};
            lock.l_type = F_WRLCK;
            lock.l_whence = SEEK_SET;
            if (::fstat(handle, &details) == 0 && S_ISREG(details.st_mode))
                locked = ::fcntl(handle, F_SETLK, &lock) != -1;
        }
#endif
        if (!locked)
            message = QStringLiteral("The node data directory is in use or cannot be locked. Repair was stopped without moving blockchain files.");
    }
    ~RepairLock() { release(); }
    RepairLock(const RepairLock&) = delete;
    RepairLock& operator=(const RepairLock&) = delete;
    bool acquired() const { return locked; }
    QString error() const { return message; }
    void release() {
#ifdef Q_OS_WIN
        if (handle != INVALID_HANDLE_VALUE) { CloseHandle(handle); handle = INVALID_HANDLE_VALUE; }
#else
        if (handle >= 0) { ::close(handle); handle = -1; }
#endif
        locked = false;
        if (ownsMutex) { ownsMutex = false; processMutex().unlock(); }
    }
private:
    // POSIX record locks are process-wide: a second open/close of .lock can
    // release the first lock. Exclude overlapping repairs before opening it.
    static QMutex& processMutex() { static QMutex mutex; return mutex; }
    bool ownsMutex = false;
    bool locked = false;
    QString message;
#ifdef Q_OS_WIN
    HANDLE handle = INVALID_HANDLE_VALUE;
#else
    int handle = -1;
#endif
};
#endif
