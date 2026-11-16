#ifndef ZCL_REPAIRPERSISTENCE_H
#define ZCL_REPAIRPERSISTENCE_H

#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <cstdio>
#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace RepairPersistence {
inline bool flushFile(QFile& file) {
    if (!file.flush()) return false;
#ifdef Q_OS_WIN
    const intptr_t handle = _get_osfhandle(file.handle());
    return handle != -1 && FlushFileBuffers(reinterpret_cast<HANDLE>(handle));
#else
    return ::fsync(file.handle()) == 0;
#endif
}

inline bool syncDirectory(const QString& path) {
#ifdef Q_OS_WIN
    Q_UNUSED(path);
    // Windows namespace persistence is requested by move() below. Directory
    // handles do not offer a portable equivalent of POSIX directory fsync.
    return true;
#else
    const int fd = ::open(QFile::encodeName(path).constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    const bool success = ::fsync(fd) == 0;
    ::close(fd);
    return success;
#endif
}

// Caller holds the datadir lock and checks both endpoints. Never use replace or
// cross-volume copy flags; a failed transition must not overwrite another copy.
inline bool move(const QString& from, const QString& to) {
    const QFileInfo destination(to);
    if (destination.exists() || destination.isSymLink()) return false;
#ifdef Q_OS_WIN
    return MoveFileExW(reinterpret_cast<LPCWSTR>(from.utf16()),
        reinterpret_cast<LPCWSTR>(to.utf16()), MOVEFILE_WRITE_THROUGH);
#else
    return ::rename(QFile::encodeName(from).constData(), QFile::encodeName(to).constData()) == 0;
#endif
}
}
#endif
