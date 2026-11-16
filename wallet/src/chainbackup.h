#ifndef ZCL_CHAINBACKUP_H
#define ZCL_CHAINBACKUP_H

#include <QDir>
#include <QFileInfo>
#include <QStringList>
#include <QTemporaryDir>
#include <functional>

namespace ChainBackup {
struct Result {
    bool success = false;
    QString path;
    QString error;
};

// Caller must first stop the daemon and exclude concurrent datadir writers.
// Never touches wallet files or removes an earlier backup. Even failed rollback
// leaves every moved directory available for manual recovery.
inline Result setAside(const QDir& data,
                       const std::function<bool(const QString&, const QString&)>& rename =
                           [](const QString& from, const QString& to) {
                               return QDir().rename(from, to);
                           }) {
    Result result;
    const QStringList names{QStringLiteral("blocks"), QStringLiteral("chainstate")};
    for (const QString& name : names) {
        const QFileInfo info(data.filePath(name));
        if (info.isSymLink() || (info.exists() && !info.isDir())) {
            result.error = QStringLiteral("Expected an ordinary directory: %1").arg(info.absoluteFilePath());
            return result;
        }
    }
    QTemporaryDir backup(data.filePath(QStringLiteral("chain-set-aside-XXXXXX")));
    backup.setAutoRemove(false);
    if (!backup.isValid()) {
        result.error = QStringLiteral("Could not create a blockchain backup directory in %1").arg(data.absolutePath());
        return result;
    }
    result.path = backup.path();
    const QDir saved(result.path);
    QStringList moved;
    for (const QString& name : names) {
        if (!QFileInfo::exists(data.filePath(name))) continue;
        if (!QFileInfo::exists(saved.filePath(name)) && rename(data.filePath(name), saved.filePath(name))) {
            moved.append(name);
            continue;
        }
        result.error = QStringLiteral("Could not move %1 into %2.").arg(data.filePath(name), result.path);
        for (auto it = moved.crbegin(); it != moved.crend(); ++it) {
            const QString original = data.filePath(*it);
            const QFileInfo destination(original);
            if (destination.exists() || destination.isSymLink() || !rename(saved.filePath(*it), original)) {
                result.error += QStringLiteral("\nCould not restore %1 to %2; both locations were preserved.")
                                    .arg(saved.filePath(*it), original);
            }
        }
        // rmdir only removes an EMPTY directory. Never recursively clean up:
        // an unsuccessful rollback may still have the sole copy of the blocks.
        QDir().rmdir(result.path);
        return result;
    }
    result.success = true;
    return result;
}
}
#endif
