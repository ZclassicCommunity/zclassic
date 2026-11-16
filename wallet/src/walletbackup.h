#ifndef ZCL_WALLETBACKUP_H
#define ZCL_WALLETBACKUP_H

#include "privatefile.h"
#include "repairlocation.h"
#include "repairpersistence.h"
#include <QTemporaryFile>
#include <QCryptographicHash>
#include <functional>

namespace WalletBackup {
struct Result {
    bool success = false;
    QString path;
    QString error;
};

// The caller holds the native datadir lock. Read the existing wallet only;
// restrict the destination before private bytes are written, then verify and
// flush the copy before publishing it without replacement.
inline Result create(const QDir& data, const QString& walletFile,
        const std::function<bool(QFile&)>& flush = RepairPersistence::flushFile) {
    Result result;
    if (!resolveRepairLocation(data.absolutePath(), "", false, false, walletFile).error.isEmpty()) {
        result.error = QStringLiteral("The configured wallet filename is invalid.");
        return result;
    }
    const QFileInfo info(data.filePath(walletFile));
    QFile source(info.filePath());
    if (!info.isFile() || info.isSymLink() || info.size() <= 0 || !source.open(QIODevice::ReadOnly)) {
        result.error = QStringLiteral("Cannot read the configured wallet for backup; repair was stopped.");
        return result;
    }
    const qint64 expectedSize = source.size();
    QString stagingPath;
    {
        QTemporaryFile staging(data.filePath(".wallet-backup-XXXXXX"));
        if (!staging.open() || !makeFileOwnerOnly(staging)) {
            result.error = QStringLiteral("Cannot create an owner-only wallet backup.");
            return result;
        }
        QCryptographicHash original(QCryptographicHash::Sha256);
        qint64 copied = 0;
        while (true) {
            const QByteArray bytes = source.read(1024 * 1024);
            if (bytes.isEmpty()) break;
            if (staging.write(bytes) != bytes.size()) {
                result.error = QStringLiteral("Cannot write the wallet backup; the original wallet was not changed.");
                return result;
            }
            original.addData(bytes);
            copied += bytes.size();
        }
        if (source.error() != QFile::NoError || copied != expectedSize || source.size() != expectedSize || !flush(staging)) {
            result.error = QStringLiteral("Cannot confirm a complete, flushed wallet backup; repair was stopped.");
            return result;
        }
        QCryptographicHash copy(QCryptographicHash::Sha256);
        if (!staging.seek(0) || !copy.addData(&staging) || copy.result() != original.result()) {
            result.error = QStringLiteral("Wallet backup verification failed; repair was stopped.");
            return result;
        }
        stagingPath = staging.fileName();
        staging.setAutoRemove(false);
    }
    result.path = data.filePath(walletFile + ".backup-" + QFileInfo(stagingPath).fileName().right(6));
    if (!RepairPersistence::move(stagingPath, result.path)) {
        result.path = stagingPath;
        result.error = QStringLiteral("Cannot publish the verified wallet backup. The private copy was retained at %1.").arg(result.path);
        return result;
    }
    if (!RepairPersistence::syncDirectory(data.absolutePath())) {
        result.error = QStringLiteral("Wallet backup was created but its directory flush failed. Copy retained at %1.").arg(result.path);
        return result;
    }
    result.success = true;
    return result;
}
}
#endif
