#include "embeddeddaemon.h"
#include "privatefile.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QStorageInfo>

QString extractEmbeddedDaemon(const QString& bundle, const QString& cacheRoot,
                              QString* error) {
    if (error) error->clear();
    auto fail = [error](const QString& why) {
        if (error) *error = why;
        return QString();
    };
    QFile self(bundle);
    if (!self.open(QIODevice::ReadOnly)) return fail(self.errorString());
    if (self.size() < 48 || !self.seek(self.size() - 48))
        return fail(QStringLiteral("Missing embedded daemon footer"));
    const QByteArray footer = self.read(48);
    if (footer.size() != 48 || footer.right(8) != "ZQWDMON1")
        return fail(QStringLiteral("Missing or truncated embedded daemon footer"));
    quint64 length = 0;
    for (int i = 0; i < 8; ++i)
        length |= quint64(uchar(footer.at(32 + i))) << (8 * i);
    if (!length || length > 512ull * 1024 * 1024 || length > quint64(self.size() - 48))
        return fail(QStringLiteral("Invalid embedded daemon length"));
    const QByteArray expected = footer.left(32);
    if (cacheRoot.isEmpty()) return fail(QStringLiteral("No writable cache location"));
    const QString directory = QDir(cacheRoot).filePath(
        "zclassic-node/" + QString::fromLatin1(expected.toHex()));
    if (!QDir().mkpath(directory)) return fail(QStringLiteral("Cannot create daemon cache"));
#ifdef Q_OS_WIN
    const QString path = QDir(directory).filePath("zqw-zclassicd.exe");
#else
    const QString path = QDir(directory).filePath("zqw-zclassicd");
#endif
    // A cache name and matching size do not establish integrity. Rehash before use.
    QFile cached(path);
    if (!QFileInfo(path).isSymLink() && cached.open(QIODevice::ReadOnly) &&
        cached.size() == qint64(length)) {
        QCryptographicHash hash(QCryptographicHash::Sha256);
        if (hash.addData(&cached) && hash.result() == expected) {
            if (!makeFileOwnerOnly(cached))
                return fail(QStringLiteral("Cannot restrict cached daemon permissions"));
#ifndef Q_OS_WIN
            if (!cached.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                       QFileDevice::ExeOwner))
                return fail(QStringLiteral("Cannot set daemon executable permissions"));
#endif
            return path;
        }
    }
    cached.close();
    if (QFileInfo(path).isSymLink()) return fail(QStringLiteral("Daemon cache is a symbolic link"));
    const qint64 available = QStorageInfo(directory).bytesAvailable();
    if (available >= 0 && available < qint64(length) + (16ll << 20))
        return fail(QStringLiteral("Insufficient disk space for embedded daemon"));
    if (!self.seek(self.size() - 48 - qint64(length)))
        return fail(QStringLiteral("Cannot seek to embedded daemon"));
    // QSaveFile owns a unique temporary file and checks flush/rename at commit.
    // Never truncate the previous cache or follow a predictable .part symlink.
    QSaveFile out(path);
    out.setDirectWriteFallback(false);
    if (!out.open(QIODevice::WriteOnly) || !makeFileOwnerOnly(out))
        return fail(QStringLiteral("Cannot create private daemon cache file: ") + out.errorString());
#ifndef Q_OS_WIN
    if (!out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                           QFileDevice::ExeOwner))
        return fail(QStringLiteral("Cannot set daemon executable permissions"));
#endif
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 remaining = qint64(length);
    while (remaining > 0) {
        const QByteArray bytes = self.read(qMin(remaining, qint64(1 << 20)));
        if (bytes.isEmpty() || out.write(bytes) != bytes.size())
            return fail(QStringLiteral("Embedded daemon read/write failed"));
        hash.addData(bytes);
        remaining -= bytes.size();
    }
    if (hash.result() != expected) return fail(QStringLiteral("Embedded daemon hash mismatch"));
    if (!out.commit()) return fail(QStringLiteral("Cannot publish daemon cache: ") + out.errorString());
    return path;
}
