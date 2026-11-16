#ifndef ZCL_CHAINBACKUP_H
#define ZCL_CHAINBACKUP_H

#include <QDir>
#include <QFileInfo>
#include <QStringList>
#include <QTemporaryDir>
#include <QSaveFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegularExpression>
#include <functional>

namespace ChainBackup {
struct Result {
    bool success = false;
    QString path;
    QString error;
};

inline QString journalPath(const QDir& data) {
    return data.filePath(QStringLiteral("chain-repair-pending.json"));
}

// Recover only the exact directories named by our journal, never overwrite a
// destination, and validate the entire plan before moving anything. The caller
// holds the native datadir lock. A journal remains until recovery is complete.
inline Result recover(const QDir& data,
        const std::function<bool(const QString&, const QString&)>& rename =
            [](const QString& from, const QString& to) { return QDir().rename(from, to); }) {
    Result result;
    const QFileInfo marker(journalPath(data));
    if (!marker.exists() && !marker.isSymLink()) { result.success = true; return result; }
    QFile file(marker.filePath());
    if (marker.isSymLink() || !marker.isFile() || marker.size() > 4096 || !file.open(QIODevice::ReadOnly)) {
        result.error = QStringLiteral("Cannot read the interrupted blockchain repair journal: %1").arg(marker.filePath());
        return result;
    }
    const auto document = QJsonDocument::fromJson(file.readAll());
    file.close();
    const auto object = document.object();
    const QString basename = object.value("backup").toString();
    const QJsonArray entries = object.value("entries").toArray();
    if (!document.isObject() || object.value("version").toInt() != 1 ||
        !QRegularExpression("\\Achain-set-aside-[A-Za-z0-9]+\\z").match(basename).hasMatch() ||
        !object.value("entries").isArray() || entries.size() > 2) {
        result.error = QStringLiteral("Invalid blockchain repair journal; all files were preserved.");
        return result;
    }
    result.path = data.filePath(basename);
    const QFileInfo savedInfo(result.path);
    if (!savedInfo.isDir() || savedInfo.isSymLink()) {
        result.error = QStringLiteral("Blockchain backup directory is unavailable: %1").arg(result.path);
        return result;
    }
    QDir saved(result.path);
    QStringList names;
    for (const auto entry : entries) {
        const QString name = entry.toString();
        if ((name != "blocks" && name != "chainstate") || names.contains(name)) {
            result.error = QStringLiteral("Invalid blockchain repair entry; all files were preserved.");
            return result;
        }
        names.append(name);
        const QFileInfo original(data.filePath(name)), backup(saved.filePath(name));
        if (original.isSymLink() || backup.isSymLink() ||
            original.exists() == backup.exists() ||
            (original.exists() && !original.isDir()) || (backup.exists() && !backup.isDir())) {
            result.error = QStringLiteral("Cannot safely restore %1 to %2; both locations were preserved.")
                .arg(backup.filePath(), original.filePath());
            return result;
        }
    }
    // An omitted entry is valid only when that component never existed. A
    // damaged journal must not clear the guard while leaving a mixed pair.
    for (const QString& name : {QStringLiteral("blocks"), QStringLiteral("chainstate")}) {
        if (names.contains(name)) continue;
        const QFileInfo original(data.filePath(name)), backup(saved.filePath(name));
        if (original.exists() || original.isSymLink() || backup.exists() || backup.isSymLink()) {
            result.error = QStringLiteral("Repair journal omits %1; all blockchain files and the journal were preserved.").arg(name);
            return result;
        }
    }
    for (auto it = names.crbegin(); it != names.crend(); ++it) {
        if (!QFileInfo::exists(saved.filePath(*it))) continue;
        if (!rename(saved.filePath(*it), data.filePath(*it))) {
            result.error = QStringLiteral("Could not restore %1 to %2; recovery can be retried.")
                .arg(saved.filePath(*it), data.filePath(*it));
            return result;
        }
    }
    if (!QFile::remove(marker.filePath())) {
        result.error = QStringLiteral("Recovered blockchain files but could not clear %1.").arg(marker.filePath());
        return result;
    }
    QDir().rmdir(result.path); // Empty only; never delete a retained copy.
    result.success = true;
    return result;
}

// Caller must first stop the daemon and exclude concurrent datadir writers.
// Never touches wallet files or removes an earlier backup. Even failed rollback
// leaves every moved directory available for manual recovery.
inline Result setAside(const QDir& data,
                       const std::function<bool(const QString&, const QString&)>& rename =
                           [](const QString& from, const QString& to) {
                               return QDir().rename(from, to);
                           }) {
    Result result;
    if (QFileInfo::exists(journalPath(data)) || QFileInfo(journalPath(data)).isSymLink()) {
        result.error = QStringLiteral("An interrupted blockchain repair must be recovered first.");
        return result;
    }
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
    QJsonArray entries;
    for (const QString& name : names)
        if (QFileInfo::exists(data.filePath(name))) entries.append(name);
    const QByteArray journal = QJsonDocument(QJsonObject{{"version", 1},
        {"backup", QFileInfo(result.path).fileName()}, {"entries", entries}}).toJson(QJsonDocument::Compact);
    QSaveFile marker(journalPath(data));
    marker.setDirectWriteFallback(false);
    if (!marker.open(QIODevice::WriteOnly) || marker.write(journal) != journal.size() || !marker.commit()) {
        result.error = QStringLiteral("Could not record blockchain repair intent; no directories were moved.");
        QDir().rmdir(result.path);
        return result;
    }
    for (const QString& name : names) {
        if (!QFileInfo::exists(data.filePath(name))) continue;
        if (!QFileInfo::exists(saved.filePath(name)) && rename(data.filePath(name), saved.filePath(name))) {
            continue;
        }
        result.error = QStringLiteral("Could not move %1 into %2.").arg(data.filePath(name), result.path);
        const auto recovery = recover(data, rename);
        if (!recovery.success) result.error += "\n" + recovery.error;
        return result;
    }
    if (!QFile::remove(journalPath(data))) {
        result.error = QStringLiteral("Blockchain files were backed up but the repair journal could not be cleared. Restart will recover the previous chain.");
        return result;
    }
    result.success = true;
    return result;
}
}
#endif
