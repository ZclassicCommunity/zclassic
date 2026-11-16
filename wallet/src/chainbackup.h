#ifndef ZCL_CHAINBACKUP_H
#define ZCL_CHAINBACKUP_H

#include <QDir>
#include <QFileInfo>
#include <QStringList>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include "repairpersistence.h"
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

struct Persistence {
    std::function<bool(QFile&)> flushFile = RepairPersistence::flushFile;
    std::function<bool(const QString&)> syncDirectory = RepairPersistence::syncDirectory;
};

inline bool syncParents(const QDir& source, const QDir& destination, const Persistence& persistence) {
    // Persist the new name before the disappearance of the old name.
    return persistence.syncDirectory(destination.absolutePath()) &&
           persistence.syncDirectory(source.absolutePath());
}

// Archive the pending journal with a checked same-volume rename. On Windows
// this requests write-through completion rather than an unchecked unlink.
inline bool finishJournal(const QDir& data, const QDir& saved, const Persistence& persistence) {
    return RepairPersistence::move(data.filePath("chain-repair-pending.json"),
               saved.filePath("repair-completed.json")) && syncParents(data, saved, persistence);
}

inline QString journalPath(const QDir& data) {
    return data.filePath(QStringLiteral("chain-repair-pending.json"));
}

inline QStringList componentNames(int version = 2) {
    QStringList names{QStringLiteral("blocks"), QStringLiteral("chainstate")};
    if (version >= 2) names << QStringLiteral("bootstrap-anchor-pending")
        << QStringLiteral("bootstrap-trustless-pending")
        << QStringLiteral("bootstrap-stub-recovery.json")
        << QStringLiteral("chainstate-verify");
    return names;
}

inline bool componentTypeMatches(const QFileInfo& info, const QString& name) {
    if (info.isSymLink()) return false;
    if (!info.exists()) return true;
    return (name == "blocks" || name == "chainstate" || name == "chainstate-verify")
        ? info.isDir() : info.isFile();
}

// Recover only the exact directories named by our journal, never overwrite a
// destination, and validate the entire plan before moving anything. The caller
// holds the native datadir lock. A journal remains until recovery is complete.
inline Result recover(const QDir& data,
        const std::function<bool(const QString&, const QString&)>& rename =
            RepairPersistence::move, const Persistence& persistence = Persistence()) {
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
    const int version = object.value("version").toInt();
    const QStringList components = componentNames(version);
    if (!document.isObject() || (version != 1 && version != 2) ||
        !QRegularExpression("\\Achain-set-aside-[A-Za-z0-9]+\\z").match(basename).hasMatch() ||
        !object.value("entries").isArray() || entries.size() > components.size()) {
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
    if (version == 1) {
        // Legacy journals never moved sidecars. Do not accept a damaged v2
        // journal relabeled v1 and silently strand verification requirements.
        for (const QString& name : componentNames().mid(2)) {
            const QFileInfo info(saved.filePath(name));
            if (info.exists() || info.isSymLink()) {
                result.error = QStringLiteral("Legacy repair journal has unexpected saved metadata; all files were preserved.");
                return result;
            }
        }
    }
    QStringList names;
    for (const auto entry : entries) {
        const QString name = entry.toString();
        if (!components.contains(name) || names.contains(name)) {
            result.error = QStringLiteral("Invalid blockchain repair entry; all files were preserved.");
            return result;
        }
        names.append(name);
        const QFileInfo original(data.filePath(name)), backup(saved.filePath(name));
        if (!componentTypeMatches(original, name) || !componentTypeMatches(backup, name) ||
            original.exists() == backup.exists()) {
            result.error = QStringLiteral("Cannot safely restore %1 to %2; both locations were preserved.")
                .arg(backup.filePath(), original.filePath());
            return result;
        }
    }
    // An omitted entry is valid only when that component never existed. A
    // damaged journal must not clear the guard while leaving a mixed pair.
    for (const QString& name : components) {
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
        if (!syncParents(saved, data, persistence)) {
            result.error = QStringLiteral("Restored %1 but could not confirm the directory flush. The repair journal was retained.").arg(*it);
            return result;
        }
    }
    // Also flush when an earlier attempt restored everything but failed its
    // barrier; no pending guard may be cleared before that retry succeeds.
    if (!syncParents(saved, data, persistence) || !finishJournal(data, saved, persistence)) {
        result.error = QStringLiteral("Recovered blockchain files but could not confirm completion of %1. The node was not restarted.").arg(marker.filePath());
        return result;
    }
    result.success = true;
    return result;
}

// Caller must first stop the daemon and exclude concurrent datadir writers.
// Never touches wallet files or removes an earlier backup. Even failed rollback
// leaves every moved directory available for manual recovery.
inline Result setAside(const QDir& data,
                       const std::function<bool(const QString&, const QString&)>& rename =
                           RepairPersistence::move, const Persistence& persistence = Persistence()) {
    Result result;
    if (QFileInfo::exists(journalPath(data)) || QFileInfo(journalPath(data)).isSymLink()) {
        result.error = QStringLiteral("An interrupted blockchain repair must be recovered first.");
        return result;
    }
    const QStringList names = componentNames();
    for (const QString& name : names) {
        const QFileInfo info(data.filePath(name));
        if (!componentTypeMatches(info, name)) {
            result.error = QStringLiteral("Unexpected blockchain component type: %1").arg(info.absoluteFilePath());
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
    const QByteArray journal = QJsonDocument(QJsonObject{{"version", 2},
        {"backup", QFileInfo(result.path).fileName()}, {"entries", entries}}).toJson(QJsonDocument::Compact);
    QString temporaryPath;
    {
        QTemporaryFile marker(data.filePath("chain-repair-intent-XXXXXX"));
        if (!marker.open() || marker.write(journal) != journal.size() || !persistence.flushFile(marker)) {
            result.error = QStringLiteral("Could not record blockchain repair intent; no directories were moved.");
            QDir().rmdir(result.path);
            return result;
        }
        temporaryPath = marker.fileName();
        marker.setAutoRemove(false);
        // Destroy the QTemporaryFile before native rename: close() alone may
        // retain Qt's underlying handle, preventing a Windows move.
    }
    if (!RepairPersistence::move(temporaryPath, journalPath(data)) || !syncParents(data, saved, persistence)) {
        result.error = QStringLiteral("Could not confirm publication of the repair journal; no blockchain components were moved. Recovery files were preserved.");
        return result;
    }
    for (const QString& name : names) {
        if (!QFileInfo::exists(data.filePath(name))) continue;
        if (!QFileInfo::exists(saved.filePath(name)) && rename(data.filePath(name), saved.filePath(name))) {
            if (!syncParents(data, saved, persistence)) {
                result.error = QStringLiteral("Moved %1 but could not confirm the directory flush. The repair journal and backups were retained.").arg(name);
                return result;
            }
            continue;
        }
        result.error = QStringLiteral("Could not move %1 into %2.").arg(data.filePath(name), result.path);
        const auto recovery = recover(data, rename, persistence);
        if (!recovery.success) result.error += "\n" + recovery.error;
        return result;
    }
    if (!finishJournal(data, saved, persistence)) {
        result.error = QStringLiteral("Blockchain files were backed up but completion could not be confirmed. The node was not restarted; recovery files were preserved.");
        return result;
    }
    result.success = true;
    return result;
}
}
#endif
