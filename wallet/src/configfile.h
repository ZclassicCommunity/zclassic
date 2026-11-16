#ifndef ZCL_CONFIGFILE_H
#define ZCL_CONFIGFILE_H

#include <QFileInfo>
#include <QDir>
#include <QTemporaryFile>
#include "privatefile.h"

// Publish a complete private config without ever replacing an existing file.
// QFile::rename fails if the destination exists, including a concurrent create.
inline bool createPrivateConfig(const QString& path, const QByteArray& contents,
                                QString& error) {
    const QFileInfo target(path);
    if (target.exists() || target.isSymLink()) {
        error = QObject::tr("The configuration already exists; it was not replaced.");
        return false;
    }
    if (!QDir().mkpath(target.absolutePath())) {
        error = QObject::tr("Cannot create the configuration directory.");
        return false;
    }
    QTemporaryFile staging(target.absolutePath() + "/.zclassic.conf.XXXXXX");
    if (!staging.open() || !makeFileOwnerOnly(staging)) {
        error = QObject::tr("Cannot create a private configuration file.");
        return false;
    }
    if (staging.write(contents) != contents.size() || !staging.flush()) {
        error = staging.errorString();
        return false;
    }
    staging.close();
    if (!staging.rename(path)) {
        error = QObject::tr("Cannot publish the configuration; any existing file was preserved.");
        return false;
    }
    staging.setAutoRemove(false);
    return true;
}
#endif
