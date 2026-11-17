#ifndef PROFILEPATHS_H
#define PROFILEPATHS_H

// Profile override: run the wallet fully isolated from the user's real state.
//
// When ZCLWALLET_PROFILE_DIR is set (or --profile-dir <dir> is passed, which
// main() turns into that variable before anything else runs), EVERY location the
// wallet decides -- QSettings, wallet log, address book / sent-tx / turnstile files,
// the extracted-daemon cache, zclassic.conf, the daemon datadir (passed explicitly
// as -datadir=), the notify socket/token, export dialogs' default folder and the
// Linux fontconfig cache -- resolves under that directory. The zk-SNARK params
// directory keeps its default (it is large and only read) unless
// ZCLWALLET_PARAMS_DIR is also set; that variable moves only the wallet's own
// params check, because the daemon has no params-dir option.
//
// Unset => every helper returns exactly the location the code used before.
// New code that needs a state location MUST call these helpers, never
// QStandardPaths/QDir::home directly.
//
// Layout under <profile>:
//   settings/            QSettings (IniFormat, user + system scope)
//   appdata/             wallet log, addresslabels.dat, senttxstore.dat, ...
//   cache/               extracted embedded daemon (zclassic-node/), fontconfig
//   run/                 notify socket + token
//   exports/             default folder for save dialogs
//   ZClassic/            zclassic.conf and the daemon datadir

#include <QByteArray>
#include <QDir>
#include <QSettings>
#include <QStandardPaths>
#include <QString>

namespace ProfilePaths {

inline QByteArray profileEnvName() { return QByteArrayLiteral("ZCLWALLET_PROFILE_DIR"); }
inline QByteArray paramsEnvName()  { return QByteArrayLiteral("ZCLWALLET_PARAMS_DIR"); }

// Absolute, cleaned profile directory, or "" when the override is not active.
inline QString dir() {
    const QString raw = QString::fromLocal8Bit(qgetenv(profileEnvName().constData())).trimmed();
    if (raw.isEmpty()) return QString();
    return QDir::cleanPath(QDir(raw).absolutePath());
}

inline bool active() { return !dir().isEmpty(); }

// True when the override is unset or names an existing directory.
inline bool valid() {
    const QString d = dir();
    return d.isEmpty() || QFileInfo(d).isDir();
}

inline QString sub(const QString& name) { return QDir(dir()).filePath(name); }

// QStandardPaths::AppDataLocation replacement (wallet log, *.dat stores).
inline QString appDataDir() {
    return active() ? sub(QStringLiteral("appdata"))
                    : QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
}

// QStandardPaths::CacheLocation replacement (extracted daemon cache).
inline QString cacheDir() {
    return active() ? sub(QStringLiteral("cache"))
                    : QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
}

// Notify socket/token directory. Empty when inactive: the caller keeps its
// existing (RuntimeLocation/Temp) resolution.
inline QString runtimeDir() {
    return active() ? sub(QStringLiteral("run")) : QString();
}

// Default folder for save dialogs. Empty when inactive.
inline QString exportsDir() {
    return active() ? sub(QStringLiteral("exports")) : QString();
}

// Home-relative cache the Linux fontconfig workaround uses. Empty when inactive.
inline QString fontconfigRoot() {
    return active() ? sub(QStringLiteral("cache/fontconfig-root")) : QString();
}

// Daemon datadir == directory holding zclassic.conf. Empty when inactive: the
// daemon then picks its own platform default and no -datadir is passed.
inline QString zclassicDataDir() {
    return active() ? sub(QStringLiteral("ZClassic")) : QString();
}

inline QString zclassicConfPath() {
    return active() ? QDir(zclassicDataDir()).filePath(QStringLiteral("zclassic.conf")) : QString();
}

// zk-SNARK params: ZCLWALLET_PARAMS_DIR when set (profile active or not), else
// the caller's default.
inline QString paramsDir(const QString& defaultDir) {
    const QString raw = QString::fromLocal8Bit(qgetenv(paramsEnvName().constData())).trimmed();
    if (!raw.isEmpty()) return QDir::cleanPath(QDir(raw).absolutePath());
    return defaultDir;
}

// Extra daemon arguments the embedded launch must carry for isolation.
inline QStringList daemonArgs() {
    QStringList a;
    if (active())
        a << QStringLiteral("-datadir=") + QDir::toNativeSeparators(zclassicDataDir());
    return a;
}

// QSettings: IniFormat under <profile>/settings for both scopes. Must run before
// the first QSettings object is created. No-op when inactive.
inline void applySettings() {
    if (!active()) return;
    const QString s = sub(QStringLiteral("settings"));
    QDir().mkpath(s);
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, s);
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, s);
}

// Title suffix shown whenever the override is active ("" otherwise).
inline QString titleMarker() {
    return active() ? QStringLiteral("  [profile: %1]").arg(QDir::toNativeSeparators(dir())) : QString();
}

// Translate `--profile-dir <dir>` / `--profile-dir=<dir>` into the environment
// variable. Returns false on a missing value. Called first thing in main().
inline bool consumeArgs(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        const QByteArray a(argv[i]);
        if (a == "--profile-dir") {
            if (i + 1 >= argc) return false;
            qputenv(profileEnvName().constData(), QByteArray(argv[i + 1]));
            return true;
        }
        if (a.startsWith("--profile-dir=")) {
            qputenv(profileEnvName().constData(), a.mid(14));
            return true;
        }
    }
    return true;
}

} // namespace ProfilePaths

#endif // PROFILEPATHS_H
