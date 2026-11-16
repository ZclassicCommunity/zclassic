#ifndef ZCL_REPAIRLOCATION_H
#define ZCL_REPAIRLOCATION_H

#include <QDir>
#include <QFileInfo>
#include <QMap>
#include <QDirIterator>
#include <cstdlib>

struct RepairConfig {
    QMap<QString, QString> values;
    QString error;
};

inline bool repairConfigBool(const QString& value) {
    return value.isEmpty() || std::atoi(value.toUtf8().constData()) != 0;
}

// Match ReadConfigFile and Boost's config_file_iterator: case-sensitive names,
// first value wins, # comments, section prefixes, and nofoo boolean aliases.
// Invalid syntax stops repair; never guess which wallet the daemon selected.
inline RepairConfig parseRepairConfig(const QString& contents) {
    RepairConfig result;
    QString prefix;
    auto trim = [](const QString& value) {
        int first = 0, last = value.size();
        const QString whitespace = QStringLiteral(" \t\r\n");
        while (first < last && whitespace.contains(value[first])) ++first;
        while (last > first && whitespace.contains(value[last - 1])) --last;
        return value.mid(first, last - first);
    };
    for (QString line : contents.split('\n')) {
        const int comment = line.indexOf('#');
        if (comment >= 0) line.truncate(comment);
        line = trim(line);
        if (line.isEmpty()) continue;
        if (line.startsWith('[') && line.endsWith(']')) {
            prefix = line.mid(1, line.size() - 2);
            if (prefix.isEmpty()) {
                result.error = QStringLiteral("An empty configuration section prevents safe repair.");
                return result;
            }
            if (!prefix.endsWith('.')) prefix += '.';
            continue;
        }
        const int equals = line.indexOf('=');
        if (equals < 0) {
            result.error = QStringLiteral("Invalid configuration syntax prevents safe repair.");
            return result;
        }
        const QString name = prefix + trim(line.left(equals));
        if (result.values.contains(name)) continue;
        const QString value = trim(line.mid(equals + 1));
        result.values.insert(name, value);
        if (name.startsWith("no") && !result.values.contains(name.mid(2)))
            result.values.insert(name.mid(2), repairConfigBool(value) ? "0" : "1");
    }
    return result;
}

struct RepairLocation {
    QString directory;
    QString walletFile;
    QString error;
};

// Select the configured network, never whichever directory happens to exist.
// Relative paths require the actual daemon working directory, which differs
// from the GUI working directory on Windows.
inline RepairLocation resolveRepairLocation(const QString& configDirectory,
        const QString& dataOverride, bool testnet, bool regtest,
        const QString& walletFile = QStringLiteral("wallet.dat"),
        const QString& daemonWorkingDirectory = QString()) {
    RepairLocation result;
    if (testnet && regtest) {
        result.error = QStringLiteral("Both testnet and regtest are selected.");
        return result;
    }
    const QString base = dataOverride.isEmpty() ? configDirectory : dataOverride;
    if (base.isEmpty()) {
        result.error = QStringLiteral("The node data directory is unknown.");
        return result;
    }
    if (walletFile.isEmpty() || walletFile == "." || walletFile == ".." ||
        QFileInfo(walletFile).isAbsolute() || walletFile.contains(':') || walletFile.contains('/') ||
        walletFile.contains('\\') || walletFile.contains(QChar(0))) {
        result.error = QStringLiteral("The configured wallet must be a filename inside the data directory.");
        return result;
    }
    if (QDir::isRelativePath(base) && daemonWorkingDirectory.isEmpty()) {
        result.error = QStringLiteral("The node working directory is unknown; a relative data directory cannot be repaired safely.");
        return result;
    }
    QDir directory(QDir::isAbsolutePath(base) ? base : QDir(daemonWorkingDirectory).filePath(base));
    if (testnet) directory = QDir(directory.filePath(QStringLiteral("testnet3")));
    if (regtest) directory = QDir(directory.filePath(QStringLiteral("regtest")));
    result.directory = directory.absolutePath();
    result.walletFile = walletFile;
    return result;
}

inline qint64 repairBlocksSize(const QString& networkDirectory) {
    if (networkDirectory.isEmpty()) return -1;
    const QDir blocks(QDir(networkDirectory).filePath("blocks"));
    if (!blocks.exists()) return -1;
    qint64 total = 0;
    QDirIterator it(blocks.absolutePath(), QDir::Files | QDir::NoSymLinks,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) { it.next(); total += it.fileInfo().size(); }
    return total;
}
#endif
