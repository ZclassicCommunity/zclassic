#include "embeddeddaemon.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <cstdio>

// Release gate: use the production extractor on the final bundle, then compare
// to the independently supplied, checksum-pinned original daemon.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    if (app.arguments().size() != 3) return 2;
    QTemporaryDir cache;
    if (!cache.isValid()) return 3;
    QString error;
    const QString path = extractEmbeddedDaemon(app.arguments().at(1), cache.path(), &error);
    if (path.isEmpty()) {
        fprintf(stderr, "Extraction failed: %s\n", qPrintable(error));
        return 4;
    }
    QFile original(app.arguments().at(2)), extracted(path);
    if (!original.open(QIODevice::ReadOnly) || !extracted.open(QIODevice::ReadOnly)) return 5;
    QCryptographicHash expected(QCryptographicHash::Sha256), actual(QCryptographicHash::Sha256);
    if (original.size() != extracted.size() || !expected.addData(&original) ||
        !actual.addData(&extracted) || expected.result() != actual.result()) return 6;
    original.close();
    extracted.close();
    // Launch exactly as the wallet does: pinned (verified, held) until start() returns.
    QProcess daemon;
    {
        EmbeddedDaemonPin pin(path, cache.path());
        if (pin.status() != EmbeddedDaemonPin::Pinned) {
            fprintf(stderr, "Pin failed: %s\n", qPrintable(pin.error()));
            return 9;
        }
        daemon.start(path, {QStringLiteral("--version")});
    }
    if (!daemon.waitForFinished(15000) || daemon.exitCode() != 0 ||
        daemon.exitStatus() != QProcess::NormalExit) return 7;
    if (extractEmbeddedDaemon(app.arguments().at(1), cache.path(), &error) != path) return 8;
    puts("PASS: final bundle extraction, original daemon hash, --version and cache reuse");
    return 0;
}
