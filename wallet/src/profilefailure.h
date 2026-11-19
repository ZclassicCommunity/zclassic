#ifndef PROFILEFAILURE_H
#define PROFILEFAILURE_H

// A profile override (ZCLWALLET_PROFILE_DIR / --profile-dir) that names a missing
// directory is fatal by design (see profilepaths.h: isolation must never silently fall
// back to the real profile, and a mistyped path must never be created). On Windows a
// GUI program has no console, so the stderr line alone is invisible and the wallet
// looked like it did nothing. This header decides WHETHER a dialog is appropriate and
// says WHAT it tells the user; main() still prints the stderr line and returns the
// same exit code.

#include <QApplication>
#include <QByteArray>
#include <QDir>
#include <QFileInfo>
#include <QMessageBox>
#include <QString>
#include <cstdio>

#include "profilepaths.h"

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace ProfileFailure {

// Modes that run without a window and keep the plain stderr + exit-code contract.
inline bool isHeadlessInvocation(int argc, char** argv) {
    static const char* const flags[] = {"--print-profile-paths", "--notify", "--headless",
                                        "--help", "-h", "--help-all", "--version", "-v"};
    for (int i = 1; i < argc; i++)
        for (const char* f : flags)
            if (qstrcmp(argv[i], f) == 0) return true;
    return false;
}

// Same line main() has always written to stderr.
inline QString stderrLine(const QString& dir) {
    return QStringLiteral("zclwallet: --profile-dir / ZCLWALLET_PROFILE_DIR must name an existing directory (%1)").arg(dir);
}

inline QString dialogTitle() { return QStringLiteral("ZClassic Wallet cannot start"); }

// Plain-language text. `dir` is the resolved path ("" when the setting is empty/blank
// or --profile-dir had no value).
inline QString dialogText(const QString& dir) {
    if (dir.isEmpty())
        return QStringLiteral(
            "A separate profile folder was requested (the --profile-dir option or the "
            "ZCLWALLET_PROFILE_DIR setting), but the folder name is empty.\n\n"
            "Give it the name of an existing folder, or remove the setting to use the "
            "normal wallet profile.\n\nThe wallet did not start.");
    return QStringLiteral(
        "The folder named for the separate profile does not exist:\n\n%1\n\n"
        "Create that folder, or remove the --profile-dir option / ZCLWALLET_PROFILE_DIR "
        "setting to use the normal wallet profile. The wallet will not create it for you, "
        "so a mistyped path cannot start a new empty wallet by accident.\n\n"
        "The wallet did not start.").arg(QDir::toNativeSeparators(dir));
}

// The Qt rendering of the message (also what the widget test inspects).
inline QMessageBox* makeBox(const QString& dir) {
    return new QMessageBox(QMessageBox::Critical, dialogTitle(), dialogText(dir), QMessageBox::Ok);
}

// Can a Qt message box be shown without aborting or blocking forever? Not on a headless Qt
// platform (offscreen would exec() forever), and, with `needX11` (Linux), only when DISPLAY
// is a local ":N[.M]" whose X socket exists (an unreachable display makes QApplication
// abort, exit 134 instead of 2). Prefer not showing over aborting; stderr still has the line.
inline bool boxPossible(const QString& qpa, const QString& display, bool x11SocketExists, bool needX11) {
    if (qpa.startsWith(QLatin1String("offscreen")) || qpa.startsWith(QLatin1String("minimal")))
        return false;
    if (!needX11) return true;
    return display.startsWith(QLatin1Char(':')) && x11SocketExists;
}

// Local X socket for a DISPLAY of the form ":N[.M]".
inline bool x11SocketFor(const QString& display) {
    if (!display.startsWith(QLatin1Char(':'))) return false;
    QString n = display.mid(1);
    const int dot = n.indexOf(QLatin1Char('.'));
    if (dot >= 0) n.truncate(dot);
    bool ok = false;
    n.toInt(&ok);
    return ok && QFileInfo::exists(QStringLiteral("/tmp/.X11-unix/X") + n);
}

// Show the message and return. Windows uses the native box (no Qt objects are alive
// yet); elsewhere a QMessageBox is shown only when boxPossible(); the exit code is the
// caller's and is the same on every path.
inline void showDialog(const QString& dir) {
#ifdef Q_OS_WIN
    const std::wstring text = dialogText(dir).toStdWString();
    const std::wstring title = dialogTitle().toStdWString();
    MessageBoxW(nullptr, text.c_str(), title.c_str(), MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
#else
#ifdef Q_OS_LINUX
    const QString display = QString::fromLocal8Bit(qgetenv("DISPLAY"));
    if (!boxPossible(QString::fromLocal8Bit(qgetenv("QT_QPA_PLATFORM")), display, x11SocketFor(display), true))
        return;   // no usable display: the stderr line is the message
    if (!qEnvironmentVariableIsSet("QT_QPA_PLATFORM"))
        qputenv("QT_QPA_PLATFORM", QByteArray("xcb"));
#else
    if (!boxPossible(QString::fromLocal8Bit(qgetenv("QT_QPA_PLATFORM")), QString(), true, false))
        return;
#endif
    static int argc = 1;
    static char name[] = "zclwallet";
    static char* argv[] = {name, nullptr};
    QApplication app(argc, argv);
    QMessageBox* box = makeBox(dir);
    box->exec();
    delete box;
#endif
}

// What main() does for an invalid profile directory: the stderr line, then (unless this
// is a headless/command mode) the message box. The caller returns exit code 2.
inline void report(int argc, char** argv) {
    const QString dir = ProfilePaths::dir();
    fprintf(stderr, "%s\n", stderrLine(dir).toLocal8Bit().constData());
    if (!isHeadlessInvocation(argc, argv)) showDialog(dir);
}

} // namespace ProfileFailure

#endif // PROFILEFAILURE_H
