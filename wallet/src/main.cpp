#include <singleapplication.h>

#include "precompiled.h"
#include "mainwindow.h"
#include "rpc.h"
#include "settings.h"
#include "turnstile.h"
#include "notifyserver.h"   // NOTIFY-SRV connector mode (--notify)
#include "guistartup.h"     // [gui-startup] client-side startup timing milestones

#include "version.h"

#include <QtNetwork/QTcpSocket>
#include <QPalette>   // Quiet+ redesign Phase 1: dark palette (pulls in QColor)

// ----------------------------------------------------------------------------
// Idiot-proof launch helpers (Wayland-survive + never-spawn-a-duplicate-node).
// ----------------------------------------------------------------------------

// True iff BOTH the ZClassic RPC and P2P ports on 127.0.0.1 are currently
// UNBOUND (connection refused/timeout). Mainnet 8023/8033, testnet 18023/18033.
// We probe BOTH port pairs so we are conservative regardless of which network a
// possibly-already-running primary chose: if ANY node is answering on ANY of the
// four ports, we treat the ports as NOT free. This runs BEFORE Settings::init(),
// so we cannot yet know testnet-vs-mainnet; checking all four is the safe choice.
// Used only to gate the secondary->primary fall-through below: we must never
// launch a second embedded zclassicd onto a live datadir.
static bool nodePortsDefinitelyFree() {
    auto portInUse = [](quint16 port) -> bool {
        QTcpSocket probe;
        probe.connectToHost(QStringLiteral("127.0.0.1"), port);
        bool connected = probe.waitForConnected(200);   // refused/timeout => free
        probe.abort();
        return connected;
    };
    // ANY of these answering => a node is live => ports are NOT free.
    return !portInUse(8023) && !portInUse(8033)
        && !portInUse(18023) && !portInUse(18033);
}

class SignalHandler 
{
public:
    SignalHandler(int mask = DEFAULT_SIGNALS);
    virtual ~SignalHandler();

    enum SIGNALS
    {
        SIG_UNHANDLED   = 0,    // Physical signal not supported by this class
        SIG_NOOP        = 1,    // The application is requested to do a no-op (only a target that platform-specific signals map to when they can't be raised anyway)
        SIG_INT         = 2,    // Control+C (should terminate but consider that it's a normal way to do so; can delay a bit)
        SIG_TERM        = 4,    // Control+Break (should terminate now without regarding the consquences)
        SIG_CLOSE       = 8,    // Container window closed (should perform normal termination, like Ctrl^C) [Windows only; on Linux it maps to SIG_TERM]
        SIG_RELOAD      = 16,   // Reload the configuration [Linux only, physical signal is SIGHUP; on Windows it maps to SIG_NOOP]
        DEFAULT_SIGNALS = SIG_INT | SIG_TERM | SIG_CLOSE,
    };
    static const int numSignals = 6;

    virtual bool handleSignal(int signal) = 0;

private:
    int _mask;
};

#include <assert.h>

#ifndef _WIN32

#include <signal.h>

#else

#endif //!_WIN32

// There can be only ONE SignalHandler per process
SignalHandler* g_handler(NULL);

#ifndef _WIN32

void POSIX_handleFunc(int);
int POSIX_physicalToLogical(int);
int POSIX_logicalToPhysical(int);

#endif //_WIN32

SignalHandler::SignalHandler(int mask) : _mask(mask)
{
    assert(g_handler == NULL);
    g_handler = this;

    for (int i=0;i<numSignals;i++)
    {
        int logical = 0x1 << i;
        if (_mask & logical)
        {
#ifndef _WIN32
            int sig = POSIX_logicalToPhysical(logical);
            bool failed = signal(sig, POSIX_handleFunc) == SIG_ERR;
            assert(!failed);
            (void)failed; // Silence the warning in non _DEBUG; TODO: something better

#endif //_WIN32
        }
    }

}

SignalHandler::~SignalHandler()
{
#ifndef _WIN32
    for (int i=0;i<numSignals;i++)
    {
        int logical = 0x1 << i;
        if (_mask & logical)
        {
            signal(POSIX_logicalToPhysical(logical), SIG_DFL);
        }
    }
#endif //_WIN32
}


#ifndef _WIN32
int POSIX_logicalToPhysical(int signal)
{
    switch (signal)
    {
    case SignalHandler::SIG_INT: return SIGINT;
    case SignalHandler::SIG_TERM: return SIGTERM;
    // In case the client asks for a SIG_CLOSE handler, accept and
    // bind it to a SIGTERM. Anyway the signal will never be raised
    case SignalHandler::SIG_CLOSE: return SIGTERM;
    case SignalHandler::SIG_RELOAD: return SIGHUP;
    default: 
        return -1; // SIG_ERR = -1
    }
}
#endif //_WIN32


#ifndef _WIN32
int POSIX_physicalToLogical(int signal)
{
    switch (signal)
    {
    case SIGINT: return SignalHandler::SIG_INT;
    case SIGTERM: return SignalHandler::SIG_TERM;
    case SIGHUP: return SignalHandler::SIG_RELOAD;
    default:
        return SignalHandler::SIG_UNHANDLED;
    }
}
#endif //_WIN32

#ifndef _WIN32
void POSIX_handleFunc(int signal)
{
    if (g_handler)
    {
        int signo = POSIX_physicalToLogical(signal);
        g_handler->handleSignal(signo);
    }
}
#endif //_WIN32

class Application : public SignalHandler
{
public:
    Application() : SignalHandler(SignalHandler::SIG_INT), w(nullptr) {}

    ~Application() { delete w; }

    int main(int argc, char *argv[]) {
        QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
        QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);

        SingleApplication a(argc, argv, true);
        GuiStartup::markQAppConstructed();   // [gui-startup] QApplication built

        // Command line parser
        QCommandLineParser parser;
        parser.setApplicationDescription("Shielded desktop wallet and embedded full node for ZClassic");
        parser.addHelpOption();

        // A boolean option for running it headless
        QCommandLineOption headlessOption(QStringList() << "headless", "Run the wallet without the GUI (headless node only).");
        parser.addOption(headlessOption);

        // No embedded will disable the embedded zclassicd node
        QCommandLineOption noembeddedOption(QStringList() << "no-embedded", "Disable embedded zclassicd");
        parser.addOption(noembeddedOption);

        // Positional argument will specify a zclassic payment URI
        parser.addPositionalArgument("zclassicURI", "An optional zclassic URI to pay");

        parser.process(a);

        // Check for a positional argument indicating a zclassic payment URI
        if (a.isSecondary()) {
            // SingleApplication says a primary already exists. The normal case:
            // forward the URI / a __SHOW__ to the live primary and exit, so we do
            // NOT start a second embedded node onto the live datadir.
            QByteArray payload = (parser.positionalArguments().length() > 0)
                ? parser.positionalArguments()[0].toUtf8()
                : QByteArray("__SHOW__");

            // Give a busy-but-alive primary real time to accept. A first-sync /
            // bootstrap primary is hammering disk and its QLocalServer accept can
            // lag well past the default 100ms; a single short flush would spuriously
            // report "not delivered" and (pre-fix) fall through to a DUPLICATE node
            // on the same LevelDB/blocks dir = classic corruption. Retry with a
            // generous timeout before concluding the primary is dead.
            bool delivered = false;
            for (int attempt = 0; attempt < 5 && !delivered; attempt++) {
                delivered = a.sendMessage(payload, 3000 /* ms */);
            }

            if (delivered) {
                // A genuine primary received the message: this is true
                // single-instance behavior, identical to before. Exit cleanly.
                a.exit(0);
                return 0;
            }

            // Delivery FAILED after generous retries. Either there is genuinely no
            // live primary (a stale shared-memory primary flag from a crash-killed
            // prior run) OR a primary is alive but unreachable. We must NOT spawn a
            // second node onto a live datadir, so before falling through to normal
            // startup we POSITIVELY PROVE the node ports are free. If anything is
            // still answering on the RPC/P2P ports, a node IS live -> never start a
            // duplicate; exit (preserving today's safe single-instance outcome).
            if (!nodePortsDefinitelyFree()) {
                qDebug() << "Secondary: message not delivered but a node is on the "
                            "ports; refusing to start a duplicate. Exiting.";
                a.exit(0);
                return 0;
            }

            // Provably no live primary AND ports are free: this is a stale-primary
            // trap. Fall through to become the usable instance so the user gets a
            // window + node instead of a silent no-op exit. (No other instance can
            // be racing our datadir because nothing is listening on the ports.)
            qDebug() << "Secondary: no live primary and node ports free; "
                        "becoming the usable instance.";
        }

        QCoreApplication::setOrganizationName("zcl-qt-wallet-org");
        QCoreApplication::setApplicationName("zcl-qt-wallet");

        QString locale = QLocale::system().name();
        locale.truncate(locale.lastIndexOf('_'));   // Get the language code
        qDebug() << "Loading locale " << locale;
        
        QTranslator translator;
        translator.load(QString(":/translations/res/zcl_qt_wallet_") + locale);
        a.installTranslator(&translator);

        QIcon icon(":/icons/res/icon.ico");
        QApplication::setWindowIcon(icon);

        // ---- Modern theme (Quiet+ redesign, Phase 1) ----
        // Fusion renders QSS consistently on Windows/macOS/static-Linux (the native
        // styles ignore much of our stylesheet). Applied before MainWindow is built.
        QApplication::setStyle("Fusion");

        // Bundled Ubuntu face on ALL platforms now (was Linux-only) at a bigger 13pt
        // base for a more readable, cross-platform-consistent type baseline. High-DPI
        // scaling (enabled above) keeps point sizes crisp on every monitor.
        QFontDatabase::addApplicationFont(":/fonts/res/Ubuntu-R.ttf");
        {
            QFont baseFont("Ubuntu", 13);
            baseFont.setStyleStrategy(QFont::PreferAntialias);
            qApp->setFont(baseFont);
        }

        // Dark palette (privacy-forward identity) for the non-QSS-styled bits
        // (tooltips, disabled text, selection) so nothing falls back to a light look.
        {
            QPalette pal;
            const QColor base("#15171c"), surface("#1d2027"), text("#e6e6e6"),
                         dim("#9aa0a6"), accent("#1f7a1f");
            pal.setColor(QPalette::Window,          base);
            pal.setColor(QPalette::WindowText,      text);
            pal.setColor(QPalette::Base,            surface);
            pal.setColor(QPalette::AlternateBase,   base);
            pal.setColor(QPalette::Text,            text);
            pal.setColor(QPalette::Button,          surface);
            pal.setColor(QPalette::ButtonText,      text);
            pal.setColor(QPalette::BrightText,      QColor("#ffffff"));
            pal.setColor(QPalette::ToolTipBase,     surface);
            pal.setColor(QPalette::ToolTipText,     text);
            pal.setColor(QPalette::Highlight,       accent);
            pal.setColor(QPalette::HighlightedText, QColor("#ffffff"));
            pal.setColor(QPalette::Link,            QColor("#5ea1e0"));
            pal.setColor(QPalette::PlaceholderText, dim);
            pal.setColor(QPalette::Disabled, QPalette::Text,       dim);
            pal.setColor(QPalette::Disabled, QPalette::ButtonText, dim);
            pal.setColor(QPalette::Disabled, QPalette::WindowText, dim);
            qApp->setPalette(pal);
        }

        // Central stylesheet: single source of truth for the modern look + type scale.
        {
            QFile qssFile(":/styles/res/styles/dark.qss");
            if (qssFile.open(QFile::ReadOnly | QFile::Text))
                qApp->setStyleSheet(QString::fromUtf8(qssFile.readAll()));
        }

        // QRandomGenerator generates a secure random number, which we use to seed.
    #if (QT_VERSION >= QT_VERSION_CHECK(5, 10, 0))
        unsigned int seed = QRandomGenerator::securelySeeded().generate();
    #else
        // This will be used only during debugging for compatibility reasons 
        unsigned int seed = std::time(0);
    #endif
        std::srand(seed);

        Settings::init();

        // Set up libsodium
        if (sodium_init() < 0) {
            /* panic! the library couldn't be initialized, it is not safe to use */
            // Never silently exit(0) reporting success. Show a visible, actionable
            // dialog (a QApplication exists here) and exit non-zero. No node or
            // datadir has been touched at this point.
            QMessageBox::critical(nullptr, QObject::tr("ZclWallet cannot start"),
                QObject::tr("A required security library (libsodium) failed to "
                            "initialize. Please reinstall ZclWallet."));
            return 1;
        }

        // Check for embedded option
        if (parser.isSet(noembeddedOption)) {
            Settings::getInstance()->setUseEmbedded(false);
        } else {
            Settings::getInstance()->setUseEmbedded(true);
        }

        w = new MainWindow();
        w->setWindowTitle("ZclWallet v" + QString(APP_VERSION));

        // If there was a payment URI on the command line, pay it
        if (parser.positionalArguments().length() > 0) {
            w->payZClassicURI(parser.positionalArguments()[0]);
        }

        // Listen for any secondary instances: bring this window to the front
        // (un-hiding from the tray if needed) and, if a payment URI was passed,
        // pay it.
        QObject::connect(&a, &SingleApplication::receivedMessage, [=] (quint32, QByteArray msg) {
            QString uri(msg);

            // We need to execute this async, otherwise the app seems to crash for some reason.
            QTimer::singleShot(1, [=]() {
                w->showFromTray();
                if (uri != QStringLiteral("__SHOW__") && !uri.isEmpty())
                    w->payZClassicURI(uri);
            });
        });

        // For MacOS, we have an event filter
        a.installEventFilter(w);

        // Suppress the spurious "error connecting to zclassicd" box on quit. The macOS
        // app-menu Quit / Cmd-Q calls QApplication::quit() directly, bypassing
        // MainWindow::closeEvent()/shutdownZClassicd() where the expected-shutdown flag
        // is normally set; aboutToQuit fires on every quit route, so mark it here.
        QObject::connect(&a, &QCoreApplication::aboutToQuit, w, [=]() {
            if (w && w->getRPC())
                w->getRPC()->onAboutToQuit();
        });

        // Check if starting headless
        if (parser.isSet(headlessOption)) {
            Settings::getInstance()->setHeadless(true);
            a.setQuitOnLastWindowClosed(false);
        } else {
            Settings::getInstance()->setHeadless(false);
            // NEVER-STRAND guarantee: disable quit-on-last-window-closed for the
            // ENTIRE GUI lifetime. With this off, NO transient/modal dialog closing
            // (the connect dialog, a connect-error box, the node-crash box, the
            // foreign-stuck box) can ever end the process by itself when the main
            // window has not yet mapped -- which is exactly bob's silent-exit class.
            // Legitimate quits do NOT rely on this flag: the SIGINT handler and the
            // node-crash/foreign-stuck dialogs call QApplication::quit() directly,
            // and MainWindow::closeEvent now calls qApp->quit() unconditionally on a
            // real (non-tray) close. applyTraySetting() no longer re-enables this
            // flag, so a Settings-OK can no longer re-arm the trap (see mainwindow.cpp).
            a.setQuitOnLastWindowClosed(false);
            w->show();
            GuiStartup::markWindowShown();   // [gui-startup] first MainWindow show requested
            w->raise();
            w->activateWindow();
        }

        return QApplication::exec();
    }

    void DispatchToMainThread(std::function<void()> callback)
    {
        // any thread
        QTimer* timer = new QTimer();
        timer->moveToThread(qApp->thread());
        timer->setSingleShot(true);
        QObject::connect(timer, &QTimer::timeout, [=]()
        {
            // main thread
            callback();
            timer->deleteLater();
        });
        QMetaObject::invokeMethod(timer, "start", Qt::QueuedConnection, Q_ARG(int, 0));
    }

    bool handleSignal(int signal)
    {
        std::cout << std::endl << "Interrupted with signal " << signal << std::endl;
        
        if (w && w->getRPC()) {            
            // Blocking call to closeEvent on the UI thread.
            DispatchToMainThread([=] { 
                w->doClose(); 
                QApplication::quit();
            });
        } else {
            QApplication::quit();
        }
        
        return true;
    }

private:
    MainWindow* w;
};

// Keep the user's terminal clean: swallow one benign Qt-internal warning that the static
// Qt 5.15 QtNetwork stack emits while servicing HTTPS (price + update-check) requests --
// "QBasicTimer::start: QBasicTimer can only be used with threads started with QThread".
// It is harmless teardown noise: no application code starts a timer off-thread (the one
// cross-thread hop, DispatchToMainThread, uses the correct moveToThread + queued-start
// pattern), but a burst of it printed right before an unrelated exit looked like a crash.
// Everything that is NOT this line is printed exactly as Qt would.
static void zclMessageFilter(QtMsgType type, const QMessageLogContext&, const QString& msg)
{
    if (msg.contains(QLatin1String("QBasicTimer")) &&
        msg.contains(QLatin1String("threads started with QThread")))
        return;
    const QByteArray line = msg.toLocal8Bit();
    fprintf(stderr, "%s\n", line.constData());
    if (type == QtFatalMsg)
        abort();
}

int main(int argc, char* argv[])
{
    // [gui-startup] Start the process clock at the very first instruction so the
    // mirror of the daemon's [startup] log measures from true process entry.
    GuiStartup::begin();

    // Install the noise filter before anything can log.
    qInstallMessageHandler(zclMessageFilter);

    // NOTIFY-SRV connector mode: `<self> --notify <id>`, invoked by zclassicd's
    // -walletnotify/-blocknotify. A tiny headless mode that connects to the GUI's
    // token-gated notify socket, sends the per-session token + the txid/blockhash,
    // and exits. Handled HERE — before the GUI/QPA platform setup and before
    // SingleApplication — so it needs no display and is never mistaken for a second
    // GUI instance trying to forward a URI.
    for (int i = 1; i < argc; i++) {
        if (qstrcmp(argv[i], "--notify") == 0) {
            const QString id = (i + 1 < argc) ? QString::fromLocal8Bit(argv[i + 1]) : QString();
            return NotifyServer::runConnector(argc, argv, id);
        }
    }
#ifdef Q_OS_LINUX
    // ROOT-CAUSE FIX for bob's silent exit on a Wayland session.
    //
    // The static bundle ships ONLY the xcb QPA plugin (Qt configured with -xcb;
    // no qtwayland is built). On a Wayland session Qt's default probe selects the
    // "wayland" plugin, fails to find it ("Could not find the Qt platform plugin
    // \"wayland\""), and the top-level window never reliably maps -> silent exit.
    //
    // We force the already-linked xcb plugin, which runs transparently under
    // XWayland. BUT: forcing xcb with NO X display would make the xcb plugin abort
    // QApplication construction (a hard SIGABRT before any window) on the rare
    // Wayland-without-XWayland configs. So we only force xcb when an X display is
    // actually reachable (DISPLAY is set + non-empty). With no DISPLAY we leave
    // Qt's own probe alone: it can still try wayland / fall back to whatever
    // platform plugins are compiled into this static build, rather than being
    // forced into a guaranteed abort. Only-if-unset preserves the power-user
    // escape hatch (export QT_QPA_PLATFORM=... still wins).
    if (!qEnvironmentVariableIsSet("QT_QPA_PLATFORM")) {
        QByteArray display = qgetenv("DISPLAY");
        QByteArray waylandDisplay = qgetenv("WAYLAND_DISPLAY");
        if (!display.isEmpty()) {
            // X11 or XWayland present: xcb is the safe, mapping-reliable choice.
            qputenv("QT_QPA_PLATFORM", QByteArray("xcb"));
        } else if (!waylandDisplay.isEmpty()) {
            // Pure Wayland, no X display: the static set has no wayland plugin and
            // forcing xcb would abort. Try a non-aborting chain instead so we never
            // hard-crash before showing anything: prefer wayland (if a system
            // plugin happens to be discoverable), then xcb, then offscreen. Qt
            // walks the semicolon list until one initialises.
            qputenv("QT_QPA_PLATFORM", QByteArray("wayland;xcb;offscreen"));
            // Last-resort visibility: if every GUI platform fails, the user still
            // gets a line on stderr instead of a bare prompt. qWarning() routes to
            // stderr and needs no extra include (QtGlobal/QDebug via precompiled.h).
            qWarning("ZclWallet: no X display found on a Wayland session. If the "
                     "window does not appear, install XWayland (package "
                     "'xorg-xwayland') and relaunch, or run with "
                     "QT_QPA_PLATFORM=wayland.");
        }
        // else: neither DISPLAY nor WAYLAND_DISPLAY -> truly headless/no display.
        // Leave Qt's probe alone; the offscreen fallback (if compiled in) or Qt's
        // own error path handles it. Do not force xcb into an abort.
    }

    // ROOT-CAUSE FIX for the "Loading locale" -> SIGSEGV at first font lookup on fresh
    // distros (Fedora 39+/Arch, e.g. bob@t14). This single-file bundle STATICALLY links
    // Ubuntu-20.04 fontconfig 2.13 (cache version 7); on a host running fontconfig 2.14+
    // (cache version 9) the old lib faults while parsing the newer /etc/fonts config tree
    // and reading foreign-version caches on the FIRST QFontDatabase population. We point
    // fontconfig at our OWN minimal config: it still scans the host font *directories*
    // (so real fonts are available for fallback), but uses an app-private cachedir and
    // does NOT <include> the host /etc/fonts/conf.d -- so the old static lib never touches
    // the incompatible host config/cache. Only-if-unset preserves a power-user override.
    if (!qEnvironmentVariableIsSet("FONTCONFIG_FILE")) {
        const QString fcDir   = QDir::homePath() + "/.cache/zcl-qt-wallet";
        const QString fcCache = fcDir + "/fontconfig";
        const QString fcConf  = fcDir + "/fonts.conf";
        if (QDir().mkpath(fcCache)) {
            QFile cf(fcConf);
            if (cf.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                QByteArray xml =
                    "<?xml version=\"1.0\"?>\n"
                    "<!DOCTYPE fontconfig SYSTEM \"fonts.dtd\">\n"
                    "<fontconfig>\n"
                    "  <dir>/usr/share/fonts</dir>\n"
                    "  <dir>/usr/local/share/fonts</dir>\n"
                    "  <dir prefix=\"xdg\">fonts</dir>\n"
                    "  <dir>~/.fonts</dir>\n"
                    "  <cachedir>" + fcCache.toUtf8() + "</cachedir>\n"
                    "  <config></config>\n"
                    "</fontconfig>\n";
                cf.write(xml);
                cf.close();
                qputenv("FONTCONFIG_FILE", fcConf.toUtf8());
            }
        }
    }

    // This widget-only wallet needs no OpenGL context, but Qt's xcb plugin creates a
    // GLX/EGL "dummy context" at first window-map -- which can SIGSEGV inside a foreign
    // host GPU driver stack. Disable it; Qt Widgets render via the raster backing store.
    // Only-if-unset so a power user can re-enable GL.
    if (!qEnvironmentVariableIsSet("QT_XCB_GL_INTEGRATION"))
        qputenv("QT_XCB_GL_INTEGRATION", QByteArray("none"));
#endif

    Application app;
    return app.main(argc, argv);
}

