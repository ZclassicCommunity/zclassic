#include "connection.h"
#include "embeddeddaemon.h"
#include "mainwindow.h"
#include "settings.h"
#include "securerandom.h"   // CONF-1: CSPRNG rpcpassword / notify token

#ifndef Q_OS_WIN
#include <sys/stat.h>       // CONF-2: umask() so a fresh zclassic.conf is born 0600
#endif
#include "ui_connection.h"
#include "ui_createzclassicconfdialog.h"
#include "rpc.h"
#include "guistartup.h"     // [gui-startup] daemon-spawned / getinfo milestones

#include "precompiled.h"

#include <QStorageInfo>
#include <QProgressBar>
#include <QElapsedTimer>
#include <QtNetwork/QTcpSocket>
#include <QStringList>
#include <QCryptographicHash>
#include <QDirIterator>

using json = nlohmann::json;

ConnectionLoader::ConnectionLoader(MainWindow* main, RPC* rpc) {
    this->main = main;
    this->rpc  = rpc;

    d = new QDialog(main);
    connD = new Ui_ConnectionDialog();
    connD->setupUi(d);
    QPixmap logo(":/img/res/logobig.gif");
    connD->topIcon->setBasePixmap(logo.scaled(256, 256, Qt::KeepAspectRatio, Qt::SmoothTransformation));

    // ---- P1-1: friendly, non-scary staged-onboarding card (built in C++ so the
    // checked-in connection.ui / ui_connection.h stay untouched). It is shown on
    // first run only and stays visible through the initial sync. ----
    ezCard = new QLabel(d);
    ezCard->setWordWrap(true);
    ezCard->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    ezCard->setTextFormat(Qt::RichText);
    ezCard->setContentsMargins(16, 8, 16, 8);
    ezCard->setText(QObject::tr(
        "<b>Setting up ZClassic</b><br>"
        "The first run downloads the security files and a copy of the blockchain, "
        "then catches up with the network — this can take a while, but you only do "
        "it once. You can leave it running and come back later; it is safe.<br><br>"
        "&nbsp;&nbsp;<b>Step 1.</b> Getting the security files ready<br>"
        "&nbsp;&nbsp;<b>Step 2.</b> Starting your wallet<br>"
        "&nbsp;&nbsp;<b>Step 3.</b> Catching up with the network"));

    ezProgress = new QProgressBar(d);
    ezProgress->setTextVisible(false);
    // Busy / indeterminate by default; switched to a real 0-100 bar once we have
    // an actual percentage (param download % or block-sync %).
    ezProgress->setRange(0, 0);

    // Insert the card above, and the progress bar below, the status labels.
    // verticalLayout order today: topIcon, line_2, status, statusDetail, line.
    // We want: topIcon, line_2, [ezCard], status, statusDetail, [ezProgress], line.
    int statusIdx = connD->verticalLayout->indexOf(connD->status);
    if (statusIdx < 0) statusIdx = 2;
    connD->verticalLayout->insertWidget(statusIdx, ezCard);
    int lineIdx = connD->verticalLayout->indexOf(connD->line);
    if (lineIdx < 0) lineIdx = connD->verticalLayout->count();
    connD->verticalLayout->insertWidget(lineIdx, ezProgress);

    // Only show the explanatory card the very first time the user ever launches.
    bool firstRun = !QSettings().value("ez/onboardingShown", false).toBool();
    ezCard->setVisible(firstRun);
    if (firstRun)
        QSettings().setValue("ez/onboardingShown", true);

    d->setMinimumWidth(540);
}

ConnectionLoader::~ConnectionLoader() {
    // W2: mark this loader as gone so any still-in-flight async probe callback
    // (e.g. the getbootstrapinfo probe, whose Connection OUTLIVES the loader) sees
    // a false 'alive' token and bails before dereferencing freed members.
    if (ezAlive)
        *ezAlive = false;
    delete d;
    delete connD;
}

void ConnectionLoader::loadConnection() {
    QTimer::singleShot(1, [=]() { this->doAutoConnect(); });

    if (Settings::getInstance()->isHeadless())
        return;   // no UI at all (test/headless): never show the dialog.

    // W1-1: NON-MODAL startup (default ON). The old form blocked the entire UI for
    // 1-2 minutes behind d->exec() (a nested event loop that hid the main window for
    // the whole first-run node warmup). Instead show the MAIN WINDOW first so the
    // user immediately sees their cached balances (restoreSavedStates paints them
    // pre-RPC), then float the warmup splash as a NON-blocking, dismissible overlay.
    //
    // CRASH-SAFETY (why this no longer reproduces the prior teardown NULL-deref):
    //  * The earlier naive show()-swap freed the loader/dialog while a queued poll
    //    singleShot or an async getbootstrapinfo probe was still pending, then that
    //    lambda ran against freed members. Here EVERY async continuation already
    //    checks the shared ezAlive token (doAutoConnect / refreshZClassicdState /
    //    probeBootstrapProgress / classifyForeignDaemon all bail on !*ezAlive), and
    //    ~ConnectionLoader sets *ezAlive=false, so a late lambda is a guarded no-op.
    //  * The loader is freed in exactly ONE place — doRPCSetConnection's DEFERRED
    //    deleteLater(d) + QTimer::singleShot(0, main, [delete this]) — which now runs
    //    in the MAIN event loop (not unwinding a nested exec()), so the proven
    //    deferred-teardown ordering is intact and there is no nested-loop frame left
    //    to corrupt. Dismissing the splash (rejected()) only hides it; it does NOT
    //    free the loader, so no pending lambda can ever deref freed memory.
    if (Settings::getInstance()->getNonModalStartup()) {
        // Show the main window first / not gated on the splash.
        if (main) {
            main->show();
            main->raise();
            main->activateWindow();
        }
        // NON-blocking overlay: at most window-modal, NEVER application-modal (which
        // would re-block the whole UI). A plain modeless show keeps the main window
        // fully interactive while the node warms up.
        d->setModal(false);
        d->setWindowModality(Qt::NonModal);
        // Dismissing the splash (title-bar X / Esc) must NOT quit the app and must NOT
        // free the loader — it simply hides the overlay while warmup continues in the
        // background (guarded poll lambdas keep running; doRPCSetConnection still
        // closes everything cleanly when the node comes online). 'main' is the QObject
        // context so this connection auto-disconnects if the window is torn down first.
        QObject::connect(d, &QDialog::rejected, main, [this]() {
            if (!ezAlive || !*ezAlive)   // loader already retired -> nothing to do
                return;
            if (ezProgrammaticClose)     // showError's d->close() owns this path
                return;
            // A user dismiss just hides the modeless overlay and leaves the main
            // window up; warmup continues in the background.
            main->logger->write("Startup splash dismissed; warmup continues in background");
        });
        d->show();
        d->raise();
        return;
    }

    // Flag OFF: retain the PROVEN application-modal d->exec() path verbatim. The
    // use-after-free fix in doRPCSetConnection (done(Accepted) + DEFERRED
    // deleteLater(d) + deferred `delete this`) is what keeps this safe — it never
    // frees the dialog/loader while exec() is still on the stack.
    d->exec();
}

void ConnectionLoader::doAutoConnect(bool tryEzclassicdStart) {
    // Re-entrancy guard: a queued poll singleShot must not run on a RETIRED loader
    // (user closed the startup splash -> quitting; or ~ConnectionLoader ran). Without
    // this, a poll firing inside the quit handler's nested waitForFinished loop would
    // touch the dialog/connection/embedded node being torn down -> UAF/SIGSEGV.
    if (!ezAlive || !*ezAlive)
        return;

    // Priority 1: zk-params. We DO NOT pre-download them from z.cash here anymore.
    // z.cash now permanently 403s the deprecated sprout-proving.key (the legacy
    // ~910 MB Sprout proving key), which used to hang a fresh install FOREVER at
    // "Step 1 of 3: Getting the security files ready…" with no way to cancel. The
    // embedded daemon already fetches any missing params from a bootstrap peer over
    // P2P, hash-verified against its compiled table (daemon init.cpp: InitSanityCheck
    // -> FetchZcashParamsFromPeer, default -bootstrap=true). So we fall through to
    // start the node: if params are present it starts immediately; if not, it fetches
    // them while the splash shows "Almost ready…" (the warmup loop waits patiently as
    // long as the process is alive), or exits with a clear error that
    // handleStartupFailure() surfaces — never a silent hang on a dead URL. A
    // non-embedded external daemon is the user's own responsibility to provision.
    // (downloadParams() is retained but no longer on the startup path.)
    if (!verifyParams()) {
        main->logger->write("zk-params not all present locally; deferring to the daemon's hash-verified peer-fetch");
        // Item 3: params are missing, so the daemon will peer-fetch ~1.7GB before it even
        // binds its RPC port (ZC_LoadParams runs before AppInitServers). Latch this so the
        // refused-connection warmup branch below shows the accurate "one-time 1.7GB, 10-20
        // min" copy instead of a frozen "Almost ready" line for the whole download. Latch-
        // only (never cleared back to false here): once the params land, getinfo succeeds
        // and the snapshot/IBD pollers overwrite the status text every poll regardless.
        ezParamFetchLikely = true;
    }

    // COOKIE-AUTH proactive migration (runs at most once, before the FIRST connect of
    // this run). If a legacy GUI-owned conf still carries rpcuser=zcl-qt-wallet +
    // rpcpassword=<rand>, strip them in place so the daemon switches to cookie auth on
    // its next start and any already-desynced shared secret is healed with zero user
    // action. No-op for an external/daemon=1 conf or once already migrated. Cheap and
    // idempotent, so calling it on each doAutoConnect entry (gated by the QSettings
    // flag) is fine; the rewrite itself happens at most once.
    this->migrateConfToCookie();

    // Priority 2: Try to connect to detect zclassic.conf and connect to it.
    auto config = autoDetectZClassicConf();
    main->logger->write(QObject::tr("Attempting autoconnect"));

    if (config.get() != nullptr) {
        auto connection = makeConnection(config);

        // P2-1: remember the datadir (holds blocks/, chainstate/, debug.log and
        // wallet.dat) so the corruption failsafe can read debug.log and back up
        // wallet.dat if the node dies before the RPC connection comes up.
        if (ezDataDir.isEmpty() && !config->zclassicDir.isEmpty())
            ezDataDir = config->zclassicDir;

        refreshZClassicdState(connection, [=] () {
            // Connection refused: the embedded node either has not started yet, or
            // it is alive but still warming up -- binding its RPC port can take ~1
            // minute while it loads the block index. Be patient and reassuring;
            // NEVER show a scary error while the node is alive or within a warmup
            // window. (Previously a transient refused during normal warmup could
            // fire a false "Couldn't start the embedded zclassicd" on first launch.)
            if (!Settings::getInstance()->useEmbedded()) {
                main->logger->write("Not using embedded and couldn't connect to zclassicd");
                this->showError(QObject::tr("ZClassic couldn't connect.\n\n"
                    "It is set to use an outside connection that isn't responding. "
                    "Please check your internet connection and try opening ZClassic again."));
                return;
            }

            // Never started yet -> start it once.
            if (ezclassicd == nullptr) {
                this->showInformation(QObject::tr("Step 2 of 3: Starting your wallet…"));
                if (!this->startEmbeddedZClassicd()) {
                    main->logger->write("Could not launch the embedded zclassicd binary");
                    this->showError(QObject::tr("ZClassic couldn't start its node.\n\n"
                        "Please reinstall the app. If the problem continues, make sure your "
                        "security software isn't blocking it."));
                    return;
                }
                ezWarmupTimer.start();
                int probeMs = (ezWarmupTimer.isValid() && ezWarmupTimer.elapsed() < 4000) ? 250 : 1000;
                QTimer::singleShot(probeMs, [=]() { doAutoConnect(); });
                return;
            }

            // Started, RPC not answering yet. While the process is alive -- or within
            // a generous warmup window after it forked into the background -- keep
            // polling with a friendly message instead of ever showing an error.
            if (ezclassicd->state() != QProcess::NotRunning ||
                (ezWarmupTimer.isValid() && ezWarmupTimer.elapsed() < 120000)) {
                // Static fallback FIRST (covers the brief pre-RPC-bind window and an
                // older daemon with no getbootstrapinfo).
                //
                // Item 3: on a FRESH install the daemon peer-fetches ~1.7GB of zk-params
                // in ZC_LoadParams BEFORE it binds its RPC port (ZC_LoadParams precedes
                // AppInitServers in init.cpp). During that 10-20 min the port is fully
                // REFUSING, so this branch — not getbootstrapinfo — is all the user sees,
                // and the generic "Almost ready (this can take a minute)" reads as a hang.
                // When we know the params were missing at connect, paint the accurate,
                // reassuring one-time-download copy instead (the same wording that already
                // lived on the dead z.cash downloadParams() path). The instant the port
                // binds and the snapshot phase starts, the probeBootstrapProgress call
                // below takes over with real percent.
                if (ezParamFetchLikely) {
                    this->showInformation(QObject::tr("Step 1 of 3: Getting the security files ready…"),
                        QObject::tr("One-time download of about 1.7 GB — on a typical home "
                            "connection this takes 10–20 minutes. You only do this once."));
                } else {
                    this->showInformation(QObject::tr("Step 2 of 3: Starting your wallet…"),
                        QObject::tr("Almost ready — getting things going (this can take a minute)…"));
                }
                // Bob-fix: getinfo here came back CONNECTION-REFUSED (the RPC port is not
                // yet answering getinfo, OR the connection-level request failed) — which is
                // exactly the multi-minute snapshot-download window on a slow link. Plain
                // getinfo can't see it, but getbootstrapinfo is WARMUP-EXEMPT and answers
                // the moment the RPC port binds (early, before the download finishes). Fire
                // it so the splash shows MOVING "Downloading blockchain — X%"/"Verifying…"
                // instead of the frozen "Almost ready" line. Async + advisory: if the port
                // is still fully refusing it just errors out harmlessly and the static text
                // above stays; it never blocks or changes the poll cadence below. Owned
                // embedded daemon only (it always has the RPC); a foreign daemon attaches on
                // the getinfo-success path before this branch matters.
                if (ezclassicd != nullptr)
                    this->probeBootstrapProgress(connection);
                // Probe quickly during the first few seconds of warmup so warm restarts
                // reconnect without waiting a full extra second, then settle to 1s.
                int probeMs = (ezWarmupTimer.isValid() && ezWarmupTimer.elapsed() < 4000) ? 250 : 1000;
                QTimer::singleShot(probeMs, [=]() { doAutoConnect(); });
                return;
            }

            // Process is genuinely dead and the warmup window elapsed. Before
            // showing a generic error, look at WHY it died: a corrupt or
            // partway block/chainstate database has a safe, staged repair path.
            main->logger->write("Embedded zclassicd exited and did not come online");
            this->handleStartupFailure();
        });
    } else {
        if (Settings::getInstance()->useEmbedded()) {
            // zclassic.conf was not found, so create one
            createZClassicConf();
        } else {
            // Fall back to manual connect
            doManualConnect();
        }
    } 
}

// [[maybe_unused]]: no longer called on the conf-write path (cookie auth replaced the
// shared rpcpassword). Retained intentionally per CONF-1 history; silence -Wunused-function.
[[maybe_unused]] static QString randomPassword() {
    // CONF-1: CSPRNG, >= 128 bits. The previous implementation drew 10 chars from
    // rand()%62 (~59.5 bits, time-seeded and predictable) and leaked the heap
    // buffer; both are gone. 32 base62 chars ≈ 190 bits. See src/securerandom.h
    // (shared with the NOTIFY-SRV per-session token so there is one CSPRNG source).
    // CONF-3: the returned value is a secret — it is written ONLY into the 0600
    // zclassic.conf below and is NEVER logged, qDebug'd, or put in a status string.
    return secureRandomBase62(32);
}

/**
 * This will create a new zclassic.conf, download ZClassic parameters.
 */ 
void ConnectionLoader::createZClassicConf() {
    main->logger->write("createZClassicConf");

    auto confLocation = zclassicConfWritableLocation();
    QFileInfo fi(confLocation);

    QDialog d(main);
    Ui_createZClassicConf ui;
    ui.setupUi(&d);

    QPixmap logo(":/img/res/zclassicdlogo.gif");
    ui.lblTopIcon->setBasePixmap(logo.scaled(256, 256, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    ui.btnPickDir->setEnabled(false);

    ui.grpAdvanced->setVisible(false);
    QObject::connect(ui.btnAdvancedConfig, &QPushButton::toggled, [=](bool isVisible) {
        ui.grpAdvanced->setVisible(isVisible);
        ui.btnAdvancedConfig->setText(isVisible ? QObject::tr("Hide Advanced Config") : QObject::tr("Show Advanced Config"));
    });

    QObject::connect(ui.chkCustomDatadir, &QCheckBox::stateChanged, [=](int chked) {
        if (chked == Qt::Checked) {
            ui.btnPickDir->setEnabled(true);
        }
        else {
            ui.btnPickDir->setEnabled(false);
        }
    });

    QObject::connect(ui.btnPickDir, &QPushButton::clicked, [=]() {
        auto datadir = QFileDialog::getExistingDirectory(main, QObject::tr("Choose data directory"), ui.lblDirName->text(), QFileDialog::ShowDirsOnly);
        if (!datadir.isEmpty()) {
            ui.lblDirName->setText(QDir::toNativeSeparators(datadir));
        }
    });

    // Show the dialog
    QString datadir = "";
    bool useTor = false;
    if (d.exec() == QDialog::Accepted) {
        datadir = ui.lblDirName->text();
        useTor = ui.chkUseTor->isChecked();
    }

    main->logger->write("Creating file " + confLocation);
    QDir().mkpath(fi.dir().absolutePath());

    // CONF-2: the conf holds the rpcpassword (and, in Phase 1, the notify token),
    // so it must be owner-only (0600) and NEVER group/world-readable for any
    // instant — the hostile co-resident local user is in the threat model. Tighten
    // the umask to 0077 ACROSS the create so a fresh conf is BORN 0600 (no TOCTOU
    // window at the umask default of ~0644 before we could chmod it); the umask is
    // restored immediately after open(). chmod-after still runs below to also narrow
    // a pre-existing conf written 0644 by an older wallet. Linux/macOS only (POSIX
    // umask); Windows file ACLs are handled by setPermissions alone.
#ifndef Q_OS_WIN
    mode_t oldMask = ::umask(0077);
#endif
    QFile file(confLocation);
    bool opened = file.open(QIODevice::ReadWrite | QIODevice::Truncate);
#ifndef Q_OS_WIN
    ::umask(oldMask);
#endif
    if (!opened) {
        main->logger->write("Could not create zclassic.conf, returning");
        // Don't silently strand the user on the connecting screen forever — tell
        // them what went wrong so they can fix permissions / free disk space.
        this->showError(QObject::tr("ZClassic couldn't save its configuration file.\n\n"
            "Please make sure you have permission to write to your home folder and "
            "enough free disk space, then open ZClassic again."));
        return;
    }

    // Belt-and-suspenders + pre-existing-conf narrowing (Truncate keeps an existing
    // file's old mode, which umask does not touch). Best-effort: on a filesystem
    // that can't honor perms we still write the conf (logged without any secret).
    if (!file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner))
        main->logger->write("warning: could not restrict zclassic.conf to 0600");

    QTextStream out(&file);
    
    out << "server=1\n";
    // No addnode here: mainnet.z.cash is a Zcash (ZEC) node, not a valid ZClassic
    // peer, and the zclassicd we drive already pins its own compiled bootstrap
    // peers / seeds as -addnode on every start. Baking a wrong peer into the
    // user's permanent conf only causes repeated failed connections.
    // COOKIE-AUTH: do NOT write a shared rpcuser/rpcpassword. With no rpcpassword in
    // the conf the daemon auto-generates <datadir>/.cookie on every start
    // (httprpc.cpp InitRPCAuthentication, gated on mapArgs["-rpcpassword"]=="") and the
    // GUI authenticates by reading that cookie on each connect attempt. With no
    // persisted shared secret, the rpcpassword desync that produced the HTTP-401
    // dead-end cannot occur for an embedded node — the 401 class is eliminated by
    // construction, not patched. The embedded launch additionally forces an absolute
    // -rpccookiefile (startEmbeddedZClassicd) so the GUI reads the exact file the
    // daemon wrote, with no testnet3/ or custom-datadir= guessing. randomPassword() is
    // retained for compatibility but is no longer on the conf-write path.
    // (Was: rpcuser=zcl-qt-wallet + rpcpassword=<randomPassword()>.)
    if (!datadir.isEmpty()) {
        out << "datadir=" % datadir % "\n";
    }
    if (useTor) {
        out << "proxy=127.0.0.1:9050\n";
    }

    file.close();

    // CONF-2 verify: read the perms BACK from disk and confirm the conf is actually
    // owner-only. setPermissions() above is best-effort (a pre-existing 0644 conf from
    // an older wallet, or an exotic filesystem, may not have narrowed). If any
    // group/other read or write bit is still set, the rpcpassword is exposed to a
    // co-resident local user — log a CLEAR diagnostic (never the password) so it's
    // visible. We do NOT abort: stranding the user on the connecting screen is worse
    // than a logged warning, and a fresh conf is born 0600 via the umask above anyway.
    {
        QFile::Permissions p = QFile::permissions(confLocation);
        const QFile::Permissions leaky =
            QFileDevice::ReadGroup  | QFileDevice::WriteGroup |
            QFileDevice::ReadOther  | QFileDevice::WriteOther;
        if (p & leaky)
            main->logger->write("WARNING: zclassic.conf could not be secured to 0600 — it "
                                "remains group/other-accessible, exposing the RPC credentials "
                                "to other local users on this machine. Please chmod 600 it.");
    }

    // Now that zclassic.conf exists, try to autoconnect again
    this->doAutoConnect();
}


// DEAD CODE — NOT on the startup path. The daemon now peer-fetches the zk-params
// itself, hash-verified (see the param-fetch note near line 115); z.cash PERMANENTLY
// 403s the URLs enqueued below, and that dead download is exactly what used to hang
// fresh installs. This function (and doNextDownload) are retained for reference only
// and have no live caller. Do NOT wire these z.cash URLs back into onboarding.
void ConnectionLoader::downloadParams(std::function<void(void)> cb) {
    main->logger->write("Adding params to download queue");

    // P1-7: make sure there is enough room before pulling ~1.7GB of security files.
    if (!ensureEnoughDiskSpace(zcashParamsDir()))
        return;

    // P1-1: this is Step 1 of onboarding.
    this->showInformation(QObject::tr("Step 1 of 3: Getting the security files ready…"),
                          QObject::tr("One-time download of about 1.7 GB — on a typical home connection this takes 10–20 minutes. You only do this once."));

    // Add all the files to the download queue
    downloadQueue = new QQueue<QUrl>();
    client = new QNetworkAccessManager(main);   
    
    downloadQueue->enqueue(QUrl("https://z.cash/downloads/sapling-output.params"));
    downloadQueue->enqueue(QUrl("https://z.cash/downloads/sapling-spend.params"));    
    downloadQueue->enqueue(QUrl("https://z.cash/downloads/sprout-proving.key"));
    downloadQueue->enqueue(QUrl("https://z.cash/downloads/sprout-verifying.key"));
    downloadQueue->enqueue(QUrl("https://z.cash/downloads/sprout-groth16.params"));

    doNextDownload(cb);    
}

void ConnectionLoader::doNextDownload(std::function<void(void)> cb) {
    auto fnSaveFileName = [&] (QUrl url) {
        QString path = url.path();
        QString basename = QFileInfo(path).fileName();

        return basename;
    };

    if (downloadQueue->isEmpty()) {
        delete downloadQueue;
        downloadQueue = nullptr;
        client->deleteLater();
        client = nullptr;

        main->logger->write("All Downloads done");
        ezRetryCount = 0;
        // Back to a busy bar; the node-start / sync phase has no per-file %.
        if (ezProgress) ezProgress->setRange(0, 0);
        this->showInformation(QObject::tr("Step 1 of 3: Security files ready."),
                              QObject::tr("Starting your wallet…"));
        cb();
        return;
    }

    QUrl url = downloadQueue->head();   // peek; only dequeue on success so retries can re-pull
    int totalFiles = 5;                 // we enqueue 5 param files
    int fileNumber = totalFiles - downloadQueue->size() + 1;

    QString filename = fnSaveFileName(url);
    QString paramsDir = zcashParamsDir();

    if (QFile(QDir(paramsDir).filePath(filename)).exists()) {
        main->logger->write(filename + " already exists, skipping");
        downloadQueue->dequeue();
        doNextDownload(cb);

        return;
    }

    // The downloaded file is written to a new name, and then renamed when the operation completes.
    currentOutput = new QFile(QDir(paramsDir).filePath(filename + ".part"));   

    if (!currentOutput->open(QIODevice::WriteOnly)) {
        main->logger->write("Couldn't open " + currentOutput->fileName() + " for writing");
        delete currentOutput;
        currentOutput = nullptr;
        // P1-2 fix: must NOT fall through after a failed open.
        this->showError(QObject::tr("ZClassic couldn't save the security files.\n\n"
            "Please make sure you have enough free disk space, then open ZClassic again."));
        return;
    }
    main->logger->write("Downloading to " + filename);
    qDebug() << "Downloading " << url << " to " << filename;
    
    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
    // P1-5: a stalled socket should fail fast and retry instead of hanging forever.
    // NOTE: in Qt 5.15 setTransferTimeout lives on QNetworkRequest / QNetworkAccessManager,
    // NOT on QNetworkReply, so it is set here on the request before get().
    request.setTransferTimeout(30000);
    currentDownload = client->get(request);
    downloadTime.start();
    
    // Download Progress
    QObject::connect(currentDownload, &QNetworkReply::downloadProgress, [=] (auto done, auto total) {
        // calculate the download speed
        double speed = done * 1000.0 / (downloadTime.elapsed() > 0 ? downloadTime.elapsed() : 1);
        QString unit;
        double dispSpeed = speed;
        if (dispSpeed < 1024) {
            unit = " bytes/sec";
        } else if (dispSpeed < 1024*1024) {
            dispSpeed /= 1024;
            unit = " kB/s";
        } else {
            dispSpeed /= 1024*1024;
            unit = " MB/s";
        }

        // P1-2: aggregate, friendly progress. Drive the real 0-100 bar off this
        // file's percentage, and show file X of N plus an ETA for the current file.
        QString eta;
        if (total > 0 && speed > 1) {
            int secsLeft = (int)((total - done) / speed);
            if (secsLeft > 90)
                eta = QObject::tr(", about ") % QString::number(secsLeft / 60) % QObject::tr(" min left");
            else if (secsLeft > 0)
                eta = QObject::tr(", about ") % QString::number(secsLeft) % QObject::tr(" sec left");
        }
        if (total > 0)
            this->setBarPercent((int)(done * 100 / total));

        this->showInformation(
            QObject::tr("Step 1 of 3: Getting the security files ready…"),
            QObject::tr("File ") % QString::number(fileNumber) % QObject::tr(" of ") % QString::number(totalFiles)
                % " — "
                % QString::number(done/1024.0/1024.0, 'f', 0) % QObject::tr(" MB of ")
                % (total > 0 ? QString::number(total/1024.0/1024.0, 'f', 0) : QObject::tr("?")) % QObject::tr(" MB at ")
                % QString::number(dispSpeed, 'f', 1) % unit % eta);
    });
    
    // Download new data available. 
    QObject::connect(currentDownload, &QNetworkReply::readyRead, [=] () {
        if (currentOutput)
            currentOutput->write(currentDownload->readAll());
    });    

    // Download Finished
    QObject::connect(currentDownload, &QNetworkReply::finished, [=] () {
        bool failed = (currentDownload->error() != QNetworkReply::NoError);

        if (currentOutput) {
            currentOutput->close();
        }
        currentDownload->deleteLater();

        // C10: a "successful" transfer that is implausibly small is almost certainly
        // a captive-portal/redirect HTML page or a truncated body, not a real param
        // (all 5 real params are far larger than 1 MB). Treat it as a failed download
        // so it falls into the same auto-retry / offerRetry path below.
        if (!failed && currentOutput && currentOutput->size() < 1000000) {
            main->logger->write(QString("Downloaded %1 is too small (%2 bytes); treating as failed")
                                    .arg(filename).arg(currentOutput->size()));
            failed = true;
        }

        if (failed) {
            main->logger->write("Downloading " + filename + " failed: " + currentDownload->errorString());
            // Drop the partial file so a retry starts clean.
            if (currentOutput) {
                currentOutput->remove();
                currentOutput->deleteLater();
                currentOutput = nullptr;
            }

            // P1-2/P1-5: auto-retry the same file a few times, then offer a Retry button
            // instead of a dead end.
            if (ezRetryCount < 3) {
                ezRetryCount++;
                main->logger->write(QString("Auto-retrying download (attempt %1)").arg(ezRetryCount));
                this->showInformation(QObject::tr("Step 1 of 3: Getting the security files ready…"),
                                      QObject::tr("Connection hiccup — retrying…"));
                QTimer::singleShot(1500, [=]() { this->doNextDownload(cb); });
            } else {
                this->offerRetry(QObject::tr("The setup files couldn't finish downloading.\n\n"
                    "This is almost always a temporary internet problem. Check your connection "
                    "(Wi-Fi / ethernet / phone hotspot), then tap Retry. Your progress so far is kept."), cb);
            }
            return;
        }

        // Success: rename the .part into place and move on.
        main->logger->write("Finished downloading " + filename);
        if (currentOutput) {
            currentOutput->rename(QDir(paramsDir).filePath(filename));
            currentOutput->deleteLater();
            currentOutput = nullptr;
        }
        ezRetryCount = 0;
        downloadQueue->dequeue();
        doNextDownload(cb);
    });
}

bool ConnectionLoader::startEmbeddedZClassicd(const QStringList& extraArgs) {
    if (!Settings::getInstance()->useEmbedded())
        return false;

    main->logger->write("Trying to start embedded zclassicd");

    if (ezclassicd != nullptr) {
        if (ezclassicd->state() == QProcess::NotRunning) {
            // The node object already exists but the process is dead. This is the
            // failsafe's job now: handleStartupFailure() inspects stderr/debug.log
            // and offers a staged repair. We do NOT show a generic dialog here, and
            // we do NOT relaunch the same dead QProcess. Caller handles the result.
            if (!ezStdErr.isEmpty())
                main->logger->write("node stderr: " + ezStdErr);
            return false;
        } else {
            return true;
        }
    }

    // Finally, start zclassicd. Resolution order is SIBLING-FIRST so that the
    // dev build, the .deb and the macOS .app (all of which ship a real daemon
    // file next to / inside the bundle) keep working exactly as before. Only the
    // single-file release -- where no sibling exists because the daemon is
    // appended to our own executable -- falls back to extracting it.
    QDir appPath(QCoreApplication::applicationDirPath());
    QString zclassicdProgram;
#ifdef Q_OS_LINUX
    zclassicdProgram = appPath.absoluteFilePath("zqw-zclassicd");
    if (!QFile(zclassicdProgram).exists())
        zclassicdProgram = appPath.absoluteFilePath("zclassicd");
    if (!QFile(zclassicdProgram).exists())
        zclassicdProgram = ensureDaemonExtracted();
#elif defined(Q_OS_DARWIN)
    // No runtime extraction on macOS: a hardened-runtime / code-signed build must
    // not exec a binary written at runtime, so the signed daemon ships as a sibling
    // inside Contents/MacOS and ensureDaemonExtracted() returns empty.
    zclassicdProgram = appPath.absoluteFilePath("zclassicd");
#else
    zclassicdProgram = appPath.absoluteFilePath("zclassicd.exe");
    if (!QFile(zclassicdProgram).exists())
        zclassicdProgram = ensureDaemonExtracted();   // absolute path under %LOCALAPPDATA%
#endif

    if (zclassicdProgram.isEmpty() || !QFile(zclassicdProgram).exists()) {
        qDebug() << "Can't find zclassicd at " << zclassicdProgram;
        main->logger->write("Can't find zclassicd at " + zclassicdProgram);
        return false;
    }

    // Reset per-launch failsafe state so each (re)launch is judged on its own output.
    ezNodeQuitDuringStartup = false;
    ezStdErr.clear();

    ezclassicd = new QProcess(main);
    // By default the node writes persistent diagnostics to debug.log. Do not
    // buffer unused stdout for the lifetime of a full-node session. Explicit
    // printtoconsole output is discarded; startup stderr is still captured below.
    ezclassicd->setStandardOutputFile(QProcess::nullDevice());
    QObject::connect(ezclassicd, &QProcess::started, [=] () {
        //qDebug() << "zclassicd started";
    });

    // NOTIFY-SRV: stand up the push socket + write the 0600 token file BEFORE launching
    // the daemon, so the socket is already listening when the node first fires a
    // -walletnotify/-blocknotify. ONLY on this OWNED-daemon path (rpc->getNotifyServer()
    // is non-null only for a non-headless session). A foreign/systemd daemon never
    // reaches here, so its socket is never started and it stays on the timer poll.
    // Tracks whether the push socket is actually listening AND its token is on
    // disk. The -walletnotify/-blocknotify launch-args below are gated on this:
    // if provisioning failed we must NOT tell the daemon to fire notifies into a
    // socket nobody is listening on (every event would spawn a connector that
    // fails to connect — wasted forks). A false here just degrades to the timer poll.
    bool notifyReady = false;
    if (rpc && rpc->getNotifyServer()) {
        NotifyServer* ns = rpc->getNotifyServer();
        // Both fail SAFE (a missing socket/token just degrades to the timer poll), but
        // log a one-line diagnostic so a silent provisioning failure isn't invisible.
        if (!ns->start(NotifyServer::defaultSocketPath()))
            main->logger->write("NOTIFY-SRV: socket listen failed; falling back to poll");
        else if (!ns->writeTokenFile())
            main->logger->write("NOTIFY-SRV: token file write failed; falling back to poll");
        else
            notifyReady = ns->isListening();   // confirm the listener is actually up
    }

    // A. DETECT: if the node EXITS before the RPC connection is established (i.e.
    // while ezWarmupTimer is still inside its window), record that it quit during
    // startup. doRPCSetConnection() clears ezWarmupTimer when RPC succeeds, so a
    // 'finished' after that is a normal shutdown and is ignored here.
    QObject::connect(ezclassicd, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                        [=](int exitCode, QProcess::ExitStatus exitStatus) {
        main->logger->write(QString("zclassicd finished: code=%1 status=%2")
                            .arg(exitCode).arg((int)exitStatus));
        // Drain any final stderr the readyRead signal hasn't delivered yet.
        if (ezclassicd)
            ezStdErr = (ezStdErr + QString::fromLocal8Bit(ezclassicd->readAllStandardError())).right(64 * 1024);
        if (ezWarmupTimer.isValid())
            ezNodeQuitDuringStartup = true;   // died before we ever connected
    });

    // A. DETECT: failure to even launch (missing exec permission, AV block, etc.).
    QObject::connect(ezclassicd, &QProcess::errorOccurred, [=] (QProcess::ProcessError error) {
        main->logger->write(QString("zclassicd errorOccurred: %1 (%2)")
                            .arg((int)error)
                            .arg(ezclassicd ? ezclassicd->errorString() : QString()));
        if (ezWarmupTimer.isValid())
            ezNodeQuitDuringStartup = true;
    });

    QObject::connect(ezclassicd, &QProcess::readyReadStandardError, [=]() {
        auto output = ezclassicd->readAllStandardError();
        main->logger->write("zclassicd stderr:" + output);
        // Keep enough recent context for startup diagnosis, with bounded memory.
        ezStdErr = (ezStdErr + QString::fromLocal8Bit(output)).right(64 * 1024);
    });

    // Startup-speed defaults. -par/-maxsigcachesize apply on every launch.
    // Leave -dbcache to the daemon and zclassic.conf: forcing 450 MiB here
    // disabled its 64-bit 1024 MiB default (2048 MiB during a rebuild) and
    // overrode the user's cache setting, causing unnecessary disk flushes.
    // -checkblocks is added only on a NORMAL launch (gated below): the default
    // 288-block startup re-verification (~12h of 2.5-min blocks, re-read every launch)
    // is the bulk of the visible warmup; the chain was already validated when first
    // connected and the corruption failsafe (handleStartupFailure) covers a damaged db
    // separately, so capping it is safe -- but during a repair relaunch the caller's
    // -reindex must run full validation, so we skip -checkblocks then.
    QStringList launchArgs;
    // COOKIE-AUTH (MANDATORY): force an ABSOLUTE -rpccookiefile so the daemon writes
    // its auth cookie to the EXACT path the GUI will read (GetAuthCookieFile honors an
    // absolute -rpccookiefile, rpc/protocol.cpp). This removes the net-specific
    // testnet3/ subdir + custom-datadir= path-guessing as a failure mode entirely.
    // Computed from the SAME conf the GUI reads, so launch path == read path. We only
    // know the conf/datadir once it has been detected; ezDataDir is set in
    // doAutoConnect from config->zclassicDir before this runs on the embedded path.
    {
        auto detected = autoDetectZClassicConf();
        if (detected) {
            QString cookiePath = cookieFilePathForConf(detected);
            if (!cookiePath.isEmpty()) {
                // Logs only the PATH, never cookie contents (matches daemon log).
                main->logger->write("Embedded launch: pinning -rpccookiefile=" + cookiePath);
                launchArgs << (QStringLiteral("-rpccookiefile=") + cookiePath);
            }
        }
    }
    launchArgs << "-par=0"                // auto-detect cores: parallel script
                                          // verification (startup verify + IBD;
                                          // daemon default is single-threaded)
               << "-maxsigcachesize=128"; // fewer redundant signature re-verifies
    // -checkblocks=12 ONLY on a normal launch. During a repair relaunch the caller
    // passes -reindex / -reindex-chainstate in extraArgs, where capping startup
    // verification would defeat the point of a full re-validation.
    if (extraArgs.isEmpty())
        launchArgs << "-checkblocks=12";
    // Opt-in "Help the network: open my port automatically" (default OFF). When the
    // user has enabled it, ask the embedded daemon to forward our own P2P listen
    // port via NAT-PMP/PCP (no UPnP) so NAT/firewalled users become reachable for
    // inbound peers. Pure net plumbing; the daemon defaults this OFF too, so the
    // flag is only ever present when the user explicitly opted in.
    if (Settings::getInstance()->getOpenPortNatpmp())
        launchArgs << "-natpmp=1";
    // NOTIFY-SRV: wire the daemon's -walletnotify/-blocknotify to our `--notify %s`
    // connector so wallet/block events PUSH a refresh instead of waiting for the poll.
    // ONLY when the socket+token were actually provisioned above (notifyReady). The arg
    // carries NO token (the connector reads it from the 0600 file); %s is substituted by
    // the daemon. If the socket never came up we leave these args OFF so the daemon does
    // not fire notifies into a dead socket — the timer poll keeps the UI fresh instead.
    if (notifyReady)
        launchArgs.append(RPC::buildNotifyArgs(QCoreApplication::applicationFilePath()));
    launchArgs.append(extraArgs);
    // NOTE: ezWarmupTimer is started by the caller (doAutoConnect / relaunchForRepair)
    // right after this returns; do NOT restart it here or the warmup-window check and
    // the startup-timing log would measure from the wrong instant.

#ifdef Q_OS_LINUX
    ezclassicd->start(zclassicdProgram, launchArgs);
#elif defined(Q_OS_DARWIN)
    ezclassicd->start(zclassicdProgram, launchArgs);
#else
    // Spawn by ABSOLUTE path: in the single-file release the daemon is extracted
    // outside appPath (under %LOCALAPPDATA%), so the old bare-name "zclassicd.exe"
    // + working-directory spawn would not find it.
    ezclassicd->setWorkingDirectory(appPath.absolutePath());
    ezclassicd->start(zclassicdProgram, launchArgs);
#endif // Q_OS_LINUX

    // [gui-startup] We own this daemon and just spawned it. First-write-wins, so a
    // later repair-relaunch never overwrites the original cold-start spawn time.
    GuiStartup::markDaemonSpawned();

    return true;
}

// Single-file release: locate the daemon payload appended to our own executable,
// verify it, and extract it to a per-user cache. Layout at the END of the file:
//   [ ...GUI ELF... ][ daemon bytes ][ sha256(daemon) :32 ][ daemon len :8 LE ][ magic :8 ]
// Returns the absolute path of the verified, executable daemon, or an empty
// string to make the caller fall back (no payload / mismatch / macOS).
QString ConnectionLoader::ensureDaemonExtracted() {
#ifdef Q_OS_DARWIN
    return QString();   // never extract+exec on macOS (hardened-runtime / signed build)
#else
    QString error;
    const QString path = extractEmbeddedDaemon(QCoreApplication::applicationFilePath(),
        QStandardPaths::writableLocation(QStandardPaths::CacheLocation), &error);
    if (path.isEmpty()) main->logger->write("Embedded daemon: " + error);
    return path;
#endif // Q_OS_DARWIN
}

// A./B. Detect-and-classify entry point. Called from doAutoConnect once the node
// is confirmed dead and the warmup window has elapsed. Reads the captured stderr
// plus the tail of <datadir>/debug.log, scans for corruption markers, and either
// offers the staged repair ladder (corruption) or shows the existing generic
// friendly error (everything else).
void ConnectionLoader::handleStartupFailure() {
    // W4: classify primarily on THIS run's stderr. debug.log is appended across runs,
    // so its 16 KB tail can still hold a corruption/anchor marker from a PRIOR run that
    // was already recovered — folding that into the diag every time can misroute this
    // run (e.g. into a needless reindex/re-download). So: if this run's stderr already
    // carries a recognized marker, classify on stderr ALONE and ignore the (possibly
    // stale) log tail. Only when stderr has NO recognized marker do we consult the
    // debug.log tail as a fallback (the daemon sometimes logs the cause only to
    // debug.log before aborting, leaving stderr empty).
    QString diag = ezStdErr;
    if (!startupDiagHasMarker(diag)) {
        QString logTail = readDebugLogTail();
        if (!logTail.isEmpty())
            diag += "\n" + logTail;
    } else {
        main->logger->write("Startup failure: this-run stderr already carries a known "
                            "marker; ignoring debug.log tail to avoid a stale-marker misroute");
    }

    main->logger->write(QString("Startup failure classification; quitDuringStartup=%1, diag bytes=%2")
                        .arg(ezNodeQuitDuringStartup).arg(diag.size()));

    // Disk full (EXPLICIT daemon signal): the daemon itself emitted "Disk space is
    // low", which means it aborted specifically because the drive is full. A repair
    // (reindex/re-download) needs MORE space, so it would only fail again — say so
    // plainly and stop. This is the ONLY hard short-circuit on disk.
    if (diag.contains("Disk space is low", Qt::CaseInsensitive)) {
        this->showError(QObject::tr("ZClassic is running low on disk space.\n\n"
            "Please free up several gigabytes on this drive, then open ZClassic again. "
            "Your wallet and coins are safe."));
        return;
    }

    // G8: a low free-space HEURISTIC (<2GB) is NOT, by itself, a reason to refuse a
    // repair: a corrupt/partway DB on a fullish disk is the most common cause of the
    // crash, and the staged ladder has its OWN space floors (redownloadChain needs
    // ~15GB; relaunchForRepair's reindex needs little). So we do NOT short-circuit
    // here. Carry the low-disk fact as CONTEXT and let the corruption/anchor
    // classifiers below run first; only the final generic fallback uses it.
    qint64 freeBytes = ezDataDir.isEmpty() ? -1 : QStorageInfo(resolveDataSubdir()).bytesAvailable();
    bool lowDiskContext = (freeBytes >= 0 && freeBytes < (qint64)2 * 1024 * 1024 * 1024);

    // Another copy is already using this data folder (a second wallet window, or a
    // manually started zclassicd). A repair is the wrong action — point at that.
    if (diag.contains("probably already running", Qt::CaseInsensitive) ||
        diag.contains("Cannot obtain a lock", Qt::CaseInsensitive)) {
        this->showError(QObject::tr("ZClassic may already be running.\n\n"
            "Please close any other ZClassic windows (or wait a moment and try again), "
            "then reopen it. Your wallet and coins are safe."));
        return;
    }

    // SELF-HEAL serialization: if a destructive heal is already armed (its relaunch
    // is pending), never start a second one. A clean getinfo clears this flag (and
    // the whole ledger). DISK_FULL / ALREADY_RUNNING above are non-destructive and
    // intentionally sit ahead of this guard. NOTE: a heal/inProgress observed at
    // process startup is cleared once in the MainWindow ctor (it can only be a stale
    // flag from a killed prior session), so reaching here means a genuine in-flight
    // heal in THIS run. We must NOT silently return and leave the modal connect
    // dialog hung with no text — surface a plain-language message that also points
    // at the always-reachable manual Help -> Repair action.
    if (healInProgress()) {
        main->logger->write("Self-heal already in progress; not starting another");
        this->showError(QObject::tr("ZClassic is already trying to fix its blockchain data — "
            "please give it a moment.\n\n"
            "If nothing happens, quit and open ZClassic again, or use the Help menu "
            "(\"Repair / Re-download blockchain…\"). Your wallet and coins are safe."));
        return;
    }

    // SELF-HEAL: terminal NEEDS_MANUAL latched — stop ALL auto-action this run, but
    // the manual Help -> Repair action stays reachable. Show the plain-language
    // pointer at the saved wallet backup once, then bail.
    if (QSettings().value("heal/manualOnly", false).toBool()) {
        this->showError(QObject::tr("ZClassic tried to fix its blockchain data automatically "
            "but couldn't.\n\n"
            "Your wallet and coins are safe — a backup copy of your wallet was saved next to "
            "it. You can try a repair yourself from the Help menu (\"Repair / Re-download "
            "blockchain…\"), or copy your wallet file somewhere safe and have this computer's "
            "disk checked."));
        return;
    }

    // EXTRACT_FAILED (single-file build only): the bundled daemon couldn't be
    // extracted/verified. This is a bundle problem, NOT chain corruption, so it must
    // NOT route through the corruption ladder. Re-extract ONCE (content-addressed,
    // SHA-256 gate never skipped); a second failure means a genuine bundle mismatch.
    if (diag.contains("payload failed verification", Qt::CaseInsensitive) ||
        diag.contains("invalid embedded payload", Qt::CaseInsensitive) ||
        diag.contains("Can't find zclassicd", Qt::CaseInsensitive)) {
        this->retryExtractionOnce(diag);
        return;
    }

    // DB_TOO_NEW: wallet.dat was written by a NEWER version of ZClassic. This is NOT
    // corruption — running -salvagewallet would needlessly rewrite a perfectly good
    // wallet (and can't help). Handle it explicitly BEFORE the corrupt classifier so
    // it can never fall through to a salvage; tell the user to update.
    if (diag.contains("requires newer version", Qt::CaseInsensitive)) {
        this->showError(QObject::tr("This wallet was created by a newer version of ZClassic — "
            "please update.\n\n"
            "Your wallet and coins are safe. Install the latest version of ZClassic to open "
            "this wallet."));
        return;
    }

    // WALLET_CORRUPT: wallet.dat itself is genuinely damaged. Chain markers are
    // independent, so this NEVER triggers a chain re-download. -salvagewallet
    // rewrites wallet.dat, so relaunchForRepair() makes the mandatory read-only
    // backup FIRST (its built-in guard). Cap 1; failure points the user at the
    // backup. Match only genuine corruption strings — NOT the broad "Error loading
    // wallet.dat", which also covers the (now excluded above) DB_TOO_NEW case.
    if (diag.contains("Wallet corrupted", Qt::CaseInsensitive) ||
        diag.contains("salvage failed", Qt::CaseInsensitive)) {
        if (healAttempts("salvage") >= 1) {
            this->latchNeedsManual(QObject::tr("ZClassic couldn't repair your wallet file.\n\n"
                "A backup copy named wallet.dat.backup-… was saved next to it in your data "
                "folder. Please copy that file somewhere safe before doing anything else."));
            return;
        }
        bumpHealAttempt("salvage");
        setHealInProgress(true);
        this->relaunchForRepair(QStringList() << "-salvagewallet");
        return;
    }

    // ANCHOR_REJECTED: the daemon's bootstrap-snapshot verification failed. It has
    // ALREADY cleared its marker and removed only blocks/chainstate (wallet-safe)
    // before exiting, so the datadir is fresh-eligible again. We NEVER wipe the
    // datadir ourselves. First two recurrences: a plain relaunch (re-bootstrap).
    // Third: relaunch with -bootstrap=0 (normal P2P, never a stub loop). Beyond
    // that: NEEDS_MANUAL.
    if (diag.contains("bootstrap snapshot verification failed", Qt::CaseInsensitive)) {
        int n = healAttempts("anchorRelaunch");
        if (n >= 3) {
            this->latchNeedsManual(QObject::tr("ZClassic couldn't download a verified copy of the "
                "blockchain after several tries.\n\n"
                "Your wallet and coins are safe. Please check your internet connection and try "
                "again later, or use the Help menu to re-download the blockchain."));
            return;
        }
        bumpHealAttempt("anchorRelaunch");
        setHealInProgress(true);
        // Exponential backoff (3s, 9s, 27s) so a hard-broken anchor can't spin.
        int backoffMs = (n == 0) ? 3000 : (n == 1) ? 9000 : 27000;
        QStringList args;
        if (n >= 2)
            args << "-bootstrap=0";   // 3rd attempt: fall back to normal P2P sync
        main->logger->write(QString("ANCHOR_REJECTED heal: relaunch in %1 ms (attempt %2)%3")
            .arg(backoffMs).arg(n + 1)
            .arg(args.isEmpty() ? QString() : QStringLiteral(" with -bootstrap=0")));
        QTimer::singleShot(backoffMs, [=]() { this->relaunchForRepair(args); });
        return;
    }

    // C. If it looks like a corrupt / partway database, offer the staged repair.
    // Only offer once per run so a user who declines isn't trapped in a loop, and
    // cap repeated attempts across runs so a failing disk can't loop a heavy rebuild.
    if (!ezRepairOffered && looksLikeDbCorruption(diag)) {
        if (QSettings().value("repair/attempts", 0).toInt() >= 3) {
            this->showError(QObject::tr("ZClassic tried to repair its blockchain data several "
                "times but couldn't fix it, which can mean a failing disk.\n\n"
                "Your wallet and coins are safe (a backup copy of your wallet was saved next "
                "to it). You may want to copy your wallet file somewhere safe and have this "
                "computer's disk checked."));
            return;
        }
        ezRepairOffered = true;
        this->offerCorruptionRepair();
        return;
    }

    // G8: nothing matched a repairable cause. If we observed a low-disk CONTEXT
    // (<2GB free) earlier, surface that now as the most likely explanation — but only
    // here, AFTER the corruption/anchor classifiers had their chance, so a corrupt DB
    // on a fullish disk is never permanently mistaken for "just free up space".
    if (lowDiskContext) {
        this->showError(QObject::tr("ZClassic is running low on disk space.\n\n"
            "Please free up several gigabytes on this drive, then open ZClassic again. "
            "Your wallet and coins are safe."));
        return;
    }

    // Otherwise: the original generic, reassuring message.
    QString detail = ezclassicd ? ezclassicd->errorString() : QString();
    this->showError(QObject::tr("ZClassic couldn't finish starting up.\n\n"
        "This usually clears up on its own — please quit and open ZClassic again. "
        "If it keeps happening, make sure you have enough free disk space and a working "
        "internet connection.")
        % (detail.isEmpty() ? QString("") : QString("\n\n(") % detail % QString(")")));
}

// W4: does this text carry ANY marker the classifier in handleStartupFailure()
// recognizes? Used to decide whether THIS run's stderr alone is enough to classify
// (so a stale debug.log marker from a prior, already-recovered run can't misroute us).
// MUST stay in sync with the substrings matched by the branches of handleStartupFailure()
// plus the DB-corruption markers in looksLikeDbCorruption(). Case-insensitive.
bool ConnectionLoader::startupDiagHasMarker(const QString& text) {
    if (text.isEmpty())
        return false;
    static const char* markers[] = {
        // explicit/non-destructive signals
        "Disk space is low",
        "probably already running",
        "Cannot obtain a lock",
        // EXTRACT_FAILED (single-file build)
        "payload failed verification",
        "invalid embedded payload",
        "Can't find zclassicd",
        // DB_TOO_NEW
        "requires newer version",
        // WALLET_CORRUPT
        "Wallet corrupted",
        "salvage failed",
        // ANCHOR_REJECTED
        "bootstrap snapshot verification failed",
    };
    for (auto m : markers) {
        if (text.contains(QString::fromLatin1(m), Qt::CaseInsensitive))
            return true;
    }
    // Chain DB-corruption markers (kept in one place in looksLikeDbCorruption()).
    return looksLikeDbCorruption(text);
}

// B. CLASSIFY: scan captured stderr + debug.log tail for the daemon's known
// block/chainstate corruption markers (see src/init.cpp). Case-insensitive.
bool ConnectionLoader::looksLikeDbCorruption(const QString& text) {
    if (text.isEmpty())
        return false;

    static const char* markers[] = {
        "Corrupted block database detected",
        "Error opening block database",
        "Error loading block database",
        "Error initializing block database",   // cross-repo contract (daemon AbortNode)
        "Aborted block database rebuild",
        "Failed to read block",
        "System error while flushing",
        "Do you want to rebuild the block database now"
    };

    for (auto m : markers) {
        if (text.contains(QString::fromLatin1(m), Qt::CaseInsensitive))
            return true;
    }
    return false;
}

// The network data subdirectory: the datadir root for mainnet, or testnet3/ when
// that subdir actually holds the chain/wallet. We probe the filesystem rather than
// Settings::isTestnet() because isTestnet() is only set from the getinfo RPC reply,
// which never arrives when the node dies during startup.
QDir ConnectionLoader::resolveDataSubdir() {
    QDir root(ezDataDir);
    QDir testnet(QDir(ezDataDir).filePath("testnet3"));
    if (testnet.exists() &&
        (QFile::exists(testnet.filePath("wallet.dat")) ||
         QFile::exists(testnet.filePath("debug.log")) ||
         QDir(testnet.filePath("blocks")).exists()))
        return testnet;
    return root;
}

// RUNTIME STUB AUTO-HEAL discriminator: total bytes of the on-disk blocks/ store.
// Static + standalone (no live loader needed) so the runtime sync poller in RPC can
// call it cheaply with just the datadir root from the active connection's config. It
// reuses the SAME root-or-testnet3/ resolution as resolveDataSubdir() so it measures
// the chain the daemon is actually running. Returns -1 when the datadir/blocks dir is
// unknown or missing (caller MUST treat -1 as "don't know" and NEVER heal on it — a
// missing blocks/ here only means we couldn't measure, not that the chain is a stub).
// This is the primary, robust stub-vs-real-chain test: a fully-synced chain is ~10
// GiB; an aborted-P2P stub is tens of MB.
qint64 ConnectionLoader::blocksDirSizeBytes(const QString& datadirRoot) {
    if (datadirRoot.isEmpty())
        return -1;

    // Mirror resolveDataSubdir(): prefer testnet3/ when it actually holds the chain.
    QDir base(datadirRoot);
    QDir testnet(QDir(datadirRoot).filePath("testnet3"));
    if (testnet.exists() &&
        (QFile::exists(testnet.filePath("wallet.dat")) ||
         QFile::exists(testnet.filePath("debug.log")) ||
         QDir(testnet.filePath("blocks")).exists()))
        base = testnet;

    QDir blocks(base.filePath("blocks"));
    if (!blocks.exists())
        return -1;   // can't measure -> "unknown", never a heal trigger

    // Sum every regular file under blocks/ (blk*.dat, rev*.dat, index/, etc.).
    qint64 total = 0;
    QDirIterator it(blocks.absolutePath(), QDir::Files | QDir::NoSymLinks,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        total += it.fileInfo().size();
    }
    return total;
}

// Read the last maxBytes of <datadir>/debug.log, READ-ONLY. Returns "" if the
// datadir/log is unknown or unreadable. Never opens any file for writing.
QString ConnectionLoader::readDebugLogTail(int maxBytes) {
    if (ezDataDir.isEmpty())
        return QString();

    QString logPath = resolveDataSubdir().filePath("debug.log");

    QFile log(logPath);
    if (!log.exists() || !log.open(QIODevice::ReadOnly))
        return QString();

    qint64 sz = log.size();
    if (sz > maxBytes)
        log.seek(sz - maxBytes);
    QString tail = QString::fromUtf8(log.readAll());
    log.close();
    return tail;
}

// C. OFFER A SAFE, STAGED REPAIR LADDER (least to most invasive). The dialog is
// plain-language and reassures the user that their wallet/keys are untouched.
// Step 0 (wallet.dat backup) always runs first inside relaunchForRepair() before
// any repair flag is applied; if that backup fails, the repair is aborted.
void ConnectionLoader::offerCorruptionRepair() {
    main->logger->write("Offering staged corruption repair");

    QMessageBox box(main);
    box.setWindowTitle(QObject::tr("ZClassic needs a quick repair"));
    box.setIcon(QMessageBox::Warning);
    box.setText(QObject::tr("ZClassic couldn't open its blockchain files."));
    box.setTextFormat(Qt::RichText);
    box.setInformativeText(QObject::tr(
        "It looks like the downloaded blockchain data on this computer was left in a "
        "damaged or half-finished state (this can happen if the app or the computer "
        "shut down while it was still working).<br><br>"
        "<b>Your wallet and your coins are safe.</b> The blockchain data is just a local "
        "copy of the public network and can always be rebuilt. None of these options "
        "touch your wallet file or private keys — and ZClassic will make a backup copy "
        "of your wallet first, just to be sure.<br><br>"
        "How would you like to fix it? Start with the fast option; you can try the next "
        "one if it doesn't work.<br><br>") +
        QObject::tr("• Re-download — sets aside the local blockchain and downloads a fresh "
            "copy (largest, slowest)."));

    // Least-invasive first. AcceptRole/ActionRole keep them in a predictable order.
    QPushButton* fastBtn   = box.addButton(QObject::tr("Repair (fast)"),            QMessageBox::AcceptRole);
    QPushButton* rebuildBtn= box.addButton(QObject::tr("Rebuild index (slower)"),   QMessageBox::ActionRole);
    QPushButton* redownBtn = box.addButton(QObject::tr("Re-download blockchain"),   QMessageBox::ActionRole);
    box.addButton(QObject::tr("Not now"),                                           QMessageBox::RejectRole);
    box.setDefaultButton(fastBtn);

    box.exec();
    QAbstractButton* clicked = box.clickedButton();

    if (clicked == fastBtn) {
        // Step 1: rebuild ONLY the chainstate/UTXO set from the existing block files.
        this->relaunchForRepair(QStringList() << "-reindex-chainstate");
    } else if (clicked == rebuildBtn) {
        // Step 2: rebuild the block index too (from the blk files). Slower.
        this->relaunchForRepair(QStringList() << "-reindex");
    } else if (clicked == redownBtn) {
        // Step 3 (last resort): genuinely re-fetch. redownloadChain() sets the local
        // blocks/ and chainstate/ aside and starts the node normally, so it re-runs
        // its automatic bootstrap-snapshot flow. It NEVER touches wallet.dat.
        auto confirm = QMessageBox::question(main, QObject::tr("Re-download the blockchain?"),
            QObject::tr("This downloads a fresh copy of the blockchain and can take a while. "
                "It still does not touch your wallet or private keys.\n\nContinue?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (confirm == QMessageBox::Yes)
            this->redownloadChain();
    } else { // "Not now" or dialog closed
        if (ezManualRepair) {
            // MANUAL-REPAIR-BACKOUT FIX: this repair was opened by the user from a HEALTHY,
            // connected wallet (Help -> Repair), and launchBlockchainRepair() already stopped
            // the node before this dialog. "Not now" means the user changed their mind — so
            // bring the node back via the normal warmup/connect path instead of stranding them
            // on a false "couldn't finish starting up" error. ezAlive-guarded (the loader is not
            // a QObject); doAutoConnect restarts the embedded node and doRPCSetConnection frees
            // this loader on success.
            main->logger->write("Manual repair declined; relaunching the node the user backed out of");
            ezManualRepair = false;
            ezWarmupTimer.start();
            auto alive = ezAlive;
            QTimer::singleShot(0, [=]() { if (alive && *alive) doAutoConnect(); });
            return;
        }
        this->showError(QObject::tr("ZClassic couldn't finish starting up.\n\n"
            "You can open ZClassic again whenever you're ready, and choose a repair "
            "option then. Your wallet and coins are safe."));
    }
}

// NOTE (edit #5): the pre-attach foreign-daemon BLOCK that used to live here has been
// REMOVED. classifyForeignDaemon() now ALWAYS attaches to any daemon that answers getinfo
// (blocker #1: getbootstrapinfo presence is not a compatibility signal — a healthy
// released daemon lacks it). The actionable, persistent, retryable dialog for a foreign
// node that is genuinely STUCK (peerless / not syncing) has been relocated to
// MainWindow::showForeignNodeStuck(), because the trigger now lives in the RUNTIME sync
// poller (src/rpc.cpp), which has only a MainWindow* — not a live ConnectionLoader — and
// has the actual-health signal (sustained peerless) the attach-time decision lacked.

// Step 0 + relaunch. ALWAYS back up wallet.dat (read+copy) first; only if that
// succeeds do we apply the one-shot repair flag and relaunch the node ONCE.
// The flag is passed only to this next start and is never written to zclassic.conf.
void ConnectionLoader::relaunchForRepair(const QStringList& extraArgs) {
    // SAFETY GATE: a repair relaunch (-reindex / -reindex-chainstate rewrites the
    // chain DB; -salvagewallet rewrites wallet.dat) must never run alongside a live
    // daemon on the same datadir. Positively confirm the node is dead; if we can't,
    // ABORT untouched and roll back the serialize guard so a later run can retry.
    if (!this->confirmDaemonDeadForRepair()) {
        main->logger->write("relaunchForRepair: daemon not confirmed stopped; aborting");
        this->setHealInProgress(false);
        this->showError(QObject::tr("Please fully quit ZClassic first.\n\n"
            "The repair couldn't run because the ZClassic node is still running. Your "
            "wallet, coins, and blockchain data have not been changed."));
        return;
    }

    // GUARD RAIL: never proceed to a repair without a fresh wallet.dat backup.
    if (!backupWalletForRepair()) {
        // Roll back the serialize guard so the user (or a later run) can retry.
        this->setHealInProgress(false);
        this->showError(QObject::tr("ZClassic couldn't make a safety backup of your wallet, "
            "so the repair was stopped.\n\n"
            "Your wallet and coins have not been changed. Please make sure you have free "
            "disk space and try again."));
        return;
    }

    // Count this repair attempt (persisted per install) so handleStartupFailure
    // can stop escalating after a few failures instead of looping a heavy rebuild.
    QSettings().setValue("repair/attempts", QSettings().value("repair/attempts", 0).toInt() + 1);

    main->logger->write("Relaunching embedded node for repair with args: " + extraArgs.join(" "));

    // Drop the dead QProcess so startEmbeddedZClassicd() creates a fresh one with
    // the one-shot repair flag. We never reuse or relaunch the old process object.
    if (ezclassicd) {
        ezclassicd->deleteLater();
        ezclassicd = nullptr;
    }
    ezNodeQuitDuringStartup = false;
    ezStdErr.clear();

    // W1(a): a repair relaunch (-reindex / -reindex-chainstate) is EXPECTED to dwell on
    // a percent-less "Verifying blocks..." / "Activating best chain..." far longer than
    // the watchdog's 180s no-progress threshold. Disable the WARMUP_WEDGED watchdog for
    // this run so it can't kill the repair it just launched. Cleared on a clean RPC.
    this->ezRepairRelaunchActive = true;

    this->showInformation(QObject::tr("Repairing your blockchain data…"),
        QObject::tr("This can take several minutes. Your wallet is safe."));

    if (!this->startEmbeddedZClassicd(extraArgs)) {
        this->setHealInProgress(false);   // relaunch never armed -> release the guard
        this->showError(QObject::tr("ZClassic couldn't start the repair.\n\n"
            "Please open ZClassic again. Your wallet and coins are safe."));
        return;
    }

    // The relaunch is armed: clear the serialize guard so the NEXT death (if the
    // repair itself fails) can classify+heal again, bounded by the per-edge ledger.
    this->setHealInProgress(false);

    // Re-arm the warmup window and resume the normal patient polling loop, which
    // will now connect once the reindex completes (or, if it fails again, fall
    // back through handleStartupFailure() — but ezRepairOffered is already set, so
    // the user gets the plain error instead of an endless repair loop).
    ezWarmupTimer.start();
    QTimer::singleShot(1000, [=]() { doAutoConnect(); });
}

// A GENUINE re-download (unlike -reindex, which rebuilds from the same possibly
// corrupt local blk files): set the local blocks/ and chainstate/ aside into ONE
// timestamped parent dir, then start the node normally so that — seeing an empty
// datadir — it re-runs its automatic bootstrap-snapshot flow and fetches a fresh
// chain. (Verified: the shipped daemon auto-bootstraps on an empty/eligible datadir
// with NO flag — -bootstrap defaults to true and -bootstrapmode defaults to
// "anchor" — so a plain start is correct here.) The move is rollback-safe: if any
// directory fails to move, every prior move is undone and the datadir is left
// exactly as found. Disk growth from the set-aside copy is bounded to ONE
// generation: a prior set-aside dir is swept before this one is created, so a
// repeated re-download never accumulates. The single "chain-set-aside-*" parent
// stays in the datadir (renaming within it is instant and recoverable); the user
// can delete it later to reclaim disk space, and the next re-download sweeps it.
//
// This only ever runs from offerCorruptionRepair <- handleStartupFailure, i.e. the
// node process is ALREADY DEAD, so there are no open file handles on these dirs.
void ConnectionLoader::redownloadChain() {
    main->logger->write("redownloadChain: wiping local chain data for fresh re-download");

    // SAFETY GATE: never move blocks/chainstate while a daemon could still hold them
    // open. Positively confirm the node is dead first; if we can't, ABORT untouched.
    if (!this->confirmDaemonDeadForRepair()) {
        main->logger->write("redownloadChain: daemon not confirmed stopped; aborting");
        this->showError(QObject::tr("Please fully quit ZClassic first.\n\n"
            "The blockchain couldn't be re-downloaded because the ZClassic node is still "
            "running. Your wallet, coins, and blockchain data have not been changed."));
        return;
    }

    // Step 0: always make a fresh wallet.dat safety backup first.
    if (!this->backupWalletForRepair()) {
        this->showError(QObject::tr("ZClassic couldn't make a safety backup of your wallet, "
            "so the re-download was stopped.\n\n"
            "Your wallet and coins have not been changed. Please make sure you have free "
            "disk space and try again."));
        return;
    }

    QDir dd = resolveDataSubdir();
    QString stamp = QDateTime::currentDateTime().toString("yyyyMMdd-hhmmss");

    // Bound disk growth to one generation: sweep any set-aside dirs left over from a
    // previous re-download before creating this one. (The node is dead, so nothing
    // holds these.) Doing this first also reclaims that space ahead of the disk check.
    for (const QString& entry : dd.entryList(QStringList() << "chain-set-aside-*",
                                             QDir::Dirs | QDir::NoDotAndDotDot)) {
        QDir(dd.filePath(entry)).removeRecursively();
    }

    // A re-download fetches a FRESH full chain that must briefly coexist on disk with
    // the set-aside old copy (the set-aside is just a rename, so it keeps occupying
    // its original space). On the near-full disk that often CAUSED the corruption,
    // this would fail partway and strand the user with no chain. Require a generous
    // floor up front and bail with a clear message rather than half-finishing. The
    // generic ensureEnoughDiskSpace() (~3 GB) is far too low for a full chain.
    {
        QStorageInfo storage(dd.absolutePath());
        const qint64 needed = (qint64)15 * 1024 * 1024 * 1024;   // ~15 GB headroom for a fresh chain
        if (storage.isValid() && storage.isReady() && storage.bytesAvailable() < needed) {
            QString human = QString::number(storage.bytesAvailable() / 1024.0 / 1024.0 / 1024.0, 'f', 1);
            main->logger->write(QString("redownloadChain: insufficient disk for re-download (%1 GB free)").arg(human));
            this->showError(QObject::tr("There isn't enough free disk space to download a fresh "
                "copy of the blockchain.\n\n"
                "About 15 GB free is needed, but only %1 GB is available. Please free up some "
                "space and open ZClassic again. Your wallet and coins are safe, and your existing "
                "blockchain data has not been changed.").arg(human));
            return;
        }
    }

    // Set aside blocks/ and chainstate/ into ONE parent rather than deleting them, so
    // the move is instant and fully recoverable. If any rename fails, roll back every
    // move already done and remove the parent, leaving the datadir exactly as found.
    QString aside = "chain-set-aside-" + stamp;
    dd.mkpath(aside);

    QStringList moved;   // names successfully moved INTO 'aside', for rollback
    bool moveFailed = false;
    for (const QString& name : { QStringLiteral("blocks"), QStringLiteral("chainstate") }) {
        if (dd.exists(name)) {
            if (!dd.rename(name, aside + "/" + name)) {
                moveFailed = true;
                break;
            }
            moved << name;
        }
    }
    if (moveFailed) {
        main->logger->write("redownloadChain: a set-aside move failed; rolling back");
        // Undo every move already done, then drop the (now-partial) parent.
        for (const QString& done : moved)
            dd.rename(aside + "/" + done, done);
        QDir(dd.filePath(aside)).removeRecursively();
        this->showError(QObject::tr("ZClassic couldn't move the old blockchain data aside.\n\n"
            "Please make sure you have free disk space and that no other copy of "
            "ZClassic is running, then try again. Your wallet and coins are safe."));
        return;
    }

    // Count this repair attempt (persisted per install), matching relaunchForRepair.
    QSettings().setValue("repair/attempts", QSettings().value("repair/attempts", 0).toInt() + 1);

    // Drop the dead QProcess so a fresh one is created with no repair flags.
    if (ezclassicd) {
        ezclassicd->deleteLater();
        ezclassicd = nullptr;
    }
    ezNodeQuitDuringStartup = false;
    ezStdErr.clear();

    // W1(a): the post-redownload fresh start re-fetches and then re-validates a whole
    // chain, sitting for a long time on percent-less verify/activate phases. Disable the
    // WARMUP_WEDGED watchdog for this run so it can't kill the fresh start. Cleared on a
    // clean RPC.
    this->ezRepairRelaunchActive = true;

    this->showInformation(QObject::tr("Re-downloading your blockchain data…"),
        QObject::tr("This downloads a fresh copy and can take a while. Your wallet is safe."));

    // Normal start (no extra args): the empty datadir triggers the daemon's own
    // bootstrap-snapshot flow. If the relaunch fails the old chain data is still
    // intact under the set-aside folder, so tell the user where it is.
    if (!this->startEmbeddedZClassicd()) {
        this->showError(QObject::tr("ZClassic couldn't start the re-download.\n\n"
            "Please open ZClassic again — it will download a fresh copy then. "
            "Your wallet and coins are safe, and your previous blockchain data was "
            "kept in a folder named \"%1\" inside the data directory.").arg(aside));
        return;
    }

    ezWarmupTimer.start();
    QTimer::singleShot(1000, [=]() { doAutoConnect(); });
}

// HARD INVARIANT enforcement: this is the ONLY code in the failsafe that touches
// wallet.dat, and it only ever READS it (QFile::copy opens the source read-only)
// to a timestamped backup beside it. It never deletes, renames, or opens
// wallet.dat for writing. Returns true on a verified successful copy.
bool ConnectionLoader::backupWalletForRepair() {
    if (ezDataDir.isEmpty()) {
        main->logger->write("Repair backup: datadir unknown, cannot locate wallet.dat");
        return false;
    }

    QDir dir = resolveDataSubdir();

    QFile wallet(dir.filePath("wallet.dat"));
    if (!wallet.exists()) {
        // No wallet.dat means there is nothing to protect (e.g. a brand-new datadir
        // that never finished its first run). Safe to proceed with the repair.
        main->logger->write("Repair backup: no wallet.dat present; nothing to back up");
        return true;
    }

    // Make sure we have room for the copy before attempting it.
    if (!ensureEnoughDiskSpace(dir.absolutePath()))
        return false;

    QString stamp = QDateTime::currentDateTime().toString("yyyyMMdd-hhmmss");
    QString backupPath = dir.filePath("wallet.dat.backup-" + stamp);

    // Don't clobber an existing backup of the same second (extremely unlikely).
    if (QFile::exists(backupPath)) {
        main->logger->write("Repair backup: target already exists, aborting to avoid overwrite");
        return false;
    }

    if (!wallet.copy(backupPath)) {
        main->logger->write("Repair backup: copy failed: " + wallet.errorString());
        return false;
    }

    main->logger->write("Repair backup: wallet.dat copied to " + backupPath);
    return true;
}

// ==================== SELF-HEAL ledger + edges (A-side) ====================

// Per-edge bounded retry counters, persisted so they survive relaunches/crashes.
// "N" always means "N consecutive failures WITHOUT a recovery in between" — a
// single successful getinfo wipes the whole ledger (clearHealLedger, called from
// doRPCSetConnection).
int ConnectionLoader::healAttempts(const QString& edge) {
    return QSettings().value("heal/attempts." + edge, 0).toInt();
}

void ConnectionLoader::bumpHealAttempt(const QString& edge) {
    QSettings s;
    s.setValue("heal/attempts." + edge, s.value("heal/attempts." + edge, 0).toInt() + 1);
}

// Global serialize guard: two destructive heals can NEVER overlap. Set before a
// destructive heal is begun; cleared once its relaunch is armed (or rolled back).
bool ConnectionLoader::healInProgress() {
    return QSettings().value("heal/inProgress", false).toBool();
}

void ConnectionLoader::setHealInProgress(bool on) {
    QSettings().setValue("heal/inProgress", on);
}

// SAFETY GATE: positively confirm NO embedded daemon is alive before a destructive
// heal mutates the datadir. There are two owners across the heal lifetime:
//   - startup-failure path: THIS loader owns ezclassicd (already exited, but we
//     terminate()/kill() + poll to be certain there is no zombie holding LevelDB);
//   - manual Help->Repair path: this loader is fresh (ezclassicd==nullptr) and the
//     live node is owned by RPC, which mainwindow stopped first — re-confirm via
//     rpc->confirmEmbeddedStopped() (which itself escalates terminate->kill).
// Returns false if a live daemon can't be confirmed dead; the caller then ABORTS
// the repair, leaving the datadir untouched, and tells the user to fully quit.
bool ConnectionLoader::confirmDaemonDeadForRepair() {
    if (ezclassicd != nullptr) {
        if (ezclassicd->state() != QProcess::NotRunning && ezclassicd->processId() != 0) {
            ezclassicd->terminate();
            ezclassicd->waitForFinished(5000);
            if (ezclassicd->state() != QProcess::NotRunning) {
                ezclassicd->kill();
                ezclassicd->waitForFinished(5000);
            }
        }
        return ezclassicd->state() == QProcess::NotRunning || ezclassicd->processId() == 0;
    }

    // No process owned by THIS loader. Defer to RPC for the EMBEDDED node it owns.
    // CORRECTION (blocker #3): rpc->confirmEmbeddedStopped() returns TRUE for a
    // not-owned daemon (rpc->ezclassicd == nullptr) WITHOUT stopping anything — so for a
    // FOREIGN daemon (one we did NOT launch: ezclassicd==nullptr and/or an external
    // -zclassicDaemon connection) it would green-light renaming blocks/chainstate under a
    // LIVE foreign node and double-launch onto its held ports. NEVER set a not-owned
    // daemon's blockchain files aside. When we do not own the node, additionally require
    // the RPC+P2P ports to be ACTUALLY unbound before declaring it safe; if the foreign
    // node still holds them, return false so the repair aborts with the existing
    // "please fully quit ZClassic first" message.
    bool ownEmbedded = (rpc != nullptr && rpc->isEmbedded());
    Connection* active = (rpc != nullptr) ? rpc->getConnection() : nullptr;
    bool externalDaemon = (active != nullptr && active->config && active->config->zclassicDaemon);
    if (!ownEmbedded || externalDaemon) {
        std::shared_ptr<ConnectionConfig> cfg =
            (active != nullptr) ? active->config : nullptr;
        if (!this->portsFree(cfg)) {
            main->logger->write("confirmDaemonDeadForRepair: foreign/not-owned node still "
                                 "holds the ports; refusing to mutate its datadir");
            return false;
        }
        // Ports are free -> nothing we don't own is alive on them. Safe to proceed.
        return true;
    }

    // We own a live embedded node (manual path): defer to RPC to stop+confirm it.
    return rpc == nullptr || rpc->confirmEmbeddedStopped();
}

// G7: true when the cached getbootstrapinfo poll says the daemon is legitimately
// busy with the bootstrap download or the multi-minute post-bootstrap UTXO verify,
// so a frozen, percent-less warmup string is EXPECTED and the WARMUP_WEDGED watchdog
// must NOT fire (it would kill a healthy node and discard a finished download).
bool ConnectionLoader::bootstrapSuppressesWedge() const {
    if (ezBootstrapPhase == QStringLiteral("active") ||
        ezBootstrapPhase == QStringLiteral("succeeded"))
        return true;
    if (ezBootstrapVerifyPending)
        return true;
    if (ezBootstrapValidationState.startsWith(QStringLiteral("provisional")))
        return true;
    return false;
}

// W1(b): a normal (non-repair) start can also legitimately sit for a long time on a
// percent-less warmup phase — verifying blocks, activating the best chain, rewinding,
// (re)loading the block index, pruning, rescanning, zapping wallet txes, upgrading the
// chainstate. None of these emit a percent, so the no-progress timer would trip even
// though the node is healthy. Suppress the watchdog whenever the -28 status matches any
// of these (case-insensitive substring); only fire when stuck on NONE of them AND no
// bootstrap activity. The daemon emits these as e.g. "Verifying blocks..." / "Activating
// best chain..." / "Loading block index..." (ThreadSafeMessageBox init messages).
bool ConnectionLoader::isLongWarmupPhase(const QString& status) {
    static const char* kPhases[] = {
        "Verifying blocks",
        "Activating best chain",
        "Rewinding",
        "Loading block index",
        "Pruning blockstore",
        "Rescanning",
        "Zapping",
        "Upgrading",
    };
    for (const char* p : kPhases) {
        if (status.contains(QLatin1String(p), Qt::CaseInsensitive))
            return true;
    }
    return false;
}

// Terminal "needs manual action": stop ALL auto-heal for the rest of this run, but
// keep the manual Help -> Repair button reachable. Show the reason once.
void ConnectionLoader::latchNeedsManual(const QString& reason) {
    QSettings s;
    s.setValue("heal/manualOnly", true);
    s.setValue("heal/state", "NEEDS_MANUAL");
    s.setValue("heal/inProgress", false);
    main->logger->write("Self-heal latched NEEDS_MANUAL");
    this->showError(reason);
}

// A clean getinfo resets MOST of the ledger to a fresh slate (called from
// doRPCSetConnection alongside the existing repair/attempts clear). Static so it
// is reachable without a live ConnectionLoader instance.
//
// G6: it deliberately does NOT clear heal/attempts.warmupRestart. The warmup-wedge
// cap exists to escalate an OSCILLATING node (one that answers a single getinfo,
// then re-wedges) to NEEDS_MANUAL. Clearing it on the first getinfo would let such a
// node reset the counter forever and never escalate. warmupRestart is cleared only
// after SUSTAINED health is confirmed (RPC::getInfoThenRefresh, several consecutive
// healthy polls / a tip that has advanced past warmup).
void ConnectionLoader::clearHealLedger() {
    QSettings s;
    s.remove("heal/inProgress");
    s.remove("heal/manualOnly");
    s.remove("heal/state");
    s.remove("heal/attempts.salvage");
    s.remove("heal/attempts.anchorRelaunch");
    s.remove("heal/attempts.extractRetry");
    // AUTH_RESTART: a one-time cookie-migration/desync glitch must NOT permanently latch
    // NEEDS_MANUAL. Clearing it on a clean getinfo lets a future, unrelated desync (very
    // unlikely with cookie auth) self-heal again. Contrast warmupRestart, deliberately
    // kept above to escalate an OSCILLATING node.
    s.remove("heal/attempts.authRestart");
    // NOTE: heal/attempts.warmupRestart is intentionally NOT removed here (see above).
}

// EXTRACT_FAILED edge (single-file build): delete the cached daemon stamp dir + any
// .part and re-extract ONCE. Content-addressed + SHA-256 gated, so a genuine bundle
// mismatch fails again and latches NEEDS_MANUAL ("reinstall the app"). Never routes
// through the corruption ladder.
void ConnectionLoader::retryExtractionOnce(const QString& diag) {
    Q_UNUSED(diag);
    if (healAttempts("extractRetry") >= 1) {
        this->latchNeedsManual(QObject::tr("ZClassic couldn't start its node, and trying again "
            "didn't help.\n\n"
            "The app's program files may be damaged. Please reinstall ZClassic. "
            "Your wallet and coins are safe."));
        return;
    }
    bumpHealAttempt("extractRetry");
    setHealInProgress(true);

    // Sweep the content-addressed extracted-daemon cache so ensureDaemonExtracted()
    // re-runs its verified (SHA-256-gated) extraction from scratch. This is the SAME
    // dir ensureDaemonExtracted() writes to (<CacheLocation>/zclassic-node); we remove
    // only our own extracted-daemon dir, never anything else.
    QDir cacheRoot(QStandardPaths::writableLocation(QStandardPaths::CacheLocation));
    QDir cache(cacheRoot.filePath("zclassic-node"));
    if (cache.exists())
        cache.removeRecursively();

    // Drop the dead process object so startEmbeddedZClassicd() re-extracts + relaunches.
    if (ezclassicd) {
        ezclassicd->deleteLater();
        ezclassicd = nullptr;
    }
    ezNodeQuitDuringStartup = false;
    ezStdErr.clear();

    // Backoff so a hard-broken bundle can't spin a re-extract loop.
    main->logger->write("EXTRACT_FAILED heal: re-extracting bundled daemon once");
    QTimer::singleShot(3000, [=]() {
        if (!this->startEmbeddedZClassicd()) {
            this->latchNeedsManual(QObject::tr("ZClassic couldn't start its node.\n\n"
                "The app's program files may be damaged. Please reinstall ZClassic. "
                "Your wallet and coins are safe."));
            return;
        }
        this->setHealInProgress(false);   // relaunch armed
        ezWarmupTimer.start();
        QTimer::singleShot(1000, [=]() { doAutoConnect(); });
    });
}

// WARMUP_WEDGED watchdog (A-side). Offers a CLEAN restart (NOT a heal): the node is
// alive but its -28 warmup status + percent have not advanced for a long stretch and
// it is NOT in an active bootstrap-snapshot download. The daemon resumes from its
// persisted index, so this never throws away chain data. Capped; a restart that dies
// with a corruption marker re-routes through handleStartupFailure -> DB_CORRUPT.
void ConnectionLoader::handleWarmupWedged() {
    if (healInProgress())
        return;
    if (healAttempts("warmupRestart") >= 2) {
        this->latchNeedsManual(QObject::tr("ZClassic's node seems stuck starting up.\n\n"
            "Please quit and open ZClassic again. If it keeps happening, you can repair the "
            "blockchain from the Help menu. Your wallet and coins are safe."));
        return;
    }
    bumpHealAttempt("warmupRestart");
    setHealInProgress(true);
    main->logger->write("WARMUP_WEDGED heal: clean restart of a wedged warmup");

    // Try a polite RPC stop first (the node answers getinfo with -28, but 'stop' is
    // accepted during warmup); fall back to terminate(). Either way we then relaunch
    // with no flags so it resumes from its persisted index.
    if (ezclassicd && ezclassicd->state() != QProcess::NotRunning) {
        ezclassicd->terminate();
        ezclassicd->waitForFinished(5000);
        if (ezclassicd->state() != QProcess::NotRunning)
            ezclassicd->kill();
    }
    if (ezclassicd) {
        ezclassicd->deleteLater();
        ezclassicd = nullptr;
    }
    ezNodeQuitDuringStartup = false;
    ezStdErr.clear();
    ezLastWarmupStatus.clear();
    ezLastWarmupPct = -1;
    ezWarmupNoProgress.invalidate();

    if (!this->startEmbeddedZClassicd()) {
        this->setHealInProgress(false);
        this->showError(QObject::tr("ZClassic couldn't restart its node.\n\n"
            "Please open ZClassic again. Your wallet and coins are safe."));
        return;
    }
    this->setHealInProgress(false);   // relaunch armed
    ezWarmupTimer.start();
    QTimer::singleShot(1000, [=]() { doAutoConnect(); });
}

// MANUAL OVERRIDE: invoked from MainWindow's always-reachable Help -> "Repair /
// Re-download blockchain…" action AFTER the running node has been stopped. Reuses
// the EXACT same staged ladder as the startup classifier. Available even after
// auto-heal has latched NEEDS_MANUAL — this is the user's escape hatch. Picking an
// option here is an explicit user choice, so it clears manualOnly and starts fresh.
void ConnectionLoader::startManualRepair() {
    QSettings().setValue("heal/manualOnly", false);
    QSettings().setValue("heal/inProgress", false);
    // Mark this as the user-initiated repair entry so "Not now" relaunches the (healthy,
    // just-stopped) node instead of showing the false startup-failure dead-end.
    ezManualRepair = true;

    // The datadir is needed to back up wallet.dat + set chain data aside. Recover it
    // the same way doAutoConnect does, since this loader is created cold.
    if (ezDataDir.isEmpty()) {
        auto config = autoDetectZClassicConf();
        if (config && !config->zclassicDir.isEmpty())
            ezDataDir = config->zclassicDir;
    }

    d->show();
    this->offerCorruptionRepair();
}

void ConnectionLoader::doManualConnect() {
    auto config = loadFromSettings();

    if (!config) {
        // Nothing configured, show an error
        QString explanation = QString()
                % QObject::tr("A manual connection was requested, but the settings are not configured.\n\n"
                "Please set the host/port and user/password in the Edit->Settings menu.");

        showError(explanation);
        doRPCSetConnection(nullptr);

        return;
    }

    auto connection = makeConnection(config);
    refreshZClassicdState(connection, [=] () {
        QString explanation = QString()
                % QObject::tr("ZClassic couldn't connect to the node in your settings.\n\n" 
                "Please check the address and sign-in details under Edit → Settings.");

        showError(explanation);
        doRPCSetConnection(nullptr);

        return;
    });
}

void ConnectionLoader::doRPCSetConnection(Connection* conn) {
    // The RPC connection is now live: the node is genuinely up, so end the warmup
    // window. After this, a QProcess 'finished' signal is a normal shutdown, not a
    // startup quit, and must NOT trigger the corruption failsafe.
    // Startup profiling: log how long from node launch to first live RPC, so the
    // warmup cost (block-index + chainstate load + checkblocks verify) is visible.
    if (ezWarmupTimer.isValid())
        main->logger->write(QString("Startup: node RPC online %1 ms after launch")
                                .arg(ezWarmupTimer.elapsed()));
    // [gui-startup] RPC is live: the node answered getinfo and we are attached. This
    // is the universal "attached" instant for both the owned-daemon and the
    // foreign/already-running-node paths. First-write-wins.
    GuiStartup::markFirstGetInfo();
    ezWarmupTimer.invalidate();
    ezNodeQuitDuringStartup = false;
    // W1: the node is genuinely up; clear the repair-relaunch suppression so the
    // watchdog is re-armed for any future run. (This loader is deleted below anyway,
    // but keep the invariant explicit.)
    ezRepairRelaunchActive = false;

    // This ConnectionLoader is about to be deleted (delete this, below), but its
    // lambdas are still connected to ezclassicd's finished/errorOccurred/readyRead
    // signals. Disconnect them so a later signal (a normal shutdown or a runtime
    // crash) can't call into freed memory. rpc, which takes ownership next, only
    // polls the process and connects no signals of its own.
    if (ezclassicd)
        QObject::disconnect(ezclassicd, nullptr, nullptr, nullptr);

    // Successful startup: clear the persistent repair-attempt counter AND the whole
    // self-heal ledger — a clean getinfo proves the node is genuinely healthy, so
    // every per-edge cap and the manualOnly latch reset to a fresh slate.
    QSettings().setValue("repair/attempts", 0);
    ConnectionLoader::clearHealLedger();

    rpc->setEZClassicd(ezclassicd);
    rpc->setConnection(conn);

    // Build/traceability sentinel (also a delivery-gate marker string): proves this
    // binary carries the UAF-safe deferred-teardown fix below.
    if (main && main->logger)
        main->logger->write("connect ok: UAF-safe deferred connect-dialog teardown");

    // ROOT-CAUSE FIX (reentrant use-after-free of the LIVE modal connect dialog).
    // doRPCSetConnection runs INSIDE d->exec()'s nested event loop: loadConnection()
    // calls d->exec() (connection.cpp:84) and the async getinfo reply that lands here
    // is dispatched while that loop is still on the call stack below us. The old code
    // did d->accept() then `delete this`, whose ~ConnectionLoader does `delete d`
    // (connection.cpp:77) -- destroying the QDialog whose exec() is STILL running on
    // the stack. As the slot returns and control unwinds back into the freed
    // QDialog::exec()/QDialogPrivate frame, it touches freed modal-window-stack /
    // event-loop bookkeeping. On a FAST connect (a daemon answers getinfo on the
    // first probe, before the main window w has actually been mapped/painted by the
    // X server) that corrupted unwind makes QApplication::exec() RETURN -> the GUI
    // silently exits right after "Payment UI now ready!", preceded by the benign ~6
    // QBasicTimer teardown warnings and with NO SIGSEGV. The slow path survives only
    // because w is already mapped by the time getinfo succeeds; the offscreen QPA
    // platform never reproduces it (no xcb modal/input-grab machinery to corrupt).
    // This is why setQuitOnLastWindowClosed(false) did not fix it: the exit is
    // exec() returning, not last-window-closed.
    //
    // Fix: close the modal loop with done(), then DEFER destroying BOTH the dialog
    // and this loader until d->exec() has fully unwound and we are back in the main
    // event loop. Null d first so ~ConnectionLoader's `delete d` becomes a safe no-op.
    //
    // W1-1: in the NON-MODAL startup mode this slot is dispatched directly in the MAIN
    // event loop (the splash was d->show()n modeless, never d->exec()'d), so there is
    // no nested exec() frame to corrupt — done(Accepted) just hides+finishes the
    // modeless dialog. The SAME deferred ordering is kept verbatim for both modes: it
    // is the single place the loader is freed, so the ezAlive-guarded poll/probe
    // lambdas can never deref a freed member, and the modeless-dismiss rejected()
    // handler never frees anything.
    if (d) {
        QDialog* dlg = d;
        d = nullptr;                       // ~ConnectionLoader must not double-free it
        dlg->done(QDialog::Accepted);      // unwinds the nested d->exec() cleanly (modal) / hides+finishes (modeless)
        dlg->deleteLater();                // freed only once back in the main loop
    }

    // NEVER-STRAND: explicitly re-show/raise the main window so the user ALWAYS sees
    // an actionable window the moment the connect dialog goes away -- not a dependency
    // on whatever mapping state w reached under XWayland. Idempotent UI-only calls.
    if (main) {
        main->show();
        main->raise();
        main->activateWindow();
    }

    // Defer self-destruction OUT of the nested d->exec() loop too. 'main' is the
    // QObject context, so the delete is cancelled if the app is torn down first.
    QTimer::singleShot(0, main, [this]() { delete this; });
}

Connection* ConnectionLoader::makeConnection(std::shared_ptr<ConnectionConfig> config) {
    QNetworkAccessManager* client = new QNetworkAccessManager(main);
         
    QUrl myurl;
    myurl.setScheme("http");
    myurl.setHost(config.get()->host);
    myurl.setPort(config.get()->port.toInt());

    QNetworkRequest* request = new QNetworkRequest();
    request->setUrl(myurl);
    request->setHeader(QNetworkRequest::ContentTypeHeader, "text/plain");
    
    QString userpass = config.get()->rpcuser % ":" % config.get()->rpcpassword;
    QString headerData = "Basic " + userpass.toLocal8Bit().toBase64();
    request->setRawHeader("Authorization", headerData.toLocal8Bit());    

    return new Connection(main, client, request, config);
}

void ConnectionLoader::refreshZClassicdState(Connection* connection, std::function<void(void)> refused) {
    // Retired-loader guard (see doAutoConnect): bail before touching torn-down state
    // if the user has quit during the startup splash or the loader is gone.
    if (!ezAlive || !*ezAlive)
        return;

    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "getinfo"}
    };
    connection->doRPC(payload,
        [=] (auto) {
            // getinfo SUCCEEDED -> the node is genuinely up. Reset the unexpected-error
            // poll counter (edit #2): any transient/odd reply streak is cleared by a
            // single healthy getinfo.
            ezUnexpectedErrPolls = 0;
            // Branch on OWNERSHIP before attaching:
            //   ezclassicd != nullptr  <=>  this is OUR embedded node coming online.
            //   ezclassicd == nullptr  <=>  a daemon we did NOT launch is on the port.
            if (ezclassicd != nullptr) {
                // Our embedded node -> compatible by construction (we launched the
                // bundled binary). Attach exactly as before; no getbootstrapinfo probe
                // and no extra round-trip on the common cold start.
                d->hide();
                main->logger->write("zclassicd is online.");
                this->doRPCSetConnection(connection);
                return;
            }
            // PRE-EXISTING/FOREIGN daemon on the port (a daemon we did NOT launch). It
            // answers getinfo, so it is alive — ATTACH. classifyForeignDaemon runs the
            // getbootstrapinfo probe ONLY to refresh the advisory warmup-progress flag;
            // it attaches on BOTH callbacks (never blocks). A genuinely stuck/peerless
            // foreign node is handled at runtime by the sync poller.
            this->classifyForeignDaemon(connection);
        },
        [=] (auto reply, auto res) {            
            // Failed, see what it is. 
            auto err = reply->error();
            //qDebug() << err << ":" << QString::fromStdString(res.dump());

            if (err == QNetworkReply::NetworkError::ConnectionRefusedError) {   
                refused();
            } else if (err == QNetworkReply::NetworkError::AuthenticationRequiredError) {
                // 401. NEVER log the credential — only that auth failed (CONF-3).
                main->logger->write("Authentication failed");

                // OWNERSHIP + EMBEDDED gate (mirrors the getinfo-SUCCESS lambda above,
                // which branches on ezclassicd != nullptr). The 401 ERROR path used to
                // dead-end identically for owned and foreign nodes — that asymmetry was
                // the bug. For OUR embedded node a 401 is a recoverable cookie/cred
                // desync (a hand-edited/partial-write conf the proactive cookie
                // migration couldn't reach, or a cookie not yet rewritten): heal it with
                // a single bounded cookie-only restart. With cookie auth in place this
                // branch is rarely reached at all; it is belt-and-suspenders.
                if (Settings::getInstance()->useEmbedded() && ezclassicd != nullptr) {
                    if (this->handleEmbeddedAuthFailure())
                        return;   // heal started/escalated — do NOT fall through to showError
                }

                // EXTERNAL / FOREIGN node (useEmbedded()==false or a daemon we did not
                // launch): we must NEVER restart or rewrite it. Route to a friendly
                // fallback dialog (it branches conf-vs-Settings internally so it is never
                // a dead end) instead of the bare critical box.
                main->logger->write("Authentication failed against an external/foreign node; offering a fix");
                d->hide();
                rpc->setEZClassicd(nullptr);
                rpc->noConnection();
                if (main) { main->show(); main->raise(); main->activateWindow(); }
                ezProgrammaticClose = true;
                d->close();
                ezProgrammaticClose = false;
                if (main) main->showExternalNodeAuthFailed();
            } else if (err == QNetworkReply::NetworkError::InternalServerError && 
                    !res.is_discarded()) {
                // The server is loading, so just poll until it succeeds
                QString status      = QString::fromStdString(res["error"]["message"]);

                // During the bootstrap snapshot download the daemon publishes its
                // progress as the warmup status, e.g.:
                //   "Bootstrap snapshot:  42%  4.10 / 9.80 GB  210.5 MB/s  (8 streams)"
                // Drive the real 0-100 bar off that percent. The "Bootstrap snapshot:"
                // prefix MUST stay in sync with the strprintf() at the snapshot-download
                // emit sites in daemon src/bootstrap.cpp.
                static const QRegularExpression reBootstrapPct(
                    QStringLiteral("Bootstrap snapshot:\\s*(\\d+)%"));
                QRegularExpressionMatch mPct = reBootstrapPct.match(status);

                // SELF-HEAL WARMUP_WEDGED watchdog: track whether the warmup status
                // string and parsed percent are ADVANCING. Reset the no-progress
                // timer whenever either changes; only consider firing when nothing
                // has moved for a long stretch. Gate strictly on ezWarmupTimer
                // validity (M1 invariant: never fire inside the 120s window or while
                // anything is advancing) and NEVER while a bootstrap snapshot is
                // actively downloading (the daemon's own BootstrapDownloadTooSlow
                // owns that — killing it would throw away a multi-GB download).
                int parsedPct = mPct.hasMatch() ? mPct.captured(1).toInt() : -1;
                bool bootstrapActive = status.contains(QStringLiteral("Bootstrap snapshot:"),
                                                       Qt::CaseInsensitive);
                // G7: the substring above only catches the active DOWNLOAD phase. After
                // the download the daemon runs a multi-minute UTXO verify with a FROZEN
                // "Verifying blocks..." status (no percent, no substring) — killing it
                // there would discard a healthy, nearly-finished bootstrap. Also suppress
                // whenever the cached getbootstrapinfo poll says bootstrap/verify is in
                // progress (phase active/succeeded, verify_pending, or provisional
                // validation). The cache is refreshed on the non-percent warmup polls
                // below, so it tracks the live phase without an extra RPC here.
                // W1(a): a repair relaunch (-reindex/-reindex-chainstate or the
                // post-redownload fresh start) is expected to dwell on a percent-less
                // phase for a long time — never let the watchdog kill the repair it just
                // launched. W1(b): even on a normal start, never fire while the status is
                // a known long, percent-less warmup phase (verifying blocks / activating
                // best chain / rewinding / loading block index / etc.). Keep the existing
                // bootstrap-download and post-bootstrap-verify suppression.
                bool suppressWedge = this->ezRepairRelaunchActive ||
                                     bootstrapActive ||
                                     this->bootstrapSuppressesWedge() ||
                                     ConnectionLoader::isLongWarmupPhase(status);
                if (status != ezLastWarmupStatus || parsedPct != ezLastWarmupPct) {
                    ezLastWarmupStatus = status;
                    ezLastWarmupPct    = parsedPct;
                    ezWarmupNoProgress.restart();
                } else if (ezWarmupTimer.isValid() && !suppressWedge &&
                           ezWarmupTimer.elapsed() > 120000 &&
                           ezWarmupNoProgress.isValid() &&
                           ezWarmupNoProgress.elapsed() > 180000) {
                    // Genuinely wedged: alive, -28, same non-download status with no
                    // percent movement for >=180s past the 120s window, and NOT in a
                    // bootstrap download / post-bootstrap verify. Clean restart.
                    main->logger->write("Warmup appears wedged (no progress >180s); restarting node");
                    this->handleWarmupWedged();
                    return;
                }

                if (mPct.hasMatch()) {
                    int pct = mPct.captured(1).toInt();
                    this->setBarPercent(pct);     // switches the bar from busy to 0-100
                    // Show the "X / Y GB  Z MB/s" tail (after the first '%') as detail.
                    QString detail = status.section(QStringLiteral("%"), 1).trimmed();
                    this->showInformation(
                        QObject::tr("Step 3 of 3: Downloading blockchain — %1%").arg(pct),
                        detail);
                } else {
                    // Every other warmup phase (Verifying wallet, Loading block index,
                    // Rewinding, Connecting to bootstrap server…, Activating best chain)
                    // has no percent: restore the busy/indeterminate bar so a stale 100%
                    // left over from a finished download phase doesn't linger.
                    bool renderedBootstrapVerify = false;
                    if (ezBootstrapVerifyPending ||
                        ezBootstrapPhase == QStringLiteral("succeeded")) {
                        if (ezProgress) ezProgress->setRange(0, 0);
                        QString detail = ezBootstrapValidationState;
                        if (detail == QStringLiteral("disabled"))
                            detail.clear();
                        this->showInformation(
                            QObject::tr("Step 3 of 3: Verifying blockchain… (a few minutes)"),
                            detail);
                        renderedBootstrapVerify = true;
                    }
                    if (!renderedBootstrapVerify) {
                        if (ezProgress) ezProgress->setRange(0, 0);
                        {
                            // DOTS FIX: the old code unconditionally chopped the LAST 3 chars
                            // before re-adding dots, so any status NOT ending in "..." got
                            // mangled (e.g. "Verifying blocks... (56%)" -> "Verifying blocks... (5...").
                            // Strip only a trailing run of dots, then re-append the animated count.
                            static int dots = 0;
                            QString base = status;
                            while (base.endsWith(QLatin1Char('.')))
                                base.chop(1);
                            status = base + QString(".").repeated(dots);
                            dots++;
                            if (dots > 3)
                                dots = 0;
                        }
                        this->showInformation(QObject::tr("Step 2 of 3: Starting your wallet…"), status);
                    }

                    // getbootstrapinfo enrichment: the warmup string carries no percent,
                    // but getbootstrapinfo is WARMUP-EXEMPT and answers with the live
                    // phase/percent/verify_pending. The shared helper drives a MOVING
                    // "Downloading blockchain — X%" (phase active) or an indeterminate
                    // "Verifying blockchain…" (verify_pending / phase succeeded) over the
                    // static text just set above, and ALSO refreshes the cached phase/verify
                    // state that bootstrapSuppressesWedge() reads. It degrades gracefully on
                    // an older daemon (advisory cache latches off; the string parse above is
                    // the sole source then). Bob-fix: this same helper is now also called
                    // from the connection-refused poll path so the download window — where
                    // getinfo is refused, not -28 — is no longer a frozen line.
                    this->probeBootstrapProgress(connection);
                }
                main->logger->write("Waiting for zclassicd to come online.");
                // Refresh quickly during the first few seconds of warmup, then every second.
                int probeMs = (ezWarmupTimer.isValid() && ezWarmupTimer.elapsed() < 4000) ? 250 : 1000;
                QTimer::singleShot(probeMs, [=]() { this->refreshZClassicdState(connection, refused); });
            } else {
                // CATCH-ALL (edit #2 / blocker #2). Any remaining QNetworkReply error not
                // handled above — including an InternalServerError whose body did NOT parse
                // (res.is_discarded()), and transient TCP/timeout/parse states a daemon can
                // emit mid-warmup. This branch MUST NOT dead-end at a frozen connect dialog.
                //
                // For the first N polls treat it as a transient warmup hiccup: re-schedule
                // the poll exactly like the -28 warmup branch and show the friendly
                // "Step 2 of 3" message so odd states recover SILENTLY. Past N, the node is
                // genuinely not coming up on its own — surface the actionable, retryable
                // stuck dialog (re-runs doAutoConnect on Retry) rather than spinning forever.
                const int kMaxUnexpectedErrPolls = 20;   // ~ the existing poll cadence
                ezUnexpectedErrPolls++;
                if (ezUnexpectedErrPolls <= kMaxUnexpectedErrPolls) {
                    if (ezProgress) ezProgress->setRange(0, 0);
                    this->showInformation(QObject::tr("Step 2 of 3: Starting your wallet…"),
                        QObject::tr("Getting things ready…"));
                    main->logger->write(QString("getinfo unexpected reply (err %1); retrying (%2/%3)")
                        .arg((int)err).arg(ezUnexpectedErrPolls).arg(kMaxUnexpectedErrPolls));
                    int probeMs = (ezWarmupTimer.isValid() && ezWarmupTimer.elapsed() < 4000) ? 250 : 1000;
                    QTimer::singleShot(probeMs, [=]() { this->refreshZClassicdState(connection, refused); });
                } else {
                    // Persistently wedged on an unexpected reply: hand off to the runtime
                    // actionable+retryable dialog (the same MainWindow primitive the foreign-
                    // node-stuck poller uses), then let it drive Retry -> doAutoConnect. Reset
                    // the counter so a Retry gets a fresh budget instead of re-firing instantly.
                    main->logger->write("getinfo unexpected reply persisted past budget; surfacing actionable retry");
                    ezUnexpectedErrPolls = 0;
                    d->hide();
                    main->showNodeNotRespondingRetry();
                }
            }
        }
    );
}

// Bob-fix: drive a MOVING bootstrap sub-status off getbootstrapinfo (WARMUP-EXEMPT —
// it answers DURING the multi-GB snapshot download/verify, when plain getinfo is still
// blocked -28 or the RPC port is even refusing). Fires ONE async getbootstrapinfo and,
// when it lands, maps phase/percent/verify_pending onto the splash so the long download
// and the post-download verify window read as moving work instead of a frozen line.
// Safe to call from BOTH polling paths and on EVERY poll: non-blocking, never changes
// cadence, never a blocker. Degrades gracefully on an older daemon (RPC_METHOD_NOT_FOUND
// -> advisory cache latches off, caller's static fallback text stays).
void ConnectionLoader::probeBootstrapProgress(Connection* connection) {
    // COSMETIC tri-state gate (same one the -28 enrichment uses): -1 unknown, 0 absent,
    // 1 present. For an OWNED embedded daemon (ezclassicd != nullptr) the bundled binary
    // ALWAYS has getbootstrapinfo, so never let a persisted 0 (left by a prior foreign/
    // older daemon session) permanently suppress the only progress source bob can see —
    // re-probe regardless of the cache when we launched the node. For a foreign daemon
    // keep the once-per-session-absent behaviour (avoids hammering an older node).
    if (ezBootstrapRpcProbed < 0)
        ezBootstrapRpcProbed = QSettings().value("heal/daemonHasBootstrapRpc", -1).toInt();
    if (ezclassicd == nullptr && ezBootstrapRpcProbed == 0)
        return;

    json biPayload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "getbootstrapinfo"}
    };
    // W2: the Connection OUTLIVES this loader (doRPCSetConnection runs 'delete this').
    // Capture the shared alive token and bail before touching any member if the loader
    // was destroyed before this reply arrives. (ConnectionLoader is not a QObject.)
    std::shared_ptr<bool> alive = ezAlive;
    connection->doRPC(biPayload,
        [=] (json bi) {
            if (!alive || !*alive) return;   // W2: loader gone — do not touch members
            ezBootstrapRpcProbed = 1;
            QSettings().setValue("heal/daemonHasBootstrapRpc", 1);

            // Refresh the cached phase/verify state (also consumed by the WARMUP_WEDGED
            // watchdog's bootstrapSuppressesWedge()). Reset first so a missing field clears.
            ezBootstrapPhase.clear();
            ezBootstrapVerifyPending   = false;
            ezBootstrapValidationState.clear();
            int pct = -1;
            if (bi.is_object()) {
                if (bi.find("phase") != bi.end() && bi["phase"].is_string())
                    ezBootstrapPhase = QString::fromStdString(bi["phase"].get<std::string>());
                if (bi.find("verify_pending") != bi.end() && bi["verify_pending"].is_boolean())
                    ezBootstrapVerifyPending = bi["verify_pending"].get<bool>();
                // W3: getbootstrapinfo emits a FLAT "validation_state"; keep the older
                // nested bootstrap_validation/validation .state as a fallback.
                if (bi.find("validation_state") != bi.end() && bi["validation_state"].is_string()) {
                    ezBootstrapValidationState = QString::fromStdString(
                        bi["validation_state"].get<std::string>());
                } else {
                    for (const char* key : {"bootstrap_validation", "validation"}) {
                        auto it = bi.find(key);
                        if (it != bi.end() && it->is_object() &&
                            it->find("state") != it->end() && (*it)["state"].is_string()) {
                            ezBootstrapValidationState = QString::fromStdString(
                                (*it)["state"].get<std::string>());
                            break;
                        }
                    }
                }
                // percent is present ONLY when phase=="active" (daemon contract).
                if (bi.find("percent") != bi.end() && bi["percent"].is_number())
                    pct = bi["percent"].get<int>();
            }

            // Render a MOVING sub-status. Active download -> real 0-100 bar + percent.
            // Verify window (verify_pending true, or finished phase still awaiting verify)
            // -> indeterminate "Verifying…" so the multi-minute verify reads as work.
            if (ezBootstrapPhase == QStringLiteral("active") && pct >= 0) {
                this->setBarPercent(pct);
                this->showInformation(
                    QObject::tr("Step 3 of 3: Downloading blockchain — %1%").arg(pct),
                    QString());
            } else if (ezBootstrapVerifyPending ||
                       ezBootstrapPhase == QStringLiteral("succeeded")) {
                if (ezProgress) ezProgress->setRange(0, 0);   // busy/indeterminate
                QString detail = ezBootstrapValidationState;
                if (detail == QStringLiteral("disabled"))
                    detail.clear();
                this->showInformation(
                    QObject::tr("Step 3 of 3: Verifying blockchain… (a few minutes)"),
                    detail);
            }
            // Any other phase (idle/skipped/failed/normal_sync) -> leave the caller's
            // text in place; the daemon is past bootstrap or never used it. The getinfo
            // -28 string parse / normal IBD poller take over from here.
        },
        [=] (auto, auto) {
            if (!alive || !*alive) return;   // W2: loader gone — do not touch members
            // Older daemon / not supported / any error: ADVISORY only. Latch the cache
            // and clear the cached state (so it can't wrongly suppress the watchdog) —
            // the caller's static fallback text stays; never a blocker.
            ezBootstrapRpcProbed = 0;
            QSettings().setValue("heal/daemonHasBootstrapRpc", 0);
            ezBootstrapPhase.clear();
            ezBootstrapVerifyPending = false;
            ezBootstrapValidationState.clear();
        });
}

// PRE-EXISTING/FOREIGN daemon classifier. Reached ONLY from refreshZClassicdState's
// getinfo-success path when ezclassicd == nullptr (a daemon we did NOT launch is on the
// RPC port — could be a synced beta5 service, a prior GUI-session daemon still up, or an
// old/beta1/foreign node). A daemon that answers getinfo is ALIVE and reachable, so we
// ALWAYS ATTACH to it — there is no compatibility gate here.
//
// CORRECTION (blocker #1): getbootstrapinfo presence is NOT a compatibility signal. The
// RPC exists ONLY in the freshly-built bundled daemon; every released/healthy daemon (a
// live synced beta5 peer) returns RPC_METHOD_NOT_FOUND for it. Gating attach on the probe
// falsely blocked every healthy pre-existing daemon (case C). So the getbootstrapinfo
// probe is now ADVISORY ONLY: it refreshes heal/daemonHasBootstrapRpc for richer warmup-
// bar progress, and BOTH callbacks ATTACH. The dialog is NEVER shown from this path; a
// stuck/peerless foreign node is handled at RUNTIME by the sync poller (rpc.cpp), which
// has the actual-health signal (sustained peerless) the attach decision lacks.
void ConnectionLoader::classifyForeignDaemon(Connection* connection) {
    json biPayload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "getbootstrapinfo"}
    };
    // W2: the Connection OUTLIVES this loader once handed to rpc (doRPCSetConnection
    // runs 'delete this'). Capture the shared 'alive' token so a late reply bails before
    // touching any freed member. (ConnectionLoader is not a QObject, so no QPointer.)
    std::shared_ptr<bool> alive = ezAlive;
    connection->doRPC(biPayload,
        [=] (json) {
            if (!alive || !*alive) return;   // W2: loader gone — do not touch members
            // Foreign node WITH the bundled feature set (advisory only). Refresh the
            // flag for richer warmup progress, then ATTACH (avoids launching a second
            // daemon onto the held ports).
            ezBootstrapRpcProbed = 1;
            QSettings().setValue("heal/daemonHasBootstrapRpc", 1);
            d->hide();
            main->logger->write("Attached to a ZClassic node already running (bundled feature set).");
            this->doRPCSetConnection(connection);
        },
        [=] (auto, auto) {
            if (!alive || !*alive) return;   // W2: loader gone — do not touch members
            // Foreign node with an OLDER feature set (no getbootstrapinfo). This is the
            // common, HEALTHY case (a released/synced daemon). The probe absence is NOT
            // an incompatibility — ATTACH anyway. (A genuinely stuck/peerless foreign
            // node is caught later by the runtime sync poller, which has the health
            // signal this attach decision does not.) Degrade the advisory flag only.
            ezBootstrapRpcProbed = 0;
            QSettings().setValue("heal/daemonHasBootstrapRpc", 0);
            d->hide();
            main->logger->write("Pre-existing ZClassic node has an older feature set (no getbootstrapinfo) — attaching anyway.");
            this->doRPCSetConnection(connection);
        });
}

// True iff BOTH the RPC port (config->port) and the matching P2P port on 127.0.0.1 are
// currently UNBOUND. Used as the double-launch guard for the optional "Use the bundled
// node" button (invariant 4): a transient connect that SUCCEEDS means the port is in use
// (return false); a refused connect means that port is free. Both free -> true.
bool ConnectionLoader::portsFree(std::shared_ptr<ConnectionConfig> config) {
    // P2P port is mainnet 8033 / testnet 18033. Derive testnet from the AUTHORITATIVE
    // signal (Settings::isTestnet()) rather than matching config->port to the literal
    // 18023 (edit #7 / review low): a testnet node with a CUSTOM rpcport would otherwise
    // be misread as mainnet and we'd probe the wrong P2P port.
    bool testnet = Settings::getInstance()->isTestnet();
    quint16 rpcPort = config ? static_cast<quint16>(config->port.toUShort()) : 0;
    quint16 p2pPort = testnet ? 18033 : 8033;

    auto portInUse = [](quint16 port) -> bool {
        if (port == 0) return false;
        QTcpSocket probe;
        probe.connectToHost(QStringLiteral("127.0.0.1"), port);
        bool connected = probe.waitForConnected(150);   // refused/timeout => free
        probe.abort();
        return connected;
    };

    return !portInUse(rpcPort) && !portInUse(p2pPort);
}

// Update the UI with the status
void ConnectionLoader::showInformation(QString info, QString detail) {
    // Once we reach the syncing phase, drop the now-stale onboarding card so it
    // doesn't contradict the live status; the progress bar carries on.
    if (info.contains(QObject::tr("Step 3")) && ezCard && ezCard->isVisible())
        ezCard->setVisible(false);

    // First-run trust: the daemon's warmup rescan status ("Rescanning...") has NO
    // ETA, so we add ONE calm, accurate hint once a rescan is detected, instead of
    // appending the old context-less "several hours" to every poll after the 10th
    // (the static counter never reset, so it stuck on for the whole session and
    // contradicted the import dialog's "several minutes" wording). The hint is a
    // stable constant string appended each rescan poll, so the label never flickers.
    static bool rescanHintShown = false;
    static int  rescanLogged    = 0;
    const bool  isRescan = detail.toLower().startsWith("rescan");
    if (isRescan && !rescanHintShown) {
        rescanHintShown = true;
    }
    if (isRescan && rescanHintShown) {
        detail = detail + "\n" + QObject::tr("Rescanning your wallet — this usually "
            "takes 10-20 minutes. Your balance will update when it finishes.");
    }

    connD->status->setText(info);
    connD->statusDetail->setText(detail);

    // Log the first few status transitions, then go quiet (avoids one log line per
    // ~1s rescan poll, matching the old rescanCount<10 intent).
    if (rescanLogged < 10) {
        main->logger->write(info + ":" + detail);
        rescanLogged++;
    }
}

/**
 * Show error will close the loading dialog and show an error. 
*/
void ConnectionLoader::showError(QString explanation) {
    rpc->setEZClassicd(nullptr);
    rpc->noConnection();

    QMessageBox::critical(main, QObject::tr("Connection Error"), explanation, QMessageBox::Ok);

    // NEVER-STRAND: after the error is acknowledged we close the modal connect
    // dialog. With quit-on-last-window-closed off for the whole lifetime this can
    // no longer quit the app, and we explicitly leave the user looking at the main
    // window (in its noConnection state, set above) with the error already seen --
    // an actionable end state, never a blank exit. Idempotent UI-only calls.
    if (main) {
        main->show();
        main->raise();
        main->activateWindow();
    }
    // Programmatic abort: d->close() invokes QDialog::reject() -> rejected(). Mark it
    // so the loadConnection rejected() handler does NOT treat this as a user quit.
    // (Leaves the user on the main window in its noConnection state -- the existing
    // actionable end state, unchanged.)
    ezProgrammaticClose = true;
    d->close();
    ezProgrammaticClose = false;
}

QString ConnectionLoader::locateZClassicConfFile() {
#ifdef Q_OS_LINUX
    auto confLocation = QStandardPaths::locate(QStandardPaths::HomeLocation, ".zclassic/zclassic.conf");
#elif defined(Q_OS_DARWIN)
    auto confLocation = QStandardPaths::locate(QStandardPaths::HomeLocation, "Library/Application Support/ZClassic/zclassic.conf");
#else
    auto confLocation = QStandardPaths::locate(QStandardPaths::AppDataLocation, "../../ZClassic/zclassic.conf");
#endif

    main->logger->write("Found zclassicconf at " + QDir::cleanPath(confLocation));
    return QDir::cleanPath(confLocation);
}

QString ConnectionLoader::zclassicConfWritableLocation() {
#ifdef Q_OS_LINUX
    auto confLocation = QDir(QStandardPaths::writableLocation(QStandardPaths::HomeLocation)).filePath(".zclassic/zclassic.conf");
#elif defined(Q_OS_DARWIN)
    auto confLocation = QDir(QStandardPaths::writableLocation(QStandardPaths::HomeLocation)).filePath("Library/Application Support/ZClassic/zclassic.conf");
#else
    auto confLocation = QDir(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)).filePath("../../ZClassic/zclassic.conf");
#endif

    main->logger->write("Found zclassicconf at " + QDir::cleanPath(confLocation));
    return QDir::cleanPath(confLocation);
}

QString ConnectionLoader::zcashParamsDir() {
    #ifdef Q_OS_LINUX
    auto paramsLocation = QDir(QDir(QStandardPaths::writableLocation(QStandardPaths::HomeLocation)).filePath(".zcash-params"));
#elif defined(Q_OS_DARWIN)
    auto paramsLocation = QDir(QDir(QStandardPaths::writableLocation(QStandardPaths::HomeLocation)).filePath("Library/Application Support/ZcashParams"));
#else
    auto paramsLocation = QDir(QDir(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)).filePath("../../ZcashParams"));
#endif

    if (!paramsLocation.exists()) {
        main->logger->write("Creating params location at " + paramsLocation.absolutePath());
        QDir().mkpath(paramsLocation.absolutePath());
    }

    main->logger->write("Found ZClassic params directory at " + paramsLocation.absolutePath());
    return paramsLocation.absolutePath();
}

bool ConnectionLoader::verifyParams() {
    QDir paramsDir(zcashParamsDir());

    if (!QFile(paramsDir.filePath("sapling-output.params")).exists()) return false;
    if (!QFile(paramsDir.filePath("sapling-spend.params")).exists()) return false;
    if (!QFile(paramsDir.filePath("sprout-proving.key")).exists()) return false;
    if (!QFile(paramsDir.filePath("sprout-verifying.key")).exists()) return false;
    if (!QFile(paramsDir.filePath("sprout-groth16.params")).exists()) return false;

    return true;
}

// COOKIE-AUTH: absolute path of the daemon's auth cookie, computed from the SAME conf
// the GUI reads so the launch-time -rpccookiefile and the read-time path are identical.
// Base = conf datadir= override if present, else the conf's directory. On testnet the
// daemon would normally place the cookie under testnet3/, but because we PIN an absolute
// -rpccookiefile to THIS path the daemon writes it here regardless — no subdir guessing.
QString ConnectionLoader::cookieFilePathForConf(const std::shared_ptr<ConnectionConfig>& cfg) {
    if (!cfg)
        return QString();
    QString base = !cfg->dataDirOverride.isEmpty() ? cfg->dataDirOverride : cfg->zclassicDir;
    if (base.isEmpty())
        return QString();
    return QDir::cleanPath(QDir(base).filePath(QStringLiteral(".cookie")));
}

// COOKIE-AUTH: read the raw "__cookie__:<base64>" line the daemon wrote (single getline,
// exactly like the daemon's GetAuthCookie). Returns nullopt when the file is
// absent/empty (daemon still pre-RPC). The cookie is a SECRET: NEVER log its contents.
QString ConnectionLoader::readAuthCookie(const std::shared_ptr<ConnectionConfig>& cfg) {
    // Returns an EMPTY QString to mean "no cookie yet" (C++14 codebase, no std::optional).
    // A valid cookie line is always non-empty, so empty is an unambiguous sentinel.
    QString path = cookieFilePathForConf(cfg);
    if (path.isEmpty())
        return QString();
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return QString();
    QTextStream in(&f);
    QString line = in.readLine();   // first line only; daemon writes no trailing newline
    f.close();
    return line.trimmed();           // empty if the file was empty -> treated as "absent"
}

// FOREIGN-NODE CREDENTIAL DISCOVERY. See header. Reads the standard pidfile then the
// running daemon's /proc/<pid>/cmdline to recover RPC creds for a node we did NOT launch
// (creds only on its command line). Returns the password (or EMPTY) + fills outUser.
// SECRET-SAFE: never logs the password/cookie/cmdline bytes; only "found", at most once.
QString ConnectionLoader::discoverCredsFromRunningDaemon(const std::shared_ptr<ConnectionConfig>& cfg, QString& outUser) {
    outUser = QString();
#ifdef Q_OS_LINUX
    if (!cfg)
        return QString();

    // Resolve the datadir base EXACTLY as cookieFilePathForConf (dataDirOverride else
    // the conf's own directory) so the pidfile and cookie paths stay consistent.
    QString base = !cfg->dataDirOverride.isEmpty() ? cfg->dataDirOverride : cfg->zclassicDir;
    if (base.isEmpty())
        return QString();

    // Standard pidfile is <datadir>/zclassicd.pid (bob's -pid= writes exactly this). On
    // testnet a RELATIVE -pid resolves under testnet3/, so also try that as a fallback.
    QStringList pidCandidates;
    pidCandidates << QDir::cleanPath(QDir(base).filePath(QStringLiteral("zclassicd.pid")));
    if (Settings::getInstance()->isTestnet())
        pidCandidates << QDir::cleanPath(QDir(base).filePath(QStringLiteral("testnet3/zclassicd.pid")));

    qint64 pid = 0;
    for (const QString& pidPath : pidCandidates) {
        QFile pf(pidPath);
        if (!pf.open(QIODevice::ReadOnly | QIODevice::Text))
            continue;
        QTextStream pin(&pf);
        bool ok = false;
        qint64 v = pin.readLine().trimmed().toLongLong(&ok);
        pf.close();
        if (ok && v > 0) { pid = v; break; }
    }
    if (pid <= 0)
        return QString();   // no pidfile -> fall back (do NOT scan unrelated zclassicd)

    // Read /proc/<pid>/cmdline: NUL-separated args (same-user readable; cross-user EACCES
    // -> open fails -> fall back). A stale/recycled PID is rejected by the basename check.
    QFile cf(QStringLiteral("/proc/%1/cmdline").arg(pid));
    if (!cf.open(QIODevice::ReadOnly))
        return QString();
    QByteArray raw = cf.readAll();
    cf.close();
    if (raw.isEmpty())
        return QString();

    QList<QByteArray> rawArgs = raw.split('\0');
    QStringList args;
    for (const QByteArray& a : rawArgs) {
        if (!a.isEmpty())
            args << QString::fromLocal8Bit(a);
    }
    if (args.isEmpty())
        return QString();

    // RIGHT-PROCESS TARGETING. The program name (args[0]) must look like a zclassicd. This
    // rejects a recycled PID now owned by some other program.
    QString prog = QFileInfo(args.first()).fileName();
    if (!prog.contains(QStringLiteral("zclassicd"), Qt::CaseInsensitive))
        return QString();

    // Scan args. If a -datadir= is present it MUST resolve to OUR base, else this is some
    // unrelated zclassicd and we fall back. When no -datadir= is present we trust the
    // pidfile anchor (the pidfile lived under OUR base).
    QString cmdUser, cmdPass, cmdCookieFile, cmdDataDir;
    for (const QString& a : args) {
        int eq = a.indexOf(QLatin1Char('='));
        if (eq < 0)
            continue;
        QString val = a.mid(eq + 1);
        if (a.startsWith(QStringLiteral("-rpcuser=")))            cmdUser       = val;
        else if (a.startsWith(QStringLiteral("-rpcpassword=")))   cmdPass       = val;
        else if (a.startsWith(QStringLiteral("-rpccookiefile="))) cmdCookieFile = val;
        else if (a.startsWith(QStringLiteral("-datadir=")))       cmdDataDir    = val;
    }

    if (!cmdDataDir.isEmpty()) {
        QString a = QDir::cleanPath(QDir(cmdDataDir).absolutePath());
        QString b = QDir::cleanPath(QDir(base).absolutePath());
        if (a != b)
            return QString();   // a DIFFERENT node's datadir -> never send its creds
    }

    // Path A: explicit -rpcpassword on the command line (bob's case). Use the cmdline's
    // -rpcuser verbatim — EMPTY when none was given (daemon then matches a ":<pass>"
    // header). Do NOT substitute "__cookie__": that literal is only correct for cookie
    // auth, and a node started with -rpcpassword and no -rpcuser uses an empty username.
    if (!cmdPass.isEmpty()) {
        outUser = cmdUser;
        if (!QSettings().value("conf/cmdlineCredsLogged", false).toBool()) {
            main->logger->write("Discovered RPC credentials from the running node's command line");
            QSettings().setValue("conf/cmdlineCredsLogged", true);
        }
        return cmdPass;   // SECRET: returned only, never logged
    }

    // Path B: the node was started with -rpccookiefile=<path> instead. Follow it and read
    // that cookie with the same single-getline as readAuthCookie.
    if (!cmdCookieFile.isEmpty()) {
        QFile ckf(cmdCookieFile);
        if (ckf.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream cin(&ckf);
            QString cookieLine = cin.readLine().trimmed();
            ckf.close();
            int colon = cookieLine.indexOf(QLatin1Char(':'));
            if (colon > 0) {
                outUser = cookieLine.left(colon);
                if (!QSettings().value("conf/cmdlineCredsLogged", false).toBool()) {
                    main->logger->write("Discovered RPC cookie from the running node's command line");
                    QSettings().setValue("conf/cmdlineCredsLogged", true);
                }
                return cookieLine.mid(colon + 1);   // SECRET: returned only, never logged
            }
        }
    }

    return QString();   // nothing usable on the cmdline -> fall back
#else
    Q_UNUSED(cfg);
    return QString();   // /proc is Linux-only; macOS/Windows fall through to QSettings/prompt
#endif
}

// PROACTIVE one-time migration of a legacy GUI-owned conf to cookie auth. Strips ONLY
// the rpcuser=/rpcpassword= lines IN PLACE (preserving server=/datadir=/proxy=/testnet=
// verbatim — we do NOT reuse createZClassicConf, which is modal + truncates and would
// clobber a custom datadir=). Gated to a GUI-owned (rpcuser=="zcl-qt-wallet"), embedded,
// non-external (daemon=1 ABSENT) conf so a user's external-node creds are never touched.
// Runs at most once (QSettings conf/cookieMigrated). Re-asserts 0600 + the read-back
// leak-warn. NEVER logs the stripped credential.
void ConnectionLoader::migrateConfToCookie() {
    // Embedded-only: never rewrite a conf the user pointed us at as an external node.
    if (!Settings::getInstance()->useEmbedded())
        return;
    if (QSettings().value("conf/cookieMigrated", false).toBool())
        return;

    QString confLocation = locateZClassicConfFile();
    if (confLocation.isEmpty())
        return;   // no conf yet -> createZClassicConf writes a cookie-mode one anyway

    QFile in(confLocation);
    if (!in.open(QIODevice::ReadOnly | QIODevice::Text))
        return;

    QStringList kept;
    bool sawGuiRpcUser   = false;   // rpcuser=zcl-qt-wallet  -> GUI-owned signal
    bool sawDaemonFlag   = false;   // daemon=1               -> deliberately external
    bool hadRpcPassword  = false;
    {
        QTextStream ts(&in);
        while (!ts.atEnd()) {
            QString line = ts.readLine();
            int s = line.indexOf(QLatin1Char('='));
            QString name  = (s < 0 ? line : line.left(s)).trimmed().toLower();
            QString value = (s < 0 ? QString() : line.mid(s + 1)).trimmed();
            if (name == QLatin1String("rpcuser")) {
                if (value == QLatin1String("zcl-qt-wallet")) sawGuiRpcUser = true;
                continue;   // strip (do not keep)
            }
            if (name == QLatin1String("rpcpassword")) {
                hadRpcPassword = true;
                continue;   // strip (do not keep) — value NEVER logged
            }
            if (name == QLatin1String("daemon") && value == QLatin1String("1"))
                sawDaemonFlag = true;
            kept << line;   // preserve EVERY other line verbatim (datadir/proxy/testnet/server)
        }
    }
    in.close();

    // Only migrate a conf that is unmistakably OUR cookie-able conf: GUI rpcuser, a
    // password to strip, and NOT a deliberately-external (daemon=1) conf. Otherwise mark
    // migrated (so we never re-scan) and leave the file untouched.
    if (!sawGuiRpcUser || !hadRpcPassword || sawDaemonFlag) {
        QSettings().setValue("conf/cookieMigrated", true);
        return;
    }

    // DEFENSIVE (belt-and-suspenders): never strip creds out from under a daemon that is
    // actively LISTENING on the conf's RPC port. The gates above already exclude a
    // deliberately-external node, but a race (a daemon coming up on this conf as we migrate)
    // could leave it 401ing. If something answers on 127.0.0.1:<rpcport> right now, SKIP the
    // rewrite this launch (do NOT set the migrated flag -> retry next clean launch). Reuses
    // the same 127.0.0.1 QTcpSocket probe shape as portsFree(). NEVER restarts the node.
    {
        quint16 rpcPort = Settings::getInstance()->isTestnet() ? 18023 : 8023;
        QTcpSocket probe;
        probe.connectToHost(QStringLiteral("127.0.0.1"), rpcPort);
        bool listening = probe.waitForConnected(150);   // refused/timeout => free
        probe.abort();
        if (listening) {
            main->logger->write("migrateConfToCookie: a daemon is listening on the RPC port; skipping conf strip this launch");
            return;   // do NOT set the migrated flag -> retry on a future clean launch
        }
    }

    // Rewrite 0600 (born owner-only via umask, exactly like createZClassicConf).
#ifndef Q_OS_WIN
    mode_t oldMask = ::umask(0077);
#endif
    QFile out(confLocation);
    bool opened = out.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text);
#ifndef Q_OS_WIN
    ::umask(oldMask);
#endif
    if (!opened) {
        main->logger->write("migrateConfToCookie: could not rewrite conf; leaving it as-is");
        return;   // do NOT set the flag -> retry on a future launch
    }
    if (!out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner))
        main->logger->write("warning: could not restrict zclassic.conf to 0600 (migration)");
    {
        QTextStream os(&out);
        for (const QString& l : kept)
            os << l << "\n";
    }
    out.close();

    // Read-back leak check (same posture as createZClassicConf).
    {
        QFile::Permissions p = QFile::permissions(confLocation);
        const QFile::Permissions leaky =
            QFileDevice::ReadGroup  | QFileDevice::WriteGroup |
            QFileDevice::ReadOther  | QFileDevice::WriteOther;
        if (p & leaky)
            main->logger->write("WARNING: zclassic.conf could not be secured to 0600 after "
                                "cookie migration; please chmod 600 it.");
    }

    QSettings().setValue("conf/cookieMigrated", true);
    main->logger->write("Migrated GUI-owned zclassic.conf to cookie auth (stripped rpcuser/rpcpassword)");
}

// REACTIVE 401 self-heal for an OWNED embedded node. See header. Bounded at cap 1 via
// the EXISTING heal ledger so 401->restart->401 can NEVER loop. Returns true if it
// handled the 401 (caller must NOT fall through to any showError).
bool ConnectionLoader::handleEmbeddedAuthFailure() {
    // INVARIANT (caller already checked, re-assert defensively): owned embedded only.
    if (!Settings::getInstance()->useEmbedded() || ezclassicd == nullptr)
        return false;   // not ours -> caller takes the external-node path

    if (healInProgress())
        return true;    // a heal is already armed; swallow this 401 (do not dead-end)

    // HARD CAP (cap 1): one cookie-only rewrite + relaunch. If that did not fix auth,
    // escalate to NEEDS_MANUAL (keeps Help->Repair reachable) rather than looping.
    if (healAttempts("authRestart") >= 1) {
        this->latchNeedsManual(QObject::tr("ZClassic couldn't sign in to its own node.\n\n"
            "It already tried to fix this automatically. Please quit and open ZClassic "
            "again. If it keeps happening, repair the blockchain from the Help menu. "
            "Your wallet and coins are safe."));
        return true;
    }
    bumpHealAttempt("authRestart");
    setHealInProgress(true);
    main->logger->write("AUTH_RESTART heal: owned-node 401 — switching conf to cookie auth and restarting once");

    // (1) Force the conf to cookie-only so the relaunched daemon writes a fresh cookie
    //     and there is no shared secret left to mismatch. Idempotent + safe even if the
    //     proactive pass already ran (it just sees nothing to strip).
    QSettings().setValue("conf/cookieMigrated", false);   // allow the rewrite to run
    this->migrateConfToCookie();

    // (2) LOOP-HAZARD DEFENSE (verified): a daemon only re-reads its conf on a FRESH
    //     start, and it holds the RPC port with the OLD credential until it exits. So we
    //     must FULLY stop + drop the QProcess BEFORE relaunch, or the relaunch would
    //     re-bind against the same stale auth and 401 forever. Exact handleWarmupWedged
    //     stop sequence (terminate -> wait -> kill -> deleteLater -> nullptr).
    if (ezclassicd && ezclassicd->state() != QProcess::NotRunning) {
        ezclassicd->terminate();
        ezclassicd->waitForFinished(5000);
        if (ezclassicd->state() != QProcess::NotRunning)
            ezclassicd->kill();
    }
    if (ezclassicd) {
        ezclassicd->deleteLater();
        ezclassicd = nullptr;
    }
    ezNodeQuitDuringStartup = false;
    ezUnexpectedErrPolls = 0;      // fresh start: clear the odd-reply streak counter
    ezStdErr.clear();
    ezLastWarmupStatus.clear();
    ezLastWarmupPct = -1;
    ezWarmupNoProgress.invalidate();

    if (!this->startEmbeddedZClassicd()) {
        this->setHealInProgress(false);
        this->latchNeedsManual(QObject::tr("ZClassic couldn't restart its node.\n\n"
            "Please open ZClassic again. Your wallet and coins are safe."));
        return true;
    }
    this->setHealInProgress(false);   // relaunch armed
    ezWarmupTimer.start();
    // ezAlive guard: ConnectionLoader is not a QObject; bail if the loader was freed
    // (deferred 'delete this' in doRPCSetConnection) before this fires.
    auto alive = ezAlive;
    QTimer::singleShot(1000, [=]() {
        if (!alive || !*alive) return;
        doAutoConnect();
    });
    return true;
}

/**
 * Try to automatically detect a zclassic.conf file in the correct location and load parameters
 */
std::shared_ptr<ConnectionConfig> ConnectionLoader::autoDetectZClassicConf() {
    auto confLocation = locateZClassicConfFile();

    if (confLocation.isNull()) {
        // No ZClassic file, just return with nothing
        return nullptr;
    }

    QFile file(confLocation);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << file.errorString();
        return nullptr;
    }

    QTextStream in(&file);

    auto zclassicconf = new ConnectionConfig();
    zclassicconf->host     = "127.0.0.1";
    zclassicconf->connType = ConnectionType::DetectedConfExternalZClassicD;
    zclassicconf->usingZClassicConf = true;
    zclassicconf->zclassicDir = QFileInfo(confLocation).absoluteDir().absolutePath();
    zclassicconf->zclassicDaemon = false;

    Settings::getInstance()->setUsingZClassicConf(confLocation);

    while (!in.atEnd()) {
        QString line = in.readLine();
        auto s = line.indexOf("=");
        QString name  = line.left(s).trimmed().toLower();
        QString value = line.right(line.length() - s - 1).trimmed();

        if (name == "rpcuser") {
            zclassicconf->rpcuser = value;
        }
        if (name == "rpcpassword") {
            zclassicconf->rpcpassword = value;
        }
        if (name == "rpcport") {
            zclassicconf->port = value;
        }
        if (name == "daemon" && value == "1") {
            zclassicconf->zclassicDaemon = true;
        }
        if (name == "proxy") {
            zclassicconf->proxy = value;
        }
        if (name == "datadir") {
            // COOKIE-AUTH: a custom datadir= means the daemon's .cookie lives under
            // THAT dir, not the conf's directory. Capture it so cookieFilePathForConf
            // resolves the cookie (and the forced -rpccookiefile) correctly.
            zclassicconf->dataDirOverride = value;
        }
        if (name == "testnet" &&
            value == "1"  &&
            zclassicconf->port.isEmpty()) {
                zclassicconf->port = "18023";
        }
    }

    // If rpcport is not in the file, and it was not set by the testnet=1 flag, then go to default
    if (zclassicconf->port.isEmpty()) zclassicconf->port = "8023";
    file.close();

    // COOKIE-AUTH read (touch-point b). When the conf carries NO rpcpassword, the
    // daemon is in cookie mode: it auto-writes <datadir>/.cookie. Read that cookie
    // FRESH on this connect attempt (never cached — doAutoConnect re-runs this every
    // poll, so a late-appearing cookie is picked up next iteration) and feed the
    // resulting "__cookie__:<b64>" line straight into rpcuser/rpcpassword so the
    // UNCHANGED makeConnection() builds the correct Basic header. A MISSING/empty
    // cookie (daemon still in its pre-RPC param/index phase) leaves rpcuser/rpcpassword
    // empty -> makeConnection sends an empty Basic header the daemon refuses at the
    // connection level (ConnectionRefusedError) during warmup, which folds into the
    // patient refused()/warmup branch in doAutoConnect — NOT the 401 dead-end. The
    // cookie line is a SECRET and is NEVER logged (CONF-3).
    if (zclassicconf->rpcpassword.isEmpty()) {
        std::shared_ptr<ConnectionConfig> tmp(zclassicconf,
                                              [](ConnectionConfig*){ /*non-owning view*/ });
        QString cookieLine = readAuthCookie(tmp);   // empty => no cookie yet
        if (!cookieLine.isEmpty()) {
            const QString& line = cookieLine;
            int colon = line.indexOf(QLatin1Char(':'));
            if (colon > 0) {
                zclassicconf->rpcuser     = line.left(colon);
                zclassicconf->rpcpassword = line.mid(colon + 1);
                zclassicconf->cookieAuth  = true;
            }
        }

        // FALLBACK 3 (foreign node, zero user action): the conf has no rpcpassword and no
        // readable cookie. If this is a node WE DID NOT LAUNCH (ezclassicd == nullptr — the
        // SAME ownership discriminator used by the getinfo-success branch at refreshZClassicd
        // and the 401 heal gate; NOTE useEmbedded() is TRUE by default even for a foreign
        // node, so it must NOT be the gate), recover its creds from its own command line via
        // <datadir>/zclassicd.pid -> /proc/<pid>/cmdline. Inert during our embedded launch
        // (ezclassicd is set there) and on macOS/Windows (helper returns empty). cookieAuth
        // is reused as the "populated this attempt, not persisted" marker. NEVER logs creds.
        if (zclassicconf->rpcpassword.isEmpty() && ezclassicd == nullptr) {
            QString discUser;
            QString discPass = discoverCredsFromRunningDaemon(tmp, discUser);
            if (!discPass.isEmpty()) {
                zclassicconf->rpcuser     = discUser;
                zclassicconf->rpcpassword = discPass;
                zclassicconf->cookieAuth  = true;   // not a persisted secret; read this attempt
            }
        }

        // FALLBACK 4 (cross-platform): still empty -> use creds the user typed into
        // Edit -> Settings (saved in QSettings connection/rpcuser+rpcpassword). This is the
        // load-bearing fix that makes manually-entered Settings creds win even when a conf
        // exists — today autoDetect always wins over loadFromSettings (only reached on the
        // no-conf doManualConnect path), so without this the typed creds were ignored. Only
        // adopt when BOTH are non-empty (same emptiness guard loadFromSettings uses), and
        // ONLY for a node we did NOT launch (ezclassicd == nullptr) — for our own embedded
        // node cookie auth is the sole path, so stale Settings creds must never override it
        // (they would 401 our own node); leave empty -> warmup/refused until the cookie lands.
        if (zclassicconf->rpcpassword.isEmpty() && ezclassicd == nullptr) {
            QSettings s;
            QString sUser = s.value("connection/rpcuser").toString();
            QString sPass = s.value("connection/rpcpassword").toString();
            if (!sUser.isEmpty() && !sPass.isEmpty()) {
                zclassicconf->rpcuser     = sUser;
                zclassicconf->rpcpassword = sPass;
                zclassicconf->cookieAuth  = true;   // populated this attempt, not from conf
            }
        }
        // else: ALL sources empty -> empty Basic header -> refused/retry; a real 401 then
        // routes to the now-editable Settings prompt (never the file dead-end).
    }

    // In addition to the zclassic.conf file, also double check the params. 

    return std::shared_ptr<ConnectionConfig>(zclassicconf);
}

/**
 * Load connection settings from the UI, which indicates an unknown, external zclassicd
 */ 
std::shared_ptr<ConnectionConfig> ConnectionLoader::loadFromSettings() {
    // Load from the QT Settings. 
    QSettings s;
    
    auto host        = s.value("connection/host").toString();
    auto port        = s.value("connection/port").toString();
    auto username    = s.value("connection/rpcuser").toString();
    auto password    = s.value("connection/rpcpassword").toString();    

    if (username.isEmpty() || password.isEmpty())
        return nullptr;

    auto uiConfig = new ConnectionConfig{ host, port, username, password, false, false, "", "", ConnectionType::UISettingsZClassicD};

    return std::shared_ptr<ConnectionConfig>(uiConfig);
}





// P1-7: refuse to start a ~1.7GB download / heavy sync when the disk is nearly full.
bool ConnectionLoader::ensureEnoughDiskSpace(const QString& path) {
    QStorageInfo storage(path);
    if (!storage.isValid() || !storage.isReady()) {
        // Can't tell -- don't block the user on an unknown.
        main->logger->write("Disk space check skipped (storage not ready) for " + path);
        return true;
    }

    const qint64 needed = (qint64)3 * 1024 * 1024 * 1024;   // ~3 GB
    qint64 avail = storage.bytesAvailable();
    main->logger->write(QString("Free space at %1: %2 MB").arg(path).arg(avail / 1024 / 1024));

    if (avail < needed) {
        QString human = QString::number(avail / 1024.0 / 1024.0 / 1024.0, 'f', 1);
        this->showError(QObject::tr("Not enough free disk space.\n\n"
            "ZClassic needs about 3 GB free to finish setting up, but only %1 GB is available. "
            "Please free up some space and open ZClassic again.").arg(human));
        return false;
    }
    return true;
}

// P1-2: switch the onboarding bar from busy/indeterminate to a real 0-100 reading.
void ConnectionLoader::setBarPercent(int pct) {
    if (!ezProgress) return;
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    if (ezProgress->maximum() == 0)
        ezProgress->setRange(0, 100);
    ezProgress->setValue(pct);
}

// P1-2: instead of a dead-end error on a failed download, let the user try again.
void ConnectionLoader::offerRetry(QString explanation, std::function<void(void)> cb) {
    auto choice = QMessageBox::warning(main, QObject::tr("ZClassic"),
        explanation % "\n\n" % QObject::tr("Would you like to try again?"),
        QMessageBox::Retry | QMessageBox::Cancel, QMessageBox::Retry);

    if (choice == QMessageBox::Retry) {
        ezRetryCount = 0;
        main->logger->write("User chose to retry param download");
        QTimer::singleShot(100, [=]() { this->doNextDownload(cb); });
    } else {
        this->showError(QObject::tr("Setup was stopped.\n\n"
            "You can open ZClassic again whenever you're ready to finish setting up."));
    }
}

/***********************************************************************************
 *  Connection Class
 ************************************************************************************/ 
Connection::Connection(MainWindow* m, QNetworkAccessManager* c, QNetworkRequest* r, 
                        std::shared_ptr<ConnectionConfig> conf) {
    this->restclient  = c;
    this->request     = r;
    this->config      = conf;
    this->main        = m;
}

Connection::~Connection() {
    delete restclient;
    delete request;
}

void Connection::doRPC(const json& payload, const std::function<void(json)>& cb, 
                       const std::function<void(QNetworkReply*, const json&)>& ne) {
    if (shutdownInProgress) {
        // Ignoring RPC because shutdown in progress
        return;
    }

    QNetworkReply *reply = restclient->post(*request, QByteArray::fromStdString(payload.dump()));

    QObject::connect(reply, &QNetworkReply::finished, [=] {
        reply->deleteLater();
        if (shutdownInProgress) {
            // Ignoring callback because shutdown in progress
            return;
        }
        
        if (reply->error() != QNetworkReply::NoError) {
            auto parsed = json::parse(reply->readAll(), nullptr, false);
            ne(reply, parsed);
            
            return;
        } 
        
        auto parsed = json::parse(reply->readAll(), nullptr, false);
        if (parsed.is_discarded()) {
            ne(reply, "Unknown error");
            // CRITICAL (edit #4): STOP here. Falling through to cb() would DOUBLE-FIRE
            // (both the error and success callbacks for one reply) and, worse, cause a
            // use-after-free: a success cb that runs doRPCSetConnection() executes
            // 'delete this' on the loader, after which control returns into the freed
            // lambda / touches parsed["result"] on a discarded json.
            return;
        }

        cb(parsed["result"]);
    });
}

void Connection::doRPCWithDefaultErrorHandling(const json& payload, const std::function<void(json)>& cb) {
    doRPC(payload, cb, [=] (auto reply, auto parsed) {
        if (!parsed.is_discarded() && !parsed["error"]["message"].is_null()) {
            this->showTxError(QString::fromStdString(parsed["error"]["message"]));    
        } else {
            this->showTxError(reply->errorString());
        }
    });
}

void Connection::doRPCIgnoreError(const json& payload, const std::function<void(json)>& cb) {
    doRPC(payload, cb, [=] (auto, auto) {
        // Ignored error handling
    });
}

void Connection::showTxError(const QString& error) {
    if (error.isNull()) return;

    // Prevent multiple dialog boxes from showing, because they're all called async
    static bool shown = false;
    if (shown)
        return;

    shown = true;
    QMessageBox::critical(main, QObject::tr("Transaction Error"), QObject::tr("There was an error sending the transaction. The error was:") + "\n\n"
        + error, QMessageBox::StandardButton::Ok);
    shown = false;
}

/**
 * Prevent all future calls from going through
 */ 
void Connection::shutdown() {
    shutdownInProgress = true;
}
