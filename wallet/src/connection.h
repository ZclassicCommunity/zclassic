#ifndef CONNECTION_H
#define CONNECTION_H

#include "mainwindow.h"
#include "ui_connection.h"
#include "precompiled.h"

using json = nlohmann::json;

class RPC;
class QProgressBar;

enum ConnectionType {
    DetectedConfExternalZClassicD = 1,
    UISettingsZClassicD,
    InternalZClassicD
};

struct ConnectionConfig {
    QString host;
    QString port;
    QString rpcuser;
    QString rpcpassword;
    bool    usingZClassicConf;
    bool    zclassicDaemon;
    QString zclassicDir;
    QString proxy;

    ConnectionType connType;

    // COOKIE-AUTH: when the GUI-owned conf carries no rpcpassword, the daemon
    // auto-generates a .cookie and the GUI authenticates from it. cookieAuth==true
    // means rpcuser/rpcpassword above were populated by READING that cookie file on
    // THIS connect attempt (so a late-appearing cookie is picked up next poll), not
    // from a persisted shared secret. dataDirOverride holds a conf `datadir=` line so
    // the cookie path is computed under the daemon's real datadir, not the conf dir.
    // NOTE: declared LAST (after connType) on purpose — loadFromSettings() uses a
    // positional aggregate-init of the first 9 fields, so these two MUST stay trailing
    // (they take their defaults there). Do not reorder.
    bool    cookieAuth = false;
    QString dataDirOverride;
};

class Connection;

class ConnectionLoader {

public:
    ConnectionLoader(MainWindow* main, RPC* rpc);
    ~ConnectionLoader();

    void loadConnection();

    // SELF-HEAL: manual-override entry point. Spun up fresh from MainWindow's
    // always-reachable Help -> "Repair / Re-download blockchain…" action AFTER the
    // running node has been stopped, so the user is never permanently stuck even
    // once auto-heal has latched NEEDS_MANUAL. It reuses the EXACT same staged
    // offerCorruptionRepair() ladder used by the startup classifier — there is no
    // second ladder.
    void startManualRepair();

    // RUNTIME STUB AUTO-HEAL discriminator (primary, robust stub-vs-real test): total
    // bytes of the on-disk blocks/ store under `datadirRoot` (root, or testnet3/ when
    // that holds the chain — same resolution as resolveDataSubdir()). Static so the
    // runtime sync poller in RPC can call it with just the active connection's datadir.
    // Returns -1 when blocks/ can't be located/measured; callers MUST treat -1 as
    // "unknown" and NEVER heal on it. A fully-synced chain is ~10 GiB; a stub is tens of MB.
    static qint64 blocksDirSizeBytes(const QString& datadirRoot);

private:
    std::shared_ptr<ConnectionConfig> autoDetectZClassicConf();
    std::shared_ptr<ConnectionConfig> loadFromSettings();

    // ============ COOKIE-AUTH (structural 401 elimination) ============
    // The daemon auto-generates <datadir>/.cookie ("__cookie__:<base64(32 rnd)>")
    // whenever it is started with no rpcpassword (httprpc.cpp InitRPCAuthentication:
    // gate is mapArgs["-rpcpassword"]==""). We force an ABSOLUTE -rpccookiefile on the
    // embedded launch so the GUI reads the EXACT file it dictated — removing all
    // net-specific (testnet3/) and custom-datadir= path guessing.
    //
    // cookieFilePathForConf(): the absolute path we pass to -rpccookiefile AND read.
    // Base is the conf's datadir= override when present, else the conf's directory.
    QString cookieFilePathForConf(const std::shared_ptr<ConnectionConfig>& cfg);
    // readAuthCookie(): mirrors the daemon's GetAuthCookie (single getline of the raw
    // "__cookie__:<b64>" line). Returns an EMPTY QString when the file is absent/empty
    // (the daemon is still pre-RPC and has not written it yet); a valid cookie line is
    // never empty, so empty is an unambiguous "absent" sentinel (the codebase is C++14,
    // so no std::optional). The returned line is a SECRET and is NEVER logged (CONF-3).
    // Re-read on EVERY connect attempt, never cached.
    QString readAuthCookie(const std::shared_ptr<ConnectionConfig>& cfg);
    // FOREIGN-NODE CREDENTIAL DISCOVERY (zero user action). When a conf carries no
    // rpcpassword AND no cookie was readable, the only remaining zero-action source for a
    // node WE DID NOT LAUNCH is the daemon's OWN command line (e.g. a hand-rolled node
    // started with -rpcuser=/-rpcpassword= or -rpccookiefile= and no conf creds). We find
    // it via the standard pidfile <datadir>/zclassicd.pid -> /proc/<pid>/cmdline (same-user
    // readable; strictly less exposure than `ps`). The daemon's datadir base is resolved
    // EXACTLY as cookieFilePathForConf (dataDirOverride else zclassicDir) so we target the
    // RIGHT process: the cmdline's program name must contain "zclassicd" AND any -datadir=
    // it carries must match OUR base (else we fall back rather than send another node's
    // creds). If the cmdline carries -rpccookiefile= we follow it via readAuthCookie's
    // single-getline. Returns the password (or EMPTY on any miss) and fills outUser; the
    // returned password + cmdline bytes are SECRETS and are NEVER logged (CONF-3) — we log
    // only that creds were found, at most once per process. Linux-only: the whole body is
    // #ifdef Q_OS_LINUX and returns EMPTY elsewhere (macOS/Windows fall through to the
    // QSettings creds, then the editable Settings prompt). NEVER kills/restarts the node.
    QString discoverCredsFromRunningDaemon(const std::shared_ptr<ConnectionConfig>& cfg, QString& outUser);
    // PROACTIVE migration of an existing GUI-owned conf that still carries the legacy
    // rpcuser=/rpcpassword= (so an upgrader switches to cookie auth on next launch and
    // an already-desynced conf is healed). Headless, in-place: strips ONLY those two
    // lines, preserves datadir=/proxy=/testnet=/server= verbatim, re-asserts 0600. Runs
    // at most once (QSettings conf/cookieMigrated). Gated to a GUI-owned, embedded,
    // non-external (daemon=1 absent) conf so a user's external-node creds are untouched.
    void migrateConfToCookie();
    // REACTIVE 401 self-heal for an OWNED embedded node (belt to the cookie suspenders:
    // covers a hand-edited/partial-write conf the proactive pass could not reach, and a
    // cookie-not-yet-rewritten race). Bounded by heal/attempts.authRestart (cap 1):
    // strip the conf to cookie-only, fully stop + drop the QProcess, relaunch ONCE, and
    // resume the poll loop; on cap-exceed latchNeedsManual(). NEVER touches an external
    // node. Returns true if a heal was started/handled (caller must not fall through to
    // any showError); false to let the caller take the external-node path.
    bool handleEmbeddedAuthFailure();

    Connection* makeConnection(std::shared_ptr<ConnectionConfig> config);

    void doAutoConnect(bool tryEzclassicdStart = true);
    void doManualConnect();

    void createZClassicConf();
    QString locateZClassicConfFile();
    QString zclassicConfWritableLocation();
    QString zcashParamsDir();

    bool verifyParams();
    void downloadParams(std::function<void(void)> cb);
    void doNextDownload(std::function<void(void)> cb);
    // P2-1: optional one-shot extra args (e.g. "-reindex-chainstate") are passed
    // ONLY to the next launch and are NOT persisted into zclassic.conf, so a
    // repair can never loop forever.
    bool startEmbeddedZClassicd(const QStringList& extraArgs = QStringList());

    void refreshZClassicdState(Connection* connection, std::function<void(void)> refused);

    // PRE-EXISTING / FOREIGN-DAEMON edge. Reached ONLY from the getinfo-success path
    // when ezclassicd == nullptr (a daemon we did NOT launch is already on the RPC port).
    // CORRECTION (blocker #1): getbootstrapinfo presence is NOT a compatibility signal —
    // it exists only in the freshly-built bundled daemon, and every released/healthy
    // daemon returns RPC_METHOD_NOT_FOUND for it. So this method ALWAYS ATTACHES on a
    // getinfo success; the getbootstrapinfo probe is ADVISORY only (it refreshes
    // heal/daemonHasBootstrapRpc for richer warmup progress on BOTH callbacks) and NEVER
    // blocks or refuses to attach. A genuinely stuck/peerless foreign node is handled at
    // RUNTIME by the sync poller (rpc.cpp -> MainWindow::showForeignNodeStuck()).
    void classifyForeignDaemon(Connection* connection);

    // Bob-fix: drive a MOVING bootstrap-progress sub-status off getbootstrapinfo, which
    // is WARMUP-EXEMPT (it answers DURING the multi-GB snapshot download/verify, when
    // plain getinfo is still blocked -28). Fires one async getbootstrapinfo on the given
    // Connection and, when it lands, maps phase/percent/verify_pending onto the splash:
    //   phase=="active" + percent      -> "Step 3 of 3: Downloading blockchain — X%"
    //   verify_pending / phase succeeded -> "Step 3 of 3: Verifying blockchain… (indeterminate)
    // Callable from BOTH polling paths (the doAutoConnect connection-refused lambda and
    // the getinfo -28 warmup branch) so the download/verify window is never a frozen line.
    // DEGRADES GRACEFULLY: any error (older daemon -> RPC_METHOD_NOT_FOUND) is ADVISORY —
    // it latches the tri-state cache and silently falls back to the caller's static text,
    // never a blocker. Non-blocking: it does NOT change polling cadence and is safe to call
    // every poll. Captures the shared ezAlive token so a late reply can't touch a freed
    // loader. Returns immediately; the splash is updated when the reply arrives.
    void probeBootstrapProgress(Connection* connection);
    // Double-launch guard. True iff BOTH the RPC port (config->port) and the matching
    // P2P port (8033 mainnet / 18033 testnet) on 127.0.0.1 are currently unbound.
    bool portsFree(std::shared_ptr<ConnectionConfig> config);

    void showError(QString explanation);
    void showInformation(QString info, QString detail = "");

    void doRPCSetConnection(Connection* conn);

    // P1-2 / P1-7 idiotproof-onboarding helpers
    bool ensureEnoughDiskSpace(const QString& path);
    void setBarPercent(int pct);
    void offerRetry(QString explanation, std::function<void(void)> cb);

    // P2-1: corruption failsafe. When the embedded node dies DURING warmup
    // (before the RPC connection is established) we classify the failure from
    // its stderr + debug.log tail and, if it looks like a corrupt/partway block
    // or chainstate database, offer a safe, staged repair ladder. NONE of these
    // paths ever touch wallet.dat except to read+copy it as a backup.
    bool        ezNodeQuitDuringStartup = false;  // node exited before RPC came up
    bool        ezRepairOffered         = false;  // repair dialog already shown this run
    QString     ezStdErr;                          // accumulated node stderr this run
    QString     ezDataDir;                         // datadir holding blocks/chainstate/debug.log/wallet.dat

    // Item 3 (legible first-run param wait). The daemon peer-fetches ~1.7GB of zk-params
    // in ZC_LoadParams BEFORE it binds its RPC port, so for 10-20 min on a fresh install
    // the port is fully REFUSING and getbootstrapinfo can't answer yet. We latch this the
    // moment verifyParams() reports the params missing (doAutoConnect), so the refused-
    // connection warmup branch can paint the accurate "one-time 1.7GB" copy instead of a
    // frozen "Almost ready" line. Single-run advisory flag; no persistence needed.
    bool        ezParamFetchLikely      = false;  // params were missing at connect -> a peer-fetch is in progress

    void    handleStartupFailure();                       // detect + classify + route
    bool    looksLikeDbCorruption(const QString& text);   // marker scan
    // W4: true if `text` carries ANY marker handleStartupFailure() classifies on; lets
    // us classify on THIS run's stderr alone and skip a stale debug.log tail.
    bool    startupDiagHasMarker(const QString& text);
    QString readDebugLogTail(int maxBytes = 16384);        // read-only tail of debug.log
    void    offerCorruptionRepair();                       // staged repair ladder dialog
    void    relaunchForRepair(const QStringList& extraArgs);  // backup wallet, then relaunch once
    void    redownloadChain();                             // set blocks/chainstate aside, fetch fresh
    bool    backupWalletForRepair();                       // read+copy wallet.dat; never writes it

    // SAFETY GATE for destructive heals: positively confirm NO embedded daemon is
    // alive before mutating the datadir (renaming blocks/chainstate, salvaging
    // wallet.dat). Polls/terminates/kills the QProcess this loader owns; for the
    // manual path it also re-checks the RPC-owned node (which mainwindow stopped
    // first). Returns false if a live daemon can't be confirmed dead — the caller
    // must then ABORT and leave the datadir untouched.
    bool    confirmDaemonDeadForRepair();
    QDir    resolveDataSubdir();                            // datadir root, or testnet3/ when it holds the chain

    // SELF-HEAL classifier additions (all hang off the EXISTING two lifecycle
    // owners — no new controller object). These run only A-side, while this
    // ConnectionLoader still exists; B-side runtime healing stays in RPC.
    //
    // bounded-retry helpers backed by a QSettings ledger (heal/attempts.*).
    // healAttempts()/bumpHealAttempt() centralise the per-edge counters so a
    // hard-broken bundle/anchor/disk can never spin a heavy operation. A
    // successful getinfo (doRPCSetConnection) resets the whole ledger.
    int     healAttempts(const QString& edge);
    void    bumpHealAttempt(const QString& edge);
    bool    healInProgress();                              // global serialize guard
    void    setHealInProgress(bool on);
    void    latchNeedsManual(const QString& reason);       // terminal: stop auto-action, keep manual button
    static void clearHealLedger();                          // wipe heal/* on a clean getinfo

    // EXTRACT_FAILED edge: single-file build couldn't extract/verify its bundled
    // daemon. Delete the stamp dir + .part and re-extract ONCE, else NEEDS_MANUAL.
    void    retryExtractionOnce(const QString& diag);

    // WARMUP_WEDGED watchdog (A-side). Fires ONLY when the node is alive, stuck on
    // an RPC -28 warmup string whose status + percent have not advanced for a long
    // stretch, and NOT during an active bootstrap-snapshot download. Offers a CLEAN
    // restart (not a heal): the daemon resumes from its persisted index.
    void    handleWarmupWedged();
    QString ezLastWarmupStatus;                            // last seen -28 message
    int     ezLastWarmupPct = -1;                          // last parsed % (or -1)
    QElapsedTimer ezWarmupNoProgress;                      // since status/% last changed

    // W1: the WARMUP_WEDGED watchdog must NEVER fire while the CURRENT launch is an
    // expected-to-be-long REPAIR relaunch (-reindex / -reindex-chainstate rebuild the
    // chain DB; the post-redownload fresh start re-validates a freshly fetched chain).
    // Those legitimately sit on a percent-less "Verifying blocks..." / "Activating best
    // chain..." far past the 180s no-progress threshold, so the watchdog would KILL the
    // very repair it just launched (then NEEDS_MANUAL). Set in relaunchForRepair()/
    // redownloadChain(); consulted in the watchdog fire condition. Cleared on a clean
    // RPC (doRPCSetConnection) so a later non-repair run re-arms the watchdog.
    bool    ezRepairRelaunchActive = false;

    // MANUAL-REPAIR entry flag. True ONLY when offerCorruptionRepair() was reached via the
    // user-initiated Help -> Repair path (startManualRepair), NOT via a startup failure. In
    // that case the node was healthy and was stopped by launchBlockchainRepair() BEFORE the
    // dialog, so "Not now" means "I changed my mind" — we must relaunch the node, never show
    // the startup-failure "couldn't finish starting up" message (which would be a lie + a
    // dead-end on a node the user deliberately had running).
    bool    ezManualRepair = false;

    // USER-QUIT-DURING-SPLASH guard. While the ApplicationModal connect dialog 'd'
    // is up (slow pre-connect startup), the main window's WM-close is swallowed by
    // the modal grab, so a genuine user dismiss of 'd' (title-bar X / Esc) is the
    // only quit gesture available. We hook d's rejected() (loadConnection) to stop
    // the loader-owned embedded node and qApp->quit(). This flag is set true ONLY
    // around the single programmatic close that also reaches reject() (showError's
    // d->close()), so that code-driven abort does NOT quit the app. done(Accepted)
    // (success) and every d->hide() never emit rejected(), so they need no guard.
    bool        ezProgrammaticClose = false;

    // True for any warmup status that is a known long, percent-less phase during which
    // the watchdog must stay quiet even on a NORMAL (non-repair) start.
    static bool isLongWarmupPhase(const QString& status);

    // W2: ConnectionLoader is NOT a QObject, so QPointer can't guard async callbacks.
    // doRPCSetConnection() runs 'delete this' while a getbootstrapinfo probe may still
    // be in flight on the Connection (which OUTLIVES the loader — it is handed to rpc).
    // A shared 'alive' token, captured by value into the probe lambda, lets the callback
    // detect that the loader was destroyed (use_count drops to 1 / the bool is false)
    // and bail before touching any freed member. Reset/destroyed in the destructor.
    std::shared_ptr<bool> ezAlive = std::make_shared<bool>(true);

    // Optional getbootstrapinfo enrichment: tri-state cache so an old daemon is
    // probed at most once. -1 unknown, 0 absent, 1 present.
    int     ezBootstrapRpcProbed = -1;

    // Edit #2 (blocker #2): bounded counter for the getinfo error handler's CATCH-ALL
    // branch (any QNetworkReply error not otherwise handled, incl. an InternalServerError
    // whose body did not parse). For the first kMaxUnexpectedErrPolls polls we re-schedule
    // silently (transient/odd warmup states recover); past that we surface the actionable
    // retry instead of dead-ending at a frozen connect dialog. Reset on any healthy getinfo.
    int     ezUnexpectedErrPolls = 0;

    // G7: cache of the most recent getbootstrapinfo poll, so the WARMUP_WEDGED
    // watchdog can suppress itself during a multi-MINUTE post-bootstrap UTXO verify
    // (which shows a FROZEN "Verifying blocks..." status with no percent). Relying on
    // the "Bootstrap snapshot:" substring alone would let the watchdog kill a healthy
    // node mid-verify. Suppress whenever phase is active/succeeded, verify_pending is
    // true, or the validation state begins with "provisional".
    QString ezBootstrapPhase;                              // last getbootstrapinfo "phase"
    bool    ezBootstrapVerifyPending = false;              // last getbootstrapinfo "verify_pending"
    QString ezBootstrapValidationState;                    // bootstrap_validation/validation "state"
    // True iff the cached state means "the daemon is busy with bootstrap/verify and a
    // frozen warmup string is EXPECTED" — computed where the cache is updated.
    bool    bootstrapSuppressesWedge() const;

    // Single-file release support: when no sibling daemon ships next to the GUI,
    // the node is appended to our OWN executable (GUI | daemon | sha256 | len | magic).
    // Extract+verify it to a per-user cache and return its absolute path; returns
    // an empty string (-> caller falls back) when there is no embedded payload,
    // on a hash mismatch, or on macOS (notarization forbids exec of an extracted file).
    QString ensureDaemonExtracted();

    QProcess*               ezclassicd  = nullptr;
    QElapsedTimer           ezWarmupTimer;   // measures embedded-node startup/warmup time

    QLabel*                 ezCard      = nullptr;   // one-time onboarding explainer card
    QProgressBar*           ezProgress  = nullptr;   // onboarding progress indicator
    int                     ezRetryCount = 0;        // consecutive param-download retries

    QDialog*                d;
    Ui_ConnectionDialog*    connD;

    MainWindow*             main;
    RPC*                    rpc;

    QNetworkReply* currentDownload = nullptr;
    QFile*         currentOutput   = nullptr;
    QQueue<QUrl>*  downloadQueue   = nullptr;

    QNetworkAccessManager* client  = nullptr; 
    QTime downloadTime;
};

/**
 * Represents a connection to a zclassicd. It may even start a new zclassicd if needed.
 * This is also a UI class, so it may show a dialog waiting for the connection.
*/
class Connection {
public:
    Connection(MainWindow* m, QNetworkAccessManager* c, QNetworkRequest* r, std::shared_ptr<ConnectionConfig> conf);
    ~Connection();

    QNetworkAccessManager*              restclient;
    QNetworkRequest*                    request;
    std::shared_ptr<ConnectionConfig>   config;
    MainWindow*                         main;

    void shutdown();

    void doRPC(const json& payload, const std::function<void(json)>& cb, 
               const std::function<void(QNetworkReply*, const json&)>& ne);
    void doRPCWithDefaultErrorHandling(const json& payload, const std::function<void(json)>& cb);
    void doRPCIgnoreError(const json& payload, const std::function<void(json)>& cb) ;

    void showTxError(const QString& error);

    // Batch method. Note: Because of the template, it has to be in the header file.
    template<class T>
    void doBatchRPC(const QList<T>& payloads,
                     std::function<json(T)> payloadGenerator,
                     std::function<void(QMap<T, json>*)> cb) {
        auto responses = new QMap<T, json>(); // zAddr -> list of responses for each call.
        int totalSize = payloads.size();
        if (totalSize == 0) {
            // N==0: nothing to fetch. Honour the contract (caller still expects its
            // cb with an allocated, empty map it then owns + deletes) and avoid a
            // leak of `responses`. Queue it to the GUI thread so the call always
            // returns to the caller first, exactly like the populated path below.
            QTimer::singleShot(0, main, [=]() {
                if (shutdownInProgress) {
                    delete responses;
                    return;
                }
                cb(responses);
            });
            return;
        }

        // PERF (Phase 4 Win 1): replace the old 100ms QTimer completion-poll with an
        // atomic completion COUNTER. Every reply's finished() lambda increments it on
        // BOTH the success AND the error branch; the lambda that takes the count to
        // totalSize fires cb() exactly once. This removes up to 100ms of dead latency
        // per batch (doubled where batches chain, e.g. refreshReceivedZTrans's
        // z_listreceivedbyaddress -> gettransaction).
        //
        // THREAD-SAFETY: QNetworkAccessManager delivers every finished() signal on the
        // GUI thread (the same thread this method runs on — `restclient` lives there and
        // these are direct-connected auto signals), so these lambdas never run
        // concurrently. A plain int behind a shared_ptr (captured by value, so it
        // outlives this stack frame) is therefore sufficient; no real atomics needed.
        auto completed = std::make_shared<int>(0);

        // Keep track of all pending method calls, so as to prevent
        // any overlapping calls
        static QMap<QString, bool> inProgress;

        QString method = QString::fromStdString(payloadGenerator(payloads[0])["method"]);
        inProgress[method] = true;

        // Single place that records one finished reply and, on the LAST one, fires cb.
        // Must be called on EVERY terminal path of EVERY reply (success, network error,
        // discarded body, shutdown) so the batch can never be left forever-incomplete.
        auto finishOne = [=]() {
            if (++(*completed) < totalSize)
                return;

            // Last reply just landed. Hand off to the caller. Queue to the GUI thread
            // (singleShot(0)) so we first unwind out of this finished() slot before the
            // caller's cb runs — cb may itself start another batch / delete objects,
            // and leaving the slot first keeps that re-entrancy safe, matching the old
            // timer-driven behaviour where cb never ran inside a reply's slot.
            inProgress[method] = false;
            QTimer::singleShot(0, main, [=]() {
                if (shutdownInProgress) {
                    delete responses;   // caller's cb would have owned + freed it
                    return;
                }
                cb(responses);
            });
        };

        for (auto item: payloads) {
            json payload = payloadGenerator(item);

            QNetworkReply *reply = restclient->post(*request, QByteArray::fromStdString(payload.dump()));

            QObject::connect(reply, &QNetworkReply::finished, [=] {
                reply->deleteLater();
                if (shutdownInProgress) {
                    // Shutdown in progress: still COUNT this reply so the batch can
                    // complete (finishOne sees shutdownInProgress and frees the map
                    // instead of calling cb). Without counting here a mid-shutdown
                    // reply would strand the batch and leak `responses`.
                    finishOne();
                    return;
                }

                auto all = reply->readAll();
                auto parsed = json::parse(all.toStdString(), nullptr, false);

                if (reply->error() != QNetworkReply::NoError) {
                    qDebug() << QString::fromStdString(parsed.dump());
                    qDebug() << reply->errorString();

                    (*responses)[item] = json::object();    // Empty object
                } else {
                    if (parsed.is_discarded()) {
                        (*responses)[item] = json::object();    // Empty object
                    } else {
                        (*responses)[item] = parsed["result"];
                    }
                }

                // CRITICAL: count this reply on EVERY non-shutdown path too (both the
                // error and success branches above fall through to here). Missing this
                // on any error branch would leave the batch one-short forever (hang).
                finishOne();
            });
        }
    }

private:
    bool shutdownInProgress = false;    
};

#endif
