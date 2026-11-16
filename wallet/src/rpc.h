#ifndef RPCCLIENT_H
#define RPCCLIENT_H

#include "precompiled.h"

#include "balancestablemodel.h"
#include "txtablemodel.h"
#include "ui_mainwindow.h"
#include "mainwindow.h"
#include "connection.h"
#include "notifyserver.h"

using json = nlohmann::json;

class Turnstile;

struct TransactionItem {
    QString         type;
    qint64            datetime;
    QString         address;
    QString         txid;
    double          amount;
    unsigned long   confirmations;
    QString         fromAddr;
    QString         memo;
};

struct WatchedTx {
    QString opid;
    Tx tx;
    std::function<void(QString, QString)> completed;
    std::function<void(QString, QString)> error;
};

class RPC
{
public:
    RPC(MainWindow* main);
    ~RPC();

    void setConnection(Connection* c);
    void setEZClassicd(QProcess* p);
    const QProcess* getEZClassicD() { return ezclassicd; }

    // The localhost-only, token-gated push trigger (NOTIFY-SRV). Constructed (and the
    // per-session token minted) ONLY for a non-headless session; null in headless/CLI.
    // The socket is started, and notified() wired, ONLY for the node WE launch (the
    // owned-daemon path) — a foreign/systemd daemon never reaches that wiring, so it
    // keeps the timer poll. See startEmbeddedZClassicd()/setEZClassicd().
    NotifyServer* getNotifyServer() { return notifyServer; }

    void refresh(bool force = false);

    void refreshAddresses();    
    
    void checkForUpdate(bool silent = true);
    void refreshZCLPrice();

    void executeTransaction(Tx tx, 
        const std::function<void(QString opid)> submitted,
        const std::function<void(QString opid, QString txid)> computed,
        const std::function<void(QString opid, QString errStr)> error);

    void fillTxJsonParams(json& params, Tx tx);
    void sendZTransaction(json params, const std::function<void(json)>& cb, const std::function<void(QString)>& err);
    void watchTxStatus();

    const QMap<QString, WatchedTx> getWatchingTxns() { return watchingOps; }
    void addNewTxToWatch(const QString& newOpid, WatchedTx wtx); 

    const TxTableModel*               getTransactionsModel() { return transactionsTableModel; }
    const QList<QString>*             getAllZAddresses()     { return zaddresses; }
    const QList<QString>*             getAllTAddresses()     { return taddresses; }
    const QList<UnspentOutput>*       getUTXOs()             { return utxos; }
    const QMap<QString, double>*      getAllBalances()       { return allBalances; }
    const QMap<QString, bool>*        getUsedAddresses()     { return usedAddresses; }

#ifdef ZCL_WIDGET_TEST
    // TEST-ONLY SEAMS (L1 widget tests). Compiled in ONLY under ZCL_WIDGET_TEST;
    // NEVER in the shipped app. Install balances/z-address state so confirmTx() and
    // createTxFromSendPage() (PRIV-10 change routing) run in-process without a live
    // daemon. testSetZAddresses lets the PRIV-10 fail-open test control whether a
    // Sapling change-sink exists.
    void testSetBalances(QMap<QString, double>* b) { delete allBalances; allBalances = b; }
    void testSetZAddresses(QList<QString>* z)       { delete zaddresses; zaddresses = z; }
    void testSetTAddresses(QList<QString>* t)       { delete taddresses; taddresses = t; }
    // Install the wallet's UTXO set so confirmedSpendableZat() (the confirmed,
    // non-coinbase change basis) can be driven without a daemon.
    void testSetUTXOs(QList<UnspentOutput>* u)      { delete utxos; utxos = u; }
    // SAFE-RACE: install the "fresh" transparent set the NEXT repollTransparentUnspent()
    // splices in (simulates a UTXO landing/leaving at the from-addr during the confirm
    // dwell). One-shot: consumed by the re-poll. Never present in the shipped app build.
    void testSetRepollUTXOs(QList<UnspentOutput>* u) { delete testRepollUTXOs; testRepollUTXOs = u; }
    // MAJOR-3: control the result of the next newZaddr(true) sync-create. A non-empty
    // string makes the create SUCCEED (returns that address); leaving it empty makes
    // the create FAIL (callback never fires), exercising the fail-closed path. The
    // string is consumed (one-shot) so a subsequent create with no fresh value fails.
    void testSetNextZaddrResult(const QString& addr) { testNextZaddrResult = addr; }
    // MINOR-1: install a sentinel Connection so the readiness guard in
    // shieldPublicFunds()/ensureSaplingProvisioned() (which mirrors the real
    // "connection up?" check) is satisfied in-process without a live daemon. The
    // installed Connection is never actually USED on these paths (the seeded
    // Sapling address resolves first), only its non-null-ness is checked.
    void testSetConnection(Connection* c) { conn = c; }
    // NOTIFY-SRV (1.3) real-seam: drive the ACTUAL onNotifyPush()/notifyDebounce
    // (not a stand-in) so a regression in the production wiring is caught.
    void testFireNotifyPush() { onNotifyPush(); }
    bool testNotifyDebounceActive() const { return notifyDebounce && notifyDebounce->isActive(); }

    // PERF harness seam (perf16_modelJank). Each call to updateUI() (under
    // ZCL_WIDGET_TEST) appends the wall-clock nanoseconds the balances-model
    // setNewData() rebuild took to this vector; the perf slot reads it to compute
    // p50/p95/p100. Entirely absent from the shipped app build (guard is compile-time).
    QVector<qint64>& testBalanceModelSamplesNs() { return balanceModelSamplesNs; }
    // Drive the REAL updateUI() path directly (no daemon) so the perf harness can
    // repeatedly re-run the balances-model rebuild over a seeded large dataset. The
    // anyUnconfirmed arg is forwarded straight through.
    void testUpdateUI(bool anyUnconfirmed) { updateUI(anyUnconfirmed); }
#endif

    // SAFE-RACE: synchronously-driven re-poll of ONLY the transparent UTXOs, spliced into
    // the cached `utxos` WITHOUT dropping the shielded-note rows. Fires the async
    // listunspent (production) or applies an injected test set, and invokes cb(true) once
    // fresh data has landed. Returns false (and cb(false)) when it could not fire (no
    // connection / no test seam), so the caller fails closed. See verifyAutoShieldUnchanged.
    bool repollTransparentUnspent(const std::function<void(bool)>& cb);

    void newZaddr(bool sapling, const std::function<void(json)>& cb);
    void newTaddr(const std::function<void(json)>& cb);

    void getZPrivKey(QString addr, const std::function<void(json)>& cb);
    void getTPrivKey(QString addr, const std::function<void(json)>& cb);
    void importZPrivKey(QString addr, bool rescan, const std::function<void(json)>& cb);
    void importTPrivKey(QString addr, bool rescan, const std::function<void(json)>& cb);

    void shutdownZClassicd();

    // Called from QCoreApplication::aboutToQuit, i.e. on EVERY quit route -- window
    // close, File->Exit, SIGINT, AND the macOS app-menu "Quit" / Cmd-Q, which calls
    // QApplication::quit() directly and bypasses MainWindow::closeEvent()/
    // shutdownZClassicd(). Marks the shutdown as expected and stops the pollers so the
    // async RPC handlers never flash a spurious "error connecting to zclassicd" dialog
    // while the embedded node is being torn down.
    void onAboutToQuit();

    // SAFETY GATE for the manual Help -> Repair path: positively confirm the
    // RPC-owned embedded node is NOT running before any datadir mutation. Polls
    // state(); if still alive, terminate() + waitForFinished, then escalate to
    // kill() + waitForFinished. Returns true only when confirmed NotRunning (or
    // there is no embedded node / it's an external daemon we don't own). The 30s
    // soft cap in shutdownZClassicd() means "quit promptly", NOT "confirmed
    // exited", so the repair path must call this before touching blocks/chainstate.
    bool confirmEmbeddedStopped();

    // preserveBalances=true => SOFT disconnect: keep the last-painted balance labels
    // and tables, just de-confidence the hero to the WARMING "refreshing" state. Used
    // by the debounced getinfo error path so a single failed poll never blanks a
    // funded wallet. Default false keeps every existing caller's full-teardown behavior.
    void noConnection(bool preserveBalances = false);
    bool isEmbedded() { return ezclassicd != nullptr; }

    // ---- NOTIFY-SRV push-wiring pure helpers (used by prod + asserted by L1) ----
    // Build the two daemon notify args (-walletnotify / -blocknotify) that invoke THIS
    // exe's `--notify %s` connector. The exe path is QUOTED (it may contain spaces);
    // `%s` is OUTSIDE the quotes so the daemon substitutes the txid/blockhash. NO token
    // ever rides the command line (it lives in a 0600 file) -- the L1 test asserts the
    // args carry no 64-hex token. Static + pure so a test can assert it without a daemon.
    static QStringList buildNotifyArgs(const QString& exePath);

    // Decide the refresh poll interval. While a healthy push channel is delivering
    // notifies we back the timer WAY off (heartbeat only); when push is stale/absent
    // (foreign/headless or the channel went quiet) we keep the existing 20s/5s poll.
    // Static + pure so the decision is unit-tested without an RPC/timer/daemon.
    static int desiredPollMs(bool isSyncing, bool pushHealthy);

    // Push-channel tuning. kHeartbeatPollMs: the slow poll used while push is healthy
    // (a sanity heartbeat, not the primary update path). kPushHealthyWindowSecs: how
    // recent the last validated notify must be for the channel to count as "healthy"
    // (PERF-5: auto-resume the 20s poll when the channel goes stale).
    static constexpr int   kHeartbeatPollMs       = 120 * 1000;   // 120 sec
    static constexpr qint64 kPushHealthyWindowSecs = 180;          // 3 min
    // Debounce window: coalesce a notify BURST (a block + its wallet txns all fire at
    // once) into a single refresh shortly after the quiet point.
    static constexpr int   kNotifyDebounceMs      = 200;

    QString getDefaultSaplingAddress();
    QString getDefaultTAddress();

    void getAllPrivKeys(const std::function<void(QList<QPair<QString, QString>>)>);

    Turnstile*  getTurnstile()  { return turnstile; }
    Connection* getConnection() { return conn; }

private:
    void refreshBalances();

    void refreshTransactions();    
    void refreshSentZTrans();
    void refreshReceivedZTrans(QList<QString> zaddresses);

    bool processUnspent     (const json& reply, QMap<QString, double>* newBalances, QList<UnspentOutput>* newUtxos);
    // SAFE-RACE: build a new owned list = the shielded-note rows kept from `oldUtxos`
    // (classified by !Settings::isTAddress) + every row of `freshT` (the re-polled
    // transparent set). Frees both inputs. Used by repollTransparentUnspent so a
    // transparent-only re-poll never drops the wallet's z-notes.
    QList<UnspentOutput>* mergeTransparentUnspent(QList<UnspentOutput>* oldUtxos,
                                                  QList<UnspentOutput>* freshT);
    void updateUI           (bool anyUnconfirmed);

    void getInfoThenRefresh(bool force);

    // Deliverable A: read-only refresh of the "you're helping the network" panel
    // (MainWindow::netHelp* labels) from getnetworkinfo + getpeerinfo. `connections`
    // is passed from the enclosing getinfo poll. Never mutates node state; both inner
    // calls are error-ignoring so an old/foreign/warming daemon degrades silently.
    void refreshNetworkHelpPanel(int connections);

    // NOTIFY-SRV: handle a validated push (NotifyServer::notified). Records the epoch
    // (so getInfoThenRefresh's interval picker sees the channel as healthy) and
    // (re)starts the single-shot debounce; the debounce timeout runs refresh(TRUE).
    void onNotifyPush();

    // RUNTIME STUB AUTO-HEAL: evaluate (conservatively) whether the live node is a
    // healthy-but-stuck STUB — it started fine, loaded a tiny non-genesis chain from an
    // aborted P2P sync, and now finds 0 peers — and, if so, route into the SAME
    // redownloadChain() ladder the manual Help -> Repair uses (via
    // MainWindow::autoHealStubChain). Called from the getblockchaininfo sync poll only
    // when (isSyncing && connections==0 && ezNoPeerPolls>=3). Fires ONLY when ALL hold:
    //   (1) connections == 0 sustained well past the banner (ezNoPeerPolls >= 12, ~60s
    //       at the 5s syncing cadence);
    //   (2) the on-disk blocks/ store is unambiguously a STUB — its total size is below
    //       a hard 1 GiB floor (a synced chain is ~10 GiB; a stub is tens of MB),
    //       measured via ConnectionLoader::blocksDirSizeBytes from the active datadir.
    //       A large blocks/ (a fully-synced node that is merely OFFLINE) is NEVER
    //       wiped — that is the dangerous lookalike;
    //   (3) it has NOT already auto-redownloaded this run (ezStubAutoHealTried) AND the
    //       persisted per-install cooldown (rpc/stubHeal.count, capped) is not exhausted,
    //       so a genuinely peerless environment can't loop wipe->rebootstrap->wipe.
    // Never fires for an external daemon we don't own, or when blocks/ can't be measured.
    // Returns true ONLY if it actually launched a heal (the caller then suppresses the
    // peerless banner for this tick).
    bool maybeAutoHealStubChain(int connections);

    // Async getbootstrapinfo poll (warmup-EXEMPT) that refreshes the ezBootstrap*
    // cache; fired from the peerless path so an in-progress bootstrap-snapshot
    // download is shown as "Downloading blockchain snapshot — X%" instead of
    // "waiting for peers", and so the stub-heal never wipes a live download.
    void pollBootstrapSnapshotStatus();

    // Once-per-process latch so the runtime stub auto-heal launches at most one
    // re-download per app run; combined with the persisted cooldown below.
    bool                        ezStubAutoHealTried         = false;
    // Once-per-session latch for clearing the persisted per-install stub-heal cap on
    // the first peered poll (so we don't rewrite QSettings every tick).
    bool                        ezStubHealCooldownCleared   = false;

    void getBalance(const std::function<void(json)>& cb);

    // INSTANT-BALANCE fast path: one getwalletsummary call returns the wallet's
    // transparent + private (shielded) totals in a single round-trip (no per-address
    // listunspent join), letting the hero balance paint instantly on connect. The
    // success cb receives the raw summary json; the err cb receives the parsed
    // JSON-RPC body so the caller can detect -32601 ("Method not found") on an OLD
    // daemon that lacks the method and latch summaryCapable=false. KEY-1: this reads
    // ONLY balance numbers — no key material is ever returned, serialized, or logged.
    void getWalletSummary(const std::function<void(json)>& cb,
                          const std::function<void(const json&)>& err);

    void getTransparentUnspent  (const std::function<void(json)>& cb, const std::function<void(void)>& err);
    void getZUnspent            (const std::function<void(json)>& cb, const std::function<void(void)>& err);
    void getTransactions        (const std::function<void(json)>& cb);
    void getZAddresses          (const std::function<void(json)>& cb);
    void getTAddresses          (const std::function<void(json)>& cb);

    // Runtime daemon-crash recovery: catch the embedded node dying at runtime
    // (OOM/crash) and offer to restart it instead of stranding the user in a
    // permanent "No Connection". ezExpectedShutdown gates the normal-shutdown
    // path; ezRestartCount caps automatic restarts.
    void handleEZClassicdCrash(int exitCode, QProcess::ExitStatus status);
    void restartEmbeddedZClassicd();   // relaunch the dead node, stripping repair flags
    bool                        ezExpectedShutdown          = false;
    bool                        ezCrashDialogOpen           = false;
    int                         ezRestartCount              = 0;
    QMetaObject::Connection     ezCrashConn;

    // Re-entrancy guard for shutdownZClassicd(): the shutdown wait spins a nested
    // event loop (and the "please wait" dialog is non-modal for the first 700ms),
    // so the main window stays live. This latch makes a second Quit / window-close
    // during that window a no-op instead of stacking a second nested loop. It
    // serializes re-entrancy WITHIN one shutdown only: it is cleared at every exit
    // of shutdownZClassicd() and when setEZClassicd() adopts a fresh live node, so
    // it never latches for the process lifetime (a later restart can shut down too).
    bool                        ezShuttingDown              = false;

    // C2/F5: once we've legitimately confirmed the chain tip (blocks>=headers with
    // peers) this latch keeps us "synced" through brief peer drops so an established
    // wallet doesn't flicker back to "syncing".
    bool                        ezEverSynced                = false;

    // C9/F6: debounce the waiting-for-peers banner; a single connections==0 sample
    // shouldn't flip the banner. Counts consecutive peerless polls; reset on a peer.
    int                         ezNoPeerPolls               = 0;

    // transient-disconnect debounce: a SINGLE failed getinfo poll (one dropped
    // reply, a momentary RPC stall) must NOT wipe a funded wallet's hero to grey
    // "0 ZCL" and demote Send. Counts consecutive getinfo error replies; reset to 0
    // on any successful getinfo. The error path keeps the last balances painted
    // (soft disconnect) until this crosses the threshold, then does a full teardown.
    int                         getInfoErrCount             = 0;

    // Cached getbootstrapinfo snapshot-download state (post-connect). A node mid
    // bootstrap-snapshot download reports 0 normal P2P peers + warming RPC, which the
    // peerless banner/heal would otherwise mislabel as "waiting for peers" (and could
    // even wipe it as an abandoned stub). pollBootstrapSnapshotStatus() refreshes this
    // async; the peerless path reads it so an active download shows real progress and
    // is never healed.
    bool                        ezBootstrapActive           = false;
    int                         ezBootstrapPct              = 0;
    qint64                      ezBootstrapRecv             = 0;
    qint64                      ezBootstrapTotal            = 0;
    double                      ezBootstrapMbps             = 0.0;

    // Edit #6 (bob-fix): once-per-run guard for MainWindow::showForeignNodeStuck(). The
    // poller fires that actionable dialog EXACTLY ONCE when an ATTACHED FOREIGN node
    // (ezclassicd == nullptr — NOT one we launched) has been peerless/stuck for a
    // sustained window. An OWNED embedded node (it self-heals + has bootstrap peers) and a
    // FOREIGN node that has peers / is syncing/synced NEVER trigger it. This bool keeps it
    // from re-showing every poll.
    bool                        ezForeignStuckShown         = false;

    // W1-4: SUSTAINED-timeout gate for the foreign-node-stuck dialog. The poll-count
    // gate (ezNoPeerPolls) alone can be reached quickly if the sync cadence is fast,
    // false-firing the dialog during a legitimate multi-minute first-run warmup where
    // a foreign node is briefly peerless. Require the peerless condition to ALSO have
    // persisted for a wall-clock window (~120s, mirroring the connection.cpp warmup
    // patience) before surfacing it. Started on the first peerless sample, invalidated
    // the moment any peer appears.
    QElapsedTimer               ezForeignStuckSince;

    // G6: the warmup-wedge cap (heal/attempts.warmupRestart) must only be cleared by
    // SUSTAINED health, never by one getinfo — otherwise a node that answers a single
    // getinfo and then re-wedges would reset the counter forever and never escalate
    // to NEEDS_MANUAL. clearHealLedger() (one getinfo) intentionally leaves
    // warmupRestart alone; we clear it here only after several consecutive healthy
    // sync polls OR after the chain tip has demonstrably advanced past warmup.
    int                         ezHealthyPolls              = 0;
    bool                        ezWarmupWedgeCleared        = false;

    // INSTANT-BALANCE daemon-capability gate. We assume the connected daemon supports
    // getwalletsummary — the single-round-trip total (read from the daemon's cached
    // note values, no per-note re-decrypt) used to paint the hero balance fast on
    // every refresh. When true, getwalletsummary {0} is the SOLE hero source and the
    // slow z_gettotalbalance is skipped; when false z_gettotalbalance is the SOLE
    // source instead. The FIRST refreshBalances() this session doubles as the version
    // probe: if getwalletsummary returns JSON-RPC -32601 ("Method not found") — i.e.
    // an OLD daemon — this latches to false and we NEVER call it again this session,
    // falling back EXACTLY to the legacy z_gettotalbalance path. Any OTHER (transient)
    // summary error does NOT latch; that cycle paints from z_gettotalbalance and the
    // next poll retries the summary. getwalletsummary {0} and z_gettotalbalance {0}
    // return the same satoshi totals, so the displayed number is identical regardless
    // of source. The per-address listunspent join remains the sole owner of the
    // per-address balances model / UTXO set and never touches the hero labels.
    bool                        summaryCapable              = true;

    Connection*                 conn                        = nullptr;
    QProcess*                   ezclassicd                     = nullptr;

    // NOTIFY-SRV push trigger. Owned by RPC (constructed in the ctor for a non-headless
    // session; stopped in shutdownZClassicd()/onAboutToQuit and stop()+delete in ~RPC).
    // Null in headless/CLI and never started/wired for a foreign daemon.
    NotifyServer*               notifyServer                = nullptr;
    // Epoch (secs) of the last validated push; 0 = none this session. Drives the
    // push-healthy window in getInfoThenRefresh()'s interval picker.
    qint64                      lastNotifyEpoch             = 0;

    QList<UnspentOutput>*       utxos                       = nullptr;
    QMap<QString, double>*      allBalances                 = nullptr;
    QMap<QString, bool>*        usedAddresses               = nullptr;
    QList<QString>*             zaddresses                  = nullptr;
    QList<QString>*             taddresses                  = nullptr;
    
    QMap<QString, WatchedTx>    watchingOps;

    TxTableModel*               transactionsTableModel      = nullptr;
    BalancesTableModel*         balancesTableModel          = nullptr;

    QTimer*                     timer;
    QTimer*                     txTimer;
    QTimer*                     priceTimer;
    // Single-shot debounce for NOTIFY-SRV pushes (kNotifyDebounceMs). Same
    // ownership/cleanup pattern as timer/txTimer (parented to main, deleted in ~RPC,
    // stopped in onAboutToQuit).
    QTimer*                     notifyDebounce;

    Ui::MainWindow*             ui;
    MainWindow*                 main;
    Turnstile*                  turnstile;

    // Current balance in the UI. If this number updates, then refresh the UI
    QString                     currentBalance;

    // W1-3: defer the price/update fetch out of the connect critical path. The
    // first checkForUpdate() after launch must NOT pop the update-available modal
    // on top of the freshly-opened window (it stalls perceived startup). The modal
    // is suppressed exactly once — the version is recorded so a LATER check still
    // surfaces it (and a non-silent, user-initiated Help->Check still always shows).
    bool                        firstUpdateCheckDone        = false;

    // W1-6: throttle the sent-z confirmation refresh. Cache the last-seen
    // confirmation count per sent-z txid; once a tx is deeply confirmed
    // (>= kDeepConfirmations) we stop re-querying gettransaction for it and reuse
    // the cached deep count, re-batching only the shallow/unconfirmed subset.
    QMap<QString, long>         sentZConfCache;
    static constexpr long       kDeepConfirmations          = 10;
    // W1-6 reorg safety: the chain height the cache reflects. A backward move => reorg
    // => drop the cache so a deep-confirmed row can't keep showing a stale (too-high)
    // confirmation count after the chain rewinds.
    int                         sentZConfCacheHeight        = 0;

#ifdef ZCL_WIDGET_TEST
    // MAJOR-3 test seam backing store: the address the next newZaddr(true) returns
    // (one-shot). Empty => the sync-create fails (fail-closed path). Never present
    // in the shipped app build.
    QString                     testNextZaddrResult;
    // PERF harness backing store: per-update nanoseconds spent in the balances-model
    // rebuild inside updateUI(). Filled only under ZCL_WIDGET_TEST; read by
    // perf16_modelJank. Never present in the shipped build.
    QVector<qint64>             balanceModelSamplesNs;
    // SAFE-RACE backing store: the transparent set the next repollTransparentUnspent()
    // splices in (one-shot). nullptr => the re-poll cannot fire (fail-closed).
    QList<UnspentOutput>*       testRepollUTXOs = nullptr;
#endif
};

#endif // RPCCLIENT_H
