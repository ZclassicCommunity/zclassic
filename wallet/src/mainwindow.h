#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "precompiled.h"
#include "logger.h"

#include <QProgressBar>
#include <QElapsedTimer>
#include <QSharedPointer>

// Forward declare to break circular dependency.
class RPC;
class Settings;
class QSystemTrayIcon;
class QButtonGroup;
class QPushButton;
class QToolButton;
class QWidget;
class QCheckBox;

using json = nlohmann::json;

// Struct used to hold destination info when sending a Tx. 
struct ToFields {
    QString addr;
    double  amount;
    QString txtMemo;
    QString encodedMemo;
};

// Struct used to represent a Transaction.
struct Tx {
    QString         fromAddr;
    QList<ToFields> toAddrs;
    double          fee;

    // Snapshot-race guard. Stamped by createTxFromSendPage()'s auto-shield branch whenever
    // the daemon could emit PUBLIC transparent change at send time -- i.e. an explicit
    // Sapling change output was built (autoShieldFullConsume=false), OR the send consumes the
    // whole confirmed balance with no change (autoShieldFullConsume=true). The pre-send gate
    // (verifyAutoShieldUnchanged) re-polls and ABORTS if the relevant live total no longer
    // matches what we sized against, so a surplus that confirms during the confirm dwell
    // cannot escape as public change. Default-off keeps non-auto-shield sends (z-from, auto-
    // shield off, Sprout recipient) byte-identical: the gate early-returns true, no re-poll.
    // C++14 default member initializers keep Tx an aggregate, so the positional
    // Tx{from, to, fee} brace-inits still compile.
    bool   autoShieldGuardActive = false;  // re-verify before the irrevocable z_sendmany
    bool   autoShieldFullConsume = false;  // true: no-change full balance spend (check total)
    qint64 builtEligibleZat      = 0;      // confirmedSpendableZat(fromAddr,false) at build time
    qint64 builtTargetZat        = 0;      // recipients (excl. change row) + fee, at build time
};

// PRIV-11 / UX-12 — the four-way SendCategory enum + the pure free classifier
// `sendCategoryOf()` are the SINGLE SOURCE OF TRUTH and live in sendcategory.h, so
// BOTH production (MainWindow::classifySend forwards there) AND the L0 unit suite
// link the exact same body (no hand-copied mirror can drift). Included AFTER the
// Tx/ToFields structs above, on which the classifier operates.
#include "sendcategory.h"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void updateLabelsAutoComplete();
    RPC* getRPC() { return rpc; }

    // PRIV-11 / UX-12 — pure, test-readable classifier. Decides the four-way send
    // category from the Tx's from/to address types alone (no widget/RPC state), so
    // both confirmTx() and the L0/L1 tests can call it. See SendCategory above.
    static SendCategory classifySend(const Tx& tx);
    // The strongest-warning de-shield case (z -> t) is the ONLY one that requires
    // the explicit acknowledgement gate (PRIV-12). Small helper kept next to the
    // classifier so the rule lives in exactly one place.
    static bool isDeshield(const Tx& tx) { return isDeshieldSend(tx); }

#ifdef ZCL_WIDGET_TEST
    // TEST-ONLY SEAM (L1 widget tests). Compiled in ONLY when ZCL_WIDGET_TEST is
    // defined (tests/widget/tst_widget.pro). NEVER present in the shipped app
    // build. Exposes the private confirmTx() so the E2 de-shield-warning test can
    // drive the real confirm dialog, and seeds an empty RPC balances map so
    // confirmTx's rpc->getAllBalances() deref is safe without a live daemon.
    bool testConfirmTx(Tx tx)  { return confirmTx(tx); }
    // Drive the REAL snapshot-race gate so the L1 race tests can assert it aborts on a
    // diverging fresh snapshot (injected via RPC::testSetRepollUTXOs) and proceeds otherwise.
    bool testVerifyAutoShield(const Tx& tx) { return verifyAutoShieldUnchanged(tx); }
    void testSeedBalances();
    // Build the send-page Tx through the REAL createTxFromSendPage() path so the
    // L1 fail-open tests (PRIV-10) exercise the actual production routing.
    Tx   testCreateTxFromSendPage() { return createTxFromSendPage(); }
    // Drive the REAL shield flow the Home fix-it button now uses (PRIV-18): set up
    // a t -> default-Sapling send on the Send page exactly as a click would.
    void testShieldPublicFunds()    { shieldPublicFunds(); }
#endif

    QString doSendTxValidations(Tx tx);
    void setDefaultPayFrom();

    void balancesReady();
    void payZClassicURI(QString uri = "");

    // PERF (warm-latency harness, t1 marker). Emitted at the END of
    // updateHomeFixIt() once the privacy-forward HERO labels have been (re)set, i.e.
    // the exact instant the user-visible balance is painted. Production-trivial: a
    // single emit on a signal nobody listens to in the shipped app (zero cost). The
    // L1 perf22 slot connects to it to time t0(onNotifyPush) -> t1(painted).
signals:
    void heroBalancesPainted();

public:

    void updateLabels();
    void updateTAddrCombo(bool checked);
    void updateFromCombo();

    Ui::MainWindow*     ui;

    // ---- Deliverable A: read-only "you're helping the network" panel ----
    // Built in C++ into the existing zclassicd-tab grid (groupBox_5/gridLayout_5)
    // so the checked-in mainwindow.ui / ui_mainwindow.h are untouched (same idiom as
    // connection.cpp's ezCard). All labels are populated by RPC::refreshNetworkHelpPanel
    // from getnetworkinfo + getpeerinfo; nothing here ever writes to the node.
    void        setupNetworkHelpPanel();          // called once from setupZClassicdTab()
    QWidget*    netHelpPanel        = nullptr;     // container row (hidden by opt-out)
    QLabel*     netHelpTitleLabel   = nullptr;     // bold "You're helping the network" heading (hidden by opt-out)
    QLabel*     netHelpStatusLabel  = nullptr;     // "P2P: ON · port 8033 · N peers (M inbound)"
    QLabel*     netHelpReachLabel   = nullptr;     // "Inbound: reachable / not yet"
    QLabel*     netHelpBlurbLabel   = nullptr;     // friendly blurb + how-to link (RichText)
    QCheckBox*  netHelpNatpmpChk     = nullptr;     // "Help the network — open my port automatically" (drives Settings::setOpenPortNatpmp; embedded-gated + honestly enabled/disabled each poll by RPC::refreshNetworkHelpPanel)

    // Phase-3c redesign (Quiet+): private-by-default RECEIVE widgets, built
    // programmatically by setupReceivePrivacyDisclosure(). Public alongside `ui`
    // (the L1 widget tests assert the private-by-default IA through these): the
    // green "Private" resting badge, the "Other address types (advanced)" toggle,
    // and the collapsible panel that hosts the (hidden-at-rest) radios.
    QToolButton*        btnReceiveAdvanced    = nullptr;   // "▸ Other address types (advanced)"
    QWidget*            receiveAdvancedPanel  = nullptr;   // collapsible container for the radios
    QLabel*             lblReceivePrivate     = nullptr;   // green "Private — shielded (z) address" badge
    // Request-amount affordances (the zclassic: payment-URI flow). Built in
    // setupReceivePrivacyDisclosure(); read by updateReceiveQRandPayload/buildReceivePaymentUri.
    QLineEdit*          txtReceiveAmount      = nullptr;   // optional "Request amount"
    QLineEdit*          txtReceiveMemo        = nullptr;   // optional z-only note for the sender
    QPushButton*        btnReceiveCopyRequest = nullptr;   // "Copy payment request" (shown when amount>0)
    bool                receiveAdvancedExpanded = false;

    QLabel*             statusLabel;
    QLabel*             statusIcon;
    QLabel*             loadingLabel;
    QWidget*            zclassicdtab;

    // P0-6: prominent sync banner on the Balance/main tab. Called by rpc.cpp
    // from the getblockchaininfo poll (setSyncStatus) and from noConnection
    // (setSyncStatusConnecting) so a non-technical user always knows the state.
    QWidget*            syncBanner       = nullptr;
    QLabel*             syncStatusLabel  = nullptr;
    QProgressBar*       syncProgressBar  = nullptr;
    // Polish P0-2: quiet inline "● Synced" pill shown at rest (full-width colored
    // banner reserved for syncing/error). Swapped by setSyncStatus().
    QLabel*             syncQuietPill    = nullptr;

    // PR-1 (snappiness): the banner stylesheet is otherwise re-applied on EVERY
    // poll tick (5s during sync) with a byte-identical string, forcing a full
    // QStyleSheetStyle re-parse + unpolish/repolish + relayout of the banner
    // subtree -> a periodic micro-hitch right while the user watches sync
    // progress. applyBannerStyle() caches the last-applied sheet here and only
    // calls setStyleSheet() when it actually changes, so same-state ticks are a
    // no-op. Pure main-thread; no async/lifecycle involvement.
    QString             lastBannerSheet;
    void applyBannerStyle(const QString& sheet);

    void setSyncStatus(bool isSyncing, int blockNumber, int estimatedHeight, double progress);
    void setSyncStatusConnecting();

    // Phase-3b redesign (Quiet+): the modern Home DASHBOARD on the Balance page.
    // updateHomeFixIt() is called from rpc.cpp's refreshBalances() (and the cached-
    // balance restore) on every balance update, mirroring the existing balSheilded/
    // balTransparent/balTotal label-update pattern. It:
    //   * refreshes the privacy-forward HERO (the big "Private balance" number,
    //     read back from balSheilded, with the Total shown secondary), and
    //   * shows/hides the amber "Shield public funds" FIX-IT card: visible ONLY when
    //     transparent > 0, hidden when transparent == 0. The caller already has the
    //     transparent amount (balT) and passes it here rather than re-querying.
    // Public so the RPC poller can call it. No-op until setupHomeDashboard() has run.
    // `fromCache` is true ONLY for the startup cached-balance restore paint; it forces
    // the WARMING (de-confidenced) hero state regardless of the isSyncing flag, which
    // is not yet set on the very first paint. All live callers use the default (false).
    void updateHomeFixIt(double transparent, bool fromCache = false);

    // PRIV-28 eager Sapling provisioning: ensure at least one Sapling z-address
    // exists so the send/shield path never has to block on key generation (the
    // synchronous mid-send create is only a last resort). Idempotent + one-shot per
    // run. Public so the RPC address-refresh path can call it once addresses load.
    void ensureSaplingProvisioned();
    // longStretch=true after a LONG peerless stretch (~3min): adds a stronger
    // "check your internet / try again later" hint (SELF-HEAL SYNCED-ZERO-PEERS).
    void setSyncStatusWaitingForPeers(bool longStretch = false);
    // Bootstrap snapshot download in progress (getbootstrapinfo phase==active): show a
    // determinate "Downloading blockchain snapshot — X%" (with GB + MB/s when known)
    // instead of the misleading "waiting for peers" -- the node is actively
    // downloading, not stuck (it reports 0 normal P2P peers during this phase).
    void setSyncStatusBootstrapSnapshot(int pct, qint64 received, qint64 total, double mbps);

    // SELF-HEAL (B-side) runtime validation surfacing. Non-blocking informational
    // banner reusing the existing syncBanner widget; empty string clears it. Set
    // from the getblockchaininfo poll when the daemon reports bootstrap_validation.
    void setBootstrapValidationBanner(const QString& msg);

    // Non-modal user notification: a system-tray balloon when the tray icon is
    // available (e.g. while running hidden in the background), otherwise a status-
    // bar message. Used so a backgrounded node-crash recovery can inform the user
    // without popping a modal dialog over a hidden window.
    void notify(const QString& title, const QString& body);

    // RUNTIME STUB AUTO-HEAL entry, called from the post-connection sync poller in
    // rpc.cpp ONLY when ALL of its conservative triggers hold (sustained 0 peers AND
    // a stub-sized blocks/ dir AND not already auto-healed this run/cooldown). It is
    // the runtime analogue of Help -> Repair: it reuses the SAME launch path
    // (launchBlockchainRepair -> startManualRepair -> redownloadChain), so every
    // existing safety guard (daemon-dead confirm, wallet.dat backup, disk floor,
    // reversible set-aside) applies. Non-interactive but surfaces a clear status.
    void autoHealStubChain();

    // P0-2 FUND-SAFETY: prompt the user (once per run) to back up wallet.dat. There
    // is no seed phrase for this wallet, so an un-backed-up wallet.dat is permanent,
    // unrecoverable loss. Invoked from rpc.cpp's balance refresh on the first fully-
    // synced poll with a positive balance (a per-run one-shot there avoids re-firing
    // on every poll). Permanently silenced after a successful backup via the
    // persisted options/walletbackedup flag. Public so the RPC poller can call it.
    // Still reachable from the Help menu; the rpc.cpp synced-edge trigger now calls
    // the NON-blocking showBackupNag() (W1-2) instead of this modal.
    void promptWalletBackup();

    // W1-2: surface the non-blocking amber "back up your wallet" Home card. Public so
    // the RPC poller can call it from refreshBalances on the synced && balTotal>0 edge.
    // No-op when already backed up (options/walletbackedup) or when the card isn't built.
    void showBackupNag();

    // First-run trust: show/hide the NON-blocking import/rescan Home card. active=true
    // shows a busy card while a user-initiated key import + wallet rescan runs (the
    // daemon emits no runtime rescan %, so it is an indeterminate spinner, not a fake
    // percent); false hides it. No-op until setupHomeDashboard() has built it. Single
    // writer: only the import flow toggles it (importPrivKeys start, doImport finish).
    void showImportProgress(bool active);

    // RUNTIME actionable dialog (edit #5). Reached from the sync poller (rpc.cpp) when an
    // ATTACHED FOREIGN node (one this wallet did NOT start: rpc->isEmbedded()==false) has
    // been peerless/stuck for a sustained window. The wallet can only download/repair the
    // chain for a node IT starts, so it cannot heal the foreign node — instead it shows a
    // CLEAR, ACTIONABLE, PERSISTENT, RETRYABLE message centred on STUCK (not "too old"):
    // stop the other node (close the other ZClassic window, or stop the zclassicd process),
    // then reopen this wallet so it manages its own node. Primary relaunches the app; Quit
    // exits; an OPTIONAL "Use the bundled node" appears only when the ports are actually
    // free (re-checked on click). NEVER kills/mutates the foreign node; NEVER a silent hang.
    void showForeignNodeStuck();

    // Sibling of the above for the connect-time CATCH-ALL (edit #2): the node answered
    // neither cleanly nor with a recognized warmup state for too long. Actionable +
    // retryable; Retry re-runs the connect flow (a fresh ConnectionLoader/doAutoConnect)
    // rather than leaving the connect dialog frozen forever.
    void showNodeNotRespondingRetry();

    // 401 from a deliberately-EXTERNAL node (useEmbedded()==false / a daemon we did not
    // launch): for the bundled node a 401 is healed automatically and never reaches here.
    // A calm, non-terminal dialog that BRANCHES on where the credentials live: when they
    // come from a detected zclassic.conf the Settings fields are read-only, so it points
    // the user at the conf file (one-click "Show me the file"); when they come from
    // Edit -> Settings it offers a one-click "Open Settings". NEVER restarts/touches the
    // external node and contains NO terminal commands.
    void showExternalNodeAuthFailed();

    // TRUE iff the detected zclassic.conf actually carries USABLE credentials — i.e. it
    // parses a non-empty rpcpassword, OR a <datadir>/.cookie is readable for it. A conf can
    // EXIST yet hold no creds (e.g. just "server=1", with the running node's creds only on
    // its command line); the three GUI gates that key on "a conf path exists" must instead
    // key on this so a cred-less conf leaves the Settings fields EDITABLE (never a dead end).
    // Small DEDICATED reader (does NOT call ConnectionLoader::autoDetectZClassicConf, which
    // has a setUsingZClassicConf side effect); base resolved like cookieFilePathForConf
    // (conf datadir= override else the conf's own directory). NEVER logs the cookie.
    bool confHasUsableCreds(const QString& confLocation);

    Logger*      logger;

    void doClose();

    // Opt-in tray-resident mode (Settings -> Options -> "Keep running in the
    // background"). showFromTray() un-hides+raises the window (also used when a
    // second launch hands off to this instance); quitApp() performs the real,
    // clean shutdown (vs. closeEvent hiding to tray). applyTraySetting() wires
    // the tray icon + app-exit semantics to the current setting.
    void showFromTray();
    void quitApp();
    void applyTraySetting(bool enabled);

private:
    void closeEvent(QCloseEvent* event);
    // Narrow-window fix: re-elide the Home hero number to the window's current width on
    // every resize, so the 40pt balance shrinks (with an ellipsis) instead of pinning a
    // large minimum width. See relayoutHero() / heroPrivateFull.
    void resizeEvent(QResizeEvent* event) override;

    void setupTrayIcon();
    QSystemTrayIcon* trayIcon       = nullptr;
    bool             quitting       = false;
    bool             trayHintShown  = false;

    void setupSendTab();
    void setupTransactionsTab();
    void setupRecieveTab();
    void setupBalancesTab();
    void setupZClassicdTab();

    void setupSettingsModal();
    void setupStatusBar();
    void setupSyncBanner();

    // Phase-3a redesign (Quiet+): a modern left vertical NAV RAIL of large
    // checkable buttons that drive ui->tabWidget->setCurrentIndex(). Built
    // PROGRAMMATICALLY (no .ui structural change): the QTabWidget and all its
    // pages/objectNames are kept intact underneath; only its tabBar is hidden,
    // so every page stays index-selectable (L0/L1 tests untouched).
    void setupNavRail();
    QButtonGroup* navRailGroup = nullptr;

    // Phase-3b redesign (Quiet+): build the Home DASHBOARD programmatically on the
    // existing Balance page (no .ui change). Adds, above the existing Summary rows:
    // a privacy-forward HERO ("Private balance" big + Total secondary), two large
    // quick-action buttons (Send/Receive -> setCurrentIndex), and a hidden amber
    // "Shield public funds" fix-it card surfaced by updateHomeFixIt() when t>0.
    void setupHomeDashboard();
    QLabel*      homeHeroPrivate   = nullptr;   // big private (shielded) number
    QLabel*      homeHeroTotal     = nullptr;   // secondary "Total NN ZCL"
    QLabel*      homeHeroHelper    = nullptr;   // UX-22 zero-balance helper line
    // Narrow-window fix: the hero labels are given QSizePolicy::Minimum + minimumWidth(0)
    // so their (40pt) sizeHint stops pinning the whole window's min width. To avoid a
    // mid-glyph hard-clip at narrow widths we ELIDE the displayed text but keep the FULL
    // string here so (a) text-selection copies the real value and (b) the number re-expands
    // when the window widens. relayoutHero() recomputes the elided text from these; it is
    // invoked BOTH where the text is set (updateHomeFixIt) AND from resizeEvent().
    QString      heroPrivateFull;               // un-elided private-balance string
    QString      heroTotalFull;                 // un-elided "Total: …" string
    void         relayoutHero();                // re-elide the hero labels to their current width
    // Trust-aware hero (item 1): inline qualifier shown under the number while the
    // balance is cached/warming/mid-sync ("Updating… not final yet" / "Last updated
    // <when> · refreshing"); hidden on the synced edge. Confidence colour is driven by
    // the heroconfident dynamic property on homeHeroPrivate (dark.qss owns the green vs
    // neutral-grey). heroLivePainted is set true ONLY once a LIVE, non-syncing, real
    // (non-blank) balance has been painted this session, so a cached/warming number is
    // NEVER shown in confident green and a real synced number is NEVER hidden behind a
    // stale label.
    QLabel*      homeHeroQualifier = nullptr;   // "…not final yet" / "Last updated … · refreshing"
    bool         heroLivePainted   = false;     // a live, synced, real balance has hit the hero this session
    QFrame*      homeFixItCard     = nullptr;   // amber card (hidden unless t>0)
    QLabel*      homeFixItText     = nullptr;   // "X ZCL is PUBLIC ..."
    QPushButton* homeSendBtn       = nullptr;   // quick action (primary when funded)
    QPushButton* homeBackupBtn     = nullptr;   // always-on Home backup front door
    QPushButton* homeReceiveBtn    = nullptr;   // quick action (primary when empty)

    // W1-2: non-blocking amber "back up your wallet" Home card. Replaces the modal
    // backup nag (promptWalletBackup's box.exec()). Built in setupHomeDashboard,
    // reusing the EXACT fix-it/callout amber styling; surfaced by showBackupNag()
    // (called from rpc.cpp on the synced && balTotal>0 && once-per-session edge),
    // hidden once options/walletbackedup is set. Its buttons reuse the existing
    // backup/export handlers. promptWalletBackup() stays reachable from Help.
    QFrame*      homeBackupCard    = nullptr;   // amber card (hidden unless un-backed-up + funded)
    QLabel*      homeBackupText    = nullptr;   // "Back up your wallet ..."

    // First-run trust (import/rescan): a NON-blocking amber Home card with an
    // INDETERMINATE busy bar, shown while a user-initiated key import + wallet rescan
    // runs. The daemon provides no runtime rescan %, so this is a busy spinner + calm
    // copy (not a fake percent). Single writer: showImportProgress(), called only by
    // the import flow (start) and doImport() (both completion paths).
    QFrame*       homeImportCard   = nullptr;   // amber card (hidden unless importing)
    QProgressBar* homeImportBar    = nullptr;   // indeterminate (range 0,0) busy bar

    // PRIV-18 — the REAL "Shield public funds" action, shared by the Home fix-it
    // card button and (conceptually) the balances context-menu "Shield balance to
    // Sapling" path. Sets up a t -> (default Sapling z) shielding send on the Send
    // page: picks the largest-balance transparent source as From, resolves the
    // default Sapling z-address (auto-creating one if none exists, PRIV-19/PRIV-28),
    // fills it as the To recipient, checks Max, and navigates to Send. It does NOT
    // auto-execute -- the user still reviews + confirms (the send is t->z shielding,
    // so no de-shield acknowledgement is added). No-op if no transparent funds.
    void shieldPublicFunds();

    // SINGLE destructive launch path shared by the Help -> Repair action and the
    // runtime stub auto-heal: stop the embedded node, then drive a fresh
    // ConnectionLoader through startManualRepair() (the staged re-download ladder).
    void launchBlockchainRepair();

    // P0-6: state used to estimate a sync ETA from observed block rate.
    QElapsedTimer       syncEtaTimer;
    bool                syncEtaStarted = false;
    int                 syncEtaStartBlock = 0;

    void removeExtraAddresses();

    Tx   createTxFromSendPage();
    bool confirmTx(Tx tx);

    // Item 2 (send affirmation + humane failure). showSendSuccess: a calm,
    // non-blocking "you did it" dialog with Copy txid + View on explorer.
    // humaneSendError: maps common z_sendmany daemon error substrings to plain,
    // actionable headline copy (raw text is kept under "Show Details" by the caller).
    void    showSendSuccess(QString txid);
    QString humaneSendError(const QString& raw);

    // PRIV-10/PRIV-19/PRIV-28 fail-open change-shielding helpers (see sendtab.cpp).
    // findUnusedSaplingChangeAddr: an existing Sapling addr not colliding with a
    // recipient, or "". createSaplingAddressSync: blocking last-resort create that
    // ONLY ever returns a real Sapling address (never degrades to Sprout/transparent).
    QString findUnusedSaplingChangeAddr(const Tx& tx);
    QString createSaplingAddressSync();
    // CONFIRMED (confirmations>0), spendable balance of `addr` in integer zatoshis,
    // summed from the wallet's UTXO set -- the correct, drift-free basis for the
    // auto-shield change amount (z_sendmany spends only confirmed notes; getAllBalances()
    // includes unconfirmed). includeCoinbase=false additionally excludes coinbase UTXOs to
    // match the daemon's has-change input set. Null-safe (returns 0 if UTXOs not loaded).
    qint64  confirmedSpendableZat(const QString& addr, bool includeCoinbase);

    // FAIL-OPEN spendable accessor (the load-bearing money-safety primitive). Returns the
    // CONFIRMED, spendable balance of `addr` (via confirmedSpendableZat, coinbase-inclusive)
    // ONLY when the UTXO set is actually loaded; otherwise it falls back to the minconf=0
    // getAllBalances() value so a not-yet-loaded UTXO set never zeroes a Send-max or blocks a
    // legitimate send. Every send-amount/validation site MUST go through this so the fail-open
    // can't be forgotten. (Coinbase-aware change correctness lives in createTxFromSendPage.)
    double  spendableOrFallback(const QString& addr);

    // Snapshot-race gate (SAFE-RACE). verifyAutoShieldUnchanged() is the LAST check before
    // the irrevocable z_sendmany: for an auto-shield-change send it synchronously re-polls
    // the from-addr's transparent UTXOs (repollFromAddrUtxos, mirroring
    // createSaplingAddressSync's bounded pump) and ABORTS fail-closed if the live eligible
    // non-coinbase total no longer matches what the change was sized against; for any other
    // send it returns true immediately. Returns false => caller must NOT send.
    enum class RepollResult { Refreshed, NoConnection, Timeout };
    RepollResult repollFromAddrUtxos();
    bool    verifyAutoShieldUnchanged(const Tx& tx);
    // Reentrancy guard for the blocking re-poll pump (sibling of saplingSyncCreateInFlight),
    // so a second sendButton click can't nest a second synchronous re-poll.
    bool    autoShieldRepollInFlight = false;
    // PRIV-27 one-shot: surface the Sprout-recipient "change stays transparent"
    // constraint at most once per run instead of nagging on every keystroke/build.
    bool sproutChangeWarned = false;
    bool saplingProvisionAttempted = false;   // one-shot guard for ensureSaplingProvisioned
    // MINOR-3: reentrancy guard for the blocking createSaplingAddressSync() pump, so a
    // second sendButton click can't nest a second synchronous create.
    bool saplingSyncCreateInFlight = false;

    void setupTurnstileDialog();
    void turnstileDoMigration(QString fromAddr = "");
    void turnstileProgress();

    void cancelButton();
    void sendButton();
    void inputComboTextChanged(int index);
    void addAddressSection();
    void maxAmountChecked(int checked);
    // STALE-MAX FIX: recompute the "Send max" amount in-place when it is currently checked.
    // The max depends on the from-address balance, the fee, and the other recipients' amounts,
    // any of which can change AFTER Max is ticked — and Amount1 is read-only while Max is on, so
    // the user can't hand-correct a stale value. Call this from every input that affects the max.
    void recomputeMaxIfChecked();

    void editSchedule();

    void addressChanged(int number, const QString& text);
    void amountChanged (int number, const QString& text);
    // PRESENTATION-ONLY helpers (no money/zatoshi math): the live private/public verdict
    // badge above the Send form (echoes sendCategoryOf), and the running "You'll send X +
    // fee = Z" totals line (aggregates on-screen amounts only).
    void updateSendPrivacyBadge();
    void updateSendTotals();

    void addNewZaddr(bool sapling);
    std::function<void(bool)> addZAddrsToComboList(bool sapling);

    // Phase-3c redesign (Quiet+): private-by-default RECEIVE. The Receive page
    // shows, at rest, ONLY the shielded Sapling z-address + a green "Private"
    // indicator — no radios. The transparent (t-Addr) option and, only when the
    // wallet holds legacy Sprout funds, the read-only Sprout view, are tucked
    // behind a collapsed "Other address types (advanced)" disclosure.
    //
    // The existing rdioZSAddr/rdioTAddr/rdioZAddr radios are KEPT as the
    // underlying state machine (every existing toggle handler is preserved), but
    // are reparented INTO the collapsible disclosure panel and hidden at rest.
    // Built programmatically (no structural .ui churn); reuses lblSproutWarning
    // for the red PUBLIC caption exactly as before.
    void setupReceivePrivacyDisclosure();
    // Receive payment-request helpers (presentation only; never mutate the combo / raw address).
    QString buildReceivePaymentUri();   // zclassic:<addr>?amt=&memo= or "" when no amount set
    void    updateReceiveQRandPayload();
    // Show/hide the advanced disclosure panel; keeps the toggle arrow + collapsed
    // state in sync and, when collapsing, returns to the private (Sapling) view.
    void setReceiveAdvancedExpanded(bool expanded);
    // True iff the wallet currently holds at least one legacy (non-Sapling/Sprout)
    // z-address; gates whether the read-only legacy-Sprout radio is offered at all.
    bool walletHasLegacySprout() const;
    // Refresh which advanced options are offered (e.g. hide the legacy-Sprout radio
    // when no Sprout funds are held). Safe to call before the disclosure is built.
    void refreshReceiveAdvancedOptions();

    void memoButtonClicked(int number, bool includeReplyTo = false);
    void setMemoEnabled(int number, bool enabled);
    
    void addressBook();
    void importPrivKey();
    void exportAllKeys();
    void exportKeys(QString addr = "");
    void backupWalletDat();
    void exportTransactions();

    // --- Unified backup IA (Krug/Sierra): every entry point converges through these
    // three helpers so there is ONE safe path and ONE success closure to maintain.
    // fnDefaultBackupDir(): an existing dir to pre-fill the Save dialog (Desktop ->
    // Documents -> Home). backupWallet(): the single safe wallet.dat copy with a
    // smart, collision-safe default name+folder. showBackupSuccess(): the one warm
    // closure (where the file is + you're safe + cloud caveat + how to restore +
    // Show-in-folder). isWalletDat=false reuses it for the advanced key-file export.
    QString fnDefaultBackupDir();
    void    backupWallet();
    void    showBackupSuccess(const QString& savedPath, bool isWalletDat);

    void doImport(QSharedPointer<QList<QString>> keys);

    void restoreSavedStates();
    bool eventFilter(QObject *object, QEvent *event);

    bool            uiPaymentsReady    = false;
    QString         pendingURIPayment;

    RPC*         rpc  = nullptr;
    QCompleter*  labelCompleter = nullptr;

    QMovie*      loadingMovie;
};

#endif // MAINWINDOW_H
