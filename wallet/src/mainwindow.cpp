#include "mainwindow.h"
#include "addressbook.h"
#include "ui_mainwindow.h"
#include <QProgressBar>
#include <QElapsedTimer>
#include "ui_addressbook.h"
#include "ui_privkey.h"
#include "ui_about.h"
#include "ui_settings.h"
#include "ui_turnstile.h"
#include "ui_turnstileprogress.h"
#include "rpc.h"
#include "balancestablemodel.h"
#include "privacybadgedelegate.h"
#include "settings.h"
#include "version.h"
#include "turnstile.h"
#include "senttxstore.h"
#include "connection.h"

#include <QSystemTrayIcon>
#include <QCloseEvent>
#include <QResizeEvent>   // narrow-window fix: re-elide the Home hero on resize
#include <QFontMetrics>   // narrow-window fix: elidedText for the 40pt hero number
#include <QtNetwork/QTcpSocket>
#include <QFrame>
#include <QLabel>
#include <QPushButton>
#include <QToolButton>
#include <QFont>
#include <QButtonGroup>
#include <QAbstractButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QTabBar>
#include <QSignalBlocker>
#include <QFileInfo>     // showExternalNodeAuthFailed: open the conf's folder

using json = nlohmann::json;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    logger = new Logger(this, QDir(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)).filePath("zcl-qt-wallet.log"));

    // SELF-HEAL: a heal/inProgress flag seen at PROCESS STARTUP is necessarily stale —
    // it's a persisted QSettings flag that a prior session set just before a deferred
    // relaunch, and that session (and its live ConnectionLoader) is gone. Left set, it
    // would make every handleStartupFailure() in this run bail at the in-progress
    // guard and strand the modal connect dialog. Clear it ONCE here, before the first
    // ConnectionLoader is created, so a fresh run can classify+heal normally. This
    // runs before rpc = new RPC(this) below (whose loadConnection() is deferred).
    QSettings().setValue("heal/inProgress", false);

    // Status Bar
    setupStatusBar();
    
    // Settings editor 
    setupSettingsModal();

    // Set up exit action. Use quitApp() (not close()) so that in tray-resident
    // mode File -> Exit really quits and cleanly stops the node, rather than
    // just hiding the window to the tray.
    QObject::connect(ui->actionExit, &QAction::triggered, this, &MainWindow::quitApp);

    // Set up check for updates action
    QObject::connect(ui->actionCheck_for_Updates, &QAction::triggered, [=] () {
        // Silent is false, so show notification even if no update was found
        rpc->checkForUpdate(false);
    });

    // Pay ZClassic URI
    QObject::connect(ui->actionPay_URI, &QAction::triggered, [=] () {
        payZClassicURI();
    });

    // Import Private Key
    QObject::connect(ui->actionImport_Private_Key, &QAction::triggered, this, &MainWindow::importPrivKey);

    // Export All Private Keys — demoted to an explicitly-advanced label so it can
    // never be mistaken for the everyday backup. Relabelled at runtime (no .ui regen).
    ui->actionExport_All_Private_Keys->setText(tr("Advanced: Export private keys (text)…"));
    QObject::connect(ui->actionExport_All_Private_Keys, &QAction::triggered, this, &MainWindow::exportAllKeys);

    // Back up my wallet — the ONE safe everyday backup, worded identically to the
    // Home card + on-sync prompt for learnable muscle-memory. Relabelled at runtime.
    ui->actionBackup_wallet_dat->setText(tr("&Back up my wallet…"));
    QObject::connect(ui->actionBackup_wallet_dat, &QAction::triggered, this, &MainWindow::backupWalletDat);

    // Export transactions
    QObject::connect(ui->actionExport_transactions, &QAction::triggered, this, &MainWindow::exportTransactions);

    // Address Book
    QObject::connect(ui->action_Address_Book, &QAction::triggered, this, &MainWindow::addressBook);

    // Set up about action
    QObject::connect(ui->actionAbout, &QAction::triggered, [=] () {
        QDialog aboutDialog(this);
        Ui_about about;
        about.setupUi(&aboutDialog);
        Settings::saveRestore(&aboutDialog);

        QString version    = QString("Version ") % QString(APP_VERSION) % " (" % QString(__DATE__) % ")";
        about.versionLabel->setText(version);

        aboutDialog.exec();
    });

    // SELF-HEAL: always-reachable manual override. The .ui file is checked in and not
    // regenerated, so the action is created in code and added to the existing Help
    // menu. It is present even after auto-heal latches NEEDS_MANUAL, so the user is
    // never permanently stuck. It cleanly stops the running node first, then spins up
    // a fresh ConnectionLoader and invokes the SAME staged repair ladder used at
    // startup (offerCorruptionRepair) — there is no second ladder.
    {
        auto* repairAction = new QAction(tr("Repair / Re-download blockchain…"), this);
        ui->menuHelp->addSeparator();
        ui->menuHelp->addAction(repairAction);
        QObject::connect(repairAction, &QAction::triggered, [=]() {
            auto confirm = QMessageBox::question(this, tr("Repair blockchain data"),
                tr("This will stop your ZClassic node so its blockchain files can be repaired "
                   "or re-downloaded.\n\n"
                   "Your wallet and coins are safe — a backup copy of your wallet is made first, "
                   "and none of these options touch your wallet or private keys.\n\nContinue?"),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (confirm != QMessageBox::Yes)
                return;

            // Drive the SAME stop-node + fresh-loader + staged-ladder flow the runtime
            // stub auto-heal uses; there is exactly one launch path (launchBlockchainRepair).
            launchBlockchainRepair();
        });
    }

    // W1-2: the synced-edge backup nag is now a NON-blocking Home card (showBackupNag),
    // not a modal. Keep the full guided backup flow (promptWalletBackup) reachable on
    // demand from the Help menu so the user can invoke it any time. Created in code for
    // the same reason as the repair action (the .ui is checked in / not regenerated).
    {
        auto* backupAction = new QAction(tr("&Back up my wallet…"), this);
        ui->menuHelp->addAction(backupAction);
        // DEAD-CLICK FIX: promptWalletBackup() early-returns (does nothing) once
        // options/walletbackedup is set — which happens after the first backup — so this
        // menu item silently no-op'd forever after. Wire it to backupWallet(), the always-works
        // copy flow (the same one the File-menu "Back up wallet.dat" uses), so it's never dead.
        QObject::connect(backupAction, &QAction::triggered, this, &MainWindow::backupWallet);
    }

    // Initialize to the balances tab
    ui->tabWidget->setCurrentIndex(0);

    // The zclassicd tab is hidden by default, and only later added in if the embedded zclassicd is started
    zclassicdtab = ui->tabWidget->widget(4);
    ui->tabWidget->removeTab(4);

    setupSendTab();
    setupTransactionsTab();
    setupRecieveTab();
    setupBalancesTab();
    setupTurnstileDialog();
    setupZClassicdTab();

    // Phase-3a redesign (Quiet+): replace the top tab bar with a modern left
    // nav rail. Built here, AFTER the tab pages are set up and the zclassicd tab
    // has been removed (above), so the rail's primary destinations map to the
    // live tab indices (Home/Balance 0, Send 1, Receive 2, Activity 3).
    setupNavRail();

    // Narrow-window fix: declare an HONEST, tested minimum width so dragging the edge has
    // predictable behaviour (a deliberate floor) instead of an emergent "mystery wall" from
    // additive child mins. Derivation: navRail setFixedWidth(168) + ~480 content budget =
    // 648. The content side reaches ~480 because the 40pt hero now elides (QSizePolicy::Minimum
    // + relayoutHero), the Summary groupBox .ui minimumSize was relaxed 250 -> 0, and the
    // Receive QR floor dropped 200 -> 140. If the rail width or those mins change, revisit 648.
    setMinimumWidth(648);

    rpc = new RPC(this);

    restoreSavedStates();

    // Opt-in tray-resident mode: set up the tray icon + app-exit semantics to
    // match the saved preference (default OFF -> no tray, quit-on-close as before).
    applyTraySetting(Settings::getInstance()->getKeepInTray());
}

void MainWindow::restoreSavedStates() {
    QSettings s;
    restoreGeometry(s.value("geometry").toByteArray());

    ui->balancesTable->horizontalHeader()->restoreState(s.value("baltablegeometry").toByteArray());
    ui->transactionsTable->horizontalHeader()->restoreState(s.value("tratablegeometry").toByteArray());

    // Paint the last-known balances immediately so the first ~1-minute node
    // warmup shows a usable view instead of a blank "0.00". The live RPC
    // overwrites these the moment it connects. Gated on its own default-ON
    // preference (independent of saved-tx-history) so every user gets the instant
    // paint; the live values are authoritative, this is only a convenience cache.
    if (Settings::getInstance()->getShowCachedBalance() && s.contains("cache/balTotal")) {
        double balT   = s.value("cache/balTransparent", 0.0).toDouble();
        double balZ   = s.value("cache/balShielded",    0.0).toDouble();
        double balTot = s.value("cache/balTotal",       0.0).toDouble();

        ui->balTransparent->setText(Settings::getZCLDisplayFormat(balT));
        ui->balSheilded   ->setText(Settings::getZCLDisplayFormat(balZ));
        ui->balTotal      ->setText(Settings::getZCLDisplayFormat(balTot));

        // Phase-3b: paint the Home dashboard from the cached balances too, so the
        // hero + fix-it card are correct during the warmup before the first live
        // refresh (which calls this again via updateHomeFixIt). Item 1: pass
        // fromCache=true so the hero paints the cached number in DE-CONFIDENCED grey
        // with a "Last updated … · refreshing" qualifier — never confident green for a
        // number we have not yet confirmed live this session (isSyncing() is not yet
        // set this early, so fromCache is what short-circuits the synced edge here).
        updateHomeFixIt(balT, /*fromCache=*/true);

        qint64 epoch = s.value("cache/lastSyncEpoch", (qint64) 0).toLongLong();
        if (epoch > 0) {
            QString when = QDateTime::fromSecsSinceEpoch(epoch).toString("MMM d, h:mm AP");
            QString tip  = tr("Last known balance — last updated %1 (refreshing…)").arg(when);
            ui->balTransparent->setToolTip(tip);
            ui->balSheilded   ->setToolTip(tip);
            ui->balTotal      ->setToolTip(tip);
        }
    }
}

void MainWindow::doClose() {
    // doClose() is the "really quit" path (e.g. an OS signal handler), so make
    // sure closeEvent performs the real shutdown rather than hiding to the tray.
    quitting = true;
    closeEvent(nullptr);
}

void MainWindow::closeEvent(QCloseEvent* event) {
    QSettings s;

    s.setValue("geometry", saveGeometry());
    s.setValue("baltablegeometry", ui->balancesTable->horizontalHeader()->saveState());
    s.setValue("tratablegeometry", ui->transactionsTable->horizontalHeader()->saveState());

    s.sync();

    // Tray-resident mode: closing the window just hides it (the node keeps
    // running so the next open is instant). Only an explicit Quit / File->Exit
    // (which sets `quitting`) tears the node down. Never silently hide if the
    // system tray is unavailable -- fall through to a real shutdown so the node
    // is never orphaned with no way to bring the window back.
    if (!quitting
            && Settings::getInstance()->getKeepInTray()
            && trayIcon != nullptr
            && QSystemTrayIcon::isSystemTrayAvailable()) {
        hide();
        if (event)
            event->ignore();

        // Show the "still running in the tray" hint AT MOST ONCE, EVER (persisted
        // across launches), so the very first close quietly teaches where the window
        // went and we NEVER nag again. trayHintShown also guards within-session
        // repeats. A joyful wallet does not pop a notification you have to dismiss
        // every time you close it.
        if (!trayHintShown && !s.value("tray/hintShown", false).toBool()) {
            trayHintShown = true;
            s.setValue("tray/hintShown", true);
            s.sync();
            trayIcon->showMessage(tr("Still here — opens instantly next time"),
                tr("ZClassic stays ready in the tray, so it opens instantly. "
                   "Use File ▸ Exit (or right-click the tray icon) to quit completely."),
                QSystemTrayIcon::Information, 4000);
        }
        return;
    }

    // Real shutdown. Let the RPC know to shut down any running service.
    rpc->shutdownZClassicd();

    // Bubble up
    if (event)
        QMainWindow::closeEvent(event);

    // quit-on-last-window-closed is now disabled for the WHOLE GUI lifetime (set
    // in main(); never re-enabled by applyTraySetting), so closing the window no
    // longer ends the app by itself. We only reach here on a REAL shutdown (the
    // tray-hide branch returned early above), i.e. the user/OS is intentionally
    // closing the window after rpc->shutdownZClassicd() -- quitting is the correct
    // outcome. Quit explicitly and UNCONDITIONALLY (not just in tray mode) so the
    // window's X button, File->Exit, the reindex/rescan close, and every
    // quitApp()-driven path still quit cleanly with the flag permanently false.
    qApp->quit();
}

void MainWindow::showFromTray() {
    showNormal();
    raise();
    activateWindow();
}

void MainWindow::quitApp() {
    // The real, clean exit: mark quitting so closeEvent stops the node instead
    // of hiding to the tray, then close (which triggers the shutdown sequence).
    quitting = true;
    close();
}

void MainWindow::setupTrayIcon() {
    if (trayIcon != nullptr)
        return;

    trayIcon = new QSystemTrayIcon(QIcon(":/icons/res/icon.ico"), this);
    trayIcon->setToolTip("ZclWallet");

    auto trayMenu = new QMenu(this);
    auto showAction = trayMenu->addAction(tr("Show ZclWallet"));
    QObject::connect(showAction, &QAction::triggered, this, &MainWindow::showFromTray);
    trayMenu->addSeparator();
    auto quitAction = trayMenu->addAction(tr("Quit"));
    QObject::connect(quitAction, &QAction::triggered, this, &MainWindow::quitApp);
    trayIcon->setContextMenu(trayMenu);

    // A left-click / double-click on the tray icon brings the window back.
    QObject::connect(trayIcon, &QSystemTrayIcon::activated, this,
        [=](QSystemTrayIcon::ActivationReason reason) {
            if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick)
                showFromTray();
        });
}

void MainWindow::applyTraySetting(bool enabled) {
    if (enabled && QSystemTrayIcon::isSystemTrayAvailable()) {
        setupTrayIcon();
        trayIcon->show();
        // The window-close should hide to tray, not end the app.
        qApp->setQuitOnLastWindowClosed(false);
    } else {
        if (trayIcon != nullptr)
            trayIcon->hide();
        // NEVER-STRAND invariant: do NOT re-enable quit-on-last-window-closed here.
        // main() disables it for the whole GUI lifetime so that no orphaned modal
        // dialog teardown (connect dialog, connect-error box, node-crash box,
        // foreign-stuck box) can silently end the process before the main window
        // maps -- bob's exact bug. Previously this branch flipped the flag back to
        // true whenever keep-in-tray was OFF (the default), which RE-ARMED that
        // trap the first time the user clicked Settings->OK. The legitimate quit on
        // a real window close is now provided unconditionally by
        // MainWindow::closeEvent() (qApp->quit()), so leaving the flag false costs
        // nothing and closes the regression.
        //
        // Intentionally a no-op on the flag in both tray-off and headless cases.
    }
}

void MainWindow::turnstileProgress() {
    Ui_TurnstileProgress progress;
    QDialog d(this);
    progress.setupUi(&d);
    Settings::saveRestore(&d);

    QIcon icon = QApplication::style()->standardIcon(QStyle::SP_MessageBoxWarning);
    progress.msgIcon->setPixmap(icon.pixmap(64, 64));

    bool migrationFinished = false;
    auto fnUpdateProgressUI = [=, &migrationFinished] () mutable {
        // Get the plan progress
        if (rpc->getTurnstile()->isMigrationPresent()) {
            auto curProgress = rpc->getTurnstile()->getPlanProgress();
            
            progress.progressTxt->setText(QString::number(curProgress.step) % QString(" / ") % QString::number(curProgress.totalSteps));
            progress.progressBar->setValue(100 * curProgress.step / curProgress.totalSteps);
            
            auto nextTxBlock = curProgress.nextBlock - Settings::getInstance()->getBlockNumber();
            
            progress.fromAddr->setText(curProgress.from);
            progress.toAddr->setText(curProgress.to);

            if (curProgress.step == curProgress.totalSteps) {
                migrationFinished = true;
                auto txt = QString("Turnstile migration finished");
                if (curProgress.hasErrors) {
                    txt = txt + ". There were some errors.\n\nYour funds are all in your wallet, so you should be able to finish moving them manually.";
                }
                progress.nextTx->setText(txt);
            } else {
                progress.nextTx->setText(QString("Next transaction in ") 
                                    % QString::number(nextTxBlock < 0 ? 0 : nextTxBlock)
                                    % " blocks via " % curProgress.via % "\n" 
                                    % (nextTxBlock <= 0 ? "(waiting for confirmations)" : ""));
            }
            
        } else {
            progress.progressTxt->setText("");
            progress.progressBar->setValue(0);
            progress.nextTx->setText("No turnstile migration is in progress");
        }
    };

    QTimer progressTimer(this);        
    QObject::connect(&progressTimer, &QTimer::timeout, fnUpdateProgressUI);
    progressTimer.start(Settings::updateSpeed);
    fnUpdateProgressUI();
    
    auto curProgress = rpc->getTurnstile()->getPlanProgress();

    // Abort button
    if (curProgress.step != curProgress.totalSteps)
        progress.buttonBox->button(QDialogButtonBox::Discard)->setText("Abort");
    else
        progress.buttonBox->button(QDialogButtonBox::Discard)->setVisible(false);

    // Abort button clicked
    QObject::connect(progress.buttonBox->button(QDialogButtonBox::Discard), &QPushButton::clicked, [&] () {
        if (curProgress.step != curProgress.totalSteps) {
            auto abort = QMessageBox::warning(this, "Are you sure you want to Abort?",
                                    "Are you sure you want to abort the migration?\nAll further transactions will be cancelled.\nAll your funds are still in your wallet.",
                                    QMessageBox::Yes, QMessageBox::No);
            if (abort == QMessageBox::Yes) {
                rpc->getTurnstile()->removeFile();
                d.close();
                ui->statusBar->showMessage("Automatic Sapling turnstile migration aborted.");
            }
        }
    });

    d.exec();    
    if (migrationFinished || curProgress.step == curProgress.totalSteps) {
        // Finished, so delete the file
        rpc->getTurnstile()->removeFile();
    }    
}

void MainWindow::turnstileDoMigration(QString fromAddr) {
    // Return if there is no connection
    if (rpc->getAllZAddresses() == nullptr)
        return;

    // If a migration is already in progress, show the progress dialog instead
    if (rpc->getTurnstile()->isMigrationPresent()) {
        turnstileProgress();
        return;
    }

    Ui_Turnstile turnstile;
    QDialog d(this);
    turnstile.setupUi(&d);
    Settings::saveRestore(&d);

    QIcon icon = QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation);
    turnstile.msgIcon->setPixmap(icon.pixmap(64, 64));

    auto fnGetAllSproutBalance = [=] () {
        double bal = 0;
        for (auto addr : *rpc->getAllZAddresses()) {
            if (Settings::getInstance()->isSproutAddress(addr)) {
                bal += rpc->getAllBalances()->value(addr);
            }
        }

        return bal;
    };

    turnstile.fromBalance->setText(Settings::getZCLUSDDisplayFormat(fnGetAllSproutBalance()));
    for (auto addr : *rpc->getAllZAddresses()) {
        auto bal = rpc->getAllBalances()->value(addr);
        if (Settings::getInstance()->isSaplingAddress(addr)) {
            turnstile.migrateTo->addItem(addr, bal);
        } else {
            turnstile.migrateZaddList->addItem(addr, bal);
        }
    }

    auto fnUpdateSproutBalance = [=] (QString addr) {
        double bal = 0;

        // The currentText contains the balance as well, so strip that.
        if (addr.contains("(")) {
            addr = addr.left(addr.indexOf("("));
        }

        if (addr.startsWith("All")) {
            bal = fnGetAllSproutBalance();
        } else {
            bal = rpc->getAllBalances()->value(addr);
        }
        
        auto balTxt = Settings::getZCLUSDDisplayFormat(bal);
        
        if (bal < Turnstile::minMigrationAmount) {
            turnstile.fromBalance->setStyleSheet("color: red;");
            turnstile.fromBalance->setText(balTxt % " [You need at least " 
                        % Settings::getZCLDisplayFormat(Turnstile::minMigrationAmount)
                        % " for automatic migration]");
            turnstile.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        } else {
            turnstile.fromBalance->setStyleSheet("");
            turnstile.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
            turnstile.fromBalance->setText(balTxt);
        }
    };

    if (!fromAddr.isEmpty())
        turnstile.migrateZaddList->setCurrentText(fromAddr);

    fnUpdateSproutBalance(turnstile.migrateZaddList->currentText());    

    // Combo box selection event
    QObject::connect(turnstile.migrateZaddList, &QComboBox::currentTextChanged, fnUpdateSproutBalance);
        
    // Privacy level combobox
    // Num tx over num blocks
    QList<std::tuple<int, int>> privOptions; 
    privOptions.push_back(std::make_tuple<int, int>(3, 576));
    privOptions.push_back(std::make_tuple<int, int>(5, 1152));
    privOptions.push_back(std::make_tuple<int, int>(10, 2304));

    QObject::connect(turnstile.privLevel, QOverload<int>::of(&QComboBox::currentIndexChanged), [=] (auto idx) {
        // Update the fees
        turnstile.minerFee->setText(
            Settings::getZCLUSDDisplayFormat(std::get<0>(privOptions[idx]) * Settings::getMinerFee()));
    });

    for (auto i : privOptions) {
        turnstile.privLevel->addItem(QString::number((int)(std::get<1>(i) / 24 / 24)) % " days (" % // 24 blks/hr * 24 hrs per day
                                     QString::number(std::get<1>(i)) % " blocks, ~" %
                                     QString::number(std::get<0>(i)) % " txns)"
        );
    }
    
    turnstile.buttonBox->button(QDialogButtonBox::Ok)->setText("Start");

    if (d.exec() == QDialog::Accepted) {
        auto privLevel = privOptions[turnstile.privLevel->currentIndex()];
        rpc->getTurnstile()->planMigration(
            turnstile.migrateZaddList->currentText(), 
            turnstile.migrateTo->currentText(),
            std::get<0>(privLevel), std::get<1>(privLevel));

        QMessageBox::information(this, "Backup your wallet.dat",
                                    "The migration will now start. You can check progress in the File -> Sapling Turnstile menu.\n\nYOU MUST BACKUP YOUR wallet.dat NOW!\n\nNew Addresses have been added to your wallet which will be used for the migration.",
                                    QMessageBox::Ok);
    }
}

void MainWindow::setupTurnstileDialog() {
    // Turnstile migration
    QObject::connect(ui->actionTurnstile_Migration, &QAction::triggered, [=] () {
        // If there is current migration that is present, show the progress button
        if (rpc->getTurnstile()->isMigrationPresent())
            turnstileProgress();
        else
            turnstileDoMigration();
    });
}

void MainWindow::setupStatusBar() {
    // Status Bar
    loadingLabel = new QLabel();
    loadingMovie = new QMovie(":/icons/res/loading.gif");
    loadingMovie->setScaledSize(QSize(32, 16));
    loadingMovie->start();
    loadingLabel->setAttribute(Qt::WA_NoSystemBackground);
    loadingLabel->setMovie(loadingMovie);

    ui->statusBar->addPermanentWidget(loadingLabel);
    loadingLabel->setVisible(false);

    // Custom status bar menu
    ui->statusBar->setContextMenuPolicy(Qt::CustomContextMenu);
    QObject::connect(ui->statusBar, &QStatusBar::customContextMenuRequested, [=](QPoint pos) {
        auto msg = ui->statusBar->currentMessage();
        QMenu menu(this);

        if (!msg.isEmpty() && msg.startsWith(Settings::txidStatusMessage)) {
            auto txid = msg.split(":")[1].trimmed();
            menu.addAction("Copy txid", [=]() {
                QGuiApplication::clipboard()->setText(txid);
            });
            menu.addAction("View tx on block explorer", [=]() {
                QString url = Settings::getExplorerTxURL(txid);
                if (!url.isEmpty())
                    QDesktopServices::openUrl(QUrl(url));
            });
        }

        menu.addAction("Refresh", [=]() {
            rpc->refresh(true);
        });
        QPoint gpos(mapToGlobal(pos).x(), mapToGlobal(pos).y() + this->height() - ui->statusBar->height());
        menu.exec(gpos);
    });

    statusLabel = new QLabel();
    ui->statusBar->addPermanentWidget(statusLabel);

    statusIcon = new QLabel();
    ui->statusBar->addPermanentWidget(statusIcon);
}

// P0-6: prominent, non-technical-friendly sync banner on the Balance/main tab.
// Built in C++ (rather than hand-editing the .ui XML) so the insertion is
// mechanically safe: gridLayout_2 holds exactly one item (horizontalLayout_5),
// which we move to row 1 while the banner takes row 0.
void MainWindow::setupSyncBanner() {
    syncBanner = new QWidget(ui->tab);
    auto* bannerLayout = new QHBoxLayout(syncBanner);
    bannerLayout->setContentsMargins(8, 6, 8, 6);
    bannerLayout->setSpacing(10);

    syncStatusLabel = new QLabel(syncBanner);
    syncStatusLabel->setWordWrap(true);
    syncStatusLabel->setText(tr("Connecting to your ZClassic node…"));
    QFont f = syncStatusLabel->font();
    f.setBold(true);
    syncStatusLabel->setFont(f);

    syncProgressBar = new QProgressBar(syncBanner);
    syncProgressBar->setRange(0, 100);
    syncProgressBar->setValue(0);
    syncProgressBar->setTextVisible(true);
    // Narrow-window fix: 120 (was 180) so the sync banner row doesn't spike the window's
    // minimum width above the honest floor while a sync is in progress. The bar is hidden
    // at rest (below), so this only matters during sync; 120px still reads clearly.
    syncProgressBar->setMinimumWidth(120);
    syncProgressBar->setMaximumWidth(300);
    syncProgressBar->setVisible(false);

    // Polish P0-2: the QUIET "Synced" inline pill. At rest, green lives on the
    // balance (the hero), not the chrome — so a fully-synced node shows this quiet
    // 24px pill (green dot + "Synced" in dim text) and the full-width colored
    // banner is hidden. The full-width banner is reserved for syncing/error
    // states only. setSyncStatus() swaps between the two.
    syncQuietPill = new QLabel(syncBanner);
    syncQuietPill->setObjectName("syncQuietPill");
    syncQuietPill->setTextFormat(Qt::RichText);
    syncQuietPill->setText(tr("<span style=\"color:#34c759;\">●</span>&nbsp;&nbsp;Synced"));
    syncQuietPill->setVisible(false);

    bannerLayout->addWidget(syncStatusLabel, 1);
    bannerLayout->addWidget(syncProgressBar, 0);
    bannerLayout->addWidget(syncQuietPill, 0);
    bannerLayout->addStretch(0);

    // Move the existing balances content (horizontalLayout_5) down to row 1 and
    // place the banner on row 0. takeAt(0) is safe: gridLayout_2 has one item.
    auto* grid = ui->gridLayout_2;
    QLayoutItem* existing = grid->takeAt(0);
    grid->addWidget(syncBanner, 0, 0, 1, 1);
    if (existing && existing->layout()) {
        grid->addItem(existing, 1, 0, 1, 1);
    } else if (existing) {
        // Fallback (shouldn't happen): re-add whatever we took.
        grid->addItem(existing, 1, 0, 1, 1);
    }
    grid->setRowStretch(0, 0);
    grid->setRowStretch(1, 1);

    // Start in the neutral "connecting" state.
    setSyncStatusConnecting();
}

// Phase-3b redesign (Quiet+): the modern Home DASHBOARD.
//
// LOW-RISK, PROGRAMMATIC build — no .ui structural change. We DO NOT remove,
// rename, or recreate any widget; we ADD new widgets as children of the existing
// Balance page (ui->tab) and prepend them into the Summary group's vertical
// layout (verticalLayout, inside groupBox/gridLayout). The existing
// balSheilded / balTransparent / balTotal labels (updated by rpc.cpp) are kept
// intact and still drive everything: the HERO mirrors their text on each update.
//
// Three additive pieces, top-to-bottom inside the Summary group:
//   1) a privacy-forward HERO — a big "Private balance NN ZCL" lead number with a
//      smaller secondary "Total NN ZCL"; the private/shielded value is the visual
//      lead (green accent), Total is dimmed.
//   2) two large quick-action buttons — Send (green primary) + Receive (secondary)
//      — that navigate via ui->tabWidget->setCurrentIndex (1 = Send, 2 = Receive);
//      setupNavRail's currentChanged handler keeps the rail's checked state synced.
//   3) an amber "Shield public funds" FIX-IT card, HIDDEN by default and surfaced
//      only when transparent > 0 (see updateHomeFixIt). Its button navigates to the
//      Send page for THIS phase (no auto-shield semantics here).
void MainWindow::setupHomeDashboard() {
    // The Summary group's content lives in verticalLayout (ui->verticalLayout),
    // which holds the Shielded / Transparent / line / Total rows. We PREPEND our
    // dashboard strip above those rows so the hero leads and the raw rows remain
    // available below. If the layout can't be found (shouldn't happen given the
    // .ui), bail out gracefully — the page still works with the original rows.
    auto* summaryVBox = ui->verticalLayout;
    if (summaryVBox == nullptr) return;

    int insertAt = 0;   // prepend, in reverse order so the final order is correct

    // ---- 1) HERO ------------------------------------------------------------
    auto* hero = new QFrame(ui->tab);
    hero->setObjectName("homeHero");
    hero->setFrameShape(QFrame::NoFrame);
    auto* heroV = new QVBoxLayout(hero);
    heroV->setContentsMargins(16, 16, 16, 16);
    heroV->setSpacing(4);

    auto* heroCaption = new QLabel(tr("Private balance"), hero);
    heroCaption->setObjectName("homeHeroCaption");

    homeHeroPrivate = new QLabel(QString(), hero);
    homeHeroPrivate->setObjectName("homeHeroPrivate");
    homeHeroPrivate->setTextInteractionFlags(Qt::TextSelectableByMouse);
    // Narrow-window fix: a 40pt non-wrapping QLabel's minimumSizeHint tracks its full
    // rendered text (~430-520px for a balance string), which propagated up through the
    // Summary groupBox -> Balance tab -> tabWidget and PINNED the whole window's minimum
    // width. QSizePolicy::Minimum lets the label shrink BELOW its sizeHint (it still won't
    // stretch wider, so the hero stays left-aligned at normal/large widths); minimumWidth(0)
    // removes the residual floor. The displayed text is elided in relayoutHero() so it shows
    // an ellipsis rather than a mid-glyph clip; heroPrivateFull keeps the real value.
    homeHeroPrivate->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Preferred);
    homeHeroPrivate->setMinimumWidth(0);

    homeHeroTotal = new QLabel(QString(), hero);
    homeHeroTotal->setObjectName("homeHeroTotal");
    homeHeroTotal->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Preferred);
    homeHeroTotal->setMinimumWidth(0);

    // Polish P1/UX-22: a one-line friendly helper, shown ONLY when the balance is
    // zero ("Your private balance — receive ZCL to get started"). Hidden once the
    // wallet is funded (updateHomeFixIt toggles it).
    homeHeroHelper = new QLabel(
        tr("Your private balance — receive ZCL to get started."), hero);
    homeHeroHelper->setObjectName("homeHeroHelper");
    homeHeroHelper->setWordWrap(true);
    homeHeroHelper->setVisible(false);

    // Trust-aware hero (item 1): an inline qualifier shown ONLY while the number is
    // cached / warming / mid-sync, so a de-confidenced grey balance always says why
    // ("Updating… not final yet" / "Last updated <when> · refreshing"). Hidden on the
    // synced edge. objectName -> dark.qss owns its colour.
    homeHeroQualifier = new QLabel(QString(), hero);
    homeHeroQualifier->setObjectName("homeHeroQualifier");
    homeHeroQualifier->setWordWrap(true);
    homeHeroQualifier->setVisible(false);

    // Born NOT-confident: the hero starts grey and only turns green on the first synced
    // paint (updateHomeFixIt). A blank or warming number must never look confident.
    homeHeroPrivate->setProperty("heroconfident", false);

    heroV->addWidget(heroCaption);
    heroV->addWidget(homeHeroPrivate);
    heroV->addWidget(homeHeroTotal);
    heroV->addWidget(homeHeroQualifier);
    heroV->addWidget(homeHeroHelper);

    summaryVBox->insertWidget(insertAt++, hero);

    // ---- 2) QUICK ACTIONS ---------------------------------------------------
    auto* actions = new QFrame(ui->tab);
    actions->setObjectName("homeQuickActions");
    actions->setFrameShape(QFrame::NoFrame);
    auto* actV = new QHBoxLayout(actions);
    actV->setContentsMargins(0, 0, 0, 8);
    actV->setSpacing(8);

    auto* sendBtn = new QPushButton(tr("Send"), actions);
    sendBtn->setObjectName("homeSendBtn");
    sendBtn->setProperty("homeaction", "primary");   // qss hook (green primary)
    sendBtn->setDefault(true);                        // QPushButton:default look
    sendBtn->setAutoDefault(false);                   // don't steal Enter on other pages
    sendBtn->setCursor(Qt::PointingHandCursor);
    sendBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    homeSendBtn = sendBtn;

    auto* recvBtn = new QPushButton(tr("Receive"), actions);
    recvBtn->setObjectName("homeReceiveBtn");
    recvBtn->setProperty("homeaction", "secondary");  // qss hook (secondary)
    recvBtn->setAutoDefault(false);
    recvBtn->setCursor(Qt::PointingHandCursor);
    recvBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    homeReceiveBtn = recvBtn;

    actV->addWidget(sendBtn);
    actV->addWidget(recvBtn);

    // Nav rail maps Send = index 1, Receive = index 2. setCurrentIndex fires the
    // tabWidget currentChanged handler installed by setupNavRail(), which re-syncs
    // the rail's checked button — so the rail highlight follows automatically.
    QObject::connect(sendBtn, &QPushButton::clicked, [this]() {
        ui->tabWidget->setCurrentIndex(1);
    });
    QObject::connect(recvBtn, &QPushButton::clicked, [this]() {
        ui->tabWidget->setCurrentIndex(2);
    });

    summaryVBox->insertWidget(insertAt++, actions);

    // ALWAYS-AVAILABLE backup front door (Krug/Sierra ROOT-CAUSE fix). The amber
    // backup CARD only appears once synced && balance>0 (showBackupNag), so a careful
    // zero-balance first-timer who wants to back up BEFORE funding finds NO entry
    // point on Home and goes hunting — which is exactly how they trip over the raw
    // key-export dialog. This quiet, full-width secondary button is the calm, balance-
    // independent answer to "how do I save my wallet": it calls the SAME safe copy
    // flow as every other surface (backupWallet) and self-hides once the wallet is
    // backed up. Its own row (not crowding Send/Receive). UAF-safe ([this], child of
    // ui->tab). KEY-1 N/A: this is a wallet.dat copy, not a key reveal.
    homeBackupBtn = new QPushButton(tr("Back up my wallet"), ui->tab);
    homeBackupBtn->setObjectName("homeBackupBtn");
    homeBackupBtn->setProperty("homeaction", "secondary");   // reuse the secondary qss hook
    homeBackupBtn->setAutoDefault(false);
    homeBackupBtn->setCursor(Qt::PointingHandCursor);
    homeBackupBtn->setVisible(!Settings::getInstance()->isWalletBackedUp());
    QObject::connect(homeBackupBtn, &QPushButton::clicked, [this]() {
        backupWallet();
        if (Settings::getInstance()->isWalletBackedUp() && homeBackupBtn)
            homeBackupBtn->setVisible(false);
    });
    summaryVBox->insertWidget(insertAt++, homeBackupBtn);

    // ---- 3) FIX-IT CARD (amber; hidden unless transparent > 0) --------------
    homeFixItCard = new QFrame(ui->tab);
    homeFixItCard->setObjectName("homeFixItCard");
    homeFixItCard->setFrameShape(QFrame::NoFrame);
    auto* cardV = new QVBoxLayout(homeFixItCard);
    cardV->setContentsMargins(12, 12, 12, 12);
    cardV->setSpacing(8);

    homeFixItText = new QLabel(QString(), homeFixItCard);
    homeFixItText->setObjectName("homeFixItText");
    homeFixItText->setWordWrap(true);

    auto* fixItBtn = new QPushButton(tr("Shield my funds"), homeFixItCard);
    fixItBtn->setObjectName("homeFixItBtn");
    fixItBtn->setAutoDefault(false);
    fixItBtn->setCursor(Qt::PointingHandCursor);
    // PRIV-18 — wire the fix-it button to the REAL shielding flow (no longer a bare
    // navigate). shieldPublicFunds() sets up a t -> (default Sapling z) shielding
    // send on the Send page, reusing the same "Shield balance to Sapling" semantics
    // as the balances context menu, then navigates to Send for the user to confirm.
    QObject::connect(fixItBtn, &QPushButton::clicked, [this]() {
        shieldPublicFunds();
    });

    cardV->addWidget(homeFixItText);
    cardV->addWidget(fixItBtn, 0, Qt::AlignLeft);

    homeFixItCard->setVisible(false);   // hidden until a positive transparent balance

    summaryVBox->insertWidget(insertAt++, homeFixItCard);

    // ---- 3b) BACK-UP CARD (W1-2: amber; hidden unless un-backed-up + funded) ----
    // Replaces the modal backup nag (promptWalletBackup's box.exec()) with a
    // non-blocking Home card that reuses the EXACT fix-it/callout amber styling
    // (same objectNames -> same dark.qss rules). Surfaced by showBackupNag() on the
    // synced && balTotal>0 edge, hidden once options/walletbackedup is set. Its two
    // buttons reuse the existing backup/export handlers; promptWalletBackup() stays
    // reachable from the Help menu for the full guided flow.
    homeBackupCard = new QFrame(ui->tab);
    homeBackupCard->setObjectName("homeFixItCard");   // reuse the amber-card qss rule
    homeBackupCard->setFrameShape(QFrame::NoFrame);
    auto* backupV = new QVBoxLayout(homeBackupCard);
    backupV->setContentsMargins(12, 12, 12, 12);
    backupV->setSpacing(8);

    homeBackupText = new QLabel(
        tr("Back up your wallet. This wallet has no recovery phrase — if this "
           "computer is lost or its disk fails and you have no backup, your coins "
           "are gone forever."),
        homeBackupCard);
    homeBackupText->setObjectName("homeFixItText");   // reuse the amber-body qss rule
    homeBackupText->setWordWrap(true);

    // Krug: ONE obvious action. The co-equal "Export Private Keys" button (and its
    // self-report quiz) is gone — raw key export is an advanced operation reachable
    // only from the File menu / Receive disclosure / right-click, never as a peer of
    // the safe backup. Identical "Back up my wallet" label on every surface.
    auto* backupRow = new QHBoxLayout();
    backupRow->setSpacing(8);
    auto* backupNowBtn = new QPushButton(tr("Back up my wallet"), homeBackupCard);
    backupNowBtn->setObjectName("homeFixItBtn");      // reuse the amber-button qss rule
    backupNowBtn->setAutoDefault(false);
    backupNowBtn->setCursor(Qt::PointingHandCursor);

    // backupWallet() is the single safe copy flow; on a verified copy it sets the
    // backed-up flag, after which showBackupNag() hides this card permanently. Drop
    // the card immediately too (idempotent) if the user actually backed up.
    QObject::connect(backupNowBtn, &QPushButton::clicked, [this]() {
        backupWallet();
        if (Settings::getInstance()->isWalletBackedUp() && homeBackupCard)
            homeBackupCard->setVisible(false);
    });
    backupRow->addWidget(backupNowBtn);
    backupRow->addStretch();

    backupV->addWidget(homeBackupText);
    backupV->addLayout(backupRow);

    homeBackupCard->setVisible(false);   // hidden until showBackupNag() surfaces it
    summaryVBox->insertWidget(insertAt++, homeBackupCard);

    // ---- 3c) IMPORT / RESCAN CARD (amber; hidden unless importing) ----------
    // First-run trust: after "Import private keys" the daemon rescans the chain
    // silently (no runtime status string, no %). This non-blocking card makes that
    // wait VISIBLE and calm with an indeterminate busy bar + accurate copy, instead
    // of a frozen-looking balance. Reuses the same amber QSS objectNames.
    homeImportCard = new QFrame(ui->tab);
    homeImportCard->setObjectName("homeFixItCard");   // reuse amber-card qss rule
    homeImportCard->setFrameShape(QFrame::NoFrame);
    auto* importV = new QVBoxLayout(homeImportCard);
    importV->setContentsMargins(12, 12, 12, 12);
    importV->setSpacing(8);

    auto* importText = new QLabel(
        tr("Importing your keys and rescanning the blockchain. This usually takes "
           "10-20 minutes — your balance will update when it finishes. You can keep "
           "using ZClassic; please leave it open."),
        homeImportCard);
    importText->setObjectName("homeFixItText");       // reuse amber-body qss rule
    importText->setWordWrap(true);

    homeImportBar = new QProgressBar(homeImportCard);
    homeImportBar->setObjectName("homeImportBar");
    homeImportBar->setRange(0, 0);                    // indeterminate / busy
    homeImportBar->setTextVisible(false);

    importV->addWidget(importText);
    importV->addWidget(homeImportBar);

    homeImportCard->setVisible(false);   // hidden until showImportProgress(true)
    summaryVBox->insertWidget(insertAt++, homeImportCard);

    // ---- 4) COLLAPSE the redundant Summary breakdown (Polish P1) ------------
    // The balance was shown up to 4x (hero + Total subline + these standalone
    // Shielded/Transparent/Total rows + the Address Balances table). The hero now
    // leads with Private + a dim Total subline, and the per-address detail lives
    // badge-tagged in Address Balances. So HIDE the standalone breakdown rows +
    // their divider. We do NOT delete the balSheilded/balTransparent/balTotal
    // labels — rpc.cpp still writes them and updateHomeFixIt() reads them back into
    // the hero; they simply become hidden data carriers.
    auto hideIfPresent = [](QWidget* w) { if (w) w->setVisible(false); };
    hideIfPresent(ui->label);            // "Shielded" caption
    hideIfPresent(ui->balSheilded);
    hideIfPresent(ui->label_2);          // "Transparent" caption
    hideIfPresent(ui->balTransparent);
    hideIfPresent(ui->label_3);          // "Total" caption
    hideIfPresent(ui->balTotal);
    hideIfPresent(ui->line);             // the divider above Total
}

// Phase-3b: keep the Home dashboard in step with the live balances. Called from
// rpc.cpp's refreshBalances() (and the cached-balance restore) right after the
// balSheilded/balTransparent/balTotal labels are set, mirroring that pattern.
//   * HERO: read back the freshly-set balSheilded (private) + balTotal label text
//     so the big number always matches the canonical labels with no re-format.
//   * FIX-IT card: visible ONLY when transparent > 0; the message names the exact
//     public amount. A tiny epsilon guards against float dust below a displayable
//     unit so a true-zero never shows the card.
void MainWindow::updateHomeFixIt(double transparent, bool fromCache) {
    // ---- ITEM 1: trust-aware hero — ONE state-driven pass ------------------------
    // Derive the hero state from inputs that already exist (the canonical balance
    // labels, Settings::isSyncing(), the cache epoch) plus the heroLivePainted session
    // flag. The number is ALWAYS painted (never blank); only its CONFIDENCE (green vs
    // neutral grey) and an inline qualifier change with state.
    //
    //   SYNCED  : live paint (!fromCache) && NOT syncing && a REAL number -> confident green
    //   WARMING : fromCache || isSyncing() || no real number yet -> grey + "not final" line
    //   FRESH   : WARMING with no number yet & no cache -> deterministic "0 <token>"
    //
    // Crucial correctness rule: green is reachable ONLY from the synced edge, and the
    // synced edge clears the qualifier in the SAME pass — so a cached/warming number is
    // never confident-green and a real synced number is never hidden behind a stale label.
    const QString balZText  = ui->balSheilded->text();
    const QString balTotTxt = ui->balTotal->text().trimmed();
    const bool    haveNumber = !balZText.trimmed().isEmpty();

    // haveNumber is REQUIRED for the synced edge: noConnection() (rpc.cpp:663) calls
    // this with the default fromCache=false and does NOT raise the syncing flag (its
    // single writer is the live status poll), but it FIRST blanks balSheilded to "".
    // Requiring a real (non-blank) number means a disconnect — or a fresh install
    // before the first status poll — reads WARMING grey-zero, never a confident green
    // zero painted over the user's just-cleared balance.
    const bool synced  = !fromCache && !Settings::getInstance()->isSyncing() && haveNumber;
    const bool warming = !synced;   // cached restore, mid-sync, disconnect, or no real number yet

    if (synced)
        heroLivePainted = true;     // latch: a live, non-syncing, real balance has been painted

    // Mirror the canonical labels into the hero. On a true FRESH install the labels are
    // still empty (""), so substitute a deterministic zero rather than paint a blank card.
    // Narrow-window fix: stash the FULL strings in members and let relayoutHero() set the
    // (possibly elided) display text, so the 40pt number never pins the window width yet
    // still copies/re-expands to its true value. relayoutHero() runs here AND on resize.
    heroPrivateFull = haveNumber ? balZText
                                 : Settings::getZCLDisplayFormat(0.0);
    heroTotalFull   = tr("Total: %1").arg(haveNumber ? ui->balTotal->text()
                                                     : Settings::getZCLDisplayFormat(0.0));
    relayoutHero();

    // Confidence colour: a dynamic property on the big number, repolished so the qss
    // recomputes (same idiom as the homeaction swap below). dark.qss owns green vs grey.
    if (homeHeroPrivate) {
        homeHeroPrivate->setProperty("heroconfident", synced);
        homeHeroPrivate->style()->unpolish(homeHeroPrivate);
        homeHeroPrivate->style()->polish(homeHeroPrivate);
    }

    // Inline qualifier: shown only while warming. Prefer the cache epoch ("Last updated
    // <when> · refreshing"); fall back to a generic "not final yet" when no epoch exists.
    if (homeHeroQualifier) {
        if (warming) {
            qint64 epoch = QSettings().value("cache/lastSyncEpoch", (qint64) 0).toLongLong();
            if (epoch > 0) {
                QString when = QDateTime::fromSecsSinceEpoch(epoch).toString("MMM d, h:mm AP");
                homeHeroQualifier->setText(tr("Last updated %1 · refreshing").arg(when));
            } else {
                homeHeroQualifier->setText(tr("Updating… not final yet"));
            }
        }
        homeHeroQualifier->setVisible(warming);
    }

    // Polish P1/UX-22: friendly empty-state helper under the hero when the wallet
    // has nothing yet. Parse the canonical Total label (e.g. "0 ZCL"); show the
    // helper only at true-zero. Make Receive the primary action when balance == 0
    // (see the quick-action swap below).
    const bool isEmpty = !haveNumber
                      || balTotTxt.startsWith("0 ")
                      || balTotTxt == "0"
                      || balTotTxt.isEmpty();
    if (homeHeroHelper)
        homeHeroHelper->setVisible(isEmpty);
    if (homeSendBtn && homeReceiveBtn) {
        // When empty, Receive becomes primary (green) and Send is demoted; once
        // funded, Send leads again. Property "homeaction" drives the qss + default.
        homeSendBtn->setDefault(!isEmpty);
        homeReceiveBtn->setDefault(isEmpty);
        homeSendBtn->setProperty("homeaction", isEmpty ? "secondary" : "primary");
        homeReceiveBtn->setProperty("homeaction", isEmpty ? "primary" : "secondary");
        // Re-polish so the property change repaints (Qt caches computed style).
        homeSendBtn->style()->unpolish(homeSendBtn);
        homeSendBtn->style()->polish(homeSendBtn);
        homeReceiveBtn->style()->unpolish(homeReceiveBtn);
        homeReceiveBtn->style()->polish(homeReceiveBtn);
    }

    if (homeFixItCard != nullptr) {
        const bool hasPublic = transparent > 0.0000001;   // below a displayable unit => zero
        if (hasPublic) {
            if (homeFixItText)
                homeFixItText->setText(
                    tr("%1 is PUBLIC and visible to everyone.")
                        .arg(Settings::getZCLDisplayFormat(transparent)));
        }
        homeFixItCard->setVisible(hasPublic);
    }

    // PERF warm-latency t1 marker: the hero balance labels above are now set, i.e.
    // the user-visible balance has been (re)painted. Emitted unconditionally (after
    // the hero is updated) on EVERY balance update so the perf22 harness can time the
    // onNotifyPush -> painted latency. No-op in the shipped app (no listeners).
    emit heroBalancesPainted();
}

// PRIV-18 — the REAL "Shield public funds" action behind the Home fix-it button.
// Reuses the SAME semantics as the balances context-menu "Shield balance to
// Sapling" path: select the largest transparent source as From, fill the default
// Sapling z-address (auto-created if none exists, PRIV-19/PRIV-28) as the To
// recipient, check Max, and navigate to the Send page for the user to confirm.
// It does NOT auto-execute -- the user reviews + confirms (this is a t->z shielding
// send, classified TToZ_shielding, so NO de-shield acknowledgement is added).
void MainWindow::shieldPublicFunds() {
    if (!rpc)
        return;

    // MINOR-1 null-deref guard: getDefaultSaplingAddress() below dereferences the
    // zaddresses list, which is null until the first refreshAddresses(). Mirror
    // ensureSaplingProvisioned()'s readiness guard -- if the connection or the
    // z-address list isn't up yet, do NOT dump the user on a blank Send form with no
    // explanation: keep them on Home and show a brief, friendly status so they know
    // to retry shielding in a moment.
    if (!rpc->getConnection() || !rpc->getAllZAddresses()) {
        ui->statusBar->showMessage(
            tr("ZClassic is still getting ready — try shielding again in a moment."),
            5 * 1000);
        return;
    }

    // 1) Pick the source transparent (t) address. Prefer the t-addr with the largest
    //    CONFIRMED, spendable balance: a t-addr that is "largest" only because of
    //    unconfirmed funds would auto-fill Send-max = 0 (the daemon won't spend 0-conf),
    //    leaving the user on a Send form that can't go through. spendableOrFallback()
    //    fails open to the minconf=0 total when the UTXO set isn't loaded, so we never
    //    refuse to shield just because UTXO data is still warming up. We ALSO track the
    //    largest minconf=0 (displayed) t-addr balance so we can (a) fall back to it when
    //    nothing is confirmed yet and (b) decide whether there is genuinely anything to
    //    shield at all.
    QString fromT;
    double  bestBal       = 0;   // largest CONFIRMED-spendable t-addr balance
    QString bestDispAddr;
    double  bestDisplayed = 0;   // largest minconf=0 (displayed, incl. 0-conf) t-addr balance
    if (rpc->getAllBalances()) {
        for (auto it = rpc->getAllBalances()->constBegin(); it != rpc->getAllBalances()->constEnd(); ++it) {
            if (!Settings::isTAddress(it.key()))
                continue;
            if (it.value() > bestDisplayed) {
                bestDisplayed = it.value();
                bestDispAddr  = it.key();
            }
            double spendable = spendableOrFallback(it.key());
            if (spendable > bestBal) {
                bestBal = spendable;
                fromT   = it.key();
            }
        }
    }
    if (fromT.isEmpty()) {
        // No t-addr has confirmed-spendable funds (e.g. everything is still confirming).
        // Fall back to the largest minconf=0 t-addr so the user still lands on the right
        // source; the spendable-based Send-max will then be small/0 and the calm
        // "still confirming" guard in doSendTxValidations explains why.
        fromT = bestDispAddr;
    }
    if (fromT.isEmpty()) {
        // Fall back to any known t-address; if there are genuinely no public funds,
        // there is nothing to shield -- just open Send.
        fromT = rpc->getDefaultTAddress();
    }
    // Nothing to shield AT ALL (no confirmed AND no pending public funds): do not run a
    // blocking Sapling create or set up a doomed Amount=0 shield -- just open Send. We
    // gate on the DISPLAYED (minconf=0) total, not the spendable figure, so the
    // all-funds-still-confirming case (bestBal==0 but bestDisplayed>0) still proceeds and
    // is explained by the "still confirming" guard rather than being silently dropped.
    if (fromT.isEmpty() || bestDisplayed <= 0.0000001) {
        ui->tabWidget->setCurrentIndex(1);
        return;
    }

    // 2) Resolve the default Sapling destination, AUTO-CREATING one if none exists
    //    (PRIV-19: callers must never degrade to Sprout/transparent).
    QString toZ = rpc->getDefaultSaplingAddress();
    if (toZ.isEmpty())
        toZ = createSaplingAddressSync();
    if (toZ.isEmpty()) {
        // Could not provision a shielded destination -- do not silently shield to a
        // non-private address; tell the user and bail to Send.
        QMessageBox::warning(this, tr("Could not shield"),
            tr("A shielded (Sapling) address could not be created right now, so your "
               "public funds were not shielded. Please try again in a moment."),
            QMessageBox::Ok);
        ui->tabWidget->setCurrentIndex(1);
        return;
    }

    // 3) Set up the send page exactly like the context-menu shield path:
    //    From = the transparent source, To = the Sapling z-address, Max checked.
    for (int i = 0; i < ui->inputsCombo->count(); i++) {
        if (ui->inputsCombo->itemText(i).startsWith(fromT)) {
            ui->inputsCombo->setCurrentIndex(i);
            break;
        }
    }
    removeExtraAddresses();
    ui->Address1->setText(toZ);
    ui->Max1->setChecked(true);

    // 4) Navigate to Send for explicit user review + confirm.
    ui->tabWidget->setCurrentIndex(1);
}

// PRIV-28 — eager Sapling provisioning. Ensure at least ONE Sapling z-address
// exists so the send/shield path never has to block on key generation (the
// synchronous mid-send create is only a last resort). Idempotent + one-shot per
// run: returns immediately if a Sapling address already exists or if we've already
// attempted provisioning this session. Called from the address-refresh path once
// addresses are known.
void MainWindow::ensureSaplingProvisioned() {
    if (saplingProvisionAttempted)
        return;
    if (!rpc || !rpc->getConnection() || !rpc->getAllZAddresses())
        return;   // not ready yet; will be retried on a later refresh

    // Already have a Sapling address? Then nothing to do (mark attempted so we don't
    // keep scanning the list on every refresh).
    if (!rpc->getDefaultSaplingAddress().isEmpty()) {
        saplingProvisionAttempted = true;
        return;
    }

    // No Sapling address yet -> create one in the background (non-blocking). Mark
    // attempted up front so concurrent refreshes don't fire multiple creates.
    saplingProvisionAttempted = true;
    rpc->newZaddr(true, [this](json reply) {
        if (reply.is_string())
            rpc->refreshAddresses();   // pull the freshly-minted address into the wallet
    });
}

// Phase-3a redesign (Quiet+): the modern left vertical NAV RAIL.
//
// LOW-RISK, PROGRAMMATIC build — no .ui structural change. We DO NOT remove,
// rename, or recreate any widget, and we DO NOT swap the QTabWidget for a
// QStackedWidget. Instead:
//   * The QTabWidget keeps all of its pages/objectNames; we only HIDE its
//     tabBar(). Pages remain index-selectable (setCurrentIndex still works), so
//     the L0/L1 harness — which drives Receive radios on tab_3 directly and
//     never touches the now-hidden tabBar — stays green.
//   * We build a QFrame#navRail of flat, checkable QPushButtons in an EXCLUSIVE
//     QButtonGroup, each wired to ui->tabWidget->setCurrentIndex(idx).
//   * We re-parent the central content into a horizontal layout
//     [ navRail | tabWidget ] by inserting the rail at column 0 of the existing
//     centralWidget grid (gridLayout_3) and moving the tabWidget to column 1.
//   * syncBanner is a child of ui->tab (the Balance page) and sits ABOVE that
//     page's content via gridLayout_2; it is unaffected and stays above the
//     content, spanning the content column (not the rail), exactly as required.
// Narrow-window fix: re-elide the Home hero number/total to the labels' CURRENT width so
// the 40pt balance shows an ellipsis instead of either pinning a large minimum width or
// hard-clipping mid-glyph. The full (un-elided) value lives in heroPrivateFull/heroTotalFull
// so text-selection copies the real number and it re-expands when the window widens. Called
// from updateHomeFixIt() (text-set) and resizeEvent() (geometry change). Cheap + idempotent.
void MainWindow::relayoutHero() {
    if (homeHeroPrivate) {
        int w = homeHeroPrivate->width();
        // Width is 0 before the first layout pass; show the full string then (resizeEvent
        // re-elides once a real width exists). elidedText with w<=0 would blank the label.
        QString shown = (w > 0)
            ? QFontMetrics(homeHeroPrivate->font()).elidedText(heroPrivateFull, Qt::ElideRight, w)
            : heroPrivateFull;
        if (homeHeroPrivate->text() != shown)
            homeHeroPrivate->setText(shown);
        // Keep the real value reachable on hover even when elided.
        homeHeroPrivate->setToolTip(shown == heroPrivateFull ? QString() : heroPrivateFull);
    }
    if (homeHeroTotal) {
        int w = homeHeroTotal->width();
        QString shown = (w > 0)
            ? QFontMetrics(homeHeroTotal->font()).elidedText(heroTotalFull, Qt::ElideRight, w)
            : heroTotalFull;
        if (homeHeroTotal->text() != shown)
            homeHeroTotal->setText(shown);
        homeHeroTotal->setToolTip(shown == heroTotalFull ? QString() : heroTotalFull);
    }
}

// Narrow-window fix: re-elide the hero on every resize so the number tracks the available
// width (shrinks with an ellipsis as the window narrows, re-expands as it widens). Base
// behaviour first, then our pass.
void MainWindow::resizeEvent(QResizeEvent* event) {
    QMainWindow::resizeEvent(event);
    relayoutHero();
}

void MainWindow::setupNavRail() {
    // 1) Hide the tab bar — pages stay; index selection still works.
    ui->tabWidget->tabBar()->hide();
    // The pane border/top-padding was sized for the (now hidden) tab strip; with
    // the rail driving navigation, drop the document-mode chrome so page content
    // sits flush against the rail.
    ui->tabWidget->setDocumentMode(true);

    // 2) Build the rail frame + its vertical layout.
    auto* navRail = new QFrame(ui->centralWidget);
    navRail->setObjectName("navRail");
    navRail->setFrameShape(QFrame::NoFrame);
    navRail->setFixedWidth(168);   // ~150-190px, on the 8px grid (21*8)

    auto* railLayout = new QVBoxLayout(navRail);
    railLayout->setContentsMargins(8, 16, 8, 16);
    railLayout->setSpacing(6);

    // 3) Exclusive group so exactly one destination is highlighted at a time.
    navRailGroup = new QButtonGroup(this);
    navRailGroup->setExclusive(true);

    // Helper: a large, flat, checkable rail button bound to a tab index.
    auto makeRailButton = [&](const QString& label, int tabIndex,
                              const QString& extraObjName = QString()) -> QPushButton* {
        auto* btn = new QPushButton(label, navRail);
        btn->setObjectName(extraObjName.isEmpty() ? "navRailButton" : extraObjName);
        btn->setCheckable(true);
        btn->setFlat(true);
        btn->setCursor(Qt::PointingHandCursor);
        btn->setProperty("navrail", true);   // qss hook: QPushButton[navrail="true"]
        btn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        navRailGroup->addButton(btn, tabIndex);
        railLayout->addWidget(btn);
        QObject::connect(btn, &QPushButton::clicked, [this, tabIndex]() {
            ui->tabWidget->setCurrentIndex(tabIndex);
        });
        return btn;
    };

    // 4) Primary destinations, in human order. Indices are the LIVE tabWidget
    //    indices at this point (zclassicd already removed): Balance 0, Send 1,
    //    Receive 2, Transactions 3.
    makeRailButton(tr("Home"),     0);   // Balance
    makeRailButton(tr("Send"),     1);
    makeRailButton(tr("Receive"),  2);
    makeRailButton(tr("Activity"), 3);   // Transactions

    // Spacer pushes the demoted "Advanced" gear to the BOTTOM of the rail.
    railLayout->addStretch(1);

    // 5) Demoted node-stats page ("zclassicd") as a small gear at the bottom.
    //    That page is added to the tabWidget LATER (rpc.cpp, when the embedded
    //    node starts) and lives at whatever index it then occupies, so resolve
    //    its index dynamically on click. It is NOT in the exclusive primary
    //    group's check-sync set above; we give it its own checkable button and
    //    add it to the same group so selecting it clears the others.
    auto* advBtn = new QPushButton(tr("⚙  Advanced"), navRail);
    advBtn->setObjectName("navRailAdvanced");
    advBtn->setCheckable(true);
    advBtn->setFlat(true);
    advBtn->setCursor(Qt::PointingHandCursor);
    advBtn->setProperty("navrail", true);
    advBtn->setProperty("navrailadv", true);   // qss hook for the smaller gear
    advBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    // Use a high group id so it never collides with a primary tab index.
    navRailGroup->addButton(advBtn, 1000);
    railLayout->addWidget(advBtn);
    QObject::connect(advBtn, &QPushButton::clicked, [this]() {
        // Find the zclassicd page in the live tabWidget; switch to it if present.
        int idx = ui->tabWidget->indexOf(zclassicdtab);
        if (idx >= 0) {
            ui->tabWidget->setCurrentIndex(idx);
            return;
        }

        // ADVANCED-TAB-FIX: the tab is added on the live-connection attach
        // (RPC::setConnection). In the sub-second cold-open window BEFORE that
        // attach fires, the tab is still absent (indexOf == -1). Never leave the
        // click a SILENT no-op (Krug: don't-make-me-think): give honest feedback,
        // then re-sync the rail's checked state so the gear does not get stuck
        // "checked" while a primary tab (e.g. Balances) is still shown. We mirror
        // the currentChanged sync handler below: under a QSignalBlocker, re-check
        // the button for the current tab so the rail reflects reality.
        ui->statusBar->showMessage(
            tr("Advanced (node stats) opens once you're connected to a node."), 3000);
        if (navRailGroup) {
            QAbstractButton* match = navRailGroup->button(ui->tabWidget->currentIndex());
            if (match) {
                QSignalBlocker block(navRailGroup);
                match->setChecked(true);
            }
        }
    });

    // 6) Keep the rail's checked state synced to the CURRENT tab index, from any
    //    source (rail click, code-driven setCurrentIndex in sendButton/receive
    //    flows, or the zclassicd tab being added/removed at runtime).
    QObject::connect(ui->tabWidget, &QTabWidget::currentChanged, this, [this](int idx) {
        if (!navRailGroup) return;
        int advIdx = ui->tabWidget->indexOf(zclassicdtab);
        QAbstractButton* match = nullptr;
        if (advIdx >= 0 && idx == advIdx) {
            match = navRailGroup->button(1000);          // Advanced
        } else {
            match = navRailGroup->button(idx);            // a primary destination
        }
        if (match && !match->isChecked()) {
            // Toggle without re-emitting a navigation click.
            QSignalBlocker block(navRailGroup);
            match->setChecked(true);
        }
    });

    // 7) Re-parent: make the central layout horizontal — [ navRail | tabWidget ].
    //    gridLayout_3 currently holds tabWidget at (0,0). Move it to (0,1) and
    //    drop the rail in at (0,0). We move the EXISTING tabWidget, not a copy.
    auto* central = qobject_cast<QGridLayout*>(ui->centralWidget->layout());
    if (central) {
        central->removeWidget(ui->tabWidget);
        central->setContentsMargins(0, 0, 0, 0);
        central->setSpacing(0);
        central->addWidget(navRail,       0, 0);
        central->addWidget(ui->tabWidget, 0, 1);
        central->setColumnStretch(0, 0);   // rail: fixed width
        central->setColumnStretch(1, 1);   // content: takes the rest
    } else {
        // Fallback (shouldn't happen given the .ui): wrap in a fresh HBox.
        auto* hbox = new QHBoxLayout(ui->centralWidget);
        hbox->setContentsMargins(0, 0, 0, 0);
        hbox->setSpacing(0);
        hbox->addWidget(navRail);
        hbox->addWidget(ui->tabWidget, 1);
    }

    // 8) Open on Home (Balance, index 0) — not Receive. Check the Home button to
    //    match. (The .ui's currentIndex=2 default is overridden here and by the
    //    ctor's setCurrentIndex(0).)
    ui->tabWidget->setCurrentIndex(0);
    if (auto* home = navRailGroup->button(0))
        home->setChecked(true);
}

// PR-1 (snappiness): apply the banner stylesheet ONLY when it actually changes.
// setStyleSheet() forces QStyleSheetStyle to re-parse the sheet and unpolish/
// repolish the widget subtree + a relayout even when the string is byte-identical
// to what is already applied. The poll calls setSyncStatus() every 5s during sync
// with the SAME orange sheet, and the at-rest heartbeat re-applies the SAME
// transparent sheet -- so dirty-checking against the cached last-applied sheet
// turns every same-state tick into a no-op (one QString compare), removing a
// recurring micro-hitch on the most-watched screen. Pure main-thread.
void MainWindow::applyBannerStyle(const QString& sheet) {
    if (syncBanner == nullptr) return;
    if (sheet == lastBannerSheet) return;   // already applied; skip the re-polish
    lastBannerSheet = sheet;
    syncBanner->setStyleSheet(sheet);
}

// P0-6: called from rpc.cpp's getblockchaininfo poll on every refresh.
void MainWindow::setSyncStatus(bool isSyncing, int blockNumber, int estimatedHeight, double progress) {
    if (syncBanner == nullptr) return;

    if (!isSyncing) {
        // Fully caught up. Polish P0-2: DON'T shout a full-width green bar at rest.
        // Hide the loud banner content + drop the colored fill (transparent), and
        // show the quiet inline "● Synced" pill. Green lives on the balance hero.
        syncEtaStarted = false;
        syncProgressBar->setVisible(false);
        syncProgressBar->setRange(0, 100);   // reset in case it was indeterminate
        syncStatusLabel->setVisible(false);
        if (syncQuietPill) {
            // P2-4: the quiet pill is the ONLY at-rest indicator. Read it as a clean
            // "Synced · block N" with thousands-separated height (single source =
            // Settings::getHeightString). No "checking blockchain…" once caught up.
            QString pill = tr("<span style=\"color:#34c759;\">●</span>&nbsp;&nbsp;Synced");
            if (blockNumber > 0)
                pill = pill % "&nbsp;&nbsp;·&nbsp;&nbsp;" %
                    tr("block %1").arg(Settings::getHeightString(blockNumber));
            syncQuietPill->setText(pill);
            syncQuietPill->setVisible(true);
        }
        applyBannerStyle("QWidget { background-color: transparent; }");
        return;
    }

    // Any syncing/error/connecting state: the full-width colored banner is the
    // indicator, so the quiet pill steps aside and the bold label comes back.
    if (syncQuietPill) syncQuietPill->setVisible(false);
    syncStatusLabel->setVisible(true);

    // Indeterminate: we are syncing but have no usable target yet (e.g. the node's
    // header height isn't known on the first poll). Show a busy bar and a friendly
    // "starting" message rather than a misleading 0%/height/ETA.
    bool indeterminate = isSyncing && (estimatedHeight <= 0 || progress < 0.0);
    if (indeterminate) {
        syncEtaStarted = false;
        syncProgressBar->setVisible(true);
        syncProgressBar->setRange(0, 0);     // busy/indeterminate animation
        // Include the live block height so the text VISIBLY changes as blocks arrive,
        // rather than a frozen "Starting your node…" that reads as stuck on a slow link.
        // When the node already has a tip (blockNumber > 0) it is finding peers / confirming
        // the chain; before that it is genuinely still starting.
        if (blockNumber > 0)
            syncStatusLabel->setText(tr("Starting your node… (block %1, connecting to peers)")
                .arg(blockNumber));
        else
            syncStatusLabel->setText(tr("Starting your node…"));
        applyBannerStyle("QWidget { background-color: #d9822b; } QLabel { color: white; }");
        return;
    }

    // Syncing: show a progress bar and an estimated time remaining. qRound (not a
    // truncating cast) so e.g. 99.6% reads 100, not 99.
    int pct = qRound(progress * 100.0);
    if (pct < 0)   pct = 0;
    if (pct > 100) pct = 100;
    syncProgressBar->setVisible(true);
    syncProgressBar->setRange(0, 100);       // reset in case it was indeterminate
    syncProgressBar->setValue(pct);

    QString etaText;
    if (estimatedHeight > 0 && blockNumber > 0) {
        if (!syncEtaStarted) {
            syncEtaStarted = true;
            syncEtaStartBlock = blockNumber;
            syncEtaTimer.restart();
        } else {
            qint64 elapsedMs = syncEtaTimer.elapsed();
            int    blocksDone = blockNumber - syncEtaStartBlock;
            if (elapsedMs > 2000 && blocksDone > 0) {
                double blocksPerSec = (double) blocksDone / (elapsedMs / 1000.0);
                int    remaining    = estimatedHeight - blockNumber;
                if (blocksPerSec > 0.0 && remaining > 0) {
                    qint64 secsLeft = (qint64) (remaining / blocksPerSec);
                    QString human;
                    if (secsLeft >= 3600)
                        human = tr("about %1h %2m").arg(secsLeft / 3600).arg((secsLeft % 3600) / 60);
                    else if (secsLeft >= 60)
                        human = tr("about %1m").arg(secsLeft / 60);
                    else
                        human = tr("less than a minute");
                    etaText = QString(" • ") % tr("ETA %1").arg(human);
                }
            }
        }
    }

    QString heightText;
    if (estimatedHeight > 0) {
        heightText = QString(" • ") % tr("block %1 / ~%2")
            .arg(QString::number(blockNumber), QString::number(estimatedHeight));
    }

    syncStatusLabel->setText(tr("Syncing blockchain… %1%").arg(pct) % heightText % etaText);
    applyBannerStyle("QWidget { background-color: #d9822b; } QLabel { color: white; }");
}

// P0-6: called from rpc.cpp's noConnection() so the user sees a clear,
// non-alarming "connecting" state instead of a blank/stuck UI.
void MainWindow::setSyncStatusConnecting() {
    if (syncBanner == nullptr) return;
    syncEtaStarted = false;
    syncProgressBar->setVisible(false);
    if (syncQuietPill) syncQuietPill->setVisible(false);
    syncStatusLabel->setVisible(true);
    syncStatusLabel->setText(tr("Connecting to your ZClassic node…"));
    applyBannerStyle("QWidget { background-color: #555555; } QLabel { color: white; }");
}

// C9: called from rpc.cpp when the node is "syncing" but has 0 peers. A fresh
// install with no peers would otherwise sit on a stuck "Syncing 0%" -- this tells
// the user the real problem (no network) instead.
void MainWindow::setSyncStatusWaitingForPeers(bool longStretch) {
    if (syncBanner == nullptr) return;
    syncEtaStarted = false;
    if (syncQuietPill) syncQuietPill->setVisible(false);
    syncStatusLabel->setVisible(true);
    syncProgressBar->setVisible(false);
    syncProgressBar->setRange(0, 100);   // reset in case it was indeterminate
    if (longStretch)
        syncStatusLabel->setText(tr("Still waiting for peers… please check your internet "
            "connection and try again later"));
    else
        syncStatusLabel->setText(tr("Waiting for peers… check your internet connection"));
    applyBannerStyle("QWidget { background-color: #d9822b; } QLabel { color: white; }");
}

// Bootstrap snapshot download in progress: show real determinate progress instead of
// the misleading "waiting for peers". The node reports 0 normal P2P peers while it
// downloads the snapshot, but it is actively working -- not stuck.
void MainWindow::setSyncStatusBootstrapSnapshot(int pct, qint64 received, qint64 total, double mbps) {
    if (syncBanner == nullptr) return;
    syncEtaStarted = false;
    if (syncQuietPill) syncQuietPill->setVisible(false);
    syncStatusLabel->setVisible(true);
    if (pct < 0)   pct = 0;
    if (pct > 100) pct = 100;
    syncProgressBar->setVisible(true);
    syncProgressBar->setRange(0, 100);
    syncProgressBar->setValue(pct);

    QString detail;
    if (total > 0) {
        const double gb = 1024.0 * 1024.0 * 1024.0;
        detail = QString(" • ") % tr("%1 / %2 GB")
            .arg(received / gb, 0, 'f', 1).arg(total / gb, 0, 'f', 1);
    }
    if (mbps > 0.0)
        detail = detail % QString(" • ") % tr("%1 MB/s").arg(mbps, 0, 'f', 1);

    syncStatusLabel->setText(tr("Downloading blockchain snapshot… %1%").arg(pct) % detail);
    applyBannerStyle("QWidget { background-color: #d9822b; } QLabel { color: white; }");
}

// SELF-HEAL (B-side): non-blocking validation banner. An empty message clears it
// (the next sync poll repaints the normal state). A non-empty message overlays a
// neutral-blue informational banner reusing the same syncBanner widget. It is
// called AFTER setSyncStatus on each poll, so an active validation message wins for
// that tick without disturbing the headers-vs-progress sync logic.
void MainWindow::setBootstrapValidationBanner(const QString& msg) {
    if (syncBanner == nullptr) return;
    if (msg.isEmpty())
        return;   // nothing to show; leave whatever setSyncStatus painted this tick
    if (syncQuietPill) syncQuietPill->setVisible(false);
    syncStatusLabel->setVisible(true);
    syncProgressBar->setVisible(false);
    syncStatusLabel->setText(msg);
    applyBannerStyle("QWidget { background-color: #2c5d8f; } QLabel { color: white; }");
}

// Non-modal notification. Prefer a system-tray balloon (visible even when the main
// window is hidden in tray-resident mode); fall back to a status-bar message when
// there is no tray. Used by the background node-crash recovery so it never pops a
// modal over a hidden window.
void MainWindow::notify(const QString& title, const QString& body) {
    if (trayIcon != nullptr && QSystemTrayIcon::isSystemTrayAvailable()) {
        trayIcon->showMessage(title, body, QSystemTrayIcon::Information, 6000);
    } else {
        ui->statusBar->showMessage(title % ": " % body, 10 * 1000);
    }
    logger->write("notify: " % title % " — " % body);
}

// SINGLE launch path for the "stop the node, then drive the staged re-download ladder"
// flow. Both the always-reachable Help -> Repair action and the runtime stub auto-heal
// (autoHealStubChain) call THIS — there is no second destructive path. It stops the
// running embedded node (a no-op + bounded wait for an external daemon we don't own),
// then spins up a fresh ConnectionLoader (the old one is deleted post-handoff) and
// invokes startManualRepair(), which runs offerCorruptionRepair()/redownloadChain()
// with all their existing guards (confirmDaemonDeadForRepair, wallet.dat backup, the
// ~15 GB disk floor, reversible set-aside rename).
void MainWindow::launchBlockchainRepair() {
    // Stop the running embedded node so there are no open LevelDB handles before any
    // set-aside/reindex. shutdownZClassicd() is a no-op for an external daemon (we
    // don't own its lifetime) and waits (bounded) for exit.
    rpc->shutdownZClassicd();

    // Fresh loader: ConnectionLoader is deleted post-handoff, so we create a new one
    // exactly like the settings-change path does, then drive the ladder.
    auto* cl = new ConnectionLoader(this, rpc);
    cl->startManualRepair();
}

// RUNTIME STUB AUTO-HEAL entry. Called from the post-connection sync poller (rpc.cpp)
// ONLY when ALL of its conservative triggers hold (sustained 0 peers AND a blocks/ dir
// far below a real chain AND not already auto-healed this run/cooldown). It is the
// runtime analogue of the Help -> Repair action: it reuses the EXACT same launch path
// (launchBlockchainRepair -> startManualRepair -> redownloadChain), so every existing
// safety guard applies. It is intentionally NON-interactive (no confirm dialog) but it
// surfaces a clear status first; the destructive work still goes through
// redownloadChain()'s daemon-dead/backup/disk/set-aside guards. The poller owns the
// trigger arithmetic and the per-process / per-install-cooldown guards; this method
// just performs the heal. Returns immediately (no-op) if a heal is already in flight.
void MainWindow::autoHealStubChain() {
    // Serialize with the heal ledger so this can't race a startup/watchdog heal that is
    // already mid-flight (mainwindow.cpp clears a stale heal/inProgress once at process
    // start, so a value seen here is a LIVE in-progress heal this run).
    if (QSettings().value("heal/inProgress", false).toBool()) {
        logger->write("autoHealStubChain: a heal is already in progress; skipping");
        return;
    }

    logger->write("autoHealStubChain: stub chain + sustained peerless -> re-downloading blockchain");

    // Clear, visible status (never a silent wipe). The connect dialog spun up by the
    // fresh ConnectionLoader / redownloadChain's own "Re-downloading…" information box
    // takes over from here, but paint the banner immediately so the moment is explained.
    if (syncStatusLabel != nullptr) {
        syncProgressBar->setVisible(false);
        syncStatusLabel->setText(tr("Re-downloading blockchain…"));
        applyBannerStyle("QWidget { background-color: #2c5d8f; } QLabel { color: white; }");
    }
    notify(tr("Re-downloading blockchain"),
        tr("ZClassic couldn't find any peers and the local copy is incomplete, so it is "
           "downloading a fresh copy. Your wallet and coins are safe."));

    launchBlockchainRepair();
}

// Local double-launch / "is anything still on the node ports?" probe for the runtime
// dialogs below (the connect-time ConnectionLoader::portsFree is private and there is no
// live loader at runtime). True iff BOTH the RPC port and the matching P2P port on
// 127.0.0.1 are currently UNBOUND. Mainnet 8023/8033, testnet 18023/18033; testnet is read
// from the authoritative Settings signal (matching edit #7).
static bool mwNodePortsFree() {
    bool testnet  = Settings::getInstance()->isTestnet();
    quint16 rpcPort = testnet ? 18023 : 8023;
    quint16 p2pPort = testnet ? 18033 : 8033;
    auto portInUse = [](quint16 port) -> bool {
        QTcpSocket probe;
        probe.connectToHost(QStringLiteral("127.0.0.1"), port);
        bool connected = probe.waitForConnected(150);   // refused/timeout => free
        probe.abort();
        return connected;
    };
    return !portInUse(rpcPort) && !portInUse(p2pPort);
}

// Relaunch this application as a fresh process, then quit the current one. Used as the
// primary "fix it" action of the runtime dialogs: after the user stops the foreign node,
// the relaunched wallet finds the ports free and starts/heals its OWN embedded node.
static void mwRelaunchSelf() {
    QStringList args = QApplication::arguments();
    if (!args.isEmpty())
        args.removeFirst();   // drop argv[0]
    QProcess::startDetached(QApplication::applicationFilePath(), args);
}

// RUNTIME actionable dialog for a FOREIGN node that is genuinely STUCK (attached, but
// peerless/not syncing for a sustained window). See the header. Persistent (looping/re-
// shown until resolved), actionable, retryable. Centred on STUCK, NOT "too old". NEVER
// kills/mutates the foreign node; NEVER a silent hang. The caller (rpc.cpp poller) guards
// it with a once-per-run bool so it cannot spam.
void MainWindow::showForeignNodeStuck() {
    logger->write("Showing foreign-node-stuck actionable dialog (attached node is peerless/not syncing)");

    for (;;) {
        QMessageBox box(this);
        box.setWindowTitle(tr("Another ZClassic node is running"));
        box.setIcon(QMessageBox::Warning);
        box.setTextFormat(Qt::RichText);
        box.setText(tr("This wallet is connected to a ZClassic node it did not start, "
                       "and that node is not syncing."));
        box.setInformativeText(tr(
            "The other node cannot find any peers, so the blockchain is not progressing. "
            "This wallet can download and repair the blockchain automatically — but only "
            "for a node it starts itself, so it can't fix the other one.<br><br>"
            "<b>Your wallet file and your coins are safe.</b> Nothing has been changed.<br><br>"
            "<b>To fix this:</b> stop the other node, then reopen this wallet so it can "
            "manage its own node.<br>"
            "&nbsp;&nbsp;• If it is another copy of ZClassic, simply close that window, or<br>"
            "&nbsp;&nbsp;• stop the <code>zclassicd</code> background process the same way you started it<br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;(for example via your service manager, or <code>pkill zclassicd</code>)."));

        // Offer "Use the bundled node" ONLY when the ports are ACTUALLY free right now
        // (the foreign node was already stopped) — re-checked on click below.
        bool portsAreFree = mwNodePortsFree();

        QPushButton* reopenBtn  = box.addButton(tr("Stop the other node, then reopen"),
                                                QMessageBox::AcceptRole);
        QPushButton* bundledBtn = portsAreFree
            ? box.addButton(tr("Use the bundled node"), QMessageBox::ActionRole)
            : nullptr;
        // W1-4: a dismissable "Remind me later" so a slow / temporarily-peerless node never
        // traps the user in a relaunch-or-quit modal. Dismissing just continues using the
        // wallet; the dialog stays suppressed (ezForeignStuckShown) until peers recover, then
        // re-fires if it gets stuck again. This is also the Escape / window-close action.
        QPushButton* laterBtn   = box.addButton(tr("Remind me later"), QMessageBox::RejectRole);
        QPushButton* quitBtn    = box.addButton(tr("Quit"), QMessageBox::DestructiveRole);
        box.setDefaultButton(reopenBtn);
        box.setEscapeButton(laterBtn);

        box.exec();
        QAbstractButton* clicked = box.clickedButton();

        if (clicked == bundledBtn) {
            // RE-CHECK at click time: never double-launch onto a held port.
            if (mwNodePortsFree()) {
                logger->write("Foreign-node-stuck: ports free; relaunching to start the bundled node");
                mwRelaunchSelf();
                quitApp();
                return;
            }
            logger->write("Foreign-node-stuck: ports still in use at click; re-showing");
            continue;   // still held — re-explain
        } else if (clicked == quitBtn) {
            logger->write("Foreign-node-stuck: Quit pressed");
            quitApp();
            return;
        } else if (clicked == reopenBtn) {
            logger->write("Foreign-node-stuck: relaunching app so this wallet manages its own node");
            mwRelaunchSelf();
            quitApp();
            return;
        } else {   // laterBtn or window-chrome close: dismiss and keep using the wallet
            logger->write("Foreign-node-stuck: 'Remind me later' — dismissed; will re-surface if still stuck after peers recover");
            return;
        }
    }
}

// 401 from a deliberately-EXTERNAL node. The bundled node's 401 is healed automatically
// (ConnectionLoader::handleEmbeddedAuthFailure) and never reaches here, so this is the one
// case where pointing the user at the credentials is correct and actionable. Krug-plain,
// Sierra-reassuring, NO terminal commands, and NEVER a dead end — it branches on WHERE the
// credentials actually live so the offered action always works.
// See header. Dedicated, side-effect-free reader: does the conf actually hold usable creds
// (rpcpassword line, OR a readable .cookie under its datadir)? Mirrors the connect path's
// base resolution (conf datadir= override else conf dir). NEVER logs the cookie contents.
bool MainWindow::confHasUsableCreds(const QString& confLocation) {
    if (confLocation.isEmpty())
        return false;

    QFile file(confLocation);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;

    QString dataDirOverride;
    bool    hasRpcPassword = false;
    {
        QTextStream in(&file);
        while (!in.atEnd()) {
            QString line = in.readLine();
            int s = line.indexOf(QLatin1Char('='));
            QString name  = (s < 0 ? line : line.left(s)).trimmed().toLower();
            QString value = (s < 0 ? QString() : line.mid(s + 1)).trimmed();
            if (name == QLatin1String("rpcpassword") && !value.isEmpty())
                hasRpcPassword = true;   // NEVER log `value`
            else if (name == QLatin1String("datadir"))
                dataDirOverride = value;
        }
    }
    file.close();

    if (hasRpcPassword)
        return true;

    // No password line -> a cookie under the daemon's datadir is the other usable source.
    QString base = !dataDirOverride.isEmpty()
                       ? dataDirOverride
                       : QFileInfo(confLocation).absoluteDir().absolutePath();
    if (base.isEmpty())
        return false;
    QString cookiePath = QDir::cleanPath(QDir(base).filePath(QStringLiteral(".cookie")));
    QFile ck(cookiePath);
    if (!ck.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;
    QTextStream cin(&ck);
    QString cookieLine = cin.readLine().trimmed();   // SECRET: presence only, never logged
    ck.close();
    return !cookieLine.isEmpty();
}

void MainWindow::showExternalNodeAuthFailed() {
    const QString confLoc   = Settings::getInstance()->getZClassicdConfLocation();
    // A conf path can exist yet hold NO usable creds (e.g. "server=1" only, with the running
    // node's creds on its command line). Only point the user at the FILE when the file truly
    // holds creds; otherwise route to the EDITABLE Settings branch so it is never a dead end.
    const bool    credsInConf = !confLoc.isEmpty() && confHasUsableCreds(confLoc);

    QMessageBox box(this);
    box.setIcon(QMessageBox::Information);
    box.setWindowTitle(tr("Let's reconnect to your node"));
    box.setText(tr("ZClassic reached your node, but the sign-in details weren't accepted."));

    if (credsInConf) {
        // Credentials come from a detected zclassic.conf that ACTUALLY holds them, so the
        // Edit -> Settings fields are read-only (setupSettingsModal disables them only when
        // the conf has usable creds). A cred-less conf takes the editable branch below.
        // Pointing at Settings would be a dead end — point at the file instead, with a
        // one-click button that opens its folder.
        box.setInformativeText(tr(
            "Your node reads its RPC username and password from this file:\n\n%1\n\n"
            "They don't match the node that's running right now. Update them there (or in "
            "your node's own settings) so they match, then open ZClassic again. Nothing is "
            "wrong with your wallet or your coins — they're safe.").arg(confLoc));
        QPushButton* showBtn = box.addButton(tr("Show me the file"), QMessageBox::AcceptRole);
        box.addButton(tr("Not now"), QMessageBox::RejectRole);
        box.setDefaultButton(showBtn);
        box.exec();
        if (box.clickedButton() == showBtn)
            QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(confLoc).absolutePath()));
    } else {
        // Credentials come from Edit -> Settings (manual external connection); those
        // fields ARE editable on this path, so a one-click jump to Settings is correct.
        box.setInformativeText(tr(
            "You've set ZClassic to use your own node, and its RPC username or password "
            "doesn't match what's saved here. Nothing is wrong with your wallet or your "
            "coins — they're safe.\n\n"
            "Open Settings to update the username and password to match your node, then "
            "ZClassic will connect."));
        QPushButton* openBtn = box.addButton(tr("Open Settings"), QMessageBox::AcceptRole);
        box.addButton(tr("Not now"), QMessageBox::RejectRole);
        box.setDefaultButton(openBtn);
        box.exec();
        if (box.clickedButton() == openBtn && ui && ui->actionSettings)
            ui->actionSettings->trigger();
    }
}

// Sibling of the above for the connect-time CATCH-ALL (edit #2). The node has not answered
// cleanly nor with a recognized warmup state for too long. Actionable + retryable; Retry
// relaunches the app (a clean reconnect) instead of leaving the connect dialog frozen.
void MainWindow::showNodeNotRespondingRetry() {
    logger->write("Showing node-not-responding actionable retry dialog");

    QMessageBox box(this);
    box.setWindowTitle(tr("ZClassic is taking longer than expected"));
    box.setIcon(QMessageBox::Warning);
    box.setText(tr("The ZClassic node hasn't finished starting up."));
    box.setInformativeText(tr(
        "It hasn't responded normally for a while. Your wallet and coins are safe — "
        "nothing has been changed.\n\n"
        "Press Retry to start over, or Quit to close ZClassic."));
    QPushButton* retryBtn = box.addButton(tr("Retry"), QMessageBox::AcceptRole);
    QPushButton* quitBtn  = box.addButton(tr("Quit"), QMessageBox::RejectRole);
    box.setDefaultButton(retryBtn);
    box.exec();

    if (box.clickedButton() == quitBtn) {
        logger->write("Node-not-responding: Quit pressed");
        quitApp();
        return;
    }
    // Retry / closed: relaunch the app to re-run the whole connect flow cleanly.
    logger->write("Node-not-responding: Retry pressed; relaunching app");
    mwRelaunchSelf();
    quitApp();
}

void MainWindow::setupSettingsModal() {    
    // Set up File -> Settings action
    QObject::connect(ui->actionSettings, &QAction::triggered, [=]() {
        QDialog settingsDialog(this);
        Ui_Settings settings;
        settings.setupUi(&settingsDialog);
        Settings::saveRestore(&settingsDialog);

        // Setup save sent check box
        QObject::connect(settings.chkSaveTxs, &QCheckBox::stateChanged, [=](auto checked) {
            Settings::getInstance()->setSaveZtxs(checked);
        });

        // Setup clear button
        QObject::connect(settings.btnClearSaved, &QCheckBox::clicked, [=]() {
            // DATA-LOSS FIX: the old `if (QMessageBox::warning(...))` ran the irreversible
            // delete for EVERY button — Yes returns 0x4000 and Cancel returns 0x400000, both
            // non-zero/truthy, and Cancel is also the Esc/X escape button. So Cancel, Esc and
            // the window-X all deleted the saved history with no way to back out. Capture the
            // result and gate on equality so ONLY "Yes" deletes.
            auto ans = QMessageBox::warning(this, tr("Clear saved history?"),
                tr("Shielded z-Address transactions are stored locally in your wallet, outside zclassicd. You may delete this saved information safely any time for your privacy.\nDo you want to delete the saved shielded transactions now?"),
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
            if (ans == QMessageBox::Yes) {
                    SentTxStore::deleteHistory();
                    // Also drop the cached last-known balances (same local data).
                    QSettings().remove("cache");
                    // Reload after the clear button so existing txs disappear
                    rpc->refresh(true);
            }
        });

        // Save sent transactions
        settings.chkSaveTxs->setChecked(Settings::getInstance()->getSaveZtxs());

        // Keep running in the background (tray-resident). Disable + explain when
        // there is no system tray available so the user isn't offered a no-op.
        settings.chkKeepInTray->setChecked(Settings::getInstance()->getKeepInTray());
        if (!QSystemTrayIcon::isSystemTrayAvailable()) {
            settings.chkKeepInTray->setEnabled(false);
            settings.chkKeepInTray->setToolTip(tr("Your desktop doesn't provide a system tray, so this option isn't available."));
        }

        // Help the network: open our P2P port automatically via NAT-PMP/PCP
        // (no UPnP). Default OFF. Only meaningful with the embedded daemon, since
        // the flag is passed at daemon launch; disable + explain otherwise.
        settings.chkNatpmp->setChecked(Settings::getInstance()->getOpenPortNatpmp());
        if (!rpc->isEmbedded()) {
            settings.chkNatpmp->setEnabled(false);
            settings.chkNatpmp->setToolTip(tr("Automatic port opening is available only when running an embedded zclassicd."));
        }

        // Custom fees
        settings.chkCustomFees->setChecked(Settings::getInstance()->getAllowCustomFees());

        // Auto shielding
        settings.chkAutoShield->setChecked(Settings::getInstance()->getAutoShield());

        // Use Tor
        bool isUsingTor = false;
        if (rpc->getConnection() != nullptr) {
            isUsingTor = !rpc->getConnection()->config->proxy.isEmpty();
        }
        settings.chkTor->setChecked(isUsingTor);
        if (rpc->getEZClassicD() == nullptr) {
            settings.chkTor->setEnabled(false);
            settings.lblTor->setEnabled(false);
            QString tooltip = tr("Tor configuration is available only when running an embedded zclassicd.");
            settings.chkTor->setToolTip(tooltip);
            settings.lblTor->setToolTip(tooltip);
        }

        // Connection Settings
        QIntValidator validator(0, 65535);
        settings.port->setValidator(&validator);

        // If values are coming from zclassic.conf, then disable all the fields — BUT only
        // when that conf actually holds usable creds. A conf can exist yet carry none (e.g.
        // "server=1" only, with a running node's creds on its command line); in that case
        // leave the fields EDITABLE so the user can supply them (never a dead end).
        auto zclassicConfLocation = Settings::getInstance()->getZClassicdConfLocation();
        bool confLocked = !zclassicConfLocation.isEmpty() && confHasUsableCreds(zclassicConfLocation);
        if (confLocked) {
            settings.confMsg->setText("Settings are being read from \n" + zclassicConfLocation);
            settings.hostname->setEnabled(false);
            settings.port->setEnabled(false);
            settings.rpcuser->setEnabled(false);
            settings.rpcpassword->setEnabled(false);
        }
        else if (!zclassicConfLocation.isEmpty()) {
            // Conf exists but has no usable creds: editable, with reassuring guidance.
            settings.confMsg->setText(tr(
                "A ZClassic node is already running, but its sign-in details aren't saved here.\n"
                "Enter its RPC username and password and ZClassic will connect."));
            settings.hostname->setEnabled(true);
            settings.port->setEnabled(true);
            settings.rpcuser->setEnabled(true);
            settings.rpcpassword->setEnabled(true);
        }
        else {
            settings.confMsg->setText("No local zclassic.conf found. Please configure connection manually.");
            settings.hostname->setEnabled(true);
            settings.port->setEnabled(true);
            settings.rpcuser->setEnabled(true);
            settings.rpcpassword->setEnabled(true);
        }

        // Load current values into the dialog        
        auto conf = Settings::getInstance()->getSettings();
        settings.hostname->setText(conf.host);
        settings.port->setText(conf.port);
        settings.rpcuser->setText(conf.rpcuser);
        settings.rpcpassword->setText(conf.rpcpassword);

        // Connection tab by default
        settings.tabWidget->setCurrentIndex(0);

        // Enable the troubleshooting options only if using embedded zclassicd
        if (!rpc->isEmbedded()) {
            settings.chkRescan->setEnabled(false);
            settings.chkRescan->setToolTip(tr("You're using an external zclassicd. Please restart zclassicd with -rescan"));

            settings.chkReindex->setEnabled(false);
            settings.chkReindex->setToolTip(tr("You're using an external zclassicd. Please restart zclassicd with -reindex"));
        }

        if (settingsDialog.exec() == QDialog::Accepted) {
            // Custom fees
            bool customFees = settings.chkCustomFees->isChecked();
            Settings::getInstance()->setAllowCustomFees(customFees);
            ui->minerFeeAmt->setReadOnly(!customFees);
            if (!customFees)
                ui->minerFeeAmt->setText(Settings::getDecimalString(Settings::getMinerFee()));

            // Auto shield
            Settings::getInstance()->setAutoShield(settings.chkAutoShield->isChecked());

            // Keep running in the background (tray-resident). Apply immediately
            // so the change takes effect this session, no restart needed.
            bool keepInTray = settings.chkKeepInTray->isChecked();
            Settings::getInstance()->setKeepInTray(keepInTray);
            applyTraySetting(keepInTray);

            // Help the network: open my port automatically (NAT-PMP/PCP, no UPnP).
            // The daemon reads -natpmp only at launch, so a change takes effect on
            // the next restart. Tell the user only when the value actually changed.
            bool wasNatpmp = Settings::getInstance()->getOpenPortNatpmp();
            bool natpmp = settings.chkNatpmp->isChecked();
            if (natpmp != wasNatpmp) {
                Settings::getInstance()->setOpenPortNatpmp(natpmp);
                QMessageBox::information(this, tr("Open port automatically"),
                    natpmp
                        ? tr("Automatic port opening will be enabled the next time ZclWallet starts its node. This asks your router to make you reachable to other peers (NAT-PMP/PCP, never UPnP).")
                        : tr("Automatic port opening will be disabled the next time ZclWallet starts its node."),
                    QMessageBox::Ok);
            }

            if (!isUsingTor && settings.chkTor->isChecked()) {
                // If "use tor" was previously unchecked and now checked
                Settings::addToZClassicConf(zclassicConfLocation, "proxy=127.0.0.1:9050");
                rpc->getConnection()->config->proxy = "proxy=127.0.0.1:9050";

                QMessageBox::information(this, tr("Enable Tor"), 
                    tr("Connection over Tor has been enabled. To use this feature, you need to restart ZclWallet."), 
                    QMessageBox::Ok);
            }

            if (isUsingTor && !settings.chkTor->isChecked()) {
                // If "use tor" was previously checked and now is unchecked
                Settings::removeFromZClassicConf(zclassicConfLocation, "proxy");
                rpc->getConnection()->config->proxy.clear();

                QMessageBox::information(this, tr("Disable Tor"),
                    tr("Connection over Tor has been disabled. To fully disconnect from Tor, you need to restart ZclWallet."),
                    QMessageBox::Ok);
            }

            // Persist + reconnect whenever the cred fields were EDITABLE this dialog — i.e.
            // no conf at all, OR a conf with no usable creds (confLocked false). Without this
            // the creds a user typed for a cred-less-conf node would never be saved, so the
            // dead end would persist even with editable fields. The saved creds are picked up
            // by autoDetectZClassicConf's QSettings fallback on the very next connect.
            if (!confLocked) {
                // Save settings
                Settings::getInstance()->saveSettings(
                    settings.hostname->text(),
                    settings.port->text(),
                    settings.rpcuser->text(),
                    settings.rpcpassword->text());

                auto cl = new ConnectionLoader(this, rpc);
                cl->loadConnection();
            }

            // Check to see if rescan or reindex have been enabled
            bool showRestartInfo = false;
            if (settings.chkRescan->isChecked()) {
                Settings::addToZClassicConf(zclassicConfLocation, "rescan=1");
                showRestartInfo = true;
            }

            if (settings.chkReindex->isChecked()) {
                Settings::addToZClassicConf(zclassicConfLocation, "reindex=1");
                showRestartInfo = true;
            }

            if (showRestartInfo) {
                auto desc = tr("ZclWallet needs to restart to rescan/reindex. ZclWallet will now close, please restart ZclWallet to continue");

                QMessageBox::information(this, tr("Restart ZclWallet"), desc, QMessageBox::Ok);
                // NO-OP-IN-TRAY FIX: in the default tray-resident/embedded config (the only
                // config where Rescan/Reindex are even enabled), close() merely HIDES to the
                // tray — closeEvent ignores it before rpc->shutdownZClassicd(), so the daemon
                // never stops and never re-reads rescan=1/reindex=1, making the whole feature a
                // silent no-op. quitApp() sets quitting=true so closeEvent actually shuts the
                // node down; the next launch then performs the rescan/reindex (matches the copy).
                // Context 'this': Qt auto-cancels the timer if the window is destroyed first.
                QTimer::singleShot(1, this, [=]() { this->quitApp(); });
            }
        }
    });
}

void MainWindow::addressBook() {
    // Check to see if there is a target.
    QRegExp re("Address[0-9]+", Qt::CaseInsensitive);
    for (auto target: ui->sendToWidgets->findChildren<QLineEdit *>(re)) {
        if (target->hasFocus()) {
            AddressBook::open(this, target);
            return;
        }
    };

    // If there was no target, then just run with no target.
    AddressBook::open(this);
}



void MainWindow::doImport(QSharedPointer<QList<QString>> keys) {
    if (rpc->getConnection() == nullptr) {
        // No connection, just return (keys is freed when the last reference drops).
        showImportProgress(false);   // don't strand the card on a dropped connection
        return;
    }

    if (keys->isEmpty()) {
        // keys is a QSharedPointer now — it frees itself; no explicit delete.
        // This branch is re-entered only AFTER the final rescan=true RPC's rescan
        // completes, so hiding the card here clears it exactly when the rescan ends.
        ui->statusBar->showMessage(tr("Private key import rescan finished"));
        showImportProgress(false);
        return;
    }

    // Pop the first key
    QString key = keys->first();
    keys->pop_front();
    bool rescan = keys->isEmpty();

    if (key.startsWith("S") ||
        key.startsWith("secret")) { // Z key
        rpc->importZPrivKey(key, rescan, [=] (auto) { this->doImport(keys); });                   
    } else {
        rpc->importTPrivKey(key, rescan, [=] (auto) { this->doImport(keys); });
    }
}


// Callback invoked when the RPC has finished loading all the balances, and the UI 
// is now ready to send transactions.
void MainWindow::balancesReady() {
    // First-time check
    if (uiPaymentsReady)
        return;

    uiPaymentsReady = true;
    qDebug() << "Payment UI now ready!";

    // There is a pending URI payment (from the command line, or from a secondary instance),
    // process it.
    if (!pendingURIPayment.isEmpty()) {
        qDebug() << "Paying zclassic URI";
        payZClassicURI(pendingURIPayment);
        pendingURIPayment = "";
    }
}

// P0-2: First-run / until-backed-up fund-safety prompt.
//
// The ZClassic wallet is wallet.dat FILE-based: there is NO BIP39 seed phrase.
// If the user loses wallet.dat (disk failure, reinstall, lost laptop) and has
// no backup, the coins are gone forever. This prompt nags on every launch
// until the user backs up (file copy) or exports their private keys, then it
// is silenced permanently via the persisted "options/walletbackedup" flag.
//
// It is modal/blocking but ALWAYS dismissible ("Maybe later") so it can never
// become an un-closable trap.
// W1-2: surface the NON-blocking amber backup card on the Home dashboard. Called from
// rpc.cpp on the synced && balTotal>0 && once-per-session edge (the same trigger that
// used to fire the modal promptWalletBackup()). No-op once the wallet has been backed
// up (options/walletbackedup) or when the card isn't built (e.g. before the dashboard
// is set up). The card's single "Back up my wallet" button silences it on a verified copy.
void MainWindow::showBackupNag() {
    if (Settings::getInstance()->isWalletBackedUp())
        return;   // already backed up -> never nag again
    if (homeBackupCard != nullptr) {
        // The amber card supersedes the quiet standalone button: showing both at
        // once duplicates the identical "Back up my wallet" control on Home. Hide
        // the standalone while the card is up (both call backupWallet(), so this is
        // pure de-duplication). If the card was never built, leave the standalone
        // visible as the sole un-backed-up entry point.
        if (homeBackupBtn != nullptr)
            homeBackupBtn->setVisible(false);
        homeBackupCard->setVisible(true);
    }
}

void MainWindow::showImportProgress(bool active) {
    // No-op if the dashboard card wasn't built (e.g. headless tests). Single writer:
    // only the import flow toggles this. The bar is permanently indeterminate, so
    // showing/hiding the card is the whole behaviour.
    if (homeImportCard != nullptr)
        homeImportCard->setVisible(active);
}

void MainWindow::promptWalletBackup() {
    // Already backed up at some point? Never nag again.
    if (QSettings().value("options/walletbackedup", false).toBool())
        return;

    // We need a live connection to know where wallet.dat lives / to copy it.
    if (!rpc || !rpc->getConnection())
        return;

    // Krug: ONE self-evident primary action + one quiet escape. No co-equal "Export
    // Private Keys" fork, no inline copy duplication (the copy lives in backupWallet),
    // no 'Did you save your keys?' quiz, no scolding 'No backup yet' modal. Sierra:
    // reassure, don't quiz. The Home card already nags non-blockingly; this prompt
    // just makes the one safe action a single click away.
    QMessageBox box(this);
    box.setWindowTitle(tr("Back up your wallet"));
    box.setIcon(QMessageBox::Warning);
    box.setText(tr("Back up your wallet"));
    box.setInformativeText(tr(
        "Your ZClassic lives in one file on this computer (wallet.dat). There is "
        "<b>no recovery phrase</b>. If this computer is lost or its disk fails and "
        "you have no backup, your coins are gone forever.<br><br>"
        "It takes one click. Keep the copy somewhere safe — a USB stick or another "
        "computer."));

    QPushButton* backupBtn = box.addButton(tr("Back up my wallet"), QMessageBox::AcceptRole);
    QPushButton* laterBtn  = box.addButton(tr("Maybe later"), QMessageBox::RejectRole);
    box.setDefaultButton(backupBtn);
    box.setEscapeButton(laterBtn);

    box.exec();
    if (box.clickedButton() == backupBtn)
        backupWallet();   // the one safe copy + the one warm closure; sets the flag on success
    // "Maybe later" / closed: do nothing. The flag stays unset, so the non-blocking
    // Home card keeps the gentle reminder. No scare modal.
}

// Event filter for MacOS specific handling of payment URIs
bool MainWindow::eventFilter(QObject *object, QEvent *event) {
    if (event->type() == QEvent::FileOpen) {
        QFileOpenEvent *fileEvent = static_cast<QFileOpenEvent*>(event);
        if (!fileEvent->url().isEmpty())
            payZClassicURI(fileEvent->url().toString());

        return true;
    }

    return QObject::eventFilter(object, event);
}


// Pay the ZClassic URI by showing a confirmation window. If the URI parameter is empty, the UI
// will prompt for one.
void MainWindow::payZClassicURI(QString uri) {
    // If the Payments UI is not ready (i.e, all balances have not loaded), defer the payment URI
    if (!uiPaymentsReady) {
        qDebug() << "Payment UI not ready, waiting for UI to pay URI";
        pendingURIPayment = uri;
        return;
    }

    // Error to display if something goes wrong.
    auto payZClassicURIError = [=] (QString errorDetail = "") {
        QMessageBox::critical(this, tr("Error paying zclassic URI"), 
                tr("URI should be of the form 'zclassic:<addr>?amt=x&memo=y") + "\n" + errorDetail);
    };

    // If there was no URI passed, ask the user for one.
    if (uri.isEmpty()) {
        uri = QInputDialog::getText(this, tr("Paste ZClassic URI"),
            "ZClassic URI" + QString(" ").repeated(180));
    }

    // If there's no URI, just exit
    if (uri.isEmpty())
        return;

    // URI should be of the form zclassic://address?amt=x&memo=y
    if (!uri.startsWith("zclassic:")) {
        payZClassicURIError();
        return;
    }

    // Extract the address
    qDebug() << "Recieved URI " << uri;
    uri = uri.right(uri.length() - QString("zclassic:").length());

    QRegExp re("([a-zA-Z0-9]+)");
    int pos;
    if ( (pos = re.indexIn(uri)) == -1 ) {
        payZClassicURIError();
        return;
    }

    QString addr = re.cap(1);
    if (!Settings::isValidAddress(addr)) {
        payZClassicURIError(tr("Could not understand address"));
        return;
    }
    uri = uri.right(uri.length() - addr.length());

    double amount = 0.0;
    QString memo  = "";

    if (!uri.isEmpty()) {
        uri = uri.right(uri.length() - 1); // Eat the "?"

        QStringList args = uri.split("&");
        for (QString arg: args) {
            QStringList kv = arg.split("=");
            if (kv.length() != 2) {
                payZClassicURIError();
                return;
            }

            if (kv[0].toLower() == "amt" || kv[0].toLower() == "amount") {
                amount = kv[1].toDouble(); 
            } else if (kv[0].toLower() == "memo" || kv[0].toLower() == "message" || kv[0].toLower() == "msg") {
                memo = kv[1];
                // Test if this is hex

                QRegularExpression hexMatcher("^[0-9A-F]+$",
                                            QRegularExpression::CaseInsensitiveOption);
                QRegularExpressionMatch match = hexMatcher.match(memo);
                if (match.hasMatch()) {
                    // Encoded as hex, convert to string
                    memo = QByteArray::fromHex(memo.toUtf8());
                }
            } else {
                payZClassicURIError(tr("Unknown field in URI:") + kv[0]);
                return;
            }
        }
    }

    // Now, set the fields on the send tab
    removeExtraAddresses();
    ui->Address1->setText(addr);
    ui->Address1->setCursorPosition(0);
    ui->Amount1->setText(QString::number(amount));
    // A URI memo can only be delivered to a shielded z-address; t-addresses carry no
    // memo field. Rather than show it on the page and then silently drop it when the tx
    // is built (MemoTxt1 is read directly into ToFields), only carry it to a z-recipient.
    // For a t-addr we clear the field (the Memo button is already disabled via
    // addressChanged above) and tell the user once, so the drop is never a surprise.
    if (!memo.isEmpty() && !Settings::isZAddress(addr)) {
        ui->MemoTxt1->clear();
        QMessageBox::information(this, tr("Memo not sent"),
            tr("The memo in this payment link was not added: memos are only delivered to shielded z-addresses, not transparent t-addresses."));
    } else {
        ui->MemoTxt1->setText(memo);
    }

    // And switch to the send tab.
    ui->tabWidget->setCurrentIndex(1);
    raise();

    // And click the send button if the amount is > 0, to validate everything. If everything is OK, it will show the confirm box
    // else, show the error message;
    if (amount > 0) {
        sendButton();
    }
}


void MainWindow::importPrivKey() {
    QDialog d(this);
    Ui_PrivKey pui;
    pui.setupUi(&d);
    Settings::saveRestore(&d);

    pui.buttonBox->button(QDialogButtonBox::Save)->setVisible(false);
    pui.helpLbl->setText(QString() %
                        tr("Please paste your private keys (z-Addr or t-Addr) here, one per line") % ".\n" %
                        tr("The keys will be imported into your connected zclassicd node"));  

    if (d.exec() == QDialog::Accepted && !pui.privKeyTxt->toPlainText().trimmed().isEmpty()) {
        auto rawkeys = pui.privKeyTxt->toPlainText().trimmed().split("\n");

        QList<QString> keysTmp;
        // Filter out all the empty keys.
        std::copy_if(rawkeys.begin(), rawkeys.end(), std::back_inserter(keysTmp), [=] (auto key) {
            return !key.startsWith("#") && !key.trimmed().isEmpty();
        });

        // QSharedPointer so the list is freed whether the deferred callback runs
        // OR is auto-cancelled (the 'this' context below cancels it on a fast quit);
        // a raw new'd list would leak on cancellation.
        auto keys = QSharedPointer<QList<QString>>::create();
        std::transform(keysTmp.begin(), keysTmp.end(), std::back_inserter(*keys), [=](auto key) {
            return key.trimmed().split(" ")[0];
        });

        // Show the non-blocking import/rescan Home card now; doImport() hides it on
        // completion (or on a dropped connection). Outlives the dismissed info box.
        showImportProgress(true);

        // Start the import. Context 'this': Qt auto-cancels the timer if the window
        // is destroyed before it fires, so the lambda never touches a freed MainWindow.
        QTimer::singleShot(1, this, [=]() {doImport(keys);});

        // Show the dialog that keys will be imported. 
        QMessageBox::information(this,
            tr("Importing keys"),
            tr("Your keys are being imported and the wallet will now rescan the "
               "blockchain. This can take several minutes — your balance will "
               "update when it finishes. Please leave ZClassic open."),
            QMessageBox::Ok);
    }
}

/** 
 * Export transaction history into a CSV file
 */
void MainWindow::exportTransactions() {
    // First, get the export file name
    QString exportName = "zclassic-transactions-" + QDateTime::currentDateTime().toString("yyyyMMdd") + ".csv";

    QUrl csvName = QFileDialog::getSaveFileUrl(this, 
            tr("Export transactions"), exportName, "CSV file (*.csv)");

    if (csvName.isEmpty())
        return;

    if (!rpc->getTransactionsModel()->exportToCsv(csvName.toLocalFile())) {
        QMessageBox::critical(this, tr("Error"), 
            tr("Error exporting transactions, file was not saved"), QMessageBox::Ok);
    }
} 

// fnDefaultBackupDir: a sensible, EXISTING folder to pre-fill the Save dialog so the
// happy path is zero-navigation — Desktop, then Documents, then Home. We never auto-
// write a spendable secret without a Save dialog (agency/safety), but we make that
// dialog open already pointing at a good place.
QString MainWindow::fnDefaultBackupDir() {
    for (auto loc : { QStandardPaths::DesktopLocation, QStandardPaths::DocumentsLocation,
                      QStandardPaths::HomeLocation }) {
        QString dir = QStandardPaths::writableLocation(loc);
        if (!dir.isEmpty() && QDir(dir).exists())
            return dir;
    }
    return QDir::homePath();
}

// backupWallet: the ONE safe everyday backup. Locates wallet.dat, opens a Save dialog
// PRE-FILLED with both a smart folder (fnDefaultBackupDir) and a collision-safe dated
// filename (so a same-day second backup never overwrites yesterday's and never raises
// an overwrite prompt). On a VERIFIED copy: set the backed-up flag (silences the card
// + prompt) and show the one warm closure. KEY-1: the secret is only ever copied to
// the local file the user confirms — never networked or logged.
void MainWindow::backupWallet() {
    if (!rpc || !rpc->getConnection())
        return;

    QDir zclassicdir(rpc->getConnection()->config->zclassicDir);
    QString namePrefix = "zclassic-wallet-backup-";
    if (Settings::getInstance()->isTestnet()) {
        zclassicdir.cd("testnet3");
        namePrefix = "testnet-" + namePrefix;
    }

    QFile wallet(zclassicdir.filePath("wallet.dat"));
    if (!wallet.exists()) {
        QMessageBox::critical(this, tr("Couldn't find your wallet file"),
            tr("Couldn't find wallet.dat on this computer. If ZClassic is running on "
               "another machine, back it up from there."), QMessageBox::Ok);
        return;
    }

    // Collision-safe dated default name (graft from Design 1): base, then base-2, -3…
    // so the native Save dialog opens already pointing at a fresh file.
    QDir   destDir(fnDefaultBackupDir());
    QString date  = QDateTime::currentDateTime().toString("yyyyMMdd");
    QString base  = namePrefix + date;
    QString fileName = base + ".dat";
    for (int i = 2; QFileInfo::exists(destDir.filePath(fileName)); ++i)
        fileName = base + "-" + QString::number(i) + ".dat";

    QString defaultPath = destDir.filePath(fileName);
    QString chosen = QFileDialog::getSaveFileName(this, tr("Save your wallet backup"),
                                                  defaultPath, tr("Data file (*.dat)"));
    if (chosen.isEmpty())
        return;   // cancelled: flag stays unset, the Home card keeps reminding

    if (wallet.copy(chosen)) {
        Settings::getInstance()->setWalletBackedUp(true);
        showBackupSuccess(chosen, /*isWalletDat=*/true);
    } else {
        QMessageBox::critical(this, tr("Couldn't save the backup"),
            tr("We couldn't save the backup file.") + "\n\n" +
            tr("Nothing was changed. Please try again, or choose a different place "
               "to save it."), QMessageBox::Ok);
    }
}

// showBackupSuccess: the ONE warm closure, reused by the wallet.dat backup AND the
// advanced key-file export (isWalletDat=false). Tells the user WHERE the secret is,
// that they're safe, NOT to cloud-sync it, and HOW TO RESTORE — the difference
// between a backup and a real backup. [Show in folder] opens the LOCAL containing
// folder only (KEY-1: nothing leaves the machine). The path is HTML-escaped because
// the body is rich text.
void MainWindow::showBackupSuccess(const QString& savedPath, bool isWalletDat) {
    QString safePath = savedPath.toHtmlEscaped();

    QString restore = isWalletDat
        ? tr("To restore later: copy this file back into the wallet's data folder and "
             "rename it to wallet.dat.")
        : tr("To restore later: open another ZClassic wallet and use "
             "File &gt; Import private key.");

    QString secretLine = isWalletDat
        ? tr("Your coins are safe as long as you keep this file. Keep it private — "
             "anyone who has it can spend your coins, so don't put it in a folder that "
             "syncs to the cloud (Dropbox, iCloud, Google Drive) unless your wallet is "
             "password-encrypted. A USB stick or a second computer is ideal.")
        : tr("These are your private keys — keep this file private; anyone who has it "
             "can spend your coins. Don't put it in a folder that syncs to the cloud "
             "(Dropbox, iCloud, Google Drive). A USB stick or a second computer is ideal.");

    QMessageBox box(this);
    box.setWindowTitle(tr("Backup saved — you're safe"));
    box.setIcon(QMessageBox::Information);
    box.setText(tr("Backup saved — you're safe"));
    box.setTextFormat(Qt::RichText);
    box.setInformativeText(
        tr("Saved to:") + "<br><b>" + safePath + "</b><br><br>" +
        secretLine + "<br><br>" + restore);

    QPushButton* showBtn = box.addButton(tr("Show in folder"), QMessageBox::ActionRole);
    QPushButton* doneBtn = box.addButton(tr("Done"), QMessageBox::AcceptRole);
    box.setDefaultButton(doneBtn);
    box.setEscapeButton(doneBtn);
    box.exec();

    if (box.clickedButton() == showBtn) {
        // KEY-1: local only. Open the containing folder (not the secret file itself).
        QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(savedPath).absolutePath()));
    }
}

/**
 * Backup the wallet.dat file. This is kind of a hack, since it has to read from the filesystem rather than an RPC call
 * This might fail for various reasons - Remote zclassicd, non-standard locations, custom params passed to zclassicd, many others
*/
void MainWindow::backupWalletDat() {
    // The File-menu "Back up my wallet…" action. One implementation: delegate to the
    // shared safe-copy helper (smart pre-filled Save dialog + collision-safe name +
    // verified-copy flag + the one warm closure). Kept as a thin wrapper because the
    // .ui action (actionBackup_wallet_dat) is wired to this slot by name.
    backupWallet();
}

void MainWindow::exportAllKeys() {
    exportKeys("");
}

void MainWindow::exportKeys(QString addr) {
    // DEAD-END FIX: the Export-keys menu items are always clickable, but without a live
    // connection getAllPrivKeys/getZPrivKey never fire their callback, so the dialog sat on
    // "Loading…" forever with Save/Copy disabled and no way forward. Guard up front (mirrors
    // the existing doImport/backupWallet null-conn guards) so the user gets a clear, recoverable
    // message instead of a frozen modal.
    if (!rpc || !rpc->getConnection()) {
        QMessageBox::information(this, tr("Not connected"),
            tr("ZClassic isn't connected to your node yet, so it can't read your keys. "
               "Please wait until it's connected, then try again."));
        return;
    }

    bool allKeys = addr.isEmpty() ? true : false;

    // Don't-make-me-think: the user explicitly chose to view their keys — don't
    // interrupt with a blocking scare popup. The calm safety framing lives INSIDE
    // the dialog (helpLbl below), read in context, not as a nag in the way.
    QDialog d(this);
    Ui_PrivKey pui;
    pui.setupUi(&d);

    // objectNames so dark.qss can give this the premium, readable treatment
    // (no .ui regeneration — same objectName->qss idiom used across the app).
    d.setObjectName("PrivKey");
    pui.helpLbl->setObjectName("privKeySecurity");
    pui.privKeyTxt->setObjectName("privKeyTextEdit");

    // ADVANCED-EXPORT ORIENTATION (Krug/Sierra): this screen now has a beginning,
    // middle, and end so it never orphans. privkey.ui is a QGridLayout (gridLayout)
    // with row0=helpLbl, row1=privKeyTxt, row2=buttonBox. We re-place helpLbl/txt/
    // buttons down one row each and insert a separate amber intro header at row0 and
    // a hidden green 'saved' confirmation line above the buttons — no .ui regen.
    // doneLbl is a LOCAL (not stashed on the generated Ui_PrivKey struct, so a uic
    // regen of ui_privkey.h can never wipe it); the Save lambda captures it by value,
    // and the QLabel lives as a child of &d for the dialog's lifetime.
    QLabel* doneLbl = nullptr;
    auto* grid = qobject_cast<QGridLayout*>(d.layout());
    if (grid) {
        grid->removeWidget(pui.helpLbl);
        grid->removeWidget(pui.privKeyTxt);
        grid->removeWidget(pui.buttonBox);

        auto* introLbl = new QLabel(&d);
        introLbl->setObjectName("privKeyIntro");
        introLbl->setWordWrap(true);
        introLbl->setText(tr(
            "Advanced — this exports raw spending keys to move an address into another "
            "wallet. It is not a regular backup. To back up everything safely, close "
            "this and use \"Back up my wallet\"."));

        doneLbl = new QLabel(&d);
        doneLbl->setObjectName("privKeyDoneLbl");
        doneLbl->setWordWrap(true);
        doneLbl->setVisible(false);            // shown inline after a successful save

        // Calm, dim reassurance so opening this just to LOOK has an obviously safe
        // exit (Sierra: make the user feel capable). Child of &d, qss-styled.
        auto* closeHint = new QLabel(&d);
        closeHint->setObjectName("privKeyCloseHint");
        closeHint->setWordWrap(true);
        closeHint->setText(tr(
            "Nothing is saved or shared until you press \"Save to file\". "
            "Closing this is safe — your keys stay in your wallet."));

        grid->addWidget(introLbl,        0, 0);
        grid->addWidget(pui.helpLbl,     1, 0);
        grid->addWidget(pui.privKeyTxt,  2, 0);
        grid->addWidget(doneLbl,         3, 0);
        grid->addWidget(closeHint,       4, 0);
        grid->addWidget(pui.buttonBox,   5, 0);
    }

    // Make the window big by default
    auto ps = this->geometry();
    QMargins margin = QMargins() + 50;
    d.setGeometry(ps.marginsRemoved(margin));

    Settings::saveRestore(&d);

    pui.privKeyTxt->setPlainText(tr("Loading..."));
    pui.privKeyTxt->setReadOnly(true);
    pui.privKeyTxt->setLineWrapMode(QPlainTextEdit::LineWrapMode::NoWrap);

    const QString securityNote = tr("These are your secret keys — anyone who has them controls these funds. "
                                    "Keep this screen private and store any saved file somewhere safe.");
    const QString whatToDo = tr("\nWhat to do: press \"Save to file\" below.");
    if (allKeys)
        pui.helpLbl->setText(securityNote + tr("\n\nShowing the keys for every address in your wallet.") + whatToDo);
    else
        pui.helpLbl->setText(securityNote + tr("\n\nShowing the key for: ") + addr + whatToDo);
    pui.helpLbl->setWordWrap(true);

    // Disable the save button until it finishes loading. Promote it to the primary
    // action: relabel "Save to file" and style it via objectName. We deliberately do
    // NOT setDefault(true) — on a screen full of secret keys, a stray Enter should
    // not begin a key-file export. (No .ui change — same objectName->qss idiom.)
    auto* saveBtn = pui.buttonBox->button(QDialogButtonBox::Save);
    saveBtn->setEnabled(false);
    saveBtn->setText(tr("Save to file"));
    saveBtn->setObjectName("privKeySaveBtn");
    pui.buttonBox->button(QDialogButtonBox::Ok)->setVisible(false);

    // Krug: the chrome itself must say 'this is the advanced thing, not your backup',
    // and the exit must be obviously consequence-free. The window title was the bare
    // jargon 'Private Key' (privkey.ui:14); relabel it in plain words. Relabel the
    // Close button so a nervous looker knows leaving without saving is safe, and make
    // it the escape/default button so a stray Enter closes rather than starting an
    // export. KEY-1: nothing is written on close.
    d.setWindowTitle(allKeys ? tr("Advanced — export private keys")
                             : tr("Advanced — export this address's private key"));
    if (auto* closeBtn = pui.buttonBox->button(QDialogButtonBox::Close)) {
        closeBtn->setText(tr("Close — nothing to save"));
        closeBtn->setDefault(true);
        closeBtn->setAutoDefault(true);
    }

    // One-click Copy All — the user shouldn't have to select-all + Ctrl-C. Added in
    // C++ (no .ui change); enabled once keys load (see fnUpdateUIWithKeys). The
    // 1.5s "Copied!" reset uses copyBtn as the singleShot context, so Qt auto-cancels
    // it if the dialog closes first (no use-after-free on fast quit).
    auto* copyBtn = pui.buttonBox->addButton(tr("Copy All"), QDialogButtonBox::ActionRole);
    copyBtn->setObjectName("privKeyCopyBtn");
    copyBtn->setEnabled(false);
    QObject::connect(copyBtn, &QPushButton::clicked, [&pui, copyBtn]() {
        QApplication::clipboard()->setText(pui.privKeyTxt->toPlainText());
        copyBtn->setText(tr("Copied!"));
        QTimer::singleShot(1500, copyBtn, [copyBtn]() { copyBtn->setText(tr("Copy All")); });
    });

    // Wire up save button. Pre-seed BOTH a smart folder (fnDefaultBackupDir) and a
    // dated default name so the Save dialog opens with nothing to type. On a
    // successful LOCAL write we fire the SAME warm closure (import-back restore hint
    // + cloud caveat) AND reveal the inline green 'Saved to <path>' line so even the
    // advanced screen confirms instead of orphaning. KEY-1: keys are written ONLY to
    // the local file the user chose — never networked, never logged. doneLbl is the
    // function-local QLabel from the grid block above, captured by value here.
    QObject::connect(pui.buttonBox->button(QDialogButtonBox::Save), &QPushButton::clicked, [=, &pui, &d] () {
        QString date = QDateTime::currentDateTime().toString("yyyyMMdd");
        QString defName = (allKeys ? tr("zclassic-private-keys-") : tr("zclassic-private-key-")) + date + ".txt";
        QString defPath = QDir(fnDefaultBackupDir()).filePath(defName);
        QString fileName = QFileDialog::getSaveFileName(&d, tr("Save your private keys"),
                           defPath, tr("Text file (*.txt)"));
        if (fileName.isEmpty())
            return;   // cancelled
        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly)) {
            QMessageBox::critical(&d, tr("Couldn't save the file"), file.errorString());
            return;
        }
        {
            QTextStream out(&file);
            out << pui.privKeyTxt->toPlainText();
        }
        file.close();

        // Inline green confirmation (stays after the closure is dismissed).
        if (doneLbl) {
            doneLbl->setText(tr("Saved to: ") + fileName);
            doneLbl->setVisible(true);
        }
        // The shared warm closure (where it is + keep it private + how to restore).
        showBackupSuccess(fileName, /*isWalletDat=*/false);
    });

    // Call the API
    auto isDialogAlive = std::make_shared<bool>(true);

    auto fnUpdateUIWithKeys = [=](QList<QPair<QString, QString>> privKeys) {
        // Check to see if we are still showing.
        if (! *(isDialogAlive.get()) ) return;

        QString allKeysTxt;
        for (auto keypair : privKeys) {
            allKeysTxt = allKeysTxt % keypair.second % " # addr=" % keypair.first % "\n";
        }

        pui.privKeyTxt->setPlainText(allKeysTxt);
        pui.buttonBox->button(QDialogButtonBox::Save)->setEnabled(true);
    };

    if (allKeys) {
        rpc->getAllPrivKeys(fnUpdateUIWithKeys);
    }
    else {        
        auto fnAddKey = [=](json key) {
            QList<QPair<QString, QString>> singleAddrKey;
            singleAddrKey.push_back(QPair<QString, QString>(addr, QString::fromStdString(key.get<json::string_t>())));
            fnUpdateUIWithKeys(singleAddrKey);
        };

        if (Settings::getInstance()->isZAddress(addr)) {
            rpc->getZPrivKey(addr, fnAddKey);
        }
        else {
            rpc->getTPrivKey(addr, fnAddKey);
        }        
    }
    
    d.exec();
    *isDialogAlive = false;
}

void MainWindow::setupBalancesTab() {
    ui->unconfirmedWarning->setVisible(false);

    // P0-6: build the prominent sync banner that sits above the balances.
    setupSyncBanner();

    // Phase-3b redesign (Quiet+): build the modern Home dashboard (hero + quick
    // actions + hidden fix-it card) on this page, above the Summary rows. Purely
    // additive (no .ui change); the fix-it card stays hidden until updateHomeFixIt
    // is called from rpc.cpp with a positive transparent balance.
    setupHomeDashboard();

    // Phase-2 redesign (privacy badges): install the PrivacyBadgeDelegate on the
    // balances table WITHOUT any .ui change. BalancesTableModel column layout
    // (balancestablemodel.cpp headerData/data): col 0 = Address, col 1 = Amount.
    // The address column gets the privacy pill; the amount column gets the
    // monospace/tabular/sign-tinted render. (setItemDelegateForColumn works
    // before or after the model is set in RPC::RPC.)
    ui->balancesTable->setItemDelegateForColumn(
        0, new PrivacyBadgeDelegate(PrivacyBadgeDelegate::Mode::Address, ui->balancesTable));
    ui->balancesTable->setItemDelegateForColumn(
        1, new PrivacyBadgeDelegate(PrivacyBadgeDelegate::Mode::Amount, ui->balancesTable));

    // Double click on balances table
    auto fnDoSendFrom = [=](const QString& addr, const QString& to = QString(), bool sendMax = false) {
        // Find the inputs combo
        for (int i = 0; i < ui->inputsCombo->count(); i++) {
            auto inputComboAddress = ui->inputsCombo->itemText(i);
            if (inputComboAddress.startsWith(addr)) {
                ui->inputsCombo->setCurrentIndex(i);
                break;
            }
        }

        // If there's a to address, add that as well
        if (!to.isEmpty()) {
            // Remember to clear any existing address fields, because we are creating a new transaction.
            this->removeExtraAddresses();
            ui->Address1->setText(to);
        }

        // See if max button has to be checked
        if (sendMax) {
            ui->Max1->setChecked(true);
        }

        // And switch to the send tab.
        ui->tabWidget->setCurrentIndex(1);
    };

    // Double click opens up memo if one exists
    QObject::connect(ui->balancesTable, &QTableView::doubleClicked, [=](auto index) {
        index = index.sibling(index.row(), 0);
        auto addr = AddressBook::addressFromAddressLabel(ui->balancesTable->model()->data(index).toString());
        
        fnDoSendFrom(addr);
    });

    // Setup context menu on balances tab
    ui->balancesTable->setContextMenuPolicy(Qt::CustomContextMenu);
    QObject::connect(ui->balancesTable, &QTableView::customContextMenuRequested, [=] (QPoint pos) {
        QModelIndex index = ui->balancesTable->indexAt(pos);
        if (index.row() < 0) return;

        index = index.sibling(index.row(), 0);
        auto addr = AddressBook::addressFromAddressLabel(
                            ui->balancesTable->model()->data(index).toString());

        QMenu menu(this);

        menu.addAction(tr("Copy address"), [=] () {
            QClipboard *clipboard = QGuiApplication::clipboard();
            clipboard->setText(addr);
            ui->statusBar->showMessage(tr("Copied to clipboard"), 3 * 1000);
        });

        menu.addAction("Send from " % addr.left(40) % (addr.size() > 40 ? "..." : ""), [=]() {
            fnDoSendFrom(addr);
        });

        if (addr.startsWith("t")) {
            auto defaultSapling = rpc->getDefaultSaplingAddress();
            if (!defaultSapling.isEmpty()) {
                menu.addAction(tr("Shield balance to Sapling"), [=] () {
                    fnDoSendFrom(addr, defaultSapling, true);
                });
            }

            menu.addAction(tr("View on block explorer"), [=] () {
                QString url = Settings::getExplorerAddressURL(addr);
                if (!url.isEmpty())
                    QDesktopServices::openUrl(QUrl(url));
                else
                    // NO-OP FIX: empty on testnet — give honest feedback, not a dead click.
                    ui->statusBar->showMessage(tr("No block explorer is available for this network."), 3 * 1000);
            });
        }

        if (Settings::getInstance()->isSproutAddress(addr)) {
            menu.addAction(tr("Migrate to Sapling"), [=] () {
                this->turnstileDoMigration(addr);
            });
        }

        // Raw spending-key export is an ADVANCED, dangerous operation (single-address
        // migration into another wallet — not a backup). It must never be a peer of
        // the everyday Copy/Send actions, so it lives only under a clearly-labelled
        // Advanced submenu at the bottom of the menu. The exportKeys() dialog already
        // carries the amber 'this is not a backup' orientation. KEY-1: keys stay
        // local (shown / saved to a user-chosen local file only), never networked.
        menu.addSeparator();
        QMenu* advMenu = menu.addMenu(tr("Advanced"));
        advMenu->addAction(tr("Export this address's private key…"), [=] () {
            this->exportKeys(addr);
        });

        menu.exec(ui->balancesTable->viewport()->mapToGlobal(pos));
    });
}

void MainWindow::setupZClassicdTab() {    
    ui->zclassicdlogo->setBasePixmap(QPixmap(":/img/res/zclassicdlogo.gif"));
    setupNetworkHelpPanel();
}

// Deliverable A: build the read-only "you're helping the network" panel inside the
// EXISTING zclassicd-tab grid. Pure widget construction in C++ (no .ui change). The
// labels start with placeholder text; RPC::refreshNetworkHelpPanel() fills them every
// poll from getnetworkinfo + getpeerinfo. This NEVER sends anything to the node.
void MainWindow::setupNetworkHelpPanel() {
    if (netHelpPanel) return;   // build once

    // gridLayout_5 already lays out: row1 Block height, row2 Connections, row3 Sol rate,
    // row4 a horizontal Line. Append our block below it (rows 7+ are free; row5/6 are a
    // mining label + spacer). Parent to groupBox_5 so it lives in the same card.
    QGridLayout* grid = ui->gridLayout_5;

    // The .ui ships a hard-coded "You are currently not mining" label (label_14) sitting
    // among the LIVE node stats. It is never updated, so it reads as live status and is
    // simply false if the daemon is mining. Hide it from code (no .ui regen) instead of
    // showing stale/incorrect mining status.
    if (ui->label_14) ui->label_14->hide();

    netHelpPanel = new QWidget(ui->groupBox_5);
    QVBoxLayout* v = new QVBoxLayout(netHelpPanel);
    v->setContentsMargins(0, 8, 0, 0);
    v->setSpacing(4);

    netHelpTitleLabel = new QLabel(tr("You're helping the network"), netHelpPanel);
    QFont tf = netHelpTitleLabel->font(); tf.setBold(true); netHelpTitleLabel->setFont(tf);

    netHelpStatusLabel = new QLabel(tr("Checking…"), netHelpPanel);
    netHelpReachLabel  = new QLabel(QString(), netHelpPanel);

    netHelpBlurbLabel = new QLabel(netHelpPanel);
    netHelpBlurbLabel->setWordWrap(true);
    netHelpBlurbLabel->setTextFormat(Qt::RichText);
    netHelpBlurbLabel->setOpenExternalLinks(true);   // how-to link opens in the browser
    netHelpBlurbLabel->setText(tr(
        "Your wallet quietly runs a full ZClassic node, so just by keeping it open "
        "you help keep ZClassic decentralized.<br>"
        "To also accept incoming connections from other wallets, turn on automatic "
        "port opening below, or forward port "
        "<b>%1</b> to this computer on your router "
        "(<a href=\"https://portforward.com/\">how do I forward a port?</a>).")
        .arg(Settings::getInstance()->isTestnet() ? 18033 : 8033));

    // One-click discoverable front door for the NAT-PMP/PCP auto-port-opening that
    // today is buried in Settings. It drives the SAME persisted setting
    // (Settings::setOpenPortNatpmp -> options/openportnatpmp) that the Settings
    // dialog (mainwindow.cpp setupSettingsModal) and the embedded-daemon launch arg
    // (connection.cpp '-natpmp=1') already read, so the two surfaces stay in sync.
    // The daemon reads -natpmp only at launch, so this takes effect on the next
    // node start -- we say so honestly and never imply instant effect/reachability.
    // It is initialized from the persisted value here; RPC::refreshNetworkHelpPanel
    // enables/disables it honestly each poll (embedded-only, exactly like the
    // Settings chkNatpmp) -- we cannot gate on rpc->isEmbedded() at build time
    // because setupZClassicdTab() runs BEFORE `rpc = new RPC(this)`.
    netHelpNatpmpChk = new QCheckBox(tr("Help the network — open my port automatically"), netHelpPanel);
    netHelpNatpmpChk->setChecked(Settings::getInstance()->getOpenPortNatpmp());
    netHelpNatpmpChk->setToolTip(tr("Asks your router to forward this node's port using NAT-PMP/PCP (never UPnP), opening only this node's own port. Takes effect the next time ZclWallet starts its node."));
    QObject::connect(netHelpNatpmpChk, &QCheckBox::toggled, this, [this](bool on) {
        if (on == Settings::getInstance()->getOpenPortNatpmp())
            return;   // no real change (e.g. programmatic setChecked) -> no dialog
        Settings::getInstance()->setOpenPortNatpmp(on);
        QMessageBox::information(this, tr("Open port automatically"),
            on
                ? tr("Automatic port opening will be enabled the next time ZclWallet starts its node. This asks your router to make you reachable to other peers (NAT-PMP/PCP, never UPnP).")
                : tr("Automatic port opening will be disabled the next time ZclWallet starts its node."),
            QMessageBox::Ok);
    });

    QCheckBox* optOut = new QCheckBox(tr("Don't show this"), netHelpPanel);
    optOut->setChecked(QSettings().value("net/helpPanelHidden", false).toBool());
    // Opt-out is cosmetic only: it hides the nudge. The node keeps listening on the
    // P2P port either way (we never pass -listen=0), so this never weakens the network.
    QObject::connect(optOut, &QCheckBox::toggled, this, [this](bool hidden) {
        QSettings().setValue("net/helpPanelHidden", hidden);
        if (netHelpTitleLabel)   netHelpTitleLabel->setVisible(!hidden);
        if (netHelpStatusLabel)  netHelpStatusLabel->setVisible(!hidden);
        if (netHelpReachLabel)   netHelpReachLabel->setVisible(!hidden);
        if (netHelpBlurbLabel)   netHelpBlurbLabel->setVisible(!hidden);
        if (netHelpNatpmpChk)    netHelpNatpmpChk->setVisible(!hidden);
    });

    v->addWidget(netHelpTitleLabel);
    v->addWidget(netHelpStatusLabel);
    v->addWidget(netHelpReachLabel);
    v->addWidget(netHelpBlurbLabel);
    v->addWidget(netHelpNatpmpChk);
    v->addWidget(optOut);

    grid->addWidget(netHelpPanel, 7, 0, 1, 3);

    // Apply the persisted opt-out immediately so the body is hidden on first paint.
    bool hidden = optOut->isChecked();
    netHelpTitleLabel->setVisible(!hidden);
    netHelpStatusLabel->setVisible(!hidden);
    netHelpReachLabel->setVisible(!hidden);
    netHelpBlurbLabel->setVisible(!hidden);
    netHelpNatpmpChk->setVisible(!hidden);
}

void MainWindow::setupTransactionsTab() {
    // Phase-2 redesign (privacy badges): install the PrivacyBadgeDelegate on the
    // transactions table WITHOUT any .ui change. TxTableModel column layout
    // (txtablemodel.cpp ctor/data): col 0 = Type, col 1 = Address, col 2 =
    // Date/Time, col 3 = Amount. The address column gets the privacy pill (and,
    // for a send to a transparent recipient, the red De-shield variant — the
    // delegate reads the sibling Type cell); the amount column gets the
    // monospace/tabular/sign-tinted render.
    ui->transactionsTable->setItemDelegateForColumn(
        1, new PrivacyBadgeDelegate(PrivacyBadgeDelegate::Mode::Address, ui->transactionsTable));
    ui->transactionsTable->setItemDelegateForColumn(
        3, new PrivacyBadgeDelegate(PrivacyBadgeDelegate::Mode::Amount, ui->transactionsTable));

    // Double click opens up memo if one exists
    QObject::connect(ui->transactionsTable, &QTableView::doubleClicked, [=] (auto index) {
        auto txModel = dynamic_cast<TxTableModel *>(ui->transactionsTable->model());
        QString memo = txModel->getMemo(index.row());

        if (!memo.isEmpty()) {
            QMessageBox mb(QMessageBox::Information, tr("Memo"), memo, QMessageBox::Ok, this);
            mb.setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
            mb.exec();
        }
    });

    // Set up context menu on transactions tab
    ui->transactionsTable->setContextMenuPolicy(Qt::CustomContextMenu);

    // Table right click
    QObject::connect(ui->transactionsTable, &QTableView::customContextMenuRequested, [=] (QPoint pos) {
        QModelIndex index = ui->transactionsTable->indexAt(pos);
        if (index.row() < 0) return;

        QMenu menu(this);

        auto txModel = dynamic_cast<TxTableModel *>(ui->transactionsTable->model());

        QString txid = txModel->getTxId(index.row());
        QString memo = txModel->getMemo(index.row());
        QString addr = txModel->getAddr(index.row());

        menu.addAction(tr("Copy txid"), [=] () {            
            QGuiApplication::clipboard()->setText(txid);
            ui->statusBar->showMessage(tr("Copied to clipboard"), 3 * 1000);
        });

        if (!addr.isEmpty()) {
            menu.addAction(tr("Copy address"), [=] () {
                QGuiApplication::clipboard()->setText(addr);
                ui->statusBar->showMessage(tr("Copied to clipboard"), 3 * 1000);
            });
        }

        menu.addAction(tr("View on block explorer"), [=] () {
            QString url = Settings::getExplorerTxURL(txid);
            if (!url.isEmpty())
                QDesktopServices::openUrl(QUrl(url));
            else
                // NO-OP FIX: getExplorerTxURL returns "" on testnet; the menu item used to
                // dead-click silently. Tell the user why nothing opened.
                ui->statusBar->showMessage(tr("No block explorer is available for this network."), 3 * 1000);
        });

        if (!memo.isEmpty()) {
            menu.addAction(tr("View Memo"), [=] () {
                QMessageBox mb(QMessageBox::Information, tr("Memo"), memo, QMessageBox::Ok, this);
                mb.setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
                mb.exec();
            });
        }

        // If memo contains a reply to address, add a "Reply to" menu item
        if (!memo.isEmpty()) {
            int lastPost     = memo.trimmed().lastIndexOf(QRegExp("[\r\n]+"));
            QString lastWord = memo.right(memo.length() - lastPost - 1);
            
            if (Settings::getInstance()->isSaplingAddress(lastWord) || 
                Settings::getInstance()->isSproutAddress(lastWord)) {
                menu.addAction(tr("Reply to ") + lastWord.left(25) + "...", [=]() {
                    // First, cancel any pending stuff in the send tab by pretending to click
                    // the cancel button
                    cancelButton();

                    // Then set up the fields in the send tab
                    ui->Address1->setText(lastWord);
                    ui->Address1->setCursorPosition(0);
                    ui->Amount1->setText("0.0001");

                    // And switch to the send tab.
                    ui->tabWidget->setCurrentIndex(1);

                    qApp->processEvents();

                    // Click the memo button
                    this->memoButtonClicked(1, true);
                });
            }
        }

        menu.exec(ui->transactionsTable->viewport()->mapToGlobal(pos));        
    });
}

void MainWindow::addNewZaddr(bool sapling) {

    rpc->newZaddr(sapling, [=] (json reply) {
        QString addr = QString::fromStdString(reply.get<json::string_t>());
        // Make sure the RPC class reloads the z-addrs for future use
        rpc->refreshAddresses();

        // Just double make sure the z-address is still checked
        if (( sapling && ui->rdioZSAddr->isChecked()) ||
            (!sapling && ui->rdioZAddr->isChecked())) {
            ui->listRecieveAddresses->insertItem(0, addr); 
            ui->listRecieveAddresses->setCurrentIndex(0);

            ui->statusBar->showMessage(QString::fromStdString("Created new zAddr") %
                                       (sapling ? "(Sapling)" : "(Sprout)"), 
                                       10 * 1000);
        }
    });
}


// Adds sapling or sprout z-addresses to the combo box. Technically, returns a
// lambda, which can be connected to the appropriate signal
std::function<void(bool)> MainWindow::addZAddrsToComboList(bool sapling) {
    return [=] (bool checked) { 
        if (checked && this->rpc->getAllZAddresses() != nullptr) { 
            auto addrs = this->rpc->getAllZAddresses();
            ui->listRecieveAddresses->clear();

            std::for_each(addrs->begin(), addrs->end(), [=] (auto addr) {
                if ( (sapling &&  Settings::getInstance()->isSaplingAddress(addr)) ||
                    (!sapling && !Settings::getInstance()->isSaplingAddress(addr))) {
                        if (rpc->getAllBalances()) {
                            auto bal = rpc->getAllBalances()->value(addr);
                            ui->listRecieveAddresses->addItem(addr, bal);
                        }
                }
            }); 

            // If z-addrs are empty, then create a new one.
            if (addrs->isEmpty()) {
                addNewZaddr(sapling);
            }
        } 
    };
}

void MainWindow::setupRecieveTab() {
    auto addNewTAddr = [=] () {
        rpc->newTaddr([=] (json reply) {
            QString addr = QString::fromStdString(reply.get<json::string_t>());

            // Just double make sure the t-address is still checked
            if (ui->rdioTAddr->isChecked()) {
                ui->listRecieveAddresses->insertItem(0, addr);
                ui->listRecieveAddresses->setCurrentIndex(0);

                ui->statusBar->showMessage(tr("Created new t-Addr"), 10 * 1000);
            }
        });
    };

    // Connect t-addr radio button
    QObject::connect(ui->rdioTAddr, &QRadioButton::toggled, [=] (bool checked) {
        // Whenever the t-address is selected, we generate a new address, because we don't
        // want to reuse t-addrs
        if (checked && this->rpc->getUTXOs() != nullptr) {
            updateTAddrCombo(checked);
            addNewTAddr();
        }
        if (checked) {
            // Transparent addresses are PUBLIC -- make that impossible to miss, but as
            // a calm CALLOUT (Polish P1), not a red crash message. Amber = PUBLIC
            // everywhere; red is reserved for de-shield. The qss [callout="public"]
            // rule supplies the tinted bg + amber left-accent + lighter body color;
            // a warning-triangle icon + a bold "PUBLIC" carry the emphasis. The copy
            // ("Transparent address.", "PUBLIC", "permanently visible") is preserved
            // for the D-series assertions.
            ui->lblSproutWarning->setProperty("callout", "public");
            ui->lblSproutWarning->setStyleSheet("");   // drop the legacy inline color:red
            ui->lblSproutWarning->setText(tr(
                "<html><head/><body><p>⚠  <b>Transparent address.</b> This address and any "
                "balance it holds are <b>PUBLIC</b> and permanently visible to everyone "
                "on the blockchain. For privacy, receive to a shielded (z) address "
                "instead.</p></body></html>"));
            ui->lblSproutWarning->style()->unpolish(ui->lblSproutWarning);
            ui->lblSproutWarning->style()->polish(ui->lblSproutWarning);
            ui->lblSproutWarning->setVisible(true);
        }
    });

    // Sprout Warning is hidden by default
    ui->lblSproutWarning->setVisible(false);

    // zAddr toggle button, one for sprout and one for sapling
    QObject::connect(ui->rdioZAddr, &QRadioButton::toggled, [=](bool checked) {
        ui->btnRecieveNewAddr->setEnabled(!checked);
        if (checked) {
            ui->btnRecieveNewAddr->setToolTip(tr("Creation of new Sprout addresses is deprecated"));
        }
        else {
            ui->btnRecieveNewAddr->setToolTip("");
        }
        
        addZAddrsToComboList(false)(checked);

        // Legacy Sprout deprecation warning (only on the pre-2.0.4 daemon). Set the
        // text explicitly here because the t-Addr branch reuses this same label for
        // its PUBLIC warning, so we must restore the Sprout message when re-showing.
        bool showWarning = checked && Settings::getInstance()->getZClassicdVersion() < 2000425;
        if (showWarning) {
            ui->lblSproutWarning->setText(tr(
                "<html><head/><body><p>You should suspend trust in the receipt of funds "
                "to Sprout z-addresses until you upgrade to zclassicd v2.0.4. See "
                "<a href=\"https://z.cash/support/security/announcements/security-announcement-2019-03-19/\">"
                "<span style=\" text-decoration: underline; color:#0000ff;\">Security Announcement</span></a>."
                "</p></body></html>"));
        }
        ui->lblSproutWarning->setVisible(showWarning);
    });

    QObject::connect(ui->rdioZSAddr, &QRadioButton::toggled, [=] (bool checked) {
        addZAddrsToComboList(true)(checked);
        // Sapling is shielded/private: clear any transparent-or-Sprout warning text
        // the other radios may have left visible.
        if (checked)
            ui->lblSproutWarning->setVisible(false);
    });

    // Explicitly get new address button.
    QObject::connect(ui->btnRecieveNewAddr, &QPushButton::clicked, [=] () {
        if (!rpc->getConnection())
            return;

        // New-address creation is shielded Sapling or transparent only. Creating NEW
        // legacy Sprout addresses is removed (Sprout is deprecated); rdioZAddr remains
        // purely a read/select view of any EXISTING Sprout funds -- spending them is
        // unaffected. Under rdioZAddr the button is already disabled (toggle handler),
        // so dropping this branch is also a belt-and-suspenders guard against a
        // user ever minting a fresh deprecated Sprout address.
        if (ui->rdioZSAddr->isChecked()) {
            addNewZaddr(true);
        } else if (ui->rdioTAddr->isChecked()) {
            addNewTAddr();
        }
    });

    // Focus enter for the Receive Tab
    QObject::connect(ui->tabWidget, &QTabWidget::currentChanged, [=] (int tab) {
        if (tab == 2) {
            // Switched to receive tab. Phase-3c: come to REST in the private view —
            // the shielded Sapling address is the only thing on screen; the
            // transparent/legacy-Sprout options stay tucked behind the collapsed
            // "Other address types (advanced)" disclosure.

            // Keep the legacy-Sprout label honest, and re-evaluate which advanced
            // options are even offered (Sprout is hidden unless funds are held).
            ui->rdioZAddr->setText(Settings::getInstance()->isSaplingActive()
                                   ? "z-Addr (Legacy Sprout)" : "z-Addr");
            refreshReceiveAdvancedOptions();

            // Collapse the disclosure and select the private (Sapling) address.
            // setReceiveAdvancedExpanded(false) checks rdioZSAddr (the state
            // machine), which loads the Sapling z-addrs and clears any warning.
            setReceiveAdvancedExpanded(false);

            // And then select the first one
            ui->listRecieveAddresses->setCurrentIndex(0);
        }
    });

    // Select item in address list. Polish P0-3: the legacy lower form (the second
    // Label/Update-Label row, the "Address balance" row, and the one-click Export
    // Private Key button) is GONE — only the address text box + QR remain, folded
    // into the "Receive privately" card. So this handler now only mirrors the
    // selected address into txtRecieve + the QR.
    QObject::connect(ui->listRecieveAddresses,
        QOverload<int>::of(&QComboBox::currentIndexChanged), [=] (int index) {
        QString addr = ui->listRecieveAddresses->itemText(index);
        if (addr.isEmpty()) {
            // Calm loading state instead of a blank field+QR (reads as "broken"); the
            // copy/request controls are disabled by updateReceiveQRandPayload() so the
            // page never offers a silent dead-click during the warmup window.
            ui->txtRecieve->setPlainText(tr("Preparing your address…"));
            ui->qrcodeDisplay->clear();
            updateReceiveQRandPayload();
            return;
        }

        // txtRecieve's plain text MUST stay the exact raw address — Copy reads it verbatim.
        ui->txtRecieve->setPlainText(addr);
        updateReceiveQRandPayload();   // builds the QR (bare addr, or zclassic: URI if amount set)
    });

    // Phase-3c: private-by-default IA. Build the disclosure LAST so it can reparent
    // the now-fully-wired radios into the collapsible advanced panel and bring the
    // page to its private resting view. Done after all the toggle handlers above
    // are connected so reparenting never drops a connection. The disclosure setup
    // also frames the QR (P0-5), adds the primary Copy button (P1/UX-24), and hangs
    // the demoted "Export private key" action behind the advanced panel (P0-4).
    setupReceivePrivacyDisclosure();
}

// Build the optional zclassic: payment-request URI for the SELECTED receive address from the
// request-amount (+ z-only memo) fields. Returns "" when no amount is set (caller then uses the
// bare address). CORRECTNESS: the address is the RAW value recovered by AddressCombo::currentText()
// (the '(' split), never re-parsed display text; the amount goes through getDecimalString so it
// round-trips through the Send-side parser's toDouble(); the memo is PERCENT-ENCODED and appended
// ONLY for a z-address, so it can never inject a '&'/'=' that would break payZClassicURI's
// arg.split('&')/kv.split('=') (which require exactly-2 parts) and matches the parser's t-addr
// memo-drop. This is the symmetric inverse of payZClassicURI — a scanned request re-enters Send.
QString MainWindow::buildReceivePaymentUri() {
    if (!txtReceiveAmount) return QString();
    QString addr = ui->listRecieveAddresses->currentText();   // raw addr (combo '(' split)
    if (addr.isEmpty()) return QString();
    double amt = txtReceiveAmount->text().trimmed().toDouble();
    if (amt <= 0) return QString();                            // no amount -> no request URI
    QString uri = QStringLiteral("zclassic:") % addr % QStringLiteral("?amt=") % Settings::getDecimalString(amt);
    if (txtReceiveMemo && Settings::isZAddress(addr)) {
        QString memo = txtReceiveMemo->text().trimmed();
        if (!memo.isEmpty())
            // HEX-encode the memo: that is the encoding payZClassicURI actually decodes (it
            // hex-decodes a `^[0-9A-F]+$` memo value), so the text round-trips back to the
            // payer EXACTLY. Hex is also injection-safe — only [0-9a-f], never a raw '&'/'='
            // that could break the parser's split('&')/split('=') arity. (Percent-encoding
            // would NOT round-trip: the parser never percent-decodes, and an all-hex plain
            // memo like "2024" would be mis-hex-decoded.)
            uri = uri % QStringLiteral("&memo=") % QString::fromUtf8(memo.toUtf8().toHex());
    }
    return uri;
}

// Refresh the Receive QR + the request-payload affordances from the current address + request
// fields. Presentation only — never mutates the combo or txtRecieve's raw-address plain text.
void MainWindow::updateReceiveQRandPayload() {
    QString addr = ui->listRecieveAddresses->currentText();   // raw addr
    bool haveAddr = !addr.isEmpty();
    bool isZ = haveAddr && Settings::isZAddress(addr);

    // Memo is only deliverable to a shielded (z) address.
    if (txtReceiveMemo) {
        txtReceiveMemo->setEnabled(haveAddr && isZ);
        txtReceiveMemo->setToolTip(isZ ? QString()
            : tr("Memos are only delivered to shielded (z) addresses."));
    }
    // Never a silent dead-click during warmup: disable the actions until an address is ready.
    if (txtReceiveAmount) txtReceiveAmount->setEnabled(haveAddr);

    QString uri = buildReceivePaymentUri();
    bool haveRequest = !uri.isEmpty();
    if (btnReceiveCopyRequest) btnReceiveCopyRequest->setVisible(haveRequest);

    if (!haveAddr) { ui->qrcodeDisplay->clear(); return; }
    // Bake the amount/memo into the QR when a request is set; else the bare address.
    ui->qrcodeDisplay->setQrcodeString(haveRequest ? uri : addr);
}

// Phase-3c (Quiet+): restructure the Receive page so it is PRIVATE BY DEFAULT.
//
// At rest the page shows ONLY the shielded Sapling z-address (combo/QR/label) plus
// a green "Private" indicator. The three radios that used to sit at the top of the
// "Address Type" group are reparented into a collapsible panel revealed by a
// "▸ Other address types (advanced)" QToolButton; the panel is HIDDEN at rest.
// Expanding it exposes the transparent (t-Addr) option and — only when the wallet
// holds legacy Sprout funds — the read-only legacy-Sprout view. The radios remain
// the underlying state machine (all their existing toggle handlers are untouched);
// we only change WHERE they live and WHEN they are shown.
void MainWindow::setupReceivePrivacyDisclosure() {
    // The radios currently live in horizontalLayout_9, itself the first item of
    // groupBox_6's verticalLayout_9. Find that group's vertical layout so we can
    // insert the private badge + disclosure ABOVE the existing address combo row.
    auto* groupLayout = qobject_cast<QVBoxLayout*>(ui->groupBox_6->layout());
    if (groupLayout == nullptr) return;   // defensive: layout shape unexpected

    // The group box "Address Type" title is now redundant clutter for the private-
    // first view; relabel it to something privacy-forward.
    ui->groupBox_6->setTitle(tr("Receive privately"));

    // ---- 0) Plain-language "Get paid" framing (the at-rest answer to "what is this?") --
    auto* lblReceiveHeadline = new QLabel(tr("Get paid"), ui->groupBox_6);
    lblReceiveHeadline->setObjectName("lblReceiveHeadline");
    auto* lblReceiveSubhead = new QLabel(tr("Share the address below to receive ZCL."), ui->groupBox_6);
    lblReceiveSubhead->setObjectName("lblReceiveSubhead");
    lblReceiveSubhead->setWordWrap(true);

    // ---- 1) Green PRIVATE indicator — the shared badge pill (Send-tab parity) -------
    lblReceivePrivate = new QLabel(ui->groupBox_6);
    lblReceivePrivate->setObjectName("lblReceivePrivate");   // qss hook
    // Answer "is this safe to share publicly?" right on the resting line (today only in a
    // tooltip). Use the standardized green badge tokens so Receive matches Send. The
    // "shielded (z) Sapling" technical detail stays in the tooltip, plain words on the line.
    lblReceivePrivate->setText(tr("●  Private — safe to share"));
    lblReceivePrivate->setTextFormat(Qt::PlainText);
    lblReceivePrivate->setProperty("badge", "true");
    lblReceivePrivate->setProperty("tone", "private");
    lblReceivePrivate->setToolTip(tr(
        "This is a shielded (z) Sapling address. The amount, sender and recipient are "
        "encrypted on the blockchain — private by default."));

    // ---- 2) Advanced disclosure toggle --------------------------------------
    btnReceiveAdvanced = new QToolButton(ui->groupBox_6);
    btnReceiveAdvanced->setObjectName("btnReceiveAdvanced");   // qss hook
    btnReceiveAdvanced->setText(tr("Other address types (advanced)"));
    btnReceiveAdvanced->setToolTip(tr(
        "Reveal transparent (public) and legacy address options. Your current address "
        "above is private — you don't need this to receive coins."));
    btnReceiveAdvanced->setCheckable(true);
    btnReceiveAdvanced->setChecked(false);
    btnReceiveAdvanced->setCursor(Qt::PointingHandCursor);
    btnReceiveAdvanced->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    btnReceiveAdvanced->setArrowType(Qt::RightArrow);          // ▸ collapsed
    btnReceiveAdvanced->setAutoRaise(true);

    // ---- 3) Collapsible panel that will HOST the reparented radios ----------
    receiveAdvancedPanel = new QWidget(ui->groupBox_6);
    receiveAdvancedPanel->setObjectName("receiveAdvancedPanel");
    auto* panelV = new QVBoxLayout(receiveAdvancedPanel);
    panelV->setContentsMargins(2, 4, 2, 4);
    panelV->setSpacing(8);

    auto* advCaption = new QLabel(receiveAdvancedPanel);
    advCaption->setObjectName("lblReceiveAdvancedCaption");
    advCaption->setWordWrap(true);
    advCaption->setText(tr(
        "⚠  Transparent (t) addresses are PUBLIC: the address and any balance it "
        "holds are permanently visible to everyone on the blockchain. For privacy, "
        "receive to a shielded (z) address instead. Legacy Sprout is shown only for "
        "funds you already hold."));

    auto* radiosRow = new QHBoxLayout();
    radiosRow->setContentsMargins(0, 0, 0, 0);
    radiosRow->setSpacing(12);

    // Reparent the existing radios out of horizontalLayout_9 into our panel. The
    // Sapling radio is the private DEFAULT and stays hidden inside the panel (it is
    // the state machine, not a user-facing choice); only t-Addr and legacy-Sprout
    // are user-visible advanced choices.
    radiosRow->addWidget(ui->rdioTAddr);
    radiosRow->addWidget(ui->rdioZAddr);
    radiosRow->addStretch(1);

    // Polish P1: the transparent (t-Addr) radio dot must be AMBER, not green — color
    // always equals privacy state. The qss [public="true"] selector recolors it.
    ui->rdioTAddr->setProperty("public", true);
    ui->rdioTAddr->setText(tr("t-Addr (PUBLIC)"));

    // rdioZSAddr is reparented too (so it lives with its peers in one button group
    // container) but stays hidden — selecting it IS the private resting view.
    ui->rdioZSAddr->setParent(receiveAdvancedPanel);
    ui->rdioZSAddr->setVisible(false);

    panelV->addWidget(advCaption);
    panelV->addLayout(radiosRow);

    // ---- Polish P0-4: EXPORT PRIVATE KEY lives ONLY here, behind the advanced
    // disclosure, never on the resting Receive page (UX-19/KEY-1). It carries an
    // explicit confirm (exportKeys() already pops a warning) for the currently
    // selected address. Demoted styling (secondary button) + a clear caption.
    auto* exportRow = new QHBoxLayout();
    exportRow->setContentsMargins(0, 8, 0, 0);
    exportRow->setSpacing(8);
    auto* btnExportKey = new QPushButton(tr("Export private key…"), receiveAdvancedPanel);
    btnExportKey->setObjectName("btnReceiveExportKey");
    btnExportKey->setCursor(Qt::PointingHandCursor);
    btnExportKey->setToolTip(tr(
        "Reveals the spending key for the selected address. Anyone with this key can "
        "spend its funds — only do this on a private screen."));
    QObject::connect(btnExportKey, &QPushButton::clicked, [this]() {
        QString addr = ui->listRecieveAddresses->currentText();
        if (addr.isEmpty())
            return;
        this->exportKeys(addr);   // opens the advanced export dialog (amber intro + in-screen security note)
    });
    exportRow->addWidget(btnExportKey, 0, Qt::AlignLeft);
    exportRow->addStretch(1);
    panelV->addLayout(exportRow);

    receiveAdvancedPanel->setVisible(false);   // collapsed at rest

    // ---- Polish P1/UX-24: a primary "Copy" button adjacent to the address, and
    // New Address demoted to a secondary button. Copy is the most common Receive
    // action. horizontalLayout_10 is [combo][New Address]; insert Copy before New
    // Address and restyle New Address as secondary.
    if (ui->btnRecieveNewAddr) {
        auto* btnCopy = new QPushButton(tr("Copy"), ui->groupBox_6);
        btnCopy->setObjectName("btnReceiveCopy");
        btnCopy->setCursor(Qt::PointingHandCursor);
        btnCopy->setToolTip(tr("Copy this address to the clipboard"));
        QObject::connect(btnCopy, &QPushButton::clicked, [this, btnCopy]() {
            QString addr = ui->txtRecieve->toPlainText().trimmed();
            if (!Settings::isValidAddress(addr))
                addr = ui->listRecieveAddresses->currentText();
            // Guard on VALIDITY, not just non-emptiness: during the warmup window txtRecieve
            // holds the "Preparing your address…" placeholder (non-empty), which must never be
            // copied as if it were an address.
            if (!Settings::isValidAddress(addr)) {
                ui->statusBar->showMessage(tr("No address to copy yet"), 3 * 1000);
                return;
            }
            QGuiApplication::clipboard()->setText(addr);
            ui->statusBar->showMessage(tr("Address copied to clipboard"), 3 * 1000);
            // Inline confirmation right at the cursor (the status bar is far at the window
            // bottom). `this` is the singleShot context so the restore is cancelled if the
            // window dies first (btnCopy is its child).
            btnCopy->setText(tr("Copied ✓"));
            QTimer::singleShot(1500, this, [btnCopy]() { btnCopy->setText(tr("Copy")); });
        });
        if (auto* combaRow = qobject_cast<QHBoxLayout*>(ui->horizontalLayout_10)) {
            // Insert Copy right after the combo (index 1), before New Address.
            combaRow->insertWidget(1, btnCopy);
        }
        // Demote "New Address" to a secondary look (Copy is the primary action).
        ui->btnRecieveNewAddr->setProperty("homeaction", "secondary");
    }

    // ---- Polish P0-5: FRAME the QR in a rounded card on the dark surface,
    // instead of an edge-bleeding white slab. Wrap qrcodeDisplay in a #receiveQrCard
    // QFrame (white bg, radius 12, 16px quiet-zone padding, 1px hairline) and center
    // it in the right column with a fixed-ish footprint. The wrapper is spliced into
    // horizontalLayout_11 in place of the bare qrcodeDisplay.
    if (auto* recvRow = qobject_cast<QHBoxLayout*>(ui->horizontalLayout_11)) {
        auto* qrCard = new QFrame(ui->groupBox_6);
        qrCard->setObjectName("receiveQrCard");
        qrCard->setFrameShape(QFrame::NoFrame);
        qrCard->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        auto* qrV = new QVBoxLayout(qrCard);
        qrV->setContentsMargins(0, 0, 0, 0);
        qrV->setSpacing(0);
        ui->qrcodeDisplay->setParent(qrCard);
        // Narrow-window fix: allow the QR to scale DOWN to 140px (QRCodeLabel.sizeHint is
        // 1:1 and resizeEvent re-renders, so it stays crisp) so the Receive page stops
        // pinning a 200px floor; keep 200 as the max so it looks identical at normal width.
        ui->qrcodeDisplay->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        ui->qrcodeDisplay->setMinimumSize(140, 140);
        ui->qrcodeDisplay->setMaximumSize(200, 200);
        qrV->addWidget(ui->qrcodeDisplay);

        // Wrap the card in a small column so it stays top-centered in the right side.
        auto* qrCol = new QVBoxLayout();
        qrCol->setContentsMargins(0, 0, 0, 0);
        qrCol->addWidget(qrCard, 0, Qt::AlignHCenter | Qt::AlignTop);
        qrCol->addStretch(1);
        recvRow->addLayout(qrCol);
    }

    // ---- 3b) REQUEST AMOUNT (optional) — the idiotproof "they pay the right amount" flow.
    // An optional amount (+ z-only memo) bakes a zclassic:<addr>?amt=&memo= payment-URI into
    // the QR + a "Copy payment request" action, so the payer's wallet pre-fills the exact
    // amount. The URI grammar is symmetric with payZClassicURI (the Send-side parser), so a
    // scanned/pasted request round-trips straight into Send. The address is always the RAW
    // value (never re-parsed display text); the memo is percent-encoded so it can't inject a
    // '&'/'=' that would break the parser; amount goes through getDecimalString.
    auto* reqRow = new QHBoxLayout();
    auto* lblReqCap = new QLabel(tr("Request amount (optional)"), ui->groupBox_6);
    lblReqCap->setObjectName("lblReceiveAddressCaption");   // reuse the dim caption style
    txtReceiveAmount = new QLineEdit(ui->groupBox_6);
    txtReceiveAmount->setObjectName("txtReceiveAmount");
    txtReceiveAmount->setPlaceholderText(tr("0.00"));
    txtReceiveAmount->setAlignment(Qt::AlignRight);
    txtReceiveAmount->setValidator(new QRegExpValidator(QRegExp("[0-9]{0,8}\\.?[0-9]{0,8}"), this));
    txtReceiveAmount->setMaximumWidth(140);
    auto* lblReqUnit = new QLabel(tr("ZCL"), ui->groupBox_6);
    txtReceiveMemo = new QLineEdit(ui->groupBox_6);
    txtReceiveMemo->setObjectName("txtReceiveMemo");
    txtReceiveMemo->setPlaceholderText(tr("Add a note for the sender (optional)"));
    reqRow->addWidget(lblReqCap);
    reqRow->addWidget(txtReceiveAmount);
    reqRow->addWidget(lblReqUnit);
    reqRow->addWidget(txtReceiveMemo);
    // Rebuild the QR/payload live as the amount/memo change.
    QObject::connect(txtReceiveAmount, &QLineEdit::textChanged, this, [this](const QString&){ updateReceiveQRandPayload(); });
    QObject::connect(txtReceiveMemo,   &QLineEdit::textChanged, this, [this](const QString&){ updateReceiveQRandPayload(); });

    // "Copy payment request" — copies the same zclassic: URI; hidden until an amount is set.
    btnReceiveCopyRequest = new QPushButton(tr("Copy payment request"), ui->groupBox_6);
    btnReceiveCopyRequest->setObjectName("btnReceiveCopyRequest");
    btnReceiveCopyRequest->setCursor(Qt::PointingHandCursor);
    btnReceiveCopyRequest->setVisible(false);
    QObject::connect(btnReceiveCopyRequest, &QPushButton::clicked, this, [this]() {
        QString uri = buildReceivePaymentUri();
        if (uri.isEmpty()) return;
        QGuiApplication::clipboard()->setText(uri);
        ui->statusBar->showMessage(tr("Payment request copied to clipboard"), 3 * 1000);
        btnReceiveCopyRequest->setText(tr("Copied ✓"));
        QTimer::singleShot(1500, this, [this]() { btnReceiveCopyRequest->setText(tr("Copy payment request")); });
    });
    if (auto* combaRow = qobject_cast<QHBoxLayout*>(ui->horizontalLayout_10))
        combaRow->addWidget(btnReceiveCopyRequest);

    // ---- 4) Splice everything in ABOVE the address-combo row ----------------
    // groupLayout currently: [0]=horizontalLayout_9 (now-empty radios row),
    // [1]=horizontalLayout_10 (combo + New Address), [2]=lblSproutWarning.
    // Insert (top to bottom): headline, subhead, badge, advanced-toggle, advanced-panel,
    // then the request-amount row just above the address+QR area.
    groupLayout->insertWidget(0, lblReceiveHeadline);
    groupLayout->insertWidget(1, lblReceiveSubhead);
    groupLayout->insertWidget(2, lblReceivePrivate);
    groupLayout->insertWidget(3, btnReceiveAdvanced);
    groupLayout->insertWidget(4, receiveAdvancedPanel);
    // Place the request-amount row just after the public/sprout warning (i.e. directly
    // above the address+QR area), or at the end if the warning isn't in this layout.
    int warnIdx = groupLayout->indexOf(ui->lblSproutWarning);
    groupLayout->insertLayout(warnIdx >= 0 ? warnIdx + 1 : groupLayout->count(), reqRow);

    // ---- 5) Wire the toggle -------------------------------------------------
    QObject::connect(btnReceiveAdvanced, &QToolButton::toggled, [=](bool checked) {
        setReceiveAdvancedExpanded(checked);
    });

    // ---- 6) Bring the page to its private resting VISUAL state --------------
    // NOTE: this runs during MainWindow construction, BEFORE `rpc` exists
    // (setupRecieveTab() is called before `rpc = new RPC(this)`). We therefore set
    // only the resting *visual* state here and must NOT fire a radio toggle that
    // would dereference the still-null rpc (addZAddrsToComboList / updateTAddrCombo
    // both deref this->rpc). The actual private (Sapling) SELECTION that populates
    // the combo happens on the first tab-switch to Receive (currentChanged, tab==2),
    // once rpc is live — exactly as the original code did. The Sapling radio itself
    // never needs to be user-visible: it is the private default state machine.
    receiveAdvancedExpanded = false;
    receiveAdvancedPanel->setVisible(false);
    {
        QSignalBlocker block(btnReceiveAdvanced);
        btnReceiveAdvanced->setChecked(false);
        btnReceiveAdvanced->setArrowType(Qt::RightArrow);
    }
    if (lblReceivePrivate)
        lblReceivePrivate->setVisible(true);
    ui->rdioZSAddr->setVisible(false);
    ui->lblSproutWarning->setVisible(false);   // no scary caption at rest

    // Sprout funds are unknown until rpc is live (returns false now, re-evaluated
    // on every Receive tab-switch); hides the legacy-Sprout radio when not held.
    refreshReceiveAdvancedOptions();
}

// Show/hide the advanced disclosure. Collapsing always returns to the private
// (Sapling) view so the page never rests on a transparent/Sprout selection.
void MainWindow::setReceiveAdvancedExpanded(bool expanded) {
    receiveAdvancedExpanded = expanded;

    if (btnReceiveAdvanced) {
        QSignalBlocker block(btnReceiveAdvanced);   // avoid toggle->this re-entry
        btnReceiveAdvanced->setChecked(expanded);
        btnReceiveAdvanced->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
    }
    if (receiveAdvancedPanel)
        receiveAdvancedPanel->setVisible(expanded);

    if (!expanded) {
        // Returning to private: re-select Sapling (clears the PUBLIC caption via the
        // rdioZSAddr toggle handler) so collapsing is also "go back to private".
        if (!ui->rdioZSAddr->isChecked())
            ui->rdioZSAddr->setChecked(true);
        else
            ui->lblSproutWarning->setVisible(false);
    }
    // The green PRIVATE badge is the resting affordance: show it only while private.
    if (lblReceivePrivate)
        lblReceivePrivate->setVisible(!expanded);
}

// True iff the wallet holds at least one legacy (non-Sapling) z-address — i.e.
// Sprout funds the user may still want to view/spend. Uses the same Sapling test
// the combo-population path uses, so it agrees with what rdioZAddr would show.
bool MainWindow::walletHasLegacySprout() const {
    if (rpc == nullptr) return false;
    auto* zaddrs = rpc->getAllZAddresses();
    if (zaddrs == nullptr) return false;
    for (const auto& addr : *zaddrs) {
        if (!Settings::getInstance()->isSaplingAddress(addr))
            return true;
    }
    return false;
}

// Offer the legacy-Sprout radio ONLY when the wallet actually holds Sprout funds;
// otherwise it is dead clutter that re-introduces a deprecated path. The t-Addr
// radio is always available under the disclosure. Safe to call before build.
void MainWindow::refreshReceiveAdvancedOptions() {
    const bool hasSprout = walletHasLegacySprout();
    ui->rdioZAddr->setVisible(hasSprout);
    // If Sprout funds vanished while it was selected, fall back to private.
    if (!hasSprout && ui->rdioZAddr->isChecked())
        ui->rdioZSAddr->setChecked(true);
}

void MainWindow::updateTAddrCombo(bool checked) {
    if (checked) {
        auto utxos = this->rpc->getUTXOs();
        ui->listRecieveAddresses->clear();

        std::for_each(utxos->begin(), utxos->end(), [=](auto& utxo) {
            auto addr = utxo.address;
            if (addr.startsWith("t") && ui->listRecieveAddresses->findText(addr) < 0) {
                auto bal = rpc->getAllBalances()->value(addr);
                ui->listRecieveAddresses->addItem(addr, bal);
            }
        });
    }
};

// Updates the labels everywhere on the UI. Call this after the labels have been updated
void MainWindow::updateLabels() {
    // Update the Receive tab
    if (ui->rdioTAddr->isChecked()) {
        updateTAddrCombo(true);
    }
    else {
        addZAddrsToComboList(ui->rdioZSAddr->isChecked())(true);
    }

    // Update the Send Tab
    updateFromCombo();

    // Update the autocomplete
    updateLabelsAutoComplete();
}

MainWindow::~MainWindow()
{
    delete ui;
    delete rpc;
    delete labelCompleter;

    delete loadingMovie;
    delete logger;
}

#ifdef ZCL_WIDGET_TEST
// TEST-ONLY SEAM (L1 widget tests). Compiled in ONLY under ZCL_WIDGET_TEST;
// NEVER present in the shipped app. Installs an empty balances map on the RPC so
// confirmTx()'s rpc->getAllBalances()->value(...) deref is safe in-process
// without a live daemon (the value() of an absent key is 0, which is fine for a
// pure UX-warning assertion).
void MainWindow::testSeedBalances() {
    rpc->testSetBalances(new QMap<QString, double>());
}
#endif
