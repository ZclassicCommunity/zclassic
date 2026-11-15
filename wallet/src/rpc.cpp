#include "rpc.h"

#include "addressbook.h"
#include "settings.h"
#include "senttxstore.h"
#include "turnstile.h"
#include "version.h"
#include "guistartup.h"     // [gui-startup] first-balance milestone + summary line

#include <QEventLoop>
#include <QElapsedTimer>

using json = nlohmann::json;

RPC::RPC(MainWindow* main) {
    auto cl = new ConnectionLoader(main, this);

    // Execute the load connection async, so we can set up the rest of RPC properly.
#ifdef ZCL_WIDGET_TEST
    // L1 widget tests construct the REAL MainWindow/RPC but have NO daemon. The
    // auto-connect kicks off a SELF-PERPETUATING doAutoConnect() re-arm chain; a
    // loop-spinning test (one that calls confirmTx -> d.exec()) would start that
    // chain, and a later step firing after the test's window is gone would touch
    // freed objects (UAF/SIGSEGV) and bleed across tests. Tests drive balances/
    // addresses via the testSet* seams instead of a live connection, so skip the
    // auto-connect entirely under the test build. (Guarded -> never in the app.)
    (void)cl;
#else
    // Context object 'main': if the window is torn down before this 1ms timer
    // fires (a very fast quit), Qt auto-cancels the singleShot so the lambda
    // never runs against the freed ConnectionLoader (UAF on a fast quit).
    QTimer::singleShot(1, main, [=]() { cl->loadConnection(); });
#endif

    this->main = main;
    this->ui = main->ui;

    this->turnstile = new Turnstile(this, main);

    // Setup balances table model
    balancesTableModel = new BalancesTableModel(main->ui->balancesTable);
    main->ui->balancesTable->setModel(balancesTableModel);

    // Setup transactions table model
    transactionsTableModel = new TxTableModel(ui->transactionsTable);
    main->ui->transactionsTable->setModel(transactionsTableModel);
    main->ui->transactionsTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);

    // Set up timer to refresh Price
    priceTimer = new QTimer(main);
    QObject::connect(priceTimer, &QTimer::timeout, [=]() {
        refreshZCLPrice();
    });
    priceTimer->start(Settings::priceRefreshSpeed);  // Every hour

    // Set up a timer to refresh the UI every few seconds
    timer = new QTimer(main);
    QObject::connect(timer, &QTimer::timeout, [=]() {
        refresh();
    });
    timer->start(Settings::updateSpeed);    

    // Set up the timer to watch for tx status
    txTimer = new QTimer(main);
    QObject::connect(txTimer, &QTimer::timeout, [=]() {
        watchTxStatus();
    });
    // Start at every 10s. When an operation is pending, this will change to every second
    txTimer->start(Settings::updateSpeed);

    // NOTIFY-SRV debounce: single-shot, coalesces a push BURST (a block + its wallet
    // txns) into one refresh. Same ownership/cleanup pattern as timer/txTimer (parented
    // to main, deleted in ~RPC, stopped in onAboutToQuit). The timeout runs
    // refresh(TRUE) -- see onNotifyPush()/the comment below for why force is mandatory.
    notifyDebounce = new QTimer(main);
    notifyDebounce->setSingleShot(true);
    QObject::connect(notifyDebounce, &QTimer::timeout, [=]() {
        // CRITICAL: force=TRUE. A -walletnotify fires on mempool/unconfirmed wallet
        // events where the block HEIGHT is unchanged; the height-gate (PERF-20) would
        // skip refresh(false), so an incoming unconfirmed payment would never repaint.
        // A validated notify is positive evidence of a change, so force past the gate.
        refresh(true);
    });

    // NOTIFY-SRV: mint the per-session push trigger, but ONLY for a non-headless
    // (GUI) session. Headless/CLI keeps the timer poll and never stands up a socket.
    // This only constructs the object + mints the token; the socket is started (and
    // notified() wired) later, ONLY on the owned-daemon launch path. Parented to main
    // (a QObject) like the timers; ~RPC stops + deletes it explicitly.
    if (!Settings::getInstance()->isHeadless())
        notifyServer = new NotifyServer(main);

    usedAddresses = new QMap<QString, bool>();
}

RPC::~RPC() {
    delete timer;
    delete txTimer;
    delete notifyDebounce;

    delete transactionsTableModel;
    delete balancesTableModel;
    delete turnstile;

    delete utxos;
    delete allBalances;
    delete usedAddresses;
    delete zaddresses;
    delete taddresses;

    // NOTIFY-SRV: stop() (removes the socket + the 0600 token file) BEFORE delete so
    // the on-disk token is invalidated even on this teardown path.
    if (notifyServer) {
        notifyServer->stop();
        delete notifyServer;
        notifyServer = nullptr;
    }

    delete conn;
}

void RPC::setEZClassicd(QProcess* p) {
    ezclassicd = p;

    if (ezclassicd && ui->tabWidget->widget(4) == nullptr) {
        ui->tabWidget->addTab(main->zclassicdtab, "zclassicd");
    }

    // F2: drop any prior finished-handler before (re)wiring. Without this, adopting a
    // new process (or re-adopting after a crash-restart) would stack a second handler
    // on top of the first, so a single death fires handleEZClassicdCrash twice.
    if (ezCrashConn) {
        QObject::disconnect(ezCrashConn);
        ezCrashConn = {};
    }

    // Now that RPC owns the live embedded node (the ConnectionLoader dropped all its
    // own handlers on handoff), watch for it dying at runtime so we can offer a
    // restart instead of stranding the user. Bind to 'main' as context so the
    // connection auto-disconnects if it is destroyed. Only when we actually have a
    // process (setEZClassicd is also called with nullptr on teardown).
    if (p != nullptr) {
        // F1: adopting/starting a node clears the deliberate-shutdown latch so a
        // later crash is actually treated as a crash (the latch is set only at the
        // top of shutdownZClassicd()). Also clear the shutdown re-entrancy latch:
        // adopting a fresh live node means any prior shutdown is fully done, so a
        // future Quit must be able to run again (the latch only serializes within
        // one shutdown, it must NOT persist for the process lifetime).
        ezExpectedShutdown = false;
        ezShuttingDown     = false;
        ezCrashConn = QObject::connect(p, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                         main, [this](int code, QProcess::ExitStatus st) {
            handleEZClassicdCrash(code, st);
        });

        // NOTIFY-SRV: wire the push channel to the debounced refresh, but ONLY when the
        // socket is actually listening. The socket is started exclusively on the
        // owned-daemon launch path (startEmbeddedZClassicd); a FOREIGN/systemd daemon we
        // merely attach to never starts it (isListening() is false), so it stays on the
        // timer poll and is never wired here. Drop any prior binding first so a
        // crash-restart re-adopt doesn't stack a second connection.
        if (notifyServer && notifyServer->isListening()) {
            QObject::disconnect(notifyServer, &NotifyServer::notified, nullptr, nullptr);
            QObject::connect(notifyServer, &NotifyServer::notified,
                             main, [this](const QString&) { onNotifyPush(); });
        }
    }
}

// Relaunch the SAME embedded node process after a crash. QProcess retains
// program()/arguments() from the prior start(), so this reuses the same
// datadir/conf and RPC port and the refresh timer auto-reconnects once it
// answers. F3: strip one-shot repair flags (-reindex/-reindex-chainstate) that
// a relaunchForRepair() launch may have carried, so a crash-restart never
// silently re-runs a multi-hour rebuild. Always called deferred (out of the
// QProcess::finished slot) so the slot has unwound before start().
void RPC::restartEmbeddedZClassicd() {
    if (!ezclassicd)
        return;
    QStringList args = ezclassicd->arguments();
    QStringList clean;
    for (const QString& a : args)
        if (!a.startsWith("-reindex"))
            clean << a;
    ezExpectedShutdown = false;   // (F1) a fresh start is not a deliberate shutdown
    main->logger->write(QString("Restarting embedded zclassicd (attempt %1)").arg(ezRestartCount));
    ezclassicd->start(ezclassicd->program(), clean);
}

// Runtime recovery for the embedded node dying unexpectedly (crash/OOM). On a
// normal shutdown (ezExpectedShutdown) this is a no-op. Otherwise we drop into the
// No-Connection state and recover, capped at a few tries (the cap resets on a
// successful getinfo, so it means "3 crashes without a recovery in between").
void RPC::handleEZClassicdCrash(int exitCode, QProcess::ExitStatus status) {
    if (ezExpectedShutdown)
        return;     // normal shutdown, ignore
    if (ezCrashDialogOpen)
        return;     // already handling

    this->noConnection();
    main->logger->write(QString("Embedded zclassicd died at runtime: code=%1 status=%2")
                            .arg(exitCode).arg((int)status));

    // Tray-resident / backgrounded: the window is hidden, so a modal would pop over
    // a window the user can't see (and may never notice) — defeating the whole point
    // of "stay synced in the background". Recover SILENTLY and post a tray
    // notification instead of stranding a dead node behind an unseen dialog.
    if (main->isHidden()) {
        if (ezRestartCount >= 3) {
            main->notify(QObject::tr("ZClassic node keeps stopping"),
                QObject::tr("The background node stopped several times. Open ZClassic to "
                    "look into it. Your wallet and coins are safe."));
            return;
        }
        ezRestartCount++;
        main->notify(QObject::tr("ZClassic node restarted"),
            QObject::tr("The node stopped and was restarted automatically. "
                "Your wallet and coins are safe."));
        // Defer so the finished slot unwinds before we start() the process again.
        QTimer::singleShot(0, main, [this]() { restartEmbeddedZClassicd(); });
        return;
    }

    if (ezRestartCount >= 3) {
        // Terminal: too many crashes without a recovery. Defer the modal too (for
        // the same reason as below: no nested event loop inside the finished slot).
        ezCrashDialogOpen = true;
        QTimer::singleShot(0, main, [this]() {
            QMessageBox::critical(main, QObject::tr("ZClassic node keeps stopping"),
                QObject::tr("The ZClassic node has stopped several times in a row. Please "
                    "restart the app, and check that you have free disk space. You can also "
                    "look at the log files for more detail.\n\nYour wallet and coins are safe."));
            ezCrashDialogOpen = false;
        });
        return;
    }

    // F2: do NOT run a modal dialog (its nested event loop) directly inside the
    // QProcess::finished slot — that re-enters the event loop from within a slot,
    // which is fragile. Defer it with singleShot(0) so the finished slot unwinds
    // first, and latch ezCrashDialogOpen so a second finished can't schedule a
    // duplicate dialog before this one is dismissed.
    ezCrashDialogOpen = true;

    QTimer::singleShot(0, main, [this]() {
        QMessageBox box(main);
        box.setIcon(QMessageBox::Warning);
        box.setWindowTitle(QObject::tr("ZClassic node stopped"));
        box.setText(QObject::tr("The ZClassic node stopped unexpectedly. You can restart it "
            "now — your wallet and coins are safe."));
        QPushButton* restartBtn = box.addButton(QObject::tr("Restart node"), QMessageBox::AcceptRole);
        QPushButton* quitBtn    = box.addButton(QObject::tr("Quit"),         QMessageBox::RejectRole);
        box.setDefaultButton(restartBtn);
        box.exec();

        if (box.clickedButton() == restartBtn) {
            ezRestartCount++;
            restartEmbeddedZClassicd();
        } else if (box.clickedButton() == quitBtn) {
            QApplication::quit();
        }

        ezCrashDialogOpen = false;
    });
}

// Called when a connection to zclassicd is available. 
void RPC::setConnection(Connection* c) {
    if (c == nullptr) return;

    delete conn;
    this->conn = c;

    // ADVANCED-TAB-FIX: the node-stats ("zclassicd") page is held aside at startup
    // (MainWindow ctor: widget(4) + removeTab(4)) and must be re-added once we are
    // attached to a LIVE node so the nav-rail "⚙ Advanced" button has somewhere to
    // land. setConnection is the universal attach instant: doRPCSetConnection calls
    // it for BOTH the embedded (owned-QProcess) path AND the foreign/already-running
    // node path, and it has already early-returned above when c == nullptr, so it
    // never fires on teardown/showError. Previously the tab was added only inside
    // setEZClassicd behind an `ezclassicd != nullptr` gate, so a foreign node (the
    // now-common path, ezclassicd stays null) never got the tab and Advanced was a
    // silent no-op. All fields on the page are RPC-derived (getinfo connections,
    // getnetworksolps, getblockchaininfo, getpeerinfo) and valid for any node; none
    // read the QProcess. Keep the widget(4)==nullptr guard — it is the genuine
    // no-double-add sentinel (tab_5/index 4 is the only widget at index>=4, the sole
    // removeTab is the ctor, the sole adds are here + the now-redundant setEZClassicd
    // path) and also honors "do not re-add after close" if a close path is ever added.
    if (main->zclassicdtab != nullptr && ui->tabWidget->widget(4) == nullptr) {
        ui->tabWidget->addTab(main->zclassicdtab, "zclassicd");
    }

    // W1-6: a new connection may be a different node/chain, so drop the sent-z
    // confirmation cache; we must never carry stale deep-conf counts across a reconnect.
    sentZConfCache.clear();
    sentZConfCacheHeight = 0;

    // Don't claim "Ready!" here -- we've only just connected to the node; it may
    // still be syncing. The real status (Syncing %/Connected) is set by the
    // getblockchaininfo poll a moment later.
    ui->statusBar->showMessage(QObject::tr("Connected — checking blockchain…"));

    // See if we need to remove the reindex/rescan flags from the zclassic.conf file
    auto zclassicConfLocation = Settings::getInstance()->getZClassicdConfLocation();
    Settings::removeFromZClassicConf(zclassicConfLocation, "rescan");
    Settings::removeFromZClassicConf(zclassicConfLocation, "reindex");

    // W1-3: get the wallet UI onto the screen FIRST. The forced refresh (balances/
    // transactions) is the critical path the user is waiting on after connect; do it
    // immediately. This might also be coming from a settings update where we need to
    // immediately refresh.
    refresh(true);

    // The price ticker and the GitHub update check are NOT on the connect critical
    // path — they hit the network and (the update check) can pop a modal. Defer them a
    // few seconds so they never stall the freshly-connected UI. 'main' is the context
    // object (RPC is not a QObject); since `delete rpc` runs inside ~MainWindow, if the
    // window is torn down before this fires Qt auto-cancels the singleShot so the
    // lambda never runs against a freed RPC (UAF-safety, per the line-31 idiom).
    QTimer::singleShot(4000, main, [this]() {
        refreshZCLPrice();
        checkForUpdate();
    });
}

void RPC::getTAddresses(const std::function<void(json)>& cb) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "getaddressesbyaccount"},
        {"params", {""}}
    };

    conn->doRPCWithDefaultErrorHandling(payload, cb);
}

void RPC::getZAddresses(const std::function<void(json)>& cb) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "z_listaddresses"},
    };

    conn->doRPCWithDefaultErrorHandling(payload, cb);
}

void RPC::getTransparentUnspent(const std::function<void(json)>& cb, const std::function<void(void)>& err) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "listunspent"},
        {"params", {0}}             // Get UTXOs with 0 confirmations as well.
    };

    // W1-5: use the error-AWARE doRPC (not the default dialog handler) so a failed
    // unspent query still notifies the caller — otherwise the count==2 join latch in
    // refreshBalances would hang forever. We swallow the dialog here (no popup during
    // warmup) and let the caller settle the join; the next refresh retries.
    conn->doRPC(payload, cb, [=] (QNetworkReply*, const json&) { err(); });
}

void RPC::getZUnspent(const std::function<void(json)>& cb, const std::function<void(void)>& err) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "z_listunspent"},
        {"params", {0}}             // Get UTXOs with 0 confirmations as well.
    };

    conn->doRPC(payload, cb, [=] (QNetworkReply*, const json&) { err(); });
}

void RPC::newZaddr(bool sapling, const std::function<void(json)>& cb) {
#ifdef ZCL_WIDGET_TEST
    // TEST-ONLY SEAM (L1 widget tests, MAJOR-3): there is NO daemon/connection, so
    // route through a controllable stub instead of conn-> (which would null-deref).
    // The test installs the next result via testSetNextZaddrResult(): a non-empty
    // string is delivered to the callback as a JSON string (a successful create);
    // an empty/unset result delivers nothing (simulates a FAILED create). This lets
    // the fail-open vs fail-closed paths in createSaplingAddressSync() be driven
    // deterministically. Compiled in ONLY under ZCL_WIDGET_TEST; never in the app.
    (void)sapling;
    if (!testNextZaddrResult.isEmpty()) {
        QString r = testNextZaddrResult;
        testNextZaddrResult.clear();   // one-shot: consume so a later create can fail
        cb(json(r.toStdString()));
    }
    return;
#else
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "z_getnewaddress"},
        {"params", { sapling ? "sapling" : "sprout" }},
    };

    conn->doRPCWithDefaultErrorHandling(payload, cb);
#endif
}

void RPC::newTaddr(const std::function<void(json)>& cb) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "getnewaddress"},
    };

    conn->doRPCWithDefaultErrorHandling(payload, cb);
}

void RPC::getZPrivKey(QString addr, const std::function<void(json)>& cb) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "z_exportkey"},
        {"params", { addr.toStdString() }},
    };
    
    conn->doRPCWithDefaultErrorHandling(payload, cb);
}

void RPC::getTPrivKey(QString addr, const std::function<void(json)>& cb) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "dumpprivkey"},
        {"params", { addr.toStdString() }},
    };
    
    conn->doRPCWithDefaultErrorHandling(payload, cb);
}

void RPC::importZPrivKey(QString addr, bool rescan, const std::function<void(json)>& cb) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "z_importkey"},
        {"params", { addr.toStdString(), (rescan? "yes" : "no") }},
    };
    
    conn->doRPCWithDefaultErrorHandling(payload, cb);
}


void RPC::importTPrivKey(QString addr, bool rescan, const std::function<void(json)>& cb) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "importprivkey"},
        {"params", { addr.toStdString(), (rescan? "yes" : "no") }},
    };
    
    conn->doRPCWithDefaultErrorHandling(payload, cb);
}


void RPC::getBalance(const std::function<void(json)>& cb) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "z_gettotalbalance"},
        {"params", {0}}             // Get Unconfirmed balance as well.
    };

    conn->doRPCWithDefaultErrorHandling(payload, cb);
}

// INSTANT-BALANCE fast path. getwalletsummary returns the wallet's transparent and
// private (shielded) totals in ONE round-trip from the daemon's cached note-value
// accessors (no per-note re-decrypt, no per-address listunspent join), so the hero
// balance paints instantly on connect — this REPLACES the slow z_gettotalbalance
// hero query when the daemon supports it (see refreshBalances).
//
// MONEY-CORRECTNESS: we pass minconf=0 to match getBalance()'s z_gettotalbalance {0}
// to the satoshi — daemon-side getwalletsummary(0).transparent == getBalanceTaddr("",0)
// (the very call z_gettotalbalance uses) and .private == cached Sprout+Sapling at
// minconf 0 (proven equal to the slow scan), so .total == z_gettotalbalance(0).total.
// minconf=0 includes 0-conf funds, exactly as the legacy hero did, so the two paths
// can never disagree and switching daemons never changes the displayed number.
//
// Amounts are FormatMoney decimal strings (identical representation to
// z_gettotalbalance). We use the error-AWARE doRPC (not the default dialog handler)
// and forward the parsed JSON-RPC body to the err cb so the caller can detect -32601
// ("Method not found") on an OLD daemon and latch the capability off — no warmup/
// transient error pops a dialog here. KEY-1: reads ONLY balance numbers; no key
// material involved.
void RPC::getWalletSummary(const std::function<void(json)>& cb,
                           const std::function<void(const json&)>& err) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "getwalletsummary"},
        {"params", {0}}             // minconf=0: match z_gettotalbalance {0} exactly.
    };

    conn->doRPC(payload, cb, [=] (QNetworkReply*, const json& parsed) { err(parsed); });
}

void RPC::getTransactions(const std::function<void(json)>& cb) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "listtransactions"}
    };

    conn->doRPCWithDefaultErrorHandling(payload, cb);
}

void RPC::sendZTransaction(json params, const std::function<void(json)>& cb, 
    const std::function<void(QString)>& err) {
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "z_sendmany"},
        {"params", params}
    };

    conn->doRPC(payload, cb,  [=] (auto reply, auto parsed) {
        if (!parsed.is_discarded() && !parsed["error"]["message"].is_null()) {
            err(QString::fromStdString(parsed["error"]["message"]));    
        } else {
            err(reply->errorString());
        }
    });
}

/**
 * Method to get all the private keys for both z and t addresses. It will make 2 batch calls,
 * combine the result, and call the callback with a single list containing both the t-addr and z-addr
 * private keys
 */ 
void RPC::getAllPrivKeys(const std::function<void(QList<QPair<QString, QString>>)> cb) {
    if (conn == nullptr) {
        // No connection, just return
        return;
    }

    // A special function that will call the callback when two lists have been added
    auto holder = new QPair<int, QList<QPair<QString, QString>>>();
    holder->first = 0;  // This is the number of times the callback has been called, initialized to 0
    auto fnCombineTwoLists = [=] (QList<QPair<QString, QString>> list) {
        // Increment the callback counter
        holder->first++;    

        // Add all
        std::copy(list.begin(), list.end(), std::back_inserter(holder->second));
        
        // And if the caller has been called twice, do the parent callback with the 
        // collected list
        if (holder->first == 2) {
            // Sort so z addresses are on top
            std::sort(holder->second.begin(), holder->second.end(), 
                        [=] (auto a, auto b) { return a.first > b.first; });

            cb(holder->second);
            delete holder;
        }            
    };

    // A utility fn to do the batch calling
    auto fnDoBatchGetPrivKeys = [=](json getAddressPayload, std::string privKeyDumpMethodName) {
        conn->doRPCWithDefaultErrorHandling(getAddressPayload, [=] (json resp) {
            QList<QString> addrs;
            for (auto addr : resp.get<json::array_t>()) {   
                addrs.push_back(QString::fromStdString(addr.get<json::string_t>()));
            }

            // Then, do a batch request to get all the private keys
            conn->doBatchRPC<QString>(
                addrs, 
                [=] (auto addr) {
                    json payload = {
                        {"jsonrpc", "1.0"},
                        {"id", "someid"},
                        {"method", privKeyDumpMethodName},
                        {"params", { addr.toStdString() }},
                    };
                    return payload;
                },
                [=] (QMap<QString, json>* privkeys) {
                    QList<QPair<QString, QString>> allTKeys;
                    for (QString addr: privkeys->keys()) {
                        allTKeys.push_back(
                            QPair<QString, QString>(
                                addr, 
                                QString::fromStdString(privkeys->value(addr).get<json::string_t>())));
                    }

                    fnCombineTwoLists(allTKeys);
                    delete privkeys;
                }
            );
        });
    };

    // First get all the t and z addresses.
    json payloadT = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "getaddressesbyaccount"},
        {"params", {""} }
    };

    json payloadZ = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "z_listaddresses"}
    };

    fnDoBatchGetPrivKeys(payloadT, "dumpprivkey");
    fnDoBatchGetPrivKeys(payloadZ, "z_exportkey");
}


// Build the RPC JSON Parameters for this tx
void RPC::fillTxJsonParams(json& params, Tx tx) {   
    Q_ASSERT(params.is_array());
    // Get all the addresses and amounts
    json allRecepients = json::array();

    // For each addr/amt/memo, construct the JSON and also build the confirm dialog box    
    for (int i=0; i < tx.toAddrs.size(); i++) {
        auto toAddr = tx.toAddrs[i];

        // Construct the JSON params
        json rec = json::object();
        rec["address"]      = toAddr.addr.toStdString();
        // Force it through string for rounding. Without this, decimal points beyond 8 places
        // will appear, causing an "invalid amount" error
        rec["amount"]       = Settings::getDecimalString(toAddr.amount).toStdString(); //.toDouble(); 
        if (toAddr.addr.startsWith("z") && !toAddr.encodedMemo.trimmed().isEmpty())
            rec["memo"]     = toAddr.encodedMemo.toStdString();

        allRecepients.push_back(rec);
    }

    // Add sender    
    params.push_back(tx.fromAddr.toStdString());
    params.push_back(allRecepients);

    // Add fees if custom fees are allowed.
    if (Settings::getInstance()->getAllowCustomFees()) {
        params.push_back(1); // minconf
        params.push_back(tx.fee);
    }
}


void RPC::noConnection(bool preserveBalances) {
    QIcon i = QApplication::style()->standardIcon(QStyle::SP_MessageBoxCritical);
    main->statusIcon->setPixmap(i.pixmap(16, 16));
    main->statusIcon->setToolTip("");
    main->statusLabel->setText(QObject::tr("No Connection"));
    main->statusLabel->setToolTip("");
    main->ui->statusBar->showMessage(QObject::tr("No Connection"), 1000);

    // P0-6: reflect the lost connection in the main-tab sync banner.
    main->setSyncStatusConnecting();

    // transient-disconnect-zeroes-hero: a SOFT disconnect (one debounced getinfo
    // error, connection still live) must NOT discard the last-known balances. Keep
    // the labels/tables/send-inputs exactly as painted and only de-confidence the
    // hero to WARMING grey with the "Last updated … · refreshing" qualifier
    // (fromCache=true). Because the canonical labels stay non-blank, updateHomeFixIt
    // reads haveNumber=true, so a funded wallet keeps Send primary and never flashes
    // grey "0 ZCL". transparent=0.0 only hides the amber shield card for the blip; it
    // re-appears on the next successful poll. The full teardown below runs only on a
    // sustained outage (or any of the many conn==nullptr callers, which pass false).
    if (preserveBalances) {
        main->updateHomeFixIt(0.0, /*fromCache=*/true);
        return;
    }

    // Clear balances table.
    QMap<QString, double> emptyBalances;
    QList<UnspentOutput>  emptyOutputs;
    balancesTableModel->setNewData(&emptyBalances, &emptyOutputs);

    // Clear Transactions table.
    QList<TransactionItem> emptyTxs;
    transactionsTableModel->addTData(emptyTxs);
    transactionsTableModel->addZRecvData(emptyTxs);
    transactionsTableModel->addZSentData(emptyTxs);

    // Clear balances
    ui->balSheilded->setText("");
    ui->balTransparent->setText("");
    ui->balTotal->setText("");

    ui->balSheilded->setToolTip("");
    ui->balTransparent->setToolTip("");
    ui->balTotal->setToolTip("");

    // Phase-3b: with no connection there is no public balance to surface — clear the
    // hero and hide the amber fix-it card (transparent == 0 hides it).
    main->updateHomeFixIt(0.0);

    // Clear send tab from address
    ui->inputsCombo->clear();
}

// Refresh received z txs by calling z_listreceivedbyaddress/gettransaction
void RPC::refreshReceivedZTrans(QList<QString> zaddrs) {
    if  (conn == nullptr) 
        return noConnection();

    // We'll only refresh the received Z txs if settings allows us.
    if (!Settings::getInstance()->getSaveZtxs()) {
        QList<TransactionItem> emptylist;
        transactionsTableModel->addZRecvData(emptylist);
        return;
    }
        
    // This method is complicated because z_listreceivedbyaddress only returns the txid, and 
    // we have to make a follow up call to gettransaction to get details of that transaction. 
    // Additionally, it has to be done in batches, because there are multiple z-Addresses, 
    // and each z-Addr can have multiple received txs. 

    // 1. For each z-Addr, get list of received txs    
    conn->doBatchRPC<QString>(zaddrs,
        [=] (QString zaddr) {
            json payload = {
                {"jsonrpc", "1.0"},
                {"id", "z_lrba"},
                {"method", "z_listreceivedbyaddress"},
                {"params", {zaddr.toStdString(), 0}}      // Accept 0 conf as well.
            };

            return payload;
        },          
        [=] (QMap<QString, json>* zaddrTxids) {
            // Process all txids, removing duplicates. This can happen if the same address
            // appears multiple times in a single tx's outputs.
            QSet<QString> txids;
            QMap<QString, QString> memos;
            for (auto it = zaddrTxids->constBegin(); it != zaddrTxids->constEnd(); it++) {
                auto zaddr = it.key();
                for (auto& i : it.value().get<json::array_t>()) {   
                    // Mark the address as used
                    usedAddresses->insert(zaddr, true);

                    // Filter out change txs
                    if (! i["change"].get<json::boolean_t>()) {
                        auto txid = QString::fromStdString(i["txid"].get<json::string_t>());
                        txids.insert(txid);    

                        // Check for Memos
                        QString memoBytes = QString::fromStdString(i["memo"].get<json::string_t>());
                        if (!memoBytes.startsWith("f600"))  {
                            QString memo(QByteArray::fromHex(
                                            QByteArray::fromStdString(i["memo"].get<json::string_t>())));
                            if (!memo.trimmed().isEmpty())
                                memos[zaddr + txid] = memo;
                        }
                    }
                }                        
            }

            // 2. For all txids, go and get the details of that txid.
            conn->doBatchRPC<QString>(txids.toList(),
                [=] (QString txid) {
                    json payload = {
                        {"jsonrpc", "1.0"},
                        {"id",  "gettx"},
                        {"method", "gettransaction"},
                        {"params", {txid.toStdString()}}
                    };

                    return payload;
                },
                [=] (QMap<QString, json>* txidDetails) {
                    QList<TransactionItem> txdata;

                    // Combine them both together. For every zAddr's txid, get the amount, fee, confirmations and time
                    for (auto it = zaddrTxids->constBegin(); it != zaddrTxids->constEnd(); it++) {                        
                        for (auto& i : it.value().get<json::array_t>()) {   
                            // Filter out change txs
                            if (i["change"].get<json::boolean_t>())
                                continue;
                            
                            auto zaddr = it.key();
                            auto txid  = QString::fromStdString(i["txid"].get<json::string_t>());

                            // Lookup txid in the map
                            auto txidInfo = txidDetails->value(txid);

                            qint64 timestamp;
                            if (txidInfo.find("time") != txidInfo.end()) {
                                timestamp = txidInfo["time"].get<json::number_unsigned_t>();
                            } else {
                                timestamp = txidInfo["blocktime"].get<json::number_unsigned_t>();
                            }
                            
                            auto amount        = i["amount"].get<json::number_float_t>();
                            auto confirmations = (unsigned long)txidInfo["confirmations"].get<json::number_unsigned_t>();                            

                            TransactionItem tx{ QString("receive"), timestamp, zaddr, txid, amount, 
                                                confirmations, "", memos.value(zaddr + txid, "") };
                            txdata.push_front(tx);
                        }
                    }

                    transactionsTableModel->addZRecvData(txdata);

                    // Cleanup both responses;
                    delete zaddrTxids;
                    delete txidDetails;
                }
            );
        }
    );
} 

/// This will refresh all the balance data from zclassicd
void RPC::refresh(bool force) {
    if  (conn == nullptr)
        return noConnection();

    getInfoThenRefresh(force);
}

// NOTIFY-SRV pure helper: the two daemon args that wire -walletnotify / -blocknotify to
// THIS exe's `--notify %s` connector. exePath is quoted (may contain spaces); %s sits
// OUTSIDE the quotes so zclassicd substitutes the txid/blockhash. No token rides here.
QStringList RPC::buildNotifyArgs(const QString& exePath) {
    const QString notifyCmd = QStringLiteral("\"%1\" --notify %s").arg(exePath);
    QStringList args;
    args << ("-walletnotify=" + notifyCmd) << ("-blocknotify=" + notifyCmd);
    return args;
}

// NOTIFY-SRV pure helper: pick the refresh poll interval. While syncing we always
// poll fast (quickUpdateSpeed) for a lively banner. When synced: a healthy push channel
// means events are pushed, so we only heartbeat-poll (kHeartbeatPollMs); otherwise keep
// the normal 20s poll (updateSpeed) -- the fallback for foreign/headless/stale-push.
int RPC::desiredPollMs(bool isSyncing, bool pushHealthy) {
    if (isSyncing)
        return Settings::quickUpdateSpeed;
    return pushHealthy ? kHeartbeatPollMs : Settings::updateSpeed;
}

// NOTIFY-SRV: a validated push arrived. Record the epoch (so getInfoThenRefresh sees the
// channel as healthy and heartbeat-polls) and (re)start the single-shot debounce so a
// burst of notifies (a block + its wallet txns) coalesces into one refresh.
void RPC::onNotifyPush() {
    lastNotifyEpoch = QDateTime::currentSecsSinceEpoch();
    if (notifyDebounce)
        notifyDebounce->start(kNotifyDebounceMs);
}


// Deliverable A: fill the "you're helping the network" panel from getpeerinfo.
// 100% read-only (doRPCIgnoreError => an old/foreign daemon, a -28 warmup, or a
// missing method just leaves the last text; never pops a dialog, never writes).
// HONESTY: reachability is derived from the INBOUND peer count, NOT from
// getnetworkinfo networks[].reachable -- that field is just !vfLimited[net]
// (net.cpp), true by default even behind a NAT, so it would falsely tell a NAT'd
// user they are reachable. inbound>0 is hard proof we actually accept incoming.
void RPC::refreshNetworkHelpPanel(int connections) {
    if (conn == nullptr || main == nullptr || main->netHelpStatusLabel == nullptr)
        return;
    // Honestly gate the panel's one-click NAT-PMP toggle: it only does anything
    // with an embedded daemon (the -natpmp flag is a launch arg we pass only when
    // WE start the node, connection.cpp). With a foreign/attached node, disable it
    // and explain -- exactly like the Settings chkNatpmp (mainwindow.cpp). We do
    // this here (not at build time) because setupNetworkHelpPanel() runs before
    // `rpc = new RPC(this)`, so rpc->isEmbedded() is only knowable by this point.
    if (main->netHelpNatpmpChk != nullptr) {
        const bool embedded = isEmbedded();
        main->netHelpNatpmpChk->setEnabled(embedded);
        if (!embedded)
            main->netHelpNatpmpChk->setToolTip(QObject::tr(
                "Automatic port opening is available only when ZclWallet runs its own (embedded) node."));
        // DESYNC FIX: the panel checkbox is set only at construction, so toggling the SAME
        // setting from the Settings dialog left this control stale (and contradicting its own
        // adjacent reach label, which is recomputed live). Re-sync the visual state each poll.
        // QSignalBlocker is required: the toggled lambda pops a QMessageBox, which we must not
        // fire from a programmatic re-sync.
        {
            QSignalBlocker b(main->netHelpNatpmpChk);
            main->netHelpNatpmpChk->setChecked(Settings::getInstance()->getOpenPortNatpmp());
        }
    }
    if (QSettings().value("net/helpPanelHidden", false).toBool())
        return;   // user opted out of the nudge; skip the extra round-trip

    const int port = Settings::getInstance()->isTestnet() ? 18033 : 8033;
    json peerPayload = {
        {"jsonrpc", "1.0"}, {"id", "someid"}, {"method", "getpeerinfo"}
    };
    conn->doRPCIgnoreError(peerPayload, [=](const json& reply) {
        if (main == nullptr || main->netHelpStatusLabel == nullptr
                || main->netHelpReachLabel == nullptr)
            return;
        int inbound = 0;
        if (reply.is_array()) {
            for (const auto& p : reply) {
                if (p.find("inbound") != p.end() && !p["inbound"].is_null()
                        && p["inbound"].get<json::boolean_t>())
                    inbound++;
            }
        }
        main->netHelpStatusLabel->setText(
            QObject::tr("P2P: ON \xc2\xb7 port %1 \xc2\xb7 %2 peers (%3 inbound)")
                .arg(port).arg(connections).arg(inbound));
        if (inbound > 0)
            main->netHelpReachLabel->setText(
                QObject::tr("Inbound connections: reachable \xe2\x80\x94 thank you for serving!"));
        else if (Settings::getInstance()->getOpenPortNatpmp())
            // Toggle is ON but no inbound peer yet. This is an ACTION statement,
            // NOT a reachability claim: a NAT-PMP/PCP mapping can succeed and the
            // user still be unreachable behind double-NAT/CGNAT, and we never
            // verify reachability -- inbound>0 above is the ONLY 'reachable' claim.
            main->netHelpReachLabel->setText(
                QObject::tr("Inbound connections: none yet \xe2\x80\x94 automatic port opening is on; "
                            "waiting for the first inbound peer. (If your router doesn't "
                            "support it, forward port %1 manually.)").arg(port));
        else
            main->netHelpReachLabel->setText(
                QObject::tr("Inbound connections: none yet \xe2\x80\x94 you're still helping by "
                            "relaying. Forward port %1 on your router to accept incoming "
                            "connections.").arg(port));
    });
}

void RPC::getInfoThenRefresh(bool force) {
    if  (conn == nullptr) 
        return noConnection();

    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "getinfo"}
    };

    static bool prevCallSucceeded = false;
    conn->doRPC(payload, [=] (const json& reply) {
        prevCallSucceeded = true;
        // A good poll clears the transient-disconnect debounce (see error cb below).
        getInfoErrCount = 0;
        // F4: a successful getinfo means the node is back up and answering, so a
        // prior crash has been fully recovered. Reset the restart counter; the cap
        // therefore means "3 crashes without a successful recovery in between"
        // rather than 3 crashes over the whole (possibly multi-hour) session.
        ezRestartCount = 0;
        // Testnet?
        if (!reply["testnet"].is_null()) {
            Settings::getInstance()->setTestnet(reply["testnet"].get<json::boolean_t>());
        };

        // Connected, so display checkmark.
        // PR-2: decode the checkmark pixmap exactly once (function-local static)
        // instead of re-reading the GIF resource + rescaling to 16x16 through the
        // image plugin on every poll tick. We still call setPixmap each tick (with
        // the pre-decoded pixmap, which is cheap), and deliberately do NOT add a
        // cross-tick "skip if unchanged" guard: noConnection() also writes
        // main->statusIcon (the red SP_MessageBoxCritical icon) on every transient
        // getinfo error without our knowledge, so such a guard would leave the stale
        // red icon stuck after a reconnect. GUI-thread only: this lambda is
        // delivered on the main thread (QNetworkReply::finished). The desired icon
        // defaults to 'connected'; the no-peers check below may flip it to the
        // warning icon, and we then apply it exactly once.
        static const QPixmap connectedPm = QIcon(":/icons/res/connected.gif").pixmap(16, 16);
        bool showWarningIcon = false;


        static int    lastBlock = 0;
        int curBlock  = reply["blocks"].get<json::number_integer_t>();
        int version = reply["version"].get<json::number_integer_t>();
        Settings::getInstance()->setZClassicdVersion(version);

        if ( force || (curBlock != lastBlock) ) {
            // Something changed, so refresh everything.
            lastBlock = curBlock;

            // See if the turnstile migration has any steps that need to be done.
            turnstile->executeMigrationStep();

            refreshBalances();        
            refreshAddresses(); // This calls refreshZSentTransactions() and refreshReceivedZTrans()
            refreshTransactions();
        }

        int connections = reply["connections"].get<json::number_integer_t>();
        Settings::getInstance()->setPeers(connections);

        if (connections == 0) {
            // If there are no peers connected, then the internet is probably off or
            // something else is wrong.
            showWarningIcon = true;
        }

        // PR-2: apply the status icon exactly once per tick (the original set it here
        // AND above on a zero-peer tick). The warning pixmap is cached in its own
        // function-local static so QStyle::standardIcon + the 16x16 scale runs at
        // most once for the whole process. We always setPixmap with the pre-decoded
        // pixmap (no cross-tick skip) so a prior noConnection() critical icon is
        // reliably cleared on recovery. connectedPm and showWarningIcon are declared
        // earlier in this same lambda body. Main-thread only.
        if (showWarningIcon) {
            static const QPixmap warningPm =
                QApplication::style()->standardIcon(QStyle::SP_MessageBoxWarning).pixmap(16, 16);
            main->statusIcon->setPixmap(warningPm);
        } else {
            main->statusIcon->setPixmap(connectedPm);
        }

        // Get network sol/s
        // ADVANCED-TAB-FIX: gate on `conn` (a live connection), NOT on `ezclassicd`
        // (the owned-QProcess pointer). numconnections + solrate are pure RPC data
        // (getinfo `connections`, already in scope; getnetworksolps) valid for ANY
        // connected node, so a foreign/already-running node must fill them too —
        // otherwise the now-visible Advanced tab sits on its "Loading..." .ui
        // placeholders. We are already inside the live getinfo doRPC reply (reached
        // only after getInfoThenRefresh's early-return-on-conn==nullptr), and the
        // node dying stops the polls, so `if (conn)` is crash-safe; do NOT introduce
        // any unconditional ezclassicd deref here.
        if (conn) {
            // DECOUPLE FIX: the peer count is already known here (from the getinfo reply), so
            // paint it NOW rather than only inside the getnetworksolps success callback. The
            // old code set numconnections only on a successful getnetworksolps (doRPCIgnoreError
            // = silent no-op on error), so on a node/build where getnetworksolps errors the
            // Advanced page's prime stat (Connections) sat on "Loading…" forever even though we
            // had the number. Sol/s stays in the callback (it genuinely needs that RPC).
            ui->numconnections->setText(QString::number(connections));

            json payload = {
                {"jsonrpc", "1.0"},
                {"id", "someid"},
                {"method", "getnetworksolps"}
            };

            conn->doRPCIgnoreError(payload, [=](const json& reply) {
                qint64 solrate = reply.get<json::number_unsigned_t>();
                ui->solrate->setText(QString::number(solrate) % " Sol/s");
            });
        }

        // Deliverable A: refresh the read-only "you're helping the network" panel.
        // READ-ONLY: getnetworkinfo + getpeerinfo only; never mutates node state.
        refreshNetworkHelpPanel(connections);


        // Call to see if the blockchain is syncing. 
        json payload = {
            {"jsonrpc", "1.0"},
            {"id", "someid"},
            {"method", "getblockchaininfo"}
        };

        conn->doRPCIgnoreError(payload, [=](const json& reply) {
            auto progress    = reply["verificationprogress"].get<double>();
            int  blockNumber = reply["blocks"].get<json::number_unsigned_t>();

            // The node's best *header* height is the reliable sync target: headers
            // download ahead of blocks during sync, and at the chain tip blocks ==
            // headers, so blocks/headers reaches exactly 100% and stays there.
            // Why this matters: on ZClassic getblockchaininfo returns NO
            // "estimatedheight", so the old code fell back to verificationprogress,
            // which is a coarse tx-count heuristic that pins near 0.963 even when
            // fully synced -- the classic "stuck at 96%" bug (verified against a live
            // node at tip: blocks==headers, estimatedheight absent, verifyprog=0.9635).
            // Prefer headers; fall back to estimatedheight. Two more edge cases the
            // old "blocks/headers" alone got wrong: headers==0 (the first poll right
            // after the RPC comes up) and blocks>headers (right after a bootstrap-
            // snapshot import) would both make target collapse to estimatedheight (=0
            // on ZClassic) and re-trigger the verificationprogress ~96% pin. So treat
            // blocks>=headers as fully-caught-up/post-snapshot (100%), and when NO
            // target is known at all, report an indeterminate state instead of a
            // bogus percentage.
            int headers = 0;
            if (reply.find("headers") != reply.end() && !reply["headers"].is_null())
                headers = reply["headers"].get<json::number_unsigned_t>();
            int estimatedheight = 0;
            if (reply.find("estimatedheight") != reply.end() && !reply["estimatedheight"].is_null())
                estimatedheight = reply["estimatedheight"].get<json::number_unsigned_t>();

            int  target;
            bool isSyncing;
            if (headers > 0 && blockNumber >= headers) {
                // Blocks reached the best header. Only trust this as fully synced once we
                // have peers to confirm we're at the real network tip: right after a
                // bootstrap-snapshot import (or the first poll after RPC) blocks==headers
                // briefly while still behind the true tip and before peer headers arrive.
                // Once legitimately synced this session, stay synced through brief peer
                // drops so an established wallet doesn't flicker. (verificationprogress is
                // unreliable on ZClassic -- pins ~0.9635 even at the tip -- so it cannot
                // be the gate.)
                if (connections > 0 || ezEverSynced) {
                    target = blockNumber; progress = 1.0; isSyncing = false; ezEverSynced = true;
                } else {
                    target = 0; progress = -1.0; isSyncing = true;   // no peers: can't confirm tip
                }
            } else if (headers > 0) {
                target    = headers;
                progress  = (double)blockNumber / (double)headers;
                if (progress < 0.0) progress = 0.0;
                if (progress > 1.0) progress = 1.0;
                isSyncing = blockNumber < (headers - 2); // within 2 blocks = synced
            } else if (estimatedheight > 0) {
                target    = estimatedheight;
                progress  = (double)blockNumber / (double)estimatedheight;
                if (progress < 0.0) progress = 0.0;
                if (progress > 1.0) progress = 1.0;
                isSyncing = blockNumber < (estimatedheight - 2);
            } else {
                // No usable target (e.g. headers==0 on the first poll): we are
                // syncing but cannot compute a %, so flag it indeterminate. Do NOT
                // fall back to verificationprogress (that's the ~96% pin bug).
                target    = 0;
                progress  = -1.0;
                isSyncing = true;
            }
            bool targetKnown = (target > 0);

            Settings::getInstance()->setSyncing(isSyncing);
            // Stamp the time of this live poll so the send gate can ignore a frozen
            // isSyncing flag (single writer: this poll, beside the flag it stamps).
            Settings::getInstance()->setLastSyncPollEpoch(QDateTime::currentSecsSinceEpoch());
            Settings::getInstance()->setBlockNumber(blockNumber);

            // G6: clear the warmup-wedge cap (heal/attempts.warmupRestart) only on
            // SUSTAINED health, never on the first getinfo (clearHealLedger leaves it
            // alone). Reaching getblockchaininfo here already means the node is well
            // past warmup; require several consecutive such polls (or being fully
            // synced) so an OSCILLATING node — one good poll then re-wedge — never
            // resets the counter and is allowed to escalate to NEEDS_MANUAL. Clear at
            // most once per session to avoid hammering QSettings every poll.
            if (!ezWarmupWedgeCleared) {
                ezHealthyPolls++;
                if (ezHealthyPolls >= 3 || !isSyncing) {
                    QSettings().remove("heal/attempts.warmupRestart");
                    ezWarmupWedgeCleared = true;
                }
            }

            // RUNTIME STUB AUTO-HEAL cooldown reset: the persisted per-install cap
            // (rpc/stubHeal.count) only exists to stop a genuinely peerless host from
            // looping wipe -> rebootstrap -> wipe. The moment we have ANY peers the
            // network is reachable, so a fresh stub later is allowed to auto-heal again
            // -- clear the cap. Guard with a once-per-session latch so we don't hammer
            // QSettings every poll, and only when peers are present.
            if (connections > 0 && !ezStubHealCooldownCleared) {
                QSettings().remove("rpc/stubHeal.count");
                ezStubHealCooldownCleared = true;
            }

            // P0-6: update the prominent sync banner on the Balance/main tab so
            // a non-technical user always sees Syncing %/ETA vs. "Synced — Ready".
            // progress<0 / target==0 signals "indeterminate" to setSyncStatus.
            // C9: a fresh install that's "syncing" but has 0 peers is really just
            // waiting for the network -- say so instead of showing a stuck 0%.
            // 'connections' is captured from the enclosing getinfo lambda.
            // F6: debounce the peerless banner — a single connections==0 sample
            // shouldn't flip it. Require ~3 consecutive peerless polls (~15s at the
            // 5s sync cadence); a single peer resets the counter instantly.
            if (connections == 0) ezNoPeerPolls++; else { ezNoPeerPolls = 0; ezForeignStuckSince.invalidate(); ezForeignStuckShown = false; }   // W1-4: peers back -> let the stuck dialog re-surface if it gets stuck again later
            if (isSyncing && connections == 0 && ezNoPeerPolls >= 3) {
                // RUNTIME STUB AUTO-HEAL: a node that STARTED FINE but loaded a tiny
                // non-genesis "stub" chain (e.g. an aborted P2P sync left ~17MB of
                // blocks/) and then can't find peers would otherwise sit on "waiting
                // for peers" forever — the startup/manual heals never reach this
                // healthy-but-stuck runtime state. Detect it here and route into the
                // SAME redownloadChain() ladder the manual Help -> Repair uses (one
                // destructive path). Fires ONLY when ALL of these conservative
                // conditions hold (see maybeAutoHealStubChain): peerless for a clear
                // margin past the banner, the on-disk blocks/ is unambiguously a stub
                // (< 1 GiB hard floor), and we haven't already auto-healed this run /
                // exhausted the persisted cooldown. Checked BEFORE the banner so the
                // heal's own status takes over; if it doesn't fire, fall through to the
                // existing waiting-for-peers banner (and the always-reachable manual
                // Help -> Repair). It returns true ONLY when it actually launched a heal.
                // SNAPSHOT-DOWNLOAD precedence: keep the getbootstrapinfo cache fresh
                // (async, warmup-EXEMPT) and, if the node is actively downloading the
                // bootstrap snapshot, show REAL progress instead of "waiting for peers"
                // -- and SKIP the stub-heal/wipe. A live snapshot download has 0 normal
                // P2P peers and a small-but-growing blocks/ dir, which would otherwise
                // look exactly like an abandoned stub; healing it here would wipe an
                // in-flight 10 GB download. The cache is ~1 poll stale, which is fine:
                // the heal only fires at ezNoPeerPolls>=12 (~60s), by which point an
                // active download has populated it.
                pollBootstrapSnapshotStatus();
                if (ezBootstrapActive) {
                    main->setSyncStatusBootstrapSnapshot(ezBootstrapPct, ezBootstrapRecv,
                                                         ezBootstrapTotal, ezBootstrapMbps);
                } else
                if (maybeAutoHealStubChain(connections)) {
                    // Heal launched: it stops this node and drives a fresh loader; the
                    // heal owns the UI now. Don't also paint the peerless banner.
                } else
                // EDIT #6 (bob-fix): a FOREIGN node (one we did NOT launch — ezclassicd ==
                // nullptr, i.e. a pre-existing systemd/manual/leftover or external daemon)
                // that has been peerless/stuck for a sustained window (the same ~3min
                // long-stretch threshold the banner uses, so there are NO false positives
                // during the brief startup 0-peer moment or legitimate IBD WITH peers)
                // cannot be healed by this wallet — we only manage a node we start. Surface
                // the actionable, persistent dialog EXACTLY ONCE (guarded) instead of a
                // silent forever-"waiting for peers". An OWNED embedded node (ezclassicd !=
                // nullptr — it self-heals at its own startup and has bootstrap peers, so it
                // is not peerless) NEVER reaches this branch; a foreign node WITH peers /
                // syncing/synced never enters this peerless block at all (case C).
                // W1-4: in addition to the poll-count gate, require a SUSTAINED
                // wall-clock window (~120s) of being peerless before surfacing the
                // actionable dialog, so a fast sync cadence can't false-fire it during
                // a legitimate multi-minute first-run warmup. Start the timer on the
                // first peerless sample seen here; it's invalidated below the moment a
                // peer appears, and reset when the dialog is shown.
                if (ezclassicd == nullptr && !ezForeignStuckSince.isValid())
                    ezForeignStuckSince.start();
                if (ezclassicd == nullptr && ezNoPeerPolls >= 36 && !ezForeignStuckShown &&
                    ezForeignStuckSince.isValid() && ezForeignStuckSince.elapsed() >= 120000) {
                    ezForeignStuckShown = true;
                    // W1-4: do NOT invalidate the timer here. ezForeignStuckShown already
                    // suppresses a repeat while we stay peerless; both it and the timer are
                    // reset the moment peers return (above), so the dialog can correctly
                    // re-fire on a fresh stuck stretch rather than being silenced forever.
                    main->logger->write("Foreign node peerless/stuck past sustained window; "
                                        "surfacing actionable dialog (cannot heal a node we "
                                        "did not start)");
                    main->setSyncStatusWaitingForPeers(true);
                    main->showForeignNodeStuck();
                } else
                // SELF-HEAL SYNCED-ZERO-PEERS: after a LONG peerless stretch (~3min at
                // the sync cadence) escalate the wording to point at the network. This
                // is NOT a wipe/re-bootstrap — the daemon owns peer discovery.
                if (ezNoPeerPolls >= 36)
                    main->setSyncStatusWaitingForPeers(true);
                else
                    main->setSyncStatusWaitingForPeers();
            } else {
                main->setSyncStatus(isSyncing, blockNumber, target, progress);
            }

            // SELF-HEAL runtime validation surfacing (B-side). A newer daemon reports a
            // bootstrap_validation object once past warmup; surface it as a NON-BLOCKING
            // banner. We NEVER force a wipe here — the daemon owns its own re-validation
            // / background reindex. Purely additive; the headers-vs-progress sync logic
            // above is untouched (the "stuck at 96%" invariant is preserved). Absent on
            // an older daemon -> no banner, no behaviour change.
            if (reply.find("bootstrap_validation") != reply.end() &&
                reply["bootstrap_validation"].is_object()) {
                const json& bv = reply["bootstrap_validation"];
                QString vstate;
                if (bv.find("state") != bv.end() && bv["state"].is_string())
                    vstate = QString::fromStdString(bv["state"].get<std::string>());
                if (vstate == "provisional" || vstate == "provisional_pruned") {
                    QString msg = QObject::tr("Verifying the downloaded blockchain — please don't "
                        "spend yet.");
                    if (vstate == "provisional_pruned")
                        msg = msg % " " % QObject::tr("(For a full re-check, re-download the "
                            "blockchain from the Help menu.)");
                    main->setBootstrapValidationBanner(msg);
                } else if (vstate == "failed") {
                    // Daemon self-heals on next restart; just inform, never wipe.
                    main->setBootstrapValidationBanner(QObject::tr("A quick blockchain re-check will "
                        "run automatically the next time you open ZClassic. Your wallet and coins "
                        "are safe."));
                } else {
                    // "validated" / "disabled" / unknown: clear any prior banner.
                    main->setBootstrapValidationBanner(QString());
                }
            }

            // Update zclassicd tab if it exists
            // ADVANCED-TAB-FIX: gate on `conn` (live connection), NOT on `ezclassicd`
            // (owned QProcess). blockheight/heightLabel are derived purely from this
            // getblockchaininfo reply (blockNumber/target/isSyncing) and are valid for
            // any connected node, so a foreign node must fill them too instead of
            // leaving the height field on its "Loading..." placeholder. This block
            // already runs inside the live conn-guarded getblockchaininfo reply, so
            // `if (conn)` is crash-safe; no unconditional ezclassicd deref is added.
            if (conn) {
                if (isSyncing) {
                    QString txt = QString::number(blockNumber);
                    if (targetKnown) {
                        txt = txt % " / ~" % QString::number(target);
                        // Use downloaded-blocks vs the header target for progress.
                        progress = (double)blockNumber / (double)target;
                        txt = txt %  " ( " % QString::number(progress * 100, 'f', 2) % "% )";
                        ui->heightLabel->setText(QObject::tr("Downloading blocks"));
                    } else {
                        // No target yet: show the height without a bogus percent.
                        ui->heightLabel->setText(QObject::tr("Starting…"));
                    }
                    ui->blockheight->setText(txt);
                } else {
                    ui->blockheight->setText(QString::number(blockNumber));
                    ui->heightLabel->setText(QObject::tr("Block height"));
                }
            }

            // Update the status bar. Only show a percent when the target is known;
            // a peerless/just-started sync has no meaningful % yet.
            // P2-4: at rest, show a thousands-separated height ("Connected (1,700,000)")
            // for readability; the syncing branch keeps its raw block/percent format.
            QString heightStr = isSyncing ? QString::number(blockNumber)
                                          : Settings::getHeightString(blockNumber);
            QString statusText = QString() %
                (isSyncing ? QObject::tr("Syncing") : QObject::tr("Connected")) %
                " (" %
                (Settings::getInstance()->isTestnet() ? QObject::tr("testnet:") : "") %
                heightStr %
                (isSyncing && targetKnown ? ("/" % QString::number(progress*100, 'f', 2) % "%") : QString()) %
                ")";
            if (isSyncing && !targetKnown)
                statusText = QObject::tr("Starting (block %1)").arg(blockNumber);
            main->statusLabel->setText(statusText);

            auto zclPrice = Settings::getUSDFormat(1);
            QString tooltip;
            if (connections > 0) {
                tooltip = QObject::tr("Connected to zclassicd");
            }
            else {
                tooltip = QObject::tr("zclassicd has no peer connections");
            }
            // FORMAT FIX: was "…zclassicd(v 2001225)" — no space before "(", and a raw
            // CLIENT_VERSION integer. Add the space and decode the standard encoding
            // (1000000*major + 10000*minor + 100*rev + build) to a dotted version.
            {
                int v = Settings::getInstance()->getZClassicdVersion();
                QString vStr = (v > 0)
                    ? QString("%1.%2.%3.%4").arg(v / 1000000).arg((v / 10000) % 100)
                                            .arg((v / 100) % 100).arg(v % 100)
                    : QString::number(v);
                tooltip = tooltip % " (v" % vStr % ")";
            }

            if (!zclPrice.isEmpty()) {
                tooltip = "1 ZCL = " % zclPrice % "\n" % tooltip;
            }
            main->statusLabel->setToolTip(tooltip);
            main->statusIcon->setToolTip(tooltip);

            // C3: poll faster while actively syncing so the banner/%/ETA stays
            // lively, and back off to the normal cadence once synced. QTimer::start()
            // restarts with the new interval; only call it when the interval actually
            // changes so we don't reset the period on every tick.
            //
            // NOTIFY-SRV: when a HEALTHY push channel is delivering events (owned daemon
            // only -- the socket is listening AND a validated notify arrived within the
            // health window), back the poll WAY off to a heartbeat: pushes drive the
            // updates, the poll is just a sanity net. If push is stale (channel went
            // quiet, PERF-5) or absent (foreign/headless -- notifyServer null,
            // PERF-24), keep the existing 20s/5s poll unchanged.
            const qint64 now = QDateTime::currentSecsSinceEpoch();
            const bool pushHealthy = notifyServer && notifyServer->isListening()
                                     && lastNotifyEpoch != 0
                                     && (now - lastNotifyEpoch) < kPushHealthyWindowSecs;
            int desired = desiredPollMs(isSyncing, pushHealthy);
            if (timer && timer->interval() != desired)
                timer->start(desired);
        });

    }, [=](QNetworkReply* reply, const json&) {
        // zclassicd has probably disappeared.
        // transient-disconnect-zeroes-hero: doRPC has no retry, so a SINGLE dropped
        // getinfo reply (a momentary RPC stall, not a real teardown) used to blank
        // the balance labels and reset the hero to grey "0 ZCL" with Send demoted —
        // a funded wallet flashed empty on one hiccup. Debounce like the peerless
        // banner (ezNoPeerPolls>=3): the first few consecutive errors do a SOFT
        // disconnect that PRESERVES the last balances (hero goes WARMING/refreshing,
        // no Send/Receive swap from a blanked label); only a sustained outage
        // (>=3 consecutive failures, ~the same dwell as the banner) does the full
        // teardown that wipes stale data.
        getInfoErrCount++;
        if (getInfoErrCount < 3)
            this->noConnection(/*preserveBalances=*/true);
        else
            this->noConnection();

        // Prevent multiple dialog boxes, because these are called async. Also
        // suppress this generic error while the crash-recovery dialog is up (or the
        // node is being deliberately shut down): handleEZClassicdCrash already owns
        // the user interaction, and a stacked "Connection Error" box on top of it is
        // confusing.
        static bool shown = false;
        if (!shown && prevCallSucceeded && !ezCrashDialogOpen && !ezExpectedShutdown) { // show error only first time
            shown = true;
            QMessageBox::critical(main, QObject::tr("Connection Error"), QObject::tr("There was an error connecting to zclassicd. The error was") + ": \n\n"
                + reply->errorString(), QMessageBox::StandardButton::Ok);
            shown = false;
        }

        prevCallSucceeded = false;
    });
}

void RPC::refreshAddresses() {
    if  (conn == nullptr) 
        return noConnection();

    delete zaddresses;
    zaddresses = new QList<QString>();

    getZAddresses([=] (json reply) {
        for (auto& it : reply.get<json::array_t>()) {
            auto addr = QString::fromStdString(it.get<json::string_t>());
            zaddresses->push_back(addr);
        }

        // PRIV-28 eager provisioning: now that the z-address list is known, make sure
        // at least one Sapling z-address exists so the send/shield path never has to
        // block on key generation. Idempotent + one-shot (no-op once a Sapling addr
        // exists or after the first attempt this run).
        main->ensureSaplingProvisioned();

        // Refresh the sent and received txs from all these z-addresses
        refreshSentZTrans();
        refreshReceivedZTrans(*zaddresses);
    });

    delete taddresses;
    taddresses = new QList<QString>();
    getTAddresses([=] (json reply) {
        for (auto& it : reply.get<json::array_t>()) {   
            auto addr = QString::fromStdString(it.get<json::string_t>());
            if (Settings::isTAddress(addr))
                taddresses->push_back(addr);
        }

        // If there are no t Addresses, create one. This callback runs on every
        // block-height change (and again from addNewZaddr), so without the
        // isEmpty() guard we minted a fresh transparent key roughly every block --
        // silently bloating wallet.dat and the user's public on-chain footprint.
        // Guarded to fire once, exactly as the comment always intended.
        if (taddresses->isEmpty()) {
            newTaddr([=] (json reply) {
                // What if taddress gets deleted before this executes?
                taddresses->append(QString::fromStdString(reply.get<json::string_t>()));
            });
        }
    });
}

// Function to create the data model and update the views, used below.
void RPC::updateUI(bool anyUnconfirmed) {
    ui->unconfirmedWarning->setVisible(anyUnconfirmed);

    // Update balances model data, which will update the table too
#ifdef ZCL_WIDGET_TEST
    // PERF harness (perf16_modelJank): time ONLY the balances-model rebuild — the
    // pure-CPU hot path the perf slot asserts on. Zero cost when ZCL_WIDGET_TEST is
    // undefined (the entire block compiles out).
    QElapsedTimer _perfTimer;
    _perfTimer.start();
    balancesTableModel->setNewData(allBalances, utxos);
    balanceModelSamplesNs.push_back(_perfTimer.nsecsElapsed());
#else
    balancesTableModel->setNewData(allBalances, utxos);
#endif

    // Update from address
    main->updateFromCombo();
};

// Function to process reply of the listunspent and z_listunspent API calls, used below.
bool RPC::processUnspent(const json& reply, QMap<QString, double>* balancesMap, QList<UnspentOutput>* newUtxos) {
    bool anyUnconfirmed = false;
    for (auto& it : reply.get<json::array_t>()) {
        QString qsAddr = QString::fromStdString(it["address"]);
        auto confirmations = it["confirmations"].get<json::number_unsigned_t>();
        if (confirmations == 0) {
            anyUnconfirmed = true;
        }

        // "generated" marks a coinbase UTXO (transparent listunspent only; z_listunspent
        // omits it). The auto-shield change basis must exclude coinbase, since z_sendmany
        // refuses to spend it to a transparent output or alongside change. (find()/end()
        // is used rather than contains() -- the bundled nlohmann::json 3.3 predates it.)
        bool coinbase = it.find("generated") != it.end() && it["generated"].get<json::boolean_t>();

        newUtxos->push_back(
            UnspentOutput{ qsAddr, QString::fromStdString(it["txid"]),
                            Settings::getDecimalString(it["amount"].get<json::number_float_t>()),
                            (int)confirmations, it["spendable"].get<json::boolean_t>(), coinbase });

        (*balancesMap)[qsAddr] = (*balancesMap)[qsAddr] + it["amount"].get<json::number_float_t>();
    }
    return anyUnconfirmed;
};

// SAFE-RACE: keep the shielded-note rows from `oldUtxos` and replace the transparent rows
// with `freshT`. A row is transparent iff Settings::isTAddress(address). Frees both inputs
// and returns a new owned list. A transparent-only re-poll thus never drops the z-notes.
QList<UnspentOutput>* RPC::mergeTransparentUnspent(QList<UnspentOutput>* oldUtxos,
                                                   QList<UnspentOutput>* freshT) {
    auto* merged = new QList<UnspentOutput>();
    if (oldUtxos) {
        for (const UnspentOutput& u : *oldUtxos)
            if (!Settings::isTAddress(u.address))     // keep shielded notes as-is
                merged->append(u);
        delete oldUtxos;
    }
    if (freshT) {
        merged->append(*freshT);
        delete freshT;
    }
    return merged;
}

// SAFE-RACE: re-poll ONLY the transparent UTXOs and splice them into the cached `utxos`,
// preserving the shielded-note rows. Invokes cb(true) once fresh data has landed; returns
// false (and cb(false)) when it cannot fire so the caller fails closed. See
// MainWindow::verifyAutoShieldUnchanged.
bool RPC::repollTransparentUnspent(const std::function<void(bool)>& cb) {
#ifdef ZCL_WIDGET_TEST
    // TEST-ONLY SEAM: no daemon. If a fresh transparent set was injected, splice it in
    // (preserving z rows) and fire the callback SYNCHRONOUSLY -- no pump, no connection.
    if (testRepollUTXOs) {
        utxos = mergeTransparentUnspent(utxos, testRepollUTXOs);   // takes ownership / frees inputs
        testRepollUTXOs = nullptr;
        cb(true);
        return true;
    }
    cb(false);
    return false;     // no seam installed -> caller fails closed
#else
    if (!conn) { cb(false); return false; }            // never null-deref getTransparentUnspent
    // MERGE RECONCILE: local getTransparentUnspent is 2-arg (cb, err). Pass an err lambda
    // that fails closed (cb(false)) instead of hanging if the unspent query errors.
    getTransparentUnspent([this, cb](json reply) {
        auto* freshT       = new QList<UnspentOutput>();
        auto* throwawayBals = new QMap<QString, double>();
        processUnspent(reply, throwawayBals, freshT);  // reuse the exact parser (sets coinbase)
        delete throwawayBals;
        utxos = mergeTransparentUnspent(utxos, freshT);
        cb(true);
    }, [cb]() { cb(false); });
    return true;
#endif
}

void RPC::refreshBalances() {
    if  (conn == nullptr)
        return noConnection();

    // 1. Get the Balances — the hero numbers (transparent / shielded / total).
    //
    // SINGLE WRITER, two interchangeable sources. getwalletsummary {0} and
    // z_gettotalbalance {0} return the SAME three FormatMoney fields and (proven) the
    // SAME satoshi totals, so we pick exactly ONE per cycle and feed it through a
    // shared paint routine — never both concurrently. That removes any last-writer
    // race over the hero labels/cache.
    //   * New daemon (summaryCapable): getwalletsummary is the SOLE hero source. It
    //     reads the daemon's cached note values in one round-trip (no per-note
    //     re-decrypt), so the hero is fast in ALL cases, not just the first paint. We
    //     SKIP the slow z_gettotalbalance entirely on this path.
    //   * Old daemon: the FIRST summary call returns JSON-RPC -32601 ("Method not
    //     found"); we latch summaryCapable=false (never call it again this session)
    //     and fall back to z_gettotalbalance — identical to the legacy behavior.
    //   * Any transient summary error (warmup -28, network) does NOT latch; we just
    //     fall back to z_gettotalbalance for THIS cycle so the hero still updates, and
    //     retry the summary on the next poll.
    // The per-address listunspent join (step 2 below) ALWAYS runs and remains the sole
    // owner of the per-address balances model / UTXO set; it does not touch the hero.
    auto paintHero = std::function<void(json)>([=] (json reply) {
        // Amounts are FormatMoney decimal STRINGS from either source.
        auto balT      = QString::fromStdString(reply["transparent"]).toDouble();
        auto balZ      = QString::fromStdString(reply["private"]).toDouble();
        auto balTotal  = QString::fromStdString(reply["total"]).toDouble();

        ui->balSheilded   ->setText(Settings::getZCLDisplayFormat(balZ));
        ui->balTransparent->setText(Settings::getZCLDisplayFormat(balT));
        ui->balTotal      ->setText(Settings::getZCLDisplayFormat(balTotal));

        // [gui-startup] The hero balances just hit the labels — the wallet is now
        // usable. Record the milestone and flush the ONE summary line, exactly once,
        // matching the daemon's [startup] log. first-write-wins + the summaryLogged
        // one-shot guarantee no later refresh re-logs it.
        GuiStartup::markFirstBalance();
        if (!GuiStartup::marks().summaryLogged && main && main->logger) {
            GuiStartup::marks().summaryLogged = true;
            main->logger->write(GuiStartup::summaryLine());
        }

        ui->balSheilded   ->setToolTip(Settings::getUSDFormat(balZ));
        ui->balTransparent->setToolTip(Settings::getUSDFormat(balT));
        ui->balTotal      ->setToolTip(Settings::getUSDFormat(balTotal));

        // Phase-3b: refresh the Home dashboard hero + amber "shield public funds"
        // fix-it card from these same freshly-set balances. We pass the transparent
        // amount we already have (balT) rather than re-querying; the hero reads the
        // labels just set above. The card shows only when balT > 0, hides at 0.
        // updateHomeFixIt() emits heroBalancesPainted() at its end.
        main->updateHomeFixIt(balT);

        // Remember the last-known balances so the next launch can paint them
        // instantly while the node warms up (see MainWindow::restoreSavedStates).
        // Convenience cache only, stored outside wallet.dat; gated on its own
        // default-ON preference (independent of saved shielded-tx history).
        if (Settings::getInstance()->getShowCachedBalance()) {
            QSettings cs;
            cs.setValue("cache/balTransparent", balT);
            cs.setValue("cache/balShielded",    balZ);
            cs.setValue("cache/balTotal",       balTotal);
            cs.setValue("cache/lastSyncEpoch",  QDateTime::currentSecsSinceEpoch());
        }

        // FUND-SAFETY: this wallet has no seed phrase, so an un-backed-up wallet.dat
        // is permanent, unrecoverable loss. Once we are fully synced AND the user
        // actually holds a balance, surface the backup reminder -- exactly ONCE per
        // run. W1-2: this now shows a NON-blocking amber Home card (showBackupNag())
        // instead of the modal promptWalletBackup() box, so it never interrupts the
        // user. It is permanently silenced after a successful backup
        // (options/walletbackedup), and the session one-shot here guarantees we never
        // re-fire on subsequent balance polls (it fires on the synced edge, not every
        // refresh). promptWalletBackup() stays reachable from the Help menu.
        static bool backupPromptShownThisSession = false;
        if (!backupPromptShownThisSession &&
            !Settings::getInstance()->isSyncing() &&
            balTotal > 0) {
            backupPromptShownThisSession = true;
            main->showBackupNag();
        }
    });

    if (summaryCapable) {
        getWalletSummary([=] (json reply) {
            // Well-formed summary => it is the sole hero source this cycle. Require all
            // three fields to be present AND strings (a forked/buggy daemon returning a
            // numeric or partial object falls back rather than throwing or painting
            // garbage).
            if (reply.is_null() ||
                reply.find("transparent") == reply.end() || !reply["transparent"].is_string() ||
                reply.find("private")     == reply.end() || !reply["private"].is_string()     ||
                reply.find("total")       == reply.end() || !reply["total"].is_string()) {
                getBalance(paintHero);   // defensive: authoritative slow path this cycle
                return;
            }
            paintHero(reply);
        },
        [=] (const json& parsed) {
            // -32601 "Method not found" => OLD daemon: latch the capability off so we
            // never call getwalletsummary again this session and log ONE diagnostic.
            // Any OTHER error (warmup -28, transient network) does NOT latch.
            if (!parsed.is_discarded() &&
                parsed.find("error") != parsed.end() && parsed["error"].is_object() &&
                parsed["error"].find("code") != parsed["error"].end() &&
                parsed["error"]["code"].is_number_integer() &&
                parsed["error"]["code"].get<int>() == -32601) {
                summaryCapable = false;
                main->logger->write("Daemon lacks getwalletsummary (-32601); "
                                    "using z_gettotalbalance for balances this session");
            }
            // Either way, paint the hero from the authoritative slow path THIS cycle so
            // a summary failure never leaves the hero stale.
            getBalance(paintHero);
        });
    } else {
        getBalance(paintHero);
    }

    // 2. Get the UTXOs
    // W1-5: fire the transparent and z unspent APIs CONCURRENTLY (they were nested/
    // serialized) and join once BOTH have returned. To avoid any shared-write race,
    // each completion writes into its OWN temporary (t* / z*); we merge them into the
    // final balances/utxos ONLY in the join, after both have landed. T-addr and z-addr
    // keys are disjoint, so the merged result is identical to the old serial fill —
    // semantics are preserved exactly, only the two round-trips now overlap.
    struct UnspentJoin {
        int pending = 2;
        bool failed = false;
        QList<UnspentOutput> tUtxos;     QMap<QString, double> tBalances;     bool tUnconfirmed = false;
        QList<UnspentOutput> zUtxos;     QMap<QString, double> zBalances;     bool zUnconfirmed = false;
    };
    auto st = std::make_shared<UnspentJoin>();

    auto finish = [=]() {
        if (--st->pending != 0)
            return;   // wait for the other stream

        // W1-5: if either stream errored, do NOT publish a partial (wrong, too-low)
        // balance — keep the last-known values and let the next refresh retry. The join
        // still settles here, so it never hangs.
        if (st->failed)
            return;

        // Both streams are in. Merge the two temporaries into the fresh containers
        // that will replace the live ones.
        auto newUtxos    = new QList<UnspentOutput>(st->tUtxos);
        auto newBalances = new QMap<QString, double>(st->tBalances);
        *newUtxos += st->zUtxos;
        for (auto it = st->zBalances.constBegin(); it != st->zBalances.constEnd(); ++it)
            (*newBalances)[it.key()] = (*newBalances)[it.key()] + it.value();

        // Swap out the balances and UTXOs
        delete allBalances;
        delete utxos;

        allBalances = newBalances;
        utxos       = newUtxos;

        updateUI(st->tUnconfirmed || st->zUnconfirmed);

        main->balancesReady();
    };

    // W1-5 blocker fix: on RPC error, mark the join failed and STILL settle the latch
    // so it can never hang. doRPC fires exactly one of {cb, err} per stream, so pending
    // still reaches 0 and finish() runs exactly once.
    auto fail = [=]() {
        st->failed = true;
        finish();
    };

    getTransparentUnspent([=] (json reply) {
        st->tUnconfirmed = processUnspent(reply, &st->tBalances, &st->tUtxos);
        finish();
    }, fail);

    getZUnspent([=] (json reply) {
        st->zUnconfirmed = processUnspent(reply, &st->zBalances, &st->zUtxos);
        finish();
    }, fail);
}

void RPC::refreshTransactions() {    
    if  (conn == nullptr) 
        return noConnection();

    getTransactions([=] (json reply) {
        QList<TransactionItem> txdata;

        for (auto& it : reply.get<json::array_t>()) {  
            double fee = 0;
            if (!it["fee"].is_null()) {
                fee = it["fee"].get<json::number_float_t>();
            }

            QString address = (it["address"].is_null() ? "" : QString::fromStdString(it["address"]));

            TransactionItem tx{
                QString::fromStdString(it["category"]),
                (qint64)it["time"].get<json::number_unsigned_t>(),
                address,
                QString::fromStdString(it["txid"]),
                it["amount"].get<json::number_float_t>() + fee,
                (unsigned long)it["confirmations"].get<json::number_unsigned_t>(),
                "", "" };

            txdata.push_back(tx);
            if (!address.isEmpty())
                usedAddresses->insert(address, true);
        }

        // Update model data, which updates the table view
        transactionsTableModel->addTData(txdata);        
    });
}

// Read sent Z transactions from the file.
void RPC::refreshSentZTrans() {
    if  (conn == nullptr) 
        return noConnection();

    // W1-6 reorg safety: the deep-confirmed entries below stop being re-queried, so a
    // reorg would otherwise freeze their now-wrong counts. If the chain height moved
    // BACKWARD since the cache was last filled, a reorg happened — drop the whole cache
    // so every tx is re-queried fresh (reorgs are rare, so a full re-query is fine).
    int curHeight = Settings::getInstance()->getBlockNumber();
    if (curHeight < sentZConfCacheHeight)
        sentZConfCache.clear();
    sentZConfCacheHeight = curHeight;

    auto sentZTxs = SentTxStore::readSentTxFile();

    // If there are no sent z txs, then empty the table.
    // This happens when you clear history.
    if (sentZTxs.isEmpty()) {
        sentZConfCache.clear();   // history cleared — drop orphaned cache entries
        transactionsTableModel->addZSentData(sentZTxs);
        return;
    }

    // W1-6: throttle the per-block gettransaction storm. A sent z-tx that is already
    // DEEPLY confirmed (>= kDeepConfirmations) will never meaningfully change, so we
    // stop re-querying it: its last (>= kDeepConfirmations) count is served straight
    // from sentZConfCache. Only the SHALLOW/unconfirmed subset (and any txid we've
    // never seen) is re-batched. This keeps the confirmation display correct —
    // deeply-confirmed rows stay shown with their cached deep count — while collapsing
    // the batch on an established wallet to just the few young transactions.
    QList<QString> shallowTxids;
    for (auto& sentTx : sentZTxs) {
        auto cached = sentZConfCache.find(sentTx.txid);
        if (cached != sentZConfCache.end() && cached.value() >= kDeepConfirmations)
            continue;   // deeply confirmed -> served from cache, no re-query
        shallowTxids.push_back(sentTx.txid);
    }

    // Apply any cached counts (deep or shallow) so the rendered list reflects what we
    // already know; the batch below refreshes only the shallow subset on top of this.
    auto applyCache = [this](QList<TransactionItem>& list) {
        for (TransactionItem& sentTx : list) {
            auto cached = sentZConfCache.find(sentTx.txid);
            if (cached != sentZConfCache.end())
                sentTx.confirmations = (unsigned long)cached.value();
        }
    };

    // Everything is deeply confirmed -> nothing to query. Render from cache and return.
    if (shallowTxids.isEmpty()) {
        auto newSentZTxs = sentZTxs;
        applyCache(newSentZTxs);
        transactionsTableModel->addZSentData(newSentZTxs);
        return;
    }

    // Look up only the shallow/unconfirmed txids to refresh their confirmation count.
    conn->doBatchRPC<QString>(shallowTxids,
        [=] (QString txid) {
            json payload = {
                {"jsonrpc", "1.0"},
                {"id", "senttxid"},
                {"method", "gettransaction"},
                {"params", {txid.toStdString()}}
            };

            return payload;
        },
        [=] (QMap<QString, json>* txidList) {
            auto newSentZTxs = sentZTxs;
            // Seed every row from the cache first (so deeply-confirmed rows we did NOT
            // re-query keep their last known count), then overlay the fresh shallow
            // results and update the cache.
            applyCache(newSentZTxs);
            for (TransactionItem& sentTx: newSentZTxs) {
                auto j = txidList->value(sentTx.txid);
                if (j.is_null())
                    continue;
                auto error = j["confirmations"].is_null();
                if (!error) {
                    auto confs = j["confirmations"].get<json::number_unsigned_t>();
                    sentTx.confirmations = confs;
                    sentZConfCache[sentTx.txid] = (long)confs;   // remember; deep ones stop re-querying
                }
            }

            transactionsTableModel->addZSentData(newSentZTxs);
            delete txidList;
        }
     );
}

void RPC::addNewTxToWatch(const QString& newOpid, WatchedTx wtx) {    
    watchingOps.insert(newOpid, wtx);

    watchTxStatus();
}


// Execute a transaction!
void RPC::executeTransaction(Tx tx, 
        const std::function<void(QString opid)> submitted,
        const std::function<void(QString opid, QString txid)> computed,
        const std::function<void(QString opid, QString errStr)> error) {
    // First, create the json params
    json params = json::array();
    fillTxJsonParams(params, tx);
    std::cout << std::setw(2) << params << std::endl;

    sendZTransaction(params, [=](const json& reply) {
        QString opid = QString::fromStdString(reply.get<json::string_t>());

        // And then start monitoring the transaction
        addNewTxToWatch( opid, WatchedTx { opid, tx, computed, error} );
        submitted(opid);
    },
    [=](QString errStr) {
        error("", errStr);
    });
}


void RPC::watchTxStatus() {
    if  (conn == nullptr) 
        return noConnection();

    // Make an RPC to load pending operation statues
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "z_getoperationstatus"},
    };

    conn->doRPCIgnoreError(payload, [=] (const json& reply) {
        // There's an array for each item in the status
        for (auto& it : reply.get<json::array_t>()) {  
            // If we were watching this Tx and its status became "success", then we'll show a status bar alert
            QString id = QString::fromStdString(it["id"]);
            if (watchingOps.contains(id)) {
                // And if it ended up successful
                QString status = QString::fromStdString(it["status"]);
                main->loadingLabel->setVisible(false);

                if (status == "success") {
                    auto txid = QString::fromStdString(it["result"]["txid"]);
                    
                    SentTxStore::addToSentTx(watchingOps[id].tx, txid);

                    auto wtx = watchingOps[id];
                    watchingOps.remove(id);
                    wtx.completed(id, txid);

                    // Refresh balances to show unconfirmed balances                    
                    refresh(true);
                } else if (status == "failed") {
                    // If it failed, then we'll actually show a warning. 
                    auto errorMsg = QString::fromStdString(it["error"]["message"]);

                    auto wtx = watchingOps[id];
                    watchingOps.remove(id);
                    wtx.error(id, errorMsg);
                } 
            }

            if (watchingOps.isEmpty()) {
                txTimer->start(Settings::updateSpeed);
            } else {
                txTimer->start(Settings::quickUpdateSpeed);
            }
        }

        // If there is some op that we are watching, then show the loading bar, otherwise hide it
        if (watchingOps.empty()) {
            main->loadingLabel->setVisible(false);
        } else {
            main->loadingLabel->setVisible(true);
            main->loadingLabel->setToolTip(QString::number(watchingOps.size()) + QObject::tr(" tx computing. This can take several minutes."));
        }
    });
}

void RPC::checkForUpdate(bool silent) {
    if  (conn == nullptr)
        return noConnection();

    // W1-3: the very FIRST automatic (silent) update check after launch must not pop
    // the "Update Available" modal on top of the just-opened window — it stalls the
    // perceived startup. Suppress the modal for that first auto check ONLY; we do NOT
    // mark the version as hidden, so a LATER automatic re-check (the periodic one)
    // still surfaces it, and a user-initiated (non-silent) Help->Check always shows it.
    bool suppressFirstModal = false;
    if (silent && !firstUpdateCheckDone) {
        firstUpdateCheckDone = true;
        suppressFirstModal   = true;
    }

    QUrl cmcURL("https://api.github.com/repos/ZclassicCommunity/zcl-qt-wallet/releases");

    QNetworkRequest req;
    req.setUrl(cmcURL);
    
    QNetworkReply *reply = conn->restclient->get(req);

    QObject::connect(reply, &QNetworkReply::finished, [=] {
        reply->deleteLater();

        try {
            if (reply->error() == QNetworkReply::NoError) {

                auto releases = QJsonDocument::fromJson(reply->readAll()).array();
                QVersionNumber maxVersion(0, 0, 0);

                for (QJsonValue rel : releases) {
                    if (!rel.toObject().contains("tag_name"))
                        continue;

                    QString tag = rel.toObject()["tag_name"].toString();
                    if (tag.startsWith("v"))
                        tag = tag.right(tag.length() - 1);

                    if (!tag.isEmpty()) {
                        auto v = QVersionNumber::fromString(tag);
                        if (v > maxVersion)
                            maxVersion = v;
                    }
                }

                auto currentVersion = QVersionNumber::fromString(APP_VERSION);
                
                // Get the max version that the user has hidden updates for
                QSettings s;
                auto maxHiddenVersion = QVersionNumber::fromString(s.value("update/lastversion", "0.0.0").toString());

                qDebug() << "Version check: Current " << currentVersion << ", Available " << maxVersion;

                if (maxVersion > currentVersion && !suppressFirstModal && (!silent || maxVersion > maxHiddenVersion)) {
                    auto ans = QMessageBox::information(main, QObject::tr("Update Available"), 
                        QObject::tr("A new release v%1 is available! You have v%2.\n\nWould you like to visit the releases page?")
                            .arg(maxVersion.toString())
                            .arg(currentVersion.toString()),
                        QMessageBox::Yes, QMessageBox::Cancel);
                    if (ans == QMessageBox::Yes) {
                        QDesktopServices::openUrl(QUrl("https://github.com/ZclassicCommunity/zcl-qt-wallet/releases"));
                    } else {
                        // If the user selects cancel, don't bother them again for this version
                        s.setValue("update/lastversion", maxVersion.toString());
                    }
                } else {
                    if (!silent) {
                        QMessageBox::information(main, QObject::tr("No updates available"), 
                            QObject::tr("You already have the latest release v%1")
                                .arg(currentVersion.toString()));
                    }
                } 
            } else {
                // A user-initiated check must never silently do nothing: report the
                // failure and offer the releases page so the Help menu always responds.
                if (!silent) {
                    auto ans = QMessageBox::warning(main, QObject::tr("Couldn't check for updates"),
                        QObject::tr("Couldn't reach the update server right now.\n\n"
                                    "Open the releases page in your browser?"),
                        QMessageBox::Yes, QMessageBox::Cancel);
                    if (ans == QMessageBox::Yes) {
                        QDesktopServices::openUrl(QUrl("https://github.com/ZclassicCommunity/zcl-qt-wallet/releases"));
                    }
                }
            }
        }
        catch (...) {
            // If anything at all goes wrong, just set the price to 0 and move on.
            qDebug() << QString("Caught something nasty");
        }       
    });
}

// Get the ZCL->USD price from coinmarketcap using their API
void RPC::refreshZCLPrice() {
    if  (conn == nullptr) 
        return noConnection();

    QUrl cmcURL("https://api.coinmarketcap.com/v1/ticker/");

    QNetworkRequest req;
    req.setUrl(cmcURL);
    
    QNetworkReply *reply = conn->restclient->get(req);

    QObject::connect(reply, &QNetworkReply::finished, [=] {
        reply->deleteLater();

        try {
            if (reply->error() != QNetworkReply::NoError) {
                // Price lookup is best-effort and non-critical. The legacy public price
                // endpoint frequently rejects unauthenticated requests (HTTP 403
                // Forbidden); that is EXPECTED and must NOT spam the user's terminal with
                // a scary "Error transferring ... server replied: Forbidden" line that
                // makes a perfectly healthy wallet look broken. Silently fall back to a
                // 0 price (the UI simply omits the fiat value).
                Settings::getInstance()->setZCLPrice(0);
                return;
            }

            auto all = reply->readAll();
            
            auto parsed = json::parse(all, nullptr, false);
            if (parsed.is_discarded()) {
                Settings::getInstance()->setZCLPrice(0);
                return;
            }

            for (const json& item : parsed.get<json::array_t>()) {
                if (item["symbol"].get<json::string_t>() == "ZCL") {
                    QString price = QString::fromStdString(item["price_usd"].get<json::string_t>());
                    qDebug() << "ZCL Price=" << price;
                    Settings::getInstance()->setZCLPrice(price.toDouble());

                    return;
                }
            }
        } catch (...) {
            // If anything at all goes wrong, just set the price to 0 and move on.
            qDebug() << QString("Caught something nasty");
        }

        // If nothing, then set the price to 0;
        Settings::getInstance()->setZCLPrice(0);
    });
}

// Async getbootstrapinfo poll (warmup-EXEMPT RPC) -> refresh the ezBootstrap* cache.
// Fired from the peerless path (connections==0) so an in-progress bootstrap-snapshot
// download is surfaced as real progress instead of "waiting for peers", and so the
// stub auto-heal never mistakes a live download for an abandoned stub and wipes it.
// RPC outlives every reply (it is main->rpc for the app lifetime), so capturing `this`
// here is safe -- no alive-token needed (unlike ConnectionLoader's pre-connect probe).
void RPC::pollBootstrapSnapshotStatus() {
    if (conn == nullptr) return;
    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "getbootstrapinfo"}
    };
    conn->doRPC(payload,
        [=] (json bi) {
            bool   active = false;
            int    pct    = 0;
            qint64 recv   = 0, total = 0;
            double mbps   = 0.0;
            if (bi.is_object() &&
                bi.find("phase") != bi.end() && bi["phase"].is_string() &&
                bi["phase"].get<std::string>() == "active") {
                active = true;
                // percent / bytes_* / mbps are present ONLY when phase=="active".
                if (bi.find("percent") != bi.end() && bi["percent"].is_number())
                    pct = bi["percent"].get<int>();
                if (bi.find("bytes_received") != bi.end() && bi["bytes_received"].is_number())
                    recv = (qint64) bi["bytes_received"].get<double>();
                if (bi.find("bytes_total") != bi.end() && bi["bytes_total"].is_number())
                    total = (qint64) bi["bytes_total"].get<double>();
                if (bi.find("mbps") != bi.end() && bi["mbps"].is_number())
                    mbps = bi["mbps"].get<double>();
            }
            ezBootstrapActive = active;
            ezBootstrapPct    = pct;
            ezBootstrapRecv   = recv;
            ezBootstrapTotal  = total;
            ezBootstrapMbps   = mbps;
        },
        [=] (auto, auto) {
            // getbootstrapinfo absent (older daemon) or a transient error -> assume the
            // node is NOT actively snapshotting; the existing peers/heal logic owns it.
            ezBootstrapActive = false;
        });
}

void RPC::onAboutToQuit() {
    // Runs on every quit route (see header). The macOS app-menu Quit / Cmd-Q skips
    // MainWindow::closeEvent()->shutdownZClassicd(), so ezExpectedShutdown was never
    // set on that path and the periodic refresh poller (RPC::refresh) could fire its
    // generic "There was an error connecting to zclassicd" box as the node exits.
    // Set the flag and silence the pollers here so no spurious dialog appears.
    ezExpectedShutdown = true;
    if (timer)          timer->stop();
    if (txTimer)        txTimer->stop();
    if (priceTimer)     priceTimer->stop();
    if (notifyDebounce) notifyDebounce->stop();
}

void RPC::shutdownZClassicd() {
    // Re-entrancy guard: the wait below spins a nested event loop while the main
    // window is still live, so a second Quit / window-close could otherwise re-enter
    // here and stack another loop. Once we're shutting down, ignore repeats.
    if (ezShuttingDown)
        return;
    ezShuttingDown = true;

    // Mark this as a deliberate shutdown so the finished handler treats the node
    // exiting as normal instead of offering a crash-restart.
    ezExpectedShutdown = true;

    // Shutdown embedded zclassicd if it was started
    if (ezclassicd == nullptr || ezclassicd->processId() == 0 || conn == nullptr) {
        // No zclassicd running internally, just return. Clear the re-entrancy latch
        // so this never stays armed for the process lifetime.
        ezShuttingDown = false;
        return;
    }

    json payload = {
        {"jsonrpc", "1.0"},
        {"id", "someid"},
        {"method", "stop"}
    };
    
    // Best-effort graceful stop: ignore errors. During warmup (e.g. quitting mid
    // snapshot-download) the daemon may refuse the connection or reply RPC_IN_WARMUP;
    // that must not pop a "Transaction Error" box -- we fall back to terminate() below.
    conn->doRPCIgnoreError(payload, [=](auto) {});
    conn->shutdown();

    // Wait for the embedded zclassicd to finish flushing its state and exit, but
    // keep quitting snappy: poll frequently (not once a second) and don't add any
    // artificial trailing delay. The "please wait" dialog is only surfaced if the
    // node is actually taking a moment, so a fast shutdown feels instant instead
    // of always costing a couple of seconds.
    QDialog d(main);
    Ui_ConnectionDialog connD;
    connD.setupUi(&d);
    connD.topIcon->setBasePixmap(QIcon(":/icons/res/icon.ico").pixmap(256, 256));
    connD.status->setText(QObject::tr("Please wait for ZclWallet to exit"));
    connD.statusDetail->setText(QObject::tr("Waiting for zclassicd to exit"));

    QElapsedTimer elapsed;
    elapsed.start();

    // True once the node is gone (or there's nothing for us to wait on, or we've
    // hit the hard cap so quitting can never hang).
    auto fnEnded = [&]() -> bool {
        return ezclassicd->state() == QProcess::NotRunning
            || ezclassicd->processId() == 0
            || conn->config->zclassicDaemon       // external daemon: we don't own its lifetime
            || elapsed.hasExpired(30000);          // hard cap (ms) so Quit never wedges
    };

    if (fnEnded()) {
        ezShuttingDown = false;   // release the re-entrancy latch; this shutdown is done
        return;     // already gone -- exit immediately, no dialog, no wait loop
    }

    QEventLoop loop;
    QTimer     waiter(main);
    QObject::connect(&waiter, &QTimer::timeout, [&]() {
        if (fnEnded()) {
            waiter.stop();
            loop.quit();
        }
    });
    waiter.start(150);

    // Only pop the wait dialog if the shutdown hasn't completed promptly, so quick
    // exits never flash a dialog. Once shown it's modal (blocks the main window) the
    // way the old always-modal d.exec() was.
    QTimer::singleShot(700, &d, [&]() {
        if (waiter.isActive() && !Settings::getInstance()->isHeadless()) {
            d.setModal(true);
            d.show();
        }
    });

    if (!Settings::getInstance()->isHeadless()) {
        loop.exec();
    } else {
        while (!fnEnded()) {
            QCoreApplication::processEvents();
            QThread::msleep(100);
        }
        waiter.stop();
    }

    d.hide();

    // NOTIFY-SRV: the daemon we launched is gone, so tear down the push socket and
    // remove the 0600 token file. (A fresh restart re-starts it in
    // startEmbeddedZClassicd before the daemon launches.)
    if (notifyServer)
        notifyServer->stop();

    // Release the re-entrancy latch now this shutdown has unwound. It serializes
    // re-entrancy WITHIN one shutdown only; it must never latch for the process
    // lifetime (a later restart + Quit must be able to run shutdown again).
    ezShuttingDown = false;
}

// SAFETY GATE for the manual Help -> Repair path. shutdownZClassicd() above is
// allowed to return on a 30s soft cap so Quit never wedges — that means "quit
// promptly", NOT "confirmed exited". Before any datadir mutation we must POSITIVELY
// confirm the embedded node is gone, so terminate()/kill() it and poll its state.
// RUNTIME STUB AUTO-HEAL evaluator. See the header for the full ALL-of trigger. Every
// branch here is a guard that must pass; the destructive work itself is delegated to
// MainWindow::autoHealStubChain() -> launchBlockchainRepair() -> redownloadChain(),
// which keeps all of redownloadChain()'s existing safety guards (daemon-dead confirm,
// wallet.dat backup, ~15 GB disk floor, reversible set-aside) and the heal ledger.
bool RPC::maybeAutoHealStubChain(int connections) {
    // DISABLED 2026-06-01 — superseded by the daemon-side abandoned-stub auto-recovery
    // (zclassicd re-bootstraps a far-below-anchor stub on startup, with a churn guard and
    // backup/restore). That path is testable headless and avoids the two HIGH hazards an
    // adversarial review found in this runtime heuristic: (a) it actually routed to the
    // INTERACTIVE repair dialog whose default (-reindex-chainstate) is a no-op for a stub,
    // and (b) it could set aside a legitimately-still-syncing small chain (a fresh node at
    // 0 peers from dead DNS seeds). We intentionally never fire here; the ordinary
    // "waiting for peers" banner below handles this state in the GUI.
    return false;
    // (1) Peerless margin: require a clear stretch beyond the ~15s banner debounce —
    // 12 polls is ~60s at the 5s syncing cadence (a syncing node uses quickUpdateSpeed).
    if (connections != 0 || ezNoPeerPolls < 12)
        return false;

    // (3a) Once per process: never launch more than one re-download per app run.
    if (ezStubAutoHealTried)
        return false;

    // Don't race a startup/watchdog heal that is already mid-flight (the heal ledger
    // serialize guard). MainWindow::autoHealStubChain re-checks this too; check early
    // so we don't even measure/log when a heal is already running.
    if (QSettings().value("heal/inProgress", false).toBool())
        return false;

    // We must own the node we'd wipe. An external daemon (its lifetime isn't ours) or a
    // not-yet-known connection is out of scope — only an embedded node we started.
    if (conn == nullptr || conn->config == nullptr || conn->config->zclassicDaemon)
        return false;
    if (!isEmbedded())   // ezclassicd == nullptr: no embedded node we own
        return false;

    // (2) Stub discriminator (PRIMARY, robust): the on-disk blocks/ store must be
    // unambiguously small. A fully-synced chain is ~10 GiB; an aborted-P2P stub is tens
    // of MB. Use a hard 1 GiB floor. CRITICAL SAFETY INVARIANT: a large blocks/ means a
    // real (possibly fully-synced) chain that is merely OFFLINE — NEVER wipe it; only
    // the banner applies. blocksDirSizeBytes() returns -1 when it can't measure, which
    // we treat as "unknown" and DO NOT heal on (fail safe -> keep the chain).
    const qint64 kStubFloor = (qint64)1024 * 1024 * 1024;   // 1 GiB hard floor
    qint64 blocksBytes = ConnectionLoader::blocksDirSizeBytes(conn->config->zclassicDir);
    if (blocksBytes < 0) {
        main->logger->write("stub-auto-heal: blocks/ size unknown; not healing (fail-safe)");
        return false;
    }
    if (blocksBytes >= kStubFloor)
        return false;   // real chain, just offline -> keep it, banner only

    // (3b) Persisted per-install cooldown: a genuinely peerless environment (e.g. a
    // firewalled host that can never reach the network) must not loop wipe -> rebootstrap
    // -> stub -> wipe forever. Cap the number of auto re-downloads per install; once the
    // cap is hit, fall back to the banner + the always-reachable Help -> Repair. Counted
    // here BEFORE launching so a crash mid-heal still consumes one attempt. The count is
    // reset on a clean, peered sync (clearStubHealCooldown, called once we have peers).
    QSettings s;
    const int kMaxAutoHeals = 2;
    int prior = s.value("rpc/stubHeal.count", 0).toInt();
    if (prior >= kMaxAutoHeals) {
        main->logger->write(QString("stub-auto-heal: per-install cap reached (%1); "
            "leaving the manual Help -> Repair as the path").arg(prior));
        // Latch the per-process guard too so we stop re-evaluating every poll this run.
        ezStubAutoHealTried = true;
        return false;
    }

    // All guards passed: commit the attempt counters, then launch the SHARED heal path.
    ezStubAutoHealTried = true;
    s.setValue("rpc/stubHeal.count", prior + 1);
    s.sync();
    main->logger->write(QString("stub-auto-heal: launching re-download (blocks/=%1 MB, "
        "noPeerPolls=%2, attempt %3/%4)")
        .arg(blocksBytes / 1024.0 / 1024.0, 0, 'f', 1)
        .arg(ezNoPeerPolls).arg(prior + 1).arg(kMaxAutoHeals));

    main->autoHealStubChain();
    return true;
}

bool RPC::confirmEmbeddedStopped() {
    // No embedded node we own (e.g. an external daemon, which has ezclassicd==nullptr,
    // or already torn down): nothing of ours can be holding the datadir open.
    if (ezclassicd == nullptr)
        return true;

    if (ezclassicd->state() == QProcess::NotRunning || ezclassicd->processId() == 0)
        return true;

    // Still alive after the polite RPC 'stop': ask it to terminate, then escalate.
    ezExpectedShutdown = true;   // a forced stop here is deliberate, not a crash
    ezclassicd->terminate();
    ezclassicd->waitForFinished(5000);
    if (ezclassicd->state() != QProcess::NotRunning) {
        ezclassicd->kill();
        ezclassicd->waitForFinished(5000);
    }

    return ezclassicd->state() == QProcess::NotRunning;
}



/**
 * Get a Sapling address from the user's wallet
 */
QString RPC::getDefaultSaplingAddress() {
    // MINOR-1 null-guard: zaddresses is null until the first refreshAddresses().
    // Never deref it -- callers (e.g. shieldPublicFunds) treat "" as "none yet".
    if (zaddresses == nullptr)
        return QString();

    for (QString addr: *zaddresses) {
        if (Settings::getInstance()->isSaplingAddress(addr))
            return addr;
    }

    return QString();
}

QString RPC::getDefaultTAddress() {
    if (getAllTAddresses()->length() > 0)
        return getAllTAddresses()->at(0);
    else 
        return QString();
}