// ============================================================================
// tst_logic — L0 unit suite for the ZClassic Qt5 GUI wallet
//
// Links ONLY the wallet's pure-logic translation units (settings.cpp,
// senttxstore.cpp, addresscombo.cpp) plus test shims. NO daemon, NO libsodium,
// NO product-code modifications: the shims (tests/shim/) shadow the heavy
// headers purely via INCLUDEPATH ordering in tests.pro.
//
// Covers checklist items from docs/TESTING.md:
//   C3  USD tooltip/format gating (price>0 && !testnet)
//   C5  getDecimalString edges
//   C6  token name ZCL/ZCT by net
//   D6  addressFromAddressLabel + paren-strip via AddressCombo
//   E7  field-validation pieces needing no RPC (amount/decimal formatting)
//   G1  getSaveZtxs() + non-z from-addr gating suppresses SentTxStore write
//   G4  SentTxStore written 0600 owner-only, testnet-prefixed name
//   H1  db-corruption / startup-marker / long-warmup classifiers (mirrored)
//   H2  blocksDirSizeBytes byte total over a temp dir (mirrored algorithm)
//   + exhaustive Settings address classifiers
//       (isTAddress/isZAddress/isSaplingAddress/isSproutAddress)
//   + formatters (getDecimalString/getZCLDisplayFormat/getUSDFormat/token name)
// ============================================================================
#include <QtTest/QtTest>
#include <QtGlobal>
#include "filepermissions.h"
#include "chainbackup.h"
#include "repairlock.h"
#include <QProcess>
#include <QProcessEnvironment>
#include <QTcpServer>
#include "repairlocation.h"
#include "profilepaths.h"
#include "daemonjob.h"
#include <QTemporaryDir>
#include "walletbackup.h"
#include "embeddeddaemon.h"
#include "releaseversion.h"
#include "fastsync.h"
#include "syncstate.h"
#include <QCryptographicHash>
#include <QStandardItemModel>

#include "settings.h"
#include "senttxstore.h"
#include "mainwindow.h"        // shim: ToFields / Tx + SendCategory
#include "rpc.h"               // shim: TransactionItem
#include "addresscombo.h"
#include "addressbook.h"       // shim
#include "privacybadgedelegate.h"   // PRIV-13/14: classify/labelFor/colorFor (real)
#include "securerandom.h"      // CONF-1/NOTIFY-SRV: CSPRNG secret generation (real)
#include "sendflow.h"          // send once: the pure rules (real)
#include "wallethealth.h"      // the wallet health line: the pure rules (real)
#include <QSet>
#include <QRegularExpression>
#include <QFileInfo>

#ifndef Q_OS_WIN
#include <unistd.h>            // getuid() — mirrors the per-user temp-fallback subdir (ITEM 5)
#endif

// ---------------------------------------------------------------------------
// Real valid ZClassic addresses, lifted from src/settings.cpp (donation/zboard).
// These pass the checksum gate in Settings::isValidAddress, so the classifiers
// run their full real path (regex + checksum) rather than the early-out.
// ---------------------------------------------------------------------------
namespace addr {
// mainnet
static const QString ZS_SAPLING   = "zs1gv64eu0v2wx7raxqxlmj354y9ycznwaau9kduljzczxztvs4qcl00kn2sjxtejvrxnkucw5xx9u";
static const QString ZS_ZBOARD    = "zs10m00rvkhfm4f7n23e4sxsx275r7ptnggx39ygl0vy46j9mdll5c97gl6dxgpk0njuptg2mn9w5s";
static const QString ZC_SPROUT    = "zcEgrceTwvoiFdEvPWcsJHAMrpLsprMF6aRJiQa3fan5ZphyXLPuHghnEPrEPRoEVzUy65GnMVyCTRdkT6BYBepnXh6NBYs";
// testnet
static const QString ZTS_SAPLING  = "ztestsapling1wn6889vznyu42wzmkakl2effhllhpe4azhu696edg2x6me4kfsnmqwpglaxzs7tmqsq7kudemp5";
static const QString ZTN_SPROUT   = "ztn6fYKBii4Fp4vbGhkPgrtLU4XjXp4ZBMZgShtopmDGbn1L2JLTYbBp2b7SSkNr9F3rQeNZ9idmoR7s4JCVUZ7iiM5byhF";
// regtest (real address from a Z23 regtest node: getinfo.testnet is false there)
static const QString ZRT_SAPLING  = "zregtestsapling1pm6ght3yqlsyupz82y5l9t9j8ram9l4e25nwvvqhqnwxt3uayjz39ydtw0scn0d00y436v9s4ha";
}

// Flip one character of a valid address to break its checksum (typo negative).
// Picks a body char and rotates it within the address's own charset family so
// the structural regex still matches but the checksum must reject it.
static QString corrupt(const QString& a) {
    QString s = a;
    int i = s.length() / 2;          // middle-ish, safely past the HRP/prefix
    QChar c = s.at(i);
    // rotate within base58/bech32-ish alnum; avoid producing the same char
    QChar repl = (c == QChar('q')) ? QChar('p') : QChar('q');
    if (s.startsWith("zc") || s.startsWith("ztn") || s.startsWith("t"))
        repl = (c == QChar('A')) ? QChar('B') : QChar('A');  // base58 keeps it in-alphabet
    s[i] = repl;
    return s;
}

// =====================================================================
// Mirror of the H1/H2 pure classifiers from src/connection.cpp.
//
// These four predicates are non-static members of the widget-entangled
// ConnectionLoader (connection.cpp pulls ui_*.h + RPC + the daemon launcher),
// so they cannot be linked at L0 and the no-src-modification constraint
// forbids extracting them. The bodies below are copied VERBATIM from
// connection.cpp at the cited line numbers and must stay in sync; the tests
// then exercise this exact classification logic and (for H2) real filesystem
// traversal over a temp dir. See tests/README.md "H1/H2 mirror" note.
// =====================================================================
namespace cxmirror {

// src/connection.cpp:995-1015  ConnectionLoader::looksLikeDbCorruption
static bool looksLikeDbCorruption(const QString& text) {
    if (text.isEmpty()) return false;
    static const char* markers[] = {
        "Corrupted block database detected",
        "Error opening block database",
        "Error loading block database",
        "Error initializing block database",
        "Aborted block database rebuild",
        "Failed to read block",
        "System error while flushing",
        "Do you want to rebuild the block database now"
    };
    for (auto m : markers)
        if (text.contains(QString::fromLatin1(m), Qt::CaseInsensitive)) return true;
    return false;
}

// src/connection.cpp:965-991  ConnectionLoader::startupDiagHasMarker
static bool startupDiagHasMarker(const QString& text) {
    if (text.isEmpty()) return false;
    static const char* markers[] = {
        "Disk space is low",
        "probably already running",
        "Cannot obtain a lock",
        "payload failed verification",
        "invalid embedded payload",
        "Can't find zclassicd",
        "requires newer version",
        "Wallet corrupted",
        "salvage failed",
        "bootstrap snapshot verification failed",
    };
    for (auto m : markers)
        if (text.contains(QString::fromLatin1(m), Qt::CaseInsensitive)) return true;
    return looksLikeDbCorruption(text);
}

// src/connection.cpp:1502-1518  ConnectionLoader::isLongWarmupPhase
static bool isLongWarmupPhase(const QString& status) {
    static const char* kPhases[] = {
        "Verifying blocks", "Activating best chain", "Rewinding",
        "Loading block index", "Pruning blockstore", "Rescanning",
        "Zapping", "Upgrading", "Reindexing",
    };
    for (const char* p : kPhases)
        if (status.contains(QLatin1String(p), Qt::CaseInsensitive)) return true;
    return false;
}

} // namespace cxmirror

// =====================================================================
// PRIV-11/UX-12 — the four-way classifier is the REAL production free function
// `sendCategoryOf()` (src/sendcategory.h), pulled in via the shim mainwindow.h
// include. There is NO hand-copied mirror: the L0 cases below call the SAME body
// production uses (MainWindow::classifySend forwards to it), so a regression in
// the classifier goes red here directly, and the L1 suite drives it via the real
// MainWindow::classifySend over the same quadrants.
// =====================================================================


class TestLogic : public QObject {
    Q_OBJECT

private slots:
    // ---- sync state mapping (syncstate.h): daemon facts -> what the user is told ----
    void syncState_data() {
        QTest::addColumn<QString>("chain");
        QTest::addColumn<int>("blocks");
        QTest::addColumn<int>("headers");
        QTest::addColumn<int>("tipAgeSecs");   // -1 = unknown
        QTest::addColumn<int>("peers");
        QTest::addColumn<int>("ibd");
        QTest::addColumn<bool>("everSynced");
        QTest::addColumn<int>("kind");
        QTest::addColumn<bool>("isSyncing");
        using namespace SyncState;
        // The owner's case: regtest, 101 blocks, no peers -> a local network, never "starting".
        QTest::newRow("regtest-101-nopeers") << "regtest" << 101 << 101 << 3600*24*30 << 0 << 0 << false << (int)LocalNetwork << false;
        QTest::newRow("regtest-genesis")     << "regtest" << 0 << 0 << -1 << 0 << -1 << false << (int)LocalNetwork << false;
        // A regtest node that is still fetching blocks it has headers for (a second local node) is syncing.
        QTest::newRow("regtest-headers-ahead") << "regtest" << 50 << 500 << 3600 << 1 << 1 << false << (int)Syncing << true;
        // Fresh snapshot import: blocks==headers at the anchor, peers up, tip 20 days old.
        QTest::newRow("post-snapshot-old-tip") << "main" << 3126937 << 3126937 << 3600*24*20 << 8 << 1 << false << (int)Syncing << true;
        QTest::newRow("headers-ahead")       << "main" << 3200000 << 3330000 << 3600*24*3 << 8 << 1 << false << (int)Syncing << true;
        QTest::newRow("at-tip-fresh")        << "main" << 3330000 << 3330000 << 120 << 8 << 0 << false << (int)Synced << false;
        QTest::newRow("within-2-headers")    << "main" << 3329998 << 3330000 << 150 << 8 << 0 << false << (int)Synced << false;
        // Restart from a synced datadir, fresh tip, peers not yet connected: not "synced" yet.
        QTest::newRow("restart-no-peers-yet") << "main" << 3330000 << 3330000 << 300 << 0 << 0 << false << (int)WaitingForPeers << true;
        // Peers drop after having been confirmed at the tip: stay synced, do not flicker.
        QTest::newRow("synced-then-peers-drop") << "main" << 3330000 << 3330000 << 300 << 0 << 0 << true << (int)Synced << false;
        QTest::newRow("no-peers-old-tip")    << "main" << 3126937 << 3126937 << 3600*24*20 << 0 << 1 << false << (int)WaitingForPeers << true;
        // Tip older than 2h with peers after being synced: wrong clock or stalled network.
        QTest::newRow("stale-tip-peers")     << "main" << 3330000 << 3330000 << 3600*5 << 8 << 0 << true << (int)StaleTip << true;
        QTest::newRow("first-poll-nothing")  << "main" << 0 << 0 << -1 << 0 << -1 << false << (int)Syncing << true;
        QTest::newRow("testnet-tip-fresh")   << "test" << 900000 << 900000 << 200 << 3 << 0 << false << (int)Synced << false;
        QTest::newRow("clock-skew-reported") << "main" << 3330000 << 3330000 << 3600*3 << 2 << 0 << false << (int)ClockSkew << false;
        // The node itself still reports initial block download with a fresh tip (its chain has less work
        // than the known minimum, e.g. a low-work chain fed by the only peers it has): never "synced".
        QTest::newRow("ibd-fresh-tip-peers")    << "main" << 3330000 << 3330000 << 120 << 8 << 1 << false << (int)Syncing << true;
        QTest::newRow("ibd-fresh-tip-everSynced-nopeers") << "main" << 3330000 << 3330000 << 120 << 0 << 1 << true << (int)WaitingForPeers << true;
    }
    void syncState() {
        QFETCH(QString, chain); QFETCH(int, blocks); QFETCH(int, headers); QFETCH(int, tipAgeSecs);
        QFETCH(int, peers); QFETCH(int, ibd); QFETCH(bool, everSynced);
        QFETCH(int, kind); QFETCH(bool, isSyncing);
        SyncState::Input in;
        in.chain = chain; in.blocks = blocks; in.headers = headers;
        in.now = 1800000000; in.tipTime = tipAgeSecs >= 0 ? in.now - tipAgeSecs : 0;
        in.connections = peers; in.ibd = ibd; in.everSynced = everSynced;
        in.clockWarning = (QByteArray(QTest::currentDataTag()) == "clock-skew-reported");
        const SyncState::Verdict v = SyncState::classify(in);
        QCOMPARE((int)v.kind, kind);
        QCOMPARE(v.isSyncing, isSyncing);
    }
    void presentation_peerlessDebounce() {
        using namespace SyncState;
        Verdict s; s.kind = WaitingForPeers; s.isSyncing = true;
        Verdict done; done.kind = Synced; done.isSyncing = false;
        QCOMPARE((int)presentation(s, 0, 1), (int)PresentConnecting);
        QCOMPARE((int)presentation(s, 0, kNoPeerDebouncePolls - 1), (int)PresentConnecting);
        QCOMPARE((int)presentation(s, 0, kNoPeerDebouncePolls), (int)PresentNoPeers);
        QCOMPARE((int)presentation(s, 3, 50), (int)PresentNormal);
        QCOMPARE((int)presentation(done, 0, 50), (int)PresentNormal);
    }
    void syncState_formatAge() {
        QCOMPARE(SyncState::formatAge(-1), QString());
        QCOMPARE(SyncState::formatAge(40), QString("40 s"));
        QCOMPARE(SyncState::formatAge(300), QString("5 min"));
        QCOMPARE(SyncState::formatAge(3 * 3600), QString("3 h"));
        QCOMPARE(SyncState::formatAge(20LL * 86400), QString("20 days"));
        QCOMPARE(SyncState::formatAge(3641LL * 86400), QString("10.0 years"));
    }

    void fastSync_existingWalletSkipsHistoricalReplay() {
        const QString existing = "bootstrap peer download requires a fresh chain datadir; /data/blocks already exists";
        QVERIFY(shouldMigrateToCheckpoint(true, true, 2719719, "skipped", existing));
        QVERIFY(shouldMigrateToCheckpoint(true, true, 1, "skipped", existing));
        QVERIFY(!shouldMigrateToCheckpoint(false, true, 2719719, "skipped", existing));
        QVERIFY(!shouldMigrateToCheckpoint(true, false, 2719719, "skipped", existing));
        QVERIFY(!shouldMigrateToCheckpoint(true, true, 0, "skipped", existing));
        QVERIFY(!shouldMigrateToCheckpoint(true, true, 3126936, "skipped", existing));
        QVERIFY(!shouldMigrateToCheckpoint(true, true, 3321378, "skipped", existing));
        QVERIFY(!shouldMigrateToCheckpoint(true, true, 2719719, "active", existing));
        QVERIFY(!shouldMigrateToCheckpoint(true, true, 2719719, "skipped", "-bootstrap=0"));
        QVERIFY(!shouldMigrateToCheckpoint(true, true, 2719719, "skipped", "incompatible import options"));
        QVERIFY(!shouldMigrateToCheckpoint(true, true, 2719719, "", ""));
    }
    void repairLocation_usesConfiguredNetworkAndWallet() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir base(temporary.path());
        QVERIFY(base.mkdir("testnet3"));
        QVERIFY(base.mkdir("regtest"));
        QVERIFY(base.mkdir("custom data"));
        const auto mainnet = resolveRepairLocation(base.path(), "", false, false);
        QVERIFY(mainnet.error.isEmpty());
        QCOMPARE(mainnet.directory, base.absolutePath());
        QCOMPARE(mainnet.walletFile, QString("wallet.dat"));
        const auto testnet = resolveRepairLocation(base.path(), "", true, false);
        QCOMPARE(testnet.directory, base.filePath("testnet3"));
        const auto regtest = resolveRepairLocation(base.path(), "", false, true);
        QCOMPARE(regtest.directory, base.filePath("regtest"));
        const auto custom = resolveRepairLocation(base.path(), base.filePath("custom data"), true, false, "savings.dat");
        QVERIFY(custom.error.isEmpty());
        QCOMPARE(custom.directory, base.filePath("custom data/testnet3"));
        QCOMPARE(custom.walletFile, QString("savings.dat"));
        const auto relative = resolveRepairLocation(base.path(), "relative-node", false, false);
        QVERIFY(!relative.error.isEmpty());
        const auto relativeKnown = resolveRepairLocation(base.path(), "relative-node", false, false,
            "wallet.dat", base.path());
        QCOMPARE(relativeKnown.directory, base.filePath("relative-node"));
        QVERIFY(!resolveRepairLocation(base.path(), "", true, true).error.isEmpty());
        QVERIFY(!resolveRepairLocation("", "", false, false).error.isEmpty());
        for (const QString& name : {QString(), QString("."), QString(".."), QString("../wallet.dat"), QString("sub/wallet.dat"), QString("sub\\wallet.dat"), base.filePath("wallet.dat")}) {
            const auto invalid = resolveRepairLocation(base.path(), "", false, false, name);
            QVERIFY2(!invalid.error.isEmpty(), qPrintable(name));
            QVERIFY(invalid.directory.isEmpty());
        }
    }
    void repairLock_childProbe() {
        const QString directory = qEnvironmentVariable("ZCL_TEST_REPAIR_LOCK_DIR");
        if (directory.isEmpty()) QSKIP("Child-process lock probe only");
        RepairLock lock(directory);
        QCOMPARE(lock.acquired(), qEnvironmentVariable("ZCL_TEST_REPAIR_LOCK_EXPECT") == "1");
    }
    void repairLock_excludesOtherProcesses() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        const QString path = QDir(temporary.path()).filePath(".lock");
        { QFile file(path); QVERIFY(file.open(QIODevice::WriteOnly)); }
        auto probe = [&](bool expected) {
            QProcess child;
            auto environment = QProcessEnvironment::systemEnvironment();
            environment.insert("ZCL_TEST_REPAIR_LOCK_DIR", temporary.path());
            environment.insert("ZCL_TEST_REPAIR_LOCK_EXPECT", expected ? "1" : "0");
            child.setProcessEnvironment(environment);
            child.start(QCoreApplication::applicationFilePath(), {"repairLock_childProbe"});
            if (!child.waitForFinished(15000)) return false;
            return child.exitStatus() == QProcess::NormalExit && child.exitCode() == 0;
        };
        {
            RepairLock lock(temporary.path());
            QVERIFY2(lock.acquired(), qPrintable(lock.error()));
            QVERIFY(probe(false));
            { RepairLock duplicate(temporary.path()); QVERIFY(!duplicate.acquired()); }
            QVERIFY(probe(false)); // Rejecting a second local lock must not release the first.
            lock.release();
            QVERIFY(probe(true));
        }
        QVERIFY(QFileInfo::exists(path)); // Never unlink the shared authority.
        QVERIFY(probe(true));
        QVERIFY(QFile::remove(path));
        RepairLock missing(temporary.path());
        QVERIFY(!missing.acquired());
    }
    void repairLock_rejectsDaemonStartup() {
        const QString daemon = qEnvironmentVariable("ZCL_TEST_REPAIR_DAEMON");
        if (daemon.isEmpty()) QSKIP("Set ZCL_TEST_REPAIR_DAEMON for real backend interoperability");
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir root(temporary.path());
        QVERIFY(root.mkdir("regtest"));
        const QString network = root.filePath("regtest");
        { QFile file(QDir(network).filePath(".lock")); QVERIFY(file.open(QIODevice::WriteOnly)); }
        RepairLock lock(network);
        QVERIFY2(lock.acquired(), qPrintable(lock.error()));
        QProcess node;
        node.start(daemon, {"-datadir=" + temporary.path(), "-regtest", "-disablewallet",
            "-listen=0", "-connect=0", "-dnsseed=0", "-bootstrap=0"});
        QVERIFY(node.waitForFinished(15000));
        QVERIFY(node.exitCode() != 0);
        const QByteArray output = node.readAllStandardError() + node.readAllStandardOutput();
        QVERIFY2(output.contains("Cannot obtain a lock on data directory"), output.constData());
    }
    void chainBackup_backendRejectsPendingJournal() {
        const QString daemon = qEnvironmentVariable("ZCL_TEST_REPAIR_DAEMON");
        if (daemon.isEmpty()) QSKIP("Set ZCL_TEST_REPAIR_DAEMON to the updated backend");
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir root(temporary.path());
        QVERIFY(root.mkdir("regtest"));
        QDir network(root.filePath("regtest"));
        { QFile marker(ChainBackup::journalPath(network));
          QVERIFY(marker.open(QIODevice::WriteOnly)); QCOMPARE(marker.write("incomplete"), qint64(10)); }
        QProcess node;
        node.start(daemon, {"-datadir=" + temporary.path(), "-regtest", "-disablewallet",
            "-listen=0", "-connect=0", "-dnsseed=0", "-bootstrap=0"});
        QVERIFY(node.waitForFinished(15000));
        QVERIFY(node.exitCode() != 0);
        const QByteArray output = node.readAllStandardError() + node.readAllStandardOutput();
        QVERIFY2(output.contains("interrupted blockchain repair needs recovery"), output.constData());
        QVERIFY(!QFileInfo::exists(network.filePath("blocks")));
        QVERIFY(!QFileInfo::exists(network.filePath("chainstate")));
        QVERIFY(QFileInfo::exists(ChainBackup::journalPath(network)));
    }
    void chainBackup_realWalletSurvivesSnapshotReplacement() {
        const QString daemon = qEnvironmentVariable("ZCL_TEST_REPAIR_DAEMON");
        if (daemon.isEmpty()) QSKIP("Set ZCL_TEST_REPAIR_DAEMON for isolated regtest wallet migration");
        const QString cli = QFileInfo(daemon).dir().filePath(
#ifdef Q_OS_WIN
            "zclassic-cli.exe"
#else
            "zclassic-cli"
#endif
        );
        QVERIFY(QFileInfo::exists(cli));
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        const QDir root(temporary.path());
        const QDir network(root.filePath("regtest"));
        QTcpServer reservation;
        QVERIFY(reservation.listen(QHostAddress::LocalHost, 0));
        const QString port = QString::number(reservation.serverPort());
        reservation.close();
        const QStringList common{"-regtest", "-datadir=" + root.path(), "-rpcport=" + port};
        QProcess node;
        auto rpc = [&](const QStringList& arguments, QByteArray& output) {
            QProcess process;
            process.start(cli, common + arguments);
            if (!process.waitForFinished(30000)) return false;
            output = process.readAllStandardOutput();
            return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        };
        auto start = [&](const QStringList& extra) {
            node.start(daemon, common + QStringList{"-listen=0", "-connect=0", "-dnsseed=0", "-bootstrap=0"} + extra);
            if (!node.waitForStarted(5000)) return false;
            QElapsedTimer elapsed; elapsed.start();
            while (elapsed.elapsed() < 30000 && node.state() != QProcess::NotRunning) {
                QByteArray output;
                if (rpc({"getwalletinfo"}, output)) return true;
                QTest::qWait(100);
            }
            return false;
        };
        auto stop = [&]() {
            QByteArray output;
            return rpc({"stop"}, output) && node.waitForFinished(30000) &&
                node.exitStatus() == QProcess::NormalExit && node.exitCode() == 0;
        };
        auto walletHash = [&]() {
            QFile file(network.filePath("wallet.dat"));
            if (!file.open(QIODevice::ReadOnly)) return QByteArray();
            QCryptographicHash hash(QCryptographicHash::Sha256);
            if (!hash.addData(&file)) return QByteArray();
            return hash.result();
        };
        QVERIFY(start({}));
        QVERIFY(!repairProcessIsStopped(&node));
        QByteArray address, output;
        QVERIFY(rpc({"getnewaddress"}, address));
        QVERIFY(!address.trimmed().isEmpty());
        QVERIFY(rpc({"generate", "12"}, output));
        QVERIFY(rpc({"getwalletinfo"}, output));
        const auto before = QJsonDocument::fromJson(output).object();
        QVERIFY(before.value("immature_balance").toDouble() > 0);
        QVERIFY(before.value("txcount").toInt() >= 12);
        QVERIFY(stop());
        QVERIFY(repairProcessIsStopped(&node));
        const QByteArray originalHash = walletHash();
        QVERIFY(!originalHash.isEmpty());
        QString backupPath;
        QString walletBackupPath;
        {
            RepairLock lock(network.path());
            QVERIFY(lock.acquired());
            const auto walletCopy = WalletBackup::create(network, "wallet.dat");
            QVERIFY2(walletCopy.success, qPrintable(walletCopy.error));
            walletBackupPath = walletCopy.path;
            QVERIFY(testFileIsOwnerOnly(walletBackupPath));
            const auto backup = ChainBackup::setAside(network);
            QVERIFY2(backup.success, qPrintable(backup.error));
            backupPath = backup.path;
            QCOMPARE(walletHash(), originalHash);
            QVERIFY(!QFileInfo::exists(network.filePath("blocks")));
            QVERIFY(!QFileInfo::exists(network.filePath("chainstate")));
        }
        // Real daemon imports the retained snapshot into fresh chain directories;
        // the original wallet remains in place throughout, with no key export.
        QVERIFY(start({"-bootstrapdatadir=" + backupPath}));
        QVERIFY(rpc({"getblockcount"}, output));
        QCOMPARE(output.trimmed().toInt(), 12);
        QVERIFY(rpc({"getwalletinfo"}, output));
        const auto after = QJsonDocument::fromJson(output).object();
        QCOMPARE(after.value("immature_balance"), before.value("immature_balance"));
        QCOMPARE(after.value("txcount"), before.value("txcount"));
        QVERIFY(rpc({"validateaddress", QString::fromUtf8(address.trimmed())}, output));
        QVERIFY(QJsonDocument::fromJson(output).object().value("ismine").toBool());
        QVERIFY(stop());
        QVERIFY(QFileInfo::exists(QDir(backupPath).filePath("blocks")));
        QVERIFY(QFileInfo::exists(QDir(backupPath).filePath("chainstate")));
        QFile walletCopy(walletBackupPath);
        QVERIFY(walletCopy.open(QIODevice::ReadOnly));
        QCryptographicHash hash(QCryptographicHash::Sha256);
        QVERIFY(hash.addData(&walletCopy));
        QCOMPARE(hash.result(), originalHash);
    }
    void walletBackup_privateVerifiedAndFailClosed() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir data(temporary.path());
        QVERIFY(!WalletBackup::create(data, "wallet.dat").success);
        QVERIFY(!WalletBackup::create(data, "missing-custom.dat").success);
        QVERIFY(!WalletBackup::create(data, "../wallet.dat").success);
        const QByteArray contents(1024 * 1024 + 17, 'x');
        { QFile source(data.filePath("savings.dat")); QVERIFY(source.open(QIODevice::WriteOnly));
          QCOMPARE(source.write(contents), qint64(contents.size())); }
        const auto first = WalletBackup::create(data, "savings.dat");
        QVERIFY2(first.success, qPrintable(first.error));
        QVERIFY(testFileIsOwnerOnly(first.path));
        QFile copy(first.path);
        QVERIFY(copy.open(QIODevice::ReadOnly));
        QCOMPARE(copy.readAll(), contents);
        copy.close();
        const auto second = WalletBackup::create(data, "savings.dat");
        QVERIFY(second.success);
        QVERIFY(second.path != first.path);
        QVERIFY(QFileInfo::exists(first.path));
        bool privateBeforeWriteCompletion = false;
        const auto failed = WalletBackup::create(data, "savings.dat", [&](QFile& file) {
            privateBeforeWriteCompletion = testFileIsOwnerOnly(file.fileName());
            return false;
        });
        QVERIFY(privateBeforeWriteCompletion);
        QVERIFY(!failed.success);
        const auto corrupt = WalletBackup::create(data, "savings.dat", [](QFile& file) {
            return file.seek(0) && file.write("bad") == 3 && RepairPersistence::flushFile(file);
        });
        QVERIFY(!corrupt.success);
        QFile source(data.filePath("savings.dat"));
        QVERIFY(source.open(QIODevice::ReadOnly));
        QCOMPARE(source.readAll(), contents);
        QCOMPARE(data.entryList({".wallet-backup-*"}, QDir::Files | QDir::Hidden).size(), 0);
    }
    void repairConfig_matchesDaemonSelection() {
        const auto parsed = parseRepairConfig("# comment\nnotestnet=0 # enable\ntestnet=0\n"
            "wallet=first.dat # keep this\nwallet=second.dat\nWallet=wrong.dat\n"
            "datadir=relative path # comment\n[other]\nwallet=section.dat\n");
        QVERIFY(parsed.error.isEmpty());
        QVERIFY(repairConfigBool(parsed.values.value("testnet")));
        QCOMPARE(parsed.values.value("wallet"), QString("first.dat"));
        QCOMPARE(parsed.values.value("datadir"), QString("relative path"));
        QCOMPARE(parsed.values.value("other.wallet"), QString("section.dat"));
        const auto positive = parseRepairConfig("testnet=0\nnotestnet=0\nnoregtest=\n");
        QVERIFY(!repairConfigBool(positive.values.value("testnet")));
        QVERIFY(!repairConfigBool(positive.values.value("regtest")));
        QVERIFY(repairConfigBool("1suffix")); // daemon uses atoi, not QString::toInt
        QVERIFY(repairConfigBool(""));
        QVERIFY(!parseRepairConfig("testnet\n").error.isEmpty());
        QVERIFY(!parseRepairConfig("[]\n").error.isEmpty());
    }
    void chainBackup_preservesEveryCopy_data() {
        QTest::addColumn<int>("failure");
        QTest::newRow("success") << 0;
        QTest::newRow("first-move-fails") << 1;
        QTest::newRow("second-move-fails") << 2;
        QTest::newRow("rollback-fails") << 3;
        QTest::newRow("rollback-destination-collision") << 4;
    }
    void chainBackup_preservesEveryCopy() {
        QFETCH(int, failure);
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir data(temporary.path());
        auto write = [](const QString& path, const QByteArray& bytes) {
            QFile f(path);
            return f.open(QIODevice::WriteOnly) && f.write(bytes) == bytes.size();
        };
        auto read = [](const QString& path) {
            QFile f(path);
            return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
        };
        QVERIFY(data.mkdir("blocks"));
        QVERIFY(data.mkdir("chainstate"));
        QVERIFY(data.mkdir("chain-set-aside-previous"));
        QVERIFY(write(data.filePath("blocks/payload"), "blocks-original"));
        QVERIFY(write(data.filePath("chainstate/payload"), "state-original"));
        QVERIFY(write(data.filePath("chain-set-aside-previous/payload"), "previous-backup"));
        QVERIFY(write(data.filePath("wallet.dat"), "wallet-untouched"));
        int call = 0;
        bool collisionCreated = false;
        const auto result = ChainBackup::setAside(data, [&](const QString& from, const QString& to) {
            ++call;
            if (failure == 1 && call == 1) return false;
            if (failure >= 2 && call == 2) {
                if (failure == 4) {
                    collisionCreated = data.mkdir("blocks") &&
                        write(data.filePath("blocks/payload"), "concurrent-copy");
                }
                return false;
            }
            if (failure == 3 && call == 3) return false;
            return QDir().rename(from, to);
        });
        QCOMPARE(result.success, failure == 0);
        QCOMPARE(read(data.filePath("wallet.dat")), QByteArray("wallet-untouched"));
        QCOMPARE(read(data.filePath("chain-set-aside-previous/payload")), QByteArray("previous-backup"));
        const QDir saved(result.path);
        const bool blocksSaved = failure == 0 || failure >= 3;
        QCOMPARE(read((blocksSaved ? saved : data).filePath("blocks/payload")), QByteArray("blocks-original"));
        QCOMPARE(read((failure == 0 ? saved : data).filePath("chainstate/payload")), QByteArray("state-original"));
        if (failure) QVERIFY(!result.error.isEmpty());
        if (failure >= 3) {
            QVERIFY(result.error.contains(saved.filePath("blocks")));
            QVERIFY(QFileInfo::exists(result.path));
        }
        if (failure == 4) {
            QVERIFY(collisionCreated);
            QCOMPARE(read(data.filePath("blocks/payload")), QByteArray("concurrent-copy"));
        }
        if (failure == 0) {
            QVERIFY(data.mkdir("blocks"));
            QVERIFY(write(data.filePath("blocks/payload"), "next-copy"));
            const auto second = ChainBackup::setAside(data);
            QVERIFY(second.success);
            QVERIFY(second.path != result.path);
            QCOMPARE(read(saved.filePath("blocks/payload")), QByteArray("blocks-original"));
            QCOMPARE(read(QDir(second.path).filePath("blocks/payload")), QByteArray("next-copy"));
        }
    }
    void chainBackup_rejectsNonDirectory() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QFile f(temporary.filePath("blocks"));
        QVERIFY(f.open(QIODevice::WriteOnly));
        QCOMPARE(f.write("keep"), qint64(4));
        f.close();
        const auto result = ChainBackup::setAside(QDir(temporary.path()));
        QVERIFY(!result.success);
        QVERIFY(result.path.isEmpty());
        QVERIFY(f.open(QIODevice::ReadOnly));
        QCOMPARE(f.readAll(), QByteArray("keep"));
    }
    void chainBackup_stopsOnPersistenceFailure_data() {
        QTest::addColumn<int>("failure");
        QTest::newRow("journal-file-flush") << 0;
        for (int step = 1; step <= 8; ++step)
            QTest::newRow(qPrintable(QString("directory-barrier-%1").arg(step))) << step;
    }
    void chainBackup_stopsOnPersistenceFailure() {
        QFETCH(int, failure);
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir data(temporary.path());
        QVERIFY(data.mkdir("blocks"));
        QVERIFY(data.mkdir("chainstate"));
        int barriers = 0, moves = 0;
        ChainBackup::Persistence persistence;
        persistence.flushFile = [&](QFile& file) { return failure != 0 && RepairPersistence::flushFile(file); };
        persistence.syncDirectory = [&](const QString& path) {
            return ++barriers != failure && RepairPersistence::syncDirectory(path);
        };
        const auto result = ChainBackup::setAside(data, [&](const QString& from, const QString& to) {
            ++moves;
            return RepairPersistence::move(from, to);
        }, persistence);
        QVERIFY(!result.success);
        QVERIFY(!result.error.isEmpty());
        if (failure <= 2) QCOMPARE(moves, 0); // No component moves without persisted intent.
        if (failure == 0) {
            QVERIFY(!QFileInfo::exists(ChainBackup::journalPath(data)));
            QVERIFY(QFileInfo::exists(data.filePath("blocks")));
            QVERIFY(QFileInfo::exists(data.filePath("chainstate")));
            return;
        }
        if (QFileInfo::exists(ChainBackup::journalPath(data))) {
            const auto recovery = ChainBackup::recover(data);
            QVERIFY2(recovery.success, qPrintable(recovery.error));
            QVERIFY(QFileInfo::exists(data.filePath("blocks")));
            QVERIFY(QFileInfo::exists(data.filePath("chainstate")));
        } else {
            // Completion rename happened before its flush failed. Both components
            // had already passed their own persistence barriers; no mixed pair.
            QVERIFY(QFileInfo::exists(QDir(result.path).filePath("blocks")));
            QVERIFY(QFileInfo::exists(QDir(result.path).filePath("chainstate")));
            QVERIFY(!QFileInfo::exists(data.filePath("blocks")));
            QVERIFY(!QFileInfo::exists(data.filePath("chainstate")));
        }
    }
    void chainBackup_recoveryRetriesFlushFailure_data() {
        QTest::addColumn<int>("failure");
        for (int step = 1; step <= 8; ++step)
            QTest::newRow(qPrintable(QString("recovery-barrier-%1").arg(step))) << step;
    }
    void chainBackup_recoveryRetriesFlushFailure() {
        QFETCH(int, failure);
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir data(temporary.path());
        QVERIFY(data.mkpath("chain-set-aside-fixture/blocks"));
        QVERIFY(data.mkpath("chain-set-aside-fixture/chainstate"));
        { QFile file(ChainBackup::journalPath(data)); QVERIFY(file.open(QIODevice::WriteOnly));
          const QByteArray bytes = "{\"version\":2,\"backup\":\"chain-set-aside-fixture\",\"entries\":[\"blocks\",\"chainstate\"]}";
          QCOMPARE(file.write(bytes), qint64(bytes.size())); }
        int barriers = 0;
        QStringList flushed;
        ChainBackup::Persistence persistence;
        persistence.syncDirectory = [&](const QString& path) {
            flushed.append(path);
            return ++barriers != failure && RepairPersistence::syncDirectory(path);
        };
        QVERIFY(!ChainBackup::recover(data, RepairPersistence::move, persistence).success);
        QCOMPARE(flushed.first(), data.absolutePath()); // Restore destination first.
        if (flushed.size() >= 2)
            QCOMPARE(flushed[1], data.filePath("chain-set-aside-fixture"));
        const auto retry = ChainBackup::recover(data);
        QVERIFY2(retry.success, qPrintable(retry.error));
        QVERIFY(QFileInfo::exists(data.filePath("blocks")));
        QVERIFY(QFileInfo::exists(data.filePath("chainstate")));
    }
    void chainBackup_journalCollisionsNeverOverwrite() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir data(temporary.path());
        QVERIFY(data.mkdir("blocks"));
        QVERIFY(data.mkdir("chainstate"));
        ChainBackup::Persistence persistence;
        persistence.flushFile = [&](QFile& file) {
            QFile collision(ChainBackup::journalPath(data));
            if (!collision.open(QIODevice::WriteOnly) || collision.write("preserve-journal") != 16) return false;
            collision.close();
            return RepairPersistence::flushFile(file);
        };
        int moves = 0;
        const auto blocked = ChainBackup::setAside(data, [&](const QString& from, const QString& to) {
            ++moves; return RepairPersistence::move(from, to);
        }, persistence);
        QVERIFY(!blocked.success);
        QCOMPARE(moves, 0);
        QFile journal(ChainBackup::journalPath(data));
        QVERIFY(journal.open(QIODevice::ReadOnly));
        QCOMPARE(journal.readAll(), QByteArray("preserve-journal"));
        journal.close();
        QVERIFY(journal.remove()); // Only this test's injected collision.
        QString receipt;
        const auto completion = ChainBackup::setAside(data, [&](const QString& from, const QString& to) {
            if (!RepairPersistence::move(from, to)) return false;
            if (QFileInfo(to).fileName() == "chainstate") {
                receipt = QFileInfo(to).dir().filePath("repair-completed.json");
                QFile collision(receipt);
                return collision.open(QIODevice::WriteOnly) && collision.write("preserve-receipt") == 16;
            }
            return true;
        });
        QVERIFY(!completion.success);
        QVERIFY(QFileInfo::exists(ChainBackup::journalPath(data)));
        const auto recovery = ChainBackup::recover(data);
        QVERIFY(!recovery.success); // Collision still prevents clearing the guard.
        QVERIFY(QFileInfo::exists(data.filePath("blocks")));
        QVERIFY(QFileInfo::exists(data.filePath("chainstate")));
        QFile saved(receipt);
        QVERIFY(saved.open(QIODevice::ReadOnly));
        QCOMPARE(saved.readAll(), QByteArray("preserve-receipt"));
        QVERIFY(QFileInfo::exists(ChainBackup::journalPath(data)));
    }
    void chainBackup_crashChild() {
        const QString directory = qEnvironmentVariable("ZCL_TEST_CHAIN_CRASH_DIR");
        if (directory.isEmpty()) QSKIP("Abrupt-exit fixture only");
        const int stop = qEnvironmentVariableIntValue("ZCL_TEST_CHAIN_CRASH_AFTER");
        RepairLock lock(directory);
        QVERIFY(lock.acquired());
        int moves = 0;
        ChainBackup::setAside(QDir(directory), [&](const QString& from, const QString& to) {
            if (moves == stop) std::_Exit(73);
            if (!QDir().rename(from, to)) return false;
            if (++moves == stop) std::_Exit(73);
            return true;
        });
        QFAIL("Crash fixture did not reach requested move boundary");
    }
    void chainBackup_recoversAbruptExit_data() {
        QTest::addColumn<int>("moves");
        QTest::newRow("before-first-move") << 0;
        QTest::newRow("between-moves") << 1;
        QTest::newRow("after-both-moves") << 2;
        QTest::newRow("after-anchor-metadata") << 3;
        QTest::newRow("after-trustless-metadata") << 4;
        QTest::newRow("after-all-metadata") << 5;
        QTest::newRow("after-verification-scratch") << 6;
    }
    void chainBackup_recoversAbruptExit() {
        QFETCH(int, moves);
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir data(temporary.path());
        for (const QString& name : {QString("blocks"), QString("chainstate")}) {
            QVERIFY(data.mkdir(name));
            QFile file(data.filePath(name + "/payload"));
            QVERIFY(file.open(QIODevice::WriteOnly));
            QCOMPARE(file.write(name.toUtf8()), qint64(name.size()));
        }
        for (const QString& name : ChainBackup::componentNames().mid(2)) {
            if (name == "chainstate-verify") QVERIFY(data.mkdir(name));
            QFile file(data.filePath(name == "chainstate-verify" ? name + "/payload" : name));
            QVERIFY(file.open(QIODevice::WriteOnly));
            QCOMPARE(file.write(name.toUtf8()), qint64(name.size()));
        }
        { QFile file(data.filePath(".lock")); QVERIFY(file.open(QIODevice::WriteOnly)); }
        { QFile file(data.filePath("wallet.dat")); QVERIFY(file.open(QIODevice::WriteOnly)); QCOMPARE(file.write("keep-wallet"), qint64(11)); }
        QProcess child;
        auto environment = QProcessEnvironment::systemEnvironment();
        environment.insert("ZCL_TEST_CHAIN_CRASH_DIR", data.path());
        environment.insert("ZCL_TEST_CHAIN_CRASH_AFTER", QString::number(moves));
        child.setProcessEnvironment(environment);
        child.start(QCoreApplication::applicationFilePath(), {"chainBackup_crashChild"});
        QVERIFY(child.waitForFinished(15000));
        QCOMPARE(child.exitCode(), 73);
        QVERIFY(QFileInfo::exists(ChainBackup::journalPath(data)));
        RepairLock lock(data.path());
        QVERIFY(lock.acquired());
        const auto recovery = ChainBackup::recover(data);
        QVERIFY2(recovery.success, qPrintable(recovery.error));
        QVERIFY(!QFileInfo::exists(ChainBackup::journalPath(data)));
        for (const QString& name : {QString("blocks"), QString("chainstate")}) {
            QFile file(data.filePath(name + "/payload"));
            QVERIFY(file.open(QIODevice::ReadOnly));
            QCOMPARE(file.readAll(), name.toUtf8());
        }
        QFile wallet(data.filePath("wallet.dat"));
        QVERIFY(wallet.open(QIODevice::ReadOnly));
        QCOMPARE(wallet.readAll(), QByteArray("keep-wallet"));
        for (const QString& name : ChainBackup::componentNames().mid(2)) {
            QFile file(data.filePath(name == "chainstate-verify" ? name + "/payload" : name));
            QVERIFY(file.open(QIODevice::ReadOnly));
            QCOMPARE(file.readAll(), name.toUtf8());
        }
        QVERIFY(ChainBackup::recover(data).success); // Retry is harmless.
    }
    void chainBackup_preservesMetadataOnSuccess() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir data(temporary.path());
        QVERIFY(data.mkdir("blocks"));
        QVERIFY(data.mkdir("chainstate"));
        for (const QString& name : ChainBackup::componentNames().mid(2)) {
            if (name == "chainstate-verify") QVERIFY(data.mkdir(name));
            QFile file(data.filePath(name == "chainstate-verify" ? name + "/payload" : name));
            QVERIFY(file.open(QIODevice::WriteOnly));
            QCOMPARE(file.write("verification-state"), qint64(18));
        }
        const auto backup = ChainBackup::setAside(data);
        QVERIFY2(backup.success, qPrintable(backup.error));
        for (const QString& name : ChainBackup::componentNames().mid(2)) {
            QVERIFY(!QFileInfo::exists(data.filePath(name)));
            QFile file(QDir(backup.path).filePath(name == "chainstate-verify" ? name + "/payload" : name));
            QVERIFY(file.open(QIODevice::ReadOnly));
            QCOMPARE(file.readAll(), QByteArray("verification-state"));
        }
    }
    void chainBackup_rejectsInvalidJournal() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        const QDir data(temporary.path());
        for (const QByteArray& contents : {QByteArray("{"), QByteArray("{\"version\":1,\"backup\":\"../outside\",\"entries\":[\"wallet.dat\"]}")}) {
            QFile marker(ChainBackup::journalPath(data));
            QVERIFY(marker.open(QIODevice::WriteOnly | QIODevice::Truncate));
            QCOMPARE(marker.write(contents), qint64(contents.size()));
            marker.close();
            QVERIFY(!ChainBackup::recover(data).success);
            QVERIFY(marker.open(QIODevice::ReadOnly));
            QCOMPARE(marker.readAll(), contents);
        }
    }
    void chainBackup_rejectsOmittedJournalEntry() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir data(temporary.path());
        QVERIFY(data.mkdir("chain-set-aside-fixture"));
        QVERIFY(data.mkpath("chain-set-aside-fixture/blocks"));
        QVERIFY(data.mkdir("chainstate"));
        for (const QByteArray& entries : {QByteArray("[]"), QByteArray("[\"chainstate\"]")}) {
            QFile marker(ChainBackup::journalPath(data));
            QVERIFY(marker.open(QIODevice::WriteOnly | QIODevice::Truncate));
            const QByteArray contents = "{\"version\":1,\"backup\":\"chain-set-aside-fixture\",\"entries\":" + entries + "}";
            QCOMPARE(marker.write(contents), qint64(contents.size()));
            marker.close();
            QVERIFY(!ChainBackup::recover(data).success);
            QVERIFY(!QFileInfo::exists(data.filePath("blocks")));
            QVERIFY(QFileInfo::exists(data.filePath("chainstate")));
            QVERIFY(QFileInfo::exists(data.filePath("chain-set-aside-fixture/blocks")));
            QVERIFY(marker.open(QIODevice::ReadOnly));
            QCOMPARE(marker.readAll(), contents);
        }
    }
    void chainBackup_legacyJournalCannotStrandMetadata() {
        QTemporaryDir temporary;
        QVERIFY(temporary.isValid());
        QDir data(temporary.path());
        QVERIFY(data.mkdir("chain-set-aside-fixture"));
        QVERIFY(data.mkdir("blocks"));
        QVERIFY(data.mkdir("chainstate"));
        const QString saved = data.filePath("chain-set-aside-fixture/bootstrap-anchor-pending");
        { QFile file(saved); QVERIFY(file.open(QIODevice::WriteOnly)); QCOMPARE(file.write("must-verify"), qint64(11)); }
        { QFile file(ChainBackup::journalPath(data)); QVERIFY(file.open(QIODevice::WriteOnly));
          const QByteArray json = "{\"version\":1,\"backup\":\"chain-set-aside-fixture\",\"entries\":[\"blocks\",\"chainstate\"]}";
          QCOMPARE(file.write(json), qint64(json.size())); }
        QVERIFY(!ChainBackup::recover(data).success);
        QVERIFY(QFileInfo::exists(ChainBackup::journalPath(data)));
        QVERIFY(QFileInfo::exists(saved));
        // A genuine v1 transition leaves metadata at the original location.
        QVERIFY(QFile::rename(saved, data.filePath("bootstrap-anchor-pending")));
        QVERIFY(ChainBackup::recover(data).success);
        QFile file(data.filePath("bootstrap-anchor-pending"));
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(file.readAll(), QByteArray("must-verify"));
    }
    void releaseVersion_ordering() {
        QVERIFY(walletReleaseOrder("2.1.2-beta7") > walletReleaseOrder("2.1.2-beta6"));
        QVERIFY(walletReleaseOrder("2.1.2-beta10") > walletReleaseOrder("2.1.2-beta9"));
        QVERIFY(walletReleaseOrder("2.1.2-rc1") > walletReleaseOrder("2.1.2-beta99"));
        QVERIFY(walletReleaseOrder("2.1.2") > walletReleaseOrder("2.1.2-rc99"));
        QVERIFY(walletReleaseOrder("2.1.3-beta1") > walletReleaseOrder("2.1.2"));
        QCOMPARE(walletReleaseOrder("v2.1.2-beta7"), walletReleaseOrder("2.1.2-beta7"));
        QVERIFY(walletReleaseOrder("2.1.2-beta7garbage").isNull());
        QVERIFY(walletReleaseOrder("999999999999.1.2").isNull());
        QVERIFY(walletReleaseOrder("2.1.2-beta999999999999").isNull());
        QVERIFY(walletReleaseOrder("").isNull());
    }
    void embeddedDaemon_integrity();
    void embeddedDaemon_footerLocation();
    void embeddedDaemon_pinsLaunchedFile();
    void embeddedDaemon_malformedPe();
    void initTestCase();
    void cleanupTestCase();

    // --- Settings address classifiers (exhaustive) ---
    void classifiers_data();
    void classifiers();

    void invalidAddressesRejected_data();
    void invalidAddressesRejected();

    // --- formatters ---
    void getDecimalString_data();   // C5
    void getDecimalString();
    void zclDisplayFormat_data();
    void zclDisplayFormat();
    void usdFormat_data();          // C3
    void usdFormat();
    void tokenName();               // C6
    void e7FieldFormatting_data();  // E7 (no-RPC field pieces)
    void e7FieldFormatting();

    // --- AddressCombo / addressbook parsing ---  D6
    void addressFromLabel_data();
    void addressFromLabel();
    void addressComboParenStrip();

    // --- SentTxStore at-rest ---  G1 / G4
    void sentTxStore_perms_and_testnetName();   // G4
    void sentTxStore_gating();                  // G1
    void sentTxStore_roundTrip();
    void sentTxStore_invalidHistoryPreserved();

    // --- H1 / H2 classifiers (mirrored) ---
    void dbCorruptionMarkers_data();   // H1
    void dbCorruptionMarkers();
    void startupMarkers_data();        // H1
    void startupMarkers();
    void longWarmupPhase_data();       // H1
    void longWarmupPhase();
    void blocksDirSizeBytes();         // H2

    // --- PRIV-9: auto-shield default-ON canary ---
    void priv9_autoShieldDefaultOn();

    // --- PRIV-11/UX-12: four-way send classification (mirror of classifySend) ---
    void priv11_sendClassification_data();
    void priv11_sendClassification();
    // PRIV-12 locus: ONLY z->t (de-shield) is the acknowledgement-gated category.
    void priv12_onlyDeshieldIsGated_data();
    void priv12_onlyDeshieldIsGated();

    // --- PRIV-13: privacy-badge classify()/classifyForIndex()/labelFor() (real) ---
    void priv13_badgeClassify_data();
    void priv13_badgeClassify();
    void priv13_deshieldOnlyForPublicSendRow();
    void priv13_transparentSendIsNotDeshield();
    void priv13_amountColumnFitsSignedAmount();
    // --- PRIV-14: badge colour hex tokens match dark.qss ---
    void priv14_badgeColorTokens();

    // --- CONF-1 / NOTIFY-SRV: CSPRNG secret generation (securerandom.h, the
    //     single source randomPassword() and the notify token both delegate to) ---
    void conf1_passwordHighEntropyCSPRNG();
    void conf1_notifyTokenHexFormat();
    void conf1_randomPasswordUsesCSPRNG();   // caller-divergence guard (connection.cpp)

    // --- Hardening guards (source-text + behavioral) ---
    void notify_tempFallbackDirIsOwnerOnly();         // ITEM 5 behavioral (mirrored)
    void notify_runtimeDirHardensTempFallback();      // ITEM 5 source guard (notifyserver.cpp)
    void notify_connectorLogsFailureToStderr();       // ITEM 4 source guard (notifyserver.cpp)
    void notify_launchArgsGatedOnSocketReady();       // ITEM 2 source guard (connection.cpp)
    void conf_permsVerifiedAfterWrite();              // ITEM 3 source guard (connection.cpp)

    // --- First-run trust: send-gate staleness predicate (pure) ---
    void sendgate_staleWhenPollStops();               // Settings::syncGateIsStale boundary
    void profile_unsetKeepsDefaults();
    void profile_setRedirectsEveryPath();
    void profile_settingsAreIniInsideProfile();
    void profile_noDirectStateLocations();
    void profile_blankValueFailsClosed();
    void daemonjob_everyLaunchPathUsesTheJob();
    void daemonjob_armedAfterEveryStart();
    void sendflow_keysAreValidAndDistinct();
    void sendflow_classifyTheAnswerToTheCall();
    void sendflow_retryPaceIsBounded();
    void sendflow_whatTheUserIsToldAboutAKeyedSend();
    void sendflow_anUnkeyedSendOnAnOlderNode();
    void sendflow_theJournalIsOnlyAskedWhenItDecides();
    void sendflow_parseWhatTheNodeSays();
    void sendflow_ownWordingIsNotRewritten();
    void health_aHealthyWalletSaysNothing();
    void health_eachAttentionStateIsReported();

private:
    QString sandboxAppData() const {
        return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    }
};

// ---------------------------------------------------------------------------
void TestLogic::initTestCase() {
    // Sandbox: route QSettings + QStandardPaths::AppDataLocation into a throwaway
    // location so we NEVER touch the user's real profile or ~/.zclassic.
    QStandardPaths::setTestModeEnabled(true);
    QCoreApplication::setOrganizationName("ZClassicTest");
    QCoreApplication::setOrganizationDomain("test.zclassic.invalid");
    QCoreApplication::setApplicationName("tst_logic");

    // Settings is a singleton accessed via getInstance(); init it once.
    Settings::init();
    QVERIFY(Settings::getInstance() != nullptr);

    // Start from a clean QSettings each run.
    QSettings().clear();
    QSettings().sync();
}

void TestLogic::cleanupTestCase() {
    QSettings().clear();
    QSettings().sync();
}

// =====================================================================
// Address classifiers (exhaustive truth table)
// =====================================================================
void TestLogic::classifiers_data() {
    QTest::addColumn<QString>("address");
    QTest::addColumn<bool>("testnet");
    QTest::addColumn<bool>("isT");
    QTest::addColumn<bool>("isZ");
    QTest::addColumn<bool>("isSapling");
    QTest::addColumn<bool>("isSprout");

    //                              addr                 net=t  isT    isZ    isSap  isSpr
    QTest::newRow("mainnet sapling zs")  << addr::ZS_SAPLING  << false << false << true  << true  << false;
    QTest::newRow("mainnet zboard zs")   << addr::ZS_ZBOARD   << false << false << true  << true  << false;
    QTest::newRow("mainnet sprout zc")   << addr::ZC_SPROUT   << false << false << true  << false << true;
    QTest::newRow("testnet sapling zts") << addr::ZTS_SAPLING << true  << false << true  << true  << false;
    QTest::newRow("testnet sprout ztn")  << addr::ZTN_SPROUT  << true  << false << true  << false << true;
    // regtest Sapling is Sapling whatever the testnet flag says (the daemon reports testnet=false)
    QTest::newRow("regtest sapling zrt")    << addr::ZRT_SAPLING << false << false << true  << true  << false;
    QTest::newRow("regtest sapling zrt tn") << addr::ZRT_SAPLING << true  << false << true  << true  << false;

    // On the WRONG network, a Sapling addr is not recognized as Sapling
    // (isSaplingAddress is net-aware), so it classifies as Sprout (z && !sapling).
    QTest::newRow("zs on testnet -> sprout") << addr::ZS_SAPLING  << true  << false << true  << false << true;
    QTest::newRow("zts on mainnet -> sprout")<< addr::ZTS_SAPLING << false << false << true  << false << true;
}

void TestLogic::classifiers() {
    QFETCH(QString, address);
    QFETCH(bool, testnet);
    QFETCH(bool, isT);
    QFETCH(bool, isZ);
    QFETCH(bool, isSapling);
    QFETCH(bool, isSprout);

    Settings::getInstance()->setTestnet(testnet);

    QCOMPARE(Settings::isTAddress(address), isT);
    QCOMPARE(Settings::isZAddress(address), isZ);
    QCOMPARE(Settings::getInstance()->isSaplingAddress(address), isSapling);
    QCOMPARE(Settings::getInstance()->isSproutAddress(address), isSprout);

    Settings::getInstance()->setTestnet(false);  // restore default
}

void TestLogic::invalidAddressesRejected_data() {
    QTest::addColumn<QString>("address");

    QTest::newRow("empty")              << QString("");
    QTest::newRow("garbage")            << QString("not-an-address");
    QTest::newRow("too short t")        << QString("t1abc");
    QTest::newRow("bad checksum zs")    << corrupt(addr::ZS_SAPLING);
    QTest::newRow("bad checksum zc")    << corrupt(addr::ZC_SPROUT);
    QTest::newRow("bad checksum zts")   << corrupt(addr::ZTS_SAPLING);
    QTest::newRow("bad checksum ztn")   << corrupt(addr::ZTN_SPROUT);
    QTest::newRow("bad checksum zrt")   << corrupt(addr::ZRT_SAPLING);
    QTest::newRow("only prefix z")      << QString("z");
    QTest::newRow("only prefix t")      << QString("t");
}

void TestLogic::invalidAddressesRejected() {
    QFETCH(QString, address);
    // Every classifier early-outs to false on a non-valid address, regardless of net.
    QVERIFY(!Settings::isValidAddress(address));
    QVERIFY(!Settings::isTAddress(address));
    QVERIFY(!Settings::isZAddress(address));
    QVERIFY(!Settings::getInstance()->isSaplingAddress(address));
    QVERIFY(!Settings::getInstance()->isSproutAddress(address));
}

// =====================================================================
// C5 — getDecimalString edges
// =====================================================================
void TestLogic::getDecimalString_data() {
    QTest::addColumn<double>("amt");
    QTest::addColumn<QString>("expected");

    QTest::newRow("1.5")        << 1.5              << QString("1.5");
    QTest::newRow("5")          << 5.0              << QString("5");
    QTest::newRow("neg zero")   << -0.0             << QString("0");
    QTest::newRow("dust")       << 0.00000001       << QString("0.00000001");
    QTest::newRow("-1.5")       << -1.5             << QString("-1.5");
    QTest::newRow("zero")       << 0.0              << QString("0");
    QTest::newRow("trailing 0s")<< 2.50000000       << QString("2.5");
    QTest::newRow("whole 100")  << 100.0            << QString("100");
}

void TestLogic::getDecimalString() {
    QFETCH(double, amt);
    QFETCH(QString, expected);
    QCOMPARE(Settings::getDecimalString(amt), expected);
}

// =====================================================================
// getZCLDisplayFormat  (decimal + token, net-aware token)
// =====================================================================
void TestLogic::zclDisplayFormat_data() {
    QTest::addColumn<double>("amt");
    QTest::addColumn<bool>("testnet");
    QTest::addColumn<QString>("expected");

    QTest::newRow("mainnet 1.5")  << 1.5  << false << QString("1.5 ZCL");
    QTest::newRow("mainnet 5")    << 5.0  << false << QString("5 ZCL");
    QTest::newRow("testnet 1.5")  << 1.5  << true  << QString("1.5 ZCT");
    QTest::newRow("mainnet dust") << 0.00000001 << false << QString("0.00000001 ZCL");
}

void TestLogic::zclDisplayFormat() {
    QFETCH(double, amt);
    QFETCH(bool, testnet);
    QFETCH(QString, expected);
    Settings::getInstance()->setTestnet(testnet);
    QCOMPARE(Settings::getZCLDisplayFormat(amt), expected);
    Settings::getInstance()->setTestnet(false);
}

// =====================================================================
// C3 — getUSDFormat: only when price>0 && !testnet
// =====================================================================
void TestLogic::usdFormat_data() {
    QTest::addColumn<double>("price");
    QTest::addColumn<bool>("testnet");
    QTest::addColumn<double>("bal");
    QTest::addColumn<QString>("expected");   // "" means: empty string expected

    QTest::newRow("mainnet priced")     << 2.0   << false << 3.0  << QString("$6.00");
    QTest::newRow("mainnet zero price") << 0.0   << false << 3.0  << QString("");
    QTest::newRow("testnet priced")     << 2.0   << true  << 3.0  << QString("");
    QTest::newRow("testnet zero price") << 0.0   << true  << 3.0  << QString("");
    QTest::newRow("mainnet neg price")  << -1.0  << false << 3.0  << QString("");
}

void TestLogic::usdFormat() {
    QFETCH(double, price);
    QFETCH(bool, testnet);
    QFETCH(double, bal);
    QFETCH(QString, expected);

    Settings::getInstance()->setTestnet(testnet);
    Settings::getInstance()->setZCLPrice(price);

    QString got = Settings::getUSDFormat(bal);
    if (expected.isEmpty())
        QVERIFY2(got.isEmpty(), qPrintable(QString("expected empty, got '%1'").arg(got)));
    else
        QCOMPARE(got, expected);

    Settings::getInstance()->setTestnet(false);
    Settings::getInstance()->setZCLPrice(0.0);
}

// =====================================================================
// C6 — token name ZCL (mainnet) / ZCT (testnet)
// =====================================================================
void TestLogic::tokenName() {
    Settings::getInstance()->setTestnet(false);
    QCOMPARE(Settings::getTokenName(), QString("ZCL"));
    Settings::getInstance()->setTestnet(true);
    QCOMPARE(Settings::getTokenName(), QString("ZCT"));
    Settings::getInstance()->setTestnet(false);
}

// =====================================================================
// E7 — field-validation pieces that need no RPC: amount/decimal formatting
// round-trips that the Send-tab validation relies on.
// =====================================================================
void TestLogic::e7FieldFormatting_data() {
    QTest::addColumn<double>("amt");
    QTest::addColumn<QString>("decimal");

    // doSendTxValidations formats amounts through getDecimalString before display;
    // these assert the boundary amounts a recipient field must round-trip exactly.
    QTest::newRow("miner fee")   << Settings::getMinerFee()    << QString("0.0001");
    QTest::newRow("zboard amt")  << Settings::getZboardAmount()<< QString("0.0001");
    QTest::newRow("8dp boundary")<< 0.12345678                 << QString("0.12345678");
    QTest::newRow("negative")    << -2.0                       << QString("-2");
}

void TestLogic::e7FieldFormatting() {
    QFETCH(double, amt);
    QFETCH(QString, decimal);
    QCOMPARE(Settings::getDecimalString(amt), decimal);
}

// =====================================================================
// D6 — addressFromAddressLabel + AddressCombo paren-strip
// =====================================================================
void TestLogic::addressFromLabel_data() {
    QTest::addColumn<QString>("input");
    QTest::addColumn<QString>("expected");

    QTest::newRow("plain addr")        << addr::ZS_SAPLING << addr::ZS_SAPLING;
    QTest::newRow("label/addr")        << QString("mylabel/") + addr::ZS_SAPLING << addr::ZS_SAPLING;
    QTest::newRow("leading space")     << QString("  trim/") + addr::ZC_SPROUT << addr::ZC_SPROUT;
    QTest::newRow("multi-slash takes last") << QString("a/b/") + addr::ZTS_SAPLING << addr::ZTS_SAPLING;
    QTest::newRow("no slash trims")    << QString("   ") + addr::ZTN_SPROUT + QString("  ") << addr::ZTN_SPROUT;
}

void TestLogic::addressFromLabel() {
    QFETCH(QString, input);
    QFETCH(QString, expected);
    QCOMPARE(AddressBook::addressFromAddressLabel(input), expected);
}

// AddressCombo::itemText/currentText strip "(amount)" then label, matching
// docs D6: `label/zaddr(1.5 ZCL)` -> `zaddr`.
void TestLogic::addressComboParenStrip() {
    AddressCombo combo;
    // Seed a label so addLabelToAddress produces "label/addr".
    AddressBook::getInstance()->addAddressLabel("donations", addr::ZS_SAPLING);

    // addItem(addr, bal>0) stores "label/addr(<bal> ZCL)" — exercise the strip.
    Settings::getInstance()->setTestnet(false);
    combo.addItem(addr::ZS_SAPLING, 1.5);
    QCOMPARE(combo.count(), 1);
    // itemText must return JUST the bare address (parens + label removed).
    QCOMPARE(combo.itemText(0), addr::ZS_SAPLING);
    QCOMPARE(combo.currentText(), addr::ZS_SAPLING);

    // An item with zero balance has no parens; still returns the bare addr.
    combo.addItem(addr::ZC_SPROUT, 0.0);
    QCOMPARE(combo.itemText(1), addr::ZC_SPROUT);
}

// =====================================================================
// G4 — SentTxStore file is 0600 owner-only, testnet-prefixed name
// =====================================================================
void TestLogic::sentTxStore_perms_and_testnetName() {
    Settings::getInstance()->setTestnet(true);
    QSettings().setValue("options/savesenttx", true);
    QSettings().sync();

    // clean slate
    SentTxStore::deleteHistory();

    Tx tx;
    tx.fromAddr = addr::ZTS_SAPLING;   // z-addr so the write is NOT gated out
    tx.fee = 0.0001;
    ToFields f; f.addr = addr::ZTN_SPROUT; f.amount = 1.25;
    tx.toAddrs.append(f);

    SentTxStore::addToSentTx(tx, "deadbeefcafetxid");

    // The file must exist under a "testnet-"-prefixed name in AppDataLocation.
    QString expected = QDir(sandboxAppData()).filePath("testnet-senttxstore.dat");
    QVERIFY2(QFile::exists(expected), qPrintable("missing: " + expected));

    // POSIX mode bits on Unix; actual DACL on Windows (Qt flags are approximate).
    QVERIFY2(testFileIsOwnerOnly(expected), "send history must be owner-only");

    SentTxStore::deleteHistory();
    Settings::getInstance()->setTestnet(false);
}

// =====================================================================
// G1 — write gated by getSaveZtxs() AND by z-prefixed from-addr
// =====================================================================
void TestLogic::sentTxStore_gating() {
    Settings::getInstance()->setTestnet(false);
    QString file = QDir(sandboxAppData()).filePath("senttxstore.dat");

    auto mkTx = [](const QString& from) {
        Tx tx; tx.fromAddr = from; tx.fee = 0.0001;
        ToFields f; f.addr = addr::ZS_SAPLING; f.amount = 2.0;
        tx.toAddrs.append(f);
        return tx;
    };

    // (a) savesenttx OFF -> no write, even with a z from-addr.
    SentTxStore::deleteHistory();
    QSettings().setValue("options/savesenttx", false);
    QSettings().sync();
    SentTxStore::addToSentTx(mkTx(addr::ZS_SAPLING), "txid_a");
    QVERIFY2(!QFile::exists(file), "savesenttx=false must suppress the write");

    // (b) savesenttx ON but from-addr is a t-addr -> still no write (G1 gate).
    QSettings().setValue("options/savesenttx", true);
    QSettings().sync();
    SentTxStore::deleteHistory();
    QString tAddr = "t1KsZQNTM8N5gxRoyfcHrDrwLgxffzPpTLg";  // shape doesn't need a real checksum: addToSentTx only checks startsWith("z")
    SentTxStore::addToSentTx(mkTx(tAddr), "txid_b");
    QVERIFY2(!QFile::exists(file), "non-z from-addr must suppress the write");

    // (c) savesenttx ON + z from-addr -> write happens.
    SentTxStore::deleteHistory();
    SentTxStore::addToSentTx(mkTx(addr::ZS_SAPLING), "txid_c");
    QVERIFY2(QFile::exists(file), "z from-addr with savesenttx=true must write");

    SentTxStore::deleteHistory();
}

// Round-trip: write then read back gives one item with the aggregated amount.
void TestLogic::sentTxStore_roundTrip() {
    Settings::getInstance()->setTestnet(false);
    QSettings().setValue("options/savesenttx", true);
    QSettings().sync();
    SentTxStore::deleteHistory();

    Tx tx; tx.fromAddr = addr::ZS_SAPLING; tx.fee = 0.0001;
    ToFields f1; f1.addr = addr::ZS_ZBOARD; f1.amount = 1.0; tx.toAddrs.append(f1);
    ToFields f2; f2.addr = addr::ZC_SPROUT; f2.amount = 0.5; tx.toAddrs.append(f2);

    SentTxStore::addToSentTx(tx, "rt_txid");

    QList<TransactionItem> items = SentTxStore::readSentTxFile();
    QCOMPARE(items.size(), 1);
    QCOMPARE(items[0].txid, QString("rt_txid"));
    // amount stored = -(sum) ; read-back = amount + fee = -(1.5) + (-0.0001)
    QVERIFY(items[0].amount < 0);
    QCOMPARE(items[0].fromAddr, addr::ZS_SAPLING);

    SentTxStore::deleteHistory();
}

// =====================================================================
// H1 — db-corruption / startup-marker / long-warmup classifiers (mirror)
// =====================================================================
void TestLogic::embeddedDaemon_integrity() {
    QTemporaryDir temp;
    QVERIFY(temp.isValid());
    const QByteArray payload("fixture daemon bytes");
    QByteArray bundle("GUI");
    bundle += payload;
    bundle += QCryptographicHash::hash(payload, QCryptographicHash::Sha256);
    quint64 length = payload.size();
    for (int i = 0; i < 8; ++i) bundle += char((length >> (8 * i)) & 255);
    bundle += "ZQWDMON1";
    const QString source = temp.filePath("bundle");
    auto write = [](const QString& path, const QByteArray& bytes) {
        QFile f(path);
        return f.open(QIODevice::WriteOnly) && f.write(bytes) == bytes.size();
    };
    QVERIFY(write(source, bundle));
    QString error;
    const QString path = extractEmbeddedDaemon(source, temp.path(), &error);
    QVERIFY2(!path.isEmpty(), qPrintable(error));
#ifdef Q_OS_WIN
    QVERIFY(testFileIsOwnerOnly(path));
#else
    const auto permissions = QFile::permissions(path);
    QVERIFY(permissions & QFileDevice::ExeOwner);
    QVERIFY(permissions & QFileDevice::ReadOwner);
    QVERIFY(permissions & QFileDevice::WriteOwner);
    QVERIFY(!(permissions & (QFileDevice::ReadGroup | QFileDevice::WriteGroup |
        QFileDevice::ExeGroup | QFileDevice::ReadOther | QFileDevice::WriteOther |
        QFileDevice::ExeOther)));
#endif
    QCOMPARE(extractEmbeddedDaemon(source, temp.path(), &error), path);
    // Same-size cache corruption must be repaired, not trusted by size/name.
    QVERIFY(write(path, QByteArray(payload.size(), 'x')));
    QCOMPARE(extractEmbeddedDaemon(source, temp.path(), &error), path);
    QFile repaired(path);
    QVERIFY(repaired.open(QIODevice::ReadOnly));
    QCOMPARE(repaired.readAll(), payload);
    repaired.close();
    // Invalid source + invalid cache must fail without publishing bad bytes.
    QVERIFY(write(path, QByteArray(payload.size(), 'x')));
    bundle[3] = 'X';
    QVERIFY(write(source, bundle));
    QVERIFY(extractEmbeddedDaemon(source, temp.path(), &error).isEmpty());
    QVERIFY(error.contains("hash mismatch"));
    QVERIFY(repaired.open(QIODevice::ReadOnly));
    QCOMPARE(repaired.readAll(), QByteArray(payload.size(), 'x'));
    repaired.close();
    // Oversized and truncated footers are rejected before extraction.
    bundle[bundle.size() - 9] = char(0xff);
    QVERIFY(write(source, bundle));
    QVERIFY(extractEmbeddedDaemon(source, temp.path(), &error).isEmpty());
    QVERIFY(error.contains("length"));
    QVERIFY(write(source, "ZQWDMON1"));
    QVERIFY(extractEmbeddedDaemon(source, temp.path(), &error).isEmpty());
}
// ---------------------------------------------------------------------------
// Embedded-daemon footer: synthetic unsigned/"signed" PE fixtures and malformed
// variants. A "signed" file is [PE headers][daemon][footer][0..7 zero pad][table],
// the table named by data directory 4 (a FILE OFFSET), as Authenticode lays it out.
// ---------------------------------------------------------------------------
namespace {
QByteArray le(quint64 value, int bytes) {
    QByteArray out;
    for (int i = 0; i < bytes; ++i) out += char((value >> (8 * i)) & 255);
    return out;
}
// Minimal PE32+: MZ header, PE signature, file header, 240-byte optional header,
// no sections; SizeOfHeaders = 0x200 so the image ends at 0x200.
QByteArray fixturePe(quint32 certOffset, quint32 certSize, quint32 dirCount = 16) {
    QByteArray h(0x200, '\0');
    h.replace(0, 2, "MZ");
    h.replace(0x3c, 4, le(0x40, 4));
    h.replace(0x40, 4, QByteArray("PE\0\0", 4));
    h.replace(0x44, 2, le(0x8664, 2));             // machine
    h.replace(0x46, 2, le(0, 2));                  // NumberOfSections
    h.replace(0x54, 2, le(240, 2));                // SizeOfOptionalHeader
    const int opt = 0x58;
    h.replace(opt, 2, le(0x20b, 2));               // PE32+
    h.replace(opt + 60, 4, le(0x200, 4));          // SizeOfHeaders
    h.replace(opt + 108, 4, le(dirCount, 4));      // NumberOfRvaAndSizes
    h.replace(opt + 112 + 4 * 8, 4, le(certOffset, 4));
    h.replace(opt + 112 + 4 * 8 + 4, 4, le(certSize, 4));
    return h;
}
// length < 0: the real length. rawLength: written verbatim when not empty.
QByteArray fixtureFooter(const QByteArray& payload, qint64 length = -1,
                         const QByteArray& hash = QByteArray(),
                         const QByteArray& rawLength = QByteArray()) {
    QByteArray f = hash.isEmpty() ? QCryptographicHash::hash(payload, QCryptographicHash::Sha256) : hash;
    f += rawLength.isEmpty() ? le(quint64(length < 0 ? payload.size() : length), 8) : rawLength;
    f += "ZQWDMON1";
    return f;
}
// Signed layout. padOverride < 0: pad to 8-byte alignment like signtool.
QByteArray fixtureSigned(const QByteArray& payload, int tableSize = 64, int padOverride = -1,
                         const QByteArray& footer = QByteArray()) {
    const QByteArray foot = footer.isEmpty() ? fixtureFooter(payload) : footer;
    QByteArray body = payload + foot;
    const int pad = padOverride >= 0 ? padOverride : int((8 - (0x200 + body.size()) % 8) % 8);
    const quint32 tableOffset = quint32(0x200 + body.size() + pad);
    body += QByteArray(pad, '\0');
    return fixturePe(tableOffset, quint32(tableSize)) + body + QByteArray(tableSize, 'C');
}
quint32 le32(const QByteArray& b, int o) {
    quint32 v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | quint32(uchar(b.at(o + i)));
    return v;
}
bool fixtureWrite(const QString& path, const QByteArray& bytes) {
    QFile f(path);
    return f.open(QIODevice::WriteOnly) && f.write(bytes) == bytes.size();
}
// Extract `bundle` into a fresh cache; returns the extracted bytes (null on failure).
QByteArray fixtureExtract(const QByteArray& bundle, QString* error) {
    QTemporaryDir dir;
    if (!dir.isValid() || !fixtureWrite(dir.filePath("bundle"), bundle)) {
        *error = "fixture error";
        return QByteArray();
    }
    const QString path = extractEmbeddedDaemon(dir.filePath("bundle"), dir.filePath("cache"), error);
    if (path.isEmpty()) return QByteArray();
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}
} // namespace

void TestLogic::embeddedDaemon_footerLocation() {
    QByteArray payload;
    for (int i = 0; i < 5000; ++i) payload += char((i * 31 + 7) & 255);
    QString error;
    // Unsigned PE: footer at EOF.
    QVERIFY2(fixtureExtract(fixturePe(0, 0) + payload + fixtureFooter(payload), &error) == payload,
             qPrintable(error));
    // Signed: footer, zero pad to 8, then the certificate table. Try every alignment.
    for (int extra = 0; extra < 9; ++extra) {
        const QByteArray p = payload + QByteArray(extra, 'x');
        QVERIFY2(fixtureExtract(fixtureSigned(p), &error) == p, qPrintable(error));
    }
    // Explicit pad lengths 0..7 and a large table.
    for (int pad = 0; pad < 8; ++pad)
        QVERIFY2(fixtureExtract(fixtureSigned(payload, 4096, pad), &error) == payload,
                 qPrintable(error));
    // Pad of 8 or more is not something a signer produces: reject.
    QVERIFY(fixtureExtract(fixtureSigned(payload, 64, 8), &error).isEmpty());
    // Non-zero bytes between footer and table: reject.
    {
        QByteArray f = fixtureSigned(payload, 64, 3);
        f[0x200 + payload.size() + 48 + 1] = 'Z';
        QVERIFY(fixtureExtract(f, &error).isEmpty());
    }
    // Signed file with no footer before the table: reject, even when the table itself
    // ends in a complete footer (the footer must precede the table, not sit in it).
    {
        QByteArray table(56, 'T');
        table += fixtureFooter(payload);
        const quint32 off = quint32(0x200 + payload.size());
        QVERIFY(fixtureExtract(fixturePe(off, quint32(table.size())) + payload + table, &error).isEmpty());
        QVERIFY(error.contains("footer"));
    }
    // A PE with no certificate table but a footer that is not last: reject.
    QVERIFY(fixtureExtract(fixturePe(0, 0) + payload + fixtureFooter(payload) + QByteArray(8, 'X'),
                           &error).isEmpty());
    // Fewer than five data directories: no certificate table is declared.
    QVERIFY(fixtureExtract(fixturePe(0, 0, 4) + payload + fixtureFooter(payload), &error) == payload);
    // Certificate table declared inconsistently: ends before EOF, runs past EOF,
    // starts past EOF, zero size with a footer that is not last, starts inside the image.
    {
        const QByteArray ok = fixtureSigned(payload, 64, 0);
        const quint32 off = quint32(0x200 + payload.size() + 48);
        QVERIFY(fixtureExtract(fixturePe(off, 32) + ok.mid(0x200), &error).isEmpty());
        QVERIFY(error.contains("certificate"));
        QVERIFY(fixtureExtract(fixturePe(off, 128) + ok.mid(0x200), &error).isEmpty());
        QVERIFY(fixtureExtract(fixturePe(off + 4096, 64) + ok.mid(0x200), &error).isEmpty());
        QVERIFY(fixtureExtract(fixturePe(off, 0) + ok.mid(0x200), &error).isEmpty());
        QVERIFY(fixtureExtract(fixturePe(0x100, quint32(ok.size() - 0x100)) + ok.mid(0x200), &error).isEmpty());
    }
    // Truncations: every cut inside the footer and the certificate table, both layouts.
    {
        const QByteArray unsignedBundle = fixturePe(0, 0) + payload + fixtureFooter(payload);
        for (int cut = 1; cut <= 60; ++cut)
            QVERIFY(fixtureExtract(unsignedBundle.left(unsignedBundle.size() - cut), &error).isEmpty());
        const QByteArray signedBundle = fixtureSigned(payload);
        for (int cut = 1; cut <= 70; ++cut)
            QVERIFY(fixtureExtract(signedBundle.left(signedBundle.size() - cut), &error).isEmpty());
        QVERIFY(fixtureExtract(QByteArray("MZ"), &error).isEmpty());
        QVERIFY(fixtureExtract(fixturePe(0, 0).left(100), &error).isEmpty());
        QVERIFY(fixtureExtract(QByteArray(), &error).isEmpty());
    }
    // Wrong hash, in both layouts.
    {
        const QByteArray wrong = QCryptographicHash::hash("other", QCryptographicHash::Sha256);
        QVERIFY(fixtureExtract(fixturePe(0, 0) + payload + fixtureFooter(payload, -1, wrong), &error).isEmpty());
        QVERIFY(error.contains("hash mismatch"));
        QVERIFY(fixtureExtract(fixtureSigned(payload, 64, -1, fixtureFooter(payload, -1, wrong)), &error).isEmpty());
        QVERIFY(error.contains("hash mismatch"));
        QByteArray flipped = fixtureSigned(payload);
        flipped[0x200 + 17] = char(flipped.at(0x200 + 17) ^ 1);
        QVERIFY(fixtureExtract(flipped, &error).isEmpty());
        QVERIFY(error.contains("hash mismatch"));
    }
    // Wrong lengths: zero, past the file, past the room after the image (would overlap
    // the PE headers), 2^64-1, over the 512 MiB limit. A shorter one is a hash error.
    {
        const QByteArray head = fixturePe(0, 0);
        const QList<QByteArray> bad = {
            le(0, 8), le(quint64(payload.size() + 1), 8), le(quint64(payload.size() + 0x200), 8),
            QByteArray(8, char(0xff)), le(quint64(1) << 30, 8)};
        for (const QByteArray& raw : bad) {
            const QByteArray foot = fixtureFooter(payload, -1, QByteArray(), raw);
            QVERIFY(fixtureExtract(head + payload + foot, &error).isEmpty());
            QVERIFY2(error.contains("length"), qPrintable(error));
            QVERIFY(fixtureExtract(fixtureSigned(payload, 64, -1, foot), &error).isEmpty());
            QVERIFY2(error.contains("length"), qPrintable(error));
        }
        QVERIFY(fixtureExtract(head + payload + fixtureFooter(payload, payload.size() - 1), &error).isEmpty());
        QVERIFY(error.contains("hash mismatch"));
        // A length that exactly fills the room up to the image end is legal.
        QVERIFY2(fixtureExtract(head + payload + fixtureFooter(payload), &error) == payload,
                 qPrintable(error));
    }
    // The footer magic inside the daemon bytes, even a complete decoy footer at the end
    // of the daemon, must not confuse the locator: only the last footer counts.
    {
        const QByteArray tricky = payload.left(1000) + fixtureFooter("decoy") + payload.mid(1000) +
                                  "ZQWDMON1" + fixtureFooter("other-decoy");
        QVERIFY2(fixtureExtract(fixturePe(0, 0) + tricky + fixtureFooter(tricky), &error) == tricky,
                 qPrintable(error));
        QVERIFY2(fixtureExtract(fixtureSigned(tricky, 64, -1), &error) == tricky, qPrintable(error));
        QVERIFY2(fixtureExtract(tricky + fixtureFooter(tricky), &error) == tricky, qPrintable(error));
    }
    // Non-PE inputs (ELF, Mach-O, plain data) keep the end-of-file rule only.
    {
        const QByteArray elf = QByteArray("\x7f" "ELF") + QByteArray(100, 'e');
        QVERIFY(fixtureExtract(elf + payload + fixtureFooter(payload), &error) == payload);
        QVERIFY(fixtureExtract(elf + payload + fixtureFooter(payload) + QByteArray(8, '\0'), &error).isEmpty());
    }
    // A length that reaches back before offset 0 on a non-PE file.
    QVERIFY(fixtureExtract(fixtureFooter("abc", 10000), &error).isEmpty());
}

void TestLogic::embeddedDaemon_pinsLaunchedFile() {
    QTemporaryDir temp;
    QVERIFY(temp.isValid());
    // This very test executable is the "daemon": a real program that exits 0 for
    // -help, so a pinned file must still be launchable.
    QFile self(QCoreApplication::applicationFilePath());
    QVERIFY(self.open(QIODevice::ReadOnly));
    const QByteArray bytes = self.readAll();
    self.close();
    const QString hex = QString::fromLatin1(
        QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
    const QString dir = QDir(temp.path()).filePath("zclassic-node/" + hex);
    QVERIFY(QDir().mkpath(dir));
#ifdef Q_OS_WIN
    const QString program = QDir(dir).filePath("zqw-zclassicd.exe");
#else
    const QString program = QDir(dir).filePath("zqw-zclassicd");
    const auto ownerOnly = QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner;
    QVERIFY(QFile::setPermissions(QDir(temp.path()).filePath("zclassic-node"), ownerOnly));
    QVERIFY(QFile::setPermissions(dir, ownerOnly));
#endif
    auto write = [](const QString& path, const QByteArray& data) {
        QFile f(path);
        return f.open(QIODevice::WriteOnly) && f.write(data) == data.size();
    };
    QVERIFY(write(program, bytes));
#ifndef Q_OS_WIN
    QVERIFY(QFile::setPermissions(program, ownerOnly));
#endif
    // Not in the cache: nothing to pin.
    {
        EmbeddedDaemonPin outside(QCoreApplication::applicationFilePath(), temp.path());
        QCOMPARE(outside.status(), EmbeddedDaemonPin::NotCached);
        EmbeddedDaemonPin empty(QString(), temp.path());
        QCOMPARE(empty.status(), EmbeddedDaemonPin::NotCached);
    }
    // Verified and held: the same file can be launched while pinned.
    {
        EmbeddedDaemonPin pin(program, temp.path());
        QVERIFY2(pin.status() == EmbeddedDaemonPin::Pinned, qPrintable(pin.error()));
#ifdef Q_OS_WIN
        // The check-to-launch window is closed: no write, delete or rename of the file
        // or of the directory holding it while the pin is alive.
        QFile writer(program);
        QVERIFY(!writer.open(QIODevice::WriteOnly | QIODevice::Append));
        QVERIFY(!QFile::remove(program));
        QVERIFY(!QFile::rename(program, program + ".moved"));
        QVERIFY(!QDir().rename(dir, dir + "-moved"));
        QVERIFY(QFileInfo::exists(program));
#endif
        QProcess process;
        process.start(program, {QStringLiteral("-help")});
        QVERIFY(process.waitForStarted(15000));
        QVERIFY(process.waitForFinished(30000));
    }
    // Released: the file can be replaced again, and a swapped file is refused.
    QVERIFY(write(program, QByteArray(bytes.size(), 'x')));
    {
        EmbeddedDaemonPin pin(program, temp.path());
        QCOMPARE(pin.status(), EmbeddedDaemonPin::Failed);
        QVERIFY(pin.error().contains("hash mismatch"));
    }
    // Same size, one byte changed: refused.
    {
        QByteArray changed = bytes;
        changed[changed.size() / 2] = char(changed.at(changed.size() / 2) ^ 1);
        QVERIFY(write(program, changed));
        QCOMPARE(EmbeddedDaemonPin(program, temp.path()).status(), EmbeddedDaemonPin::Failed);
    }
    // Missing file and a non-content-addressed directory: refused, never launched.
    QVERIFY(QFile::remove(program));
    {
        QCOMPARE(EmbeddedDaemonPin(program, temp.path()).status(), EmbeddedDaemonPin::Failed);
        const QString bad = QDir(temp.path()).filePath("zclassic-node/not-a-digest");
        QVERIFY(QDir().mkpath(bad));
        QVERIFY(write(QDir(bad).filePath("zqw-zclassicd"), bytes));
        QCOMPARE(EmbeddedDaemonPin(QDir(bad).filePath("zqw-zclassicd"), temp.path()).status(),
                 EmbeddedDaemonPin::Failed);
    }
#ifndef Q_OS_WIN
    // POSIX: a group-writable program, a symbolic link or a group-writable directory
    // is refused.
    QVERIFY(write(program, bytes));
    QVERIFY(QFile::setPermissions(program, ownerOnly | QFileDevice::WriteGroup));
    QCOMPARE(EmbeddedDaemonPin(program, temp.path()).status(), EmbeddedDaemonPin::Failed);
    QVERIFY(QFile::remove(program));
    QVERIFY(write(QDir(temp.path()).filePath("real"), bytes));
    QVERIFY(QFile::link(QDir(temp.path()).filePath("real"), program));
    QCOMPARE(EmbeddedDaemonPin(program, temp.path()).status(), EmbeddedDaemonPin::Failed);
    QVERIFY(QFile::remove(program));
    QVERIFY(write(program, bytes));
    QVERIFY(QFile::setPermissions(program, ownerOnly));
    QVERIFY(QFile::setPermissions(dir, ownerOnly | QFileDevice::WriteGroup));
    QCOMPARE(EmbeddedDaemonPin(program, temp.path()).status(), EmbeddedDaemonPin::Failed);
#endif
}

// Malformed or hostile PE headers in the bundle: every damaged header is refused with
// an error (never read out of bounds, never treated as "no certificate"), section
// sizes cannot overflow, the daemon may not overlap the PE image, and the PE32
// optional-header layout is located like PE32+.
void TestLogic::embeddedDaemon_malformedPe() {
    QByteArray payload;
    for (int i = 0; i < 3000; ++i) payload += char((i * 13 + 5) & 255);
    const QByteArray foot = fixtureFooter(payload);
    QString error;
    auto patched = [](QByteArray h, int offset, quint64 value, int bytes) {
        h.replace(offset, bytes, le(value, bytes));
        return h;
    };
    const int opt = 0x58, sect = 0x58 + 240;
    // Unknown optional-header magic, optional header too small, PE32+ magic with a
    // header too small for its data directories, too many sections.
    for (const QByteArray& h : {patched(fixturePe(0, 0), opt, 0x10c, 2),
                                patched(fixturePe(0, 0), 0x54, 64, 2),
                                patched(fixturePe(0, 0), 0x54, 100, 2),
                                patched(fixturePe(0, 0), 0x46, 97, 2)}) {
        QVERIFY(fixtureExtract(h + payload + foot, &error).isEmpty());
        QVERIFY2(error.contains("Malformed PE"), qPrintable(error));
    }
    // Section table runs past the end of the file.
    QVERIFY(fixtureExtract(patched(fixturePe(0, 0), 0x46, 96, 2), &error).isEmpty());
    QVERIFY2(error.contains("Malformed PE"), qPrintable(error));
    // A section whose raw data covers the daemon: the daemon would overlap the image.
    {
        QByteArray h = patched(fixturePe(0, 0), 0x46, 1, 2);
        h = patched(h, sect + 20, 0x200, 4);                       // PointerToRawData
        h = patched(h, sect + 16, quint64(payload.size()), 4);     // SizeOfRawData
        QVERIFY(fixtureExtract(h + payload + foot, &error).isEmpty());
        QVERIFY2(error.contains("length"), qPrintable(error));
        // The same section ending exactly where the daemon starts is fine.
        h = patched(h, sect + 16, 0, 4);
        QVERIFY2(fixtureExtract(h + payload + foot, &error) == payload, qPrintable(error));
    }
    // Pointer + size that would overflow 32 bits: no wrap-around, refused.
    {
        QByteArray h = patched(fixturePe(0, 0), 0x46, 1, 2);
        h = patched(h, sect + 20, 0xffffffffu, 4);
        h = patched(h, sect + 16, 0xffffffffu, 4);
        QVERIFY(fixtureExtract(h + payload + foot, &error).isEmpty());
        QVERIFY2(error.contains("length"), qPrintable(error));
        const QByteArray ok = fixtureSigned(payload);
        QByteArray s = patched(ok.left(0x200), 0x46, 1, 2);
        s = patched(s, sect + 20, 0xffffffffu, 4);
        s = patched(s, sect + 16, 0xffffffffu, 4);
        QVERIFY(fixtureExtract(s + ok.mid(0x200), &error).isEmpty());
        QVERIFY2(error.contains("certificate"), qPrintable(error));
    }
    // A certificate table that starts inside a section is inconsistent.
    {
        const QByteArray ok = fixtureSigned(payload, 64);
        const quint32 tableOffset = quint32(le32(ok, opt + 112 + 32));
        QByteArray h = patched(ok.left(0x200), 0x46, 1, 2);
        h = patched(h, sect + 20, 0x200, 4);
        h = patched(h, sect + 16, tableOffset - 0x200 + 8, 4);
        QVERIFY(fixtureExtract(h + ok.mid(0x200), &error).isEmpty());
        QVERIFY2(error.contains("certificate"), qPrintable(error));
    }
    // A security directory beyond NumberOfRvaAndSizes is ignored: the end-of-file rule
    // applies, so a signed layout is refused and an unsigned one accepted.
    {
        const QByteArray ok = fixtureSigned(payload, 64);
        QVERIFY(fixtureExtract(patched(ok.left(0x200), opt + 108, 4, 4) + ok.mid(0x200), &error).isEmpty());
        QVERIFY(fixtureExtract(fixturePe(0x400, 64, 4) + payload + foot, &error) == payload);
    }
    // e_lfanew far past the end of the file: not a PE, end-of-file rule, no crash.
    QVERIFY(fixtureExtract(patched(fixturePe(0, 0), 0x3c, 0xfffffff0u, 4) + payload + foot, &error) == payload);
    // PE32 (magic 0x10b): data directories start at 96, the count at 92.
    {
        const QByteArray ok = fixtureSigned(payload, 64);
        const quint64 tableOffset = le32(ok, opt + 112 + 32), tableSize = le32(ok, opt + 112 + 36);
        QByteArray h(0x200, 0);
        h.replace(0, opt, ok.left(opt));
        h = patched(h, 0x54, 224, 2);
        h = patched(h, opt, 0x10b, 2);
        h = patched(h, opt + 60, 0x200, 4);
        h = patched(h, opt + 92, 16, 4);
        h = patched(h, opt + 96 + 32, tableOffset, 4);
        h = patched(h, opt + 96 + 36, tableSize, 4);
        QVERIFY2(fixtureExtract(h + ok.mid(0x200), &error) == payload, qPrintable(error));
        QVERIFY(fixtureExtract(patched(h, opt + 96 + 36, tableSize + 8, 4) + ok.mid(0x200), &error).isEmpty());
    }
}

void TestLogic::sentTxStore_invalidHistoryPreserved() {
    Settings::getInstance()->setTestnet(false);
    QSettings().setValue("options/savesenttx", true);
    SentTxStore::deleteHistory();
    const QString path = QDir(sandboxAppData()).filePath("senttxstore.dat");
    QFile file(path);
    QVERIFY(file.open(QIODevice::WriteOnly));
    const QByteArray damaged("[{incomplete-history");
    QCOMPARE(file.write(damaged), qint64(damaged.size()));
    file.close();
    Tx tx; tx.fromAddr = addr::ZS_SAPLING; tx.fee = 0.0001;
    ToFields recipient; recipient.addr = addr::ZS_ZBOARD; recipient.amount = 1;
    tx.toAddrs.append(recipient);
    SentTxStore::addToSentTx(tx, "fixture-txid");
    QVERIFY(file.open(QIODevice::ReadOnly));
    QCOMPARE(file.readAll(), damaged);
    file.close();
    SentTxStore::deleteHistory();
}

void TestLogic::dbCorruptionMarkers_data() {
    QTest::addColumn<QString>("text");
    QTest::addColumn<bool>("hit");

    QTest::newRow("empty")            << QString("")                                   << false;
    QTest::newRow("clean log")        << QString("UpdateTip: new best=abc height=100") << false;
    QTest::newRow("corrupted block")  << QString("Corrupted block database detected")  << true;
    QTest::newRow("case-insensitive") << QString("CORRUPTED BLOCK DATABASE DETECTED")  << true;
    QTest::newRow("error opening")    << QString("...\nError opening block database\n")<< true;
    QTest::newRow("failed to read")   << QString("Failed to read block")               << true;
    QTest::newRow("rebuild prompt")   << QString("Do you want to rebuild the block database now") << true;
}

void TestLogic::dbCorruptionMarkers() {
    QFETCH(QString, text);
    QFETCH(bool, hit);
    QCOMPARE(cxmirror::looksLikeDbCorruption(text), hit);
}

void TestLogic::startupMarkers_data() {
    QTest::addColumn<QString>("text");
    QTest::addColumn<bool>("hit");

    QTest::newRow("empty")          << QString("")                                  << false;
    QTest::newRow("benign")         << QString("zclassicd starting up nicely")      << false;
    QTest::newRow("lock")           << QString("Cannot obtain a lock on data dir")  << true;
    QTest::newRow("already running")<< QString("zclassicd is probably already running") << true;
    QTest::newRow("disk low")       << QString("Error: Disk space is low!")         << true;
    QTest::newRow("db newer")       << QString("requires newer version of ...")     << true;
    QTest::newRow("wallet corrupt") << QString("Wallet corrupted")                  << true;
    QTest::newRow("anchor reject")  << QString("bootstrap snapshot verification failed") << true;
    QTest::newRow("delegates to db")<< QString("Corrupted block database detected") << true;
}

void TestLogic::startupMarkers() {
    QFETCH(QString, text);
    QFETCH(bool, hit);
    QCOMPARE(cxmirror::startupDiagHasMarker(text), hit);
}

void TestLogic::longWarmupPhase_data() {
    QTest::addColumn<QString>("status");
    QTest::addColumn<bool>("hit");

    QTest::newRow("empty")           << QString("")                       << false;
    QTest::newRow("idle")            << QString("Done loading")           << false;
    QTest::newRow("verifying")       << QString("Verifying blocks 3 of 6")<< true;
    QTest::newRow("best chain")      << QString("Activating best chain...")<< true;
    QTest::newRow("loading index")   << QString("Loading block index...") << true;
    QTest::newRow("rescanning")      << QString("Rescanning... 42%")      << true;
    QTest::newRow("upgrading")       << QString("Upgrading database")     << true;
    QTest::newRow("reindexing")      << QString("Reindexing the block database: the block index is empty...") << true;
    QTest::newRow("case insens")     << QString("REWINDING blocks")       << true;
}

void TestLogic::longWarmupPhase() {
    QFETCH(QString, status);
    QFETCH(bool, hit);
    QCOMPARE(cxmirror::isLongWarmupPhase(status), hit);
}

// =====================================================================
// H2 — blocksDirSizeBytes correct byte total over a temp dir
// =====================================================================
void TestLogic::blocksDirSizeBytes() {
    // empty/unknown root -> -1
    QCOMPARE(repairBlocksSize(QString()), (qint64)-1);

    QTemporaryDir tmp;
    QVERIFY(tmp.isValid());
    QString root = tmp.path();

    // No blocks/ dir yet -> -1 ("can't measure", never a heal trigger).
    QCOMPARE(repairBlocksSize(root), (qint64)-1);

    // Build root/blocks/{blk00000.dat, index/foo.ldb} with known byte sizes.
    QDir(root).mkpath("blocks/index");
    auto writeBytes = [](const QString& path, int n) {
        QFile f(path);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write(QByteArray(n, 'x'));
        f.close();
    };
    writeBytes(QDir(root).filePath("blocks/blk00000.dat"), 1000);
    writeBytes(QDir(root).filePath("blocks/rev00000.dat"), 500);
    writeBytes(QDir(root).filePath("blocks/index/000001.ldb"), 250);

    // Recursive sum = 1000 + 500 + 250 = 1750.
    QCOMPARE(repairBlocksSize(root), (qint64)1750);

    // Coexisting testnet data must never override the selected mainnet directory.
    QString root2;
    {
        QTemporaryDir tmp2;
        QVERIFY(tmp2.isValid());
        root2 = tmp2.path();
        QDir(root2).mkpath("blocks");                 // mainnet blocks (would be 0/empty)
        QDir(root2).mkpath("testnet3/blocks");
        // mark testnet3 as the live chain
        writeBytes(QDir(root2).filePath("testnet3/debug.log"), 1);
        writeBytes(QDir(root2).filePath("testnet3/blocks/blk00000.dat"), 4096);
        QCOMPARE(repairBlocksSize(root2), (qint64)0);
        QCOMPARE(repairBlocksSize(QDir(root2).filePath("testnet3")), (qint64)4096);
    }
}

// =====================================================================
// PRIV-9 — auto-shield default is ON. CANARY: if someone flips the
// QSettings default back to false (settings.cpp getAutoShield), this goes red.
// We must assert the DEFAULT, i.e. with options/autoshield UNSET.
// =====================================================================
void TestLogic::priv9_autoShieldDefaultOn() {
    // Ensure the key is genuinely unset so we read the compiled-in default.
    QSettings().remove("options/autoshield");
    QSettings().sync();

    QVERIFY2(Settings::getInstance()->getAutoShield(),
             "PRIV-9 CANARY: getAutoShield() must default to TRUE when "
             "options/autoshield is unset (privacy-by-default flip). If this fails, "
             "someone reverted the default back to false in settings.cpp.");

    // And the setter must still round-trip both ways (off stays off, on stays on).
    Settings::getInstance()->setAutoShield(false);
    QVERIFY(!Settings::getInstance()->getAutoShield());
    Settings::getInstance()->setAutoShield(true);
    QVERIFY(Settings::getInstance()->getAutoShield());

    // Restore the unset/default state for any later test.
    QSettings().remove("options/autoshield");
    QSettings().sync();
}

// =====================================================================
// PRIV-11 / UX-12 — four-way from-aware classification, all quadrants.
// Uses real checksum-valid addresses so Settings::isT/isZ run their full path.
// =====================================================================
void TestLogic::priv11_sendClassification_data() {
    QTest::addColumn<QString>("from");
    QTest::addColumn<QString>("to");
    QTest::addColumn<int>("expected");   // SendCategory as int

    const QString T  = "t1HsdDMzmJfq4vc7T17XYjEkLMLvbgM1fCi";  // mainnet t-addr
    // z->z private (shielded from, shielded to)
    QTest::newRow("z->z private")    << addr::ZS_SAPLING << addr::ZS_ZBOARD << int(SendCategory::ZToZ_private);
    QTest::newRow("z->z sprout from")<< addr::ZC_SPROUT  << addr::ZS_SAPLING << int(SendCategory::ZToZ_private);
    // t->z shielding (transparent from, shielded to)
    QTest::newRow("t->z shielding")  << T               << addr::ZS_SAPLING << int(SendCategory::TToZ_shielding);
    // z->t de-shield (shielded from, transparent to) — the strongest warning case
    QTest::newRow("z->t deshield")   << addr::ZS_SAPLING << T               << int(SendCategory::ZToT_deshield);
    QTest::newRow("sprout->t desh")  << addr::ZC_SPROUT  << T               << int(SendCategory::ZToT_deshield);
    // t->t public (transparent from, transparent to)
    QTest::newRow("t->t public")     << T               << T               << int(SendCategory::TToT_public);
}

void TestLogic::priv11_sendClassification() {
    QFETCH(QString, from);
    QFETCH(QString, to);
    QFETCH(int, expected);

    Settings::getInstance()->setTestnet(false);

    Tx tx;
    tx.fromAddr = from;
    tx.fee = 0.0001;
    ToFields f; f.addr = to; f.amount = 1.0;
    tx.toAddrs.append(f);

    // Calls the REAL production classifier (src/sendcategory.h), the same body
    // MainWindow::classifySend forwards to — no mirror.
    QCOMPARE(int(sendCategoryOf(tx)), expected);
}

// PRIV-12: ONLY a z->t DE-SHIELD requires the acknowledgement gate; the other
// three categories MUST NOT add that friction. This drives the REAL product gate
// `isDeshieldSend()` (src/sendcategory.h — the same body MainWindow::isDeshield
// forwards to) over a real Tx per quadrant, NOT a value computed in the test. A
// z->t with MULTIPLE recipients (one transparent) must still be gated: ANY
// transparent recipient taints the whole send.
void TestLogic::priv12_onlyDeshieldIsGated_data() {
    QTest::addColumn<QString>("from");
    QTest::addColumn<QString>("to");
    QTest::addColumn<QString>("to2");   // optional 2nd recipient ("" => none)
    QTest::addColumn<bool>("gated");

    const QString T = "t1HsdDMzmJfq4vc7T17XYjEkLMLvbgM1fCi";   // mainnet t-addr

    QTest::newRow("z->z private not gated")   << addr::ZS_SAPLING << addr::ZS_ZBOARD << QString() << false;
    QTest::newRow("t->z shielding not gated") << T               << addr::ZS_SAPLING << QString() << false;
    QTest::newRow("z->t deshield GATED")      << addr::ZS_SAPLING << T               << QString() << true;
    QTest::newRow("t->t public not gated")    << T               << T               << QString() << false;
    // z -> (z, t): a single transparent recipient among shielded ones still gates.
    QTest::newRow("z->(z,t) deshield GATED")  << addr::ZS_SAPLING << addr::ZS_ZBOARD << T         << true;
}

void TestLogic::priv12_onlyDeshieldIsGated() {
    QFETCH(QString, from);
    QFETCH(QString, to);
    QFETCH(QString, to2);
    QFETCH(bool, gated);

    Settings::getInstance()->setTestnet(false);

    Tx tx;
    tx.fromAddr = from;
    tx.fee = 0.0001;
    ToFields f; f.addr = to; f.amount = 1.0;
    tx.toAddrs.append(f);
    if (!to2.isEmpty()) {
        ToFields f2; f2.addr = to2; f2.amount = 0.5;
        tx.toAddrs.append(f2);
    }

    // Calls the REAL product gate (no value recomputed inside the test).
    QCOMPARE(isDeshieldSend(tx), gated);
}

// =====================================================================
// PRIV-13 — privacy-badge classify() maps each address family correctly. Uses
// the REAL PrivacyBadgeDelegate::testClassify seam (no duplicated truth table).
// =====================================================================
void TestLogic::priv13_badgeClassify_data() {
    QTest::addColumn<QString>("display");
    QTest::addColumn<bool>("testnet");
    QTest::addColumn<int>("kind");   // PrivacyBadgeDelegate::Kind as int

    using K = PrivacyBadgeDelegate::Kind;
    QTest::newRow("sapling -> Private")        << addr::ZS_SAPLING << false << int(K::Private);
    QTest::newRow("sprout -> PrivateLegacy")   << addr::ZC_SPROUT  << false << int(K::PrivateLegacy);
    QTest::newRow("t -> Public")               << QString("t1HsdDMzmJfq4vc7T17XYjEkLMLvbgM1fCi") << false << int(K::Public);
    QTest::newRow("(Shielded) -> Private")     << QString("(Shielded)") << false << int(K::Private);
    QTest::newRow("empty -> None")             << QString("")      << false << int(K::None);
    QTest::newRow("label(addr) strip sapling") << (QString("Alice (") + addr::ZS_SAPLING + ")") << false << int(K::Private);
    QTest::newRow("testnet sapling -> Private")<< addr::ZTS_SAPLING << true  << int(K::Private);
}

void TestLogic::priv13_badgeClassify() {
    QFETCH(QString, display);
    QFETCH(bool, testnet);
    QFETCH(int, kind);

    Settings::getInstance()->setTestnet(testnet);
    QCOMPARE(int(PrivacyBadgeDelegate::testClassify(display)), kind);
    Settings::getInstance()->setTestnet(false);
}

// PRIV-13 — Deshield is promoted ONLY for a Public (transparent) recipient on a
// row whose Type cell (col 0) contains send/sent. A transparent recipient on a
// receive row stays Public; a shielded recipient never becomes Deshield.
void TestLogic::priv13_deshieldOnlyForPublicSendRow() {
    using K = PrivacyBadgeDelegate::Kind;
    Settings::getInstance()->setTestnet(false);

    const QString T  = "t1HsdDMzmJfq4vc7T17XYjEkLMLvbgM1fCi";
    const QString ZS = addr::ZS_SAPLING;

    // A model with col0 = Type, col1 = Address (mirrors the transactions table).
    QStandardItemModel model(3, 2);
    model.setData(model.index(0, 0), "send");      model.setData(model.index(0, 1), T);
    model.setData(model.index(1, 0), "receive");   model.setData(model.index(1, 1), T);
    model.setData(model.index(2, 0), "send");      model.setData(model.index(2, 1), ZS);

    // send + transparent recipient -> Deshield (the privacy-leaking case).
    QCOMPARE(int(PrivacyBadgeDelegate::testClassifyForIndex(model.index(0, 1), T)),  int(K::Deshield));
    // receive + transparent -> stays Public (incoming public funds, not a leak).
    QCOMPARE(int(PrivacyBadgeDelegate::testClassifyForIndex(model.index(1, 1), T)),  int(K::Public));
    // send + shielded recipient -> Private (never Deshield).
    QCOMPARE(int(PrivacyBadgeDelegate::testClassifyForIndex(model.index(2, 1), ZS)), int(K::Private));

    // No model / no Type column -> the bare classify() result (Public), never Deshield.
    QCOMPARE(int(PrivacyBadgeDelegate::testClassifyForIndex(QModelIndex(), T)), int(K::Public));
}

// UX: an ordinary transparent payment (t -> t) was badged as a red "De-shield", which says
// private funds leaked when none did. When the model says where the money came from
// (PrivacyBadgeDelegate::FromAddrRole), only a send FROM a shielded address is a de-shield.
void TestLogic::priv13_transparentSendIsNotDeshield() {
    using K = PrivacyBadgeDelegate::Kind;
    Settings::getInstance()->setTestnet(false);
    const QString T  = "t1HsdDMzmJfq4vc7T17XYjEkLMLvbgM1fCi";
    const QString ZS = addr::ZS_SAPLING;

    QStandardItemModel model(3, 2);
    const int R = PrivacyBadgeDelegate::FromAddrRole;
    // row 0: sent to a t-address, from a t-address (the wallet's own history rows: empty from)
    model.setData(model.index(0, 0), "send"); model.setData(model.index(0, 1), T);
    model.setData(model.index(0, 0), QString(), R);
    // row 1: sent to a t-address FROM a shielded address -> the real de-shield
    model.setData(model.index(1, 0), "send"); model.setData(model.index(1, 1), T);
    model.setData(model.index(1, 0), ZS, R);
    // row 2: sent to a t-address from another t-address
    model.setData(model.index(2, 0), "send"); model.setData(model.index(2, 1), T);
    model.setData(model.index(2, 0), T, R);

    QCOMPARE(int(PrivacyBadgeDelegate::testClassifyForIndex(model.index(0, 1), T)), int(K::Public));
    QCOMPARE(int(PrivacyBadgeDelegate::testClassifyForIndex(model.index(1, 1), T)), int(K::Deshield));
    QCOMPARE(int(PrivacyBadgeDelegate::testClassifyForIndex(model.index(2, 1), T)), int(K::Public));
}

// UX: the Activity list sizes its Amount column from the delegate's sizeHint. That hint
// was measured in the default font but the amount is painted in the wider monospace
// face, so the column came out too narrow and a sent amount lost its leading "-".
void TestLogic::priv13_amountColumnFitsSignedAmount() {
    QStandardItemModel model(1, 1);
    const QString text = "-1.52000245 ZCL";
    model.setData(model.index(0, 0), text);
    PrivacyBadgeDelegate d(PrivacyBadgeDelegate::Mode::Amount);
    QStyleOptionViewItem opt;
    opt.font = QApplication::font();
    QFont mono = PrivacyBadgeDelegate::testMonoFont();
    mono.setPointSizeF(opt.font.pointSizeF() > 0 ? opt.font.pointSizeF() : mono.pointSizeF());
    const int need = QFontMetrics(mono).horizontalAdvance(text) + 16;   // 8px padding each side
    QVERIFY2(d.sizeHint(opt, model.index(0, 0)).width() >= need,
             qPrintable(QString("hint %1 < painted %2").arg(d.sizeHint(opt, model.index(0, 0)).width()).arg(need)));
}

// =====================================================================
// PRIV-14 — badge label + colour hex tokens. The hex MUST match dark.qss:
//   green #1f7a1f (Private/Legacy), amber #d9822b (Public), red #c0392b (Deshield).
// We also grep the shipped res/styles/dark.qss for the same tokens so the badge
// and the stylesheet can never silently drift apart.
// =====================================================================
void TestLogic::priv14_badgeColorTokens() {
    using K = PrivacyBadgeDelegate::Kind;

    // Labels.
    QCOMPARE(PrivacyBadgeDelegate::testLabelFor(K::Private),       QString("Private"));
    QCOMPARE(PrivacyBadgeDelegate::testLabelFor(K::PrivateLegacy), QString("Private (legacy)"));
    QCOMPARE(PrivacyBadgeDelegate::testLabelFor(K::Public),        QString("PUBLIC"));
    QCOMPARE(PrivacyBadgeDelegate::testLabelFor(K::Deshield),      QString("De-shield"));

    // Colour hex (QColor::name() is lower-case "#rrggbb").
    QCOMPARE(PrivacyBadgeDelegate::testColorHexFor(K::Private),       QString("#1f7a1f"));
    QCOMPARE(PrivacyBadgeDelegate::testColorHexFor(K::PrivateLegacy), QString("#1f7a1f"));
    QCOMPARE(PrivacyBadgeDelegate::testColorHexFor(K::Public),        QString("#d9822b"));
    QCOMPARE(PrivacyBadgeDelegate::testColorHexFor(K::Deshield),      QString("#c0392b"));

    // Guard: the SAME hex tokens must be present in the shipped dark.qss. Resolve
    // the stylesheet relative to this test file's source dir (set by qmake via
    // QT_TESTCASE_BUILDDIR = the tests/ dir; dark.qss lives at ../res/styles).
    QStringList candidates = {
        QStringLiteral(QT_TESTCASE_BUILDDIR) + "/../res/styles/dark.qss",
        QFINDTESTDATA("../res/styles/dark.qss"),
    };
    QString qss;
    for (const QString& c : candidates) {
        if (c.isEmpty()) continue;
        QFile f(c);
        if (f.open(QIODevice::ReadOnly)) { qss = QString::fromUtf8(f.readAll()); break; }
    }
    QVERIFY2(!qss.isEmpty(), "could not locate res/styles/dark.qss to guard the colour tokens");

    // NIT-4: strip C-style /* ... */ comments before grepping, so the guard proves
    // each token backs a REAL rule (not just a mention in the header legend). A token
    // present only inside a comment must NOT satisfy the guard. Manual single-pass
    // strip (avoids QRegExp greedy-match foot-guns across multiple comment blocks).
    QString code;
    {
        int i = 0;
        while (i < qss.length()) {
            if (i + 1 < qss.length() && qss[i] == '/' && qss[i+1] == '*') {
                int end = qss.indexOf("*/", i + 2);
                if (end < 0) break;          // unterminated comment -> drop the rest
                i = end + 2;
            } else {
                code.append(qss[i]);
                ++i;
            }
        }
    }

    QVERIFY2(code.contains("#1f7a1f", Qt::CaseInsensitive),
             "dark.qss missing green token #1f7a1f in a REAL (non-comment) rule");
    QVERIFY2(code.contains("#d9822b", Qt::CaseInsensitive),
             "dark.qss missing amber token #d9822b in a REAL (non-comment) rule");
    QVERIFY2(code.contains("#c0392b", Qt::CaseInsensitive),
             "dark.qss missing red token #c0392b in a REAL (non-comment) rule");
}

// ---------------------------------------------------------------------------
// CONF-1 / NOTIFY-SRV — the wallet's secrets (rpcpassword + per-session notify
// token) MUST come from the system CSPRNG with >= 128 bits. The first two tests
// exercise the shared securerandom.h body DIRECTLY (a short / weak / charset-
// stuck generator inside the header fails their length + bit-floor + charset-
// coverage asserts). connection.cpp — which holds randomPassword() — is too heavy
// to link into this guiless suite, so the third test (conf1_randomPasswordUsesCSPRNG)
// is a STATIC guard that pins the delegation: the conf writer must call
// secureRandomBase62() and contain no raw rand()/qrand(), catching a caller that
// diverges back to a weak RNG.
// ---------------------------------------------------------------------------
void TestLogic::conf1_passwordHighEntropyCSPRNG() {
    // Default length is 32 base62 chars (the value randomPassword() uses).
    const QString pw = secureRandomBase62();
    QCOMPARE(pw.length(), 32);

    // Bit floor: chars * log2(62) must clear the 128-bit CONF-1 requirement.
    const double bits = pw.length() * 5.9541963;   // log2(62)
    QVERIFY2(bits >= 128.0,
             qPrintable(QString("rpcpassword entropy %1 bits < 128").arg(bits, 0, 'f', 1)));

    // Charset: every character is base62 [0-9A-Za-z] (conf-parser-safe — no
    // whitespace, '#', '=' or newline that could corrupt a key=value line).
    const QString allowed =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (const QChar c : pw)
        QVERIFY2(allowed.contains(c),
                 qPrintable(QString("rpcpassword has non-base62 char '%1'").arg(c)));

    // CSPRNG sanity over a large sample: every value distinct (collision among
    // ~190-bit strings is astronomically impossible — a constant/buggy generator
    // would collide), and the full 62-symbol alphabet is exercised (a generator
    // stuck on a subset — e.g. digits only — would be caught).
    QSet<QString> seen;
    QSet<QChar>   chars;
    const int N = 512;
    for (int i = 0; i < N; ++i) {
        const QString s = secureRandomBase62();
        seen.insert(s);
        for (const QChar c : s) chars.insert(c);
    }
    QCOMPARE(seen.size(), N);                 // no repeats across 512 draws
    QVERIFY2(chars.size() >= 60,
             qPrintable(QString("only %1/62 base62 symbols seen across %2 samples — "
                                "generator may be stuck on a subset").arg(chars.size()).arg(N)));

    // Explicit length is honored (used to mint shorter/longer secrets if needed).
    QCOMPARE(secureRandomBase62(22).length(), 22);   // ~131 bits, the 128-bit minimum
}

void TestLogic::conf1_notifyTokenHexFormat() {
    // The notify token MUST match the on-the-wire NOTIFY-SRV payload contract
    // exactly: 64 lowercase-hex chars (32 bytes = 256 bits). Validated here so the
    // listener's `^[0-9a-f]{64}$` guard and the token minter agree by construction.
    const QRegularExpression re("^[0-9a-f]{64}$");
    const QString tok = secureRandomHex();
    QCOMPARE(tok.length(), 64);
    QVERIFY2(re.match(tok).hasMatch(),
             qPrintable("notify token not 64 lowercase-hex chars: " + tok));

    // Distinctness over a large sample (no repeats; full nibble alphabet seen).
    QSet<QString> seen;
    QSet<QChar>   nibbles;
    const int N = 512;
    for (int i = 0; i < N; ++i) {
        const QString s = secureRandomHex();
        QVERIFY(re.match(s).hasMatch());
        seen.insert(s);
        for (const QChar c : s) nibbles.insert(c);
    }
    QCOMPARE(seen.size(), N);
    QCOMPARE(nibbles.size(), 16);            // all of 0-9a-f exercised

    // Explicit byte count is honored: 16 bytes -> 32 hex chars (128 bits).
    QCOMPARE(secureRandomHex(16).length(), 32);
}

void TestLogic::conf1_randomPasswordUsesCSPRNG() {
    // Locate connection.cpp the same way priv14 finds dark.qss (QT_TESTCASE_BUILDDIR
    // is the tests/ dir; src/ is its sibling).
    QStringList candidates = {
        QStringLiteral(QT_TESTCASE_BUILDDIR) + "/../src/connection.cpp",
        QFINDTESTDATA("../src/connection.cpp"),
    };
    QString src;
    for (const QString& c : candidates) {
        if (c.isEmpty()) continue;
        QFile f(c);
        if (f.open(QIODevice::ReadOnly)) { src = QString::fromUtf8(f.readAll()); break; }
    }
    QVERIFY2(!src.isEmpty(), "could not locate src/connection.cpp for the CSPRNG caller guard");

    // Strip // line + /* ... */ block comments so a 'rand()' written in PROSE (the
    // comments here deliberately document the OLD weak generator) cannot fool the
    // guard. We assert on the remaining real code only.
    QString code;
    {
        int i = 0, n = src.length();
        while (i < n) {
            if (i + 1 < n && src[i] == '/' && src[i+1] == '/') {
                int end = src.indexOf('\n', i + 2);
                if (end < 0) break;
                i = end;                          // keep the newline
            } else if (i + 1 < n && src[i] == '/' && src[i+1] == '*') {
                int end = src.indexOf("*/", i + 2);
                if (end < 0) break;
                i = end + 2;
            } else {
                code.append(src[i]);
                ++i;
            }
        }
    }

    QVERIFY2(code.contains("secureRandomBase62"),
             "connection.cpp must mint the rpcpassword via secureRandomBase62() (CONF-1)");
    // 'rand()' (lowercase + parens) matches the weak C RNG but NOT QRandomGenerator
    // ('Random', capital R, no parens) — so this fires only on a real regression.
    QVERIFY2(!code.contains("rand()"),
             "connection.cpp calls rand() in real code — CONF-1 forbids the weak/predictable RNG");
    QVERIFY2(!code.contains("qrand"),
             "connection.cpp uses qrand() — CONF-1 requires QRandomGenerator::system()");
}

// =====================================================================
// Hardening guards (ITEMs 2-5)
//
// ITEMs 2/3 live in connection.cpp and ITEMs 4/5 in notifyserver.cpp; the
// behavior (gating launch-args on socketReady, reading conf perms back,
// logging a connector failure, a 0700 temp-fallback dir) is wired into Qt
// process/socket plumbing that the L0 binary does not link. These are
// SOURCE-TEXT divergence guards in the SAME STYLE as
// conf1_randomPasswordUsesCSPRNG() above: they read the real source and assert
// the safety wiring is present, so a regression that silently drops it fails
// the suite. ITEM 5 ALSO has a behavioral test below (the dir-creation logic is
// small enough to mirror and verify the resulting perms are owner-only).
// =====================================================================

// Locate + comment-strip a src/ file the same way conf1_randomPasswordUsesCSPRNG does.
static QString readStrippedSrc(const QString& relName) {
    QStringList candidates = {
        QStringLiteral(QT_TESTCASE_BUILDDIR) + "/../src/" + relName,
        QFINDTESTDATA("../src/" + relName),
    };
    QString src;
    for (const QString& c : candidates) {
        if (c.isEmpty()) continue;
        QFile f(c);
        if (f.open(QIODevice::ReadOnly)) { src = QString::fromUtf8(f.readAll()); break; }
    }
    if (src.isEmpty()) return QString();

    QString code;
    int i = 0, n = src.length();
    while (i < n) {
        if (i + 1 < n && src[i] == '/' && src[i+1] == '/') {
            int end = src.indexOf('\n', i + 2);
            if (end < 0) break;
            i = end;
        } else if (i + 1 < n && src[i] == '/' && src[i+1] == '*') {
            int end = src.indexOf("*/", i + 2);
            if (end < 0) break;
            i = end + 2;
        } else {
            code.append(src[i]);
            ++i;
        }
    }
    return code;
}

// ITEM 5 behavioral: the SHARED-temp fallback must yield an owner-only (0700) dir.
// notifyRuntimeDir()'s fallback is file-static + not linked here, so mirror its exact
// dir-creation steps into the test sandbox and assert the resulting perms confine access.
void TestLogic::notify_tempFallbackDirIsOwnerOnly() {
#ifdef Q_OS_WIN
    QSKIP("POSIX dir-perm check; Windows uses ACLs (setPermissions) not mode bits");
#else
    // A throwaway "shared temp" root, then the per-user subdir the real code carves out.
    const QString temp = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    const QString sub  = QStringLiteral("zqw-test-%1").arg((uint)::getuid());
    const QString dir  = QDir(temp).filePath(sub);
    QDir().rmdir(dir);                       // clean slate (ignore if absent)
    QDir().mkpath(dir);
    QFile::setPermissions(dir, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);

    QVERIFY2(QFileInfo(dir).isDir(), qPrintable("fallback dir not created: " + dir));
    QFile::Permissions p = QFile::permissions(dir);
    // Owner may traverse; group/other must have NOTHING (0700 confinement).
    QVERIFY(p.testFlag(QFileDevice::ReadOwner));
    QVERIFY(p.testFlag(QFileDevice::WriteOwner));
    QVERIFY(p.testFlag(QFileDevice::ExeOwner));
    QVERIFY(!p.testFlag(QFileDevice::ReadGroup));
    QVERIFY(!p.testFlag(QFileDevice::WriteGroup));
    QVERIFY(!p.testFlag(QFileDevice::ExeGroup));
    QVERIFY(!p.testFlag(QFileDevice::ReadOther));
    QVERIFY(!p.testFlag(QFileDevice::WriteOther));
    QVERIFY(!p.testFlag(QFileDevice::ExeOther));

    QDir().rmdir(dir);                       // tidy up
#endif
}

// ITEM 5 source guard: notifyRuntimeDir() must harden the TempLocation fallback with a
// per-user subdir + mkpath + 0700 setPermissions (NOT return the shared temp dir bare).
void TestLogic::notify_runtimeDirHardensTempFallback() {
    const QString code = readStrippedSrc("notifyserver.cpp");
    QVERIFY2(!code.isEmpty(), "could not locate src/notifyserver.cpp");
    QVERIFY2(code.contains("TempLocation"),
             "notifyserver.cpp no longer references TempLocation fallback");
    QVERIFY2(code.contains("mkpath"),
             "ITEM 5: temp fallback must mkpath a per-user subdir");
    QVERIFY2(code.contains("setPermissions") && code.contains("ExeOwner"),
             "ITEM 5: temp fallback subdir must be narrowed to owner-only (0700) perms");
}

// ITEM 4 source guard: runConnector() must emit a stderr diagnostic on a non-zero
// sendNotify() result (the headless connector has no logger). No secret is printed.
void TestLogic::notify_connectorLogsFailureToStderr() {
    const QString code = readStrippedSrc("notifyserver.cpp");
    QVERIFY2(!code.isEmpty(), "could not locate src/notifyserver.cpp");
    QVERIFY2(code.contains("fprintf(stderr") || code.contains("qWarning"),
             "ITEM 4: runConnector must log a connector failure to stderr/qWarning");
    // Defense-in-depth: no stderr/qWarning diagnostic line may interpolate the token.
    static const QRegularExpression leakyDiag(
        "(fprintf\\s*\\(\\s*stderr|qWarning\\s*\\(\\s*)[^;]*token", QRegularExpression::DotMatchesEverythingOption);
    QVERIFY2(!leakyDiag.match(code).hasMatch(),
             "ITEM 4: the connector diagnostic must not print the token/secret");
}

// ITEM 2 source guard: the -walletnotify/-blocknotify launch-args must be gated on the
// socket having actually started (a notifyReady/isListening flag), NOT appended
// unconditionally whenever a NotifyServer object merely exists.
void TestLogic::notify_launchArgsGatedOnSocketReady() {
    const QString code = readStrippedSrc("connection.cpp");
    QVERIFY2(!code.isEmpty(), "could not locate src/connection.cpp");
    QVERIFY2(code.contains("isListening"),
             "ITEM 2: notify launch-args must consult the socket's isListening() state");
    QVERIFY2(code.contains("buildNotifyArgs"),
             "connection.cpp no longer wires buildNotifyArgs (regression?)");
    // The gate guard ('if (notifyReady)') and the append must both be present, and the
    // append must be reached THROUGH the gate — not the old unconditional
    // 'if (rpc && rpc->getNotifyServer()) ... buildNotifyArgs'.
    QVERIFY2(code.contains("notifyReady"),
             "ITEM 2: a notifyReady gate flag must guard the buildNotifyArgs append");
    const int gateIdx   = code.indexOf("if (notifyReady)");
    const int appendIdx = code.indexOf("launchArgs.append(RPC::buildNotifyArgs");
    QVERIFY2(gateIdx >= 0 && appendIdx > gateIdx,
             "ITEM 2: buildNotifyArgs must be appended only inside the notifyReady gate");
}

// ITEM 3 source guard: createZClassicConf() must READ the perms back from disk after the
// setPermissions(0600) call and log a diagnostic if group/other bits remain (best-effort,
// never aborts). The diagnostic must not echo the rpcpassword.
void TestLogic::conf_permsVerifiedAfterWrite() {
    const QString code = readStrippedSrc("connection.cpp");
    QVERIFY2(!code.isEmpty(), "could not locate src/connection.cpp");
    // Read-back of the on-disk perms after the write.
    QVERIFY2(code.contains("QFile::permissions(confLocation)"),
             "ITEM 3: createZClassicConf must read the conf perms back from disk");
    // Tests for any group/other access bit and logs about it.
    QVERIFY2(code.contains("ReadGroup") && code.contains("ReadOther"),
             "ITEM 3: the verify must test for group/other read/write bits");
    QVERIFY2(code.contains("could not be secured to 0600"),
             "ITEM 3: a clear 0600 diagnostic must be logged when the conf stays leaky");
}

// First-run trust: the send gate must ignore a FROZEN isSyncing flag (a poll that
// stopped refreshing) so a wedged flag can't imply a fresh sync problem — but must
// NOT treat a fresh flag, or a never-polled flag, as stale. Pure boundary check.
void TestLogic::sendgate_staleWhenPollStops() {
    const qint64 W = Settings::kSyncGateStaleSecs;   // window (180s)
    const qint64 now = 1'000'000;
    // Never polled yet (last==0): NOT stale -> let the normal gate run.
    QVERIFY(!Settings::syncGateIsStale(now, 0));
    // Fresh poll: not stale.
    QVERIFY(!Settings::syncGateIsStale(now, now));
    // Just inside the window: not stale.
    QVERIFY(!Settings::syncGateIsStale(now, now - (W - 1)));
    // Exactly at the window edge: not stale (uses '>' not '>=').
    QVERIFY(!Settings::syncGateIsStale(now, now - W));
    // Past the window: stale.
    QVERIFY(Settings::syncGateIsStale(now, now - (W + 1)));
    QVERIFY(Settings::syncGateIsStale(now, now - 10 * W));
}

// ---- Profile override (ZCLWALLET_PROFILE_DIR) -------------------------------------
// Unset => helpers return exactly the pre-override locations; set => every helper
// resolves inside the profile; settings become IniFormat files inside it.
void TestLogic::profile_unsetKeepsDefaults() {
    qunsetenv("ZCLWALLET_PROFILE_DIR");
    qunsetenv("ZCLWALLET_PARAMS_DIR");
    QVERIFY(!ProfilePaths::active());
    QVERIFY(ProfilePaths::valid());
    QCOMPARE(ProfilePaths::appDataDir(), QStandardPaths::writableLocation(QStandardPaths::AppDataLocation));
    QCOMPARE(ProfilePaths::cacheDir(), QStandardPaths::writableLocation(QStandardPaths::CacheLocation));
    QVERIFY(ProfilePaths::runtimeDir().isEmpty());
    QVERIFY(ProfilePaths::exportsDir().isEmpty());
    QVERIFY(ProfilePaths::fontconfigRoot().isEmpty());
    QVERIFY(ProfilePaths::zclassicDataDir().isEmpty());
    QVERIFY(ProfilePaths::zclassicConfPath().isEmpty());
    QVERIFY(ProfilePaths::daemonArgs().isEmpty());          // no -datadir: daemon default
    QVERIFY(ProfilePaths::titleMarker().isEmpty());
    QCOMPARE(ProfilePaths::paramsDir("/default/params"), QString("/default/params"));
    const auto before = QSettings::defaultFormat();
    ProfilePaths::applySettings();                           // must be a no-op
    QCOMPARE(QSettings::defaultFormat(), before);
}

void TestLogic::profile_setRedirectsEveryPath() {
    QTemporaryDir tmp;
    QVERIFY(tmp.isValid());
    const QString root = QDir::cleanPath(QFileInfo(tmp.path()).absoluteFilePath());
    qputenv("ZCLWALLET_PROFILE_DIR", root.toLocal8Bit());
    qunsetenv("ZCLWALLET_PARAMS_DIR");
    auto under = [&](const QString& p) {
        return QDir::cleanPath(p) == root || QDir::cleanPath(p).startsWith(root + "/");
    };
    QVERIFY(ProfilePaths::active());
    QVERIFY(ProfilePaths::valid());
    QCOMPARE(ProfilePaths::dir(), root);
    const QStringList all = {
        ProfilePaths::appDataDir(), ProfilePaths::cacheDir(), ProfilePaths::runtimeDir(),
        ProfilePaths::exportsDir(), ProfilePaths::fontconfigRoot(),
        ProfilePaths::zclassicDataDir(), ProfilePaths::zclassicConfPath(),
    };
    for (const QString& p : all) {
        QVERIFY2(!p.isEmpty(), "profile helper returned an empty path");
        QVERIFY2(under(p), qPrintable("outside the profile: " + p));
    }
    QCOMPARE(ProfilePaths::zclassicConfPath(), root + "/ZClassic/zclassic.conf");
    // The embedded daemon must be pinned to the profile datadir, never its default.
    const QStringList args = ProfilePaths::daemonArgs();
    QCOMPARE(args.size(), 1);
    QVERIFY(args[0].startsWith("-datadir="));
    QVERIFY2(under(QDir::fromNativeSeparators(args[0].mid(9))), qPrintable(args[0]));
    QVERIFY(ProfilePaths::titleMarker().contains("profile:"));
    // Params keep their default unless ZCLWALLET_PARAMS_DIR says otherwise.
    QCOMPARE(ProfilePaths::paramsDir("/default/params"), QString("/default/params"));
    qputenv("ZCLWALLET_PARAMS_DIR", (root + "/params").toLocal8Bit());
    QVERIFY(under(ProfilePaths::paramsDir("/default/params")));
    // A set-but-missing profile dir is invalid (main() refuses to start).
    qputenv("ZCLWALLET_PROFILE_DIR", (root + "/does-not-exist").toLocal8Bit());
    QVERIFY(!ProfilePaths::valid());
    qunsetenv("ZCLWALLET_PROFILE_DIR");
    qunsetenv("ZCLWALLET_PARAMS_DIR");
}

void TestLogic::profile_settingsAreIniInsideProfile() {
    QTemporaryDir tmp;
    QVERIFY(tmp.isValid());
    const QString root = QDir::cleanPath(QFileInfo(tmp.path()).absoluteFilePath());
    qputenv("ZCLWALLET_PROFILE_DIR", root.toLocal8Bit());
    const QString oldOrg = QCoreApplication::organizationName(), oldApp = QCoreApplication::applicationName();
    QCoreApplication::setOrganizationName("profile-test-org");
    QCoreApplication::setApplicationName("profile-test-app");
    const auto fmt = QSettings::defaultFormat();
    ProfilePaths::applySettings();
    QCOMPARE(QSettings::defaultFormat(), QSettings::IniFormat);
    {
        // The wallet only ever uses the default constructor (QSettings s;).
        QSettings s;
        QCOMPARE(s.format(), QSettings::IniFormat);
        s.setValue("k", 1);
        s.sync();
        QVERIFY2(QDir::cleanPath(s.fileName()).startsWith(root + "/"), qPrintable(s.fileName()));
        QVERIFY(QFileInfo::exists(s.fileName()));
    }
    {
        QSettings sys(QSettings::IniFormat, QSettings::SystemScope, "o", "a");
        QVERIFY2(QDir::cleanPath(sys.fileName()).startsWith(root + "/"), qPrintable(sys.fileName()));
    }
    QSettings::setDefaultFormat(fmt);
    qunsetenv("ZCLWALLET_PROFILE_DIR");
    QCoreApplication::setOrganizationName(oldOrg);
    QCoreApplication::setApplicationName(oldApp);
}

// Source guard: no state location is decided outside ProfilePaths any more.
void TestLogic::profile_noDirectStateLocations() {
    for (const char* f : {"addressbook.cpp", "senttxstore.cpp", "turnstile.cpp", "mainwindow.cpp",
                          "connection.cpp", "notifyserver.cpp", "main.cpp"}) {
        const QString code = readStrippedSrc(f);
        QVERIFY2(!code.isEmpty(), f);
        QVERIFY2(!code.contains("QStandardPaths::AppDataLocation") ||
                 QString(f) == "connection.cpp" /* legacy conf path in the inactive branch */,
                 f);
        QVERIFY2(!code.contains("QStandardPaths::CacheLocation"), f);
    }
    const QString conn = readStrippedSrc("connection.cpp");
    QVERIFY2(conn.contains("ProfilePaths::daemonArgs()"), "embedded launch must pin -datadir under a profile");
    QVERIFY2(conn.contains("ProfilePaths::zclassicConfPath()"), "conf lookup must honour the profile");
    // A conf datadir= line must not steer cookie/repair/backup paths outside the profile.
    QVERIFY2(conn.contains("zclassicconf->dataDirOverride.clear()"),
             "profile override must ignore a conf datadir= line");
}

// Isolation requested but empty/blank must fail closed (exit 2 in main), never mean "use
// the real profile"; pin() canonicalizes once so cwd changes and symlink aliases agree.
void TestLogic::profile_blankValueFailsClosed() {
    qunsetenv("ZCLWALLET_PROFILE_DIR");
    QVERIFY(ProfilePaths::valid());
    qputenv("ZCLWALLET_PROFILE_DIR", QByteArray(""));
    if (qEnvironmentVariableIsSet("ZCLWALLET_PROFILE_DIR"))   // empty values are unsettable on Windows
        QVERIFY2(!ProfilePaths::valid(), "set-but-empty profile dir must be invalid");
    qputenv("ZCLWALLET_PROFILE_DIR", QByteArray("   "));
    QVERIFY2(!ProfilePaths::valid(), "blank profile dir must be invalid");
    qunsetenv("ZCLWALLET_PROFILE_DIR");

    auto consume = [](QList<QByteArray> words) {
        QList<QByteArray> store = words;
        std::vector<char*> argv;
        for (auto& w : store) argv.push_back(w.data());
        return ProfilePaths::consumeArgs(static_cast<int>(argv.size()), argv.data());
    };
    QVERIFY(!consume({"zclwallet", "--profile-dir="}));
    QVERIFY(!consume({"zclwallet", "--profile-dir", ""}));
    QVERIFY(!consume({"zclwallet", "--profile-dir", " "}));
    QVERIFY(!consume({"zclwallet", "--profile-dir"}));
    QVERIFY(!qEnvironmentVariableIsSet("ZCLWALLET_PROFILE_DIR"));
    QVERIFY(consume({"zclwallet"}));
    QVERIFY(!qEnvironmentVariableIsSet("ZCLWALLET_PROFILE_DIR"));

    QTemporaryDir tmp;
    QVERIFY(tmp.isValid());
    const QString canon = QFileInfo(tmp.path()).canonicalFilePath();
    QVERIFY(consume({"zclwallet", QByteArray("--profile-dir=") + (tmp.path() + "/.").toLocal8Bit()}));
    QVERIFY(ProfilePaths::valid());
    ProfilePaths::pin();
    QCOMPARE(QString::fromLocal8Bit(qgetenv("ZCLWALLET_PROFILE_DIR")), canon);
    qunsetenv("ZCLWALLET_PROFILE_DIR");
}

// Source guard: the embedded daemon is only ever launched through DaemonJob::start(). A bare
// QProcess::start() (or a `started` signal hook, which ConnectionLoader drops on handoff to
// RPC) would leave a daemon restarted after an unexpected exit without the kill-on-close job.
void TestLogic::daemonjob_everyLaunchPathUsesTheJob() {
    for (const char* f : {"connection.cpp", "rpc.cpp"}) {
        const QString code = readStrippedSrc(f);
        QVERIFY2(!code.isEmpty(), f);
        QVERIFY2(!code.contains(QRegularExpression(R"(ezclassicd\s*->\s*start\s*\()")),
                 qPrintable(QString("%1 launches the daemon without DaemonJob::start").arg(f)));
        QVERIFY2(!code.contains("DaemonJob::bind"), f);
    }
    QVERIFY(readStrippedSrc("connection.cpp").contains("DaemonJob::start(ezclassicd"));
    QVERIFY(readStrippedSrc("rpc.cpp").contains("DaemonJob::start(ezclassicd"));
    QVERIFY(readStrippedSrc("rpc.cpp").contains("DaemonJob::disarm()"));
}

// Windows: a started child is in an armed job BEFORE it runs, the job handle is not
// inheritable, disarm() really clears kill-on-close, and a RESTART of the same QProcess
// (what RPC::restartEmbeddedZClassicd does) is bound and armed again. Elsewhere: no-op.
void TestLogic::daemonjob_armedAfterEveryStart() {
#ifndef Q_OS_WIN
    QSKIP("Windows job-object backstop only");
#else
    QProcess p;
    const QString ping = QStringLiteral("ping.exe");
    const QStringList args{"-n", "2", "127.0.0.1"};
    for (int round = 0; round < 3; ++round) {
        QCOMPARE(DaemonJob::start(&p, ping, args), 0ul);
        QVERIFY2(p.state() == QProcess::Running, "child must be resumed and running");
        QVERIFY2(DaemonJob::isInJob(&p), qPrintable(QString("round %1 not in job").arg(round)));
        QVERIFY2(DaemonJob::isArmed(&p), qPrintable(QString("round %1 not armed").arg(round)));
        DWORD flags = 0;
        QVERIFY(GetHandleInformation(DaemonJob::entries().back().job, &flags));
        QVERIFY2(!(flags & HANDLE_FLAG_INHERIT), "job handle must not be inheritable");
        if (round == 1) {
            DaemonJob::disarm();
            QVERIFY(DaemonJob::isInJob(&p));
            QVERIFY2(!DaemonJob::isArmed(&p), "disarm must clear kill-on-close");
        }
        QVERIFY2(p.waitForFinished(15000), "resumed child must run to completion");
        QCOMPARE(p.exitStatus(), QProcess::NormalExit);
    }
    // A launch that fails to start has nothing to bind and leaks no job.
    QProcess bad;
    const size_t before = DaemonJob::entries().size();
    QCOMPARE(DaemonJob::start(&bad, "Z:/definitely/not/here.exe", {}), 0ul);
    QVERIFY2(DaemonJob::entries().size() <= before, "failed launch must not record a job");
#endif
}


// ---- send once (src/sendflow.h): the rules that decide what the user is told about a send ----

void TestLogic::sendflow_keysAreValidAndDistinct() {
    QSet<QString> seen;
    const QRegularExpression ok("^[A-Za-z0-9._:-]{1,128}$");
    for (int i = 0; i < 200; ++i) {
        const QString k = sendflow::newKey();
        QVERIFY2(ok.match(k).hasMatch(), qPrintable(k));
        QVERIFY2(k.size() >= 32, "enough entropy: a 128-bit floor needs at least 22 base62 characters");
        QVERIFY2(!seen.contains(k), "a key must never repeat");
        seen.insert(k);
    }
}

void TestLogic::sendflow_classifyTheAnswerToTheCall() {
    using sendflow::CallClass;
    QString msg;
    // no usable answer at all: may or may not have been queued
    QCOMPARE(sendflow::classifyCall(nlohmann::json::parse("garbage", nullptr, false), 0, true, &msg), CallClass::Ambiguous);
    QCOMPARE(sendflow::classifyCall(nlohmann::json("Unknown error"), 0, true, &msg), CallClass::Ambiguous);
    QCOMPARE(sendflow::classifyCall(nlohmann::json::object(), 502, true, &msg), CallClass::Ambiguous);
    QCOMPARE(sendflow::classifyCall(nlohmann::json::object(), 503, true, &msg), CallClass::Ambiguous);
    // the node answered with a JSON-RPC error: nothing was queued
    nlohmann::json e = {{"result", nullptr}, {"error", {{"code", -6}, {"message", "Insufficient funds"}}}};
    QCOMPARE(sendflow::classifyCall(e, 500, true, &msg), CallClass::Definitive);
    QCOMPARE(msg, QString("Insufficient funds"));
    // the credentials were refused before the call was looked at
    QCOMPARE(sendflow::classifyCall(nlohmann::json::object(), 401, true, &msg), CallClass::Definitive);
    QVERIFY(msg.contains("401"));
    // an older node: its usage text for too many parameters (and only when the key was sent)
    nlohmann::json old = {{"error", {{"code", -1}, {"message", "z_sendmany \"fromaddress\" [{\"address\":... ,\"amount\":...},...] ( minconf ) ( fee )\n\nSend multiple times."}}}};
    QCOMPARE(sendflow::classifyCall(old, 500, true, &msg), CallClass::KeyUnsupported);
    QCOMPARE(sendflow::classifyCall(old, 500, false, &msg), CallClass::Definitive);
    // a node that knows the key and refuses something else about the call is final, never a reason to drop the key
    nlohmann::json newer = {{"error", {{"code", -1}, {"message", "z_sendmany \"fromaddress\" ... ( \"idempotency_key\" )\n\nusage"}}}};
    QCOMPARE(sendflow::classifyCall(newer, 500, true, &msg), CallClass::Definitive);
    nlohmann::json badKey = {{"error", {{"code", -8}, {"message", "Invalid parameter, idempotency_key must be 1 to 128 characters"}}}};
    QCOMPARE(sendflow::classifyCall(badKey, 500, true, &msg), CallClass::Definitive);
    // an error from another call is not the old node's usage text
    nlohmann::json other = {{"error", {{"code", -4}, {"message", "Wallet is locked"}}}};
    QCOMPARE(sendflow::classifyCall(other, 500, true, &msg), CallClass::Definitive);
    // a node that is still starting did not look at the call: a keyed call is asked again; without a key, as before
    nlohmann::json warm = {{"error", {{"code", -28}, {"message", "Loading block index..."}}}};
    QCOMPARE(sendflow::classifyCall(warm, 500, true, &msg), CallClass::Ambiguous);
    QCOMPARE(sendflow::classifyCall(warm, 500, false, &msg), CallClass::Definitive);
}

void TestLogic::sendflow_retryPaceIsBounded() {
    QCOMPARE(sendflow::retryDelayMs(1), 1000);
    QCOMPARE(sendflow::retryDelayMs(2), 2000);
    QCOMPARE(sendflow::retryDelayMs(3), 4000);
    QCOMPARE(sendflow::retryDelayMs(4), 8000);
    QCOMPARE(sendflow::retryDelayMs(5), 15000);
    QCOMPARE(sendflow::retryDelayMs(500), 15000);
    QCOMPARE(sendflow::retryDelayMs(0), 1000);
    QCOMPARE(sendflow::retryDelayMs(3, 20), 80);
    // the whole window stays far below the time after which a node releases an unmined key (20 blocks past expiry)
    qint64 total = 0;
    for (int a = 1; a < sendflow::kMaxSendAttempts; ++a) total += sendflow::retryDelayMs(a);
    QVERIFY(total < 20 * 60 * 1000);
}

namespace {
sendflow::QueueEntry Q(const char* status, const char* txid = "", const char* err = "", bool lastErr = false) {
    sendflow::QueueEntry q; q.present = true; q.status = status; q.txid = txid; q.error = err; q.hasLastError = lastErr; return q;
}
sendflow::JournalEntry J(const char* state, const char* txid = "") {
    sendflow::JournalEntry j; j.present = true; j.state = state; j.txid = txid; return j;
}
}

void TestLogic::sendflow_whatTheUserIsToldAboutAKeyedSend() {
    using sendflow::State;
    const sendflow::QueueEntry none;
    const sendflow::JournalEntry nojournal;
    // live operation
    QCOMPARE(sendflow::resolve(true, Q("queued"), false, nojournal).state, State::Sending);
    QCOMPARE(sendflow::resolve(true, Q("executing"), false, nojournal).state, State::Sending);
    auto done = sendflow::resolve(true, Q("success", "tx1"), false, nojournal);
    QCOMPARE(done.state, State::Sent); QCOMPARE(done.txid, QString("tx1"));
    // the broadcast failed after the build: the journal still holds it
    auto v = sendflow::resolve(true, Q("failed", "", "refused"), true, J("outcome_unknown", "tx2"));
    QCOMPARE(v.state, State::Unknown); QCOMPARE(v.txid, QString("tx2"));
    QVERIFY(v.text.contains("Outcome unknown")); QVERIFY(v.text.contains("will not send again"));
    // ...and later the journal settles it
    QCOMPARE(sendflow::resolve(true, Q("failed", "", "refused"), true, J("committed", "tx2")).state, State::Sent);
    QCOMPARE(sendflow::resolve(true, Q("failed", "", "refused"), true, J("committed", "tx2")).txid, QString("tx2"));
    auto ex = sendflow::resolve(true, Q("failed", "", "refused"), true, J("expired"));
    QCOMPARE(ex.state, State::Expired); QVERIFY(ex.text.contains("Funds are available again"));
    // failed before anything was built: the record is erased, the reason is the node's
    auto f = sendflow::resolve(true, Q("failed", "", "Insufficient funds"), true, nojournal);
    QCOMPARE(f.state, State::Failed); QCOMPARE(f.text, QString("Insufficient funds"));
    auto rel = sendflow::resolve(true, Q("failed", "", "boom"), true, J("released"));
    QCOMPARE(rel.state, State::Failed); QCOMPARE(rel.text, QString("boom"));
    // gone from the queue (restart)
    QCOMPARE(sendflow::resolve(true, none, true, J("committed", "tx3")).state, State::Sent);
    QCOMPARE(sendflow::resolve(true, none, true, J("outcome_unknown", "tx3")).state, State::Unknown);
    QCOMPARE(sendflow::resolve(true, none, true, J("expired")).state, State::Expired);
    QCOMPARE(sendflow::resolve(true, none, true, J("started")).state, State::Sending);
    QCOMPARE(sendflow::resolve(true, none, true, J("released")).state, State::Failed);
    auto gone = sendflow::resolve(true, none, true, nojournal);
    QCOMPARE(gone.state, State::Failed); QVERIFY(gone.text.contains("Nothing was sent"));
    // the node answers for the id from its journal (built, not in a block or the mempool): the txid rides on it
    QCOMPARE(sendflow::resolve(true, Q("executing", "tx4", "", true), false, nojournal).state, State::Unknown);
    QCOMPARE(sendflow::resolve(true, Q("executing", "", "", true), false, nojournal).state, State::Unknown);
}

void TestLogic::sendflow_anUnkeyedSendOnAnOlderNode() {
    using sendflow::State;
    const sendflow::JournalEntry nojournal;
    QCOMPARE(sendflow::resolve(false, Q("executing"), false, nojournal).state, State::Sending);
    QCOMPARE(sendflow::resolve(false, Q("success", "tx"), false, nojournal).state, State::Sent);
    QCOMPARE(sendflow::resolve(false, Q("failed", "", "nope"), false, nojournal).state, State::Failed);
    // the queue forgot it: the wallet cannot tell, and says so instead of "failed"
    auto lost = sendflow::resolve(false, sendflow::QueueEntry(), false, nojournal);
    QCOMPARE(lost.state, State::Lost);
    QVERIFY(lost.text.contains("Check your transactions before sending again"));
    // a journal is never consulted for a send that has no key
    QVERIFY(!sendflow::needsJournal(false, sendflow::QueueEntry(), false));
    QVERIFY(!sendflow::needsJournal(false, Q("failed"), true));
}

void TestLogic::sendflow_theJournalIsOnlyAskedWhenItDecides() {
    QVERIFY(!sendflow::needsJournal(true, Q("executing"), false));
    QVERIFY(!sendflow::needsJournal(true, Q("success", "tx"), false));
    QVERIFY(sendflow::needsJournal(true, Q("failed"), false));
    QVERIFY(sendflow::needsJournal(true, sendflow::QueueEntry(), false));
    QVERIFY(sendflow::needsJournal(true, Q("executing"), true));      // already of unknown outcome
}

void TestLogic::sendflow_parseWhatTheNodeSays() {
    auto q = sendflow::parseQueueEntry(nlohmann::json::parse(
        R"({"id":"opid-1","status":"success","result":{"txid":"aa"}})"));
    QVERIFY(q.present); QCOMPARE(q.status, QString("success")); QCOMPARE(q.txid, QString("aa"));
    auto f = sendflow::parseQueueEntry(nlohmann::json::parse(
        R"({"id":"opid-1","status":"failed","error":{"code":-4,"message":"boom"}})"));
    QCOMPARE(f.error, QString("boom"));
    auto b = sendflow::parseQueueEntry(nlohmann::json::parse(
        R"({"id":"opid-1","status":"executing","txid":"bb","expiryheight":9,"last_error":{"code":-1,"message":"m"}})"));
    QCOMPARE(b.txid, QString("bb")); QVERIFY(b.hasLastError);
    QVERIFY(!sendflow::parseQueueEntry(nlohmann::json("x")).present);
    QVERIFY(!sendflow::parseJournalEntry(nlohmann::json::array()).present);
    auto j = sendflow::parseJournalEntry(nlohmann::json::parse(R"({"opid":"o","state":"committed","txid":"cc","stored_state":"committed"})"));
    QVERIFY(j.present); QCOMPARE(j.state, QString("committed")); QCOMPARE(j.txid, QString("cc"));
    // wrong types never throw
    auto w = sendflow::parseQueueEntry(nlohmann::json::parse(R"({"status":5,"result":3,"error":"x"})"));
    QVERIFY(w.present); QVERIFY(w.status.isEmpty());
}

void TestLogic::sendflow_ownWordingIsNotRewritten() {
    for (const QString& s : { sendflow::unknownText(), sendflow::expiredText(), sendflow::lostText(),
                              sendflow::interruptedText(), sendflow::gaveUpText(), sendflow::oldNodeAmbiguousText() })
        QVERIFY(sendflow::isFlowText(s));
    QVERIFY(!sendflow::isFlowText("Insufficient funds"));
    // none of them invites the user to simply try again, except the ones where nothing was sent
    QVERIFY(!sendflow::unknownText().contains("try again", Qt::CaseInsensitive));
    QVERIFY(!sendflow::gaveUpText().contains("try again", Qt::CaseInsensitive));
    // a refused repeat keeps the node's reason and is never "try again"
    const QString rr = sendflow::retryRefusedText("Wallet is locked");
    QVERIFY(sendflow::isFlowText(rr));
    QVERIFY(rr.contains("Wallet is locked"));
    QVERIFY(!rr.contains("try again", Qt::CaseInsensitive));
}


// ---- wallet health line (src/wallethealth.h) ----

namespace {
nlohmann::json healthInfo(nlohmann::json patch = nlohmann::json::object()) {
    nlohmann::json pool = {{"notes_unspent", 3}, {"notes_spent", 9}, {"witness_ready", 3}, {"witness_missing", 0}, {"witness_stale", 0},
                           {"unconfirmed", 0}, {"unmined_dead", 0}, {"witnesses_held_unspent", 3}, {"witnesses_held_spent", 0}};
    nlohmann::json h = {{"tip_height", 2000000}, {"checkpoint_height", 1999990}, {"witness_cache_size", 100},
                        {"witness_rebuild_pending", false}, {"sapling", pool}, {"sprout", pool},
                        {"pending_sends", {{"in_mempool", 0}, {"not_in_mempool", 0}, {"expiring_soon", 0}, {"expired", 0}, {"conflicted", 0}}}};
    for (auto it = patch.begin(); it != patch.end(); ++it) {
        if (it.key() == "pending_sends") for (auto p = it->begin(); p != it->end(); ++p) h["pending_sends"][p.key()] = p.value();
        else if (it.key() == "sapling") for (auto p = it->begin(); p != it->end(); ++p) h["sapling"][p.key()] = p.value();
        else h[it.key()] = it.value();
    }
    return {{"walletversion", 60000}, {"balance", 1.5}, {"health", h}};
}
}

void TestLogic::health_aHealthyWalletSaysNothing() {
    QVERIFY(!wallethealth::assess(healthInfo(), true).any());
    QVERIFY(!wallethealth::assess(healthInfo(), false).any());
    // a normal pending send (in the mempool) is not a concern
    QVERIFY(!wallethealth::assess(healthInfo({{"pending_sends", {{"in_mempool", 2}}}}), true).any());
    // a checkpoint that has not been written yet
    QVERIFY(!wallethealth::assess(healthInfo({{"checkpoint_height", -1}}), true).any());
    // an older node has no health object; garbage never throws
    QVERIFY(!wallethealth::assess(nlohmann::json{{"balance", 1.0}}, true).any());
    QVERIFY(!wallethealth::assess(nlohmann::json::array(), true).any());
    QVERIFY(!wallethealth::assess(nlohmann::json(), true).any());
    QVERIFY(!wallethealth::assess(nlohmann::json{{"health", "oops"}}, true).any());
    QVERIFY(!wallethealth::assess(nlohmann::json{{"health", {{"sapling", 3}, {"pending_sends", "x"}, {"tip_height", "high"}}}}, true).any());
}

void TestLogic::health_eachAttentionStateIsReported() {
    auto one = [](nlohmann::json patch, bool synced, const char* needle) {
        const auto r = wallethealth::assess(healthInfo(patch), synced);
        return r.lines.size() == 1 && r.lines[0].contains(needle);
    };
    QVERIFY(one({{"witness_rebuild_pending", true}}, true, "being rebuilt"));
    QVERIFY(one({{"witness_rebuild_pending", true}}, false, "being rebuilt"));          // also while catching up
    QVERIFY(one({{"sapling", {{"witness_missing", 2}}}}, true, "2 shielded note(s) cannot be spent yet"));
    QVERIFY(one({{"checkpoint_height", 1998000}}, true, "2000 blocks ago"));
    QVERIFY(one({{"checkpoint_failed", true}, {"checkpoint_failures", 1}}, true, "could not be saved"));
    // pinned: the line is part of the synced block, so it is silent while the node still catches up
    QVERIFY(!wallethealth::assess(healthInfo({{"checkpoint_failed", true}}), false).any());
    // a failed write is reported once, not together with the lag it causes
    QVERIFY(one({{"checkpoint_failed", true}, {"checkpoint_height", 1998000}}, true, "could not be saved"));
    QVERIFY(one({{"pending_sends", {{"not_in_mempool", 1}}}}, true, "not in the node's mempool"));
    QVERIFY(one({{"pending_sends", {{"expiring_soon", 3}}}}, true, "will expire within a few blocks"));
    QVERIFY(one({{"pending_sends", {{"expired", 1}}}}, true, "funds are back in your balance") ||
            one({{"pending_sends", {{"expired", 1}}}}, true, "back in your balance"));
    QVERIFY(one({{"pending_sends", {{"conflicted", 4}}}}, true, "will never confirm"));
    // the boundary: exactly the lag is fine, one block more is not
    QVERIFY(!wallethealth::assess(healthInfo({{"checkpoint_height", 2000000 - wallethealth::kCheckpointLagBlocks}}), true).any());
    QVERIFY(wallethealth::assess(healthInfo({{"checkpoint_height", 2000000 - wallethealth::kCheckpointLagBlocks - 1}}), true).any());
    // while the node is still catching up the checkpoint and the proofs are legitimately behind: no noise
    QVERIFY(!wallethealth::assess(healthInfo({{"checkpoint_height", 1000}}), false).any());
    QVERIFY(!wallethealth::assess(healthInfo({{"sapling", {{"witness_missing", 7}}}}), false).any());
    // several at once: one line each, one summary
    const auto many = wallethealth::assess(healthInfo({{"witness_rebuild_pending", true}, {"pending_sends", {{"expired", 1}, {"conflicted", 1}}}}), true);
    QCOMPARE(many.lines.size(), 3);
    QVERIFY(many.summary().contains("3"));
    QVERIFY(many.tooltip().contains("being rebuilt") && many.tooltip().contains("never confirm"));
}

QTEST_MAIN(TestLogic)
#include "tst_logic.moc"
