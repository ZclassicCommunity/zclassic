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
#include "embeddeddaemon.h"
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
        "Zapping", "Upgrading",
    };
    for (const char* p : kPhases)
        if (status.contains(QLatin1String(p), Qt::CaseInsensitive)) return true;
    return false;
}

// src/connection.cpp:1041-1067  ConnectionLoader::blocksDirSizeBytes
// (root-or-testnet3 resolution + recursive Files sum; -1 == "can't measure")
static qint64 blocksDirSizeBytes(const QString& datadirRoot) {
    if (datadirRoot.isEmpty()) return -1;
    QDir base(datadirRoot);
    QDir testnet(QDir(datadirRoot).filePath("testnet3"));
    if (testnet.exists() &&
        (QFile::exists(testnet.filePath("wallet.dat")) ||
         QFile::exists(testnet.filePath("debug.log")) ||
         QDir(testnet.filePath("blocks")).exists()))
        base = testnet;
    QDir blocks(base.filePath("blocks"));
    if (!blocks.exists()) return -1;
    qint64 total = 0;
    QDirIterator it(blocks.absolutePath(), QDir::Files | QDir::NoSymLinks,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) { it.next(); total += it.fileInfo().size(); }
    return total;
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
    void embeddedDaemon_integrity();
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
    QCOMPARE(cxmirror::blocksDirSizeBytes(QString()), (qint64)-1);

    QTemporaryDir tmp;
    QVERIFY(tmp.isValid());
    QString root = tmp.path();

    // No blocks/ dir yet -> -1 ("can't measure", never a heal trigger).
    QCOMPARE(cxmirror::blocksDirSizeBytes(root), (qint64)-1);

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
    QCOMPARE(cxmirror::blocksDirSizeBytes(root), (qint64)1750);

    // testnet3/ resolution: when testnet3/ holds the chain, it's measured instead.
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
        QCOMPARE(cxmirror::blocksDirSizeBytes(root2), (qint64)4096);
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

QTEST_MAIN(TestLogic)
#include "tst_logic.moc"
