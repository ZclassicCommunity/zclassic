#include "mainwindow.h"
#include "settings.h"

#include <QCryptographicHash>
#include <QVector>
#include <cstring>

// ============================================================================
// Address checksum validation helpers (file-local).
//
// The point of these is to catch TYPOS so funds are never sent to a mistyped
// address. We verify checksum INTEGRITY only -- we deliberately do NOT
// hardcode a version-byte whitelist, so no legitimate ZClassic address can be
// rejected just because we didn't anticipate its prefix.
// ============================================================================
namespace {

// ----- base58check (transparent t-addrs and Sprout zc/ztn addrs) -----------
static const char* B58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Decode a base58 string into raw bytes. Returns false on any non-base58
// character. Handles leading '1's as leading zero bytes.
static bool base58Decode(const QString& str, QByteArray& out) {
    // Build a big-endian byte vector by repeated base-58 -> base-256 conversion.
    QByteArray b256; // accumulates the big number, big-endian
    for (QChar qc : str) {
        // Reject non-ASCII and characters outside the alphabet.
        if (qc.unicode() > 127)
            return false;
        const char* p = strchr(B58_ALPHABET, qc.toLatin1());
        if (p == nullptr || *p == '\0')   // '\0' guard: strchr matches terminator
            return false;
        int carry = static_cast<int>(p - B58_ALPHABET);

        for (int i = b256.size() - 1; i >= 0; i--) {
            carry += 58 * static_cast<unsigned char>(b256.at(i));
            b256[i] = static_cast<char>(carry & 0xFF);
            carry >>= 8;
        }
        while (carry > 0) {
            b256.prepend(static_cast<char>(carry & 0xFF));
            carry >>= 8;
        }
    }

    // Each leading '1' in the input is a leading zero byte.
    QByteArray leadingZeros;
    for (QChar qc : str) {
        if (qc == QChar('1'))
            leadingZeros.append('\0');
        else
            break;
    }

    out = leadingZeros + b256;
    return true;
}

// Verify a base58check string: last 4 bytes must equal the first 4 bytes of
// the double-SHA256 of the preceding payload.
static bool base58CheckValid(const QString& str) {
    QByteArray raw;
    if (!base58Decode(str, raw))
        return false;

    // Need at least 1 payload byte + 4 checksum bytes.
    if (raw.size() < 5)
        return false;

    QByteArray payload  = raw.left(raw.size() - 4);
    QByteArray checksum = raw.right(4);

    QByteArray h1 = QCryptographicHash::hash(payload, QCryptographicHash::Sha256);
    QByteArray h2 = QCryptographicHash::hash(h1,      QCryptographicHash::Sha256);

    return h2.left(4) == checksum;
}

// ----- bech32 (Sapling zs / ztestsapling addrs) -----------------------------
static const char* BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static quint32 bech32Polymod(const QVector<int>& values) {
    static const quint32 GEN[5] = {
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    };
    quint32 chk = 1;
    for (int v : values) {
        quint32 b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ static_cast<quint32>(v);
        for (int i = 0; i < 5; i++) {
            if ((b >> i) & 1)
                chk ^= GEN[i];
        }
    }
    return chk;
}

// Verify a bech32 string's checksum (the original BIP173 polymod == 1 form,
// which is what Zcash/ZClassic Sapling addresses use).
static bool bech32ChecksumValid(const QString& addr) {
    // bech32 must be entirely lower-case or entirely upper-case (no mixing).
    QString lower = addr.toLower();
    QString upper = addr.toUpper();
    if (addr != lower && addr != upper)
        return false;
    QString s = lower;

    int sep = s.lastIndexOf(QChar('1'));
    // HRP must be non-empty; data part (incl. 6-char checksum) must be present.
    if (sep < 1 || sep + 7 > s.size())
        return false;

    QVector<int> values;
    // Expand the human-readable part.
    const QString hrp = s.left(sep);
    for (QChar c : hrp)
        values.append(c.unicode() >> 5);
    values.append(0);
    for (QChar c : hrp)
        values.append(c.unicode() & 31);

    // Append the data part (everything after the separator).
    for (int i = sep + 1; i < s.size(); i++) {
        const char* p = strchr(BECH32_CHARSET, s.at(i).toLatin1());
        if (p == nullptr || *p == '\0')
            return false;
        values.append(static_cast<int>(p - BECH32_CHARSET));
    }

    return bech32Polymod(values) == 1;
}

} // anonymous namespace

Settings* Settings::instance = nullptr;

Settings* Settings::init() {    
    if (instance == nullptr) 
        instance = new Settings();

    return instance;
}

Settings* Settings::getInstance() {
    return instance;
}

Config Settings::getSettings() {
    // Load from the QT Settings. 
    QSettings s;
    
    auto host        = s.value("connection/host").toString();
    auto port        = s.value("connection/port").toString();
    auto username    = s.value("connection/rpcuser").toString();
    auto password    = s.value("connection/rpcpassword").toString();    

    return Config{host, port, username, password};
}

void Settings::saveSettings(const QString& host, const QString& port, const QString& username, const QString& password) {
    QSettings s;

    s.setValue("connection/host", host);
    s.setValue("connection/port", port);
    s.setValue("connection/rpcuser", username);
    s.setValue("connection/rpcpassword", password);

    s.sync();

    // re-init to load correct settings
    init();
}

void Settings::setUsingZClassicConf(QString confLocation) {
    if (!confLocation.isEmpty())
        _confLocation = confLocation;
}

bool Settings::isTestnet() {
    return _isTestnet;
}

void Settings::setTestnet(bool isTestnet) {
    this->_isTestnet = isTestnet;
}

bool Settings::isSaplingAddress(QString addr) {
    if (!isValidAddress(addr))
        return false;

    return ( isTestnet() && addr.startsWith("ztestsapling")) ||
           (!isTestnet() && addr.startsWith("zs"));
}

bool Settings::isSproutAddress(QString addr) {
    if (!isValidAddress(addr))
        return false;
        
    return isZAddress(addr) && !isSaplingAddress(addr);
}

bool Settings::isZAddress(QString addr) {
    if (!isValidAddress(addr))
        return false;
        
    return addr.startsWith("z");
}

bool Settings::isTAddress(QString addr) {
    if (!isValidAddress(addr))
        return false;
        
    return addr.startsWith("t");
}

int Settings::getZClassicdVersion() {
    return _zclassicdVersion;
}

void Settings::setZClassicdVersion(int version) {
    _zclassicdVersion = version;
}

bool Settings::isSyncing() {
    return _isSyncing;
}

void Settings::setSyncing(bool syncing) {
    this->_isSyncing = syncing;
}

int Settings::getBlockNumber() {
    return this->_blockNumber;
}

void Settings::setBlockNumber(int number) {
    this->_blockNumber = number;
}

bool Settings::isSaplingActive() {
    return  (isTestnet() && getBlockNumber() > 280000) ||
           (!isTestnet() && getBlockNumber() > 419200);
}

double Settings::getZCLPrice() { 
    return zclPrice; 
}

bool Settings::getAutoShield() {
    // PRIV-9 (privacy-by-default): auto-shield is ON unless the user explicitly
    // turned it off. When set, transparent change is routed to a Sapling z-address
    // (PRIV-10), so a default send never silently leaves change sitting on a public
    // t-address. A canary L0 test (TestLogic::priv9_autoShieldDefaultOn) asserts
    // this default stays TRUE -- if someone flips it back to false, that test goes
    // red. NOTE: scope is shield-CHANGE only (DECISION #1), not full output
    // shielding -- explicitly sending to a t-recipient stays allowed (with the
    // de-shield warning + acknowledgement, PRIV-11/PRIV-12).
    return QSettings().value("options/autoshield", true).toBool();
}

void Settings::setAutoShield(bool allow) {
    QSettings().setValue("options/autoshield", allow);
}

bool Settings::getAllowCustomFees() {
    // Load from the QT Settings. 
    return QSettings().value("options/customfees", false).toBool();
}

void Settings::setAllowCustomFees(bool allow) {
    QSettings().setValue("options/customfees", allow);
}

bool Settings::isWalletBackedUp() {
    // Load from the QT Settings. Defaults to false so a brand-new wallet is
    // treated as un-backed-up until the user actually confirms a backup.
    return QSettings().value("options/walletbackedup", false).toBool();
}

void Settings::setWalletBackedUp(bool backedUp) {
    QSettings().setValue("options/walletbackedup", backedUp);
}

bool Settings::getSaveZtxs() {
    // Load from the QT Settings.
    return QSettings().value("options/savesenttx", true).toBool();
}

void Settings::setSaveZtxs(bool save) {
    QSettings().setValue("options/savesenttx", save);
}

bool Settings::getKeepInTray() {
    // Default ON: closing the window keeps the node warm in the tray so RE-OPENING
    // is instant (attaches to the already-loaded daemon) instead of paying the
    // ~1-min cold block-index/chainstate load every launch. Opt-out via the wired
    // Settings checkbox; closeEvent falls back to a real shutdown when no system
    // tray is available, so headless desktops never orphan the node.
    return QSettings().value("options/keepintray", true).toBool();
}

void Settings::setKeepInTray(bool keep) {
    QSettings().setValue("options/keepintray", keep);
}

bool Settings::getShowCachedBalance() {
    // Default ON: paint the last-known balance instantly on startup so users don't
    // stare at "syncing 0%". Independent of getSaveZtxs() so the privacy opt-out
    // (don't store tx history) does not also disable the instant-balance paint.
    return QSettings().value("options/showcachedbalance", true).toBool();
}

void Settings::setShowCachedBalance(bool show) {
    QSettings().setValue("options/showcachedbalance", show);
}

bool Settings::getNonModalStartup() {
    // W1-1 default ON: the MainWindow appears at once (already painting cached
    // balances pre-RPC) and the warmup splash is a non-blocking, dismissible
    // overlay rather than a UI-blocking nested d->exec() modal loop.
    return QSettings().value("options/nonmodalstartup", true).toBool();
}

void Settings::setNonModalStartup(bool on) {
    QSettings().setValue("options/nonmodalstartup", on);
}

bool Settings::getOpenPortNatpmp() {
    // Default OFF for the first beta. When enabled, the embedded daemon is
    // launched with -natpmp=1 and asks the router (via NAT-PMP/PCP, never UPnP)
    // to forward our own P2P listen port so inbound peers can reach us.
    return QSettings().value("options/openportnatpmp", false).toBool();
}

void Settings::setOpenPortNatpmp(bool on) {
    QSettings().setValue("options/openportnatpmp", on);
}

void Settings::setPeers(int peers) {
    _peerConnections = peers;
}

int Settings::getPeers() {
    return _peerConnections;
}
//=================================
// Static Stuff
//=================================
void Settings::saveRestore(QDialog* d) {
    d->restoreGeometry(QSettings().value(d->objectName() % "geometry").toByteArray());

    QObject::connect(d, &QDialog::finished, [=](auto) {
        QSettings().setValue(d->objectName() % "geometry", d->saveGeometry());
    });
}

QString Settings::getUSDFormat(double bal) {
    if (!Settings::getInstance()->isTestnet() && Settings::getInstance()->getZCLPrice() > 0) 
        return "$" + QLocale(QLocale::English).toString(bal * Settings::getInstance()->getZCLPrice(), 'f', 2);
    else 
        return QString();
}

QString Settings::getDecimalString(double amt) {
    QString f = QString::number(amt, 'f', 8);

    while (f.contains(".") && (f.right(1) == "0" || f.right(1) == ".")) {
        f = f.left(f.length() - 1);
    }
    if (f == "-0")
        f = "0";

    return f;
}

QString Settings::getHeightString(qint64 height) {
    // Locale-aware grouping so the height reads naturally for the user's region
    // (e.g. "1,700,000" or "1.700.000"). Negative/unknown heights pass through.
    return QLocale::system().toString((qlonglong) height);
}

QString Settings::getZCLDisplayFormat(double bal) {
    // This is idiotic. Why doesn't QString have a way to do this?
    return getDecimalString(bal) % " " % Settings::getTokenName();
}

QString Settings::getZCLUSDDisplayFormat(double bal) {
    auto usdFormat = getUSDFormat(bal);
    if (!usdFormat.isEmpty())
        return getZCLDisplayFormat(bal) % " (" % getUSDFormat(bal) % ")";
    else
        return getZCLDisplayFormat(bal);
}

const QString Settings::txidStatusMessage = QString(QObject::tr("Tx submitted (right click to copy) txid:"));

QString Settings::getTokenName() {
    if (Settings::getInstance()->isTestnet()) {
        return "ZCT";
    } else {
        return "ZCL";
    }
}

// ZClassic mainnet block explorer (Insight URL scheme). There is no known live
// ZClassic testnet explorer, so testnet returns an empty string and callers skip
// opening a link rather than sending the user to a dead/wrong page.
QString Settings::getExplorerTxURL(QString txid) {
    if (Settings::getInstance()->isTestnet())
        return "";
    return "https://explorer.zcl.zelcore.io/tx/" + txid;
}

QString Settings::getExplorerAddressURL(QString addr) {
    if (Settings::getInstance()->isTestnet())
        return "";
    return "https://explorer.zcl.zelcore.io/address/" + addr;
}

QString Settings::getDonationAddr(bool sapling) {
    if (Settings::getInstance()->isTestnet()) 
        if (sapling)
            return "ztestsapling1wn6889vznyu42wzmkakl2effhllhpe4azhu696edg2x6me4kfsnmqwpglaxzs7tmqsq7kudemp5";
        else
            return "ztn6fYKBii4Fp4vbGhkPgrtLU4XjXp4ZBMZgShtopmDGbn1L2JLTYbBp2b7SSkNr9F3rQeNZ9idmoR7s4JCVUZ7iiM5byhF";
    else 
        if (sapling)
            return "zs1gv64eu0v2wx7raxqxlmj354y9ycznwaau9kduljzczxztvs4qcl00kn2sjxtejvrxnkucw5xx9u";
        else
            return "zcEgrceTwvoiFdEvPWcsJHAMrpLsprMF6aRJiQa3fan5ZphyXLPuHghnEPrEPRoEVzUy65GnMVyCTRdkT6BYBepnXh6NBYs";    
}

bool Settings::addToZClassicConf(QString confLocation, QString line) {
    QFile file(confLocation);
    if (!file.open(QIODevice::ReadWrite | QIODevice::Append))
        return false;
    

    QTextStream out(&file);
    out << line << "\n";
    file.close();

    return true;
}

bool Settings::removeFromZClassicConf(QString confLocation, QString option) {
    if (confLocation.isEmpty())
        return false;

    // To remove an option, we'll create a new file, and copy over everything but the option.
    QFile file(confLocation);
    if (!file.open(QIODevice::ReadOnly)) 
        return false;
    
    QList<QString> lines;
    QTextStream in(&file);
    while (!in.atEnd()) {
        QString line = in.readLine();
        auto s = line.indexOf("=");
        QString name = line.left(s).trimmed().toLower();
        if (name != option) {
            lines.append(line);
        }
    }    
    file.close();
    
    QFile newfile(confLocation);
    if (!newfile.open(QIODevice::ReadWrite | QIODevice::Truncate))
        return false;

    QTextStream out(&newfile);
    for (QString line : lines) {
        out << line << endl;
    }
    newfile.close();

    return true;
}

double Settings::getMinerFee() {
    return 0.0001;
}

double Settings::getZboardAmount() {
    return 0.0001;
}

QString Settings::getZboardAddr() {
    if (Settings::getInstance()->isTestnet()) {
        return getDonationAddr(true);
    }
    else {
        return "zs10m00rvkhfm4f7n23e4sxsx275r7ptnggx39ygl0vy46j9mdll5c97gl6dxgpk0njuptg2mn9w5s";
    }
}

bool Settings::isValidAddress(QString addr) {
    // Structural pre-filter (same shapes the wallet has always accepted). This
    // bounds length/charset cheaply; the checksum gate below then verifies the
    // address is actually self-consistent so typos are caught.
    // SP-1: these patterns are immutable, so compile them ONCE (function-local
    // statics) instead of re-parsing four QRegExp on every call. isValidAddress
    // is hit ~4x per privacy-badge classify() and classify() runs per address
    // cell per paint -> this was ~16 pattern recompiles per cell per frame on
    // scroll/resize. C++11 guarantees thread-safe init of these statics, and
    // QRegExp::exactMatch is const; every isValidAddress() caller runs on the
    // single GUI thread (addressbook/sendtab/mainwindow/settings/delegate-paint),
    // so the shared QRegExp match state is never touched concurrently.
    static const QRegExp zcexp("^z[a-z0-9]{94}$",  Qt::CaseInsensitive);   // Sprout  (zc.. / ztn..)
    static const QRegExp zsexp("^z[a-z0-9]{77}$",  Qt::CaseInsensitive);   // Sapling (zs1..)
    static const QRegExp ztsexp("^ztestsapling[a-z0-9]{76}", Qt::CaseInsensitive); // testnet Sapling
    static const QRegExp texp("^t[a-z0-9]{34}$", Qt::CaseInsensitive);     // transparent (t1.. / t3..)

    // Sapling addresses are bech32 -> verify the bech32 polymod checksum.
    // Note: the testnet-Sapling regex is a prefix match (matches the broader
    // Sprout shape too), so test bech32 first and fall through on failure.
    if (addr.startsWith("zs", Qt::CaseInsensitive) || addr.startsWith("ztestsapling", Qt::CaseInsensitive)) {
        if (zsexp.exactMatch(addr) || ztsexp.exactMatch(addr))
            return bech32ChecksumValid(addr);
        return false;
    }

    // Transparent and Sprout addresses are base58check -> verify the 4-byte
    // double-SHA256 checksum.
    if (texp.exactMatch(addr) || zcexp.exactMatch(addr))
        return base58CheckValid(addr);

    return false;
}

const QString Settings::labelRegExp("[a-zA-Z0-9\\-_]{0,40}");
