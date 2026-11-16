#ifndef SETTINGS_H
#define SETTINGS_H

#include "precompiled.h"

struct Config {
    QString host;
    QString port;
    QString rpcuser;
    QString rpcpassword;
};

struct ToFields;
struct Tx;

class Settings
{
public:
    static  Settings* init();
    static  Settings* getInstance();

    Config  getSettings();
    void    saveSettings(const QString& host, const QString& port, const QString& username, const QString& password);

    bool    isTestnet();
    void    setTestnet(bool isTestnet);
            
    bool    isSaplingAddress(QString addr);
    bool    isSproutAddress(QString addr);
            
    bool    isSyncing();
    void    setSyncing(bool syncing);

    // Send-gate staleness: epoch (secs) of the last successful sync poll, plus a PURE
    // predicate deciding whether a still-true isSyncing flag is stale (no poll refreshed
    // it within the window) and so must NOT block a send. now/last are passed in so the
    // decision is unit-testable with no clock (mirrors RPC::desiredPollMs).
    void    setLastSyncPollEpoch(qint64 e) { _lastSyncPollEpoch = e; }
    qint64  getLastSyncPollEpoch() { return _lastSyncPollEpoch; }
    static const qint64 kSyncGateStaleSecs = 180;   // 3 min with no live poll => stale
    static bool syncGateIsStale(qint64 nowEpoch, qint64 lastPollEpoch) {
        if (lastPollEpoch == 0) return false;       // never polled yet -> let normal gate run
        return (nowEpoch - lastPollEpoch) > kSyncGateStaleSecs;
    }

    int     getZClassicdVersion();
    void    setZClassicdVersion(int version);
    
    void    setUseEmbedded(bool r) { _useEmbedded = r; }
    bool    useEmbedded() { return _useEmbedded; }

    void    setHeadless(bool h) { _headless = h; }
    bool    isHeadless() { return _headless; }

    int     getBlockNumber();
    void    setBlockNumber(int number);
            
    bool    getSaveZtxs();
    void    setSaveZtxs(bool save);

    // Opt-in: keep ZclWallet (and its embedded node) running in the system tray
    // when the window is closed, so the next launch is instant instead of paying
    // the ~1-minute node warmup again. Default OFF -> behaves exactly as before.
    bool    getKeepInTray();
    void    setKeepInTray(bool keep);

    // Opt-out (default ON): paint last-known balance instantly on startup,
    // independent of getSaveZtxs() so the privacy opt-out keeps the fast paint.
    bool    getShowCachedBalance();
    void    setShowCachedBalance(bool show);

    // W1-1 (opt-out, default ON): show the MainWindow immediately on startup and
    // run the node-warmup splash as a NON-blocking, dismissible overlay instead of
    // blocking the UI behind a nested d->exec() modal loop for 1-2 minutes. When
    // OFF (or headless) the proven d->exec() modal path is retained verbatim.
    bool    getNonModalStartup();
    void    setNonModalStartup(bool on);

    // Opt-in (default OFF for the first beta): ask the router to open our P2P
    // listen port automatically via NAT-PMP/PCP (no UPnP), so NAT/firewalled
    // users become reachable for inbound peers. When on, connection.cpp passes
    // -natpmp=1 to the embedded daemon. Maps only our own listen port.
    bool    getOpenPortNatpmp();
    void    setOpenPortNatpmp(bool on);

    bool    isWalletBackedUp();
    void    setWalletBackedUp(bool backedUp);

    bool    getAutoShield();
    void    setAutoShield(bool allow);

    bool    getAllowCustomFees();
    void    setAllowCustomFees(bool allow);
            
    bool    isSaplingActive();

    void    setUsingZClassicConf(QString confLocation);
    const   QString& getZClassicdConfLocation() { return _confLocation; }

    void    setZCLPrice(double p) { zclPrice = p; }
    double  getZCLPrice();

    void    setPeers(int peers);
    int     getPeers();
       
    // Static stuff
    static const QString txidStatusMessage;
    
    static void saveRestore(QDialog* d);

    static bool    isZAddress(QString addr);
    static bool    isTAddress(QString addr);

    static QString getDecimalString(double amt);
    // Thousands-separated integer for block heights, e.g. 1700000 -> "1,700,000".
    // Single source of truth so every "block N" string reads the same.
    static QString getHeightString(qint64 height);
    static QString getUSDFormat(double bal);
    static QString getZCLDisplayFormat(double bal);
    static QString getZCLUSDDisplayFormat(double bal);

    static QString getTokenName();
    static QString getDonationAddr(bool sapling);

    // ZClassic block-explorer URLs (single source of truth for all menu actions).
    // Returns an empty string when no explorer is available (e.g. testnet), in
    // which case callers should not open a link.
    static QString getExplorerTxURL(QString txid);
    static QString getExplorerAddressURL(QString addr);

    static double  getMinerFee();
    static double  getZboardAmount();
    static QString getZboardAddr();

    static int     getMaxMobileAppTxns() { return 30; }
    
    static bool    isValidAddress(QString addr);

    static bool    addToZClassicConf(QString confLocation, QString line);
    static bool    removeFromZClassicConf(QString confLocation, QString option);

    static const QString labelRegExp;

    static const int     updateSpeed         = 20 * 1000;        // 20 sec
    static const int     quickUpdateSpeed    = 5  * 1000;        // 5 sec
    static const int     priceRefreshSpeed   = 60 * 60 * 1000;   // 1 hr

private:
    // This class can only be accessed through Settings::getInstance()
    Settings() = default;
    ~Settings() = default;

    static Settings* instance;

    QString _confLocation;
    QString _executable;
    bool    _isTestnet        = false;
    bool    _isSyncing        = false;
    qint64  _lastSyncPollEpoch = 0;   // secs-since-epoch of last successful sync poll (send-gate staleness)
    int     _blockNumber      = 0;
    int     _zclassicdVersion    = 0;
    bool    _useEmbedded      = false;
    bool    _headless         = false;
    int     _peerConnections  = 0;
    
    double  zclPrice          = 0.0;
};

#endif // SETTINGS_H