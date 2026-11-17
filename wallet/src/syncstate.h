#ifndef SYNCSTATE_H
#define SYNCSTATE_H

// Pure mapping from node facts (getblockchaininfo + peer count) to the sync state the
// wallet shows. No RPC, no widgets: unit-tested in tests/tst_logic.cpp.
//
// Why a tip-time test: "blocks >= headers" only means "no better header is known yet".
// Right after a bootstrap-snapshot import, or on a node whose peers have not sent
// headers yet, blocks == headers sits weeks behind the real tip, so a block counter
// alone declares "Synced" wrongly. A block's timestamp cannot lie that way.

#include <QCoreApplication>
#include <QString>

namespace SyncState {

enum Kind {
    Syncing,        // behind: headers ahead of blocks, or the tip is old
    WaitingForPeers,// caught up with every header we know, but no peers to confirm the tip
    Synced,         // at the network tip (fresh block, peers or previously confirmed)
    LocalNetwork,   // regtest: a private test chain; there is no network tip to chase
    StaleTip,       // looks caught up but the newest block is old although peers exist
    ClockSkew       // the node reports a wrong system clock; block ages cannot be trusted
};

struct Input {
    QString chain;          // getblockchaininfo.chain: "main", "test", "regtest"
    int     blocks = 0;
    int     headers = 0;    // 0 = unknown/absent
    qint64  tipTime = 0;    // tip block timestamp (epoch s); 0 = unknown
    qint64  now = 0;        // local clock (epoch s)
    int     connections = 0;
    int     ibd = -1;       // getblockchaininfo.initialblockdownload: -1 absent, 0 false, 1 true
    bool    everSynced = false; // already confirmed at tip this session
    bool    clockWarning = false; // node says the local clock disagrees with its peers
};

struct Verdict {
    Kind   kind = Syncing;
    bool   isSyncing = true;   // drives Settings::setSyncing (send gate, hero colour)
    qint64 tipAge = -1;        // seconds since the tip block, -1 unknown
    bool   headersAhead = false;
};

// A mainnet block takes ~150 s; ten minutes without one is unusual, two hours is a
// stall or a wrong clock. The wide margin keeps a lucky/slow block from flickering.
static const qint64 kFreshTipSecs = 2 * 3600;

inline Verdict classify(const Input& in) {
    Verdict v;
    if (in.tipTime > 0 && in.now > 0)
        v.tipAge = in.now > in.tipTime ? in.now - in.tipTime : 0;

    if (in.chain == QLatin1String("regtest")) {
        // The owner's "block 101" case: a private chain never has peers or a moving tip.
        v.kind = LocalNetwork; v.isSyncing = false;
        return v;
    }

    // A wrong clock makes every block look old (or new). The node's own header/peer view
    // is then the only trustworthy signal: caught up with peers and not in IBD = synced.
    if (in.clockWarning && in.connections > 0 && in.headers > 0 &&
        in.blocks >= in.headers - 2 && in.ibd != 1) {
        v.kind = ClockSkew; v.isSyncing = false; return v;
    }

    const bool headersKnown = in.headers > 0;
    v.headersAhead = headersKnown && in.blocks < in.headers - 2;
    const bool tipOld = v.tipAge > kFreshTipSecs;

    if (v.headersAhead) { v.kind = Syncing; v.isSyncing = true; return v; }

    if (!headersKnown && v.tipAge < 0) {       // first poll, nothing to judge by
        v.kind = Syncing; v.isSyncing = true; return v;
    }

    // Caught up with every header we know. Is that the network tip?
    // The node's own initial-block-download flag outranks a fresh-looking tip: a chain with less
    // work than the known minimum can carry fresh timestamps, and the node then refuses to call it synced.
    if (tipOld || in.ibd == 1) {
        // Old newest block: we are behind (or our clock is). With peers this is real
        // catching-up (snapshot just imported, headers not yet arrived); say Syncing.
        v.kind = in.connections > 0 ? Syncing : WaitingForPeers;
        v.isSyncing = true;
        if (in.connections > 0 && in.everSynced && tipOld) v.kind = StaleTip;
        return v;
    }
    if (in.connections > 0 || in.everSynced) {
        v.kind = Synced; v.isSyncing = false; return v;
    }
    v.kind = WaitingForPeers; v.isSyncing = true;
    return v;
}

// "12 min", "3 h", "5 days" for a duration in seconds.
inline QString formatAge(qint64 s) {
    if (s < 0) return QString();
    if (s < 90)         return QCoreApplication::translate("SyncState", "%1 s").arg(s);
    if (s < 90 * 60)    return QCoreApplication::translate("SyncState", "%1 min").arg((s + 30) / 60);
    if (s < 36 * 3600)  return QCoreApplication::translate("SyncState", "%1 h").arg((s + 1800) / 3600);
    if (s >= 400LL * 86400)
        return QCoreApplication::translate("SyncState", "%1 years").arg(s / (365.25 * 86400), 0, 'f', 1);
    return QCoreApplication::translate("SyncState", "%1 days").arg((s + 43200) / 86400);
}

} // namespace SyncState

#endif
