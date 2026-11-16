#ifndef ZCL_WALLET_FASTSYNC_H
#define ZCL_WALLET_FASTSYNC_H

#include <QString>

// Scheduling policy only. The backend still verifies its compiled checkpoint
// commitment and validates subsequent blocks. Avoid replacing a nearly caught-up
// chain with a large download, or overriding an explicit bootstrap opt-out.
inline bool shouldMigrateToCheckpoint(bool owned, bool mainnet, int height,
                                      const QString& phase, const QString& reason) {
    return owned && mainnet && height > 0 && height < 3126937 - 100000 &&
        phase == QStringLiteral("skipped") &&
        reason.startsWith(QStringLiteral("bootstrap peer download requires a fresh chain datadir;"));
}

#endif
