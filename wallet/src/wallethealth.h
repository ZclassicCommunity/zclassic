// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// What the status bar says about the wallet itself, from getwalletinfo's "health" object (pure: QtCore + json, so
// tst_logic links the body the wallet runs).
//
// The line is for things that need attention and nothing else: a healthy wallet shows nothing at all, and so does a
// node that is too old to report health. Every condition below names what the user can expect, not an internal
// counter.
#ifndef ZCL_WALLETHEALTH_H
#define ZCL_WALLETHEALTH_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QtGlobal>

#include "3rdparty/json/json.hpp"

namespace wallethealth {

using json = nlohmann::json;

// The node writes its wallet checkpoint about hourly (about 48 blocks), and as soon as it has caught up with the
// network after a long sync (CWallet::CheckpointIfLagging). A checkpoint this far behind the tip on a node that is
// up to date means the node could not write it, and a restart would have a long rescan to do.
constexpr qint64 kCheckpointLagBlocks = 1000;

struct Report {
    QStringList lines;
    bool any() const { return !lines.isEmpty(); }
    QString summary() const { return QObject::tr("Wallet needs attention (%n)", nullptr, lines.size()); }
    QString tooltip() const { return lines.join(QStringLiteral("\n\n")); }
};

inline qint64 num(const json& o, const char* k) {
    if (!o.is_object()) return 0;
    auto f = o.find(k);
    if (f == o.end()) return 0;
    if (f->is_number_integer()) return (qint64)f->get<json::number_integer_t>();
    if (f->is_number_unsigned()) return (qint64)f->get<json::number_unsigned_t>();
    return 0;
}

inline bool flag(const json& o, const char* k) {
    if (!o.is_object()) return false;
    auto f = o.find(k);
    return f != o.end() && f->is_boolean() && f->get<bool>();
}

// The checkpoint line: a failed write, else a lag that persisted.
inline void checkpointLine(const json& h, Report& r) {
    const qint64 tip = num(h, "tip_height"), cp = num(h, "checkpoint_height");
    if (flag(h, "checkpoint_failed"))
        r.lines << QObject::tr("The wallet file could not be saved. Your funds are safe, but if the node stops unexpectedly it "
                               "will have to rescan the blockchain at the next start. Check the free disk space.");
    else if (cp >= 0 && tip - cp > kCheckpointLagBlocks)
        r.lines << QObject::tr("The wallet file was last saved %1 blocks ago. If the node stops unexpectedly it will "
                               "have to rescan from there.").arg(tip - cp);
}

// info: the reply of getwalletinfo. synced: the node is up to date with the network (while it catches up the
// checkpoint and the note proofs are legitimately behind, and saying so would only be noise).
inline Report assess(const json& info, bool synced) {
    Report r;
    if (!info.is_object()) return r;
    auto hi = info.find("health");
    if (hi == info.end() || !hi->is_object()) return r;     // an older node: nothing to say
    const json& h = *hi;

    if (flag(h, "witness_rebuild_pending"))
        r.lines << QObject::tr("The proofs needed to spend your shielded funds are being rebuilt after a change in the "
                               "blockchain. Shielded funds may show as unavailable until the wallet has finished rescanning.");

    if (synced) {
        qint64 missing = 0;
        for (const char* pool : { "sapling", "sprout" }) {
            auto p = h.find(pool);
            if (p != h.end()) missing += num(*p, "witness_missing");
        }
        if (missing > 0)
            r.lines << QObject::tr("%1 shielded note(s) cannot be spent yet: the wallet is still rebuilding their proofs.").arg(missing);

        checkpointLine(h, r);
    }

    auto ps = h.find("pending_sends");
    if (ps != h.end() && ps->is_object()) {
        const qint64 notIn = num(*ps, "not_in_mempool"), soon = num(*ps, "expiring_soon");
        const qint64 expired = num(*ps, "expired"), conflicted = num(*ps, "conflicted");
        if (notIn > 0)
            r.lines << QObject::tr("%1 sent transaction(s) are not in the node's mempool and have not been mined. They expire if "
                                   "they are not mined in time.").arg(notIn);
        if (soon > 0)
            r.lines << QObject::tr("%1 sent transaction(s) will expire within a few blocks if they are not mined.").arg(soon);
        if (expired > 0)
            r.lines << QObject::tr("%1 sent transaction(s) expired without being mined. Their funds are back in your balance.").arg(expired);
        if (conflicted > 0)
            r.lines << QObject::tr("%1 sent transaction(s) conflict with one that was mined and will never confirm.").arg(conflicted);
    }
    return r;
}

}  // namespace wallethealth

#endif  // ZCL_WALLETHEALTH_H
