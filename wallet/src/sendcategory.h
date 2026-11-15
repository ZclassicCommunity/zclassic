// ============================================================================
// sendcategory.h — the SINGLE SOURCE OF TRUTH for the PRIV-11/UX-12 four-way
// send classification.
//
// Header-only: the enum + the pure free classifier `sendCategoryOf()` live here
// and ONLY here, so production (MainWindow::classifySend forwards to it) AND the
// L0 unit suite (tst_logic) link the exact same body — no hand-copied mirror can
// silently drift. The classifier depends only on Settings::isZAddress (a static),
// so this header pulls in settings.h; it constructs no MainWindow / widget / RPC.
//
// Tx/ToFields are defined by whatever mainwindow.h is in scope (the real one in
// the app build, the lightweight shim in the L0 build), so this header is
// included AFTER those structs are declared.
// ============================================================================
#ifndef SENDCATEGORY_H
#define SENDCATEGORY_H

#include "settings.h"

// PRIV-11 / UX-12 — four-way, from-aware privacy classification of a send.
// Replaces the old binary "isPublicTx". The category is decided by the FROM
// address type and whether ANY recipient is transparent:
//   ZToZ_private    z-from, all recipients shielded    -> private/green, no warning
//   TToZ_shielding  t-from, all recipients shielded     -> shielding/neutral
//   ZToT_deshield   z-from, ANY transparent recipient   -> DE-SHIELD/red (strongest;
//                       names PUBLIC + sender-linkage; PRIV-12 requires an explicit
//                       acknowledgement before sending)
//   TToT_public     t-from, ANY transparent recipient   -> public/amber
enum class SendCategory {
    ZToZ_private,
    TToZ_shielding,
    ZToT_deshield,
    TToT_public
};

// The pure classifier. Depends ONLY on the address TYPES (no widget / RPC state),
// so both confirmTx() and the L0/L1 tests drive every quadrant directly.
//
// NIT-1 fail-safe: an UNPARSEABLE / invalid recipient (NOT a recognized z-address)
// is treated as TRANSPARENT, so a malformed z->? errs toward the stronger
// DE-SHIELD warning, never toward "private".
inline SendCategory sendCategoryOf(const Tx& tx) {
    bool anyTransparentRecipient = false;
    for (const auto& to : tx.toAddrs) {
        // Public the moment ANY recipient is transparent OR is not a recognized
        // z-address (fail-safe: anything not provably shielded counts as public).
        if (!Settings::isZAddress(to.addr)) {
            anyTransparentRecipient = true;
            break;
        }
    }

    const bool fromShielded = Settings::isZAddress(tx.fromAddr);

    if (anyTransparentRecipient)
        return fromShielded ? SendCategory::ZToT_deshield : SendCategory::TToT_public;
    else
        return fromShielded ? SendCategory::ZToZ_private : SendCategory::TToZ_shielding;
}

// PRIV-12 — the de-shield acknowledgement gate fires IFF the send is a z->t
// DE-SHIELD. Single source of truth so production (MainWindow::isDeshield) and the
// L0 gate test agree by construction.
inline bool isDeshieldSend(const Tx& tx) {
    return sendCategoryOf(tx) == SendCategory::ZToT_deshield;
}

#endif // SENDCATEGORY_H
