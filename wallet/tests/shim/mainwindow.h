// ============================================================================
// TEST SHIM mainwindow.h  (L0 unit suite — tst_logic)
//
// Stands in for src/mainwindow.h so that senttxstore.cpp / settings.cpp resolve
// their `#include "mainwindow.h"` to a *lightweight* header that carries ONLY
// the plain-data structs they actually use (ToFields, Tx) — and pulls in NO
// QMainWindow, NO Ui::, NO RPC, NO logger.
//
// The ToFields/Tx layout is copied EXACTLY from src/mainwindow.h:18-31 so the
// aggregate fields senttxstore.cpp reads (tx.fromAddr, tx.toAddrs, tx.fee,
// ToFields::addr, ToFields::amount) are byte-for-byte the same product type.
// ============================================================================
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "precompiled.h"

using json = nlohmann::json;

// Struct used to hold destination info when sending a Tx.  (src/mainwindow.h:18-23)
struct ToFields {
    QString addr;
    double  amount;
    QString txtMemo;
    QString encodedMemo;
};

// Struct used to represent a Transaction.  (src/mainwindow.h:26-30)
struct Tx {
    QString         fromAddr;
    QList<ToFields> toAddrs;
    double          fee;
};

// PRIV-11 / UX-12 — the four-way SendCategory enum AND the pure classifier
// `sendCategoryOf()` are the SINGLE SOURCE OF TRUTH in src/sendcategory.h (resolved
// via the L0 target's INCLUDEPATH += ../src). The L0 suite links that exact body —
// no hand-copied enum or mirrored logic lives in this shim anymore. Included AFTER
// the Tx/ToFields structs above, on which the classifier operates.
#include "sendcategory.h"

#endif // MAINWINDOW_H
