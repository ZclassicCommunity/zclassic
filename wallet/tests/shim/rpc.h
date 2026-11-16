// ============================================================================
// TEST SHIM rpc.h  (L0 unit suite — tst_logic)
//
// Stands in for src/rpc.h so senttxstore.cpp resolves `#include "rpc.h"` to a
// header carrying ONLY the TransactionItem struct it needs — NO RPC class, NO
// balancestablemodel/txtablemodel/ui_mainwindow/connection pulls.
//
// TransactionItem layout copied EXACTLY from src/rpc.h:16-25. senttxstore.cpp:42
// aggregate-initializes all 8 fields in this exact order/type, so a mere forward
// declaration would NOT compile — the full definition is mandatory:
//   { "send", (qint64)datetime, address, txid, amount, 0, from, "" }
//     type    datetime          address  txid  amount  conf from  memo
// ============================================================================
#ifndef RPCCLIENT_H
#define RPCCLIENT_H

#include "precompiled.h"
#include "mainwindow.h"

using json = nlohmann::json;

struct TransactionItem {
    QString         type;
    qint64          datetime;
    QString         address;
    QString         txid;
    double          amount;
    unsigned long   confirmations;
    QString         fromAddr;
    QString         memo;
};

#endif // RPCCLIENT_H
