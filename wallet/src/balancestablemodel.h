#ifndef BALANCESTABLEMODEL_H
#define BALANCESTABLEMODEL_H

#include "precompiled.h"
#include <QSet>

struct UnspentOutput {
    QString address;
    QString txid;
    QString amount;
    int     confirmations;
    bool    spendable;
    // listunspent "generated": true for a coinbase UTXO. z_sendmany cannot spend
    // coinbase to a transparent output or alongside change (consensus rule
    // bad-txns-coinbase-spend-has-transparent-outputs), so the auto-shield change
    // basis must EXCLUDE these. C++14 default member init keeps this an aggregate,
    // so existing brace-initializers without the field still compile (coinbase=false).
    bool    coinbase = false;
};

class BalancesTableModel : public QAbstractTableModel
{
public:
    BalancesTableModel(QObject* parent);
    ~BalancesTableModel();

    void setNewData(const QMap<QString, double>* balances, const QList<UnspentOutput>* outputs);

    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

private:
    // PERF (Phase 4 Win 2): content fingerprint of the incoming balances + utxos, so
    // an unchanged poll early-outs without re-emitting model signals (no flicker, no
    // CPU). Folds in per-address balances AND each utxo's address+confirmations
    // (confirmations==0 paints a row red, so it must affect the fingerprint).
    static QByteArray fingerprint(const QMap<QString, double>* balances,
                                  const QList<UnspentOutput>* outputs);
    QByteArray lastFingerprint;

    QList<std::tuple<QString, double>>*    modeldata   = nullptr;
    QList<UnspentOutput>*                  utxos       = nullptr;

    // PERF (PM-2): precomputed set of addresses that have at least one utxo with
    // confirmations==0 (those rows paint red). Built once in setNewData() (behind the
    // fingerprint gate, so only on real data change) and queried O(1) in
    // data(ForegroundRole), replacing a per-repaint O(rows*utxos) scan that also deep-
    // copied each UnspentOutput per inner step.
    QSet<QString>                          unconfirmedAddrs;

    bool loading = true;
};

#endif // BALANCESTABLEMODEL_H