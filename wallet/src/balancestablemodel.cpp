#include "balancestablemodel.h"
#include "addressbook.h"
#include "settings.h"


BalancesTableModel::BalancesTableModel(QObject *parent)
    : QAbstractTableModel(parent) {
}

// PERF (Phase 4 Win 2): fold the render-affecting inputs into a compact fingerprint.
// The displayed rows are (address -> balance) for every positive balance; row COLOUR
// additionally depends on whether ANY utxo for that address has confirmations==0. So
// we hash both the (sorted) balances and each utxo's (address, confirmations). A
// leading sentinel keeps an empty input distinct from a never-set (null) cache.
QByteArray BalancesTableModel::fingerprint(const QMap<QString, double>* balances,
                                           const QList<UnspentOutput>* outputs) {
    QByteArray buf;
    buf.append('v');   // sentinel: non-null even when both inputs are empty

    // Balances: iterate in QMap's key order (deterministic) for a stable encoding.
    buf.append('B');
    for (auto it = balances->constBegin(); it != balances->constEnd(); ++it) {
        buf.append(it.key().toUtf8());                       buf.append('\x1f');
        buf.append(QByteArray::number(it.value(), 'f', 8));  buf.append('\x1e');
    }

    // UTXOs: only the fields that affect display/colour (address + confirmations).
    buf.append('U');
    for (const auto& u : *outputs) {
        buf.append(u.address.toUtf8());                      buf.append('\x1f');
        buf.append(QByteArray::number(u.confirmations));     buf.append('\x1e');
    }

    return QCryptographicHash::hash(buf, QCryptographicHash::Sha1);
}

void BalancesTableModel::setNewData(const QMap<QString, double>* balances,
    const QList<UnspentOutput>* outputs)
{
    loading = false;

    // PERF (Phase 4 Win 2): unchanged data -> skip the rebuild entirely (no
    // dataChanged/layoutChanged, no flicker, no per-poll CPU). NOTE: `loading` is
    // cleared above first, so the very first real call (which flips loading false and
    // replaces the "Loading..." placeholder row) is never wrongly suppressed by a
    // stale fingerprint.
    QByteArray fp = fingerprint(balances, outputs);
    if (fp == lastFingerprint)
        return;
    lastFingerprint = fp;

    int currentRows = rowCount(QModelIndex());
    // Copy over the utxos for our use
    delete utxos;
    utxos = new QList<UnspentOutput>();
    // This is a QList deep copy.
    *utxos = *outputs;

    // PERF (PM-2): precompute the address->has-unconfirmed-utxo relation ONCE here
    // (we are past the fingerprint gate, so this only runs on a real data change).
    // data(ForegroundRole) then does an O(1) set lookup instead of scanning every
    // utxo (with a per-element struct copy) for every visible row on every repaint.
    unconfirmedAddrs.clear();
    for (const auto& u : *outputs) {
        if (u.confirmations == 0)
            unconfirmedAddrs.insert(u.address);
    }

    // Process the address balances into a list
    delete modeldata;
    modeldata = new QList<std::tuple<QString, double>>();
    std::for_each(balances->keyBegin(), balances->keyEnd(), [=] (auto keyIt) {
        if (balances->value(keyIt) > 0)
            modeldata->push_back(std::make_tuple(keyIt, balances->value(keyIt)));
    });

    // And then update the data
    dataChanged(index(0, 0), index(modeldata->size()-1, columnCount(index(0,0))-1));

    // Change the layout only if the number of rows changed
    if (modeldata && modeldata->size() != currentRows)
        layoutChanged();
}

BalancesTableModel::~BalancesTableModel() {
    delete modeldata;
    delete utxos;
}

int BalancesTableModel::rowCount(const QModelIndex&) const
{
    if (modeldata == nullptr) {
        if (loading) 
            return 1;
        else 
            return 0;
    }
    return modeldata->size();
}

int BalancesTableModel::columnCount(const QModelIndex&) const
{
    return 2;
}

QVariant BalancesTableModel::data(const QModelIndex &index, int role) const
{
    if (loading) {
        if (role == Qt::DisplayRole) 
            return "Loading...";
        else
            return QVariant();
    }

    if (role == Qt::TextAlignmentRole && index.column() == 1) return QVariant(Qt::AlignRight | Qt::AlignVCenter);
    
    if (role == Qt::ForegroundRole) {
        // PERF (PM-2): O(1) lookup against the set precomputed in setNewData(), instead
        // of an O(utxos) scan (with a per-iteration UnspentOutput copy) on every repaint.
        // If any utxo for this address is unconfirmed, paint the row red.
        const auto& addr = std::get<0>(modeldata->at(index.row()));
        QBrush b;
        b.setColor(unconfirmedAddrs.contains(addr) ? Qt::red : Qt::black);
        return b;
    }
    
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case 0: return AddressBook::addLabelToAddress(std::get<0>(modeldata->at(index.row())));
        case 1: return Settings::getZCLDisplayFormat(std::get<1>(modeldata->at(index.row())));
        }
    }

    if(role == Qt::ToolTipRole) {
        switch (index.column()) {
        case 0: return AddressBook::addLabelToAddress(std::get<0>(modeldata->at(index.row())));
        case 1: return Settings::getUSDFormat(std::get<1>(modeldata->at(index.row())));
        }
    }
    
    return QVariant();
}


QVariant BalancesTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::TextAlignmentRole && section == 1) {
        return QVariant(Qt::AlignRight | Qt::AlignVCenter);
    }

    if (role == Qt::FontRole) {
        QFont f;
        f.setBold(true);
        return f;
    }

    if (role != Qt::DisplayRole)
        return QVariant();

    if (orientation == Qt::Horizontal) {
        switch (section) {
        case 0:                 return tr("Address");
        case 1:                 return tr("Amount");
        default:                return QVariant();
        }
    }
    return QVariant();
}

