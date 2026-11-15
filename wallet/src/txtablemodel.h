#ifndef STRINGSTABLEMODEL_H
#define STRINGSTABLEMODEL_H

#include "precompiled.h"

struct TransactionItem;

class TxTableModel: public QAbstractTableModel
{
public:
    TxTableModel(QObject* parent);    
    ~TxTableModel();

    void addTData    (const QList<TransactionItem>& data);
    void addZSentData(const QList<TransactionItem>& data);
    void addZRecvData(const QList<TransactionItem>& data);     

    QString  getTxId(int row) const;
    QString  getMemo(int row) const;
    QString  getAddr(int row) const;
    qint64   getDate(int row) const;
    QString  getType(int row) const;
    qint64   getConfirmations(int row) const;
    QString  getAmt (int row) const;

    bool     exportToCsv(QString fileName) const;

    int      rowCount(const QModelIndex &parent) const;
    int      columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

private:
    void updateAllData();

    // PERF (Phase 4 Win 2): a cheap content fingerprint of an incoming list, so a
    // setter whose data is byte-for-byte identical to what's already applied can
    // early-out without rebuilding the model (no dataChanged/layoutChanged -> no
    // flicker, no wasted CPU on every poll). The fingerprint folds in every field
    // that affects rendering -- crucially `confirmations`, so a pending->confirmed
    // transition changes the fingerprint and repaints.
    static QByteArray fingerprint(const QList<TransactionItem>& data);
    QByteArray lastTFingerprint;
    QByteArray lastZrFingerprint;
    QByteArray lastZsFingerprint;

    QList<TransactionItem>*  tTrans      = nullptr;
    QList<TransactionItem>*  zrTrans     = nullptr;     // Z received
    QList<TransactionItem>*  zsTrans     = nullptr;     // Z sent

    QList<TransactionItem>* modeldata    = nullptr;

    QList<QString>           headers;
};


#endif // STRINGSTABLEMODEL_H
