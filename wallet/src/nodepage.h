// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The Node page: what the wallet's own node sees. Status tiles (block height,
// peers, network hashrate, difficulty), the network hashrate over the last day,
// facts about the chain read from the node, the latest blocks with a block
// lookup, and the "helping the network" panel. The page only shows what it is
// given (nodewiring.cpp asks the node); it never talks to the node itself, so
// tests fill it directly.
#ifndef NODEPAGE_H
#define NODEPAGE_H

#include <QList>
#include <QPair>
#include <QString>
#include <QVector>
#include <QWidget>

#include <functional>

class QGridLayout;
class QGroupBox;
class QLabel;
class QLineEdit;
class QTreeWidget;
class QVBoxLayout;

// One row of "Latest blocks".
struct NodeBlockRow {
    int     height = 0;
    qint64  time = 0;       // block time, seconds since the epoch
    int     txs = 0;
    int     size = 0;       // bytes
    QString hash;
};

// A plain line chart with a filled area: y over x, oldest first.
class HashrateChart : public QWidget {
public:
    explicit HashrateChart(QWidget* parent = nullptr);
    // (seconds before now, solutions per second), oldest first.
    void setSeries(const QVector<QPair<qint64, double>>& points);
    int  pointCount() const { return _points.size(); }
    QSize sizeHint() const override { return QSize(420, 190); }
protected:
    void paintEvent(QPaintEvent*) override;
private:
    QVector<QPair<qint64, double>> _points;
};

class NodePage : public QWidget {
public:
    explicit NodePage(QWidget* parent = nullptr);

    // Asked of MainWindow: look up a block by height or hash.
    std::function<void(const QString&)> onLookup;

    // From the node.
    void setTip(int height, int headers, qint64 tipTime, bool syncing);
    void setPeers(int total, int inbound);
    void setHashrate(double solutionsPerSecond);
    void setDifficulty(double difficulty);
    void setHashrateSeries(const QVector<QPair<qint64, double>>& points);
    void setBlocks(const QList<NodeBlockRow>& newestFirst);
    void setFacts(const QList<QPair<QString, QString>>& facts);
    void setLookupResult(const QString& text, bool found);
    void setDisconnected();
    // The existing "helping the network" panel (built by MainWindow) moves here.
    void adoptHelpPanel(QWidget* panel);
    // "12 s ago" texts age without a new answer from the node.
    void refreshAges();

    // "14.5 kSol/s"; "3,333,515"; "12 s ago" / "4 min ago" / "3 h ago".
    static QString formatRate(double solutionsPerSecond);
    static QString formatCount(qint64 n);
    static QString formatAge(qint64 seconds);

private:
    QWidget*   buildTiles();
    QGroupBox* buildChartCard();
    QGroupBox* buildFactsCard();
    QGroupBox* buildBlocksCard();
    QWidget*   makeTile(const QString& caption, QLabel*& value, QLabel*& note);
    void       runLookup();

    QLabel* _heightValue = nullptr;  QLabel* _heightNote = nullptr;
    QLabel* _peersValue = nullptr;   QLabel* _peersNote = nullptr;
    QLabel* _rateValue = nullptr;    QLabel* _rateNote = nullptr;
    QLabel* _diffValue = nullptr;    QLabel* _diffNote = nullptr;
    HashrateChart* _chart = nullptr;
    QLabel*      _chartNote = nullptr;
    QGridLayout* _factsGrid = nullptr;
    QTreeWidget* _blocks = nullptr;
    QLineEdit*   _lookupField = nullptr;
    QLabel*      _lookupResult = nullptr;
    QGroupBox*   _helpCard = nullptr;
    QVBoxLayout* _helpBox = nullptr;

    int    _height = -1;
    int    _headers = -1;
    qint64 _tipTime = 0;
    bool   _syncing = false;
    QList<NodeBlockRow> _rows;
};

#endif // NODEPAGE_H
