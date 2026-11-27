// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MainWindow's side of the Node page (nodepage.cpp): it replaces the old contents of
// the node tab and asks the node for what the page shows. Only read-only calls:
//   getblockchaininfo            height, headers, tip time, difficulty, shielded pools
//   getpeerinfo                  peers, how many incoming
//   getnetworksolps ( n height ) network hashrate now, and 36 points over the last day
//   getblock <height> 1          the latest blocks, the first block, the block lookup
//   getblocksubsidy ( height )   the block reward and where it halves next
//   getmempoolinfo, getnetworkinfo
// Nothing is asked while another page is shown.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "nodepage.h"
#include "connection.h"
#include "rpc.h"
#include "settings.h"

#include <QDateTime>
#include <QLabel>
#include <QLayout>
#include <QMap>
#include <QPalette>
#include <QPointer>
#include <QTimer>

namespace {
const int kLatestBlocks = 6;
const int kSeriesPoints = 36;          // over 24 hours
const qint64 kDaySeconds = 86400;

json rpcCall(const char* method, const json& params = json::array()) {
    return json{ {"jsonrpc", "1.0"}, {"id", "someid"}, {"method", method}, {"params", params} };
}

double numberAt(const json& o, const char* key, double fallback = 0.0) {
    if (!o.is_object()) return fallback;
    const auto it = o.find(key);
    return it != o.end() && it->is_number() ? it->get<double>() : fallback;
}

QString stringAt(const json& o, const char* key) {
    if (!o.is_object()) return QString();
    const auto it = o.find(key);
    return it != o.end() && it->is_string() ? QString::fromStdString(it->get<std::string>()) : QString();
}

NodeBlockRow blockRow(const json& b) {
    NodeBlockRow r;
    r.height = int(numberAt(b, "height"));
    r.time = qint64(numberAt(b, "time"));
    r.size = int(numberAt(b, "size"));
    r.hash = stringAt(b, "hash");
    const auto tx = b.is_object() ? b.find("tx") : b.end();
    r.txs = b.is_object() && tx != b.end() && tx->is_array() ? int(tx->size()) : 0;
    return r;
}

// "Sapling" pool value from getblockchaininfo's valuePools, or a negative number.
double poolValue(const json& info, const char* id) {
    const auto pools = info.is_object() ? info.find("valuePools") : info.end();
    if (!info.is_object() || pools == info.end() || !pools->is_array()) return -1.0;
    for (const auto& p : *pools)
        if (stringAt(p, "id") == QLatin1String(id)) return numberAt(p, "chainValue", -1.0);
    return -1.0;
}

// Asks the node and fills the page. One per window; parented to the page.
class NodeFeed : public QObject {
public:
    NodeFeed(RPC* rpc, NodePage* page) : QObject(page), _rpc(rpc), _page(page) {
        auto* poll = new QTimer(this);
        poll->setInterval(5000);
        QObject::connect(poll, &QTimer::timeout, this, [this]() { refresh(); });
        poll->start();
        auto* ages = new QTimer(this);
        ages->setInterval(1000);
        QObject::connect(ages, &QTimer::timeout, this, [this]() { if (_page->isVisible()) _page->refreshAges(); });
        ages->start();
        _page->onLookup = [this](const QString& q) { lookup(q); };
    }

    // Called by the timer and when the page is opened.
    void refresh() {
        if (!_page->isVisible()) return;
        if (_rpc == nullptr || _rpc->getConnection() == nullptr) {
            _page->setDisconnected();
            return;
        }
        ask("getblockchaininfo", json::array(), [this](const json& r) { onChainInfo(r); });
        ask("getpeerinfo", json::array(), [this](const json& r) { onPeers(r); });
        ask("getnetworksolps", json::array(), [this](const json& r) {
            if (r.is_number()) _page->setHashrate(r.get<double>());
        });
        ask("getmempoolinfo", json::array(), [this](const json& r) {
            _mempool = int(numberAt(r, "size", -1));
            publishFacts();
        });
        if (_version.isEmpty())
            ask("getnetworkinfo", json::array(), [this](const json& r) {
                _version = stringAt(r, "subversion").remove('/').replace("MagicBean:", "");
                publishFacts();
            });
    }

private:
    void ask(const char* method, const json& params, const std::function<void(const json&)>& ok,
             const std::function<void()>& failed = nullptr) {
        Connection* conn = _rpc ? _rpc->getConnection() : nullptr;
        if (conn == nullptr) return;
        QPointer<NodeFeed> self(this);
        conn->doRPC(rpcCall(method, params),
            [self, ok](json reply) { if (self) ok(reply); },
            [self, failed](QNetworkReply*, const json&) { if (self && failed) failed(); });
    }

    void onChainInfo(const json& info) {
        if (!info.is_object()) return;
        const int height = int(numberAt(info, "blocks"));
        const int headers = int(numberAt(info, "headers"));
        _tipTime = qint64(numberAt(info, "tiptime"));
        const bool syncing = Settings::getInstance()->isSyncing() || headers > height + 2;
        _page->setTip(height, headers, _tipTime, syncing);
        _page->setDifficulty(numberAt(info, "difficulty"));
        _sapling = poolValue(info, "sapling");
        _sprout = poolValue(info, "sprout");
        if (height != _tip) {
            _tip = height;
            loadBlocks();
            loadReward();
        }
        if (_seriesTip < 0 || height - _seriesTip >= 32) loadSeries();
        if (_genesisTime == 0)
            ask("getblock", json::array({ "0", 1 }), [this](const json& b) {
                _genesisTime = qint64(numberAt(b, "time"));
                publishFacts();
            });
        publishFacts();
    }

    void onPeers(const json& peers) {
        if (!peers.is_array()) return;
        int inbound = 0;
        for (const auto& p : peers) {
            const auto in = p.is_object() ? p.find("inbound") : p.end();
            if (p.is_object() && in != p.end() && in->is_boolean() && in->get<bool>()) ++inbound;
        }
        _page->setPeers(int(peers.size()), inbound);
    }

    // The newest blocks, newest first. Rows already known are kept; only new ones are asked.
    void loadBlocks() {
        const int tip = _tip;
        for (int h = tip; h > tip - kLatestBlocks && h >= 0; --h) {
            if (_blocks.contains(h)) continue;
            ask("getblock", json::array({ std::to_string(h), 1 }), [this](const json& b) {
                const NodeBlockRow row = blockRow(b);
                if (row.hash.isEmpty()) return;
                _blocks.insert(row.height, row);
                publishBlocks();
            });
        }
        publishBlocks();
    }

    void publishBlocks() {
        while (_blocks.size() > kLatestBlocks * 2) _blocks.erase(_blocks.begin());   // oldest first in a QMap
        QList<NodeBlockRow> rows;
        for (int h = _tip; h > _tip - kLatestBlocks; --h)
            if (_blocks.contains(h)) rows.append(_blocks.value(h));
        _page->setBlocks(rows);
        if (rows.size() >= 2) {
            _avgSpacing = double(rows.first().time - rows.last().time) / double(rows.size() - 1);
            publishFacts();
        }
    }

    // 36 points over the last day: the hashrate over each stretch of blocks.
    void loadSeries() {
        const int tip = _tip;
        const int step = qMax(1, int(kDaySeconds / 75 / kSeriesPoints));   // blocks per point at the 75 s target
        _seriesTip = tip;
        auto points = std::make_shared<QMap<int, double>>();
        auto left = std::make_shared<int>(0);
        for (int i = 0; i < kSeriesPoints; ++i) {
            const int h = tip - i * step;
            if (h <= step) break;
            ++*left;
            auto done = [this, points, left, step, tip]() {
                if (--*left > 0) return;
                QVector<QPair<qint64, double>> series;
                for (auto it = points->constBegin(); it != points->constEnd(); ++it)
                    series.append(qMakePair(qint64(tip - it.key()) * 75, it.value()));
                _page->setHashrateSeries(series);
            };
            ask("getnetworksolps", json::array({ step, h }),
                [points, h, done](const json& r) { if (r.is_number()) points->insert(h, r.get<double>()); done(); },
                done);
        }
    }

    // The block reward now, and by bisection the height where it next drops.
    void loadReward() {
        const int tip = _tip;
        ask("getblocksubsidy", json::array({ tip }), [this, tip](const json& r) {
            _reward = numberAt(r, "miner", -1.0);
            publishFacts();
            if (_reward > 0 && (_halvingAt < 0 || tip >= _halvingAt))
                bisectHalving(tip, tip + 4000000, _reward, 24);
        });
    }

    void bisectHalving(int lo, int hi, double rewardNow, int stepsLeft) {
        if (hi - lo <= 1 || stepsLeft == 0) {
            _halvingAt = hi;
            publishFacts();
            return;
        }
        const int mid = lo + (hi - lo) / 2;
        ask("getblocksubsidy", json::array({ mid }), [this, lo, hi, mid, rewardNow, stepsLeft](const json& r) {
            const double reward = numberAt(r, "miner", -1.0);
            if (reward < 0) return;
            if (reward < rewardNow) bisectHalving(lo, mid, rewardNow, stepsLeft - 1);
            else                    bisectHalving(mid, hi, rewardNow, stepsLeft - 1);
        });
    }

    void publishFacts() {
        QList<QPair<QString, QString>> facts;
        addRewardFacts(facts);
        addChainFacts(facts);
        _page->setFacts(facts);
    }

    void addRewardFacts(QList<QPair<QString, QString>>& facts) const {
        if (_reward >= 0)
            facts << qMakePair(tr("Block reward"), Settings::getZCLDisplayFormat(_reward));
        if (_halvingAt > 0 && _tip > 0 && _halvingAt > _tip) {
            const double days = double(_halvingAt - _tip) * 75.0 / 86400.0;
            facts << qMakePair(tr("Next halving"), tr("block %1 · about %2 days")
                .arg(NodePage::formatCount(_halvingAt)).arg(QString::number(days, 'f', 0)));
        }
    }

    void addChainFacts(QList<QPair<QString, QString>>& facts) const {
        if (_avgSpacing > 0)
            facts << qMakePair(tr("Block time"), tr("%1 s lately · target 75 s")
                .arg(QString::number(_avgSpacing, 'f', 0)));
        if (_sapling >= 0)
            facts << qMakePair(tr("In private addresses"), tr("%1 ZCL").arg(NodePage::formatCount(qint64(_sapling)))
                + (_sprout > 0 ? tr(" (plus %1 in legacy Sprout)").arg(tr("%1 ZCL").arg(NodePage::formatCount(qint64(_sprout)))) : QString()));
        if (_mempool >= 0)
            facts << qMakePair(tr("Waiting transactions"), _mempool == 0 ? tr("none") : QString::number(_mempool));
        if (_genesisTime > 0) {
            const qint64 days = (QDateTime::currentSecsSinceEpoch() - _genesisTime) / 86400;
            facts << qMakePair(tr("Running since"), tr("%1 · %2 days")
                .arg(QDateTime::fromSecsSinceEpoch(_genesisTime).toUTC().date().toString("d MMM yyyy"))
                .arg(NodePage::formatCount(days)));
        }
        if (!_version.isEmpty())
            facts << qMakePair(tr("Node version"), _version);
    }

    void lookup(const QString& query) {
        ask("getblock", json::array({ query.toStdString(), 1 }),
            [this](const json& b) {
                const NodeBlockRow r = blockRow(b);
                if (r.hash.isEmpty()) {
                    _page->setLookupResult(tr("No block found for that height or hash."), false);
                    return;
                }
                _page->setLookupResult(tr("Block %1 · mined %2 UTC · %3 transactions · %4 bytes · difficulty %5\n%6")
                    .arg(NodePage::formatCount(r.height))
                    .arg(QDateTime::fromSecsSinceEpoch(r.time).toUTC().toString("d MMM yyyy, HH:mm:ss"))
                    .arg(r.txs).arg(NodePage::formatCount(r.size))
                    .arg(QString::number(numberAt(b, "difficulty"), 'f', 2)).arg(r.hash), true);
            },
            [this]() { _page->setLookupResult(tr("No block found for that height or hash."), false); });
    }

    RPC*      _rpc;
    NodePage* _page;
    int       _tip = -1;
    int       _seriesTip = -1;
    qint64    _tipTime = 0;
    qint64    _genesisTime = 0;
    double    _reward = -1.0;
    int       _halvingAt = -1;
    double    _avgSpacing = 0.0;
    double    _sapling = -1.0;
    double    _sprout = -1.0;
    int       _mempool = -1;
    QString   _version;
    QMap<int, NodeBlockRow> _blocks;
};
}   // namespace

// Replace the old node tab (a logo, three bare rows) with the Node page. The old
// labels stay, hidden: rpc.cpp still writes them.
void MainWindow::buildNodePage() {
    if (nodePage != nullptr || zclassicdtab == nullptr || zclassicdtab->layout() == nullptr) return;
    ui->zclassicdlogo->hide();
    ui->groupBox_5->hide();
    nodePage = new NodePage(zclassicdtab);
    zclassicdtab->layout()->addWidget(nodePage);
    nodePage->adoptHelpPanel(netHelpPanel);
    QObject::connect(ui->tabWidget, &QTabWidget::currentChanged, this, [this](int) {
        if (ui->tabWidget->currentWidget() == zclassicdtab) refreshNodePage();
    });
}

// Start asking the node once there is one; called when the page is opened.
void MainWindow::refreshNodePage() {
    if (nodePage == nullptr || rpc == nullptr) return;
    auto* feed = nodePage->findChild<QObject*>("nodeFeed");
    if (feed == nullptr) {
        feed = new NodeFeed(rpc, nodePage);
        feed->setObjectName("nodeFeed");
    }
    static_cast<NodeFeed*>(feed)->refresh();
}
