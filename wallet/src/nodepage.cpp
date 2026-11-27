// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "nodepage.h"

#include <QDateTime>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QClipboard>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace {
const QColor kGreen(0x5f, 0xd3, 0x8d);
const QColor kDim(0x9a, 0xa5, 0x9d);
const QColor kLine(0x23, 0x2b, 0x26);

QLabel* dimLabel(const QString& text, QWidget* parent) {
    auto* l = new QLabel(text, parent);
    l->setObjectName("nodeDim");
    l->setWordWrap(true);
    return l;
}
}   // namespace

// ---- chart -------------------------------------------------------------------

HashrateChart::HashrateChart(QWidget* parent) : QWidget(parent) {
    setObjectName("nodeChart");
    setMinimumHeight(150);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
}

void HashrateChart::setSeries(const QVector<QPair<qint64, double>>& points) {
    _points = points;
    update();
}

void HashrateChart::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF plot = QRectF(rect()).adjusted(4, 22, -4, -22);
    QFont small = font();
    small.setPointSizeF(9.5);
    p.setFont(small);
    p.setPen(kDim);
    if (_points.size() < 2) {
        p.drawText(rect(), Qt::AlignCenter, QObject::tr("Collecting the last 24 hours…"));
        return;
    }
    double lo = _points.first().second, hi = lo;
    for (const auto& pt : _points) { lo = qMin(lo, pt.second); hi = qMax(hi, pt.second); }
    const double pad = qMax((hi - lo) * 0.15, hi * 0.02);
    const double yMin = qMax(0.0, lo - pad), yMax = hi + pad;
    const qint64 xMin = _points.first().first, xMax = _points.last().first;   // seconds before now: large -> small
    auto at = [&](const QPair<qint64, double>& pt) {
        const double fx = xMin == xMax ? 1.0 : double(xMin - pt.first) / double(xMin - xMax);
        const double fy = yMax <= yMin ? 0.5 : (pt.second - yMin) / (yMax - yMin);
        return QPointF(plot.left() + fx * plot.width(), plot.bottom() - fy * plot.height());
    };
    QPainterPath line;
    line.moveTo(at(_points.first()));
    for (int i = 1; i < _points.size(); ++i) line.lineTo(at(_points.at(i)));
    QPainterPath area = line;
    area.lineTo(plot.right(), plot.bottom());
    area.lineTo(plot.left(), plot.bottom());
    area.closeSubpath();

    p.setPen(QPen(kLine, 1));
    p.drawLine(plot.bottomLeft(), plot.bottomRight());
    p.drawLine(plot.topLeft(), plot.topRight());
    QColor fill = kGreen;
    fill.setAlpha(38);
    p.fillPath(area, fill);
    p.setPen(QPen(kGreen, 2));
    p.drawPath(line);

    p.setPen(kDim);
    p.drawText(QRectF(plot.left(), 0, plot.width(), 20), Qt::AlignLeft | Qt::AlignVCenter,
               QObject::tr("high %1").arg(NodePage::formatRate(hi)));
    p.drawText(QRectF(plot.left(), 0, plot.width(), 20), Qt::AlignRight | Qt::AlignVCenter,
               QObject::tr("low %1").arg(NodePage::formatRate(lo)));
    p.drawText(QRectF(plot.left(), plot.bottom() + 2, plot.width(), 20), Qt::AlignLeft | Qt::AlignVCenter,
               NodePage::formatAge(xMin));
    p.drawText(QRectF(plot.left(), plot.bottom() + 2, plot.width(), 20), Qt::AlignRight | Qt::AlignVCenter,
               QObject::tr("now"));
}

// ---- formatting --------------------------------------------------------------

QString NodePage::formatRate(double sol) {
    if (sol >= 1e9) return QString::number(sol / 1e9, 'f', 2) + QObject::tr(" GSol/s");
    if (sol >= 1e6) return QString::number(sol / 1e6, 'f', 2) + QObject::tr(" MSol/s");
    if (sol >= 1e3) return QString::number(sol / 1e3, 'f', 1) + QObject::tr(" kSol/s");
    return QString::number(sol, 'f', 0) + QObject::tr(" Sol/s");
}

QString NodePage::formatCount(qint64 n) {
    return QLocale(QLocale::English).toString(n);
}

QString NodePage::formatAge(qint64 seconds) {
    if (seconds < 0) seconds = 0;
    if (seconds < 90) return QObject::tr("%1 s ago").arg(seconds);
    if (seconds < 5400) return QObject::tr("%1 min ago").arg((seconds + 30) / 60);
    if (seconds < 172800) return QObject::tr("%1 h ago").arg((seconds + 1800) / 3600);
    return QObject::tr("%1 days ago").arg((seconds + 43200) / 86400);
}

// ---- construction ------------------------------------------------------------

NodePage::NodePage(QWidget* parent) : QWidget(parent) {
    setObjectName("nodePage");
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea(this);
    scroll->setObjectName("nodeScroll");
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* body = new QWidget(scroll);
    body->setObjectName("nodeBody");
    auto* col = new QVBoxLayout(body);
    col->setContentsMargins(0, 0, 8, 0);
    col->setSpacing(14);

    col->addWidget(buildTiles());
    _mid = new QBoxLayout(QBoxLayout::LeftToRight);
    _mid->setSpacing(14);
    _mid->addWidget(buildChartCard(), 5);
    _mid->addWidget(buildFactsCard(), 4);
    col->addLayout(_mid);
    col->addWidget(buildBlocksCard());

    _helpCard = new QGroupBox(tr("Your node and the network"), body);
    _helpCard->setObjectName("nodeHelpCard");
    _helpBox = new QVBoxLayout(_helpCard);
    _helpCard->hide();   // shown once MainWindow hands over its panel
    col->addWidget(_helpCard);
    col->addStretch(1);

    scroll->setWidget(body);
    outer->addWidget(scroll);
    setDisconnected();
}

QWidget* NodePage::makeTile(const QString& caption, QLabel*& value, QLabel*& note) {
    auto* tile = new QFrame(this);
    tile->setObjectName("nodeTile");
    auto* v = new QVBoxLayout(tile);
    v->setContentsMargins(18, 14, 18, 14);
    v->setSpacing(2);
    auto* cap = new QLabel(caption, tile);
    cap->setObjectName("nodeTileCaption");
    value = new QLabel(QStringLiteral("—"), tile);
    value->setObjectName("nodeTileValue");
    value->setTextInteractionFlags(Qt::TextSelectableByMouse);
    note = new QLabel(tile);
    note->setObjectName("nodeTileNote");
    note->setWordWrap(true);   // a long note wraps instead of widening the tile
    v->addWidget(cap);
    v->addWidget(value);
    v->addWidget(note);
    return tile;
}

QWidget* NodePage::buildTiles() {
    auto* row = new QWidget(this);
    _tilesGrid = new QGridLayout(row);
    _tilesGrid->setContentsMargins(0, 0, 0, 0);
    _tilesGrid->setSpacing(14);
    _tiles << makeTile(tr("Block height"), _heightValue, _heightNote)
           << makeTile(tr("Peers"), _peersValue, _peersNote)
           << makeTile(tr("Network hashrate"), _rateValue, _rateNote)
           << makeTile(tr("Difficulty"), _diffValue, _diffNote);
    _heightValue->setObjectName("nodeTileValueLead");
    reflow(4, true);
    return row;
}

// A page too narrow for four tiles in a row shows them two by two, and a narrower one puts
// the facts under the chart, so nothing is cut off at the right edge.
void NodePage::reflow(int tileColumns, bool chartBesideFacts) {
    if (tileColumns != _tileColumns) {
        _tileColumns = tileColumns;
        for (QWidget* t : _tiles) _tilesGrid->removeWidget(t);
        for (int i = 0; i < _tiles.size(); ++i) _tilesGrid->addWidget(_tiles.at(i), i / tileColumns, i % tileColumns);
        for (int c = 0; c < 4; ++c) _tilesGrid->setColumnStretch(c, c < tileColumns ? 1 : 0);
    }
    if (_mid) _mid->setDirection(chartBesideFacts ? QBoxLayout::LeftToRight : QBoxLayout::TopToBottom);
}

void NodePage::resizeEvent(QResizeEvent* event) {
    QWidget::resizeEvent(event);
    int fourAcross = 3 * 14 + 24;   // gaps, the scroll bar and its margin
    for (QWidget* t : _tiles) fourAcross += t->minimumSizeHint().width();
    reflow(width() >= fourAcross ? 4 : 2, width() >= 880);
    QTimer::singleShot(0, this, [this]() { fitHashes(); });   // once the new widths are laid out
}

QGroupBox* NodePage::buildChartCard() {
    auto* card = new QGroupBox(tr("Network hashrate, last 24 hours"), this);
    card->setObjectName("nodeChartCard");
    auto* v = new QVBoxLayout(card);
    v->setSpacing(6);
    _chart = new HashrateChart(card);
    v->addWidget(_chart, 1);
    _chartNote = dimLabel(tr("The combined mining power securing ZClassic, as this node estimates it from recent blocks."), card);
    v->addWidget(_chartNote);
    return card;
}

QGroupBox* NodePage::buildFactsCard() {
    auto* card = new QGroupBox(tr("About the chain"), this);
    card->setObjectName("nodeFactsCard");
    _factsGrid = new QGridLayout(card);
    _factsGrid->setHorizontalSpacing(16);
    _factsGrid->setVerticalSpacing(8);
    _factsGrid->setColumnStretch(1, 1);
    return card;
}

QGroupBox* NodePage::buildBlocksCard() {
    auto* card = new QGroupBox(tr("Latest blocks"), this);
    card->setObjectName("nodeBlocksCard");
    auto* v = new QVBoxLayout(card);
    v->setSpacing(10);
    _blocksBox = new QVBoxLayout();
    _blocksBox->setSpacing(0);
    v->addLayout(_blocksBox);

    auto* row = new QHBoxLayout();
    row->setSpacing(8);
    _lookupField = new QLineEdit(card);
    _lookupField->setObjectName("nodeLookup");
    _lookupField->setPlaceholderText(tr("Look up a block: height or hash"));
    _lookupField->setClearButtonEnabled(true);
    auto* go = new QPushButton(tr("Look up"), card);
    go->setObjectName("nodeLookupButton");
    QObject::connect(go, &QPushButton::clicked, this, [this]() { runLookup(); });
    QObject::connect(_lookupField, &QLineEdit::returnPressed, this, [this]() { runLookup(); });
    row->addWidget(_lookupField, 1);
    row->addWidget(go);
    v->addLayout(row);
    _lookupResult = new QLabel(card);
    _lookupResult->setObjectName("nodeLookupResult");
    _lookupResult->setWordWrap(true);
    _lookupResult->setTextInteractionFlags(Qt::TextSelectableByMouse);
    _lookupResult->hide();
    v->addWidget(_lookupResult);
    return card;
}

void NodePage::runLookup() {
    const QString q = _lookupField->text().trimmed();
    if (q.isEmpty()) {
        _lookupResult->hide();
        return;
    }
    if (onLookup) onLookup(q);
}

// ---- data --------------------------------------------------------------------

void NodePage::setDisconnected() {
    _height = -1;
    for (QLabel* v : { _heightValue, _peersValue, _rateValue, _diffValue }) v->setText(QStringLiteral("—"));
    _heightNote->setText(tr("Waiting for the node"));
    _peersNote->clear();
    _rateNote->clear();
    _diffNote->clear();
}

void NodePage::setTip(int height, int headers, qint64 tipTime, bool syncing) {
    _height = height;
    _headers = headers;
    _tipTime = tipTime;
    _syncing = syncing;
    _heightValue->setText(formatCount(height));
    refreshAges();
}

void NodePage::refreshAges() {
    if (_height < 0) return;
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const QString age = _tipTime > 0 ? tr("last block %1").arg(formatAge(now - _tipTime)) : QString();
    if (_syncing && _headers > _height)
        _heightNote->setText(tr("Syncing · %1 blocks to go").arg(formatCount(_headers - _height)));
    else if (_syncing)
        _heightNote->setText(tr("Syncing · %1").arg(age));
    else
        _heightNote->setText(tr("Synced · %1").arg(age));
    for (int i = 0; i < _blockMeta.size() && i < _rows.size(); ++i)
        _blockMeta.at(i)->setText(blockMeta(_rows.at(i), now));
}

void NodePage::setPeers(int total, int inbound) {
    _peersValue->setText(QString::number(total));
    _peersNote->setText(total == 0 ? tr("Looking for peers…")
                                   : tr("%1 outgoing · %2 incoming").arg(total - inbound).arg(inbound));
}

void NodePage::setHashrate(double sol) {
    _rateValue->setText(formatRate(sol));
    _rateNote->setText(tr("all miners together"));
}

void NodePage::setDifficulty(double difficulty) {
    _diffValue->setText(QLocale(QLocale::English).toString(difficulty, 'f', difficulty < 100 ? 2 : 1));
    _diffNote->setText(tr("adjusts every block"));
}

void NodePage::setHashrateSeries(const QVector<QPair<qint64, double>>& points) {
    _chart->setSeries(points);
}

// "13 s ago · 2 transactions · 682 bytes"
QString NodePage::blockMeta(const NodeBlockRow& r, qint64 now) {
    const QString size = r.size >= 10240 ? tr("%1 KB").arg(QString::number(r.size / 1024.0, 'f', 1))
                                         : tr("%1 bytes").arg(formatCount(r.size));
    return tr("%1 · %2 · %3").arg(formatAge(now - r.time))
        .arg(r.txs == 1 ? tr("1 transaction") : tr("%1 transactions").arg(r.txs)).arg(size);
}

// One block is two lines: its height with when it was mined, how many transactions and
// its size; then the whole hash. A table lost its last columns on a narrow window; these
// rows wrap instead, so no window size hides anything.
void NodePage::setBlocks(const QList<NodeBlockRow>& rows) {
    _rows = rows;
    _blockMeta.clear();
    _blockHash.clear();
    while (QLayoutItem* it = _blocksBox->takeAt(0)) {
        delete it->widget();
        delete it;
    }
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    for (const NodeBlockRow& r : rows) {
        auto* row = new QFrame(this);
        row->setObjectName("nodeBlockRow");
        auto* v = new QVBoxLayout(row);
        v->setContentsMargins(4, 8, 4, 8);
        v->setSpacing(2);
        auto* top = new QHBoxLayout();
        top->setSpacing(12);
        auto* height = new QLabel(formatCount(r.height), row);
        height->setObjectName("nodeBlockHeight");
        auto* meta = new QLabel(blockMeta(r, now), row);
        meta->setObjectName("nodeBlockMeta");
        meta->setWordWrap(true);
        auto* copy = new QToolButton(row);
        copy->setObjectName("nodeBlockCopy");
        copy->setIcon(QIcon(":/icons/res/icons/copy-light.svg"));
        copy->setIconSize(QSize(16, 16));
        copy->setAutoRaise(true);
        copy->setCursor(Qt::PointingHandCursor);
        copy->setToolTip(tr("Copy this block's hash"));
        const QString hash = r.hash;
        QObject::connect(copy, &QToolButton::clicked, this, [hash]() { QGuiApplication::clipboard()->setText(hash); });
        top->addWidget(height);
        top->addWidget(meta, 1);
        top->addWidget(copy);
        v->addLayout(top);
        auto* hashLabel = new QLabel(r.hash, row);
        hashLabel->setObjectName("nodeBlockHash");
        hashLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        hashLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);   // never widens the page
        hashLabel->setMinimumWidth(0);
        v->addWidget(hashLabel);
        _blocksBox->addWidget(row);
        _blockMeta << meta;
        _blockHash << hashLabel;
    }
    QTimer::singleShot(0, this, [this]() { fitHashes(); });
    refreshAges();
}

// A hash is 64 characters with no place to break: show it whole on one line when the row
// is wide enough, otherwise as two halves. It is never cut short.
void NodePage::fitHashes() {
    for (int i = 0; i < _blockHash.size() && i < _rows.size(); ++i) {
        QLabel* label = _blockHash.at(i);
        const QString hash = _rows.at(i).hash;
        label->ensurePolished();
        const bool fits = QFontMetrics(label->font()).horizontalAdvance(hash) <= label->width();
        const QString text = fits ? hash : hash.left(hash.size() / 2) + QLatin1Char('\n') + hash.mid(hash.size() / 2);
        if (label->text() != text) label->setText(text);
    }
}

void NodePage::setFacts(const QList<QPair<QString, QString>>& facts) {
    while (QLayoutItem* it = _factsGrid->takeAt(0)) {
        delete it->widget();
        delete it;
    }
    int row = 0;
    for (const auto& f : facts) {
        auto* name = new QLabel(f.first, this);
        name->setObjectName("nodeFactName");
        auto* value = new QLabel(f.second, this);
        value->setObjectName("nodeFactValue");
        value->setWordWrap(true);
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        _factsGrid->addWidget(name, row, 0, Qt::AlignTop);
        _factsGrid->addWidget(value, row, 1, Qt::AlignTop);
        ++row;
    }
    _factsGrid->setRowStretch(row, 1);
}

void NodePage::setLookupResult(const QString& text, bool found) {
    _lookupResult->setText(text);
    _lookupResult->setProperty("tone", found ? "ok" : "warn");
    _lookupResult->show();
}

void NodePage::adoptHelpPanel(QWidget* panel) {
    if (panel == nullptr) return;
    panel->setParent(_helpCard);
    _helpBox->addWidget(panel);
    panel->show();
    _helpCard->show();
}
