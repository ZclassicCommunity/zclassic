// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokensview.h"

#include "connection.h"
#include "mainwindow.h"
#include "precompiled.h"
#include "rpc.h"

#include <QDialog>
#include <QFrame>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

using json = nlohmann::json;

namespace {
const int kPollMs = 15000;

json payload(const char* method, json params = json::array())
{
    return {{"jsonrpc", "1.0"}, {"id", "tokens"}, {"method", method}, {"params", params}};
}

QTableWidget* makeTable(const QStringList& headers, QWidget* parent)
{
    auto* t = new QTableWidget(0, headers.size(), parent);
    t->setHorizontalHeaderLabels(headers);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setAlternatingRowColors(true);
    t->verticalHeader()->hide();
    t->horizontalHeader()->setStretchLastSection(true);
    return t;
}

void setCell(QTableWidget* t, int row, int col, const QString& text, const QString& tip = QString(),
             bool right = false)
{
    auto* item = new QTableWidgetItem(text);
    if (!tip.isEmpty())
        item->setToolTip(tip);
    if (right)
        item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    t->setItem(row, col, item);
}
} // namespace

TokensView* TokensView::install(MainWindow* main)
{
    return main ? new TokensView(main) : nullptr;
}

TokensView::TokensView(MainWindow* main)
    : QObject(main), main_(main), timer_(new QTimer(this))
{
    connect(timer_, &QTimer::timeout, this, &TokensView::poll);
    timer_->start(kPollMs);
    QTimer::singleShot(2000, this, &TokensView::poll);
}

void TokensView::poll()
{
    RPC* rpc = main_->getRPC();
    Connection* conn = rpc ? rpc->getConnection() : nullptr;
    if (!conn || inFlight_)
        return;
    inFlight_ = true;
    // A daemon without the index (or an old daemon without the command) answers with an error: the view hides.
    conn->doRPC(payload("zslp_getindexinfo"), [this](const json& result) {
        inFlight_ = false;
        const tokens::IndexStatus st = tokens::parseIndexInfo(result);
        setAvailable(st.enabled);
        if (st.enabled)
            applyStatus(st);
    }, [this](QNetworkReply*, const json&) {
        inFlight_ = false;
        setAvailable(false);
    });
}

void TokensView::setAvailable(bool available)
{
    if (available == available_)
        return;
    available_ = available;
    ensureRailButton();
    if (railButton_)
        railButton_->setVisible(available);
    if (!available && dialog_)
        dialog_->hide();
}

void TokensView::ensureRailButton()
{
    if (railButton_ || !available_)
        return;
    // The navigation rail is built by MainWindow::setupNavRail(); put the button above the stretch that
    // holds "Advanced" at the bottom. If the rail is not there (a layout change), the view is simply
    // not reachable rather than misplaced.
    auto* rail = main_->findChild<QFrame*>(QStringLiteral("navRail"));
    auto* box = rail ? qobject_cast<QVBoxLayout*>(rail->layout()) : nullptr;
    auto* adv = rail ? rail->findChild<QPushButton*>(QStringLiteral("navRailAdvanced")) : nullptr;
    if (!box || !adv)
        return;
    railButton_ = new QPushButton(tr("Tokens"), rail);
    railButton_->setObjectName(QStringLiteral("navRailButton"));
    railButton_->setFlat(true);
    railButton_->setCursor(Qt::PointingHandCursor);
    railButton_->setProperty("navrail", true);
    railButton_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    const int advIndex = box->indexOf(adv);
    box->insertWidget(advIndex > 0 ? advIndex - 1 : box->count(), railButton_);
    connect(railButton_, &QPushButton::clicked, this, &TokensView::openWindow);
}

void TokensView::openWindow()
{
    if (!dialog_) {
        dialog_ = new QDialog(main_);
        dialog_->setWindowTitle(tr("Tokens"));
        dialog_->resize(860, 560);
        auto* lay = new QVBoxLayout(dialog_);

        auto* notice = new QLabel(tokens::protectedNotice(), dialog_);
        notice->setWordWrap(true);
        lay->addWidget(notice);

        statusLabel_ = new QLabel(dialog_);
        statusLabel_->setWordWrap(true);
        lay->addWidget(statusLabel_);

        auto* h1 = new QLabel(tr("<b>Your token balances</b>"), dialog_);
        lay->addWidget(h1);
        balances_ = makeTable({tr("Token"), tr("Name"), tr("Amount")}, dialog_);
        balances_->setMaximumHeight(170);
        lay->addWidget(balances_);

        auto* h2 = new QLabel(tr("<b>Token outputs in this wallet</b> (protected from ordinary spending)"), dialog_);
        lay->addWidget(h2);
        outputs_ = makeTable({tr("Token"), tr("Kind"), tr("Amount"), tr("Address"), tr("Confirmations"),
                              tr("Output"), tr("Protected")}, dialog_);
        lay->addWidget(outputs_, 1);

        emptyLabel_ = new QLabel(tr("This wallet holds no tokens."), dialog_);
        lay->addWidget(emptyLabel_);

        auto* close = new QPushButton(tr("Close"), dialog_);
        connect(close, &QPushButton::clicked, dialog_, &QDialog::hide);
        lay->addWidget(close, 0, Qt::AlignRight);
    }
    dialog_->show();
    dialog_->raise();
    dialog_->activateWindow();
    refreshOutputs();
}

void TokensView::applyStatus(const tokens::IndexStatus& status)
{
    if (statusLabel_)
        statusLabel_->setText(tokens::statusLine(status));
    if (dialog_ && dialog_->isVisible())
        refreshOutputs();
}

void TokensView::refreshOutputs()
{
    RPC* rpc = main_->getRPC();
    Connection* conn = rpc ? rpc->getConnection() : nullptr;
    if (!conn || !available_)
        return;
    conn->doRPCIgnoreError(payload("zslp_listunspent", json::array({1})), [this](const json& result) {
        tokens::Snapshot snap;
        if (tokens::parseSnapshot(result, &snap))
            applySnapshot(snap);
    });
}

void TokensView::applySnapshot(const tokens::Snapshot& snap)
{
    if (!balances_ || !outputs_)
        return;
    balances_->setRowCount(snap.balances.size());
    for (int i = 0; i < snap.balances.size(); i++) {
        const tokens::Balance& b = snap.balances[i];
        setCell(balances_, i, 0, tokens::displayTicker(b.ticker, b.tokenId), b.tokenId);
        setCell(balances_, i, 1, b.ticker.isEmpty() ? tr("(unnamed token)") : b.ticker, b.tokenId);
        setCell(balances_, i, 2, b.amount, QString(), true);
    }
    outputs_->setRowCount(snap.outputs.size());
    for (int i = 0; i < snap.outputs.size(); i++) {
        const tokens::Output& o = snap.outputs[i];
        setCell(outputs_, i, 0, tokens::displayTicker(o.ticker, o.tokenId), o.tokenId);
        setCell(outputs_, i, 1, tokens::roleText(o.role));
        setCell(outputs_, i, 2, o.role == QLatin1String("mintbaton") ? QStringLiteral("-") : o.amount, QString(), true);
        setCell(outputs_, i, 3, o.address, o.address);
        setCell(outputs_, i, 4, QString::number(o.confirmations), QString(), true);
        setCell(outputs_, i, 5, tokens::shortOutpoint(o.txid, o.vout), QStringLiteral("%1:%2").arg(o.txid).arg(o.vout));
        setCell(outputs_, i, 6, o.isProtected ? tr("Yes: never used as ordinary funds") : tr("No"));
    }
    emptyLabel_->setVisible(snap.outputs.isEmpty());
    balances_->setVisible(!snap.balances.isEmpty());
    outputs_->setVisible(!snap.outputs.isEmpty());
}
