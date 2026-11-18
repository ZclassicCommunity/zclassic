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
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

using json = nlohmann::json;

namespace {
const int kPollMs = 15000;
// How long a dialog request may stay unanswered before it is reported as "outcome unknown".
const int kCallTimeoutMs = 120000;

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

// The dialogs' view of the daemon: the wallet's own connection. A daemon error arrives as its message.
class ConnectionRpc : public tokens::TokensRpc {
public:
    explicit ConnectionRpc(MainWindow* main) : main_(main) {}
    void call(const QString& method, const json& params, std::function<void(const json&)> ok,
              std::function<void(const QString&)> fail) override
    {
        RPC* rpc = main_->getRPC();
        Connection* conn = rpc ? rpc->getConnection() : nullptr;
        if (!conn) {
            fail(QObject::tr("The wallet is not connected to the node."));
            return;
        }
        if (conn->isShuttingDown()) {
            // doRPC() would drop the call without answering either callback and the dialog would wait for ever.
            fail(QObject::tr("The node is restarting. Check your transactions before trying again."));
            return;
        }
        // Answer exactly once. Connection::doRPC() never answers a call that a shutdown or a restart drops, and
        // nothing else bounds the wait: the dialog (which cannot be closed while it waits) would lock the whole
        // wallet. A late answer, if it ever comes, is ignored.
        auto answered = std::make_shared<bool>(false);
        QTimer::singleShot(kCallTimeoutMs, main_, [answered, fail]() {
            if (*answered)
                return;
            *answered = true;
            fail(QObject::tr("The node did not answer in time. The outcome is unknown: check your transactions before "
                             "trying again."));
        });
        json p = {{"jsonrpc", "1.0"}, {"id", "tokens"}, {"method", method.toStdString()}, {"params", params}};
        conn->doRPC(p, [ok, answered](const json& result) {
                        if (*answered)
                            return;
                        *answered = true;
                        ok(result);
                    },
                    [fail, answered](QNetworkReply* reply, const json& parsed) {
                        if (*answered)
                            return;
                        *answered = true;
                        QString msg;
                        if (parsed.is_object()) {
                            auto e = parsed.find("error");
                            if (e != parsed.end() && e->is_object()) {
                                auto m = e->find("message");
                                if (m != e->end() && m->is_string())
                                    msg = QString::fromStdString(m->get<std::string>());
                            }
                        }
                        if (msg.isEmpty())
                            msg = reply ? reply->errorString() : QObject::tr("The node did not answer.");
                        fail(msg);
                    });
    }

private:
    MainWindow* main_;
};
} // namespace

TokensView* TokensView::install(MainWindow* main)
{
    return main ? new TokensView(main) : nullptr;
}

TokensView::TokensView(MainWindow* main)
    : QObject(main), main_(main), timer_(new QTimer(this)), rpc_(new ConnectionRpc(main))
{
    connect(timer_, &QTimer::timeout, this, &TokensView::poll);
    timer_->start(kPollMs);
    QTimer::singleShot(2000, this, &TokensView::poll);
}

void TokensView::poll()
{
    RPC* rpc = main_->getRPC();
    Connection* conn = rpc ? rpc->getConnection() : nullptr;
    if (!conn)
        return;
    const PollGuard::Ticket ticket = pollGuard_.begin(conn, conn->isShuttingDown());
    if (ticket == 0)
        return;
    // A daemon without the index (or an old daemon without the command) answers with an error: the view hides.
    conn->doRPC(payload("zslp_getindexinfo"), [this, ticket](const json& result) {
        pollGuard_.end(ticket);
        const tokens::IndexStatus st = tokens::parseIndexInfo(result);
        setAvailable(st.enabled);
        if (st.enabled)
            applyStatus(st);
    }, [this, ticket](QNetworkReply*, const json&) {
        pollGuard_.end(ticket);
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

        auto* row = new QHBoxLayout;
        sendButton_ = new QPushButton(tr("Send tokens..."), dialog_);
        sendButton_->setObjectName(QStringLiteral("tokensSendButton"));
        createButton_ = new QPushButton(tr("Create token... (advanced)"), dialog_);
        createButton_->setObjectName(QStringLiteral("tokensCreateButton"));
        row->addWidget(sendButton_);
        row->addWidget(createButton_);
        row->addStretch(1);
        auto* close = new QPushButton(tr("Close"), dialog_);
        connect(close, &QPushButton::clicked, dialog_, &QDialog::hide);
        row->addWidget(close);
        lay->addLayout(row);
        connect(sendButton_, &QPushButton::clicked, this, &TokensView::openSend);
        connect(createButton_, &QPushButton::clicked, this, &TokensView::openCreate);
        updateActionButtons();
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
    indexSynced_ = status.synced && status.error.isEmpty();
    updateActionButtons();
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
    lastSnap_ = snap;
    updateActionButtons();
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

// Sending needs the index at the chain tip (it decides which outputs are valid tokens) and something to
// send; creating needs the index at the tip. The daemon refuses otherwise, with a clear message; the
// buttons say why in advance.
void TokensView::updateActionButtons()
{
    if (!sendButton_ || !createButton_)
        return;
    const bool hasTokens = !tokens::choicesFromSnapshot(lastSnap_).isEmpty();
    sendButton_->setEnabled(indexSynced_ && hasTokens);
    createButton_->setEnabled(indexSynced_);
    const QString wait = tr("Available when the token index is up to date.");
    sendButton_->setToolTip(!indexSynced_ ? wait : hasTokens ? QString() : tr("This wallet holds no confirmed tokens to send."));
    createButton_->setToolTip(indexSynced_ ? tr("Create a new token. Advanced.") : wait);
}

void TokensView::openSend()
{
    auto* d = new tokens::TokenSendDialog(rpc_.get(), tokens::choicesFromSnapshot(lastSnap_), dialog_);
    d->setAttribute(Qt::WA_DeleteOnClose);
    connect(d, &tokens::StepDialog::sent, this, [this](const QString&) { refreshOutputs(); });
    d->open();
}

void TokensView::openCreate()
{
    auto* d = new tokens::TokenCreateDialog(rpc_.get(), dialog_);
    d->setAttribute(Qt::WA_DeleteOnClose);
    connect(d, &tokens::StepDialog::sent, this, [this](const QString&) { refreshOutputs(); });
    d->open();
}
