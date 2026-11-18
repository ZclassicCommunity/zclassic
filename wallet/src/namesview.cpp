// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "namesview.h"

#include "connection.h"
#include "mainwindow.h"
#include "precompiled.h"
#include "rpc.h"
#include "settings.h"

#include <QDialog>
#include <QPointer>
#include <QFormLayout>
#include <QFrame>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

using json = nlohmann::json;

namespace {
const int kPollMs = 20000;

json payload(const char* method, json params = json::array())
{
    return {{"jsonrpc", "1.0"}, {"id", "names"}, {"method", method}, {"params", params}};
}

QString errorText(const json& err)
{
    if (err.is_object()) {
        auto e = err.find("error");
        if (e != err.end() && e->is_object()) {
            auto m = e->find("message");
            if (m != e->end() && m->is_string())
                return QString::fromStdString(m->get<std::string>());
        }
    }
    return QObject::tr("The node did not answer.");
}
} // namespace

NamesView* NamesView::install(MainWindow* main)
{
    return main ? new NamesView(main) : nullptr;
}

NamesView::NamesView(MainWindow* main)
    : QObject(main), main_(main), timer_(new QTimer(this))
{
    connect(timer_, &QTimer::timeout, this, &NamesView::poll);
    timer_->start(kPollMs);
    QTimer::singleShot(2500, this, &NamesView::poll);
}

void NamesView::poll()
{
    RPC* rpc = main_->getRPC();
    Connection* conn = rpc ? rpc->getConnection() : nullptr;
    if (!conn || inFlight_)
        return;
    inFlight_ = true;
    // A daemon without the index answers {"enabled": false}; an old daemon answers an error. Either way: hidden.
    conn->doRPC(payload("znam_getindexinfo"), [this](const json& result) {
        inFlight_ = false;
        const names::IndexStatus st = names::parseIndexInfo(result);
        setAvailable(st.enabled);
        if (st.enabled && statusLabel_)
            statusLabel_->setText(st.synced ? tr("Name index is up to date (block %1).").arg(st.indexedHeight)
                                            : tr("Name index is building: %1%.").arg(int(st.progress * 100)));
        if (st.enabled && dialog_ && dialog_->isVisible())
            refreshNames();
    }, [this](QNetworkReply*, const json&) {
        inFlight_ = false;
        setAvailable(false);
    });
}

void NamesView::setAvailable(bool available)
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

void NamesView::ensureRailButton()
{
    if (railButton_ || !available_)
        return;
    auto* rail = main_->findChild<QFrame*>(QStringLiteral("navRail"));
    auto* box = rail ? qobject_cast<QVBoxLayout*>(rail->layout()) : nullptr;
    auto* adv = rail ? rail->findChild<QPushButton*>(QStringLiteral("navRailAdvanced")) : nullptr;
    if (!box || !adv)
        return;
    railButton_ = new QPushButton(tr("Names"), rail);
    railButton_->setObjectName(QStringLiteral("navRailButton"));
    railButton_->setFlat(true);
    railButton_->setCursor(Qt::PointingHandCursor);
    railButton_->setProperty("navrail", true);
    railButton_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    const int advIndex = box->indexOf(adv);
    box->insertWidget(advIndex > 0 ? advIndex - 1 : box->count(), railButton_);
    connect(railButton_, &QPushButton::clicked, this, &NamesView::openWindow);
}

void NamesView::openWindow()
{
    if (!dialog_) {
        dialog_ = new QDialog(main_);
        dialog_->setWindowTitle(tr("Names"));
        dialog_->resize(820, 560);
        auto* lay = new QVBoxLayout(dialog_);

        auto* notice = new QLabel(tr("A name points at an address. To pay a name, type <b>@name</b> in the Pay to field of the "
                                     "Send tab: the address it resolves to is shown to you to check and confirm first. The names "
                                     "below are the ones whose owner key is in this wallet."), dialog_);
        notice->setWordWrap(true);
        lay->addWidget(notice);

        statusLabel_ = new QLabel(dialog_);
        lay->addWidget(statusLabel_);

        table_ = new QTableWidget(0, 4, dialog_);
        table_->setHorizontalHeaderLabels({tr("Name"), tr("Points to"), tr("Type"), tr("Registered at block")});
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setSelectionMode(QAbstractItemView::SingleSelection);
        table_->setAlternatingRowColors(true);
        table_->verticalHeader()->hide();
        table_->horizontalHeader()->setStretchLastSection(true);
        lay->addWidget(table_, 1);
        emptyLabel_ = new QLabel(tr("This wallet owns no names."), dialog_);
        lay->addWidget(emptyLabel_);

        auto* upd = new QGroupBox(tr("Change where the selected name points"), dialog_);
        auto* uf = new QFormLayout(upd);
        updTarget_ = new QLineEdit(upd);
        updTarget_->setPlaceholderText(tr("A t-address or z-address"));
        uf->addRow(tr("New address"), updTarget_);
        auto* updBtn = new QPushButton(tr("Update name"), upd);
        connect(updBtn, &QPushButton::clicked, this, &NamesView::updateClicked);
        uf->addRow(QString(), updBtn);
        lay->addWidget(upd);

        auto* reg = new QGroupBox(tr("Register a new name"), dialog_);
        auto* rf = new QFormLayout(reg);
        regName_ = new QLineEdit(reg);
        regName_->setPlaceholderText(tr("1-63 of a-z 0-9 and -, no capitals"));
        rf->addRow(tr("Name"), regName_);
        regTarget_ = new QLineEdit(reg);
        regTarget_->setPlaceholderText(tr("The address people will pay when they pay this name"));
        rf->addRow(tr("Points to"), regTarget_);
        auto* regBtn = new QPushButton(tr("Register name"), reg);
        connect(regBtn, &QPushButton::clicked, this, &NamesView::registerClicked);
        rf->addRow(QString(), regBtn);
        auto* hint = new QLabel(tr("Names are first come, first served, and anyone watching the network can see a pending "
                                   "registration. Registering sends a small transaction from this wallet; the name belongs to "
                                   "the address that signs it."), reg);
        hint->setWordWrap(true);
        rf->addRow(hint);
        lay->addWidget(reg);

        auto* close = new QPushButton(tr("Close"), dialog_);
        connect(close, &QPushButton::clicked, dialog_, &QDialog::hide);
        lay->addWidget(close, 0, Qt::AlignRight);
    }
    dialog_->show();
    dialog_->raise();
    dialog_->activateWindow();
    refreshNames();
}

void NamesView::refreshNames()
{
    RPC* rpc = main_->getRPC();
    Connection* conn = rpc ? rpc->getConnection() : nullptr;
    if (!conn || !available_ || !table_)
        return;
    conn->doRPCIgnoreError(payload("znam_listmine"), [this](const json& result) {
        QVector<names::OwnedName> v;
        if (!names::parseOwnedNames(result, &v) || !table_)
            return;
        table_->setRowCount(v.size());
        for (int i = 0; i < v.size(); i++) {
            const names::OwnedName& n = v[i];
            auto cell = [&](int col, const QString& t, const QString& tip = QString()) {
                auto* item = new QTableWidgetItem(t);
                if (!tip.isEmpty())
                    item->setToolTip(tip);
                table_->setItem(i, col, item);
            };
            cell(0, QStringLiteral("@") + n.name, n.owner);
            cell(1, n.value, n.value);
            cell(2, n.type);
            cell(3, QString::number(n.registeredHeight));
        }
        emptyLabel_->setVisible(v.isEmpty());
        table_->setVisible(!v.isEmpty());
    });
}

void NamesView::sendOperation(const char* method, const QString& name, const QString& target, const QString& what)
{
    RPC* rpc = main_->getRPC();
    Connection* conn = rpc ? rpc->getConnection() : nullptr;
    if (!conn)
        return;
    json params = json::array({name.toStdString(), target.toStdString()});
    QPointer<NamesView> self(this);
    conn->doRPC(payload(method, params), [self, what](const json& result) {
        if (!self)
            return;
        QString txid;
        if (result.is_object()) {
            auto it = result.find("txid");
            if (it != result.end() && it->is_string())
                txid = QString::fromStdString(it->get<std::string>());
        }
        QMessageBox::information(self->dialog_, QObject::tr("Name transaction sent"),
            QObject::tr("%1\n\nTransaction %2\n\nThe change takes effect when the transaction is mined and your node's name "
                        "index has read the block.").arg(what, txid));
        self->refreshNames();
    }, [self](QNetworkReply*, const json& err) {
        if (!self)
            return;
        QMessageBox::warning(self->dialog_, QObject::tr("The name transaction was not sent"), errorText(err));
    });
}

void NamesView::registerClicked()
{
    const QString raw = regName_->text();
    names::Parsed p = names::parsePayTo(QStringLiteral("@") + raw.trimmed());
    if (p.kind != names::InputKind::Name) {
        QMessageBox::warning(dialog_, tr("Not a valid name"), p.problem.isEmpty() ? tr("Enter a name.") : p.problem);
        return;
    }
    const QString target = regTarget_->text().trimmed();
    if (!Settings::isValidAddress(target)) {
        QMessageBox::warning(dialog_, tr("Not a valid address"), tr("The name must point at a valid t-address or z-address."));
        return;
    }
    const auto answer = QMessageBox::question(dialog_, tr("Register this name?"),
        tr("Register @%1, pointing at\n\n%2\n\nThis sends a transaction from this wallet. If someone else's registration of the "
           "same name is mined first, yours is ignored.").arg(p.name, target));
    if (answer != QMessageBox::Yes)
        return;
    sendOperation("znam_register", p.name, target, tr("Registering @%1.").arg(p.name));
}

void NamesView::updateClicked()
{
    const int row = table_ ? table_->currentRow() : -1;
    if (row < 0 || !table_->item(row, 0)) {
        QMessageBox::warning(dialog_, tr("Select a name"), tr("Select one of your names in the list first."));
        return;
    }
    const QString name = table_->item(row, 0)->text().mid(1);
    const QString target = updTarget_->text().trimmed();
    if (!Settings::isValidAddress(target)) {
        QMessageBox::warning(dialog_, tr("Not a valid address"), tr("The name must point at a valid t-address or z-address."));
        return;
    }
    const auto answer = QMessageBox::question(dialog_, tr("Change this name?"),
        tr("Make @%1 point at\n\n%2\n\nPeople who pay @%1 will then be shown this address, with a warning for the next while "
           "that it changed.").arg(name, target));
    if (answer != QMessageBox::Yes)
        return;
    sendOperation("znam_update", name, target, tr("Updating @%1.").arg(name));
}
