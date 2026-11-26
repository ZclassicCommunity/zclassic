// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Receive page layout: the address-type tabs (Private | Transparent | Legacy
// Sprout), one share card (QR beside the full address, Copy, New address, the
// optional request) and "Your addresses", every address of the chosen type with
// its balance and its own Copy and Export-key buttons. The hidden radios and the
// address combo stay the state machine; nothing here signs, sends or reveals a key
// on its own (Export key opens the existing exportKeys() dialog).
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "addressbook.h"
#include "privacybadgedelegate.h"
#include "addresscell.h"
#include "rpc.h"
#include "settings.h"

#include <QButtonGroup>
#include <QClipboard>
#include <QComboBox>
#include <QFrame>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSet>
#include <QSignalBlocker>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace {
enum class ReceiveKind { Private, Transparent, Legacy };

bool addressIsKind(const QString& addr, ReceiveKind kind) {
    if (kind == ReceiveKind::Transparent)
        return Settings::isTAddress(addr);
    const bool sapling = Settings::getInstance()->isSaplingAddress(addr);
    return Settings::isZAddress(addr) && (kind == ReceiveKind::Legacy ? !sapling : sapling);
}
}   // namespace

// ---- privacy signal ----------------------------------------------------------

// The privacy signal always matches the address on display, however it was picked
// (tab or the "Your addresses" list): green badge for a private address, the amber
// PUBLIC callout for a transparent one.
void MainWindow::updateReceivePrivacySignal(bool isZ) {
    if (!isZ) {
        if (lblReceivePrivate) lblReceivePrivate->setVisible(false);
        showPublicReceiveCallout();
        return;
    }
    if (lblReceivePrivate) lblReceivePrivate->setVisible(!receiveAdvancedExpanded);
    if (ui->lblSproutWarning->property("showsPublic").toBool())
        ui->lblSproutWarning->setVisible(false);
}

// The amber PUBLIC callout for a transparent receive address. Keeps the copy the
// D-series asserts ("Transparent address.", "PUBLIC", "permanently visible").
void MainWindow::showPublicReceiveCallout() {
    ui->lblSproutWarning->setProperty("callout", "public");
    ui->lblSproutWarning->setProperty("showsPublic", true);
    ui->lblSproutWarning->setMargin(8);   // breathing room inside the card border
    ui->lblSproutWarning->setStyleSheet("");   // drop the legacy inline color:red
    ui->lblSproutWarning->setText(tr(
        "<html><head/><body><p>⚠  <b>Transparent address.</b> This address and any "
        "balance it holds are <b>PUBLIC</b> and permanently visible to everyone "
        "on the blockchain. For privacy, receive to a shielded (z) address "
        "instead.</p></body></html>"));
    ui->lblSproutWarning->style()->unpolish(ui->lblSproutWarning);
    ui->lblSproutWarning->style()->polish(ui->lblSproutWarning);
    ui->lblSproutWarning->setVisible(true);
}

QString MainWindow::currentReceiveAddress() const {
    if (!receiveShownAddr.isEmpty())
        return receiveShownAddr;
    return ui->listRecieveAddresses->currentText();
}

// ---- transparent address reuse -------------------------------------------------

// A transparent address to offer for receiving that was never used: no balance, no
// unspent output and no transaction in the history. Empty when none is left (the
// caller then makes a new one). Transparent addresses must not be reused.
QString MainWindow::unusedTAddress() const {
    if (rpc == nullptr || rpc->getAllTAddresses() == nullptr)
        return QString();
    QSet<QString> used;
    if (const TxTableModel* txs = rpc->getTransactionsModel()) {
        for (int r = 0; r < txs->rowCount(QModelIndex()); ++r)
            used.insert(txs->getAddr(r));
    }
    if (const auto* utxos = rpc->getUTXOs()) {
        for (const auto& u : *utxos)
            used.insert(u.address);
    }
    const auto* bals = rpc->getAllBalances();
    const auto& taddrs = *rpc->getAllTAddresses();
    for (int i = taddrs.size() - 1; i >= 0; --i) {   // newest keys come last
        const QString& a = taddrs.at(i);
        if (!used.contains(a) && (bals == nullptr || bals->value(a) == 0.0))
            return a;
    }
    return QString();
}

// Put a never-used t-address at the top of the combo and show it; when none is
// left, makeNew mints one (the Transparent tab no longer makes a key per visit).
void MainWindow::showUnusedTAddress(const std::function<void()>& makeNew) {
    const QString unused = unusedTAddress();
    if (unused.isEmpty()) {
        makeNew();
        return;
    }
    const int at = ui->listRecieveAddresses->findText(unused);
    if (at >= 0) ui->listRecieveAddresses->removeItem(at);
    ui->listRecieveAddresses->insertItem(0, unused);
    ui->listRecieveAddresses->setCurrentIndex(0);
}

// ---- layout ------------------------------------------------------------------

// Called at the end of setupReceivePrivacyDisclosure() with the widgets it built.
// One share card (tabs + badge, then QR beside the address, its actions and the
// request) and the "Your addresses" card below it.
void MainWindow::layoutReceivePage(QVBoxLayout* groupLayout, QLabel* headline, QLabel* subhead,
                                   QLayout* requestRow, QLabel* requestCaption) {
    ui->groupBox_6->setTitle(QString());
    headline->setVisible(false);          // the nav rail already says Receive
    subhead->setVisible(false);
    requestCaption->setVisible(false);    // the placeholder says it
    btnReceiveAdvanced->setVisible(false);   // replaced by the tabs
    txtReceiveAmount->setPlaceholderText(tr("Request amount (optional)"));
    txtReceiveAmount->setMaximumWidth(260);
    txtReceiveMemo->setPlaceholderText(tr("Note for the sender (optional)"));
    ui->listRecieveAddresses->setVisible(false);   // the list below is the picker
    ui->lblReceiveAddressCaption->setVisible(false);
    ui->btnRecieveNewAddr->setText(tr("New address"));
    ui->btnRecieveNewAddr->setToolTip(tr("Make a new private (shielded) address"));

    for (QWidget* w : { static_cast<QWidget*>(headline), static_cast<QWidget*>(subhead),
                        static_cast<QWidget*>(lblReceivePrivate), static_cast<QWidget*>(btnReceiveAdvanced),
                        receiveAdvancedPanel, static_cast<QWidget*>(ui->lblSproutWarning) })
        groupLayout->removeWidget(w);
    groupLayout->removeItem(requestRow);

    auto* headRow = new QHBoxLayout();
    headRow->setSpacing(12);
    headRow->addWidget(buildReceiveTypeTabs(), 0, Qt::AlignVCenter);
    headRow->addStretch(1);
    headRow->addWidget(lblReceivePrivate, 0, Qt::AlignVCenter);

    groupLayout->insertLayout(0, headRow);
    groupLayout->insertLayout(1, buildReceiveShareRow(requestRow));
    groupLayout->addWidget(btnReceiveAdvanced, 0, Qt::AlignLeft);   // hidden state holder
    groupLayout->addWidget(receiveAdvancedPanel);                   // hidden radios
    ui->verticalLayout_8->removeItem(ui->horizontalLayout_11);     // old row, now empty
    ui->verticalLayout_8->addWidget(buildReceiveAddressesCard(), 1);
}

// Private | Transparent (| Legacy Sprout while such funds are held). The tabs
// drive the hidden radios, so every existing handler still applies, and follow
// them back whoever moved them.
QWidget* MainWindow::buildReceiveTypeTabs() {
    auto* tabs = new QFrame(ui->groupBox_6);
    tabs->setObjectName("receiveTypeTabs");
    auto* row = new QHBoxLayout(tabs);
    row->setContentsMargins(3, 3, 3, 3);
    row->setSpacing(2);
    auto* group = new QButtonGroup(tabs);
    group->setExclusive(true);
    receiveTabPrivate = makeReceiveTab(tabs, row, group, tr("Private"), "receiveTabPrivate",
        tr("Shielded (z) addresses: amounts and parties are encrypted"));
    receiveTabPublic = makeReceiveTab(tabs, row, group, tr("Transparent"), "receiveTabPublic",
        tr("Transparent (t) addresses: everything is PUBLIC on the blockchain"));
    receiveTabLegacy = makeReceiveTab(tabs, row, group, tr("Legacy Sprout"), "receiveTabLegacy",
        tr("Old Sprout addresses, shown only while they hold funds"));
    receiveTabPrivate->setChecked(true);
    receiveTabLegacy->setVisible(false);

    QObject::connect(receiveTabPrivate, &QPushButton::clicked, this, [this]() {
        setReceiveAdvancedExpanded(false);   // selects Sapling, clears warnings
    });
    QObject::connect(receiveTabPublic, &QPushButton::clicked, this, [this]() {
        setReceiveAdvancedExpanded(true);
        ui->rdioTAddr->setChecked(true);
    });
    QObject::connect(receiveTabLegacy, &QPushButton::clicked, this, [this]() {
        setReceiveAdvancedExpanded(true);
        ui->rdioZAddr->setChecked(true);
    });
    QObject::connect(ui->rdioZSAddr, &QRadioButton::toggled, this,
                     [this](bool on) { followReceiveRadio(receiveTabPrivate, on); });
    QObject::connect(ui->rdioTAddr, &QRadioButton::toggled, this,
                     [this](bool on) { followReceiveRadio(receiveTabPublic, on); });
    QObject::connect(ui->rdioZAddr, &QRadioButton::toggled, this,
                     [this](bool on) { followReceiveRadio(receiveTabLegacy, on); });
    return tabs;
}

QPushButton* MainWindow::makeReceiveTab(QWidget* parent, QHBoxLayout* row, QButtonGroup* group,
                                        const QString& label, const char* objName, const QString& tip) {
    auto* b = new QPushButton(label, parent);
    b->setObjectName(objName);
    b->setCheckable(true);
    b->setCursor(Qt::PointingHandCursor);
    b->setProperty("segment", true);
    b->setToolTip(tip);
    b->setAutoDefault(false);
    group->addButton(b);
    row->addWidget(b);
    return b;
}

void MainWindow::followReceiveRadio(QPushButton* tab, bool checked) {
    if (!checked || tab == nullptr) return;
    QSignalBlocker block(tab);
    tab->setChecked(true);
    if (tab != receiveTabLegacy)   // Legacy keeps its "deprecated" tooltip
        ui->btnRecieveNewAddr->setToolTip(tab == receiveTabPublic
            ? tr("Make a new transparent (PUBLIC) address")
            : tr("Make a new private (shielded) address"));
    receivePage = 0;   // a new type starts at its first page
    refreshReceiveAddressList();
}

// QR on the left; on the right the full address (shown once), Copy / New address /
// Copy payment request, the optional request and the PUBLIC callout.
QHBoxLayout* MainWindow::buildReceiveShareRow(QLayout* requestRow) {
    // The full address: selectable, wraps anywhere (addresses have no spaces), no box.
    ui->verticalLayout_10->removeWidget(ui->txtRecieve);
    ui->txtRecieve->setReadOnly(true);
    ui->txtRecieve->setFrameShape(QFrame::NoFrame);
    ui->txtRecieve->setWordWrapMode(QTextOption::WrapAnywhere);
    ui->txtRecieve->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    ui->txtRecieve->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    ui->txtRecieve->ensurePolished();
    ui->txtRecieve->setFixedHeight(QFontMetrics(ui->txtRecieve->font()).lineSpacing() * 3 + 16);

    auto* actions = new QHBoxLayout();
    actions->setSpacing(8);
    if (auto* copy = ui->groupBox_6->findChild<QPushButton*>("btnReceiveCopy")) {
        ui->horizontalLayout_10->removeWidget(copy);
        actions->addWidget(copy);
    }
    ui->horizontalLayout_10->removeWidget(ui->btnRecieveNewAddr);
    actions->addWidget(ui->btnRecieveNewAddr);
    ui->horizontalLayout_10->removeWidget(btnReceiveCopyRequest);
    actions->addWidget(btnReceiveCopyRequest);
    actions->addStretch(1);

    auto* right = new QVBoxLayout();
    right->setSpacing(10);
    right->addWidget(ui->txtRecieve);
    right->addLayout(actions);
    right->addLayout(requestRow);
    right->addWidget(ui->lblSproutWarning);
    right->addStretch(1);

    auto* body = new QHBoxLayout();
    body->setSpacing(20);
    // The framed QR card was built on the page; move it into the share card.
    if (auto* qrCard = ui->tab_3->findChild<QFrame*>("receiveQrCard")) {
        for (int i = 0; i < ui->horizontalLayout_11->count(); ++i)
            if (auto* l = ui->horizontalLayout_11->itemAt(i)->layout())
                l->removeWidget(qrCard);
        qrCard->setParent(ui->groupBox_6);   // setParent hides it; show again
        qrCard->show();
        body->addWidget(qrCard, 0, Qt::AlignTop);
    }
    body->addLayout(right, 1);
    return body;
}

// "Your addresses": search, sort and a 10-per-page list of every address of the
// chosen type, with a pager under it.
QGroupBox* MainWindow::buildReceiveAddressesCard() {
    receiveAddressesBox = new QGroupBox(tr("Your addresses"), ui->tab_3);
    receiveAddressesBox->setObjectName("receiveAddressesBox");
    auto* box = new QVBoxLayout(receiveAddressesBox);
    box->setSpacing(8);
    auto* hint = new QLabel(tr(
        "Every address of this type in your wallet, including empty ones. Click one to "
        "show its QR code. Back up again after making new addresses."), receiveAddressesBox);
    hint->setObjectName("lblReceiveListHint");
    hint->setWordWrap(true);
    box->addWidget(hint);
    box->addLayout(buildReceiveListTools());

    receiveAddressList = new QTreeWidget(receiveAddressesBox);
    receiveAddressList->setObjectName("receiveAddressList");
    receiveAddressList->setColumnCount(3);
    receiveAddressList->setHeaderLabels({tr("Address"), tr("Balance"), QString()});
    receiveAddressList->setRootIsDecorated(false);
    receiveAddressList->setUniformRowHeights(true);
    receiveAddressList->setSelectionMode(QAbstractItemView::SingleSelection);
    receiveAddressList->header()->setStretchLastSection(false);
    receiveAddressList->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    receiveAddressList->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    receiveAddressList->header()->setSectionResizeMode(2, QHeaderView::Fixed);
    receiveAddressList->header()->resizeSection(2, 48);   // Export key icon
    receiveAddressList->setItemDelegateForColumn(0, new AddressCellDelegate(receiveAddressList));
    receiveAddressList->setItemDelegateForColumn(
        1, new PrivacyBadgeDelegate(PrivacyBadgeDelegate::Mode::Amount, receiveAddressList));
    receiveAddressList->setMinimumHeight(430);   // a full page of 10 rows, no inner scrolling
    box->addWidget(receiveAddressList, 1);
    box->addLayout(buildReceivePager());

    // Picking a row shows that address in the share card (QR, Copy, request, badge).
    QObject::connect(receiveAddressList, &QTreeWidget::currentItemChanged, this,
                     [this](QTreeWidgetItem* item, QTreeWidgetItem*) {
        const QString addr = item ? item->data(0, Qt::UserRole).toString() : QString();
        if (addr.isEmpty() || addr == currentReceiveAddress()) return;
        receiveShownAddr = addr;
        ui->txtRecieve->setPlainText(addr);
        updateReceiveQRandPayload();
    });
    // Keep balances and new addresses current while the page is on screen; the
    // refresh is a no-op when nothing changed.
    auto* poll = new QTimer(receiveAddressesBox);
    poll->setInterval(3000);
    QObject::connect(poll, &QTimer::timeout, this, [this]() {
        if (isVisible() && ui->tabWidget->currentWidget() == ui->tab_3)
            refreshReceiveAddressList();
    });
    poll->start();
    return receiveAddressesBox;
}

// Search (address or label) and the balance order. Either change starts at page 1.
QHBoxLayout* MainWindow::buildReceiveListTools() {
    auto* row = new QHBoxLayout();
    row->setSpacing(8);
    receiveSearch = new QLineEdit(receiveAddressesBox);
    receiveSearch->setObjectName("receiveSearch");
    receiveSearch->setPlaceholderText(tr("Search addresses or labels"));
    receiveSearch->setClearButtonEnabled(true);
    receiveSort = new QComboBox(receiveAddressesBox);
    receiveSort->setObjectName("receiveSort");
    receiveSort->addItem(tr("Highest balance first"));
    receiveSort->addItem(tr("Lowest balance first"));
    QObject::connect(receiveSearch, &QLineEdit::textChanged, this, [this]() {
        receivePage = 0;
        refreshReceiveAddressList();
    });
    QObject::connect(receiveSort, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]() {
        receivePage = 0;
        refreshReceiveAddressList();
    });
    row->addWidget(receiveSearch, 1);
    row->addWidget(receiveSort);
    return row;
}

// Previous / "Page 2 of 5" / Next, shown only when there is more than one page.
QHBoxLayout* MainWindow::buildReceivePager() {
    auto* row = new QHBoxLayout();
    row->setSpacing(8);
    receivePrev = new QPushButton(tr("‹ Previous"), receiveAddressesBox);
    receivePrev->setObjectName("receivePrev");
    receiveNext = new QPushButton(tr("Next ›"), receiveAddressesBox);
    receiveNext->setObjectName("receiveNext");
    receivePageLabel = new QLabel(receiveAddressesBox);
    receivePageLabel->setObjectName("receivePageLabel");
    QObject::connect(receivePrev, &QPushButton::clicked, this, [this]() {
        receivePage = qMax(0, receivePage - 1);
        refreshReceiveAddressList();
    });
    QObject::connect(receiveNext, &QPushButton::clicked, this, [this]() {
        ++receivePage;   // clamped by the refresh
        refreshReceiveAddressList();
    });
    row->addStretch(1);
    row->addWidget(receivePrev);
    row->addWidget(receivePageLabel);
    row->addWidget(receiveNext);
    return row;
}

// ---- the list ------------------------------------------------------------------

namespace {
const int kReceivePageSize = 10;
}

// Every address of the selected tab's type that this wallet holds keys for,
// including ones that never received a coin (the Home balance list leaves those
// out), narrowed by the search, in the chosen balance order, 10 per page.
// Rebuilt only when something on screen would change.
void MainWindow::refreshReceiveAddressList() {
    if (receiveAddressList == nullptr || rpc == nullptr)
        return;
    ReceiveKind kind = ReceiveKind::Private;
    if (receiveTabPublic && receiveTabPublic->isChecked()) kind = ReceiveKind::Transparent;
    else if (receiveTabLegacy && receiveTabLegacy->isChecked()) kind = ReceiveKind::Legacy;

    const auto* bals = rpc->getAllBalances();
    QList<QPair<QString, double>> all;
    for (const QList<QString>* list : { rpc->getAllZAddresses(), rpc->getAllTAddresses() }) {
        if (list == nullptr) continue;
        for (const auto& a : *list)
            if (addressIsKind(a, kind)) all.append(qMakePair(a, bals ? bals->value(a) : 0.0));
    }
    const QList<QPair<QString, double>> rows = searchAndSortReceiveRows(all);
    const int pages = qMax(1, (rows.size() + kReceivePageSize - 1) / kReceivePageSize);
    receivePage = qBound(0, receivePage, pages - 1);
    const auto pageRows = rows.mid(receivePage * kReceivePageSize, kReceivePageSize);

    QString fingerprint = QString::number(static_cast<int>(kind)) % QLatin1Char('#')
                        % QString::number(rows.size()) % QLatin1Char('#');
    for (const auto& r : pageRows)
        fingerprint += r.first % QLatin1Char('=') % QString::number(r.second, 'f', 8)
                     % QLatin1Char('|') % AddressBook::addLabelToAddress(r.first) % QLatin1Char(';');
    updateReceivePager(pages);
    setReceiveListTitle(static_cast<int>(kind), rows.size(), all.size());
    if (fingerprint == receiveAddressList->property("fingerprint").toString())
        return;
    receiveAddressList->setProperty("fingerprint", fingerprint);

    const QString shown = currentReceiveAddress();
    QSignalBlocker block(receiveAddressList);
    receiveAddressList->clear();
    for (const auto& r : pageRows)
        addReceiveAddressRow(r.first, r.second, r.first == shown);
}

QList<QPair<QString, double>> MainWindow::searchAndSortReceiveRows(const QList<QPair<QString, double>>& all) const {
    const QString query = receiveSearch ? receiveSearch->text().trimmed() : QString();
    QList<QPair<QString, double>> rows;
    for (const auto& r : all) {
        if (query.isEmpty() || AddressBook::addLabelToAddress(r.first).contains(query, Qt::CaseInsensitive))
            rows.append(r);
    }
    const bool lowestFirst = receiveSort && receiveSort->currentIndex() == 1;
    std::stable_sort(rows.begin(), rows.end(),
        [lowestFirst](const QPair<QString, double>& a, const QPair<QString, double>& b) {
            return lowestFirst ? a.second < b.second : a.second > b.second;
        });
    return rows;
}

void MainWindow::updateReceivePager(int pages) {
    if (receivePageLabel == nullptr) return;
    receivePageLabel->setText(tr("Page %1 of %2").arg(receivePage + 1).arg(pages));
    receivePrev->setEnabled(receivePage > 0);
    receiveNext->setEnabled(receivePage < pages - 1);
    for (QWidget* w : { static_cast<QWidget*>(receivePrev), static_cast<QWidget*>(receiveNext),
                        static_cast<QWidget*>(receivePageLabel) })
        w->setVisible(pages > 1);
}

// "Your private addresses (15)", or "(3 of 15)" while a search narrows it.
void MainWindow::setReceiveListTitle(int kind, int shown, int total) {
    const QString title = kind == static_cast<int>(ReceiveKind::Transparent) ? tr("Your transparent addresses (%1)")
                        : kind == static_cast<int>(ReceiveKind::Legacy)      ? tr("Your legacy Sprout addresses (%1)")
                        :                                                      tr("Your private addresses (%1)");
    const QString count = shown == total ? QString::number(total) : tr("%1 of %2").arg(shown).arg(total);
    receiveAddressesBox->setTitle(title.arg(count));
}

// One row: badge + address (with its copy / full-address icon, see addresscell.h),
// balance, and the Export-key button.
void MainWindow::addReceiveAddressRow(const QString& addr, double balance, bool current) {
    auto* item = new QTreeWidgetItem(receiveAddressList);
    item->setText(0, AddressBook::addLabelToAddress(addr));
    item->setData(0, Qt::UserRole, addr);
    item->setText(1, Settings::getZCLDisplayFormat(balance));
    item->setTextAlignment(1, Qt::AlignRight | Qt::AlignVCenter);

    auto* actions = new QWidget(receiveAddressList);
    actions->setObjectName("receiveRowActions");
    auto* row = new QHBoxLayout(actions);
    row->setContentsMargins(4, 0, 4, 0);
    auto* keyBtn = makeRowButton(actions, ":/icons/res/icons/key-light.svg",
        tr("Export private key… (anyone with it can spend this address's funds)"), "rowExportKey");
    row->addWidget(keyBtn);
    QObject::connect(keyBtn, &QToolButton::clicked, this, [this, addr]() { exportKeys(addr); });
    receiveAddressList->setItemWidget(item, 2, actions);

    if (current)
        receiveAddressList->setCurrentItem(item);
}

QToolButton* MainWindow::makeRowButton(QWidget* parent, const char* icon, const QString& tip,
                                       const char* objName) {
    auto* b = new QToolButton(parent);
    b->setObjectName(objName);
    b->setIcon(QIcon(icon));
    b->setIconSize(QSize(18, 18));
    b->setToolTip(tip);
    b->setCursor(Qt::PointingHandCursor);
    b->setAutoRaise(true);
    return b;
}
