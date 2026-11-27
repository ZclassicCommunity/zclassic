// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The Address book as a page of its own (nav rail, Edit > Address book, Ctrl+B):
// add an address with a label, import a CSV, search, and per saved address copy,
// send to it, or delete it. The quick picker opened from Send's book button stays a
// dialog (AddressBook::open). Labels are stored by the AddressBook singleton, as before.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "addressbook.h"
#include "addresscell.h"
#include "rpc.h"
#include "settings.h"

#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegExpValidator>
#include <QScrollArea>
#include <QToolButton>
#include <QTreeWidget>
#include <QVBoxLayout>

void MainWindow::buildAddressBookPage() {
    addressBookPage = new QWidget();
    addressBookPage->setObjectName("addressBookPage");
    auto* column = new QVBoxLayout(addressBookPage);
    column->setSpacing(16);   // the page gutter comes from applyPageGutters()
    column->addWidget(buildAddressBookAddCard());
    column->addWidget(buildAddressBookListCard(), 1);
    ui->tabWidget->addTab(addressBookPage, tr("Address book"));
}

// "Add an address": label + address + Add, and Import from file.
QGroupBox* MainWindow::buildAddressBookAddCard() {
    auto* card = new QGroupBox(tr("Add an address"), addressBookPage);
    auto* row = new QHBoxLayout(card);
    row->setSpacing(8);
    bookLabel = new QLineEdit(card);
    bookLabel->setObjectName("bookLabel");
    bookLabel->setPlaceholderText(tr("Label, e.g. Alice"));
    bookLabel->setValidator(new QRegExpValidator(QRegExp(Settings::labelRegExp), bookLabel));
    bookLabel->setMaximumWidth(220);
    bookAddress = new QLineEdit(card);
    bookAddress->setObjectName("bookAddress");
    bookAddress->setPlaceholderText(tr("z-address or t-address"));
    attachAddressScroll(bookAddress);
    auto* add = new QPushButton(tr("Add"), card);
    add->setObjectName("bookAdd");
    add->setDefault(true);
    auto* import = new QPushButton(tr("Import from file"), card);
    import->setObjectName("bookImport");
    import->setToolTip(tr("A CSV file with one \"address,label\" per line"));
    QObject::connect(add, &QPushButton::clicked, this, &MainWindow::addAddressBookEntry);
    QObject::connect(bookAddress, &QLineEdit::returnPressed, this, &MainWindow::addAddressBookEntry);
    QObject::connect(import, &QPushButton::clicked, this, [this]() {
        AddressBook::importFromCsv(this, [](const QString& label, const QString& addr) {
            AddressBook::getInstance()->addAddressLabel(label, addr);
        });
        addressBookChanged();
    });
    row->addWidget(bookLabel);
    row->addWidget(bookAddress, 1);
    row->addWidget(add);
    row->addWidget(import);
    return card;
}

// "Saved addresses": search and the list.
QGroupBox* MainWindow::buildAddressBookListCard() {
    bookListCard = new QGroupBox(tr("Saved addresses"), addressBookPage);
    auto* box = new QVBoxLayout(bookListCard);
    box->setSpacing(8);
    bookSearch = new QLineEdit(bookListCard);
    bookSearch->setObjectName("bookSearch");
    bookSearch->setPlaceholderText(tr("Search labels or addresses"));
    bookSearch->setClearButtonEnabled(true);
    QObject::connect(bookSearch, &QLineEdit::textChanged, this, &MainWindow::refreshAddressBookPage);
    bookList = new QTreeWidget(bookListCard);
    bookList->setObjectName("bookList");
    bookList->setColumnCount(3);
    bookList->setHeaderLabels({tr("Label"), tr("Address"), QString()});
    bookList->setRootIsDecorated(false);
    bookList->setUniformRowHeights(true);
    bookList->header()->setStretchLastSection(false);
    bookList->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    bookList->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    bookList->header()->setSectionResizeMode(2, QHeaderView::Fixed);
    bookList->header()->resizeSection(2, 84);   // Send to + Delete icons
    bookList->setItemDelegateForColumn(1, new AddressCellDelegate(bookList));
    box->addWidget(bookSearch);
    box->addWidget(bookList, 1);
    return bookListCard;
}

void MainWindow::openAddressBookPage() {
    refreshAddressBookPage();
    ui->tabWidget->setCurrentIndex(ui->tabWidget->indexOf(addressBookPage));
}

void MainWindow::addAddressBookEntry() {
    const QString label = bookLabel->text().trimmed();
    const QString addr = bookAddress->text().trimmed();
    if (label.isEmpty() || addr.isEmpty()) {
        ui->statusBar->showMessage(tr("Enter a label and an address to add."), 3 * 1000);
        return;
    }
    if (!Settings::isValidAddress(addr)) {
        QMessageBox::critical(this, tr("Address Format Error"),
            addr + tr(" doesn't seem to be a valid ZClassic address."), QMessageBox::Ok);
        return;
    }
    AddressBook::getInstance()->addAddressLabel(label, addr);
    bookLabel->clear();
    bookAddress->clear();
    addressBookChanged();
}

// After any change: this list, label completions everywhere, and the labels the
// other pages show (as closing the dialog did).
void MainWindow::addressBookChanged() {
    refreshAddressBookPage();
    updateLabels();
    if (rpc && rpc->getConnection())
        rpc->refresh(true);
}

void MainWindow::refreshAddressBookPage() {
    if (bookList == nullptr) return;
    const QString query = bookSearch->text().trimmed();
    const auto& all = AddressBook::getInstance()->getAllAddressLabels();
    bookList->clear();
    int shown = 0;
    for (const auto& entry : all) {
        if (!query.isEmpty() && !entry.first.contains(query, Qt::CaseInsensitive)
                && !entry.second.contains(query, Qt::CaseInsensitive))
            continue;
        addAddressBookRow(entry.first, entry.second);
        ++shown;
    }
    const QString count = shown == all.size() ? QString::number(all.size())
                                              : tr("%1 of %2").arg(shown).arg(all.size());
    bookListCard->setTitle(tr("Saved addresses (%1)").arg(count));
}

// One saved address: label, address (Copy / full-address icon), Send to, Delete.
void MainWindow::addAddressBookRow(const QString& label, const QString& addr) {
    auto* item = new QTreeWidgetItem(bookList);
    item->setText(0, label);
    item->setText(1, addr);
    auto* actions = new QWidget(bookList);
    actions->setObjectName("receiveRowActions");
    auto* row = new QHBoxLayout(actions);
    row->setContentsMargins(4, 0, 4, 0);
    row->setSpacing(6);
    auto* sendTo = makeRowButton(actions, ":/icons/res/icons/send-light.svg",
                                 tr("Send to this address"), "bookSendTo");
    auto* remove = makeRowButton(actions, ":/icons/res/icons/trash-light.svg",
                                 tr("Delete from the address book"), "bookDelete");
    row->addWidget(sendTo);
    row->addWidget(remove);
    QObject::connect(sendTo, &QToolButton::clicked, this, [this, label, addr]() {
        removeExtraAddresses();
        ui->Address1->setText(label % "/" % addr);   // the picker's "label/address" form
        ui->tabWidget->setCurrentIndex(1);
    });
    QObject::connect(remove, &QToolButton::clicked, this, [this, label, addr]() {
        if (QMessageBox::question(this, tr("Delete address?"),
                tr("Remove \"%1\" from your address book? The address itself is not affected.").arg(label),
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) != QMessageBox::Yes)
            return;
        AddressBook::getInstance()->removeAddressLabel(label, addr);
        addressBookChanged();
    });
    bookList->setItemWidget(item, 2, actions);
}
