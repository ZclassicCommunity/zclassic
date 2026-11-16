// ============================================================================
// TEST SHIM addressbook.h  (L0 unit suite — tst_logic)
//
// Stands in for src/addressbook.h. addresscombo.cpp uses ONLY these three
// AddressBook entry points:
//     AddressBook::addressFromAddressLabel(const QString&)   (static, pure)
//     AddressBook::addLabelToAddress(QString)                (static)
//     AddressBook::getInstance()->getLabelForAddress(QString)
//
// The full src/addressbook.h drags in AddressBookModel (QAbstractTableModel),
// AddressBook::open(MainWindow*, QLineEdit*) (QtWidgets + dialogs + RPC) and
// QSettings/QDataStream file IO. NONE of that is needed to exercise the combo's
// pure label<->address round-trip, so this shim provides a tiny in-memory book.
//
// Semantics MATCH src/addressbook.cpp:340-350 exactly:
//   addressFromAddressLabel("label/addr") -> "addr"  (trim, split "/", last)
//   addLabelToAddress(addr) -> "label/addr" if a label exists, else addr
// ============================================================================
#ifndef ADDRESSBOOK_H
#define ADDRESSBOOK_H

#include "precompiled.h"

class AddressBook {
public:
    static AddressBook* getInstance();

    // Pure: identical body to src/addressbook.cpp:348-350.
    static QString addressFromAddressLabel(const QString& lblAddr);

    // Identical body to src/addressbook.cpp:340-346.
    static QString addLabelToAddress(QString addr);

    // First label registered for an address, or "" — src/addressbook.cpp:331-338.
    QString getLabelForAddress(QString address);

    // Test-only helper to seed the in-memory book (not in product API).
    void addAddressLabel(QString label, QString address);

private:
    AddressBook() = default;
    QList<QPair<QString, QString>> allLabels;   // (label, address), insertion order
    static AddressBook* instance;
};

#endif // ADDRESSBOOK_H
