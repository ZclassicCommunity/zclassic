// ============================================================================
// TEST SHIM addressbook_stub.cpp  (L0 unit suite — tst_logic)
//
// Implements the tiny AddressBook surface declared in tests/shim/addressbook.h.
// Bodies mirror src/addressbook.cpp semantics exactly so addresscombo.cpp's
// label<->address handling is exercised against faithful behaviour, without the
// QtWidgets dialog / QSettings persistence of the real class.
// ============================================================================
#include "addressbook.h"

AddressBook* AddressBook::instance = nullptr;

AddressBook* AddressBook::getInstance() {
    if (!instance)
        instance = new AddressBook();
    return instance;
}

// src/addressbook.cpp:348-350 — pure.
QString AddressBook::addressFromAddressLabel(const QString& lblAddr) {
    return lblAddr.trimmed().split("/").last();
}

// src/addressbook.cpp:331-338 — first label whose address matches, else "".
QString AddressBook::getLabelForAddress(QString addr) {
    for (auto i : allLabels) {
        if (i.second == addr)
            return i.first;
    }
    return "";
}

// src/addressbook.cpp:340-346.
QString AddressBook::addLabelToAddress(QString addr) {
    QString label = AddressBook::getInstance()->getLabelForAddress(addr);
    if (!label.isEmpty())
        return label + "/" + addr;
    else
        return addr;
}

// Test-only seeding helper (semantics like addAddressLabel but no file IO and
// no isValidAddress assertion, so tests can register arbitrary corpora).
void AddressBook::addAddressLabel(QString label, QString address) {
    allLabels.push_back(QPair<QString, QString>(label, address));
}
