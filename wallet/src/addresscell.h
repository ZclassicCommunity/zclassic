// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ADDRESSCELL_H
#define ADDRESSCELL_H

#include "privacybadgedelegate.h"

#include <QFrame>

class QAbstractItemView;
class QComboBox;
class QLineEdit;

// An address column cell: the privacy pill and the address (PrivacyBadgeDelegate),
// plus one icon at the right end of the cell.
//   * The whole address fits: a Copy icon; clicking it copies the address.
//   * The address is cut with "…": an "i" icon; pointing at it (no delay) or
//     clicking it opens a small card with the full address and a Copy button.
// Cells whose text is not an address (e.g. "Loading...") get no icon.
class AddressCellDelegate : public PrivacyBadgeDelegate {
public:
    explicit AddressCellDelegate(QAbstractItemView* view);

    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override;
    bool eventFilter(QObject* watched, QEvent* event) override;

    // Where the icon sits inside a cell rect, and the copyable address of a cell
    // ("" when the cell holds no valid address).
    static QRect iconRect(const QRect& cell);
    static QString addressAt(const QModelIndex& index);

private:
    QAbstractItemView* _view;
    QStyleOptionViewItem optionAt(const QModelIndex& index) const;
    void copyFromCell(const QModelIndex& index, const QString& addr);
    QPersistentModelIndex _copied;   // shows a green tick for a moment after a copy
};

// The small card that shows a full address with a Copy button, opened under an
// anchor (the "i" icon). Only one is open at a time. It stays while the pointer is
// on the anchor or the card, and closes when it leaves both, on Escape, or on a
// click elsewhere.
class AddressPopup : public QFrame {
public:
    // Open (or keep open) the card for address under the anchor rect, in global
    // coordinates. Opening it for the address already shown is a no-op.
    static void showFor(QWidget* parent, const QString& address, const QRect& globalAnchor);
    static AddressPopup* current();
    QString address() const { return _address; }
protected:
    void mouseMoveEvent(QMouseEvent* event) override;
private:
    AddressPopup(QWidget* parent, const QString& address, const QRect& globalAnchor);
    QString _address;
    QRect   _anchor;
};

// Copy an address and say so in the window's status bar, when it has one.
void copyAddressToClipboard(QWidget* from, const QString& address);

// Send's Pay to field: a thin scroll bar along its bottom edge, shown only while the
// address is wider than the field (it hides once the field shows it in full).
void attachAddressScroll(QLineEdit* field);
// Send's Pay from combo: sizes from a short minimum (the address is shortened in the
// middle) so a long one cannot widen the page, plus an "i" beside it, shown only
// while the address is cut, that opens the full-address card.
void attachAddressInfo(QComboBox* combo);

#endif // ADDRESSCELL_H
