// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "addresscell.h"
#include "addressbook.h"
#include "settings.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QBoxLayout>
#include <QClipboard>
#include <QComboBox>
#include <QGuiApplication>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMouseEvent>
#include <QPainter>
#include <QPointer>
#include <QPushButton>
#include <QScreen>
#include <QScrollBar>
#include <QSignalBlocker>
#include <memory>
#include <QStatusBar>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <functional>

namespace {
const int kSlot = 28;   // px reserved at the right of every address cell
const int kIcon = 16;

QPointer<AddressPopup>& openPopup() {
    static QPointer<AddressPopup> popup;
    return popup;
}

QIcon infoIcon() { return QIcon(":/icons/res/icons/info-light.svg"); }

// Calls a function whenever the watched widget is resized.
class ResizeWatcher : public QObject {
public:
    ResizeWatcher(QObject* watched, std::function<void()> onResize)
        : QObject(watched), _onResize(std::move(onResize)) { watched->installEventFilter(this); }
    bool eventFilter(QObject*, QEvent* e) override {
        if (e->type() == QEvent::Resize || e->type() == QEvent::Show) _onResize();
        return false;
    }
private:
    std::function<void()> _onResize;
};

// The layout box that holds w directly, searched from lay down.
QBoxLayout* boxHolding(QLayout* lay, QWidget* w) {
    if (lay == nullptr) return nullptr;
    for (int i = 0; i < lay->count(); ++i) {
        QLayoutItem* item = lay->itemAt(i);
        if (item->widget() == w) return qobject_cast<QBoxLayout*>(lay);
        if (QBoxLayout* found = boxHolding(item->layout(), w)) return found;
    }
    return nullptr;
}

QString comboAddress(const QComboBox* combo) {
    return AddressBook::addressFromAddressLabel(combo->currentText().split("(")[0].trimmed());
}
}   // namespace

void copyAddressToClipboard(QWidget* from, const QString& address) {
    QGuiApplication::clipboard()->setText(address);
    auto* window = from ? qobject_cast<QMainWindow*>(from->window()) : nullptr;
    if (window && window->statusBar())
        window->statusBar()->showMessage(QObject::tr("Address copied to clipboard"), 3 * 1000);
}

// ---- table cells -----------------------------------------------------------------

AddressCellDelegate::AddressCellDelegate(QAbstractItemView* view)
    : PrivacyBadgeDelegate(Mode::Address, view), _view(view) {
    setTrailingReserve(kSlot);
    // Pointing at an "i" opens the card at once (no tooltip delay): watch moves.
    view->viewport()->setMouseTracking(true);
    view->viewport()->installEventFilter(this);
}

QRect AddressCellDelegate::iconRect(const QRect& cell) {
    const QRect slot(cell.right() - 6 - kSlot + 1, cell.top(), kSlot, cell.height());
    return QRect(slot.center().x() - kIcon / 2, slot.center().y() - kIcon / 2, kIcon, kIcon);
}

QString AddressCellDelegate::addressAt(const QModelIndex& index) {
    const QString addr = addressFromDisplay(index.data(Qt::DisplayRole).toString());
    return Settings::isValidAddress(addr) ? addr : QString();
}

QStyleOptionViewItem AddressCellDelegate::optionAt(const QModelIndex& index) const {
    QStyleOptionViewItem opt;
    opt.rect = _view->visualRect(index);
    opt.font = _view->font();
    return opt;
}

void AddressCellDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
                                const QModelIndex& index) const {
    PrivacyBadgeDelegate::paint(painter, option, index);
    if (addressAt(index).isEmpty())
        return;
    static const QIcon info = infoIcon();
    static const QIcon copy(":/icons/res/icons/copy-light.svg");
    static const QIcon done(":/icons/res/icons/check-green.svg");
    const QIcon& icon = index == _copied ? done : addressTextElided(option, index) ? info : copy;
    icon.paint(painter, iconRect(option.rect));
}

// The icon owns its clicks, so pressing it never selects (highlights) the row:
// a fully shown address is copied and its icon turns into a green tick for a
// moment; a cut one opens the full-address card. Pointing at an "i" opens the
// card right away. Everything else in the cell behaves as usual.
bool AddressCellDelegate::eventFilter(QObject* watched, QEvent* event) {
    const QEvent::Type type = event->type();
    const bool mouse = type == QEvent::MouseMove || type == QEvent::MouseButtonPress
                    || type == QEvent::MouseButtonRelease || type == QEvent::MouseButtonDblClick;
    if (!mouse || watched != _view->viewport())
        return false;
    const auto* me = static_cast<QMouseEvent*>(event);
    const QModelIndex index = _view->indexAt(me->pos());
    if (!index.isValid() || _view->itemDelegateForColumn(index.column()) != this)
        return false;
    const QStyleOptionViewItem opt = optionAt(index);
    const QRect icon = iconRect(opt.rect).adjusted(-4, -4, 4, 4);
    const QString addr = addressAt(index);
    if (addr.isEmpty() || !icon.contains(me->pos()))
        return false;
    const bool cut = addressTextElided(opt, index);
    const QRect anchor(_view->viewport()->mapToGlobal(icon.topLeft()), icon.size());
    if (type == QEvent::MouseMove) {
        if (cut) AddressPopup::showFor(_view, addr, anchor);
        return false;
    }
    if (type == QEvent::MouseButtonRelease && me->button() == Qt::LeftButton)
        cut ? AddressPopup::showFor(_view, addr, anchor) : copyFromCell(index, addr);
    return true;   // press, double-click and release on the icon stay with the icon
}

void AddressCellDelegate::copyFromCell(const QModelIndex& index, const QString& addr) {
    copyAddressToClipboard(_view, addr);
    _copied = QPersistentModelIndex(index);
    _view->viewport()->update();
    QTimer::singleShot(1200, this, [this]() {
        _copied = QPersistentModelIndex();
        _view->viewport()->update();
    });
}

// ---- the full-address card -------------------------------------------------------

AddressPopup* AddressPopup::current() { return openPopup().data(); }

void AddressPopup::showFor(QWidget* parent, const QString& address, const QRect& globalAnchor) {
    if (AddressPopup* open = current()) {
        if (open->address() == address && open->isVisible()) return;   // already showing it
        open->close();
    }
    auto* popup = new AddressPopup(parent, address, globalAnchor);
    openPopup() = popup;
    popup->adjustSize();
    // Just under the anchor, right edges aligned, kept on screen.
    QPoint at(globalAnchor.right() - popup->width() + 1, globalAnchor.bottom() + 2);
    if (const QScreen* screen = QGuiApplication::screenAt(globalAnchor.center())) {
        const QRect area = screen->availableGeometry();
        at.setX(qBound(area.left(), at.x(), area.right() - popup->width()));
        if (at.y() + popup->height() > area.bottom())   // no room below: open above
            at.setY(globalAnchor.top() - popup->height() - 2);
    }
    popup->move(at);
    popup->show();
}

AddressPopup::AddressPopup(QWidget* parent, const QString& address, const QRect& globalAnchor)
    : QFrame(parent, Qt::Popup), _address(address), _anchor(globalAnchor.adjusted(-6, -6, 6, 6)) {
    setObjectName("addressPopup");
    setAttribute(Qt::WA_DeleteOnClose);
    setMouseTracking(true);
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(14, 12, 14, 12);
    layout->setSpacing(10);
    auto* text = new QLabel(address, this);
    text->setObjectName("addressPopupText");
    text->setTextInteractionFlags(Qt::TextSelectableByMouse);
    text->setMouseTracking(true);
    auto* copy = new QPushButton(tr("Copy"), this);
    copy->setObjectName("addressPopupCopy");
    copy->setCursor(Qt::PointingHandCursor);
    QObject::connect(copy, &QPushButton::clicked, this, [this, copy]() {
        copyAddressToClipboard(parentWidget(), _address);
        copy->setText(tr("Copied ✓"));
        QTimer::singleShot(700, this, &QWidget::close);
    });
    layout->addWidget(text);
    layout->addWidget(copy, 0, Qt::AlignRight);
}

// The card grabs the mouse while open, so every move outside it arrives here.
// Close once the pointer has left both the card and its "i".
void AddressPopup::mouseMoveEvent(QMouseEvent* event) {
    QFrame::mouseMoveEvent(event);
    const QPoint global = event->globalPos();
    if (!frameGeometry().contains(global) && !_anchor.contains(global))
        close();
}

// ---- Send page fields ----------------------------------------------------------------

// ---- Pay to: a thin scroll bar while the address does not fit -----------------

namespace {
const int kTextPad = 14;   // the line edit's text inset (qss padding + Qt's own margin)

int visibleTextWidth(const QLineEdit* field) {
    return field->width() - 2 * kTextPad - field->textMargins().left() - field->textMargins().right();
}

// Index of the first character the field shows, from where it draws its cursor.
int firstVisibleChar(const QLineEdit* field) {
    const QString text = field->text();
    const QFontMetrics fm = field->fontMetrics();
    const int cursorX = field->inputMethodQuery(Qt::ImCursorRectangle).toRect().x();
    const int hidden = fm.horizontalAdvance(text.left(field->cursorPosition()))
                     - (cursorX - kTextPad - field->textMargins().left());
    int i = 0;
    while (i < text.size() && fm.horizontalAdvance(text.left(i + 1)) <= hidden) ++i;
    return i;
}

// The first character from which the rest of the text fits: the bar's maximum.
int lastFirstChar(const QLineEdit* field) {
    const QString text = field->text();
    const QFontMetrics fm = field->fontMetrics();
    const int room = visibleTextWidth(field);
    int i = text.size();
    while (i > 0 && fm.horizontalAdvance(text.mid(i - 1)) <= room) --i;
    return i;
}
}   // namespace

namespace {
// Keeps the bar in step with a line edit. QLineEdit settles its own scroll offset
// only while painting, so the bar's position is read just after each paint.
class FieldScroll : public QObject {
public:
    FieldScroll(QLineEdit* field, QScrollBar* bar) : QObject(field), _field(field), _bar(bar) {
        field->installEventFilter(this);
        QObject::connect(field, &QLineEdit::textChanged, this, [this]() { layout(); });
        QObject::connect(bar, &QScrollBar::valueChanged, this, [this](int first) { scrollTo(first); });
    }
    bool eventFilter(QObject*, QEvent* e) override {
        if (e->type() == QEvent::Resize || e->type() == QEvent::Show)
            layout();
        if (e->type() == QEvent::Paint && !_pending) {
            _pending = true;
            QTimer::singleShot(0, this, [this]() { _pending = false; syncValue(); });
        }
        return false;
    }
private:
    // Shown only while the text is wider than the field, along its bottom edge.
    void layout() {
        const int max = lastFirstChar(_field);
        _bar->setGeometry(kTextPad, _field->height() - 7, _field->width() - 2 * kTextPad, 4);
        _bar->setVisible(max > 0);
        _syncing = true;
        _bar->setRange(0, max);
        _bar->setPageStep(qMax(1, _field->text().size() - max));
        _syncing = false;
    }
    void syncValue() {
        _syncing = true;
        _bar->setValue(firstVisibleChar(_field));
        _syncing = false;
    }
    // Dragging scrolls the text: show the end first (a real paint settles that
    // offset), then put the cursor on the wanted first character, which the field
    // then keeps at its left edge.
    void scrollTo(int first) {
        if (_syncing) return;
        const QSignalBlocker block(_field);
        _field->setCursorPosition(_field->text().size());
        _field->repaint();
        _field->setCursorPosition(first);
        _field->update();
    }
    QLineEdit*  _field;
    QScrollBar* _bar;
    bool _syncing = false;
    bool _pending = false;
};
}   // namespace

void attachAddressScroll(QLineEdit* field) {
    auto* bar = new QScrollBar(Qt::Horizontal, field);
    bar->setObjectName("fieldScroll");
    bar->setCursor(Qt::ArrowCursor);
    bar->setFocusPolicy(Qt::NoFocus);
    bar->hide();
    new FieldScroll(field, bar);
}

void attachAddressInfo(QComboBox* combo) {
    // Size from a short minimum, not the longest address: the address is shown
    // shortened in the middle (AddressCombo) and the full one is a click away.
    combo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    combo->setMinimumContentsLength(18);
    combo->setSizePolicy(QSizePolicy::Expanding, combo->sizePolicy().verticalPolicy());
    auto* info = new QToolButton(combo->parentWidget());
    info->setObjectName("comboAddressInfo");
    info->setIcon(infoIcon());
    info->setIconSize(QSize(18, 18));
    info->setAutoRaise(true);
    info->setCursor(Qt::PointingHandCursor);
    info->setToolTip(QObject::tr("Show the full address"));
    info->setVisible(false);
    if (QBoxLayout* box = boxHolding(combo->parentWidget()->layout(), combo))
        box->insertWidget(box->indexOf(combo) + 1, info);
    auto update = [combo, info]() {
        const QString full = combo->currentText();
        info->setVisible(Settings::isValidAddress(comboAddress(combo))
                         && combo->fontMetrics().horizontalAdvance(full) > combo->width() - 40);
    };
    QObject::connect(combo, QOverload<int>::of(&QComboBox::currentIndexChanged), combo, update);
    new ResizeWatcher(combo, update);
    QObject::connect(info, &QToolButton::clicked, combo, [combo, info]() {
        AddressPopup::showFor(combo, comboAddress(combo),
                              QRect(info->mapToGlobal(QPoint(0, 0)), info->size()));
    });
}
