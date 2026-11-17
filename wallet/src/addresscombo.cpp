#include "addresscombo.h"
#include "addressbook.h"
#include "settings.h"
#include <QStylePainter>
#include <QStyleOptionComboBox>
#include <QAbstractItemView>
#include <QFontMetrics>

AddressCombo::AddressCombo(QWidget* parent) : 
    QComboBox(parent) {
    // The dropdown list elides in the middle too, instead of cutting the end (the balance) off.
    if (view()) view()->setTextElideMode(Qt::ElideMiddle);
    // Size from a short minimum, not from the longest address in the list: the box shrinks and elides.
    setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLength);
    setMinimumContentsLength(24);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
}

QString AddressCombo::itemText(int i) {
    QString txt = QComboBox::itemText(i);
    return AddressBook::addressFromAddressLabel(txt.split("(")[0].trimmed());
}

QString AddressCombo::currentText() {
    QString txt = QComboBox::currentText();
    return AddressBook::addressFromAddressLabel(txt.split("(")[0].trimmed());
}

void AddressCombo::setCurrentText(const QString& text) {
    for (int i=0; i < count(); i++) {
        if (itemText(i) == text) {
            QComboBox::setCurrentIndex(i);
        }
    }
} 

void AddressCombo::addItem(const QString& text, double bal) {
    QString txt = AddressBook::addLabelToAddress(text);
    if (bal > 0)
        txt = txt % "(" % Settings::getZCLDisplayFormat(bal) % ")";
        
    QComboBox::addItem(txt);
}

void AddressCombo::insertItem(int index, const QString& text, double bal) {
    QString txt = AddressBook::addLabelToAddress(text) % 
                    "(" % Settings::getZCLDisplayFormat(bal) % ")";
    QComboBox::insertItem(index, txt);
}

QString AddressCombo::displayText(int availableWidth) const {
    const QString full = QComboBox::currentText();
    const int paren = full.indexOf(QLatin1Char('('));
    const QString head = paren < 0 ? full : full.left(paren);
    const QString tail = paren < 0 ? QString() : full.mid(paren);   // "(1.5 ZCL)" stays whole
    const QFontMetrics fm(font());
    const int room = availableWidth - fm.horizontalAdvance(tail);
    if (room <= 0) return tail;
    return fm.elidedText(head, Qt::ElideMiddle, room) + tail;
}

void AddressCombo::paintEvent(QPaintEvent*) {
    QStylePainter p(this);
    p.setPen(palette().color(QPalette::ButtonText));
    QStyleOptionComboBox opt;
    initStyleOption(&opt);
    p.drawComplexControl(QStyle::CC_ComboBox, opt);
    const QRect edit = style()->subControlRect(QStyle::CC_ComboBox, &opt,
                                               QStyle::SC_ComboBoxEditField, this);
    opt.currentText = displayText(edit.width() - 6);
    p.drawControl(QStyle::CE_ComboBoxLabel, opt);
}
