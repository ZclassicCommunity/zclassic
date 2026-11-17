#ifndef ADDRESSCOMBO_H
#define ADDRESSCOMBO_H

#include "precompiled.h"

class AddressCombo : public QComboBox 
{
    Q_OBJECT;
public:
    explicit    AddressCombo(QWidget* parent = nullptr);

    QString     itemText(int i);
    QString     currentText();

    void        addItem(const QString& itemText, double bal);
    void        insertItem(int index, const QString& text, double bal = 0.0);

    // What the closed box shows: the address elided in the MIDDLE to fit, the "(balance)" suffix
    // always whole. Display only; currentText()/itemText() still return the full address.
    QString     displayText(int availableWidth) const;

protected:
    void        paintEvent(QPaintEvent* e) override;

public slots:
    void setCurrentText(const QString& itemText);

private:
};

#endif // ADDRESSCOMBO_H
