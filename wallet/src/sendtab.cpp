#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "addressbook.h"
#include "ui_confirm.h"
#include "ui_memodialog.h"
#include "ui_newrecurring.h"
#include "settings.h"
#include "rpc.h"
#include "recurring.h"

using json = nlohmann::json;

// Convert a ZCL amount to integer zatoshis (1 ZCL = 1e8 zat). Wallet money is otherwise
// carried as double; the auto-shield change must be computed in integer zatoshis so the
// daemon's selected inputs are consumed EXACTLY (a fraction-of-a-zatoshi drift would make
// z_sendmany either reject the tx or emit a public transparent-change output). The input
// MUST be a <=8-decimal-place amount (the send/fee QRegExpValidators guarantee this), so
// llround is exact and no half-zatoshi tie can occur for any value within MAX_MONEY.
static inline qint64 toZat(double zcl) {
    return static_cast<qint64>(llround(zcl * 1e8));
}

void MainWindow::setupSendTab() {
    // Create the validator for send to/amount fields
    auto amtValidator = new QRegExpValidator(QRegExp("[0-9]{0,8}\\.?[0-9]{0,8}"));    
    ui->Amount1->setValidator(amtValidator);

    // Send button
    QObject::connect(ui->sendTransactionButton, &QPushButton::clicked, this, &MainWindow::sendButton);

    // Cancel Button
    QObject::connect(ui->cancelSendButton, &QPushButton::clicked, this, &MainWindow::cancelButton);

    // Input Combobox current text changed
    QObject::connect(ui->inputsCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
        this, &MainWindow::inputComboTextChanged);

    // Hook up add address button click
    QObject::connect(ui->addAddressButton, &QPushButton::clicked, this, &MainWindow::addAddressSection);

    // "Send all" — now a checkable button (was a bare checkbox). It stays checkable so
    // recomputeMaxIfChecked()/setChecked(false) keep working; toggled(bool) is adapted to
    // the existing maxAmountChecked(int) slot so the max math (recomputeMaxIfChecked) is
    // entirely unchanged.
    QObject::connect(ui->Max1, &QPushButton::toggled, this, [this](bool on) {
        maxAmountChecked(on ? Qt::Checked : Qt::Unchecked);
    });

    // The first Address button
    QObject::connect(ui->Address1, &QLineEdit::textChanged, [=] (auto text) {
        this->addressChanged(1, text);
    });

    // The first Memo button
    QObject::connect(ui->MemoBtn1, &QPushButton::clicked, [=] () {
        this->memoButtonClicked(1);
    });
    setMemoEnabled(1, false);
        
    // This is the damnest thing ever. If we do AddressBook::readFromStorage() directly, the whole file
    // doesn't get read. It needs to run in a timer after everything has finished to be able to read
    // the file properly.
    // `this` is the receiver/context object so Qt CANCELS this 2s callback if the
    // MainWindow is destroyed first — otherwise an orphaned singleShot fires
    // updateLabelsAutoComplete() on freed memory (crash on a fast quit during the
    // first 2s of startup; surfaced as a use-after-free under the test event loop).
    QTimer::singleShot(2000, this, [this]() { updateLabelsAutoComplete(); });

    // The first address book button
    QObject::connect(ui->AddressBook1, &QPushButton::clicked, [=] () {
        AddressBook::open(this, ui->Address1);
    });

    // The first Amount button
    QObject::connect(ui->Amount1, &QLineEdit::textChanged, [=] (auto text) {
        this->amountChanged(1, text);
    });

    // Fee amount changed
    // Disable custom fees if settings say no
    ui->minerFeeAmt->setReadOnly(!Settings::getInstance()->getAllowCustomFees());
    QObject::connect(ui->minerFeeAmt, &QLineEdit::textChanged, [=](auto txt) {
        ui->lblMinerFeeUSD->setText(Settings::getUSDFormat(txt.toDouble()));
        recomputeMaxIfChecked();   // fee changed -> the "Send max" amount must follow
    });
    ui->minerFeeAmt->setText(Settings::getDecimalString(Settings::getMinerFee()));
    // Network-fee read-only hint (custom fees default OFF): explain the greyed field
    // instead of leaving a mysterious dead control.
    if (!Settings::getInstance()->getAllowCustomFees()) {
        QString feeHint = tr("Default network fee. Turn on “Allow custom fees” in Settings to change it.");
        ui->minerFeeAmt->setToolTip(feeHint);
        ui->minerFeeLabel->setToolTip(feeHint);
    }
    // Keep the running totals line current when the fee changes.
    QObject::connect(ui->minerFeeAmt, &QLineEdit::textChanged, [=](auto) { updateSendTotals(); });

     // Set up focus enter to set fees
    QObject::connect(ui->tabWidget, &QTabWidget::currentChanged, [=] (int pos) {
        if (pos == 1) {
            QString txt = ui->minerFeeAmt->text();
            ui->lblMinerFeeUSD->setText(Settings::getUSDFormat(txt.toDouble()));
            // Re-sync the read-only state + hint each time Send is shown, so toggling
            // "Allow custom fees" in Settings is reflected without a restart.
            bool custom = Settings::getInstance()->getAllowCustomFees();
            ui->minerFeeAmt->setReadOnly(!custom);
            QString feeHint = custom ? QString()
                : tr("Default network fee. Turn on “Allow custom fees” in Settings to change it.");
            ui->minerFeeAmt->setToolTip(feeHint);
            ui->minerFeeLabel->setToolTip(feeHint);
        }
    });
    //Fees validator
    auto feesValidator = new QRegExpValidator(QRegExp("[0-9]{0,8}\\.?[0-9]{0,8}")); 
    ui->minerFeeAmt->setValidator(feesValidator);

    // The first Memo label uses the base font (no shrink) so an entered private note
    // is readable, not a tiny afterthought.

    // Recurring button
    QObject::connect(ui->chkRecurring, &QCheckBox::stateChanged, [=] (int checked) {
        if (checked) {
            ui->btnRecurSchedule->setEnabled(true);            
        } else {
            ui->btnRecurSchedule->setEnabled(false);
            ui->lblRecurDesc->setText("");
        }

    });

    // Recurring schedule button
    QObject::connect(ui->btnRecurSchedule, &QPushButton::clicked, this, &MainWindow::editSchedule);

    // Hide the recurring section for now
    ui->chkRecurring->setVisible(false);
    ui->lblRecurDesc->setVisible(false);
    ui->btnRecurSchedule->setVisible(false);

    // Set the default state for the whole page
    removeExtraAddresses();
}

void MainWindow::editSchedule() {
    // Open the edit schedule dialog
    Recurring::showEditDialog(this, this, createTxFromSendPage());

}

void MainWindow::updateLabelsAutoComplete() {
    QList<QString> list;
    auto labels = AddressBook::getInstance()->getAllAddressLabels();
    
    std::transform(labels.begin(), labels.end(), std::back_inserter(list), [=] (auto la) -> QString {
        return la.first % "/" % la.second;
    });
    
    delete labelCompleter;
    labelCompleter = new QCompleter(list, this);
    labelCompleter->setCaseSensitivity(Qt::CaseInsensitive);

    // Then, find all the address fields and update the completer.
    QRegExp re("Address[0-9]+", Qt::CaseInsensitive);
    for (auto target: ui->sendToWidgets->findChildren<QLineEdit *>(re)) {
        target->setCompleter(labelCompleter);
    }
}

void MainWindow::setDefaultPayFrom() {
    auto findMax = [=] (QString startsWith) {
        double max_amt = 0;
        int    idx     = -1;

        for (int i=0; i < ui->inputsCombo->count(); i++) {
            auto addr = ui->inputsCombo->itemText(i);
            if (addr.startsWith(startsWith)) {
                auto amt = rpc->getAllBalances()->value(addr);
                if (max_amt < amt) {
                    max_amt = amt;
                    idx = i;
                }
            }                
        }

        return idx;
    };

    // By default, select the z-address with the most balance from the inputs combo
    auto maxZ = findMax("z");
    if (maxZ >= 0) {
        ui->inputsCombo->setCurrentIndex(maxZ);                
    } else {
        auto maxT = findMax("t");
        maxT  = maxT >= 0 ? maxT : 0;
        ui->inputsCombo->setCurrentIndex(maxT);
    }
};

void MainWindow::updateFromCombo() {
    if (!rpc || !rpc->getAllBalances())
        return;

    auto lastFromAddr = ui->inputsCombo->currentText();

    ui->inputsCombo->clear();
    auto i = rpc->getAllBalances()->constBegin();

    // Add all the addresses into the inputs combo box
    while (i != rpc->getAllBalances()->constEnd()) {
        ui->inputsCombo->addItem(i.key(), i.value());
        if (i.key() == lastFromAddr) ui->inputsCombo->setCurrentText(i.key());

        ++i;
    }

    if (lastFromAddr.isEmpty()) {
        setDefaultPayFrom();
    }
    else {
        ui->inputsCombo->setCurrentText(lastFromAddr);
    }
}

void MainWindow::inputComboTextChanged(int index) {
    auto addr      = ui->inputsCombo->itemText(index);
    double displayed = rpc->getAllBalances()->value(addr);   // minconf=0 total (incl. 0-conf)
    double spendable = spendableOrFallback(addr);            // confirmed-spendable, fails open

    // LEGIBILITY: the "Available" line shows what is actually spendable now (so it agrees
    // with the spendable-based Send-max), and when some funds for this address are still
    // confirming we append a calm "(+X confirming)" qualifier so the user is not surprised
    // that the field auto-filled less than the hero total. pending = displayed - spendable
    // is only meaningful when the UTXO set is loaded; spendableOrFallback() returns the
    // displayed value when it isn't, so pending is then 0 and no qualifier is shown.
    double pending = displayed - spendable;
    if (pending < 0) pending = 0;
    QString balFmt = Settings::getZCLDisplayFormat(spendable);
    if (Settings::getDecimalString(pending) != "0")
        balFmt = balFmt % " (+" % Settings::getZCLDisplayFormat(pending) % tr(" confirming") % ")";

    ui->sendAddressBalance->setText(balFmt);
    ui->sendAddressBalanceUSD->setText(Settings::getUSDFormat(spendable));
    recomputeMaxIfChecked();   // from-address changed -> its balance drives the "Send max" amount
    updateSendPrivacyBadge();  // from-address private/public-ness feeds the verdict
    updateSendTotals();
}

    
void MainWindow::addAddressSection() {
    int itemNumber = ui->sendToWidgets->children().size() - 1;

    auto verticalGroupBox = new QGroupBox(ui->sendToWidgets);
    verticalGroupBox->setTitle(QString(tr("Recipient ")) % QString::number(itemNumber));
    verticalGroupBox->setObjectName(QString("AddressGroupBox") % QString::number(itemNumber));
    auto sendAddressLayout = new QVBoxLayout(verticalGroupBox);
    sendAddressLayout->setSpacing(6);
    sendAddressLayout->setContentsMargins(11, 11, 11, 11);

    auto horizontalLayout_12 = new QHBoxLayout();
    horizontalLayout_12->setSpacing(6);
    auto label_4 = new QLabel(verticalGroupBox);
    label_4->setText(tr("Pay to"));
    horizontalLayout_12->addWidget(label_4);

    auto Address1 = new QLineEdit(verticalGroupBox);
    Address1->setObjectName(QString("Address") % QString::number(itemNumber));
    Address1->setPlaceholderText(tr("Paste a z-address (private) or t-address (public)"));
    QObject::connect(Address1, &QLineEdit::textChanged, [=] (auto text) {
        this->addressChanged(itemNumber, text);
    });
    Address1->setCompleter(labelCompleter);

    horizontalLayout_12->addWidget(Address1);

    auto addressBook1 = new QPushButton(verticalGroupBox);
    addressBook1->setObjectName(QStringLiteral("AddressBook") % QString::number(itemNumber));
    addressBook1->setText(tr("Address Book"));
    QObject::connect(addressBook1, &QPushButton::clicked, [=] () {
        AddressBook::open(this, Address1);
    });

    horizontalLayout_12->addWidget(addressBook1);

    sendAddressLayout->addLayout(horizontalLayout_12);

    auto horizontalLayout_13 = new QHBoxLayout();
    horizontalLayout_13->setSpacing(6);
        
    auto label_6 = new QLabel(verticalGroupBox);
    label_6->setText(tr("Amount"));
    horizontalLayout_13->addWidget(label_6);

    auto Amount1 = new QLineEdit(verticalGroupBox);
    Amount1->setPlaceholderText(tr("0.00"));
    Amount1->setObjectName(QString("Amount") % QString::number(itemNumber));
    Amount1->setBaseSize(QSize(200, 0));
    Amount1->setAlignment(Qt::AlignRight);
    // Create the validator for send to/amount fields
    auto amtValidator = new QRegExpValidator(QRegExp("[0-9]{0,8}\\.?[0-9]{0,8}"));
    Amount1->setValidator(amtValidator);
    QObject::connect(Amount1, &QLineEdit::textChanged, [=] (auto text) {
        this->amountChanged(itemNumber, text);
    });

    horizontalLayout_13->addWidget(Amount1);

    // Always-on "ZCL" unit so the amount field's currency is clear before typing.
    auto amountUnit = new QLabel(verticalGroupBox);
    amountUnit->setObjectName(QString("amountUnit") % QString::number(itemNumber));
    amountUnit->setText(tr("ZCL"));
    horizontalLayout_13->addWidget(amountUnit);

    auto AmtUSD1 = new QLabel(verticalGroupBox);
    AmtUSD1->setObjectName(QString("AmtUSD") % QString::number(itemNumber));   
    horizontalLayout_13->addWidget(AmtUSD1);

    auto horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    horizontalLayout_13->addItem(horizontalSpacer_4);

    auto MemoBtn1 = new QPushButton(verticalGroupBox);
    MemoBtn1->setObjectName(QString("MemoBtn") % QString::number(itemNumber));
    MemoBtn1->setText(tr("Add private note"));
    // Connect Memo Clicked button
    QObject::connect(MemoBtn1, &QPushButton::clicked, [=] () {
        this->memoButtonClicked(itemNumber);
    });
    horizontalLayout_13->addWidget(MemoBtn1);
    setMemoEnabled(itemNumber, false);

    sendAddressLayout->addLayout(horizontalLayout_13);

    auto MemoTxt1 = new QLabel(verticalGroupBox);
    MemoTxt1->setObjectName(QString("MemoTxt") % QString::number(itemNumber));
    // Base font (no shrink) so an entered private note is readable.
    MemoTxt1->setWordWrap(true);
    sendAddressLayout->addWidget(MemoTxt1);

    ui->sendToLayout->insertWidget(itemNumber-1, verticalGroupBox);         

    // Set focus into the address
    Address1->setFocus();

    // Delay the call to scroll to allow the scroll window to adjust. `this` is the
    // context object so Qt cancels the callback if the MainWindow is destroyed
    // within 10ms (same orphaned-singleShot UAF class as the updateLabelsAutoComplete
    // fix above — captures `ui`, which dies with the window).
    QTimer::singleShot(10, this, [this] () {ui->sendToScrollArea->ensureWidgetVisible(ui->addAddressButton);});
}

void MainWindow::addressChanged(int itemNumber, const QString& text) {
    auto addr = AddressBook::addressFromAddressLabel(text);
    setMemoEnabled(itemNumber, addr.startsWith("z"));

    // Live validation affordance: green border the instant a typed/resolved address
    // parses, red when it clearly won't, neutral while empty — so an invalid address
    // is caught as you type, not as a surprise failure at Send. isValidAddress is
    // static and touches no daemon, so it is safe on every keystroke. Single writer
    // of the field's "validation" property; the qss border rules do the rest.
    auto* fld = ui->sendToWidgets->findChild<QLineEdit*>(QString("Address") + QString::number(itemNumber));
    if (fld) {
        const char* state = text.trimmed().isEmpty() ? "empty"
                          : (Settings::isValidAddress(addr) ? "valid" : "invalid");
        if (fld->property("validation").toString() != QString(state)) {
            fld->setProperty("validation", state);
            fld->style()->unpolish(fld);   // property selectors need a re-polish
            fld->style()->polish(fld);
        }
    }

    updateSendPrivacyBadge();   // recipient changed -> the private/public verdict may change
    updateSendTotals();
}

void MainWindow::amountChanged(int item, const QString& text) {
    auto usd = ui->sendToWidgets->findChild<QLabel*>(QString("AmtUSD") % QString::number(item));
    usd->setText(Settings::getUSDFormat(text.toDouble()));

    // Live amount affordance, mirroring the address border: neutral while empty, green
    // once it's a positive number, red if it parses to zero/negative. This is a LOCAL
    // format check only (>0) — it does NOT compare against the balance and does NOT call
    // doSendTxValidations; the authoritative overspend check stays at Send time.
    auto* fld = ui->sendToWidgets->findChild<QLineEdit*>(QString("Amount") % QString::number(item));
    if (fld) {
        const char* state = text.trimmed().isEmpty() ? "empty"
                          : (text.toDouble() > 0 ? "valid" : "invalid");
        if (fld->property("validation").toString() != QString(state)) {
            fld->setProperty("validation", state);
            fld->style()->unpolish(fld);
            fld->style()->polish(fld);
        }
    }

    updateSendTotals();   // any amount change updates the running "You will send …" line

    // A change to ANOTHER recipient's amount (item != 1) shrinks the max available for
    // recipient 1; recompute it. Guard on item != 1 to avoid recursing on our own setText
    // of Amount1 (which would re-emit amountChanged(1)).
    if (item != 1)
        recomputeMaxIfChecked();
}

void MainWindow::setMemoEnabled(int number, bool enabled) {
    auto memoBtn = ui->sendToWidgets->findChild<QPushButton*>(QString("MemoBtn") % QString::number(number));
     if (enabled) {
        memoBtn->setEnabled(true);
        memoBtn->setToolTip(tr("Attach an encrypted message only the recipient can read"));
    } else {
        memoBtn->setEnabled(false);
        memoBtn->setToolTip(tr("Private notes are only available for z-addresses (private)"));
    }
}

void MainWindow::memoButtonClicked(int number, bool includeReplyTo) {
    // Memos can only be used with zAddrs. So check that first
    auto addr = ui->sendToWidgets->findChild<QLineEdit*>(QString("Address") + QString::number(number));
    if (!AddressBook::addressFromAddressLabel(addr->text()).startsWith("z")) {
        QMessageBox msg(QMessageBox::Critical, tr("Memos can only be used with z-addresses"),
        tr("The memo field can only be used with a z-address.\n") + addr->text() + tr("\ndoesn't look like a z-address"),
        QMessageBox::Ok, this);

        msg.exec();
        return;
    }

    // Get the current memo if it exists
    auto memoTxt = ui->sendToWidgets->findChild<QLabel *>(QString("MemoTxt") + QString::number(number));
    QString currentMemo = memoTxt->text();

    Ui_MemoDialog memoDialog;
    QDialog dialog(this);
    memoDialog.setupUi(&dialog);
    Settings::saveRestore(&dialog);

    QObject::connect(memoDialog.memoTxt, &QPlainTextEdit::textChanged, [=] () {
        QString txt = memoDialog.memoTxt->toPlainText();
        memoDialog.memoSize->setText(QString::number(txt.toUtf8().size()) + "/512");

        if (txt.toUtf8().size() <= 512) {
            // Everything is fine
            memoDialog.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
            memoDialog.memoSize->setStyleSheet("");
        }
        else {
           // Overweight
            memoDialog.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
            memoDialog.memoSize->setStyleSheet("color: red;");
        }
        
    });

    auto fnAddReplyTo = [=, &dialog]() {
        QString replyTo = ui->inputsCombo->currentText();
        if (!Settings::isZAddress(replyTo)) {
            replyTo = rpc->getDefaultSaplingAddress();
            if (replyTo.isEmpty())
                return;
        }
        auto curText = memoDialog.memoTxt->toPlainText();
        if (curText.endsWith(replyTo))
            return;

        memoDialog.memoTxt->setPlainText(curText + "\n" + tr("Reply to") + ":\n" + replyTo);

        // MacOS has a really annoying bug where the Plaintext doesn't refresh when the content is
        // updated. So we do this ugly hack - resize the window slightly to force it to refresh
        dialog.setGeometry(dialog.geometry().adjusted(0,0,0,1));
        dialog.setGeometry(dialog.geometry().adjusted(0,0,0,-1));
    };

    // Insert From Address button. Including a reply address writes the sender's OWN
    // z-address into the encrypted memo -- only the recipient can read it, but it
    // de-anonymizes the sender to that recipient and links the payment to their
    // shielded address. Educate always (tooltip) and require explicit one-time
    // consent on the FIRST manual click (persisted, never nags again).
    memoDialog.btnInsertFrom->setToolTip(tr(
        "Writes your z-address into the encrypted memo so the recipient can reply.\n"
        "This reveals your identity to that recipient and links this payment to\n"
        "your shielded address."));
    QObject::connect(memoDialog.btnInsertFrom, &QPushButton::clicked, [=, &dialog]() {
        if (!QSettings().value("memo/replyToWarned", false).toBool()) {
            auto proceed = QMessageBox::question(&dialog, tr("Reveal your address to the recipient?"),
                tr("Including a reply address writes <b>your own z-address</b> into the "
                   "encrypted memo. Only the recipient can read it, but it reveals your "
                   "identity to them and lets them link this payment to your shielded "
                   "address.<br><br>Include your reply address anyway?"),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
            if (proceed != QMessageBox::Yes)
                return;
            QSettings().setValue("memo/replyToWarned", true);
        }
        fnAddReplyTo();
    });

    memoDialog.memoTxt->setPlainText(currentMemo);
    memoDialog.memoTxt->setFocus();

    // Programmatic reply-to (e.g. recurring/scheduled sends): never block on a dialog
    // -- the persistent tooltip + one-time manual consent cover the interactive case.
    if (includeReplyTo)
        fnAddReplyTo();

    if (dialog.exec() == QDialog::Accepted) {
        // MONEY-SAFETY: store the RAW memo only. createTxFromSendPage reads this exact
        // QLabel verbatim as the on-chain memo (and hex-encodes it), so ANY decoration
        // here would be SENT on-chain, accumulate on re-edit, and escape the 512-byte
        // dialog limit. The "private note" framing lives in the button label + tooltips,
        // never in the payload text.
        memoTxt->setText(memoDialog.memoTxt->toPlainText());
    }
}

void MainWindow::removeExtraAddresses() {
    // The last one is a spacer, so ignore that
    int totalItems = ui->sendToWidgets->children().size() - 2; 

    // Clear the first recipient fields
    auto addr = ui->sendToWidgets->findChild<QLineEdit*>(QString("Address1"));
    addr->clear();
    auto amt  = ui->sendToWidgets->findChild<QLineEdit*>(QString("Amount1"));
    amt->clear();
    auto amtUSD  = ui->sendToWidgets->findChild<QLabel*>(QString("AmtUSD1"));
    amtUSD->clear();
    // "Send all" is now a checkable QPushButton (was a QCheckBox) — cast accordingly or
    // findChild returns null and this null-derefs.
    auto max  = ui->sendToWidgets->findChild<QPushButton*>(QString("Max1"));
    if (max) max->setChecked(false);
    auto memo = ui->sendToWidgets->findChild<QLabel*>(QString("MemoTxt1"));
    memo->clear();

    // Disable first memo btn
    setMemoEnabled(1, false);

    // Reset the fee
    ui->minerFeeAmt->setText(Settings::getDecimalString(Settings::getMinerFee()));

    // Start the deletion after the first item, since we want to keep 1 send field there all there
    for (int i=1; i < totalItems; i++) {
        auto addressGroupBox = ui->sendToWidgets->findChild<QGroupBox*>(QString("AddressGroupBox") % QString::number(i+1));
            
        delete addressGroupBox;
    }    

    // Reset the recurring button
    ui->chkRecurring->setCheckState(Qt::Unchecked);
    ui->btnRecurSchedule->setEnabled(false);
    ui->lblRecurDesc->setText("");

    // Clear the live privacy badge + running totals back to their resting state.
    updateSendPrivacyBadge();
    updateSendTotals();
}

void MainWindow::maxAmountChecked(int checked) {
    if (checked == Qt::Checked) {
        ui->Amount1->setReadOnly(true);
        recomputeMaxIfChecked();
    } else if (checked == Qt::Unchecked) {
        // Just remove the readonly part, don't change the content
        ui->Amount1->setReadOnly(false);
    }
}

// STALE-MAX FIX: recompute the max amount IN PLACE whenever Max is currently checked. Called
// on the checkbox toggle AND from every later input that changes the result (from-address,
// fee, other recipients) so the read-only Amount1 never shows a stale max. Early-returns when
// Max is unchecked, so it is safe to call unconditionally. Setting Amount1 here can re-emit
// amountChanged(1), but that path is guarded (item==1 does not recompute), so no recursion.
void MainWindow::recomputeMaxIfChecked() {
    if (!ui->Max1->isChecked()) return;
    if (rpc->getAllBalances() == nullptr) return;

    // Calculate maximum amount
    double sumAllAmounts = 0.0;
    // Calculate all other amounts
    int totalItems = ui->sendToWidgets->children().size() - 2;   // The last one is a spacer, so ignore that
    // Start counting the sum skipping the first one, because the MAX button is on the first one, and we don't
    // want to include it in the sum.
    for (int i=1; i < totalItems; i++) {
        auto amt  = ui->sendToWidgets->findChild<QLineEdit*>(QString("Amount")  % QString::number(i+1));
        if (amt)
            sumAllAmounts += amt->text().toDouble();
    }

    if (Settings::getInstance()->getAllowCustomFees()) {
        // += (not =): must ADD the custom fee to the other recipients' amounts
        // already summed above, else MAX is computed too large (it ignores the
        // other outputs) and the send fails with a confusing "Not enough funds".
        sumAllAmounts += ui->minerFeeAmt->text().toDouble();
    }
    else {
        sumAllAmounts += Settings::getMinerFee();
    }

    auto addr = ui->inputsCombo->currentText();

    // SPENDABLE-MAX FIX: base "Send max" / "Shield my funds" on the CONFIRMED, spendable
    // balance, not the minconf=0 getAllBalances() total. The daemon (z_sendmany,
    // minconf=1) spends only confirmed inputs, so a max derived from the unconfirmed-
    // inclusive total asks to move more than is spendable and the send is rejected with
    // "insufficient funds" -- the exact dead-end the user hit. spendableOrFallback()
    // fails OPEN (returns the minconf=0 value) when the UTXO set isn't loaded, so a
    // legitimate send is never blocked. Fee accounting is unchanged: sumAllAmounts
    // already folds in the fee (custom ui->minerFeeAmt or Settings::getMinerFee()), and
    // the (<0 -> 0) clamp keeps the result non-negative. The value written to the
    // read-only Amount1 is exactly what flows into z_sendmany, so shown == sent.
    double maxamount = spendableOrFallback(addr) - sumAllAmounts;
    maxamount        = (maxamount < 0) ? 0 : maxamount;

    ui->Amount1->setText(Settings::getDecimalString(maxamount));
}

// PRIV-11 / UX-12 — pure four-way classifier. The actual body is the single
// source of truth `sendCategoryOf()` in sendcategory.h, which both production and
// the L0 unit suite link directly (no hand-copied mirror). This member just
// forwards so existing callers (confirmTx) and the static seam keep working.
SendCategory MainWindow::classifySend(const Tx& tx) {
    return sendCategoryOf(tx);
}

// Create a Tx from the current state of the send page.
Tx MainWindow::createTxFromSendPage() {
    Tx tx;

    bool sendChangeToSapling = Settings::getInstance()->getAutoShield();

    // Gather the from / to addresses
    tx.fromAddr = ui->inputsCombo->currentText();
    sendChangeToSapling = sendChangeToSapling && Settings::isTAddress(tx.fromAddr);

    // For each addr/amt in the sendTo tab
    int totalItems = ui->sendToWidgets->children().size() - 2;   // The last one is a spacer, so ignore that
    bool   sproutRecipient = false;
    for (int i=0; i < totalItems; i++) {
        QString addr = ui->sendToWidgets->findChild<QLineEdit*>(QString("Address") % QString::number(i+1))->text().trimmed();
        // Remove label if it exists
        addr = AddressBook::addressFromAddressLabel(addr);

        // If address is sprout, then we can't send change to sapling, because of turnstile.
        if (Settings::getInstance()->isSproutAddress(addr))
            sproutRecipient = true;
        sendChangeToSapling = sendChangeToSapling && !Settings::getInstance()->isSproutAddress(addr);

        double  amt  = ui->sendToWidgets->findChild<QLineEdit*>(QString("Amount")  % QString::number(i+1))->text().trimmed().toDouble();
        QString memo = ui->sendToWidgets->findChild<QLabel*>(QString("MemoTxt")  % QString::number(i+1))->text().trimmed();

        tx.toAddrs.push_back( ToFields{addr, amt, memo, memo.toUtf8().toHex()} );
    }

    if (Settings::getInstance()->getAllowCustomFees()) {
        tx.fee = ui->minerFeeAmt->text().toDouble();
    }
    else {
        tx.fee = Settings::getMinerFee();
    }

    // PRIV-27 — for a Sprout recipient, Sapling change is suppressed (turnstile
    // forbids mixing), so the change cannot be shielded to Sapling on THIS tx.
    // Surface that constraint to the user (once) rather than silently leaving the
    // change transparent. We only nag when auto-shield is ON and the from-addr is
    // transparent (the only case where change WOULD otherwise be shielded).
    if (Settings::getInstance()->getAutoShield() && Settings::isTAddress(tx.fromAddr)
            && sproutRecipient && !sproutChangeWarned) {
        sproutChangeWarned = true;
        QMessageBox::information(this, tr("Change cannot be shielded for this send"),
            tr("Because a recipient is a legacy Sprout (zc...) z-address, this wallet "
               "cannot route the transparent change to a shielded Sapling address on the "
               "same transaction (the network forbids mixing Sprout and Sapling). Any "
               "change from this send will remain on a PUBLIC transparent address.\n\n"
               "To keep everything private, send to a Sapling (zs...) recipient instead, "
               "or migrate your Sprout funds to Sapling first."),
            QMessageBox::Ok);
    }

    // PRIV-10 / PRIV-19 / PRIV-28 — auto-shield, FAIL CLOSED on privacy. With
    // auto-shield ON and a transparent from-addr, any change MUST be routed to a
    // Sapling z-address, never left on a PUBLIC t-address.
    //
    // The change amount is computed in INTEGER ZATOSHIS against the exact set of UTXOs
    // z_sendmany will actually spend. Three daemon facts drive this (verified against
    // the running daemon and its source); getting any of them wrong is what made the
    // old double-arithmetic, coinbase-blind change either bounce with "insufficient
    // funds" or leak a public transparent-change output:
    //   1. z_sendmany has NO change-address parameter: taddr change ALWAYS flows to a
    //      fresh keypool t-addr. The only way to shield it is to hand-build an explicit
    //      Sapling output that consumes the spendable inputs EXACTLY (so the daemon's
    //      own residual change is 0). Integer math removes the float drift that
    //      otherwise left a few stray zatoshis as public change.
    //   2. The daemon will NOT spend COINBASE UTXOs in a multi-output / has-change send
    //      (consensus forbids coinbase->transparent; it spends coinbase only to a single
    //      zaddr, whole value consumed). So the eligible set EXCLUDES coinbase, matching
    //      the daemon's find_utxos(false) selection. (On ZClassic mainnet Overwinter is
    //      active, so the daemon's t-input count cap is 0 and the eligible set is spent
    //      in full with no truncation.)
    //   3. z_sendmany spends ONLY confirmed notes (minconf 1), so unconfirmed UTXOs are
    //      excluded -- a change based on getAllBalances() (which sums unconfirmed) would
    //      be unfundable.
    if (Settings::getInstance()->getAutoShield() && sendChangeToSapling) {
        // Eligible = CONFIRMED, spendable, NON-coinbase (what the daemon spends for a
        // has-change send). The coinbase-inclusive total is the affordability ceiling:
        // the daemon CAN spend coinbase, but only to a single zaddr with full
        // consumption (no change), so it is fundable even when not "eligible" for change.
        const qint64 eligibleZat       = confirmedSpendableZat(tx.fromAddr, /*includeCoinbase=*/false);
        const qint64 confirmedTotalZat = confirmedSpendableZat(tx.fromAddr, /*includeCoinbase=*/true);

        qint64 sendZat = 0;
        for (const ToFields& t : tx.toAddrs)        // recipients only -- change not added yet
            sendZat += toZat(t.amount);
        const qint64 targetZat = sendZat + toZat(tx.fee);

        // Not enough CONFIRMED funds (coinbase included) to cover amount+fee. Surface the
        // friendly message UP FRONT and abort rather than letting the daemon reject later.
        if (targetZat > confirmedTotalZat) {
            QMessageBox::critical(this, tr("Transaction Error"),
                tr("Not enough confirmed funds. You're trying to send %1 (including the "
                   "fee), but this address only holds %2 in confirmed, spendable funds. "
                   "Wait for your incoming funds to confirm and try again.")
                   .arg(Settings::getZCLDisplayFormat((double)targetZat / 1e8))
                   .arg(Settings::getZCLDisplayFormat((double)confirmedTotalZat / 1e8)),
                QMessageBox::Ok);
            return Tx();   // invalid: empty fromAddr -> sendButton aborts the send
        }

        // Coinbase-only shortfall: the target fits the CONFIRMED total but NOT the
        // non-coinbase eligible set, so the gap is mined (coinbase) money. A has-change
        // send cannot spend coinbase (consensus: bad-txns-coinbase-spend-has-transparent-
        // outputs), and a partial coinbase spend can't leave change either, so the daemon
        // would reject cryptically. Steer the user to the dedicated shield instead.
        // EXCEPTION: a single Sapling-recipient "shield everything" (target == the whole
        // confirmed total) legitimately consumes coinbase to one zaddr with NO change --
        // that path is allowed and handled by the changeZat<=0 branch below.
        if (targetZat > eligibleZat
                && !(tx.toAddrs.size() == 1
                     && Settings::getInstance()->isSaplingAddress(tx.toAddrs[0].addr)
                     && targetZat == confirmedTotalZat)) {
            QMessageBox::warning(this, tr("Shield your mined funds first"),
                tr("Part of this address's balance is newly mined (coinbase) coins, which "
                   "can only be moved by shielding the whole balance to a private address "
                   "first.\n\nUse \"Shield my public funds\" to move them privately, then "
                   "send again."),
                QMessageBox::Ok);
            return Tx();   // invalid: empty fromAddr -> sendButton aborts the send
        }

        // NOTE: z_sendmany does not pin inputs, so the no-leak reasoning below is sized
        // against the UTXO snapshot polled HERE. The pre-send gate verifyAutoShieldUnchanged()
        // re-polls and ABORTS if this exact eligible set changes before the deferred send, so
        // a t-UTXO confirming during the confirm dwell can no longer turn into public change.
        // That shrinks but does not fully close the TOCTOU (a UTXO can still confirm between
        // the gate's re-poll and the daemon's own selection); the complete fix is daemon-side
        // input pinning.
        const qint64 changeZat = eligibleZat - targetZat;
        if (changeZat > 0) {
            // There is non-coinbase change to shield. Route it to a Sapling z-address;
            // the extra output keeps the send multi-output, so the daemon stays on its
            // non-coinbase selection path and (against the polled snapshot) consumes the
            // eligible set exactly -- residual 0, no public transparent change.
            QString changeAddr = findUnusedSaplingChangeAddr(tx);

            // No existing usable Sapling address -> create one NOW. Blocking RPC, but only
            // on the (rare) first-ever send before any Sapling key exists; the common case
            // is covered by ensureSaplingProvisioned() at first funding.
            if (changeAddr.isEmpty())
                changeAddr = createSaplingAddressSync();

            if (changeAddr.isEmpty()) {
                // Fail CLOSED: with no Sapling change sink the change would otherwise stay
                // PUBLIC. Surface a blocking warning and abort with an invalid Tx.
                QMessageBox::warning(this, tr("Could not shield"),
                    tr("Could not shield — a Sapling change address could not be created, "
                       "so your change would stay PUBLIC. Please try again in a moment."),
                    QMessageBox::Ok);
                return Tx();   // invalid: empty fromAddr -> sendButton aborts the send
            }

            QString changeMemo = tr("Change from ") + tx.fromAddr;
            tx.toAddrs.push_back(ToFields{ changeAddr, (double)changeZat / 1e8,
                                           changeMemo, changeMemo.toUtf8().toHex() });

            // SAFE-RACE: stamp the basis this change was sized against. The pre-send gate
            // (verifyAutoShieldUnchanged) re-polls and ABORTS if eligibleZat no longer
            // matches at send time -- closing the window where a t-UTXO confirms during the
            // confirm dwell and the daemon emits the surplus as public transparent change.
            tx.autoShieldGuardActive = true;
            tx.builtEligibleZat      = eligibleZat;
            tx.builtTargetZat        = targetZat;
        } else if (targetZat == confirmedTotalZat) {
            // Full-consume "shield everything": no change output -- the daemon consumes the
            // WHOLE confirmed balance to the lone recipient (this is the single-Sapling-
            // recipient shield, and the only changeZat<=0 case the band-abort lets through).
            // Still race-prone: the recipient amount is frozen at build, so if ANY UTXO
            // confirms at the from-addr during the dwell the live total exceeds it and the
            // daemon can fund the frozen amount while leaving the surplus as PUBLIC change.
            // Arm the guard to re-verify the live confirmed TOTAL is unchanged before sending.
            tx.autoShieldGuardActive = true;
            tx.autoShieldFullConsume = true;
            tx.builtTargetZat        = targetZat;
        } else {
            // changeZat == 0 with coinbase left idle (targetZat == eligibleZat <
            // confirmedTotalZat). This leg is ONLY ever the exact non-coinbase consume: a
            // changeZat < 0 (targetZat > eligibleZat) that is not the targetZat==confirmedTotal
            // shield was already band-aborted above. The daemon funds the non-coinbase eligible
            // set EXACTLY with ZERO change -- a clean, fundable shielding tx (NOT a reject) --
            // so it is race-prone exactly like the changeZat>0 path: if a non-coinbase t-UTXO
            // confirms at the from-addr during the confirm dwell, the live eligible set grows
            // and the daemon emits the surplus as PUBLIC transparent change. Arm the
            // eligible-set guard so verifyAutoShieldUnchanged() re-polls and aborts fail-closed
            // if the live non-coinbase eligible total moved.
            tx.autoShieldGuardActive = true;
            tx.builtEligibleZat      = eligibleZat;
            tx.builtTargetZat        = targetZat;
        }
    }

    return tx;
}

// Sum, in integer zatoshis, the CONFIRMED (confirmations > 0), spendable UTXOs the GUI
// holds for `addr`. z_sendmany spends only confirmed notes, so this -- not the
// unconfirmed-inclusive getAllBalances() total -- is the correct basis for the auto-shield
// change. With includeCoinbase=false the result also excludes coinbase UTXOs, matching the
// daemon's input set for a has-change (multi-output) send; includeCoinbase=true gives the
// full confirmed-spendable ceiling (the daemon can still spend coinbase, but only to a
// single zaddr with full consumption). Null-safe: returns 0 if the UTXO set isn't loaded.
qint64 MainWindow::confirmedSpendableZat(const QString& addr, bool includeCoinbase) {
    if (!rpc || !rpc->getUTXOs())
        return 0;
    qint64 sum = 0;
    for (const UnspentOutput& u : *rpc->getUTXOs()) {
        if (u.address == addr && u.confirmations > 0 && u.spendable
                && (includeCoinbase || !u.coinbase))
            sum += toZat(u.amount.toDouble());
    }
    return sum;
}

// FAIL-OPEN spendable accessor. The daemon (z_sendmany, minconf=1) spends only
// CONFIRMED, spendable inputs, so the amount the GUI offers / validates for the Available
// line + send-max must be the confirmed-spendable figure -- NOT the minconf=0
// getAllBalances() total, which leaks 0-conf funds and causes the daemon to reject with
// "insufficient funds". BUT the UTXO set is null until the first successful unspent-join
// and publishes nothing on a stream error, so confirmedSpendableZat() would return 0
// there. Failing CLOSED on missing data would wrongly block a legitimate send during
// warmup, so when the UTXO set is unavailable/empty we fall back to today's behavior
// (getAllBalances()->value(addr)) and let the daemon stay the final source of truth.
// MERGE NOTE: rewired onto PR#15's integer-zatoshi confirmedSpendableZat (the old double
// confirmedSpendableBalance is gone). Kept COINBASE-INCLUSIVE to preserve the prior
// display/max behavior (and so the "Shield my funds" button still offers mined coins);
// the coinbase-aware change correctness for an auto-shield send is enforced inside
// createTxFromSendPage()/verifyAutoShieldUnchanged(), not here. Money-safety: never asserts
// a higher spendable amount than the daemon will spend, and never blocks a good send.
double MainWindow::spendableOrFallback(const QString& addr) {
    bool haveUtxoData = rpc && rpc->getUTXOs() && !rpc->getUTXOs()->isEmpty();
    if (haveUtxoData)
        return (double)confirmedSpendableZat(addr, /*includeCoinbase=*/true) / 1e8;
    double fallback = 0.0;
    if (rpc && rpc->getAllBalances())
        fallback = rpc->getAllBalances()->value(addr);
    return fallback;
}

// SAFE-RACE: synchronously re-poll the from-addr's transparent UTXOs so the cached set
// confirmedSpendableZat() reads reflects the daemon's LIVE selection at send time. Mirrors
// createSaplingAddressSync()'s pattern exactly: a reentrancy guard with RAII clear, and a
// bounded ExcludeUserInputEvents pump gated on an existing connection (so it cannot wedge a
// send against a dead daemon). Returns Refreshed only when fresh data actually landed;
// NoConnection / Timeout are treated by the caller as "cannot verify" -> fail closed.
MainWindow::RepollResult MainWindow::repollFromAddrUtxos() {
    if (!rpc)                       return RepollResult::NoConnection;
    if (autoShieldRepollInFlight)   return RepollResult::NoConnection;   // refuse to nest
    autoShieldRepollInFlight = true;
    struct ClearGuard { bool* f; ~ClearGuard() { *f = false; } } _clr{ &autoShieldRepollInFlight };

    // `done` is a shared_ptr, NOT a stack bool captured by reference: the production
    // listunspent reply is an async Qt slot that is NOT cancelled if our bounded pump times
    // out. A by-ref capture would let that late reply write into this frame's destroyed stack
    // (use-after-free). The shared_ptr keeps the flag alive for the late writer; on timeout we
    // simply ignore it (the send aborts fail-closed) and the heap flag is freed when the last
    // owner -- the outstanding callback -- runs.
    auto done = std::make_shared<bool>(false);
    // Fire the re-poll. In production this returns immediately (the listunspent reply lands
    // during the pump below); in the L1 test build the injected set is applied synchronously
    // (*done==true before the loop). false => could not fire (no connection / no test seam).
    if (!rpc->repollTransparentUnspent([done](bool ok){ *done = ok; }))
        return RepollResult::NoConnection;

    QElapsedTimer t; t.start();
    while (!*done && rpc->getConnection() && t.elapsed() < 8000)
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 50);

    if (*done)
        return RepollResult::Refreshed;
    return rpc->getConnection() ? RepollResult::Timeout : RepollResult::NoConnection;
}

// SAFE-RACE gate: the LAST check before the irrevocable z_sendmany. For any non-auto-shield
// send the stamp is inactive -> returns true immediately (today's behavior, no re-poll). For
// an auto-shield-change send it re-polls the from-addr and ABORTS fail-closed on ANY change
// to the eligible non-coinbase total, so a surplus that confirmed during the confirm dwell
// can never escape as PUBLIC transparent change. This shrinks the TOCTOU window from tens of
// seconds (poll staleness + dwell) to one RPC round-trip; fully closing it needs daemon-side
// input pinning (z_sendmany with a fixed input set), which is a separate, daemon-side change.
bool MainWindow::verifyAutoShieldUnchanged(const Tx& tx) {
    if (!tx.autoShieldGuardActive)
        return true;                                   // no-op for non-auto-shield sends

    const RepollResult r = repollFromAddrUtxos();
    if (r != RepollResult::Refreshed) {                // could not verify -> FAIL CLOSED
        QMessageBox::warning(this, tr("Could not verify balance"),
            tr("Your balance could not be re-checked before sending, so for your privacy "
               "the transaction was NOT sent. Please try again in a moment."),
            QMessageBox::Ok);
        return false;
    }

    // Full-consume (no change) send: safe only while the live confirmed TOTAL still equals
    // exactly what we sized the spend against. Any new confirmation grows the total beyond
    // the frozen amount -> the daemon can fund the amount and leave the surplus as PUBLIC
    // change -> abort. (A coinbase-inclusive total is the right basis: the daemon draws the
    // whole balance to the single z-recipient.)
    if (tx.autoShieldFullConsume) {
        if (confirmedSpendableZat(tx.fromAddr, /*includeCoinbase=*/true) == tx.builtTargetZat)
            return true;                               // still an exact full consume -> SAFE
        QMessageBox::warning(this, tr("Balance changed — not sent"),
            tr("Your balance for this address changed while you were confirming. For your "
               "privacy the transaction was NOT sent. Please review the amounts and send again."),
            QMessageBox::Ok);
        return false;
    }

    const qint64 liveEligibleZat = confirmedSpendableZat(tx.fromAddr, /*includeCoinbase=*/false);
    if (liveEligibleZat == tx.builtEligibleZat)
        return true;                                   // verified identical -> SAFE to send

    // The eligible non-coinbase set moved during the dwell. A GROWN set would let the daemon
    // emit the surplus as PUBLIC change; a SHRUNK set would make it reject. Either way the
    // stale change must NOT be sent. When the shortfall is purely mined (coinbase) funds,
    // steer the user to the dedicated shield; otherwise show the generic notice.
    const qint64 liveTotalZat = confirmedSpendableZat(tx.fromAddr, /*includeCoinbase=*/true);
    if (tx.builtTargetZat <= liveTotalZat && tx.builtTargetZat > liveEligibleZat) {
        QMessageBox::warning(this, tr("Shield your mined funds first"),
            tr("Part of this address's balance is newly mined (coinbase) coins, which can "
               "only be moved by shielding the whole balance to a private address first. For "
               "your privacy the transaction was NOT sent.\n\nUse \"Shield my public funds\" "
               "to move them privately, then send again."),
            QMessageBox::Ok);
        return false;
    }

    QMessageBox::warning(this, tr("Balance changed — not sent"),
        tr("Your balance for this address changed while you were confirming. For your "
           "privacy the transaction was NOT sent. Please review the amounts and send again."),
        QMessageBox::Ok);
    return false;
}

// Find an existing Sapling z-address usable as the change sink: it must be a real
// Sapling address AND not collide with any recipient (zclassic rejects a duplicate
// output address). Returns "" if none exists. Factored out of createTxFromSendPage
// so the fail-open create path is a clean single branch.
QString MainWindow::findUnusedSaplingChangeAddr(const Tx& tx) {
    if (!rpc || !rpc->getAllZAddresses())
        return QString();
    for (const QString& a : *rpc->getAllZAddresses()) {
        if (!Settings::getInstance()->isSaplingAddress(a))
            continue;
        bool collides = false;
        for (const auto& t : tx.toAddrs)
            if (t.addr == a) { collides = true; break; }
        if (!collides)
            return a;
    }
    return QString();
}

// PRIV-10 fail-open last resort: synchronously create a fresh Sapling z-address via
// the daemon and return it. Blocks the GUI thread briefly; only reached when NO
// Sapling address exists at send time (the eager ensureSaplingProvisioned() path
// normally pre-creates one at first funding). Returns "" if creation fails (so the
// caller degrades gracefully rather than crashing) -- but NEVER returns a non-Sapling
// address, so change is never routed to Sprout/transparent.
QString MainWindow::createSaplingAddressSync() {
    if (!rpc)
        return QString();

    // MINOR-3 reentrancy guard: the event-loop pump below keeps the app live, so a
    // second sendButton click (or any code path) could re-enter this blocking
    // create. Refuse to nest -- a single in-flight create at a time.
    if (saplingSyncCreateInFlight)
        return QString();
    saplingSyncCreateInFlight = true;
    // RAII-clear on every return path (early-outs below included).
    struct ClearGuard { bool* f; ~ClearGuard() { *f = false; } } _clr{ &saplingSyncCreateInFlight };

    QString created;
    rpc->newZaddr(true, [&](json reply) {
        if (reply.is_string())
            created = QString::fromStdString(reply.get<json::string_t>());
    });

    // newZaddr is async on the network thread; pump the event loop briefly so the
    // reply lands before we return. Bounded so a dead daemon can never wedge a send.
    // ExcludeUserInputEvents (MINOR-3): suppress mouse/key delivery during the pump
    // so a second sendButton click can't be processed mid-create. We only pump while
    // a connection actually exists -- with no daemon connection the async create can
    // never complete, so pumping would just spin to the timeout for nothing (and the
    // caller will fail CLOSED on the empty result).
    // UITB-1: cap the GUI-thread pump at 3000ms (was 8000ms) so a wedged or warming
    // daemon can never freeze the window for 8s. The caller already fails CLOSED with
    // a 'try again in a moment' QMessageBox on an empty result (sendtab.cpp ~601,
    // mainwindow.cpp ~1106), so a shorter cap just routes to that message sooner.
    QElapsedTimer t; t.start();
    while (created.isEmpty() && rpc->getConnection() && t.elapsed() < 3000) {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 50);
    }

    if (!created.isEmpty()) {
        // Make the new address available to the rest of the wallet immediately. Only
        // when a connection exists -- a successful create implies one; calling
        // refreshAddresses() with no connection just bounces to noConnection() (which
        // tears down the live UI state), so skip it on that impossible-in-prod path.
        if (rpc->getConnection())
            rpc->refreshAddresses();
        // Defensive: only ever return a real Sapling address (never degrade).
        if (!Settings::getInstance()->isSaplingAddress(created))
            return QString();
    }
    return created;
}

bool MainWindow::confirmTx(Tx tx) {
    auto fnSplitAddressForWrap = [=] (const QString& a) -> QString {
        if (!a.startsWith("z")) return a;

        auto half = a.length() / 2;
        auto splitted = a.left(half) + "\n" + a.right(a.length() - half);
        return splitted;
    };


    // Show a confirmation dialog
    QDialog d(this);
    Ui_confirm confirm;
    confirm.setupUi(&d);

    // Remove all existing address/amt qlabels on the confirm dialog.
    int totalConfirmAddrItems = confirm.sendToAddrs->children().size();
    for (int i = 0; i < totalConfirmAddrItems / 3; i++) {
        auto addr   = confirm.sendToAddrs->findChild<QLabel*>(QString("Addr")   % QString::number(i+1));
        auto amt    = confirm.sendToAddrs->findChild<QLabel*>(QString("Amt")    % QString::number(i+1));
        auto memo   = confirm.sendToAddrs->findChild<QLabel*>(QString("Memo")   % QString::number(i+1));
        auto amtUSD = confirm.sendToAddrs->findChild<QLabel*>(QString("AmtUSD") % QString::number(i+1));
        auto spacer = confirm.sendToAddrs->findChild<QLabel*>(QString("spacer") % QString::number(i+1));

        delete memo;
        delete addr;
        delete amt;
        delete amtUSD;
        delete spacer;
    }

    // Remove the fee labels
    delete confirm.sendToAddrs->findChild<QLabel*>("labelMinerFee");
    delete confirm.sendToAddrs->findChild<QLabel*>("minerFee");
    delete confirm.sendToAddrs->findChild<QLabel*>("minerFeeUSD");
    
    // PRIV-11 / UX-12 — four-way, from-aware privacy classification. The legacy
    // binary isPublicTx is gone; the category drives BOTH the publicWarning copy and
    // the dialog title/badge below, and (PRIV-12) whether the z->t acknowledgement
    // gate fires before the send.
    const SendCategory category = classifySend(tx);

    // For each addr/amt/memo, construct the JSON and also build the confirm dialog box
    int row = 0;
    double totalSpending = 0;

    // NIT-2 — recognize the auto-shield CHANGE output so we can label it as such in
    // the confirm dialog (rather than showing a bare zs... recipient that looks like
    // an unexpected payee). The change row is the Sapling output whose memo is the
    // change memo createTxFromSendPage() stamped: tr("Change from ") + fromAddr.
    const QString changeMemoMarker = tr("Change from ") + tx.fromAddr;

    for (int i=0; i < tx.toAddrs.size(); i++) {
        auto toAddr = tx.toAddrs[i];

        const bool isAutoShieldChange =
            Settings::getInstance()->getAutoShield()
            && Settings::isTAddress(tx.fromAddr)
            && Settings::getInstance()->isSaplingAddress(toAddr.addr)
            && toAddr.txtMemo == changeMemoMarker;

        // Add new Address widgets instead of the same one.
        {
            // Address
            auto Addr = new QLabel(confirm.sendToAddrs);
            Addr->setObjectName(QString("Addr") % QString::number(i + 1));
            Addr->setWordWrap(true);
            // NIT-2: a clear, reassuring label for the auto-shielded change row.
            if (isAutoShieldChange)
                Addr->setText(tr("Change (auto-shielded to your wallet)"));
            else
                Addr->setText(fnSplitAddressForWrap(toAddr.addr));
            confirm.gridLayout->addWidget(Addr, row, 0, 1, 1);

            // Amount (ZCL)
            auto Amt = new QLabel(confirm.sendToAddrs);
            Amt->setObjectName(QString("Amt") % QString::number(i + 1));
            Amt->setText(Settings::getZCLDisplayFormat(toAddr.amount));
            Amt->setAlignment(Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
            confirm.gridLayout->addWidget(Amt, row, 1, 1, 1);
            totalSpending += toAddr.amount;

            // Amount (USD)
            auto AmtUSD = new QLabel(confirm.sendToAddrs);
            AmtUSD->setObjectName(QString("AmtUSD") % QString::number(i + 1));
            AmtUSD->setText(Settings::getUSDFormat(toAddr.amount));
            AmtUSD->setAlignment(Qt::AlignRight | Qt::AlignTrailing | Qt::AlignVCenter);
            confirm.gridLayout->addWidget(AmtUSD, row, 2, 1, 1);            

            // Memo (suppressed for the auto-shield change row -- its Addr label
            // already says "Change (auto-shielded to your wallet)"; NIT-2).
            if (!isAutoShieldChange && toAddr.addr.startsWith("z") && !toAddr.txtMemo.isEmpty()) {
                row++;
                auto Memo = new QLabel(confirm.sendToAddrs);
                Memo->setObjectName(QStringLiteral("Memo") % QString::number(i + 1));
                Memo->setText(toAddr.txtMemo);
                QFont font1 = Addr->font();
                font1.setPointSize(font1.pointSize() - 1);
                Memo->setFont(font1);
                Memo->setWordWrap(true);

                confirm.gridLayout->addWidget(Memo, row, 0, 1, 3);
            }

            row ++;

            // Add an empty spacer to create a blank space
            auto spacer = new QLabel(confirm.sendToAddrs);
            spacer->setObjectName(QString("spacer") % QString::number(i + 1));
            confirm.gridLayout->addWidget(spacer, row, 0, 1, 1);

            row++;
        }
    }

    // Add fees
    {
        auto labelMinerFee = new QLabel(confirm.sendToAddrs);
        labelMinerFee->setObjectName(QStringLiteral("labelMinerFee"));
        confirm.gridLayout->addWidget(labelMinerFee, row, 0, 1, 1);
        labelMinerFee->setText(tr("Miner Fee"));

        auto minerFee = new QLabel(confirm.sendToAddrs);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        minerFee->setSizePolicy(sizePolicy);
        minerFee->setObjectName(QStringLiteral("minerFee"));
        minerFee->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        confirm.gridLayout->addWidget(minerFee, row, 1, 1, 1);
        minerFee->setText(Settings::getZCLDisplayFormat(tx.fee));
        totalSpending += tx.fee;

        auto minerFeeUSD = new QLabel(confirm.sendToAddrs);
        QSizePolicy sizePolicy1(QSizePolicy::Minimum, QSizePolicy::Preferred);
        minerFeeUSD->setSizePolicy(sizePolicy1);
        minerFeeUSD->setObjectName(QStringLiteral("minerFeeUSD"));
        minerFeeUSD->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        confirm.gridLayout->addWidget(minerFeeUSD, row, 2, 1, 1);
        minerFeeUSD->setText(Settings::getUSDFormat(tx.fee));

        if (Settings::getInstance()->getAllowCustomFees() && tx.fee != Settings::getMinerFee()) {
            confirm.warningLabel->setVisible(true);            
        } else {
            // Default fee
            confirm.warningLabel->setVisible(false);
        }
    }

    // Syncing warning
    confirm.syncingWarning->setVisible(Settings::getInstance()->isSyncing());

    // No peers warning
    confirm.nopeersWarning->setVisible(Settings::getInstance()->getPeers() == 0);

    // PRIV-11 / UX-12 — drive the confirm dialog wording + a privacy badge from the
    // four-way category. Tokens mirror dark.qss / PrivacyBadgeDelegate:
    //   green #1f7a1f  amber #d9822b  red #c0392b
    // A small badge QLabel ("confirmPrivacyBadge") is created once and reused; the
    // existing red publicWarning label carries the long-form copy and is only shown
    // for the two public quadrants (z->t de-shield = strongest; t->t = public).
    {
        QString badgeText, badgeColor, dialogTitle, warningText;
        // NIT-3: the reused publicWarning label is tinted per category token instead
        // of the .ui's static "color: red;" -- amber for plain public, red (strongest)
        // for the de-shield leak. Mirrors dark.qss / PrivacyBadgeDelegate tokens.
        QString warningColor;
        bool    showWarning = false;

        switch (category) {
        case SendCategory::ZToZ_private:
            badgeText   = tr("PRIVATE  z → z");
            badgeColor  = "#1f7a1f";                       // green
            dialogTitle = tr("Confirm private transaction");
            break;
        case SendCategory::TToZ_shielding:
            badgeText   = tr("SHIELDING  t → z");
            badgeColor  = "#e6e6e6";                       // neutral text
            dialogTitle = tr("Confirm shielding transaction");
            break;
        case SendCategory::ZToT_deshield:
            badgeText    = tr("DE-SHIELD  z → t");
            badgeColor   = "#c0392b";                      // red (strongest)
            warningColor = "#c0392b";                      // red de-shield warning
            dialogTitle  = tr("Confirm DE-SHIELD (public) transaction");
            warningText  = tr("DE-SHIELD: you are moving funds from a PRIVATE (shielded) "
                             "address to a PUBLIC transparent address. The amount, the "
                             "recipient, AND the link back to your shielded sender become "
                             "permanently visible to everyone on the blockchain.");
            showWarning = true;
            break;
        case SendCategory::TToT_public:
            badgeText    = tr("PUBLIC  t → t");
            badgeColor   = "#d9822b";                      // amber
            warningColor = "#d9822b";                      // amber public warning
            dialogTitle  = tr("Confirm public transaction");
            warningText  = tr("This transaction is PUBLIC: the amount and recipient will "
                             "be permanently visible to everyone on the blockchain.");
            showWarning = true;
            break;
        }

        d.setWindowTitle(dialogTitle);

        // The privacy badge: created once on the From group's layout so it sits at
        // the very top of the dialog. objectName is stable so the L1 test can read it.
        auto* badge = d.findChild<QLabel*>("confirmPrivacyBadge");
        if (!badge) {
            badge = new QLabel(confirm.groupBox);
            badge->setObjectName("confirmPrivacyBadge");
            confirm.verticalLayout_2->insertWidget(0, badge);
        }
        badge->setText(badgeText);
        badge->setStyleSheet(QString("font-weight: 700; color: %1;").arg(badgeColor));

        // The long-form warning copy (publicWarning): shown for the two public
        // quadrants only, with category-specific text + token color (NIT-3).
        if (showWarning) {
            confirm.publicWarning->setText(warningText);
            confirm.publicWarning->setStyleSheet(
                QString("color: %1; font-weight: 600;").arg(warningColor));
        }
        confirm.publicWarning->setVisible(showWarning);
    }

    // And FromAddress in the confirm dialog
    confirm.sendFrom->setText(fnSplitAddressForWrap(tx.fromAddr));
    QString tooltip = tr("Current balance      : ") +
        Settings::getZCLUSDDisplayFormat(rpc->getAllBalances()->value(tx.fromAddr));
    tooltip += "\n" + tr("Balance after this Tx: ") +
        Settings::getZCLUSDDisplayFormat(rpc->getAllBalances()->value(tx.fromAddr) - totalSpending);
    confirm.sendFrom->setToolTip(tooltip);

    // Show the dialog and submit it if the user confirms
    if (d.exec() == QDialog::Accepted) {
        // PRIV-12 — a z->t DE-SHIELD send requires an explicit, non-default-accept
        // acknowledgement before it proceeds. The other three categories
        // (z->z private, t->z shielding, t->t public) MUST NOT add this friction.
        // Default button is No, so a careless Enter does not de-shield.
        if (category == SendCategory::ZToT_deshield) {
            // Explicit QMessageBox instance (objectName "deshieldAck") rather than the
            // blocking static, so the acknowledgement is reliably testable and the
            // default button is the SAFE No (a careless Enter does not de-shield).
            QMessageBox ack(QMessageBox::Warning, tr("De-shield to a public address?"),
                tr("This send moves funds OUT of your private (shielded) balance onto a "
                   "PUBLIC transparent address. The amount, the recipient, and the link "
                   "back to your shielded sender will be permanently visible on the "
                   "blockchain.\n\nThis cannot be undone. De-shield anyway?"),
                QMessageBox::Yes | QMessageBox::No, this);
            ack.setObjectName("deshieldAck");
            ack.setDefaultButton(QMessageBox::No);
            if (ack.exec() != QMessageBox::Yes)
                return false;
        }

        // NB: the send-page fields are cleared by sendButton() only AFTER the pre-send
        // SAFE-RACE gate passes, so an abort there preserves the user's typed recipients
        // for a one-click resend.
        return true;
    } else {
        return false;
    }
}

// Send button clicked
void MainWindow::sendButton() {
    Tx tx = createTxFromSendPage();

    // MAJOR-1/MAJOR-2 fail-closed abort: createTxFromSendPage() returns an INVALID
    // Tx (empty fromAddr) when it has already surfaced a blocking reason -- the
    // change could not be shielded (privacy fail-closed), or there are not enough
    // confirmed funds. Bail silently here so we don't stack a second, vaguer
    // "From Address is Invalid" error on top of the precise one already shown.
    if (tx.fromAddr.isEmpty())
        return;

    // Still-syncing acknowledgement gate: during sync the balance/UTXO set is
    // incomplete, so a send can silently fail. Make the user explicitly accept
    // that risk (default No) instead of relying only on the soft confirm label.
    if (Settings::getInstance()->isSyncing()) {
        const qint64 now  = QDateTime::currentSecsSinceEpoch();
        const qint64 last = Settings::getInstance()->getLastSyncPollEpoch();
        const bool   stale = Settings::syncGateIsStale(now, last);
        // Distinguish the user's OWN import/rescan (homeImportCard visible) from a
        // network catch-up, and soften when the flag looks stale (no live poll refreshed
        // it recently) — but keep it a SOFT Yes/No warning (default No) so even a wedged
        // flag can never hard-block a send.
        const bool importBusy = (homeImportCard != nullptr && homeImportCard->isVisible());
        QString title = tr("Wallet still syncing");
        QString body;
        if (importBusy) {
            title = tr("Still importing your keys");
            body  = tr("Your wallet is still importing and rescanning, so your balance "
                       "may be incomplete and this transaction could fail.\n\nSend anyway?");
        } else if (stale) {
            body  = tr("Your wallet hasn't reported sync progress recently. Your balance "
                       "may be up to date, or syncing may have paused.\n\nSend anyway?");
        } else {
            body  = tr("Your wallet is still catching up with the network, so your balance "
                       "may be incomplete and this transaction could fail.\n\nSend anyway?");
        }
        auto res = QMessageBox::warning(this, title, body,
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (res != QMessageBox::Yes)
            return;
    }

    QString error = doSendTxValidations(tx);
    if (!error.isEmpty()) {
        // Something went wrong, so show an error and exit
        QMessageBox msg(QMessageBox::Critical, tr("Transaction Error"), error,
                        QMessageBox::Ok, this);

        msg.exec();

        // abort the Tx
        return;
    }
    
    // Show a dialog to confirm the Tx
    if (confirmTx(tx)) {
        // SAFE-RACE: re-poll + verify the from-addr's live eligible set immediately before
        // the irrevocable z_sendmany. Fail-closed: on any divergence (or inability to
        // verify) abort WITHOUT clearing the user's recipients, so they can review/resend.
        if (!verifyAutoShieldUnchanged(tx))
            return;

        // Commit: clear the send page now that the Tx is actually being dispatched.
        removeExtraAddresses();

        // And send the Tx
        rpc->executeTransaction(tx,
            [=] (QString opid) {
                ui->statusBar->showMessage(tr("Computing Tx: ") % opid);
            },
            [=] (QString, QString txid) {
                // Keep the long-standing status-bar line so the right-click
                // "Copy txid"/"View on explorer" status-bar menu keeps working,
                // then surface the calm, non-blocking "you did it" affirmation.
                ui->statusBar->showMessage(Settings::txidStatusMessage + " " + txid);
                showSendSuccess(txid);
            },
            [=] (QString opid, QString errStr) {
                ui->statusBar->showMessage(QObject::tr("Transaction couldn't be sent"), 15 * 1000);

                // Humane failure: a plain, actionable headline (no opid noise),
                // raw daemon text tucked under the native "Show Details" expander.
                // Warning (not Critical) -- a declined send isn't a crash.
                QMessageBox msg(QMessageBox::Warning, QObject::tr("Couldn't send"),
                                humaneSendError(errStr), QMessageBox::Ok, this);
                QString details = errStr;
                if (!opid.isEmpty())
                    details = QObject::tr("Operation id: ") % opid % "\n\n" + details;
                msg.setDetailedText(details);
                msg.exec();
            }
        );
    }        
}

QString MainWindow::doSendTxValidations(Tx tx) {
    if (!Settings::isValidAddress(tx.fromAddr)) return QString(tr("From Address is Invalid"));    

    for (auto toAddr : tx.toAddrs) {
        if (!Settings::isValidAddress(toAddr.addr)) {
            QString addr = (toAddr.addr.length() > 100 ? toAddr.addr.left(100) + "..." : toAddr.addr);
            return QString(tr("Recipient Address ")) % addr % tr(" is Invalid");
        }

        // This technically shouldn't be possible, but issue #62 seems to have discovered a bug
        // somewhere, so just add a check to make sure.
        if (toAddr.amount < 0) {
            return QString(tr("Amount '%1' is invalid!").arg(toAddr.amount));
        }

        // ZERO-AMOUNT FIX: a blank/zero amount (the validator accepts an empty field, which
        // reads as 0.0) used to pass ALL client checks and walk the user through the confirm
        // dialog before z_sendmany rejected it. Catch it here with a clear message instead.
        if (toAddr.amount == 0) {
            return tr("Enter an amount greater than 0 for each recipient.");
        }
    }

    // Insufficient-funds guard: catch an overspend up front with a friendly
    // message instead of letting it fail minutes later with a cryptic node
    // error. Only enforced when the balance is reliable (not mid-sync), and
    // null-guarded since balances may not be loaded yet during early startup.
    if (!Settings::getInstance()->isSyncing()) {
        auto bals = rpc ? rpc->getAllBalances() : nullptr;
        if (bals && bals->contains(tx.fromAddr)) {
            // Compare in INTEGER ZATOSHIS, never double. A "send max" / shield makes
            // total == amount+fee land a fraction-of-a-zatoshi ABOVE the balance in IEEE-754
            // (e.g. 0.1199 + 0.0001 -> 0.120000000002 vs a 0.12 balance -> 0.119999999996),
            // which false-aborts "Not enough funds" with BOTH sides displaying "0.12" -- the
            // exact dead-end the user hit. Rounding each value to the nearest zatoshi removes
            // the drift (the spendableOrFallback -> confirmedSpendableZat rewire fixed the
            // auto-shield block but NOT this generic guard).
            const qint64 displayedZat = toZat(bals->value(tx.fromAddr));    // minconf=0 total
            const qint64 confirmedZat = toZat(spendableOrFallback(tx.fromAddr));
            qint64 totalZat = toZat(tx.fee);
            for (auto toAddr : tx.toAddrs)
                totalZat += toZat(toAddr.amount);

            // Three-way guard so the user is never dead-ended:
            //  1) confirmed >= total            -> PASS (proceed exactly as today). NEVER
            //                                       block a send the daemon would accept.
            //  2) confirmed < total <= displayed -> they DO own the funds, some are just
            //                                       still confirming. Show a calm, honest
            //                                       message instead of a scary "insufficient".
            //  3) total > displayed             -> they genuinely don't have it: keep
            //                                       today's "only holds %2" message.
            // The daemon's own insufficient-funds rejection (mapped by humaneSendError)
            // remains the final backstop; this is just an EARLIER, friendlier check.
            if (confirmedZat >= totalZat) {
                // ok -- fall through, do not block
            }
            else if (displayedZat >= totalZat) {
                const qint64 stillZat = (totalZat > confirmedZat) ? (totalZat - confirmedZat) : 0;
                return tr("%1 of these funds is still confirming (about a few minutes). "
                          "You can shield or send it as soon as it confirms.")
                       .arg(Settings::getZCLDisplayFormat((double)stillZat / 1e8));
            }
            else {
                return tr("Not enough funds. You're trying to send %1 (including the fee), "
                          "but this address only holds %2.")
                       .arg(Settings::getZCLDisplayFormat((double)totalZat / 1e8))
                       .arg(Settings::getZCLDisplayFormat((double)displayedZat / 1e8));
            }
        }
    }

    return QString();
}

void MainWindow::cancelButton() {
    // Forgiving: don't silently destroy typed work. If the user has started a payment
    // (a recipient or amount is entered), confirm before clearing the form. An empty
    // form clears silently. removeExtraAddresses() itself is unchanged.
    auto* addr = ui->sendToWidgets->findChild<QLineEdit*>("Address1");
    auto* amt  = ui->sendToWidgets->findChild<QLineEdit*>("Amount1");
    bool hasInput = (addr && !addr->text().trimmed().isEmpty())
                 || (amt  && !amt->text().trimmed().isEmpty());
    if (hasInput) {
        auto r = QMessageBox::question(this, tr("Discard this payment?"),
            tr("Your typed recipients and amounts will be cleared."),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (r != QMessageBox::Yes)
            return;
    }
    removeExtraAddresses();
}

// PRESENTATION-ONLY: drive the live private/public verdict badge above the Send form
// from the wallet's own daemon-free classifier (sendCategoryOf, sendcategory.h). It
// builds a lightweight ECHO Tx from the on-screen From + recipient addresses and reads
// the category — it never sends, never touches the spendable/zatoshi math, and the
// classifier errs toward the stronger public/de-shield verdict on an unparseable
// address, so it can only over-warn, never under-warn.
void MainWindow::updateSendPrivacyBadge() {
    auto* badge = ui->sendPrivacyBadge;
    if (!badge) return;

    // Gather resolved recipient addresses currently on screen.
    Tx tx;
    tx.fromAddr = ui->inputsCombo->currentText();
    bool anyRecipient = false;
    QRegExp re("Address[0-9]+", Qt::CaseInsensitive);
    for (auto* fld : ui->sendToWidgets->findChildren<QLineEdit*>(re)) {
        QString a = AddressBook::addressFromAddressLabel(fld->text().trimmed());
        if (a.isEmpty()) continue;
        anyRecipient = true;
        ToFields t; t.addr = a; t.amount = 0; tx.toAddrs.push_back(t);
    }

    QString text, tone;
    if (!anyRecipient || tx.fromAddr.isEmpty()) {
        text = tr("Set who you are paying to see if this send is private");
        tone = QString();   // neutral
    } else {
        switch (sendCategoryOf(tx)) {
        case SendCategory::ZToZ_private:
            text = tr("● Private — only you and the recipient can see this"); tone = "private"; break;
        case SendCategory::TToZ_shielding:
            text = tr("● Shielding — this becomes private"); tone = "private"; break;
        case SendCategory::TToT_public:
            text = tr("● Public — the amount and recipient are visible to everyone"); tone = "public"; break;
        case SendCategory::ZToT_deshield:
            text = tr("● De-shield — this leaves your private balance and becomes public forever"); tone = "deshield"; break;
        }
    }
    badge->setText(text);
    badge->setProperty("badge", tone.isEmpty() ? QVariant() : QVariant("true"));
    badge->setProperty("tone", tone.isEmpty() ? QVariant() : QVariant(tone));
    badge->style()->unpolish(badge);
    badge->style()->polish(badge);
}

// PRESENTATION-ONLY: the running "You will send X + fee Y = Z" line under the fee row.
// It only AGGREGATES values already on screen (the same read-only findChild loop the
// max math uses) — it writes nothing, computes no spendable/zatoshi math, and the
// authoritative total still comes from confirmTx. Hidden until an amount is entered.
void MainWindow::updateSendTotals() {
    auto* line = ui->sendTotalsLine;
    if (!line) return;

    double sum = 0; bool any = false;
    QRegExp re("Amount[0-9]+", Qt::CaseInsensitive);
    for (auto* fld : ui->sendToWidgets->findChildren<QLineEdit*>(re)) {
        QString t = fld->text().trimmed();
        if (t.isEmpty()) continue;
        double v = t.toDouble();
        if (v > 0) { sum += v; any = true; }
    }
    if (!any) { line->clear(); return; }

    double fee = ui->minerFeeAmt->text().trimmed().toDouble();
    double total = sum + fee;
    QString usd = Settings::getUSDFormat(total);
    QString msg = tr("You'll send %1 + %2 fee = %3 ZCL")
                    .arg(Settings::getZCLDisplayFormat(sum))
                    .arg(Settings::getZCLDisplayFormat(fee))
                    .arg(Settings::getZCLDisplayFormat(total));
    if (!usd.isEmpty())
        msg = msg % "  (~" % usd % ")";
    line->setText(msg);
}

// Item 2: calm, NON-blocking "you did it" affirmation shown once a send confirms.
// Parented to `this` with WA_DeleteOnClose + show() (not exec()) so it never blocks
// the UI and Qt owns its lifetime (auto-destroyed if the window closes) -- UAF-safe.
void MainWindow::showSendSuccess(QString txid) {
    auto box = new QMessageBox(this);
    box->setAttribute(Qt::WA_DeleteOnClose);
    box->setWindowModality(Qt::NonModal);
    box->setIcon(QMessageBox::Information);
    box->setWindowTitle(tr("Sent! Your ZCL is on its way"));
    box->setText(tr("Sent! Your ZCL is on its way"));
    box->setInformativeText(tr("Your transaction was accepted by the network. "
                               "It will appear in your transactions in a few minutes."));
    box->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);

    // One-click Copy txid (clipboard idiom matches addressbook.cpp / mainwindow.cpp),
    // plus a brief status-bar echo so the user sees it took.
    QPushButton* copyBtn = box->addButton(tr("Copy txid"), QMessageBox::ActionRole);
    QObject::connect(copyBtn, &QPushButton::clicked, this, [this, txid]() {
        QGuiApplication::clipboard()->setText(txid);
        ui->statusBar->showMessage(tr("Copied to clipboard"), 3 * 1000);
    });

    // View on explorer -- only when there's a live explorer (empty on testnet).
    QString url = Settings::getExplorerTxURL(txid);
    if (!url.isEmpty()) {
        QPushButton* viewBtn = box->addButton(tr("View on explorer"), QMessageBox::ActionRole);
        QObject::connect(viewBtn, &QPushButton::clicked, this, [url]() {
            QDesktopServices::openUrl(QUrl(url));
        });
    }

    box->addButton(tr("Close"), QMessageBox::AcceptRole);
    box->show();
}

// Item 2: map common z_sendmany daemon error substrings to plain, actionable copy.
// The raw daemon text is preserved by the caller under "Show Details" -- this only
// produces the friendly HEADLINE, and never hides the underlying error.
QString MainWindow::humaneSendError(const QString& raw) {
    const QString e = raw.toLower();

    // Order matters: check the most specific causes before the generic ones.
    if (e.contains("coinbase") || e.contains("must be sent to a single z") ||
        e.contains("to a zaddr") || e.contains("shielding coinbase"))
        return tr("Mined (coinbase) ZCL must be sent to exactly one shielded (z) "
                  "address at a time. Send it to a single z-address first, then "
                  "spend normally.");

    if (e.contains("no utxo") || e.contains("no unspent"))
        return tr("These coins aren't confirmed yet. Wait a few minutes for the "
                  "network to confirm them, then try again.");

    if (e.contains("insufficient") || e.contains("not enough"))
        return tr("You don't have enough confirmed ZCL to cover this amount plus the "
                  "network fee. Wait for recent deposits to confirm, or send a "
                  "smaller amount.");

    if (e.contains("try again") || e.contains("still syncing") ||
        e.contains("downloading blocks") || e.contains("is downloading") ||
        e.contains("loading block index") || e.contains("rescanning"))
        return tr("Your wallet is still catching up with the network. Let it finish "
                  "syncing, then try sending again.");

    if (e.contains("wallet is locked") || e.contains("walletpassphrase"))
        return tr("Your wallet is locked. Unlock it, then try sending again.");

    if (e.contains("amount out of range") || e.contains("invalid amount") ||
        e.contains("too small") || e.contains("dust"))
        return tr("That amount is too small to send. Try a larger amount.");

    return tr("Your transaction couldn't be sent. The details are below -- you can "
              "try again.");
}

