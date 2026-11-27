// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Settings as a page of its own (opened from the nav rail, Edit > Settings or
// Ctrl+P) instead of a dialog. It reuses the Settings form's own widgets, grouped
// into cards with short explanations, and saves exactly as the dialog's OK did:
// the same Settings calls, zclassic.conf edits, restart notices and reconnect.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "ui_settings.h"
#include "connection.h"
#include "rpc.h"
#include "senttxstore.h"
#include "settings.h"
#include "timeformat.h"

#include <QCheckBox>
#include <QDialog>
#include <QDir>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIntValidator>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QVBoxLayout>

// ---- building the page -------------------------------------------------------------

void MainWindow::buildSettingsPage() {
    settingsPage = new QWidget();
    settingsPage->setObjectName("settingsPage");
    // The form is set up on a hidden host dialog that is never shown; its widgets
    // are moved into the page's cards below.
    settingsHost = new QDialog(settingsPage, Qt::Widget);
    settingsHost->hide();
    settingsForm = new Ui_Settings();
    settingsForm->setupUi(settingsHost);
    settingsHost->hide();
    settingsForm->port->setValidator(new QIntValidator(0, 65535, settingsForm->port));

    auto* outer = new QVBoxLayout(settingsPage);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea(settingsPage);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* content = new QWidget(scroll);
    auto* column = new QVBoxLayout(content);
    column->setContentsMargins(0, 0, 8, 0);   // the page gutter comes from applyPageGutters()
    column->setSpacing(16);
    column->addWidget(buildSettingsPrivacyCard());
    column->addWidget(buildSettingsAppCard());
    column->addWidget(buildSettingsConnectionCard());
    column->addWidget(buildSettingsTroubleshootingCard());
    column->addStretch(1);
    column->addLayout(buildSettingsActions());
    scroll->setWidget(content);
    outer->addWidget(scroll);
    ui->tabWidget->addTab(settingsPage, tr("Settings"));
    wireSettingsForm();
}

QGroupBox* MainWindow::settingsCard(const QString& title, QVBoxLayout** body) {
    auto* card = new QGroupBox(title, settingsPage);
    card->setObjectName("settingsCard");
    *body = new QVBoxLayout(card);
    (*body)->setSpacing(4);
    return card;
}

// One option: its checkbox, and a short line under it saying what it does.
void MainWindow::addSettingsRow(QVBoxLayout* body, QCheckBox* box, const QString& title,
                                   QLabel* caption, const QString& text) {
    box->setText(title);
    caption->setText(text);
    caption->setObjectName("settingsCaption");
    caption->setWordWrap(true);
    caption->setContentsMargins(30, 0, 0, 10);
    body->addWidget(box);
    body->addWidget(caption);
}

QGroupBox* MainWindow::buildSettingsPrivacyCard() {
    QVBoxLayout* body = nullptr;
    QGroupBox* card = settingsCard(tr("Privacy"), &body);
    Ui_Settings* f = settingsForm;
    addSettingsRow(body, f->chkAutoShield, tr("Send change to my private address"), f->label_7,
        tr("Change from a public (t) address goes to your private address, not to another public one."));
    addSettingsRow(body, f->chkCustomFees, tr("Allow custom fees"), f->label_6,
        tr("Lets you change the network fee. Fees are public, so an unusual one can make a payment stand out."));
    addSettingsRow(body, f->chkSaveTxs, tr("Remember private transactions"), f->label_5,
        tr("Keeps a list of your private transactions on this computer so Activity can show them."));
    f->btnClearSaved->setText(tr("Clear saved history"));
    body->addWidget(f->btnClearSaved, 0, Qt::AlignLeft);
    body->addSpacing(10);
    addSettingsRow(body, f->chkTor, tr("Connect through Tor"), f->lblTor,
        tr("Sends node traffic through Tor (127.0.0.1:9050). Tor must be installed and running. "
           "Applies after a restart."));
    return card;
}

QGroupBox* MainWindow::buildSettingsAppCard() {
    QVBoxLayout* body = nullptr;
    QGroupBox* card = settingsCard(tr("App"), &body);
    Ui_Settings* f = settingsForm;
    addSettingsRow(body, f->chkKeepInTray, tr("Keep running in the background"), f->label_tray,
        tr("Closing the window keeps the wallet and node in the tray, so it opens instantly. "
           "Quit from the tray icon or More > Exit."));
    addSettingsRow(body, f->chkNatpmp, tr("Open my port automatically"), f->label_natpmp,
        tr("Asks your router to let other nodes reach yours (NAT-PMP/PCP, never UPnP). "
           "Applies when the node next starts."));
    auto* timeRow = new QWidget(card);
    timeRow->setLayout(new QVBoxLayout());
    timeRow->layout()->setContentsMargins(0, 0, 0, 0);
    TimeFormat::addSettingsOption(timeRow);
    body->addWidget(timeRow);
    return card;
}

QGroupBox* MainWindow::buildSettingsConnectionCard() {
    QVBoxLayout* body = nullptr;
    QGroupBox* card = settingsCard(tr("Node connection"), &body);
    Ui_Settings* f = settingsForm;
    f->confMsg->setWordWrap(true);
    f->confMsg->setObjectName("settingsCaption");
    body->addWidget(f->confMsg);
    settingsConnectionFields = new QWidget(card);
    auto* form = new QFormLayout(settingsConnectionFields);
    form->setContentsMargins(0, 8, 0, 0);
    f->label_3->setText(tr("RPC username"));
    f->label_4->setText(tr("RPC password"));
    form->addRow(f->label, f->hostname);
    form->addRow(f->label_2, f->port);
    form->addRow(f->label_3, f->rpcuser);
    form->addRow(f->label_4, f->rpcpassword);
    body->addWidget(settingsConnectionFields);
    return card;
}

QGroupBox* MainWindow::buildSettingsTroubleshootingCard() {
    QVBoxLayout* body = nullptr;
    QGroupBox* card = settingsCard(tr("Troubleshooting"), &body);
    Ui_Settings* f = settingsForm;
    addSettingsRow(body, f->chkRescan, tr("Rescan"), f->label_9,
        tr("Searches the blockchain again for missing wallet transactions. The wallet restarts; "
           "this can take hours."));
    addSettingsRow(body, f->chkReindex, tr("Reindex"), f->label_11,
        tr("Rebuilds the whole blockchain database. The wallet restarts; this can take hours or days."));
    return card;
}

QHBoxLayout* MainWindow::buildSettingsActions() {
    auto* row = new QHBoxLayout();
    row->setSpacing(10);
    auto* undo = new QPushButton(tr("Undo changes"), settingsPage);
    undo->setObjectName("settingsUndo");
    auto* save = new QPushButton(tr("Save changes"), settingsPage);
    save->setObjectName("settingsSave");
    save->setDefault(true);   // the green primary look
    QObject::connect(undo, &QPushButton::clicked, this, &MainWindow::loadSettingsForm);
    QObject::connect(save, &QPushButton::clicked, this, [this]() {
        saveSettingsForm();
        loadSettingsForm();
        ui->statusBar->showMessage(tr("Settings saved"), 3 * 1000);
    });
    row->addStretch(1);
    row->addWidget(undo);
    row->addWidget(save);
    return row;
}

// The two options that act at once (as in the dialog): remember private
// transactions, and clearing the saved history.
void MainWindow::wireSettingsForm() {
    QObject::connect(settingsForm->chkSaveTxs, &QCheckBox::stateChanged, this, [](int checked) {
        Settings::getInstance()->setSaveZtxs(checked);
    });
    QObject::connect(settingsForm->btnClearSaved, &QPushButton::clicked, this, [this]() {
        // Only "Yes" deletes: Cancel, Esc and the window X must keep the history.
        auto ans = QMessageBox::warning(this, tr("Clear saved history?"),
            tr("Shielded z-Address transactions are stored locally in your wallet, outside zclassicd. You may delete this saved information safely any time for your privacy.\nDo you want to delete the saved shielded transactions now?"),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
        if (ans != QMessageBox::Yes) return;
        SentTxStore::deleteHistory();
        QSettings().remove("cache");   // the cached last-known balances, same local data
        rpc->refresh(true);            // so existing txs disappear
    });
}

// ---- opening and loading ----------------------------------------------------------

void MainWindow::openSettingsPage() {
    loadSettingsForm();
    ui->tabWidget->setCurrentIndex(ui->tabWidget->indexOf(settingsPage));
}

// Fill the page from the saved settings (also "Undo changes").
void MainWindow::loadSettingsForm() {
    Ui_Settings* f = settingsForm;
    Settings* s = Settings::getInstance();
    f->chkSaveTxs->setChecked(s->getSaveZtxs());
    f->chkCustomFees->setChecked(s->getAllowCustomFees());
    f->chkAutoShield->setChecked(s->getAutoShield());
    f->chkRescan->setChecked(false);
    f->chkReindex->setChecked(false);

    // No system tray: the option would be a no-op, so it is off and says why.
    f->chkKeepInTray->setChecked(s->getKeepInTray());
    const bool tray = QSystemTrayIcon::isSystemTrayAvailable();
    f->chkKeepInTray->setEnabled(tray);
    f->chkKeepInTray->setToolTip(tray ? QString()
        : tr("Your desktop doesn't provide a system tray, so this option isn't available."));

    // NAT-PMP is passed at daemon launch, so it only means something for our own node.
    f->chkNatpmp->setChecked(s->getOpenPortNatpmp());
    f->chkNatpmp->setEnabled(rpc->isEmbedded());
    f->chkNatpmp->setToolTip(rpc->isEmbedded() ? QString()
        : tr("Automatic port opening is available only when running an embedded zclassicd."));

    settingsUsingTor = rpc->getConnection() != nullptr && !rpc->getConnection()->config->proxy.isEmpty();
    f->chkTor->setChecked(settingsUsingTor);
    const bool ownNode = rpc->getEZClassicD() != nullptr;
    const QString torTip = ownNode ? QString()
        : tr("Tor configuration is available only when running an embedded zclassicd.");
    f->chkTor->setEnabled(ownNode);
    f->chkTor->setToolTip(torTip);
    f->lblTor->setToolTip(torTip);

    loadSettingsConnection();
}

// The connection card. Fields are editable unless zclassic.conf already holds
// usable credentials; with our own built-in node there is nothing to fill in.
void MainWindow::loadSettingsConnection() {
    Ui_Settings* f = settingsForm;
    settingsConfLocation = Settings::getInstance()->getZClassicdConfLocation();
    settingsConfLocked = !settingsConfLocation.isEmpty() && confHasUsableCreds(settingsConfLocation);
    QString message;
    if (settingsConfLocked)
        message = tr("Settings are read from %1").arg(QDir::toNativeSeparators(settingsConfLocation));
    else if (!settingsConfLocation.isEmpty())
        message = tr("A ZClassic node is running, but its sign-in details aren't saved here. "
                     "Enter its RPC username and password to connect.");
    else
        message = tr("No local zclassic.conf found. Enter the connection details below.");
    bool editable = !settingsConfLocked;
    if (rpc->isEmbedded()) {
        message = tr("This wallet runs its own built-in ZClassic node and connects to it "
                     "automatically; there is nothing to fill in.\nNode settings file: %1")
                      .arg(QDir::toNativeSeparators(settingsConfLocation));
        editable = false;
    }
    f->confMsg->setText(message);
    for (QLineEdit* e : { f->hostname, f->port, f->rpcuser, f->rpcpassword })
        e->setEnabled(editable);
    settingsConnectionFields->setVisible(!rpc->isEmbedded());

    const auto conf = Settings::getInstance()->getSettings();
    f->hostname->setText(conf.host);
    f->port->setText(conf.port);
    f->rpcuser->setText(conf.rpcuser);
    f->rpcpassword->setText(conf.rpcpassword);

    // Rescan / reindex need our own node; an external one is restarted by hand.
    f->chkRescan->setEnabled(rpc->isEmbedded());
    f->chkRescan->setToolTip(rpc->isEmbedded() ? QString()
        : tr("You're using an external zclassicd. Please restart zclassicd with -rescan"));
    f->chkReindex->setEnabled(rpc->isEmbedded());
    f->chkReindex->setToolTip(rpc->isEmbedded() ? QString()
        : tr("You're using an external zclassicd. Please restart zclassicd with -reindex"));
}

// ---- saving ---------------------------------------------------------------------------

// "Save changes": what the Settings dialog's OK did.
void MainWindow::saveSettingsForm() {
    Ui_Settings* f = settingsForm;
    Settings* s = Settings::getInstance();
    const bool customFees = f->chkCustomFees->isChecked();
    s->setAllowCustomFees(customFees);
    ui->minerFeeAmt->setReadOnly(!customFees);
    if (!customFees)
        ui->minerFeeAmt->setText(Settings::getDecimalString(Settings::getMinerFee()));
    s->setAutoShield(f->chkAutoShield->isChecked());

    // Tray: applied at once, no restart needed.
    s->setKeepInTray(f->chkKeepInTray->isChecked());
    applyTraySetting(f->chkKeepInTray->isChecked());

    saveSettingsNetwork();

    // Editable credentials (no conf, or a conf without usable ones) are saved and the
    // wallet reconnects with them.
    if (!settingsConfLocked) {
        s->saveSettings(f->hostname->text(), f->port->text(), f->rpcuser->text(), f->rpcpassword->text());
        auto cl = new ConnectionLoader(this, rpc);
        cl->loadConnection();
    }
    saveSettingsRestart();
}

// NAT-PMP (read by the node at launch) and Tor (a proxy line in zclassic.conf).
void MainWindow::saveSettingsNetwork() {
    Ui_Settings* f = settingsForm;
    const bool natpmp = f->chkNatpmp->isChecked();
    if (natpmp != Settings::getInstance()->getOpenPortNatpmp()) {
        Settings::getInstance()->setOpenPortNatpmp(natpmp);
        QMessageBox::information(this, tr("Open port automatically"),
            natpmp
                ? tr("Automatic port opening will be enabled the next time ZclWallet starts its node. This asks your router to make you reachable to other peers (NAT-PMP/PCP, never UPnP).")
                : tr("Automatic port opening will be disabled the next time ZclWallet starts its node."),
            QMessageBox::Ok);
    }
    const bool torWanted = f->chkTor->isChecked();
    if (!settingsUsingTor && torWanted) {
        Settings::addToZClassicConf(settingsConfLocation, "proxy=127.0.0.1:9050");
        if (rpc->getConnection()) rpc->getConnection()->config->proxy = "proxy=127.0.0.1:9050";   // not connected yet during start-up
        QMessageBox::information(this, tr("Enable Tor"),
            tr("Connection over Tor has been enabled. To use this feature, you need to restart ZclWallet."),
            QMessageBox::Ok);
    }
    if (settingsUsingTor && !torWanted) {
        Settings::removeFromZClassicConf(settingsConfLocation, "proxy");
        if (rpc->getConnection()) rpc->getConnection()->config->proxy.clear();
        QMessageBox::information(this, tr("Disable Tor"),
            tr("Connection over Tor has been disabled. To fully disconnect from Tor, you need to restart ZclWallet."),
            QMessageBox::Ok);
    }
}

// Rescan / reindex are flags in zclassic.conf read at the node's next start, so
// the wallet quits (really quits, also from tray mode) for the user to reopen it.
void MainWindow::saveSettingsRestart() {
    bool restart = false;
    if (settingsForm->chkRescan->isChecked()) {
        Settings::addToZClassicConf(settingsConfLocation, "rescan=1");
        restart = true;
    }
    if (settingsForm->chkReindex->isChecked()) {
        Settings::addToZClassicConf(settingsConfLocation, "reindex=1");
        restart = true;
    }
    if (!restart) return;
    QMessageBox::information(this, tr("Restart ZclWallet"),
        tr("ZclWallet needs to restart to rescan/reindex. ZclWallet will now close, please restart ZclWallet to continue"),
        QMessageBox::Ok);
    QTimer::singleShot(1, this, [=]() { this->quitApp(); });
}
