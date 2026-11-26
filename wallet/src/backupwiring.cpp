// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// MainWindow's side of the Backup page (backuppage.cpp): the node's recovery-phrase
// RPCs, the Home reminder's wording, and "Move" pre-filling Send. Everything that
// signs or sends still goes through the Send page: Move only fills it in.
//
// Node RPCs (a node without them answers -32601 and the page keeps only its file
// card, as before):
//   z_getphraseinfo          -> {available, fingerprint, not_covered: [addr...]}
//   z_getrecoveryphrase      -> {phrase, fingerprint}
//   z_restorefromphrase "p"  -> {fingerprint, transparent: [...], sapling: [...]} (rescans)
// The phrase travels only in these RPC bodies; it is never logged or kept.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "backuppage.h"
#include "phrase.h"
#include "rpc.h"
#include "settings.h"

#include <QMessageBox>
#include <QNetworkReply>
#include <QPushButton>

namespace {
const int kMethodNotFound = -32601;

json rpcCall(const char* method, const json& params = json::array()) {
    return json{ {"jsonrpc", "1.0"}, {"id", "someid"}, {"method", method}, {"params", params} };
}

QString rpcError(QNetworkReply* reply, const json& parsed) {
    if (!parsed.is_discarded() && parsed.is_object() && parsed.find("error") != parsed.end()
            && parsed["error"].is_object() && parsed["error"]["message"].is_string())
        return QString::fromStdString(parsed["error"]["message"].get<std::string>());
    return reply ? reply->errorString() : QString();
}

QStringList stringList(const json& arr) {
    QStringList out;
    if (!arr.is_array()) return out;
    for (const auto& v : arr)
        if (v.is_string()) out << QString::fromStdString(v.get<std::string>());
    return out;
}
}   // namespace

void MainWindow::buildBackupPage() {
    backupPage = new BackupPage();
    backupPage->addFileActions(ui->actionBackup_wallet_dat, ui->actionExport_All_Private_Keys,
                               ui->actionImport_Private_Key);
    backupPage->onShowPhrase = [this]() { showRecoveryPhrase(); };
    backupPage->onRestore    = [this](const QString& phrase) { restoreFromPhrase(phrase); };
    backupPage->onMove       = [this](const QString& addr) { moveToPhraseAddress(addr); };
    backupPage->balanceOf    = [this](const QString& addr) {
        return (rpc && rpc->getAllBalances()) ? rpc->getAllBalances()->value(addr) : 0.0;
    };
    ui->tabWidget->addTab(backupPage, tr("Backup"));
    // The words stay on screen only while the page is shown.
    QObject::connect(ui->tabWidget, &QTabWidget::currentChanged, this, [this](int) {
        if (ui->tabWidget->currentWidget() != backupPage) backupPage->hideWords();
    });
}

void MainWindow::openBackupPage() {
    ui->tabWidget->setCurrentIndex(ui->tabWidget->indexOf(backupPage));
    refreshPhraseInfo();
}

// Ask the node what it knows about the phrase. Called once connected and each time
// the page opens; an older node without the RPCs keeps today's behaviour.
void MainWindow::refreshPhraseInfo() {
    if (!rpc || !rpc->getConnection() || !backupPage) return;
    rpc->getConnection()->doRPC(rpcCall("z_getphraseinfo"), [this](json reply) {
        applyPhraseInfo(reply);
    }, [this](QNetworkReply*, const json& parsed) {
        const bool missing = parsed.is_discarded() || !parsed.is_object() || parsed.find("error") == parsed.end()
            || !parsed["error"].is_object() || parsed["error"].value("code", 0) == kMethodNotFound;
        if (missing) {
            backupPage->setSupported(false);
            phraseSupported = false;
        }
    });
}

void MainWindow::applyPhraseInfo(const json& reply) {
    if (!reply.is_object()) return;
    phraseSupported = true;
    backupPage->setPhraseInfo(reply.value("available", false),
                              QString::fromStdString(reply.value("fingerprint", std::string())),
                              stringList(reply.value("not_covered", json::array())));
    applyPhraseToHome();
}

// The Home reminder points at the phrase, and its button opens the Backup page.
void MainWindow::applyPhraseToHome() {
    if (homeBackupText)
        homeBackupText->setText(backupReminderText());
    QPushButton* btn = homeBackupCard ? homeBackupCard->findChild<QPushButton*>("homeFixItBtn") : nullptr;
    if (btn && !btn->property("opensBackupPage").toBool()) {
        btn->setProperty("opensBackupPage", true);
        QObject::disconnect(btn, &QPushButton::clicked, nullptr, nullptr);
        QObject::connect(btn, &QPushButton::clicked, this, &MainWindow::openBackupPage);
    }
}

// The reminder's words: the phrase when the node has one, else the wallet.dat copy.
QString MainWindow::backupReminderText() const {
    if (phraseSupported)
        return tr("Write down your recovery phrase. If this computer is lost and you have "
                  "no backup, your coins are gone forever.");
    return tr("Back up your wallet. This wallet has no recovery phrase — if this "
              "computer is lost or its disk fails and you have no backup, your coins "
              "are gone forever.");
}

void MainWindow::showRecoveryPhrase() {
    if (!rpc || !rpc->getConnection()) return;
    rpc->getConnection()->doRPC(rpcCall("z_getrecoveryphrase"), [this](json reply) {
        if (!reply.is_object()) return;
        const QStringList words = Phrase::split(QString::fromStdString(reply.value("phrase", std::string())));
        backupPage->showWords(words, QString::fromStdString(reply.value("fingerprint", std::string())));
    }, [this](QNetworkReply* r, const json& parsed) {
        QMessageBox::warning(this, tr("Recovery phrase"),
                             tr("The phrase couldn't be shown.") + "\n\n" + rpcError(r, parsed));
    });
}

// Restore: the node keeps every key it has, takes the phrase's seed for new
// addresses and rescans. That can take long, so the page and Home show it's busy.
void MainWindow::restoreFromPhrase(const QString& phrase) {
    if (!rpc || !rpc->getConnection()) return;
    backupPage->setRestoring(true);
    showImportProgress(true);
    rpc->getConnection()->doRPC(rpcCall("z_restorefromphrase", json::array({ phrase.toStdString() })),
        [this](json reply) {
        backupPage->setRestoring(false);
        backupPage->clearRestoreField();
        showImportProgress(false);
        if (reply.is_object())
            BackupPage::setWrittenDown(QString::fromStdString(reply.value("fingerprint", std::string())));
        const int found = stringList(reply.value("transparent", json::array())).size()
                        + stringList(reply.value("sapling", json::array())).size();
        ui->statusBar->showMessage(found == 1 ? tr("Restore finished: 1 address with history found.")
            : tr("Restore finished: %1 addresses with history found.").arg(found), 10000);
        rpc->refresh(true);
        refreshPhraseInfo();
    }, [this](QNetworkReply* r, const json& parsed) {
        backupPage->setRestoring(false);
        showImportProgress(false);
        QMessageBox::critical(this, tr("Restore from a phrase"),
                              tr("The restore didn't finish.") + "\n\n" + rpcError(r, parsed));
    });
}

// "Move": fill Send with this address as Pay from, a fresh address of the phrase
// as Pay to and "Send all". Nothing is sent: the user reviews and presses Send.
// Old Sprout money goes to a new private (Sapling) address.
void MainWindow::moveToPhraseAddress(const QString& from) {
    if (!rpc) return;
    auto fill = [this, from](json reply) {
        if (!reply.is_string()) return;
        const QString to = QString::fromStdString(reply.get<std::string>());
        ui->tabWidget->setCurrentIndex(1);
        removeExtraAddresses();
        if (ui->inputsCombo->findText(from) < 0)
            ui->inputsCombo->addItem(from, rpc->getAllBalances() ? rpc->getAllBalances()->value(from) : 0.0);
        ui->inputsCombo->setCurrentText(from);
        ui->Address1->setText(to);
        ui->Max1->setChecked(true);
        ui->statusBar->showMessage(tr("Check the details, then press Send."), 8000);
    };
    if (from.startsWith('t')) rpc->newTaddr(fill);
    else                      rpc->newZaddr(true, fill);
}
