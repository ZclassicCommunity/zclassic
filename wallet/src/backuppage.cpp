// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "backuppage.h"
#include "addresscell.h"
#include "phrase.h"
#include "settings.h"

#include <QAction>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRandomGenerator>
#include <QScrollArea>
#include <QSettings>
#include <QStyle>
#include <QToolButton>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace {
const int kChecks = 3;   // words the check step asks for

void setTone(QLabel* label, const char* tone) {
    label->setProperty("tone", tone);   // qss: QLabel#backupStatus[tone="..."]
    label->style()->unpolish(label);
    label->style()->polish(label);
}
}   // namespace

BackupPage::BackupPage(QWidget* parent) : QWidget(parent) {
    setObjectName("backupPage");
    auto* outer = new QVBoxLayout(this);   // the page gutter comes from applyPageGutters()
    auto* scroll = new QScrollArea(this);
    scroll->setObjectName("backupScroll");
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto* content = new QWidget(scroll);
    content->setObjectName("backupContent");
    auto* column = new QVBoxLayout(content);
    column->setContentsMargins(0, 0, 6, 0);
    column->setSpacing(16);
    column->addWidget(buildPhraseCard());
    column->addWidget(buildNotCoveredCard());
    column->addWidget(buildRestoreCard());
    column->addWidget(buildFilesCard());
    column->addStretch(1);
    scroll->setWidget(content);
    outer->addWidget(scroll);
    setSupported(false);
}

QLabel* BackupPage::caption(const QString& text, QWidget* parent) {
    auto* l = new QLabel(text, parent);
    l->setObjectName("settingsCaption");   // the dim one-line explanation style
    l->setWordWrap(true);
    return l;
}

// ---- Recovery phrase: status, the words (hidden), write-down check -------------
QGroupBox* BackupPage::buildPhraseCard() {
    _phraseCard = new QGroupBox(tr("Recovery phrase"), this);
    _phraseCard->setObjectName("phraseCard");
    auto* box = new QVBoxLayout(_phraseCard);
    box->setSpacing(10);
    box->addWidget(caption(tr("24 words that bring back this wallet on any computer. "
                              "Write them on paper and keep it safe: anyone with them can spend your money."),
                           _phraseCard));
    _status = new QLabel(_phraseCard);
    _status->setObjectName("backupStatus");
    _status->setWordWrap(true);
    box->addWidget(_status);

    _grid = new QWidget(_phraseCard);
    _grid->setObjectName("phraseGrid");
    auto* grid = new QGridLayout(_grid);
    grid->setContentsMargins(0, 6, 0, 6);
    grid->setHorizontalSpacing(12);
    grid->setVerticalSpacing(8);
    for (int i = 0; i < Phrase::kWords; ++i) {
        auto* cell = new QLabel(_grid);
        cell->setObjectName("phraseWord");
        cell->setTextFormat(Qt::RichText);
        cell->setTextInteractionFlags(Qt::NoTextInteraction);   // no select-and-copy
        grid->addWidget(cell, i % 6, i / 6);   // numbered down each of 4 columns
        _cells << cell;
    }
    _grid->hide();
    box->addWidget(_grid);

    _checkStep = buildCheckStep(_phraseCard);
    box->addWidget(_checkStep);

    auto* row = new QHBoxLayout();
    row->setSpacing(8);
    _showBtn = new QPushButton(tr("Show phrase"), _phraseCard);
    _showBtn->setObjectName("phraseShow");
    _wroteBtn = new QPushButton(tr("I wrote it down"), _phraseCard);
    _wroteBtn->setObjectName("phraseWrote");
    _wroteBtn->hide();
    QObject::connect(_showBtn, &QPushButton::clicked, this, [this]() {
        if (!_words.isEmpty()) { hideWords(); return; }
        if (onShowPhrase) onShowPhrase();
    });
    QObject::connect(_wroteBtn, &QPushButton::clicked, this, &BackupPage::startCheck);
    row->addWidget(_showBtn);
    row->addWidget(_wroteBtn);
    row->addStretch(1);
    box->addLayout(row);
    return _phraseCard;
}

// "Type these words from your paper": three positions, picked at random.
QWidget* BackupPage::buildCheckStep(QWidget* parent) {
    auto* step = new QWidget(parent);
    step->setObjectName("phraseCheck");
    auto* v = new QVBoxLayout(step);
    v->setContentsMargins(0, 4, 0, 4);
    v->setSpacing(8);
    v->addWidget(caption(tr("From your paper, type these words:"), step));
    auto* row = new QHBoxLayout();
    row->setSpacing(10);
    for (int i = 0; i < kChecks; ++i) {
        auto* label = new QLabel(step);
        label->setObjectName("phraseCheckLabel");
        auto* input = new QLineEdit(step);
        input->setObjectName("phraseCheckInput");
        input->setMaximumWidth(150);
        QObject::connect(input, &QLineEdit::returnPressed, this, &BackupPage::runCheck);
        row->addWidget(label);
        row->addWidget(input);
        _checkLabels << label;
        _checkInputs << input;
    }
    auto* check = new QPushButton(tr("Check"), step);
    check->setObjectName("phraseCheckButton");
    QObject::connect(check, &QPushButton::clicked, this, &BackupPage::runCheck);
    row->addWidget(check);
    row->addStretch(1);
    v->addLayout(row);
    _checkResult = new QLabel(step);
    _checkResult->setObjectName("backupStatus");
    _checkResult->hide();
    v->addWidget(_checkResult);
    step->hide();
    return step;
}

// ---- Restore from a phrase --------------------------------------------------
QGroupBox* BackupPage::buildRestoreCard() {
    _restoreCard = new QGroupBox(tr("Restore from a phrase"), this);
    _restoreCard->setObjectName("restoreCard");
    auto* box = new QVBoxLayout(_restoreCard);
    box->setSpacing(10);
    box->addWidget(caption(tr("Bring back money from a phrase you wrote down. "
                              "The addresses already here stay."), _restoreCard));
    _restoreField = new QPlainTextEdit(_restoreCard);
    _restoreField->setObjectName("restorePhrase");
    _restoreField->setPlaceholderText(tr("word1 word2 word3 …"));
    _restoreField->setTabChangesFocus(true);
    _restoreField->setFixedHeight(76);
    QObject::connect(_restoreField, &QPlainTextEdit::textChanged, this, &BackupPage::restoreTextChanged);
    box->addWidget(_restoreField);

    auto* row = new QHBoxLayout();
    _restoreHint = new QLabel(_restoreCard);
    _restoreHint->setObjectName("restoreHint");
    _restoreBtn = new QPushButton(tr("Restore"), _restoreCard);
    _restoreBtn->setObjectName("restoreButton");
    QObject::connect(_restoreBtn, &QPushButton::clicked, this, &BackupPage::confirmRestore);
    row->addWidget(_restoreHint, 1);
    row->addWidget(_restoreBtn);
    box->addLayout(row);

    _restoreBusy = new QProgressBar(_restoreCard);
    _restoreBusy->setObjectName("homeImportBar");   // the same busy bar as Home's import card
    _restoreBusy->setRange(0, 0);
    _restoreBusy->setTextVisible(false);
    _restoreBusy->hide();
    box->addWidget(_restoreBusy);
    restoreTextChanged();
    return _restoreCard;
}

// ---- Money on addresses the phrase does not cover ---------------------------
QGroupBox* BackupPage::buildNotCoveredCard() {
    _notCoveredCard = new QGroupBox(tr("Not in your phrase"), this);
    _notCoveredCard->setObjectName("notCoveredCard");
    auto* box = new QVBoxLayout(_notCoveredCard);
    box->setSpacing(10);
    box->addWidget(caption(tr("These older addresses hold money but aren't in your phrase. "
                              "Move it to a new address and your phrase covers it."), _notCoveredCard));
    _notCoveredList = new QTreeWidget(_notCoveredCard);
    _notCoveredList->setObjectName("notCoveredList");
    _notCoveredList->setColumnCount(3);
    _notCoveredList->setHeaderLabels({tr("Address"), tr("Balance"), QString()});
    _notCoveredList->setRootIsDecorated(false);
    _notCoveredList->setUniformRowHeights(true);
    _notCoveredList->header()->setStretchLastSection(false);
    _notCoveredList->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    _notCoveredList->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    _notCoveredList->header()->setSectionResizeMode(2, QHeaderView::Fixed);
    _notCoveredList->header()->resizeSection(2, 48);
    _notCoveredList->setItemDelegateForColumn(0, new AddressCellDelegate(_notCoveredList));
    _notCoveredList->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    box->addWidget(_notCoveredList);
    _notCoveredCard->hide();
    return _notCoveredCard;
}

// ---- The wallet file and private keys (the existing actions) ----------------
QGroupBox* BackupPage::buildFilesCard() {
    _filesCard = new QGroupBox(tr("Wallet file and keys"), this);
    _filesCard->setObjectName("backupFilesCard");
    _filesRow = new QVBoxLayout(_filesCard);
    _filesRow->setSpacing(10);
    _filesRow->addWidget(caption(tr("A copy of wallet.dat keeps every address, "
                                    "including ones your phrase doesn't cover."), _filesCard));
    return _filesCard;
}

void BackupPage::addFileActions(QAction* backup, QAction* exportKeys, QAction* importKeys) {
    auto* row = new QHBoxLayout();
    row->setSpacing(8);
    const QList<QPair<QAction*, QString>> buttons = {
        { backup,     tr("Save a copy of wallet.dat") },
        { exportKeys, tr("Export private keys") },
        { importKeys, tr("Import private keys") },
    };
    for (const auto& b : buttons) {
        auto* btn = new QPushButton(b.second, _filesCard);
        btn->setObjectName("backupFileButton");
        QAction* action = b.first;
        QObject::connect(btn, &QPushButton::clicked, action, &QAction::trigger);
        row->addWidget(btn);
    }
    row->addStretch(1);
    _filesRow->addLayout(row);
}

// ---- State ------------------------------------------------------------------
void BackupPage::setSupported(bool supported) {
    _supported = supported;
    _phraseCard->setVisible(supported);
    _restoreCard->setVisible(supported);
    if (!supported) {
        hideWords();
        _notCoveredCard->hide();
    }
}

void BackupPage::setPhraseInfo(bool available, const QString& fingerprint, const QStringList& notCovered) {
    setSupported(true);
    _available = available;
    if (fingerprint != _fingerprint) hideWords();
    _fingerprint = fingerprint;
    _notCovered = notCovered;
    _showBtn->setVisible(available);
    updateStatus();
    refreshNotCovered();
}

void BackupPage::updateStatus() {
    if (!_available) {
        _status->setText(tr("This wallet's phrase can't be shown right now."));
        setTone(_status, "dim");
        return;
    }
    const bool written = isWrittenDown(_fingerprint);
    QString text = written ? tr("Written down") : tr("Not written down yet");
    if (!_notCovered.isEmpty())
        text += QStringLiteral(" · ") + (_notCovered.size() == 1
            ? tr("1 older address isn't in it, so keep a wallet.dat copy too.")
            : tr("%1 older addresses aren't in it, so keep a wallet.dat copy too.").arg(_notCovered.size()));
    _status->setText(text);
    setTone(_status, written ? "ok" : "warn");
}

void BackupPage::refreshNotCovered() {
    _notCoveredList->clear();
    for (const QString& addr : _notCovered) {
        const double bal = balanceOf ? balanceOf(addr) : 0.0;
        if (bal <= 0) continue;
        auto* item = new QTreeWidgetItem(_notCoveredList);
        item->setText(0, addr);
        item->setText(1, Settings::getZCLDisplayFormat(bal));
        auto* move = new QToolButton(_notCoveredList);
        move->setObjectName("notCoveredMove");
        move->setIcon(QIcon(":/icons/res/icons/send-light.svg"));
        move->setIconSize(QSize(18, 18));
        move->setToolTip(tr("Move to a new address (you review it on Send)"));
        move->setCursor(Qt::PointingHandCursor);
        move->setAutoRaise(true);
        QObject::connect(move, &QToolButton::clicked, this, [this, addr]() {
            if (onMove) onMove(addr);
        });
        _notCoveredList->setItemWidget(item, 2, move);
    }
    // As tall as its rows (up to six), so a single address leaves no empty box.
    const int rows = qMin(_notCoveredList->topLevelItemCount(), 6);
    const int rowH = rows > 0 ? qMax(_notCoveredList->sizeHintForRow(0), 40) : 0;
    _notCoveredList->setFixedHeight(_notCoveredList->header()->sizeHint().height() + rows * rowH + 6);
    _notCoveredCard->setVisible(_supported && _notCoveredList->topLevelItemCount() > 0);
}

void BackupPage::showWords(const QStringList& words, const QString& fingerprint) {
    if (words.size() != Phrase::kWords) return;
    _words = words;
    _shownFingerprint = fingerprint;
    for (int i = 0; i < _cells.size(); ++i)
        _cells.at(i)->setText(QStringLiteral("<span style='color:#9aa59d'>%1</span>&nbsp;&nbsp;%2")
                              .arg(QString::number(i + 1).rightJustified(2).replace(" ", "&nbsp;"))
                              .arg(words.at(i).toHtmlEscaped()));
    _grid->show();
    _showBtn->setText(tr("Hide phrase"));
    _wroteBtn->show();
}

void BackupPage::hideWords() {
    _words.clear();
    _shownFingerprint.clear();
    for (QLabel* cell : _cells) cell->clear();
    if (_grid) _grid->hide();
    if (_showBtn) _showBtn->setText(tr("Show phrase"));
    if (_wroteBtn) _wroteBtn->hide();
    if (_checkStep) _checkStep->hide();
    for (QLineEdit* in : _checkInputs) in->clear();
}

// Hide the words (the paper is the copy now) and ask for three of them.
void BackupPage::startCheck() {
    if (_words.isEmpty()) return;
    _asked.clear();
    while (_asked.size() < kChecks) {
        const int pos = int(QRandomGenerator::global()->bounded(Phrase::kWords));
        if (!_asked.contains(pos)) _asked << pos;
    }
    std::sort(_asked.begin(), _asked.end());
    for (int i = 0; i < kChecks; ++i) {
        _checkLabels.at(i)->setText(tr("Word %1").arg(_asked.at(i) + 1));
        _checkInputs.at(i)->clear();
    }
    _checkResult->hide();
    _grid->hide();
    _wroteBtn->hide();
    _checkStep->show();
    _checkInputs.first()->setFocus();
}

void BackupPage::runCheck() {
    if (_words.isEmpty() || _asked.size() != kChecks) return;
    bool ok = true;
    for (int i = 0; i < kChecks; ++i)
        ok = ok && _checkInputs.at(i)->text().trimmed().toLower() == _words.at(_asked.at(i));
    _checkResult->show();
    if (!ok) {
        _checkResult->setText(tr("That doesn't match. Look at your paper and try again."));
        setTone(_checkResult, "warn");
        return;
    }
    setWrittenDown(_shownFingerprint);
    hideWords();
    updateStatus();
}

void BackupPage::restoreTextChanged() {
    const Phrase::Check c = Phrase::check(_restoreField->toPlainText());
    _restoreHint->setText(Phrase::hint(c));
    const bool problem = c.state == Phrase::Check::UnknownWord || c.state == Phrase::Check::BadChecksum
                         || c.state == Phrase::Check::TooMany;
    setTone(_restoreHint, problem ? "warn" : (c.state == Phrase::Check::Valid ? "ok" : "dim"));
    _restoreBtn->setEnabled(c.state == Phrase::Check::Valid && !_restoreBusy->isVisible());
}

void BackupPage::confirmRestore() {
    const QString text = _restoreField->toPlainText();
    if (Phrase::check(text).state != Phrase::Check::Valid) return;
    QMessageBox box(this);
    box.setIcon(QMessageBox::Question);
    box.setWindowTitle(tr("Restore from this phrase?"));
    box.setText(tr("Restore from this phrase?"));
    box.setInformativeText(tr("Your current addresses stay in this wallet, and new addresses will come from this phrase. "
                              "ZClassic then rescans the blockchain for its money, which can take a while."));
    QPushButton* go = box.addButton(tr("Restore"), QMessageBox::AcceptRole);
    box.addButton(QMessageBox::Cancel);
    box.setDefaultButton(go);
    box.exec();
    if (box.clickedButton() != go) return;
    if (onRestore) onRestore(Phrase::split(text).join(' '));
}

void BackupPage::setRestoring(bool busy) {
    _restoreBusy->setVisible(busy);
    _restoreField->setReadOnly(busy);
    if (busy) {
        _restoreHint->setText(tr("Restoring… Keep ZClassic open."));
        setTone(_restoreHint, "dim");
        _restoreBtn->setEnabled(false);
    } else {
        restoreTextChanged();
    }
}

void BackupPage::clearRestoreField() {
    _restoreField->clear();
}

bool BackupPage::isWrittenDown(const QString& fingerprint) {
    return !fingerprint.isEmpty() && QSettings().value("backup/phrase/" + fingerprint, false).toBool();
}

void BackupPage::setWrittenDown(const QString& fingerprint) {
    if (fingerprint.isEmpty()) return;
    QSettings().setValue("backup/phrase/" + fingerprint, true);
    Settings::getInstance()->setWalletBackedUp(true);   // the Home reminder stops too
}
