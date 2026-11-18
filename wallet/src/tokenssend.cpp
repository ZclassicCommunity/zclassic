// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokenssend.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QStackedWidget>
#include <QVBoxLayout>

namespace tokens {

using json = nlohmann::json;

namespace {

// Chain data (tickers, names, addresses) is untrusted text: never let a label interpret it as HTML.
QLabel* plainLabel(const QString& text, QWidget* parent, bool wrap = true)
{
    auto* l = new QLabel(text, parent);
    l->setTextFormat(Qt::PlainText);
    l->setWordWrap(wrap);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return l;
}

} // namespace

// ---- StepDialog --------------------------------------------------------------------------------

StepDialog::StepDialog(TokensRpc* rpc, QWidget* parent) : QDialog(parent), rpc_(rpc) {}

int StepDialog::page() const { return stack_ ? stack_->currentIndex() : -1; }

void StepDialog::buildChrome(QWidget* form, const QString& sendText)
{
    auto* root = new QVBoxLayout(this);
    stack_ = new QStackedWidget(this);
    stack_->setObjectName(QStringLiteral("stack"));
    root->addWidget(stack_);

    // page 0: the form
    auto* formPage = new QWidget(stack_);
    auto* fl = new QVBoxLayout(formPage);
    fl->addWidget(form);
    errorLabel_ = plainLabel(QString(), formPage);
    errorLabel_->setObjectName(QStringLiteral("errorLabel"));
    errorLabel_->setStyleSheet(QStringLiteral("color: #b00020;"));
    errorLabel_->hide();
    fl->addWidget(errorLabel_);
    auto* fb = new QHBoxLayout;
    fb->addStretch(1);
    cancelButton_ = new QPushButton(tr("Cancel"), formPage);
    cancelButton_->setObjectName(QStringLiteral("cancelButton"));
    reviewButton_ = new QPushButton(tr("Review"), formPage);
    reviewButton_->setObjectName(QStringLiteral("reviewButton"));
    reviewButton_->setDefault(true);
    fb->addWidget(cancelButton_);
    fb->addWidget(reviewButton_);
    fl->addLayout(fb);
    stack_->addWidget(formPage);

    // page 1: review
    auto* reviewPage = new QWidget(stack_);
    auto* rl = new QVBoxLayout(reviewPage);
    reviewLabel_ = plainLabel(QString(), reviewPage);
    reviewLabel_->setObjectName(QStringLiteral("reviewLabel"));
    rl->addWidget(reviewLabel_);
    rl->addStretch(1);
    auto* rb = new QHBoxLayout;
    rb->addStretch(1);
    backButton_ = new QPushButton(tr("Back"), reviewPage);
    backButton_->setObjectName(QStringLiteral("backButton"));
    sendButton_ = new QPushButton(sendText, reviewPage);
    sendButton_->setObjectName(QStringLiteral("sendButton"));
    rb->addWidget(backButton_);
    rb->addWidget(sendButton_);
    rl->addLayout(rb);
    stack_->addWidget(reviewPage);

    // page 2: result
    auto* resultPage = new QWidget(stack_);
    auto* tl = new QVBoxLayout(resultPage);
    resultLabel_ = plainLabel(QString(), resultPage);
    resultLabel_->setObjectName(QStringLiteral("resultLabel"));
    tl->addWidget(resultLabel_);
    tl->addStretch(1);
    auto* tb = new QHBoxLayout;
    tb->addStretch(1);
    closeButton_ = new QPushButton(tr("Close"), resultPage);
    closeButton_->setObjectName(QStringLiteral("closeButton"));
    tb->addWidget(closeButton_);
    tl->addLayout(tb);
    stack_->addWidget(resultPage);

    connect(cancelButton_, &QPushButton::clicked, this, &QDialog::reject);
    connect(closeButton_, &QPushButton::clicked, this, &QDialog::accept);
    connect(backButton_, &QPushButton::clicked, this, [this] { if (!busy_) showPage(FormPage); });
    connect(reviewButton_, &QPushButton::clicked, this, [this] { if (!busy_) onReview(); });
    connect(sendButton_, &QPushButton::clicked, this, [this] { if (!busy_) onSend(); });
    showPage(FormPage);
}

void StepDialog::setError(const QString& text)
{
    errorLabel_->setText(text);
    errorLabel_->setVisible(!text.isEmpty());
}

void StepDialog::setBusy(bool busy)
{
    busy_ = busy;
    reviewButton_->setEnabled(!busy);
    backButton_->setEnabled(!busy);
    sendButton_->setEnabled(!busy);
    cancelButton_->setEnabled(!busy);
}

void StepDialog::showPage(Page p)
{
    stack_->setCurrentIndex(p);
    if (p == FormPage)
        setError(QString());
}

// ---- send -------------------------------------------------------------------------------------

TokenSendDialog::TokenSendDialog(TokensRpc* rpc, const QVector<TokenChoice>& choices, QWidget* parent)
    : StepDialog(rpc, parent), choices_(choices)
{
    setWindowTitle(tr("Send tokens"));
    setObjectName(QStringLiteral("tokenSendDialog"));
    resize(560, 360);

    auto* form = new QWidget(this);
    auto* fl = new QFormLayout(form);
    tokenBox_ = new QComboBox(form);
    tokenBox_->setObjectName(QStringLiteral("tokenBox"));
    for (const TokenChoice& c : choices_)
        tokenBox_->addItem(displayTicker(c.ticker, c.tokenId) + QStringLiteral("  (") + c.balance + QLatin1Char(')'));
    fl->addRow(tr("Token"), tokenBox_);
    availableLabel_ = plainLabel(QString(), form, false);
    availableLabel_->setObjectName(QStringLiteral("availableLabel"));
    fl->addRow(QString(), availableLabel_);
    toEdit_ = new QLineEdit(form);
    toEdit_->setObjectName(QStringLiteral("toEdit"));
    toEdit_->setPlaceholderText(tr("Transparent address (starts with t)"));
    fl->addRow(tr("To"), toEdit_);
    auto* amountRow = new QHBoxLayout;
    amountEdit_ = new QLineEdit(form);
    amountEdit_->setObjectName(QStringLiteral("amountEdit"));
    maxButton_ = new QPushButton(tr("Max"), form);
    maxButton_->setObjectName(QStringLiteral("maxButton"));
    amountRow->addWidget(amountEdit_, 1);
    amountRow->addWidget(maxButton_);
    fl->addRow(tr("Amount"), amountRow);
    auto* note = plainLabel(tr("Tokens travel on small ZCL outputs and can only be sent to transparent addresses. "
                               "The network fee is paid in ordinary ZCL, not in tokens. Only confirmed tokens can be sent; "
                               "any token change returns to you."), form);
    fl->addRow(note);

    buildChrome(form, tr("Send tokens"));
    connect(tokenBox_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { onTokenChanged(); });
    connect(maxButton_, &QPushButton::clicked, this, [this] { onMax(); });
    if (choices_.isEmpty()) {
        reviewButton_->setEnabled(false);
        maxButton_->setEnabled(false);
        availableLabel_->setText(tr("This wallet holds no confirmed tokens to send."));
    } else {
        onTokenChanged();
    }
}

TokenChoice TokenSendDialog::current() const
{
    const int i = tokenBox_->currentIndex();
    return i >= 0 && i < choices_.size() ? choices_[i] : TokenChoice();
}

void TokenSendDialog::onTokenChanged()
{
    const TokenChoice c = current();
    availableLabel_->setText(tr("Available (confirmed): %1 %2").arg(c.balance, displayTicker(c.ticker, c.tokenId)));
    setError(QString());
}

void TokenSendDialog::onMax()
{
    amountEdit_->setText(current().balance);
}

void TokenSendDialog::onReview()
{
    setError(QString());
    const TokenChoice token = current();
    const SendCheck check = checkSend(token, toEdit_->text(), amountEdit_->text());
    if (!check.ok) {
        setError(check.error);
        return;
    }
    setBusy(true);
    rpc_->call(QStringLiteral("zslp_send"), sendParams(token, check, /*dryRun=*/true),
        [this, token, check](const json& result) {
            setBusy(false);
            const TxPlan plan = parseTxPlan(result);
            if (!plan.ok || plan.broadcast) { // a dry run must not have broadcast anything
                setError(plan.ok ? tr("Unexpected answer from the wallet: the check was not a dry run. Nothing more was done; look at your transactions before trying again.")
                                 : plan.error);
                return;
            }
            sentToken_ = token;
            check_ = check;
            plan_ = plan;
            reviewLabel_->setText(sendReviewText(token, check, plan));
            showPage(ReviewPage);
        },
        [this](const QString& message) {
            setBusy(false);
            setError(friendlyError(message));
        });
}

void TokenSendDialog::onSend()
{
    setBusy(true);
    rpc_->call(QStringLiteral("zslp_send"), sendParams(sentToken_, check_, /*dryRun=*/false),
        [this](const json& result) {
            setBusy(false);
            const TxPlan plan = parseTxPlan(result);
            if (!plan.ok || !plan.broadcast) {
                resultLabel_->setText(tr("The transaction was not sent.\n\n%1").arg(plan.ok ? tr("The wallet did not broadcast it.") : plan.error));
                showPage(ResultPage);
                return;
            }
            plan_ = plan;
            sendButton_->setEnabled(false); // never send twice from one review
            resultLabel_->setText(sendResultText(sentToken_, check_, plan));
            showPage(ResultPage);
            emit sent(plan.txid);
        },
        [this](const QString& message) {
            setBusy(false);
            resultLabel_->setText(tr("The transaction was not sent.\n\n%1").arg(friendlyError(message)));
            showPage(ResultPage);
        });
}

// ---- create ------------------------------------------------------------------------------------

TokenCreateDialog::TokenCreateDialog(TokensRpc* rpc, QWidget* parent) : StepDialog(rpc, parent)
{
    setWindowTitle(tr("Create token"));
    setObjectName(QStringLiteral("tokenCreateDialog"));
    resize(620, 560);

    auto* form = new QWidget(this);
    auto* outer = new QVBoxLayout(form);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* explain = plainLabel(createExplanation(), form);
    explain->setObjectName(QStringLiteral("explainLabel"));
    outer->addWidget(explain);
    auto* fl = new QFormLayout;
    tickerEdit_ = new QLineEdit(form);
    tickerEdit_->setObjectName(QStringLiteral("tickerEdit"));
    tickerEdit_->setMaxLength(10);
    nameEdit_ = new QLineEdit(form);
    nameEdit_->setObjectName(QStringLiteral("nameEdit"));
    nameEdit_->setMaxLength(64);
    decimalsEdit_ = new QLineEdit(QStringLiteral("0"), form);
    decimalsEdit_->setObjectName(QStringLiteral("decimalsEdit"));
    quantityEdit_ = new QLineEdit(form);
    quantityEdit_->setObjectName(QStringLiteral("quantityEdit"));
    urlEdit_ = new QLineEdit(form);
    urlEdit_->setObjectName(QStringLiteral("urlEdit"));
    hashEdit_ = new QLineEdit(form);
    hashEdit_->setObjectName(QStringLiteral("hashEdit"));
    batonBox_ = new QCheckBox(tr("Keep a mint baton (lets me create more of this token later)"), form);
    batonBox_->setObjectName(QStringLiteral("batonBox"));
    batonBox_->setChecked(true);
    fl->addRow(tr("Ticker"), tickerEdit_);
    fl->addRow(tr("Name"), nameEdit_);
    fl->addRow(tr("Decimal places (0-8)"), decimalsEdit_);
    fl->addRow(tr("First supply"), quantityEdit_);
    fl->addRow(tr("Document link (optional)"), urlEdit_);
    fl->addRow(tr("Document hash (optional, 64 hex)"), hashEdit_);
    fl->addRow(batonBox_);
    outer->addLayout(fl);

    buildChrome(form, tr("Create token"));
}

GenesisDraft TokenCreateDialog::draft() const
{
    GenesisDraft d;
    d.ticker = tickerEdit_->text();
    d.name = nameEdit_->text();
    d.decimals = decimalsEdit_->text();
    d.quantity = quantityEdit_->text();
    d.url = urlEdit_->text();
    d.hash = hashEdit_->text();
    d.baton = batonBox_->isChecked();
    return d;
}

void TokenCreateDialog::onReview()
{
    setError(QString());
    const GenesisDraft d = draft();
    const GenesisCheck check = checkGenesis(d);
    if (!check.ok) {
        setError(check.error);
        return;
    }
    setBusy(true);
    rpc_->call(QStringLiteral("zslp_genesis"), genesisParams(d, check, /*dryRun=*/true),
        [this, d, check](const json& result) {
            setBusy(false);
            const TxPlan plan = parseTxPlan(result);
            if (!plan.ok || plan.broadcast) {
                setError(plan.ok ? tr("Unexpected answer from the wallet: the check was not a dry run. Look at your transactions before trying again.")
                                 : plan.error);
                return;
            }
            sentDraft_ = d;
            check_ = check;
            plan_ = plan;
            reviewLabel_->setText(genesisReviewText(d, check, plan));
            showPage(ReviewPage);
        },
        [this](const QString& message) {
            setBusy(false);
            setError(friendlyError(message));
        });
}

void TokenCreateDialog::onSend()
{
    setBusy(true);
    rpc_->call(QStringLiteral("zslp_genesis"), genesisParams(sentDraft_, check_, /*dryRun=*/false),
        [this](const json& result) {
            setBusy(false);
            const TxPlan plan = parseTxPlan(result);
            if (!plan.ok || !plan.broadcast) {
                resultLabel_->setText(tr("The token was not created.\n\n%1").arg(plan.ok ? tr("The wallet did not broadcast it.") : plan.error));
                showPage(ResultPage);
                return;
            }
            plan_ = plan;
            sendButton_->setEnabled(false);
            resultLabel_->setText(genesisResultText(sentDraft_, check_, plan));
            showPage(ResultPage);
            emit sent(plan.txid);
        },
        [this](const QString& message) {
            setBusy(false);
            resultLabel_->setText(tr("The token was not created.\n\n%1").arg(friendlyError(message)));
            showPage(ResultPage);
        });
}

} // namespace tokens
