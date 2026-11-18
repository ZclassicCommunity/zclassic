// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The two dialogs of the Tokens window that change something: "Send tokens" and "Create token".
// They are independent of MainWindow and of the network: everything they ask of the daemon goes
// through a TokensRpc, which the Tokens window implements with the wallet's connection and the tests
// implement with a fake. The ZCL send flow is not touched.
//
// Both follow the pattern of the ZCL send flow: a form, then a REVIEW page that shows what will happen
// (the daemon has already built and checked the transaction, as a dry run, so the fee is exact), then
// the send itself, then a result page. Nothing is broadcast before the user presses the send button on
// the review page.
#ifndef ZCL_TOKENSSEND_H
#define ZCL_TOKENSSEND_H

#include <QDialog>
#include <QVector>

#include <functional>

#include "tokenssendmodel.h"

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QStackedWidget;

namespace tokens {

// What the dialogs need from the daemon. `call` answers exactly once, through ok or fail (fail gets the
// daemon's own message).
class TokensRpc {
public:
    virtual ~TokensRpc() {}
    virtual void call(const QString& method, const nlohmann::json& params,
                      std::function<void(const nlohmann::json&)> ok,
                      std::function<void(const QString&)> fail) = 0;
};

// Shared page machinery: form (0), review (1), result (2).
class StepDialog : public QDialog {
    Q_OBJECT
public:
    enum Page { FormPage = 0, ReviewPage = 1, ResultPage = 2 };
    int page() const;

signals:
    // a transaction was accepted by the node
    void sent(const QString& txid);

protected:
    StepDialog(TokensRpc* rpc, QWidget* parent);
    void buildChrome(QWidget* form, const QString& sendText);
    void setError(const QString& text);
    void setBusy(bool busy);
    void showPage(Page p);

    TokensRpc* rpc_;
    QStackedWidget* stack_ = nullptr;
    QLabel* errorLabel_ = nullptr;
    QLabel* reviewLabel_ = nullptr;
    QLabel* resultLabel_ = nullptr;
    QPushButton* reviewButton_ = nullptr;
    QPushButton* backButton_ = nullptr;
    QPushButton* sendButton_ = nullptr;
    QPushButton* cancelButton_ = nullptr;
    QPushButton* closeButton_ = nullptr;
    bool busy_ = false;

    // what the review and send buttons do; not slots, the buttons are wired with lambdas
    virtual void onReview() = 0;
    virtual void onSend() = 0;
};

class TokenSendDialog : public StepDialog {
    Q_OBJECT
public:
    TokenSendDialog(TokensRpc* rpc, const QVector<TokenChoice>& choices, QWidget* parent = nullptr);

private:
    void onReview() override;
    void onSend() override;

private slots:
    void onTokenChanged();
    void onMax();

private:
    TokenChoice current() const;
    QVector<TokenChoice> choices_;
    QComboBox* tokenBox_ = nullptr;
    QLabel* availableLabel_ = nullptr;
    QLineEdit* toEdit_ = nullptr;
    QLineEdit* amountEdit_ = nullptr;
    QPushButton* maxButton_ = nullptr;
    SendCheck check_;
    TokenChoice sentToken_;
    TxPlan plan_;
};

class TokenCreateDialog : public StepDialog {
    Q_OBJECT
public:
    explicit TokenCreateDialog(TokensRpc* rpc, QWidget* parent = nullptr);

private:
    void onReview() override;
    void onSend() override;

private:
    GenesisDraft draft() const;
    QLineEdit* tickerEdit_ = nullptr;
    QLineEdit* nameEdit_ = nullptr;
    QLineEdit* decimalsEdit_ = nullptr;
    QLineEdit* quantityEdit_ = nullptr;
    QLineEdit* urlEdit_ = nullptr;
    QLineEdit* hashEdit_ = nullptr;
    QCheckBox* batonBox_ = nullptr;
    GenesisDraft sentDraft_;
    GenesisCheck check_;
    TxPlan plan_;
};

} // namespace tokens

#endif // ZCL_TOKENSSEND_H
