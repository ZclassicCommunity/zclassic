// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// "Tokens" view. It appears (a rail button, and a window it opens) only
// when the daemon reports that its ZSLP token index is switched on
// (zslp_getindexinfo answers; with the index off the daemon answers with an error
// and nothing is shown). It lists the wallet's token balances and token outputs and
// says plainly that those outputs are protected from ordinary spending. From it the user can send tokens
// and, as an advanced step, create a token (src/tokenssend.*); the ZCL send flow is not involved.
#ifndef ZCL_TOKENSVIEW_H
#define ZCL_TOKENSVIEW_H

#include <QObject>

#include <memory>

#include "pollguard.h"
#include "tokensmodel.h"
#include "tokenssend.h"

class MainWindow;
class QDialog;
class QLabel;
class QPushButton;
class QTableWidget;
class QTimer;

class TokensView : public QObject {
    Q_OBJECT
public:
    // Creates the view as a child of `main` (so it is deleted with it) and starts
    // polling the daemon. This is the whole registration: one call from MainWindow.
    static TokensView* install(MainWindow* main);

private slots:
    void poll();
    void openWindow();
    void openSend();
    void openCreate();

private:
    explicit TokensView(MainWindow* main);
    void ensureRailButton();
    void setAvailable(bool available);
    void applyStatus(const tokens::IndexStatus& status);
    void applySnapshot(const tokens::Snapshot& snap);
    void refreshOutputs();
    void updateActionButtons();

    MainWindow*   main_;
    QTimer*       timer_;
    QDialog*      dialog_      = nullptr;
    QLabel*       statusLabel_ = nullptr;
    QLabel*       emptyLabel_  = nullptr;
    QTableWidget* balances_    = nullptr;
    QTableWidget* outputs_     = nullptr;
    QPushButton*  railButton_  = nullptr;
    QPushButton*  sendButton_  = nullptr;
    QPushButton*  createButton_ = nullptr;
    tokens::Snapshot lastSnap_;
    bool          indexSynced_ = false;
    std::unique_ptr<tokens::TokensRpc> rpc_;
    bool          available_   = false;
    PollGuard     pollGuard_;   // one poll at a time, never stuck by a restart (see pollguard.h)
};

#endif // ZCL_TOKENSVIEW_H
