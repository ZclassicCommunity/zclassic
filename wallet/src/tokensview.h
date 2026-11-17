// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Read-only "Tokens" view. It appears (a rail button, and a window it opens) only
// when the daemon reports that its ZSLP token index is switched on
// (zslp_getindexinfo answers; with the index off the daemon answers with an error
// and nothing is shown). It lists the wallet's token balances and token outputs and
// says plainly that those outputs are protected from ordinary spending. It sends
// nothing and changes nothing.
#ifndef ZCL_TOKENSVIEW_H
#define ZCL_TOKENSVIEW_H

#include <QObject>

#include "tokensmodel.h"

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

private:
    explicit TokensView(MainWindow* main);
    void ensureRailButton();
    void setAvailable(bool available);
    void applyStatus(const tokens::IndexStatus& status);
    void applySnapshot(const tokens::Snapshot& snap);
    void refreshOutputs();

    MainWindow*   main_;
    QTimer*       timer_;
    QDialog*      dialog_      = nullptr;
    QLabel*       statusLabel_ = nullptr;
    QLabel*       emptyLabel_  = nullptr;
    QTableWidget* balances_    = nullptr;
    QTableWidget* outputs_     = nullptr;
    QPushButton*  railButton_  = nullptr;
    bool          available_   = false;
    bool          inFlight_    = false;
};

#endif // ZCL_TOKENSVIEW_H
