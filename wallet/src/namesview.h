// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// A small "Names" window: the names this wallet owns, and forms to register a new name and to change where one of
// them points. It appears (a rail button, and the window it opens) only when the daemon reports that its name index is
// switched on (znam_getindexinfo). It lists and changes nothing else, and sending money to a name is not done here: see
// the "Pay to" field of the Send tab (src/namepaybox.h).
#ifndef ZCL_NAMESVIEW_H
#define ZCL_NAMESVIEW_H

#include <QObject>

#include "namesmodel.h"
#include "pollguard.h"

class MainWindow;
class QDialog;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTimer;

class NamesView : public QObject {
    Q_OBJECT
public:
    // Creates the view as a child of `main` and starts polling the daemon. The whole registration is this one call.
    static NamesView* install(MainWindow* main);

private slots:
    void poll();
    void openWindow();
    void registerClicked();
    void updateClicked();

private:
    explicit NamesView(MainWindow* main);
    void ensureRailButton();
    void setAvailable(bool available);
    void refreshNames();
    void sendOperation(const char* method, const QString& name, const QString& target, const QString& what);

    MainWindow*   main_;
    QTimer*       timer_;
    QDialog*      dialog_      = nullptr;
    QLabel*       statusLabel_ = nullptr;
    QLabel*       emptyLabel_  = nullptr;
    QTableWidget* table_       = nullptr;
    QLineEdit*    regName_     = nullptr;
    QLineEdit*    regTarget_   = nullptr;
    QLineEdit*    updTarget_   = nullptr;
    QPushButton*  railButton_  = nullptr;
    bool          available_   = false;
    PollGuard     pollGuard_;   // one poll at a time, never stuck by a restart (see pollguard.h)
};

#endif // ZCL_NAMESVIEW_H
