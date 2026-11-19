#ifndef CLOSEFLOW_H
#define CLOSEFLOW_H

// Feedback and stop delivery while the wallet closes (MainWindow::closeEvent).
//
// 1. A visible "Closing: stopping the ZClassic node safely..." notice appears on the
//    first close request, before anything can wait (the node's own wait dialog only
//    appears after a delay, and nothing is shown while the node is still starting).
// 2. `stop` is re-sent every 500 ms until the node accepts it (see stopretry.h), driven
//    by a timer that runs inside the nested wait loop of RPC::shutdownZClassicd. It adds
//    no timeout and never ends a wait earlier: the existing wait is untouched.

#include <QApplication>
#include <QCoreApplication>
#include <QDialog>
#include <QLabel>
#include <QProcess>
#include <QTimer>
#include <QVBoxLayout>

#include "rpc.h"
#include "settings.h"
#include "stopretry.h"

namespace CloseFlow {

inline QString noticeText() { return QStringLiteral("Closing: stopping the ZClassic node safely\u2026"); }
inline QString noticeDetail() {
    return QStringLiteral("The node is saving its data. This can take a while if it is still starting. "
                          "Please keep this window open.");
}

// Modeless notice, painted before this returns. Parent owns it.
inline QDialog* showNotice(QWidget* owner) {
    auto* d = new QDialog(owner);
    d->setObjectName(QStringLiteral("closingNotice"));
    d->setWindowTitle(QStringLiteral("ZClassic"));
    d->setModal(false);
    auto* lay = new QVBoxLayout(d);
    auto* head = new QLabel(noticeText(), d);
    head->setObjectName(QStringLiteral("closingNoticeStatus"));
    QFont f = head->font(); f.setBold(true); head->setFont(f);
    auto* sub = new QLabel(noticeDetail(), d);
    sub->setWordWrap(true);
    lay->addWidget(head);
    lay->addWidget(sub);
    d->setMinimumWidth(420);
    d->show();
    d->raise();
    QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    return d;
}

// Lives across the shutdown call. The first stop is sent by shutdownZClassicd itself;
// this only repeats it.
class Assist {
public:
    Assist(QWidget* owner, RPC* r) : rpc(r), conn(r ? r->getConnection() : nullptr), stopper(conn, 500) {
        if (!Settings::getInstance()->isHeadless())
            notice = showNotice(owner);
        stopper.noteFirstSentElsewhere();
        timer = new QTimer(owner);
        QObject::connect(timer, &QTimer::timeout, timer, [this]() { pump(); });
        timer->start(150);
        // When the node is ours and RPC is attached, shutdownZClassicd shows its own wait
        // dialog after a short delay: hand over to it so two dialogs never stack.
        if (notice && conn && rpc->isEmbedded())
            QTimer::singleShot(600, notice, [d = notice]() { d->hide(); });
    }
    ~Assist() { delete timer; }   // the notice stays: the application is quitting
    Assist(const Assist&) = delete;
    Assist& operator=(const Assist&) = delete;

private:
    void pump() {
        if (!conn || rpc->getConnection() != conn) return;
        const QProcess* p = rpc->getEZClassicD();
        if (p && p->state() != QProcess::NotRunning) stopper.tick();
    }
    RPC* rpc;
    Connection* conn;
    StopRetrier stopper;
    QTimer* timer = nullptr;
    QDialog* notice = nullptr;
};

} // namespace CloseFlow

#endif // CLOSEFLOW_H
