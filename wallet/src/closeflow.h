#ifndef CLOSEFLOW_H
#define CLOSEFLOW_H

// Feedback and stop delivery while the wallet closes (MainWindow::closeEvent).
//
// 1. A visible notice appears on the first close request, before anything can wait (the
//    node's own wait dialog only appears after a delay, and nothing is shown while the node
//    is still starting). It says "stopping the ZClassic node safely" only when the wallet
//    owns a running node; otherwise a neutral "Closing...".
//    It needs one pass of the event loop to really be on screen (show()+repaint() alone
//    paints nothing under xcb). So RPC::noteExpectedShutdown() is called FIRST: it sets the
//    same expected-shutdown flag shutdownZClassicd sets, and the handlers that could run
//    during that pass (the "Connection Error" box, handleEZClassicdCrash, the restart it
//    queues) already stay quiet once it is set. User input is excluded from that pass.
// 2. `stop` is re-sent every second until the node accepts it or is clearly exiting (see
//    stopretry.h), driven by a timer inside the nested wait loop of shutdownZClassicd. It adds
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

inline QString noticeText(bool ownedNode) {
    return ownedNode ? QStringLiteral("Closing: stopping the ZClassic node safely…")
                     : QStringLiteral("Closing…");
}
inline QString noticeDetail(bool ownedNode) {
    return ownedNode ? QStringLiteral("The node is saving its data. This can take a while if it is still starting. "
                                      "Please keep this window open.")
                     : QStringLiteral("The wallet is closing.");
}

// True when this wallet owns a node process that is still running.
inline bool ownsRunningNode(RPC* rpc) {
    const QProcess* p = rpc ? rpc->getEZClassicD() : nullptr;
    return rpc && rpc->isEmbedded() && p && p->state() != QProcess::NotRunning;
}

// Modeless notice, really painted before this returns (one event-loop pass, no user input).
// The caller must already have called RPC::noteExpectedShutdown().
inline QDialog* showNotice(QWidget* owner, bool ownedNode) {
    auto* d = new QDialog(owner);
    d->setObjectName(QStringLiteral("closingNotice"));
    d->setWindowTitle(QStringLiteral("ZClassic"));
    d->setModal(false);
    auto* lay = new QVBoxLayout(d);
    auto* head = new QLabel(noticeText(ownedNode), d);
    head->setObjectName(QStringLiteral("closingNoticeStatus"));
    QFont f = head->font(); f.setBold(true); head->setFont(f);
    auto* sub = new QLabel(noticeDetail(ownedNode), d);
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
    Assist(QWidget* owner, RPC* r) : rpc(r), conn(r ? r->getConnection() : nullptr), stopper(conn, 1000) {
        if (r) r->noteExpectedShutdown();   // before anything can run: see the header comment
        const bool owned = ownsRunningNode(r);
        if (!Settings::getInstance()->isHeadless())
            notice = showNotice(owner, owned);
        stopper.noteFirstSentElsewhere();
        timer = new QTimer(owner);
        QObject::connect(timer, &QTimer::timeout, timer, [this]() { pump(); });
        timer->start(150);
        // When the node is ours and RPC is attached, shutdownZClassicd shows its own wait
        // dialog after a short delay: hand over to it so two dialogs never stack.
        if (notice && conn && owned)
            QTimer::singleShot(600, notice, [d = notice]() { d->hide(); });
    }
    ~Assist() { delete timer; }   // the notice stays: the application is quitting
    Assist(const Assist&) = delete;
    Assist& operator=(const Assist&) = delete;

private:
    void pump() {
        if (!conn || rpc->getConnection() != conn) return;
        if (ownsRunningNode(rpc)) stopper.tick();
    }
    RPC* rpc;
    Connection* conn;
    StopRetrier stopper;
    QTimer* timer = nullptr;
    QDialog* notice = nullptr;
};

} // namespace CloseFlow

#endif // CLOSEFLOW_H
