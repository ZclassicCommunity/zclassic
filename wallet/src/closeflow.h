#ifndef CLOSEFLOW_H
#define CLOSEFLOW_H

// Feedback and stop delivery while the wallet closes (MainWindow::closeEvent).
//
// 1. A visible notice appears on the first close request, before anything can wait (the
//    node's own wait dialog only appears after a delay, and nothing is shown while the node
//    is still starting). It says "stopping the ZClassic node safely" only when the wallet
//    owns a running node; otherwise a neutral "Closing...".
//    It is painted with show() + repaint(), NOT by running the event loop: until
//    RPC::shutdownZClassicd has set its expected-shutdown flag, a delivered poll error or
//    process-finished event would be handled as an unexpected failure (error box, crash
//    handler, restart), so no queued event may run between the close click and that flag.
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

// Modeless notice, painted before this returns without delivering any queued event.
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
    d->repaint();           // synchronous paint of this widget only; no event loop
    return d;
}

// Lives across the shutdown call. The first stop is sent by shutdownZClassicd itself;
// this only repeats it.
class Assist {
public:
    Assist(QWidget* owner, RPC* r) : rpc(r), conn(r ? r->getConnection() : nullptr), stopper(conn, 1000) {
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
