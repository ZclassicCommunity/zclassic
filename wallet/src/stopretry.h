#ifndef STOPRETRY_H
#define STOPRETRY_H

// Deliver the RPC "stop" to the embedded node reliably when the wallet closes.
//
// The close path used to send `stop` exactly once and ignore the answer. While the
// node is still starting (snapshot download, loading the block index) the RPC port
// refuses connections or answers a warm-up error (-28), so that one request was lost
// and the node was never asked to stop: the wallet then waited out its whole cap with
// the node still running and quit into a hard kill. This sends `stop` again, one
// request at a time, until the node accepts it (HTTP 200). It is driven by the
// shutdown wait loop's timer (tick()), so it adds no thread, no new timeout and no
// earlier kill: the cap stays whatever the caller already had.
//
// Requests are posted straight on the Connection's network manager: Connection::doRPC
// refuses everything once Connection::shutdown() has been called, which the close path
// does right after the first stop.

#include <QElapsedTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <memory>

#include "connection.h"

class StopRetrier {
public:
    // `intervalMs`: minimum gap between two attempts (an attempt in flight is never doubled).
    explicit StopRetrier(Connection* c, int intervalMs = 500) : conn(c), interval(intervalMs),
        st(std::make_shared<State>()) { clock.start(); }
    ~StopRetrier() { st->alive = false; }
    StopRetrier(const StopRetrier&) = delete;
    StopRetrier& operator=(const StopRetrier&) = delete;

    // Send a stop if none is delivered/in flight and the interval has passed.
    void tick() {
        if (!conn || !conn->restclient || !conn->request) return;
        if (!shouldSend(st->delivered, st->inFlight, attempts_, lastMs, clock.elapsed(), interval)) return;
        attempts_++;
        lastMs = clock.elapsed();
        st->inFlight = true;
        const QByteArray body = QByteArrayLiteral(
            "{\"jsonrpc\":\"1.0\",\"id\":\"someid\",\"method\":\"stop\",\"params\":[]}");
        QNetworkReply* reply = conn->restclient->post(*conn->request, body);
        const std::shared_ptr<State> s = st;
        QObject::connect(reply, &QNetworkReply::finished, reply, [s, reply]() {
            reply->deleteLater();
            if (!s->alive) return;
            s->inFlight = false;
            if (isDelivered(reply->error())) s->delivered = true;   // else: refused / -28 / dropped: retry
        });
    }

    // The caller already sent the first stop itself: count it, and wait one interval before repeating.
    void noteFirstSentElsewhere() { attempts_ = 1; lastMs = clock.elapsed(); st->inFlight = false; }

    bool delivered() const { return st->delivered; }
    int attempts() const { return attempts_; }

    // Pure decisions (pinned by tests).
    static bool isDelivered(QNetworkReply::NetworkError e) { return e == QNetworkReply::NoError; }
    static bool shouldSend(bool delivered, bool inFlight, int attempts, qint64 lastMs, qint64 nowMs, int intervalMs) {
        if (delivered || inFlight) return false;
        return attempts == 0 || nowMs - lastMs >= intervalMs;
    }

private:
    struct State { bool alive = true; bool delivered = false; bool inFlight = false; };
    Connection* conn;
    int interval;
    std::shared_ptr<State> st;
    QElapsedTimer clock;
    int attempts_ = 0;
    qint64 lastMs = 0;
};

#endif // STOPRETRY_H
