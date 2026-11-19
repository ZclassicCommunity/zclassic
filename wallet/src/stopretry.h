#ifndef STOPRETRY_H
#define STOPRETRY_H

// Re-send the RPC "stop" to the embedded node while the wallet closes, only as long as needed.
//
// The close path (RPC::shutdownZClassicd) sends `stop` exactly once and ignores the answer. A
// lost stop comes from a refused port (the node is still starting and not listening yet), a
// 401 (credentials not matching yet) or a dropped connection. This tree's node lets `stop`
// through during warm-up (src/rpc/server.cpp:480-489), so a -28 is not the normal cause.
// The one request is then never repeated and the node is not asked to stop. This sends it
// again, one request at a time, driven by the shutdown wait loop's timer (tick()): no
// thread, no new timeout, no earlier kill. The wait's own cap is unchanged.
//
// It stops as soon as more requests would be pointless:
//   * the node answered 200 (stop accepted);
//   * the node answers 503 (its HTTP server is shutting down), or refuses / drops the
//     connection after having been reachable (it is exiting).
// A refused port BEFORE the node was ever reachable keeps retrying: that is the start-up
// case this exists for.
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
    enum Outcome { Delivered, Retry, GiveUp };

    // `intervalMs`: minimum gap between two attempts (an attempt in flight is never doubled).
    explicit StopRetrier(Connection* c, int intervalMs = 1000) : conn(c), interval(intervalMs),
        st(std::make_shared<State>()) { clock.start(); }
    ~StopRetrier() { st->alive = false; }
    StopRetrier(const StopRetrier&) = delete;
    StopRetrier& operator=(const StopRetrier&) = delete;

    // Send a stop if none is delivered/in flight and the interval has passed.
    void tick() {
        if (!conn || !conn->restclient || !conn->request) return;
        if (!shouldSend(st->delivered || st->gaveUp, st->inFlight, attempts_, lastMs, clock.elapsed(), interval)) return;
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
            const int http = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            switch (classify(reply->error(), http, s->reachable)) {
                case Delivered: s->delivered = true; break;
                case GiveUp:    s->gaveUp = true; break;
                case Retry:     break;
            }
            if (http > 0) s->reachable = true;      // any HTTP answer: the node is listening
        });
    }

    // The caller already sent the first stop itself (its answer is not visible here): count it
    // and wait one interval before repeating.
    void noteFirstSentElsewhere() { attempts_ = 1; lastMs = clock.elapsed(); st->inFlight = false; }

    bool delivered() const { return st->delivered; }
    bool gaveUp() const { return st->gaveUp; }
    int attempts() const { return attempts_; }

    // Pure decisions (pinned by tests). `http` is 0 when there was no HTTP answer at all.
    static Outcome classify(QNetworkReply::NetworkError e, int http, bool reachableBefore) {
        if (e == QNetworkReply::NoError) return Delivered;
        if (http == 503) return GiveUp;                    // HTTP server is shutting down
        if (http > 0) return Retry;                        // 500/-28, 401...: listening, not accepted yet
        return reachableBefore ? GiveUp : Retry;           // refused/dropped: exiting, or not up yet
    }
    static bool isDelivered(QNetworkReply::NetworkError e) { return e == QNetworkReply::NoError; }
    static bool shouldSend(bool done, bool inFlight, int attempts, qint64 lastMs, qint64 nowMs, int intervalMs) {
        if (done || inFlight) return false;
        return attempts == 0 || nowMs - lastMs >= intervalMs;
    }

private:
    struct State { bool alive = true; bool delivered = false; bool gaveUp = false; bool inFlight = false; bool reachable = false; };
    Connection* conn;
    int interval;
    std::shared_ptr<State> st;
    QElapsedTimer clock;
    int attempts_ = 0;
    qint64 lastMs = 0;
};

#endif // STOPRETRY_H
