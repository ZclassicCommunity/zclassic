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
//   * the node answers 503 that is NOT the JSON "RPC server busy" reply (that is
//     http_reject_request_cb, src/httpserver.cpp:351: the HTTP server is shutting down);
//   * a connection is REFUSED after the node had been reachable (it has closed its port).
// A 503 busy reply (work queue full, src/httpserver.cpp:343), a reset or a timeout keep
// retrying: a busy node is still running and has not taken the stop. A refused port BEFORE the
// node was ever reachable keeps retrying too: that is the start-up case this exists for.
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
            const bool busy = http == 503 && isBusyReply(reply->header(QNetworkRequest::ContentTypeHeader).toString(),
                                                         reply->readAll());
            switch (classify(reply->error(), http, s->reachable, busy)) {
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
    // The node busy reply: 503 with a JSON body naming the full work queue.
    static bool isBusyReply(const QString& contentType, const QByteArray& body) {
        return contentType.contains(QLatin1String("application/json"), Qt::CaseInsensitive) &&
               body.contains("RPC server busy");
    }
    static Outcome classify(QNetworkReply::NetworkError e, int http, bool reachableBefore, bool busy503 = false) {
        if (e == QNetworkReply::NoError) return Delivered;
        if (http == 503) return busy503 ? Retry : GiveUp;  // busy: still running; else: HTTP server shutting down
        if (http > 0) return Retry;                        // 500/-28, 401...: listening, not accepted yet
        // no answer: only a refused connection after being reachable means the port is closed;
        // a reset or a timeout may be a busy node, keep going
        return (reachableBefore && e == QNetworkReply::ConnectionRefusedError) ? GiveUp : Retry;
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
