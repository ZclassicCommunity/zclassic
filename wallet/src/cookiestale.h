#ifndef COOKIESTALE_H
#define COOKIESTALE_H

// First-launch auth race. The node binds its RPC port (InitHTTPServer) before it writes its
// auth cookie (StartHTTPRPC). On a fresh profile the node reaches that point within a second
// of starting, so the wallet's first poll can read "no cookie yet", send empty credentials,
// have the connection accepted by the already-bound port, and be answered 401 a moment later
// when the node is serving and the cookie exists. That 401 is not a credential desync: the
// cookie on disk now differs from what the request carried. Treating it as one made the
// wallet kill the node it had just started and start it a second time (two process launches,
// two firewall prompts).
//
// A 401 is retried (instead of healed) only when ALL hold:
//   * the request's credentials came from the cookie path or were empty (never conf
//     rpcuser/rpcpassword: those are rebuilt identically on every poll, a retry cannot help);
//   * a cookie exists and the request did not carry exactly it;
//   * that cookie is not the one a previous retry already used (a hash is remembered);
//   * fewer than kMaxRetries retries were made by this loader.
// Anything else falls through to the one-shot heal, so the heal can never be starved by a
// retry loop (a leftover .cookie from a killed node plus a node that keeps answering 401).

#include <QByteArray>
#include <QCryptographicHash>
#include <QString>

namespace CookieStale {

enum { kMaxRetries = 2 };

struct RetryState {
    QByteArray lastHash;   // SHA-256 of the cookie line last retried against (never the cookie itself)
    int retries = 0;
};

// `cookieLine` is the first line of the cookie file ("__cookie__:<secret>", "" when absent).
// True when the cookie exists and the request did not carry exactly it.
inline bool sentCredsAreStale(const QString& sentUser, const QString& sentPass, const QString& cookieLine) {
    if (cookieLine.isEmpty()) return false;               // no cookie on disk: nothing newer to retry with
    return (sentUser + QLatin1Char(':') + sentPass) != cookieLine;
}

// Were the sent credentials taken from the cookie path (cookieAuth) or empty? Conf
// rpcuser/rpcpassword are neither.
inline bool sentFromCookiePath(bool cookieAuth, const QString& user, const QString& pass) {
    return cookieAuth || (user.isEmpty() && pass.isEmpty());
}

// The whole decision. Updates `st` only when it answers true.
inline bool shouldRetry(bool cookieAuth, const QString& user, const QString& pass,
                        const QString& cookieLine, RetryState& st) {
    if (!sentFromCookiePath(cookieAuth, user, pass)) return false;
    if (!sentCredsAreStale(user, pass, cookieLine)) return false;
    if (st.retries >= kMaxRetries) return false;
    const QByteArray h = QCryptographicHash::hash(cookieLine.toUtf8(), QCryptographicHash::Sha256);
    if (h == st.lastHash) return false;                   // already retried against this very cookie
    st.lastHash = h;
    st.retries++;
    return true;
}

} // namespace CookieStale

#endif // COOKIESTALE_H
