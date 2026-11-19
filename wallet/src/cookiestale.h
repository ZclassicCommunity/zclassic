#ifndef COOKIESTALE_H
#define COOKIESTALE_H

// First-launch auth race. The node binds its RPC port (InitHTTPServer) before it writes
// its auth cookie (StartHTTPRPC). On a fresh profile the node reaches that point within a
// second of starting, so the wallet's first poll can read "no cookie yet", send empty
// credentials, have the connection accepted by the already-bound port, and be answered
// 401 a moment later when the node is serving and the cookie exists. That 401 is not a
// credential desync: the cookie on disk now differs from what the request carried.
// Treating it as one made the wallet kill the node it had just started and start it a
// second time (two process launches, two firewall prompts).
//
// Only a 401 whose request used something OTHER than the cookie now on disk is
// "stale-by-timing" and is simply retried with the current cookie. A 401 that carried the
// current cookie (or where no cookie exists) is a real mismatch and still takes the heal
// path.

#include <QString>

namespace CookieStale {

// `cookieLine` is the first line of the cookie file ("__cookie__:<secret>", "" when absent).
// True when the cookie exists and the request did not carry exactly it.
inline bool sentCredsAreStale(const QString& sentUser, const QString& sentPass, const QString& cookieLine) {
    if (cookieLine.isEmpty()) return false;               // no cookie on disk: nothing newer to retry with
    return (sentUser + QLatin1Char(':') + sentPass) != cookieLine;
}

} // namespace CookieStale

#endif // COOKIESTALE_H
