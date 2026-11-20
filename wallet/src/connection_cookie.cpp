#include "connection.h"
#include "cookiestale.h"
#include "mainwindow.h"

#include <QTimer>

// First-launch race (see cookiestale.h). `sent` is the config the failed request was built
// from. Returns true when the 401 was only a timing artefact and a re-poll is scheduled.
bool ConnectionLoader::retryWithCurrentCookie(const std::shared_ptr<ConnectionConfig>& sent) {
    if (!sent || !CookieStale::shouldRetry(sent->cookieAuth, sent->rpcuser, sent->rpcpassword,
                                           readAuthCookie(sent), cookieRetry))
        return false;
    main->logger->write("Sign-in predates the node's current cookie; retrying (no restart)");
    const auto alive = ezAlive;
    QTimer::singleShot(250, [=]() { if (alive && *alive) doAutoConnect(); });
    return true;
}

// The 401 handler for an owned node: retry first (bounded), restart only if the
// credentials are genuinely stale (the request carried the current cookie, the retry
// budget is spent, or the credentials came from the conf).
bool ConnectionLoader::retryOrHealAuth(const std::shared_ptr<ConnectionConfig>& sent) {
    return retryWithCurrentCookie(sent) || handleEmbeddedAuthFailure();
}
