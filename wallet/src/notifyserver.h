#ifndef NOTIFYSERVER_H
#define NOTIFYSERVER_H

#include <QObject>
#include <QString>
#include <QByteArray>

class QLocalServer;
class QLocalSocket;

// ============================================================================
// NotifyServer (NOTIFY-SRV) — a localhost-only, token-gated trigger the GUI
// stands up so the embedded zclassicd can PUSH wallet/block events (via
// -walletnotify/-blocknotify invoking the GUI's own `--notify` connector)
// instead of the GUI polling on a fixed timer. It carries NO wallet data: a
// validated notify is only a kick to run the normal authenticated balance
// refresh. Security invariants (all enforced here; see SPEC NOTIFY-SRV):
//
//   * Transport: a QLocalServer — a unix-domain socket created owner-only (0600
//     via UserAccessOption + umask) on Linux/macOS; a user-restricted-DACL named
//     pipe on Windows. Never a routable/TCP bind, so there is no network surface
//     and no "other local user dials 127.0.0.1:port" exposure.
//   * A per-session >=128-bit CSPRNG token (securerandom.h: 64 lowercase-hex =
//     256 bits) gates EVERY notify. A wrong / short / absent token is dropped
//     BEFORE `notified()` is emitted, via a length-checked CONSTANT-TIME compare
//     (no first-mismatch early-out timing oracle on the token value).
//   * The id after the token MUST match ^[0-9a-f]{64}$ (a txid / blockhash);
//     anything else is dropped — no shell / file / RPC injection can ride the
//     payload into a refresh.
//   * Reads are hard-capped at kMaxBytes; a connection that has not delivered a
//     complete valid line within kIdleMs is reaped (slow-loris / dribble).
//   * A successful notify grants NO data: the peer receives only "OK\n". The
//     socket is an un-spoofable trigger, not a data channel.
//   * stop()/dtor tears the server down and removes the socket; the in-memory
//     token dies with the object. A fresh token is minted per construction
//     (per GUI session), so a token from a previous session is dead.
// ============================================================================
class NotifyServer : public QObject {
    Q_OBJECT
public:
    explicit NotifyServer(QObject* parent = nullptr);
    ~NotifyServer() override;

    // Start listening on the unix-socket path `socketPath` (the caller chooses it;
    // in production it lives in the wallet datadir). A stale socket file from a
    // crashed prior session is cleared first. Returns true iff the server is up.
    // Idempotent: a second call with the server already listening is a no-op true.
    bool start(const QString& socketPath);
    void stop();

    bool    isListening() const;
    QString token() const { return sessionToken; }   // the per-session secret (64 hex)
    QString socketPath() const { return path; }

    // Write the current session token to defaultTokenPath() as a 0600 file the
    // connector reads. Keeping the token in a 0600 file (NOT in -walletnotify's
    // command line) keeps it out of argv / `ps` for any co-resident process.
    // Returns false on failure. Removed again by stop().
    bool writeTokenFile() const;

    // --- Connector / shared-path plumbing (NOTIFY-SRV) --------------------------
    // Per-user paths the GUI (server) and the `--notify` connector BOTH derive from
    // QStandardPaths, so they agree without parsing the conf or the (custom) datadir.
    // The socket lives in the per-user runtime dir (Linux: /run/user/UID, 0700 tmpfs).
    static QString defaultSocketPath();
    static QString defaultTokenPath();
    // Read a token file (default path when `path` empty); "" if absent/unreadable.
    static QString readTokenFile(const QString& path = QString());

    // The connector wire (pure + testable): connect to `socketPath`, send
    // "<token> <id>\n", return 0 IFF the server acked "OK" (a validated notify).
    // Non-zero: 2 bad id, 3 empty token, 4 not listening, 5 no/!OK ack.
    static int sendNotify(const QString& socketPath, const QString& token, const QString& id);

    // Process entry for `<self> --notify <id>` (invoked by zclassicd's
    // -walletnotify/-blocknotify): a tiny headless QCoreApplication that reads the
    // token file and sendNotify()s the default socket. Returns the exit code.
    static int runConnector(int argc, char** argv, const QString& id);

    // Hard limits (also asserted by the L1 tests).
    static constexpr int kMaxBytes = 4096;   // per-connection read cap
    static constexpr int kIdleMs   = 2000;   // reap a connection that dribbles

    // Test-only: shorten the idle-reap window so the slow-loris test need not
    // wait 2 s. No-op effect on production (default kIdleMs).
    void testSetIdleMs(int ms) { idleMs = ms; }

signals:
    // Emitted EXACTLY once per VALIDATED notify. `id` is the checked 64-hex
    // txid/blockhash. Wire this to the debounced refresh (PERF-3/4).
    void notified(const QString& id);

private slots:
    void onNewConnection();

private:
    // Constant-time, length-checked compare of a candidate token against the
    // session token. Returns true only on an exact match.
    bool tokenMatches(const QByteArray& candidate) const;

    // Single teardown for a connection: optionally write `ack` (only "OK\n" on a
    // validated notify; empty = drop), disconnect our handlers so nothing fires
    // again, and schedule the socket for deletion (deleteLater coalesces a second
    // schedule, so the object is deleted exactly once).
    void finish(QLocalSocket* c, const QByteArray& ack);

    QLocalServer* server = nullptr;
    QString       sessionToken;        // 64 lowercase-hex (256 bits), minted in ctor
    QByteArray    sessionTokenBytes;   // cached Latin1 of sessionToken (compare hot path)
    QString       path;
    int           idleMs = kIdleMs;
};

#endif // NOTIFYSERVER_H
