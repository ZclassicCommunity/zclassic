#include "notifyserver.h"
#include "securerandom.h"   // CSPRNG per-session token
#include "privatefile.h"
#include <QSaveFile>

#include <QLocalServer>
#include <QLocalSocket>
#include <QTimer>
#include <QRegularExpression>
#include <QSharedPointer>
#include <QPointer>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QCoreApplication>

#include <cstdio>           // fprintf(stderr, ...) for the headless connector diagnostic

#ifndef Q_OS_WIN
#include <sys/stat.h>       // umask()/mkdir()/lstat() so the unix socket + temp dir are owner-only
#include <unistd.h>         // geteuid() for the per-user 0700 temp-fallback subdir
#include <cerrno>           // errno (EEXIST) for the secure mkdir-then-verify fallback
#endif

// Protocol (one line, newline-terminated): "<token> <id>\n"
//   <token> = the 64-hex per-session secret this server minted
//   <id>    = the 64-hex txid (walletnotify) or blockhash (blocknotify)
// Both fields are hex with no spaces, so a single space-split is unambiguous.

NotifyServer::NotifyServer(QObject* parent) : QObject(parent) {
    // Per-session secret: 32 CSPRNG bytes = 64 lowercase-hex = 256 bits. Minted
    // here so every NotifyServer (every GUI session) has a fresh, independent token
    // and a token captured from a previous run is worthless.
    sessionToken      = secureRandomHex(32);
    sessionTokenBytes = sessionToken.toLatin1();   // cached for the constant-time compare
}

NotifyServer::~NotifyServer() {
    stop();
}

bool NotifyServer::isListening() const {
    return server != nullptr && server->isListening();
}

bool NotifyServer::start(const QString& socketPath) {
    if (isListening())
        return true;                       // idempotent

    path = socketPath;

    // Clear a stale socket file left by a crashed prior session (otherwise listen()
    // fails with AddressInUseError on a dead socket path).
    QLocalServer::removeServer(path);

    if (!server) {
        server = new QLocalServer(this);
        // Owner-only access: on Unix this chmods the socket to user-only; on Windows
        // it builds a DACL granting only the current user. Defense-in-depth — the
        // token is the real gate, but a co-resident user shouldn't even connect.
        server->setSocketOptions(QLocalServer::UserAccessOption);
        // Backpressure: notifies arrive one-at-a-time from the daemon, so a small
        // queue is plenty; this bounds how many connections can pile up at once.
        server->setMaxPendingConnections(16);
        connect(server, &QLocalServer::newConnection, this, &NotifyServer::onNewConnection);
    }

#ifndef Q_OS_WIN
    // Born owner-only: tighten umask across the bind so the socket file is created
    // 0600 with no group/other bits for any instant, then restore.
    mode_t oldMask = ::umask(0077);
#endif
    bool ok = server->listen(path);
#ifndef Q_OS_WIN
    ::umask(oldMask);
#endif
    return ok;
}

void NotifyServer::stop() {
    if (server) {
        server->close();
        QLocalServer::removeServer(path);
        // Invalidate the session token on disk too (the connector can no longer
        // read it; the in-memory token dies with this object).
        QFile::remove(defaultTokenPath());
        // deleteLater (not delete): stop() may be reached from inside a slot driven
        // by one of this server's child sockets (e.g. a future notified() handler
        // that tears the server down) — a synchronous delete there would free the
        // socket whose lambda is still on the stack. Defer to the event loop.
        server->deleteLater();
        server = nullptr;
    }
}

void NotifyServer::onNewConnection() {
    while (server && server->hasPendingConnections()) {
        QLocalSocket* c = server->nextPendingConnection();
        if (!c) break;

        auto buf = QSharedPointer<QByteArray>::create();

        // Idle reaper: single-shot, parented to the socket (so it dies with it).
        // The timeout is bound to `this` and QPointer-guarded, so a queued timeout
        // can NEVER deref a socket that has already been freed (the bug that made
        // an accumulated-state run crash).
        QPointer<QLocalSocket> guard(c);
        QTimer* reaper = new QTimer(c);
        reaper->setSingleShot(true);
        connect(reaper, &QTimer::timeout, this, [this, guard]() {
            if (guard) finish(guard.data(), QByteArray());   // drop, no signal
        });
        reaper->start(idleMs);

        // A peer that hangs up before sending a full line is cleaned up.
        connect(c, &QLocalSocket::disconnected, c, &QLocalSocket::deleteLater);

        auto onData = [this, c, buf, reaper]() {
            // Read with a hard per-drain cap so `buf` can never exceed kMaxBytes+1
            // even if the kernel delivers a huge single chunk (readAll() would copy
            // it all). A peer that floods without a newline is then dropped.
            const qint64 room = (qint64)kMaxBytes + 1 - buf->size();
            if (room > 0)
                buf->append(c->read(room));
            if (buf->size() > kMaxBytes) {
                reaper->stop();
                finish(c, QByteArray());
                return;
            }

            // Need a full first line before we decide anything.
            const int nl = buf->indexOf('\n');
            if (nl < 0)
                return;

            reaper->stop();   // from here we decide exactly once and close

            // First line only; trim a trailing \r and surrounding space.
            const QByteArray line = buf->left(nl).trimmed();
            const QList<QByteArray> fields = line.split(' ');

            QString id;
            QByteArray ack;   // non-empty ("OK\n") ONLY on a fully-validated notify
            if (fields.size() == 2 && tokenMatches(fields[0])) {
                // Token gate passed (constant-time). Now a strict 64-hex id check —
                // no shell/file/RPC injection can ride the payload into a refresh.
                static const QRegularExpression hex64("^[0-9a-f]{64}$");
                const QString cand = QString::fromLatin1(fields[1]);
                if (hex64.match(cand).hasMatch()) {
                    id  = cand;
                    ack = "OK\n";   // a validated notify grants ONLY an ack, no data
                }
            }

            finish(c, ack);
            // Emit AFTER teardown so the downstream (debounced) refresh can't re-enter
            // this connection. Only on a validated notify.
            if (!id.isEmpty())
                emit notified(id);
        };

        connect(c, &QLocalSocket::readyRead, this, onData);
        // The payload can arrive BETWEEN accept() and the connect() above; readyRead
        // does NOT re-fire for bytes already buffered, so drain them now or the
        // connection would stall until the idle reaper (and the connector would see
        // no ack). Deterministic regardless of accept/data ordering.
        if (c->bytesAvailable() > 0)
            onData();
    }
}

void NotifyServer::finish(QLocalSocket* c, const QByteArray& ack) {
    if (!c)
        return;
    // Stop our handlers firing again for this socket (readyRead / reaper timeout),
    // so finish() runs at most once per connection regardless of event ordering.
    disconnect(c, nullptr, this, nullptr);

    if (!ack.isEmpty() && c->state() == QLocalSocket::ConnectedState) {
        c->write(ack);
        c->flush();
    }
    if (c->state() != QLocalSocket::UnconnectedState)
        c->disconnectFromServer();
    c->deleteLater();
}

bool NotifyServer::tokenMatches(const QByteArray& candidate) const {
    const QByteArray& tok = sessionTokenBytes;   // cached; avoids a per-call alloc
    const int n = tok.size();
    // The token LENGTH (64) is fixed and public — only its VALUE is secret. Start
    // `diff` non-zero on a length mismatch, then compare the full token length with
    // NO early-out so the time taken never depends on where (or whether) the first
    // differing byte is. `candidate.size()` is attacker-controlled (not secret), so
    // branching on it leaks nothing about the token value.
    int diff = (candidate.size() == n) ? 0 : 1;
    for (int i = 0; i < n; ++i) {
        const char cc = (i < candidate.size()) ? candidate.at(i) : char(0);
        diff |= (cc ^ tok.at(i));
    }
    return diff == 0;
}

// ---- Connector / shared-path plumbing --------------------------------------

static QString notifyRuntimeDir() {
    // Per-user + stable across the GUI and the connector process (same user => same
    // QStandardPaths). Prefer the OS runtime dir (Linux: /run/user/UID, a 0700
    // tmpfs); fall back to the temp dir where that is unavailable (macOS/Windows or
    // a session with no XDG_RUNTIME_DIR).
    QString d = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
    if (!d.isEmpty())
        return d;   // already a 0700 per-user dir (e.g. /run/user/UID) — unchanged

    // FALLBACK: TempLocation is a SHARED directory (e.g. /tmp, %TEMP%), so the socket
    // and token would otherwise land where any local user can see/connect. Carve out a
    // per-user 0700 subdirectory inside it so the containing directory confines access
    // the way /run/user/UID does on Linux. Stable name (same user => same dir) so the
    // GUI server and the headless connector agree on the path.
    const QString temp = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
#ifndef Q_OS_WIN
    // POSIX shared temp (e.g. /tmp): create the per-user subdir SECURELY. The name is
    // predictable, so a co-resident attacker could pre-create it (or a symlink) — never
    // trust a path we didn't make. ::mkdir(0700) sets the mode atomically at creation
    // (no chmod window). On EEXIST, only trust it if it is a REAL directory (lstat, so a
    // symlink fails S_ISDIR), owned by us, with NO group/other bits. Otherwise fall back
    // to the shared temp dir directly: the token file is still 0600 and the socket is
    // owner-only, so the token stays the gate — we just don't rely on a dir we can't vouch
    // for. (This whole branch is unreachable on a normal Linux desktop, which uses the
    // 0700 /run/user/UID RuntimeLocation above.)
    const QString dir = QDir(temp).filePath(QStringLiteral("zqw-%1").arg((uint)::getuid()));
    const QByteArray dirBytes = QFile::encodeName(dir);
    if (::mkdir(dirBytes.constData(), 0700) == 0)
        return dir;                                  // freshly created, ours, 0700
    if (errno == EEXIST) {
        struct stat st;
        if (::lstat(dirBytes.constData(), &st) == 0 &&
            S_ISDIR(st.st_mode) &&                   // a real dir (symlink would fail this)
            st.st_uid == ::geteuid() &&              // owned by us
            (st.st_mode & (S_IRWXG | S_IRWXO)) == 0) // no group/other access
            return dir;                              // pre-existing but verifiably ours + 0700
    }
    return temp;                                     // suspect/unsecurable -> don't trust it
#else
    // Windows: %TEMP% is already per-user (under the user profile); a stable per-user name
    // isolates concurrent sessions, and setPermissions applies an owner-only DACL.
    const QString sub = QStringLiteral("zqw-%1").arg(QStandardPaths::writableLocation(
                            QStandardPaths::HomeLocation).section('/', -1).section('\\', -1));
    const QString dir = QDir(temp).filePath(sub);
    QDir().mkpath(dir);
    QFile::setPermissions(dir, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    return dir;
#endif
}

QString NotifyServer::defaultSocketPath() {
    return QDir(notifyRuntimeDir()).filePath("zqw-notify.sock");
}

QString NotifyServer::defaultTokenPath() {
    return QDir(notifyRuntimeDir()).filePath("zqw-notify.token");
}

QString NotifyServer::readTokenFile(const QString& path) {
    QFile f(path.isEmpty() ? defaultTokenPath() : path);
    if (!f.open(QIODevice::ReadOnly))
        return QString();
    // The token is 64 bytes; bound the read so a tampered/huge file can't blow up.
    const QByteArray b = f.read(128);
    return QString::fromLatin1(b).trimmed();
}

bool NotifyServer::writeTokenFile() const {
    const QString p = defaultTokenPath();
    if (!QDir().mkpath(QFileInfo(p).absolutePath()))
        return false;
#ifndef Q_OS_WIN
    mode_t oldMask = ::umask(0077);   // born 0600 (no group/other), no TOCTOU window
#endif
    QSaveFile f(p);
    bool ok = f.open(QIODevice::WriteOnly | QIODevice::Truncate);
#ifndef Q_OS_WIN
    ::umask(oldMask);
#endif
    if (!ok)
        return false;
    const QByteArray bytes = sessionToken.toLatin1();
    return makeFileOwnerOnly(f) && f.write(bytes) == bytes.size() && f.commit();
}

int NotifyServer::sendNotify(const QString& socketPath, const QString& token, const QString& id) {
    if (token.isEmpty())
        return 3;   // no token provisioned (GUI not running / not the owner)
    static const QRegularExpression hex64("^[0-9a-f]{64}$");
    if (!hex64.match(id).hasMatch())
        return 2;   // garbage id — fail fast (the server would reject it anyway)

    QLocalSocket s;
    s.connectToServer(socketPath);
    if (!s.waitForConnected(800))
        return 4;   // nobody listening (foreign daemon, or GUI closed)

    const QByteArray payload = token.toLatin1() + ' ' + id.toLatin1() + '\n';
    if (s.write(payload) != payload.size())
        return 5;
    s.flush();
    // A Windows named pipe can finish the write during flush(). Waiting for
    // another bytesWritten signal then burns the entire timeout per notify.
    if (s.bytesToWrite() > 0 && !s.waitForBytesWritten(800))
        return 5;
    if (s.bytesAvailable() == 0 && !s.waitForReadyRead(800))
        return 5;
    const QByteArray ack = s.readAll();
    s.disconnectFromServer();
    return (ack == "OK\n") ? 0 : 5;   // 0 only when the server acknowledged
}

int NotifyServer::runConnector(int argc, char** argv, const QString& id) {
    // Headless: a QCoreApplication (no GUI/QPA) just to drive QLocalSocket's
    // synchronous waitFor* calls. Reads the token from the 0600 file (never argv).
    QCoreApplication app(argc, argv);
    const int rc = sendNotify(defaultSocketPath(), readTokenFile(), id);
    // This connector has no logger; on failure it would vanish silently and a dead
    // push channel would be undiagnosable. Emit ONE line to stderr (captured in the
    // daemon's output) naming the failure code. NO token/secret is printed; rc codes:
    //   2 bad id, 3 no token, 4 nobody listening, 5 no/!OK ack (see sendNotify()).
    if (rc != 0)
        fprintf(stderr, "zqw-notify: push failed (code %d) — falling back to poll\n", rc);
    return rc;
}
