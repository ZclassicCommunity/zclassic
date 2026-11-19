#ifndef LAUNCHPROBE_H
#define LAUNCHPROBE_H

// Launch-path decisions of the embedded node, kept out of connection.cpp so they
// can be tested on their own (tests/tst_logic).
//
// 1. The first getinfo of a launch exists to find a node that is already
//    running. On Windows a refused loopback connect is not instant: it took
//    2.4 s on a Windows 10 PC (4.1 s for "localhost"). A normal launch paid it
//    twice before the node was spawned (once before the file-access check, once
//    after); in a beta13 wallet log each probe took 4 s, 8 s of the 8.7 s between
//    the window and the spawn. On Windows an exclusive bind of the RPC port
//    answers the same question at once (portprobe_win.h). Linux and macOS refuse
//    a closed loopback port at once, so the probe stays there.
// 2. While the owned node answers "warming up" (RPC error -28) the replies are
//    cheap, so the readiness poll can be short; the per-reply side work is
//    throttled with Every.

#include <QtGlobal>
#include <QElapsedTimer>
#include <QString>
#include <functional>

namespace LaunchProbe {

// The skip exists only where a refused connect is slow.
#ifdef Q_OS_WIN
static const bool kSkipSupported = true;
#else
static const bool kSkipSupported = false;
#endif

// True when nothing is bound to the RPC port (Windows: portprobe_win.h). Off
// Windows it is always false. Any doubt is false, which keeps the probe.
bool loopbackPortFree(quint16 port);

// True when the conf at `path` has an rpcallowip or rpcbind line, or cannot be
// read. Either makes the node bind addresses other than loopback (0.0.0.0 and
// [::] for rpcallowip without rpcbind), so the wallet keeps the probe.
bool confNamesRpcNetwork(const QString& path);

struct ProbeInputs {
    bool useEmbedded;      // the wallet manages its own node
    bool externalDaemon;   // the conf says daemon=1: someone else's node
    bool nodeSpawned;      // this launch already spawned the node
    QString host;          // RPC host from the conf
    QString port;          // RPC port from the conf
    std::function<QString()> confPath;   // the conf both the wallet and the node read;
                                         // located only when everything else allows a skip
};

// The initial getinfo is skipped only when its refusal is certain: a supported
// platform, the wallet manages its own node, the conf names no external daemon
// and no rpcallowip or rpcbind, no node has been spawned, the RPC host is
// 127.0.0.1, and nothing is bound to the port. The conf is read and the port
// bound only when everything before holds. The last three parameters are
// replaceable for tests.
inline bool skipInitialProbe(const ProbeInputs& in, bool platformSupported = kSkipSupported,
                             bool (*portFree)(quint16) = loopbackPortFree,
                             bool (*confNamesRpc)(const QString&) = confNamesRpcNetwork)
{
    if (!platformSupported || !in.useEmbedded || in.externalDaemon || in.nodeSpawned ||
        in.host != QStringLiteral("127.0.0.1"))
        return false;
    bool ok = false;
    const uint p = in.port.toUInt(&ok);
    if (!ok || p == 0 || p > 65535)
        return false;
    if (confNamesRpc(in.confPath ? in.confPath() : QString()))
        return false;
    return portFree(static_cast<quint16>(p));
}

// Interval of the readiness poll while the owned node is warming up: 100 ms for
// the first 2 s after the spawn, 250 ms up to 30 s (a normal restart is ready
// well inside that), then 1000 ms for long warmups such as a bootstrap or a
// rebuild. Was 250 ms for 4 s, then 1000 ms: on average 0.5 s after the node was
// ready on every launch. A negative (unknown) time since the spawn polls at the
// long interval.
inline int warmupPollMs(qint64 sinceSpawnMs)
{
    if (sinceSpawnMs < 0)
        return 1000;
    return sinceSpawnMs < 2000 ? 100 : sinceSpawnMs < 30000 ? 250 : 1000;
}

// Runs f at most once per interval: the first call runs it, later calls only once
// `ms` have passed since the last run. For per-poll side work (getbootstrapinfo,
// which also writes QSettings, and the "waiting" log line) that must not follow
// a faster poll.
class Every {
public:
    template <typename F> bool run(qint64 ms, F f)
    {
        if (last.isValid() && last.elapsed() < ms)
            return false;
        last.start();
        f();
        return true;
    }
private:
    QElapsedTimer last;
};

} // namespace LaunchProbe

#endif // LAUNCHPROBE_H
