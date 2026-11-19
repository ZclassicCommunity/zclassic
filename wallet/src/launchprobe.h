#ifndef LAUNCHPROBE_H
#define LAUNCHPROBE_H

// Launch-path decisions of the embedded node, kept out of connection.cpp so they
// can be tested on their own (tests/tst_logic).
//
// 1. The first getinfo of a launch exists to find a node that is already
//    running. When nothing listens on 127.0.0.1:<rpcport> its answer is known
//    in advance, and on Windows a refused loopback connect is not instant: it
//    took 2.4 s on a Windows 10 PC (4.1 s for "localhost"). A normal launch
//    paid it twice before the node was spawned (once before the file-access
//    check, once after); in a beta13 wallet log each probe took 4 s, 8 s of the
//    8.7 s between the window and the spawn. A bind on the port answers the
//    same question at once.
// 2. While the owned node answers "warming up" (RPC error -28) the replies are
//    cheap, so the readiness poll can be short.

#include <QtGlobal>
#include <QString>

namespace LaunchProbe {

// True when a TCP listen on 127.0.0.1:port succeeds right now, i.e. no node's
// RPC server is listening there. The probe socket is closed before returning.
// Any failure to bind (port in use, permission, no loopback) returns false, so
// the caller falls back to the getinfo probe.
bool loopbackPortFree(quint16 port);

// The initial getinfo is skipped only when its outcome is already known: the
// wallet manages its own node, the configuration names no external daemon, no
// node has been spawned yet, the RPC host is the IPv4 loopback the embedded node
// binds, and that port is free. The port is bound only when everything else
// holds; portFree is replaceable for tests.
inline bool skipInitialProbe(bool useEmbedded, bool externalDaemon, bool nodeSpawned,
                             const QString& host, const QString& port,
                             bool (*portFree)(quint16) = loopbackPortFree)
{
    if (!useEmbedded || externalDaemon || nodeSpawned || host != QStringLiteral("127.0.0.1"))
        return false;
    bool ok = false;
    const uint p = port.toUInt(&ok);
    if (!ok || p == 0 || p > 65535)
        return false;
    return portFree(static_cast<quint16>(p));
}

// Interval of the readiness poll while the owned node is warming up: 100 ms for
// the first 2 s after the spawn, 250 ms up to 30 s (a normal restart is ready
// well inside that), then 1000 ms for long warmups such as a bootstrap or a
// rebuild, so they do not log four lines a second for minutes. Was 250 ms for
// 4 s, then 1000 ms: on average 0.5 s after the node was ready on every launch.
// A negative (unknown) time since the spawn polls at the long interval.
inline int warmupPollMs(qint64 sinceSpawnMs)
{
    if (sinceSpawnMs < 0)
        return 1000;
    return sinceSpawnMs < 2000 ? 100 : sinceSpawnMs < 30000 ? 250 : 1000;
}

} // namespace LaunchProbe

#endif // LAUNCHPROBE_H
