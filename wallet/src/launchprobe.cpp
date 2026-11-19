#include "launchprobe.h"

#include <QHostAddress>
#include <QTcpServer>

namespace LaunchProbe {

bool loopbackPortFree(quint16 port)
{
    if (port == 0)
        return false;
    // QTcpServer binds exclusively on Windows (SO_EXCLUSIVEADDRUSE) and fails on
    // a port with a listening socket on every platform.
    QTcpServer probe;
    const bool free = probe.listen(QHostAddress(QHostAddress::LocalHost), port);
    probe.close();
    return free;
}

} // namespace LaunchProbe
