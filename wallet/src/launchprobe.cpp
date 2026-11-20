#include "launchprobe.h"
#include "portprobe_win.h"

#include <QFile>
#include <QTextStream>

namespace LaunchProbe {

bool loopbackPortFree(quint16 port)
{
#ifdef Q_OS_WIN
    return windowsPortUnbound(port);
#else
    // A Qt listen test is not reliable here: QTcpServer binds without exclusive
    // use, so on macOS (and on Windows) it succeeds next to a node on 0.0.0.0 or
    // [::]. The skip is Windows-only, so never claim the port is free.
    Q_UNUSED(port);
    return false;
#endif
}

bool confNamesRpcNetwork(const QString& path)
{
    if (path.isEmpty())
        return true;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return true;
    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#')))
            continue;
        const QString key = line.section(QLatin1Char('='), 0, 0).trimmed();
        if (key == QLatin1String("rpcallowip") || key == QLatin1String("rpcbind"))
            return true;
    }
    return false;
}

} // namespace LaunchProbe
