#ifndef ZCL_STARTUPACCESS_H
#define ZCL_STARTUPACCESS_H
#include <QStringList>
#include <functional>

struct StartupAccessResult {
    int checked = 0;
    int repairable = 0;
    int repaired = 0;
    int skippedLinks = 0;
    bool cancelled = false;
    QString error;
};

// Windows-only metadata operation. Repair requires prior consent for these
// exact roots. Never reads/writes file contents. Only empty owner ACLs and the
// narrowly recognized owner-private directory inheritance defect are repaired.
StartupAccessResult checkStartupAccess(const QStringList& roots, bool repair,
    const std::function<bool(int, int)>& progress = {});
#endif
