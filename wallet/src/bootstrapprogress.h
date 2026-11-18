// Parsing of the daemon's bootstrap snapshot progress line, shared by the wallet
// (connection.cpp) and its test (tests/check-bootstrap-progress.cpp) so the two
// can never drift apart.
//
// The daemon (src/bootstrap_resume.cpp, BootstrapFormatProgressLine) publishes
//     "Bootstrap snapshot:  42%  4.10 / 9.80 GiB  210.5 MiB/s  (8 streams)"
// in binary units. Daemons before the unit fix printed the same numbers labelled
// "GB" and "MB/s"; both spellings are accepted.
#ifndef ZCLWALLET_BOOTSTRAPPROGRESS_H
#define ZCLWALLET_BOOTSTRAPPROGRESS_H

#include <QRegularExpression>
#include <QString>

// Matches the prefix and percent: "Bootstrap snapshot:  42%". Capture 1 is the percent.
inline const QRegularExpression& bootstrapPercentRegex()
{
    static const QRegularExpression re(QStringLiteral("Bootstrap snapshot:\\s*(\\d+)%"));
    return re;
}

// Matches "X / Y GiB  Z MiB/s" (or the legacy GB / MB/s). Captures: 1 = received,
// 2 = total (both in GiB), 3 = rate (MiB/s).
inline const QRegularExpression& bootstrapRateRegex()
{
    static const QRegularExpression re(QStringLiteral(
        "([0-9.]+)\\s*/\\s*([0-9.]+)\\s*(?:GiB|GB)\\s+([0-9.]+)\\s*(?:MiB|MB)/s"));
    return re;
}

#endif // ZCLWALLET_BOOTSTRAPPROGRESS_H
