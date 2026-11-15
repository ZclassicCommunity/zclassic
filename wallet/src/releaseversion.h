#ifndef ZCL_RELEASEVERSION_H
#define ZCL_RELEASEVERSION_H
#include <QRegularExpression>
#include <QVersionNumber>

// QVersionNumber::fromString alone discards "-betaN", treating beta6 and beta7
// as equal. Keep prerelease ordering: beta < rc < final, then numeric suffix.
inline QVersionNumber walletReleaseOrder(const QString& tag) {
    if (tag.size() > 64) return {};
    static const QRegularExpression pattern(
        "^v?([0-9]+)\\.([0-9]+)\\.([0-9]+)(?:-(beta|rc)([0-9]+))?$");
    const auto match = pattern.match(tag);
    if (!match.hasMatch()) return {};
    QVector<int> segments;
    for (int i = 1; i <= 3; ++i) {
        bool ok = false;
        const int value = match.captured(i).toInt(&ok);
        if (!ok) return {};
        segments.append(value);
    }
    const QString phase = match.captured(4);
    segments.append(phase.isEmpty() ? 2 : phase == "rc" ? 1 : 0);
    bool ok = true;
    const int number = phase.isEmpty() ? 0 : match.captured(5).toInt(&ok);
    if (!ok) return {};
    segments.append(number);
    return QVersionNumber(segments);
}
#endif
