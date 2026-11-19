// Checks that the wallet still parses the daemon's bootstrap progress line, in
// the current binary-unit spelling and in the legacy GB / MB/s spelling.
#include "../src/bootstrapprogress.h"

#include <QStringList>

#include <cstdio>

static int failures = 0;

static void check(bool ok, const char* what)
{
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

int main()
{
    const QString current = QStringLiteral("Bootstrap snapshot:  42%  4.10 / 9.80 GiB  210.5 MiB/s  (8 streams)");
    const QString legacy = QStringLiteral("Bootstrap snapshot:  42%  4.10 / 9.80 GB  210.5 MB/s  (8 streams)");
    const QString single = QStringLiteral("Bootstrap snapshot:   7%  0.73 / 10.43 GiB  12.0 MiB/s");

    QStringList lines;
    lines << current << legacy;
    for (const QString& line : lines) {
        const QRegularExpressionMatch p = bootstrapPercentRegex().match(line);
        check(p.hasMatch() && p.captured(1).toInt() == 42, "percent");
        const QString detail = line.section(QStringLiteral("%"), 1).trimmed();
        const QRegularExpressionMatch r = bootstrapRateRegex().match(detail);
        check(r.hasMatch(), "rate regex matches");
        if (r.hasMatch()) {
            check(r.captured(1).toDouble() == 4.10, "received");
            check(r.captured(2).toDouble() == 9.80, "total");
            check(r.captured(3).toDouble() == 210.5, "rate");
        }
    }
    const QRegularExpressionMatch p = bootstrapPercentRegex().match(single);
    check(p.hasMatch() && p.captured(1).toInt() == 7, "percent without a stream suffix");
    const QRegularExpressionMatch r = bootstrapRateRegex().match(single.section(QStringLiteral("%"), 1).trimmed());
    check(r.hasMatch() && r.captured(2).toDouble() == 10.43, "total without a stream suffix");
    check(!bootstrapPercentRegex().match(QStringLiteral("Loading block index...")).hasMatch(), "unrelated warmup status");

    if (failures == 0)
        puts("PASS: bootstrap progress line parsing (GiB/MiB/s and legacy GB/MB/s)");
    return failures == 0 ? 0 : 1;
}
