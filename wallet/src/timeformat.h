// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef TIMEFORMAT_H
#define TIMEFORMAT_H

#include <QString>
#include <QtGlobal>

class QAbstractItemView;
class QWidget;

// How the wallet shows transaction times (Settings > Options > Time format):
//   Standard  2026-11-26 14:05       (the default)
//   Clock12   2026-11-26 2:05 PM
//   Relative  12s ago, 5m ago, 3h ago, 2d ago, 1y ago   (updated every second)
// Stored as options/timeformat; the full date and time stay in the tooltip.
namespace TimeFormat {
enum Mode { Standard = 0, Clock12 = 1, Relative = 2 };

Mode current();
void set(Mode mode);

// Text for a time given in seconds since the epoch, in the current mode.
QString format(qint64 epochSeconds);
// "12s ago" … "1y ago" for an age in seconds (negative = just now).
QString relative(qint64 ageSeconds);

// Repaint one column of a view every second while times are relative (and once
// after a mode change), so "5s ago" keeps counting.
void keepFresh(QAbstractItemView* view, int column);

// The "Time format" choice, added at the end of the Settings Options page.
void addSettingsOption(QWidget* optionsPage);
}

#endif // TIMEFORMAT_H
