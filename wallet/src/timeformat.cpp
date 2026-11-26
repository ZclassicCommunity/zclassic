// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "timeformat.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QGridLayout>
#include <QBoxLayout>
#include <memory>
#include <QHBoxLayout>
#include <QLabel>
#include <QLayout>
#include <QSettings>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

namespace {
const char* kKey = "options/timeformat";

int& cached() {
    static int mode = -1;   // -1 = not read yet
    return mode;
}

QString tr(const char* text) { return QCoreApplication::translate("TimeFormat", text); }
}

TimeFormat::Mode TimeFormat::current() {
    if (cached() < 0) {
        const int stored = QSettings().value(kKey, Standard).toInt();
        cached() = (stored >= Standard && stored <= Relative) ? stored : Standard;
    }
    return static_cast<Mode>(cached());
}

void TimeFormat::set(Mode mode) {
    cached() = mode;
    QSettings().setValue(kKey, static_cast<int>(mode));
}

QString TimeFormat::relative(qint64 age) {
    if (age < 1) return tr("just now");
    if (age < 60) return tr("%1s ago").arg(age);
    if (age < 3600) return tr("%1m ago").arg(age / 60);
    if (age < 86400) return tr("%1h ago").arg(age / 3600);
    if (age < 365 * 86400) return tr("%1d ago").arg(age / 86400);
    return tr("%1y ago").arg(age / (365 * 86400));
}

QString TimeFormat::format(qint64 epochSeconds) {
    const QDateTime when = QDateTime::fromMSecsSinceEpoch(epochSeconds * 1000).toLocalTime();
    switch (current()) {
    case Clock12:  return when.toString("yyyy-MM-dd h:mm AP");
    case Relative: return relative(QDateTime::currentSecsSinceEpoch() - epochSeconds);
    case Standard: break;
    }
    return when.toString("yyyy-MM-dd hh:mm");   // compact, scannable; full ts in tooltip
}

void TimeFormat::keepFresh(QAbstractItemView* view, int column) {
    auto* timer = new QTimer(view);
    timer->setInterval(1000);
    auto shown = std::make_shared<int>(current());
    QObject::connect(timer, &QTimer::timeout, view, [view, column, shown]() {
        QAbstractItemModel* model = view->model();
        const int mode = current();
        if (!model || !view->isVisible() || (mode != Relative && mode == *shown)) return;
        *shown = mode;
        const int rows = model->rowCount();
        if (rows > 0)
            emit model->dataChanged(model->index(0, column), model->index(rows - 1, column));
    });
    timer->start();
}

void TimeFormat::addSettingsOption(QWidget* optionsPage) {
    if (optionsPage == nullptr || optionsPage->layout() == nullptr) return;
    auto* row = new QWidget(optionsPage);
    auto* h = new QHBoxLayout(row);
    h->setContentsMargins(0, 8, 0, 0);
    auto* label = new QLabel(tr("Time format"), row);
    auto* choice = new QComboBox(row);
    choice->setObjectName("cmbTimeFormat");
    choice->addItem(tr("Date and 24-hour time (2026-11-26 14:05)"), Standard);
    choice->addItem(tr("Date and 12-hour time (2026-11-26 2:05 PM)"), Clock12);
    choice->addItem(tr("How long ago (12s ago, 5m ago, 3h ago, 2d ago)"), Relative);
    choice->setCurrentIndex(choice->findData(current()));
    QObject::connect(choice, QOverload<int>::of(&QComboBox::currentIndexChanged), choice,
                     [choice](int) { set(static_cast<Mode>(choice->currentData().toInt())); });
    h->addWidget(label);
    h->addWidget(choice, 1);
    if (auto* grid = qobject_cast<QGridLayout*>(optionsPage->layout()))
        grid->addWidget(row, grid->rowCount(), 0, 1, grid->columnCount());
    else if (auto* box = qobject_cast<QBoxLayout*>(optionsPage->layout()))
        box->addWidget(row);
}
