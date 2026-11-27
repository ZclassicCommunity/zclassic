// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Home's balance while the node cannot be asked: it dropped, is restarting, or has
// not answered yet. The user should always see their balance, so the last balance
// this wallet showed stays on screen, greyed and dated, instead of a dash.
#include "mainwindow.h"
#include "settings.h"

#include <QDateTime>
#include <QLabel>
#include <QSettings>
#include <QStyle>

// Paint the last known balance into the Home hero. False when none was ever recorded
// or the "show cached balance" preference is off; the caller then says it is unknown.
bool MainWindow::showLastKnownBalance() {
    QSettings s;
    if (!Settings::getInstance()->getShowCachedBalance() || !s.contains("cache/balTotal"))
        return false;
    heroPrivateFull = Settings::getZCLDisplayFormat(s.value("cache/balShielded", 0.0).toDouble());
    heroTotalFull   = tr("Total: %1").arg(Settings::getZCLDisplayFormat(s.value("cache/balTotal", 0.0).toDouble()));
    relayoutHero();
    if (homeHeroQualifier) {
        const qint64 epoch = s.value("cache/lastSyncEpoch", (qint64) 0).toLongLong();
        const QString tail = tr("It updates once the wallet is connected to its node.");
        homeHeroQualifier->setText(epoch > 0
            ? tr("Last known balance, from %1.").arg(QDateTime::fromSecsSinceEpoch(epoch).toString("MMM d, h:mm AP")) + " " + tail
            : tr("Last known balance.") + " " + tail);
        homeHeroQualifier->setVisible(true);
    }
    if (homeHeroHelper)
        homeHeroHelper->setVisible(false);
    if (homeHeroPrivate) {   // never the confident green: this number is not live
        homeHeroPrivate->setProperty("heroconfident", false);
        homeHeroPrivate->style()->unpolish(homeHeroPrivate);
        homeHeroPrivate->style()->polish(homeHeroPrivate);
    }
    return true;
}
