// Copyright (C) 2022-2026 zclassic Community
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Window chrome for the "Greenback" theme: the left navigation rail (brand,
// destinations, shortcuts, the "More" menu that replaces the menu bar), the
// sync-banner card styles and small shared icon helpers. Presentation only: every
// item here triggers an existing page, QAction or MainWindow handler.
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "addresscell.h"
#include "rpc.h"
#include "timeformat.h"
#include "backuppage.h"

#include <QAbstractButton>
#include <QButtonGroup>
#include <QFile>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QSet>
#include <QSignalBlocker>
#include <QSvgRenderer>
#include <QTabBar>
#include <QTimer>
#include <QLineEdit>
#include <QVBoxLayout>

namespace {
// Group id of the Node page in the rail's button group (above any tab index).
const int kNodeButtonId = 1000;

// A rail icon from a single-colour SVG (stroke #000000), recoloured per state:
// dim when idle, money green when its page is selected (QIcon::On).
QPixmap tintedSvg(const QByteArray& svg, const QColor& colour) {
    QByteArray tinted = svg;
    tinted.replace("#000000", colour.name().toLatin1());
    QSvgRenderer renderer(tinted);
    const qreal dpr = qApp->devicePixelRatio();
    QPixmap pm(QSize(20, 20) * dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    renderer.render(&p);
    p.end();
    pm.setDevicePixelRatio(dpr);
    return pm;
}

QIcon railIcon(const QString& resource) {
    QFile f(resource);
    if (!f.open(QIODevice::ReadOnly)) return QIcon();
    const QByteArray svg = f.readAll();
    const QPixmap off = tintedSvg(svg, QColor("#9aa59d"));
    const QPixmap on  = tintedSvg(svg, QColor("#5fd38d"));
    QIcon icon;
    icon.addPixmap(off, QIcon::Normal, QIcon::Off);
    icon.addPixmap(off, QIcon::Active, QIcon::Off);
    icon.addPixmap(on,  QIcon::Normal, QIcon::On);
    icon.addPixmap(on,  QIcon::Active, QIcon::On);
    return icon;
}
}   // namespace

// Sync banner card for each state. Scoped to #syncBanner so the border and tint
// stay on the card and never cascade onto its progress bar or buttons. Amber =
// needs attention / in progress, neutral = connecting, blue = information.
QString MainWindow::bannerSheet(BannerTone tone) {
    switch (tone) {
    case BannerTone::Warn:
        return QStringLiteral("#syncBanner { background-color: rgba(217, 130, 43, 0.12); "
            "border: 1px solid rgba(217, 130, 43, 0.40); border-radius: 14px; } "
            "#syncBanner QLabel { color: #f0b878; }");
    case BannerTone::Neutral:
        return QStringLiteral("#syncBanner { background-color: #121714; "
            "border: 1px solid #232b26; border-radius: 14px; } "
            "#syncBanner QLabel { color: #e8ece9; }");
    case BannerTone::Info:
        return QStringLiteral("#syncBanner { background-color: rgba(74, 143, 214, 0.12); "
            "border: 1px solid rgba(74, 143, 214, 0.40); border-radius: 14px; } "
            "#syncBanner QLabel { color: #b9d5f2; }");
    case BannerTone::Rest:
        break;
    }
    return QStringLiteral("#syncBanner { background-color: transparent; border: none; }");
}

// The Send page's per-recipient address-book button: the rail already says
// "Address book", so here it is a book icon with a tooltip.
void MainWindow::styleAddressBookButton(QPushButton* button) {
    button->setText(QString());
    button->setIcon(QIcon(":/icons/res/icons/book-light.svg"));
    button->setIconSize(QSize(20, 20));
    button->setToolTip(tr("Pick a saved address"));
}

// Phase-3a: the left NAV RAIL. The QTabWidget keeps every page and objectName;
// only its tab bar is hidden and the rail drives setCurrentIndex. Order: brand,
// Home / Send / Receive / Activity, then at the bottom Address book, Settings,
// Node and More. The menu bar is hidden; its items live under More.
void MainWindow::setupNavRail() {
    ui->tabWidget->tabBar()->hide();
    buildAddressBookPage();   // pages like the others, reached from the rail
    buildBackupPage();
    buildNodePage();
    buildSettingsPage();
    ui->tabWidget->setDocumentMode(true);   // page content sits flush to the rail

    auto* navRail = new QFrame(ui->centralWidget);
    navRail->setObjectName("navRail");
    navRail->setFrameShape(QFrame::NoFrame);
    navRail->setFixedWidth(204);
    navRail->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    auto* railLayout = new QVBoxLayout(navRail);
    railLayout->setContentsMargins(12, 16, 12, 10);
    railLayout->setSpacing(2);

    addNavBrand(navRail, railLayout);

    navRailGroup = new QButtonGroup(this);
    navRailGroup->setExclusive(true);
    // Live tab indices at this point (the zclassicd page is attached later).
    addRailPage(navRail, railLayout, tr("Home"),     ":/icons/res/icons/nav-home.svg",     0);
    addRailPage(navRail, railLayout, tr("Send"),     ":/icons/res/icons/nav-send.svg",     1);
    addRailPage(navRail, railLayout, tr("Receive"),  ":/icons/res/icons/nav-receive.svg",  2);
    addRailPage(navRail, railLayout, tr("Activity"), ":/icons/res/icons/nav-activity.svg", 3);
    railLayout->addStretch(1);
    addRailShortcuts(navRail, railLayout);

    QObject::connect(ui->tabWidget, &QTabWidget::currentChanged, this, &MainWindow::syncNavRailToTab);
    placeNavRail(navRail);
    hideMenuBarKeepShortcuts();
    styleAddressBookButton(ui->AddressBook1);
    tidySendPage();
    TimeFormat::keepFresh(ui->transactionsTable, 2);   // live "5s ago" times
    lockUntilConnected();
    applyPageGutters();

    // Open on Home (Balance, index 0), with its rail entry checked.
    ui->tabWidget->setCurrentIndex(0);
    if (auto* home = navRailGroup->button(0))
        home->setChecked(true);
}

// Brand header: the ZClassic mark + wordmark.
void MainWindow::addNavBrand(QWidget* rail, QVBoxLayout* railLayout) {
    auto* brand = new QWidget(rail);
    auto* row = new QHBoxLayout(brand);
    row->setContentsMargins(8, 0, 4, 16);
    row->setSpacing(10);
    auto* mark = new QLabel(brand);
    mark->setObjectName("navBrandMark");
    const qreal dpr = qApp->devicePixelRatio();
    QPixmap pm = QPixmap(":/img/res/zcl-mark.png")
        .scaled(QSize(34, 34) * dpr, Qt::KeepAspectRatio, Qt::SmoothTransformation);
    pm.setDevicePixelRatio(dpr);
    mark->setPixmap(pm);
    mark->setFixedSize(34, 34);
    auto* words = new QVBoxLayout();
    words->setContentsMargins(0, 0, 0, 0);
    words->setSpacing(0);
    auto* name = new QLabel(QStringLiteral("ZClassic"), brand);
    name->setObjectName("navBrandName");
    auto* sub = new QLabel(tr("Your money."), brand);
    sub->setObjectName("navBrandSub");
    words->addWidget(name);
    words->addWidget(sub);
    row->addWidget(mark, 0, Qt::AlignVCenter);
    row->addLayout(words, 1);
    railLayout->addWidget(brand);
}

// A flat rail button with an icon; secondary entries are a step smaller.
QPushButton* MainWindow::makeRailItem(QWidget* rail, QVBoxLayout* railLayout, const QString& label,
                                      const QString& icon, const QString& objName, bool secondary) {
    auto* btn = new QPushButton(QStringLiteral("  ") + label, rail);
    btn->setObjectName(objName);
    btn->setFlat(true);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setProperty("navrail", true);   // qss hook: QPushButton[navrail="true"]
    if (secondary) btn->setProperty("navrailadv", true);
    btn->setIcon(railIcon(icon));
    btn->setIconSize(QSize(20, 20));
    btn->setToolTip(label);
    btn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    railLayout->addWidget(btn);
    return btn;
}

// A checkable destination bound to a page index, in the exclusive group.
void MainWindow::addRailPage(QWidget* rail, QVBoxLayout* railLayout, const QString& label,
                             const QString& icon, int tabIndex) {
    auto* btn = makeRailItem(rail, railLayout, label, icon, "navRailButton", false);
    btn->setCheckable(true);
    navRailGroup->addButton(btn, tabIndex);
    QObject::connect(btn, &QPushButton::clicked, this, [this, tabIndex]() {
        ui->tabWidget->setCurrentIndex(tabIndex);
    });
}

// Bottom group: Address book and Settings run the same Edit-menu actions, Node
// opens the node page, More holds the File and Help items.
void MainWindow::addRailShortcuts(QWidget* rail, QVBoxLayout* railLayout) {
    auto* bookBtn = makeRailItem(rail, railLayout, tr("Address book"),
                                 ":/icons/res/icons/nav-book.svg", "navRailAddressBook", true);
    bookBtn->setCheckable(true);   // a page of its own (addressbookpage.cpp)
    navRailGroup->addButton(bookBtn, ui->tabWidget->indexOf(addressBookPage));
    QObject::connect(bookBtn, &QPushButton::clicked, this, &MainWindow::openAddressBookPage);
    auto* backupBtn = makeRailItem(rail, railLayout, tr("Backup"),
                                   ":/icons/res/icons/nav-backup.svg", "navRailBackup", true);
    backupBtn->setCheckable(true);   // a page of its own (backuppage.cpp)
    navRailGroup->addButton(backupBtn, ui->tabWidget->indexOf(backupPage));
    QObject::connect(backupBtn, &QPushButton::clicked, this, &MainWindow::openBackupPage);
    auto* settingsBtn = makeRailItem(rail, railLayout, tr("Settings"),
                                     ":/icons/res/icons/nav-settings.svg", "navRailSettings", true);
    settingsBtn->setCheckable(true);   // a page of its own (settingspage.cpp)
    navRailGroup->addButton(settingsBtn, ui->tabWidget->indexOf(settingsPage));
    QObject::connect(settingsBtn, &QPushButton::clicked, this, &MainWindow::openSettingsPage);

    auto* nodeBtn = makeRailItem(rail, railLayout, tr("Node"),
                                 ":/icons/res/icons/nav-node.svg", "navRailAdvanced", true);
    nodeBtn->setCheckable(true);
    navRailGroup->addButton(nodeBtn, kNodeButtonId);
    QObject::connect(nodeBtn, &QPushButton::clicked, this, &MainWindow::openNodePage);

    auto* moreBtn = makeRailItem(rail, railLayout, tr("More"),
                                 ":/icons/res/icons/nav-more.svg", "navRailMore", true);
    auto* moreMenu = new QMenu(moreBtn);
    moreMenu->setObjectName("navMoreMenu");
    QObject::connect(moreBtn, &QPushButton::clicked, this, [this, moreBtn, moreMenu]() {
        fillMoreMenu(moreMenu);
        // Open beside the rail, bottom-aligned with the button.
        QPoint at = moreBtn->mapToGlobal(QPoint(moreBtn->width() + 6, moreBtn->height()));
        at.ry() -= moreMenu->sizeHint().height();
        moreMenu->exec(at);
    });
}

// The node page is attached once the node connects (rpc.cpp), at whatever index it
// then has. Before that, say so instead of a silent no-op, and keep the rail on
// the page that is really shown.
void MainWindow::openNodePage() {
    const int idx = ui->tabWidget->indexOf(zclassicdtab);
    if (idx >= 0) {
        ui->tabWidget->setCurrentIndex(idx);
        return;
    }
    ui->statusBar->showMessage(tr("Node details open once you're connected to a node."), 3000);
    syncNavRailToTab(ui->tabWidget->currentIndex());
}

// Keep the rail's checked entry equal to the page shown, whoever changed it.
void MainWindow::syncNavRailToTab(int idx) {
    if (!navRailGroup) return;
    const int nodeIdx = ui->tabWidget->indexOf(zclassicdtab);
    QAbstractButton* match = navRailGroup->button(nodeIdx >= 0 && idx == nodeIdx ? kNodeButtonId : idx);
    if (match && !match->isChecked()) {
        QSignalBlocker block(navRailGroup);   // no navigation click re-emitted
        match->setChecked(true);
    }
}

// More = the File menu (without Exit and the Backup page items), then Help, then Exit. Rebuilt on each
// open so actions added later appear; an item both menus carry (the backup) is
// listed once. The QActions are the menu bar's own, so handlers and shortcuts hold.
void MainWindow::fillMoreMenu(QMenu* menu) {
    emit ui->menuFile->aboutToShow();   // refresh labels such as Exit's wording
    menu->clear();
    QSet<QString> seen;
    // The backup, key export and key import live on the Backup page; their
    // shortcuts still work (hideMenuBarKeepShortcuts).
    for (QAction* onBackupPage : { ui->actionBackup_wallet_dat, ui->actionExport_All_Private_Keys,
                                   ui->actionImport_Private_Key })
        seen.insert(onBackupPage->text().remove(QLatin1Char('&')));
    addMenuActionsOnce(menu, ui->menuFile, seen);
    addMenuActionsOnce(menu, ui->menuHelp, seen);
    if (!menu->actions().isEmpty() && !menu->actions().last()->isSeparator())
        menu->addSeparator();
    menu->addAction(ui->actionExit);
}

void MainWindow::addMenuActionsOnce(QMenu* target, QMenu* source, QSet<QString>& seen) {
    for (QAction* a : source->actions()) {
        const bool trailingSeparator = target->actions().isEmpty() || target->actions().last()->isSeparator();
        if (a->isSeparator()) {
            if (!trailingSeparator) target->addSeparator();
            continue;
        }
        const QString key = a->text().remove(QLatin1Char('&'));
        if (a == ui->actionExit || !a->isVisible() || seen.contains(key)) continue;
        seen.insert(key);
        target->addAction(a);
    }
    if (!target->actions().isEmpty() && !target->actions().last()->isSeparator())
        target->addSeparator();
}

// Make the central layout [ navRail | tabWidget ], moving the existing tabWidget.
void MainWindow::placeNavRail(QFrame* navRail) {
    auto* central = qobject_cast<QGridLayout*>(ui->centralWidget->layout());
    if (central) {
        central->removeWidget(ui->tabWidget);
        central->setContentsMargins(0, 0, 0, 0);
        central->setSpacing(0);
        central->addWidget(navRail,       0, 0);
        central->addWidget(ui->tabWidget, 0, 1);
        central->setColumnStretch(0, 0);   // rail: fixed width
        central->setColumnStretch(1, 1);   // content: takes the rest
        return;
    }
    auto* hbox = new QHBoxLayout(ui->centralWidget);   // fallback; the .ui has a grid
    hbox->setContentsMargins(0, 0, 0, 0);
    hbox->setSpacing(0);
    hbox->addWidget(navRail);
    hbox->addWidget(ui->tabWidget, 1);
}

// No menu bar in the window: Address book and Settings have rail entries and the
// File/Help items live under More. The actions are added to the window itself so
// their shortcuts (Ctrl+B, Ctrl+P, ...) still work with the bar hidden. A native
// (macOS) menu bar sits outside the window and stays.
void MainWindow::hideMenuBarKeepShortcuts() {
    addActions(ui->menuFile->actions());
    addActions(ui->menu_Edit->actions());
    addActions(ui->menuHelp->actions());
    if (!ui->menuBar->isNativeMenuBar())
        ui->menuBar->hide();
}

// Every page gets the same gutter now that it sits beside the rail instead of
// inside a tab frame (the zclassicd page is attached later).
void MainWindow::applyPageGutters() {
    for (int i = 0; i < ui->tabWidget->count(); ++i) {
        if (auto* lay = ui->tabWidget->widget(i)->layout())
            lay->setContentsMargins(24, 20, 24, 20);
    }
    if (zclassicdtab && zclassicdtab->layout())
        zclassicdtab->layout()->setContentsMargins(24, 20, 24, 20);
}

// Send page: a long address can no longer widen the page. Pay from shows its
// address shortened in the middle, Pay to keeps its own width, and both get an "i"
// for the full address while it does not fit. The running total wraps.
void MainWindow::tidySendPage() {
    attachAddressInfo(ui->inputsCombo);
    attachAddressScroll(ui->Address1);
    ui->sendTotalsLine->setWordWrap(true);
}

// Every recipient row's Pay to field (Send's first row and each added one).
void MainWindow::setupRecipientAddressField(QLineEdit* field) {
    field->setPlaceholderText(tr("Paste a z-address (private) or t-address (public)"));
    attachAddressScroll(field);
}

// While the node is still loading, the pages and tools that need it are greyed
// out with a reason; Home (with the live startup progress), Settings and More
// (Exit, repair, About) stay available. All open as soon as the node answers.
void MainWindow::lockUntilConnected() {
    QList<QAbstractButton*> locked;
    for (int id : {1, 2, 3, ui->tabWidget->indexOf(backupPage), kNodeButtonId})
        if (QAbstractButton* b = navRailGroup->button(id)) locked << b;

    for (QAbstractButton* b : locked) {
        b->setEnabled(false);
        b->setToolTip(tr("Available once your ZClassic node has loaded"));
    }
    auto* waiting = new QTimer(this);
    waiting->setInterval(500);
    QObject::connect(waiting, &QTimer::timeout, this, [this, locked, waiting]() {
        if (rpc == nullptr || rpc->getConnection() == nullptr) return;
        for (QAbstractButton* b : locked) {
            b->setEnabled(true);
            b->setToolTip(b->text().trimmed());
        }
        // The Backup page and Home reminder learn about the phrase, a moment later: in a wallet
        // with tens of thousands of old addresses the node takes about a second to answer and
        // holds the wallet lock, which would delay the first balance on screen.
        QTimer::singleShot(2500, this, [this]() { refreshPhraseInfo(); });
        refreshReceivedTAddresses();   // Receive learns which transparent addresses were paid
        waiting->deleteLater();
    });
    waiting->start();
}
