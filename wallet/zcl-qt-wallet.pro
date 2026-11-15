#-------------------------------------------------
#
# Project created by QtCreator 2018-10-05T09:54:45
#
#-------------------------------------------------

QT       += core gui network

# Phase-2 redesign: QtSvg powers the privacy-badge icon set (PrivacyBadgeDelegate
# renders the bundled monochrome SVGs as tinted, cached pixmaps). Declaring the
# module here makes qmake auto-import the static svg image-format plugin into the
# single-file bundle (it is built but NOT auto-imported otherwise), so the badges
# render identically on the static Linux/Windows builds and the test harness.
QT += svg

CONFIG += precompile_header

PRECOMPILED_HEADER = src/precompiled.h

QT += widgets

TARGET = zclwallet

TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += \
    QT_DEPRECATED_WARNINGS

INCLUDEPATH  += $$PWD/src $$PWD/src/3rdparty

RESOURCES     = application.qrc

MOC_DIR = bin
OBJECTS_DIR = bin
UI_DIR = src

CONFIG += c++14

# A static Qt build alone still imports GCC's exception, C++ and pthread DLLs.
# Portable Windows releases must link ALL third-party runtimes statically.
contains(CONFIG, zqw_portable) {
    !win32-g++: error(zqw_portable requires the MinGW Windows toolchain)
    contains(QT_CONFIG, shared): error(zqw_portable requires static Qt)
    QMAKE_CFLAGS += -ffunction-sections -fdata-sections
    QMAKE_CXXFLAGS += -ffunction-sections -fdata-sections
    QMAKE_LFLAGS += -static -static-libgcc -static-libstdc++ -Wl,--gc-sections
}

SOURCES += \
    src/embeddeddaemon.cpp \
    src/main.cpp \
    src/mainwindow.cpp \
    src/rpc.cpp \
    src/balancestablemodel.cpp \
    src/privacybadgedelegate.cpp \
    src/3rdparty/qrcode/BitBuffer.cpp \
    src/3rdparty/qrcode/QrCode.cpp \
    src/3rdparty/qrcode/QrSegment.cpp \
    src/settings.cpp \
    src/sendtab.cpp \
    src/senttxstore.cpp \
    src/txtablemodel.cpp \
    src/turnstile.cpp \
    src/qrcodelabel.cpp \
    src/connection.cpp \
    src/fillediconlabel.cpp \
    src/addressbook.cpp \
    src/logger.cpp \
    src/addresscombo.cpp \
    src/recurring.cpp \
    src/notifyserver.cpp

HEADERS += \
    src/embeddeddaemon.h \
    src/notifyserver.h \
    src/securerandom.h \
    src/privatefile.h \
    src/mainwindow.h \
    src/precompiled.h \
    src/rpc.h \
    src/balancestablemodel.h \
    src/privacybadgedelegate.h \
    src/3rdparty/qrcode/BitBuffer.hpp \
    src/3rdparty/qrcode/QrCode.hpp \
    src/3rdparty/qrcode/QrSegment.hpp \
    src/3rdparty/json/json.hpp \
    src/settings.h \
    src/txtablemodel.h \
    src/senttxstore.h \
    src/turnstile.h \
    src/qrcodelabel.h \
    src/connection.h \
    src/fillediconlabel.h \
    src/addressbook.h \
    src/logger.h \
    src/addresscombo.h \ 
    src/recurring.h

FORMS += \
    src/mainwindow.ui \
    src/settings.ui \
    src/about.ui \
    src/confirm.ui \
    src/turnstile.ui \
    src/turnstileprogress.ui \
    src/privkey.ui \
    src/memodialog.ui \ 
    src/connection.ui \
    src/addressbook.ui \
    src/createzclassicconfdialog.ui \
    src/recurringdialog.ui \
    src/newrecurring.ui


TRANSLATIONS = res/zcl_qt_wallet_es.ts \
               res/zcl_qt_wallet_fr.ts \
               res/zcl_qt_wallet_de.ts \
               res/zcl_qt_wallet_pt.ts \
               res/zcl_qt_wallet_it.ts 

include(singleapplication/singleapplication.pri)
DEFINES += QAPPLICATION_CLASS=QApplication

# NEVER-STRAND (static build): explicitly link BOTH the xcb and offscreen QPA
# platform plugins so the runtime platform fallback chain in main() (set via
# QT_QPA_PLATFORM=wayland;xcb;offscreen on a no-XWayland Wayland session) always
# has a non-aborting last resort compiled in. qmake's default static import_plugins
# already pulls these in for this Qt config; naming them here makes the requirement
# explicit and build-verifiable, so a future configure-flag change cannot silently
# drop offscreen and re-introduce the hard-abort strand on Wayland-without-XWayland.
static:unix:!macx {
    QTPLUGIN.platforms = qxcb qoffscreen
}

QMAKE_INFO_PLIST = res/Info.plist

win32: RC_ICONS = res/icon.ico
ICON = res/logo.icns

libsodium.target = $$PWD/res/libsodium.a
libsodium.commands = res/libsodium/buildlibsodium.sh

QMAKE_EXTRA_TARGETS += libsodium
QMAKE_CLEAN += res/libsodium.a

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/res/ -llibsodium
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/res/ -llibsodiumd
else:unix: LIBS += -L$$PWD/res/ -lsodium

INCLUDEPATH += $$PWD/res
DEPENDPATH += $$PWD/res

win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/res/liblibsodium.a
else:win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/res/liblibsodium.a
else:win32:!win32-g++:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/res/libsodium.lib
else:win32:!win32-g++:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/res/libsodiumd.lib
else:unix: PRE_TARGETDEPS += $$PWD/res/libsodium.a
