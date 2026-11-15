# ============================================================================
# tst_widget — L1 widget / integration test target for the ZClassic Qt5 GUI.
#
# Links the FULL wallet app MINUS src/main.cpp, runs under
# QT_QPA_PLATFORM=offscreen, constructs the REAL MainWindow (which creates the
# REAL RPC), and asserts the privacy UX in-process via the public widget API
# (MainWindow::ui).  No daemon, no X server, no synthetic input.
#
# Build + run (inside the proot chroot, glibc-2.31, static Qt 5.15):
#   /home/rhett/zclbuild/prun bash -c '\
#     cd /src/wallet/tests/widget && \
#     /opt/qt-static/bin/qmake tst_widget.pro && make -j$(nproc) && \
#     QT_QPA_PLATFORM=offscreen ./tst_widget'
#
# IMPORTANT: distinct OBJECTS_DIR/MOC_DIR/DESTDIR under tests/widget/bin so this
# NEVER collides with the app's bin/ or the L0 tests/bin.
# ============================================================================
TEMPLATE = app
TARGET   = tst_widget

CONFIG  += c++14 console precompile_header
CONFIG  -= app_bundle

QT      += core gui network widgets testlib svg

PRECOMPILED_HEADER = ../../src/precompiled.h

# All build artifacts isolated under tests/widget/bin.
OBJECTS_DIR = bin
MOC_DIR     = bin
RCC_DIR     = bin
UI_DIR      = bin
DESTDIR     = .

DEFINES += QT_DEPRECATED_WARNINGS
DEFINES += QAPPLICATION_CLASS=QApplication
# Compile-in the test-only public seam used by E2 (drive the private confirmTx).
# Guarded so it is NEVER present in the shipped app build.
DEFINES += ZCL_WIDGET_TEST

INCLUDEPATH += $$PWD/../../src
INCLUDEPATH += $$PWD/../../src/3rdparty
INCLUDEPATH += $$PWD/../../res
DEPENDPATH  += $$PWD/../../res

# The whole app, EXCEPT src/main.cpp (QtTest provides its own main via
# QTEST_MAIN). Mirror of zcl-qt-wallet.pro SOURCES minus main.cpp, plus the
# qrcode 3rdparty + singleapplication + the test itself.
SOURCES += \
    ../../src/embeddeddaemon.cpp \
    ../../src/mainwindow.cpp \
    ../../src/rpc.cpp \
    ../../src/balancestablemodel.cpp \
    ../../src/privacybadgedelegate.cpp \
    ../../src/3rdparty/qrcode/BitBuffer.cpp \
    ../../src/3rdparty/qrcode/QrCode.cpp \
    ../../src/3rdparty/qrcode/QrSegment.cpp \
    ../../src/settings.cpp \
    ../../src/sendtab.cpp \
    ../../src/senttxstore.cpp \
    ../../src/txtablemodel.cpp \
    ../../src/turnstile.cpp \
    ../../src/qrcodelabel.cpp \
    ../../src/connection.cpp \
    ../../src/fillediconlabel.cpp \
    ../../src/addressbook.cpp \
    ../../src/logger.cpp \
    ../../src/addresscombo.cpp \
    ../../src/recurring.cpp \
    ../../src/notifyserver.cpp \
    tst_widget.cpp

# Q_OBJECT headers so MOC runs (matches zcl-qt-wallet.pro HEADERS that carry
# Q_OBJECT, plus singleapplication).
HEADERS += \
    ../../src/mainwindow.h \
    ../../src/privacybadgedelegate.h \
    ../../src/qrcodelabel.h \
    ../../src/fillediconlabel.h \
    ../../src/addresscombo.h \
    ../../src/notifyserver.h \
    ../../src/logger.h

FORMS += \
    ../../src/mainwindow.ui \
    ../../src/settings.ui \
    ../../src/about.ui \
    ../../src/confirm.ui \
    ../../src/turnstile.ui \
    ../../src/turnstileprogress.ui \
    ../../src/privkey.ui \
    ../../src/memodialog.ui \
    ../../src/connection.ui \
    ../../src/addressbook.ui \
    ../../src/createzclassicconfdialog.ui \
    ../../src/recurringdialog.ui \
    ../../src/newrecurring.ui

# Image/qrc resources the .ui files reference (logos, gifs).
RESOURCES = ../../application.qrc

# singleapplication is pulled in by mainwindow/main glue; include its .pri so its
# sources + Q_OBJECT headers are compiled and MOC'd.
include(../../singleapplication/singleapplication.pri)

# libsodium static archive — built by res/libsodium/buildlibsodium.sh in the
# chroot if missing. The app links it via -lsodium against res/.
LIBS         += -L$$PWD/../../res/ -lsodium
PRE_TARGETDEPS += $$PWD/../../res/libsodium.a

# Static-Qt offscreen platform plugin import (no X server in the chroot). qmake
# emits the Q_IMPORT_PLUGIN glue from QTPLUGIN into a generated _plugin_import.cpp.
static {
    win32: QTPLUGIN.platforms = qwindows
    else: QTPLUGIN.platforms = qoffscreen
}
