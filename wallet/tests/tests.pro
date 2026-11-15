# ============================================================================
# tst_logic — L0 unit test target for the ZClassic Qt5 GUI wallet.
#
# Links ONLY pure-logic product TUs (settings.cpp, senttxstore.cpp,
# addresscombo.cpp) + test shims. No daemon, no libsodium, no main.cpp.
#
# Build + run (inside the proot chroot):
#   /home/rhett/zclbuild/prun bash -c '\
#     cd /src/wallet/tests && /opt/qt-static/bin/qmake tests.pro && make -j$(nproc) && \
#     QT_QPA_PLATFORM=offscreen ./tst_logic'
# ============================================================================
TEMPLATE = app
TARGET   = tst_logic

CONFIG  += c++14 console
CONFIG  -= app_bundle

# widgets is required only because addresscombo.cpp derives from QComboBox.
# We run guiless via QT_QPA_PLATFORM=offscreen (no X server needed). svg is needed
# by privacybadgedelegate.cpp (QSvgRenderer for the tinted badge icons).
QT      += core testlib widgets network gui svg
win32: LIBS += -ladvapi32

# PRIV-13/14: compile the privacybadgedelegate test seams (testClassify/...). The
# define gates ONLY the static forwarding accessors in privacybadgedelegate.h; it
# adds NO behavior and is never present in the shipped app build.
DEFINES += ZCL_WIDGET_TEST

# Keep all build artifacts inside tests/bin so they NEVER collide with the
# app's own bin/ (which holds the product objects/moc).
OBJECTS_DIR = bin
MOC_DIR     = bin
RCC_DIR     = bin
UI_DIR      = bin
DESTDIR     = .

# INCLUDEPATH ORDER IS LOad-BEARING: shim/ first so `#include "mainwindow.h"`,
# "rpc.h", "precompiled.h", "addressbook.h" resolve to the SHIMS, then ../src
# for the real settings.h / senttxstore.h / addresscombo.h, then 3rdparty.
INCLUDEPATH += $$PWD/shim
INCLUDEPATH += $$PWD/../src
INCLUDEPATH += $$PWD/../src/3rdparty

# Quoted includes search the product source directory BEFORE INCLUDEPATH.
# Preload the shims (which share product header guards) so clean/shadow builds
# do not accidentally pull the full RPC/UI dependency graph into this suite.
CONFIG += precompile_header
PRECOMPILED_HEADER = $$PWD/shim/preload.h

# addresscombo.h + privacybadgedelegate.h carry Q_OBJECT -> qmake must run moc on
# them (generates the vtable). Listing them in HEADERS triggers that without
# touching the source files.
HEADERS += ../src/addresscombo.h
HEADERS += ../src/privacybadgedelegate.h

# Product pure-logic sources (UNMODIFIED) + shims + the test.
# privacybadgedelegate.cpp is pure classification + paint logic; the PRIV-13/14
# tests exercise ONLY classify*/labelFor/colorFor via the test seam (no painting),
# but linking the whole TU keeps the tested logic byte-identical to production.
SOURCES += \
    ../src/embeddeddaemon.cpp \
    ../src/settings.cpp \
    ../src/senttxstore.cpp \
    ../src/addresscombo.cpp \
    ../src/privacybadgedelegate.cpp \
    shim/addressbook_stub.cpp \
    tst_logic.cpp

# Static-Qt offscreen platform plugin import (no X server in the chroot).
static {
    win32: QTPLUGIN.platforms = qwindows
    else: QTPLUGIN.platforms = qoffscreen
}
