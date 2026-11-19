# ============================================================================
# tst_names: logic and widget tests of "pay to a name" (src/namesmodel.cpp,
# src/namepaybox.cpp). No daemon, no MainWindow: the name lookup is a fake.
#
#   cd wallet/tests && qmake names.pro && make && QT_QPA_PLATFORM=offscreen ./tst_names
# ============================================================================
TEMPLATE = app
TARGET   = tst_names

CONFIG  += c++14 console testcase
CONFIG  -= app_bundle
QT      += core gui widgets testlib

OBJECTS_DIR = bin-names
MOC_DIR     = bin-names
DESTDIR     = .

INCLUDEPATH += $$PWD/../src
INCLUDEPATH += $$PWD/../src/3rdparty

SOURCES += \
    ../src/namesmodel.cpp \
    ../src/namepaybox.cpp \
    tst_names.cpp

HEADERS += \
    ../src/namesmodel.h \
    ../src/namepaybox.h
