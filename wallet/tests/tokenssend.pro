# ============================================================================
# tst_tokenssend: tests of sending and creating tokens from the Tokens window.
# The pure logic (src/tokenssendmodel.cpp) and the two dialogs (src/tokenssend.cpp), the dialogs
# driven offscreen against a fake daemon. Links no MainWindow, no daemon, no libsodium.
#
#   cd wallet/tests && qmake tokenssend.pro && make && QT_QPA_PLATFORM=offscreen ./tst_tokenssend
# ============================================================================
TEMPLATE = app
TARGET   = tst_tokenssend

CONFIG  += c++14 console testcase
CONFIG  -= app_bundle
QT      += core gui widgets testlib

OBJECTS_DIR = bin-tokenssend
MOC_DIR     = bin-tokenssend
DESTDIR     = .

INCLUDEPATH += $$PWD/../src
INCLUDEPATH += $$PWD/../src/3rdparty

SOURCES += \
    ../src/tokensmodel.cpp \
    ../src/tokenssendmodel.cpp \
    ../src/tokenssend.cpp \
    tst_tokenssend.cpp

HEADERS += \
    ../src/tokensmodel.h \
    ../src/tokenssendmodel.h \
    ../src/tokenssend.h
