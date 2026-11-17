# ============================================================================
# tst_tokens: L0 logic tests of the read-only Tokens view (src/tokensmodel.cpp).
# Links only tokensmodel.cpp: no daemon, no widgets, no libsodium.
#
#   cd wallet/tests && qmake tokens.pro && make && QT_QPA_PLATFORM=offscreen ./tst_tokens
# ============================================================================
TEMPLATE = app
TARGET   = tst_tokens

CONFIG  += c++14 console testcase
CONFIG  -= app_bundle
QT      += core testlib

OBJECTS_DIR = bin-tokens
MOC_DIR     = bin-tokens
DESTDIR     = .

INCLUDEPATH += $$PWD/../src
INCLUDEPATH += $$PWD/../src/3rdparty

SOURCES += \
    ../src/tokensmodel.cpp \
    tst_tokens.cpp

HEADERS += ../src/tokensmodel.h
