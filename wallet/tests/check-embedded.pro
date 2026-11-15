QT = core
CONFIG += console c++14
CONFIG -= app_bundle
TEMPLATE = app
TARGET = check-embedded
SOURCES = check-embedded.cpp ../src/embeddeddaemon.cpp
INCLUDEPATH += ../src
win32: LIBS += -ladvapi32
