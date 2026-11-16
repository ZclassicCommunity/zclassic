TEMPLATE = app
TARGET = check-node-startup
CONFIG += console c++14
CONFIG -= app_bundle
QT += core network
QT -= gui
SOURCES += check-node-startup.cpp
win32: QMAKE_LFLAGS += -static -static-libgcc -static-libstdc++
