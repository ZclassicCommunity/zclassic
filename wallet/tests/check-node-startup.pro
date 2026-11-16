TEMPLATE = app
TARGET = check-node-startup
CONFIG += console c++14
CONFIG -= app_bundle
QT += core network
QT -= gui
SOURCES += check-node-startup.cpp
SOURCES += ../src/startupaccess.cpp
win32: DEFINES += _WIN32_WINNT=0x0601 WINVER=0x0601
win32: QMAKE_LFLAGS += -static -static-libgcc -static-libstdc++
