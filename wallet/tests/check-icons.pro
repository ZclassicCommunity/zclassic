QT = core gui widgets
CONFIG += console c++14
CONFIG -= app_bundle
TEMPLATE = app
TARGET = check-icons
SOURCES = check-icons.cpp ../src/fillediconlabel.cpp
HEADERS = ../src/fillediconlabel.h
INCLUDEPATH = ../src
RESOURCES = ../application.qrc

static {
    win32: QTPLUGIN.platforms = qwindows qoffscreen
    else: QTPLUGIN.platforms = qoffscreen
}
