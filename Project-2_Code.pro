#-------------------------------------------------
#
# Project created by QtCreator 2011-10-15T12:09:18
#
#-------------------------------------------------


TARGET = runme.out
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

SOURCES += main.cpp


documentation.path = ~/Documents
documentation.files = docs/*

INSTALLS +=documentation
#QMAKE_CXX = g++-4.6
QMAKE_CXX = g++
# QMAKE_CXXFLAGS = --std=c++0x

HEADERS += \
    vspcap.h \
    inputfiles.h \
    vsgeneralexception.h \
    callbackfunc.h \
    project2report.h \
    p538project2.h \
    dhcp.h

LIBS -= -lQtGui -lQtCore -lpthread
LIBS += -lpcap
INCLUDEPATH += /myfiles/LinuxProject/verbalsaint/include












