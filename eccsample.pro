TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c
LIBS += -lssl -lcrypto
include(deployment.pri)
qtcAddDeployment()

