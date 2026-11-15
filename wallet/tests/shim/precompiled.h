// ============================================================================
// TEST SHIM precompiled.h  (L0 unit suite — tst_logic)
//
// This is a DELIBERATELY MINIMAL stand-in for src/precompiled.h. It carries
// ONLY the QtCore / QtNetwork-lite includes that the pure-logic translation
// units we link actually use:
//     settings.cpp, senttxstore.cpp, addresscombo.cpp
//
// Crucially it does **NOT** define SODIUM_STATIC and does **NOT** include any
// sodium header, so the test binary needs no libsodium at link time.
//
// It lives on the include path AHEAD of ../src (see tests.pro), so every
// `#include "precompiled.h"` in the linked src/*.cpp resolves to THIS file.
//
// NOTE: no `src/` file is modified — substitution happens purely via the
// INCLUDEPATH ordering in tests.pro.
// ============================================================================
#if defined __cplusplus

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <memory>

#include <QtGlobal>

// --- QtCore: used by settings.cpp / senttxstore.cpp ---
#include <QString>
#include <QStringBuilder>     // the `%` operator used throughout
#include <QStringList>
#include <QByteArray>
#include <QVector>
#include <QList>
#include <QPair>
#include <QMap>
#include <QSettings>
#include <QStandardPaths>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileDevice>
#include <QFileInfo>
#include <QTextStream>
#include <QIODevice>
#include <QDateTime>
#include <QRegExp>
#include <QRegularExpression>
#include <QCryptographicHash>
#include <QLocale>
#include <QObject>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>

// QDialog is referenced only by a Settings::saveRestore signature (not exercised
// at L0) — forward declaration via the lightweight QtCore-friendly include keeps
// the header self-contained without pulling QtWidgets into the PCH for the
// guiless targets. addresscombo.cpp adds QT += widgets which provides the real
// QComboBox/QWidget transitively.
class QDialog;

// The bundled JSON header is referenced by mainwindow.h / rpc.h shims (the
// `using json = nlohmann::json;` aliases). It is header-only.
#include "3rdparty/json/json.hpp"

#define QT6_VIRTUAL

#endif
