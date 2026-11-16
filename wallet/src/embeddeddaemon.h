#ifndef ZCL_EMBEDDEDDAEMON_H
#define ZCL_EMBEDDEDDAEMON_H
#include <QString>

// Verify the packaged payload or cached copy; never execute anything here.
QString extractEmbeddedDaemon(const QString& bundle, const QString& cacheRoot,
                              QString* error);
#endif
