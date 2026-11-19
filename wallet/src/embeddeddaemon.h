#ifndef ZCL_EMBEDDEDDAEMON_H
#define ZCL_EMBEDDEDDAEMON_H
#include <QFile>
#include <QString>
#include <memory>

// Verify the packaged payload or cached copy; never execute anything here.
//
// Layout at the end of the all-in-one executable:
//   [ image ][ daemon ][ sha256(daemon) :32 ][ daemon length :8 LE ][ "ZQWDMON1" ]
// The footer is found at the very end of the file or, for an
// Authenticode-signed executable (the signature appends an attribute certificate
// table, 8-byte aligned, after everything), immediately before that table as named
// by the PE security data directory. Non-PE files (ELF, Mach-O) use the end only.
QString extractEmbeddedDaemon(const QString& bundle, const QString& cacheRoot,
                              QString* error);

// Hold the exact file that is about to be launched. Construct it right before the
// QProcess is started and keep it alive until start() has returned (on Windows
// QProcess::start has created the process by then, so the running image is the
// verified one).
//
// A program that does not sit in <cacheRoot>/zclassic-node/<64 hex>/ (a sibling
// zclassicd shipped in the bundle, a system install) is NotCached: nothing is done
// and the caller launches as before. For a cached program the file is opened without
// following links, hashed through that open handle against the digest that names its
// directory, and, on Windows, kept open with a share mode that denies write, delete
// and rename of the file (and so of its directories) until destruction. On POSIX the
// file, its directory and the cache directory must also be owned by this user and not
// group/world-writable. Any failure is Failed with a message: the caller must not
// launch.
class EmbeddedDaemonPin {
public:
    enum Status { NotCached, Pinned, Failed };
    EmbeddedDaemonPin(const QString& program, const QString& cacheRoot);
    ~EmbeddedDaemonPin();
    EmbeddedDaemonPin(const EmbeddedDaemonPin&) = delete;
    EmbeddedDaemonPin& operator=(const EmbeddedDaemonPin&) = delete;
    Status status() const { return status_; }
    const QString& error() const { return error_; }
private:
    Status status_ = NotCached;
    QString error_;
    std::unique_ptr<QFile> file_;
};
#endif
