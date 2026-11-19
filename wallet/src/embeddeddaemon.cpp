#include "embeddeddaemon.h"
#include "privatefile.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStorageInfo>
#ifdef Q_OS_WIN
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

const qint64 kFooterSize = 48;                       // sha256 + length + magic
const quint64 kMaxDaemon = 512ull * 1024 * 1024;

quint32 le32(const QByteArray& b, int o) {
    quint32 v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | quint32(uchar(b.at(o + i)));
    return v;
}
quint16 le16(const QByteArray& b, int o) {
    return quint16(uchar(b.at(o)) | (uchar(b.at(o + 1)) << 8));
}
bool readAt(QFile& f, qint64 offset, int length, QByteArray* out) {
    if (offset < 0 || !f.seek(offset)) return false;
    *out = f.read(length);
    return out->size() == length;
}

// What the footer search needs from a PE (Windows) executable.
struct PeInfo {
    bool isPe = false;
    bool hasCertTable = false;
    qint64 certOffset = 0;   // file offset of the attribute certificate table
    qint64 certSize = 0;
    qint64 imageEnd = 0;     // end of the headers and of every section's raw data
};

// A file without a valid MZ/PE signature is not a PE (ELF, Mach-O, test fixtures):
// isPe stays false and the caller uses the end-of-file rule. A PE whose headers are
// damaged is an error, never silently treated as "no certificate".
bool parsePe(QFile& f, PeInfo* pe, QString* why) {
    const qint64 size = f.size();
    QByteArray dos;
    if (!readAt(f, 0, 64, &dos) || dos.left(2) != "MZ") return true;
    const quint32 peOffset = le32(dos, 0x3c);
    QByteArray head;
    if (peOffset < 64 || qint64(peOffset) + 24 > size || !readAt(f, peOffset, 24, &head) ||
        head.left(4) != QByteArray("PE\0\0", 4))
        return true;
    pe->isPe = true;
    auto bad = [&](const char* text) { *why = QString::fromLatin1(text); return false; };
    const int sections = le16(head, 6);
    const int optSize = le16(head, 20);
    const qint64 optOffset = qint64(peOffset) + 24;
    QByteArray opt;
    if (optSize < 96 || !readAt(f, optOffset, qMin(optSize, 240), &opt) || opt.size() < 96)
        return bad("Malformed PE header");
    const quint16 magic = le16(opt, 0);
    int dirBase = 0, countOffset = 0;
    if (magic == 0x10b) { dirBase = 96; countOffset = 92; }
    else if (magic == 0x20b) { dirBase = 112; countOffset = 108; }
    else return bad("Malformed PE header");
    if (opt.size() < dirBase) return bad("Malformed PE header");
    qint64 imageEnd = le32(opt, 60);                 // SizeOfHeaders
    if (sections > 96) return bad("Malformed PE header");
    QByteArray table;
    if (sections && !readAt(f, optOffset + optSize, sections * 40, &table))
        return bad("Malformed PE section table");
    for (int i = 0; i < sections; ++i) {
        const qint64 end = qint64(le32(table, i * 40 + 20)) + le32(table, i * 40 + 16);
        if (end > imageEnd) imageEnd = end;
    }
    pe->imageEnd = imageEnd;
    const quint32 directories = le32(opt, countOffset);
    if (directories > 4 && opt.size() >= dirBase + 5 * 8) {
        const quint32 offset = le32(opt, dirBase + 4 * 8);
        const quint32 length = le32(opt, dirBase + 4 * 8 + 4);
        if (offset || length) {
            pe->hasCertTable = true;
            pe->certOffset = offset;                 // a file offset, not an RVA
            pe->certSize = length;
        }
    }
    return true;
}

// Footer layout: [sha256 :32][length :8 LE][magic :8]; the daemon ends where it starts.
// Returns the offset just past the magic, or -1 with `why` set.
qint64 locateFooterEnd(QFile& f, const PeInfo& pe, QString* why) {
    const qint64 size = f.size();
    auto magicEndsAt = [&](qint64 end) {
        QByteArray tail;
        return end >= kFooterSize && readAt(f, end - 8, 8, &tail) && tail == "ZQWDMON1";
    };
    if (pe.isPe && pe.hasCertTable) {
        // Authenticode puts the certificate table last, so it must end exactly at the
        // end of the file and start after the image; nothing else may follow it.
        if (pe.certSize <= 0 || pe.certOffset < pe.imageEnd ||
            pe.certOffset > size || pe.certSize != size - pe.certOffset) {
            *why = QStringLiteral("Inconsistent PE certificate table");
            return -1;
        }
        // The signer pads the file with zero bytes (at most 7) to 8-byte alignment
        // before the table, so the footer ends 0..7 zero bytes before it.
        for (qint64 pad = 0; pad < 8; ++pad) {
            const qint64 end = pe.certOffset - pad;
            if (!magicEndsAt(end)) continue;
            QByteArray gap;
            if (pad && (!readAt(f, end, int(pad), &gap) || gap != QByteArray(int(pad), '\0')))
                continue;
            return end;
        }
        *why = QStringLiteral("Missing embedded daemon footer before the certificate table");
        return -1;
    }
    if (size < kFooterSize || !magicEndsAt(size)) {
        *why = size < kFooterSize ? QStringLiteral("Missing embedded daemon footer")
                                  : QStringLiteral("Missing or truncated embedded daemon footer");
        return -1;
    }
    return size;
}

#ifdef Q_OS_WIN
Qt::CaseSensitivity pathCase() { return Qt::CaseInsensitive; }
#else
Qt::CaseSensitivity pathCase() { return Qt::CaseSensitive; }

bool privateOwnedByUs(const struct stat& st, bool directory) {
    if (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) return false;
    return st.st_uid == geteuid() && !(st.st_mode & (S_IWGRP | S_IWOTH));
}
// The cache directories hold code this process will execute: ours alone may write.
bool privateDirectory(const QString& path, bool tighten) {
    const QByteArray native = QFile::encodeName(path);
    struct stat st;
    if (lstat(native.constData(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid())
        return false;
    if (!(st.st_mode & (S_IWGRP | S_IWOTH))) return true;
    return tighten && chmod(native.constData(), st.st_mode & ~mode_t(S_IWGRP | S_IWOTH)) == 0;
}
#endif

} // namespace

QString extractEmbeddedDaemon(const QString& bundle, const QString& cacheRoot,
                              QString* error) {
    if (error) error->clear();
    auto fail = [error](const QString& why) {
        if (error) *error = why;
        return QString();
    };
    QFile self(bundle);
    if (!self.open(QIODevice::ReadOnly)) return fail(self.errorString());
    PeInfo pe;
    QString why;
    if (!parsePe(self, &pe, &why)) return fail(why);
    const qint64 footerEnd = locateFooterEnd(self, pe, &why);
    if (footerEnd < 0) return fail(why);
    QByteArray footer;
    if (!readAt(self, footerEnd - kFooterSize, int(kFooterSize), &footer))
        return fail(QStringLiteral("Missing or truncated embedded daemon footer"));
    quint64 length = 0;
    for (int i = 0; i < 8; ++i)
        length |= quint64(uchar(footer.at(32 + i))) << (8 * i);
    // The daemon must fit between the start of the file (or the end of the PE image)
    // and the footer; anything else is an inconsistent or overlapping length.
    const qint64 floor = pe.isPe ? pe.imageEnd : 0;
    if (!length || length > kMaxDaemon || length > quint64(footerEnd - kFooterSize) ||
        qint64(footerEnd - kFooterSize) - qint64(length) < floor)
        return fail(QStringLiteral("Invalid embedded daemon length"));
    const qint64 daemonStart = footerEnd - kFooterSize - qint64(length);
    const QByteArray expected = footer.left(32);
    if (cacheRoot.isEmpty()) return fail(QStringLiteral("No writable cache location"));
    const QString directory = QDir(cacheRoot).filePath(
        "zclassic-node/" + QString::fromLatin1(expected.toHex()));
    if (!QDir().mkpath(directory)) return fail(QStringLiteral("Cannot create daemon cache"));
#ifndef Q_OS_WIN
    if (!privateDirectory(QDir(cacheRoot).filePath("zclassic-node"), true) ||
        !privateDirectory(directory, true))
        return fail(QStringLiteral("Daemon cache directory is not private to this user"));
#endif
#ifdef Q_OS_WIN
    const QString path = QDir(directory).filePath("zqw-zclassicd.exe");
#else
    const QString path = QDir(directory).filePath("zqw-zclassicd");
#endif
    // A cache name and matching size do not establish integrity. Rehash before use.
    QFile cached(path);
    if (!QFileInfo(path).isSymLink() && cached.open(QIODevice::ReadOnly) &&
        cached.size() == qint64(length)) {
        QCryptographicHash hash(QCryptographicHash::Sha256);
        if (hash.addData(&cached) && hash.result() == expected) {
            if (!makeFileOwnerOnly(cached))
                return fail(QStringLiteral("Cannot restrict cached daemon permissions"));
#ifndef Q_OS_WIN
            if (!cached.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                                       QFileDevice::ExeOwner))
                return fail(QStringLiteral("Cannot set daemon executable permissions"));
#endif
            return path;
        }
    }
    cached.close();
    if (QFileInfo(path).isSymLink()) return fail(QStringLiteral("Daemon cache is a symbolic link"));
    const qint64 available = QStorageInfo(directory).bytesAvailable();
    if (available >= 0 && available < qint64(length) + (16ll << 20))
        return fail(QStringLiteral("Insufficient disk space for embedded daemon"));
    if (!self.seek(daemonStart))
        return fail(QStringLiteral("Cannot seek to embedded daemon"));
    // QSaveFile owns a unique temporary file and checks flush/rename at commit.
    // Never truncate the previous cache or follow a predictable .part symlink.
    QSaveFile out(path);
    out.setDirectWriteFallback(false);
    if (!out.open(QIODevice::WriteOnly) || !makeFileOwnerOnly(out))
        return fail(QStringLiteral("Cannot create private daemon cache file: ") + out.errorString());
#ifndef Q_OS_WIN
    if (!out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner |
                           QFileDevice::ExeOwner))
        return fail(QStringLiteral("Cannot set daemon executable permissions"));
#endif
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 remaining = qint64(length);
    while (remaining > 0) {
        const QByteArray bytes = self.read(qMin(remaining, qint64(1 << 20)));
        if (bytes.isEmpty() || out.write(bytes) != bytes.size())
            return fail(QStringLiteral("Embedded daemon read/write failed"));
        hash.addData(bytes);
        remaining -= bytes.size();
    }
    if (hash.result() != expected) return fail(QStringLiteral("Embedded daemon hash mismatch"));
    if (!out.commit()) return fail(QStringLiteral("Cannot publish daemon cache: ") + out.errorString());
    return path;
}

EmbeddedDaemonPin::EmbeddedDaemonPin(const QString& program, const QString& cacheRoot) {
    if (program.isEmpty() || cacheRoot.isEmpty()) return;
    // <cacheRoot>/zclassic-node/<64 hex digest>/<file>: the digest is the file's name.
    const QString root = QDir::cleanPath(QDir(cacheRoot).absoluteFilePath("zclassic-node"));
    const QFileInfo info(QDir::cleanPath(QDir::current().absoluteFilePath(program)));
    const QString dir = info.absolutePath();
    if (!dir.startsWith(root + '/', pathCase()) || QFileInfo(dir).dir().path().compare(root, pathCase()) != 0)
        return;                                       // not the extracted cache: not ours to pin
    const QString digest = QFileInfo(dir).fileName();
    static const QRegularExpression hex(QStringLiteral("^[0-9a-f]{64}$"));
    status_ = Failed;
    if (!hex.match(digest).hasMatch()) {
        error_ = QStringLiteral("Daemon cache path is not content-addressed");
        return;
    }
    const QByteArray expected = QByteArray::fromHex(digest.toLatin1());
    auto file = std::make_unique<QFile>();
#ifdef Q_OS_WIN
    const QString native = QDir::toNativeSeparators(info.absoluteFilePath());
    HANDLE handle = INVALID_HANDLE_VALUE;
    // FILE_SHARE_READ only: while this handle lives nobody can open the file for
    // writing, delete or rename it, nor rename a directory above it. Retry briefly
    // for a scanner that holds it open without FILE_SHARE_READ.
    for (int attempt = 0; attempt < 10; ++attempt) {
        handle = CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle != INVALID_HANDLE_VALUE || GetLastError() != ERROR_SHARING_VIOLATION) break;
        Sleep(100);
    }
    if (handle == INVALID_HANDLE_VALUE) {
        error_ = QStringLiteral("Cannot open the extracted daemon exclusively (win32 error %1)")
                     .arg(GetLastError());
        return;
    }
    BY_HANDLE_FILE_INFORMATION details;
    if (!GetFileInformationByHandle(handle, &details) ||
        (details.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) {
        CloseHandle(handle);
        error_ = QStringLiteral("Extracted daemon is not a regular file");
        return;
    }
    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle), _O_RDONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(handle);
        error_ = QStringLiteral("Cannot adopt the extracted daemon handle");
        return;
    }
    if (!file->open(fd, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
        _close(fd);
        error_ = QStringLiteral("Cannot read the extracted daemon: ") + file->errorString();
        return;
    }
#else
    const QByteArray native = QFile::encodeName(info.absoluteFilePath());
    const int fd = ::open(native.constData(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        error_ = QStringLiteral("Cannot open the extracted daemon without following links");
        return;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !privateOwnedByUs(st, false) ||
        !privateDirectory(dir, false) || !privateDirectory(root, false)) {
        ::close(fd);
        error_ = QStringLiteral("Extracted daemon or its directory is not private to this user");
        return;
    }
    if (!file->open(fd, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
        ::close(fd);
        error_ = QStringLiteral("Cannot read the extracted daemon: ") + file->errorString();
        return;
    }
#endif
    // Hash exactly the bytes behind the handle we keep.
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(file.get()) || hash.result() != expected) {
        error_ = QStringLiteral("Extracted daemon hash mismatch; refusing to start it");
        return;
    }
    file_ = std::move(file);
    status_ = Pinned;
}

EmbeddedDaemonPin::~EmbeddedDaemonPin() = default;
