// ============================================================================
// securerandom.h — the SINGLE SOURCE OF TRUTH for wallet-secret generation.
//
// CONF-1 / NOTIFY-SRV: EVERY secret the GUI mints — the generated `rpcpassword`
// and the per-session notify token — MUST come from the system CSPRNG
// (`QRandomGenerator::system()`), never `rand()`/`qrand()` (time-seeded and
// predictable; the old randomPassword() drew 10 chars from rand()%62 ≈ 59.5
// bits). Header-only + pure (QtCore only, constructs nothing) so the production
// conf-writer (connection.cpp) AND the L0 unit suite (tst_logic) link the exact
// same body — no hand-copied mirror can silently drift back to a weak RNG.
//
// `QRandomGenerator::system()->bounded(n)` maps a fresh 32-bit CSPRNG draw into
// [0, n) by fixed-point scaling (multiply-shift: v*n >> 32), NOT classic `% n`.
// For n=62 / n=256 the residual non-uniformity is ~2^-26 per draw — far below any
// cryptographic concern and immaterial to the >=128-bit entropy floor below.
// ============================================================================
#ifndef SECURERANDOM_H
#define SECURERANDOM_H

#include <QString>
#include <QChar>
#include <QRandomGenerator>

// Uniformly-random base62 ([0-9A-Za-z]) string of `chars` characters.
// Entropy = chars * log2(62) ≈ chars * 5.954 bits: 22 chars ≈ 131 bits, the
// default 32 ≈ 190 bits — comfortably above the 128-bit CONF-1 floor. base62 is
// used for the rpcpassword because it stays conf-parser-safe: no whitespace,
// '#', '=', or newline that could break a `key=value` line or be read as a
// comment.
inline QString secureRandomBase62(int chars = 32) {
    if (chars <= 0) return QString();   // defensive: never loop on a bad count
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    const quint32 n = (quint32)(sizeof(alphanum) - 1);   // 62
    QRandomGenerator* rng = QRandomGenerator::system();
    QString out;
    out.reserve(chars);
    for (int i = 0; i < chars; ++i)
        out.append(QChar::fromLatin1(alphanum[rng->bounded(n)]));
    return out;
}

// Uniformly-random lowercase-hex string of `bytes` random bytes (2*bytes chars).
// The default 32 bytes = 64 hex chars = 256 bits, and matches the NOTIFY-SRV
// notify-token payload contract exactly: `^[0-9a-f]{64}$`. Hex (not base62) is
// used for the token so the on-the-wire payload is trivially length+charset
// validated before use (no shell/file/RPC injection surface).
inline QString secureRandomHex(int bytes = 32) {
    if (bytes <= 0) return QString();   // defensive: never loop on a bad count
    static const char hexd[] = "0123456789abcdef";
    QRandomGenerator* rng = QRandomGenerator::system();
    QString out;
    out.reserve(bytes * 2);
    for (int i = 0; i < bytes; ++i) {
        quint32 b = rng->bounded((quint32)256);
        out.append(QChar::fromLatin1(hexd[(b >> 4) & 0xF]));
        out.append(QChar::fromLatin1(hexd[b & 0xF]));
    }
    return out;
}

#endif // SECURERANDOM_H
