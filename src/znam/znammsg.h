// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM (ZCL Names) message bridge — a thin C++ wrapper around the plain-C
// znam_parse()/znam_build_* so the rest of the daemon never includes the C
// header directly. Mirrors zslp/zslpmsg.{h,cpp}.
//
// Unlike ZSLP, znam.h carries no `struct uint256`, so there is no hard type
// clash — but we keep the same bridge boundary for two reasons: (1) znam.h has
// C linkage and no `extern "C"` guard, so it must be included inside one
// extern "C" TU (znammsg.cpp); (2) callers get a daemon-friendly std::string
// POD instead of fixed C char buffers, and the one relay-cap policy lives in
// one place.

#ifndef BITCOIN_ZNAM_ZNAMMSG_H
#define BITCOIN_ZNAM_ZNAMMSG_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/** ZNAM command kinds (mirror enum znam_command, daemon-side; values are the
 *  permanent on-chain command codes). */
enum ZNAMMsgCommand {
    ZNAMMSG_INVALID    = 0,
    ZNAMMSG_REGISTER   = 1,
    ZNAMMSG_UPDATE     = 2,
    ZNAMMSG_TRANSFER   = 3,
    ZNAMMSG_RENEW      = 4,
    ZNAMMSG_SET_RECORD = 5,
    ZNAMMSG_SET_TEXT   = 6,
};

/** ZNAM target types (mirror ZNAM_TYPE_*; permanent on-chain type codes). */
enum ZNAMTargetType {
    ZNAM_TARGET_ONION   = 0x01,
    ZNAM_TARGET_ZADDR   = 0x02,
    ZNAM_TARGET_TADDR   = 0x03,
    ZNAM_TARGET_BTC     = 0x04,
    ZNAM_TARGET_LTC     = 0x05,
    ZNAM_TARGET_DOGE    = 0x06,
    ZNAM_TARGET_CONTENT = 0x07,
};

/** Parsed ZNAM message in a daemon-friendly POD form (no C char buffers). */
struct ZNAMMessage {
    ZNAMMsgCommand command;
    std::string name;
    uint8_t targetType;        // REGISTER/UPDATE/SET_RECORD: a ZNAM_TARGET_*
    std::string targetValue;   // REGISTER/UPDATE/SET_RECORD
    std::string newOwner;      // TRANSFER
    std::string textKey;       // SET_TEXT
    std::string textValue;     // SET_TEXT (may be empty == record deletion)

    ZNAMMessage() : command(ZNAMMSG_INVALID), targetType(0) {}
};

/**
 * Parse a raw OP_RETURN scriptPubKey into a ZNAM message.
 * Returns true and fills `out` when the script is a valid ZNAM message.
 */
bool ZNAMParseScript(const uint8_t* script, size_t scriptLen, ZNAMMessage& out);

/** Daemon-side name validation (mirrors znam_validate_name): lowercase
 *  [a-z0-9-], no leading/trailing hyphen, 1..63 bytes. Also rejects an
 *  embedded NUL (a std::string can carry one; the C validator would stop at
 *  the terminator and mis-accept the prefix). */
bool ZNAMValidateName(const std::string& name);

// ── Build direction (write path) ────────────────────────────────────
//
// Thin C++ wrappers around znam_build_*. Each returns the COMPLETE OP_RETURN
// script bytes (leading 0x6a included), or an EMPTY vector on ANY failure
// (encoder returned 0 = invalid input / buffer, or the produced script exceeds
// the MAX_OP_RETURN_RELAY 223-byte relay cap). An empty return MUST be treated
// by the caller as "invalid / metadata too large" and the build aborted.

std::vector<unsigned char> ZNAMBuildRegister(
    const std::string& name, uint8_t targetType, const std::string& targetValue);
std::vector<unsigned char> ZNAMBuildUpdate(
    const std::string& name, uint8_t targetType, const std::string& targetValue);
std::vector<unsigned char> ZNAMBuildTransfer(
    const std::string& name, const std::string& newOwner);
std::vector<unsigned char> ZNAMBuildRenew(const std::string& name);
std::vector<unsigned char> ZNAMBuildSetRecord(
    const std::string& name, uint8_t targetType, const std::string& targetValue);
std::vector<unsigned char> ZNAMBuildSetText(
    const std::string& name, const std::string& key, const std::string& value);

#endif // BITCOIN_ZNAM_ZNAMMSG_H
