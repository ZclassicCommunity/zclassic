// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM message bridge implementation. This translation unit is the ONLY place
// that includes the plain-C znam.h (which has C linkage and no extern "C"
// guard); it is wrapped in extern "C" here. Mirrors zslp/zslpmsg.cpp. Keep this
// file's includes minimal.

#include "znam/znammsg.h"

#include <cstring>

extern "C" {
#include "znam/znam.h"
}

// Compile-time proof the daemon-side enum values match the C protocol numbers,
// so the two layers never disagree about the permanent wire command/type codes.
static_assert((int)ZNAMMSG_REGISTER   == (int)ZNAM_CMD_REGISTER,   "ZNAM REGISTER code mismatch");
static_assert((int)ZNAMMSG_UPDATE     == (int)ZNAM_CMD_UPDATE,     "ZNAM UPDATE code mismatch");
static_assert((int)ZNAMMSG_TRANSFER   == (int)ZNAM_CMD_TRANSFER,   "ZNAM TRANSFER code mismatch");
static_assert((int)ZNAMMSG_RENEW      == (int)ZNAM_CMD_RENEW,      "ZNAM RENEW code mismatch");
static_assert((int)ZNAMMSG_SET_RECORD == (int)ZNAM_CMD_SET_RECORD, "ZNAM SET_RECORD code mismatch");
static_assert((int)ZNAMMSG_SET_TEXT   == (int)ZNAM_CMD_SET_TEXT,   "ZNAM SET_TEXT code mismatch");
static_assert((int)ZNAM_TARGET_ONION   == (int)ZNAM_TYPE_ONION,   "ZNAM ONION type mismatch");
static_assert((int)ZNAM_TARGET_CONTENT == (int)ZNAM_TYPE_CONTENT, "ZNAM CONTENT type mismatch");
static_assert(ZNAM_NAME_MAX == 63, "ZNAM name cap changed (permanent wire constant)");

bool ZNAMValidateName(const std::string& name)
{
    // A std::string can carry an embedded NUL; the C validator stops at the
    // terminator and would mis-accept the prefix. Reject it up front, then
    // defer to the single authoritative C rule.
    if (name.find('\0') != std::string::npos) return false;
    return znam_validate_name(name.c_str());
}

bool ZNAMParseScript(const uint8_t* script, size_t scriptLen, ZNAMMessage& out)
{
    struct znam_message msg;
    if (!znam_parse(script, scriptLen, &msg))
        return false;

    out = ZNAMMessage();
    out.command = (ZNAMMsgCommand)msg.command;
    out.name = msg.name;

    switch (msg.command) {
    case ZNAM_CMD_REGISTER:
    case ZNAM_CMD_UPDATE:
    case ZNAM_CMD_SET_RECORD:
        out.targetType = msg.target_type;
        out.targetValue = msg.target_value;
        return true;
    case ZNAM_CMD_TRANSFER:
        out.newOwner = msg.new_owner;
        return true;
    case ZNAM_CMD_RENEW:
        return true;
    case ZNAM_CMD_SET_TEXT:
        out.textKey = msg.text_key;
        out.textValue = msg.text_value;
        return true;
    default:
        return false;
    }
}

// ── Build direction ─────────────────────────────────────────────────

// Relay cap mirrored locally for include-minimalism parity with zslpmsg.cpp.
// Kept equal to MAX_OP_RETURN_RELAY (script/standard.h:34).
static const size_t ZNAM_BRIDGE_MAX_OP_RETURN_RELAY = 223;

// A 256-byte scratch buffer comfortably exceeds the 223-byte relay cap, so an
// over-cap message is detected by the length check below rather than truncating.
static const size_t ZNAM_BUILD_BUF = 256;

static std::vector<unsigned char> FinishBuild(const uint8_t* buf, size_t n)
{
    if (n == 0)
        return std::vector<unsigned char>(); // encoder failure / invalid input
    if (n > ZNAM_BRIDGE_MAX_OP_RETURN_RELAY)
        return std::vector<unsigned char>(); // too large for one relayed OP_RETURN
    return std::vector<unsigned char>(buf, buf + n);
}

std::vector<unsigned char> ZNAMBuildRegister(
    const std::string& name, uint8_t targetType, const std::string& targetValue)
{
    uint8_t buf[ZNAM_BUILD_BUF];
    size_t n = znam_build_register(buf, sizeof(buf), name.c_str(),
                                   targetType, targetValue.c_str());
    return FinishBuild(buf, n);
}

std::vector<unsigned char> ZNAMBuildUpdate(
    const std::string& name, uint8_t targetType, const std::string& targetValue)
{
    uint8_t buf[ZNAM_BUILD_BUF];
    size_t n = znam_build_update(buf, sizeof(buf), name.c_str(),
                                 targetType, targetValue.c_str());
    return FinishBuild(buf, n);
}

std::vector<unsigned char> ZNAMBuildTransfer(
    const std::string& name, const std::string& newOwner)
{
    uint8_t buf[ZNAM_BUILD_BUF];
    size_t n = znam_build_transfer(buf, sizeof(buf), name.c_str(),
                                   newOwner.c_str());
    return FinishBuild(buf, n);
}

std::vector<unsigned char> ZNAMBuildRenew(const std::string& name)
{
    uint8_t buf[ZNAM_BUILD_BUF];
    size_t n = znam_build_renew(buf, sizeof(buf), name.c_str());
    return FinishBuild(buf, n);
}

std::vector<unsigned char> ZNAMBuildSetRecord(
    const std::string& name, uint8_t targetType, const std::string& targetValue)
{
    uint8_t buf[ZNAM_BUILD_BUF];
    size_t n = znam_build_set_record(buf, sizeof(buf), name.c_str(),
                                     targetType, targetValue.c_str());
    return FinishBuild(buf, n);
}

std::vector<unsigned char> ZNAMBuildSetText(
    const std::string& name, const std::string& key, const std::string& value)
{
    // znam_build_set_text accepts an empty value (record deletion) but rejects
    // an empty key (returns 0). Pass value through as a C string; an empty
    // std::string yields an empty push, matching the C builder's value==""
    // path.
    uint8_t buf[ZNAM_BUILD_BUF];
    size_t n = znam_build_set_text(buf, sizeof(buf), name.c_str(),
                                   key.c_str(), value.c_str());
    return FinishBuild(buf, n);
}
