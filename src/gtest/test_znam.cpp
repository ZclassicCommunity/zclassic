// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM (ZCL Names) parser + builder round-trip and rejection tests, exercised
// through the daemon-side bridge (zslp-style). The wire bytes these assert are
// PERMANENT — see doc/platform/ZNAM_DETERMINISM_SPEC.md.

#include <gtest/gtest.h>

#include "znam/znammsg.h"

#include <string>
#include <vector>

namespace {

std::vector<unsigned char> raw(std::initializer_list<int> bytes)
{
    std::vector<unsigned char> v;
    for (int b : bytes) v.push_back((unsigned char)(b & 0xff));
    return v;
}

bool parse(const std::vector<unsigned char>& s, ZNAMMessage& out)
{
    return ZNAMParseScript(s.data(), s.size(), out);
}

} // namespace

// ── Name validation ──────────────────────────────────────────────────

TEST(ZNAM, ValidateNameAccepts)
{
    EXPECT_TRUE(ZNAMValidateName("a"));
    EXPECT_TRUE(ZNAMValidateName("alice"));
    EXPECT_TRUE(ZNAMValidateName("alice-bob"));
    EXPECT_TRUE(ZNAMValidateName("a1b2c3"));
    EXPECT_TRUE(ZNAMValidateName("0"));
    EXPECT_TRUE(ZNAMValidateName(std::string(63, 'a'))); // max length
}

TEST(ZNAM, ValidateNameRejects)
{
    EXPECT_FALSE(ZNAMValidateName(""));                    // empty
    EXPECT_FALSE(ZNAMValidateName(std::string(64, 'a')));  // too long
    EXPECT_FALSE(ZNAMValidateName("-alice"));              // leading hyphen
    EXPECT_FALSE(ZNAMValidateName("alice-"));              // trailing hyphen
    EXPECT_FALSE(ZNAMValidateName("Alice"));               // uppercase
    EXPECT_FALSE(ZNAMValidateName("al ice"));              // space
    EXPECT_FALSE(ZNAMValidateName("ali.ce"));              // dot
    EXPECT_FALSE(ZNAMValidateName("ali_ce"));              // underscore
    EXPECT_FALSE(ZNAMValidateName(std::string("a\0b", 3))); // embedded NUL
    // unicode/homoglyph reject-don't-normalize (bytes >= 0x80)
    EXPECT_FALSE(ZNAMValidateName("\xc3\xa9"));            // 'é' UTF-8
}

// ── REGISTER ─────────────────────────────────────────────────────────

TEST(ZNAM, RegisterRoundTripOnion)
{
    const std::string onion =
        "c3jj5rang52ev5ijv3v2zlnez2uymsbdxyh7n5b5lf7b42urt3fhmrad.onion";
    auto s = ZNAMBuildRegister("alice", ZNAM_TARGET_ONION, onion);
    ASSERT_FALSE(s.empty());
    EXPECT_EQ(s[0], 0x6a); // OP_RETURN

    ZNAMMessage m;
    ASSERT_TRUE(parse(s, m));
    EXPECT_EQ(m.command, ZNAMMSG_REGISTER);
    EXPECT_EQ(m.name, "alice");
    EXPECT_EQ(m.targetType, ZNAM_TARGET_ONION);
    EXPECT_EQ(m.targetValue, onion);
}

TEST(ZNAM, RegisterRoundTripAllTargetTypes)
{
    for (int t = ZNAM_TARGET_ONION; t <= ZNAM_TARGET_CONTENT; ++t) {
        auto s = ZNAMBuildRegister("name", (uint8_t)t, "value-data");
        ASSERT_FALSE(s.empty()) << "type " << t;
        ZNAMMessage m;
        ASSERT_TRUE(parse(s, m)) << "type " << t;
        EXPECT_EQ(m.command, ZNAMMSG_REGISTER);
        EXPECT_EQ((int)m.targetType, t);
        EXPECT_EQ(m.targetValue, "value-data");
    }
}

TEST(ZNAM, RegisterRejectsBadTargetType)
{
    // type 0 and type 8 are out of the 1..7 range -> empty build
    EXPECT_TRUE(ZNAMBuildRegister("name", 0, "v").empty());
    EXPECT_TRUE(ZNAMBuildRegister("name", 8, "v").empty());
}

TEST(ZNAM, RegisterRejectsInvalidName)
{
    EXPECT_TRUE(ZNAMBuildRegister("Alice", ZNAM_TARGET_ONION, "v").empty());
    EXPECT_TRUE(ZNAMBuildRegister("-x", ZNAM_TARGET_ONION, "v").empty());
    EXPECT_TRUE(ZNAMBuildRegister(std::string(64, 'a'), ZNAM_TARGET_ONION, "v").empty());
}

// ── UPDATE / TRANSFER / RENEW / SET_RECORD ───────────────────────────

TEST(ZNAM, UpdateRoundTrip)
{
    auto s = ZNAMBuildUpdate("alice", ZNAM_TARGET_TADDR, "t1abc");
    ASSERT_FALSE(s.empty());
    ZNAMMessage m;
    ASSERT_TRUE(parse(s, m));
    EXPECT_EQ(m.command, ZNAMMSG_UPDATE);
    EXPECT_EQ(m.name, "alice");
    EXPECT_EQ(m.targetType, ZNAM_TARGET_TADDR);
    EXPECT_EQ(m.targetValue, "t1abc");
}

TEST(ZNAM, TransferRoundTrip)
{
    auto s = ZNAMBuildTransfer("alice", "t1NewOwnerAddress");
    ASSERT_FALSE(s.empty());
    ZNAMMessage m;
    ASSERT_TRUE(parse(s, m));
    EXPECT_EQ(m.command, ZNAMMSG_TRANSFER);
    EXPECT_EQ(m.name, "alice");
    EXPECT_EQ(m.newOwner, "t1NewOwnerAddress");
}

TEST(ZNAM, RenewRoundTrip)
{
    auto s = ZNAMBuildRenew("alice");
    ASSERT_FALSE(s.empty());
    ZNAMMessage m;
    ASSERT_TRUE(parse(s, m));
    EXPECT_EQ(m.command, ZNAMMSG_RENEW);
    EXPECT_EQ(m.name, "alice");
}

TEST(ZNAM, SetRecordRoundTrip)
{
    auto s = ZNAMBuildSetRecord("alice", ZNAM_TARGET_BTC, "bc1qxyz");
    ASSERT_FALSE(s.empty());
    ZNAMMessage m;
    ASSERT_TRUE(parse(s, m));
    EXPECT_EQ(m.command, ZNAMMSG_SET_RECORD);
    EXPECT_EQ(m.targetType, ZNAM_TARGET_BTC);
    EXPECT_EQ(m.targetValue, "bc1qxyz");
}

// ── SET_TEXT ─────────────────────────────────────────────────────────

TEST(ZNAM, SetTextRoundTrip)
{
    auto s = ZNAMBuildSetText("alice", "url", "https://zclassic.org");
    ASSERT_FALSE(s.empty());
    ZNAMMessage m;
    ASSERT_TRUE(parse(s, m));
    EXPECT_EQ(m.command, ZNAMMSG_SET_TEXT);
    EXPECT_EQ(m.textKey, "url");
    EXPECT_EQ(m.textValue, "https://zclassic.org");
}

TEST(ZNAM, SetTextEmptyValueIsDeletion)
{
    auto s = ZNAMBuildSetText("alice", "url", "");
    ASSERT_FALSE(s.empty());
    ZNAMMessage m;
    ASSERT_TRUE(parse(s, m));
    EXPECT_EQ(m.command, ZNAMMSG_SET_TEXT);
    EXPECT_EQ(m.textKey, "url");
    EXPECT_TRUE(m.textValue.empty());
}

TEST(ZNAM, SetTextEmptyKeyRejected)
{
    EXPECT_TRUE(ZNAMBuildSetText("alice", "", "v").empty());
}

TEST(ZNAM, SetTextOverRelayCapReturnsEmpty)
{
    // name(63) + key(32) + value(128) exceeds the 223-byte OP_RETURN relay cap.
    auto s = ZNAMBuildSetText(std::string(63, 'a'), std::string(32, 'k'),
                              std::string(128, 'v'));
    EXPECT_TRUE(s.empty());
}

// ── Malformed-script rejection (permanent framing invariants) ─────────

TEST(ZNAM, RejectsNonOpReturn)
{
    ZNAMMessage m;
    EXPECT_FALSE(parse(raw({0x6b, 0x04, 'Z', 'N', 'A', 'M'}), m));
}

TEST(ZNAM, RejectsBadLokad)
{
    ZNAMMessage m;
    // "ZNAX" instead of "ZNAM"
    EXPECT_FALSE(parse(raw({0x6a, 0x04, 'Z', 'N', 'A', 'X',
                            0x01, 0x01, 0x01, 0x01, 0x01, 'a'}), m));
}

TEST(ZNAM, RejectsBadVersion)
{
    ZNAMMessage m;
    // version 2
    EXPECT_FALSE(parse(raw({0x6a, 0x04, 'Z', 'N', 'A', 'M',
                            0x01, 0x02, 0x01, 0x01, 0x01, 'a'}), m));
}

TEST(ZNAM, RejectsBadCommand)
{
    ZNAMMessage m;
    // command 7 (out of 1..6)
    EXPECT_FALSE(parse(raw({0x6a, 0x04, 'Z', 'N', 'A', 'M',
                            0x01, 0x01, 0x01, 0x07, 0x01, 'a'}), m));
    // command 0
    EXPECT_FALSE(parse(raw({0x6a, 0x04, 'Z', 'N', 'A', 'M',
                            0x01, 0x01, 0x01, 0x00, 0x01, 'a'}), m));
}

TEST(ZNAM, RejectsInvalidNameInScript)
{
    ZNAMMessage m;
    // REGISTER with uppercase name 'A' -> validate_name fails
    EXPECT_FALSE(parse(raw({0x6a, 0x04, 'Z', 'N', 'A', 'M',
                            0x01, 0x01, 0x01, 0x01, 0x01, 'A'}), m));
}

TEST(ZNAM, RejectsTruncatedScript)
{
    ZNAMMessage m;
    // declares REGISTER but is cut off before target_type
    EXPECT_FALSE(parse(raw({0x6a, 0x04, 'Z', 'N', 'A', 'M',
                            0x01, 0x01, 0x01, 0x01, 0x01, 'a'}), m));
}

TEST(ZNAM, RejectsBadTargetTypeInScript)
{
    ZNAMMessage m;
    // REGISTER "a" target_type 8 (out of 1..7) value "x"
    EXPECT_FALSE(parse(raw({0x6a, 0x04, 'Z', 'N', 'A', 'M',
                            0x01, 0x01, 0x01, 0x01, 0x01, 'a',
                            0x01, 0x08, 0x01, 'x'}), m));
}

TEST(ZNAM, RejectsEmptyScript)
{
    ZNAMMessage m;
    EXPECT_FALSE(parse(raw({}), m));
}
