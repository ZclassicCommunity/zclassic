// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Tests for the ported ZSLP Simple Ledger Protocol (SLP) parser and builders.
// Ported from github.com/RhettCreighton/zclassic-c (lib/test/src/test_slp.c),
// translated from the reference's hand-rolled assertions to GoogleTest.
// Covers the same GENESIS / MINT / SEND build + parse round-trips and edge
// cases as the reference.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "zslp/slp.h"

// ── Parse valid GENESIS ───────────────────────────────────────────

TEST(ZSLP, ParseValidGenesis)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "ZCL", "ZClassic Token", "https://zclassic.org", nullptr,
        8, 0, 1000000);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_GENESIS);
    EXPECT_EQ(msg.token_type, SLP_TOKEN_TYPE_1);
    EXPECT_STREQ(msg.ticker, "ZCL");
    EXPECT_STREQ(msg.name, "ZClassic Token");
    EXPECT_STREQ(msg.document_url, "https://zclassic.org");
    EXPECT_FALSE(msg.has_document_hash);
    EXPECT_EQ(msg.decimals, 8);
    EXPECT_EQ(msg.mint_baton_vout, 0);
    EXPECT_EQ(msg.initial_quantity, 1000000u);
}

TEST(ZSLP, ParseGenesisWithDocumentHash)
{
    uint8_t hash[32];
    memset(hash, 0xAB, 32);
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "TEST", "Test Token", "https://example.com", hash,
        4, 2, 5000);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_GENESIS);
    EXPECT_TRUE(msg.has_document_hash);
    EXPECT_EQ(memcmp(msg.document_hash, hash, 32), 0);
    EXPECT_EQ(msg.decimals, 4);
    EXPECT_EQ(msg.mint_baton_vout, 2);
    EXPECT_EQ(msg.initial_quantity, 5000u);
}

// ── Parse valid MINT ──────────────────────────────────────────────

TEST(ZSLP, ParseValidMint)
{
    struct uint256 token_id;
    memset(token_id.data, 0xCC, 32);
    uint8_t buf[256];
    size_t len = slp_build_mint(buf, sizeof(buf), &token_id, 2, 999999);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_MINT);
    EXPECT_EQ(msg.token_type, SLP_TOKEN_TYPE_1);
    EXPECT_EQ(memcmp(msg.token_id.data, token_id.data, 32), 0);
    EXPECT_EQ(msg.mint_baton_vout, 2);
    EXPECT_EQ(msg.additional_quantity, 999999u);
}

TEST(ZSLP, ParseMintNoBaton)
{
    struct uint256 token_id;
    memset(token_id.data, 0xDD, 32);
    uint8_t buf[256];
    size_t len = slp_build_mint(buf, sizeof(buf), &token_id, 0, 42);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_MINT);
    EXPECT_EQ(msg.mint_baton_vout, 0);
    EXPECT_EQ(msg.additional_quantity, 42u);
}

// ── Parse valid SEND ──────────────────────────────────────────────

TEST(ZSLP, ParseValidSendOneOutput)
{
    struct uint256 token_id;
    memset(token_id.data, 0xEE, 32);
    uint64_t qty[] = { 100 };
    uint8_t buf[256];
    size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 1);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_SEND);
    EXPECT_EQ(msg.num_outputs, 1);
    EXPECT_EQ(msg.output_quantities[0], 100u);
}

TEST(ZSLP, ParseValidSendMultipleOutputs)
{
    struct uint256 token_id;
    memset(token_id.data, 0xFF, 32);
    uint64_t qty[] = { 10, 20, 30, 40, 50 };
    uint8_t buf[512];
    size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 5);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_SEND);
    EXPECT_EQ(msg.num_outputs, 5);
    for (int i = 0; i < 5; i++)
        EXPECT_EQ(msg.output_quantities[i], qty[i]);
}

// ── NULL / empty / too-short / malformed scripts ──────────────────

TEST(ZSLP, ParseNullScript)
{
    struct slp_message msg;
    EXPECT_FALSE(slp_parse(nullptr, 0, &msg));
    EXPECT_EQ(msg.type, SLP_TX_INVALID);
}

TEST(ZSLP, ParseEmptyScript)
{
    uint8_t buf[1] = { 0 };
    struct slp_message msg;
    EXPECT_FALSE(slp_parse(buf, 0, &msg));
    EXPECT_EQ(msg.type, SLP_TX_INVALID);
}

TEST(ZSLP, ParseTooShortScriptJustOpReturn)
{
    uint8_t buf[] = { 0x6a };
    struct slp_message msg;
    EXPECT_FALSE(slp_parse(buf, 1, &msg));
}

TEST(ZSLP, ParseScriptNotStartingWithOpReturn)
{
    uint8_t buf[] = { 0x00, 0x04, 'S', 'L', 'P', 0x00 };
    struct slp_message msg;
    EXPECT_FALSE(slp_parse(buf, sizeof(buf), &msg));
}

// ── Invalid lokad_id ──────────────────────────────────────────────

TEST(ZSLP, ParseInvalidLokadId)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "X", "X", "", nullptr, 0, 0, 1);
    ASSERT_GT(len, 0u);
    // lokad_id is at offset 2 (after OP_RETURN + push opcode)
    buf[2] = 'X'; // corrupt first byte of "SLP\0"
    struct slp_message msg;
    EXPECT_FALSE(slp_parse(buf, len, &msg));
}

// ── Wrong token_type ──────────────────────────────────────────────

TEST(ZSLP, ParseWrongTokenType)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "X", "X", "", nullptr, 0, 0, 1);
    ASSERT_GT(len, 0u);
    // lokad_id: OP_RETURN(1) + push(1) + 4 bytes = offset 6
    // token_type: push(1) + 1 byte at offset 7
    buf[7] = 2; // change token_type from 1 to 2
    struct slp_message msg;
    EXPECT_FALSE(slp_parse(buf, len, &msg));
}

// ── Build + parse round-trips ─────────────────────────────────────

TEST(ZSLP, BuildGenesisRoundTrip)
{
    uint8_t hash[32];
    for (int i = 0; i < 32; i++) hash[i] = (uint8_t)i;
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "MYTOKEN", "My Token Name", "https://mytoken.org", hash,
        6, 3, UINT64_C(1000000000000));
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_GENESIS);
    EXPECT_STREQ(msg.ticker, "MYTOKEN");
    EXPECT_STREQ(msg.name, "My Token Name");
    EXPECT_STREQ(msg.document_url, "https://mytoken.org");
    EXPECT_TRUE(msg.has_document_hash);
    EXPECT_EQ(memcmp(msg.document_hash, hash, 32), 0);
    EXPECT_EQ(msg.decimals, 6);
    EXPECT_EQ(msg.mint_baton_vout, 3);
    EXPECT_EQ(msg.initial_quantity, UINT64_C(1000000000000));
}

TEST(ZSLP, BuildMintRoundTrip)
{
    struct uint256 token_id;
    for (int i = 0; i < 32; i++) token_id.data[i] = (uint8_t)(0x10 + i);
    uint8_t buf[256];
    size_t len = slp_build_mint(buf, sizeof(buf), &token_id, 4,
                                UINT64_C(9999999999));
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_MINT);
    EXPECT_EQ(memcmp(msg.token_id.data, token_id.data, 32), 0);
    EXPECT_EQ(msg.mint_baton_vout, 4);
    EXPECT_EQ(msg.additional_quantity, UINT64_C(9999999999));
}

TEST(ZSLP, BuildSendRoundTrip)
{
    struct uint256 token_id;
    memset(token_id.data, 0x55, 32);
    uint64_t qty[] = { 100, 200, 300 };
    uint8_t buf[512];
    size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 3);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_SEND);
    EXPECT_EQ(msg.num_outputs, 3);
    EXPECT_EQ(msg.output_quantities[0], 100u);
    EXPECT_EQ(msg.output_quantities[1], 200u);
    EXPECT_EQ(msg.output_quantities[2], 300u);
}

// ── Edge cases: ticker lengths ────────────────────────────────────

TEST(ZSLP, BuildGenesisEmptyTicker)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "", "No Ticker", "", nullptr, 0, 0, 1);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_GENESIS);
    EXPECT_EQ(msg.ticker[0], '\0'); // empty ticker
    EXPECT_EQ(msg.initial_quantity, 1u);
}

TEST(ZSLP, BuildGenesisNullTicker)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        nullptr, "Null Ticker", "", nullptr, 0, 0, 1);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_GENESIS);
    EXPECT_EQ(msg.ticker[0], '\0');
}

TEST(ZSLP, BuildGenesisMaxLengthTicker63Chars)
{
    char long_ticker[64];
    memset(long_ticker, 'Z', 63);
    long_ticker[63] = '\0';
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        long_ticker, "Long", "", nullptr, 0, 0, 1);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_GENESIS);
    EXPECT_STREQ(msg.ticker, long_ticker);
}

// ── Edge cases: decimals ──────────────────────────────────────────

TEST(ZSLP, BuildGenesisZeroDecimals)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "NDC", "No Decimals Coin", "", nullptr, 0, 0, 100);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.decimals, 0);
}

TEST(ZSLP, BuildGenesisEightDecimals)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "BTC", "Bitcoin Clone", "", nullptr, 8, 0, 2100000000000000ULL);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.decimals, 8);
    EXPECT_EQ(msg.initial_quantity, 2100000000000000ULL);
}

// ── Edge cases: SEND outputs ──────────────────────────────────────

TEST(ZSLP, BuildSendZeroOutputsShouldFail)
{
    struct uint256 token_id;
    memset(token_id.data, 0x11, 32);
    uint64_t qty[] = { 0 };
    uint8_t buf[256];
    size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 0);
    EXPECT_EQ(len, 0u); // builder should reject 0 outputs
}

TEST(ZSLP, BuildSendNineteenOutputsMax)
{
    struct uint256 token_id;
    memset(token_id.data, 0x22, 32);
    uint64_t qty[19];
    for (int i = 0; i < 19; i++) qty[i] = (uint64_t)(i + 1) * 100;
    uint8_t buf[1024];
    size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 19);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_SEND);
    EXPECT_EQ(msg.num_outputs, 19);
    for (int i = 0; i < 19; i++)
        EXPECT_EQ(msg.output_quantities[i], qty[i]);
}

TEST(ZSLP, BuildSendTwentyOutputsOverMaxShouldFail)
{
    struct uint256 token_id;
    memset(token_id.data, 0x33, 32);
    uint64_t qty[20];
    for (int i = 0; i < 20; i++) qty[i] = 1;
    uint8_t buf[1024];
    size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 20);
    EXPECT_EQ(len, 0u); // builder should reject >19 outputs
}

// ── Large quantity (UINT64_MAX) ───────────────────────────────────

TEST(ZSLP, BuildGenesisMaxQuantity)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "MAX", "Max Supply", "", nullptr, 0, 0, UINT64_MAX);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.initial_quantity, UINT64_MAX);
}

TEST(ZSLP, BuildMintMaxQuantity)
{
    struct uint256 token_id;
    memset(token_id.data, 0xAA, 32);
    uint8_t buf[256];
    size_t len = slp_build_mint(buf, sizeof(buf), &token_id, 0, UINT64_MAX);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.additional_quantity, UINT64_MAX);
}

// ── Zero quantity ─────────────────────────────────────────────────

TEST(ZSLP, BuildGenesisZeroQuantity)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "ZERO", "Zero Token", "", nullptr, 0, 0, 0);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.initial_quantity, 0u);
}

// ── Truncated GENESIS (cut off before initial_quantity) ───────────

TEST(ZSLP, ParseTruncatedGenesis)
{
    uint8_t buf[512];
    size_t len = slp_build_genesis(buf, sizeof(buf),
        "X", "X", "", nullptr, 0, 0, 1);
    ASSERT_GT(len, 10u);
    // Truncate to remove the last field (initial_quantity)
    struct slp_message msg;
    EXPECT_FALSE(slp_parse(buf, len - 10, &msg));
}

// ── SEND with zero-value quantities ───────────────────────────────

TEST(ZSLP, BuildSendWithZeroQuantities)
{
    struct uint256 token_id;
    memset(token_id.data, 0x44, 32);
    uint64_t qty[] = { 0, 0, 0 };
    uint8_t buf[512];
    size_t len = slp_build_send(buf, sizeof(buf), &token_id, qty, 3);
    ASSERT_GT(len, 0u);

    struct slp_message msg;
    ASSERT_TRUE(slp_parse(buf, len, &msg));
    EXPECT_EQ(msg.type, SLP_TX_SEND);
    EXPECT_EQ(msg.num_outputs, 3);
    EXPECT_EQ(msg.output_quantities[0], 0u);
    EXPECT_EQ(msg.output_quantities[1], 0u);
    EXPECT_EQ(msg.output_quantities[2], 0u);
}
