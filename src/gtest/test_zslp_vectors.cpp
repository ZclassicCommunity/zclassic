// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP R-VECTORS corpus — the cross-implementation AGREEMENT contract.
//
// Security for the ZSLP overlay IS cross-implementation bit-exact agreement
// (SECURITY_MODEL.md §1.3): there is no consensus over the token ledger, so two
// observers that disagree on ANY edge case fork the ledger and the attacker
// shows each victim a different "ownership truth". This file is the published,
// versioned set of adversarial input -> expected-result vectors that pins every
// canonical rule unambiguously, so any second implementation of F can prove
// agreement (R-VECTORS / R-DIFF, SECURITY_MODEL.md §7 closure criterion).
//
// Two layers are covered:
//   (A) PARSER vectors: a raw OP_RETURN byte string -> expected parse
//       accept/reject (and the parsed fields). These exercise the REAL canonical
//       parser (slp_parse via ZSLPParseScript), the load-bearing push grammar,
//       field-length, quantity-domain, trailing-data, and SEND-cap rules.
//   (B) LEDGER vectors: a transaction (or same-block sequence) -> expected
//       ledger snapshot (token rows / token-UTXO set / balances). These exercise
//       the REAL indexer parse seam (CZSLPIndexer::ParseTx — vout[0]-ONLY,
//       coinbase-skip) feeding the REAL store (CZSLPStore::ApplyTransaction),
//       i.e. the exact production path, with no chain state required.
//
// Rule keys (R-*) reference SECURITY_MODEL.md. Where the prose split (R-SEND-4),
// SECURITY_MODEL.md §2.6 PINS Reading A (out-of-range positive quantity burns
// ONLY that quantity; in-range outputs still apply; budget checked first) at
// ZSLP_SPEC_VERSION = 1 — these vectors are the authoritative tiebreaker.

#include <gtest/gtest.h>

#include "primitives/transaction.h"
#include "script/script.h"
#include "uint256.h"
#include "zslp/zslpindexer.h"
#include "zslp/zslpmsg.h"  // the C++ bridge; we MUST NOT include zslp/slp.h here
#include "zslp/zslpstore.h"
//
// NOTE on includes: zslp/slp.h pulls in the protocol library's plain-C
// `struct uint256` (uint256_c.h), which collides with the daemon's
// `class uint256` (src/uint256.h, reached via primitives/transaction.h). The
// two cannot coexist in one TU — that is the entire reason the ZSLPParseScript
// bridge exists. This corpus therefore drives the parser EXCLUSIVELY through
// ZSLPParseScript (which compiles slp.c in its own TU) and never includes
// slp.h. The bridge result (ZSLPMessage) exposes every field these vectors
// assert. The canonical SEND cap is ZSLP_MAX_SEND_OUTPUTS (== the C parser's
// ZSLP_SEND_MAX_OUTPUTS, pinned by a static_assert in zslpmsg.cpp).

#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace {

// ── Raw-script builders (hand-rolled, so we control EVERY byte) ─────────

// A single canonical data push using the smallest direct/PUSHDATA1/PUSHDATA2
// encoding (matches op_return_push.h's writer). Used to build VALID baselines.
void PushBytes(std::vector<uint8_t>& s, const uint8_t* d, size_t len)
{
    if (len <= 0x4b) {
        s.push_back((uint8_t)len);
    } else if (len <= 0xff) {
        s.push_back(0x4c);
        s.push_back((uint8_t)len);
    } else {
        s.push_back(0x4d);
        s.push_back((uint8_t)(len & 0xff));
        s.push_back((uint8_t)((len >> 8) & 0xff));
    }
    for (size_t i = 0; i < len; ++i) s.push_back(d[i]);
}
void PushStr(std::vector<uint8_t>& s, const char* str)
{
    PushBytes(s, (const uint8_t*)str, strlen(str));
}
void PushU8(std::vector<uint8_t>& s, uint8_t v) { PushBytes(s, &v, 1); }
void PushEmpty(std::vector<uint8_t>& s) { s.push_back(0x4c); s.push_back(0x00); }
void PushU64BE(std::vector<uint8_t>& s, uint64_t v)
{
    uint8_t b[8];
    for (int i = 7; i >= 0; --i) { b[i] = (uint8_t)(v & 0xff); v >>= 8; }
    PushBytes(s, b, 8);
}
// Force a PUSHDATA1 encoding regardless of length (for the dual-encoding vector).
void PushBytesP1(std::vector<uint8_t>& s, const uint8_t* d, size_t len)
{
    s.push_back(0x4c);
    s.push_back((uint8_t)len);
    for (size_t i = 0; i < len; ++i) s.push_back(d[i]);
}

// "SLP\0" lokad (4 bytes incl. the NUL) + token_type 1 + tx_type.
std::vector<uint8_t> SlpHeader(const char* txType)
{
    std::vector<uint8_t> s;
    s.push_back(0x6a); // OP_RETURN
    static const uint8_t kLokad[4] = { 'S', 'L', 'P', 0x00 };
    PushBytes(s, kLokad, 4);
    PushU8(s, 1);                      // token_type = 1
    PushStr(s, txType);               // "GENESIS" / "MINT" / "SEND"
    return s;
}

// A minimal VALID GENESIS: empty ticker/name/url, no doc hash, decimals 0, no
// baton, initial_quantity = qty. (qty must be < 2^63 to be valid.)
std::vector<uint8_t> GenesisScript(uint64_t qty, int batonVout = 0,
                                   int decimals = 0, int hashLen = 0)
{
    std::vector<uint8_t> s = SlpHeader("GENESIS");
    PushEmpty(s);                     // ticker
    PushEmpty(s);                     // name
    PushEmpty(s);                     // document_url
    if (hashLen == 0) {
        PushEmpty(s);                 // document_hash (absent)
    } else {
        std::vector<uint8_t> h(hashLen, 0xAB);
        PushBytes(s, h.data(), h.size());
    }
    PushU8(s, (uint8_t)decimals);     // decimals
    if (batonVout >= 2) PushU8(s, (uint8_t)batonVout);
    else PushEmpty(s);                // mint_baton_vout
    PushU64BE(s, qty);                // initial_quantity
    return s;
}

std::vector<uint8_t> MintScript(const uint8_t tokenId[32], uint64_t qty,
                                int batonVout = 0)
{
    std::vector<uint8_t> s = SlpHeader("MINT");
    PushBytes(s, tokenId, 32);
    if (batonVout >= 2) PushU8(s, (uint8_t)batonVout);
    else PushEmpty(s);
    PushU64BE(s, qty);
    return s;
}

std::vector<uint8_t> SendScript(const uint8_t tokenId[32],
                                const std::vector<uint64_t>& qtys)
{
    std::vector<uint8_t> s = SlpHeader("SEND");
    PushBytes(s, tokenId, 32);
    for (size_t i = 0; i < qtys.size(); ++i) PushU64BE(s, qtys[i]);
    return s;
}

// Parse a raw OP_RETURN through the canonical bridge (which runs slp.c). All
// parser vectors below assert on the resulting ZSLPMessage.
bool Parse(const std::vector<uint8_t>& s, ZSLPMessage& m)
{
    return ZSLPParseScript(s.data(), s.size(), m);
}

const uint64_t kTwo63 = (UINT64_C(1) << 63);          // 2^63 (high bit set)
const uint64_t kTwo64m1 = ~UINT64_C(0);               // 2^64 - 1
const uint64_t kMaxValid = (UINT64_C(1) << 63) - 1;   // 2^63 - 1 (high bit clear)

} // namespace

// ════════════════════════════════════════════════════════════════════════
//  (A) PARSER VECTORS — raw OP_RETURN bytes -> expected parse result
// ════════════════════════════════════════════════════════════════════════

// ── Baselines parse (sanity for the hand-rolled builders) ───────────────

TEST(ZslpVectors, BaselineGenesisParses)
{
    ZSLPMessage m;
    ASSERT_TRUE(Parse(GenesisScript(1000), m));
    EXPECT_EQ(m.type, ZSLPMSG_GENESIS);
    EXPECT_EQ(m.initialQuantity, 1000u);
    EXPECT_EQ(m.decimals, 0);
    EXPECT_EQ(m.mintBatonVout, 0);
}

TEST(ZslpVectors, BaselineSendParses)
{
    uint8_t tid[32]; memset(tid, 0x11, 32);
    ZSLPMessage m;
    ASSERT_TRUE(Parse(SendScript(tid, {5, 6, 7}), m));
    EXPECT_EQ(m.type, ZSLPMSG_SEND);
    EXPECT_EQ(m.numOutputs, 3);
    EXPECT_EQ(m.outputQuantities[0], 5u);
    EXPECT_EQ(m.outputQuantities[2], 7u);
}

// ── R-SCRIPT-1: push grammar — reject PUSHDATA4 and OP_N (R-5) ───────────

TEST(ZslpVectors, RejectPushdata4Field)
{
    // A token_type field encoded with OP_PUSHDATA4 (0x4e) must be rejected:
    // read_push accepts ONLY {0x01..0x4b, 0x4c, 0x4d}.
    std::vector<uint8_t> s;
    s.push_back(0x6a);
    static const uint8_t kLokad[4] = { 'S', 'L', 'P', 0x00 };
    PushBytes(s, kLokad, 4);
    // token_type via PUSHDATA4 (len=1): 0x4e 01 00 00 00 01
    s.push_back(0x4e);
    s.push_back(0x01); s.push_back(0x00); s.push_back(0x00); s.push_back(0x00);
    s.push_back(0x01);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, RejectOpNAsField)
{
    // OP_1 (0x51) is NOT a data push for ZSLP; a field encoded as OP_1 must
    // reject (read_push returns NULL for 0x51).
    std::vector<uint8_t> s;
    s.push_back(0x6a);
    static const uint8_t kLokad[4] = { 'S', 'L', 'P', 0x00 };
    PushBytes(s, kLokad, 4);
    s.push_back(0x51); // OP_1 where token_type push is expected
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, RejectOp0AsField)
{
    // OP_0 (0x00) is not a data push for ZSLP fields either.
    std::vector<uint8_t> s;
    s.push_back(0x6a);
    static const uint8_t kLokad[4] = { 'S', 'L', 'P', 0x00 };
    PushBytes(s, kLokad, 4);
    s.push_back(0x00); // OP_0 where token_type push is expected
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

// ── R-SCRIPT-2: dual encoding (direct vs PUSHDATA1) parses identically (R-6) ─

TEST(ZslpVectors, DualEncodingTokenTypeEqual)
{
    // token_type 1 via direct push (0x01 0x01) vs via PUSHDATA1 (0x4c 0x01 0x01)
    // MUST yield the IDENTICAL parsed message. No minimal-push requirement; the
    // lenient behavior is FROZEN canonical (SECURITY_MODEL R-SCRIPT-2).
    uint8_t tid[32]; memset(tid, 0x22, 32);

    std::vector<uint8_t> direct = MintScript(tid, 42, 0);

    std::vector<uint8_t> p1;
    p1.push_back(0x6a);
    static const uint8_t kLokad[4] = { 'S', 'L', 'P', 0x00 };
    PushBytes(p1, kLokad, 4);
    uint8_t tt = 1; PushBytesP1(p1, &tt, 1);   // token_type via PUSHDATA1
    PushStr(p1, "MINT");
    PushBytes(p1, tid, 32);
    PushEmpty(p1);                              // no baton
    PushU64BE(p1, 42);

    ZSLPMessage md, mp;
    ASSERT_TRUE(Parse(direct, md));
    ASSERT_TRUE(Parse(p1, mp));
    EXPECT_EQ(md.type, mp.type);
    // (the bridge has no token_type field; a parsed message implies type 1,
    //  since the parser rejects any token_type != 1)
    EXPECT_EQ(md.additionalQuantity, mp.additionalQuantity);
    EXPECT_EQ(memcmp(md.tokenId, mp.tokenId, 32), 0);
}

TEST(ZslpVectors, Pushdata2AcceptedFrozen)
{
    // SECURITY_MODEL.md R-SCRIPT-1 FREEZES OP_PUSHDATA2 (0x4d) as ACCEPTED
    // (unlike the determinism-spec draft which proposed rejecting it). Pin the
    // pinned choice: a field via PUSHDATA2 parses. token_type 1 via 0x4d.
    std::vector<uint8_t> s;
    s.push_back(0x6a);
    static const uint8_t kLokad[4] = { 'S', 'L', 'P', 0x00 };
    PushBytes(s, kLokad, 4);
    // token_type via PUSHDATA2 len=1: 0x4d 01 00 01
    s.push_back(0x4d); s.push_back(0x01); s.push_back(0x00); s.push_back(0x01);
    PushStr(s, "MINT");
    uint8_t tid[32]; memset(tid, 0x33, 32);
    PushBytes(s, tid, 32);
    PushEmpty(s);
    PushU64BE(s, 7);
    ZSLPMessage m;
    ASSERT_TRUE(Parse(s, m));
    EXPECT_EQ(m.type, ZSLPMSG_MINT);
    EXPECT_EQ(m.additionalQuantity, 7u);
}

// ── R-7 / R-SCRIPT-5: trailing data after GENESIS/MINT => reject ─────────

TEST(ZslpVectors, GenesisTrailingByteRejected)
{
    std::vector<uint8_t> s = GenesisScript(1000);
    PushU8(s, 0x00); // one appended push after the final required field
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, MintTrailingByteRejected)
{
    uint8_t tid[32]; memset(tid, 0x44, 32);
    std::vector<uint8_t> s = MintScript(tid, 5);
    PushU8(s, 0x00);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

// ── R-8 / R-SCRIPT-6: field-length rules ─────────────────────────────────

TEST(ZslpVectors, Genesis31ByteHashRejected)
{
    std::vector<uint8_t> s = GenesisScript(1000, /*baton=*/0, /*dec=*/0,
                                           /*hashLen=*/31);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m)); // document_hash length must be exactly 0 or 32
}

TEST(ZslpVectors, Genesis33ByteHashRejected)
{
    std::vector<uint8_t> s = GenesisScript(1000, 0, 0, /*hashLen=*/33);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, Genesis32ByteHashAccepted)
{
    std::vector<uint8_t> s = GenesisScript(1000, 0, 0, /*hashLen=*/32);
    ZSLPMessage m;
    ASSERT_TRUE(Parse(s, m));
    EXPECT_TRUE(m.hasDocumentHash);
}

TEST(ZslpVectors, BatonLenGreaterThanOneRejected)
{
    // mint_baton_vout pushed as a 2-byte value => reject the whole message.
    std::vector<uint8_t> s = SlpHeader("GENESIS");
    PushEmpty(s); PushEmpty(s); PushEmpty(s);   // ticker/name/url
    PushEmpty(s);                               // doc hash
    PushU8(s, 0);                               // decimals
    uint8_t baton2[2] = { 0x02, 0x00 };         // 2-byte baton push
    PushBytes(s, baton2, 2);
    PushU64BE(s, 1000);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, BatonValueOneRejected)
{
    // mint_baton_vout value 1 (must be >= 2) => reject.
    std::vector<uint8_t> s = GenesisScript(1000, /*baton=*/0);
    // Rebuild with baton value 1 explicitly.
    s = SlpHeader("GENESIS");
    PushEmpty(s); PushEmpty(s); PushEmpty(s);
    PushEmpty(s);
    PushU8(s, 0);
    PushU8(s, 1);                               // baton vout = 1 (illegal)
    PushU64BE(s, 1000);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, BatonValueZeroRejected)
{
    std::vector<uint8_t> s = SlpHeader("GENESIS");
    PushEmpty(s); PushEmpty(s); PushEmpty(s);
    PushEmpty(s);
    PushU8(s, 0);
    PushU8(s, 0);                               // baton vout = 0 (illegal as 1-byte)
    PushU64BE(s, 1000);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, Decimals10Rejected)
{
    std::vector<uint8_t> s = GenesisScript(1000, /*baton=*/0, /*dec=*/10);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m)); // decimals must be 0..9
}

TEST(ZslpVectors, Decimals9Accepted)
{
    std::vector<uint8_t> s = GenesisScript(1000, 0, /*dec=*/9);
    ZSLPMessage m;
    ASSERT_TRUE(Parse(s, m));
    EXPECT_EQ(m.decimals, 9);
}

TEST(ZslpVectors, SevenByteQuantityRejected)
{
    // initial_quantity pushed as 7 bytes (must be exactly 8) => reject.
    std::vector<uint8_t> s = SlpHeader("GENESIS");
    PushEmpty(s); PushEmpty(s); PushEmpty(s);
    PushEmpty(s);
    PushU8(s, 0);
    PushEmpty(s);                               // no baton
    uint8_t q7[7] = {0,0,0,0,0,0,1};
    PushBytes(s, q7, 7);                        // 7-byte quantity
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, SendThirtyOneByteTokenIdRejected)
{
    // token_id must be exactly 32 bytes.
    std::vector<uint8_t> s = SlpHeader("SEND");
    std::vector<uint8_t> tid31(31, 0x55);
    PushBytes(s, tid31.data(), tid31.size());
    PushU64BE(s, 1);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

// ── R-INT-1 / R-10: high-bit (>= 2^63) quantity => whole message INVALID ──
//    Pinned for ALL THREE message types with both 2^63 and 2^64-1.

TEST(ZslpVectors, GenesisHighBitQuantityRejected)
{
    ZSLPMessage m;
    EXPECT_FALSE(Parse(GenesisScript(kTwo63), m));
    EXPECT_FALSE(Parse(GenesisScript(kTwo64m1), m));
    EXPECT_TRUE(Parse(GenesisScript(kMaxValid), m)); // 2^63-1 is valid
    EXPECT_EQ(m.initialQuantity, kMaxValid);
}

TEST(ZslpVectors, MintHighBitQuantityRejected)
{
    uint8_t tid[32]; memset(tid, 0x66, 32);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(MintScript(tid, kTwo63), m));
    EXPECT_FALSE(Parse(MintScript(tid, kTwo64m1), m));
    EXPECT_TRUE(Parse(MintScript(tid, kMaxValid), m));
    EXPECT_EQ(m.additionalQuantity, kMaxValid);
}

TEST(ZslpVectors, SendHighBitOutputQuantityRejected)
{
    uint8_t tid[32]; memset(tid, 0x77, 32);
    ZSLPMessage m;
    // a single high-bit output
    EXPECT_FALSE(Parse(SendScript(tid, {kTwo63}), m));
    EXPECT_FALSE(Parse(SendScript(tid, {kTwo64m1}), m));
    // high bit on a LATER output still rejects the whole SEND
    EXPECT_FALSE(Parse(SendScript(tid, {1, 2, kTwo63}), m));
    // all in-domain is fine
    ASSERT_TRUE(Parse(SendScript(tid, {1, 2, kMaxValid}), m));
    EXPECT_EQ(m.outputQuantities[2], kMaxValid);
}

// ── R-SEND-1 / R-12: SEND output count 0 / 19 / 20 ───────────────────────

TEST(ZslpVectors, SendZeroOutputsRejected)
{
    uint8_t tid[32]; memset(tid, 0x88, 32);
    std::vector<uint8_t> s = SlpHeader("SEND");
    PushBytes(s, tid, 32);
    // no quantity pushes at all
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, SendNineteenOutputsAccepted)
{
    uint8_t tid[32]; memset(tid, 0x99, 32);
    std::vector<uint64_t> q(19);
    for (int i = 0; i < 19; ++i) q[i] = (uint64_t)(i + 1);
    ZSLPMessage m;
    ASSERT_TRUE(Parse(SendScript(tid, q), m));
    EXPECT_EQ(m.numOutputs, ZSLP_MAX_SEND_OUTPUTS);
    EXPECT_EQ(m.numOutputs, 19);
    EXPECT_EQ(m.outputQuantities[18], 19u);
}

TEST(ZslpVectors, SendTwentyOutputsRejected)
{
    // A 20th 8-byte push is TRAILING DATA => whole SEND INVALID (NOT first 19).
    uint8_t tid[32]; memset(tid, 0xAA, 32);
    std::vector<uint64_t> q(20, 1);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(SendScript(tid, q), m));
}

// ── R-SCRIPT-3: lokad + token_type ───────────────────────────────────────

TEST(ZslpVectors, WrongLokadRejected)
{
    std::vector<uint8_t> s;
    s.push_back(0x6a);
    static const uint8_t kBad[4] = { 'S', 'L', 'P', 0x01 }; // not "SLP\0"
    PushBytes(s, kBad, 4);
    PushU8(s, 1);
    PushStr(s, "SEND");
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

TEST(ZslpVectors, WrongTokenTypeRejected)
{
    uint8_t tid[32]; memset(tid, 0xBB, 32);
    std::vector<uint8_t> s;
    s.push_back(0x6a);
    static const uint8_t kLokad[4] = { 'S', 'L', 'P', 0x00 };
    PushBytes(s, kLokad, 4);
    PushU8(s, 2);                  // token_type 2 (we implement only 1)
    PushStr(s, "SEND");
    PushBytes(s, tid, 32);
    PushU64BE(s, 1);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(s, m));
}

// ── R-INT-2: be_to_u64 canonical decode (0 and 2^63-1) ───────────────────

TEST(ZslpVectors, BigEndianQuantityDecode)
{
    ZSLPMessage m;
    ASSERT_TRUE(Parse(GenesisScript(0), m));
    EXPECT_EQ(m.initialQuantity, 0u);
    ASSERT_TRUE(Parse(GenesisScript(kMaxValid), m));
    EXPECT_EQ(m.initialQuantity, kMaxValid);
    // A specific BE pattern: 0x0102030405060708.
    ASSERT_TRUE(Parse(GenesisScript(UINT64_C(0x0102030405060708)), m));
    EXPECT_EQ(m.initialQuantity, UINT64_C(0x0102030405060708));
}

// ── Bridge agreement: the C++ bridge (ZSLPParseScript -> ZSLPMessage) is the
//    daemon-side surface of slp.c. Pin that the SEND quantities survive the
//    bridge copy intact and the rejects propagate (this is the exact path the
//    indexer uses; Parse() == ZSLPParseScript here).

TEST(ZslpVectors, BridgeMatchesParserOnRejects)
{
    uint8_t tid[32]; memset(tid, 0xCC, 32);
    ZSLPMessage m;
    EXPECT_FALSE(Parse(GenesisScript(kTwo63), m));      // high bit
    {
        std::vector<uint8_t> s = GenesisScript(1000); PushU8(s, 0);
        EXPECT_FALSE(Parse(s, m));                      // trailing
    }
    {
        std::vector<uint64_t> q(20, 1);
        EXPECT_FALSE(Parse(SendScript(tid, q), m));     // 20 outputs
    }
    {
        ASSERT_TRUE(Parse(SendScript(tid, {1, 2, 3}), m));
        EXPECT_EQ(m.numOutputs, 3);
        EXPECT_EQ(m.outputQuantities[2], 3u);
    }
}

// ════════════════════════════════════════════════════════════════════════
//  (B) LEDGER VECTORS — tx / same-block sequence -> expected snapshot
//      Driven through the REAL indexer parse seam + REAL store.
// ════════════════════════════════════════════════════════════════════════

namespace {

uint256 H(uint8_t b)
{
    std::vector<unsigned char> v(32, 0);
    v[0] = b;
    return uint256(v);
}

// Deterministic test address per vout index (the indexer's AddressOfVout is a
// pure function of the real scriptPubKey; here the recipient identity is not
// under test, only the position/conservation rules, so a fixed per-vout label
// keys the balances deterministically). vout 0 (the OP_RETURN) -> "".
std::function<std::string(int32_t)> AddrLabels()
{
    return [](int32_t n) -> std::string {
        if (n <= 0) return std::string();
        return std::string("t1vout") + std::to_string(n);
    };
}

// Build a CTransaction with `nOut` outputs; output `opRetIdx` carries `script`
// (an OP_RETURN), the rest are dummy non-OP_RETURN outputs. `vins` are the
// prevouts spent. `coinbase` makes vin[0] the null prevout.
CTransaction MakeTx(const std::vector<uint8_t>& opRetScript, int opRetIdx,
                    int nOut, const std::vector<COutPoint>& vins,
                    bool coinbase = false)
{
    CMutableTransaction mtx;
    if (coinbase) {
        CTxIn in;
        in.prevout.SetNull();
        mtx.vin.push_back(in);
    } else {
        for (size_t i = 0; i < vins.size(); ++i)
            mtx.vin.push_back(CTxIn(vins[i]));
    }
    for (int i = 0; i < nOut; ++i) {
        CTxOut out;
        out.nValue = (i == opRetIdx) ? 0 : 1000;
        if (i == opRetIdx) {
            out.scriptPubKey = CScript(opRetScript.begin(), opRetScript.end());
        } else {
            // A dummy non-OP_RETURN script (a single OP_TRUE) — its content is
            // irrelevant; the test addrOfVout supplies the keying address.
            out.scriptPubKey = CScript() << OP_TRUE;
        }
        mtx.vout.push_back(out);
    }
    return CTransaction(mtx);
}

// Apply a CTransaction through the EXACT production path: ParseTx (vout[0]-only)
// + ApplyTransaction, using the per-vout label addresses. Returns the tx hash.
uint256 ApplyRealTx(CZSLPStore* s, const CTransaction& tx, int64_t height)
{
    CZSLPParsedMsg parsed;
    CZSLPToken genesisMeta;
    bool haveGenesis = false;
    bool present = CZSLPIndexer::ParseTx(tx, height, parsed, genesisMeta,
                                         haveGenesis);
    std::vector<COutPoint> vin;
    for (size_t k = 0; k < tx.vin.size(); ++k)
        vin.push_back(tx.vin[k].prevout);
    s->ApplyTransaction(vin, present ? &parsed : NULL, tx.GetHash(), height,
                        haveGenesis ? &genesisMeta : NULL, AddrLabels(),
                        (int32_t)tx.vout.size());
    return tx.GetHash();
}

CZSLPStore* NewStore()
{
    return new CZSLPStore("zslp-vectors", 1 << 20, /*fMemory=*/true,
                          /*fWipe=*/true);
}

// On-chain token_id field = the genesis txid in DISPLAY (big-endian) order =
// the reverse of the uint256 internal bytes. The indexer reverses it back via
// TokenIdToUint256, so this round-trips to the genesis tokenId.
void TokenIdField(const uint256& genesisTxid, uint8_t out[32])
{
    std::vector<unsigned char> v(genesisTxid.begin(), genesisTxid.end());
    for (int i = 0; i < 32; ++i) out[i] = v[31 - i];
}

} // namespace

// ── R-PARSE-1/2: SLP message at vout[1] is IGNORED; vout[0] decides ─────

TEST(ZslpVectors, MessageAtVout1Ignored)
{
    CZSLPStore* s = NewStore();
    // GENESIS at vout[1] (a payment-looking output at vout[0]). vout[0] is a
    // non-OP_RETURN script => the tx has NO SLP message. No token is created.
    std::vector<uint8_t> gen = GenesisScript(1000);
    CTransaction tx = MakeTx(gen, /*opRetIdx=*/1, /*nOut=*/2, {});
    uint256 txid = ApplyRealTx(s, tx, 100);

    EXPECT_EQ(s->TokenCount(), 0);
    CZSLPToken t;
    EXPECT_FALSE(s->GetToken(txid, t));
    EXPECT_EQ(s->UtxoCount(), 0);
    delete s;
}

// ── R-PARSE-2: two OP_RETURNs (vout0 + vout1) — vout[0] wins, vout[1] noop ─

TEST(ZslpVectors, TwoOpReturnsVout0Wins)
{
    CZSLPStore* s = NewStore();
    // vout[0] is a VALID GENESIS qty 500; vout[1] is ALSO an OP_RETURN GENESIS
    // qty 999 (would mint a different supply). Only vout[0] is parsed.
    std::vector<uint8_t> g0 = GenesisScript(500);
    std::vector<uint8_t> g1 = GenesisScript(999);
    CMutableTransaction mtx;
    {
        CTxOut o0; o0.nValue = 0;
        o0.scriptPubKey = CScript(g0.begin(), g0.end());
        mtx.vout.push_back(o0);
        CTxOut o1; o1.nValue = 0;
        o1.scriptPubKey = CScript(g1.begin(), g1.end());
        mtx.vout.push_back(o1);
        // A real recipient output at vout[2] so the genesis qty has a home.
        CTxOut o2; o2.nValue = 1000; o2.scriptPubKey = CScript() << OP_TRUE;
        mtx.vout.push_back(o2);
    }
    CTransaction tx(mtx);
    uint256 txid = ApplyRealTx(s, tx, 100);

    CZSLPToken t;
    ASSERT_TRUE(s->GetToken(txid, t));
    EXPECT_EQ(t.totalMinted, 500);     // vout[0]'s 500, NEVER vout[1]'s 999
    EXPECT_EQ(s->GetBalance(txid, "t1vout1"), 500); // created at vout[1]
    delete s;
}

// ── R-PARSE-3: coinbase is never SLP (skipped by ConnectBlock) ──────────

TEST(ZslpVectors, CoinbaseIgnored)
{
    // We model ConnectBlock's coinbase skip: a coinbase whose vout[0] is a
    // valid GENESIS must create NOTHING. (ConnectBlock starts the tx loop at
    // index 1; here we assert the rule by simply never applying the coinbase.)
    CZSLPStore* s = NewStore();
    std::vector<uint8_t> gen = GenesisScript(1000);
    CTransaction cb = MakeTx(gen, 0, 2, {}, /*coinbase=*/true);
    EXPECT_TRUE(cb.IsCoinBase());
    // Per R-PARSE-3 the indexer SKIPS vtx[0] — we do not apply it.
    EXPECT_EQ(s->TokenCount(), 0);
    EXPECT_EQ(s->UtxoCount(), 0);
    // Sanity: the SAME tx, if it WERE applied (non-coinbase position), would
    // create the token — proving the skip is what suppresses it.
    CTransaction nonCb = MakeTx(gen, 0, 2, {});
    uint256 txid = ApplyRealTx(s, nonCb, 100);
    CZSLPToken t;
    EXPECT_TRUE(s->GetToken(txid, t));
    delete s;
}

// ── R-GEN-3 / R-MINT-3: GENESIS / MINT with NO vout[1] => totalMinted 0 ──

TEST(ZslpVectors, GenesisNoVout1TotalMintedZero)
{
    CZSLPStore* s = NewStore();
    // GENESIS with ONLY the OP_RETURN output (voutCount == 1). The initial
    // quantity is declared 1000 but vout[1] does not exist => nothing created,
    // totalMinted == 0 (R-GEN-3 FIX), token row still inserted.
    std::vector<uint8_t> gen = GenesisScript(1000);
    CTransaction tx = MakeTx(gen, 0, /*nOut=*/1, {});
    uint256 txid = ApplyRealTx(s, tx, 100);

    CZSLPToken t;
    ASSERT_TRUE(s->GetToken(txid, t));
    EXPECT_EQ(t.totalMinted, 0);       // NOT 1000
    EXPECT_EQ(s->UtxoCount(), 0);      // no token UTXO created
    delete s;
}

TEST(ZslpVectors, MintNoVout1TotalMintedUnchanged)
{
    CZSLPStore* s = NewStore();
    // GENESIS with a baton (vout 2), 100 at vout1.
    std::vector<uint8_t> gen = GenesisScript(100, /*baton=*/2);
    CTransaction g = MakeTx(gen, 0, /*nOut=*/3, {});
    uint256 tokenId = ApplyRealTx(s, g, 100);
    CZSLPToken t0; ASSERT_TRUE(s->GetToken(tokenId, t0));
    EXPECT_EQ(t0.totalMinted, 100);

    // MINT that spends the baton (tokenId, vout2) but has NO vout[1]
    // (voutCount == 1): declares +5000 but creates nothing => totalMinted
    // unchanged (R-MINT-3 FIX). Baton not re-declared (no room) => baton ends.
    uint8_t tidField[32]; TokenIdField(tokenId, tidField);
    std::vector<uint8_t> mint = MintScript(tidField, 5000, /*baton=*/0);
    CTransaction m = MakeTx(mint, 0, /*nOut=*/1, { COutPoint(tokenId, 2) });
    ApplyRealTx(s, m, 101);

    CZSLPToken t1; ASSERT_TRUE(s->GetToken(tokenId, t1));
    EXPECT_EQ(t1.totalMinted, 100);    // unchanged
    EXPECT_EQ(t1.mintBatonVout, 0);    // baton consumed, not re-declared => ended
    delete s;
}

// ── R-MINT-1: unknown-token MINT and MINT-without-baton create nothing ──

TEST(ZslpVectors, UnknownTokenMintCreatesNothing)
{
    CZSLPStore* s = NewStore();
    uint256 neverGenesised = H(0xEE);
    uint8_t tidField[32]; TokenIdField(neverGenesised, tidField);
    std::vector<uint8_t> mint = MintScript(tidField, 1000, /*baton=*/2);
    // Spend SOME input that happens to be a baton of a DIFFERENT (nonexistent)
    // token — there is no token row, so nothing is created.
    CTransaction m = MakeTx(mint, 0, 3, { COutPoint(H(0xDD), 0) });
    ApplyRealTx(s, m, 100);
    EXPECT_EQ(s->TokenCount(), 0);
    EXPECT_EQ(s->UtxoCount(), 0);
    delete s;
}

TEST(ZslpVectors, MintWithoutBatonCreatesNothing)
{
    CZSLPStore* s = NewStore();
    std::vector<uint8_t> gen = GenesisScript(100, /*baton=*/2);
    CTransaction g = MakeTx(gen, 0, 3, {});
    uint256 tokenId = ApplyRealTx(s, g, 100);

    // MINT that spends the QUANTITY UTXO (vout1), NOT the baton (vout2).
    uint8_t tidField[32]; TokenIdField(tokenId, tidField);
    std::vector<uint8_t> mint = MintScript(tidField, 9999, /*baton=*/2);
    CTransaction m = MakeTx(mint, 0, 3, { COutPoint(tokenId, 1) }); // not baton
    ApplyRealTx(s, m, 101);

    CZSLPToken t; ASSERT_TRUE(s->GetToken(tokenId, t));
    EXPECT_EQ(t.totalMinted, 100);                 // no inflation
    CZSLPTokenUtxo u;
    EXPECT_FALSE(s->GetUtxo(m.GetHash(), 1, u));    // no new UTXO created
    // The spent quantity UTXO was burned; baton at vout2 untouched.
    EXPECT_FALSE(s->GetUtxo(tokenId, 1, u));
    ASSERT_TRUE(s->GetUtxo(tokenId, 2, u));
    EXPECT_TRUE(u.isMintBaton);
    delete s;
}

// ── R-SEND-4 (Reading A PINNED): out-of-range output index burns ONLY that
//    quantity; in-range outputs still apply; budget checked over ALL declared.

TEST(ZslpVectors, OutOfRangeOutputBurnsThatQuantityOnly)
{
    CZSLPStore* s = NewStore();
    // GENESIS 1000 at vout1.
    std::vector<uint8_t> gen = GenesisScript(1000);
    CTransaction g = MakeTx(gen, 0, 2, {});
    uint256 tokenId = ApplyRealTx(s, g, 100);
    EXPECT_EQ(s->GetBalance(tokenId, "t1vout1"), 1000);

    // SEND with THREE quantities {400, 100, 100} = 600 required, availIn 1000
    // (>= 600 OK), on a tx with only 2 outputs (vout0 OP_RETURN + vout1). So:
    //   q[0]=400 -> vout1 (exists)      => created (400)
    //   q[1]=100 -> vout2 (DOES NOT EXIST) => burned (Reading A)
    //   q[2]=100 -> vout3 (DOES NOT EXIST) => burned (Reading A)
    // Reading B (rejected) would invalidate the whole SEND. We PIN Reading A:
    // only vout1's 400 is created; the rest (and the 400 surplus) burned.
    uint8_t tidField[32]; TokenIdField(tokenId, tidField);
    std::vector<uint8_t> snd = SendScript(tidField, {400, 100, 100});
    CTransaction m = MakeTx(snd, 0, /*nOut=*/2, { COutPoint(tokenId, 1) });
    ApplyRealTx(s, m, 101);

    EXPECT_EQ(s->GetBalance(tokenId, "t1vout1"), 400); // ONLY the in-range output
    EXPECT_EQ(s->UtxoCount(), 1);
    CZSLPTokenUtxo u;
    ASSERT_TRUE(s->GetUtxo(m.GetHash(), 1, u));
    EXPECT_EQ(u.amount, 400);
    delete s;
}

// ── R-SEND-3: output-sum overflow => SEND INVALID (create nothing, burn) ──

TEST(ZslpVectors, SendSumOverflowInvalid)
{
    CZSLPStore* s = NewStore();
    // Genesis a large but in-domain supply at vout1.
    std::vector<uint8_t> gen = GenesisScript(kMaxValid);
    CTransaction g = MakeTx(gen, 0, 2, {});
    uint256 tokenId = ApplyRealTx(s, g, 100);

    // SEND two outputs each (2^63 - 1): sum overflows int64 => INVALID. Inputs
    // (the kMaxValid UTXO) are still burned; nothing is created.
    uint8_t tidField[32]; TokenIdField(tokenId, tidField);
    std::vector<uint8_t> snd = SendScript(tidField, {kMaxValid, kMaxValid});
    CTransaction m = MakeTx(snd, 0, 3, { COutPoint(tokenId, 1) });
    ApplyRealTx(s, m, 101);

    EXPECT_EQ(s->GetBalance(tokenId, "t1vout1"), 0); // input burned
    EXPECT_EQ(s->UtxoCount(), 0);                    // nothing created
    delete s;
}

TEST(ZslpVectors, SendSumAtInt64MaxValid)
{
    CZSLPStore* s = NewStore();
    // availIn must be >= requiredOut. Genesis kMaxValid (= 2^63-1) at vout1,
    // then SEND a single output of exactly kMaxValid => valid, fully conserved.
    std::vector<uint8_t> gen = GenesisScript(kMaxValid);
    CTransaction g = MakeTx(gen, 0, 2, {});
    uint256 tokenId = ApplyRealTx(s, g, 100);

    uint8_t tidField[32]; TokenIdField(tokenId, tidField);
    std::vector<uint8_t> snd = SendScript(tidField, {kMaxValid});
    CTransaction m = MakeTx(snd, 0, 2, { COutPoint(tokenId, 1) });
    ApplyRealTx(s, m, 101);

    EXPECT_EQ(s->GetBalance(tokenId, "t1vout1"), (int64_t)kMaxValid);
    delete s;
}

// ── R-BURN-3 / R-BURN-4: same-block genesis (tx1) then send (tx2) ───────

TEST(ZslpVectors, SameBlockGenesisThenSend)
{
    CZSLPStore* s = NewStore();
    uint256 blk = H(0x55);
    s->ConnectBlockBegin(blk);

    // tx1: GENESIS 700 -> vout1.
    std::vector<uint8_t> gen = GenesisScript(700);
    CTransaction g = MakeTx(gen, 0, 2, {});
    uint256 tokenId = ApplyRealTx(s, g, 7);

    // tx2 (same block): SEND spending (tokenId, vout1) -> 700 to vout1.
    uint8_t tidField[32]; TokenIdField(tokenId, tidField);
    std::vector<uint8_t> snd = SendScript(tidField, {700});
    CTransaction m = MakeTx(snd, 0, 2, { COutPoint(tokenId, 1) });
    uint256 sendTxid = ApplyRealTx(s, m, 7);

    s->ConnectBlockEnd(7, blk);

    // tx2 must have SEEN tx1's UTXO and moved it.
    EXPECT_EQ(s->GetBalance(tokenId, "t1vout1"), 700); // now under the send tx
    EXPECT_EQ(s->UtxoCount(), 1);
    CZSLPTokenUtxo u;
    EXPECT_FALSE(s->GetUtxo(tokenId, 1, u));        // genesis UTXO consumed
    ASSERT_TRUE(s->GetUtxo(sendTxid, 1, u));        // send UTXO live
    EXPECT_EQ(u.amount, 700);
    delete s;
}

// ── R-ID-1 / R-9: token_id endianness round-trip (genesis -> MINT/SEND) ──

TEST(ZslpVectors, TokenIdEndiannessRoundTrip)
{
    CZSLPStore* s = NewStore();
    std::vector<uint8_t> gen = GenesisScript(50, /*baton=*/2);
    CTransaction g = MakeTx(gen, 0, 3, {});
    uint256 tokenId = ApplyRealTx(s, g, 100); // tokenId == genesis txid

    // A MINT quoting the genesis txid's DISPLAY-hex (big-endian) must resolve to
    // the SAME tokenId the GENESIS produced (TokenIdToUint256 reverses it).
    uint8_t tidField[32]; TokenIdField(tokenId, tidField);
    std::vector<uint8_t> mint = MintScript(tidField, 25, /*baton=*/2);
    CTransaction m = MakeTx(mint, 0, 3, { COutPoint(tokenId, 2) });
    ApplyRealTx(s, m, 101);

    CZSLPToken t; ASSERT_TRUE(s->GetToken(tokenId, t));
    EXPECT_EQ(t.totalMinted, 75); // 50 + 25: the MINT resolved the right token
    delete s;
}

// ── R-24: ListTransfers is bounded — peak memory O(from+count) ───────────
//    (Functional pin: with many transfers, paging returns the right window in
//    newest-first order and never returns more than `count`.)

TEST(ZslpVectors, ListTransfersBoundedAndOrdered)
{
    CZSLPStore* s = NewStore();
    std::vector<uint8_t> gen = GenesisScript(100000);
    CTransaction g = MakeTx(gen, 0, 2, {});
    uint256 tokenId = ApplyRealTx(s, g, 1);

    // Chain 30 SENDs, each moving the whole balance forward one hop, at
    // increasing heights -> 31 transfer rows (1 genesis + 30 sends).
    uint256 prevTxid = g.GetHash();
    uint8_t tidField[32]; TokenIdField(tokenId, tidField);
    for (int i = 0; i < 30; ++i) {
        std::vector<uint8_t> snd = SendScript(tidField, {100000});
        CTransaction m = MakeTx(snd, 0, 2, { COutPoint(prevTxid, 1) });
        ApplyRealTx(s, m, 2 + i);
        prevTxid = m.GetHash();
    }

    // count clamps the slice; newest-first ordering preserved.
    std::vector<CZSLPTransfer> page;
    int n = s->ListTransfers(tokenId, /*from=*/0, /*count=*/5, page);
    EXPECT_EQ(n, 5);
    ASSERT_EQ(page.size(), 5u);
    // Newest first: the highest-height transfer (height 31) is row 0.
    EXPECT_EQ(page[0].blockHeight, 31);
    EXPECT_EQ(page[1].blockHeight, 30);
    EXPECT_GT(page[0].blockHeight, page[4].blockHeight);

    // Paging: from=5 returns the next-older window, still newest-first.
    std::vector<CZSLPTransfer> page2;
    int n2 = s->ListTransfers(tokenId, /*from=*/5, /*count=*/5, page2);
    EXPECT_EQ(n2, 5);
    EXPECT_EQ(page2[0].blockHeight, 26); // one older than page[4] (height 27)
    delete s;
}

// ── R-24 (regression): a huge `from` must NOT allocate O(from) ───────────
//    The first ring-buffer fix sized its window to (from+count), so a single
//    `zslp_listtransfers "tid" 1 2000000000` would try to allocate ~2e9 rows
//    and OOM the daemon. Peak memory is now O(count) regardless of `from`:
//    a from >= total returns empty immediately, and a near-INT_MAX from on a
//    tiny token returns empty without a giant allocation. (If this regressed,
//    the process would OOM/crash here rather than fail the assertion.)

TEST(ZslpVectors, ListTransfersHugeFromIsBounded)
{
    CZSLPStore* s = NewStore();
    std::vector<uint8_t> gen = GenesisScript(100000);
    CTransaction g = MakeTx(gen, 0, 2, {});
    uint256 tokenId = ApplyRealTx(s, g, 1);

    // A handful of transfers (total rows is small).
    uint256 prevTxid = g.GetHash();
    uint8_t tidField[32]; TokenIdField(tokenId, tidField);
    for (int i = 0; i < 4; ++i) {
        std::vector<uint8_t> snd = SendScript(tidField, {100000});
        CTransaction m = MakeTx(snd, 0, 2, { COutPoint(prevTxid, 1) });
        ApplyRealTx(s, m, 2 + i);
        prevTxid = m.GetHash();
    }
    // 1 genesis + 4 sends = 5 transfer rows total.

    // from far beyond INT-range-but-valid: returns empty, no OOM.
    std::vector<CZSLPTransfer> page;
    int n = s->ListTransfers(tokenId, /*from=*/2000000000, /*count=*/10, page);
    EXPECT_EQ(n, 0);
    EXPECT_TRUE(page.empty());

    // from exactly at total -> empty; from just under total -> the single
    // oldest row, still bounded.
    int n_at = s->ListTransfers(tokenId, /*from=*/5, /*count=*/10, page);
    EXPECT_EQ(n_at, 0);
    int n_last = s->ListTransfers(tokenId, /*from=*/4, /*count=*/10, page);
    EXPECT_EQ(n_last, 1);
    ASSERT_EQ(page.size(), 1u);
    EXPECT_EQ(page[0].blockHeight, 1); // the genesis row (oldest)

    // count larger than total still bounded to total, newest-first.
    int n_all = s->ListTransfers(tokenId, /*from=*/0, /*count=*/10, page);
    EXPECT_EQ(n_all, 5);
    ASSERT_EQ(page.size(), 5u);
    EXPECT_EQ(page[0].blockHeight, 5); // newest (4th send at height 5)
    EXPECT_EQ(page[4].blockHeight, 1); // oldest (genesis)
    delete s;
}
