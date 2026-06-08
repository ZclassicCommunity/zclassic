// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP content-fingerprint AGREEMENT tests. The daemon module
// (zslp/contentfingerprint.{h,cpp}) MUST produce the byte-identical anchor the
// Qt wallet's ContentEngine does, or a CLI-minted token's document_hash would
// fail the GUI verify badge (and vice versa). This file pins the algorithm with
// an INDEPENDENT reference reimplementation (a second code path, structured
// differently from the module) and asserts the module matches it across the
// degenerate + boundary cases — using a TINY chunk size so multi-chunk cases
// are small and exact.
//
// It also exercises the zslp_decode parse path: build a real GENESIS / MINT /
// SEND OP_RETURN with the production encoders and re-parse it via the same
// ZSLPParseScript bridge zslp_decode uses (no wallet / chain state needed).

#include <gtest/gtest.h>

#include "crypto/sha256.h"
#include "utilstrencodings.h"        // HexStr, ParseHex
#include "zslp/contentfingerprint.h"
#include "zslp/zslpmsg.h"           // ZSLPParseScript + ZSLPBuild{Genesis,Mint,Send}

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> Bytes;

// ── INDEPENDENT reference implementation (NOT shared with the module) ──

Bytes refSha256(const unsigned char* p, size_t n) {
    Bytes out(32);
    CSHA256 h;
    if (n) h.Write(p, n);
    h.Finalize(out.data());
    return out;
}

Bytes refLeaf(const Bytes& chunk) {
    // leaf = SHA256(0x00 || chunk)
    Bytes in;
    in.push_back(0x00);
    in.insert(in.end(), chunk.begin(), chunk.end());
    return refSha256(in.data(), in.size());
}

Bytes refNode(const Bytes& l, const Bytes& r) {
    // node = SHA256(0x01 || left || right)
    Bytes in;
    in.push_back(0x01);
    in.insert(in.end(), l.begin(), l.end());
    in.insert(in.end(), r.begin(), r.end());
    return refSha256(in.data(), in.size());
}

Bytes refRoot(const std::vector<Bytes>& leaves) {
    if (leaves.empty()) return Bytes();
    if (leaves.size() == 1) return leaves[0];
    std::vector<Bytes> level = leaves;
    while (level.size() > 1) {
        std::vector<Bytes> next;
        for (size_t i = 0; i < level.size(); i += 2) {
            if (i + 1 < level.size()) next.push_back(refNode(level[i], level[i + 1]));
            else                      next.push_back(level[i]); // promote odd
        }
        level = next;
    }
    return level[0];
}

struct RefDesc {
    std::string anchorHex, sha256WholeHex, merkleRootHex;
    uint64_t fileSize;
    uint64_t chunkCount;
};

RefDesc refDescribe(const Bytes& data, uint32_t chunkSize) {
    std::vector<Bytes> leaves;
    for (size_t off = 0; off < data.size(); off += chunkSize) {
        size_t take = std::min((size_t)chunkSize, data.size() - off);
        leaves.push_back(refLeaf(Bytes(data.begin() + off, data.begin() + off + take)));
    }
    Bytes whole = refSha256(data.empty() ? NULL : data.data(), data.size());
    Bytes root  = refRoot(leaves);

    RefDesc d;
    d.sha256WholeHex = HexStr(whole);
    d.merkleRootHex  = root.empty() ? std::string() : HexStr(root);
    d.fileSize       = data.size();
    d.chunkCount     = leaves.size();
    d.anchorHex      = (d.chunkCount > 1 && !d.merkleRootHex.empty())
                           ? d.merkleRootHex : d.sha256WholeHex;
    return d;
}

// Assert the module's ZSLPHashBytes output equals the independent reference.
void expectModuleMatchesRef(const Bytes& data, uint32_t chunkSize) {
    RefDesc ref = refDescribe(data, chunkSize);
    ZSLPContentDescriptor got;
    ASSERT_TRUE(ZSLPHashBytes(data.empty() ? NULL : data.data(), data.size(),
                              got, chunkSize));
    EXPECT_EQ(ref.anchorHex,      got.anchorHex);
    EXPECT_EQ(ref.sha256WholeHex, got.sha256WholeHex);
    EXPECT_EQ(ref.merkleRootHex,  got.merkleRootHex);
    EXPECT_EQ(ref.fileSize,       got.fileSize);
    EXPECT_EQ(ref.chunkCount,     got.chunkCount);
    EXPECT_EQ(chunkSize,          got.chunkSize);
}

Bytes seq(size_t n, unsigned char start = 0) {
    Bytes b; b.reserve(n);
    for (size_t i = 0; i < n; ++i) b.push_back((unsigned char)(start + i));
    return b;
}

bool writeTempFile(const std::string& path, const Bytes& data) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = data.empty() || fwrite(data.data(), 1, data.size(), f) == data.size();
    fclose(f);
    return ok;
}

// Assert the STREAMING file path (ZSLPHashFile — the GUI's real mint path) yields
// the same descriptor as the in-memory ZSLPHashBytes for identical content. This
// covers the bounded-buffer tiling / lazy-prime / EOF handling that the in-memory
// path does not exercise.
void expectFileMatchesBytes(const Bytes& data, uint32_t chunkSize) {
    const std::string path = "zslp_fp_stream_test.tmp";
    ASSERT_TRUE(writeTempFile(path, data));
    ZSLPContentDescriptor fromBytes, fromFile;
    ASSERT_TRUE(ZSLPHashBytes(data.empty() ? NULL : data.data(), data.size(),
                              fromBytes, chunkSize));
    ASSERT_TRUE(ZSLPHashFile(path, fromFile, chunkSize));
    EXPECT_EQ(fromBytes.anchorHex,      fromFile.anchorHex);
    EXPECT_EQ(fromBytes.sha256WholeHex, fromFile.sha256WholeHex);
    EXPECT_EQ(fromBytes.merkleRootHex,  fromFile.merkleRootHex);
    EXPECT_EQ(fromBytes.fileSize,       fromFile.fileSize);
    EXPECT_EQ(fromBytes.chunkCount,     fromFile.chunkCount);
    std::remove(path.c_str());
}

} // namespace

// ── Empty input: anchor == whole-SHA == SHA256(""), no merkle root. ──
TEST(zslp_fingerprint, empty) {
    Bytes empty;
    ZSLPContentDescriptor d;
    ASSERT_TRUE(ZSLPHashBytes(NULL, 0, d, /*chunkSize=*/4));
    EXPECT_EQ((uint64_t)0, d.fileSize);
    EXPECT_EQ((uint64_t)0, d.chunkCount);
    EXPECT_EQ(std::string(), d.merkleRootHex);             // empty input => no root
    // SHA256("") sanity anchor.
    const std::string kEmptySha =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    EXPECT_EQ(kEmptySha, d.sha256WholeHex);
    EXPECT_EQ(kEmptySha, d.anchorHex);                     // anchor falls back to whole
    expectModuleMatchesRef(empty, 4);
}

// ── Single short buffer (< chunk): one leaf. anchor == whole-SHA, and the
//    anchor is NOT the single-leaf merkle root (chunkCount==1 picks whole). ──
TEST(zslp_fingerprint, single_short_buffer) {
    Bytes data = seq(3); // 3 bytes, chunkSize 4 => exactly one (partial) leaf
    expectModuleMatchesRef(data, 4);

    ZSLPContentDescriptor d;
    ASSERT_TRUE(ZSLPHashBytes(data.data(), data.size(), d, 4));
    EXPECT_EQ((uint64_t)1, d.chunkCount);
    EXPECT_EQ(d.sha256WholeHex, d.anchorHex);  // single leaf => anchor is whole-SHA
    // The single-leaf merkle root equals leaf_0 (== merkleRootHex), and that is a
    // DIFFERENT value from the whole-SHA (leaf is domain-prefixed with 0x00), so
    // the anchor selection genuinely matters even for one chunk.
    EXPECT_NE(d.merkleRootHex, d.sha256WholeHex);
    EXPECT_NE(d.merkleRootHex, d.anchorHex);
}

// ── Exactly 2 chunks: anchor == merkle root == node(leaf0, leaf1). ──
TEST(zslp_fingerprint, two_chunks) {
    Bytes data = seq(8); // chunkSize 4 => 2 full chunks
    expectModuleMatchesRef(data, 4);

    ZSLPContentDescriptor d;
    ASSERT_TRUE(ZSLPHashBytes(data.data(), data.size(), d, 4));
    EXPECT_EQ((uint64_t)2, d.chunkCount);
    EXPECT_EQ(d.merkleRootHex, d.anchorHex);   // multi-chunk => anchor is the root
    EXPECT_NE(d.merkleRootHex, d.sha256WholeHex);
}

// ── Exactly 3 chunks: odd promotion at the first level. ──
TEST(zslp_fingerprint, three_chunks_odd_promotion) {
    Bytes data = seq(12); // chunkSize 4 => 3 full chunks (odd)
    expectModuleMatchesRef(data, 4);

    ZSLPContentDescriptor d;
    ASSERT_TRUE(ZSLPHashBytes(data.data(), data.size(), d, 4));
    EXPECT_EQ((uint64_t)3, d.chunkCount);
    EXPECT_EQ(d.merkleRootHex, d.anchorHex);
}

// ── Non-aligned multi-chunk size: last leaf is a partial remainder. ──
TEST(zslp_fingerprint, non_aligned_multichunk) {
    Bytes data = seq(13); // chunkSize 4 => 3 full + 1 partial = 4 leaves
    expectModuleMatchesRef(data, 4);

    ZSLPContentDescriptor d;
    ASSERT_TRUE(ZSLPHashBytes(data.data(), data.size(), d, 4));
    EXPECT_EQ((uint64_t)4, d.chunkCount);

    Bytes data2 = seq(5); // chunkSize 4 => 1 full + 1 partial = 2 leaves
    expectModuleMatchesRef(data2, 4);
    ZSLPContentDescriptor d2;
    ASSERT_TRUE(ZSLPHashBytes(data2.data(), data2.size(), d2, 4));
    EXPECT_EQ((uint64_t)2, d2.chunkCount);
    EXPECT_EQ(d2.merkleRootHex, d2.anchorHex);
}

// ── Streaming ZSLPHashFile == in-memory ZSLPHashBytes across small-chunk tiling
//    and a >1 MiB buffer-spanning case at the production chunk size. ──
TEST(zslp_fingerprint, file_stream_matches_bytes) {
    expectFileMatchesBytes(Bytes(),  4);   // empty file
    expectFileMatchesBytes(seq(3),   4);   // single partial leaf
    expectFileMatchesBytes(seq(8),   4);   // exactly 2 chunks
    expectFileMatchesBytes(seq(13),  4);   // 4 leaves, partial last
    // Production chunk size over a multi-MiB file: exercises buffer-vs-chunk
    // spanning and the streaming read loop (chunk == 1 MiB).
    expectFileMatchesBytes(seq(3 * 1024 * 1024 + 7, 1), ZSLP_CONTENT_CHUNK_BYTES);
}

// ── zslp_decode parse-path round-trips (no wallet / chain). Build a real
//    OP_RETURN with the production encoders and re-parse via ZSLPParseScript
//    (the exact bridge zslp_decode drives). ──

TEST(zslp_fingerprint, decode_genesis_roundtrip) {
    uint8_t docHash[32];
    for (int i = 0; i < 32; ++i) docHash[i] = (uint8_t)(0xA0 + i);
    std::vector<unsigned char> opret = ZSLPBuildGenesis(
        "GOLD", "Gold Token", "https://x", docHash,
        /*decimals=*/2, /*baton=*/2, /*qty=*/100000);
    ASSERT_FALSE(opret.empty());

    ZSLPMessage m;
    ASSERT_TRUE(ZSLPParseScript(opret.data(), opret.size(), m));
    EXPECT_EQ(ZSLPMSG_GENESIS, m.type);
    EXPECT_EQ(std::string("GOLD"), m.ticker);
    EXPECT_EQ(std::string("Gold Token"), m.name);
    EXPECT_EQ(std::string("https://x"), m.documentUrl);
    EXPECT_EQ((uint8_t)2, m.decimals);
    EXPECT_EQ((uint8_t)2, m.mintBatonVout);
    EXPECT_EQ((uint64_t)100000, m.initialQuantity);
    ASSERT_TRUE(m.hasDocumentHash);
    // document_hash is on-chain/display order: a plain HexStr is the dump.
    EXPECT_EQ(HexStr(docHash, docHash + 32),
              HexStr(m.documentHash, m.documentHash + 32));
}

TEST(zslp_fingerprint, decode_mint_roundtrip) {
    uint8_t tidBE[32];
    for (int i = 0; i < 32; ++i) tidBE[i] = (uint8_t)(0x10 + i);
    std::vector<unsigned char> opret = ZSLPBuildMint(tidBE, /*baton=*/2, /*qty=*/42);
    ASSERT_FALSE(opret.empty());

    ZSLPMessage m;
    ASSERT_TRUE(ZSLPParseScript(opret.data(), opret.size(), m));
    EXPECT_EQ(ZSLPMSG_MINT, m.type);
    EXPECT_EQ(HexStr(tidBE, tidBE + 32), HexStr(m.tokenId, m.tokenId + 32));
    EXPECT_EQ((uint64_t)42, m.additionalQuantity);
    EXPECT_EQ((uint8_t)2, m.mintBatonVout);
}

TEST(zslp_fingerprint, decode_send_roundtrip) {
    uint8_t tidBE[32];
    for (int i = 0; i < 32; ++i) tidBE[i] = (uint8_t)(0x20 + i);
    std::vector<uint64_t> q;
    q.push_back(5);
    q.push_back(3);
    q.push_back(2);
    std::vector<unsigned char> opret = ZSLPBuildSend(tidBE, q);
    ASSERT_FALSE(opret.empty());

    ZSLPMessage m;
    ASSERT_TRUE(ZSLPParseScript(opret.data(), opret.size(), m));
    EXPECT_EQ(ZSLPMSG_SEND, m.type);
    EXPECT_EQ(HexStr(tidBE, tidBE + 32), HexStr(m.tokenId, m.tokenId + 32));
    ASSERT_EQ(3, m.numOutputs);
    EXPECT_EQ((uint64_t)5, m.outputQuantities[0]); // -> vout[1]
    EXPECT_EQ((uint64_t)3, m.outputQuantities[1]); // -> vout[2]
    EXPECT_EQ((uint64_t)2, m.outputQuantities[2]); // -> vout[3]
}

// A non-SLP / garbage script must be rejected (zslp_decode returns valid:false).
TEST(zslp_fingerprint, decode_rejects_non_slp) {
    std::vector<unsigned char> junk = ParseHex("6a04deadbeef"); // OP_RETURN + 4 bytes
    ZSLPMessage m;
    EXPECT_FALSE(ZSLPParseScript(junk.data(), junk.size(), m));
    std::vector<unsigned char> empty;
    EXPECT_FALSE(ZSLPParseScript(empty.data(), empty.size(), m));
}
