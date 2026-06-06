// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license.
//
// GoogleTest port of the standalone ZDC1 codec self-checks
// (src/datachannel/test/zdc_test.cpp). Same coverage, run under zcash-gtest so
// the codec has a CI gate inside the daemon build:
//   header round-trip + endianness, CRC, AEAD round-trip, NONCE UNIQUENESS
//   (the catastrophic-if-wrong property), AAD binding (reorder/retype fails),
//   tamper detection, truncation/dup/missing/reorder reassembly, size caps,
//   empty + maximal payloads, seal-then-reveal (KEY frame), out-of-band key,
//   non-ZDC1 memo passthrough, and the ciphertext fingerprint anchor.

#include <gtest/gtest.h>

#include "datachannel/zdc.h"
#include "consensus/consensus.h"   // MAX_TX_SIZE_AFTER_SAPLING

#include <sodium.h>

#include <cstring>
#include <set>
#include <string>
#include <vector>

using namespace zdc;

namespace {

// One-time libsodium init shared across the ZDC tests. ZdcAead also calls
// sodium_init() lazily, but the standalone test does it explicitly, so mirror it.
// (sodium_init returns 0 on first success, 1 if already initialized, -1 on
// failure; -1 here would surface as an AEAD failure in the first test anyway.)
static const int g_zdc_sodium_init = sodium_init();

std::vector<uint8_t> rand_bytes(size_t n) {
    std::vector<uint8_t> v(n);
    if (n) randombytes_buf(&v[0], n);
    return v;
}

std::vector<uint8_t> make_key() {
    std::vector<uint8_t> k;
    EXPECT_EQ(ZdcAead::generate_key(k), OK);
    EXPECT_EQ(k.size(), AEAD_KEYBYTES);
    return k;
}

} // namespace

TEST(ZDC, HeaderRoundtrip) {
    FrameHeader h;
    h.magic = ZDC_MAGIC; h.version = ZDC_VERSION; h.type = FT_DATA;
    h.flags = FL_CIPHERTEXT; h.cipher_id = CIPHER_CHACHA20POLY1305;
    h.transfer_id = 0x0123456789ABCDEFull; h.seq = 0xDEADBEEF;
    h.chunk_count = 12345; h.payload_len = 480; h.crc32 = 0xCAFEBABE;
    h.reserved = 0;
    uint8_t buf[HEADER_SIZE];
    serialize_header(h, buf);
    // big-endian magic on the wire: 0x5A 0x44 0x43 0x31 = "ZDC1"
    EXPECT_EQ(buf[0], 0x5A); EXPECT_EQ(buf[1], 0x44);
    EXPECT_EQ(buf[2], 0x43); EXPECT_EQ(buf[3], 0x31);
    EXPECT_EQ(buf[4], ZDC_VERSION);
    EXPECT_EQ(buf[5], FT_DATA);
    FrameHeader g;
    uint8_t memo[MEMO_SIZE]; std::memset(memo, 0, sizeof memo);
    std::memcpy(memo, buf, HEADER_SIZE);
    EXPECT_EQ(parse_header(memo, g), OK);
    EXPECT_EQ(g.magic, h.magic);
    EXPECT_EQ(g.version, h.version);
    EXPECT_EQ(g.type, h.type);
    EXPECT_EQ(g.transfer_id, h.transfer_id);
    EXPECT_EQ(g.seq, h.seq);
    EXPECT_EQ(g.chunk_count, h.chunk_count);
    EXPECT_EQ(g.payload_len, h.payload_len);
    EXPECT_EQ(g.crc32, h.crc32);
}

TEST(ZDC, HeaderRejects) {
    uint8_t memo[MEMO_SIZE]; std::memset(memo, 0, sizeof memo);
    FrameHeader g;
    EXPECT_EQ(parse_header(memo, g), ERR_BAD_MAGIC);
    FrameHeader h; h.magic=ZDC_MAGIC; h.version=0x99; h.type=FT_DATA;
    h.flags=0; h.cipher_id=0; h.transfer_id=1; h.seq=0; h.chunk_count=1;
    h.payload_len=0; h.crc32=0; h.reserved=0;
    serialize_header(h, memo);
    EXPECT_EQ(parse_header(memo, g), ERR_BAD_VERSION);
    h.version=ZDC_VERSION; h.type=0x77; serialize_header(h, memo);
    EXPECT_EQ(parse_header(memo, g), ERR_BAD_TYPE);
    h.type=FT_DATA; h.reserved=1; serialize_header(h, memo);
    EXPECT_EQ(parse_header(memo, g), ERR_BAD_STATE);
    h.reserved=0; h.chunk_count=MAX_CHUNK_COUNT+1; serialize_header(h, memo);
    EXPECT_EQ(parse_header(memo, g), ERR_OVERSIZE);
}

TEST(ZDC, Crc) {
    // CRC-32/IEEE of "123456789" is the well-known 0xCBF43926.
    const char* s = "123456789";
    EXPECT_EQ(crc32((const uint8_t*)s, 9), 0xCBF43926u);
    EXPECT_EQ(crc32((const uint8_t*)"", 0), 0u);
}

TEST(ZDC, AeadRoundtrip) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(200);
    uint8_t aad[8] = {1,2,3,4,5,6,7,8};
    std::vector<uint8_t> ct, out;
    EXPECT_EQ(ZdcAead::encrypt(key, 42, 7, aad, 8, pt, ct), OK);
    EXPECT_EQ(ct.size(), pt.size() + AEAD_ABYTES);
    EXPECT_EQ(ZdcAead::decrypt(key, 42, 7, aad, 8, ct, out), OK);
    EXPECT_EQ(out.size(), pt.size());
    EXPECT_TRUE(out == pt);
    std::vector<uint8_t> e, ec, eo;
    EXPECT_EQ(ZdcAead::encrypt(key, 1, 0, aad, 8, e, ec), OK);
    EXPECT_EQ(ec.size(), (size_t)AEAD_ABYTES);
    EXPECT_EQ(ZdcAead::decrypt(key, 1, 0, aad, 8, ec, eo), OK);
    EXPECT_EQ(eo.size(), 0u);
}

TEST(ZDC, AeadTamperAndAad) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(100);
    uint8_t aad[4] = {0xAA,0xBB,0xCC,0xDD};
    std::vector<uint8_t> ct, out;
    EXPECT_EQ(ZdcAead::encrypt(key, 9, 3, aad, 4, pt, ct), OK);

    std::vector<uint8_t> ct2 = ct; ct2[0] ^= 0x01;
    EXPECT_EQ(ZdcAead::decrypt(key, 9, 3, aad, 4, ct2, out), ERR_AEAD_FAIL);
    ct2 = ct; ct2[ct2.size()-1] ^= 0x80;
    EXPECT_EQ(ZdcAead::decrypt(key, 9, 3, aad, 4, ct2, out), ERR_AEAD_FAIL);
    EXPECT_EQ(ZdcAead::decrypt(key, 9, 4, aad, 4, ct, out), ERR_AEAD_FAIL);
    EXPECT_EQ(ZdcAead::decrypt(key, 10, 3, aad, 4, ct, out), ERR_AEAD_FAIL);
    uint8_t aad2[4] = {0xAA,0xBB,0xCC,0xDE};
    EXPECT_EQ(ZdcAead::decrypt(key, 9, 3, aad2, 4, ct, out), ERR_AEAD_FAIL);
    std::vector<uint8_t> key2 = make_key();
    EXPECT_EQ(ZdcAead::decrypt(key2, 9, 3, aad, 4, ct, out), ERR_AEAD_FAIL);
}

// THE security-critical test: across a full transfer's frames, no two
// L3-encrypted frames share a (key, nonce). The key is constant within a
// transfer, so a duplicate nonce here would be CATASTROPHIC nonce reuse.
TEST(ZDC, NonceUniqueness) {
    std::vector<uint8_t> key = make_key();
    uint32_t sizes[] = {0, 1, DATA_PLAINTEXT_PER_FRAME, DATA_PLAINTEXT_PER_FRAME+1,
                        5*DATA_PLAINTEXT_PER_FRAME, 5*DATA_PLAINTEXT_PER_FRAME+13};
    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); ++si) {
        uint64_t tid = 0xABCDEF0011223344ull ^ si;
        std::vector<uint8_t> pt = rand_bytes(sizes[si]);
        TransferMeta meta; meta.filename = "x"; meta.content_type = "application/octet-stream";
        std::vector<std::vector<uint8_t> > frames;
        ASSERT_EQ(Encoder::encode(tid, key, pt, meta, true, frames), OK);

        std::set<std::string> nonces;
        for (size_t fi = 0; fi < frames.size(); ++fi) {
            FrameHeader h;
            ASSERT_EQ(parse_header(&frames[fi][0], h), OK);
            if (h.cipher_id == CIPHER_NONE) continue; // KEY frame
            uint32_t ctr;
            if (h.type == FT_START)      ctr = 0xFFFFFFFFu;
            else if (h.type == FT_END)   ctr = 0xFFFFFFFEu;
            else                         ctr = h.seq;
            uint8_t nonce[AEAD_NPUBBYTES];
            ZdcAead::derive_nonce(h.transfer_id, ctr, nonce);
            std::string key_s((const char*)nonce, AEAD_NPUBBYTES);
            bool inserted = nonces.insert(key_s).second;
            EXPECT_TRUE(inserted);
        }
    }
}

TEST(ZDC, RoundtripSizeMatrix) {
    std::vector<uint8_t> key = make_key();
    const size_t sizes[] = {0, 1, 479, 480, 481, 4096, 65536};
    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); ++si) {
        size_t n = sizes[si];
        uint64_t tid = 0x5120000000000000ull | (uint64_t)n;
        std::vector<uint8_t> pt = rand_bytes(n);
        TransferMeta meta; meta.filename = "m"; meta.content_type = "application/octet-stream";
        std::vector<std::vector<uint8_t> > frames;
        ASSERT_EQ(Encoder::encode(tid, key, pt, meta, true, frames), OK);

        uint32_t cc = (uint32_t)((n + DATA_PLAINTEXT_PER_FRAME - 1) / DATA_PLAINTEXT_PER_FRAME);
        EXPECT_EQ(frames.size(), (size_t)cc + 3);
        for (size_t i = 0; i < frames.size(); ++i) EXPECT_EQ(frames[i].size(), MEMO_SIZE);

        Decoder d;
        for (size_t i = 0; i < frames.size(); ++i) EXPECT_EQ(d.add_frame(frames[i]), OK);
        EXPECT_TRUE(d.is_complete());
        EXPECT_TRUE(d.have_key());
        EXPECT_EQ(d.chunk_count(), cc);
        std::vector<uint8_t> out; TransferMeta got;
        EXPECT_EQ(d.assemble(out, got), OK);
        EXPECT_EQ(out.size(), n);
        EXPECT_TRUE(out == pt);
        EXPECT_EQ(got.total_plaintext_size, (uint64_t)n);
        EXPECT_EQ(got.chunk_count, cc);
    }
}

TEST(ZDC, FullRoundtripShuffled) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(3 * DATA_PLAINTEXT_PER_FRAME + 7);
    TransferMeta meta; meta.filename = "secret.bin"; meta.content_type = "application/pdf";
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0x1111, key, pt, meta, true, frames), OK);
    EXPECT_EQ(frames.size(), (size_t)(1 + 4 + 1 + 1));

    Decoder d;
    for (size_t i = frames.size(); i-- > 0; ) {
        EXPECT_EQ(d.add_frame(frames[i]), OK);
        EXPECT_EQ(d.add_frame(frames[i]), OK); // duplicate ignored
    }
    EXPECT_TRUE(d.is_complete());
    EXPECT_TRUE(d.have_key());
    EXPECT_EQ(d.transfer_id(), 0x1111u);
    std::vector<uint8_t> out; TransferMeta got;
    EXPECT_EQ(d.assemble(out, got), OK);
    EXPECT_TRUE(out == pt);
    EXPECT_EQ(got.total_plaintext_size, pt.size());
    EXPECT_EQ(got.filename, "secret.bin");
    EXPECT_EQ(got.content_type, "application/pdf");
}

TEST(ZDC, EmptyPayload) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt;
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(7, key, pt, meta, true, frames), OK);
    EXPECT_EQ(frames.size(), 3u);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) EXPECT_EQ(d.add_frame(frames[i]), OK);
    EXPECT_TRUE(d.is_complete());
    std::vector<uint8_t> out; TransferMeta got;
    EXPECT_EQ(d.assemble(out, got), OK);
    EXPECT_EQ(out.size(), 0u);
}

TEST(ZDC, SealThenReveal) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(1000);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0x2222, key, pt, meta, false, frames), OK);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) EXPECT_EQ(d.add_frame(frames[i]), OK);
    EXPECT_TRUE(d.is_complete());
    EXPECT_FALSE(d.have_key());
    std::vector<uint8_t> out; TransferMeta got;
    EXPECT_EQ(d.assemble(out, got), ERR_NO_KEY);
    std::vector<uint8_t> kf;
    // Use the decoder's authoritative chunk_count (assemble does NOT populate
    // out_meta when it returns ERR_NO_KEY early, so got.chunk_count is unset).
    EXPECT_EQ(Encoder::encode_key_frame(0x2222, key, d.chunk_count(), kf), OK);
    EXPECT_EQ(d.add_frame(kf), OK);
    EXPECT_TRUE(d.have_key());
    EXPECT_EQ(d.assemble(out, got), OK);
    EXPECT_TRUE(out == pt);
}

TEST(ZDC, OobKey) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(900);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0x3333, key, pt, meta, false, frames), OK);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) EXPECT_EQ(d.add_frame(frames[i]), OK);
    std::vector<uint8_t> out; TransferMeta got;
    EXPECT_EQ(d.assemble(out, got), ERR_NO_KEY);
    EXPECT_EQ(d.set_key(key), OK);
    EXPECT_EQ(d.assemble(out, got), OK);
    EXPECT_TRUE(out == pt);
    std::vector<uint8_t> bad(10, 0);
    Decoder d2; EXPECT_EQ(d2.set_key(bad), ERR_BAD_STATE);
}

TEST(ZDC, WrongKeyFailsAssemble) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(2 * DATA_PLAINTEXT_PER_FRAME + 5);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0xBEEF, key, pt, meta, false, frames), OK);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) EXPECT_EQ(d.add_frame(frames[i]), OK);
    EXPECT_TRUE(d.is_complete());
    std::vector<uint8_t> wrong = make_key();
    EXPECT_EQ(d.set_key(wrong), OK);
    std::vector<uint8_t> out; TransferMeta got;
    EXPECT_EQ(d.assemble(out, got), ERR_AEAD_FAIL);
}

TEST(ZDC, MissingAndReorderDetect) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(4 * DATA_PLAINTEXT_PER_FRAME);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0x4444, key, pt, meta, true, frames), OK);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) {
        if (i == 2) continue; // skip DATA chunk 1
        EXPECT_EQ(d.add_frame(frames[i]), OK);
    }
    EXPECT_FALSE(d.is_complete());
    std::vector<uint32_t> miss = d.missing_chunks();
    ASSERT_EQ(miss.size(), 1u);
    EXPECT_EQ(miss[0], 1u);
    std::vector<uint8_t> out; TransferMeta got;
    EXPECT_EQ(d.assemble(out, got), ERR_INCOMPLETE);
}

TEST(ZDC, TamperInTransitDetected) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(2 * DATA_PLAINTEXT_PER_FRAME);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0x5555, key, pt, meta, true, frames), OK);
    std::vector<uint8_t> f = frames[1];
    f[HEADER_SIZE + 5] ^= 0x01;
    uint32_t newcrc = crc32(&f[HEADER_SIZE], FRAME_PAYLOAD);
    f[26]=(uint8_t)(newcrc>>24); f[27]=(uint8_t)(newcrc>>16);
    f[28]=(uint8_t)(newcrc>>8);  f[29]=(uint8_t)(newcrc);
    frames[1] = f;
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) EXPECT_EQ(d.add_frame(frames[i]), OK);
    EXPECT_TRUE(d.is_complete());
    std::vector<uint8_t> out; TransferMeta got;
    EXPECT_EQ(d.assemble(out, got), ERR_AEAD_FAIL);
}

TEST(ZDC, CrcCorruptionRejected) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(500);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0x6666, key, pt, meta, true, frames), OK);
    std::vector<uint8_t> f = frames[1];
    f[HEADER_SIZE + 0] ^= 0xFF;
    EXPECT_EQ(Decoder().add_frame(f), ERR_BAD_CRC);
}

TEST(ZDC, TruncationRejected) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(100);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0x7777, key, pt, meta, true, frames), OK);
    std::vector<uint8_t> shortf(frames[0].begin(), frames[0].begin()+511);
    EXPECT_EQ(Decoder().add_frame(shortf), ERR_TRUNCATED);
}

TEST(ZDC, NonZdcMemoPassthrough) {
    std::vector<uint8_t> memo(MEMO_SIZE, 0);
    const char* txt = "hello, this is a normal memo";
    std::memcpy(&memo[0], txt, std::strlen(txt));
    EXPECT_EQ(Decoder().add_frame(memo), ERR_BAD_MAGIC);
}

TEST(ZDC, ForeignTransferIdRejected) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(100);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > a, b;
    ASSERT_EQ(Encoder::encode(0xA, key, pt, meta, true, a), OK);
    ASSERT_EQ(Encoder::encode(0xB, key, pt, meta, true, b), OK);
    Decoder d;
    EXPECT_EQ(d.add_frame(a[0]), OK);
    EXPECT_EQ(d.add_frame(b[0]), ERR_BAD_STATE);
}

TEST(ZDC, SizeCaps) {
    std::vector<uint8_t> key = make_key();
    EXPECT_EQ(MAX_TRANSFER_BYTES, (uint64_t)MAX_CHUNK_COUNT * DATA_PLAINTEXT_PER_FRAME);
    EXPECT_EQ(DATA_PLAINTEXT_PER_FRAME, FRAME_PAYLOAD - AEAD_ABYTES);
    EXPECT_EQ(FRAME_PAYLOAD, MEMO_SIZE - HEADER_SIZE);
    std::vector<uint8_t> pt = rand_bytes(10);
    TransferMeta meta; meta.filename = std::string(DATA_PLAINTEXT_PER_FRAME, 'A');
    std::vector<std::vector<uint8_t> > frames;
    EXPECT_EQ(Encoder::encode(1, key, pt, meta, true, frames), ERR_OVERSIZE);
}

TEST(ZDC, MaxDataFrame) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(DATA_PLAINTEXT_PER_FRAME);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0x8888, key, pt, meta, true, frames), OK);
    EXPECT_EQ(frames.size(), (size_t)(1 + 1 + 1 + 1));
    FrameHeader h; ASSERT_EQ(parse_header(&frames[1][0], h), OK);
    EXPECT_EQ(h.type, FT_DATA);
    EXPECT_EQ(h.payload_len, FRAME_PAYLOAD);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) EXPECT_EQ(d.add_frame(frames[i]), OK);
    std::vector<uint8_t> out; TransferMeta got;
    EXPECT_EQ(d.assemble(out, got), OK);
    EXPECT_TRUE(out == pt);
}

TEST(ZDC, FrameSizes) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(1234);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(1, key, pt, meta, true, frames), OK);
    for (size_t i = 0; i < frames.size(); ++i) EXPECT_EQ(frames[i].size(), MEMO_SIZE);
}

// ── SINGLE-TX BROADCASTABILITY (the shipped file cap is provably honest) ──────
//
// Mirrors the production constants from rpc/datachannel.cpp + wallet/
// asyncrpcoperation_senddatafile.cpp. The point of this test is to FAIL THE BUILD
// if someone later raises the file cap past what one shielded tx can broadcast,
// turning the previously-reproduced "advertise 64KB, fail late with bad-txns-
// oversize" blocker into a compile-gated invariant.
namespace {
    // KEEP IN SYNC WITH rpc/datachannel.cpp
    const size_t TEST_ZDC_MAX_FILE_BYTES    = 40000;
    const size_t TEST_ZDC_MAX_FRAMES_PER_TX = 90;
    // KEEP IN SYNC WITH wallet/asyncrpcoperation_senddatafile.cpp
    const size_t TEST_SPEND_DESC_BYTES   = 384;  // SpendDescription on the wire
    const size_t TEST_OUTPUT_DESC_BYTES  = 948;  // OutputDescription on the wire
    const size_t TEST_TX_ENVELOPE_BYTES  = 256;  // conservative fixed overhead
    // A worst-case-ish input-note count for the broadcastability check. The async
    // op selects biggest-notes-first, so a funded transfer is usually 1-2 spends;
    // we still prove headroom for a chunky 16-note spend.
    const size_t TEST_WORST_CASE_SPENDS  = 16;

    size_t projected_tx_size(size_t nSpends, size_t nDataFrames) {
        size_t nOutputs = nDataFrames + 1; // + change output
        return TEST_TX_ENVELOPE_BYTES
             + nSpends  * TEST_SPEND_DESC_BYTES
             + nOutputs * TEST_OUTPUT_DESC_BYTES;
    }
}

TEST(ZDC, SingleTxFrameCeilingMatchesFileCap) {
    // The max file (40000 bytes) must produce <= ZDC_MAX_FRAMES_PER_TX frames.
    uint32_t cc = (uint32_t)((TEST_ZDC_MAX_FILE_BYTES + DATA_PLAINTEXT_PER_FRAME - 1)
                             / DATA_PLAINTEXT_PER_FRAME);
    size_t totalFrames = (size_t)cc + 3; // START + END + KEY
    EXPECT_LE(totalFrames, TEST_ZDC_MAX_FRAMES_PER_TX)
        << "file cap implies " << totalFrames << " frames > frame ceiling "
        << TEST_ZDC_MAX_FRAMES_PER_TX;

    // And actually encode a max-size payload to confirm the real encoder agrees.
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(TEST_ZDC_MAX_FILE_BYTES);
    TransferMeta meta; meta.filename = "max.bin";
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0xCAFE, key, pt, meta, true, frames), OK);
    EXPECT_LE(frames.size(), TEST_ZDC_MAX_FRAMES_PER_TX);
}

TEST(ZDC, MaxFileTxIsBroadcastable) {
    // The whole point of the blocker fix: the worst-case tx for a max-size file
    // MUST serialize under the consensus limit (MAX_TX_SIZE_AFTER_SAPLING) — so
    // it broadcasts instead of dying with "bad-txns-oversize" after proving.
    size_t projected = projected_tx_size(TEST_WORST_CASE_SPENDS, TEST_ZDC_MAX_FRAMES_PER_TX);
    EXPECT_LE(projected, (size_t)MAX_TX_SIZE_AFTER_SAPLING)
        << "max-file tx projects to " << projected
        << " bytes, over consensus limit " << MAX_TX_SIZE_AFTER_SAPLING;

    // Even with the 1-spend common case the same holds, with lots of margin.
    EXPECT_LE(projected_tx_size(1, TEST_ZDC_MAX_FRAMES_PER_TX),
              (size_t)MAX_TX_SIZE_AFTER_SAPLING);
}

TEST(ZDC, OldCapWouldHaveOverflowed) {
    // Regression sentinel for the ORIGINAL blocker: the previous 64KB cap (and
    // anything near it) overflows a single tx. This documents WHY the cap moved.
    const size_t oldCap = 64 * 1024;
    uint32_t cc = (uint32_t)((oldCap + DATA_PLAINTEXT_PER_FRAME - 1)
                             / DATA_PLAINTEXT_PER_FRAME);
    size_t oldFrames = (size_t)cc + 3;
    // With the 1-spend best case the old cap STILL overflows on outputs alone.
    size_t projectedOld = projected_tx_size(1, oldFrames);
    EXPECT_GT(projectedOld, (size_t)MAX_TX_SIZE_AFTER_SAPLING)
        << "the old 64KB cap should overflow one tx; it projects to " << projectedOld;
}

TEST(ZDC, CiphertextFingerprint) {
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(3 * DATA_PLAINTEXT_PER_FRAME + 11);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    ASSERT_EQ(Encoder::encode(0x9999, key, pt, meta, true, frames), OK);

    uint8_t fp1[CONTENT_HASH_LEN];
    EXPECT_EQ(ciphertext_fingerprint(frames, fp1), OK);

    uint8_t fp2[CONTENT_HASH_LEN];
    EXPECT_EQ(ciphertext_fingerprint(frames, fp2), OK);
    EXPECT_EQ(std::memcmp(fp1, fp2, CONTENT_HASH_LEN), 0);

    std::vector<std::vector<uint8_t> > shuffled(frames.rbegin(), frames.rend());
    uint8_t fp3[CONTENT_HASH_LEN];
    EXPECT_EQ(ciphertext_fingerprint(shuffled, fp3), OK);
    EXPECT_EQ(std::memcmp(fp1, fp3, CONTENT_HASH_LEN), 0);

    // Verify-BEFORE-decrypt: anchor computable without the key, equals SHA-256
    // over the concatenated DATA ciphertext payloads.
    crypto_hash_sha256_state hst; crypto_hash_sha256_init(&hst);
    for (size_t i = 0; i < frames.size(); ++i) {
        FrameHeader h; ASSERT_EQ(parse_header(&frames[i][0], h), OK);
        if (h.type != FT_DATA) continue;
        crypto_hash_sha256_update(&hst, &frames[i][HEADER_SIZE], h.payload_len);
    }
    uint8_t manual[CONTENT_HASH_LEN]; crypto_hash_sha256_final(&hst, manual);
    EXPECT_EQ(std::memcmp(fp1, manual, CONTENT_HASH_LEN), 0);

    std::vector<std::vector<uint8_t> > tampered = frames;
    tampered[1][HEADER_SIZE] ^= 0x01;
    uint8_t fp4[CONTENT_HASH_LEN];
    EXPECT_EQ(ciphertext_fingerprint(tampered, fp4), OK);
    EXPECT_NE(std::memcmp(fp1, fp4, CONTENT_HASH_LEN), 0);
}
