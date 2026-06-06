// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license.
//
// Standalone unit tests for the ZDC1 codec. No gtest dependency — a tiny
// self-contained CHECK harness so it runs anywhere.
//
//   g++ -std=c++11 ../zdc.cpp zdc_test.cpp -lsodium -o /tmp/zdc_test && /tmp/zdc_test
//
// Covers: header round-trip + endianness, CRC, AEAD round-trip, NONCE
// UNIQUENESS (the catastrophic-if-wrong property), AAD binding (reorder/retype
// fails), tamper detection, truncation/dup/missing/reorder reassembly, size
// caps, empty + maximal payloads, seal-then-reveal (KEY frame), out-of-band key,
// and non-ZDC1 memo passthrough.

#include "../zdc.h"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <set>
#include <string>
#include <vector>

using namespace zdc;

// ---- tiny test harness ----
static int g_checks = 0;
static int g_fails  = 0;
static const char* g_case = "";

#define CASE(name) do { g_case = name; } while (0)
#define CHECK(cond) do { \
    ++g_checks; \
    if (!(cond)) { ++g_fails; \
        std::printf("  FAIL [%s] %s:%d  CHECK(%s)\n", g_case, __FILE__, __LINE__, #cond); } \
} while (0)
#define CHECK_EQ(a,b) do { \
    ++g_checks; \
    long long _a=(long long)(a), _b=(long long)(b); \
    if (_a != _b) { ++g_fails; \
        std::printf("  FAIL [%s] %s:%d  CHECK_EQ(%s,%s)  %lld != %lld\n", \
            g_case, __FILE__, __LINE__, #a, #b, _a, _b); } \
} while (0)

static std::vector<uint8_t> rand_bytes(size_t n) {
    std::vector<uint8_t> v(n);
    if (n) randombytes_buf(&v[0], n);
    return v;
}
static std::vector<uint8_t> make_key() {
    std::vector<uint8_t> k;
    CHECK_EQ(ZdcAead::generate_key(k), OK);
    CHECK_EQ(k.size(), AEAD_KEYBYTES);
    return k;
}

// ===========================================================================
static void test_header_roundtrip() {
    CASE("header_roundtrip");
    FrameHeader h;
    h.magic = ZDC_MAGIC; h.version = ZDC_VERSION; h.type = FT_DATA;
    h.flags = FL_CIPHERTEXT; h.cipher_id = CIPHER_CHACHA20POLY1305;
    h.transfer_id = 0x0123456789ABCDEFull; h.seq = 0xDEADBEEF;
    h.chunk_count = 12345; h.payload_len = 480; h.crc32 = 0xCAFEBABE; // count <= MAX_CHUNK_COUNT
    h.reserved = 0;
    uint8_t buf[HEADER_SIZE];
    serialize_header(h, buf);
    // big-endian magic on the wire: 0x5A 0x44 0x43 0x31 = "ZDC1"
    CHECK_EQ(buf[0], 0x5A); CHECK_EQ(buf[1], 0x44);
    CHECK_EQ(buf[2], 0x43); CHECK_EQ(buf[3], 0x31);
    CHECK_EQ(buf[4], ZDC_VERSION);
    CHECK_EQ(buf[5], FT_DATA);
    FrameHeader g;
    // parse_header validates payload_len<=480; pad a full 512 buffer for the test.
    uint8_t memo[MEMO_SIZE]; std::memset(memo, 0, sizeof memo);
    std::memcpy(memo, buf, HEADER_SIZE);
    CHECK_EQ(parse_header(memo, g), OK);
    CHECK_EQ(g.magic, h.magic);
    CHECK_EQ(g.version, h.version);
    CHECK_EQ(g.type, h.type);
    CHECK_EQ(g.transfer_id, h.transfer_id);
    CHECK_EQ(g.seq, h.seq);
    CHECK_EQ(g.chunk_count, h.chunk_count);
    CHECK_EQ(g.payload_len, h.payload_len);
    CHECK_EQ(g.crc32, h.crc32);
}

static void test_header_rejects() {
    CASE("header_rejects");
    uint8_t memo[MEMO_SIZE]; std::memset(memo, 0, sizeof memo);
    FrameHeader g;
    // all zero => bad magic
    CHECK_EQ(parse_header(memo, g), ERR_BAD_MAGIC);
    // good magic, bad version
    FrameHeader h; h.magic=ZDC_MAGIC; h.version=0x99; h.type=FT_DATA;
    h.flags=0; h.cipher_id=0; h.transfer_id=1; h.seq=0; h.chunk_count=1;
    h.payload_len=0; h.crc32=0; h.reserved=0;
    serialize_header(h, memo);
    CHECK_EQ(parse_header(memo, g), ERR_BAD_VERSION);
    // good version, bad type
    h.version=ZDC_VERSION; h.type=0x77; serialize_header(h, memo);
    CHECK_EQ(parse_header(memo, g), ERR_BAD_TYPE);
    // reserved != 0
    h.type=FT_DATA; h.reserved=1; serialize_header(h, memo);
    CHECK_EQ(parse_header(memo, g), ERR_BAD_STATE);
    // chunk_count over cap
    h.reserved=0; h.chunk_count=MAX_CHUNK_COUNT+1; serialize_header(h, memo);
    CHECK_EQ(parse_header(memo, g), ERR_OVERSIZE);
}

static void test_crc() {
    CASE("crc");
    // CRC-32/IEEE of "123456789" is the well-known 0xCBF43926.
    const char* s = "123456789";
    CHECK_EQ(crc32((const uint8_t*)s, 9), 0xCBF43926u);
    CHECK_EQ(crc32((const uint8_t*)"", 0), 0u);
}

static void test_aead_roundtrip() {
    CASE("aead_roundtrip");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(200);
    uint8_t aad[8] = {1,2,3,4,5,6,7,8};
    std::vector<uint8_t> ct, out;
    CHECK_EQ(ZdcAead::encrypt(key, 42, 7, aad, 8, pt, ct), OK);
    CHECK_EQ(ct.size(), pt.size() + AEAD_ABYTES);
    CHECK_EQ(ZdcAead::decrypt(key, 42, 7, aad, 8, ct, out), OK);
    CHECK_EQ(out.size(), pt.size());
    CHECK(out == pt);
    // empty plaintext is valid (tag-only ciphertext)
    std::vector<uint8_t> e, ec, eo;
    CHECK_EQ(ZdcAead::encrypt(key, 1, 0, aad, 8, e, ec), OK);
    CHECK_EQ(ec.size(), (size_t)AEAD_ABYTES);
    CHECK_EQ(ZdcAead::decrypt(key, 1, 0, aad, 8, ec, eo), OK);
    CHECK_EQ(eo.size(), 0);
}

static void test_aead_tamper_and_aad() {
    CASE("aead_tamper_and_aad");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(100);
    uint8_t aad[4] = {0xAA,0xBB,0xCC,0xDD};
    std::vector<uint8_t> ct, out;
    CHECK_EQ(ZdcAead::encrypt(key, 9, 3, aad, 4, pt, ct), OK);

    // flip a ciphertext byte -> fail
    std::vector<uint8_t> ct2 = ct; ct2[0] ^= 0x01;
    CHECK_EQ(ZdcAead::decrypt(key, 9, 3, aad, 4, ct2, out), ERR_AEAD_FAIL);
    // flip the tag -> fail
    ct2 = ct; ct2[ct2.size()-1] ^= 0x80;
    CHECK_EQ(ZdcAead::decrypt(key, 9, 3, aad, 4, ct2, out), ERR_AEAD_FAIL);
    // wrong nonce counter (== reordered/retyped frame) -> fail
    CHECK_EQ(ZdcAead::decrypt(key, 9, 4, aad, 4, ct, out), ERR_AEAD_FAIL);
    // wrong transfer_id -> fail
    CHECK_EQ(ZdcAead::decrypt(key, 10, 3, aad, 4, ct, out), ERR_AEAD_FAIL);
    // changed AAD -> fail
    uint8_t aad2[4] = {0xAA,0xBB,0xCC,0xDE};
    CHECK_EQ(ZdcAead::decrypt(key, 9, 3, aad2, 4, ct, out), ERR_AEAD_FAIL);
    // wrong key -> fail
    std::vector<uint8_t> key2 = make_key();
    CHECK_EQ(ZdcAead::decrypt(key2, 9, 3, aad, 4, ct, out), ERR_AEAD_FAIL);
}

// THE security-critical test: across a full transfer's frames, no two
// L3-encrypted frames share a (key, nonce). Because the key is constant within
// a transfer, that means no two share a NONCE. We reconstruct the exact nonce
// each frame uses by parsing the produced frames and re-deriving from the role.
static void test_nonce_uniqueness() {
    CASE("nonce_uniqueness");
    std::vector<uint8_t> key = make_key();
    // Use several sizes incl. the smallest (1 chunk) where START/DATA0 collide if buggy.
    uint32_t sizes[] = {0, 1, DATA_PLAINTEXT_PER_FRAME, DATA_PLAINTEXT_PER_FRAME+1,
                        5*DATA_PLAINTEXT_PER_FRAME, 5*DATA_PLAINTEXT_PER_FRAME+13};
    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); ++si) {
        uint64_t tid = 0xABCDEF0011223344ull ^ si;
        std::vector<uint8_t> pt = rand_bytes(sizes[si]);
        TransferMeta meta; meta.filename = "x"; meta.content_type = "application/octet-stream";
        std::vector<std::vector<uint8_t> > frames;
        Status s = Encoder::encode(tid, key, pt, meta, true /*key frame*/, frames);
        CHECK_EQ(s, OK);

        // Collect the 12-byte nonce of every L3-encrypted frame (START/DATA/END).
        // The KEY frame is NOT L3-encrypted (cipher_id NONE) so it is excluded.
        std::set<std::string> nonces;
        for (size_t fi = 0; fi < frames.size(); ++fi) {
            FrameHeader h;
            CHECK_EQ(parse_header(&frames[fi][0], h), OK);
            if (h.cipher_id == CIPHER_NONE) continue; // KEY frame
            uint32_t ctr;
            if (h.type == FT_START)      ctr = 0xFFFFFFFFu;        // NONCE_CTR_START
            else if (h.type == FT_END)   ctr = 0xFFFFFFFEu;        // NONCE_CTR_END
            else                         ctr = h.seq;              // DATA -> chunk index
            uint8_t nonce[AEAD_NPUBBYTES];
            ZdcAead::derive_nonce(h.transfer_id, ctr, nonce);
            std::string key_s((const char*)nonce, AEAD_NPUBBYTES);
            bool inserted = nonces.insert(key_s).second;
            CHECK(inserted); // a duplicate here would be CATASTROPHIC nonce reuse
        }
    }
}

// Full encode -> reassemble -> equals across the exact size matrix that straddles
// the chunk boundaries (DATA_PLAINTEXT_PER_FRAME == 464). 479/480/481 sit around
// the 480-byte frame field; 4 KB and 64 KB are the practical message/file sizes.
// Each size is delivered IN ORDER (this is the "does the bytes survive a round
// trip" test; out-of-order is covered separately by test_full_roundtrip_shuffled).
static void test_roundtrip_size_matrix() {
    CASE("roundtrip_size_matrix");
    std::vector<uint8_t> key = make_key();
    const size_t sizes[] = {0, 1, 479, 480, 481, 4096, 65536};
    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); ++si) {
        size_t n = sizes[si];
        uint64_t tid = 0x5120000000000000ull | (uint64_t)n;
        std::vector<uint8_t> pt = rand_bytes(n);
        TransferMeta meta; meta.filename = "m"; meta.content_type = "application/octet-stream";
        std::vector<std::vector<uint8_t> > frames;
        CHECK_EQ(Encoder::encode(tid, key, pt, meta, true, frames), OK);

        // chunk_count must be ceil(n / 464); frame count = START + DATA*cc + END + KEY.
        uint32_t cc = (uint32_t)((n + DATA_PLAINTEXT_PER_FRAME - 1) / DATA_PLAINTEXT_PER_FRAME);
        CHECK_EQ(frames.size(), (size_t)cc + 3);
        for (size_t i = 0; i < frames.size(); ++i) CHECK_EQ(frames[i].size(), MEMO_SIZE);

        Decoder d;
        for (size_t i = 0; i < frames.size(); ++i) CHECK_EQ(d.add_frame(frames[i]), OK);
        CHECK(d.is_complete());
        CHECK(d.have_key());
        CHECK_EQ(d.chunk_count(), cc);
        std::vector<uint8_t> out; TransferMeta got;
        CHECK_EQ(d.assemble(out, got), OK);
        CHECK_EQ(out.size(), n);
        CHECK(out == pt); // exact byte-for-byte recovery
        CHECK_EQ(got.total_plaintext_size, (long long)n);
        CHECK_EQ(got.chunk_count, cc);
    }
}

// Round-trip a full transfer through Encoder + Decoder, frames delivered in
// SHUFFLED order with a DUPLICATE injected, to prove order-independence.
static void test_full_roundtrip_shuffled() {
    CASE("full_roundtrip_shuffled");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(3 * DATA_PLAINTEXT_PER_FRAME + 7);
    TransferMeta meta; meta.filename = "secret.bin"; meta.content_type = "application/pdf";
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(0x1111, key, pt, meta, true, frames), OK);
    // START + 4 DATA + END + KEY = 7 frames
    CHECK_EQ(frames.size(), 1 + 4 + 1 + 1);

    Decoder d;
    // Deliver reversed, and feed each frame twice (dup must be ignored).
    for (size_t i = frames.size(); i-- > 0; ) {
        CHECK_EQ(d.add_frame(frames[i]), OK);
        CHECK_EQ(d.add_frame(frames[i]), OK); // duplicate
    }
    CHECK(d.is_complete());
    CHECK(d.have_key());
    CHECK_EQ(d.transfer_id(), 0x1111u);
    std::vector<uint8_t> out; TransferMeta got;
    CHECK_EQ(d.assemble(out, got), OK);
    CHECK(out == pt);
    CHECK_EQ(got.total_plaintext_size, pt.size());
    CHECK(got.filename == "secret.bin");
    CHECK(got.content_type == "application/pdf");
}

static void test_empty_payload() {
    CASE("empty_payload");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt; // zero bytes
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(7, key, pt, meta, true, frames), OK);
    // START + 0 DATA + END + KEY
    CHECK_EQ(frames.size(), 3);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) CHECK_EQ(d.add_frame(frames[i]), OK);
    CHECK(d.is_complete());
    std::vector<uint8_t> out; TransferMeta got;
    CHECK_EQ(d.assemble(out, got), OK);
    CHECK_EQ(out.size(), 0);
}

static void test_seal_then_reveal() {
    CASE("seal_then_reveal");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(1000);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    // include_key_frame = false => content published, key withheld.
    CHECK_EQ(Encoder::encode(0x2222, key, pt, meta, false, frames), OK);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) CHECK_EQ(d.add_frame(frames[i]), OK);
    CHECK(d.is_complete());
    CHECK(!d.have_key());
    std::vector<uint8_t> out; TransferMeta got;
    // Sealed: complete content but no key yet.
    CHECK_EQ(d.assemble(out, got), ERR_NO_KEY);
    // Reveal later via a standalone KEY frame.
    std::vector<uint8_t> kf;
    CHECK_EQ(Encoder::encode_key_frame(0x2222, key, got.chunk_count, kf), OK);
    CHECK_EQ(d.add_frame(kf), OK);
    CHECK(d.have_key());
    CHECK_EQ(d.assemble(out, got), OK);
    CHECK(out == pt);
}

static void test_oob_key() {
    CASE("oob_key");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(900);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(0x3333, key, pt, meta, false, frames), OK);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) CHECK_EQ(d.add_frame(frames[i]), OK);
    std::vector<uint8_t> out; TransferMeta got;
    CHECK_EQ(d.assemble(out, got), ERR_NO_KEY);
    CHECK_EQ(d.set_key(key), OK);  // delivered out-of-band
    CHECK_EQ(d.assemble(out, got), OK);
    CHECK(out == pt);
    // wrong-length OOB key rejected
    std::vector<uint8_t> bad(10, 0);
    Decoder d2; CHECK_EQ(d2.set_key(bad), ERR_BAD_STATE);
}

// Wrong key supplied to a COMPLETE transfer must fail at assemble (AEAD tag), not
// silently return garbage. Distinct from test_aead_tamper_and_aad (raw AEAD) and
// test_oob_key (right key out-of-band): this drives the full Decoder path.
static void test_wrong_key_fails_assemble() {
    CASE("wrong_key_fails_assemble");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(2 * DATA_PLAINTEXT_PER_FRAME + 5);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(0xBEEF, key, pt, meta, false, frames), OK);
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) CHECK_EQ(d.add_frame(frames[i]), OK);
    CHECK(d.is_complete());
    std::vector<uint8_t> wrong = make_key(); // different 32B key
    CHECK_EQ(d.set_key(wrong), OK);          // accepted (right length), but wrong
    std::vector<uint8_t> out; TransferMeta got;
    // START decrypts first; AEAD tag rejects the wrong key -> ERR_AEAD_FAIL.
    CHECK_EQ(d.assemble(out, got), ERR_AEAD_FAIL);
}

static void test_missing_and_reorder_detect() {
    CASE("missing_and_reorder_detect");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(4 * DATA_PLAINTEXT_PER_FRAME);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(0x4444, key, pt, meta, true, frames), OK);
    // Withhold one DATA frame (index 2 = START at 0, DATA0 at 1, DATA1 at 2).
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) {
        if (i == 2) continue; // skip DATA chunk 1
        CHECK_EQ(d.add_frame(frames[i]), OK);
    }
    CHECK(!d.is_complete());
    std::vector<uint32_t> miss = d.missing_chunks();
    CHECK_EQ(miss.size(), 1);
    CHECK_EQ(miss[0], 1u);
    std::vector<uint8_t> out; TransferMeta got;
    CHECK_EQ(d.assemble(out, got), ERR_INCOMPLETE);
}

static void test_tamper_in_transit_detected() {
    CASE("tamper_in_transit_detected");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(2 * DATA_PLAINTEXT_PER_FRAME);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(0x5555, key, pt, meta, true, frames), OK);
    // Flip a payload byte in DATA frame 1 (index 1) AND fix its crc so it passes
    // the transport check — the AEAD tag must still catch it.
    std::vector<uint8_t> f = frames[1];
    f[HEADER_SIZE + 5] ^= 0x01;
    uint32_t newcrc = crc32(&f[HEADER_SIZE], FRAME_PAYLOAD);
    // rewrite crc field (offset 26, big-endian)
    f[26]=(uint8_t)(newcrc>>24); f[27]=(uint8_t)(newcrc>>16);
    f[28]=(uint8_t)(newcrc>>8);  f[29]=(uint8_t)(newcrc);
    frames[1] = f;
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) CHECK_EQ(d.add_frame(frames[i]), OK);
    CHECK(d.is_complete());
    std::vector<uint8_t> out; TransferMeta got;
    CHECK_EQ(d.assemble(out, got), ERR_AEAD_FAIL); // tag catches the flip
}

static void test_crc_corruption_rejected() {
    CASE("crc_corruption_rejected");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(500);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(0x6666, key, pt, meta, true, frames), OK);
    // Corrupt a payload byte WITHOUT fixing crc -> transport rejects it.
    std::vector<uint8_t> f = frames[1];
    f[HEADER_SIZE + 0] ^= 0xFF;
    CHECK_EQ(Decoder().add_frame(f), ERR_BAD_CRC);
}

static void test_truncation_rejected() {
    CASE("truncation_rejected");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(100);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(0x7777, key, pt, meta, true, frames), OK);
    std::vector<uint8_t> shortf(frames[0].begin(), frames[0].begin()+511);
    CHECK_EQ(Decoder().add_frame(shortf), ERR_TRUNCATED);
}

static void test_non_zdc_memo_passthrough() {
    CASE("non_zdc_memo_passthrough");
    // An ordinary 512-byte text memo must be reported as not-a-ZDC1-frame so the
    // caller routes it to the text inbox, not the data channel.
    std::vector<uint8_t> memo(MEMO_SIZE, 0);
    const char* txt = "hello, this is a normal memo";
    std::memcpy(&memo[0], txt, std::strlen(txt));
    CHECK_EQ(Decoder().add_frame(memo), ERR_BAD_MAGIC);
}

static void test_foreign_transfer_id_rejected() {
    CASE("foreign_transfer_id_rejected");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(100);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > a, b;
    CHECK_EQ(Encoder::encode(0xA, key, pt, meta, true, a), OK);
    CHECK_EQ(Encoder::encode(0xB, key, pt, meta, true, b), OK);
    Decoder d;
    CHECK_EQ(d.add_frame(a[0]), OK);           // locks transfer_id = 0xA
    CHECK_EQ(d.add_frame(b[0]), ERR_BAD_STATE); // 0xB rejected
}

static void test_size_caps() {
    CASE("size_caps");
    std::vector<uint8_t> key = make_key();
    // One byte over the absolute transfer cap must be rejected before any frame.
    // (Allocating MAX_TRANSFER_BYTES would be huge; just verify the guard math by
    //  checking that chunk_count over MAX_CHUNK_COUNT is refused via a forged
    //  meta path is unnecessary — encode computes chunk_count and rejects.)
    // Use a payload that yields exactly MAX_CHUNK_COUNT+0 chunks is too big to
    // allocate here; instead assert the constants are internally consistent.
    CHECK_EQ(MAX_TRANSFER_BYTES, (uint64_t)MAX_CHUNK_COUNT * DATA_PLAINTEXT_PER_FRAME);
    CHECK_EQ(DATA_PLAINTEXT_PER_FRAME, FRAME_PAYLOAD - AEAD_ABYTES);
    CHECK_EQ(FRAME_PAYLOAD, MEMO_SIZE - HEADER_SIZE);
    // A modest oversize via filename that won't fit the START frame.
    std::vector<uint8_t> pt = rand_bytes(10);
    TransferMeta meta; meta.filename = std::string(DATA_PLAINTEXT_PER_FRAME, 'A');
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(1, key, pt, meta, true, frames), ERR_OVERSIZE);
}

static void test_max_data_frame() {
    CASE("max_data_frame");
    // Exactly one full DATA chunk (464 bytes) -> 1 chunk, frame payload == 480.
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(DATA_PLAINTEXT_PER_FRAME);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(0x8888, key, pt, meta, true, frames), OK);
    CHECK_EQ(frames.size(), 1 + 1 + 1 + 1);
    FrameHeader h; CHECK_EQ(parse_header(&frames[1][0], h), OK);
    CHECK_EQ(h.type, FT_DATA);
    CHECK_EQ(h.payload_len, FRAME_PAYLOAD); // 464 plaintext + 16 tag = 480
    Decoder d;
    for (size_t i = 0; i < frames.size(); ++i) CHECK_EQ(d.add_frame(frames[i]), OK);
    std::vector<uint8_t> out; TransferMeta got;
    CHECK_EQ(d.assemble(out, got), OK);
    CHECK(out == pt);
}

// Every produced frame must be exactly 512 bytes.
static void test_frame_sizes() {
    CASE("frame_sizes");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(1234);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(1, key, pt, meta, true, frames), OK);
    for (size_t i = 0; i < frames.size(); ++i) CHECK_EQ(frames[i].size(), MEMO_SIZE);
}

static void test_ciphertext_fingerprint() {
    CASE("ciphertext_fingerprint");
    std::vector<uint8_t> key = make_key();
    std::vector<uint8_t> pt = rand_bytes(3 * DATA_PLAINTEXT_PER_FRAME + 11);
    TransferMeta meta;
    std::vector<std::vector<uint8_t> > frames;
    CHECK_EQ(Encoder::encode(0x9999, key, pt, meta, true, frames), OK);

    uint8_t fp1[CONTENT_HASH_LEN];
    CHECK_EQ(ciphertext_fingerprint(frames, fp1), OK);

    // Deterministic: recomputing over the same frames yields the same anchor.
    uint8_t fp2[CONTENT_HASH_LEN];
    CHECK_EQ(ciphertext_fingerprint(frames, fp2), OK);
    CHECK_EQ(std::memcmp(fp1, fp2, CONTENT_HASH_LEN), 0);

    // Order-independent: shuffle the frame vector, anchor is unchanged (it sorts
    // DATA frames by seq internally).
    std::vector<std::vector<uint8_t> > shuffled(frames.rbegin(), frames.rend());
    uint8_t fp3[CONTENT_HASH_LEN];
    CHECK_EQ(ciphertext_fingerprint(shuffled, fp3), OK);
    CHECK_EQ(std::memcmp(fp1, fp3, CONTENT_HASH_LEN), 0);

    // Verify-BEFORE-decrypt: the anchor is computable without the key, and it
    // equals SHA-256 over the concatenated DATA ciphertext payloads.
    crypto_hash_sha256_state hst; crypto_hash_sha256_init(&hst);
    for (size_t i = 0; i < frames.size(); ++i) {
        FrameHeader h; CHECK_EQ(parse_header(&frames[i][0], h), OK);
        if (h.type != FT_DATA) continue;
        crypto_hash_sha256_update(&hst, &frames[i][HEADER_SIZE], h.payload_len);
    }
    uint8_t manual[CONTENT_HASH_LEN]; crypto_hash_sha256_final(&hst, manual);
    CHECK_EQ(std::memcmp(fp1, manual, CONTENT_HASH_LEN), 0);

    // A flipped ciphertext byte changes the anchor (tamper visible pre-decrypt).
    std::vector<std::vector<uint8_t> > tampered = frames;
    tampered[1][HEADER_SIZE] ^= 0x01;
    uint8_t fp4[CONTENT_HASH_LEN];
    CHECK_EQ(ciphertext_fingerprint(tampered, fp4), OK);
    CHECK(std::memcmp(fp1, fp4, CONTENT_HASH_LEN) != 0);
}

int main() {
    if (sodium_init() < 0) { std::printf("sodium_init failed\n"); return 2; }
    std::printf("ZDC1 codec unit tests\n");

    test_header_roundtrip();
    test_header_rejects();
    test_crc();
    test_aead_roundtrip();
    test_aead_tamper_and_aad();
    test_nonce_uniqueness();
    test_roundtrip_size_matrix();
    test_full_roundtrip_shuffled();
    test_empty_payload();
    test_seal_then_reveal();
    test_oob_key();
    test_wrong_key_fails_assemble();
    test_missing_and_reorder_detect();
    test_tamper_in_transit_detected();
    test_crc_corruption_rejected();
    test_truncation_rejected();
    test_non_zdc_memo_passthrough();
    test_foreign_transfer_id_rejected();
    test_size_caps();
    test_max_data_frame();
    test_frame_sizes();
    test_ciphertext_fingerprint();

    std::printf("\n%d checks, %d failures\n", g_checks, g_fails);
    if (g_fails) { std::printf("RESULT: FAIL\n"); return 1; }
    std::printf("RESULT: PASS\n");
    return 0;
}
