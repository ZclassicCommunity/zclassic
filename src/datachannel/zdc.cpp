// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license.
//
// ZDC1 codec implementation. See zdc.h for the full security model. C++11 only.

#include "zdc.h"

#include <sodium.h>

#include <cstring>

namespace zdc {

// One-time libsodium init. Thread-safe per libsodium docs (sodium_init may be
// called multiple times / concurrently after the first success).
static bool ensure_sodium() {
    static int rc = sodium_init(); // 0 = ok, 1 = already initialized, -1 = fail
    return rc >= 0;
}

// Compile-time sanity: our constants must match libsodium's.
static_assert(AEAD_KEYBYTES  == crypto_aead_chacha20poly1305_ietf_KEYBYTES,  "key size");
static_assert(AEAD_NPUBBYTES == crypto_aead_chacha20poly1305_ietf_NPUBBYTES, "nonce size");
static_assert(AEAD_ABYTES    == crypto_aead_chacha20poly1305_ietf_ABYTES,    "tag size");
static_assert(AEAD_NPUBBYTES == 12, "nonce must be transfer_id(8)+counter(4)");

// ----------------------------------------------------------------------------
// NONCE COUNTER DOMAIN (the security-critical part).
//
// The 12-byte AEAD nonce = transfer_id(8 BE) || counter(4 BE). The key is fresh
// per transfer, so uniqueness reduces to: every L3-encrypted frame in ONE
// transfer must use a DISTINCT 32-bit counter. The wire `seq` field alone is
// UNSAFE as that counter, because START (seq 0) and DATA chunk 0 (seq 0) would
// collide, and END (seq == chunk_count) could collide with a future use of the
// seq space. We therefore map each frame ROLE to a globally-unique counter,
// reserving the top of the 32-bit range for the singleton control frames. This
// is collision-free by construction because DATA counters are exactly the chunk
// index in [0, chunk_count) and chunk_count <= MAX_CHUNK_COUNT (65535), far
// below the reserved band. (Proven in test/zdc_test.cpp.)
//
//   DATA chunk i  -> counter = i               (0 .. chunk_count-1, <= 65534)
//   START         -> counter = 0xFFFFFFFF      NONCE_CTR_START
//   END           -> counter = 0xFFFFFFFE      NONCE_CTR_END
//   (KEY frame is NOT L3-encrypted, so it consumes no counter.)
// ----------------------------------------------------------------------------
static const uint32_t NONCE_CTR_START = 0xFFFFFFFFu;
static const uint32_t NONCE_CTR_END   = 0xFFFFFFFEu;

// ============================================================================
// big-endian helpers
// ============================================================================
static void put_be16(uint8_t* p, uint16_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static void put_be32(uint8_t* p, uint32_t v) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}
static void put_be64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (56 - 8*i));
}
static uint16_t get_be16(const uint8_t* p) { return (uint16_t)((p[0]<<8) | p[1]); }
static uint32_t get_be32(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|((uint32_t)p[3]);
}
static uint64_t get_be64(const uint8_t* p) {
    uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v<<8) | p[i]; return v;
}

// ============================================================================
// CRC-32 (IEEE 802.3, reflected). Transport integrity only — NOT security.
// ============================================================================
uint32_t crc32(const uint8_t* data, size_t len) {
    static uint32_t table[256];
    static bool built = false;
    if (!built) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        built = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
        c = table[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ============================================================================
// header (de)serialization
// ============================================================================
// Layout (32 bytes, all multi-byte big-endian):
//   0  4 magic        4 1 version  5 1 type      6 1 flags    7 1 cipher_id
//   8  8 transfer_id  16 4 seq     20 4 chunk_count
//   24 2 payload_len  26 4 crc32   30 2 reserved
void serialize_header(const FrameHeader& h, uint8_t* out) {
    put_be32(out + 0,  h.magic);
    out[4] = h.version;
    out[5] = h.type;
    out[6] = h.flags;
    out[7] = h.cipher_id;
    put_be64(out + 8,  h.transfer_id);
    put_be32(out + 16, h.seq);
    put_be32(out + 20, h.chunk_count);
    put_be16(out + 24, h.payload_len);
    put_be32(out + 26, h.crc32);
    put_be16(out + 30, h.reserved);
}

Status parse_header(const uint8_t* in, FrameHeader& h) {
    h.magic       = get_be32(in + 0);
    h.version     = in[4];
    h.type        = in[5];
    h.flags       = in[6];
    h.cipher_id   = in[7];
    h.transfer_id = get_be64(in + 8);
    h.seq         = get_be32(in + 16);
    h.chunk_count = get_be32(in + 20);
    h.payload_len = get_be16(in + 24);
    h.crc32       = get_be32(in + 26);
    h.reserved    = get_be16(in + 30);

    if (h.magic != ZDC_MAGIC)       return ERR_BAD_MAGIC;
    if (h.version != ZDC_VERSION)   return ERR_BAD_VERSION;
    if (h.type != FT_START && h.type != FT_DATA &&
        h.type != FT_END   && h.type != FT_KEY) return ERR_BAD_TYPE;
    if (h.payload_len > FRAME_PAYLOAD) return ERR_BAD_PAYLOAD_LEN;
    if (h.reserved != 0)            return ERR_BAD_STATE;
    if (h.chunk_count > MAX_CHUNK_COUNT) return ERR_OVERSIZE;
    return OK;
}

// Build a full 512-byte frame from header + (already-final) payload bytes.
// Sets payload_len and crc32 over the zero-padded 480-byte payload field.
static void pack_frame(FrameHeader& h, const uint8_t* payload, size_t payload_len,
                       std::vector<uint8_t>& out) {
    out.assign(MEMO_SIZE, 0);
    h.payload_len = (uint16_t)payload_len;
    if (payload_len > 0)
        std::memcpy(&out[HEADER_SIZE], payload, payload_len);
    // crc covers the full 480-byte payload field (including zero padding) so it is
    // deterministic regardless of payload_len.
    h.crc32 = crc32(&out[HEADER_SIZE], FRAME_PAYLOAD);
    serialize_header(h, &out[0]);
}

// ============================================================================
// L3 AEAD
// ============================================================================
Status ZdcAead::generate_key(std::vector<uint8_t>& key) {
    if (!ensure_sodium()) return ERR_INTERNAL;
    key.assign(AEAD_KEYBYTES, 0);
    randombytes_buf(&key[0], AEAD_KEYBYTES);
    return OK;
}

void ZdcAead::derive_nonce(uint64_t transfer_id, uint32_t nonce_ctr,
                           uint8_t out_nonce[AEAD_NPUBBYTES]) {
    // nonce = transfer_id(8 BE) || nonce_ctr(4 BE). The caller passes a counter
    // that is unique per frame WITHIN the transfer (DATA->chunk index, START/END
    // -> reserved high values). It is NOT the wire `seq`; see the NONCE COUNTER
    // DOMAIN note above. Combined with a per-transfer-unique key this guarantees
    // every (key, nonce) pair is used at most once.
    put_be64(out_nonce + 0, transfer_id);
    put_be32(out_nonce + 8, nonce_ctr);
}

Status ZdcAead::encrypt(const std::vector<uint8_t>& key,
                        uint64_t transfer_id, uint32_t seq,
                        const uint8_t* aad, size_t aad_len,
                        const std::vector<uint8_t>& plaintext,
                        std::vector<uint8_t>& ciphertext) {
    if (!ensure_sodium()) return ERR_INTERNAL;
    if (key.size() != AEAD_KEYBYTES) return ERR_INTERNAL;
    uint8_t nonce[AEAD_NPUBBYTES];
    derive_nonce(transfer_id, seq, nonce);
    ciphertext.assign(plaintext.size() + AEAD_ABYTES, 0);
    unsigned long long clen = 0;
    const unsigned char* m = plaintext.empty() ? (const unsigned char*)"" : &plaintext[0];
    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
        &ciphertext[0], &clen,
        m, plaintext.size(),
        aad, aad_len,
        NULL, nonce, &key[0]);
    if (rc != 0) return ERR_INTERNAL;
    ciphertext.resize((size_t)clen);
    return OK;
}

Status ZdcAead::decrypt(const std::vector<uint8_t>& key,
                        uint64_t transfer_id, uint32_t seq,
                        const uint8_t* aad, size_t aad_len,
                        const std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& plaintext) {
    if (!ensure_sodium()) return ERR_INTERNAL;
    if (key.size() != AEAD_KEYBYTES) return ERR_NO_KEY;
    if (ciphertext.size() < AEAD_ABYTES) return ERR_AEAD_FAIL;
    uint8_t nonce[AEAD_NPUBBYTES];
    derive_nonce(transfer_id, seq, nonce);
    plaintext.assign(ciphertext.size() - AEAD_ABYTES, 0);
    unsigned long long mlen = 0;
    unsigned char* m = plaintext.empty() ? NULL : &plaintext[0];
    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
        m, &mlen, NULL,
        &ciphertext[0], ciphertext.size(),
        aad, aad_len,
        nonce, &key[0]);
    if (rc != 0) return ERR_AEAD_FAIL;
    plaintext.resize((size_t)mlen);
    return OK;
}

Status ZdcAead::sha256(const uint8_t* data, size_t len, uint8_t out[CONTENT_HASH_LEN]) {
    if (!ensure_sodium()) return ERR_INTERNAL;
    static_assert(CONTENT_HASH_LEN == crypto_hash_sha256_BYTES, "sha256 len");
    const unsigned char* d = (len == 0) ? (const unsigned char*)"" : data;
    if (crypto_hash_sha256(out, d, len) != 0) return ERR_INTERNAL;
    return OK;
}

// ============================================================================
// START metadata (de)serialization — the PLAINTEXT that gets AEAD-encrypted into
// the START frame payload. Compact, self-describing, fits in 464 plaintext bytes.
//   u64 total_plaintext_size | u32 chunk_count
//   u16 filename_len | filename | u16 content_type_len | content_type
// ============================================================================
static void serialize_meta(const TransferMeta& m, std::vector<uint8_t>& out) {
    out.clear();
    uint8_t tmp[8];
    put_be64(tmp, m.total_plaintext_size); out.insert(out.end(), tmp, tmp+8);
    put_be32(tmp, m.chunk_count);          out.insert(out.end(), tmp, tmp+4);
    uint16_t fl = (uint16_t)m.filename.size();
    put_be16(tmp, fl); out.insert(out.end(), tmp, tmp+2);
    out.insert(out.end(), m.filename.begin(), m.filename.end());
    uint16_t cl = (uint16_t)m.content_type.size();
    put_be16(tmp, cl); out.insert(out.end(), tmp, tmp+2);
    out.insert(out.end(), m.content_type.begin(), m.content_type.end());
}

static Status deserialize_meta(const std::vector<uint8_t>& in, TransferMeta& m) {
    size_t p = 0;
    if (in.size() < 14) return ERR_BAD_STATE;
    m.total_plaintext_size = get_be64(&in[p]); p += 8;
    m.chunk_count          = get_be32(&in[p]); p += 4;
    uint16_t fl = get_be16(&in[p]); p += 2;
    if (p + fl > in.size()) return ERR_BAD_STATE;
    m.filename.assign(in.begin()+p, in.begin()+p+fl); p += fl;
    if (p + 2 > in.size()) return ERR_BAD_STATE;
    uint16_t cl = get_be16(&in[p]); p += 2;
    if (p + cl > in.size()) return ERR_BAD_STATE;
    m.content_type.assign(in.begin()+p, in.begin()+p+cl); p += cl;
    return OK;
}

// ============================================================================
// Encoder
// ============================================================================
static void base_header(FrameHeader& h, uint64_t transfer_id, uint8_t type,
                        uint32_t seq, uint32_t chunk_count, bool ciphertext) {
    h.magic = ZDC_MAGIC; h.version = ZDC_VERSION; h.type = type;
    h.flags = ciphertext ? FL_CIPHERTEXT : 0;
    h.cipher_id = ciphertext ? CIPHER_CHACHA20POLY1305 : CIPHER_NONE;
    h.transfer_id = transfer_id; h.seq = seq; h.chunk_count = chunk_count;
    h.payload_len = 0; h.crc32 = 0; h.reserved = 0;
}

// Build the 32-byte AAD = the header WITH crc32 and payload_len zeroed, so that
// AAD is computable identically by encoder (before crc/len known) and decoder
// (which strips them). AAD binds version/type/transfer_id/seq/chunk_count/flags/
// cipher — everything that defines the frame's ROLE — but not the transport-only
// crc or the length (the AEAD tag already protects the ciphertext length).
static void aad_from_header(const FrameHeader& h, uint8_t out_aad[HEADER_SIZE]) {
    FrameHeader a = h;
    a.crc32 = 0; a.payload_len = 0;
    serialize_header(a, out_aad);
}

Status Encoder::encode(uint64_t transfer_id,
                       const std::vector<uint8_t>& key,
                       const std::vector<uint8_t>& plaintext,
                       const TransferMeta& meta_in,
                       bool include_key_frame,
                       std::vector<std::vector<uint8_t> >& frames_out) {
    if (!ensure_sodium()) return ERR_INTERNAL;
    if (key.size() != AEAD_KEYBYTES) return ERR_INTERNAL;
    if (plaintext.size() > MAX_TRANSFER_BYTES) return ERR_OVERSIZE;

    // chunk_count = ceil(len / 464); a zero-length payload still has 0 DATA frames.
    uint64_t cc64 = (plaintext.size() + DATA_PLAINTEXT_PER_FRAME - 1) / DATA_PLAINTEXT_PER_FRAME;
    if (cc64 > MAX_CHUNK_COUNT) return ERR_OVERSIZE;
    uint32_t chunk_count = (uint32_t)cc64;

    frames_out.clear();
    frames_out.reserve(chunk_count + 3);

    // ---- START ----
    {
        TransferMeta meta = meta_in;
        meta.total_plaintext_size = plaintext.size();
        meta.chunk_count = chunk_count;
        std::vector<uint8_t> meta_pt; serialize_meta(meta, meta_pt);
        if (meta_pt.size() > DATA_PLAINTEXT_PER_FRAME) {
            // filename/content_type too long to fit one START frame.
            return ERR_OVERSIZE;
        }
        FrameHeader h; base_header(h, transfer_id, FT_START, 0, chunk_count, true);
        uint8_t aad[HEADER_SIZE]; aad_from_header(h, aad);
        std::vector<uint8_t> ct;
        // START uses the reserved START nonce counter (NOT seq 0) so it can never
        // collide with DATA chunk 0's nonce under the same key.
        Status s = ZdcAead::encrypt(key, transfer_id, NONCE_CTR_START, aad, HEADER_SIZE, meta_pt, ct);
        if (s != OK) return s;
        std::vector<uint8_t> frame; pack_frame(h, ct.empty()?NULL:&ct[0], ct.size(), frame);
        frames_out.push_back(frame);
    }

    // ---- DATA ----
    for (uint32_t i = 0; i < chunk_count; ++i) {
        size_t off = (size_t)i * DATA_PLAINTEXT_PER_FRAME;
        size_t n = plaintext.size() - off;
        if (n > DATA_PLAINTEXT_PER_FRAME) n = DATA_PLAINTEXT_PER_FRAME;
        std::vector<uint8_t> chunk(plaintext.begin()+off, plaintext.begin()+off+n);
        FrameHeader h; base_header(h, transfer_id, FT_DATA, i, chunk_count, true);
        uint8_t aad[HEADER_SIZE]; aad_from_header(h, aad);
        std::vector<uint8_t> ct;
        Status s = ZdcAead::encrypt(key, transfer_id, i, aad, HEADER_SIZE, chunk, ct);
        if (s != OK) return s;
        std::vector<uint8_t> frame; pack_frame(h, &ct[0], ct.size(), frame);
        frames_out.push_back(frame);
    }

    // ---- END (content hash over full plaintext) ----
    {
        uint8_t hash[CONTENT_HASH_LEN];
        Status s = ZdcAead::sha256(plaintext.empty()?NULL:&plaintext[0], plaintext.size(), hash);
        if (s != OK) return s;
        std::vector<uint8_t> hpt(hash, hash + CONTENT_HASH_LEN);
        // END wire seq == chunk_count (distinct from any DATA seq for routing), but
        // its AEAD nonce uses the reserved END counter so it never collides even when
        // chunk_count==0 (END counter == 0xFFFFFFFE, START == 0xFFFFFFFF, DATA < count).
        FrameHeader h; base_header(h, transfer_id, FT_END, chunk_count, chunk_count, true);
        uint8_t aad[HEADER_SIZE]; aad_from_header(h, aad);
        std::vector<uint8_t> ct;
        s = ZdcAead::encrypt(key, transfer_id, NONCE_CTR_END, aad, HEADER_SIZE, hpt, ct);
        if (s != OK) return s;
        std::vector<uint8_t> frame; pack_frame(h, &ct[0], ct.size(), frame);
        frames_out.push_back(frame);
    }

    // ---- KEY (optional; plaintext key — its confidentiality is L0/L1 Sapling) ----
    if (include_key_frame) {
        std::vector<uint8_t> frame;
        Status s = encode_key_frame(transfer_id, key, chunk_count, frame);
        if (s != OK) return s;
        frames_out.push_back(frame);
    }
    return OK;
}

Status Encoder::encode_key_frame(uint64_t transfer_id,
                                 const std::vector<uint8_t>& key,
                                 uint32_t chunk_count,
                                 std::vector<uint8_t>& frame_out) {
    if (key.size() != AEAD_KEYBYTES) return ERR_INTERNAL;
    // The KEY payload is the raw 32-byte key. It is NOT L3-AEAD-encrypted (it IS the
    // L3 secret); its on-chain confidentiality is the Sapling memo encryption to the
    // recipient's ivk (L1). cipher_id=NONE, flags=0 so it is self-describing.
    FrameHeader h; base_header(h, transfer_id, FT_KEY, 0, chunk_count, false);
    pack_frame(h, &key[0], key.size(), frame_out);
    return OK;
}

// ============================================================================
// Decoder
// ============================================================================
Decoder::Decoder()
    : seen_any_(false), transfer_id_(0), have_start_(false), have_end_(false),
      have_key_(false), chunk_count_(0) {}

// Wipe the 32-byte key from memory on destruction. sodium_memzero is not optimized
// away by the compiler (unlike memset), so the secret cannot survive in freed heap.
Decoder::~Decoder() {
    if (!key_.empty())
        sodium_memzero(&key_[0], key_.size());
}

Status Decoder::add_frame(const std::vector<uint8_t>& memo) {
    return add_frame(memo.empty()?NULL:&memo[0], memo.size());
}

Status Decoder::add_frame(const uint8_t* memo, size_t len) {
    if (memo == NULL || len < MEMO_SIZE) return ERR_TRUNCATED;
    FrameHeader h;
    Status s = parse_header(memo, h);
    if (s != OK) return s; // BAD_MAGIC => "ordinary memo, ignore"

    // verify transport crc over the 480-byte payload field
    uint32_t got = crc32(memo + HEADER_SIZE, FRAME_PAYLOAD);
    if (got != h.crc32) return ERR_BAD_CRC;

    if (h.payload_len > FRAME_PAYLOAD) return ERR_BAD_PAYLOAD_LEN;
    return ingest_parsed(h, memo + HEADER_SIZE);
}

Status Decoder::ingest_parsed(const FrameHeader& h, const uint8_t* payload) {
    if (!seen_any_) { seen_any_ = true; transfer_id_ = h.transfer_id; }
    else if (h.transfer_id != transfer_id_) return ERR_BAD_STATE;

    uint8_t aad[HEADER_SIZE]; aad_from_header(h, aad);
    std::vector<uint8_t> body(payload, payload + h.payload_len);

    switch (h.type) {
    case FT_START:
        if (h.seq != 0) return ERR_BAD_STATE;
        if (!have_start_) {
            have_start_ = true;
            chunk_count_ = h.chunk_count;
            start_meta_ct_ = body;
            start_meta_aad_.assign(aad, aad + HEADER_SIZE);
        }
        return OK;
    case FT_DATA:
        if (h.seq >= h.chunk_count) return ERR_BAD_STATE;
        if (data_.find(h.seq) == data_.end()) { // first wins; dup ignored
            data_[h.seq] = body;
            data_aad_[h.seq].assign(aad, aad + HEADER_SIZE);
        }
        return OK;
    case FT_END:
        if (!have_end_) {
            have_end_ = true;
            end_hash_ct_ = body;
            end_hash_aad_.assign(aad, aad + HEADER_SIZE);
        }
        return OK;
    case FT_KEY:
        if (!have_key_) {
            if (h.payload_len != AEAD_KEYBYTES) return ERR_BAD_STATE;
            key_.assign(body.begin(), body.end());
            have_key_ = true;
        }
        return OK;
    default:
        return ERR_BAD_TYPE;
    }
}

Status Decoder::set_key(const std::vector<uint8_t>& key) {
    if (key.size() != AEAD_KEYBYTES) return ERR_BAD_STATE;
    // Wipe any prior key bytes before the assignment can reallocate the buffer,
    // so a replaced secret is not left behind in freed memory.
    if (!key_.empty())
        sodium_memzero(&key_[0], key_.size());
    key_ = key;
    have_key_ = true;
    return OK;
}

bool Decoder::is_complete() const {
    if (!have_start_ || !have_end_) return false;
    if (data_.size() != chunk_count_) return false;
    if (chunk_count_ == 0) return true;            // empty transfer: no DATA frames
    // data_ is a sorted map of UNIQUE seqs. Given size == chunk_count_, the keys are
    // exactly {0..chunk_count_-1} iff the largest key is < chunk_count_ (pigeonhole:
    // chunk_count_ distinct non-negative ints all below chunk_count_ must be that set).
    // O(1) via rbegin() — was O(N) per call (O(N^2) over the documented add-then-check loop).
    return data_.rbegin()->first < chunk_count_;
}

std::vector<uint32_t> Decoder::missing_chunks() const {
    std::vector<uint32_t> miss;
    if (!have_start_) return miss;
    for (uint32_t i = 0; i < chunk_count_; ++i)
        if (data_.find(i) == data_.end()) miss.push_back(i);
    return miss;
}

Status Decoder::assemble(std::vector<uint8_t>& out_plaintext, TransferMeta& out_meta) const {
    if (!is_complete()) return ERR_INCOMPLETE;
    if (!have_key_)     return ERR_NO_KEY;

    // START meta (decrypts with the reserved START nonce counter)
    std::vector<uint8_t> meta_pt;
    Status s = ZdcAead::decrypt(key_, transfer_id_, NONCE_CTR_START,
                                &start_meta_aad_[0], HEADER_SIZE,
                                start_meta_ct_, meta_pt);
    if (s != OK) return s;
    s = deserialize_meta(meta_pt, out_meta);
    if (s != OK) return s;
    if (out_meta.chunk_count != chunk_count_) return ERR_HASH_MISMATCH;

    // DATA chunks, in seq order
    out_plaintext.clear();
    out_plaintext.reserve((size_t)out_meta.total_plaintext_size);
    for (uint32_t i = 0; i < chunk_count_; ++i) {
        std::map<uint32_t, std::vector<uint8_t> >::const_iterator it = data_.find(i);
        std::map<uint32_t, std::vector<uint8_t> >::const_iterator ai = data_aad_.find(i);
        std::vector<uint8_t> pt;
        s = ZdcAead::decrypt(key_, transfer_id_, i,
                             &ai->second[0], HEADER_SIZE, it->second, pt);
        if (s != OK) return s;
        out_plaintext.insert(out_plaintext.end(), pt.begin(), pt.end());
    }
    if (out_plaintext.size() != out_meta.total_plaintext_size) return ERR_HASH_MISMATCH;

    // END content hash (decrypts with the reserved END nonce counter)
    std::vector<uint8_t> end_pt;
    s = ZdcAead::decrypt(key_, transfer_id_, NONCE_CTR_END,
                         &end_hash_aad_[0], HEADER_SIZE, end_hash_ct_, end_pt);
    if (s != OK) return s;
    if (end_pt.size() != CONTENT_HASH_LEN) return ERR_HASH_MISMATCH;
    uint8_t calc[CONTENT_HASH_LEN];
    s = ZdcAead::sha256(out_plaintext.empty()?NULL:&out_plaintext[0],
                        out_plaintext.size(), calc);
    if (s != OK) return s;
    if (sodium_memcmp(calc, &end_pt[0], CONTENT_HASH_LEN) != 0) return ERR_HASH_MISMATCH;

    return OK;
}

// ============================================================================
// NFT fingerprint over ciphertext (the on-chain anchor). DATA frames only.
// ============================================================================
Status ciphertext_fingerprint(const std::vector<std::vector<uint8_t> >& frames,
                              uint8_t out[CONTENT_HASH_LEN]) {
    if (!ensure_sodium()) return ERR_INTERNAL;
    crypto_hash_sha256_state hst;
    crypto_hash_sha256_init(&hst);
    // Hash DATA-frame ciphertext payloads IN ASCENDING seq order so the anchor is
    // deterministic regardless of the order frames appear in the vector.
    // Gather (seq -> ciphertext pointer/len) first, then fold in order.
    std::map<uint32_t, std::pair<const uint8_t*, size_t> > by_seq;
    for (size_t i = 0; i < frames.size(); ++i) {
        const std::vector<uint8_t>& f = frames[i];
        if (f.size() < MEMO_SIZE) return ERR_BAD_STATE;
        FrameHeader h;
        Status s = parse_header(&f[0], h);
        if (s != OK) return s;
        if (h.type != FT_DATA) continue;
        if (h.payload_len > FRAME_PAYLOAD) return ERR_BAD_PAYLOAD_LEN;
        by_seq[h.seq] = std::make_pair(&f[HEADER_SIZE], (size_t)h.payload_len);
    }
    for (std::map<uint32_t, std::pair<const uint8_t*, size_t> >::const_iterator
             it = by_seq.begin(); it != by_seq.end(); ++it) {
        const uint8_t* p = it->second.first;
        size_t n = it->second.second;
        crypto_hash_sha256_update(&hst, n ? p : (const unsigned char*)"", n);
    }
    crypto_hash_sha256_final(&hst, out);
    return OK;
}

// ============================================================================
const char* status_str(Status s) {
    switch (s) {
    case OK:                  return "OK";
    case ERR_TRUNCATED:       return "frame shorter than 512 bytes";
    case ERR_BAD_MAGIC:       return "not a ZDC1 frame";
    case ERR_BAD_VERSION:     return "unsupported ZDC1 version";
    case ERR_BAD_TYPE:        return "unknown frame type";
    case ERR_BAD_PAYLOAD_LEN: return "payload length out of range";
    case ERR_BAD_CRC:         return "transport CRC mismatch (corruption)";
    case ERR_BAD_CIPHER:      return "unsupported cipher";
    case ERR_AEAD_FAIL:       return "AEAD verification failed (tamper or wrong key)";
    case ERR_OVERSIZE:        return "transfer exceeds size cap";
    case ERR_INCOMPLETE:      return "transfer incomplete (missing frames)";
    case ERR_HASH_MISMATCH:   return "content hash mismatch after reassembly";
    case ERR_NO_KEY:          return "key not yet available (sealed)";
    case ERR_BAD_STATE:       return "protocol state error";
    case ERR_INTERNAL:        return "internal/libsodium error";
    }
    return "unknown status";
}

} // namespace zdc
