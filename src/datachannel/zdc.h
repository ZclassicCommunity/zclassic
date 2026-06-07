// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license.
//
// ZDC1 — ZClassic Shielded Data Channel, version 1.
//
// PURE LOGIC CODEC. No daemon, no chain, no Qt, no globals. Depends ONLY on
// libsodium and the C++11 standard library, so it builds BOTH standalone
// (host g++ -lsodium, for unit tests) AND inside the daemon (which already
// links -lsodium and compiles -std=c++11 -noext; see configure.ac:68,783).
//
// WHAT THIS IS
// ------------
// A transport for moving an arbitrary ENCRYPTED byte stream (a private message,
// a file, a private NFT's asset bytes) across many 512-byte Sapling memos. Each
// memo carries exactly one ZDC1 FRAME. The Sapling shielded pool is the privacy
// base layer (consensus-enforced zk-SNARKs hide sender/recipient/amount, and the
// memo is itself ChaCha20-Poly1305-encrypted to the recipient's incoming viewing
// key). ON TOP of that, this codec applies an INDEPENDENT application-layer AEAD
// (libsodium ChaCha20-Poly1305 IETF) under a per-transfer symmetric key, so that:
//   * content can be published now and the key revealed later ("seal then reveal"),
//   * a break in one layer does not cascade into the other,
//   * a single ciphertext can be opened by N recipients (one KEY frame each).
//
// THE LAYERS (full stack):
//   L0 Sapling shielded pool      consensus zk-SNARK privacy (NOT this code)
//   L1 Sapling per-output memo    512B, ChaCha20-Poly1305 to ivk (NOT this code)
//   L2 ZDC1 transport             framing + reassembly      (this code)
//   L3 ZDC1 application AEAD       per-transfer key, per-chunk Poly1305 (this code)
//
// HONEST LIMITS (the codec cannot fix these; callers must surface them):
//   * METADATA LEAKS: the NUMBER of outputs reveals approximate transfer size;
//     timing of the burst is observable; "a shielded tx occurred" is observable.
//     "Private" is NOT "undetectable". This is a CONFIDENTIALITY channel, not a
//     steganographic one.
//   * PERMANENCE: every memo is stored by every full node FOREVER. Encrypted-but-
//     undeletable. Size caps below are about responsibility, not just performance.
//   * NO CONSENSUS ENFORCES ANY OF THIS. It is wallet/application policy only.
//
// SECURITY MODEL (see ZdcAead):
//   * Key  = 32 random bytes from randombytes_buf() per transfer. Never reused,
//            never logged. The KEY frame carries it (or it travels out-of-band).
//   * Nonce= 12 bytes = transfer_id(8) || nonce_ctr(4), where nonce_ctr is a
//            per-frame COUNTER unique within the transfer (DATA[i]->i, START->
//            0xFFFFFFFF, END->0xFFFFFFFE), NOT the wire seq (START seq 0 and
//            DATA[0] seq 0 would otherwise collide). The key is fresh per transfer,
//            so every (key, nonce) pair is unique by construction. Nonce reuse is
//            catastrophic for ChaCha20-Poly1305; this is unit-tested.
//   * AAD  = the 32-byte frame header (version/type/transfer_id/seq/chunk_count/...)
//            so a reordered, retyped, or rewritten frame fails decryption.
//   * Tag  = per-chunk Poly1305 (16B) is the SECURITY integrity check.
//   * crc32= header field is TRANSPORT integrity only (corruption / foreign-data
//            detection). It is NOT security. Do not rely on it for tamper-evidence.
//   * Content hash = SHA-256 over the full PLAINTEXT, carried in the END frame and
//            verified after reassembly+decrypt. This binds the stream to the NFT
//            fingerprint (the ZSLP document_hash anchor; see doc/nft/CONTENT_MODEL.md).

#ifndef ZCLASSIC_DATACHANNEL_ZDC_H
#define ZCLASSIC_DATACHANNEL_ZDC_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace zdc {

// ---- wire constants (frozen; changing any of these is a NEW protocol version) ----
static const uint32_t ZDC_MAGIC        = 0x5A444331u; // "ZDC1"
static const uint8_t  ZDC_VERSION      = 0x01;

static const size_t   MEMO_SIZE        = 512;  // Sapling ZC_MEMO_SIZE
static const size_t   HEADER_SIZE      = 32;   // fixed header
static const size_t   FRAME_PAYLOAD    = MEMO_SIZE - HEADER_SIZE; // 480 bytes/frame

// AEAD (libsodium ChaCha20-Poly1305 IETF) sizes — asserted against sodium in .cpp.
static const size_t   AEAD_KEYBYTES    = 32;
static const size_t   AEAD_NPUBBYTES   = 12;   // = 8 (transfer_id) + 4 (nonce_ctr)
static const size_t   AEAD_ABYTES      = 16;   // Poly1305 tag
static const size_t   CONTENT_HASH_LEN = 32;   // SHA-256

// L3 AEAD expands each chunk by the 16-byte tag, so the usable PLAINTEXT per DATA
// frame is 480 - 16 = 464 bytes. START/END/KEY use the payload differently (below).
static const size_t   DATA_PLAINTEXT_PER_FRAME = FRAME_PAYLOAD - AEAD_ABYTES; // 464

// ---- responsibility caps (policy, not consensus). Reject oversize transfers. ----
// Max DATA chunks the codec will encode/reassemble. 65535 * 464B ~= 29 MB plaintext.
// Callers SHOULD impose far tighter limits (64 KB default per shielded-data-protocol.md);
// this is the codec's absolute structural ceiling so a hostile START can't allocate forever.
static const uint32_t MAX_CHUNK_COUNT  = 65535;
static const uint64_t MAX_TRANSFER_BYTES = (uint64_t)MAX_CHUNK_COUNT * DATA_PLAINTEXT_PER_FRAME;

// Frame types (header byte 5).
enum FrameType {
    FT_START = 0x01, // encrypted metadata blob; carries authoritative chunk_count
    FT_DATA  = 0x02, // one AEAD-encrypted plaintext chunk
    FT_END   = 0x03, // sha256(full plaintext); seq == chunk_count
    FT_KEY   = 0x04, // the 32B per-transfer key (reveal-later); processed last
};

// Header flag bits (header byte 6).
enum FrameFlags {
    FL_CIPHERTEXT = 0x01, // payload is L3-AEAD ciphertext (DATA/START/END always set)
};

// Cipher id (header byte 7).
enum CipherId {
    CIPHER_NONE              = 0x00,
    CIPHER_CHACHA20POLY1305  = 0x01, // the only one implemented
};

// Decode/codec status codes. 0 == OK; negatives are hard failures.
enum Status {
    OK                    = 0,
    ERR_TRUNCATED         = -1,  // buffer shorter than 512 bytes
    ERR_BAD_MAGIC         = -2,  // not a ZDC1 frame (e.g. an ordinary text memo)
    ERR_BAD_VERSION       = -3,
    ERR_BAD_TYPE          = -4,
    ERR_BAD_PAYLOAD_LEN   = -5,  // payload_len > 480
    ERR_BAD_CRC           = -6,  // transport corruption
    ERR_BAD_CIPHER        = -7,
    ERR_AEAD_FAIL         = -8,  // Poly1305 verification failed (tamper / wrong key)
    ERR_OVERSIZE          = -9,  // chunk_count or transfer exceeds caps
    ERR_INCOMPLETE        = -10, // reassembly asked but frames missing
    ERR_HASH_MISMATCH     = -11, // reassembled plaintext != END content hash
    ERR_NO_KEY            = -12, // content present but key not yet revealed
    ERR_BAD_STATE         = -13, // protocol misuse (e.g. START seq != 0)
    ERR_INTERNAL          = -14, // libsodium / invariant failure
};

// Parsed frame header (host-endian fields; wire is big-endian, handled in .cpp).
struct FrameHeader {
    uint32_t magic;
    uint8_t  version;
    uint8_t  type;
    uint8_t  flags;
    uint8_t  cipher_id;
    uint64_t transfer_id;
    uint32_t seq;
    uint32_t chunk_count;
    uint16_t payload_len;
    uint32_t crc32;       // over the 480-byte payload field (transport integrity)
    uint16_t reserved;    // must be 0
};

// Plaintext metadata that lives (encrypted) inside the START frame.
struct TransferMeta {
    std::string filename;          // may be empty (e.g. a raw message)
    std::string content_type;      // MIME-ish; may be empty
    uint64_t    total_plaintext_size; // exact byte count of the reassembled plaintext
    uint32_t    chunk_count;          // number of DATA frames
    // content_hash is carried in END, not here, so it cannot be forged independent of bytes.
};

// ============================================================================
// Low-level header (de)serialization + transport CRC. No crypto here.
// ============================================================================

// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) over [data, data+len).
// Transport integrity only; NOT a security primitive.
uint32_t crc32(const uint8_t* data, size_t len);

// Serialize header into out[0..31]. out must have >= HEADER_SIZE bytes.
void serialize_header(const FrameHeader& h, uint8_t* out);

// Parse header from in[0..31]. Returns OK or a hard error. Validates magic,
// version, type, payload_len bound, reserved==0. Does NOT verify crc (crc covers
// the payload, which the caller has; see verify_payload_crc / decode_frame).
Status parse_header(const uint8_t* in, FrameHeader& out);

// ============================================================================
// L3 application AEAD — ChaCha20-Poly1305 IETF, per-transfer key.
// ============================================================================
class ZdcAead {
public:
    // Fill key with 32 fresh CSPRNG bytes. One-time global sodium_init() is handled.
    // Returns OK or ERR_INTERNAL.
    static Status generate_key(std::vector<uint8_t>& key /*out, 32B*/);

    // Deterministic nonce = transfer_id(8, big-endian) || nonce_ctr(4, big-endian).
    // nonce_ctr is a per-frame COUNTER unique WITHIN the transfer (NOT the wire seq):
    //   DATA chunk i -> i ;  START -> 0xFFFFFFFF ;  END -> 0xFFFFFFFE.
    // Using the wire seq directly would be UNSAFE (START seq 0 collides with DATA[0]
    // seq 0 under the same key). The key is fresh per transfer, so a unique counter
    // makes every (key, nonce) pair unique. Exposed so tests can assert uniqueness.
    static void derive_nonce(uint64_t transfer_id, uint32_t nonce_ctr,
                             uint8_t out_nonce[AEAD_NPUBBYTES]);

    // Encrypt plaintext -> ciphertext (= plaintext_len + 16B tag). aad binds the frame
    // header. Returns OK or ERR_INTERNAL. key must be 32 bytes.
    static Status encrypt(const std::vector<uint8_t>& key,
                          uint64_t transfer_id, uint32_t seq,
                          const uint8_t* aad, size_t aad_len,
                          const std::vector<uint8_t>& plaintext,
                          std::vector<uint8_t>& ciphertext /*out*/);

    // Decrypt ciphertext (>= 16B) -> plaintext. Returns OK, ERR_AEAD_FAIL (tamper /
    // wrong key / wrong aad), or ERR_INTERNAL.
    static Status decrypt(const std::vector<uint8_t>& key,
                          uint64_t transfer_id, uint32_t seq,
                          const uint8_t* aad, size_t aad_len,
                          const std::vector<uint8_t>& ciphertext,
                          std::vector<uint8_t>& plaintext /*out*/);

    // SHA-256 over [data,data+len) -> out[0..31]. Used for the content-hash anchor.
    static Status sha256(const uint8_t* data, size_t len, uint8_t out[CONTENT_HASH_LEN]);
};

// ============================================================================
// Encoder — plaintext bytes + meta -> a vector of 512-byte memo frames.
// ============================================================================
class Encoder {
public:
    // Build the full frame list for a transfer:
    //   frames[0]            = START (encrypted meta)
    //   frames[1..N]         = DATA  (encrypted chunks, seq 0..N-1)
    //   frames[N+1]          = END   (encrypted content hash, seq == chunk_count)
    //   frames[N+2]          = KEY   (the 32B key) IFF include_key_frame == true
    // Each frame is exactly 512 bytes (zero-padded past payload_len).
    //
    // transfer_id: caller-chosen (random 64-bit, or a ZSLP token_id) so concurrent
    //   transfers don't collide.
    // key: 32 bytes (from ZdcAead::generate_key). Reused only within this one transfer.
    // include_key_frame: false = "seal then reveal" (deliver key later / out-of-band).
    //
    // Returns OK, ERR_OVERSIZE (plaintext too large), or ERR_INTERNAL.
    static Status encode(uint64_t transfer_id,
                         const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& plaintext,
                         const TransferMeta& meta_in,
                         bool include_key_frame,
                         std::vector<std::vector<uint8_t> >& frames_out);

    // Build ONLY the KEY frame (for reveal-later as a separate later tx).
    static Status encode_key_frame(uint64_t transfer_id,
                                   const std::vector<uint8_t>& key,
                                   uint32_t chunk_count,
                                   std::vector<uint8_t>& frame_out);
};

// ============================================================================
// Decoder — stateful reassembly across many memos (out-of-order, dup, partial).
//
// USAGE:
//   Decoder d;
//   for each decrypted memo m (512 bytes): d.add_frame(m);   // any order, dups ok
//   if (d.is_complete()) {
//     std::vector<uint8_t> out; TransferMeta meta;
//     Status s = d.assemble(out, meta);   // needs key (via add_frame KEY or set_key)
//   }
//
// One Decoder == one transfer_id. Caller routes frames by (zaddr, transfer_id);
// add_frame rejects frames whose transfer_id doesn't match the first one seen.
// ============================================================================
class Decoder {
public:
    Decoder();
    // Zeroizes the per-transfer key (sodium_memzero) so the secret never lingers
    // in freed heap memory. Ciphertext/aad buffers hold no secret and are not wiped.
    ~Decoder();

    // Feed one 512-byte memo. Non-ZDC1 / wrong-version / bad-crc memos are rejected
    // with the corresponding ERR_* (caller treats ERR_BAD_MAGIC as "ordinary memo,
    // not for me"). Duplicate seq is ignored (first wins) and returns OK. A KEY frame
    // populates the key. Mismatched transfer_id returns ERR_BAD_STATE.
    Status add_frame(const uint8_t* memo, size_t len);
    Status add_frame(const std::vector<uint8_t>& memo);

    // Supply the per-transfer key out-of-band (when no KEY frame is on chain).
    Status set_key(const std::vector<uint8_t>& key);

    bool     have_start()  const { return have_start_; }
    bool     have_end()    const { return have_end_; }
    bool     have_key()    const { return have_key_; }
    uint64_t transfer_id() const { return transfer_id_; }

    // chunk_count from START (authoritative) or 0 if START not yet seen.
    uint32_t chunk_count() const { return chunk_count_; }
    // how many distinct DATA seqs received so far.
    uint32_t received_chunks() const { return (uint32_t)data_.size(); }

    // Structurally complete: START + END + all DATA seqs in [0,chunk_count). Does
    // NOT require the key (you can be complete-but-sealed).
    bool is_complete() const;

    // List of missing DATA seqs in [0,chunk_count) (empty if complete or no START).
    std::vector<uint32_t> missing_chunks() const;

    // Reassemble + AEAD-decrypt + verify END content hash. Requires is_complete()
    // AND have_key(). On success out_plaintext holds the exact original bytes and
    // out_meta the START metadata.
    // Returns OK, ERR_INCOMPLETE, ERR_NO_KEY, ERR_AEAD_FAIL, ERR_HASH_MISMATCH.
    Status assemble(std::vector<uint8_t>& out_plaintext, TransferMeta& out_meta) const;

private:
    bool     seen_any_;
    uint64_t transfer_id_;
    bool     have_start_;
    bool     have_end_;
    bool     have_key_;
    uint32_t chunk_count_;
    std::vector<uint8_t> key_;                 // 32B once known
    std::vector<uint8_t> start_meta_ct_;       // START payload ciphertext
    std::vector<uint8_t> start_meta_aad_;      // START header bytes (for AEAD aad)
    std::vector<uint8_t> end_hash_ct_;         // END payload ciphertext
    std::vector<uint8_t> end_hash_aad_;        // END header bytes
    std::map<uint32_t, std::vector<uint8_t> > data_;     // seq -> ciphertext
    std::map<uint32_t, std::vector<uint8_t> > data_aad_; // seq -> header bytes

    Status ingest_parsed(const FrameHeader& h, const uint8_t* payload);
};

// ============================================================================
// NFT fingerprint binding (the on-chain anchor).
//
// The END frame carries SHA-256 over the PLAINTEXT (an integrity check used at
// reassembly). The on-chain NFT anchor, however, commits to the CIPHERTEXT (see
// doc/nft/CONTENT_MODEL.md §2.6 "the Merkle is over CIPHERTEXT", verify-before-
// decrypt). This helper computes that ciphertext fingerprint = SHA-256 over the
// concatenated DATA-frame ciphertext payloads (payload_len bytes each, in seq
// order), so:
//   * the MINT path can set ZSLP document_hash = ciphertext_fingerprint(frames),
//     making the public token cryptographically commit to the private bytes;
//   * a RECIPIENT (or any node) can verify the on-chain anchor matches the
//     received frames BEFORE possessing the key (verify-before-decrypt), proving
//     "these are the committed bytes" without revealing the plaintext.
//
// `frames` is the encoder output (START, DATA*, END[, KEY]); only DATA frames
// contribute. Returns ERR_BAD_STATE if a frame is malformed, else OK with the
// 32-byte fingerprint in `out`. Computing it over ciphertext means it is stable
// regardless of whether the key has been revealed.
// ============================================================================
Status ciphertext_fingerprint(const std::vector<std::vector<uint8_t> >& frames,
                              uint8_t out[CONTENT_HASH_LEN]);

// Human-readable status string (for logs / RPC errors). Never logs key material.
const char* status_str(Status s);

} // namespace zdc

#endif // ZCLASSIC_DATACHANNEL_ZDC_H
