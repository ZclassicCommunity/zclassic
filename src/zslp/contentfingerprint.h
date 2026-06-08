// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP content fingerprint — the daemon-side, byte-for-byte reimplementation of
// the Qt wallet's ContentEngine anchor algorithm. A CLI mint MUST produce the
// IDENTICAL document_hash the GUI does for the same bytes, or a token minted on
// one path would fail the other's verify badge.
//
// Algorithm (pinned against zcl-qt-wallet/src/contentengine.cpp):
//   chunkSize  = 1 MiB (parametric so tests can use tiny sizes).
//   leaf_i     = SHA256( 0x00 || raw_chunk_i )          (domain-separated)
//   node       = SHA256( 0x01 || left32 || right32 )    (over RAW 32B digests)
//   a lone trailing node is PROMOTED UNCHANGED (NOT Bitcoin-duplicated).
//   merkleRoot = the single remaining node (== leaf_0 for one leaf; "" empty).
//   sha256Whole= SHA256(all bytes), no prefix.
//   anchor     = (chunkCount > 1 && merkleRoot non-empty) ? merkleRoot
//                                                         : sha256Whole.
//   chunkCount = number of leaves (ceil(size/chunkSize); 0 for empty input).
// All hex outputs are lowercase (HexStr already lowercases).

#ifndef BITCOIN_ZSLP_CONTENTFINGERPRINT_H
#define BITCOIN_ZSLP_CONTENTFINGERPRINT_H

#include <stddef.h>
#include <stdint.h>
#include <string>

/** The default 1 MiB leaf size (matches ContentEngine::kChunkBytes). */
static const uint32_t ZSLP_CONTENT_CHUNK_BYTES = 1048576u; // 1 << 20

/** Describes a piece of content: its anchor (the document_hash) plus the
 *  cross-check fields. anchorHex/sha256WholeHex are always 64 lowercase hex;
 *  merkleRootHex is 64 hex for a non-empty input, or "" for empty input. */
struct ZSLPContentDescriptor {
    std::string anchorHex;       // the document_hash to put on-chain
    std::string sha256WholeHex;  // whole-input SHA-256 (small/single-chunk mode)
    std::string merkleRootHex;   // chunk-tree root, or "" if empty input
    uint64_t fileSize;
    uint32_t chunkSize;
    uint64_t chunkCount;

    ZSLPContentDescriptor()
        : fileSize(0), chunkSize(ZSLP_CONTENT_CHUNK_BYTES), chunkCount(0) {}
};

/** Fingerprint an in-memory buffer. Always succeeds (returns true). */
bool ZSLPHashBytes(const unsigned char* data, size_t len,
                   ZSLPContentDescriptor& out,
                   uint32_t chunkSize = ZSLP_CONTENT_CHUNK_BYTES);

/** Fingerprint a file by STREAMING it through a bounded buffer (never readAll),
 *  computing the whole-SHA and the per-chunk leaves in one pass. Returns false
 *  if the path does not exist / cannot be opened / a read fails. */
bool ZSLPHashFile(const std::string& path, ZSLPContentDescriptor& out,
                  uint32_t chunkSize = ZSLP_CONTENT_CHUNK_BYTES);

#endif // BITCOIN_ZSLP_CONTENTFINGERPRINT_H
