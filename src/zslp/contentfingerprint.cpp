// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP content fingerprint implementation. See contentfingerprint.h for the
// contract and the pinned algorithm (mirrors zcl-qt-wallet ContentEngine).

#include "zslp/contentfingerprint.h"

#include "crypto/sha256.h"
#include "utilstrencodings.h"

#include <cstdio>
#include <vector>

namespace {

// One reusable streaming read buffer (matches the GUI's kHashBufBytes = 1 MiB).
// Independent of chunkSize so an arbitrary (tiny, test) chunkSize still tiles.
const size_t ZSLP_HASH_BUF_BYTES = 1u << 20; // 1 MiB

typedef std::vector<unsigned char> Bytes; // a raw 32-byte digest

// leaf_i = SHA256(0x00 || chunkBytes)
Bytes MerkleLeaf(const unsigned char* chunk, size_t len)
{
    CSHA256 h;
    const unsigned char zero = 0x00;
    h.Write(&zero, 1);
    h.Write(chunk, len);
    Bytes out(CSHA256::OUTPUT_SIZE);
    h.Finalize(out.data());
    return out;
}

// node = SHA256(0x01 || left32 || right32) over the RAW 32-byte digests.
Bytes MerkleNode(const Bytes& left, const Bytes& right)
{
    CSHA256 h;
    const unsigned char one = 0x01;
    h.Write(&one, 1);
    h.Write(left.data(), left.size());
    h.Write(right.data(), right.size());
    Bytes out(CSHA256::OUTPUT_SIZE);
    h.Finalize(out.data());
    return out;
}

// Build the Merkle root from leaves. Empty -> empty; 1 leaf -> leaf_0; else
// pair up (0x01||L||R), promoting a lone trailing node UNCHANGED.
Bytes MerkleRootFromLeaves(const std::vector<Bytes>& leaves)
{
    if (leaves.empty())
        return Bytes();           // empty content => no leaves => empty root
    if (leaves.size() == 1)
        return leaves.front();    // 1-leaf degenerate: root == leaf_0

    std::vector<Bytes> level = leaves;
    while (level.size() > 1) {
        std::vector<Bytes> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            if (i + 1 < level.size())
                next.push_back(MerkleNode(level[i], level[i + 1]));
            else
                next.push_back(level[i]); // ODD NODE: promote unchanged
        }
        level.swap(next);
    }
    return level.front();
}

// Finish: assemble the descriptor from the streamed whole-SHA + leaves.
void Finish(CSHA256& whole, const std::vector<Bytes>& leaves,
            uint64_t total, uint32_t chunkSize, ZSLPContentDescriptor& out)
{
    Bytes wholeDigest(CSHA256::OUTPUT_SIZE);
    whole.Finalize(wholeDigest.data());

    Bytes root = MerkleRootFromLeaves(leaves);

    out.sha256WholeHex = HexStr(wholeDigest);
    out.merkleRootHex  = root.empty() ? std::string() : HexStr(root);
    out.fileSize       = total;
    out.chunkSize      = chunkSize;
    out.chunkCount     = (uint64_t)leaves.size();

    // anchor = merkleRoot for multi-chunk content (chunkCount>1 && root present),
    // else the whole-input SHA-256.
    out.anchorHex = (out.chunkCount > 1 && !out.merkleRootHex.empty())
                        ? out.merkleRootHex
                        : out.sha256WholeHex;
}

} // namespace

bool ZSLPHashBytes(const unsigned char* data, size_t len,
                   ZSLPContentDescriptor& out, uint32_t chunkSize)
{
    if (chunkSize == 0)
        chunkSize = ZSLP_CONTENT_CHUNK_BYTES;

    CSHA256 whole;
    if (len > 0)
        whole.Write(data, len);

    // Tile the buffer into chunkSize-byte leaves; final leaf is the remainder.
    std::vector<Bytes> leaves;
    for (size_t off = 0; off < len; off += chunkSize) {
        size_t take = (len - off < chunkSize) ? (len - off) : (size_t)chunkSize;
        leaves.push_back(MerkleLeaf(data + off, take));
    }

    Finish(whole, leaves, (uint64_t)len, chunkSize, out);
    return true;
}

bool ZSLPHashFile(const std::string& path, ZSLPContentDescriptor& out,
                  uint32_t chunkSize)
{
    if (chunkSize == 0)
        chunkSize = ZSLP_CONTENT_CHUNK_BYTES;

    FILE* f = fopen(path.c_str(), "rb");
    if (f == NULL)
        return false; // does not exist / cannot open

    CSHA256 whole;       // streaming whole-input SHA-256
    CSHA256 leaf;        // current-chunk leaf hasher (domain-separated below)
    std::vector<Bytes> leaves;

    const unsigned char zero = 0x00;
    bool leafPrimed = false;
    // (re)prime the current leaf hasher with the 0x00 domain-separation byte.
    // CSHA256 has no copy/clone, so we hash incrementally then Finalize.
    // Prime lazily so an empty file produces ZERO leaves (root = empty).

    std::vector<unsigned char> buf(ZSLP_HASH_BUF_BYTES);
    uint64_t total = 0;
    uint32_t chunkFilled = 0; // bytes accumulated into the current leaf

    for (;;) {
        size_t n = fread(buf.data(), 1, buf.size(), f);
        if (n == 0) {
            if (ferror(f)) { fclose(f); return false; } // read error
            break;                                        // EOF
        }
        whole.Write(buf.data(), n);
        total += (uint64_t)n;

        // Feed bytes into chunkSize-boundaried leaves. A single buffer fill can
        // span a chunk boundary (if chunkSize < buffer); tile the general case.
        size_t off = 0;
        while (off < n) {
            if (!leafPrimed) { leaf.Reset(); leaf.Write(&zero, 1); leafPrimed = true; }
            uint32_t room  = chunkSize - chunkFilled;
            size_t   avail = n - off;
            size_t   take  = (avail < (size_t)room) ? avail : (size_t)room;

            leaf.Write(buf.data() + off, take);
            chunkFilled += (uint32_t)take;
            off         += take;

            if (chunkFilled == chunkSize) {
                Bytes d(CSHA256::OUTPUT_SIZE);
                leaf.Finalize(d.data());
                leaves.push_back(d);
                leafPrimed = false;
                chunkFilled = 0;
            }
        }
    }
    fclose(f);

    // Flush a final partial chunk (last leaf, < chunkSize) for non-empty input.
    if (total > 0 && chunkFilled > 0) {
        Bytes d(CSHA256::OUTPUT_SIZE);
        leaf.Finalize(d.data());
        leaves.push_back(d);
    }

    Finish(whole, leaves, total, chunkSize, out);
    return true;
}
