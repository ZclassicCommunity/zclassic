# Bitcoin ABC AssumeUTXO Analysis

## Overview

After reviewing the Bitcoin AssumeUTXO proposal and examining Bitcoin ABC's production code, here's what we learned for implementing ZClassic's snapshot state verification.

## Key Findings from Bitcoin ABC

### 1. Source Code Examined

- **Repository**: https://github.com/Bitcoin-ABC/bitcoin-abc
- **License**: MIT (compatible with ZClassic)
- **Files Reviewed**:
  - `src/kernel/coinstats.h` - Data structures
  - `src/kernel/coinstats.cpp` - UTXO hash calculation
  - `src/kernel/chainparams.h` - Assumeutxo checkpoint structure

### 2. Bitcoin ABC's Approach

#### Checkpoint Structure (Much Simpler!)

```cpp
/**
 * Holds configuration for use during UTXO snapshot load and validation.
 * Adapted from Bitcoin ABC (MIT License)
 * Copyright (c) 2022 The Bitcoin Core developers
 */
struct AssumeutxoData {
    int height;                      // Block height
    AssumeutxoHash hash_serialized;  // UTXO set hash (CRITICAL!)
    unsigned int nChainTx;           // Total transaction count
    BlockHash blockhash;             // Block hash at this height
};
```

**Key Insight**: They do NOT include chain work, Merkle roots, or other blockchain state in the checkpoint. They ONLY verify the UTXO set hash!

#### Why This is Better

1. **Simpler**: Fewer fields to hardcode
2. **Focused**: Verifies what matters (UTXO set)
3. **Block headers already verified**: Chain work is already validated through normal block header verification
4. **Proven**: This is production code used by Bitcoin Cash

### 3. UTXO Hash Calculation

The Bitcoin ABC code has a CRITICAL WARNING:

```cpp
//! Warning: be very careful when changing this! assumeutxo and UTXO snapshot
//! validation commitments are reliant on the hash constructed by this
//! function.
//!
//! If the construction of this hash is changed, it will invalidate
//! existing UTXO snapshots. This will not result in any kind of consensus
//! failure, but it will force clients that were expecting to make use of
//! assumeutxo to do traditional IBD instead.
//!
//! It is also possible, though very unlikely, that a change in this
//! construction could cause a previously invalid (and potentially malicious)
//! UTXO snapshot to be considered valid.
```

#### The Algorithm

1. **Iterate through all UTXOs** using CCoinsViewCursor
2. **Group by transaction ID** (not individual outputs)
3. **For each transaction**, serialize outputs in sorted order (std::map ensures this)
4. **Hash includes**:
   - Block hash (PrepareHash step)
   - For each TX with unspent outputs:
     - txid
     - height * 2 + coinbase_flag (clever: packs both in one field!)
     - For each output (sorted by index):
       - output_index + 1 (VARINT)
       - scriptPubKey
       - value (VARINT)
     - Terminating VARINT(0) after last output
5. **Result**: SHA256 hash of this deterministic serialization

#### Critical Implementation Details

**From `ApplyHash()` in coinstats.cpp (lines 48-65)**:

```cpp
static void ApplyHash(HashWriter &ss, const TxId &txid,
                      const std::map<uint32_t, Coin> &outputs) {
    for (auto it = outputs.begin(); it != outputs.end(); ++it) {
        if (it == outputs.begin()) {
            ss << txid;
            ss << VARINT(it->second.GetHeight() * 2 + it->second.IsCoinBase());
        }

        ss << VARINT(it->first + 1);  // output index + 1
        ss << it->second.GetTxOut().scriptPubKey;
        ss << VARINT_MODE(it->second.GetTxOut().nValue / SATOSHI,
                          VarIntMode::NONNEGATIVE_SIGNED);

        if (it == std::prev(outputs.end())) {
            ss << VARINT(0u);  // Terminator
        }
    }
}
```

**Why group by txid?**
- More efficient (serialize txid once per transaction, not per output)
- Cursor already returns items sorted by (txid, vout)
- std::map<uint32_t, Coin> automatically sorts outputs by index

**Why `output_index + 1`?**
- Allows distinguishing output 0 from terminator

**Why `height * 2 + coinbase_flag`?**
- Packs two pieces of info into one field
- Even number = regular tx, odd number = coinbase
- Saves space with VARINT encoding

## 4. How It Differs from Our Original Proposal

| Aspect | Original Proposal | Bitcoin ABC Approach |
|--------|------------------|----------------------|
| **What to hash** | UTXO set + Sprout anchor + Sapling root + chain work | UTXO set ONLY |
| **Checkpoint data** | 5 fields (height, block hash, state hash, chain tx, chain work) | 4 fields (height, block hash, UTXO hash, chain tx) |
| **Iteration method** | Collect all UTXOs, then sort | Group by txid during iteration (already sorted) |
| **Memory usage** | High (store all UTXOs in vector) | Low (process on-the-fly) |
| **Complexity** | Higher | Lower |

## 5. Why Bitcoin ABC's Approach is Better

1. **Production-tested**: Used by Bitcoin Cash in production
2. **More efficient**: Doesn't need to collect all UTXOs in memory first
3. **Simpler**: Only verifies UTXO set, not extra state
4. **ZClassic-specific state**: We can verify Sprout/Sapling separately if needed

## 6. Adaptation for ZClassic

### What to Keep

✅ Bitcoin ABC's UTXO hashing algorithm
✅ Bitcoin ABC's checkpoint structure
✅ Bitcoin ABC's group-by-txid optimization

### What to Add (ZClassic-specific)

For ZClassic, we MAY want to add separate verification for:
- Sprout note commitment tree anchor
- Sapling note commitment tree root

**BUT**: These should be verified SEPARATELY, not mixed into the UTXO hash. Why?
- Keeps UTXO hash algorithm standard (same as Bitcoin)
- Allows reusing Bitcoin test vectors for verification
- Makes debugging easier
- Follows principle of separation of concerns

### Recommended Approach

```cpp
struct ZClassicSnapshotCheckpoint {
    // Standard Bitcoin fields (from Bitcoin ABC)
    int nHeight;
    uint256 hashBlock;
    uint256 hashUTXOSet;        // Bitcoin-compatible UTXO hash
    uint64_t nChainTx;

    // ZClassic-specific fields (verified separately)
    uint256 hashSproutAnchor;    // Sprout note commitment tree
    uint256 hashSaplingRoot;     // Sapling note commitment tree
};
```

**Verification logic**:
1. Extract snapshot
2. Load chainstate
3. Calculate UTXO hash → compare with `hashUTXOSet`
4. Check Sprout anchor → compare with `hashSproutAnchor`
5. Check Sapling root → compare with `hashSaplingRoot`
6. All three must match to accept snapshot

## 7. Implementation Priority

1. **Phase 1 (MVP)**: Implement ONLY UTXO hash verification
   - Use Bitcoin ABC's exact algorithm
   - Test determinism across nodes
   - This alone provides strong security

2. **Phase 2 (Later)**: Add Sprout/Sapling verification
   - Separate checks, not mixed into UTXO hash
   - Only if we determine it's necessary

## 8. Copyright and Licensing

Bitcoin ABC code is MIT licensed. We can adapt it for ZClassic with proper attribution:

```cpp
// Copyright (c) 2022 The Bitcoin Core developers
// Copyright (c) 2025 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Adapted from Bitcoin ABC's assumeutxo implementation
```

## 9. Testing Strategy

1. **Test determinism**: Run hash calculation on 3 different fully-synced nodes
2. **Compare results**: ALL nodes MUST return identical hash
3. **Add checkpoint**: Hardcode the verified hash
4. **Test verification**: Extract snapshot and verify it passes
5. **Test corruption**: Modify snapshot and verify it fails

## 10. Next Steps

See updated SNAPSHOT-STATE-VERIFICATION.md for implementation details.
