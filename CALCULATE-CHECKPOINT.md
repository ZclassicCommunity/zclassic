# How to Calculate the UTXO Checkpoint Hash

## Purpose

The UTXO checkpoint hash provides Bitcoin ABC-style security for snapshot verification. It ensures that the downloaded snapshot matches a known-good state of the blockchain.

## Prerequisites

- Fully synced ZClassic node at block height 2879438 (or desired snapshot height)
- Access to the node's RPC interface
- The node must have completed all blockchain validation up to the checkpoint height

## Step-by-Step Process

### Step 1: Ensure Node is Synced to Target Height

```bash
# Check current block height
zclassic-cli getblockcount

# Should show: 2879438 (or higher)
```

### Step 2: Get Block Hash at Snapshot Height

```bash
# Get the block hash at height 2879438
zclassic-cli getblockhash 2879438

# Example output:
# 0000000002c5c0a02461a1a2f7b23451c5c14faaeb6c2ea322676fe9aeca38c4
```

### Step 3: Calculate UTXO Set Hash

```bash
# This will take several minutes to complete!
zclassic-cli gettxoutsetinfo

# Example output:
{
  "height": 2879438,
  "bestblock": "0000000002c5c0a02461a1a2f7b23451c5c14faaeb6c2ea322676fe9aeca38c4",
  "transactions": 1234567,
  "txouts": 2345678,
  "bytes_serialized": 123456789,
  "hash_serialized": "abc123def456...",  ← THIS IS THE UTXO HASH WE NEED!
  "total_amount": 12345678.90
}
```

**IMPORTANT NOTES:**
- The `gettxoutsetinfo` command may take 5-15 minutes to complete
- The node must NOT be restarted or interrupted during this calculation
- The hash is deterministic - running it multiple times on the same chain state will always give the same result

### Step 4: Verify Block Hash Matches

Ensure the `bestblock` from `gettxoutsetinfo` matches the block hash from Step 2!

```bash
# They MUST match:
bestblock from gettxoutsetinfo:   0000000002c5c0a02461a1a2f7b23451c5c14faaeb6c2ea322676fe9aeca38c4
getblockhash 2879438:              0000000002c5c0a02461a1a2f7b23451c5c14faaeb6c2ea322676fe9aeca38c4
                                   ✓ MATCH!
```

### Step 5: Update src/chainparams.cpp

Open `src/chainparams.cpp` and find the snapshot checkpoint initialization (around line 195-206):

**BEFORE:**
```cpp
// Snapshot checkpoints for fast sync verification
vSnapshotCheckpoints = {
    CSnapshotCheckpoint(
        2879438,  // Height
        uint256S("0x0000000002c5c0a02461a1a2f7b23451c5c14faaeb6c2ea322676fe9aeca38c4"),  // Block hash
        uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"),  // PLACEHOLDER!
        0  // PLACEHOLDER!
    )
};
```

**AFTER (with real values):**
```cpp
// Snapshot checkpoints for fast sync verification
// Calculated on trusted fully-synced node at block 2879438
vSnapshotCheckpoints = {
    CSnapshotCheckpoint(
        2879438,
        uint256S("0x0000000002c5c0a02461a1a2f7b23451c5c14faaeb6c2ea322676fe9aeca38c4"),
        uint256S("0xABC123DEF456..."),  // ← Real hash_serialized from Step 3
        1234567ULL  // ← Real transactions count from Step 3
    )
};
```

### Step 6: Recompile

```bash
cd /path/to/zclassic
make -j4
```

### Step 7: Test Verification

After recompiling, test that the verification works:

```bash
# Start a test node that loads the snapshot
# The debug log should show:
# "UTXO verification: Calculated hash matches checkpoint!"
```

## Security Best Practices

1. **Use Multiple Nodes:**
   - Calculate the UTXO hash on at least 2-3 independent, fully-synced nodes
   - Verify they all produce the SAME hash
   - If hashes differ, investigate before using!

2. **Trusted Source:**
   - Only use nodes you fully control
   - Never trust UTXO hashes from untrusted sources
   - The hash is hardcoded in source code - this is the security model

3. **Document the Process:**
   - Record the date/time of calculation
   - Record the node version used
   - Store the raw `gettxoutsetinfo` output for reference

## Troubleshooting

### "height differs from checkpoint"
- Node is not at the correct block height
- Wait for sync to complete, then retry

### "UTXO hash verification failed"
- If using placeholder (all zeros): This is expected
- If using real hash: **DO NOT DEPLOY** - investigate immediately
  - Verify calculation was done correctly
  - Check node was fully synced
  - Recalculate on independent node

### "gettxoutsetinfo is taking forever"
- Normal! Can take 5-15 minutes depending on hardware
- The node is scanning the entire UTXO set
- Do not interrupt the process

## Production Deployment Checklist

- [ ] Snapshot created at block 2879438
- [ ] UTXO hash calculated on trusted node
- [ ] UTXO hash verified on 2nd independent node (hashes match!)
- [ ] Block hash verified (matches getblockhash)
- [ ] src/chainparams.cpp updated with real values
- [ ] Code recompiled successfully
- [ ] Test verification on local node
- [ ] Deploy snapshot chunks to serving infrastructure
- [ ] Update documentation with snapshot details

## Example Complete Checkpoint

```cpp
// Real example (values shown are illustrative):
vSnapshotCheckpoints = {
    CSnapshotCheckpoint(
        2879438,  // Snapshot block height
        uint256S("0x0000000002c5c0a02461a1a2f7b23451c5c14faaeb6c2ea322676fe9aeca38c4"),
        uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        3456789ULL  // Total transaction count at this height
    )
};
```

## References

- Bitcoin ABC UTXO hash implementation
- Bitcoin Core AssumeUTXO (BIP)
- ZClassic snapshot system documentation (SNAPSHOT-README.md)

---

**Status:** Ready for production use once checkpoint is calculated and updated.

**Last Updated:** 2025-10-19
