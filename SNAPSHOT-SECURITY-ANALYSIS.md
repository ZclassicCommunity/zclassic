# Snapshot System: Security, Privacy & Robustness Analysis

## Critical Question: Auto-Update?

**Short answer: NO. Bitcoin doesn't auto-update, and we shouldn't either.**

### Why Bitcoin ABC/Core Don't Auto-Update

```cpp
// From Bitcoin ABC chainparams.cpp
// Snapshot checkpoints are HARDCODED in source code:
m_assumeutxo_data = MapAssumeutxo{
    {
        840'000,
        {AssumeutxoHash{uint256S("0xabcd...")}, 123456789},
    },
};
```

**How Bitcoin updates snapshots:**
1. Developer calculates UTXO hash on trusted fully-synced node
2. Hash is hardcoded into chainparams.cpp
3. Code is reviewed by multiple developers
4. Hash is committed to Git repo
5. New software version is released
6. Users upgrade their node software

**Why this is secure:**
- Checkpoint hash is part of the CODE, reviewed on GitHub
- Can't be changed without code review
- Can't be attacked via network
- Users choose when to upgrade

## Security Analysis

### ✅ What Bitcoin ABC Does (SECURE)

1. **Hardcoded checkpoint** in source code (chainparams.cpp)
2. **Manual updates** via software releases
3. **Code review** before checkpoint is added
4. **Optional feature** - users can disable with `-noassumeutxo`
5. **Fallback to full sync** if verification fails

### ❌ What We Should NOT Do (INSECURE)

1. **Auto-download checkpoints** from a server
   - Creates centralization point
   - Server could be hacked
   - Man-in-the-middle attack possible

2. **Dynamic checkpoint updates** via P2P
   - Could be poisoned by malicious peers
   - No code review process
   - Users don't know hash changed

3. **Trust DNS/HTTP** for checkpoint distribution
   - DNS can be hijacked
   - HTTP can be intercepted
   - HTTPS still requires trusting CA

### 🎯 Recommended Approach for ZClassic

**Phase 1: Initial Implementation (Single Hardcoded Checkpoint)**

```cpp
// In src/chainparams.cpp (CMainParams constructor)
vSnapshotCheckpoints = {
    CSnapshotCheckpoint(
        2879438,  // Height (current snapshot)
        uint256S("0x0000000002c5c0a02461a1a2f7b23451c5c14faaeb6c2ea322676fe9aeca38c4"),
        uint256S("0x[CALCULATED_UTXO_HASH]"),  // From trusted node
        12345678  // nChainTx from getblockchaininfo
    )
};
```

**Phase 2: Update Process (Every 6-12 months)**

1. Community member runs `gettxoutsetinfo` on trusted fully-synced node
2. Posts hash + height to GitHub issue for review
3. Multiple community members verify hash matches on their nodes
4. Developer adds new checkpoint to chainparams.cpp
5. Pull request reviewed on GitHub
6. Merged and included in next release
7. Users upgrade when ready

**Phase 3: Multiple Checkpoints (Future)**

Allow multiple checkpoint heights:
```cpp
vSnapshotCheckpoints = {
    CSnapshotCheckpoint(2879438, ...), // Old snapshot (still works)
    CSnapshotCheckpoint(3500000, ...), // New snapshot (6 months newer)
};
```

Users can choose which snapshot to use, or do full sync.

## Privacy Analysis

### 🔒 Privacy Protection Rules

**NEVER include in snapshots:**

```bash
# In create-snapshot.sh - STRICT exclusions
--exclude='wallet.dat'           # PRIVATE KEYS
--exclude='wallet.dat.bak'       # Backup wallets
--exclude='wallet*.dat'          # All wallet files
--exclude='peers.dat'            # IP addresses of peers
--exclude='peers.dat.old'        # Old peer list
--exclude='debug.log'            # May contain IP addresses
--exclude='debug.log.old'        # Old logs
--exclude='db.log'               # LevelDB logs
--exclude='.lock'                # Lock files
--exclude='*.lock'               # All locks
--exclude='fee_estimates.dat'   # Fee estimates (not consensus-critical)
--exclude='mempool.dat'         # Unconfirmed txs (privacy + not consensus)
--exclude='banlist.dat'         # Banned IPs
--exclude='*.tmp'               # Temporary files
--exclude='*.log'               # All log files
```

**ONLY include:**
- `blocks/` directory (public blockchain data)
- `chainstate/` directory (public UTXO set)

**Verification before distribution:**
```bash
# Before uploading snapshot, verify no private data:
tar -tzf snapshot.tar.gz | grep -E "(wallet|peers|debug|log|lock)"
# Should return NOTHING. If it finds anything, ABORT!
```

### Privacy Attack Scenarios

**Scenario 1: Malicious snapshot creator includes wallet.dat**
- ✅ PREVENTED: Strict --exclude rules
- ✅ BACKUP: Pre-distribution verification script
- ✅ BACKUP: Community review of snapshot creation process

**Scenario 2: LevelDB includes IP addresses**
- ✅ SAFE: LevelDB only stores blockchain data, no network info
- ✅ VERIFICATION: Can inspect LevelDB with tools to verify

**Scenario 3: Metadata leaks information**
- ✅ SAFE: We only hash UTXO set, not file metadata
- ✅ SAFE: Tar doesn't include creator info by default

## Robustness Analysis

### 🛡️ Failure Modes & Recovery

**Scenario 1: Snapshot verification FAILS (corrupted or malicious)**

```cpp
if (actualUTXOHash != checkpoint->hashUTXOSet) {
    LogPrintf("ERROR: Snapshot verification FAILED!\n");
    LogPrintf("  Expected: %s\n", checkpoint->hashUTXOSet.GetHex());
    LogPrintf("  Actual:   %s\n", actualUTXOHash.GetHex());

    // DELETE corrupted data immediately
    boost::filesystem::remove_all(dataDir / "chainstate");
    boost::filesystem::remove_all(dataDir / "blocks");

    // Fall back to full sync
    LogPrintf("Falling back to full blockchain sync...\n");
    return false;  // Node will start full IBD
}
```

**Recovery**: Node automatically falls back to full sync. No manual intervention needed.

**Scenario 2: Snapshot download never completes (network issues)**

```cpp
// After 24 hours of failed download attempts:
if (nSnapshotDownloadStartTime + 86400 < GetTime()) {
    LogPrintf("Snapshot download timeout. Falling back to full sync.\n");
    fUseSnapshot = false;  // Disable snapshot, start full sync
}
```

**Recovery**: Node gives up on snapshot and does full sync.

**Scenario 3: User wants to disable snapshots entirely**

```bash
# User can add to zclassic.conf:
nosnapshot=1

# Or command line:
./zclassicd -nosnapshot
```

**Recovery**: Node ignores snapshots completely, does full sync.

**Scenario 4: Checkpoint becomes outdated (too old)**

```cpp
// Only use snapshot if it's less than 1 year old
if (checkpoint->nHeight < chainActive.Height() - 525600) {  // ~1 year of blocks
    LogPrintf("Snapshot too old (height %d vs current %d). Using full sync.\n",
              checkpoint->nHeight, chainActive.Height());
    return false;
}
```

**Recovery**: Node detects old snapshot, uses full sync instead.

**Scenario 5: Software bug in snapshot code crashes node**

```bash
# User can disable snapshots without recompiling:
echo "nosnapshot=1" >> ~/.zclassic/zclassic.conf
./zclassicd --reindex  # Rebuild from blocks on disk
```

**Recovery**: User disables feature, node works normally.

## Trust Model

### What Users Must Trust

**WITH snapshots (assumeutxo):**
1. ✅ ZClassic developers didn't put malicious hash in code
2. ✅ Majority of hashpower is honest (same as always)
3. ✅ Cryptography (SHA256) is not broken

**WITHOUT snapshots (full sync):**
1. ✅ Majority of hashpower is honest
2. ✅ Cryptography (SHA256) is not broken

**Key insight**: Snapshot adds ONE additional trust assumption: developers. But:
- Code is open source (anyone can verify hash)
- Hash is on GitHub (public, reviewable)
- Community can verify hash on their own nodes
- Feature is optional (can disable)

### Comparison to Existing Trust

**Users already trust developers for:**
- Consensus rules (what blocks are valid)
- Network protocol (how nodes communicate)
- Cryptography implementation (signature verification)
- Checkpoint at block 0 (genesis block)

**Snapshot checkpoint is similar to:**
- Genesis block hash (hardcoded, trusted)
- DNS seeds (hardcoded, trusted)
- Alert key (historical, now removed)

**More secure than:**
- Central servers (we use P2P)
- DNS for bootstrap (we use hardcoded values)
- Single developer control (we use code review)

## Deployment Strategy

### Rollout Plan (Conservative & Safe)

**Version 1: No snapshots (baseline)**
- Current state
- Full sync only
- 100% trustless

**Version 2: Add snapshot code + ONE checkpoint (opt-in)**
```bash
# Default: full sync
# To use snapshot:
./zclassicd -usesnapshot
```
- Feature exists but disabled by default
- Users must opt-in
- Reduces risk of breaking existing nodes
- Allows testing in production

**Version 3: Enable by default (after 3-6 months of testing)**
```bash
# Default: use snapshot
# To disable:
./zclassicd -nosnapshot
```
- Flip default after community testing
- Still allow disabling
- Update checkpoint every 6-12 months

**Version 4: Multiple checkpoints (1+ years later)**
- Add new checkpoint
- Keep old one working
- Users can pick which to use
- Further reduces centralization

### Safety Measures

1. **Testnet first** - Deploy on testnet, test for 1 month
2. **Opt-in initially** - Don't enable by default at first
3. **Clear documentation** - Explain what snapshots are, how to disable
4. **Monitoring** - Log snapshot downloads, failures
5. **Community testing** - Ask users to verify hash on their nodes
6. **Gradual rollout** - Don't rush the default flip

## Configuration Options

```bash
# zclassic.conf

# Disable snapshots entirely (use full sync)
nosnapshot=1

# Force snapshot usage (fail if can't download)
requiresnapshot=1

# Snapshot download timeout (seconds, default 86400 = 24h)
snapshottimeout=43200

# Debug snapshot operations
debug=snapshot
```

## Monitoring & Metrics

```cpp
// Add to getinfo RPC:
"snapshot": {
    "enabled": true,
    "height": 2879438,
    "verified": true,
    "download_time": 3600,  // seconds
    "chunks_downloaded": 171
}
```

## Security Checklist

Before deploying:

- [ ] UTXO hash calculation is deterministic (test on 3+ nodes)
- [ ] create-snapshot.sh excludes ALL private data
- [ ] Verification deletes corrupted data immediately
- [ ] Fallback to full sync works
- [ ] User can disable feature
- [ ] Checkpoint is reviewed on GitHub
- [ ] Multiple developers verify hash
- [ ] Documentation explains trust model
- [ ] Testnet deployment successful
- [ ] Community has tested for >1 month

## Conclusion

**Bitcoin ABC's approach is secure because:**
1. Checkpoints hardcoded in source code (GitHub review)
2. No auto-update (user chooses when to upgrade)
3. Optional feature (can disable)
4. Fails safely (falls back to full sync)
5. Open process (community can verify hash)

**We should follow the same model:**
- NO auto-update of checkpoints
- Update via software releases
- Code review on GitHub
- Community verification
- Conservative rollout

**Privacy is protected by:**
- Strict exclusion rules
- Pre-distribution verification
- Only public blockchain data
- No metadata leakage

**Robustness is ensured by:**
- Multiple failure recovery paths
- User control (can disable)
- Automatic fallback to full sync
- No breaking changes to existing nodes
- Conservative defaults

**This is the right way to do it.**
