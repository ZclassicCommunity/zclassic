# BIP-155 (addrv2) Implementation for Zclassic

> **Document Version:** 3.0
> **Date:** December 11, 2025
> **Branch:** `feature/onion-v3-cleanup`
> **Status:** ✅ IMPLEMENTED, TESTED & CLEANED UP (macOS only)
> **WARNING:** Tested only on macOS ARM64. Requires further testing on Linux/Windows before mainnet release.

## What's New in v3.0

- **NET_ONION removed** - All references replaced with `NET_TORV3`
- **Tor v2 code removed** - `pchOnionCat` constant and 16-char .onion parsing deleted
- **Cleaner codebase** - No more dual enum confusion (NET_ONION vs NET_TORV3)

---

## Executive Summary

This document describes the BIP-155 (addrv2) implementation for Zclassic, incorporating lessons learned from Bitcoin Core and Zcash implementations.

### Implementation Status

| Component | Status |
|-----------|--------|
| Protocol Version | ✅ Bumped to 170012 |
| Data Structures | ✅ Completed |
| Protocol Messages | ✅ sendaddrv2/addrv2 handlers |
| Address Relay | ✅ addrv2-aware relay logic |
| Backward Compatibility | ✅ Tested with 170011 peers |
| Enable/Disable Flag | ✅ `-enablebip155` (default: on) |

---

## 1. Lessons Learned from Bitcoin Core & Zcash

### 1.1 Issues Encountered in Bitcoin Core

| Issue | PR/Issue | Solution Applied |
|-------|----------|------------------|
| **Network type ambiguity** | #19031 | Added explicit `CNetAddr::m_net` member to store network type |
| **Dual enum problem** | #19031 | Created separate private `BIP155NetworkId` enum to avoid breaking existing loops |
| **sendaddrv2 timing** | #20564 | Send `sendaddrv2` BEFORE `verack`, not after |
| **Pre-70016 software crashes** | #20564 | Don't send `sendaddrv2` to nodes with protocol version < 70016 |
| **Address relay black holes** | #20564 | Check peer addrv2 support before relaying Tor v3 addresses |
| **anchors.dat incompatibility** | #20511 | Use ADDRV2_FORMAT for anchors.dat serialization |
| **peers.dat backwards incompatibility** | #19954 | Repurpose keysize field as version; older nodes fail gracefully |
| **Spam vector via unknown networks** | #20119 | Initially restrict relay to IPv4/IPv6/Tor only |
| **I2P relay before support** | #20119, #22211 | Only relay I2P addresses when `-i2psam` is configured |
| **gitian build symbol export** | #19954 | Use local static variable instead of global `in6addr_loopback` |

### 1.2 Zcash Status

| Item | Status | Notes |
|------|--------|-------|
| Issue #5277 (addrv2 support) | Open since Aug 2021 | Not implemented |
| PR #5313 (ZIP-155 attempt) | Closed Jan 2022 | Reorganization needed |
| PR #5366 (TorV3 test) | Closed Draft | Exploratory only |

**Key Insight:** Zcash has NOT implemented BIP-155/ZIP-155 yet. Zclassic would be ahead of Zcash if implemented.

---

## 2. Implementation Strategy

### 2.1 Guiding Principles

1. **Minimal invasive changes** - Avoid large refactors where possible
2. **Backward compatible** - Graceful fallback to legacy `addr` message
3. **Fail-safe** - Older peers.dat files should not crash new nodes
4. **Security first** - Strict parsing, rate limiting, spam prevention

### 2.2 Protocol Version Strategy

Current Zclassic protocol version needs verification. We will:
- Add `sendaddrv2` support at current protocol version
- Only send `sendaddrv2` to peers that support it
- Send `sendaddrv2` BEFORE `verack` (lesson from Bitcoin #20564)

---

## 3. Files to Modify

### 3.1 Core Header Files

| File | Changes |
|------|---------|
| `src/netbase.h` | Add `m_net` member, `NET_TORV3` enum, `BIP155NetworkId` private enum |
| `src/protocol.h` | Add `sendaddrv2`, `addrv2` message constants |
| `src/net.h` | Add `m_wants_addrv2` flag to `CNode` |
| `src/addrman.h` | Support variable-length addresses, version field |
| `src/serialize.h` | Add `ADDRV2_FORMAT` flag, `AddrV2Serializer` |

### 3.2 Core Implementation Files

| File | Changes |
|------|---------|
| `src/netbase.cpp` | `SerializeV2()`, `UnserializeV2()`, network detection |
| `src/protocol.cpp` | Register new message types |
| `src/main.cpp` | Message handlers for `sendaddrv2`, `addrv2` |
| `src/net.cpp` | Send `sendaddrv2` during handshake (before verack) |
| `src/addrman.cpp` | Store/retrieve variable-length addresses, migration |

### 3.3 Test Files

| File | Changes |
|------|---------|
| `src/test/netbase_tests.cpp` | Tor v3 address parsing, addrv2 serialization |
| `src/test/addrman_tests.cpp` | Variable-length storage, migration tests |
| `src/test/net_tests.cpp` | Protocol negotiation tests |

---

## 4. Implementation Phases

### Phase 1: Data Structures ✅ COMPLETED

**Objective:** Core data structures without protocol changes

- [x] Add `BIP155NetworkId` enum to `netbase.h`
- [x] Add `m_net` member to `CNetAddr`
- [x] Add `NET_TORV3`, `NET_I2P`, `NET_CJDNS` to `Network` enum
- [x] Implement `GetBIP155Network()`, `SetFromBIP155()`, `GetAddrBytes()`
- [x] Add address size constants (`ADDR_TORV3_SIZE`, etc.)

**Files Modified:**
- `src/netbase.h` - Network enum, BIP155Network enum, CNetAddr extensions
- `src/netbase.cpp` - Implementation of BIP155 methods

### Phase 2: Protocol Messages ✅ COMPLETED

**Objective:** P2P message handling

- [x] Add `m_wants_addrv2` flag to `CNode` in `net.h`
- [x] Send `sendaddrv2` BEFORE VERACK (per BIP155 spec)
- [x] Handle incoming `sendaddrv2` message with safeguards
- [x] Handle incoming `addrv2` message with full parsing
- [x] Only send addrv2 to peers that negotiated it

**Files Modified:**
- `src/net.h` - MAX_ADDRV2_COUNT, m_wants_addrv2 flag
- `src/main.cpp` - sendaddrv2/addrv2 handlers, version handshake

**Critical Implementation Details:**
```cpp
// In net.cpp, after sending VERSION:
if (nVersion >= MIN_ADDRV2_VERSION) {
    PushMessage(pfrom, "sendaddrv2");  // BEFORE verack!
}

// In main.cpp ProcessMessage:
else if (strCommand == "sendaddrv2") {
    // Only accept before VERACK
    if (pfrom->fSuccessfullyConnected) {
        // Ignore post-verack (compatibility with draft BIP)
        return true;
    }
    pfrom->m_wants_addrv2 = true;
    return true;
}
```

**Deliverable:** Nodes can negotiate addrv2 support

### Phase 3: Address Manager ✅ COMPLETED

**Objective:** Relay logic for addrv2 addresses

- [x] Update address relay to check peer addrv2 support
- [x] Prevent "black hole" relay (don't relay Tor v3 to non-addrv2 peers)
- [x] Implement `PushAddrV2Message()` for sending addrv2 format
- [x] Add `-enablebip155` config flag (default: true)

**Files Modified:**
- `src/main.cpp` - PushAddrV2Message(), addr/addrv2 relay logic
- `src/init.cpp` - `-enablebip155` help message
- `src/version.h` - PROTOCOL_VERSION 170012, BIP155_VERSION constant

**peers.dat Format (Bitcoin Core compatible):**
```
Legacy:    [magic(4)][format=0x01][compat=0x20(32)]... (keysize=32)
V3_BIP155: [magic(4)][format=0x03][compat=0x23(35)]... (INCOMPATIBILITY_BASE + 3)
```

**Versioning Scheme (from Bitcoin Core PR #19954, #20284):**
- Byte 0 after magic: Format version (V1_DETERMINISTIC=1, V3_BIP155=3)
- Byte 1 after magic: INCOMPATIBILITY_BASE(32) + lowest_compatible_version
- Old nodes see keysize=35 which is != 32, fail gracefully with "Corrupt peers.dat"
- New nodes detect format by checking if compat >= INCOMPATIBILITY_BASE

**Migration Strategy:**
1. On load, check compat byte at offset 5
2. If compat == 32 (legacy): read V1 format, set m_net from IP content
3. If compat >= 32: extract version = compat - 32, use addrv2 format
4. On save, always use V3_BIP155 format with addrv2 serialization

**Critical Bug Fixes Applied:**
1. Missing nVersion read in CAddress deserialization (SER_DISK writes version first)
2. m_net field detection after legacy format read (IsIPv4/IsTor/IPv6)

**Deliverable:** Tor v3 addresses persist across restarts

### Phase 4: Testing & Hardening ✅ COMPLETED (macOS only)

**Objective:** Production readiness

- [x] Build tested successfully on macOS ARM64
- [x] Mixed network test (upgraded + legacy nodes)
- [x] Edge case handling (malformed messages, unexpected sendaddrv2)
- [x] Documentation updates
- [ ] **TODO:** Linux build and test
- [ ] **TODO:** Windows build and test
- [ ] **TODO:** Extended testnet validation before mainnet release

### Phase 5: Onion v2 Cleanup ✅ COMPLETED

**Objective:** Remove deprecated Tor v2 code, unify to NET_TORV3

**Files Modified:**
| File | Changes |
|------|---------|
| `src/netbase.h` | Removed `#define NET_ONION NET_TORV3` alias |
| `src/netbase.cpp` | Removed `pchOnionCat[]`, v2 16-char parsing, v2 ToStringIP encoding |
| `src/init.cpp` | Replaced 6x `NET_ONION` → `NET_TORV3`, cleaned up duplicate calls |
| `src/torcontrol.cpp` | Replaced 2x `NET_ONION` → `NET_TORV3` |
| `src/test/netbase_tests.cpp` | Updated tests to use `NET_TORV3`, removed onioncat test |

**What Was Removed:**
```cpp
// REMOVED from netbase.cpp
static const unsigned char pchOnionCat[] = {0xFD,0x87,0xD8,0x7E,0xEB,0x43};

// REMOVED: 16-char v2 onion parsing in SetSpecial()
else if (vchAddr.size() == 10) {
    memcpy(ip, pchOnionCat, sizeof(pchOnionCat));
    // v2 onion encoding...
}

// REMOVED: v2 ToStringIP encoding
if (memcmp(ip, pchOnionCat, sizeof(pchOnionCat)) == 0)
    return EncodeBase32(&ip[6], 10) + ".onion";
```

**Result:**
- Clean codebase with only `NET_TORV3` (no dual enum)
- All Tor v2 legacy code removed
- Code is easier to maintain and understand

**Test Results (from debug.log on macOS ARM64):**
1. ✅ Node advertises protocol version 170012
2. ✅ Legacy peer (170011) receives legacy `addr` messages
3. ✅ Unexpected sendaddrv2 from 170011 peer correctly rejected
4. ✅ Tor v3 onion address correctly advertised
5. ✅ Block sync works normally with mixed peers
6. ✅ peers.dat legacy → addrv2 migration successful
7. ✅ peers.dat addrv2 reload successful (2059 addresses)

---

## 5. Security Considerations

### 5.1 Parsing Safety

```cpp
// Always validate network ID
switch (network_id) {
    case NET_ID_IPV4:
    case NET_ID_IPV6:
    case NET_ID_TORV3:
        break;  // Known types
    default:
        return error("Unknown network ID %d", network_id);
}

// Always validate address length
if (addr_len > MAX_ADDR_SIZE) {
    return error("Address too long: %d", addr_len);
}
if (addr_len != expected_len_for_network(network_id)) {
    return error("Invalid address length for network");
}
```

### 5.2 Spam Prevention

- Rate limit addrv2 messages (same as addr)
- Initially only relay IPv4/IPv6/Tor (not I2P/CJDNS)
- Misbehavior scoring for protocol violations

### 5.3 Relay Safety

```cpp
// In RelayAddress(), check peer support
void RelayAddress(const CAddress& addr) {
    LOCK(cs_vNodes);
    for (CNode* pnode : vNodes) {
        if (addr.IsAddrV2Only() && !pnode->m_wants_addrv2) {
            continue;  // Don't relay Tor v3 to legacy peers
        }
        pnode->PushAddress(addr);
    }
}
```

---

## 6. Upgrade Instructions

### Before Upgrading to BIP-155

**IMPORTANT:** Backup your peers.dat before upgrading!

```bash
# 1. Stop the daemon
zclassic-cli stop

# 2. Wait for shutdown
sleep 5

# 3. Backup peers.dat (REQUIRED)
cp ~/Library/Application\ Support/ZClassic/peers.dat \
   ~/Library/Application\ Support/ZClassic/peers.dat.preBIP155

# 4. Install new version with BIP-155 support

# 5. Start daemon
zclassicd -daemon
```

The new daemon will:
1. Load your legacy peers.dat (`01 20` format)
2. On first flush (~15 min), write addrv2 format (`03 23`)
3. Subsequent restarts will use the new format

### Rollback Plan

If issues are discovered post-deployment:

1. **Soft rollback:** Disable `sendaddrv2` sending via config flag (`-enablebip155=0`)
2. **Hard rollback:** Revert to previous version and restore backup:
   ```bash
   zclassic-cli stop
   cp ~/Library/Application\ Support/ZClassic/peers.dat.preBIP155 \
      ~/Library/Application\ Support/ZClassic/peers.dat
   # Install previous version
   zclassicd -daemon
   ```
3. **Data recovery:** peers.dat v2 can be deleted; node re-discovers peers

---

## 7. Success Criteria

- [x] `zclassicd` accepts `sendaddrv2` and `addrv2` messages
- [x] Tor v3 addresses propagate between upgraded nodes
- [x] Legacy nodes continue working without crashes
- [x] `getpeerinfo` shows Tor v3 addresses
- [x] ZipherX wallet can advertise its .onion address

---

## 8. References

### Bitcoin Core PRs
- [#19031 - Implement ADDRv2 support](https://github.com/bitcoin/bitcoin/pull/19031)
- [#19954 - Complete BIP155 and TORv3](https://github.com/bitcoin/bitcoin/pull/19954)
- [#20119 - BIP155 follow-ups](https://github.com/bitcoin/bitcoin/pull/20119)
- [#20564 - sendaddrv2 timing fix](https://github.com/bitcoin/bitcoin/pull/20564)
- [#20511 - anchors.dat issue](https://github.com/bitcoin/bitcoin/issues/20511)

### Zcash Issues
- [#5277 - addrv2 support](https://github.com/zcash/zcash/issues/5277)
- [#3051 - Tor v3 support](https://github.com/zcash/zcash/issues/3051)

### Specifications
- [BIP-155](https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki)
- [ZIP-155](https://zips.z.cash/zip-0155) (if exists)

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-09 | ZipherX/Claude | Initial plan based on Bitcoin/Zcash research |
| 2.0 | 2025-12-09 | ZipherX/Claude | Implementation completed & tested |
| 2.1 | 2025-12-09 | ZipherX/Claude | peers.dat persistence with Bitcoin Core compatible versioning |
| 3.0 | 2025-12-11 | ZipherX/Claude | NET_ONION → NET_TORV3 migration, Tor v2 code removal |
