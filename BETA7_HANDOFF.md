# ZClassic v2.1.2-beta7 — Developer Handoff

**Date:** 2026-06-08 · **Branch:** `feature/beta7-platform` (daemon repo) · **Coin:** ZClassic / ZCL
(never ZEC/Zcash in user-facing strings)

This is a **WIP checkpoint** committed so work is not lost and the next developer can take over. It
bundles the accumulated beta7 platform work. **Master is HELD** — do NOT merge to master or publish a
release until the repo owner gives an explicit go.

---

## 0. TL;DR status

| Area | State | Green? | Next |
|------|-------|--------|------|
| **ZNAM names — parser + C++ bridge** | landed this session | ✅ 22/22 gtest, full suite 431 | indexer |
| **ZNAM determinism spec** | authoritative, matches ported parser | n/a | owner sign-off on §12 constants |
| **ZNAM indexer / store / RPC / wallet** | NOT started | — | see §3 (design is fully worked out) |
| **Embedded Tor T1 (compile-in)** | done | ✅ `TorEmbed` 3/3 | — |
| **Embedded Tor T2 (onion bring-up + DEANON guard)** | proven end-to-end on real Tor net | ✅ | fold fork-hardening |
| **Embedded Tor T3 stage-1 (v3 identity load-bearing)** | done | ✅ `TorV3Identity` 5/5 | stages 1b–1d |
| **Tor auth_cb 9050 bug** | fix APPLIED in init.cpp | ⚠️ not yet rebuilt | batch into next build |
| **T3 stages 1b–1d (BIP155 ADDRv2 serialize/addrman/negotiate)** | NOT started | — | task #145 |
| **Marketplace P1–P3 (bounds, RAM offerpool, gossip)** | committed earlier + WIP | partial | P4–P5 RPCs + name↔offer sig |
| **GUI Names/Market/Tor tabs (zcl-qt-wallet)** | NOT started | — | separate repo |
| **Version macro** | `CLIENT_VERSION_BUILD = 6` (beta7 track) | — | finalize at release |

**Integrated full-tree build status: UNVERIFIED this session.** Each piece was green when built in
isolation (NFT #122 committed green; ZNAM green this session via the proot gtest; Tor T1/T2/T3-s1 green
per the build logs). The whole working tree compiling together has NOT been re-verified — that is the
first thing the next dev / the release-wrap step (task #152) should confirm.

---

## 1. How to build (proot, no Docker / no root)

The reproducible build runs in an Ubuntu-20.04 (glibc 2.31) proot rootfs at `/home/rhett/zclbuild`.

```
cd /home/rhett/zclbuild && ./prun bash /build/<script>.sh
```

Binds inside proot: `/src/daemon` = this repo (host) · `/build/daemon` = the build tree ·
`/src/wallet` = the zcl-qt-wallet repo. Prefix: `/build/daemon/depends/x86_64-unknown-linux-gnu`.

Proven build scripts (`/home/rhett/zclbuild/focal/build/`):
- `p7-znam-parser.sh` — full ZNAM gtest build (autogen → config.status --recheck → make zcash-gtest).
- `p7b-znam-fix.sh` — lean rebuild (single file, no autogen).
- `p6-t3s1-torv3-identity.sh` — Tor T3 stage-1 gtest build (the canonical "small recompile" template).
- `p5-tor-depends.sh`, `p5b-tor-only.sh`, `p5c-tor-link.sh` — embedded-Tor depends + link.

**LESSON (do not repeat):** never run a bare `automake`; it bumps `aclocal.m4`'s timestamp → forces a
full `config.status` → `configure` → "libdb_cxx headers missing" abort + a *stale* gtest binary that
silently runs (false pass). Always use `./autogen.sh` then
`CONFIG_SITE=$PFX/share/config.site ./config.status --recheck`.

### Embedded-Tor build prerequisite (IMPORTANT)
`depends/sources/tor-73bd405.tar.gz` (10 MB) is **git-ignored** and NOT in this commit. To build the
Tor depends you need it host-side at `/home/rhett/zclbuild/focal/build/daemon/depends/sources/`:
- source: `github.com/RhettCreighton/tor` branch `dynhost` @ `73bd405` (Tor 0.4.9.2-alpha)
- sha256: `178fb8242d5a1066c3535f1328d8b5ef1e4578e318a8e622d6a6732144fa2517`
- it also needs a matching stamp:
  `cd depends/sources && sha256sum tor-73bd405.tar.gz > download-stamps/.stamp_fetched-tor-tor-73bd405.tar.gz.hash`
- depends `make` MUST carry `NO_PROTON=1` (proton/AMQP needs cmake, absent in the focal proot).

---

## 2. ZNAM (ZCL Names) — what landed this session ✅

A non-consensus on-chain name registry (`OP_RETURN` overlay, exactly like ZSLP/NFT — never touches
consensus). Ported from `github.com/RhettCreighton/zclassic-c` `lib/znam` (Apache-2.0, Rhett Creighton).

**Files added (daemon side, all green):**
- `src/znam/znam.{h,c}` — pure-C parser + OP_RETURN builder. Lokad `"ZNAM"`, version 1, 6 commands
  (REGISTER/UPDATE/TRANSFER/RENEW/SET_RECORD/SET_TEXT), 7 target types (ONION/ZADDR/TADDR/BTC/LTC/
  DOGE/CONTENT), names `[a-z0-9-]` 1..63. Shares `src/zslp/op_return_push.h` with `slp.c`.
- `src/znam/znammsg.{h,cpp}` — C++ bridge (mirrors `zslp/zslpmsg`): `ZNAMParseScript` +
  `ZNAMBuild*` + `ZNAMValidateName`. The ONLY TU that includes the C header (inside `extern "C"`).
  static_asserts pin the enum codes to the permanent wire numbers.
- `src/gtest/test_znam.cpp` — 22 round-trip + rejection tests.
- Wired into `src/Makefile.am` (znam.c → libbitcoin_common, znammsg.cpp → libbitcoin_server, headers
  → BITCOIN_CORE_H) and `src/Makefile.gtest.include`.

**Bug fixed during the port:** the reference `znam_build_set_text` emitted a bare `0x00` (OP_0) for an
empty value (record deletion), which this codebase's `read_push` cannot decode (it accepts
`0x01..0x4b`/`0x4c`/`0x4d` only). Fixed to emit the canonical empty push `0x4c 0x00`. Caught by the
round-trip gtest.

**Permanent-bytes spec:** `doc/platform/ZNAM_DETERMINISM_SPEC.md` — authoritative, matches the parser
byte-for-byte. **§12 has the constants that need owner sign-off before mainnet** (REGISTRATION_DURATION
~210000 blocks, GRACE ~52500, MAX_REGISTRATION ~2.1M, RESERVE_BURN default 0). These are non-consensus
indexer policy, tunable on regtest/testnet right up to mainnet activation; they don't change wire bytes.

## 3. ZNAM indexer/RPC/wallet — design is fully worked out, NOT yet coded (next task #147→#148)

Clone the proven ZSLP pattern. The structural map (file:line) is in the agent recon above; the key
seams to mirror:
- **Indexer** `CZNAMIndexer : CValidationInterface` (model `src/zslp/zslpindexer.{h,cpp}`): `ChainTip`
  → ConnectBlock/DisconnectBlock; background catch-up worker; OpenStore + version-stamp migration;
  `-znamindex` flag in `init.cpp` (mirror `-zslpindex` at init.cpp:~3345 + Shutdown calls).
- **Store** `CZNAMStore : CDBWrapper` (model `src/zslp/zslpstore.{h,cpp}`) at `blocks/znam/`. Schema in
  spec §10. LIFO undo log (`CZNAMUndoOp`) + tip marker + version stamp.
- **THE ONE NEW MECHANIC vs ZSLP — owner = vin[0] P2PKH signer (spec §4):** ZSLP only needed addresses
  of its own token outputs; ZNAM needs the address that authorized `vin[0]`. Resolve it deterministically
  from the block's **undo data**: `UndoReadFromDisk(blockUndo, pindex->GetUndoPos(),
  pindex->pprev->GetBlockHash())` (main.cpp:2250), then `blockUndo.vtxundo[i-1].vprevout[0].txout.
  scriptPubKey` (undo.h `CTxInUndo::txout`) → `ExtractDestination` → if exactly `TX_PUBKEYHASH`
  (CKeyID), `EncodeDestination` = owner; **else the record is a no-op (P2PKH-or-drop).** This is a total
  function of the confirmed chain and is exactly what disconnect already uses to restore coins.
- **RPC** `rpc/znam.cpp` (model `rpc/zslp.cpp`): `name_register/update/transfer/renew/setrecord/settext`
  (wallet) + `name_resolve/list/listmine/info/history` (read). Register via `rpc/register.h`.
- **Wallet** `wallet/znamwallet.cpp` (model `wallet/zslpwallet.cpp` `BuildAndCommitZSLP`): build the
  OP_RETURN via `ZNAMBuild*`, fund the owner address from a **dedicated `names` derivation path**
  (privacy, spec §4.4), emit the reserve-burn output if RESERVE_BURN>0, self-validate before broadcast.
- **gtests** `test_znam_indexer.cpp`: the §13 conformance vectors (FIFS, auth, transfer,
  reorg-across-transfer, expiry/grace, SET_TEXT ASCII allowlist, P2PKH-or-drop).

---

## 4. Embedded Tor — see `doc/net/EMBEDDED_TOR_BLUEPRINT.md` + memory `embedded-tor-build-status`

T1/T2/T3-s1 done & green. **auth_cb fix is applied in `init.cpp` but not yet rebuilt — batch it into
the next build.** Next: T3 stages 1b–1d (version-gated BIP155 serializer + `CADDR_ADDRV2_VERSION`,
peers.dat v1→v2, sendaddrv2/addrv2 + per-peer `fSendAddrV2` negotiation), then a deep networking
review. Two **fork-hardening** items to fold into the alpha→stable Tor rebase (do once, on stable, in
the RhettCreighton/tor dynhost branch): (1) relay.c:1707 notice-level log spam on the hot data-cell
path (44k lines/3min) → drop to debug; (2) unused dynhost beacon (dynhost_sys.c:49) auto-creates a 2nd
ephemeral onion → disable. Tor fork is 0.4.9.2-**alpha** — rebase onto stable + CVE process BEFORE any
default-on. Windows: compile-in on all platforms (owner decision); code-sign + VirusTotal-measure at
release (AV flags the whole binary even with `-embeddedtor` OFF).

## 5. Marketplace — see `doc/nft/MARKETPLACE_*` + memory `marketplace-tor-relay-convergence`
P1 (offer bounds), P2 (RAM offerpool `src/nft/offerpool`), P3 (5-msg P2P gossip) done. Next: P4/P5
publish RPCs + multi-node regtest; bind "listed by alice.zcl" by **signature** over the owner P2PKH key
(`signmessage`/`verifymessage`, spec §11) — never by coin co-location (deanon finding); route relay
over the embedded-Tor onion conduit; Hashcash PoW-gate gossip (task #143). `-nftmarket` default OFF
(interim); flip ON once Tor relay ships.

## 6. Also in this checkpoint
- **NFT collections + content-fingerprint** (`src/zslp/contentfingerprint.*`, group/child 'g' index).
- **Datachannel / ZDC1 removed** (deletions of `src/datachannel/*`, `rpc/datachannel.*`,
  `asyncrpcoperation_senddatafile.*`) — superseded; the shielded data path was consolidated.
- **blockindex-cache** WIP (memory `blockindex-cache-status`).
- **Lots of design docs** under `doc/nft/`, `doc/net/`, `doc/platform/`.

---

## 7. Tasks (this session created #146–#152)
- #146 ✅ ZNAM parser+bridge+gtest · #147 ⏳ ZNAM indexer+store · #148 ZNAM RPC+wallet
- #149 Tor auth_cb rebuild + T3 1b–1d · #150 marketplace Tor-relay + sig binding + PoW
- #151 GUI tabs (zcl-qt-wallet) · #152 release wrap (master HELD)
- Long-running: #144 (embedded Tor), #145 (BIP155), #139 (marketplace P4/P5), #143 (PoW gossip).

## 8. Hard rules for whoever picks this up
- **NON-consensus only.** ZNAM/ZSLP/marketplace are OP_RETURN overlays + observers. Never touch
  consensus, PoW, block/tx validity, mempool acceptance, or wallet spends.
- **Never disturb the live mainnet node** (datadir `~/.zclassic`). Build in the proot tree; run
  daemons only on throwaway regtest datadirs under /tmp.
- **One proot build at a time. No non-interactive sudo.**
- **Master is HELD** until the owner says go. Commit/push to feature branches only.
- Determinism IS security for the overlays — every rule a total function; wire bytes are permanent.
