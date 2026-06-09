# ZClassic NFT — Master Feature Checklist

> **REMOVED — shielded data channel / on-chain private files.** The "Shield" pillar and the ZDC1
> data-channel items below (`z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer`, the
> `-datachannel` option, the ZDC1 codec) have been **removed entirely** from the daemon. ZClassic
> deliberately provides **no wallet path to store arbitrary files on-chain**. NFT content is always
> off-chain, bound to the token only by a `document_hash` fingerprint. Treat every Shield / private
> file / ZDC1 line below as **historical**.

The single source of truth for the four NFT pillars: **Mint · View · Shield · Sell.**
Scope: daemon (`/home/rhett/github/zclassic`, branch `feature/zslp-nft-indexer`, all NFT
work UNCOMMITTED) + GUI (`/home/rhett/github/zcl-qt-wallet`, C++14).

> Honesty rule for this doc: **"implemented" = code exists AND is reachable. "tested" = a
> real automated test exercises it. "documented" = a user/dev can find how to use it.**
> In-flight and design-only work is NEVER marked done.

Marker legend (used in every cell):

| Marker | Meaning |
|--------|---------|
| ✅ | Done — exists, reachable, and (for test cells) a real automated test exercises it |
| 🟡 | Partial — exists but incomplete, indirect, untested-at-this-layer, or stale/misleading |
| ❌ | Missing — does not exist at this layer |

> **2026-06-06 GUI-LANDING UPDATE.** The NFT dialogs (`nftmintdialog.*`,
> `nftdetaildialog.*`, `nftsenddialog.*`, `nftgallerymodel/delegate`) that were previously
> in-flight (workflow `wnr918pfq`) **have LANDED** in the GUI tree and are graded here as
> real code (no more 🔭). They remain UNCOMMITTED (`??`) and so are at risk until committed.
> Grading is from a read-only audit of the now-present source + the L0/L1 test files.
> The **GUI build backlog now lives in its own doc: [`NFT_GUI_PLAN.md`](NFT_GUI_PLAN.md)**.

---

## 1. Honest status header — the four pillars

| Pillar | One-line real-state verdict |
|--------|------------------------------|
| **MINT** | **Daemon: shippable-but-unproven.** `zslp_genesis` (nft preset) is implemented, reachable, registered, helped, CLI-arg-converted, and self-validates before broadcast — but **no test drives the RPC or the `BuildAndCommitZSLP` write path** (only pure builders/parser/store/self-validate gate are gtested). **GUI mint dialog (`nftmintdialog.*`) has LANDED** (file→stream-hash→review→`zslp_genesis`, Create gated on name+fingerprint, honest "only the fingerprint goes on-chain" copy, 0-conf terminal). Infra (ContentEngine hash, `RPC::mintNFT`) is done + tested. **But the mint dialog is NEVER constructed in any test** (no L1 covers Create-gating, fingerprint streaming, the privacy-drop reject, the in-flight `closeEvent` swallow, or the success/failure terminal); `mintNFT` has no test-injection seam. In-app: no permanence/public-ledger warning, no help. |
| **VIEW** | **Most-complete pillar. Daemon read RPCs done (untested at RPC layer); GUI gallery infra done + L0-tested; detail dialog has LANDED + has one L1 test.** No web browser anywhere. Honest gaps: **a RECEIVED NFT can NEVER reach the green verify badge** — `refreshNFTs` hard-sets `cachePath=''` (rpc.cpp:960, privacy: never auto-fetch) and the ONLY cache writer is the in-session mint (`ContentEngine::cachePut`, nftmintdialog.cpp:249); there is **no "attach the file you have" affordance** anywhere (no `getOpenFileName` in the detail/gallery), so the core promise (verify the image) is structurally unreachable for anything not minted in-session. A hash-less NFT (`document_hash` optional for nft=true) is permanently unverifiable. `refreshNFTs` repaints only on a new block. **No in-app help/onboarding at all** (0 `setWhatsThis` in the whole GUI; the verify badge has no "matches fingerprint ≠ genuine/official" disambiguation); the spec'd 4-page hero stack (guide §2.3) was NOT built — only a single grey `nftStateLabel`. The detail dialog's verified/mismatch/pending **badge-copy mapping is untested** (only the no-bytes terminal branch is). |
| **SHIELD** | **~25% built, 0% reachable in the GUI.** The ZDC1 codec exists; **the privacy RPCs `z_senddatafile` / `z_getdatatransfer` / `z_listdatatransfers` are now BUILT in the daemon** (`src/rpc/datachannel.cpp`, registered, CLI-arg-converted at `client.cpp:138-139`, gated behind `-datachannel` default-OFF, `z_senddatafile` requires `acknowledge_permanent=true`) — they are **no longer "unbuilt", they are built-with-ZERO-GUI-affordance.** GUI is honestly hard-gated off (`isPrivateMintWired()==false`, rpc.h:225); no GUI caller for any datachannel RPC; the binary-safe memo-read sniff is not applied. Shielding token *ownership* is consensus-impossible (correctly out of scope). |
| **SELL** | **Daemon BUILT + atomic-swap regtest-proven (committed); GUI greenfield.** The 6 `nft_*` offer RPCs exist (`src/rpc/nftoffer.cpp`, registered :1094-1104, register fn :1106) with CLI conversion + 6 gtests + `qa/zslp/nft-sell-regtest.sh`; no GUI surface yet. The authoritative design is `NFT_SELL_DESIGN.md` (fixed-template `SIGHASH_ALL\|ANYONECANPAY`: OP_RETURN ZSLP SEND@vout[0] / buyer NFT dust@vout[1] / seller ZCL payout@vout[2]); the older `ONCHAIN_TRADES.md` is SUPERSEDED (its `SINGLE\|ANYONECANPAY` layout is funds-losing — SINGLE would pin the OP_RETURN, not the payout, and burn the seller NFT). The transparent-swap *primitives* (`signrawtransaction` ALL\|ANYONECANPAY + CombineSignatures, ZIP-243 masking, P2SH/CLTV/multisig) are reused; the two classic blockers are HANDLED in the build — `createrawtransaction` cannot emit OP_RETURN (so the builder hand-assembles vout[0] via `ZSLPBuildSend`), and `fundrawtransaction` is avoided entirely (it would insert change at a random vout and break the seller's `ALL` signature). |

**Bottom line:** Mint + View now have **landed (uncommitted) GUI dialogs** on top of infra-complete primitives, but the dialog wiring is **almost entirely untested at the widget level** (only the detail no-bytes terminal has an L1 test) and View's headline promise — verify a *received* image — is structurally unreachable (no attach-local-bytes path). The daemon write path is still untested. Shield's privacy RPCs are now *built* in the daemon but have **zero GUI affordance** (honestly hard-gated off). Sell is design-only. Nothing is end-to-end shippable to a non-technical user today.

---

## 2. Capability matrix

Columns: **CLI impl / CLI test / CLI doc** = the daemon side. **GUI impl / GUI test / GUI doc** = the wallet side. `—` = not applicable to that layer.

### MINT

| Capability | Pillar | CLI impl | CLI test | CLI doc | GUI impl | GUI test | GUI doc | Notes / Gap |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| `zslp_genesis` (mint; nft preset forces decimals0/qty1/no-baton) | Mint | ✅ | ❌ | ✅ | ✅ | ❌ | 🟡 | RPC reachable + self-validates (`zslp.cpp:326`, table :649-661, `client.cpp:138`). **No test drives the RPC fn or NFT-preset rejections.** GUI: `RPC::mintNFT` (rpc.cpp:1037) is driven by the landed `NftMintDialog`. **GUI test ❌: the dialog is never constructed in any test; `mintNFT` has no test seam** (unlike `testSetNextZaddrResult`). |
| `zslp_mint` (fungible re-issue via baton) | Mint | ✅ | ❌ | ✅ | ❌ | ❌ | 🟡 | `zslp.cpp:462`. Requires live baton UTXO. **CLI-only by design — no GUI** (guide §1: NFT write path = genesis/send only). RPC untested. |
| `BuildAndCommitZSLP` (coin select, anti-burn funding fence, sign, self-validate, commit) | Mint | ✅ | ❌ | 🟡 | — | — | — | `zslpwallet.cpp:195`. **Single biggest write-path coverage hole** — test header (`test_zslp_wallet.cpp:25`) explicitly disclaims it; covered "by code review" only. |
| C parser `slp.c` round-trip + edge cases | Mint | ✅ | ✅ | 🟡 | — | — | — | 29 tests (`test_zslp.cpp`). Strong. |
| Builder bridge bytes + canonical layout + 223-byte cap | Mint | ✅ | 🟡 | 🟡 | — | — | — | `test_zslp_wallet.cpp:154`. 223 is a raw length assert, **NOT tied to IsStandard/`-datacarriersize`** (see HARD-CONSTRAINT row). |
| Self-validation gate `WouldBeValid` (pre-broadcast) | Mint | ✅ | ✅ | 🟡 | — | — | — | `test_zslp_wallet.cpp:314`. The exact gate the builder calls. Well covered. |
| ContentEngine `document_hash` = streaming SHA-256 of content | Mint | — | — | — | ✅ | ✅ | ✅ | `contentengine.cpp`; `RPC::mintNFT` builds the param. 14 `ce*` L0 tests. |
| GUI "Make a collectible" wizard (file→hash→review→genesis) | Mint | — | — | — | ✅ | ❌ | 🟡 | `nftmintdialog.*` LANDED (uncommitted). Create gated on name+fingerprint+!hashing+!inflight (`refreshCreateEnabled`:207); streaming fingerprint UI; web-link drop rejected inline; 0-conf "appears once it confirms" terminal; `closeEvent` swallowed while in-flight. **No L1 flow test (dialog never constructed).** Doc 🟡: honest privacy copy ships but **NO in-app permanence/public-ledger warning** and no help (G-HELP). |
| **`zslp_burn` / intentional destroy** | Mint | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **No sanctioned burn primitive** — anti-burn prevents accidents but offers no way to intentionally retire an edition. |

### VIEW

| Capability | Pillar | CLI impl | CLI test | CLI doc | GUI impl | GUI test | GUI doc | Notes / Gap |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| `zslp_gettoken` | View | ✅ | 🟡 | ✅ | ✅(wrap) | 🟡 | ✅ | `zslp.cpp:84`. Store layer gtested; **RPC fn + not-found path untested.** GUI wraps it TWICE: batch in `refreshNFTs` (every card's name/hash/height) + `RPC::nftProvenance` for the detail back-fill — but **the back-fill is a no-op stub on success** (nftdetaildialog.cpp:326): Set/Creator read, not displayed. |
| `zslp_listtokens` (paged, clamped to 1000) | View | ✅ | 🟡 | ✅ | ❌ | ❌ | ✅ | `zslp.cpp:120`. Clamp tested at store, not RPC. |
| `zslp_listtransfers` (DoS-bounded paging) | View | ✅ | ✅ | ✅ | ❌ | ❌ | 🟡 | `zslp.cpp:155`. DoS bound + ordering tested at store/vector layer. **GUI: NO caller** (grep `listtransfers` in GUI = none). The detail dialog advertises "provenance" but never calls it — chain-of-custody history is unreachable from the GUI. |
| `zslp_listmytokens` (wallet roll-up, per-address breakdown) | View | ✅ | ❌ | ✅ | ✅(wrap) | 🟡 | ✅ | `zslp.cpp:204`. **Zero coverage of the wallet-intersection/aggregation** — most complex read RPC. GUI's primary feed (`refreshNFTs`). |
| Native gallery (QListView IconMode model+delegate, no browser) | View | — | — | — | ✅ | ✅ | ✅ | `nftgallerymodel/delegate`, `setupNFTTab` (`mainwindow.cpp:3019`). Fingerprint-guarded; 5+ L0 tests. |
| ContentEngine poster / chunked-Merkle verify / content-addressed cache | View | — | — | — | ✅ | ✅ | ✅ | `contentengine.cpp` (882 lines). Privacy-hard (no network). 14 `ce*` L0 tests. |
| NFT detail dialog (decode, downscale, verify badge, provenance) | View | — | — | — | ✅ | 🟡 | 🟡 | `nftdetaildialog.*` LANDED (uncommitted). **GUI test 🟡: only the no-bytes terminal branch is tested** (`nftDetail_noBytesIsTerminalNotSpinner`, tst_widget.cpp:1869); the VERIFIED/MISMATCH/PENDING badge-copy mapping (`applyVerifyBadge`:279) and the undecodable-image branch (:257) are untested. Doc 🟡: provenance back-fill (`zslp_listtransfers`) is NOT called — header advertises "provenance" but only mint-id + received height show; no help on the verify badge. |
| Verify badge semantics (0 pending / 1 verified / 2 mismatch) | View | — | — | — | ✅ | 🟡 | ✅ | `nft.h`; the enum + model-level state are L0-tested (`nftCachePipelineVerifyMismatchPending`, `nftModelRolesAndOnImageReady`). 🟡: the **dialog's** state→copy mapping ("matches" / "does NOT match" / "Checking") in `applyVerifyBadge` is NOT tested (only the no-bytes branch). |
| `getExplorerTxURL` deep-link (testnet-empty, !isPrivate gated) | View | — | — | — | ✅ | ❌ | 🟡 | `settings.cpp:418`. **No test pins the URL scheme or testnet `''` sentinel.** |
| **Content/metadata fetch RPC** (resolve document_url/hash → bytes) | View | ❌ | ❌ | ❌ | — | — | — | No daemon-side content resolve/verify RPC. Left entirely to GUI ContentEngine. |
| **0-conf freshness** (newly minted card visible pre-block) | View | — | — | — | 🟡 | ❌ | ❌ | `refreshNFTs` runs only on new block + mint/send success (`rpc.cpp:1309`); a same-block re-open can look empty. |
| **"Attach the file you have" affordance** (supply local bytes for a RECEIVED NFT) | View | — | — | — | ❌ | ❌ | ❌ | **CONFIRMED WORST GAP (G-VIEW).** `refreshNFTs` hard-sets `cachePath=''` (rpc.cpp:960); the ONLY cache writer is the in-session mint (`ContentEngine::cachePut`, nftmintdialog.cpp:249); no `getOpenFileName`/attach anywhere in `nftdetaildialog`/gallery; "Re-check image" just re-runs the empty cache. A RECEIVED NFT shows "Can't check — isn't on this computer" FOREVER. The detail no-bytes tooltip even *promises* "open it to check it yourself" — an action no button performs. |
| **`document_hash` required for nft=true** (else permanently unverifiable) | View | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ | `document_hash` is OPTIONAL for nft=true daemon-side (validated only IF present; the nft preset adds no requirement). GUI mint requires an anchor before Create, but any CLI/foreign hash-less NFT is **structurally impossible to ever verify** (no anchor → no cacheGet → badge stays neutral). Decision needed (see GUI plan). |

### SHIELD

| Capability | Pillar | CLI impl | CLI test | CLI doc | GUI impl | GUI test | GUI doc | Notes / Gap |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| ZDC1 codec (transport + per-transfer AEAD + KEY frame + fingerprint) | Shield | ✅ | 🟡 | ✅ | — | — | — | **CORRECTION (was 🟡/🟡, "not a gtest target"): `src/datachannel/zdc.{h,cpp}` is COMPILED** (`src/Makefile.am:248,295`) **AND has a gtest target** (`src/gtest/test_zdc.cpp`). 🟡 test = confirm the gtest exercises nonce-uniqueness/AEAD round-trip in CI (was a standalone g++ harness). |
| **Compile codec into daemon** (`Makefile.am` entry) | Infra | ✅ | — | ✅ | — | — | — | **CORRECTION (was ❌, "confirmed absent"): NOW PRESENT** — `src/Makefile.am:248` (`datachannel/zdc.h`), `:294` (`rpc/datachannel.cpp`), `:295` (`datachannel/zdc.cpp`). The pillar is no longer dead code. |
| `z_senddatafile` (+ `AsyncRPCOperation_senddatafile`) | Shield | ✅ | 🟡 | ✅ | ❌ | ❌ | ✅ | **CORRECTION (was ❌): BUILT** — `datachannel.cpp:215`, registered `:704-711`, CLI-arg-converted `client.cpp:138`, requires `acknowledge_permanent=true`. **GUI: zero affordance** (`isPrivateMintWired()==false`). CLI test 🟡 (confirm a regtest round-trip drives it). |
| `z_revealkey` (seal-then-reveal trigger) | Shield | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | **DESIGNED-NOT-BUILT.** Codec primitive `encode_key_frame` ready; **RPC + key-store glue still absent** (NOT in the datachannel command table `:704-711`). |
| `z_listdatatransfers` (Decoder reassembly, sealed-metadata hiding) | Shield | ✅ | 🟡 | ✅ | ❌ | ❌ | ✅ | **CORRECTION (was ❌): BUILT** — `datachannel.cpp:430`, registered `:704-711`. GUI: zero affordance. CLI test 🟡. |
| `z_getdatatransfer` (verify-before-decrypt, ERR_NO_KEY vs ERR_AEAD_FAIL) | Shield | ✅ | 🟡 | ✅ | ❌ | ❌ | ✅ | **CORRECTION (was ❌): BUILT** — `datachannel.cpp:471`, registered `:704-711`, CLI-arg-converted `client.cpp:139`. GUI: zero affordance. CLI test 🟡 (confirm ERR_NO_KEY/ERR_AEAD_FAIL mapping is tested). |
| `zslp_mint_private` (encrypt asset, document_hash = ciphertext_fingerprint) | Shield | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | **DESIGNED-NOT-BUILT.** Core "private NFT". Depends on the (now-built) datachannel send path; **the `zslp_mint_private` RPC itself is still absent.** |
| Default-OFF master gate (`-datachannel` → `-32601`) | Infra | ✅ | 🟡 | ✅ | 🟡 | — | ✅ | **CORRECTION (was ❌, "daemon gate unbuilt"): BUILT** — `RegisterDataChannelRPCCommands` (`datachannel.cpp:713`, `register.h:38`) only appends the commands when `-datachannel` is on, else dispatcher throws `-32601`; help string `init.cpp:527`, default 0. GUI already latches `-32601` as "feature not present". CLI test 🟡 (no test asserts off→-32601). |
| Safety: required-true `acknowledge_permanent` + shielded-funding/recipient checks | Infra | 🟡 | ❌ | ✅ | ❌ | ❌ | ✅ | `z_senddatafile` now REQUIRES `acknowledge_permanent=true` (`datachannel.cpp:22,156+`). Shielded-from/to validation depth + a test are still owed. |
| DoS governance: 64KB/256KB caps, rate-limit, 72h TTL-GC, max-inflight | Infra | ❌ | ❌ | ✅ | — | — | ✅ | Codec only enforces ~29MB structural ceiling; caller governance unbuilt. |
| GUI binary-safe memo read (sniff ZDC1 magic before QString) | View | — | — | — | ❌ | ❌ | ✅ | Documented confirmed bug-fix at `rpc.cpp ~756`; **not applied.** |
| GUI private-mint / private-send / private-receive UI | Shield | — | — | — | ❌ | ❌ | ✅ | Hard-gated off (`isPrivateMintWired()==false`, `rpc.h:225`); send dialog only accepts t-addr. Honest, but absent. |
| Selective disclosure = reuse `z_exportviewingkey` (no new RPC) | Shield | ✅ | 🟡 | ✅ | ❌ | ❌ | ✅ | `rpcdump.cpp:801` exists today — reachable always-on (the datachannel RPCs are also reachable now, but only behind `-datachannel`). No NFT-privacy-specific test; no GUI "verify privately" wrapper; per-item single-use-zaddr convention unenforced. |
| Shield token VALUE/ownership through Sapling | Shield | ❌(consensus) | — | — | ❌(consensus) | — | ✅ | **Genuinely impossible on existing consensus** (z-notes carry no script). Correctly out of scope. |

### SELL

| Capability | Pillar | CLI impl | CLI test | CLI doc | GUI impl | GUI test | GUI doc | Notes / Gap |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| `zslp_send` (transfer; one-way gift) | Sell | ✅ | ❌ | ✅ | ✅ | ❌ | 🟡 | `zslp.cpp:541`. Closest to SELL but **one-way only — not an atomic trade.** RPC fn + coin-selection/change untested. GUI: `RPC::sendNFT` (rpc.cpp:1081) driven by the landed `NFTSendDialog`. **GUI test ❌: dialog never constructed; `sendNFT` has no test seam.** |
| GUI send/gift dialog (transparent recipient only) | Sell | — | — | — | ✅ | ❌ | 🟡 | `nftsenddialog.*` LANDED (uncommitted). 4-state recipient validation; hard-rejects shielded ("Private gifts coming soon") + mismatch (verifyState==2 keeps Send disabled, red "we won't send it"). **No L1 test (dialog never constructed)** — the mismatch send-guard (strongest honesty guarantee) has ZERO coverage. Doc 🟡: no help on what gifting means / its irreversibility. |
| `nft_makeoffer` / `nft_takeoffer` / `nft_verifyoffer` / `nft_listoffers` / `nft_canceloffer` / `nft_requestbuy` | Sell | ✅ | ✅ | 🟡 | ❌ | ❌ | 🟡 | **BUILT** `src/rpc/nftoffer.cpp` (registered :1094-1104, register fn :1106, CLI-converted). Fixed-template `ALL\|ANYONECANPAY`; reuses `ZSLPBuildSend` (DRY); anti-burn on buyer funding; `nft_verifyoffer` VerifyScripts the seller `vin[0]`; `nft_takeoffer` requires `acknowledge` on overshoot. Tested: 6 gtests (`test_nftoffer.cpp`) + committed `qa/zslp/nft-sell-regtest.sh` (atomic swap + sig-tamper/forged/token-funding/overshoot refusals). GUI surface pending (#118). |
| `signrawtransaction` ALL\|ANYONECANPAY + CombineSignatures merge | Sell | ✅ | ✅ | ✅ | — | — | — | `rawtransaction.cpp:726`. Tested generically (`rpc_tests.cpp:92`). **Used by no sell flow.** The sell design needs `ALL\|ANYONECANPAY` (seller pins the WHOLE output set incl. the OP_RETURN@vout[0]); `SINGLE\|ANYONECANPAY` is WRONG for ZSLP (it would pin vout[0]=OP_RETURN, not the payout). |
| ZIP-243 SIGHASH masking (ANYONECANPAY/ALL) | Sell | ✅ | ✅ | ✅ | — | — | — | `interpreter.cpp:1069`. Load-bearing primitive; tested; unused by NFT code. `ANYONECANPAY` zeroes prevouts/sequence (buyer appends inputs); `ALL` commits all outputs (seller fixes OP_RETURN@0 / buyer-NFT@1 / payout@2). |
| `createrawtransaction` (inputs/outputs/locktime/expiry) | Sell | 🟡 | ✅ | ✅ | — | — | — | **CANNOT emit OP_RETURN** (confirmed: 0 OP_RETURN paths) → RESOLVED: the sell builder hand-assembles vout[0] via the shared `ZSLPBuildSend` encoder (not `createrawtransaction`). |
| `decoderawtransaction` (offer inspection) | Sell | ✅ | ✅ | ✅ | — | — | — | Used by `nft_verifyoffer` (BUILT) — which also `VerifyScript`s the seller `vin[0]` against the live prevout (cryptographic pre-pay guarantee, not just field checks). |
| `sendrawtransaction` (broadcast filled swap) | Sell | ✅ | 🟡 | ✅ | — | — | — | Reusable as-is; no sell flow calls it. |
| `fundrawtransaction` (auto-funding) | Sell | 🟡 | 🟡 | ✅ | — | — | — | **FOOTGUN: it inserts change at a random vout (`wallet.cpp:3698`) AND adds an output at all — both break the seller's `ALL` signature** (the offer commits the EXACT output set: OP_RETURN@0 / buyer-NFT@1 / payout@2; any new or moved output invalidates `vin[0]`). The sell builder must hand-place inputs only — **never `fundrawtransaction`**. (This footgun broke the rejected SINGLE design too, for the same reason.) |
| P2SH / CLTV / CHECKMULTISIG / CHECKDATASIG (HTLC + escrow primitives) | Sell | 🟡 | ✅ | ✅ | — | — | — | Script primitives tested. **CSV/BIP112 ABSENT** (OP_NOP3 inert) → HTLCs limited to absolute CLTV. No redeem-script builder/flow/RPC. |
| PSBT (BIP174) interchange | Sell | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | No PSBT anywhere; offers must use raw partial-hex + CombineSignatures. |
| Wallet NFT-outpoint LOCK API (lock on makeoffer, release on cancel) | Sell | ✅ | ✅ | 🟡 | — | — | — | **BUILT**: `nft_makeoffer` `LockCoin`s the NFT outpoint; `nft_canceloffer` releases it (regtest-verified via `listlockunspent`). |
| GUI marketplace UI (offer cards, list/buy/cancel, "settles publicly" copy) | Sell | — | — | — | ❌ | ❌ | 🟡 | Entirely greenfield; can reuse RPC wrapper + ContentEngine + explorer URL. |

### CROSS-CUTTING (infra / docs / hard constraint)

| Capability | Pillar | CLI impl | CLI test | CLI doc | GUI impl | GUI test | GUI doc | Notes / Gap |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| **HARD CONSTRAINT: IsStandard/RequireStandard relay accepts the OP_RETURN unchanged** | Infra | 🟡 | ❌ | 🟡 | — | — | — | **The stated no-fork constraint is verified by NO test.** Only the 223-byte builder-length assert exists; not tied to mainnet `-datacarriersize`/policy. |
| Wallet anti-burn predicate `ZSLPIsProtectedTokenOutpoint` / `MsgWouldMakeTokenOutput` | Shield | ✅ | ❌ | 🟡 | — | — | — | `zslpwallet.cpp:68`, consumed `wallet.cpp:3197`. **The actual anti-burn decision fn is untested** (only its confirmed data source `store->GetUtxo` is). |
| `ZSLPFindWalletTokenUtxos` (deterministic selection; baton vs qty) | Sell | ✅ | ❌ | 🟡 | — | — | — | Sort key + filtering untested. |
| Live indexer plumbing: Init / migration / CatchUp / per-tip idempotence guard | Infra | ✅ | ❌ | 🟡 | — | — | — | `zslpindexer.cpp:62`. Migration, crash-resume, re-delivered-connect double-count guard untested. |
| Real `ConnectBlock` coinbase-skip loop (`for i=1`) | Infra | ✅ | 🟡 | 🟡 | — | — | — | Coinbase skip is only MODELED in test (author restraint), not executed. |
| Multi-token mixed-input tx (one tx spends two tokenIds) | Shield | ✅ | ❌ | 🟡 | — | — | — | **Security-relevant + untested:** non-declared token silently burned; correctness unproven. |
| Second-wallet receive-and-respend | Sell | ✅ | ❌ | 🟡 | — | — | — | The whole point of transfer; no test models a distinct receiving wallet. |
| RPC layer arg-conversion (`client.cpp`) | Infra | ✅ | ❌ | ✅ | — | — | — | Entries correct (`client.cpp:138-145`); a missing entry is a classic silent CLI bug, untested. |
| `-zslpindex` default state | Infra | ✅ | — | 🟡 | — | — | — | **Default-ON** (`init.cpp:3272` `GetBoolArg("-zslpindex", true)`), but error string + guide §2.3 imply opt-in. Misleading. |
| Main repo `README.md` discoverability | Infra | — | — | ✅ | — | — | ✅ | **DONE:** both READMEs now carry an "NFTs / Collectibles" section (daemon: model + `-zslpindex` on by default + CLI walkthrough; GUI: Collections tab + mint-from-file + verify-the-image), framed dev/testnet-stage. |
| End-to-end CLI walkthrough (mint→inspect→send→list sequence) | Infra | — | — | ✅ | — | — | — | **DONE:** the daemon `README.md` NFT section ships a copy-paste `zclassic-cli zslp_genesis → zslp_gettoken → zslp_send → zslp_listmytokens` session with the real positional RPCs. |
| User-facing GUI how-to (open Collections → make first collectible) | View | — | — | — | ✅ | ❌ | 🟡 | Dialogs LANDED, so the flow exists. 🟡 doc: no user step doc / screenshots; the spec'd 4-page hero stack (guide §2.3) was NOT built — only a single grey `nftStateLabel` (mainwindow.cpp:3051). |
| In-app NFT help / onboarding / tooltips | View | — | — | — | ❌ | ❌ | ❌ | **CONFIRMED near-total gap (G-HELP).** 0 `setWhatsThis` in the whole GUI; only 2 `setToolTip` on the verify badge, both echo the verdict. NO first-run "What is a collectible?", NO "matches fingerprint ≠ genuine/official" disambiguation (the single most-misunderstood element), NO permanence/public-ledger warning on mint, NO explanation of pending/no-bytes/0-conf, NO experimental-status notice. No L0/L1 covers any help/honesty-disambiguation surface. |
| `MINT_TRANSFER_SPEC.md` JSON multi-recipient `zslp_send` form | Mint | — | — | ✅ | — | — | — | **FIXED:** the fictional `{addr:amt}` JSON-map form is removed; the doc now states the real positional signature `zslp_send "tokenid" "to_address" ( amount change_address )` (single recipient) and notes the builder is multi-output-capable but the RPC arg surface is single-recipient. |
| ONCHAIN_TRADES.md (SUPERSEDED) | Sell | — | — | 🟡 | — | — | — | **SUPERSEDED by `NFT_SELL_DESIGN.md`** (banner added). Its `SINGLE\|ANYONECANPAY` layout is funds-losing (pins OP_RETURN, not payout → burns the seller NFT); its "ZSLP never reads tx.vin / only credits" and "no zslp_send builder / no ZSLP in wallet" claims are STALE (the live indexer debits inputs + enforces conservation; the write path + anti-burn now exist). Do not use as a build spec. |

---

## 3. Prioritized gap backlog

Ordered to reach: **all four pillars implemented, tested (CLI + GUI), documented.** Each item names the concrete file/RPC/test/doc.

### P0 — Prove what already exists (highest ROI; closes the biggest unproven-risk gaps)

- [ ] **Add a regtest RPC test for the full write path** (`qa/rpc-tests/zslp_nft.py` or equiv): `zslp_genesis nft:true` → capture tokenid → `zslp_gettoken` → `zslp_send <id> <addr> 1` → `zslp_listmytokens` on a second wallet. Closes the single biggest hole (`BuildAndCommitZSLP`, coin selection, conservation, RPC arg-parsing, `client.cpp` conversions) — all currently untested.
- [ ] **gtest the anti-burn decision fn** `ZSLPIsProtectedTokenOutpoint` + `MsgWouldMakeTokenOutput` (new cases in `src/gtest/test_zslp_wallet.cpp`): cover the 0-conf/IsFromMe branch and per-type vout arithmetic. Today a regression burns a token UTXO as fee with no test failing.
- [ ] **Test the HARD CONSTRAINT**: run a built ZSLP tx through `IsStandard`/`AcceptToMemoryPool` on real mainnet `CChainParams` (`src/gtest` or `src/test`), and tie the 223 magic number to the actual `-datacarriersize` policy constant. The no-fork guarantee is currently unverified.
- [ ] **gtest the multi-token mixed-input case** (`test_zslp_indexer.cpp`): a SEND whose vin carries token A *and* token B — assert B's UTXO burns/credits nobody while A conserves. Realistic accidental-burn vector, unproven.
- [ ] **gtest the live indexer plumbing** (`test_zslp_indexer.cpp`): migration (stale/absent version → wipe+reindex), the re-delivered-connect idempotence guard (`zslpindexer.cpp:189`), and the real `ConnectBlock` `for i=1` coinbase-skip executed (not modeled).
- [ ] **Test `zslp_listmytokens` aggregation** (per-address balance roll-up) and `ZSLPFindWalletTokenUtxos` deterministic ordering.

### P0 — Discoverability & doc-truth (cheap; unblocks every user)

- [x] **Add an NFT section to the main `README.md`** (daemon) + GUI `README.md`: what ZSLP NFTs are, `-zslpindex` is default-ON, the `zslp_*` RPCs, a CLI walkthrough, and a link to `doc/nft/README.md`. **Done** in both repos.
- [x] **CLI walkthrough** — shipped inline in the daemon `README.md` NFT section: copy-paste `zclassic-cli zslp_genesis "{...}"` → `zslp_gettoken` → `zslp_send` → `zslp_listmytokens`.
- [x] **Fix `MINT_TRANSFER_SPEC.md`**: the non-existent `zslp_send "tokenid" {addr:amt}` JSON-map form is removed; the real positional signature is documented.
- [ ] **Fix the index-off error string** to reflect `-zslpindex` default-ON (`init.cpp:3272`). (Docs already correct: the daemon README states default-ON; the guide §2.3 INDEX-OFF page is a legitimate UI state for when a foreign/old daemon has it off, not an implication of opt-in-by-default.)
- [x] **Reconcile `ONCHAIN_TRADES.md`** — done: a SUPERSEDED banner points to `NFT_SELL_DESIGN.md`, and the stale "ZSLP never reads tx.vin / only credits / no zslp_send builder" claims (`:42-45`, appendix `:230-232`) are corrected against the now-present write path + UTXO-bound conservation indexer + wallet anti-burn.

### P1 — Finish View (the GUI dialogs LANDED — now close honest gaps + test)

> The detailed, prioritized, per-dialog/label/test GUI build backlog moved to its own doc:
> **[`NFT_GUI_PLAN.md`](NFT_GUI_PLAN.md)**. The items below are the checklist-level summary.

- [x] **Land the NFT dialogs** (`nftdetaildialog.*`, `nftmintdialog.*`, `nftsenddialog.*`). **Done** (LANDED, still UNCOMMITTED `??` — commit them before they're lost).
- [ ] **Add an "attach the file you have" affordance** (G-VIEW, the worst gap) — a `getOpenFileName` on the detail dialog → `ContentEngine::cachePut(docHashHex, path)` → re-poster, so a RECEIVED NFT can reach the green verify badge. Today `cachePath=''` forever for anything not minted in-session.
- [ ] **Decide & enforce the nft=true `document_hash` requirement** so a hash-less NFT is not permanently unverifiable (GUI guard + daemon-side requirement).
- [ ] **Add L1 widget flow tests** for the now-landed dialogs (mint Create-gating + fingerprint streaming + privacy-drop reject + 0-conf terminal + in-flight `closeEvent` swallow; send recipient 4-state + verifyState==2 mismatch send-guard; detail VERIFIED/MISMATCH badge copy). Needs a `mintNFT`/`sendNFT` test-injection seam. See `NFT_GUI_PLAN.md`.
- [ ] **Make `refreshNFTs` show a 0-conf pending card** (not gated solely on `curBlock != lastBlock`, `rpc.cpp:1309`).
- [ ] **Add a unit test pinning `getExplorerTxURL` scheme + testnet `''` sentinel.**
- [ ] **Add in-app NFT help/onboarding** (G-HELP): first-run Collections intro + What's-This on the verify badge ("matches fingerprint ≠ genuine/official") + permanence/public-ledger warning on mint + pending/no-bytes/0-conf explanations. See `NFT_GUI_PLAN.md`.
- [ ] **Surface provenance**: call `zslp_listtransfers` in the detail dialog (today it's advertised but never called) and display the `zslp_gettoken` Set/Creator the back-fill already reads.
- [ ] **Optional: add a daemon content/metadata-fetch+verify RPC** so non-GUI clients can resolve `document_url`/`document_hash`.

### P1 — Mint completeness

- [ ] **Add `zslp_burn`** (send-to-unspendable / amount-to-no-output) as a sanctioned, anti-burn-aware destroy primitive + help + `client.cpp` entry + gtest + doc.
- [ ] **Decide & document the `zslp_mint` (fungible re-issue) UX**: either add a GUI affordance or explicitly document it as CLI-only.

### P2 — Shield (the codec + 3 RPCs LANDED in the daemon; close the rest + build GUI)

> **2026-06-06 correction:** the codec is compiled, has a gtest, and `z_senddatafile` /
> `z_listdatatransfers` / `z_getdatatransfer` are built + registered + arg-converted +
> gated default-OFF. The earlier "not compiled / dead code / RPCs absent" framing was stale.

- [x] **Add `src/datachannel/zdc.{cpp,h}` to `src/Makefile.am`.** **Done** (`Makefile.am:248,295`).
- [x] **Wrap the ZDC harness as a gtest target.** **Done** (`src/gtest/test_zdc.cpp` exists). Remaining: confirm it gates nonce-uniqueness/AEAD round-trip in CI (test cell 🟡).
- [x] **Build the default-OFF master gate `-datachannel` throwing `-32601`.** **Done** (`RegisterDataChannelRPCCommands` registers only when on; `init.cpp:527`; default 0). Remaining: a test asserting off→-32601.
- [x] **Build `z_senddatafile`** (requires `acknowledge_permanent=true`) + `client.cpp` entry. **Done** (`datachannel.cpp:215`, registered `:704-711`, `client.cpp:138`). Remaining: regtest round-trip test.
- [x] **Build `z_listdatatransfers` + `z_getdatatransfer`** (+ arg-convert). **Done** (`datachannel.cpp:430,471`, registered `:704-711`, `client.cpp:139`). Remaining: regtest round-trip test + ERR_NO_KEY/ERR_AEAD_FAIL mapping test.
- [ ] **Build `z_revealkey`** (seal-then-reveal trigger) + **`zslp_mint_private`** (document_hash = ciphertext_fingerprint) — still absent (not in the datachannel command table).
- [ ] **Deepen + test `acknowledge_permanent` + shielded-from/to validation** on every sending RPC.
- [ ] **Add DoS governance**: 64KB policy cap (`-datachannelmaxbytes` clamped 256KB), token-bucket rate limit, 72h inbound TTL-GC, 256 max-inflight.
- [ ] **Apply the GUI binary-safe memo read fix** (`zcl-qt-wallet/src/rpc.cpp ~756`: sniff `0x5A,0x44,0x43,0x31` on the 512-byte QByteArray before any QString conversion) → route binary frames to a data-channel inbox.
- [ ] **Build the GUI private-mint / private-send / private-receive surface** + flip `isPrivateMintWired()` only when the daemon RPCs exist.
- [ ] **Add a "let someone verify this privately" GUI wrapper** over the existing `z_exportviewingkey`, and enforce the per-item single-use-zaddr convention in `zslp_mint_private`/`z_senddatafile`.
- [ ] **Document the consensus limit in UX copy**: ownership stays a public ZSLP UTXO; key-possession cannot stop a prior holder keeping a copy (no DRM).

### P3 — Sell (daemon BUILT + regtest-proven; GUI greenfield)

- [ ] **Add the OP_RETURN carrier**: a thin RPC or a `createrawtransaction` `data` output (or port `op_return_push.h`) — `createrawtransaction` confirmed cannot emit OP_RETURN today, which a fill tx needs.
- [ ] **Build `nft_makeoffer`** (seller signs ONLY `vin[0]` = the live, CONFIRMED token UTXO with `ALL\|ANYONECANPAY` over the COMPLETE fixed 3-output template — OP_RETURN ZSLP SEND@vout[0] / buyer NFT dust@vout[1] / seller ZCL payout@vout[2], dust value FEE-RATE-DERIVED; a single-input `ALL\|ANYONECANPAY` sign on the complete template returns `complete:true`; lock the NFT outpoint) — add a **wallet NFT-outpoint lock/unlock API** (lock on offer, release on cancel) on top of the existing passive anti-burn. See `NFT_SELL_DESIGN.md §2`. (NOT SINGLE\|ANYONECANPAY: SINGLE would pin vout[0]=OP_RETURN, not the payout, and burn the seller NFT.)
- [ ] **Build `nft_verifyoffer`** on `decoderawtransaction`: confirm `vout[0]` is a ZSLP SEND for the tokenid crediting `vout[1]`, `vin[0]` is the live token UTXO, the `ALL`-pinned `vout[2]` price matches, SEND mapping credits the buyer, not expired/already-spent; re-run `WouldBeValid` BEFORE the buyer signs. Mandatory.
- [ ] **Build `nft_takeoffer`** (buyer appends funding `vin[1..]` only — **NEVER `fundrawtransaction`**, whose random change vout at `wallet.cpp:3698` AND any added output break the seller's `ALL` signature; the appended funding inputs MUST EXCLUDE ZSLP-protected outpoints (re-apply the anti-burn filter, else `ApplyTransaction` burns any token UTXO the buyer accidentally funds with); signs the buyer's own inputs `ALL\|ANYONECANPAY`; merge via CombineSignatures; broadcast via `sendrawtransaction`) + `nft_listoffers` + `nft_canceloffer`.
- [ ] **Add regtest RPC test** for the full make→verify→take→settle swap (transparent legs atomic).
- [ ] **Build the GUI marketplace** (offer-cards grid reusing ContentEngine, "List for sale" modal, "Buy" confirm, cancel, honest "settles publicly — no privacy on a transparent trade" copy) + L0/L1 tests. Per-dialog/label/test breakdown in `NFT_GUI_PLAN.md` (§ SELL).
- [x] **`doc/nft/NFT_SELL_DESIGN.md` exists** at design fidelity (offer payload format, `ALL\|ANYONECANPAY` pinning rules, verify checklist, footguns). Remaining: bring it to `MINT_TRANSFER_SPEC` build-spec fidelity + add a CLI walkthrough once the RPCs exist.

---

## 4. Definition of Done per pillar

A pillar is **shippable to real users** only when ALL of its boxes below are true.

### MINT — Done when:
- [ ] `zslp_genesis` (nft preset) is driven by an automated regtest RPC test that mints, then re-reads via `zslp_gettoken`, on a live chain (not just builders).
- [ ] `BuildAndCommitZSLP` (coin selection, anti-burn funding fence, change-LAST, pre-commit self-validate) is exercised by that test — not "code review only."
- [ ] The anti-burn predicate has a direct unit test.
- [ ] The HARD CONSTRAINT (OP_RETURN passes mainnet `IsStandard`/mempool, no fork) is test-proven.
- [ ] The GUI mint wizard is committed (not untracked) and has an L1 flow test.
- [ ] A new user can find it: README mentions NFTs + a CLI walkthrough exists.

### VIEW — Done when:
- [ ] All four read RPCs are exercised at the RPC layer (shapes + error paths), including `zslp_listmytokens` aggregation.
- [x] The gallery + detail dialog are landed... **but NOT yet** committed or L1-tested end-to-end (only the no-bytes terminal has an L1 test; the verified/mismatch badge mapping, mint, and send dialogs have ZERO widget tests). Remains open.
- [ ] A freshly minted token shows a pending card immediately (0-conf), and there is a built path to supply local bytes so a **received** card can reach "verified" (G-VIEW — the attach-local-bytes affordance does NOT exist today).
- [ ] In-app help explains the verify badge ("matches fingerprint ≠ genuine/official") and the pending/no-bytes/0-conf states; README + a user how-to document the GUI flow. (G-HELP — entirely absent today.)
- [x] No web browser is used anywhere (true — keep it true: no QtWebEngine/QtMultimedia, `document_url` never auto-fetched).

### SHIELD — Done when:
- [x] ZDC1 is compiled into the daemon (`Makefile.am:248,295`) and has a gtest target (`src/gtest/test_zdc.cpp`). **Done** (confirm it's a permanent CI gate).
- [ ] `z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer` exist + are CLI-arg-converted + default-OFF behind `-datachannel` (**these three DONE**); `z_revealkey` + `zslp_mint_private` still absent; and a regtest round-trip test (send a file privately → list → assemble → hash-verify) is still owed.
- [ ] `acknowledge_permanent` + shielded-from/to validation + DoS caps/TTL-GC are enforced daemon-side and tested.
- [ ] The GUI binary-safe memo read fix is applied; a private NFT can be minted, sent to a z-addr, received, and decrypted-in-gallery; `isPrivateMintWired()` flipped true.
- [ ] UX copy states the honest consensus limit (public ownership UTXO, no DRM).
- [ ] Selective disclosure via `z_exportviewingkey` has an NFT-privacy test and a GUI wrapper.

### SELL — Done when:
- [ ] An OP_RETURN-carrying fill tx can be built (carrier RPC/path exists).
- [ ] `nft_makeoffer` / `nft_verifyoffer` / `nft_takeoffer` / `nft_listoffers` / `nft_canceloffer` exist with `client.cpp` entries, a wallet outpoint lock/unlock lifecycle, and the `fundrawtransaction` footgun guarded against.
- [ ] A regtest test proves a full transparent make→verify→take→settle swap is atomic for the coin legs and correctly attributes the token to the buyer.
- [ ] The GUI marketplace (list / browse / buy / cancel) is built, L0/L1-tested, with honest "settles publicly" copy.
- [ ] `doc/nft/NFT_SELL_DESIGN.md` is brought to build-spec fidelity + a CLI walkthrough exists. (`ONCHAIN_TRADES.md` is already reconciled — SUPERSEDED banner + stale-claim corrections.)
- [ ] Docs state plainly: any shielded leg cannot be atomic on existing consensus (transparent-only trustless trade).

---

*Generated from a read-only audit of the daemon (`feature/zslp-nft-indexer`, uncommitted) and GUI (`zcl-qt-wallet`) trees. The NFT GUI dialogs (formerly in-flight, workflow `wnr918pfq`) have LANDED and are graded as real-but-mostly-untested code; the GUI build backlog lives in [`NFT_GUI_PLAN.md`](NFT_GUI_PLAN.md). Last refreshed 2026-06-06.*
