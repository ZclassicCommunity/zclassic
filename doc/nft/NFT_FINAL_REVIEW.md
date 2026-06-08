# NFT Feature — Final Whole-Feature Review

> **REMOVED — shielded data channel / on-chain private files.** The "Shield" pillar and ZDC1 data
> channel reviewed below (`z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer`, the
> `-datachannel` option, the ZDC1 codec, `src/datachannel/`) have been **removed entirely** from
> the daemon. ZClassic deliberately provides **no wallet path to store arbitrary files on-chain**.
> NFT content is always off-chain, bound to the token only by a `document_hash` fingerprint. Treat
> every Shield / private file / ZDC1 finding below as **historical**.

> **Scope:** The first review possible now that all four pillars coexist in one tree.
> Coin is **ZCL (ZClassic)**, never ZEC. The NFT system is a **non-consensus ZSLP overlay**:
> old/unmodified nodes relay and mine every one of these transactions unchanged; security
> comes from honest wallets **re-validating deterministically**, not from the chain rejecting
> bad transactions. *A forgery can be mined, but it credits nobody.*
>
> **Read this as:** ground-truth status as of the working tree on `feature/zslp-nft-indexer`
> (daemon) and `feature/nft-gallery` (GUI). All claims below are sourced to `file:line`.
> This document is READ-ONLY synthesis; it changes no code.

---

## 1. One-screen verdict — the four pillars as a UNIT

**Overall: dev/testnet-ready. NOT mainnet / real-user / money-at-stake ready.**

All four pillars are real, reachable, and **compiled** (daemon `src/Makefile.am:225-345`;
GUI `zcl-qt-wallet.pro:49-88`). The **daemon** ZSLP/ZDC/offer code is now **committed** on
`feature/zslp-nft-indexer`; merging the NFT track into the release line is still pending.

| Pillar | Daemon RPC | Native GUI | Cross-party / cross-node | Tests | Unit verdict |
|---|---|---|---|---|---|
| **MINT** | built (`zslp_genesis`/`mint`/`send`) | built, wired (`mainwindow.cpp:3022,3178,3191`) | n/a (on-chain, public) | gtest + shell regtest | **usable (transparent)** |
| **VIEW** | built (`gettoken`/`listtokens`/`listtransfers`/`listmytokens`) | built incl. **attach-file verify** (`nftdetaildialog.cpp:164,490,552`) | reads public chain | L0 strong, L1 ~1 test | **usable (transparent)** |
| **SELL** | built (`nft_makeoffer`/`verifyoffer`/`takeoffer`/...), ALL\|ANYONECANPAY atomic swap | **NONE** (greenfield) | swap shape correct; CI proof = same-node only | 6 gtests + shell regtest | **CLI-only / not user-facing** |
| **SHIELD** | built (`z_senddatafile`/`list`/`get`), default-OFF `-datachannel` | **NONE** (greenfield) | **structurally impossible today** (#117) | 25 codec gtests; **0 cross-RPC seam tests** | **sender-same-session only** |

**Bottom line for a non-technical user with money:**
- They **can** mint and view/verify a transparent NFT end-to-end from the wallet.
- They **cannot** sell an NFT from the wallet (no GUI), and they **cannot** send a private
  NFT to *anyone else* at all — the SHIELD retrieval path requires an in-process registry
  record that only the sending node has, this session only.
- The honest first user-facing release is **MINT + VIEW (transparent)**; SELL and SHIELD
  must be labeled CLI-only / experimental until a GUI exists and SHIELD cross-wallet
  receive is solved.

---

## 2. Cross-pillar security findings (SELL × SHIELD × MINT/indexer × anti-burn)

**Verdict: APPROVE.** The pillars compose without opening a burn/grief/mis-credit vector.
The anti-burn fence is correct and defense-in-depth, independent of UI locks.

- **SHIELD never touches token UTXOs — clean.** `z_senddatafile` funds *only* from Sapling
  notes (`asyncrpcoperation_senddatafile.cpp:171,175-177`), change goes back to the z-addr
  (`:248`), and its tx has no `vout[0]` OP_RETURN, so `CZSLPIndexer::ParseTx` returns false
  and the indexer spends nothing token-bearing. SHIELD is fully isolated from the ledger.
- **Sell swap is indexed identically to a normal SEND — no mis-credit.** The swap tx is a
  canonical ZSLP SEND at `vout[0]` crediting `vout[1]` (buyer NFT); same
  `ParseTx`/`ApplyTransaction` seam, conservation `availIn==requiredOut==1`
  (`nftoffer.cpp:570-580`; `zslpindexer.cpp:220-319`; `zslpstore.cpp:548-592`). `takeoffer`
  re-runs the production parse + `WouldBeValid` before broadcast (`nftoffer.cpp:937-958`).
- **Buyer funding cannot grief/burn a token — triple-fenced.** Explicit `fundingInputs`
  rejected if protected (`:820`); auto-select uses `AvailableCoins(fExcludeZSLPTokens=true)`
  + re-check (`:847`); the confirmed-truth branch matches *any* tokenId via the global store
  (`zslpwallet.cpp:107-112`), catching even a *different*-token funding burn the per-token
  conservation check would miss; a final pre-broadcast post-check re-asserts no `vin[k>=1]`
  is a token UTXO (`nftoffer.cpp:943`); `WouldBeValid` enforces exact conservation.
- **LockCoin / anti-burn / cancel compose correctly — no double-unlock.** `makeoffer`
  LockCoins (idempotent); `cancel` UnlockCoins then self-sends, re-locking on builder
  failure (`nftoffer.cpp:1104-1107`); `ScopedTokenLock` RAII unlocks on every exit and the
  pinned NFT is excluded from the scoped set (`zslpwallet.cpp:227-245`).
- **Anti-burn does NOT depend on the offer lock.** A user `lockunspent`-unlock (or a restart,
  which clears all in-memory locks) does **not** create a burn vector: every normal
  t-send / shield path uses `AvailableCoins(fExcludeZSLPTokens=true)`, which drops the
  confirmed NFT via `ZSLPIsProtectedTokenOutpoint` independent of lock state
  (`wallet.cpp:3197-3199`). The lock is advisory convenience only.

**Two cosmetic / honesty notes (no fund risk):**
- *nit:* stale offer locks persist in the SELLER's wallet after a counterparty fills the
  offer, until restart — inert (outpoint no longer exists), only clutters `listlockunspent`
  (`nftoffer.cpp:630,1021-1031`).
- *minor:* SHIELD on-chain bloat is bounded **only by ordinary fee economics** (identical to
  any large memo tx). `ZdcRateGuard` (4/s) and `ZDC_MAX_INFLIGHT(256)` are **single-node
  RPC** DoS guards, **not** network/per-block anti-spam. The real mitigation is default-OFF
  `-datachannel`. Document this honestly in PRIVACY/THREATS; do not read the rate guard as
  consensus/relay protection (`datachannel.cpp:86-91` caps, `:133-140` rate guard, `:713-722` registration gate).

---

## 3. Private-NFT composition — status + minimal path to make it real

**Status: COMPOSABLE-MANUALLY (CLI, 2 steps), but the verify-before-decrypt guarantee it
sells does NOT compose for the audience it is meant for.**

**What genuinely works (byte-compatible loop):**
`z_senddatafile` → `fingerprint` (64-hex, `datachannel.cpp:301,365`) → `zslp_genesis
document_hash=<fingerprint>` (stored unreversed, round-trips through the double byte-order
reversal so `zslp_gettoken.documenthash == fingerprint`, `zslp.cpp:377-391`, `slp.c:248-250`,
`zslpindexer.cpp:254`, `uint256.cpp:25`) → `z_getdatatransfer verify_fingerprint=<documenthash>`
which refuses plaintext unless the on-chain ciphertext SHA-256 equals it
(`datachannel.cpp:453-458,540-565`). The docs (`NATIVE_NFT_GUIDE §3.3`) describe this
accurately. `zslp_mint_private` is speced but **unnecessary** — a `transfer_id==token_id`
binding is impossible (genesis txid unknown at send time), so the random-transfer_id
fingerprint is the correct anchor.

**Why it is not real for the intended audience (two `major` gaps):**
1. **verify-before-decrypt is unreachable for any viewer who is not the sender's same session.**
   `z_getdatatransfer` hard-throws *"transfer not found in this node's registry"* whenever the
   transfer is not in the in-process, non-persisted `g_zdcTransfers` map
   (`datachannel.cpp:484-486`, populated only by `z_senddatafile` this session). The
   holder/buyer/auditor who has the published `document_hash` + on-chain frames + key has
   **no reachable verify path**. This is #117 surfacing inside the composition. — *Verified
   verbatim at `datachannel.cpp:484-486`.*
2. **End-to-end composition is exercised NOWHERE.** Both regtests mint with a hardcoded dummy
   `document_hash` (`...0001` / `...00aa`; `zslp-nft-regtest.sh:152`,
   `nft-sell-regtest.sh:129`) — never a real fingerprint. `grep` over `qa/` finds zero
   `z_senddatafile` / `z_getdatatransfer` / `-datachannel` usage. The 25 zdc gtests cover the
   codec in isolation; the cross-RPC seam — the actual private-NFT claim, crossing three files
   with a double byte-order reversal — is **untested**, which is exactly where a silent
   regression hides.

**Minimal path to make private-NFT composition REAL (in priority order):**
1. **Make `z_getdatatransfer` registry-free when `verify_fingerprint` is supplied** (+ key +
   address): scan wallet Sapling notes for the `transfer_id`, recompute the ciphertext
   fingerprint, gate on `== verify_fingerprint`, then decrypt with the caller-supplied key —
   i.e. make `haveRec` optional iff `verify_fingerprint` is present. This is the single change
   that makes "verify the document_hash == ciphertext fingerprint BEFORE decrypting" true for
   someone other than the original sender. (Subsumes #117 retrieval for the verify-then-open
   case; the full key-delivery problem in §5 is the remaining half.)
2. **Add a cross-RPC regtest** (`-datachannel -zslpindex`): `FP=$(z_senddatafile).fingerprint`;
   `TID=$(zslp_genesis {nft,document_hash:FP}).tokenid`; assert
   `zslp_gettoken(TID).documenthash == FP`; mine; assert `z_getdatatransfer(verify_fingerprint=FP)`
   returns verified + correct hexdata, and a **wrong** fingerprint returns
   `ERR_HASH_MISMATCH` with **no plaintext**.
3. *minor:* "mint a private NFT" needs BOTH `-zslpindex` and `-datachannel` on and is silent if
   either is off (`zslp.cpp:361`, `datachannel.cpp:608-609`). Acceptable for CLI; wire the
   fingerprint hand-off in the eventual SHIELD GUI so no hex is copied by hand.

---

## 4. Whole-feature honesty sweep — overclaims to fix

The **MINT / VIEW / SELL verify-badge and uniqueness copy is rigorously honest** — the green
check explicitly disclaims "genuine/official/authorized," `nft_verifyoffer` calls itself a
*mandatory* buyer check, SELL copy says trust-minimized (not trustless), and
`SECURITY_MODEL §5` / `GUIDE §4` carry an explicit "what this does NOT do" list. **Keep this
copy as the bar for the SHIELD GUI when it lands.** The honesty failures are concentrated in
the **SHIELD/private** surface and in stale docs:

**Major overclaims (fix before any "NFT release" marketing):**
- **README headline sells private NFTs as a delivered, two-party feature.** First sentence:
  *"…and — uniquely — **private** NFTs over the shielded pool."* (`README.md:3-5`, verified).
  Reality: cross-wallet recipient retrieval is impossible (#117, `datachannel.cpp:484-486`)
  and there is no GUI (`RPC::isPrivateMintWired()==false`, `zcl-qt-wallet/src/rpc.h:241`).
  The build-status blockquote partially corrects this, but the lead reads as shipped.
  **Fix:** scope it honestly, e.g. *"(experimental, sender-side today) confidential
  file/asset delivery over the shielded pool,"* or drop "uniquely private NFTs" from the lead.
- **GUI "ownership is shielded" / green Private pill overclaim shielded ownership that does
  not exist.** `nftdetaildialog.cpp:217-219` renders *"Private — only you can see this. Its
  ownership is shielded,"* `nft.h:28` defaults `isPrivate=true` ("shielded provenance"). ZSLP
  NFT ownership is **always transparent/public** (the token rides transparent dust;
  acknowledged at `rpc.cpp:964`). The real load path forces `isPrivate=false` (`rpc.cpp:965`)
  so users don't *see* it today, but the claim text + green-pill machinery + default+comment
  are live code asserting a capability that exists nowhere. **Fix:** remove/gate the pill,
  flip `nft.h:28` to false, fix the comment; if SHIELD ships, the honest claim is the *asset
  bytes* are confidential, never that *ownership* is shielded.
- **GUIDE §3.2/§3.3 invents a disabled-state error and an `-experimentalfeatures` gate the
  daemon doesn't implement.** Guide quotes the gate as `fExperimentalMode && -datachannel`
  with a custom *"Data channel is disabled… -experimentalfeatures -datachannel…"* message
  (`NATIVE_NFT_GUIDE.md:560-563,592`). As built, `RegisterDataChannelRPCCommands` gates only
  on `-datachannel` (`datachannel.cpp:713-722`), no `-experimentalfeatures`, and when off the
  methods are simply **absent** → generic `-32601`, no custom text. **Fix:** make doc and code
  agree (drop `-experimentalfeatures` from the doc, or add it to the code).

**Minor / nit honesty items (stale/front-door docs and help text):**
- *minor:* `PRIVACY.md:51-53,92` states the file cap as ~64 KB; as-built cap is **40000 bytes**
  (`datachannel.cpp:86`). Correct to 40000 / ~40 KB.
- *minor:* `PRIVACY.md:54-59,96-99` lists "Seal now, reveal later" and "Private NFTs
  (ownership shielded)" as capabilities; `z_senddatafile` always sets `include_key_frame=true`
  (`datachannel.cpp:346`), `z_revealkey` is "designed, not built" (GUIDE §3.3), and
  ownership is transparent. Mark designed/not-built or fold PRIVACY.md into the guide.
- *minor:* `GUIDE §3.2` quotes permanence + shielded-funding error strings the code does not
  emit (real strings at `datachannel.cpp:269-271` and `asyncrpcoperation_senddatafile.cpp:84-105`;
  the shielded-from check is in the async op, not synchronous). Substance is honest; fix the
  quoted strings/locations.
- *minor:* `z_getdatatransfer` help reads as general recipient retrieval but the registry gate
  makes it sender-session-only (`datachannel.cpp:414-416` vs `:484-486`). Add the one-line
  caveat `z_listdatatransfers` already has (`:379`).
- *nit:* `z_senddatafile` help leads with "Send a PRIVATE file" then honestly discloses
  permanence two lines down (`datachannel.cpp:166-170`). Optionally soften "PRIVATE" to
  "confidential."

---

## 5. SINGLE prioritized remaining-work list to reach real-user-shippable

De-duplicated across **#112** (pre-mainnet hardening), **#117** (SHIELD cross-wallet receive),
**#118** (GUI backlog), and items newly surfaced by this whole-feature review. Each item has a
severity and a binary done-criterion.

### BLOCKERS — cannot ship to real users until all are done

1. **Commit the entire NFT feature on both repos.** *(blocker; tracking-only)*
   The whole daemon write/sell/shield path + every GUI NFT dialog are untracked/unstaged
   (daemon: 19 modified + 18 untracked incl. `src/datachannel/`, `src/rpc/{nftoffer,datachannel}.cpp`,
   `src/wallet/zslpwallet.*`, `src/wallet/asyncrpcoperation_senddatafile.*`, `doc/nft/`, `qa/zslp/`;
   GUI: nft*dialog + `M rpc/contentengine`). A bad checkout loses everything.
   **Done when:** daemon `feature/zslp-nft-indexer` and GUI `feature/nft-gallery` have all NFT
   files committed; `git status` shows no untracked NFT sources.

2. **Decide v1 scope; do not market SELL/SHIELD as user features without a GUI.** *(blocker)*
   SELL and SHIELD are CLI/daemon-only — `grep` of the GUI tree finds **no**
   `makeoffer`/marketplace/`senddatafile` caller. A non-technical user cannot sell or privately
   send an NFT from the wallet at all.
   **Done when:** either (a) the release ships/markets **MINT+VIEW (transparent)** only, with
   SELL/SHIELD explicitly labeled CLI-only/experimental in README + GUIDE; **or** (b) the Sell
   and Shield GUIs (`NFT_GUI_PLAN §C/§D`) are built, wired, and L1-tested.

3. **Make SHIELD work across wallets/nodes (#117) — or label it sender-side experimental.** *(blocker)*
   The per-transfer AEAD key lives only in a process-local, never-persisted `std::map`
   (`datachannel.cpp:111,353`); `z_getdatatransfer` hard-requires a local record before it
   decrypts (`:484-486`, verified). A recipient on another wallet/node has no key and gets a
   flat refusal. "Send a private NFT to someone" does not work.
   **Done when:** (a) the recipient can obtain the key (on-chain encrypted KEY frame openable
   by their ivk, or out-of-band selective disclosure) AND `z_getdatatransfer` can decrypt from
   chain+ivk without a local sender record (this is the same change as §3 step 1); (b) a
   **two-wallet/two-node regtest** proves round-trip receive; **until done,** README/GUIDE/help
   say "sender-side experimental."

### MAJOR — required for money-at-stake confidence

4. **Make verify-before-decrypt reachable for non-sender viewers.** *(major; subset of #3 step a)*
   See §3 step 1. **Done when:** `z_getdatatransfer` with `verify_fingerprint` (+key+address)
   verifies the on-chain ciphertext hash and decrypts without a registry record; wrong
   fingerprint → `ERR_HASH_MISMATCH` and no plaintext.

5. **Add the cross-RPC private-NFT regtest (the composition is exercised nowhere).** *(major)*
   See §3 step 2. **Done when:** a CI-gated regtest runs `z_senddatafile` → `zslp_genesis
   document_hash=<fingerprint>` → `zslp_gettoken` equality → `z_getdatatransfer
   verify_fingerprint` happy + mismatch, all green.

6. **Add a CI-run write-path + two-node settlement test.** *(major)*
   `BuildAndCommitZSLP` (coin selection, anti-burn fence, sign, self-validate, commit) is
   covered "by code review only" (`test_zslp_wallet.cpp:25`); the shell regtests are manual and
   the sell regtest buys from a **second address in the same node** (`nft-sell-regtest.sh:22`),
   so true cross-party atomic settlement is unproven.
   **Done when:** a CI regtest mints, sends to a **second node's** wallet, re-reads via
   `zslp_listmytokens` there, and runs make→verify→take→settle across two nodes — green in the
   gate.

7. **Add L1 (widget) coverage for the honesty-critical GUI paths.** *(major; part of #118)*
   Only one NFT widget test exists (`tst_widget.cpp:1869`); `NftMintDialog`/`NFTSendDialog` are
   never constructed in any test, and there is no `RPC::mintNFT`/`sendNFT` test-injection seam.
   **Done when:** `testSetNextMintResult`/`testSetNextSendResult` seams exist and L1 tests cover
   mint create-gating/streaming/0-conf, the send 4-state + `verifyState==2` mismatch guard,
   attach match/mismatch, and VERIFIED/MISMATCH badge copy.

8. **Turn #112 pre-mainnet hardening into an explicit, binary checklist.** *(major)*
   No hardening/TODO markers exist in the ZSLP sources; the no-fork HARD CONSTRAINT is tested
   only at `IsStandardTx` level (`test_zslp_wallet.cpp:538`, which itself notes it does not call
   `AcceptToMemoryPool` with a live UTXO view).
   **Done when:** #112 enumerates and ticks: (a) live public-testnet soak of mint/send/swap;
   (b) full `AcceptToMemoryPool`/relay test on **mainnet** `CChainParams`; (c) gtest for
   indexer migration + reconnect idempotence + multi-token mixed-input silent-burn; (d) fuzz
   the `slp.c` parser + zdc codec — each with a pass/fail criterion.

9. **Fix the SHIELD/private overclaims in front-door surfaces.** *(major; honesty)*
   See §4 — README headline, GUI "ownership is shielded" + green Private pill (`nft.h:28`
   default), and GUIDE §3.2 invented error/gate.
   **Done when:** README lead is scoped to "experimental sender-side confidential delivery";
   the shielded-ownership claim + green pill are removed/gated and `nft.h:28` defaults false;
   GUIDE §3.2/§3.3 match the actual `-datachannel`-only gate and generic `-32601`.

### MINOR — quality / completeness, not ship-blocking for a MINT+VIEW v1

10. **VIEW provenance: `zslp_listtransfers` is never called from the GUI** (`zslp.cpp:155`
    built; no GUI caller). Add `RPC::nftTransfers` + a compact timeline; show the Set/Creator
    already read and discarded (`nftdetaildialog.cpp ~326`). **Done when:** the detail dialog
    shows chain-of-custody from `zslp_listtransfers`.
11. **MINT: no sanctioned burn primitive (`zslp_burn`).** Editions can never be intentionally
    retired; combined with permanence, a typo'd mint is unfixable. Add anti-burn-aware
    `zslp_burn` + `client.cpp` entry + gtest + a mint-dialog permanence warning above Create.
    **Done when:** `zslp_burn` exists, tested, and the mint dialog warns about permanence.
12. **SHIELD daemon completeness:** `z_revealkey` (seal-then-reveal) and `zslp_mint_private`
    are unbuilt (NOT in the datachannel command table `datachannel.cpp:704-711`); no GUI wrapper over `z_exportviewingkey`.
    **Done when (after #3/#4):** either build them, or document the as-built 2-step path as the
    canonical recipe. *Note: DoS caps ARE built (cap `:84`, inflight `:86`, TTL-GC,
    rate-limit `:88-89`) — re-grade the stale "DoS unbuilt" rows.*
13. **Honesty doc cleanups (§4 minors/nits):** PRIVACY.md 64KB→40000B; mark seal-then-reveal &
    shielded-ownership as designed/not-built; fix GUIDE §3.2 quoted error strings; add the
    sender-session caveat to `z_getdatatransfer` help; optionally soften `z_senddatafile`
    lead. **Done when:** each stale string matches the as-built daemon.
14. **Docs↔code reconciliation pass.** Mark G-VIEW (attach-file **built**), G-HELP (9
    `setWhatsThis` **built**), DoS governance (**built**), and the IsStandard HARD CONSTRAINT
    test (now exists, `test_zslp_wallet.cpp:538`) as landed in
    `NFT_FEATURE_CHECKLIST.md`/`NFT_GUI_PLAN.md`/`CAPABILITY_MAP.md`; keep **one** status table
    (`GUIDE §1`) as canonical. **Done when:** the checklist no longer mis-states readiness in
    either direction.

### NIT — cosmetic

15. Stale offer locks in the seller's wallet after a fill (`nftoffer.cpp:630,1021-1031`) —
    optionally `UnlockCoin` when `nft_listoffers` recomputes filled/expired.
16. Document SHIELD on-chain bloat is bounded only by ordinary fee economics and the rate guard
    is single-node, not network-level (PRIVACY/THREATS).

---

## Appendix — finding tally

- **Blockers: 1** (SELL+SHIELD have zero GUI / scope-not-user-ready). *(Two earlier
  "blockers" are now resolved: the daemon tree is committed, and SHIELD cross-wallet receive
  is built via the registry-free reconstruct-from-chain path, `datachannel.cpp:568-600`.)*
- **Majors: 8** (verify-before-decrypt unreachable; composition tested nowhere; README
  headline overclaim; GUI shielded-ownership overclaim; GUIDE §3.2 invented gate/error; no CI
  write-path/two-node settlement test; no L1 GUI coverage; #112 unscoped).
- **Cross-pillar security: APPROVE** — no burn/grief/mis-credit vector across SELL × SHIELD ×
  MINT/indexer × anti-burn.
- **Private-NFT status: COMPOSABLE-MANUALLY** (byte-compatible 2-step CLI loop; the
  verify-before-decrypt guarantee does not yet compose for non-sender viewers).
