# NFT API / UX / DRY Audit + Refactor Punch List

> **REMOVED — shielded data channel / on-chain private files.** Audit items below that reference
> the shielded data channel (`z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer`, the
> `-datachannel` option, `rpc/datachannel.cpp`, the ZDC1 codec) are **obsolete**: that capability
> has been **removed entirely** from the daemon. ZClassic deliberately provides **no wallet path to
> store arbitrary files on-chain**.

Status: read-only audit converted to an actionable, prioritized punch list. No code changed by this document.

Scope:
- Daemon: `/home/rhett/github/zclassic` (C++11), branch `feature/zslp-nft-indexer` — carries ALL ZSLP/NFT code in the working tree.
- GUI: `/home/rhett/github/zcl-qt-wallet` (C++14), branch `feature/nft-gallery`.

Hard model (true, unchanged):
- The coin is **ZClassic / ZCL**. Zcash-lineage code identifiers (`zclassicd`, `z_sendmany`, `.zcash-params`, Sapling, `ivk`) keep their names, but the money a user holds, sends, or sells for is always **ZCL**.
- **ZSLP NFT ownership is ALWAYS PUBLIC.** Tokens ride transparent 546-sat dust UTXOs; who-owns-what and every transfer is fully visible on-chain. No item below makes ownership private, shielded, anonymous, or confidential.
- The **only** privacy technology in this feature is the **ZDC1 shielded data-channel**. It encrypts **FILE CONTENT** (the bytes) with ChaCha20-Poly1305 AEAD and ships the ciphertext inside Sapling shielded memos. It hides the payload and the data-transfer linkage — it does **not** hide token ownership.
- The NFT layer is a **non-consensus OP_RETURN overlay**. Old unmodified nodes relay and mine the OP_RETURN with no rule change; security comes from every honest wallet deterministically re-validating confirmed history. There is no consensus fork.

Built-vs-designed legend (each capability tagged exactly one):
**BUILT+TESTED** / **BUILT-CLI-ONLY** / **DESIGNED-NOT-BUILT** / **FUTURE-IDEA**.

Pillar status (for context — see the capability survey for detail):
- MINT / VIEW (`zslp_*`): **BUILT+TESTED** (RPC built, primitives gtested, GUI dialogs + L1 tests exist).
- SELL / TRADE (`nft_*`): primitives **BUILT+TESTED**; RPC dispatchers **BUILT-CLI-ONLY** (no direct gtest); GUI dialogs + L1 tests exist.
- SHIELD / PRIVACY (ZDC1 `z_*datafile` / `z_*datatransfer`): daemon **BUILT-CLI-ONLY** (codec gtested as ZDC); GUI **DESIGNED-NOT-BUILT** (zero GUI surface; `RPC::isPrivateMintWired()` hard-returns `false`).

Honesty review of the code as read: **clean.** User-facing copy says ZCL (never ZEC/Zcash); ownership-is-public is stated repeatedly and correctly; ZDC privacy is scoped to file content only ("public ciphertext", permanent); the non-consensus overlay framing is consistent. The findings below are engineering hygiene, not honesty defects.

---

## Priority key

- **P0** — correctness/coherence risk a user or integrator can hit, or a load-bearing safety guard that is copy-pasted (drift risk). Do first.
- **P1** — meaningful DRY/consistency/test-coverage win with clear payoff; no immediate user harm.
- **P2** — cleanup, dead-param removal, polish, aspirational-helper pruning.

Each item lists: the problem, the concrete fix, the file(s). Line numbers are as of this audit and may shift.

---

## Area A — API consistency (daemon RPC)

### P0

**A-1. `nft_listoffers` `mine` param is dead end-to-end.** *(was DEAD-1; verified both ends)*
- Problem: the daemon parses `onlyMine` then discards it — `(void)onlyMine;` with comment "every record in the local store is mine" (`src/rpc/nftoffer.cpp:1000-1002`), and the fetched `store` is also `(void)store;` (`:1042`, `:1064`). The GUI wrapper accepts `bool mineOnly`, does `(void)mineOnly;` (`zcl-qt-wallet/src/rpc.cpp:1384`), yet still sends `{"mine": mineOnly}` over the wire (`:1390`). So a filter is advertised in help and on the wire that does nothing — it implies a capability that does not exist.
- Fix: pick one. Either (a) honor the filter (record send/receive provenance and filter on it), or (b) drop `mine` from the RPC `help`, stop sending it from the GUI, and remove the `mineOnly` arg from `RPC::nftListOffers`. Given the receive path is not built (see A-7 / D-3), **(b) remove** is the honest choice for now.
- Files: `zclassic/src/rpc/nftoffer.cpp` (~`:993-1064`, help text); `zcl-qt-wallet/src/rpc.cpp:1371-1392`.

### P1

**A-2. Naming-family split: object-param vs positional-param surface.** *(API-1)*
- Problem: three prefixes, two param conventions. `zslp_genesis` takes an object (`src/rpc/zslp.cpp:326`); `zslp_mint`/`zslp_send`/`zslp_listtokens`/`zslp_listtransfers` take POSITIONAL params (`zslp.cpp:462,541,120,155`). All `nft_*` take a single object (`src/rpc/nftoffer.cpp`). All `z_*datafile`/`z_*datatransfer` take a single object (`src/rpc/datachannel.cpp`). A reader cannot predict the shape from the name.
- Fix: document the split prominently in each RPC `help` and in `doc/nft/README.md`; longer-term, accept an optional object form for `zslp_mint`/`zslp_send` so the write surface is uniformly object-style. Do NOT break the existing positional form (CLI users depend on it) — add the object form, keep positional.
- Files: `zclassic/src/rpc/zslp.cpp` (mint `:464`, send `:543`); `zclassic/src/rpc/client.cpp:136-158` (would need new conversion entries if object form is added); `zclassic/doc/nft/README.md`.

**A-3. `zslp_listmytokens` returns a different, smaller object than `zslp_listtokens`/`zslp_gettoken`.** *(API-4 — pairs with C-3)*
- Problem: `zslp_listtokens`/`zslp_gettoken` emit the full token via `TokenToJSON` (`documenturl`, `documenthash`, `genesisheight`, `totalminted`, `mintbatonvout`, `hasmintbaton`), but `zslp_listmytokens` hand-rolls a smaller object — only `tokenid,ticker,name,decimals,balance,addresses[]` (`zslp.cpp:~250-258`, verified). Crucially it omits `documenthash`, which is exactly why the GUI fires a second `zslp_gettoken` per token (see C-3). Two divergent shapes for "a token" is a drift hazard.
- Fix: have `zslp_listmytokens` embed the `TokenToJSON(token)` object (it already does `store->GetToken(...)` in the loop) plus the per-wallet `balance`/`addresses[]`. This makes the shapes consistent and is the server half of deleting the GUI's per-token batch (C-3).
- Files: `zclassic/src/rpc/zslp.cpp` (~`:245-262`; reuse the `TokenToJSON` helper in the same file).

**A-4. Inconsistent "not found" error mapping.** *(API-5 wart)*
- Problem: a missing token in `zslp_gettoken` throws `RPC_INVALID_ADDRESS_OR_KEY` (`zslp.cpp:103`) — semantically odd (the arg is a token id, neither an address nor a key). The `nft_*` cancel/not-found paths use `RPC_INVALID_PARAMETER`. Everything else is coherent (`RPC_MISC_ERROR` for index-off, `RPC_WALLET_INSUFFICIENT_FUNDS` for balance, `RPC_VERIFY_REJECTED` for a failed offer).
- Fix: map "token not found" to one consistent code across `zslp_*` and `nft_*`. `RPC_INVALID_PARAMETER` (the arg names a thing that does not exist) is the most defensible; align `zslp_gettoken:103` to it (or pick `RPC_INVALID_ADDRESS_OR_KEY` everywhere — just be consistent).
- Files: `zclassic/src/rpc/zslp.cpp:103`; cross-check `zclassic/src/rpc/nftoffer.cpp` not-found throws.

### P2

**A-5. `nft_takeoffer` `changeAddr` is a reserved no-op param.** *(DEAD-2)*
- Problem: help says "reserved for a pre-size prep tx (unused here)" (`nftoffer.cpp:758`); the param is accepted but ignored. Honest in help, but it is a no-op surface that can mislead integrators into thinking change routing is controllable.
- Fix: either implement the pre-size prep tx, or drop the param until it is. If kept as a forward-compat placeholder, keep the explicit "(unused here)" note.
- Files: `zclassic/src/rpc/nftoffer.cpp` (~`:758`, takeoffer help + parse).

**A-6. `client.cpp` arg-conversion map must stay lock-step with dispatcher signatures.** *(API-6 — note, not a bug)*
- Problem: `src/rpc/client.cpp:136-158` correctly converts arg0 for every object-param RPC and the numeric positional args of `zslp_mint`/`zslp_send`/`zslp_listtokens`/`zslp_listtransfers`; `z_listdatatransfers` (0 args) and string-only positionals correctly have no entry. No bug today — but it is a second place that silently breaks if a signature changes.
- Fix: add a one-line comment block at the table head pointing to the dispatcher files, and (if A-2 adds object forms) update entries in the same commit. Optional: a regtest assertion that each registered NFT RPC round-trips its documented arg shape.
- Files: `zclassic/src/rpc/client.cpp:136-158`.

**A-7. `z_listdatatransfers` advertises a `direction`/`status` vocabulary it never varies.** *(DEAD-3)*
- Problem: `ZdcDirToStr` is an identity passthrough — `static const char* ZdcDirToStr(const char* d){return d;}` (`datachannel.cpp:152`); `direction` is always literal `"sent"` (`:356`) and `status` always `"recorded"` (`:397`). There is no "received"/"complete" state because the receive path is not built. The RPC implies a richer state machine than exists.
- Fix: until a receive path lands, either drop the `direction`/`status` fields, or document them in help as "always 'sent'/'recorded' in this build; 'received'/'complete' are reserved for the unbuilt receive path." Remove the no-op `ZdcDirToStr` wrapper. Tag this surface **BUILT-CLI-ONLY** with reserved fields.
- Files: `zclassic/src/rpc/datachannel.cpp` (`:152`, `:356`, `:395-397`).

**A-8. ZDC file cap = 40000 bytes (RESOLVED — the stale "64 KB" comment is gone).**
- The built constant is `ZDC_MAX_FILE_BYTES = 40000` (`datachannel.cpp:86`), enforced at `:301` and `:319` (and re-checked in the frame guard at `:373`). The top-of-file comment now correctly states 40000 bytes (`:25`); the earlier "64 KB" comment no longer exists.
- Files: `zclassic/src/rpc/datachannel.cpp` (header comment block; `:84`).

---

## Area B — daemon DRY (shared helpers)

### P0

**B-1. Duplicated quantity/zat parsers — 3 copies, subtly divergent.** *(API-2)*
- Problem: three near-identical "string|int → unsigned, digits-only, overflow-guarded" parsers: `ParseQuantity` (`src/rpc/zslp.cpp:284`, rejects `>= 2^63`), `NftParseZat` (`src/rpc/nftoffer.cpp:103`, rejects `> MAX_MONEY`), and the GUI's `RPC::zclToZat` (`zcl-qt-wallet/src/rpc.cpp:1216`, the only float→zat path). The first two are byte-for-byte the same logic with one different bound and one different error string. Divergent bounds/messages in money parsers are a P0 drift hazard.
- Fix: extract one daemon helper (e.g. `ParseAmountField(v, field, maxInclusive, what)`) into `wallet/zslpwallet.h`/`.cpp` next to the already-shared `ZSLPTokenIdToBE`; have `ParseQuantity` and `NftParseZat` call it with their respective bounds. Leave the GUI's `zclToZat` as the single GUI-side path (it is tested — see C-2) but cross-reference it in a comment.
- Files: `zclassic/src/rpc/zslp.cpp:284`; `zclassic/src/rpc/nftoffer.cpp:103`; new home in `zclassic/src/wallet/zslpwallet.{h,cpp}`.

**B-2. Duplicated address/script + store-or-throw helpers, re-declared only to dodge a name clash.** *(API-3)*
- Problem: `ScriptForTAddr`+`FreshWalletScript` (`zslp.cpp:309,319`) are re-declared verbatim as `NftScriptForTAddr`+`NftFreshWalletScript`+`NftAddrFromScript` (`nftoffer.cpp:75,93,85`) purely to avoid a symbol clash in the same TU set. `GetZSLPStoreOrThrow` (`zslp.cpp:38`) and `NftGetStoreOrThrow` (`nftoffer.cpp:66`) are byte-identical. These are load-bearing (they build the actual scriptPubKeys for token carriers and the offer template) and copy-pasted.
- Fix: move one canonical set into `wallet/zslpwallet.h` (alongside `ZSLPTokenIdToBE`): `ZSLPStoreOrThrow()`, `ZSLPScriptForTAddr()`, `ZSLPFreshWalletScript()`, `ZSLPAddrFromScript()`. Delete both prefixed copies and call the shared ones. Confirmed call sites to repoint: `zslp.cpp` (`:38,98,121,158,205,309,319,361,422-423,446,485,523,526,566,574,585,631`) and `nftoffer.cpp` (`:66,75,85,93,360,366,474,487,494,496-497,689,764,867,994,1063,1096,1139,1159-1160`).
- Files: `zclassic/src/rpc/zslp.cpp`; `zclassic/src/rpc/nftoffer.cpp`; new home `zclassic/src/wallet/zslpwallet.{h,cpp}`.

---

## Area C — GUI DRY (the refactor core)

### P0

**C-1. In-flight / QPointer / Done-state async-dialog scaffold is copy-pasted 4-5x — the biggest DRY + safety win.** *(DRY-1)*
- Problem: the exact pattern { set `m_inFlight`; disable button + relabel "…ing"; `QPointer<Self>` guard across the async callback; on success switch the button to a terminal "Done" via `disconnect(SIGNAL(clicked()))` + reconnect to `onDoneClicked`; on error "Try again" + red result line; `closeEvent` swallow while in flight } is duplicated across `nftmintdialog.cpp:227-306`, `nftsenddialog.cpp:137-204`, `nftselldialog.cpp:190-389` (twice — make AND cancel), `nftbuydialog.cpp:355-425`. The `QPointer` guard is the **load-bearing UAF protection**; copy-pasting it means a future dialog can forget it (this exact UAF class has bitten before per project history).
- Fix: introduce a small `NftAsyncDialog` base (or a free helper taking the button + result label + two lambdas `{startFn, onResult}`) under `src/` that centralizes: in-flight latch, button relabel/disable, the `QPointer` guard, success→Done transition, error→Try-again, and the `closeEvent` swallow. Migrate all five flows onto it. Removes ~150 lines and makes the UAF guard impossible to omit.
- Files: new `zcl-qt-wallet/src/nftasyncdialog.{h,cpp}`; refactor `zcl-qt-wallet/src/nftmintdialog.cpp:227-306`, `nftsenddialog.cpp:137-204`, `nftselldialog.cpp:190-389`, `nftbuydialog.cpp:355-425`. (Note: `nftdetaildialog.cpp` also uses `QPointer` — evaluate whether it benefits.)
- Build constraint: the GUI is **C++14** (`zcl-qt-wallet.pro` `CONFIG += c++14`). Do NOT use `std::optional`/`std::string_view`; declare any header-signature types' includes in the header.

### P1

**C-2. `humanZcl` is a private, untested, bespoke money formatter living next to a tested canonical one.** *(DRY-2; pairs with E-3)*
- Problem: `NFTBuyDialog::humanZcl` (static; impl `nftbuydialog.cpp:408`, decl `nftbuydialog.h:76`) is a zat→display formatter used at `nftbuydialog.cpp:258,268,379`. It exists nowhere else and has **no test**. Meanwhile the canonical, L0-tested formatter is `Settings::getDecimalString` (`src/settings.cpp:377`), and the inverse `RPC::zclToZat` (`src/rpc.cpp:1216`) is L1-tested (`tst_widget.cpp:2450`). A bespoke untested money formatter next to a tested one is exactly the kind of drift that produces wrong on-screen amounts.
- Fix: delete `humanZcl`; format via the tested `Settings::getDecimalString` path (convert zat→ZCL through the same arithmetic `zclToZat` uses, or add a tiny tested `Settings::zatToDecimalString(qint64)` and route both the buy dialog and any future caller through it).
- Files: `zcl-qt-wallet/src/nftbuydialog.cpp` (`:258,268,379,408`), `nftbuydialog.h:76`; canonical home `zcl-qt-wallet/src/settings.cpp`.

**C-3. Per-token `zslp_gettoken` fan-out in `refreshNFTs` — a symptom of A-3.** *(DRY-4)*
- Problem: `refreshNFTs` calls `zslp_listmytokens` (`rpc.cpp:880`) then fans out one `zslp_gettoken` per listed token (Stage 2, `rpc.cpp:895-917`+) purely to recover `documenthash`/`genesisheight` that the list call omits. This doubles RPC round-trips per gallery refresh.
- Fix: land A-3 (server returns the full `TokenToJSON` object in `zslp_listmytokens`), then delete the Stage-2 batch and read the metadata straight off the list response.
- Files: `zcl-qt-wallet/src/rpc.cpp:824-984` (Stage 2 deletion); depends on `zclassic/src/rpc/zslp.cpp` A-3.

**C-4. Address-validator + public-trade copy duplicated across send/sell/buy.** *(DRY-3)*
- Problem: `nftsenddialog.cpp:109-126` and `nftselldialog.cpp:162-177` are the same 4-state validator ("That doesn't look like a ZClassic address." / "Looks good — public (transparent)" / needs-public / valid-z-but-unsupported) with identical strings and identical `Settings::isTAddress` gating in their `refresh*Enabled` (`nftsenddialog.cpp:114,116,132,141`; `nftselldialog.cpp:166,168,185,198`). Separately, the public-trade sentence "This trade settles publicly on-chain — the price and both addresses are visible…" is verbatim in `nftselldialog.cpp:115` and `nftbuydialog.cpp:114`. Duplicated strings double the translation entry and risk drift between dialogs.
- Fix: add one shared `nftValidateTAddrInto(QLabel* status, const QString& addr) -> bool` helper and one `QString nftPublicTradeNote()`; call from all three dialogs.
- Files: new helper in `zcl-qt-wallet/src/` (e.g. `nftcommon.{h,cpp}` or fold into the C-1 base); refactor `nftsenddialog.cpp:109-141`, `nftselldialog.cpp:115,162-198`, `nftbuydialog.cpp:114`.

### Note (no action — for the record)

**C-5. GUI does NOT duplicate daemon security logic — correct.** *(DRY-5)*
- The GUI never re-implements offer verification (delegates to `nft_verifyoffer`), conservation, or anti-burn; `zclToZat` is the only arithmetic it owns. No GUI-vs-daemon duplication of security logic. Keep it this way.

---

## Area D — error mapping + missing GUI wrappers

### Note (no action — clean)

**D-1. Honest error mapping verified clean.** `zclToZat`/`zslpCalmError` (`zcl-qt-wallet/src/rpc.cpp:1016`) maps -13/-6/-1 to calm sentences and passes the daemon's own message through otherwise — never fabricating success. Success callbacks check for empty txid/blob and surface "unexpected reply" rather than fake a result (`mintNFT` `:1092`, `nftMakeOffer` `:1270`). `nftJsonStr/Int/Bool` (`:846-869`) are SIGABRT-safe readers (const `operator[]` asserts under the shipped build's active C-asserts — the comment documents this correctly). No change needed.

### P1

**D-2. `nft_requestbuy` has no GUI wrapper and no GUI test.** *(COV-4)*
- Problem: `nft_requestbuy` is registered and CLI-mapped (`zclassic/src/rpc/client.cpp:158`) but there is no `nftRequestBuy` wrapper in `zcl-qt-wallet/src/rpc.cpp` (grep-confirmed absent). The buyer-address handshake is daemon/CLI-only. Tag: **BUILT-CLI-ONLY**.
- Fix: either (a) add a `RPC::nftRequestBuy` wrapper + a GUI affordance if the buyer-address-request flow is wanted in v1, or (b) document it as intentionally CLI-only and ensure no GUI copy implies a one-click request-to-buy exists. Decide based on whether open/handshake listings are in scope (they are FUTURE-IDEA per the capability survey).
- Files: `zcl-qt-wallet/src/rpc.cpp` (new wrapper if pursued); `zclassic/src/rpc/nftoffer.cpp` (requestbuy dispatcher, for reference).

### P2

**D-3. No GUI caller for `zslp_listtransfers` — provenance is unreachable from the GUI.** *(capability gap; honesty-adjacent)*
- Problem: the daemon `zslp_listtransfers` exists (`zclassic/src/rpc/zslp.cpp:155`, newest-first, reorg-safe) but no GUI code calls it (grep-confirmed empty in `zcl-qt-wallet/src/`). The detail dialog presents an NFT's identity but a user cannot view the public chain-of-custody history in-app. Status: **DESIGNED-NOT-BUILT (GUI)**. Make sure the detail dialog does not advertise provenance it cannot show.
- Fix: add a provenance list in `NFTDetailDialog` backed by a new `RPC::nftListTransfers` wrapper over `zslp_listtransfers`; until then, ensure no GUI string promises in-app history. (Public-by-design: history is fully visible on-chain — labeling it "public transfer history" is correct and required.)
- Files: `zcl-qt-wallet/src/nftdetaildialog.{cpp,h}`, `zcl-qt-wallet/src/rpc.cpp` (new wrapper); `zclassic/src/rpc/zslp.cpp:155` (source RPC).

---

## Area E — test coverage gaps

Primitive coverage is excellent: `test_zslp`(29), `test_zslp_vectors`(43), `test_zslp_indexer`(16), `test_zslp_wallet`(21), `test_zdc`(25), `test_nftoffer`(6); GUI L1 covers all five dialogs (mint/send/sell/buy/detail: success + gate + mismatch + close-swallow). The gaps below are at the **RPC-dispatcher** and **bespoke-helper** layers.

### P1

**E-1. NFT-offer RPC dispatchers are not directly tested — and the test re-implements prod logic.** *(COV-1)*
- Problem: `test_nftoffer.cpp` rebuilds the 3-output template and re-runs `WouldBeValid`/`VerifyScript` **by hand** (`test_nftoffer.cpp:107,122,245`) because the real `NftVerify` is `static` in `nftoffer.cpp:309`, hence untestable. So the actual `nft_makeoffer`/`nft_verifyoffer`/`nft_takeoffer` dispatcher paths — param parsing, expiry-bound checks, the overshoot-ack gate, the `fundingInputs` anti-burn loop, the registry/listoffers status recompute — have **zero direct coverage**, and the test itself duplicates prod logic (a DRY violation inside the test). Same shape for `zslp_genesis`/`zslp_mint`/`zslp_send`: only `ZSLPBuild*` + `BuildAndCommitZSLP` are tested, not the RPC layer with its nft-preset conflict rejections (`zslp.cpp:402-411`).
- Fix: either (a) de-`static` + expose `NftVerify` (and the offer template builder) so the gtest calls the real function instead of a hand-rolled copy, or (b) add an RPC-level harness (regtest / `CallRPC`) exercising the dispatchers end-to-end. (a) is the smaller change and also kills the in-test duplication. The `qa/zslp/nft-sell-regtest.sh` regtest covers the happy path + sig-tamper/forged/overshoot refusals, but it is not a unit gate.
- Files: `zclassic/src/rpc/nftoffer.cpp:309` (de-static `NftVerify`); `zclassic/src/gtest/test_nftoffer.cpp:107,122,245`; `zclassic/src/rpc/zslp.cpp:402-411` (preset-conflict paths to cover).

**E-2. Datachannel (ZDC) RPC layer is untested above the codec.** *(COV-2)*
- Problem: `test_zdc.cpp`(25) thoroughly tests the ZDC1 codec, but `z_senddatafile`/`z_listdatatransfers`/`z_getdatatransfer` have no test — the registry, TTL expiry (`ZdcExpireOld`), rate guard (`ZdcRateGuard`), the verify-before-decrypt branch logic, and the registry-miss fingerprint-grouping fallback (`datachannel.cpp:513-536`) are all uncovered. This is the privacy surface (file-content confidentiality via ZDC1), so its registry/verify branches deserve a gate. Note this is **BUILT-CLI-ONLY**, default-OFF behind `-experimentalfeatures -datachannel`.
- Fix: add an RPC/regtest harness (or unit tests around the extractable registry/TTL/rate-guard functions) exercising send→list→get, TTL expiry, rate-guard rejection, and the verify-before-decrypt failure modes (`ERR_NO_KEY`/`ERR_AEAD_FAIL`/`ERR_HASH_MISMATCH`). The cross-wallet round-trip in `qa/zslp/zdc-xwallet-regtest.sh` exists but is not a unit gate.
- Files: `zclassic/src/rpc/datachannel.cpp` (`ZdcExpireOld`, `ZdcRateGuard`, `:407` getdatatransfer, `:513-536` fallback); new gtest or regtest.

**E-3. `humanZcl` is untested.** *(COV-3 — resolved by C-2)*
- Problem: the bespoke buy-dialog money formatter (`nftbuydialog.cpp:408`) has no test. Resolved automatically by C-2 (delete it, route through the tested `Settings`/`zclToZat` path). If C-2 is deferred, add a direct test for `humanZcl` covering rounding, zero, and large values.
- Files: see C-2.

### P2

**E-4. The non-consensus no-fork guarantee is under-tested.** *(cross-cutting risk)*
- Problem: the HARD constraint — the NFT OP_RETURN must pass mainnet `IsStandard`/`-datacarriersize` policy unchanged so unmodified nodes relay and mine it — is currently backed only by a 223-byte builder-length assert, not by any test tied to mainnet policy. The "no fork" claim is not test-proven against real relay policy.
- Fix: add a test that constructs a representative ZSLP genesis/send/offer OP_RETURN and asserts it passes `IsStandardTx`/`AreInputsStandard` under default mainnet `-datacarriersize`. This converts the no-fork claim from asserted to proven.
- Files: new gtest in `zclassic/src/gtest/`; policy under `zclassic/src/policy/policy.cpp`.

---

## Area F — dead / placeholder code

### P2

**F-1. `NFTSellDialog::trimmedExpiryLabel` is unused/aspirational.** *(DEAD-4)*
- Problem: `trimmedExpiryLabel` (`nftselldialog.cpp:379`) builds a "~N days" label, but the expiry combo has only the single 7-day row (`:88`) and the user-facing label is hard-coded "expires in ~7 days." elsewhere (`:242`). The helper is unreachable; the combo itself is a single-choice placeholder (arbitrary expiry is a documented follow-up at `:86-90`).
- Fix: remove `trimmedExpiryLabel` until multi-choice expiry lands; or wire it up if a second expiry option is added now. Keep the "arbitrary expiry is a follow-up" comment so the placeholder intent stays honest.
- Files: `zcl-qt-wallet/src/nftselldialog.cpp` (`:86-90`, `:242`, `:379`).

(See also A-1 `nft_listoffers mine`, A-5 `nft_takeoffer changeAddr`, A-7 `ZdcDirToStr`/never-varied status — all dead-param/placeholder items filed under Area A because the fix lives in the RPC surface.)

---

## Suggested refactor order (highest leverage first)

1. **C-1** — shared async-dialog scaffold (biggest LOC win + centralizes the load-bearing UAF guard). **P0**
2. **B-1 / B-2** — shared daemon helpers (amount parser, store-or-throw, t-addr script/addr) into `zslpwallet.h`. **P0/P0**
3. **A-3 + C-3** — embed the full `TokenToJSON` object in `zslp_listmytokens`; delete the GUI per-token batch. **P1/P1**
4. **E-1 / E-2** — RPC-dispatcher tests; de-`static` `NftVerify` so the test stops duplicating prod logic. **P1/P1**
5. **C-2 / C-4 / E-3** — fold `humanZcl` into the tested `Settings` path; share the t-addr validator + public-trade note. **P1/P1**
6. **A-1** — honor or remove the dead `nft_listoffers` `mine` param (and the GUI side). **P0** (small; can be batched with step 1.)

Remaining P2 items (A-5, A-6, A-7, A-8, D-3, E-4, F-1) are cleanup/coverage to schedule opportunistically.

---

## Appendix — verification notes

Every load-bearing claim above was spot-checked against the working tree on the stated branches (daemon `feature/zslp-nft-indexer`, GUI `feature/nft-gallery`):
- A-1: `(void)onlyMine;`/`(void)store;` confirmed at `nftoffer.cpp:1000-1064`; GUI sends `{"mine": mineOnly}` at `rpc.cpp:1390` while `(void)mineOnly;` at `:1384` — dead both ends.
- A-3: `zslp_listmytokens` hand-rolled object (no `documenthash`) confirmed at `zslp.cpp:~250-258`.
- A-4: `RPC_INVALID_ADDRESS_OR_KEY` for "Token not found" confirmed at `zslp.cpp:103`; `RPC_INVALID_PARAMETER` used elsewhere in the file.
- A-7/A-8: `ZdcDirToStr` identity wrapper `:152`, `direction="sent"` `:356`, `status="recorded"` `:397`, `ZDC_MAX_FILE_BYTES=40000` `:84`.
- B-1: `ParseQuantity` `zslp.cpp:284` vs `NftParseZat` `nftoffer.cpp:103` confirmed.
- B-2: prefixed-duplicate helpers and call sites confirmed in both `zslp.cpp` and `nftoffer.cpp` (line lists above).
- C-1: `m_inFlight`/`QPointer` pattern present in all of `nftmint/send/sell/buy` (and `nftdetail`) dialogs.
- C-2: `humanZcl` only in `nftbuydialog.{cpp,h}`; `Settings::getDecimalString` `settings.cpp:377`; `RPC::zclToZat` `rpc.cpp:1216`.
- C-3: two-stage `zslp_listmytokens` → per-token `zslp_gettoken` confirmed at `rpc.cpp:871-917`.
- C-4: duplicated validator strings + `isTAddress` gating + duplicated public-trade sentence confirmed across `nftsend/sell/buy`.
- D-2: no `nftRequestBuy`/`nft_requestbuy` in GUI `src/` (grep empty).
- D-3: no `zslp_listtransfers` caller in GUI `src/` (grep empty).
- SHIELD GUI gate: `isPrivateMintWired()` returns `false` (`rpc.h:326`); "coming in this release"/"coming soon" copy at `nftmintdialog.cpp:86-90`, `nftsenddialog.cpp:79`.
