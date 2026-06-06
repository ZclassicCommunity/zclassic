# ZClassic NFT — GUI Build Backlog (prioritized)

The prioritized, concrete build plan for the native (no-browser) NFT GUI in
`/home/rhett/github/zcl-qt-wallet` (C++14 — **no** `std::optional`/`string_view`; use
empty-`QString` sentinels). Companion to [`NFT_FEATURE_CHECKLIST.md`](NFT_FEATURE_CHECKLIST.md)
(the status matrix), [`NATIVE_NFT_GUIDE.md`](NATIVE_NFT_GUIDE.md) §2 (the native-UI spec),
and [`NFT_SELL_DESIGN.md`](NFT_SELL_DESIGN.md) (the approved Sell/Buy UX).

> **Honesty rules for this doc.** "tested" = a real L0 (`tests/tst_logic.cpp`) or L1
> (`tests/widget/tst_widget.cpp`, gated behind `ZCL_WIDGET_TEST` + offscreen QPA) test
> exercises it. "documented/onboarded" = a user can understand it **in-app** (no web
> browser, no external README). Coin = **ZCL** (never ZCL).
>
> **State as of 2026-06-06.** The NFT dialogs have LANDED (`nftmintdialog.*`,
> `nftdetaildialog.*`, `nftsenddialog.*`, `nftgallerymodel/delegate`) but are
> **UNCOMMITTED** and their widget wiring is **almost entirely untested** — only the
> detail no-bytes terminal has an L1 test (`nftDetail_noBytesIsTerminalNotSpinner`,
> tst_widget.cpp:1869). `NftMintDialog` and `NFTSendDialog` are **never constructed** in
> any test. The engine PRIMITIVES under these dialogs (ContentEngine streaming-hash/Merkle/
> poster/verify, `NFTGalleryModel`, `NFTImageCache`) ARE L0-tested (~12 `ce*`/`nftModel*`
> tests); the dialog wiring that turns them into user-facing behavior is not.

The four pillars: **MINT · VIEW · SHIELD · SELL.** Priority order across pillars below is
A → E as the task requires: (A) make the verify badge reachable for received NFTs; (B)
in-app onboarding + honesty copy; (C) Sell/Buy UI; (D) Shield private-send UI; (E) the
specific L0/L1 tests. Within each section items are listed highest-impact-first.

---

## P0 — Pre-work (do first; cheap, prevents loss)

- [ ] **Commit the landed-but-untracked NFT dialogs** (`nftmintdialog.*`,
  `nftdetaildialog.*`, `nftsenddialog.*`, `nftgallerymodel.cpp`, `nftgallerydelegate.cpp`,
  `nft.h`, `nftimagecache.*`) and the ContentEngine `posterForToken`/`posterReady`
  additions — currently `??`, lost if not committed. (No code change; tracking only.)
- [ ] **Add a `mintNFT`/`sendNFT` test-injection seam to `RPC`** (rpc.h:194,203) mirroring
  the existing `testSetNextZaddrResult` pattern (rpc.h:98) — e.g.
  `testSetNextMintResult(txid, errStr)` / `testSetNextSendResult(...)` / a
  `testSetNextTxReceivedDate(...)` for `txReceivedDate` (rpc.h:218). **Blocker for every
  mint/send L1 success/failure test** (§E) — today the dialogs cannot be driven to a
  terminal state in a test because they reach a live daemon.

---

## (A) VIEW — make the verify badge REACHABLE (the worst gap, G-VIEW)

The headline VIEW promise is "verify the image." Today a RECEIVED NFT can **never** reach
the green badge: `RPC::refreshNFTs` hard-sets `it.cachePath = QString()` for privacy
(rpc.cpp:960, never auto-fetch), and the ONLY writer of the content-addressed cache is the
in-session mint (`ContentEngine::cachePut`, nftmintdialog.cpp:249). There is **no**
attach-local-file affordance anywhere (no `getOpenFileName` in `nftdetaildialog.cpp` or the
gallery). "Re-check image" (`onRecheck`, nftdetaildialog.cpp:408) just re-runs
`requestPoster()` against the same empty cache. The no-bytes tooltip even *promises* "open
it to check it yourself" — an action no button performs.

- [ ] **Add an "Attach the file you have" button to `NFTDetailDialog`** (next to
  `m_recheckBtn`, nftdetaildialog.cpp:162). On click: `QFileDialog::getOpenFileName`,
  reject remote/non-local via `ContentEngine::isRemoteUrl` (reuse the mint guard at
  nftmintdialog.cpp:163), stream-hash the file, and **only if the anchor matches
  `it.docHashHex`** call `ContentEngine::cachePut(docHashHex, path)` then re-run
  `requestPoster()` (nftdetaildialog.cpp:220) so the badge flips to VERIFIED. If the
  attached file's fingerprint does NOT match, show the honest red "this file does NOT match
  this collectible's on-chain fingerprint" inline — do **not** cache it.
- [ ] **Show the Attach button only in the no-bytes terminal state** (`applyNoBytesBadge`,
  nftdetaildialog.cpp:302) so it appears exactly when it's useful; hide it once bytes exist.
- [ ] **Fix the no-bytes tooltip to match reality** — until Attach lands, the gallery
  tooltip (nftgallerymodel.cpp:66-70) and detail no-bytes copy must not promise "open it to
  check it yourself"; after Attach lands, update the copy to point at the new button.
- [ ] **Decide & enforce the `nft=true` `document_hash` requirement.** Daemon-side
  `zslp_genesis` makes `document_hash` OPTIONAL for `nft=true` (validated only IF present;
  the nft preset adds no requirement), so a hash-less NFT is **structurally impossible to
  ever verify** in the GUI (no anchor → no `cacheGet` → badge stays neutral, nftdetaildialog.cpp:226).
  The GUI mint wizard already requires an anchor before Create (`refreshCreateEnabled`,
  nftmintdialog.cpp:211), so GUI-minted NFTs always carry a hash; the gap is CLI/foreign
  hash-less NFTs. **Decision:** either (a) require `document_hash` for `nft=true` daemon-side
  (cleanest — closes it for all clients), or (b) show an honest "no fingerprint was recorded
  for this collectible — it can't be verified" terminal in the detail dialog when
  `it.docHashHex` is empty (nftdetaildialog.cpp:194-196 already labels it "none recorded
  on-chain" but does not explain the consequence). Pick (a) if a daemon change is in scope;
  else ship (b) as a GUI-only honest dead-end.

---

## (B) VIEW — in-app onboarding + honesty copy (G-HELP)

Near-total gap: **0** `setWhatsThis` in the entire GUI; only 2 `setToolTip` on the verify
badge (nftdetaildialog.cpp:296,311), both merely echo the verdict. The spec'd 4-page hero
stack (NATIVE_NFT_GUIDE.md §2.3) was NOT built — only a single grey `nftStateLabel`
(mainwindow.cpp:3051-3056, 3175-3190). The honest substance that ships (uniqueness
footnote, "matches fingerprint" never says "genuine", privacy pills, explorer reveal
warning) is presented passively as static labels a user must already know to read.

- [ ] **Verify-badge disambiguation (highest impact — the single most-misunderstood
  element).** Add a richer `setToolTip`/What's-This directly on the badge + `m_verifyLine`
  (nftdetaildialog.cpp:296, in `applyVerifyBadge`:279) that states what a green check does
  NOT mean: e.g. *"Green means the picture on your computer is exactly the one recorded
  on-chain. It does NOT mean this collectible is official, genuine, or made by the original
  artist — anyone can mint a copy."* Mirror a shorter form into the gallery card
  `ToolTipRole` (nftgallerymodel.cpp:63-65).
- [ ] **First-run Collections hero (NATIVE_NFT_GUIDE §2.3).** Replace the single
  `nftStateLabel` empty-state (mainwindow.cpp:3051) with the spec'd centered hero card:
  Page-1 EMPTY title "No collectibles yet" + green primary **"Make your first collectible"**
  (opens `NftMintDialog`) + flat link **"What is a collectible?"** opening a short *in-app*
  explainer (a `QDialog`/`QLabel` — **no web browser**). None of those strings exist in the
  source today (grepped).
- [ ] **Index-off page with a copyable `zslpindex=1` line.** The index-off branch
  (mainwindow.cpp:3175-3190) is prose only — a dead end for foreign/old daemons. Add the
  spec'd amber "Collectibles tracking is turned off" page with a copyable
  `zslpindex=1` config line + "Copy line" button (NATIVE_NFT_GUIDE §2.3 Page-2).
- [ ] **Mint permanence/public-ledger warning.** The mint "honest" label
  (nftmintdialog.cpp:102) correctly says the FILE stays private, but nothing warns that the
  name + collection + fingerprint are written to a **permanent, public** ledger and cannot
  be edited or removed (no burn primitive exists, G-PARITY). Add one line above Create:
  *"The name, collection and fingerprint go on the public ledger permanently — they can't be
  edited or removed later."*
- [ ] **Pending / no-bytes / 0-conf explainers.** The states are NAMED honestly but never
  EXPLAINED. Add a What's-This on the no-bytes badge (`applyNoBytesBadge`,
  nftdetaildialog.cpp:302) clarifying that for privacy the wallet never downloads images
  automatically (ties to the §A Attach button so the instruction is honest), and on the
  0-conf "Just arrived — confirming…" line (nftdetaildialog.cpp:197-199) explaining a held
  NFT is real once it confirms.
- [ ] **Quiet experimental-status line.** Nothing on the NFT surface tells the user this is
  a new non-consensus overlay. Add a single calm line in the Collections header
  (mainwindow.cpp `setupNFTTab` sub-head) or the mint footer: *"Collectibles are a new
  feature — please use small amounts while we harden it."* Honest, non-alarming.
- [ ] **Surface provenance (chain-of-custody).** The detail dialog advertises "provenance"
  in its header comment but never calls `zslp_listtransfers` (no GUI caller anywhere). Add a
  `RPC::nftTransfers` wrapper over `zslp_listtransfers` and a compact timeline in the detail
  dialog; also display the `zslp_gettoken` Set/Creator that `nftProvenance` already reads
  but the back-fill stub discards (nftdetaildialog.cpp:326-337).

---

## (C) SELL — Buy/Sell UI (per NFT_SELL_DESIGN.md)

GUI-greenfield, but the daemon side is DONE — the `nft_*` offer RPCs are **built + regtest-proven**
(`src/rpc/nftoffer.cpp`: `nft_makeoffer`, `nft_verifyoffer`, `nft_takeoffer`, `nft_listoffers`,
`nft_canceloffer`, `nft_requestbuy` — see NFT_SELL_DESIGN.md §6), so the GUI work is **UNBLOCKED**.
The GUI target is the do-not-make-me-think flow from §5: **Sell ~3 taps, Buy ~3 taps.** Build the
RPC wrappers + dialogs against the existing daemon RPCs.

- [ ] **`RPC::nftMakeOffer` / `nftVerifyOffer` / `nftTakeOffer` / `nftListOffers` /
  `nftCancelOffer` wrappers** in `rpc.{h,cpp}`, each with a test-injection seam (like §P0).
- [ ] **`NFTSellDialog`** on an owned NFT card (reuse `NFTSendDialog` patterns): one *Price
  in ZCL* field + *Expires in [7 days ▾]*; "List" → `nft_makeoffer` (locks the NFT outpoint)
  → "Offer ready — Copy / Save / Show QR. Expires in 7d." The card then shows a "Listed"
  badge + **Cancel** (→ `nft_canceloffer`, confirmed "voids the listing, frees your NFT").
- [ ] **`NFTBuyDialog`** (Paste / Open `*.znftoffer` file / Scan QR): auto-run
  `nft_verifyoffer`, render the offer card (image via ContentEngine, name, **price**,
  "Expires in 6d", green check or amber reason). Confirmation sheet: *You pay **P ZCL**
  (+ ~fee F). You receive: <NFT name>* plus the **mandatory honest privacy line**: *"This
  trade settles publicly on-chain — price and addresses are visible. Only negotiation can be
  private."* "Buy" → silent pre-sized funding UTXO (§2.5) → `nft_takeoffer` → spinner →
  "NFT received." Never expose vout indices / ANYONECANPAY / templates.
- [ ] **Offer-blob (de)serializer + `*.znftoffer` file association** (NFT_SELL_DESIGN.md §4):
  base64 of the compact-binary `ZNFTOFFER1` header + raw hex; Copy/Paste/QR; **no web
  service**. The GUI registers the extension.
- [ ] **MISMATCH + expiry honesty in Buy.** Reuse the existing verifyState==2 red-mismatch
  pattern (nftsenddialog.cpp:41-47): a verify-failed or expired offer renders amber/red with
  the reason and **disables Buy**.

---

## (D) SHIELD — private-send / private-NFT toggle

The daemon datachannel RPCs are now **BUILT** (`z_senddatafile` / `z_listdatatransfers` /
`z_getdatatransfer`, gated behind `-datachannel` default-OFF, `z_senddatafile` requires
`acknowledge_permanent=true`). But the GUI has **zero affordance**: `isPrivateMintWired()`
hard-returns `false` (rpc.h:225), every NFT dialog shows "Private — coming in this release"
(nftmintdialog.cpp:96, nftsenddialog.cpp:77), and the binary-safe memo-read sniff is not
applied. `z_revealkey` + `zslp_mint_private` are still absent daemon-side.

- [ ] **Apply the GUI binary-safe memo read fix** (rpc.cpp ~756): sniff the ZDC1 magic
  `0x5A,0x44,0x43,0x31` on the raw 512-byte `QByteArray` **before** any `QString`
  conversion, and route binary frames to a data-channel inbox instead of mangling them.
  (Documented bug-fix; not applied.)
- [ ] **`RPC::sendDataFile` / `listDataTransfers` / `getDataTransfer` wrappers** over the
  built daemon RPCs, each handling the `-32601` "feature not present" latch the GUI already
  understands (so a daemon with `-datachannel` off degrades honestly).
- [ ] **Flip `isPrivateMintWired()` to a real probe** (call the daemon once; true only if a
  datachannel RPC does not return `-32601`) instead of the hard `false`. Until then keep the
  honest "coming soon" gate.
- [ ] **Private-send toggle in `NFTSendDialog`** — once wired: a "Send privately" option that
  accepts a `zs…` recipient (lift the current hard t-addr-only reject at nftsenddialog.cpp:129)
  and routes through the datachannel path with the **`acknowledge_permanent=true`** consent
  surfaced honestly ("the encrypted bytes are permanent and public on-chain"). Keep the
  consensus-limit copy: ownership stays a public ZSLP UTXO; key-possession is not DRM.
- [ ] **Private-mint** (blocked on daemon `zslp_mint_private`): once it lands, add the
  encrypt-the-asset path to `NftMintDialog` (document_hash = ciphertext fingerprint) behind
  the same wired probe.

---

## (E) Tests to add (per untested path)

All L1 tests are gated behind `ZCL_WIDGET_TEST` + the offscreen QPA and live in
`tests/widget/tst_widget.cpp`; L0 unit tests live in `tests/tst_logic.cpp`. The mint/send
success/failure tests are **blocked on the §P0 RPC test seam**.

### MINT (L1 — `NftMintDialog` is never constructed today)
- [ ] **Create-button gating** (`refreshCreateEnabled`, nftmintdialog.cpp:207-213): construct
  `NftMintDialog(engine, rpc)`, find `nftMintCreateButton` — assert DISABLED with empty
  name/no file, ENABLED only after a name is typed AND a fingerprint arrives, DISABLED again
  while `m_hashing`/`m_inFlight`, and DISABLED after `m_succeeded`.
- [ ] **Fingerprint streaming UI** (`setPickedFile`/`onDescriptorReady`, nftmintdialog.cpp:162-205):
  feed a real temp file, pump the loop, assert `m_fpLabel` reaches "Fingerprint ready …"
  (nftmintdialog.cpp:199) with the anchor's first 8 hex chars. Plus an **L0** unit for
  `anchorHexFor` returning `merkleRoot` when `chunkCount>1` else `sha256Whole`.
- [ ] **Privacy-drop reject** (`dropEvent`/`setPickedFile`, nftmintdialog.cpp:142-167): feed a
  non-local `QUrl` (or an `http` path to `setPickedFile`); assert `m_fpLabel` shows "drop a
  local file — not a web link" (nftmintdialog.cpp:149) in red and `m_srcPath` stays empty
  (Create stays disabled).
- [ ] **0-conf success terminal + in-flight lock** (`onCreate`/`closeEvent`,
  nftmintdialog.cpp:215-294): with the §P0 seam — in-flight → Create reads "Creating…" +
  `closeEvent`/[X] swallowed; success → Create retires to "Done", result line contains
  "confirm", dialog NOT yet `accept()`ed, `ContentEngine::cachePut` called; failure → "Try
  again" + the honest daemon `errStr`.

### VIEW (L1/L0)
- [ ] **Detail VERIFIED/MISMATCH badge copy** (`applyVerifyBadge`, nftdetaildialog.cpp:279):
  construct `NFTDetailDialog` with a cached/local image whose anchor MATCHES (assert
  `nftDetailVerifyLine` contains "matches its on-chain fingerprint") and one that MISMATCHES
  (assert "does NOT match" + red), driving `onPosterReady` via the real engine. The only
  honesty-critical VIEW copy currently unverified.
- [ ] **Undecodable-image branch** (`onPosterReady` `img.isNull()`, nftdetaildialog.cpp:257-266):
  one L1 case for an image present but undecodable (distinct from the tested no-bytes branch).
- [ ] **Attach-local-bytes happy + mismatch path** (§A, once built): attach a matching file →
  badge flips to VERIFIED; attach a non-matching file → red "does NOT match", not cached.
- [ ] **0-conf "Received" line** (`backfillReceived`, nftdetaildialog.cpp:340-364): drive
  `txReceivedDate` via the §P0 seam — assert "confirming" for `confs < kFinalConfs` and an
  ISO date for `confs >= kFinalConfs`.
- [ ] **Delegate paint (optional, rendering not logic)** — grab/paint test for the neutral
  dash badge + "Image not on this device" placeholder (nftgallerydelegate.cpp:150-192); only
  `sizeHint` is covered today (`nftDelegateSizeHintStable`).
- [ ] **Honesty-copy presence (G-HELP, once added)** — L1 asserting the verify-badge tooltip
  rejects "genuine"/"official" framing and the mint dialog mentions permanence; per the
  honesty rule, untested honest copy can regress silently.

### SELL (GUI L1/L0 — none exist yet; the daemon side HAS 6 gtests + the nft-sell regtest)
- [ ] `NFTSendDialog` recipient validation (the closest existing surface): construct
  `NFTSendDialog(item, rpc)`, type each of {empty, garbage, valid t-addr, valid zs-addr}
  into the recipient field (`onRecipientChanged`, nftsenddialog.cpp:106) — assert the status
  copy and that `nftSendButton` is ENABLED only for the valid t-addr (zs-addr REJECTED with
  "Private gifts coming soon").
- [ ] **Send mismatch guard** (the strongest honesty guarantee, ZERO coverage): construct
  `NFTSendDialog` with `NFTItem{verifyState=2}` — assert the red mismatch warning is present
  (nftsenddialog.cpp:41-47) AND `nftSendButton` stays disabled even with a valid t-addr
  (`notMismatch`, nftsenddialog.cpp:130); a sibling with `verifyState=1` must allow the send.
- [ ] **Send success/failure terminal** (`onSendClicked`, nftsenddialog.cpp:134): with the
  §P0 `sendNFT` seam — success → "on its way — confirming" copy; failure → honest `errStr`.
- [ ] Sell/Buy dialog tests (once §C lands): offer build/verify/take happy paths + the
  verify-failed/expired amber-disable path.

### SHIELD (L1, once §D wired)
- [ ] Binary-safe memo sniff unit (L0): a 512-byte buffer starting `5A 44 43 31` is routed to
  the data-channel path, not converted to `QString`.
- [ ] Private-send toggle: a `zs…` recipient is accepted only when the wired probe is true,
  with the `acknowledge_permanent` consent surfaced.

---

## Cross-cutting

- [ ] **`getExplorerTxURL` unit test** (L0): pin the URL scheme + the testnet `''` sentinel
  (settings.cpp:418); no test covers it today and the explorer reveal is honesty-gated.
- [ ] **Keep the no-browser invariant** — no `QtWebEngine`/`QtMultimedia`; `document_url` is
  never auto-fetched. Add a guard/grep test if feasible so a regression is caught.
- [ ] **C++14 discipline** — no `std::optional`/`std::string_view`; declare header-signature
  types' includes in the header (see `gui-cpp14-constraint`).

---

*Companion to `NFT_FEATURE_CHECKLIST.md`. Read-only audit basis: the landed (uncommitted)
GUI tree + the L0/L1 test files. Daemon RPC line refs are against `feature/zslp-nft-indexer`.*
