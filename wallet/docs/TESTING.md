# ZClassic wallet — automated testing & UX checklist

> **Engineering doc — not user documentation.** Some checklist items reference Tier-0
> privacy behaviors on `feature/privacy-by-default-tier0` that are not yet in the
> released v2.1.2-beta5.

How to prove the wallet (and its privacy-by-default UX) actually works, automatically.
Designed + adversarially reviewed against the real code. The wallet's *only* network
primitive is `Connection::doRPC` posting plain HTTP/Basic-auth to a `QNetworkAccessManager`
(`connection.cpp:1777-1794`) — so a **localhost JSON-RPC mock is a zero-product-change
drop-in for `zclassicd`**, reused by every layer.

## The three-layer ladder (cheapest layer that suffices)

| Layer | What | How it runs | Proves |
|-------|------|-------------|--------|
| **L0 — Unit** | QtTest *guiless*; links only `settings.cpp` + `senttxstore.cpp` + `addresscombo.cpp` + a few extracted pure helpers + test shims. No daemon, no widgets, no libsodium. | `/opt/qt-static/bin/qmake tests.pro && make && ./tst_logic` in the proot chroot. | Address classifiers/formatters, `senttxstore` 0600 round-trip, address parsing, and the privacy *predicates* (`isPublicTx`, change-to-shielded decision, backup-nag gate) as exhaustive truth tables. |
| **L1 — Integration / widget** | QtTest with `-platform offscreen`; links the full app **minus `main.cpp`**, points the **real** `RPC` at the localhost mock via the public `rpc->setConnection()` (`rpc.h:40`). Drives widgets in-process (`setChecked`/`click`/`keyClicks`). | Same `tests/` tree, second target. A `QTimer::singleShot(0)` modal-dismisser reads dialog state *before* closing and injects Yes/No. | **Every privacy dialog/caption/warning** — PUBLIC receive caption, de-shield warning, memo reply-to consent, Sprout-button-disabled, backup nag — because it needs neither a daemon nor any X input tool. |
| **L2/L3 — E2E** | The **existing Xvfb harness** (`uxmatrix.sh`/`run.sh`/`shot.sh`) booting the **real unmodified bundle** with `--no-embedded` against the localhost mock. | Real Xvfb :99 + isolated datadir/ports. Asserts via log-grep + `xwininfo` + screenshot. | The real `ConnectionLoader` handshake, staged banners, splash, graceful quit, and on-disk effects (wallet.dat copy, file perms, no-secrets-in-log). |

**The localhost mock** is one ~120-line `python3 http.server` (python3 is in the rootfs),
scenario-driven by an env var, one flat-JSON-per-method fixture dir per scenario, ignoring
Basic auth. Same artifact for L1 and L2/L3 — build once, reuse everywhere. It records request
bodies so tests can assert the `z_sendmany` change-routing payload.

## Headless input (no xdotool exists in the chroot)
1. **Primary — in-process (L1):** drive every privacy click/toggle via the QtTest widget API under `-platform offscreen` (`rdioTAddr->setChecked(true)`, `btnInsertFrom->click()`, `QTest::keyClicks`). No X server, no synthetic input. This is why the radio/caption/consent items are L1.
2. **E2E without synthetic input (L2):** use inputs the bundle already accepts — a `zclassic:<addr>?amount=…` arg pre-fills the Send tab (`main.cpp:296`); pre-seed QSettings one-shots so first-run dialogs fire on the connect path. Dismiss via the existing `wmclose` (WM_DELETE), detect via `xwininfo`.
3. **Last resort (L2):** a ~40-line test-only `wmclick`/`wmtype` built from `wmclose.c` using **XTEST** (`XTestFakeButtonEvent`) — *not* plain `XSendEvent`, which Qt ignores. Never linked into the wallet. Only for the 2-3 Receive-radio E2E cases TIER-2 can't reach.

## Prioritized build plan
0. **Phase 0 (S) — 3 mechanical, behavior-preserving seams** (unblocks exhaustive L0): (A) delete the unused `#include "mainwindow.h"` at `settings.cpp:1`; (B) extract `isPublicTx()` + the change-to-shielded decision into header-only `src/txclassify.h` and swap the call sites in `sendtab.cpp`; (C) extract the backup-nag gate into a free `bool shouldPromptBackup(alreadyShownSession, isSyncing, balTotal, alreadyBackedUp)` called at `rpc.cpp:1124`.
1. **Phase 1 (M) — L0 `tst_logic`** with 4 shims (sodium-free `precompiled.h`; full `ToFields`/`Tx`; full 8-field `TransactionItem`; `AddressBook` stub). Covers ~18 checklist items, zero flakiness.
2. **Phase 2 (S) — the localhost JSON-RPC mock + fixtures** (the reusable asset for L1 + E2E).
3. **Phase 3 (L) — L1 `tst_widget`** (full app minus `main.cpp` + `libsodium.a` + `qoffscreen` plugin import + the modal-dismisser). The privacy-dialog core.
4. **Phase 4 (M) — extend `uxmatrix.sh`** with `setup_mock_node` + `--no-embedded` + a seeded wallet.dat stub for the on-disk/handshake items.
5. **Phase 5 (S, only if needed) — the `wmclick`/`wmtype` XTEST helper.**

## Key risks (designed-for)
- **Blocking modals deadlock in-process tests** → the mandatory `QTimer::singleShot(0)` dismisser (reads state, then injects the answer).
- **`backupPromptShownThisSession` is a function-local static** (`rpc.cpp:1124`) → extract the gate to a pure function (L0), run the residual widget cases in per-scenario binaries.
- **L1 links the entire app** (incl. the `QProcess` daemon launcher, dead weight) → it's an L-effort target, not lightweight.
- **Static-Qt offscreen** → the test `.pro` must replicate `QTPLUGIN.platforms=qoffscreen` + `Q_IMPORT_PLUGIN`.
- **`G5` (no-secrets-in-log)** is best-effort (greps known strings only). **`F5`** (native save picker) is manual-only.

---

# UX checklist (52 items)
Legend: **[L0]** unit · **[L1]** widget/mock-RPC · **[L2]** Xvfb E2E · **[manual]**.

### A. First-run / Onboarding
- [L2] **A1** Fresh HOME shows the onboarding card + "Step 1 of 3: Getting the security files ready…" banner. (`connection.cpp:63-66,318`)
- [L0] **A2** `ez/onboardingShown` persists → card never re-appears on 2nd launch. (`connection.cpp:65-66`)
- [L2] **A3** No pre-download hang — reaches interactive UI without z.cash param pre-download (daemon peer-fetches). 
- [L2] **A4** Staged-banner monotonicity Step1→Step2→"zclassicd is online."→"Payment UI now ready!" never regresses. (`connection.cpp:1821`)

### B. Connection / Sync states
- [L1] **B1** `getinfo` cb drives sync icon + peer count from canned JSON. (`rpc.cpp:673-704`)
- [L1] **B2** 96%-stuck fix — sync% computed from HEADERS not blocks; `blocks<<headers` shows correct sub-100% and keeps moving. (`rpc.cpp:738+`)
- [L1] **B3** Zero peers → "Waiting for peers… check your internet connection", not a frozen "syncing 0". (`mainwindow.cpp:684`)
- [L1] **B5** `noConnection()` clears balance/tx/address models (no stale data) on transport error. (`rpc.cpp:506-526`)
- [L2] **B4** v3 bootstrap shows "Downloading blockchain snapshot… N%" advancing. (`mainwindow.cpp:709`)
- [L2] **B6** Fully-synced edge flips status to ready + stops spinner exactly once.

### C. Balance / Privacy framing
- [L1] **C1** `z_gettotalbalance` → Shielded/Transparent/Total labels via `getZCLDisplayFormat`. (`rpc.cpp:1092-1131`)
- [L1] **C2** Privacy framing explicit — "Shielded" + "Transparent" labels (not one opaque "Balance"). (`mainwindow.ui:62,89`)
- [L1] **C4** Cached-balance write gated by `getShowCachedBalance()`; relaunch shows last-known. (`rpc.cpp:1109-1114`)
- [L0] **C3** USD tooltip only when `price>0 && !testnet`. (`settings.cpp:325-330`)
- [L0] **C5** `getDecimalString` edges (`1.5`, `5`, `-0`→`0`, `0.00000001`, `-1.5`). (`settings.cpp:332-355`)
- [L0] **C6** Token name ZCL mainnet / ZCT testnet. (`settings.cpp:442-457`)

### D. Receive / Address hygiene (PUBLIC caption + removed Sprout backdoor)
- [L1] **D1** `rdioTAddr` → red PUBLIC caption ("Transparent address.", "**PUBLIC**", "permanently visible"). (`mainwindow.cpp:1804-1814`)
- [L1] **D2** Default receive type is shielded Sapling (`rdioZSAddr`), not transparent. (`mainwindow.cpp:1879-1885`)
- [L1] **D3** Sprout-create backdoor removed — New-Address button DISABLED under `rdioZAddr`. (`mainwindow.cpp:1820-1864`)
- [L1] **D4** Sprout still spendable/viewable (no spend regression). *[mock MUST seed a Sprout addr]* (`mainwindow.cpp:1860-1885`)
- [L1] **D5** `rdioTAddr`→`rdioZSAddr` CLEARS the warning (shielded addr never carries a scary caption). *[two sequential setChecked]* (`mainwindow.cpp:1846-1851`)
- [L0] **D6** `addressFromAddressLabel` + paren-parse `label/zaddr(1.5 ZCL)`→`zaddr`. (`addresscombo.cpp:11/16`)

### E. Send / Privacy
- [L0] **E1** `isPublicTx` (post-extract) — all-z→private; any t→public; empty→private. (`sendtab.cpp:581-587`)
- [L1] **E2** De-shield warning — confirm with any t-recipient makes `publicWarning` VISIBLE; all-shielded keeps it hidden. (`sendtab.cpp:677`)
- [L0] **E3** Auto-shield change DECISION (post-extract) — default off; `autoShield+t-from+non-Sprout`→true; z-from→false; Sprout→false. (`sendtab.cpp:480-495`)
- [L1] **E3b** Auto-shield ACTUAL routing — recorded `z_sendmany` payload routes change to a `zs`-addr when on, transparent when off. (`sendtab.cpp:511-533`)
- [L1] **E4** Memo reply-to one-time consent — first manual "Insert From" pops the reveal-warning; No aborts; Yes writes + sets `memo/replyToWarned`; 2nd click never re-prompts. (`sendtab.cpp:378-391`)
- [L1] **E5** Reply-to educational tooltip ALWAYS present (even after consent). (`sendtab.cpp:374-377`)
- [L1] **E6** Memo gated to z-only — disabled with tooltip when recipient is a t-addr. (`sendtab.cpp:301-309`)
- [L0] **E7** `doSendTxValidations` field logic — invalid-from, recipient truncation, negative-amount rejection, no RPC. (`sendtab.cpp:752-758`)
- [L1] **E8** New send/reply-to address defaults to Sapling (`zs`-prefixed), not t/Sprout. (`rpc.cpp:283`)

### F. Backup / Fund-safety (the nag)
- [L1] **F1** Synced-edge nag — `isSyncing` false AND `balTotal>0` → `promptWalletBackup()` fires EXACTLY once per session. *[own binary — static one-shot]* (`rpc.cpp:1124-1130`)
- [L0] **F2** Nag suppressed when balance==0 or still syncing (pure `shouldPromptBackup` truth table). (`rpc.cpp:1125-1127`)
- [L1] **F3** Permanent silence after backup — `options/walletbackedup` true → returns without showing. *[own binary]* (`mainwindow.cpp:1157-1190`)
- [L1] **F4** Nag copy states the no-seed reality ("no seed phrase / recovery phrase", "keep a copy somewhere safe"). (`mainwindow.cpp:1172-1179`)
- [manual] **F5** Backup copies wallet.dat to a chosen path (native `QFileDialog` picker — not headless-drivable). (`mainwindow.cpp:1190-1213`)

### G. Security / At-rest
- [L0] **G1** `getSaveZtxs()` gates SentTxStore writes; non-`z` from-addr suppresses write. (`senttxstore.cpp:58`)
- [L0] **G4** SentTxStore written 0600 owner-only under testnet-prefixed name. (`senttxstore.cpp`)
- [L1] **G3** Export/import key flows gated behind explicit menu actions; export shows a clear-key warning. (`mainwindow.ui:1063-1130`)
- [L2] **G2** Shielded-tx local store deletable; menu copy explains "stored locally… delete… any time for your privacy". (`mainwindow.cpp:934`)
- [L2] **G5** No secrets in log (grep for conf password / seeded privkey is empty). *[best-effort: known strings only]* (`logger.cpp`)

### H. Error / Repair
- [L0] **H1** `looksLikeDbCorruption`/`startupDiagHasMarker`/`isLongWarmupPhase` classify daemon-stderr markers (pure). (`connection.cpp:965/995`)
- [L0] **H2** `blocksDirSizeBytes` correct byte total over a temp dir. (`connection.cpp:1041`)
- [L1] **H5** Malformed JSON → `noConnection()` empty-state, no crash/stale-balance/UAF. (`rpc.cpp:506-526`)
- [L2] **H3** Repair backs up wallet.dat FIRST ("Repair backup: wallet.dat copied to …" before touching chain data). (`connection.cpp:1377-1399`)
- [L2] **H4** Peerless attached node surfaces the foreign-node-stuck dialog, not a silent hang. (`mainwindow.cpp:831`)
- [L2] **H6** node-corrupt under `--no-embedded` shows "ZClassic couldn't connect." (not a silent splash hang). (`connection.cpp:139-145`)

### I. Speed / Responsiveness
- [L1] **I2** `doBatchRPC` 100ms QTimer resolves all replies + fires once, no busy-spin. (`connection.h:287-356`)
- [L1] **I5** Refresh idempotence — two back-to-back `refresh(true)` leave identical row counts (no leak). 
- [L2] **I1** Cached-balance instant paint — seeded `cache/*` renders before daemon online (no zero-flash). (`mainwindow.cpp:154-166`)
- [L2] **I3** `--headless` skips the connect splash so the UI is drivable immediately. (`main.cpp:182`)
- [L2] **I4** Clean graceful quit — WM_DELETE → `closeEvent` → exit 0, no hang/UAF.

**Coverage:** ~18 items at L0 (pure, instant), ~20 at L1 (in-process, the privacy core), ~13 at L2 (real E2E), 1 manual (F5).
