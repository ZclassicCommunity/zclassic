# Privacy-by-default UX/UI roadmap — ZClassic wallet

> **Engineering / roadmap doc — not user documentation.** The Tier-0 items below are
> implemented on `feature/privacy-by-default-tier0` and are **not yet in the released
> v2.1.2-beta5**.

Goal: make the wallet **private by default**, **private without annoying the user**,
and **fast + secure**, grounded in the actual code (not generic advice). Produced by
a multi-agent audit of the real `.ui`/`.cpp` plus a live headless run of the shipped
build.

## Guiding principles
1. **Private by default, no action required.** Flip defaults rather than add opt-in
   toggles nobody finds.
2. **Never fail open silently.** A default that quietly degrades (auto-shield no-ops
   when no z-addr exists) is worse than none — guarantee the precondition or visibly
   disclose the transparent fallback.
3. **Privacy without annoyance.** No new blocking modals, no per-keystroke nags.
   Inform at the confirm dialog (where the user is already looking); gate one-time
   warnings behind a persisted flag.
4. **Tell the truth in warnings.** Reserve red for the genuinely harmful **z→t
   de-shield**, not already-public t→t. No fake zk-proof %, no overselling encrypted
   self-memos as on-chain leaks.
5. **Make the private path feel fast.** A silent multi-minute shielded proof pushes
   users toward fast transparent sends. Perceived speed is a privacy lever.
6. **Self-custody is the precondition.** An un-backed-up `wallet.dat` (no seed phrase)
   is the biggest catastrophic-loss vector.

## Tier 0 — shipped on `feature/privacy-by-default-tier0`
| # | Change | Files |
|---|--------|-------|
| 1 | **Wire up the dead backup nag.** `promptWalletBackup()` had zero call sites; now fires once per run on the first fully-synced poll with a positive balance (session one-shot, permanently silenced after backup). | `mainwindow.{h,cpp}`, `rpc.cpp` |
| 3 | **Fix unconditional t-addr minting.** `refreshAddresses()` minted a fresh transparent key roughly every block; guarded with `if (taddresses->isEmpty())` to match its own comment. | `rpc.cpp` |
| 5a | **Remove the new-Sprout creation backdoor** + add a red **"Transparent: PUBLIC on-chain"** caption when the t-Addr radio is selected on Receive (reuses `lblSproutWarning`). | `mainwindow.cpp` |
| 6 | **Memo Reply-to self-dox guard** — always-on tooltip + one-time consent on the first manual "Include Reply Address" click; the programmatic (recurring-send) path never blocks. | `sendtab.cpp` |
| 9 | **0600 the shielded send history** — `senttxstore.dat` (plaintext recipient+amount of every shielded send) is now owner-only at both write sites. | `senttxstore.cpp` |

**Dropped from Tier 0 after verification:** clipboard auto-clear (#8). The audit
assumed exported **private keys** were copied to the clipboard; reading the code,
**no private key is ever placed on the clipboard** — only addresses/txids (which the
audit itself rated minor). Not worth the same-value-guard complexity / mid-paste
surprise. Revisit only if a key-copy path is ever added.

## Tier 1 — planned (send-path / UX; needs careful testing before shipping)
- **#2 Shielded change by default** *(biggest by-default win)* — flip `getAutoShield()`
  ON **and** fix the silent fail-open (auto-create a Sapling z-addr if none exists,
  else disclose transparent fallback); drop the self-doxing "Change from <addr>" memo.
  `settings.cpp`, `sendtab.cpp`, `rpc.cpp`
- **#4 From-aware tx classification in the confirm dialog** — replace binary
  "any t-recipient = red" with **Fully private (z→z) / Shielding (t→z) / De-shielding
  (z→t, red) / Public (t→t)**. `sendtab.cpp`, `confirm.ui`
- **#7 Calm send-progress** — elapsed + real `z_getoperationstatus` phase, **no fake %**.
  `rpc.cpp`, `mainwindow.cpp`
- **#10 Stop the clear-net startup leak** — defer `checkForUpdate()`/`refreshZCLPrice()`
  off the connect path; **skip** (don't proxy) under Tor. `rpc.cpp`, `connection.cpp`
- **#11 Public/Private tag at the Pay-From combo** — must store the bare address in
  `Qt::UserRole` (the `split('(')` parse is fragile). `addresscombo.*`
- Collapse t-Addr + Sprout behind an "Other address types (advanced)" disclosure on
  Receive (deferred vs. the cheap PUBLIC caption above).

## Verified dead-ends (do not relitigate)
- **One-click "shield all" via `z_sendmany ANY_TADDR`** — the RPC rejects ANY_TADDR;
  only `z_mergetoaddress` accepts it (not called by the GUI).
- **Default-enable Tor** — no bundled Tor; `proxy=127.0.0.1:9050` with no listener
  kills all sync. Keep opt-in; reword the checkbox only.
- **Proxy the shared `restclient` for Tor** — it's the same `QNetworkAccessManager`
  as localhost node RPC → would sever the wallet from its own node.
- **Per-keystroke "fully private" badge** — `isZAddress` needs a complete checksum, so
  it flickers red the whole time you type. Put the airtight verdict in the confirm
  dialog instead.
- **In-GUI "Encrypt wallet…"** — `encryptwallet` is hard-gated behind
  `fExperimentalMode` + `-experimentalfeatures`. Only a per-send unlock prompt
  (reading `unlocked_until`) is salvageable.
