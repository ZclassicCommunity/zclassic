# Receive form — UX redesign ("don't make me think")

Goal: a newcomer should read the Receive tab as one sentence — *"this is my address, it's
**Private** so it's safe to share, here's a **Copy** that confirms itself, and if I want a
specific amount I type it and the QR + link carry it."* All changes are presentation-only and
preserve the privacy-load-bearing spine.

## What changed

| # | Change | Why |
|---|--------|-----|
| 1 | **Request amount (+ z-only memo)** bakes a `zclassic:<addr>?amt=&memo=` payment-URI into the QR + a **"Copy payment request"** button | The headline win: answers *"how do they pay the right amount?"* The payer's wallet pre-fills the exact amount — killing the #1 wrong-amount cause. Symmetric to the Send-side `payZClassicURI`, so a scanned request round-trips into Send. |
| 2 | **"Get paid"** headline + subhead; the private indicator becomes the **shared green badge** (`● Private — safe to share`) matching the Send tab | Answers *"what is this / is it safe to share?"* at rest, in plain words — not just a tooltip. |
| 3 | **Inline "Copied ✓"** on the Copy button (kept the status-bar message too) | Feedback at the cursor, not 600px away at the window bottom. |
| 4 | **QR → MEDIUM** error-correction | Scans far more reliably off a screen photo, and keeps the longer payment-URI payload scannable. |
| 5 | **Calm loading state** (`Preparing your address…`) + disabled actions during warmup | A blank field+QR read as "broken"; never a silent dead-click. |
| 6 | Visual-parity QSS tokens for the new controls | Receive feels like the same product as the redesigned Send tab. |

## Correctness (the load-bearing constraints)
- **Address recovery untouched.** Every new affordance reads the **raw** address from
  `AddressCombo::currentText()` (the `(`-split recovery path) — never re-parsed display text, and
  nothing is ever written back into the combo. `txtRecieve`'s plain text stays the **exact raw
  address** (Copy reads it verbatim), so chunking was deliberately **rejected** — readability
  comes from layout, not inserted spaces.
- **Private-by-default IA preserved.** Sapling z rests in front; t-Addr + legacy Sprout + Export
  key stay behind the collapsed *"Other address types (advanced)"* disclosure; the amber t-PUBLIC
  warning is kept. Privacy is strengthened (badge says "safe to share"; memo disabled for t-addrs),
  never weakened.
- **URI is parser-safe.** Amount via `getDecimalString` (round-trips through the parser's
  `toDouble()`); memo **hex-encoded** (the encoding payZClassicURI decodes) and appended **only** for a z-address, so it can never
  inject a `&`/`=` that would break `payZClassicURI`'s `split('&')`/`split('=')`.
- **No daemon/RPC/address-creation change** — `addNewZaddr`/`addNewTAddr` untouched; no auto-mint.

## Deferred (next pass)
- Click-to-copy on the address field + monospace "hero" presentation (via a *separate* display
  label so `txtRecieve` stays the raw address).
- "Save QR image…" PNG export; persisting/clearing the last request amount; New-address tooltip.
