# Send form — UX redesign ("don't make me think")

Goal: a non-expert should be able to answer the three questions that actually matter —
**who am I paying, exactly how much will it cost, and will the world see this** — *before*
they ever reach the confirm dialog. Every change here is presentation-only; none touch the
stabilized money/validation logic (`createTxFromSendPage`, `doSendTxValidations`,
`confirmedSpendableZat`, `spendableOrFallback`, `verifyAutoShieldUnchanged`).

## What changed, and why

| # | Change | Why (crypto-UX / Krug principle) |
|---|--------|----------------------------------|
| 1 | **Live privacy badge** above the form (`sendPrivacyBadge`) — green *Private*, *Shielding*, amber *Public*, red *De-shield* | The single most important fact for a shielded wallet was invisible until the confirm modal. Now the page itself tells one consistent privacy story, in plain words, as you type. Driven by the wallet's own `sendCategoryOf()` classifier — a pure display echo that errs toward the *stronger* warning. |
| 2 | Plain-language labels: **Pay from / Available to send / Pay to / Network fee / Review & send** | "From", "Address Balance", "Miner Fee" are jargon. Self-evident words remove the need to interpret. |
| 3 | **Teaching placeholders** — address: *"Paste a z-address (private) or t-address (public)"*; amount: *"0.00"* | Placeholder-as-label-word taught nothing. Now the field shows what a valid input looks like. |
| 4 | Always-on **`ZCL` unit** next to amount and fee | A money field with no unit is a classic make-me-think; the unit is visible before you type. |
| 5 | **Live amount border** (green when > 0, red when not), mirroring the existing live address border | Catches mistakes as you type, not as a surprise failure at Send. Local format check only — never compares to balance. |
| 6 | **`Review & send`** is the green primary/default button; **`Cancel` is forgiving** (confirms before discarding typed work) | The irreversible action is the visual anchor and maps to Enter; Cancel no longer silently destroys a half-typed payment. |
| 7 | **`Send all`** replaces the bare "Max Available" checkbox (checkable button) | A checkbox in the middle of the amount row was ambiguous ("max of what? did it break the field?"). An honest button reads as an action. Routes through the unchanged max math. |
| 8 | **Memos discoverable**: button reads *"Add private note"*, tooltips explain encryption, the note renders at base font prefixed *"Private note:"* | The big privacy feature (encrypted notes) was a greyed button with a hover-only tooltip. |
| 9 | **Running total** line: *"You'll send 1.50 + 0.0001 fee = 1.5001 ZCL (~$X)"* | No more mental math; the total is shown live. Aggregates on-screen amounts only — no new money math. |
| 10 | **De-nested** the single-recipient box-in-a-box; fee field no longer flashes a literal `0` | Less visual noise; calmer default. |

## Money-safety

All twelve changes are in safe seams (`mainwindow.ui`, `setupSendTab`/`addAddressSection`,
copy/label/qss, the presentation-only `updateSendPrivacyBadge`/`updateSendTotals`). The
privacy badge and confirm badge are **pure display echoes** of `sendCategoryOf()` (fail-safe:
an unparseable recipient is treated as transparent → stronger public/de-shield verdict). The
amount border is a local `> 0` check that never calls `doSendTxValidations`. The running total
only sums values already on screen; the authoritative amount still comes solely from
`createTxFromSendPage`. `Send all` keeps `Max1` checkable and routes through the unchanged
`maxAmountChecked`/`recomputeMaxIfChecked` path (only the widget class + a `toggled(bool)`
signal adapter changed).

**Memo note:** the "private note" framing lives only in the button label + tooltips. The memo
text label (`MemoTxt%N`) is stored **raw** and is byte-identical to canonical, because
`createTxFromSendPage` reads it verbatim as the on-chain memo — so no decoration is ever added
to the payload. (An earlier draft prefixed the label and was caught + reverted in review.)

## Deferred (next pass)
- Human-readable From-combo items (label + type word + spaced balance) — touches the `(`-split
  contract that recovers `tx.fromAddr`; land alone with a byte-identical round-trip assertion.
- Per-recipient remove control; per-row privacy badges; QR-scan / paste-and-fill on the address.
- Confirm-dialog: reuse the page badge component + "Total leaving / Left after" rows.
