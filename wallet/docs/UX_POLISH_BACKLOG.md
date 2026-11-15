# Visual UX/UI Polish Backlog (2026-06-03)

Output of a four-lens design review (modern aesthetics, typography/readability, privacy-UX, simplicity/hierarchy) of the **shipped** redesign, judged from real screenshots.

**Verdict: polish-recommended, not a re-do.** All four lenses agree the information architecture is correct and modern (nav rail, private hero, badges, private-by-default Receive). The gap is *finish*. Two themes dominate:
1. **Privacy isn't carried by color where it matters most** — the hero balance is white (`dark.qss:~211`) while the loudest green at rest is a full-bleed "Synced" banner (`mainwindow.cpp:~998`), so the eye goes to chrome, not the user's private money.
2. **The Receive page is half-migrated** — the entire legacy form (second address combo, second QR, Label/Update Label, one-click Export Private Key) still sits below the new private card: redundant clutter and a privacy footgun (conflicts with SPEC UX-19 / KEY-1).

The rest is token-level. Ship P0 as a "visual-truth" pass, then P1 depth, then P2 long tail.

---

## P0 — visual truth & declutter (near-pure-QSS / low risk; highest impact)

- **[P0] Home — color the PRIVATE BALANCE hero GREEN** (`dark.qss` `#homeHeroPrivate`, currently white). Use a brightened green that passes WCAG AA on the dark card — **`#34c759`** (not `#1f7a1f`, which fails as text). Closes PRIV-21 / UX-6. *Highest impact, near-zero risk.*
- **[P0] Home — demote the "Synced — Ready to use" banner** from a full-bleed saturated green bar (`mainwindow.cpp:~998`) to a quiet inline pill (24px, radius 12px, green dot + "Synced" in `#9aa0a6`/13pt). Reserve the full-width colored banner ONLY for syncing/error (amber/red). At rest, green lives on the balance, not the chrome.
- **[P0] Receive — delete the legacy lower form** (second Address box/combo, Label/Update Label, "Address balance", second QR). Fold only the useful pieces into the new "Receive privately" card. Removes the biggest clutter in the app.
- **[P0] Receive — move "Export Private Key" off the page** entirely, behind the Advanced gear (or per-address overflow) with an explicit confirm. A key-export action must never rest on the default Receive view (UX-19 / KEY-1).
- **[P0] Receive — frame the QR in a card** instead of an unframed white slab bleeding to the window edge: white QR in a rounded container (radius 12px, ~16px quiet-zone padding), on the dark surface with a 1px `#2a2d35` border, fixed ~200×200, centered in a right column.

## P1 — depth, consistency, primary actions

- **[P1] Home — bump hero to ~40pt/700** (currently ~28pt). The #1 explicit ask is bigger fonts; target a ~3× hero-to-body ratio (40pt vs 13pt).
- **[P1] Home — collapse the redundant Summary breakdown.** Balance is shown up to 4×: hero + Total subline + Shielded/Transparent/Total rows + Address Balances table. Keep hero (Private headline + dim Total subline); drop the standalone breakdown rows (detail already lives badge-tagged in Address Balances).
- **[P1] All screens — surface elevation token system.** 2–3 steps: app bg `#0f1115` → card `#15171c` → inset `#1d2027`, 12px radius, 1px `#2a2d35` border, subtle shadow on top-level cards. Cards currently read as flat zones.
- **[P1] Standardize the privacy badge component:** pill height 20px, radius 10px, 8px h-padding, 11pt/600, 12px icon optically centered, filled-tint bg (~15% token color) + full-strength text/border. Fixes inconsistent widths + cell clipping.
- **[P1] Receive — add a primary "Copy" button** adjacent to the address (≥40px), demote "New Address" to secondary. Copy is the most common Receive action and is currently absent (UX-24).
- **[P1] Unify public color: amber `#d9822b` = PUBLIC/transparent everywhere** (badge, Shield card, AND the Receive transparent warning). Reserve red `#c0392b` exclusively for **de-shield** (z→t send confirm + Activity de-shield rows). Aligns with PRIV-14.
- **[P1] Receive — recolor the t-Addr radio dot off green.** A green dot on the transparent option contradicts "green = private." Use amber + the eye icon, so color always equals privacy state.
- **[P1] Friendly empty states (UX-22):** under the 0 ZCL hero add "Your private balance — receive ZCL to get started"; replace the empty Address Balances body with a centered "No addresses yet" block; make **Receive** the primary action when balance == 0.
- **[P1] Home — fix-it card:** raise body to 13pt, button to 12pt with ≥44px target; soften from a saturated amber flood to an amber-tinted card + left-accent bar + normal body text (guidance, not alarm).
- **[P1] Home — wire the fix-it button to the REAL shield flow** (PRIV-18): pre-populate Send From=transparent, To=default Sapling (auto-create per PRIV-19), amount=full transparent. (Also a Phase-0 item.)
- **[P1] Nav — raise the Advanced gear label to `#9aa0a6`** (currently ~`#6b7177`, ~3.1:1, fails AA). Never go below `#9aa0a6` for live clickable text (UX-18).
- **[P1] Receive — soften the red PUBLIC warning** into a callout card: bg `rgba(192,57,43,.12)`, 1px `rgba(192,57,43,.4)` border, radius 8px, warning-triangle icon, "PUBLIC" bold but body in a lighter danger tint (`#e06b5e`, ~6.5:1) — currently full-bold red ~4.3:1 reads as a crash message.

## P2 — long tail

- **[P2] Adopt a discrete 1.2 modular type scale** (11 / 13 / 15 / 18 / 40), snap every token to it, collapse the ad-hoc 10/11/12 cluster.
- **[P2] Section titles must not be smaller than body** — set QGroupBox::title / "Receive privately" to 12–13pt/700 `#e6e6e6` (keep quiet via case/spacing, never sub-body size).
- **[P2] Replace boxed Summary rows with a clean key/value list** (label left `#9aa0a6`/13pt, value right `#e6e6e6`/14pt/600, 1px divider above Total only; Transparent value amber when >0).
- **[P2] Single-source status:** when synced, status bar reads "Synced · block 1,700,000" (thousands separators), drop "checking blockchain…"; remove the top banner at rest so there's exactly one indicator.
- **[P2] Define a content container:** 24px outer padding, ~1100px max readable width centered when wider, equal left/right margins so nothing bleeds to the window edge.
- **[P2] Unify the Summary card into ONE component** (hero → quick actions → conditional fix-it → breakdown), in fixed order — the two Home shots show divergent layouts; delete the bare-breakdown variant (UX-25).
- **[P2] Receive — fold Label inline** under the address as an optional secondary row + a one-line reassurance ("Funds sent here stay private. Share this address freely.").
- **[P2] Consistent privacy vocabulary:** pick "Private" as the user-facing word ("Shielded" as tooltip); drop the redundant "Shielded" sub-row when the hero already states it.

---

*Cross-reference: items tagged with SPEC IDs (PRIV-14/18/19, UX-6/18/19/22/24/25) close or advance existing SPEC.md requirements. P0+P1 should be built before handing the wallet to the user.*
