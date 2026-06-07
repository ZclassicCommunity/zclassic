# Transparent-Value Shielded Pool (TVSP) for Zclassic

**A shielded pool that makes per-transaction value conservation public and exact — removing the homomorphic value-balance / binding-signature soundness class — while keeping participant (sender / receiver / graph) privacy. It narrows, but does not eliminate, proof-system counterfeiting risk.**

Status: Draft proposal (v2, corrected security claims) · Target: Zclassic (ZipherX), Sapling/Groth16 lineage · Audience: protocol engineers, reviewers

> **What changed in v2.** v1 of this document overclaimed. It said public amounts make the supply "provably non-inflatable" and that any soundness bug becomes "immediately visible." That is false: the privacy that hides *which* note is spent also hides whether the value claimed for that note is legitimate. Public amounts make value *arithmetic* public — they do **not** make note *existence* or *uniqueness* public. v2 states the honest, narrower claim and is explicit about what remains inside the proof. The Orchard premise is also corrected to match the official Zcash Foundation disclosure.

---

## 1. Abstract

Every privacy coin that hides transaction **amounts** inside a zero-knowledge proof concentrates a lot of trust in one place: the soundness of the shielded circuit (and, for Groth16, its trusted setup) plus the binding of its value commitments. If the value-conservation argument inside the proof is wrong, value can be forged inside the pool, and because the amounts are hidden the forgery carries no obvious on-chain signature — it is contained, but not necessarily *seen*, by a turnstile.

The June-2026 Zcash **Orchard** incident is the reference point, and it is worth stating precisely (see §2.1): it was *a soundness bug in the `halo2_gadgets` Orchard Action circuit* that could "accept invalid state transitions … potentially permitting **double-spending** of funds within Orchard." The Zcash Foundation was explicit that there was **"no ability to inflate the total ZEC supply, which is protected by Zcash's turnstile mechanism."** So the canonical 2026 incident is a *double-spend / invalid-state-transition* bug whose supply impact was **contained by the turnstile** — not the "unlimited undetectable minting" of market commentary.

This proposal takes a deliberate design choice for a *new* Zclassic shielded pool: **make the note value public, keep the participants private.** The amount of every note is published in the clear; the proof is reduced to *spend authority + note membership + value-binding + nullifier correctness* and no longer carries a homomorphic value balance. Value conservation becomes ordinary public integer arithmetic enforced by consensus.

The honest result:

- **Per-transaction value conservation becomes a public, exact, non-circuit consensus check.** A transaction that does not conserve value is rejected in the clear. The *homomorphic value-balance / binding-signature* soundness class — a category of under-constrained in-circuit value arithmetic — is removed by construction. (This is **adjacent to but distinct from** the Orchard Action-circuit bug, which the official record describes as an invalid-state-transition / double-spend bug that TVSP does *not* fully fix — §6.2.)
- **The proving circuit shrinks** to authority + membership + value-binding + nullifier: a strictly smaller, easier-to-audit surface.
- **The pool's net solvency is continuously, publicly auditable** — `nChainTVSPValue` is reconstructible from public data at every height, so the turnstile becomes *exact* rather than derived from hidden commitments.
- **Sender, receiver, and the input↔output link remain hidden** — the proof still hides *which* note is spent and *who* owns it.

And the honest limits (§6 in full):

- **It does NOT make the supply "provably non-inflatable."** Membership, value-binding, nullifier, and authorization soundness all still live inside the proof. A bug in any of them still injects value, and that injection is **bounded — not detected — by the (now-exact) turnstile, exactly as today.** Public amounts prove arithmetic, not the existence or uniqueness of the notes behind it.
- **Amount privacy is given up**, and because public amounts leak linkage via amount-correlation, robust graph privacy requires **fixed denominations** (a mixer-style pool).

This is a *different* privacy model than Zcash, not a strictly superior one. It trades amount-confidentiality for a smaller, public, exactly-auditable value surface — with the residual ZK risk **contained, not eliminated**.

---

## 2. Motivation

### 2.1 The Orchard incident, stated correctly

The official Zcash Foundation disclosure (Zebra 4.5.3 / 5.0.0 emergency soft fork, NU6.2) describes the bug as:

> "a soundness bug in the implementation of the Orchard zero-knowledge proof circuit in the `halo2_gadgets` crate … could allow the Orchard pool to accept invalid state transitions … potentially permitting **double-spending** of funds within Orchard."

and, crucially:

> "**no ability to inflate the total ZEC supply, which is protected by Zcash's turnstile mechanism** … [the turnstile] tracks the total ZEC balance across all value pools [and] provided a ground truth that ecosystem participants could use to confirm the supply cap remained intact."

The advisory is tracked as **GHSA-jfw5-j458-pfv6** (Critical), mitigated by a soft fork temporarily disabling Orchard actions. The disclosers' official post-mortem (*The Orchard Counterfeiting Vulnerability — And Next Steps*) gives the most precise primary root cause: *"an under-constrained element of the Orchard circuit, because of which it was possible to put arbitrary false inputs into an elliptic curve multiplication and still have the multiplication check pass."* No primary source names a specific gadget; the finer "variable-base scalar-multiplication" attribution circulating in community and third-party write-ups is **not** in any primary disclosure, so this document does not assert it.

Two lessons for this proposal, and both cut against the v1 framing:

1. The 2026 incident is a **double-spend / invalid-state-transition** bug — exactly the class TVSP does **not** fully fix (see §6.2). It is *not* an example of undetectable supply inflation.
2. In that incident the **turnstile provided the containment / ground-truth mechanism**; had exploitation occurred, it would have bounded cross-pool extraction at the supply level. The turnstile is not "only a seatbelt that proves nothing"; it is a real, load-bearing layer — which is precisely why TVSP keeps it (made exact), rather than replacing it.

For context, the April-2026 Zcash advisories also included a **turnstile-accounting bypass** (a re-seen block header silently overwriting a block index's pool-balance fields with `nullopt`, disabling enforcement across blocks) and a **signed-integer overflow in per-pool value-delta computation** that "could potentially have caused turnstile checks to be skipped, consensus validation to return early, or pool balance values to be computed incorrectly." These are directly relevant to TVSP's implementation surface (§7): TVSP moves *more* logic into public pool arithmetic, so that arithmetic must be overflow-safe and applied on every path.

### 2.2 The structural problem TVSP targets

In Sapling (Zclassic's current shielded pool) the value `v` of a note is never revealed. It is carried in a homomorphic **Pedersen value commitment**

```
cv = [v]·V + [rcv]·R          (V, R = fixed independent generators)
```

and a **binding signature** over the sum of all `cv` proves

```
Σ cv(inputs) − Σ cv(outputs) = [valueBalance]·V
```

i.e. that inputs and outputs balance — without revealing any individual `v`. Conservation therefore rests on **two** in-circuit / commitment properties being simultaneously correct:

1. the value commitment being **binding**, and
2. the Spend/Output **circuit being sound** so the `cv` matches the note actually owned.

If either fails, an attacker can make a transaction *appear* to conserve value when it does not, minting value inside the pool. TVSP removes this specific failure mode by deleting `cv` and the binding signature and checking conservation as public integers instead (§4.5).

### 2.3 What the turnstile does and does not do — precisely

A turnstile (Zcash's ZIP-209; the same mechanism Zclassic now enforces — see §2.4) tracks the pool's net balance and **rejects any block that would drive it negative**. It is genuinely valuable (it held supply during the Orchard incident), but its guarantee is **net solvency bounded by liquidity**, not per-note provenance:

| The turnstile **does** | The turnstile **does not** |
|---|---|
| Cap the maximum extractable counterfeit at the pool's real liquidity | Prevent extraction up to that liquidity |
| Detect insolvency **at the boundary** (when net balance would go negative) | Detect a counterfeit while the pool stays net-solvent (latent) |
| Contain counterfeit inside the pool boundary | Recover funds, identify the attacker, or prove no counterfeit exists internally |

This is true under Sapling **and under TVSP**. TVSP makes the turnstile *exact and public* (anyone can recompute it), but does **not** change its essential nature: it bounds, it does not detect-per-note. The improvement TVSP brings is to the *value-conservation* check (§4.5), not to the turnstile's containment semantics.

### 2.4 Status in the current Zclassic tree

This is no longer aspirational: the current ZipherX tree enables ZIP-209 on mainnet (`src/chainparams.cpp` — `fZIP209Enabled = true`, Sprout checkpoint at height 3,000,000, balance `1316412375709`), and `ConnectBlock` rejects negative Sprout/Sapling pool balances under `if (chainparams.ZIP209Enabled())` (`src/main.cpp:2590`). Sapling nullifier double-spend checks are present (`src/coins.cpp:596`). An exhaustive `--full` history scan found `negative_pool_events: 0` across all ~3.13M blocks, and both pools are net-positive at the tip — strong evidence **no net drain has occurred**, but (as the audit notes themselves state) **not** proof of the absence of a latent, unexploited circuit bug. That gap is exactly what motivates moving value out of the proof.

### 2.5 The design goal

> Keep **who** private. Make **how much** public, conserved by plain arithmetic, and shrink the proof to the smallest authority+membership+nullifier statement.

---

## 3. Design overview

We introduce a new shielded transaction type — the **Transparent-Value Shielded Pool (TVSP)** — alongside (not replacing) the existing transparent and Sapling pools. Funds enter via a *shield* action and leave via an *unshield* action; internal transfers move value between TV-notes.

A **TV-note** is the same as a Sapling note **except its value is public**:

```
TV-note = ( diversifier d, pk_d, value v, rcm )      // v is published in the clear
commitment  cm = NoteCommit( g_d, pk_d, v )           // unchanged: cm still commits to v
```

Compared to Sapling, the change is surgical:

| Component | Sapling (today) | TVSP (proposed) |
|---|---|---|
| Note value `v` | **hidden** (witness) | **public** (in the tx, and a *public input* to the circuit) |
| Value commitment `cv` | present (`[v]·V+[rcv]·R`) | **removed** |
| Binding signature | present (proves Σ`cv` balances) | **removed** |
| Value-conservation check | homomorphic commitment balance (in-proof) | **plain public arithmetic in consensus** |
| Spend circuit proves | authority + membership + nullifier + value commitment | authority + membership + nullifier + **value-binding of public `v` to `cm`** |
| Nullifier `nf` | `BLAKE2s(nk‖ρ)` | unchanged (own domain — see §7) |
| Spend authority `rk` | `ak + [ar]·G` | unchanged |
| Note encryption | encrypts `v` to recipient | recipient still gets a memo/key; `v` no longer needs hiding |

Everything that provides **participant privacy** (membership-hiding spend, hidden spend authority, nullifiers, diversified addresses) is **kept**. The **value commitment and binding signature** are **removed**, and the amount is published and conserved by consensus arithmetic. The value-binding constraint (`cm` opens to the declared public `v`) **moves into the proof** and becomes a high-value audit target (§6.2).

---

## 4. Technical specification

### 4.1 Note and commitment

A TV-note commits to its value exactly as Sapling does:

```
cm = PedersenHash( NoteCommit_personalization, [ value(64 bits) ‖ g_d(256) ‖ pk_d(256) ] ) + [rcm]·NoteCommitRandomness
```

The only change is that `value` is **also revealed in the clear** in the spend/output description, and the circuit takes `value` as a **public input** (not a private witness). The circuit must prove that the opened `cm` uses exactly that public `value`. This binds the public value to the note — **conditional on the NoteCommit gadget and the membership path being sound** (see §6.2; this is *not* a free public guarantee, it is an in-circuit one).

### 4.2 Transaction format

A new transaction version `TVSP_TX_VERSION` (new `nVersionGroupId`, new consensus branch ID) carries:

```
tvSpends[]  : { anchor, nullifier nf, rk, value v_in (PUBLIC), zkproof }      // no cv, no bindingSig
tvOutputs[] : { cmu, ephemeralKey, encCiphertext, value v_out (PUBLIC), zkproof }
valueBalanceTVSP : signed integer (net public value leaving the pool to transparent)
```

`v_in` and `v_out` are explicit public integers. There is **no** `bindingSig`. The sighash must cover all public value fields and `valueBalanceTVSP`.

### 4.3 Spend circuit (TVSP)

Identical to the Sapling Spend circuit **minus** the value-commitment gadget. It proves, for a public `value v_in`:

1. The prover knows `ak, nsk` ⇒ `nk = [nsk]·G`, `ivk = CRH(ak, nk)`.
2. `rk = ak + [ar]·SpendAuthGenerator` is exposed (re-randomized spend-auth key; the spend signature verifies against `rk`).
3. The note commitment `cm = NoteCommit(g_d, pk_d, v_in)` opens to the **public** `v_in` (value-binding constraint).
4. `cm` is a member of the note-commitment tree at the public `anchor` (Merkle path), gated by `v_in ≠ 0` (dummy notes exempt).
5. `nf = PRF^{nf}(nk, ρ)` is correctly derived and exposed.

It does **not** prove anything about a value commitment, and there is no homomorphic value balance inside the proof. Constraints (3), (4), (5) are the residual soundness-critical surface (§6.2).

### 4.4 Output circuit (TVSP)

Identical to Sapling Output **minus** the value-commitment gadget. It proves, for a public `value v_out`, that `cmu` is a correct note commitment to `(g_d, pk_d, v_out)`.

### 4.5 Consensus: value conservation is now public arithmetic

TVSP mirrors the existing Sapling convention exactly — it does **not** invent a per-pool fee equation. Define the net public flow as a single signed quantity:

```
valueBalanceTVSP  :=  Σ tvSpends[i].v_in  −  Σ tvOutputs[j].v_out
```

with the same sign meaning as Sapling's `valueBalance`: **positive** = value leaving the TVSP pool *into* the transparent value pool (acts like a transparent input); **negative** = value entering the TVSP pool *from* transparent (acts like a transparent output). Consensus folds it into the **global** transaction value pool exactly as the code does for Sapling (`GetShieldedValueIn()` / `GetValueOut()`):

- `GetShieldedValueIn()` adds `valueBalanceTVSP` when it is **positive** (like an input);
- `GetValueOut()` adds `−valueBalanceTVSP` when it is **negative** (like an output).

The **fee is the single global remainder across all value pools**, never attributed to the TVSP component:

```
nValueIn  =  Σ(transparent vin)  +  GetShieldedValueIn()     // incl. +valueBalanceTVSP, sprout vpub_new, sapling
require    nValueIn  ≥  GetValueOut()                         // GetValueOut incl. −valueBalanceTVSP
fee       =  nValueIn  −  GetValueOut()                       // one global subtraction (CheckTxInputs)
```

There is **no** `+ fee` term inside any per-pool balance equation. (An earlier draft wrote `Σ v_in == Σ v_out + fee + valueBalanceTVSP`; that wrongly localizes the fee to the shielded pool and is rejected — see `src/main.cpp:2135,2140,2146` and `src/primitives/transaction.cpp:285,309`, where the fee is the global remainder spanning transparent + sprout + sapling.) As `CheckTransaction` does for Sapling (`src/main.cpp` ~1252–1260), consensus also range-checks `|valueBalanceTVSP| ≤ MAX_MONEY` and rejects a non-zero `valueBalanceTVSP` when there are no TVSP spends/outputs.

The pool-level invariant (an exact, public turnstile) — accumulating the per-block delta as `−valueBalanceTVSP`, mirroring `src/main.cpp:4117`, with checked arithmetic (§7):

```
nChainTVSPValue  =  Σ (value shielded in)  −  Σ (value unshielded out)   ≥  0   at every height
```

**What this does and does not guarantee.** The global value-conservation rule is a *hard public guarantee*: a transaction whose inputs do not cover its outputs (across all value pools) is rejected in the clear, no circuit involved. The pool invariant is *net solvency*: it is exact and public, but — as §2.3 and §6.2 explain — it bounds counterfeit extraction at the pool's liquidity; it does **not** detect a counterfeit that is balanced internally or extracted within available liquidity. Per-note provenance is not public (privacy hides which note is spent), so the soundness of constraints §4.3(3)–(5) still matters.

### 4.6 What is no longer needed

- The **binding signature** and its key.
- The **value-commitment generators** and the `[v]·V` / `[rcv]·R` gadgets in both circuits (a real reduction in circuit size and in the soundness-critical surface).
- Encrypting the value to the recipient is optional (the value is public); the encrypted memo channel is retained for the rest of the note plaintext.

---

## 5. Privacy model — what you keep, what you lose

### 5.1 Kept (participant / graph privacy)

- **Which note is spent is hidden** — membership-hiding spend, exactly as Sapling.
- **Spender identity is hidden** — only `rk` (a re-randomization of the spend-auth key) is revealed; unlinkable across spends.
- **Recipient identity is hidden** — outputs reveal only `cmu` and an ephemeral key.
- **Nullifiers** prevent double-spends without linking to the note.

### 5.2 Lost (amount privacy) — and the correlation caveat

- **Amounts are public.** An observer sees that "13.37 ZCL" moved (but not who).
- **Public amounts leak linkage.** A spend of `13.37` and an output of `13.37` are probably the same flow — *amount-correlation* re-links inputs to outputs even though the specific note is hidden. With arbitrary values, graph privacy **largely collapses**.

### 5.3 The fix: fixed denominations (and segregated denomination trees)

To preserve graph privacy with public amounts, TVSP should operate on **fixed denominations** (e.g. notes only in {0.01, 0.1, 1, 10, 100} ZCL). Then every spend and output of a given denomination is identical in value → no amount-correlation, and the anonymity set is "all notes of that denomination." This turns TVSP into a **denomination pool / mixer**:

- Arbitrary amounts are expressed as a **set** of fixed-denomination notes (like cash).
- The anonymity set for each note is the count of same-denomination notes ever created.
- UX cost: wallets split/merge into denominations (more notes per transaction); liquidity fragments per bucket; low-volume chains accumulate large anonymity sets slowly. Timing + public value + network observation still permit statistical attacks even with denominations.

**Security bonus:** if each denomination has its **own commitment tree** and a spend declares which tree it draws from, then `v_in` is *structurally* fixed to that denomination. This upgrades the "open a real note to a higher `v`" defense (§6.2) from circuit-dependent to structural — you cannot spend a denom-1 note as denom-100 because it is not in the denom-100 tree. (Membership-forgery and double-spend *within* a denom tree still rest on the circuit.) Segregated denomination trees are therefore recommended both for privacy and for narrowing the residual soundness surface.

**Honest core trade-off:** strong graph privacy + public amounts is achievable only via fixed denominations. With free-form amounts you get public conservation but weak graph privacy.

---

## 6. Security analysis (corrected)

### 6.1 What TVSP genuinely fixes

- **Removes the homomorphic value-balance / binding-signature soundness class.** Conservation is checked as public integers; there is no `cv` to mis-bind and no binding signature to be unsound. A transaction that does not conserve value cannot be validly included — it is rejected in the clear by consensus, not by a circuit. This removes the *homomorphic value-balance / binding-signature* category of in-circuit value-arithmetic soundness bug. That category is **adjacent to but distinct from** the Orchard Action-circuit bug, which the official record describes as an invalid-state-transition / double-spend bug (an under-constrained element that let false inputs pass an elliptic-curve multiplication check; §2.1) — a class TVSP does *not* fully fix (§6.2). No primary source attributes the Orchard bug to a specific named gadget, so none is claimed here.
- **Shrinks the proving circuit** to authority + membership + value-binding + nullifier — fewer constraints, smaller audit surface, and (relative to Sapling) the deletion of the value gadgets is a net auditing win.
- **Makes net pool solvency continuously and publicly auditable.** `nChainTVSPValue` is exact and recomputable from public data at every block — the **non-negative net pool balance is publicly recomputable** at every height, with no forced migration or “prove-supply” ceremony required. (This is net balance only; it does **not** certify the absence of a latent, internally-balanced counterfeit, which remains turnstile-bounded, not detected — §6.2.)

### 6.2 What TVSP does **not** fix (the honest limits)

TVSP **does not** make the supply "provably non-inflatable," and over-claims are **not** "immediately visible." Membership, value-binding, nullifier, and authorization soundness remain inside the proof, and the privacy that hides *which* note is spent also hides whether its claimed value is legitimate. Therefore:

- **Forged membership (counterfeit note from nothing).** A bug that proves membership of a `cm` never inserted into the tree, with public `v=10`, lets you spend it → output a real `v=10` note. The per-tx equation balances (you control both sides); `nChainTVSPValue` only drops on unshield, and only goes negative once cumulative fake extraction exceeds the pool's **total real liquidity**. Until then nothing looks wrong. **This is "accumulate undetectable fake value, drain later" — the seatbelt, not a real-time ledger.**
- **Value-binding break (open a real low-`v` note to a higher `v_in`).** If §4.3(3) is under-constrained, an attacker spends a real `v=5` note declaring `v_in=10`. Consensus cannot catch it, because membership privacy hides *which* note was spent, so it cannot compare `v_in=10` to the note's creation value `5`. Invisible per-tx; bounded only by liquidity. *(Segregated denomination trees, §5.3, neutralize this specific sub-case structurally.)*
- **Double-spend / nullifier soundness.** A bug that lets one note produce two valid nullifiers permits spending it twice; each spend can be internally balanced. The over-extraction is bounded by the turnstile but is **not** visible as a per-tx imbalance. Detectable only as eventual net insolvency, exactly as today.
- **Spend-authority break.** A bug allowing a forged authorization lets an attacker spend notes they don't own — theft up to available liquidity. Value-public does not address this.
- **Trusted-setup residue (if Groth16 is kept for the reduced statement).** A ceremony compromise can no longer forge *value* (value is public arithmetic) but can still forge spends (theft / double-nullify of real notes). Smaller scope than full value-forgery, still serious. Pairing TVSP with a **transparent-setup** proof system (Halo 2 with the IPA/inner-product commitment, or a STARK) removes the **ceremony-class residual entirely** — no trusted setup, no toxic waste, no parameter-generation ceremony to compromise. It does **not** remove proof-system or circuit (constraint-system) soundness risk, which is independent of how parameters are generated. And transparency ≠ post-quantum: **Halo 2-IPA rests on the elliptic-curve discrete-log assumption and is *not* post-quantum** (Shor breaks it); only a hash-based **STARK** is plausibly post-quantum.

**The correct one-line claim:** TVSP prevents incorrect hidden-value *openings* and removes the homomorphic-balance soundness class; it **does not** eliminate proof-system counterfeiting as a class. Any residual membership/value-binding/nullifier/authority bug still injects value that is **bounded — not detected — by the (now-exact) turnstile.** The win is a smaller, public, exactly-auditable value surface with the residual ZK risk *contained*, not eliminated.

### 6.3 Where TVSP sits on the spectrum

```
Transparent (Bitcoin)   everything public · no privacy · supply trivially auditable · public UTXO arithmetic; no hidden-pool inflation opacity
TVSP (this proposal)    WHO hidden · HOW MUCH public · per-tx conservation public+exact · net solvency public+exact
                        · residual membership/nullifier/authority soundness still in-proof, turnstile-bounded
                        · graph privacy strong only with fixed denominations                              ← here
Sapling / Orchard       everything hidden · max privacy · supply rests entirely on circuit+binding+setup
                        · value-forgery AND double-spend risk if a soundness bug exists (turnstile bounds supply)
```

TVSP is a coherent **middle point**: it sacrifices amount-confidentiality to make value conservation public/exact and to shrink the proof, while retaining identity/graph privacy and *containing* (not removing) the residual ZK risk.

---

## 7. Implementation risks — new code, new consensus surface

A correct TVSP fork is much more than new fields. Each item below is a place a bug would re-introduce the exact "accept bad value flows" class that the historical IBD bypass (CR-01) enabled for Sapling.

- **Checked arithmetic everywhere — already started.** The per-pool delta path has already been hardened in the working tree: `ReceivedBlockTransactions` accumulates the Sprout/Sapling deltas via `CheckedAddTo` (`src/main.cpp:4117`, `4123–4124`; helpers `CheckedAdd` / `CheckedAddTo` at `src/amount.h:40–52`), falling back to `boost::none` on overflow, and chain-value propagation uses `CheckedAdd` — mirroring the April-2026 Zcash fix for the signed-integer per-pool-delta overflow class. *(As of this writing these changes are uncommitted in the working tree — unbuilt/untested.)* TVSP must extend the same `CheckedAddTo` / `CheckedAdd` discipline to `nChainTVSPValue` and every new per-tx check, including the sign handling on `valueBalanceTVSP`.
- **Separate pool plumbing.** New nullifier set, anchor DB, commitment tree, mempool nullifier maps, and a chain-index running total (`nChainTVSPValue`) — likely with a block-header commitment analogous to `hashFinalSaplingRoot` (`src/primitives/block.h`).
- **Domain separation.** TVSP commitments and nullifiers must use distinct personalization / a strictly separate tree from Sapling, or cross-pool replay/confusion becomes possible.
- **Consensus-enforced denominations.** Wallet-only denominations do not protect privacy or bound the value-binding surface; the denomination set (and, ideally, segregated trees, §5.3) must be a consensus rule.
- **Apply the check on every path.** The per-tx conservation and exact turnstile must run in `CheckTransaction` / `ContextualCheckTransaction` / `ConnectBlock` for **all** node states. Apply the CR-01 discipline (no validation shortcut during IBD/import/reindex) to the new paths from day one. A reindex under a buggy TVSP binary would be dangerous.
- **Reorg / reindex correctness.** `nChainTVSPValue` and the TVSP nullifier/anchor sets must rewind correctly on reorg and re-accumulate correctly during reindex/IBD.
- **Format surface.** New `nVersionGroupId`, branch ID, parser/serialization (public value fields, no `bindingSig`), sighash coverage, RPC encoding, `getblocktemplate`/miner policy, wallet note structures.
- **Legacy-pool policy.** While Sapling/Sprout shielding remains enabled, global supply still inherits their hidden-pool risk. Draining a legacy pool makes its *final net* auditable but does **not** retro-prove no prior inflation.
- **Orthogonal hardening still applies.** Bootstrap/fast-sync trust (no signed manifest in the reviewed tree), proving-key/parameter trust, DoS via many small-denom notes or large proofs, side-channels in proof generation — none are solved by TVSP.
- **Not post-quantum by itself.** The retained ZK is still discrete-log / Jubjub / Groth16; transparent ECDSA unchanged. TVSP can be *paired* with a PQ proof system but does not provide PQ guarantees on its own.

---

## 8. Recommendations (if pursuing TVSP)

1. **First, independently of TVSP:** patch Zclassic's existing pool accounting with checked-delta arithmetic and add chain-value recomputation / checkpoint tests (this also hardens the live ZIP-209 path).
2. Treat the public-conservation and exact-turnstile enforcement as consensus-critical; add property-based / differential tests: replay historical flows, force over-claims and duplicate nullifiers, and assert that invalid TV txs are rejected **even under `isInitBlockDownload()`**.
3. Use **fixed denominations from the start** for any claim of strong privacy, and prefer **segregated denomination trees** (privacy + structural value-binding). Document the anonymity-set math and correlation/timing risks.
4. Regenerate keys for the reduced circuit; strongly prefer a **transparent-setup** proving system for the residual authority+membership+nullifier statement (note: Halo 2-IPA is transparent but **not** post-quantum; only a hash-based STARK is plausibly post-quantum).
5. Separate activation height + a **mixed-pool test matrix** (Sapling spend + TV shield/unshield/internal in one block, reorgs, reindex from genesis).
6. Expose `nChainTVSPValue` (and the sum of public output values) via **RPC + block explorer** as a live, independently verifiable shielded-supply figure.
7. Commission a **focused audit on the delta**: removed value gadgets vs. added public checks and the value-binding constraint (§4.3(3)) + the new consensus arithmetic. Consider formal methods / circuit-equivalence checks for the retained NoteCommit + membership + nullifier logic.
8. **Sunset policy:** Sapling spendable long-term; new shielding into Sapling eventually disabled; users migrate at their pace — bounding ceremony risk for the old pool.
9. **Public communication:** this is a deliberate privacy-model shift (identity/graph privacy + public amounts + public conservation + *contained* residual ZK risk), **not** "Zcash but more private" and **not** "provably non-inflatable supply." Set expectations accordingly.
10. Gate any TVSP work on completing the broader hardening already surfaced in the repo's own audit documents (CR-01 IBD discipline, ZIP-209 correctness, download verification).

---

## 9. Conclusion

The Orchard episode showed that putting value *inside* a ZK proof makes supply integrity rest on the fallible circuit + binding + setup, and that a turnstile contains the blast radius at the supply level (it did, in 2026) without proving the absence of an internal bug. TVSP responds by publishing amounts and proving only *authority + membership + value-binding + no-double-spend*: per-transaction conservation becomes a public, exact, non-circuit consensus check; the proof shrinks; and net pool solvency is continuously, publicly auditable.

What TVSP does **not** do is equally important and was overstated in v1: it does not make the supply "provably non-inflatable," and it does not make over-claims "immediately visible." Membership, value-binding, nullifier, and authorization soundness remain inside the proof, and any bug there still injects value that the (now-exact) turnstile **bounds but does not detect** — the same containment semantics as today. The honest claim is narrower and still worthwhile: **a smaller, public, exactly-auditable value surface, with the residual ZK risk contained rather than eliminated, in exchange for amount confidentiality and a denomination-based UX.**

It is not "more private than Zcash." It is **differently private, with public value conservation** — a defensible choice for a chain that wants its shielded value arithmetic in the open and its proving surface as small as possible, while being candid that a latent membership/nullifier/authority bug would still be contained, not impossible.

---

### Appendix A — Why "value as a public input" binds the amount, and exactly how far that goes

Making `value` a public input and constraining `cm = NoteCommit(g_d, pk_d, value)` ties the declared public `v_in` to the specific committed `cm` — **provided the NoteCommit gadget and the Merkle membership path are sound, and the spent `cm` is genuinely in the tree.** What this does *not* provide is a *public* check that `v_in` equals the value the note was created with: the spend hides which note it is, so consensus cannot make that comparison. The binding is therefore an **in-circuit** guarantee (as strong as constraints §4.3(3)–(4)), not a free public one. Segregated denomination trees (§5.3) convert the value-binding into a *structural* public guarantee for the denomination dimension, which is why they are recommended.

### Appendix B — Relationship to the turnstile (ZIP-209)

ZIP-209 enforces `pool balance ≥ 0`. In Sapling those flows are derived from hidden commitments; in TVSP the same constraint is enforced on **public** per-transaction values, so `nChainTVSPValue` is fully reconstructible from chain data and the turnstile is *exact*. But "exact" refers to the **net** balance, not to per-note provenance: TVSP's turnstile, like Sapling's, **bounds** counterfeit extraction at the pool's liquidity and surfaces only **net** insolvency. It is ZIP-209 with the amounts in the open — a better, public, recomputable seatbelt, not a per-note fraud detector.

### Appendix C — Contrast with the Zinnia / STARK direction

The `doc/zinnia-*` proposals aim higher (post-quantum + no trusted setup) by introducing a new AIR circuit, a new hash (RPO256 on Goldilocks), a new Merkle (RpoHash FFI), large proofs (~80–100 KB), and (at the time) acknowledged ZK-completeness gaps on an unaudited Winterfell branch — a larger implementation/audit risk and a block-size impact. TVSP is the more conservative step: it reuses the relatively well-exercised Sapling gadgets *minus* the value parts, directly targets the value-conservation surface, and does not mandate a block-size jump. The two are compatible — TVSP can later adopt a transparent/PQ proof system for its reduced statement (recommendation 4).
