# Testing ZIP-209 + CR-01 (ZipherX consensus hardening)

These builds carry two consensus-validation fixes on top of upstream ZClassic:

- **ZIP-209 shielded turnstile (mainnet)** — a block that would drive the Sprout
  or Sapling shielded value-pool balance negative is rejected as invalid.
- **CR-01** — `ContextualCheckTransaction()` no longer skips contextual crypto
  checks during initial block download / import / reindex.

This document is the checklist for testers. Everything except step 4 is
read-only and safe to run on a production node.

> **Prerequisite:** a **fully-synced mainnet** node. The auditor reads the
> chainstate via RPC, so RPC must be enabled in `zclassic.conf`.

---

## 1. Pre-flight: confirm your node matches the compiled checkpoint (~1s)

ZIP-209 ships a hardcoded Sprout value-pool checkpoint. A genesis-tracking node
asserts its own computed balance against it at startup — a mismatch aborts the
daemon. Verify the value before running a ZIP-209 binary:

```bash
./src/zclassic-cli getblock $(./src/zclassic-cli getblockhash 3000000) | grep -A4 '"id": "sprout"'
# Expected:  "chainValueZat": 1316412375709
```

If `chainValueZat` is **not** `1316412375709`, stop and report it — your
chainstate differs from the canonical chain (or is corrupt).

## 2. Full turnstile audit (read-only, ~20–30 min)

Prove that **no** historical block ever drove a shielded pool negative, so
enabling ZIP-209 — and a later `-reindex` — will not reject the chain:

```bash
python3 scripts/audit-mainnet-history.py --full --supply-check --json-output audit-full.json
```

Expected:

```
negative pool events found in scan: 0
status=OK: observable supply does not exceed expected issuance
```

This only issues read-only RPCs (`getblockchaininfo`, `getblock`,
`gettxoutsetinfo`); it never modifies the node, datadir, or chain.

> The default (without `--full`) is a sampled scan and cannot prove absence of a
> transient historical negative pool. Use `--full` for the real proof.

## 3. Build, run, and confirm the turnstile build

```bash
./zcutil/build.sh -j$(nproc)        # macOS: -j$(sysctl -n hw.ncpu)
./src/zclassicd
./src/zclassic-cli getnetworkinfo | grep subversion
# Expected:  "/ZipherX:2.1.2-ZIP209-beta6/"
```

A clean startup (no `turnstile violation ... shielded value pool` abort) means
ZIP-209 loaded and validated the checkpoint against your chainstate.

## 4. Optional: full historical re-validation (slow)

Re-validate every block from genesis with the turnstile **and** the CR-01
contextual checks enforced (this is the CR-01 deployment step — a reindex on an
*un*fixed binary does not re-validate, since reindex keeps the node in IBD):

```bash
./src/zclassic-cli stop
./src/zclassicd -reindex
```

Watch the log. It must reach the chain tip **without** printing:

- `turnstile violation in Sprout/Sapling shielded value pool` (ZIP-209), or
- any `ConnectBlock` / contextual-check block rejection (CR-01).

A reindex that reaches the tip cleanly is independent confirmation that the
whole chain validates under the hardened ruleset.

---

## Do testers need to run the audit?

Not strictly — the mainnet chain history is identical for everyone, and it has
already been proven clean (`negative pool events: 0` across all blocks). But
running step 1 is the **minimum** (it prevents a startup assert on a node whose
chainstate differs), and step 2 is recommended as independent verification.

## Network note

ZIP-209 is a soft-fork-class rule tightening. A single node enforcing it while
the rest of the network does not is harmless (stricter, and the chain never
violates the rule today) but only protects that node. For ZIP-209 to be a
network-wide defense, a majority of nodes/miners must run a ZIP-209 build with
the **same** checkpoint, ideally behind a coordinated activation height — see
[zip209-mainnet-reactivation.md](zip209-mainnet-reactivation.md).
