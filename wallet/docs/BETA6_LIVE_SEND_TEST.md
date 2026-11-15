# beta6 — live money-path test (the one gate tests can't replace)

Every auto-shield / Max-shield / leak-guard fix in beta6 is proven by the L0/L1 suites and a
source-level review against the node — but **none has been broadcast on-chain**. Before signing
the release, do one real small `t→z` send-with-change on a funded node and confirm the change
lands **shielded**, not public. This is a real spend — **your call to run it.**

Run these in the app (preferred) *or* via `zcl-cli` against the same node. Use a **small** amount.

## What to test (3 cases, each with a confirmed transparent balance)

### 1. Normal t→z with change (the core case)
- From a **t-address** holding e.g. `1.0` confirmed (non-coinbase) ZCL, send `0.3` to any
  **z-address**, auto-shield ON.
- **Expect:** tx broadcasts; recipient gets `0.3`; the **change (~0.6999) is a shielded
  z-output**, not a public t-address. Verify in the tx detail / explorer that there is **no
  transparent change output**.

### 2. Max shield (the bug bob hit)
- Same t-address, click **Send all** → a z-address.
- **Expect:** it does **not** falsely say "Not enough funds… only holds X" (the float bug), and
  the whole confirmed balance moves; change is `0` or shielded.

### 3. Coinbase / mined funds
- From a t-address that holds **mined (coinbase)** coins, try a partial shield.
- **Expect:** either it shields cleanly, or it shows the calm "shield your mined funds first"
  message — **never** a raw "insufficient funds", and **never** a public change output.

## How to verify "shielded, not public"
After each send, open the tx and check the outputs:
- ✅ recipient z-output + (if any) a **z-change output** → correct.
- ❌ any **t- (transparent) output back to your own address** → that's a leak; stop and report.

Manual cross-check (optional):
```bash
zcl-cli z_sendmany "<t_from>" '[{"address":"<z_to>","amount":0.3}]'   # let the daemon pick change
zcl-cli z_getoperationresult '["<opid>"]'                              # see the verbatim result
zcl-cli gettransaction <txid>                                         # inspect vout for any t-change
```

## Pass criteria for the release gate
- All 3 cases broadcast successfully.
- **Shown == sent** (the amount you confirmed is the amount that moved).
- **Zero public transparent change** in any auto-shield send.

Record the txids in the beta6 checklist when done.
