# ZClassic NFT — Write Path (Mint + Secure Transfer) on Unchanged Consensus

**Status:** implementation-ready design. Design + doc only — no `src/` edits, no build.
**Scope:** the WRITE path for the ZSLP overlay (mint an NFT from any file/image/video, and
transfer/gift it), built so **unchanged ZClassic nodes relay and mine these transactions and
unchanged miners include them normally**. We add **nothing** at the consensus layer. Token
ledger safety comes from the deterministic non-consensus overlay (`CZSLPIndexer`/`CZSLPStore`)
re-validating every tx, plus a builder-side **self-validate-before-broadcast** gate (R-WALLET-9).

**Companion docs:** `doc/nft/SECURITY_MODEL.md` (R-WALLET-1..11), `doc/nft/CANONICAL_VALIDATION_SPEC.md`
(R1/R5 vout rules), `doc/nft/CONTENT_MODEL.md` (off-chain bytes + future Merkle root),
`doc/nft/NATIVE_UX.md` (GUI flows).

All file:line references below were verified against this tree.

---

## 1. Overview + the missing-primitive problem

ZSLP = SLP Token Type 1 over a single `OP_RETURN`. Token id = genesis txid. An **NFT** is a
baton-less GENESIS with `decimals=0`, `initial_quantity=1`. The encoders are already ported and
gtested: `slp_build_genesis` / `slp_build_mint` / `slp_build_send` (`src/zslp/slp.h:77-95`,
`src/zslp/slp.c:170-292`) plus `src/zslp/op_return_push.h`. Parse/index/store are
`src/zslp/{zslpmsg,zslpindexer,zslpstore}.*` (UTXO-bound + conservation-checked, 43/43 gtests).
Read RPCs live in `src/rpc/zslp.cpp` (gettoken/listtokens/listtransfers/listmytokens).

**THE GAP — there is no write RPC, and `createrawtransaction` cannot make one.**
`createrawtransaction` only emits address outputs: for each destination it does
`GetScriptForDestination(DecodeDestination(name))` and pushes a `CTxOut`
(`src/rpc/rawtransaction.cpp:554-571`). There is **no data/OP_RETURN output path**. So minting and
transfer must build the OP_RETURN tx natively via `CRecipient{ scriptPubKey, nAmount,
fSubtractFeeFromAmount }` → `CWallet::CreateTransaction` → `CommitTransaction`
(`src/wallet/wallet.h:129-134`, `1242-1244`; pattern at `SendMoney`,
`src/wallet/rpcwallet.cpp:380-409`).

**THE BLOCKING DISCOVERY — naive `CreateTransaction` will silently burn the NFT.** Two hazards:

1. **Change is inserted at a RANDOM vout index.** After coin selection, `CreateTransaction` does
   `nChangePosRet = GetRandInt(txNew.vout.size()+1); txNew.vout.insert(begin()+nChangePosRet,
   newTxOut)` (`src/wallet/wallet.cpp:3680-3682`). Change can land at **vout[0]**, displacing the
   OP_RETURN. The overlay reads the SLP message only when it parses at the canonical position; a
   shifted layout means the indexer sees a different/no message and the token is **burned or
   mis-assigned**. Relying on `vecSend` ordering alone is **insufficient** — outputs from `vecSend`
   are pushed in order (`wallet.cpp:3552-3580`), but the change insert ignores that order.
2. **Auto coin-selection can spend a token UTXO / baton as fee or change.** `SelectCoins` over
   `AvailableCoins` has no SLP awareness, and dust change is folded into the fee
   (`nFeeRet += nChange`, `wallet.cpp:3674`). A token "rides" a dust output far below the change-fold
   threshold → silent burn (T3, `SECURITY_MODEL.md:157`).

The fix is a **dedicated builder that controls vout order and funding** — described in §2.

---

## 2. The shared OP_RETURN tx builder

Put **one** builder in a new wallet TU so all three write RPCs share a single code path and it is
unit-testable: **`src/wallet/zslpwallet.{h,cpp}`** (touches `CWallet`; keeps the pure-C encoders in
`src/zslp/slp.c` consensus/UI-agnostic). The C++↔C bridge is a thin shim
(`ZSLPBuild{Genesis,Mint,Send}`) added beside the existing parser bridge in
`src/zslp/zslpmsg.{h,cpp}` so `wallet.cpp`/`zslpwallet.cpp` never include `slp.h` directly (avoids
the `struct uint256` vs `class uint256` clash — same reason `zslpmsg` exists, `zslpmsg.h:6-11`).

### 2.1 Core signature (DRY across GENESIS / MINT / SEND)

```cpp
struct ZSLPTokenOut { CScript dest;   CAmount dustSats; };  // P2PKH recipient + dust value
struct ZSLPBuildReq {
    CScript                 opret;          // the OP_RETURN script (from slp_build_*)
    std::vector<ZSLPTokenOut> tokenOuts;    // canonical order: maps qty j -> vout[1+j]
    std::vector<COutPoint>  tokenInputs;    // token/baton UTXOs to FORCE-include
                                            //   GENESIS: empty;  MINT: the baton;  SEND: chosen token UTXOs
    uint256                 selfValidateTokenId; // tokenId the built tx must conserve (0 for GENESIS)
};

bool BuildAndCommitZSLP(CWallet* w, const ZSLPBuildReq& req,
                        CWalletTx& wtxOut, std::string& err);   // returns false on any failure
```

### 2.2 vout[0] pinning — recommended strategy (build canonical, sign last)

Do **not** trust `CreateTransaction`'s ordering. Construct a `CMutableTransaction` by hand with a
**fixed** layout, fund the fee deterministically, and sign last:

```
vout[0]            = CTxOut(0, opret)                       // OP_RETURN, value 0
vout[1..k]         = CTxOut(SLP_TOKEN_DUST, tokenOuts[i].dest)   // token quantity outputs (canonical order)
vout[k+1] (opt)    = CTxOut(SLP_TOKEN_DUST, ownChange)      // SEND token-change (surplus), if any
[ZCL change]       = appended at the TAIL, never index 0    // ordinary P2PKH change
```

Funding + signing, replicating the proven internals:

1. **Coin selection for fee + dust:** run a `CreateTransaction` pass with `sign=false` (its 8th/9th
   params, `wallet.h:1242-1244`) to obtain coin selection, `nFeeRet`, and the change script/amount —
   **or** call `SelectCoins` directly. Either way pin token inputs and exclude all token UTXOs from
   the auto-pool (§2.4).
2. **Assemble** the `CMutableTransaction` in the canonical order above; append ZCL change LAST.
3. **Sign each input yourself**, mirroring `wallet.cpp:3712-3737` exactly:
   `auto consensusBranchId = CurrentEpochBranchId(chainActive.Height()+1, Params().GetConsensus());`
   then per input
   `ProduceSignature(TransactionSignatureCreator(w, &txConst, nIn, prevValue, SigHashType()),
   scriptPubKey, sigdata, consensusBranchId); UpdateTransaction(txNew, nIn, sigdata);`
   The OP_RETURN output needs no signing. Re-signing is mandatory because moving outputs changes the
   sighash (`risk #2`). **Why build-then-sign and not reorder-after-sign:** moving outputs after
   signing invalidates every signature, so the controlled layout MUST be finalized before signing.

This guarantees `vout[0]==OP_RETURN` deterministically and preserves the positional `qty j -> vout[1+j]`
mapping the store relies on (`zslpstore.cpp:553-563`).

> If a maintainer prefers to reuse `CreateTransaction` wholesale, the only safe fallback is: call it,
> then if `wtx.vout[0]` is not the OP_RETURN, **rebuild + re-sign** in canonical order. This is the
> same work as the recommended path with extra fragility; prefer the controlled build.

### 2.3 Dust value (exact, load-bearing)

`CTxOut::GetDustThreshold = 3 * minRelayTxFee.GetFee(serializeSize + 148)`
(`src/primitives/transaction.h:452-467`). `minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE=100)`
(`src/main.h:64`, `src/main.cpp:98`). For a 34-byte P2PKH output:
`3 * 100 * (34+148)/1000 = 3 * 18 = 54 sat`. The code comment at `transaction.h:460` says exactly
"dust is a spendable txout less than 54 satoshis with default minRelayTxFee".

- **Each token output MUST be ≥ 54 sat.** Use **`SLP_TOKEN_DUST = 546 sat`** (standard SLP/BCH
  convention; ~10× over the 54-sat floor; survives a `-minrelaytxfee` bump and `CreateTransaction`'s
  change-raising). The **1-sat NFT prose** in some earlier notes is illustrative only — 1 sat is
  BELOW 54 and would be rejected as `dust` (`main.cpp:771`). Surface the per-output 546 sat as real
  ZCL spent in the GUI fee preview.
- **The OP_RETURN carries `nValue=0`** and is dust-exempt: `IsUnspendable()` ⇒ `GetDustThreshold`
  returns 0 (`transaction.h:462-463`), and `IsStandardTx` skips the dust branch for `TX_NULL_DATA`
  (`main.cpp:766-771`). Keep every recipient `fSubtractFeeFromAmount=false` so the 0-value
  OP_RETURN and the 546-sat outputs are never shaved (`wallet.cpp:3556-3566`).

### 2.4 Anti-burn funding selection (R-WALLET-1..3, task #108)

Funding for fee + dust must **never** consume a token UTXO or a baton.

- **Pin intended inputs:** `CCoinControl cc; cc.fAllowOtherInputs = true;` and `cc.Select(outpoint)`
  for each `req.tokenInputs` entry. `SelectCoins` force-includes the preset set and lets it add plain
  coins for fee/change (`wallet.cpp:3383-3419` preset-input path; `coincontrol.h` `Select`/
  `fAllowOtherInputs`).
- **Exclude every other token UTXO from the auto-pool.** `AvailableCoins` is the auto-source and
  honors `IsLockedCoin` (`wallet.cpp:3151-3184`, lock-skip at 3180). Two coordinated mechanisms:
  - the task #108 `AvailableCoins` filter that consults `g_zslpIndexer->store->GetUtxo()` and drops
    any live token/baton outpoint, **and**
  - belt-and-suspenders: `LockCoin` every wallet token/baton outpoint for the duration of the build
    (`wallet.cpp:4345`), released via an **RAII guard even on exception** (a failed build must not
    leave the user's tokens locked, `risk #6`).
- **Defensive post-check:** before signing, assert no selected input is a token UTXO of a *different*
  token or a baton (`store->GetUtxo` miss for funding inputs); abort otherwise (R-WALLET-3).
- **Fail CLOSED if `-zslpindex` is off** (R-WALLET-6): without the store the wallet cannot classify
  dust → refuse to spend sub-threshold dust rather than risk a burn. GENESIS funding still needs the
  store to protect *other* tokens' dust in the same wallet.

### 2.5 SEND conservation + input enumeration (the read gap)

The store exposes `GetUtxo(txid,vout)` and `GetTokensForAddress` (balances, **not** outpoints)
(`zslpstore.h:357,366-367`) — there is **no by-token UTXO enumeration**. Fill it the
wallet-correct way (also the anti-burn source of truth): **intersect `CWallet::AvailableCoins()` with
`store->GetUtxo()`** — for each spendable `COutput`, call `store->GetUtxo(coin.txid, coin.i, rec)`;
keep those with `rec.tokenId == target && !rec.isMintBaton && rec.amount > 0 && IsMine`. (Optionally
also add a `CZSLPStore::ListUtxosForToken` enumerator over the `'u'` key-space for non-wallet uses,
but the intersection is sufficient and correct for the builder.)

Selection + conservation (mirrors `zslpstore.cpp:531-569`):
- Greedily accumulate token inputs (deterministic order: sort by `(height, txid, vout)`) until
  `availIn = Σ input qty ≥ requiredOut = Σ output qty`. If short → fail "insufficient token balance".
- `tokenChange = availIn - requiredOut`; if `>0`, append a token-change output to the sender's own
  fresh t-addr and add its quantity to the `slp_build_send` quantities array. **Surplus is NEVER
  silently burned** (matches the implicit burn at `zslpstore.cpp:565`).
- Spend **only** the chosen token inputs.
- Quantities are uint64 BE; **reject any qty with the high bit set (≥ 2^63)** before encoding — the
  store treats negative int64 as INVALID (`zslpstore.cpp:545-546`).
- **SEND ≤ 19 outputs** (`slp_build_send` returns 0 if `num_outputs<1||>19`, `slp.c:270`);
  token-change counts toward the 19. Enforce `recipients + (tokenChange?1:0) ≤ 19`.

### 2.6 Relay-size budget (≤ 223 bytes)

Every builder MUST (a) treat a `slp_build_*` return of `0` as "metadata too large / limit exceeded"
(it returns 0 on buffer overflow, `slp.c:233/263/291`) and (b) assert the produced script length
≤ `MAX_OP_RETURN_RELAY = 223` (`standard.h:34`) before adding it. Computed payload sizes (§6) prove
MINT and every SEND always fit; only GENESIS with long ticker/name/url can exceed — reject pre-build
and keep `document_url` short (the 32-byte `document_hash` is the real anchor).

---

## 3. `zslp_genesis` — mint RPC

New wallet-gated RPC under `ENABLE_WALLET`, registered in a new `src/wallet/rpcwalletzslp.cpp` (or in
`src/rpc/zslp.cpp`'s `commands[]`, `zslp.cpp:263-270`), category `"zslp"`, `okSafeMode=false`. It is
the canonical NFT mint path and the write counterpart to the read RPCs.

```
zslp_genesis '{ "ticker"?, "name"?, "document_url"?, "document_hash"?(64-hex/32B),
                "decimals"?(0..9, default 0), "quantity"(string|num, default 1 for nft),
                "mint_baton_vout"?(0/1=none, >=2=baton), "to"?(t-addr), "nft"?(bool) }'
   -> { "txid": "<hex>", "tokenid": "<hex>" }      // tokenid == txid (zslpindexer.cpp:229)
```

**Validation (throw `RPC_INVALID_PARAMETER` before building anything):**
1. `decimals ∈ [0,9]`.
2. `quantity` parsed from a **string** to uint64 (JSON doubles lose precision above 2^53); **reject
   high bit**: `if (q >> 63) throw "quantity exceeds 2^63-1"`. Land this on the WRITE side
   regardless of any pending read-side guard (`SECURITY_MODEL.md` R-INT-1).
3. `nft=true` (or the GUI "Create NFT" flow): force `decimals=0, quantity=1, mint_baton_vout<2`;
   reject conflicting explicit values → a 1-of-1, non-reissuable, indivisible token.
4. `document_hash`: if non-empty, exactly 64 hex → 32 raw bytes via `ParseHex`; pass those raw bytes
   straight to `slp_build_genesis` (**not reversed** — the indexer reverses only for *display*,
   `zslpindexer.cpp:242-245`, so round-trip `GUI-hash-hex == gettoken.documenthash`). Empty ⇒ empty
   push.
5. ticker/name/document_url byte caps + the §2.6 relay-size pre-check.
6. `mint_baton_vout` 0/1 (none) or `[2, voutCount)`; absent for the NFT preset.

**Build (via §2 builder):** `opret = ZSLPBuildGenesis(...)`;
`tokenOuts = [{P2PKH(to or fresh key), 546}]` carrying qty at vout[1] (`zslpstore.cpp:474-477`);
if a baton, the builder also places a 546-sat baton output at its declared vout
(`zslpstore.cpp:479-483`). `tokenInputs` empty (genesis has no token inputs). Fund + sign + self-
validate (§4.3) + `CommitTransaction`.

**Examples:**
- NFT: `zslp_genesis '{"nft":true,"name":"My Photo #1","document_url":"ipfs://...","document_hash":"<64hex>"}'`
- Fungible w/ baton: `zslp_genesis '{"ticker":"GOLD","name":"Gold Coin","decimals":2,"quantity":"100000","mint_baton_vout":2}'`

`zslp_mint tokenid amount [batonvout]` mirrors this for fungible re-issue (requires spending the live
baton UTXO as a pinned input; look it up via the §2.5 intersection). **NFTs never use MINT.**

---

## 4. `zslp_send` — secure transfer RPC with self-validation

```
zslp_send "tokenid" "to_address" ( amount change_address )   -> { "txid": "<hex>" }
   // POSITIONAL args only (verified src/rpc/zslp.cpp:551):
   //   "tokenid"        (string, required)
   //   "to_address"     (string, required)  single recipient t-address
   //   amount           (numeric/string, optional, default 1)
   //   change_address   (string, optional)  token-change t-addr (default: fresh own)
   // NFT gift: amount defaults to 1; single recipient, qty 1.
   // NOTE: there is NO {"taddr": amount, ...} JSON-map / multi-recipient form
   //   on this RPC — it takes one recipient. (The builder CAN emit up to 19
   //   token outputs; that multi-output path is not exposed via this RPC's args.)
```

### 4.1 Algorithm (under `LOCK2(cs_main, cs_wallet)`)
> **RPC vs builder scope.** The shipped `zslp_send` RPC takes ONE positional recipient
> (`"tokenid" "to_address" ( amount change_address )`). The algorithm below describes the
> underlying `BuildAndCommitZSLP` *builder*, which is multi-output-capable (up to 19 SEND
> outputs); the single-recipient RPC is the only arg surface that exposes it today.

1. Validate intent: `1 ≤ recipients ≤ 18` (reserve one of the 19 SEND slots for token-change); each
   `qty > 0` and `< 2^63`. (Via the RPC, `recipients == 1`.)
2. Enumerate the wallet's token UTXOs of `tokenid` via the §2.5 intersection; greedily select until
   `availIn ≥ requiredOut`; compute `tokenChange`.
3. `opret = ZSLPBuildSend(tokenIdBE, quantities=[recip qtys..., (tokenChange?)], n)` — convert
   `tokenId` to on-chain **BE** order (inverse of `TokenIdToUint256`, `zslpindexer.cpp:147-153/256`).
4. `tokenOuts = [{P2PKH(recip_i), 546}...]` + (if `tokenChange>0`) `{P2PKH(ownFresh), 546}`.
   `tokenInputs = the chosen token UTXOs`. Fund (anti-burn) + sign (§2.2).
5. **Self-validate (§4.3); refuse to broadcast on any failure.** Then `CommitTransaction`.

### 4.2 NFT transfer (the common case)
`vin = [the NFT's 546-sat token UTXO + anti-burn-filtered fee coins]`;
`vout[0] = slp_build_send(tokenid, [1], 1)`; `vout[1] = 546 sat → recipient`;
ZCL change at the tail. `availIn(1) == requiredOut(1)` ⇒ no token-change.

### 4.3 R-WALLET-9 self-validate-before-broadcast (non-negotiable)

After the tx is fully built **and signed**, before `CommitTransaction`, run it through the **same
parse + conservation logic the indexer uses** so the wallet computes the identical ledger result.
**Do NOT call `CZSLPStore::ApplyTransaction`** — it WRITES leveldb (`zslpstore.cpp:579`). Add a pure
read-only predicate, e.g. `bool CZSLPStore::WouldBeValid(const CTransaction& tx, std::string& reason)
const` (or a free `ZSLPValidateBuiltTx`), factored to share literally the indexer's steps:

1. **Parse vout[0]:** `Solver(vout[0].scriptPubKey) == TX_NULL_DATA` (mirror
   `zslpindexer.cpp:211-216`) then `ZSLPParseScript` (`zslpmsg.h:63`) yields the expected
   GENESIS/MINT/SEND with the intended fields. Assert the message is at **vout[0]** and is the only
   OP_RETURN.
2. **Recompute availIn** read-only via `store->GetUtxo` over each `tx.vin` (mirror
   `zslpstore.cpp:437-445`: batons and non-token inputs contribute 0).
3. **Conservation:** `requiredOut = Σ output quantities` with the SAME overflow guard
   (`zslpstore.cpp:537-552`); assert `!overflow && availIn ≥ requiredOut`; reject any qty ≥ 2^63.
4. **Layout:** qty outputs map to `vout[1..n]` and exist; baton (if any) at its declared vout
   `< voutCount`; every non-OP_RETURN output `!IsDust`; SEND `≤ 19` outputs.
5. **Belt-and-suspenders anti-burn:** no selected `vin` is a token UTXO of a *different* token or a
   baton (R-WALLET-3).

Factor steps 1–3 into ONE shared function used by both the indexer and the builder so a divergence
can never make the wallet broadcast a tx the ledger would burn (SECURITY = DETERMINISM + AGREEMENT).
Ship a gtest that builds a SEND, feeds it through the indexer, and asserts the recipient is credited
and supply is unchanged (§7).

> **Coupled prerequisite:** the live indexer currently scans *all* vouts for the first parsable
> OP_RETURN (`zslpindexer.cpp:211`, "first valid wins" at 277-278), but `CANONICAL_VALIDATION_SPEC.md`
> R1 mandates **vout[0]-only**. The builder places the OP_RETURN at vout[0] regardless (future-proof);
> flag the indexer R1 tightening as a coupled change so a future-correct node and this builder agree.

---

## 5. Native mint + transfer UX (honest about public + irreversible)

**Mint** (`NATIVE_UX.md` §3.3): drag any file → the content engine **stream-hashes** it
(SHA-256 = `document_hash`, on a worker thread) and detects type → name / collection / ticker →
**PRIVATE (default)** vs **PUBLIC** tiles → **Review** screen that shows BOTH the network fee (from a
`sign=false` dry-run `nFeeRet`) AND **exactly** what becomes public — in plain language:
> "These bytes go on the public blockchain forever: `<name>`, `<ticker>`, `<document_url>`,
>  and the file fingerprint `<document_hash>`. The file itself stays off-chain; only its fingerprint
>  is recorded." → **Create** calls `zslp_genesis`.

- **PUBLIC** = also publish the bytes + URL to a pin/host; **PRIVATE** = only the 32-byte hash on
  chain, bytes kept local. Never imply the file is private when only its hash is published.
- The Public tile may stay disabled ("Coming in this release") until these RPCs ship; a private NFT
  can ship first via shielded memo (no consensus RPC needed).

**Transfer / gift** (`NATIVE_UX.md` §3.4): open NFT → Send/Gift → pick recipient t-addr → confirm
screen states the token, recipient, the 546-sat dust + network fee, and **"This is public and
irreversible — a send to the wrong address cannot be undone"** → `zslp_send "tokenid" "addr" 1`
(positional args; see §4).
Show PENDING until the confirmation depth required by the reorg policy (`REORG_CONFIRMATION_*`).

---

## 6. OLD-CONSENSUS PROOF (unchanged nodes relay + mine; consensus untouched)

A mint/transfer tx is **structurally an ordinary payment**: normal P2PKH/P2SH inputs and outputs,
normal P2PKH change, plus **exactly one** `TX_NULL_DATA` OP_RETURN at vout[0]. Walking the actual
standardness path on an unmodified node:

1. **Output classification — `src/script/standard.cpp:71-73`:** any `OP_RETURN <push-only>` is
   classified `TX_NULL_DATA` ("So long as script passes IsUnspendable() and all but the first byte
   passes IsPushOnly() we don't care what exactly is in the script"). The node **never parses SLP**;
   the SLP bytes are opaque pushdata.
2. **Datacarrier RELAY gate — `src/script/standard.cpp:197-199`:** a `TX_NULL_DATA` output is
   rejected only if `!GetBoolArg("-datacarrier", true)` (default **true**) **or**
   `scriptPubKey.size() > nMaxDatacarrierBytes`. `nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY = 223`
   (`standard.cpp:19`, `standard.h:34`), overridable by `-datacarriersize` (`init.cpp:553,1833`).
   These are **RELAY policy** (`-datacarrier`/`-datacarriersize`, defaults printed at
   `init.cpp:552-553`), living in `IsStandard`/`IsStandardTx` — **never** in `CheckTransaction`/
   `ConnectBlock`.
3. **Per-tx standardness — `src/main.cpp:714-784`:** every vout must pass `::IsStandard`
   (`main.cpp:761`); the OP_RETURN is counted (`766-767`) and **exempt from the dust check** (the
   dust test is in the `else if` branch, so `TX_NULL_DATA` skips it, `766-774`); the 546-sat token
   outputs clear the 54-sat dust floor (`771`); **exactly one OP_RETURN** is allowed
   (`nDataOut > 1 ⇒ "multi-op-return"`, `778-781`). We emit exactly one, at vout[0].
4. **Mempool admission — `src/main.cpp:1466`:** `Params().RequireStandard() && !IsStandardTx(...)`
   is the ONLY standardness gate; pass it and the tx relays. Miners pull from the same mempool and
   include it as an ordinary fee-paying tx; they never interpret SLP. **Consensus
   (`CheckTransaction`/`ConnectBlock`) is untouched** — ZSLP adds/changes no consensus rule.

**Plain statement:** an old node will happily relay/mine an SLP tx the overlay deems INVALID; that tx
simply burns its tokens in the overlay (`zslpstore.cpp:565-568`). Validity is an **overlay
convention**, not a new rule old nodes must learn — which is exactly why the builder must
self-validate (R-WALLET-9) before broadcast.

**Payload sizes vs the 223-byte limit** (from `slp.c` encoders + `op_return_push.h` push sizing):
- **SEND, 19 outputs (max):** `1(OP_RETURN) + 5(push4 LOKAD) + 2(push1 type) + 5(push4 "SEND") +
  33(push32 tokenid) + 19×9(push8 qty) = 217 ≤ 223` ✓. SEND-1 = 55 B, SEND-2 (recip + change) = 64 B.
- **MINT:** `1 + 5 + 2 + 5(push4 "MINT") + 33 + 2(empty baton) + 9 ≈ 57 B` ✓ (always fits).
- **GENESIS fixed overhead** (`OP_RETURN + push4 LOKAD + push1 type + push7 "GENESIS" + push32 hash +
  push1 decimals + baton + push8 qty`) ≈ **62–68 B**, leaving ≈ **153–161 B** for
  ticker+name+document_url **including their push opcodes**. A long name/url **can exceed 223** →
  the builder rejects pre-broadcast (`slp_build_genesis` returns 0, plus the explicit length check),
  and the GUI keeps fields short or pushes large metadata off-chain (`CONTENT_MODEL.md`). MINT and
  every SEND **always** fit.

**Dust the old node accepts:** ≥ 54 sat (computed in §2.3 from `transaction.h:452-467`,
`main.h:64`, `main.cpp:98`); we use 546. The 0-value OP_RETURN is dust-exempt.

---

## 7. Implementation order + gtest/QA plan

**Order:**
1. Land the **anti-burn** `AvailableCoins` filter + `listunspent` annotation (task #108,
   R-WALLET-1..3) — prerequisite so funding can never auto-pick a token/baton.
2. Add the C++↔C **builder bridge** `ZSLPBuild{Genesis,Mint,Send}` in `zslpmsg.{h,cpp}` (wraps the
   existing `slp_build_*`; treats return 0 as error; asserts ≤ 223).
3. Add the read-only **`CZSLPStore::WouldBeValid`** predicate (shares indexer parse + conservation).
4. Add the **shared builder** `BuildAndCommitZSLP` in `src/wallet/zslpwallet.{h,cpp}` (canonical
   vout order, anti-burn funding via `CCoinControl` + `LockCoin`-RAII, manual sign, self-validate,
   commit).
5. Add the **`zslp_genesis` / `zslp_send` / `zslp_mint`** RPCs (thin shells → the one builder);
   register beside the read commands.
6. Tighten the indexer to **vout[0]-only** (R1 coupled prerequisite) and wire the **GUI** flows.

**gtest / QA:**
- **Builder→indexer round-trip:** build an NFT GENESIS; feed the raw tx through the indexer; assert a
  token row with `tokenId==txid`, `totalMinted==1`, a qty-1 UTXO at vout[1], no baton.
- **NFT genesis → send → ownership moves:** mint to A; `zslp_send` to B; index both; assert B owns
  qty 1, A owns 0, supply unchanged, and the OP_RETURN is at vout[0] in each tx.
- **Conservation + token-change:** SEND a 7-of-10 token holding; assert recipient gets the requested
  qty and a 3-qty token-change output returns to the sender (no burn).
- **Self-validation rejects malformed:** construct a SEND with `Σ out > Σ in`, or qty ≥ 2^63, or
  >19 outputs, or OP_RETURN not at vout[0]; assert `WouldBeValid` returns false and the builder
  refuses to broadcast.
- **Anti-burn:** 1000 randomized ordinary sends never select the NFT outpoint; a tx that would route
  the NFT to fee fails with a token-protection error, not a burn (R-WALLET-2/3/11).
- **Relay-size:** GENESIS with an over-long name/url is rejected pre-broadcast with a clear
  "metadata too large for one OP_RETURN (max 223 bytes)" error; SEND@19 = 217 B accepted.
- **Standardness:** assert a built mint/send passes `IsStandardTx` at the current tip height and is
  accepted to a local mempool with default policy.
- **`-zslpindex` off fail-safe:** sub-threshold-dust spend blocked/routed-around, never a silent burn.

---

## 8. Honest limits

- **Overlay validity is a convention, not consensus.** Old nodes relay/mine SLP-INVALID txs; the
  overlay burns them. The self-validate gate (R-WALLET-9) is the only thing standing between a buggy
  builder and a real burn.
- **Anti-burn is a dependency.** Until task #108's `AvailableCoins` filter lands, the builder must
  carry its own `CCoinControl` + `LockCoin` fence; the global filter is the durable fix.
- **Indexer R1 (vout[0]-only) is a coupled change.** The builder is future-proof, but a fully
  spec-compliant indexer must also enforce vout[0]-only so every observer agrees.
- **Relay policy ≠ consensus, but operators matter.** A node run with `-datacarrier=0` or a tiny
  `-datacarriersize` won't *relay* these; any miner on defaults still includes them. Document that
  operators keep defaults.
- **Metadata size is tight.** Rich NFT metadata must live off-chain; only the 32-byte hash + a short
  URL are on-chain (`CONTENT_MODEL.md`).
- **Irreversibility + privacy.** A send to a wrong address is unrecoverable; the OP_RETURN publicly
  reveals every mint/transfer and the `document_hash` forever. The confirm-gate copy and the honest
  review screen are the only user protections.
- **Dust floor can drift.** 546 sat gives ~10× headroom over today's 54-sat floor; if
  `-minrelaytxfee` is raised network-wide, recompute `GetDustThreshold` dynamically rather than
  trusting the constant.
