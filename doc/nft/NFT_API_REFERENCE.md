# ZClassic NFT / ZSLP / Token / Shield / Coin-Control RPC Reference

This is the authoritative call-shape reference for the on-chain collectible, token, and coin-control RPCs served by `zclassicd`. It is generated against the as-built daemon source (`src/rpc/zslp.cpp`, `src/rpc/nftoffer.cpp`, and the inherited wallet `z_sendmany`). The in-binary `help <command>` output remains ground truth; this document mirrors it.

> **Removed:** The shielded data-channel / arbitrary-file-transfer capability (the former `z_senddatafile` / `z_listdatatransfers` / `z_getdatatransfer` RPCs and the `-datachannel` option) has been **removed entirely** from the daemon. ZClassic deliberately provides **no wallet path to store arbitrary files on-chain**. NFTs reference their content only by an off-chain `document_hash` fingerprint (see below); the bytes themselves are never put on-chain.

The coin is **ZClassic (ZCL)**. All amounts denominated in "zatoshi" are ZCL base units.

## Orientation: how this works

- **ZSLP is a non-consensus OP_RETURN overlay.** Tokens and NFTs are SLP Token-Type-1 messages encoded in an `OP_RETURN` output and carried by 546-sat ("dust") transparent outputs. Consensus does not know about tokens; an *index* (`-zslpindex`, default on) parses every block and maintains the token ledger. Disabling the index makes the read/write RPCs fail closed.
- **Tokens ride transparent (t-) addresses only.** Shielded (z-) addresses never hold ZSLP tokens. Wallet token operations select, conserve, and protect transparent token "carrier" dust, and refuse to spend it as fees (anti-burn).
- **Images and files are off-chain.** The chain stores at most a 32-byte `document_hash` (a content fingerprint) plus a short `document_url`. The actual artwork/file lives off-chain; a consumer verifies authenticity by hashing the file and comparing to the on-chain `document_hash`.
- **`tokenid == genesis txid.`** A token's id IS the txid of the transaction that minted it. To get the full genesis transaction, call `getrawtransaction "<tokenid>" 1`.
- **Call-shape footgun:** `zslp_genesis` takes a **single JSON object** argument. `zslp_gettoken`, `zslp_listtokens`, `zslp_listtransfers`, `zslp_mint`, `zslp_send` take **positional** arguments. All `nft_*` offer RPCs take a **single JSON object** argument.
- **Gating flags:**
  - `-zslpindex` (default **on**): required for every `zslp_*` and `nft_*` RPC. When off, those RPCs throw `RPC_MISC_ERROR` "ZSLP index is not enabled...".
  - Wallet-write RPCs require a wallet-enabled build (`ENABLE_WALLET`); on a no-wallet build the write RPCs are not registered and `zslp_listmytokens` returns an explicit error.

Common error codes seen below: `RPC_INVALID_PARAMETER (-8)`, `RPC_INVALID_ADDRESS_OR_KEY (-5)`, `RPC_WALLET_ERROR`, `RPC_WALLET_INSUFFICIENT_FUNDS`, `RPC_MISC_ERROR`, `RPC_VERIFY_REJECTED`, `RPC_TRANSACTION_REJECTED`, `RPC_DESERIALIZATION_ERROR`, `RPC_METHOD_NOT_FOUND (-32601)`.

---

## Category: zslp (tokens & NFTs)

Read RPCs (`zslp_gettoken`, `zslp_listtokens`, `zslp_listtransfers`, `zslp_listmytokens`, `zslp_listcollectionmembers`, `zslp_collectioninfo`) work on any build with `-zslpindex` on. Write RPCs (`zslp_genesis`, `zslp_mint`, `zslp_send`) require a wallet-enabled build.

All token objects below share the **TokenToJSON shape**:

```json
{
  "tokenid": "<hex>",
  "ticker": "<string>",
  "name": "<string>",
  "documenturl": "<string>",
  "documenthash": "<hex, or \"\" if none>",
  "decimals": <0..9>,
  "genesisheight": <n>,
  "totalminted": <n>,
  "mintbatonvout": <n>,
  "hasmintbaton": <bool; true when mintbatonvout >= 2>,
  "group": "<hex parent collection id, or \"\" — set ONLY for an AUTHORIZED child>",
  "group_authorized": <bool; verified collection member>,
  "group_claimed": <bool; the GENESIS named a group on-chain — a CLAIM, NEVER membership>
}
```

> **Collections (spec-v2):** `group_authorized` is the only field that means membership — it is true only when the token's GENESIS both NAMED the parent collection (`group_id`) AND spent a live parent-token unit/baton of it as authorization (burned; one unit = one child). `group_claimed` is the raw on-chain claim and may be set by anyone; never treat it as membership. Surface members via `zslp_listcollectionmembers` (the authorized-only index).

### zslp_gettoken

Return metadata for one ZSLP token by its token id (genesis txid). Read-only.

| Param | Type | Req | Description |
|---|---|---|---|
| `token_id` | string | required | The token id (genesis txid, hex) |

**Result:** one token object (TokenToJSON shape above).

**Examples:**
```bash
zclassic-cli zslp_gettoken "<txid>"
```
```bash
# JSON-RPC
curl --user u:p --data-binary \
  '{"jsonrpc":"1.0","id":"x","method":"zslp_gettoken","params":["<txid>"]}' \
  -H 'content-type:text/plain;' http://127.0.0.1:8232/
```

**Notable errors:**
- `RPC_MISC_ERROR` — "ZSLP index is not enabled. Start zclassicd with -zslpindex." (when `-zslpindex` off)
- `RPC_INVALID_PARAMETER` — "Token not found"

> Note: there is no separate `genesistxid` field because the id *is* the genesis txid. For full genesis tx details, call `getrawtransaction "<tokenid>" 1`.

### zslp_listtokens

Bounded, paginated list of known ZSLP tokens. Read-only; no wallet needed.

| Param | Type | Req | Description |
|---|---|---|---|
| `count` | numeric | optional, default 100 | Max tokens to return; clamped to `[0, 1000]` (`ZSLP_LIST_MAX`) |
| `from` | numeric | optional, default 0 | Number of tokens to skip; clamped to `>= 0` |

**Result:** array of token objects (TokenToJSON shape).

**Examples:**
```bash
zclassic-cli zslp_listtokens 100 0
```
```
# JSON-RPC params: [100, 0]
```

**Notable errors:**
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."

### zslp_listtransfers

Bounded, newest-height-first list of transfer rows (GENESIS / MINT / SEND) for a token. This is the provenance / audit log. Read-only.

| Param | Type | Req | Description |
|---|---|---|---|
| `token_id` | string | required | The token id (hex) |
| `count` | numeric | optional, default 100 | Max rows; clamped to `[0, 1000]` |
| `from` | numeric | optional, default 0 | Rows to skip; clamped to `>= 0` |

**Result:** array of transfer objects:
```json
[
  {
    "txid": "<hex>",
    "tokenid": "<hex>",
    "type": "GENESIS" | "MINT" | "SEND" | "UNKNOWN",
    "amount": <n>,
    "vout": <n>,
    "height": <n>,
    "blockhash": "<hex>",
    "address": "<t-address (recipient at this transfer)>"
  }
]
```

**Examples:**
```bash
zclassic-cli zslp_listtransfers "<txid>" 100 0
```

**Notable errors:**
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."

> Note: `address` is the *recipient* at each transfer, not a live current-holder view.

### zslp_listmytokens

List ZSLP tokens with a positive balance at any of this wallet's transparent addresses, with per-wallet aggregate balance and per-address breakdown. Read-only (wallet-scoped).

| Param | Type | Req | Description |
|---|---|---|---|
| _(none)_ | | | |

**Result:** array. Each entry is the full token object (TokenToJSON shape) plus:
```json
{
  "...token fields...": "...",
  "balance": <this wallet's aggregate balance of this token>,
  "addresses": [ { "address": "<t-addr>", "balance": <n> }, ... ]
}
```
Bounded by `ZSLP_LIST_MAX` (1000). Returns `[]` when no wallet is loaded.

**Examples:**
```bash
zclassic-cli zslp_listmytokens
```

**Notable errors:**
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."
- `RPC_MISC_ERROR` — "zslp_listmytokens requires a wallet-enabled build" (no-wallet build only)

> To get your balance of one specific token, call this and filter client-side by `tokenid` (there is no single-token balance RPC — see gap report).

### zslp_listcollectionmembers

List the **AUTHORIZED** children of a ZSLP collection. Read-only; no wallet needed. A child is authorized only when its GENESIS named this group AND spent a live parent-token unit/baton of it as authorization (closed/owner-authorized membership). A token that merely names the group (a `group_claimed` squatter) is never returned here.

| Param | Type | Req | Description |
|---|---|---|---|
| `group_id` | string | required | The collection (parent) genesis txid (hex) |
| `count` | numeric | optional, default 100 | Max members; clamped to `[0, 1000]` (`ZSLP_LIST_MAX`) |
| `from` | numeric | optional, default 0 | Members to skip; clamped to `>= 0` |

**Result:** array, leveldb-key ordered (child tokenId ascending):
```json
[ { "tokenid": "<hex>", "name": "<string>", "group_authorized": true }, ... ]
```

**Examples:**
```bash
zclassic-cli zslp_listcollectionmembers "<group_id>" 100 0
```

**Notable errors:**
- `RPC_INVALID_PARAMETER` — "Collection (group) not found"
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."

### zslp_collectioninfo

Return a collection's parent token (TokenToJSON shape) plus its authorized member count and whether the collection is still **open** (a live parent **unit** still exists, so the owner can authorize another child while keeping the baton) or sealed. Read-only.

| Param | Type | Req | Description |
|---|---|---|---|
| `group_id` | string | required | The collection (parent) genesis txid (hex) |

**Result:** the parent token object plus:
```json
{
  "...token fields...": "...",
  "member_count": <n; authorized children>,
  "open": <bool; a live parent UNIT still exists -> can authorize more children>
}
```

**Examples:**
```bash
zclassic-cli zslp_collectioninfo "<group_id>"
```

**Notable errors:**
- `RPC_INVALID_PARAMETER` — "Collection (group) not found"
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."

### zslp_genesis

Mint a new ZSLP token, or an NFT when `nft:true`. Builds one `OP_RETURN` at `vout[0]`, a 546-sat token output at `vout[1]` (plus an optional re-issue baton), self-validates against the overlay ledger, and broadcasts. **Single JSON object argument.** Requires a wallet-enabled build.

| Member | Type | Req | Description |
|---|---|---|---|
| `ticker` | string | optional | Short symbol |
| `name` | string | optional | Display name |
| `document_url` | string | optional | Short URL/URI |
| `document_hash` | string | optional | Exactly 64 hex chars (32 bytes), the off-chain content fingerprint |
| `decimals` | numeric | optional, default 0 | 0..9 |
| `quantity` | string\|numeric | optional, default 1 | Initial supply (`< 2^63`) |
| `mint_baton_vout` | numeric | optional | `>= 2` to issue a re-issue baton (placed at that vout); omit/0 for none |
| `to` | string | optional | Recipient t-address (default: a fresh wallet address) |
| `nft` | bool | optional | Force decimals 0, quantity 1, no baton (1-of-1) |
| `group_id` | string | optional | 64 hex parent collection genesis txid — mint an AUTHORIZED child of that collection. The wallet spends ONE live **single-unit** parent-token UTXO as authorization; because a child is a GENESIS it cannot return parent-token change, so the spent outpoint is **burned in full** — it must hold **exactly 1 unit** (one unit = one card). A multi-unit authority output is **refused** (it would burn every unit for one card); split it first. |
| `authority` | object | optional | `{"txid":"<hex>","vout":<n>}` — pin a SPECIFIC parent authority UTXO (only with `group_id`). It must hold **exactly 1 unit**; a `>1`-unit outpoint is rejected (would burn all units). If omitted, auto-selects a 1-unit output (never a multi-unit output, never the baton). |
| `allow_baton` | bool | optional | Permit spending the collection's mint baton as authority when no single-unit output exists. Spending the baton in a child GENESIS **burns the baton and SEALS the collection** (no more authority can be minted) — strictly opt-in. |

**Result:**
```json
{ "txid": "<hex>", "tokenid": "<hex; == txid>" }
```

**Examples:**
```bash
# Mint a 1-of-1 NFT bound to an off-chain image fingerprint
zclassic-cli zslp_genesis '{"nft":true,"name":"My Photo #1","document_hash":"<64hex>"}'

# Mint a fungible token with a re-issue baton
zclassic-cli zslp_genesis '{"ticker":"GOLD","decimals":2,"quantity":"100000","mint_baton_vout":2}'

# Create a COLLECTION parent: a normal token WITH a mint baton + N authority
# units (here 100). Its tokenid is the group_id you pass to children. The baton
# lets you mint MORE authority units later (zslp_mint).
GROUP=$(zclassic-cli zslp_genesis '{"ticker":"S1","name":"Series 1","quantity":"100","mint_baton_vout":2}' | jq -r .tokenid)

# SPLIT the authority into single-unit outputs — each child mint must burn
# EXACTLY ONE unit (a child is a GENESIS and cannot return parent-token change,
# so a multi-unit authority output would be burned in full). Up to 19 single-
# unit recipients per zslp_send; repeat for all 100. Send to your OWN addresses.
ME=$(zclassic-cli getnewaddress)
zclassic-cli zslp_send "$GROUP" '[{"address":"'"$ME"'","amount":1},{"address":"'"$ME"'","amount":1}]'   # ...repeat to split all 100

# Mint an AUTHORIZED child of that collection (auto-spends one 1-unit output):
zclassic-cli zslp_genesis '{"nft":true,"name":"Series 1 Card #1","group_id":"'"$GROUP"'"}'
```

**Notable errors:**
- `RPC_INVALID_PARAMETER` — "document_hash must be 64 hex characters (32 bytes)"
- `RPC_INVALID_PARAMETER` — "an NFT must have decimals 0" / "an NFT must have quantity 1" / "an NFT cannot have a mint baton"
- `RPC_INVALID_PARAMETER` — "decimals must be 0..9"
- `RPC_INVALID_PARAMETER` — "mint_baton_vout 1 collides with the token output at vout[1]; use 0 (none) or >=2"
- `RPC_INVALID_PARAMETER` — "group_id must be 64 hex characters (the parent collection genesis txid)"
- `RPC_INVALID_PARAMETER` — "group_id names no known collection (parent token not found)"
- `RPC_INVALID_PARAMETER` — "authority outpoint is not a live parent-token UTXO of the collection"
- `RPC_INVALID_PARAMETER` — "authority outpoint holds N units of collection <G>; ... it would BURN all N units for one card. Split your authority into single units first ..." (a pinned authority output must hold exactly 1 unit)
- `RPC_INVALID_PARAMETER` — "authority outpoint is the collection mint baton; spending it in a child mint BURNS the baton and SEALS the collection ... Pass allow_baton:true to do this deliberately ..."
- `RPC_WALLET_ERROR` — "Collection <G> authority is held in a multi-unit output; minting a card would burn all of it. Split your authority into single units first (zslp_send <G> to your own address with per-recipient amount 1, up to 19 recipients per tx), then retry."
- `RPC_WALLET_ERROR` — "no spendable single-unit authority for collection <G>; mint more collection authority units (or split a multi-unit output into single units ...), or pass allow_baton to seal the collection by burning its baton"
- `RPC_INVALID_PARAMETER` — "metadata too large for one OP_RETURN (max 223 bytes); ..."
- `RPC_INVALID_PARAMETER` — quantity parse errors (non-digit / negative / "exceeds the maximum (2^63-1)")
- `RPC_WALLET_ERROR` — propagated build/commit error
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..." (fail closed)
- Wallet-locked / passphrase errors (unlock the wallet first)

### zslp_mint

Issue additional supply of an existing fungible token by spending its live mint baton. The wallet must hold the baton UTXO. NFTs never use MINT. Positional args. Requires a wallet-enabled build.

| Param | Type | Req | Description |
|---|---|---|---|
| `tokenid` | string | required | The token id (hex) |
| `amount` | string\|numeric | required | Additional quantity (`< 2^63`) |
| `baton_vout` | numeric | optional, default 2 | `>= 2` to continue the baton; `0` to end it |

**Result:**
```json
{ "txid": "<hex>" }
```

**Examples:**
```bash
zclassic-cli zslp_mint "<tokenid>" "1000"
zclassic-cli zslp_mint "<tokenid>" "1000" 2
```

**Notable errors:**
- `RPC_INVALID_ADDRESS_OR_KEY` — "Token not found"
- `RPC_INVALID_PARAMETER` — "amount must be > 0"
- `RPC_INVALID_PARAMETER` — "baton_vout 1 collides with the mint output; use 0 (end) or >=2"
- `RPC_INVALID_PARAMETER` — "failed to build MINT OP_RETURN"
- `RPC_WALLET_ERROR` — "This wallet does not hold the mint baton for that token (cannot mint)"
- `RPC_WALLET_ERROR` — UTXO-find / build-commit errors
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."
- Wallet-locked / passphrase errors

### zslp_send

Transfer ZSLP token amounts to a recipient (NFT gift defaults to amount 1). Selects the wallet's token UTXOs, conserves supply (token change to a fresh own t-address or `change_address`), anti-burn-filters fee coins, self-validates, broadcasts; never burns the token. Positional args. Requires a wallet-enabled build.

| Param | Type | Req | Description |
|---|---|---|---|
| `tokenid` | string | required | The token id (hex) |
| `to_address` | string | required | Recipient t-address |
| `amount` | string\|numeric | optional, default 1 | Amount to send (`< 2^63`) |
| `change_address` | string | optional | Token-change t-address (default: a fresh own address) |

**Result:**
```json
{ "txid": "<hex>" }
```

**Examples:**
```bash
# Gift an NFT (amount defaults to 1)
zclassic-cli zslp_send "<tokenid>" "t1RecipientAddress..." 1

# Send 5 units of a fungible token
zclassic-cli zslp_send "<tokenid>" "t1RecipientAddress..." "5"
```

**Notable errors:**
- `RPC_INVALID_ADDRESS_OR_KEY` — "Token not found"
- `RPC_INVALID_PARAMETER` — "amount must be > 0"
- `RPC_WALLET_INSUFFICIENT_FUNDS` — "Insufficient token balance: have <X>, need <Y>"
- `RPC_INVALID_PARAMETER` — "too many SEND outputs" (> `ZSLP_MAX_SEND_OUTPUTS` = 19)
- `RPC_INVALID_PARAMETER` — "failed to build SEND OP_RETURN"
- `RPC_WALLET_ERROR` — UTXO-find / build-commit errors
- `RPC_INVALID_PARAMETER` — amount / t-address parse errors
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."
- Wallet-locked / passphrase errors

---

## Category: nft (atomic NFT ↔ ZCL sell offers)

Offers are buyer-sealed atomic swaps shared **offline as base64 blobs** (`znftoffer:...`). There is no on-chain or network marketplace discovery; `nft_listoffers` returns only your own locally stored offers. All `nft_*` RPCs require `-zslpindex`; the write ones require a wallet-enabled build.

### nft_verifyoffer

Mandatory buyer-side safety check run **before** signing. Decodes a sell offer, re-derives every field from the partial tx, and re-runs the real ZSLP parse + conservation check + live-UTXO check + seller-signature (`VerifyScript`) check on `vin[0]`. A forged or edited offer fails here with explicit reasons. Read-only.

| Param | Type | Req | Description |
|---|---|---|---|
| `params` | object | required | `{ "offerBlob": "<base64 or znftoffer:...>" }` |

**Result:**
```json
{
  "ok": <bool>,
  "tokenId": "<hex>",
  "priceZat": <n>,
  "payoutAddr": "<t-addr>",
  "buyerNftAddr": "<t-addr>",
  "expiryHeight": <n>,
  "reasons": [ "<string>", ... ]   // non-empty when ok=false
}
```
Re-derived fields fall back to the blob's advertised values when the verifier could not recompute them.

**Examples:**
```bash
zclassic-cli nft_verifyoffer '{"offerBlob":"znftoffer:..."}'
```

**Notable errors:**
- `RPC_INVALID_PARAMETER` — "offerBlob is required"
- `RPC_DESERIALIZATION_ERROR` — "offer blob is not valid base64" / "offer blob decode failed: ..."
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."

### nft_listoffers

List offers from the **local store** (`datadir/nftoffers.json`); status is recomputed live against the UTXO set. Every stored record is yours. Read-only.

| Param | Type | Req | Description |
|---|---|---|---|
| _(none)_ | | | |

**Result:**
```json
[
  {
    "offerId": "<hex>",
    "tokenId": "<hex>",
    "priceZat": <n>,
    "expiryHeight": <n>,
    "role": "<string>",
    "status": "open" | "filled" | "expired" | "canceled"
  }
]
```
Status rules: terminal stored states (canceled/filled) are sticky; spent NFT outpoint → "filled"; tip > expiry → "expired"; else "open".

**Examples:**
```bash
zclassic-cli nft_listoffers
```

**Notable errors:**
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."

> This is local-only. It cannot surface offers from other sellers (see gap report).

### nft_makeoffer

Create a buyer-sealed atomic NFT → ZCL sell offer (mechanism A'). **Does not broadcast.** Builds a fixed 3-output ZSLP SEND template, signs **only** `vin[0]` (the NFT dust UTXO) with `SIGHASH_ALL|ANYONECANPAY` so a buyer can only append funding inputs, locks the NFT outpoint, self-validates, persists to `datadir/nftoffers.json`, and returns a base64 offer blob to share. Single JSON object argument. Requires a wallet.

| Member | Type | Req | Description |
|---|---|---|---|
| `tokenId` | string | required | The NFT token id (hex) |
| `priceZat` | string\|numeric | required | Asking price in zatoshi |
| `buyerNftAddr` | string | required | The buyer's NFT receive t-address (this is a **targeted** offer, not an open/floor listing) |
| `payoutAddr` | string | optional | Your payout t-address (default: fresh) |
| `expiryHeight` | numeric | optional | Offer deadline (default: tip + ~7 days = tip + 7·1440 blocks) |

**Result:**
```json
{
  "offerBlob": "znftoffer:<base64>",
  "offerId": "<hex; first 16 hex of SHA256(blob)>",
  "nftOutpoint": "<txid:n>",
  "fingerprint": "<hex; == offerId>"
}
```

**Examples:**
```bash
zclassic-cli nft_makeoffer '{"tokenId":"<txid>","priceZat":"100000000","buyerNftAddr":"t1Buyer..."}'
```

**Notable errors:**
- `RPC_INVALID_PARAMETER` — "priceZat must be > 0" / "buyerNftAddr is required"
- `RPC_INVALID_ADDRESS_OR_KEY` — "Token not found"
- `RPC_WALLET_ERROR` — "No confirmed quantity-1 NFT UTXO for that token in this wallet ..."
- `RPC_WALLET_ERROR` — "NFT UTXO is not live in the chainstate (still confirming?)"
- `RPC_INVALID_PARAMETER` — expiry errors ("expiryHeight must be >= 0" / "...too soon..." / "...must be < threshold")
- `RPC_WALLET_ERROR` — "failed to sign the NFT input (vin[0]) — wallet does not hold its key?"
- `RPC_WALLET_ERROR` — "self-check: seller signature did not verify: ..." / "self-validate of the built offer failed: ..."
- `RPC_INVALID_PARAMETER` — priceZat parse errors ("exceeds MAX_MONEY")
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."; Wallet-locked errors

### nft_takeoffer

Verify, fund, and broadcast an NFT sell offer atomically. Verifies first (refuses if `ok=false`), appends funding inputs that **exclude** every ZSLP-protected outpoint (anti-burn), adds no new outputs, signs buyer inputs `ALL|ANYONECANPAY`, merges the seller's `vin[0]` via `CombineSignatures`, self-validates, then `AcceptToMemoryPool` + relay. Any overshoot beyond price+dust+fee is donated to the miner. Single JSON object argument. Requires a wallet.

| Member | Type | Req | Description |
|---|---|---|---|
| `offerBlob` | string | required | base64 or `znftoffer:` blob |
| `fundingInputs` | array | optional | Explicit `["txid:n", ...]` funding outpoints |
| `changeAddr` | string | optional | Reserved for a pre-size prep tx (unused here) |
| `acknowledge` | bool | optional | Acknowledge overshoot-to-fee; required when the overpay exceeds dust |

**Result:**
```json
{ "txid": "<hex>", "overshootZat": <n; total network fee donated> }
```

**Examples:**
```bash
zclassic-cli nft_takeoffer '{"offerBlob":"znftoffer:..."}'
# If it reports an overpay-to-fee greater than dust:
zclassic-cli nft_takeoffer '{"offerBlob":"znftoffer:...","acknowledge":true}'
```

**Notable errors:**
- `RPC_INVALID_PARAMETER` — "offerBlob is required"
- `RPC_DESERIALIZATION_ERROR` — blob decode failure
- `RPC_TYPE_ERROR` — "acknowledge must be a boolean"
- `RPC_VERIFY_REJECTED` — "offer failed verification: ..."
- `RPC_INVALID_PARAMETER` — "fundingInputs entry not in txid:n form: ..." / "anti-burn: funding input is a ZSLP token/baton UTXO: ..." / "funding input is not live: ..."
- `RPC_WALLET_INSUFFICIENT_FUNDS` — "Insufficient funds to fund the swap: have <X>, need ~<Y> (price+dust+fee, no change output is possible)"
- `RPC_INVALID_PARAMETER` — "you would overpay <X> ZCL to miner fees ...; pass acknowledge:true to proceed"
- `RPC_WALLET_ERROR` — signing / liveness / VerifyScript / self-validate failures
- `RPC_TRANSACTION_REJECTED` — "<rejectCode>: <rejectReason>"
- `RPC_TRANSACTION_ERROR` — "Missing inputs" / reject reason
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."; Wallet-locked errors

### nft_canceloffer

Cancel an outstanding sell offer by self-spending its NFT UTXO (a 1-output ZSLP SEND to a fresh own address), voiding any offer referencing that outpoint and unlocking it. Marks the local store record `status="canceled"` with a `cancelTxid`. Re-locks the outpoint on failure. Single JSON object argument. Requires a wallet.

| Param | Type | Req | Description |
|---|---|---|---|
| `params` | object | required | `{ "offerId": "<hex>" }` |

**Result:**
```json
{ "txid": "<hex>" }
```

**Examples:**
```bash
zclassic-cli nft_canceloffer '{"offerId":"<hex>"}'
```

**Notable errors:**
- `RPC_INVALID_PARAMETER` — "offerId is required" / "offerId not found in the local store" / "stored nftOutpoint is malformed" / "failed to build cancel SEND OP_RETURN"
- `RPC_WALLET_ERROR` — build/commit error (NFT re-locked on failure)
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."; Wallet-locked errors

> Requires the `offerId` to exist in **this node's** local `nftoffers.json`.

### nft_requestbuy

Produce a fresh buyer NFT receive t-address plus a versioned request blob (magic `ZNFTREQ1`) so a seller can seal an offer to it. Accepts a `tokenId`, or an `offerId` (resolved to its tokenId). Address-handshake only. Single JSON object argument. Requires a wallet.

| Param | Type | Req | Description |
|---|---|---|---|
| `params` | object | required | `{ "tokenId": "<hex>" }` (or `{ "offerId": "<hex>" }`) |

**Result:**
```json
{ "buyerNftAddr": "<t-addr>", "requestBlob": "znftreq:<base64>" }
```

**Examples:**
```bash
zclassic-cli nft_requestbuy '{"tokenId":"<hex>"}'
```

**Notable errors:**
- `RPC_INVALID_PARAMETER` — "offerId not found" / "tokenId or offerId is required"
- `RPC_MISC_ERROR` — "ZSLP index is not enabled..."; Wallet-locked errors

---

## Category: datachannel — REMOVED

The shielded data-channel RPCs (`z_senddatafile`, `z_listdatatransfers`, `z_getdatatransfer`) and the `-datachannel` option have been **removed entirely**. ZClassic provides **no wallet path to store arbitrary files on-chain**. These methods are no longer registered; calling them returns `RPC_METHOD_NOT_FOUND (-32601)`. NFT content is referenced only by an off-chain `document_hash` fingerprint (see "Images and files are off-chain" above) — the file bytes are never placed on-chain.

---

## Category: coin-control

> Availability note: the coin-control `inputs` parameter ships on branches `beta7/integration-all` and `beta7/coincontrol-inputs`. It is **NOT** present on the currently checked-out HEAD. Confirm `help z_sendmany` on your running daemon shows the 5th `inputs` parameter before relying on it.

### z_sendmany (`inputs` coin-control parameter)

Coin-control is an optional **5th parameter `inputs`** added to the inherited wallet RPC `z_sendmany` (it is not a new command). It restricts the spend to exactly the listed UTXOs/notes. All inputs must belong to `fromaddress` and be of the same pool (no mixing transparent with shielded). Non-consensus: it only narrows which already-valid inputs the wallet selects.

> **Availability:** the `inputs` parameter ships on the beta7 coin-control integration branch and is **not** present on every daemon build. Confirm on your binary with `zclassic-cli help z_sendmany` — if the help text lists no `inputs` argument, your build does not yet accept a 5th positional parameter.

| Param | Type | Req | Description |
|---|---|---|---|
| `fromaddress` | string | required | Inherited: taddr or zaddr to send from |
| `amounts` | array | required | Inherited: `[{ "address", "amount", "memo"? }, ...]` |
| `minconf` | numeric | optional, default 1 | Inherited |
| `fee` | numeric | optional, default async-op default | Inherited |
| `inputs` | array | optional | Added: restrict spend to exactly these UTXOs/notes (see entry shape below) |

`inputs` entry object:

| Field | Type | Req | Description |
|---|---|---|---|
| `type` | string | required | One of `"transparent"`, `"sapling"`, `"sprout"` |
| `txid` | string | required | 64-char hex |
| `vout` | numeric | required for transparent | Output index |
| `outindex` | numeric | required for sapling | Sapling `vShieldedOutput` index |
| `jsindex` | numeric | required for sprout | Joinsplit index |
| `jsoutindex` | numeric | required for sprout | Joinsplit output index, in `[0, ZC_NUM_JS_OUTPUTS)` |

The help text includes a **privacy warning** that hand-selecting shielded notes can reduce privacy by linking notes.

**Result:** `operationid` (string) — unchanged; poll via `z_getoperationstatus`/`z_getoperationresult`.

**Examples:**
```bash
# Existing positional form (no inputs):
zclassic-cli z_sendmany "t1Sender..." '[{"address":"ztfaW...","amount":5.0}]'

# With coin-control pinning to one transparent UTXO:
zclassic-cli z_sendmany "t1Sender..." '[{"address":"ztfaW...","amount":5.0}]' 1 0.0001 \
  '[{"type":"transparent","txid":"<64hex>","vout":0}]'
```

**Notable errors:**
- `RPC_INVALID_PARAMETER` — "expected object in inputs array" / "unknown key in inputs: <name>" / 'input "type" is required (transparent, sapling or sprout)'
- `RPC_INVALID_PARAMETER` — 'input "txid" is required' / "...must be a 64-character hex string"
- `RPC_INVALID_PARAMETER` — type/pool mismatch and missing-field messages (transparent requires `vout`; sapling requires `outindex`; sprout requires `jsindex`/`jsoutindex`)
- `RPC_INVALID_PARAMETER` — "cannot mix transparent and shielded inputs" / "unknown input type: <type>" / "inputs array is empty"
- `RPC_WALLET_INSUFFICIENT_FUNDS` — thrown later when the pinned set cannot cover the target (e.g. "Insufficient transparent funds, have <X>, need <Y>")

---

## End-to-end walkthrough: mint → list → get info → transfer → sell → buy

Assumes a wallet-enabled daemon with `-zslpindex` on, an unlocked wallet, and funds for fees.

```bash
# 1. MINT a 1-of-1 NFT bound to an off-chain image fingerprint.
#    (Compute the 64-hex document_hash off-node from your image; see gap report
#     re: a daemon-side fingerprint RPC.)
TOKENID=$(zclassic-cli zslp_genesis \
  '{"nft":true,"name":"My Photo #1","document_hash":"<64hex>"}' | jq -r .tokenid)

# 2. LIST what this wallet holds.
zclassic-cli zslp_listmytokens

# 3. GET full metadata for the token, and its provenance log.
zclassic-cli zslp_gettoken "$TOKENID"
zclassic-cli zslp_listtransfers "$TOKENID" 100 0

# (Browse all chain tokens, e.g. for an explorer:)
zclassic-cli zslp_listtokens 100 0

# 4. TRANSFER / gift the NFT (amount defaults to 1).
zclassic-cli zslp_send "$TOKENID" "t1Friend..." 1

# --- SELL FLOW (atomic NFT -> ZCL swap, shared offline) ---

# 5a. (Buyer) generate a receive address + request blob and hand it to the seller.
zclassic-cli nft_requestbuy '{"tokenId":"'"$TOKENID"'"}'
#     -> { "buyerNftAddr":"t1Buyer...", "requestBlob":"znftreq:..." }

# 5b. (Seller) SELL: create a targeted offer to that buyer address.
OFFER=$(zclassic-cli nft_makeoffer \
  '{"tokenId":"'"$TOKENID"'","priceZat":"100000000","buyerNftAddr":"t1Buyer..."}' \
  | jq -r .offerBlob)
#     Share $OFFER (the znftoffer: blob) with the buyer out-of-band.

# 6a. (Buyer) VERIFY the offer before paying. ok must be true.
zclassic-cli nft_verifyoffer '{"offerBlob":"'"$OFFER"'"}'

# 6b. (Buyer) BUY: fund + broadcast the swap atomically.
zclassic-cli nft_takeoffer '{"offerBlob":"'"$OFFER"'"}'
#     If it reports an overpay-to-fee greater than dust, re-run with "acknowledge":true.

# Seller can track/cancel before it fills:
zclassic-cli nft_listoffers
zclassic-cli nft_canceloffer '{"offerId":"<hex>"}'
```

> **Note:** There is no on-chain private-file path. NFT content lives off-chain; bind it to the token only via an off-chain `document_hash` fingerprint passed to `zslp_genesis`. ZClassic provides no wallet RPC to store file bytes on-chain.

---

## Walkthrough: create a collection → mint authorized children → list members

A **collection** is just a normal ZSLP token minted WITH a mint baton and **N
authority units**. Its tokenid is the `group_id`. Each child is an AUTHORIZED
member only if its GENESIS spends a live parent-token unit (or, with
`allow_baton`, the baton).

**Authority model — split before you mint.** A child mint is a GENESIS: it
describes only the CHILD token, so it CANNOT carry a parent-token change output.
The parent outpoint it spends is therefore **burned in full**, regardless of how
many units it holds. So each card mint must spend an authority output holding
**EXACTLY 1 unit** (decimals are 0; one unit = one card). After creating the
parent you must **SPLIT** the N units into single-unit outputs — one `zslp_send`
to your OWN address(es) with N recipients of `amount 1` (up to 19 per tx, repeat
for more). The daemon **refuses** to spend a multi-unit authority output (it
would silently burn every unit for one card) and tells you to split first. The
**baton** lets you mint MORE authority units later (`zslp_mint`); spending the
baton itself in a child GENESIS burns it and SEALS the collection, so it is
strictly opt-in via `allow_baton`. Membership is unforgeable: a non-owner can
name your group but can never appear in the members list. Assumes `-zslpindex`
on and an unlocked wallet.

```bash
# 1. CREATE the collection parent: a token with a baton + 100 authority units.
GROUP=$(zclassic-cli zslp_genesis \
  '{"ticker":"S1","name":"Series 1","quantity":"100","mint_baton_vout":2}' | jq -r .tokenid)

# 2. INSPECT the collection (0 members yet; open == true while a unit/baton lives).
zclassic-cli zslp_collectioninfo "$GROUP"

# 3. SPLIT the 100 units into single-unit outputs so each card mint burns exactly
#    one. Send to your OWN address; up to 19 single-unit recipients per zslp_send
#    (so ~6 sends for 100). Example splitting 2 units; repeat to cover all 100.
ME=$(zclassic-cli getnewaddress)
zclassic-cli zslp_send "$GROUP" \
  '[{"address":"'"$ME"'","amount":1},{"address":"'"$ME"'","amount":1}]'

# 4. MINT authorized children. Each auto-spends ONE single-unit output (burned).
zclassic-cli zslp_genesis '{"nft":true,"name":"Card #1","group_id":"'"$GROUP"'"}'
zclassic-cli zslp_genesis '{"nft":true,"name":"Card #2","group_id":"'"$GROUP"'"}'

# 5. LIST the verified members (authorized children only — squatters never appear).
zclassic-cli zslp_listcollectionmembers "$GROUP" 100 0

# 6. A child's token object shows its verified membership:
#    "group_authorized": true, "group": "<GROUP>".  A token that merely NAMED the
#    group without spending a parent unit shows group_authorized:false and is
#    ABSENT from step 5.
zclassic-cli zslp_gettoken "<child_tokenid>"
```