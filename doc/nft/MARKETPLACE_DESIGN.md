# ZClassic NFT Marketplace (ZMARKET) — Normative Design

Status: **NORMATIVE** (target: v2.1.2-beta7). Coin is **ZClassic / ZCL**, never ZEC/Zcash.

This document specifies a **decentralized, peer-to-peer NFT marketplace** for ZClassic:
users list NFTs for sale, discover others' listings, and buy them atomically — with **no
central server, no trusted indexer, and no new bytes on the blockchain**. It builds entirely
on the existing, audited ZSLP token overlay and the existing atomic-swap trade primitive.

It is companion to and bound by [`PROTOCOL_STANDARD.md`](PROTOCOL_STANDARD.md) (the 5 hard
invariants and the mandatory layer pipeline) and [`NFT_API_REFERENCE.md`](NFT_API_REFERENCE.md).

---

## 1. Hard invariants (release-gating)

A marketplace change that violates any of these is rejected:

1. **No consensus impact.** All code lives in net / wallet / RPC paths only. Nothing touches
   `CheckBlock`/`ConnectBlock`/`CheckInputs`/`pow.cpp`/script-verify/acceptance rules. New P2P
   commands are dedicated `NetMsgType` strings dispatched by name, with the existing "ignore
   unknown commands" fallthrough so unmodified nodes are unaffected. `git diff` on
   `src/consensus/`, `src/pow.cpp`, and `main.cpp` validation paths MUST be empty.
2. **No files on chain.** The marketplace adds **zero** new on-chain bytes. The only on-chain
   artifact is the pre-existing settlement `SEND` OP_RETURN (~55 bytes, length-gated, zero
   attacker-chosen free bytes — see §6). The off-chain transport is **hard-bounded** so it can
   never be abused as a blob/file channel (see §5).
3. **Genuinely decentralized.** Permissionless flood-gossip over the existing peer mesh,
   verify-on-receipt, no central server / DHT bootstrap dependency / trusted indexer.
4. **Scam-proof.** Settlement atomicity + ownership proof are inherited unchanged from the
   audited atomic swap (see §4). Every node re-verifies every offer, so the transport is
   untrusted.
5. **Spam / DoS resistant.** Listing requires a real, confirmed, owned NFT UTXO; gossip is
   rate-limited, deduped-before-verify, ban-scored, and the offerpool is hard-capped (see §5).
6. **Privacy honesty.** Settlement of a ZSLP token is irreducibly **public/transparent**
   (t-addr only; `ALL|ANYONECANPAY` does not compose with Sapling whole-tx binding). The GUI
   states this plainly and MUST NOT advertise "private NFT trading."

---

## 2. Architecture (three layers, strict reuse-first)

| Layer | What | Reuse |
|------|------|-------|
| **Global index** | "All NFTs / collections / owners / provenance" | The existing `-zslpindex` `CZSLPStore` leveldb (a zero-consensus `CValidationInterface` observer). **No new schema, no `ZSLP_INDEX_VERSION` / `ZSLP_SPEC_VERSION` bump.** |
| **Discovery** | List + propagate + browse offers | **NEW**: flood-gossip of the existing offer blob over 5 dedicated P2P messages into a RAM-only offerpool; verify-on-receipt. |
| **Settlement** | Atomic buy | 100% reuse of `nft_makeoffer` / `nft_verifyoffer` / `nft_takeoffer` + `CNftOfferBlob` + `NftVerify`. **Zero new settlement code, zero new trust.** |

The "for-sale" set is deliberately **not** an on-chain index — it lives only in the ephemeral
in-RAM offerpool.

---

## 3. Discovery — the decentralized crux

### 3.1 P2P protocol (5 dedicated commands)

Modeled byte-for-byte on the in-tree bootstrap messages (`getbsman`/`bsman`, see
`main.cpp` ProcessMessage), each carrying its **own** payload struct. The offer hash is
**NEVER** placed in the shared `inv`/`CInv` path — `CInv::GetCommand()` throws
`std::out_of_range` for unknown inv types (`protocol.cpp`), which would abort co-batched
tx/block invs on unmodified nodes. Dedicated commands guarantee old nodes safely ignore us.

| Command | Payload | Purpose |
|--------|---------|---------|
| `nftinv` | up to N (cap 1000) 32-byte offerIds | announce known offers |
| `getnftoffer` | one 32-byte offerId | pull a blob |
| `nftoffer` | one `CNftOfferBlob` (**hard-capped**, §5) | the blob itself |
| `getnftinv` | (none) | cold-start digest sync on connect |
| `nftabort` | one 32-byte offerId | advisory spent/cancel hint (never authoritative) |

### 3.2 Flow

`publish → push nftinv(hash) → peer lacking it (and under rate-limit) sends getnftoffer →
seller sends nftoffer(blob) → receiver: (a) check body-size cap + advertised hash ==
SHA256(body) BEFORE deserialize, (b) dedupe by offerId BEFORE verifying, (c) run NftVerify
under cs_main, (d) only if ok + novel + under pool bounds: insert and re-announce nftinv to
its peers.`

A node that drops/censors an offer cannot suppress it (any honest peer re-floods); no peer can
inject an invalid one (verify-on-receipt). Cold start = `getnftinv`-on-connect +
re-announce-on-restart → completeness with zero on-chain bytes (this is why no on-chain
"listing beacon" is needed, and none is added).

### 3.3 Offerpool

`src/nft/offerpool.{h,cpp}`: RAM-only map keyed by offerId. Hard caps: max-offers, max-bytes,
per-token cap (so one NFT can't flood price variants). Eviction on every connected block:
re-check each offer's `vin[0]` against `pcoinsTip` and evict spent/filled/expired (reuse the
live-status recompute already in `nft_listoffers`). A filled/canceled listing self-evicts
network-wide. `nftabort` only *accelerates* eviction; the chain is the authority.

---

## 4. Settlement — 100% reuse (already audited)

`nft_makeoffer` builds a fixed **3-output** ZSLP `SEND`: `vout[0]` = `SEND` OP_RETURN
(value 0, credits `vout[1]`); `vout[1]` = buyer NFT dust → `buyerNftAddr`; `vout[2]` = ZCL
payout (`priceZat`) → `payoutAddr`; `vin[0]` = the seller's qty-1 NFT UTXO, signed
**`SIGHASH_ALL | ANYONECANPAY`**.

- `ALL` pins **every** output → price, recipient, and OP_RETURN are uneditable (any edit breaks
  `VerifyScript`).
- `ANYONECANPAY` lets the **buyer append funding inputs only** (`vin[1..]`), never edit/add an
  output. No change output is possible.
- Result: the buyer gets the NFT **iff** the seller is paid, in one indivisible standard
  transparent tx that unmodified nodes relay/mine. `SINGLE|ANYONECANPAY` is **proven
  insufficient** (leaves payout editable) — `ALL` is mandatory.

`NftVerify` (the safety core, re-run by every node and every buyer) re-derives **every** field
from the blob and checks: real parse of `vout[0]` as `SEND` crediting qty1 to `vout[1]`;
`vout[1]`→`buyerNftAddr`; `vout[2]`==`priceZat`→`payoutAddr`; `vin[0]` is a **live** unspent
UTXO **and** a confirmed qty-1 non-baton token UTXO; the **cryptographic backstop**
`VerifyScript` of the seller's `ALL|ANYONECANPAY` signature over the live prevout; conservation
(`WouldBeValid`); and not-expiring-soon. Lying header fields are caught because everything is
re-derived.

Multi-buyer race is benign (first to confirm wins; the loser double-spends `vin[0]` and is
rejected at ATMP). Front-run theft is impossible (an interceptor can only complete the exact
pinned trade).

---

## 5. File-smuggling defense (MANDATORY — phase P1)

The red-team proved the off-chain blob, **as it exists today**, is an unbounded ~2 MiB
content-addressed flood-store (`offerHex`/`payoutAddr`/`buyerNftAddr` are plain `std::string`
in `nftoffer.h`; `NftVerify` has no `vin.size()` cap). Without bounds, the gossip layer would
be a file-distribution backdoor — violating invariant #2. The following are **load-bearing**,
not optional, and ship even ahead of the gossip layer because they harden the existing blob
path too:

- On read, deserialize with `LIMITED_STRING`: `payoutAddr`≤128, `buyerNftAddr`≤128,
  `offerHex`≤4096.
- `nftoffer` body hard-capped at **8 KiB** (`OFFERPOOL_MAX_OFFER_BYTES`); reject +
  `Misbehaving()` **before** full read. (Coherent with the field caps above: a legitimate
  blob is up to `offerHex` 4096 + two ≤128 addrs + ~50 B framing ≈ 4.4 KiB, so 8 KiB gives
  headroom without admitting a meaningfully larger attacker-controlled frame; worst-case pool
  RAM = 5000 × 8 KiB = 40 MiB, bounded further by the 32 MiB `OFFERPOOL_MAX_BYTES` total cap.)
- `NftVerify` caps `vin.size()` at a small N (a seller partial has exactly 1 input; cap ≤8).
- Enforce advertised `offerId == SHA256(body)` before insert (anti-amplification / anti-grind).
- Per-peer token-bucket rate-limit on `getnftinv`/`nftinv`/`getnftoffer`/`nftoffer`; `Misbehaving`
  ban-score on malformed / oversize / trailing-byte / hash-mismatch and on **structural** verify
  failures (forgery). A verify failure that is only a chain-state race (the offer's NFT input was
  just spent/filled, the offer expired, or a reorg) is **dropped without ban** — relaying a
  just-stale offer is normal honest behaviour in a busy market.
- Offerpool caps (max-offers, max-bytes, per-token) + expiry/liveness GC.

With these, the off-chain transport carries at most a ~1 KB structured swap blob — **not** a
blob channel.

> Note: the former ZDC1 private-delivery / shielded data-channel capability has been **removed**
> from the daemon. ZClassic provides **no wallet path to store arbitrary files on-chain**;
> private delivery of NFT content is out of scope. NFT content stays off-chain, bound only by a
> `document_hash` fingerprint.

---

## 6. On-chain footprint (proof it can't store files)

The entire marketplace adds **zero** new on-chain bytes. The only on-chain artifact is the
pre-existing settlement OP_RETURN at `vout[0]`:
`"SLP\0"(4) + token_type=1(1) + "SEND"(4) + token_id(push gated to EXACTLY 32) +
per-output uint64 qty(each gated to EXACTLY 8)`, with full-consumption `p==end` rejecting any
trailing push (`slp.c`), output count ≤ `ZSLP_SEND_MAX_OUTPUTS=19`, and the whole OP_RETURN
hard-capped at `MAX_OP_RETURN_RELAY=223`. Worst case ~55 bytes, **zero attacker-chosen free
bytes** (the token_id is the genesis txid). There is no variable-length user push in a `SEND`,
so it cannot store files.

---

## 7. RPC API

New (thin; all fail-closed when `-zslpindex`/offerpool disabled):

| Method | Args | Purpose |
|--------|------|---------|
| `nft_publishoffer` | `{offerBlob\|offerId,[powBits]}` | re-verify, insert into offerpool, flood `nftinv` |
| `nft_unpublishoffer` | `{offerId}` | drop from local pool + stop re-announcing (network cancel still needs `nft_canceloffer`) |
| `nft_browseoffers` | `{[tokenId],[groupId],[maxPriceZat],[minExpiry],[from],[count]}` | query pool; re-verify + live-status each; join `zslp_gettoken`; sort by price (floor = elem 0) |
| `nft_getoffer` | `{offerId}` | return the full verified blob + decoded fields |
| `nft_offerpoolinfo` | `{}` | diagnostics (count, bytes, caps, floorByCollection, peersServing) |

Reused unchanged: `nft_makeoffer`, `nft_verifyoffer`, `nft_takeoffer`, `nft_canceloffer`,
`nft_requestbuy`, plus the `zslp_*` enumeration RPCs. CLI arg-conversion entries added in
`rpc/client.cpp`.

---

## 8. GUI (feature/nft-gallery; calls RPCs only)

- **Marketplace tab**: grid from `nft_browseoffers`; each card shows thumbnail (resolved
  off-chain from `documentUrl` **only on explicit click**, integrity-checked vs the 32-byte
  `documentHash`), name/ticker, **price in ZCL** (`priceZat/1e8`), collection chip, and
  "for sale" + "ownership verified" badges. Filters: collection, max price, recently-listed.
  Per-collection **Floor: X ZCL** header. Unsolicited offers hidden-by-default; no auto-fetch
  of remote images.
- **Buy sheet**: `nft_verifyoffer` (show re-derived truth + "ownership proven, atomic, no
  central server") → `nft_takeoffer` with an overshoot/fee consent dialog.
- **Sell sheet**: pick an owned NFT (`zslp_listmytokens`), set price in ZCL,
  "List publicly (peers)" → `nft_makeoffer` + `nft_publishoffer`.
- **My Listings**: `nft_listoffers` live status; cancel warns "not effective until the cancel
  tx confirms."
- **Honesty banner** on Buy/Sell: "Sales settle on the public ZClassic chain — the price, the
  NFT, and both addresses are visible to everyone."

---

## 9. Test plan (mirror the existing ZSLP discipline)

- **gtest** (`src/gtest/test_nft_marketplace.cpp`): blob cap rejection (oversize fields,
  `vin>8`); `offerId != SHA256(body)` rejected pre-insert; verify-on-receipt accept/reject
  (forged/tampered/expired/dead-UTXO never inserted or re-announced; valid accepted once);
  liveness prune on spend; offerpool bound eviction; no-fork standardness of the settlement tx.
- **Live multi-node regtest** (`qa/zslp/nft-marketplace-regtest.sh`): 3-node seller/relay/buyer
  — offer reaches a buyer never directly connected to the seller (decentralization); forged
  offer dropped + ban-scored + never relayed; spam flood bounded; happy-path buy transfers
  ownership + pays seller in one tx + self-evicts; two-buyer race resolves with no funds lost.
- **Headless GUI E2E** (per the gui-headless-e2e harness): node A lists → node B's Marketplace
  tab shows it with floor → B buys (verify panel + overshoot consent) → ownership moves →
  honesty banner present → all copy ZCL never ZEC.

---

## 10. Phased plan

| Phase | Deliverable | Layer |
|------|-------------|-------|
| **P0** | This normative doc + `MARKETPLACE_THREATS.md` (red-team findings + designed-out fixes); decision: no version bump, dedicated commands not `CInv` | docs |
| **P1** | Blob hardening (`LIMITED_STRING` caps + `vin.size()` cap + `offerId==SHA256`) — ships independently; also hardens the existing offer path | daemon |
| **P2** | `offerpool.{h,cpp}` (RAM map, caps, eviction-on-ChainTip, relay cache) + unit gtests | daemon |
| **P3** | P2P gossip transport (5 dedicated commands + handlers w/ body-cap+hash-check before read, dedupe-before-verify, NftVerify gate, token-bucket, ban-score) + `RelayNftOffer` + getnftinv-on-connect | daemon |
| **P4** | Marketplace RPCs (§7) + CLI conversions + help | daemon |
| **P5** | gtest + multi-node regtest (§9) | daemon |
| **P6** | GUI Marketplace tab (§8) | gui |
| **P7** | Headless GUI E2E + doc updates | both |
| P8 *(optional, separate track)* | by-owner reverse index (`'a'+address+tokenId`, `ZSLP_INDEX_VERSION` 3→4 clean reindex) — never on the critical path | daemon |

---

## 11. Release decision & soak

- **Target: v2.1.2-beta7.** Owner directive (2026-06-08): the marketplace is in beta7.
- **Gossip overlay default: OFF (interim), converging to ON-over-Tor** (owner directive,
  revised 2026-06-08). Relay is `-nftmarket`, defaulted **OFF** in P4 because a node relaying
  others' sale offers over *clearnet* is exposed to the "relaying an order book" legal surface.
  The convergence target is to flip the default **ON once offer gossip rides the node's
  embedded-Tor P2P** — there a relayer is an unlinkable conduit (no one can tell who relayed
  what to whom), which dissolves that surface and gives strong, zero-config decentralized
  relay. See `doc/net/EMBEDDED_TOR_BLUEPRINT.md`. The §5 hardening, ban-scoring, PoW anti-spam,
  and offerpool caps remain mandatory regardless of the default, and the overlay MUST be soaked
  on our own multi-node setup before the public beta7 build. Until the flip, liquidity comes
  from opted-in relays (`-nftmarket=1`), our seed nodes, and direct buyer↔seller offer links.
- **Master merge HELD** until owner go + the standard beta-release gates (clean rebuild, full
  test suite green incl. `test_bitcoin`, adversarial diff review of the net handlers, multi-node
  soak).

---

## 12. Open questions (tracked)

1. Exact offerpool bounds (start conservative: 4 KiB body, `vin≤8`, ~5000 offers / 32 MiB /
   16-per-token; finalize from soak measurement).
2. NIP-13 PoW stamp (`powBits`): accept-but-ignore for forward-compat in v1; revisit in v2.
3. Seller-signs-LAST true open-listing (one-click floor buy): v2, not built in beta7.
4. `nftabort` stays advisory + low-trust (authoritative eviction is the chain) to avoid abuse.
5. Private delivery of NFT content is **out of scope** — the ZDC1 / shielded data-channel
   capability has been removed; ZClassic provides no on-chain arbitrary-file path.
6. by-owner reverse index (P8) only if by-owner browse is wanted; avoid the index-version bump
   otherwise.
