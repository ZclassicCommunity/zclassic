# ZCL NFT Marketplace — Unified Design & Build Plan

*An OpenSea-class experience, peer-to-peer with no middleman, built into the ZClassic full node and wallet.*

Status: **DESIGN — master-held.** Every line below is NON-consensus. This document merges the
recon inventory, three design tracks (UX, service layer, discovery/media/history), and two
red-team passes (UX, architecture/security) into one buildable plan. Where the tracks conflicted,
the conflict is resolved here decisively and the resolution is called out. Currency is **ZCL**
(never ZEC). GUI is Qt5 **C++14** (separate `zcl-qt-wallet` repo); daemon C++ is locked to the
project's existing standard — no `std::optional`/`string_view`, empty-string/zero sentinels as
`TokenToJSON` already does.

---

## 1. Vision

OpenSea is a web2 application wearing a blockchain hat: an indexer, an image CDN, a search cluster,
and an off-chain signed-order database do all the work, and the chain is a settlement rail it
touches only at fill time. We build the same premium experience — image-rich grids, floor and price
history, one-tap buy, floor-sweep — but with **no company, no account, and no middleman**. The chain
carries only ownership truth and the final atomic settlement (a markerless transfer that looks like
any other). Offers live off-chain as seller-pre-signed partial transactions, gossiped peer-to-peer
through nodes that *opt in* to the relay role. Discovery, search, history, and floor are rebuilt as a
**derived, wipe-and-rebuildable read-model inside the user's own node**, served over a localhost-only
REST surface in the exact JSON the wallet wants. Every centralized OpenSea backend is either
reproduced locally-and-trustlessly (each operator gets their own copy from their own chain) or turned
into a visible decentralization *win*: no marketplace fee, no custody, atomic-or-refund, and your own
node cryptographically verifying every purchase. We are honest about the few surfaces that are
genuinely worse without a central server — and we fix the substrate so we rarely have to apologize.

---

## 2. Architecture in One Picture

```
                          THE CHAIN  (consensus, permanent, global truth)
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  ZSLP tokens/NFTs (OP_RETURN overlay)   •   ownership = CZSLPStore 'u' UTXO map      │
  │  collections (group/child, authorized)  •   SETTLEMENT tx = ONE atomic transfer      │
  │  documentHash[32] = SHA-256(image)      •   (markerless — looks like any transfer)   │
  └──────────────────────────────────────────────────────────────────────────────────┘
        ▲ writes are REAL txs (zslp_genesis/mint/send, nft_takeoffer settlement)
        │ reads (observe only)
        │
   OFF-CHAIN OFFER LAYER  (soft state, RAM, gossiped — NOT on the chain)
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  CNftOfferBlob = seller-pre-signed partial (vin[0] SIGHASH_ALL|ANYONECANPAY,         │
  │     fixed outs: ZSLP SEND, NFT→buyer, price→seller).  RAM g_offerPool (5000/32MiB).  │
  │  5 P2P gossip cmds: getnftinv / nftinv / getnftoffer / nftoffer / nftabort.          │
  │  NftVerify = verify-on-receipt (re-derive every field, live vin[0] UTXO, sig binds   │
  │     exact payout, ZSLP conservation).  OPT-IN relay role (-nftmarket, default OFF).   │
  └──────────────────────────────────────────────────────────────────────────────────┘
        ▲ Browse() / FloorByToken()  (price-ascending; element 0 = floor)
        │
   LOCAL IN-NODE SERVICE LAYER  (derived cache — wipe-and-rebuildable, NEVER truth)
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  SQLite read-model (catalog): tokens / owners / transfers / collections / FTS5      │
  │     — driven post-commit from the ONE existing CZSLPIndexer (CValidationInterface).  │
  │  Offers/floor = RAM-joined at query time (NEVER persisted to SQLite).                │
  │  REST (GET-only, localhost-bound): /rest/nft/{tokens,owned,collections,search,       │
  │     activity,status,offers,mytokens}.  JSON contract == the wallet RPCs.             │
  └──────────────────────────────────────────────────────────────────────────────────┘
        ▲ JSON (or fall back to RPC: nft_browseoffers / zslp_* / nft_*)
        │
   THE WALLET  (Qt5 C++14 — the UX)
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │  Market home • Collection • Item • List • Buy (verify-on-receipt set-piece) •        │
  │  My Listings/Offers/Activity • Sweep • content-addressed image cache + verify badge. │
  │  Money decisions ALWAYS re-run live NftVerify — the cache is display-only.            │
  └──────────────────────────────────────────────────────────────────────────────────┘
```

**The split, stated once:** *the chain is truth, your node is your window, offers are signed
messages in the wind.* Three completeness guarantees, never conflated: **chain-derived** data
(ownership, transfers, sale history, catalog) is globally consistent and reproducible by anyone;
**offer-derived** data (live listings, floor) is "what your node has heard"; **settlement** is a
fresh cryptographic verify plus one atomic on-chain tx that never trusts any cache.

---

## 3. The Experience — Screens, Flows, and the Honesty Rules

### 3.0 The honesty rules (the substrate that lets the copy be quiet)

The UX red-team's central finding governs everything below: *a UI that constantly explains why it's
not as good as the thing the user already knows trains the user that it's not as good.* So the rule is
**fix the substrate so the bad moments become rare, then delete the hedging copy.** Five honesty
primitives exist, but they are used *sparingly* and only where load-bearing:

1. **"Chain" vs "seen" labeling** — solid lines / absolute counts for chain-derived truth; the "your
   node's view" caveat reserved for *genuinely divergent* surfaces (live floor on a thin item), **not**
   stamped on every number. Show **depth, not disclaimers**: "Floor 12 ZCL · 8 offers" reassures
   where "Floor 12 (your node's view)" corrodes. (Red-team UX #2.)
2. **"Your node checked this. No middleman."** — verify-on-receipt surfaced as confidence at buy time.
3. **"Someone got there first. Your money was not spent."** — the universal, calm race resolution.
4. **"You own the listing; share it your way."** — peer-to-peer propagation as control, not a gap.
5. **The on-chain collection chip** — cryptographic provenance, *never* dressed as an editorial blue check.

A single dismissible top strip on the Market tab carries the whole story in eight words:
**"Live offers, peer-to-peer. Buying settles on-chain."** That lets every screen below stay clean.

### 3.1 Entry, opt-in, and the four standing states

A top-level **Market** tab sits beside the existing NFT gallery (gallery = "what I own"; Market =
"what's for sale"). Because `-nftmarket` flips to **off-by-default** (legal posture, §6), first run
shows a calm opt-in card, framed as empowerment not deprivation:

> **See what's for sale** — Turn on the live market to discover listings shared across the network.
> [ Turn on Market ] · *You can help relay listings for others too — optional.*

Two checkboxes under "Options": **Discover listings** (join the gossip read side) and **Help relay
listings** (the opt-in relay role, off by default — *"Your node passes signed offers along. It never
holds anyone's NFT or money."*).

Four standing states every Market screen inherits: **Loading** ("Listening for offers…", soft pulse,
never a spinner-of-doom); **Empty** (framed as *early*, see the cold-start fix in 3.2); **Error**
("Can't reach your node." + Retry — distinct from empty); **Stale/indexing** (thin ribbon: *"Catalog
still indexing — prices are accurate, some images may be missing,"* never blocks browsing).

### 3.2 Market Home — and the cold-start fix (red-team UX #1, launch-blocking)

The cold-start death spiral is the existential risk: with `-nftmarket` off network-wide, a fresh
opted-in node's `getnftinv` returns nothing from stock peers, so Market is an empty room with a sign
reading "early" — indistinguishable from an abandoned project. Three fixes, the first a **launch
blocker**:

- **Seeded archive nodes baked into `chainparams.cpp`** (like DNS seeds). The instant a wallet opts
  in, it dials 3–5 well-known archive endpoints and pulls a near-complete live offer set in one round
  trip. *Without this the marketplace is non-functional at launch regardless of UI polish.* (See §6
  for why the archive role is deferred-but-its-seed-infrastructure-is-not — the launch archives are
  operated as known community infra; the general `-nftarchive` operator role is a later tier.)
- **"Recent sales" carries the first screen.** It is chain-derived (`zslp_listtransfers` + the sale
  detector, §5), deterministic, and **always populated once `-zslpindex` is synced** — independent of
  the gossip net existing. When offers are sparse it is the **hero**, not a footer.
- **Honest, hopeful empty copy that doesn't promise "shortly."** If after a real interval and N
  reachable relay-capable peers it is still empty, the copy stops implying imminent arrival and pivots
  to the always-populated catalog + "Be the first to list in this collection."

Home layout: **Floor finds** (lowest live offer per collection via `FloorByToken()`); **Lowest
prices right now** (`Browse()` ascending — poster, name, collection, big ZCL price, "N offers" depth);
**Collections with listings** (grouped by `group_id`); **Recent sales** (chain). We never fabricate a
global "24h volume" a single node can't truthfully compute; we show counts the node can stand behind.

### 3.3 Collection page

Header: name + (if `group_authorized`) a small **"On-chain collection"** chip — our honest,
*stronger-than-OpenSea* substitute for the blue check. **Critical red-team UX #8 constraint:** the
chip proves "minted as part of this collection," it does **not** prove "this is the famous one." A
scam clone is internally self-consistent and will earn the same chip. So the chip copy is precise and
silent about what it doesn't prove — **never** blue-check visual language. Identity trust is provided
separately by the **community allowlist** (§6, launch-blocking #2).

Stats strip: **Floor** (live, with depth) · **Items** (`CountCollectionMembers`, absolute) · **Listed**
(members with ≥1 live offer) · **Owners** (holders index, absolute). Chart: two clearly-labeled
series — **Sales** (solid, chain-truth) and **Floor seen** (dotted, your node's session view). Items
grid joins `GetCollectionMembers` to `Browse(tokenId)`: each card shows **price + [Buy]** or a quiet
**"Not listed."** Filters are honest about what ZSLP actually supports: **Status** (Buy now / All),
**Price range**, **Sort** (Price ↑, Recently listed, Recently sold). We do **not** fabricate a
"Background: Blue" trait facet we have no data for.

When a searched collection exists on-chain but has zero live offers (red-team UX #6, the
discovery dead-end): say exactly that and give an action — *"Zcats: 200 items on-chain · 0 currently
listed. [Watch for listings] [Make an offer]."* This separates "doesn't exist" from "not for sale
right now," the distinction the user needs to not give up.

### 3.4 Item page — the money screen

Two columns. **Left:** large poster (content-addressed cache, `verifyState` badge), **About** (name,
collection chip, `documentUrl` link), **Details** (the chain truths: Token ID = genesis txid, Type:
NFT, Standard: ZSLP — no caveats). **Right:** **History (on-chain)** provenance timeline
(`zslp_listtransfers`); **For sale now** (live asks price-ascending, each row: price · *expires in N
blocks* · [Buy]); **Price history** (sales line, chain); big primary **[ Buy for X ZCL ]** on the
lowest *fresh, re-verified* ask (see ordering below); secondary **[ Make an offer ]** = the
`nft_requestbuy` handshake (honestly "request to buy," not an instant bid).

The asks list self-heals: an expired/spent offer **softly greys to "No longer available"** and the
next ask slides up — the user never hits a dead button (`EvictStale` + per-tip eviction already prune
the pool). If owner-is-me (`zslp_listmytokens`), the Buy column becomes **[ Sell this ]**.

### 3.5 List-for-sale — and the "Listed!" lie fix (red-team UX #7)

Steps: **Pick** (owned NFTs via `zslp_listmytokens`) → **Price** (one field; "You'll receive X ZCL";
*"No marketplace fee — you keep the full price"*) → **Who can buy** (default Anyone; advanced =
specific buyer via `znftreq:`) → **Review** (*"This locks the NFT's coin so it can't be double-spent
while listed"* — honest about the outpoint lock) → **[ List it ]** (`nft_makeoffer`, self-validates
via `NftVerify`).

**The fix:** do **not** say "Listed!" until the offer has actually propagated. `nft_makeoffer` writes
only the *local* store; the offer reaches the net only via the publish seam. So split the states
honestly:

> **Signed ✓ — now publish to make it visible.**
> **[ Publish to the network ]** (primary, unmissable) · [ Copy offer ] · [ Save offer file ]

After publish, **confirm propagation, don't assume it**: "Sent to N relay peers" (counting INV
fan-out). If zero relay peers are reachable (the off-by-default network reality), say so and surface
the copy/QR path as the *working* fallback: *"No relay nodes reachable — share your listing directly
with a buyer."* The list flow detects "no relay peer" and offers one tap to connect to a seeded
archive that accepts publishes — otherwise the off-by-default posture silently breaks the *seller's*
path, not just the operator's.

### 3.6 Buy-now — verify-on-receipt as confidence, and the race fix (red-team UX #3)

1. **Confirm sheet:** poster, collection chip, **Price · Network fee ~Y · You pay ~Z**, [ Confirm ].
   Overshoot honesty: under ALL there is no change output, so overshoot becomes fee — shown plainly
   for large overshoot with the existing `acknowledge` checkbox.
2. **The verify set-piece** (runs `nft_verifyoffer` → `NftVerify` under `cs_main` *before* broadcast),
   shown as three ticks — **but worded to survive a subsequent race** (the fix): tick 1 does NOT
   claim the perishable "unsold" state, because the celebratory UI must not assert something a
   broadcast-time race can retract:
   > ✓ Verified genuine and conservation-correct
   > ✓ The seller's signature matches this exact price
   > ✓ You get the NFT, or your money back — never split
   > *Your node checked this. No middleman.*
3. **Broadcast** (`nft_takeoffer`: appends buyer funding with ZSLP-protected outpoints auto-excluded
   for anti-burn, merges seller vin[0], self-validates again — TOCTOU closed — `sendrawtransaction`).
4. **Done:** "It's yours!" → [View in gallery].

**Race handling, made rare then made calm:**
- **Re-verify liveness when the Buy sheet opens AND poll while it's up**, greying Confirm to "No
  longer available — see next" *before* the user commits emotionally, not after.
- **Order asks by fill-probability, not just price**: a fresh, just-re-verified 12-ZCL ask outranks a
  40-blocks-stale 8-ZCL ghost. Trade a tiny price optimum for a large reliability win.
- If the race is still lost: **"Someone got there first. Your money was not spent. [See other
  listings] [Try next-cheapest (X ZCL)]"** — and the retry candidate is **pre-verified live before it
  is offered** (a retry button that keeps failing is worse than none).

### 3.7 My Listings / My Offers / Activity

**My Listings** (`nft_listoffers`, local store, status live-recomputed): rows with status chips
**Live / Sold / Expired / Cancelled**; actions [Publish] [Update price = cancel+relist] [Cancel =
`nft_canceloffer`]; a Sold chip celebrates "Sold for X ZCL." **My Offers** = the honest
"Requests to buy" I've initiated (`nft_requestbuy` handshakes) — no fake "live bid." **Activity** =
the unified feed, honest about its two halves: on-chain events (mints/transfers/**sales**) from
`zslp_listtransfers`, plus *my* local market events. We do **not** fake a global everyone's-listings
feed (that half lives only in each node's RAM, exactly like OpenSea's off-chain half, but we say we
don't have it). Header: *"Your activity & on-chain sales."*

### 3.8 Sweep / aggregate buy — N fills as one flow, honest cost up front (red-team UX #4)

The locked-architecture truth: ANYONECANPAY partials **cannot be merged** — buying N offers is
structurally **N settlement txs**. The fix is to put the real cost and the partial-fill reality in
the number the user anchors on, not in the confirm:

- Slider quotes a **range including fees**: *"Buy 10 cheapest ≈ 95 ZCL + ~3 ZCL fees (10 separate
  sends). You'll likely get 7–10 — some of the cheapest may already be taken."* A sweep that delivers
  7/10 against a "7–10" promise feels like success; against a "10" promise it feels like failure.
- **Verify-liveness the swept set before showing the total**, so the cheapest ghosts are excluded
  from the estimate up front ("≈100 for 9 verified-live" beats "≈95 for 10" where one is a ghost).
- Progress is one unified panel, N steps, each a real `nft_takeoffer` with per-row state (queued →
  sending → bought / *someone got there first — skipped, not charged*), **[Stop after current]**, and
  an end rollup: *"Sweep done: 4 of 5 bought. You weren't charged for the misses. [Try next-cheapest]
  [View my new items]."*

### 3.9 Media in the grid — speed without lying (red-team UX #5)

Content-addressing is a security win but its failure mode is a grid of gray boxes. Resolution:
**fast unverified thumbnails in the grid, strict verification at the item page and before Buy.**
Archives may serve fast previews (subtle "preview" treatment, never a scary "UNVERIFIED" stamp);
the full image is hash-verified against `documentHash` on the item page and *always* before purchase.
Cache verified bytes content-addressed (instant second view). Time-box fetches and fall to a fast
skeleton/placeholder rather than a spinner that hangs forever on a dead source. The mint flow
**defaults a "pin my image durably" step** — an unpinned mint is a future gray box. (Full media design: §5.)

---

## 4. The In-Node Service Layer (SQLite read-model + DAO + REST + FTS5)

This rebuilds three of OpenSea's four centralized backends (indexer DB, search, order-book
read-model) as a **derived, wipe-and-rebuildable projection inside the user's own node**, served
localhost-only in the exact `TokenToJSON` shape. The fourth — the image CDN — is **deliberately NOT
rebuilt at the node** (§5; this resolves a contradiction between the design tracks, see §5/§6). This
is the build-out of `doc/nft/MARKET_SERVICE_DESIGN.md`, reconciled forward: its catalog half (P0–P4)
is endorsed unchanged; its deferred offers half is now buildable because the offerpool exists.

### 4.1 CQRS spine

- **Write model = sources of truth, untouched.** leveldb `CZSLPStore` (the `'u'`+txid+vout →
  `CZSLPTokenUtxo` map is ownership truth) and the RAM `g_offerPool` (offer/price truth). Every
  Create/Update/Delete is a real chain tx or a real gossip action through existing validated actors.
- **Read model = this layer.** A denormalized SQLite catalog updated strictly as a *consequence* of
  confirmed `ConnectBlock`/`DisconnectBlock`, plus the live RAM offerpool joined at query time. Reads
  are SQLite SELECTs + a RAM `Browse()`, served over REST.

### 4.2 Which query powers which surface

| UI surface | Data source | Route / call |
|---|---|---|
| Discovery grid, newest, by-collection | `tokens` + height/name/collection indexes, keyset | `GET /rest/nft/tokens?sort=&group=&nftonly=1` |
| Item metadata (image hint + hash) | `tokens` point-lookup | `GET /rest/nft/tokens/<id>` |
| Item provenance / price history | `transfers` + `idx_transfers_token` | `GET /rest/nft/tokens/<id>/history` |
| **Portfolio ("everything X owns")** | `owners`, **address-leading** index | `GET /rest/nft/owned/<address>` |
| Collection header + `member_count` | `collections` | `GET /rest/nft/collections/<gid>` |
| Collection item grid (authorized only) | `idx_tokens_collection` | `GET /rest/nft/collections/<gid>/members` |
| Search box | `tokens_fts` (FTS5; optional flag) | `GET /rest/nft/search?q=` |
| Honest "still indexing" | `meta` cursor vs chain tip | `GET /rest/nft/status` |
| Global activity feed | `transfers` + `idx_transfers_global` (height,seq DESC) | `GET /rest/nft/activity` |
| **Listings / best-ask / floor / depth** | **`g_offerPool.Browse()`/`FloorByToken()`** + catalog join | `GET /rest/nft/offers` |
| "My NFTs" (live wallet, never cached) | pass-through to `zslp_listmytokens` | `GET /rest/nft/mytokens` |

The two structurally-hard queries justify the whole layer: **"everything address X owns"** (leveldb's
`GetTokensForAddress` scans the entire `'b'` keyspace because address is the *trailing* key
component; the address-*leading* SQLite index is the fix) and **prefix/substring search** (impossible
on leveldb's exact-prefix iteration; FTS5 is the single-node Elasticsearch analog). `/rest/nft/offers`
params map `COfferPoolFilter` directly: `tokenid`, `group`, `maxprice`, `minexpiry`, `info=1`
(floor/depth projection), `from`/`count`.

### 4.3 How the projection stays fresh — one observer, one deterministic primitive

Driven from the **one existing** `CZSLPIndexer` (a pure `CValidationInterface`) — never a second
observer. The SQLite writer is invoked *inside* `ConnectBlock`/`DisconnectBlock`, **after** leveldb
commits, under the same `cs_main` hold, eliminating the two-observer reorg-divergence bug class. The
same `-zslpindex` gate covers both.

No store API exposes "what `(txid,vout)` did this block change," and **we add none** (that hard
constraint keeps it consensus-inert). Instead the block is in scope at both hook sites, so the writer
(1) **re-parses** `block.vtx[1..]` with the authoritative `CZSLPIndexer::ParseTx` + prevout
collection to *identify* created/consumed outpoints, then (2) **point-reads committed leveldb**
(`GetUtxo`/`GetToken`) for ground truth. Connect: created hit → `UpsertOwner` + `AppendTransfer`;
parsed message → `UpsertToken`; consumed prevout → `DeleteOwner`; newly-authorized child →
`AddCollectionMember`; all + `SetCursor` in one transaction. Disconnect: leveldb already reverted via
its `'r'` log; re-parse the disconnecting block, delete created owners, and `GetUtxo`-restore owners
that connect had deleted (the subtle case), `RecomputeCollection` for affected groups. The rows are a
pure function of (block data + committed leveldb).

### 4.4 DAO

`GetDataDir()/zslp/nftcache.sqlite`, `PRAGMA user_version = NFTCACHE_SCHEMA_VERSION` (a bump →
drop+rebuild). Two RAII primitives: `NftCacheDb` (owns `sqlite3*`, single WAL writer + per-worker
read-only connections) and `Stmt` (owns a prepared `sqlite3_stmt*`, move-only, cached). Flat
free-function repository over POD rows. **All SQL parameterized via `sqlite3_bind_*` — never
concatenation; sort columns through an allowlist enum; FTS `MATCH` bound not interpolated** →
injection-proof by construction. Single writer = the `cs_main`-serialized indexer thread. Per-worker
readers each carry a `LIMIT` + `sqlite3_progress_handler` budget so no pathological query pins a
libevent worker. SQLite arrives via a vendored static `depends/packages/sqlite.mk` (system
`-lsqlite3` would break the glibc-2.31 portable-static floor), compiled hardened:
`SQLITE_OMIT_LOAD_EXTENSION`, `THREADSAFE=1`, `DEFAULT_FILE_PERMISSIONS=0600`, FTS5 post-MVP.

### 4.5 Wipe-and-rebuild safety (six release-gating invariants)

- **INV-1: SQLite is NEVER truth.** Delete `nftcache.sqlite{,-wal,-shm}` at any instant → zero
  ledger/consensus loss; rebuild from chain + offerpool on next start. (Regtest `rm`s mid-run and
  asserts identical results after rebuild.)
- **INV-2: zero consensus impact.** No file touches `consensus/`, `pow.cpp`,
  `CheckBlock`/`ConnectBlock`/`CheckInputs`/script-verify; no authoritative-store schema/index/write
  is added (the re-parse primitive in 4.3 is engineered precisely to avoid one).
- **INV-3: no on-chain bytes, no file-smuggling.** GET-only; stores only the 32-byte `documentHash`
  + off-chain URL already in the ledger; never fetches/proxies images; never serves `offerHex`.
- **INV-4: money never trusts a row** — a fresh `NftVerify` precedes any buy.
- **INV-5: CRUD = real actions** (mint/transfer/offer through validated paths; REST never writes).
- **INV-6: the writer is totally exception-isolated.** `ChainTip(...)` is emitted *bare* (no
  try/catch) after the tip already advanced; a SQLite throw (ENOSPC on `-wal`, read-only fs, corrupt
  page) would destabilize the node post-tip-advance. So the entire writer body is wrapped: swallow +
  log, set the `degraded` flag (which clears the serve-gate so REST honestly reports "still indexing"
  instead of serving stale rows), and defer to the standing wipe+rebuild.

**Startup reconciliation** (closes the leveldb@N / SQLite@N-1 crash window — idempotence means
`ConnectBlock(N)` is never re-delivered, so "self-heals on next block" is *false*): at open, read both
cursors; **on any mismatch or `degraded` → full wipe+rebuild** (the bespoke gap-replay path is deleted
in favor of the already-tested rebuild). **Rebuild** is a per-block chain replay in `cs_main`-yielding
128-block chunks, sequenced strictly after leveldb `OpenStore` and not begun until leveldb
`IsSynced()`; FTS index deferred to the end. **Honest cost:** the first `-nftcache` run is a *second*
full-chain walk after the leveldb ZSLP rebuild — bounded but real; the serve-gate keeps the gallery
honestly *unavailable* (not misleadingly-empty) during it.

### 4.6 REST surface and the security gate (red-team ARCH V1 — must-do, gating)

Routes register as prefix handlers into the **existing shared libevent HTTP server** (the one serving
JSON-RPC and `/rest`) via a `StartNFTREST()`/`StopNFTREST()` pair. **Ground-truth danger, confirmed
in code:** `InitHTTPServer` (`src/httpserver.cpp:324–345`) binds that shared server to **`0.0.0.0`
and `::` whenever `-rpcallowip` is set** (a common remote-wallet config), and `/rest` is
unauthenticated. So `/rest/nft/owned/<address>` — a deanonymizing map of which NFTs an address holds —
would be exposed to anyone reachable on the RPC port. The design's prior "Host-header check" is
**insufficient**: no Host-checking exists today, and a Host check defeats browser DNS-rebinding but
**not** a direct attacker who simply sends `Host: localhost` to the real IP. The real defense is the
unspoofable peer socket address:

- **Reject any non-loopback *peer address*** (via `evhttp_connection_get_peer` on the `HTTPRequest`),
  not the Host header, unless `-nftrestpublic` is explicitly set.
- **Refuse to register** the privacy-sensitive routes (`/owned/`, `/mytokens`, `/offers`) at all when
  the shared server is non-loopback-bound and `-nftrestpublic` is absent — fail fast at init *and*
  enforce per-route.
- Keep the Host-header check **additionally** as the anti-rebinding layer, never as the primary gate.
- `-nftrest` defaults **off**.

Per-handler preamble (framework enforces none of it): **method check (reject non-GET** — the dispatch
treats GET/POST/HEAD identically, so an ignored 32 MiB POST is a DoS amplifier *and* contract
violation); the peer-IP gate above; `CheckWarmup()`; strict param validation (64-hex ids,
base58check addresses, integer `from`/`count` clamped to `[1,500]`, keyset cursor preferred over deep
`OFFSET`); the serve-gate (INV-6/4.5); parameterized SELECT → serialize to the **exact `TokenToJSON`
shape** (one-contract guarantee with the RPCs) → `application/json`. Most-specific prefix registered
first so `/tokens/<id>/history` isn't swallowed by `/tokens`.

### 4.7 The offers route: RAM-joined, never persisted

This is the load-bearing CQRS decision. Offers are **not** projected into SQLite, for three concrete,
code-grounded reasons: (1) **liveness flips every block** (`pcoinsTip->GetCoins(nftOp) &&
IsAvailable` recomputed at tip) — persisting would duplicate `EvictStale` and risk advertising a
"live" listing the pool already evicted; (2) the pool is **hard-capped and ephemeral by design**
(5000 / 32 MiB / 16-per-token / 8 KiB, reject-when-full so a stale flood can't displace honest
offers; re-floods on restart via `getnftinv`) — durability buys nothing; (3) **money never trusts a
cached row** (INV-4). So the offers route is a thin handler over `Browse(filter)` / `FloorByToken()`
with each entry's `tokenId` joined to a `tokens` point-lookup; sorted price-ascending via the entry's
cached scalars (element 0 = floor).

**Factual correction the build must inherit (red-team ARCH):** "offerHex is never stored" is **false
for the RAM pool** — `COfferPoolEntry` stores the **full `CNftOfferBlob`** (confirmed `offerpool.h:60`,
"the ONLY large field"), and `offerHex` is the seller's partial tx the buyer *needs* to complete the
trade. The correct, narrow statement: **`offerHex` is never stored in SQLite and never served over
REST** — the GET layer echoes only derived truth fields. The RAM pool legitimately holds it; do not
strip it (that would break buying).

---

## 5. Decentralized Discovery, Media, and Settlement-Anchored History

### 5.1 Discovery — sampling the network's gossip state (honest foundation)

The offerpool + 5 gossip commands are a complete **epidemic broadcast** substrate: a new offer floods
O(log N) hops; `getnftinv` digests up to 1000 hashes; `Browse()` returns price-ascending. But the
pool is **soft state** — RAM-only, capped, evicting. So discovery is not "query the order book"; it
is "sample the network's current gossip state," and the design is honest about that.

**Cold start** (already mostly plumbed): on each handshake the node sends `getnftinv`, receives up to
1000 hashes, then `getnftoffer`s the ones it lacks (rate-limited), each pulled blob running the full
inbound verify path (body-cap → dedupe → `NftVerify` under `cs_main` → `Insert` re-checking id==hash +
caps → re-flood). Across K peers this samples K slices of network RAM; the union converges fast.

**Two connective gaps to build:**
- **Read RPCs (build first):** `nft_browseoffers` (filter tokenId/maxPrice/minExpiry, keyset,
  price-ascending) and `nft_offerpoolinfo` (count/bytes/per-token floor via `FloorByToken()`). The
  backends exist and are tested; only the RPC-table entries and the GUI Browse surface are absent.
  Without these the network has an order book no client can read. The REST offers route (4.2) and
  these RPCs are siblings reading the same backend and **must share one serializer**.
- **Publish seam:** `nft_publishoffer(blob)` (or an opt-in flag on `nft_makeoffer`). Today
  `nft_makeoffer` writes only the *local* store; an offer reaches the net only if a peer happens to
  pull it — a dead end for a seller. **Red-team ARCH V3 (must-do):** publish must route through one
  shared **`AcceptAndRelayOffer(blob)`** used by *both* the P2P `NFTOFFER` handler and the RPC — the
  identical `NftVerify` + `Insert` (id==hash, caps, body-bound) path, **no trusted-local shortcut**,
  with the per-source **rate limit inside it** (`RelayNftOfferInv` fans an INV to *all* peers, so an
  unrated `nft_publishoffer` loop is a personal flood cannon). Gated by `-nftmarket` like everything
  else: a node that hasn't opted into the relay role cannot inject — it can only hand the seller a
  blob to share out-of-band (a *feature*: the most private, most censorship-resistant sale path).

**Honest limits** (state plainly, don't pretend away): no completeness guarantee (only "every listing
held by a node you can reach"); eclipse/partition can *hide* offers but — because of `NftVerify` —
**can never forge a buyable one** (forged → `structurallyInvalid` → banned; stale → fails the
live-UTXO check at take time); global visibility is eventually-consistent (seconds, occasionally
never); the RAM caps are a deliberate DoS tradeoff, leaning on seeded archives for scale.

### 5.2 Media — content-addressed images vs. the on-chain hash

On-chain we have exactly the right thing: `documentHash[32]` = SHA-256 of the image, plus an optional
`documentUrl`. The chain commits to *which* image, never *the* image. Verification is total and
source-independent: **fetch bytes from anywhere, SHA-256, compare to `documentHash`. Match =
authentic, full stop** — strictly *better* than OpenSea, where you trust `i.seadn.io` to faithfully
represent the original. The GUI already models this (`NFTItem.verifyState` 0/1/2, async
`onImageReady`, `zslp_verifyfile`/`zslp_filefingerprint`).

Tiered, content-addressed retrieval (acceptance always hash-gated):
1. **Wallet content-addressed cache**, keyed by `documentHash` (auto-dedup; the minter's wallet is the
   canonical first source). The mint flow **defaults a durable-pin step** (an unpinned mint is a
   future gray box); optionally carry small assets inline via the existing `nftdatachannel` (ZDC1,
   40 KB cap) on gift/transfer.
2. **`documentUrl` as a hint, never a trust anchor.** Try it, hash the result, display only on match;
   a rotted or hostile URL can never poison the gallery (wrong bytes → placeholder, never the wrong
   image). If `documentHash` is standardized as an IPFS-compatible multihash, the CID *is* the
   on-chain commitment and any IPFS gateway becomes a free, verifiable CDN.
3. **Grid previews fast, full image verified at purchase** (red-team UX #5): previews may be served
   unverified for grid speed (subtle "preview" treatment); the full image is hash-verified on the item
   page and *always* before Buy — a pretty thumbnail never stands in for verification at the moment
   money moves.

**RESOLVED CONFLICT (red-team ARCH V2.1):** the discovery track proposed an `-nftarchivemedia`
node role (a content-addressed image blob store served from the node). That **contradicts** the media
track's own correct principle that proxying images is "the one centralized, content-liability surface
the locked architecture forbids," and re-introduces an arbitrary-byte host at the operator. **DECISION:
`-nftarchivemedia` is CUT.** Node operators are never in the business of storing/serving others' image
bytes. Media availability is solved by the minter's cache + content-addressed `documentUrl` (IPFS) +
third-party IPFS pinning services *outside* the node. (Optional far-future P2P media gossip
`getnftmedia/nftmedia`, content-addressed and verified, is mentioned only for completeness and is not
in scope.)

**Honest limits:** availability is voluntary — the hash lets you *recognize* the right image forever
but guarantees nothing about *finding* it; no default server-side resize pipeline (you must fetch full
bytes to verify); SVG/animation sanitization becomes a client responsibility; cold first-view latency
is worse than a warm CDN edge (cache makes the second view instant).

### 5.3 History & floor — settlement-anchored, zero new on-chain bytes

**Provenance is free and total:** every NFT ownership change is a SEND already indexed
(`'x'`+tokenId+height transfer log, `'u'` ownership, exposed via `zslp_listtransfers` /
`GetHoldersForToken`). The full chain of custody is a deterministic, reorg-exact projection any node
recomputes identically — strictly better than OpenSea's trust-the-DB reconstruction.

**The hard part — distinguishing a sale from an ordinary transfer** (settlements are markerless by
mandate). Our settlement has a precise structural fingerprint, so a read-side **sale detector** in the
SQLite projection flags a SEND as a sale when: (1) the token-bearing `vin[0]` carries an
`ANYONECANPAY` sighash; (2) exactly one non-dust, non-token-change ZCL output flows to a party that is
not the token's previous owner (that output's value = the "price"); (3) token recipient ≠ value
recipient. This records a derived `(tokenId, height, priceZat, seller, buyer)` event with **zero new
on-chain bytes** — pure pattern recognition over already-indexed data.

**Red-team ARCH V4 (gating — keep the wall absolute):** the detector is consensus-inert (pure
read-side), but the ANYONECANPAY-with-payout shape is **not unique to our marketplace**, so an
attacker can broadcast a self-constructed tx matching the template with an arbitrary `vout[2]` value
to **mint a fake price-history print** for the cost of fees. Therefore the detector ships **only** as
an *advisory* `is_sale`/`sale_price` annotation in the read-model, the GUI labels the derived line
**"Sales (on-chain, detected)"**, and **the floor shown for buying is ALWAYS the live-offer floor (a
real, takeable price), never the detected-sale history.** Detected-sale prices never drive a default
sort or a headline "floor" number. The UX "Sales (solid) vs Floor seen (dotted)" wall stays absolute.

**Wash-trading honesty:** the structural detector cleanly separates settlements from gifts/self-moves
(kills the laziest fake-floor), but ANYONECANPAY self-trade (Alice→Alice via two addresses) is real
on-chain value movement, structurally indistinguishable from an arm's-length trade — *OpenSea has the
identical problem and only "solves" it with private centralized heuristics.* We surface **multiple
honest aggregates** (last sale, median over window, **count of distinct counterparties**, live-offer
floor) rather than one gameable number, and **flag wash-suspect sales next to the floor** (red-team
UX #8: same-funding-ancestor / repeated pair / round-trip-within-N-blocks). Our live-offer floor is
*more* wash-resistant than OpenSea's off-chain fake bids, because a fake-cheap offer is genuinely
**takeable** by anyone — washing the offer-side floor risks actually selling at that price.

---

## 6. Legal & Operational Posture

The architecture's central conviction — *a stock node hosts no order book; relaying offers is a
deliberate, separate role* — becomes concrete here.

**The must-do default flip (red-team both, highest priority, one line).** Confirmed in code:
`fNftMarket = true` at `src/main.cpp:84` and `GetBoolArg("-nftmarket", true)` at `src/init.cpp:3299`
mean a **stock node currently relays offers** — a live violation of the locked posture. **Flip to
`false`.** The gate already exists: `NftMarketActive() = fNftMarket && store != NULL` no-ops *every*
gossip handler (GETNFTINV/NFTINV/GETNFTOFFER/NFTOFFER/NFTABORT) the instant the flag is false, so the
one-line flip is sufficient and clean — a stock node validating the chain neither stores, serves, nor
relays a single offer, and provably does not touch the order-book code paths. **Ship this regardless
of everything else.**

**Three escalating, deliberately-opt-in roles:**
1. **Stock node (default).** Validates consensus; optionally runs `-zslpindex` (read-only *analysis of
   public records* — ownership/provenance/derived sale history; stores no offers, serves no order
   book). Hosts nothing tradeable. The legally cleanest posture, and now the default.
2. **Relay node (`-nftmarket`, opt-in).** Joins the gossip net: holds the RAM offerpool, relays/serves
   *verified, self-describing, cryptographically-bound* offers (`NftVerify`), stores **no media**
   (offerpool holds no decoded images), and **never holds anyone's asset or funds**. Posture: "I relay
   signed messages," analogous to relaying transactions — not "I broker trades."
3. **Archive node (`-nftarchive`, opt-in superset) — DEFERRED (red-team ARCH V2.2).** Durable disk
   store of verified offers + uncapped `getnftinv`. **Not in the MVP:** it re-opens disk-exhaustion
   flooding (the RAM cap exists precisely as anti-flood; "remove the cap onto disk" undoes that), and
   it carries the most legal/abuse surface for the least-proven benefit. The honest shippable baseline
   is the RAM-gossip floor ("if zero archives exist, discovery degrades to RAM"). When archive does
   ship, it requires its own **disk cap + per-peer admission rate-limit + dead-vin eviction**.
   **`-nftarchivemedia` is CUT entirely** (§5.2). *Caveat:* the **launch seed archives** baked into
   `chainparams.cpp` (the cold-start fix, §3.2) are operated as known community infrastructure to
   bootstrap discovery; the general operator-facing `-nftarchive` role is the deferred tier — these
   are not the same decision.

**Two non-node launch-blocking artifacts (red-team UX):**
- **Seeded archive endpoints in `chainparams.cpp`** (§3.2) — without them the marketplace is empty at
  launch regardless of UI.
- **A shipped, signed community collection-allowlist** (like checkpoints) — without it the marketplace
  fills with chip-bearing scam clones, because `group_authorized` proves membership, not editorial
  identity. The allowlist is a first-class artifact: an in-wallet, updatable, source-visible list of
  known-genuine collection genesis-txids, labeled *"community-curated, not a guarantee."* Pair the
  buy-time "Your node checked this" with an identity line when a collection is **not** on the list:
  *"This collection is not on your known-collections list — double-check it's the one you want,"* so
  settlement-confidence never bleeds into false identity-confidence.

**Why the posture is defensible (not legal advice):** no custody ever (settlement is one atomic
buyer-broadcast tx; asset and money only ever exist in the two parties' own UTXOs); no matching, no
operator fee, no operator order-execution; relays store no media; the baseline participant is a pure
validator and the market roles are explicit, separable, and documented. **Honest caveat:** "I only
relay signed messages" is a posture, not a guaranteed shield; an archive operator who makes a real
market discoverable takes on more exposure than a stock validator. The design *minimizes and
clarifies* the role so each operator chooses informed.

---

## 7. Honest Tradeoffs vs. OpenSea

| Capability | OpenSea | Us | Gap | Mitigation |
|---|---|---|---|---|
| **Final settlement** | Atomic on-chain (Seaport) | Atomic on-chain, custody-free, independently verifiable | **None / better** | — |
| **Ownership & transfer history** | Indexer DB you trust | Deterministic chain projection, reorg-exact, recomputable by anyone | **Better** | — |
| **Price *history*** | Private reconstruction | Settlement-anchored detector, zero new on-chain bytes, globally consistent | **Better, but false-positive prints possible** | Advisory-only label; never drives floor/sort (§5.3 V4) |
| **Media authenticity** | Trust `i.seadn.io` | Every byte hash-verified vs on-chain `documentHash` | **Better** | — |
| **Listing/offer creation** | Gasless DB write, instant-global | Free+instant *locally* (a signature); global = gossip-eventual | **No instant global visibility** | Publish seam + propagation confirm; "share it your way" fallback (§3.5) |
| **Discovery (live offers)** | Complete order book | Gossip sample of reachable nodes' RAM | **No completeness; eclipse can hide** | Seeded archives (launch-blocking); eclipse can hide but never forge a buyable offer |
| **Floor (live)** | Globally consistent | Per-viewer (your node's view) | **Divergent on thin items** | Multi-archive convergence makes divergence rare → drop per-number hedge; show depth (§3.0, RT-UX #2) |
| **Media *availability*** | Pinned + transcoded, always there | Voluntary hosting; recognizable forever, findable only if hosted | **Worse** | Minter durable-pin default + IPFS content-addressing; no node media host (CUT `-nftarchivemedia`) |
| **Grid speed** | Pre-rendered WebP/AVIF CDN | Fetch+verify; cold first view slower | **Worse first view** | Fast unverified previews in grid; verify at item/buy; content-addressed cache (§3.9) |
| **Search** | Always-on global Elasticsearch | FTS5, single-node | **Worse scale; build-flag risk** | FTS5 default-on for any release exposing search; hide box if absent — never a silent-dead box (RT-UX #6) |
| **Sweep / bulk buy** | One ~atomic tx, near-certain fill | Structurally N txs, partial-fill expected | **N fees, partial fills** | Range quote incl. fees + verify-live before total; per-row progress, "not charged for misses" (§3.8) |
| **Buy reliability (the cheap click)** | Visible listing is fillable | Cheapest offers most likely stale/sniped | **Best clicks fail most** | Order by fill-probability; re-verify on sheet-open + poll; ticks don't claim "unsold" (§3.6, RT-UX #3) |
| **Editorial "verified" blue check** | Central curation tells you "the real one" | `group_authorized` = membership, NOT identity | **Cannot self-provide identity trust** | Community allowlist (launch-blocking); chip never styled as a blue check; wash-flag at floor (§6, RT-UX #8) |
| **Wash-trade defense** | Private heuristics | Structural sale/gift split + distinct-counterparty aggregates + suspect flags | **Equal — unsolved everywhere** | Surface multiple aggregates not one number; live-offer floor is *more* wash-resistant (takeable) |
| **Watchlists / notifications / push / accounts** | Server + account features | Out of scope (per-user state belongs in GUI settings) | **Worse / absent** | Local GUI watchlist; poll-bounded updates; no real-time push |
| **Marketplace fee** | 2.5%+ | **None** | **Better** | "No marketplace fee — you keep the full price" |
| **Custody / middleman** | Platform-mediated | None — true P2P | **Better** | — |

---

## 8. Phased Build Plan

Reconciles with the existing marketplace **P1–P3** (built: offer-blob hardening, RAM offerpool, the 5
gossip commands, `NftVerify`) and the SQLite service layer (`MARKET_SERVICE_DESIGN.md`). Dependency
order; each phase **shippable, testable, NON-consensus, master-held**. Phases 0–3 are the daemon
substrate the wallet UX depends on; the existing GUI already calls the make/verify/take/cancel RPCs,
so the wallet phases layer cleanly on top.

> **Numbering note:** P1–P3 are *done* (recon). This plan continues at **P4** and threads the
> red-team must-dos into the earliest phases. "P5" in `MARKET_SERVICE_DESIGN.md` (the deferred offers
> route) maps to **P6** here.

**P4 — Safety baseline (smallest, highest-leverage; ship first, independently).**
- Flip `-nftmarket` default to `false` (`src/main.cpp:84`, `src/init.cpp:3299`) — the live posture
  violation. *Test:* stock node provably no-ops every gossip handler; relay node unchanged when
  explicitly enabled.
- *(Done in parallel, no dependency on the rest.)* This phase is the one-line fix that makes the
  network's baseline participant a pure validator.

**P5 — Read & publish the order book (the connective tissue).**
- `nft_browseoffers` + `nft_offerpoolinfo` RPCs over `Browse()`/`FloorByToken()` (the backends exist).
- `nft_publishoffer` via the **single shared `AcceptAndRelayOffer(blob)`** (RT-ARCH V3): one verify +
  cap + rate-limit path used by both the P2P handler and the RPC; no trusted-local shortcut.
- *Test:* two-regtest-node gossip — publish on A, browse on B; cap/rate-limit/anti-grind honored;
  forged blob → `structurallyInvalid` ban; stale blob → no-ban + take-time liveness fail.

**P6 — SQLite catalog read-model (the indexer DB), catalog half first.**
- `depends/packages/sqlite.mk` (vendored static, hardened flags); `src/nft/nftcache.{h,cpp}` (DAO +
  schema + RAII); the writer hooked inside `CZSLPIndexer` ConnectBlock/DisconnectBlock with the
  re-parse + point-read primitive (4.3); INV-1..INV-6 incl. exception isolation; startup
  reconciliation → wipe+rebuild; rebuild-on-`IsSynced`.
- *Test:* `rm` the sqlite triple mid-run → identical after rebuild (INV-1); reorg parity vs leveldb;
  forced SQLite throw → node stays up, `degraded` set, REST honestly "still indexing" (INV-6);
  address-leading owner query matches leveldb truth.

**P7 — REST surface (the local OpenSea API), with the security gate built in from line one.**
- `src/nft/nftrest.cpp` + `StartNFTREST`/`StopNFTREST`; catalog routes
  (`/tokens`,`/tokens/<id>`,`/history`,`/owned`,`/collections`,`/search`,`/status`,`/activity`,`/mytokens`).
- **RT-ARCH V1 gate:** peer-IP loopback enforcement (not Host header) + per-route refusal on a
  non-loopback-bound shared server without `-nftrestpublic`; non-GET rejection; param validation;
  serve-gate; `-nftrest` default off. FTS5 default-on for any build exposing `/search` (RT-UX #6).
- *Test:* attempt `/owned/<addr>` from a non-loopback peer on an `-rpcallowip` node → refused;
  oversize POST → rejected not buffered; JSON byte-identical to the matching RPC; `/search` returns
  results or the route is absent (never a silent-dead box).

**P8 — The offers route + sale detector (the `MARKET_SERVICE_DESIGN.md` deferred half).**
- `/rest/nft/offers` as a thin RAM-join over `Browse()`/`FloorByToken()` (sharing P5's serializer);
  **never persisted, never serves `offerHex`** (4.7). The sale detector as an **advisory**
  `is_sale`/`sale_price` annotation only (RT-ARCH V4) feeding `/history` and "Recent sales," never the
  buy-floor.
- *Test:* offers route reflects pool eviction within a block; floor == live-offer floor never
  detected-sale; a self-constructed template-matching tx is annotated advisory, never drives floor/sort.

**P9 — Wallet: Browse, Item, Buy with the race fixes (the UX core).**
- Market home (Recent-sales-as-hero when offers sparse, RT-UX #1), Collection, Item, Buy. Re-verify on
  sheet-open + poll; fill-probability ordering; ticks reworded to not claim "unsold" (RT-UX #3);
  content-addressed cache with fast previews + verify-at-buy (RT-UX #5).
- *Test:* offscreen headless E2E against a regtest offer daemon (per the GUI-headless-E2E harness):
  race-loss shows "your money was not spent"; stale next-cheapest is pre-verified before offered.

**P10 — Wallet: List/Publish, My Listings/Offers/Activity, Sweep.**
- List flow split "Signed ✓ / Publish" with propagation confirm + no-relay fallback (RT-UX #7); Sweep
  with range-quote-incl-fees + verify-live-before-total + partial-fill rollup (RT-UX #4).
- *Test:* E2E sweep with injected ghosts → partial-fill rollup, no overcharge; publish with zero relay
  peers → honest fallback, never a false "Listed!".

**P11 — Trust & identity launch artifacts.**
- Shipped signed **community collection-allowlist** + seeded **archive endpoints** in chainparams
  (both launch-blocking, RT-UX #1/#8); wash-suspect flag surfaced at the floor; chip copy audited to
  never read as a blue check.
- *Test:* unknown collection → identity-warning line beside the verify ticks; allowlist update flow;
  cold fresh wallet pulls a near-complete set from a seed archive in one round trip.

**Deferred (post-MVP, only after the base loop is measured):** `-nftarchive` operator role with disk
cap + admission rate-limit + dead-vin eviction; optional transient in-RAM `offers` sort table (only if
sorting ≤5000 entries ever proves slow — it won't); P2P media gossip. **Permanently CUT:**
`-nftarchivemedia` (content-liability surface). **Out of scope:** server-side notifications/push,
accounts, editorial verification (substituted by the allowlist), trait facets (no ZSLP trait schema).

---

## 9. What Makes It Feel Premium (the delight list)

- **One-tap buy that visibly verifies itself.** "Your node checked this. No middleman." — the
  decentralization value proposition delivered at the moment of maximum trust-need, with three ticks
  mapping exactly to what `NftVerify` proves.
- **No marketplace fee, ever.** "You set the price, you keep it." A structural win OpenSea can't match.
- **Atomic-or-refund, stated as a feeling, not a footnote.** "You get the NFT, or your money back —
  never split."
- **Content-verified images.** A subtle "content-verified" badge is a claim OpenSea never makes — the
  bytes are provably exactly what the minter committed to.
- **On-chain provenance that anyone can recompute.** The history timeline is cryptographic truth, not
  a vendor's DB — a quiet flex for collectors who care.
- **Self-healing listings.** Dead offers grey out and the next ask slides up; the user never taps a
  dead button. The race, when it happens, is a calm "someone got there first," never a stack trace.
- **Floor with depth.** "Floor 12 ZCL · 8 offers" reads as a real market — quantity reassures more
  than any disclaimer.
- **Sweep that's honest and still smooth.** A range quote that *includes* the partial-fill reality, a
  unified progress panel, and "you weren't charged for the misses" — so 7-of-10 feels like a win.
- **Skeleton grids, instant second views.** Content-addressed caching makes return scrolls instant;
  fast previews keep the first scroll alive.
- **Privacy by default.** REST is loopback-only; relaying is opt-in; the offer you share out-of-band
  is the most private sale on any chain.
- **A marketplace that rarely apologizes.** The deepest delight is the one the user never notices: the
  substrate (seeded archives, fill-probability ordering, propagation confirmation, default-on search,
  a community allowlist) is good enough that the honesty becomes a quiet footnote instead of the
  product's dominant voice.
