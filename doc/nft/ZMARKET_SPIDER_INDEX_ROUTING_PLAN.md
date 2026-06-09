# ZMarket Spider, Routing, and Local Offer Index Plan

Status: design and safe implementation scaffold. Non-consensus. Default off.
Scope: opt-in marketplace discovery for ZSLP NFTs using signed off-chain
messages, local indexing, and P2P/Tor routing. Settlement remains the existing
`ZNFTOFFER1` atomic trade flow in `src/rpc/nftoffer.cpp`.

Hard implementation requirement: all marketplace spidering, routing, indexing,
validation-cache, and hot-path data-structure code lives in C modules under
`src/zmarket/`. The daemon and GUI may use thin C++/Qt bridges for lifecycle,
RPC, wallet signing, chain lookups, P2P message attachment, and UI rendering,
but they must not own the marketplace engine state.

This document deliberately keeps four boundaries hard:

- No central party or required hosted order book.
- No NFT files on-chain. The chain may carry `document_hash` and
  `document_url`; file bytes stay off-chain.
- No node hosts arbitrary files as a side effect of marketplace participation.
- Content hosting is explicit per-file opt-in, hash-checked before publishing.

Owner framing: ZMARKET is "everyone holding a yard sale in their own yard" for
their NFTs. Each seller's own node is the origin for that seller's listings and
buyer-specific signed orders. Other nodes are neighbors who gossip about what
they saw where, cache small signed adverts, and route pre-signed order messages
over ordinary P2P links or Tor onion services. No neighbor becomes the auction
house, the file host, or the source of truth.

## 1. Goals and Non-Goals

Goals:

- Let each node operator independently opt into listing, buying, selling,
  spidering, relaying, routing, and local indexing of signed NFT marketplace
  messages.
- Preserve the yard-sale model: sellers originate their own adverts and orders,
  buyers verify locally, and gossip nodes only report signed sightings.
- Give the wallet a high-performance local marketplace UI: search, sort by
  price/expiry/newest, collection filters, verified mirror status, and direct
  buy-request routing without a central server.
- Keep all marketplace state non-consensus and disposable. A node can wipe and
  rebuild its marketplace index without changing chain state.
- Make every relayed object self-authenticating and bounded before it reaches
  expensive validation.
- Keep hot-path parsing, dedupe, indexing, routing, validation cache, peer caps,
  and local store scans in C for predictable allocation and cross-build behavior.
- Preserve the existing `nft_verifyoffer` safety rule: a buyer verifies the final
  settlement offer locally before signing or broadcasting anything.

Non-goals:

- ZMARKET itself does not create a global identity/name registry. Seller display
  strings are signed by a seller key and are not unique by themselves. Optional
  ZNAM binding can upgrade a display string to "this current ZNAM owner signed
  this listing," but the market still verifies the signed offer and live NFT
  state before display or purchase.
- No automatic file mirroring, no remote URL proxying, and no automatic content
  fetching for marketplace indexing.
- No promise that Tor works as global onion peer discovery until the network
  stack can safely propagate v3 onion addresses. Before ADDRv2/BIP155 support,
  onion routes are direct route hints, manually connected peers, or local Tor
  proxy paths.
- No SQLite dependency in `zclassicd` for the first implementation. SQLite is
  documented below only as a possible wallet-local adapter shape.
- No C++ marketplace engine. C++ may bridge into wallet, chain, LevelDB path
  setup, P2P send/receive, and RPC JSON conversion, but C modules own the
  spider/router/index state and record admission path.

## 2. C Hot-Path Architecture

The implementation should extend the existing `src/zmarket` C namespace rather
than creating a parallel C++ marketplace subsystem. Existing seed modules:

- `src/zmarket/zmarket_record.{h,c}`: allocation-free canonical record framing
  and bounded parse.
- `src/zmarket/zmarket_policy.{h,c}`: node modes, caps, and explicit content-host
  policy.
- `src/zmarket/zmarket_index.{h,c}`: fixed-memory id dedupe/index primitive.

Before any network ABI is locked, update the record type enum to match this
protocol precisely: `LISTING`, `BUYREQ_ROUTE`, `SEALED_OFFER_ROUTE`, `CANCEL`,
`MIRROR`, and `MIRROR_SET`. If the existing `ZMARKET_RECORD_OFFER` name is kept,
it must be documented as the public listing advert type, not the buyer-specific
`ZNFTOFFER1` settlement offer.

Concrete C modules to add:

| C module | Hot-path responsibility |
|---|---|
| `src/zmarket/zmarket_object.{h,c}` | Parse and canonicalize `ZMARKET_LISTING1`, `ZMARKET_BUYREQ1`, `ZMARKET_CANCEL1`, `ZMARKET_MIRROR1`, and route payload headers inside the bounded `zmarket_record_view`. |
| `src/zmarket/zmarket_hash.{h,c}` | Record id, domain-separated digest construction, PoW target checks, compact fingerprint helpers. Uses C SHA256 code or a C callback wired once at init. |
| `src/zmarket/zmarket_sig.{h,c}` | secp256k1-based identity signature verification, signature cache keys, and signature result codes. Owner address/script checks that require wallet/chain code are callback-driven. |
| `src/zmarket/zmarket_validate.{h,c}` | Cheap validation pipeline: caps, TTL, PoW, canonical field checks, signature checks, and callback-based chain binding. |
| `src/zmarket/zmarket_cache.{h,c}` | Fixed-size validation-result cache keyed by `{objectHash, chainHeight, chainTipHash}` with stale/valid/invalid states. |
| `src/zmarket/zmarket_store.{h,c}` | Store-neutral C interface/types used by the hot path. The daemon implementation should persist through a thin C++ `CDBWrapper` bridge, not by adding a second raw LevelDB integration surface. |
| `src/zmarket/zmarket_memindex.{h,c}` | In-RAM sorted/search indices for token price, collection price, seller, expiry, text terms, mirrors, and route queue. |
| `src/zmarket/zmarket_spider.{h,c}` | Peer inventory cache, request scheduler, dedupe, per-peer token buckets, reject accounting, and batch selection. |
| `src/zmarket/zmarket_router.{h,c}` | Encrypted route-packet cache, TTL/hop decrement, fanout selection, duplicate suppression, and Tor-only/clearnet policy checks. |
| `src/zmarket/zmarket_peer.{h,c}` | Peer score, byte/object quotas, backoff, and relay eligibility decisions. |
| `src/zmarket/zmarket_content.{h,c}` | Explicit content allowlist index: exact hash rows, byte caps, served counters, and mirror descriptor generation. Actual HTTP serving is bridged. |
| `src/zmarket/zmarket_engine.{h,c}` | One C facade that wires policy, store, memindex, spider, router, validation cache, and content allowlist together. |

Thin bridge files:

| Bridge | Responsibility |
|---|---|
| `src/nft/zmarket_bridge.h` / `src/nft/zmarket_bridge.cpp` | C++ lifecycle, datadir/config translation, chain/wallet callbacks, `uint256` and address conversion, and locking around calls into C. |
| `src/rpc/nftmarket.cpp` | JSON-RPC argument/result conversion only. Calls `zmarket_engine_*` and existing `nft_*` settlement RPC helpers. |
| `src/net/zmarket_p2p_bridge.cpp` or local `net_processing` hooks | Convert P2P payload bytes to/from C `zmarket_wire_*` buffers. P2P scheduling decisions stay in C. |
| GUI/Qt layer | Calls daemon RPCs. No local marketplace spider/router/index engine in Qt. |

Suggested C callback interface:

```c
typedef int (*zmarket_chain_lookup_fn)(
    void *ctx,
    const uint8_t token_id[32],
    const uint8_t prev_txid[32],
    uint32_t prev_vout,
    const char *owner_taddr,
    uint32_t *out_height,
    uint8_t out_group_id[32],
    int *out_is_nft,
    int *out_live_prevout_matches);

typedef int (*zmarket_owner_sig_verify_fn)(
    void *ctx,
    const char *owner_taddr,
    const uint8_t digest[32],
    const uint8_t *sig,
    size_t sig_len);

typedef int (*zmarket_now_fn)(void *ctx, uint64_t *out_unix, uint32_t *out_height);

struct zmarket_callbacks {
    void *ctx;
    zmarket_chain_lookup_fn chain_lookup;
    zmarket_owner_sig_verify_fn owner_sig_verify;
    zmarket_now_fn now;
};
```

The C engine owns parsed records, validation cache, memindex rows, route queues,
and peer scoring. The C++ bridge supplies facts the C code cannot know without
linking wallet/chain internals: current token ownership, address signature
verification for legacy wallet keys, current height/time, and outbound P2P send.

Required facade API shape:

```c
struct zmarket_engine;

int zmarket_engine_open(struct zmarket_engine **out,
                        const char *db_path,
                        const struct zmarket_policy *policy,
                        const struct zmarket_callbacks *callbacks);
void zmarket_engine_close(struct zmarket_engine *engine);

int zmarket_engine_submit(struct zmarket_engine *engine,
                          const uint8_t *record,
                          size_t record_len,
                          const char *source_peer,
                          uint8_t out_hash[32]);

int zmarket_engine_search(struct zmarket_engine *engine,
                          const struct zmarket_search_query *query,
                          struct zmarket_search_result *out);

int zmarket_engine_get(struct zmarket_engine *engine,
                       const uint8_t hash[32],
                       struct zmarket_object_result *out);

int zmarket_engine_on_inv(struct zmarket_engine *engine,
                          const char *peer_id,
                          const struct zmarket_inv_item *items,
                          size_t item_count);

int zmarket_engine_next_getdata(struct zmarket_engine *engine,
                                const char *peer_id,
                                uint8_t *out_hashes,
                                size_t max_hashes,
                                size_t *out_count);

int zmarket_engine_on_route(struct zmarket_engine *engine,
                            const char *peer_id,
                            const uint8_t *packet,
                            size_t packet_len);
```

Memory rule: C APIs either write into caller-owned bounded buffers or return
opaque handles freed by explicit `zmarket_*_free()` functions. No unbounded
`malloc` on P2P receive. No C++ containers in the engine.

## 3. Operator Modes

All modes require `-zslpindex=1` for validation. Marketplace networking defaults
to off. A node that does not opt in behaves like an ordinary ZClassic node.

Suggested flags:

| Flag | Default | Meaning |
|---|---:|---|
| `-nftmarket=0` | `0` | Enables local marketplace RPCs and local index. No P2P relay unless the relay/spider flags are also on. |
| `-nftmarketspider=0` | `0` | Ask opted-in peers for marketplace inventories and locally index valid public adverts. |
| `-nftmarketrelay=0` | `0` | Relay valid public adverts and encrypted route packets to other opted-in peers. |
| `-nftmarkettor=off` | `off` | `off`, `prefer`, or `only` for marketplace route packets. `only` refuses clearnet market routing. |
| `-nftmarketpowbits=<n>` | network default | Minimum proof-of-work bits for public adverts accepted from peers. |
| `-nftmarketmaxdisk=<MiB>` | `256` | Disk budget for the local marketplace cache. Expired and lowest-score records prune first. |
| `-nftmarketmaxlive=<n>` | `50000` | Maximum live public adverts in the local index. |
| `-nftcontenthost=0` | `0` | Enables serving only explicitly imported content files whose bytes match an NFT `document_hash`. |

Operator choices:

- Seller only: `-nftmarket=1`, create signed listing adverts and sealed offers,
  but do not relay third-party adverts.
- Buyer/browser only: `-nftmarket=1 -nftmarketspider=1`, index peer adverts and
  route buy requests, but do not relay as a wider public node.
- Relay/spider node: add `-nftmarketrelay=1`, accept the bandwidth/storage risk
  under caps.
- Content mirror: add `-nftcontenthost=1` and opt in each exact file with an RPC.

In yard-sale terms, `-nftmarket=1` lets your own yard have signs and take orders.
`-nftmarketspider=1` lets you walk around and remember what other yards are
selling. `-nftmarketrelay=1` lets you tell other opted-in nodes what you saw,
subject to caps and validation. `-nftcontenthost=1` is not part of ordinary
gossip; it is the separate act of putting one exact verified file on your own
table.

## 4. Marketplace Object Model

The existing settlement offer is buyer-specific: the seller's
`ALL|ANYONECANPAY` signature commits to `vout[1] = buyerNftAddr`, so a public
posting cannot be filled by an arbitrary buyer without a buyer-address round
trip. The marketplace therefore uses two stages:

1. Public signed listing advert: spidered, relayed, and indexed.
2. Buyer-specific signed settlement offer: routed to the intended buyer and
   verified with `nft_verifyoffer` before `nft_takeoffer`.

Message classes:

| Type | Publicly spidered? | Purpose |
|---|---:|---|
| `ZMARKET_LISTING1` | yes | Seller-signed public advert: token, live NFT outpoint, price, expiry, seller identity, route hints, optional mirror descriptors. Not directly spendable. |
| `ZMARKET_BUYREQ1` | no, routed | Buyer request containing a fresh `buyerNftAddr`, target listing id, and reply route. Should be encrypted to the seller identity key when routed over relays. |
| `ZNFTOFFER1` | no, routed/local | Existing buyer-sealed atomic settlement offer. Stored by the local buyer/seller wallet; relays treat it as opaque encrypted route payload only. |
| `ZMARKET_CANCEL1` | yes | Seller-signed tombstone for a listing id, plus ordinary live-UTXO revalidation as the real final authority. |
| `ZMARKET_MIRROR1` | yes | Mirror descriptor for one exact `document_hash` and URL/onion URL. It is a link attestation, not file bytes. |

Public listing adverts are "yard signs": small seller-signed statements about
what a seller claims to have for sale and where to contact them. Routed buy
requests and `ZNFTOFFER1` payloads are "orders": buyer-specific, pre-signed or
ready-to-sign trade messages passed between buyer and seller, optionally over
Tor hidden onion services. Gossip nodes may carry those order packets, but only
as opaque bounded route messages.

Canonical envelope rules:

- Binary canonical encoding, not free-form JSON, for all signed and hashed
  fields.
- `objectHash = SHA256d(canonicalEnvelopeWithoutTransportMetadata)`.
- Every signature is domain-separated by message type and network name.
- Maximum public envelope size: 16 KiB. Maximum routed encrypted packet: 64 KiB.
- Records include `network`, `createdMtp`, `expiryHeight`, `validUntilMtp`,
  `hopLimit`, `workNonce`, and `workBits`.

## 5. Listing Signature and Name Binding

`ZMARKET_LISTING1` fields:

```text
magic/version
network
tokenId
nftPrevoutTxid
nftPrevoutVout
ownerTaddr
priceZat
sellerIdentityPubKey
sellerDisplayName
sellerNameHash = SHA256(normalize_name(sellerDisplayName))
routeHints[]
mirrorDescriptors[]
expiryHeight
validUntilMtp
createdMtp
workBits
workNonce
ownerSig
identitySig
```

Verification:

1. Cheap parse: size, magic, version, network, sane field lengths, expiry not in
   the past, caps, and proof-of-work.
2. Owner binding: `ownerSig` is a signature by the key controlling `ownerTaddr`
   over `H("ZMARKET_LISTING_OWNER_V1" || canonicalBodyWithoutSignatures)`.
3. Live NFT binding: local `-zslpindex` proves `nftPrevout` is the current live
   carrier UTXO for `tokenId`, the token is an NFT (`decimals=0`, `quantity=1`,
   no live mint baton for the NFT itself), and the carrier output pays
   `ownerTaddr`.
4. Identity/name binding: `identitySig` is a signature by
   `sellerIdentityPubKey` over
   `H("ZMARKET_LISTING_IDENTITY_V1" || canonicalBodyWithoutSignatures || ownerSig)`.
   This binds the display name, route hints, price, expiry, and mirror links to
   the seller identity key.
5. UI rule: the display name is never treated as globally unique. The wallet
   shows the seller key fingerprint and warns on local name collisions.

This gives useful authenticity without inventing a name registry. "Alice" means
"the holder of seller key X signs the display string Alice", not "globally
unique Alice".

`ZMARKET_CANCEL1` uses the same seller identity key and, where possible, an owner
signature over the listing id. A cancel tombstone is advisory; spending or moving
the NFT outpoint is the authoritative invalidation.

## 6. P2P and Tor Routing

Marketplace relay uses ordinary ZClassic P2P connections between opted-in peers.
Peers advertise a service bit such as `NODE_NFTMARKET` only when market relay or
spidering is enabled.

Suggested P2P messages:

| Message | Payload | Notes |
|---|---|---|
| `zmkinv` | compact records `{hash,type,expiry,bytes,workBits}` | Inventory only. No file bytes, no offer hex for private routed offers. |
| `zmkget` | list of hashes | Bounded request. Unknown or expired hashes ignored. |
| `zmkobj` | one public envelope | `ZMARKET_LISTING1`, `ZMARKET_CANCEL1`, or `ZMARKET_MIRROR1`. |
| `zmkroute` | encrypted route packet | Store-and-forward buyer requests and buyer-specific offers. Relays index only routing metadata, not inner contents. |
| `zmkping` | capabilities and caps | Includes max object size, PoW floor, relay mode, Tor preference. |

Wire encode/decode belongs in `src/zmarket/zmarket_wire.{h,c}`. The C++ P2P
bridge only extracts payload bytes from `CDataStream`, calls `zmarket_wire_*` or
`zmarket_engine_*`, and serializes returned bounded buffers back to peers.

Spider behavior:

- Maintain a peer score and recent inventory cache.
- Request small batches, newest first, from peers with `NODE_NFTMARKET`.
- Validate cheap fields and PoW before queueing expensive chain/signature checks.
- Index only valid public objects. Invalid public objects are not relayed.
- Revalidate listings on new blocks, reorgs, and expiry boundaries.
- Treat public adverts as signed sightings: "peer X says it saw listing hash H
  at seller route R." The index records provenance and last-seen data, but local
  validation decides whether the wallet can show or use the listing.

Routing behavior:

- `ZMARKET_BUYREQ1` is addressed to `sellerIdentityPubKey`.
- Seller replies with an encrypted route packet containing `ZNFTOFFER1`, sealed
  to the buyer's `buyerNftAddr`.
- Sellers may pre-sign buyer-specific `ZNFTOFFER1` orders and pass them through
  Tor/onion route packets. Relays can forward the packet, but cannot make it
  valid for another buyer because the offer is sealed to `buyerNftAddr`.
- Relays store route packets only until `routeTtlSec` or `expiryHeight`, whichever
  is sooner. They do not parse or index sealed offers.
- Route packets have `hopLimit` capped at 6 by default. Each relay decrements it.
- Duplicate route packets are deduped by packet hash.

Tor behavior:

- `-nftmarkettor=prefer` uses onion route hints when available and falls back to
  ordinary P2P routing.
- `-nftmarkettor=only` refuses clearnet market route packets and should not
  publish clearnet route hints.
- Tor hidden onion services are the preferred way for yard-sale nodes to pass
  buyer requests and pre-signed orders without publishing a clearnet contact
  route.
- Seller route hints may include `.onion` endpoints, but v3 onion peer gossip
  must not be promised until ADDRv2/BIP155 support makes onion addresses
  serializable, persistable, and distinct in addrman.
- Before ADDRv2, onion routing is safe only through direct route hints,
  `-addnode`/manual peers, or a local Tor proxy path. The marketplace docs and UI
  must say this plainly.

## 7. Local Index Shape

The daemon hot path should stay in C for record admission, validation, routing,
spider scheduling, dedupe, ranking, and in-memory search indexes. Durable
persistence should be a thin C++ `CDBWrapper` bridge under the daemon datadir.
That keeps ZMARKET on the same database lifecycle, cache accounting, build
system, and source distribution path as the rest of `zclassicd` without moving
market policy into C++.

Do not add a separate raw LevelDB C API dependency for beta7 unless a measured
performance bottleneck proves the bridge is the limiting factor. SQLite is
included here only as a possible wallet-local adapter shape, not as a daemon
dependency for the first implementation.

### 7.1 CDBWrapper-Backed Market Store Bridge

Database directory: `<datadir>/nftmarket/`.

Primary records:

| Key prefix | Value | Purpose |
|---|---|---|
| `M:v` | schema version | Wipe/rebuild on incompatible changes. |
| `M:o:<objectHash>` | public envelope bytes plus parsed metadata | Listing, cancel, and mirror records. |
| `M:t:<tokenId>:<priceBE>:<expiryBE>:<objectHash>` | empty | Token/price/expiry listing index. |
| `M:g:<groupId>:<priceBE>:<objectHash>` | empty | Collection listing index. |
| `M:e:<expiryBE>:<objectHash>` | empty | Fast expiry and GC. |
| `M:s:<sellerKeyHash>:<objectHash>` | empty | Seller browse and per-seller caps. |
| `M:n:<term>:<objectHash>` | empty | Name/ticker/seller-name text index. |
| `M:c:<listingId>` | cancel/tombstone metadata | Advisory cancel cache. |
| `M:m:<tokenId>:<documentHash>:<mirrorHash>` | mirror descriptor metadata | Mirror link browse and verification state. |
| `M:r:<routeHash>` | encrypted packet metadata | Short-lived routed packets only. |
| `M:p:<peerId>` | score, bytes, rejects, last seen | Peer rate limiting and diagnostics. |

Parsed metadata stored with `M:o`:

```text
objectHash
type
tokenId
groupId
priceZat
expiryHeight
validUntilMtp
sellerIdentityPubKey
sellerKeyHash
sellerDisplayName
sellerNameNorm
sellerNameHash
ownerTaddr
nftPrevout
routeFlags
mirrorCount
workBits
serializedBytes
verifyState
firstSeen
lastSeen
lastVerifiedHeight
sourcePeer
```

Do not store arbitrary file bytes in this database. Do not persist decrypted
buyer-specific `ZNFTOFFER1` route payloads in the public market index. The local
wallet offer store may keep sent/received sealed offers for the user's own
trades, ideally encrypted with wallet storage when that becomes available.

An in-RAM C read model should be rebuilt from the C++ store bridge at startup
for UI speed:

- `byTokenPrice[tokenId] -> sorted listing ids`
- `byCollectionPrice[groupId] -> sorted listing ids`
- `byExpiry -> listing ids`
- `bySeller -> listing ids`
- `terms -> sorted listing ids`
- `mirrorStatus[tokenId][documentHash] -> descriptors`

Concrete C store facade API:

```c
struct zmarket_store;

int zmarket_store_put_object(struct zmarket_store *store,
                             const struct zmarket_object_meta *meta,
                             const uint8_t *record,
                             size_t record_len);
int zmarket_store_get_object(struct zmarket_store *store,
                             const uint8_t hash[32],
                             uint8_t *record_out,
                             size_t record_cap,
                             size_t *record_len_out,
                             struct zmarket_object_meta *meta_out);
int zmarket_store_delete_object(struct zmarket_store *store,
                                const uint8_t hash[32]);
int zmarket_store_scan_prefix(struct zmarket_store *store,
                              const uint8_t *prefix,
                              size_t prefix_len,
                              zmarket_store_scan_fn cb,
                              void *cb_ctx,
                              size_t max_rows);
int zmarket_store_gc(struct zmarket_store *store,
                     uint64_t now_unix,
                     uint32_t chain_height,
                     size_t target_bytes);
```

The concrete daemon object behind `struct zmarket_store` is owned by a C++
bridge, for example `CMarketStore : CDBWrapper`. The C hot path sees only the
bounded function table/facade above; it does not include LevelDB headers, STL,
RPC JSON, wallet state, or file-serving code.

Concrete C memindex API:

```c
struct zmarket_memindex;

int zmarket_memindex_build(struct zmarket_memindex **out,
                           struct zmarket_store *store,
                           const struct zmarket_policy *policy);
void zmarket_memindex_free(struct zmarket_memindex *idx);

int zmarket_memindex_upsert(struct zmarket_memindex *idx,
                            const struct zmarket_object_meta *meta);
int zmarket_memindex_remove(struct zmarket_memindex *idx,
                            const uint8_t hash[32]);
int zmarket_memindex_search(struct zmarket_memindex *idx,
                            const struct zmarket_search_query *query,
                            struct zmarket_search_result *out);
```

### 7.2 SQLite Adapter Shape

If the GUI later wants a private SQLite cache, it should be generated from
daemon RPC results or the same parsed records. It is not authoritative.

Suggested tables:

```sql
CREATE TABLE market_objects (
  hash BLOB PRIMARY KEY,
  type INTEGER NOT NULL,
  token_id BLOB NOT NULL,
  group_id BLOB,
  price_zat INTEGER,
  expiry_height INTEGER NOT NULL,
  valid_until_mtp INTEGER NOT NULL,
  seller_key BLOB NOT NULL,
  seller_key_hash BLOB NOT NULL,
  seller_name TEXT NOT NULL,
  seller_name_norm TEXT NOT NULL,
  seller_name_hash BLOB NOT NULL,
  owner_taddr TEXT NOT NULL,
  nft_prevout_txid BLOB NOT NULL,
  nft_prevout_vout INTEGER NOT NULL,
  route_flags INTEGER NOT NULL,
  work_bits INTEGER NOT NULL,
  serialized_bytes INTEGER NOT NULL,
  verify_state INTEGER NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  last_verified_height INTEGER NOT NULL,
  envelope BLOB NOT NULL
);

CREATE INDEX market_token_price
  ON market_objects(token_id, price_zat, expiry_height);
CREATE INDEX market_group_price
  ON market_objects(group_id, price_zat, expiry_height);
CREATE INDEX market_seller
  ON market_objects(seller_key_hash, expiry_height);
CREATE INDEX market_expiry
  ON market_objects(expiry_height);

CREATE TABLE market_terms (
  term TEXT NOT NULL,
  hash BLOB NOT NULL,
  PRIMARY KEY(term, hash)
);

CREATE TABLE market_mirrors (
  mirror_hash BLOB PRIMARY KEY,
  token_id BLOB NOT NULL,
  document_hash BLOB NOT NULL,
  url TEXT NOT NULL,
  content_length INTEGER,
  mime TEXT,
  expires_mtp INTEGER,
  mirror_key BLOB,
  verify_state INTEGER NOT NULL,
  last_verified INTEGER
);

CREATE TABLE market_routes (
  route_hash BLOB PRIMARY KEY,
  to_key_hash BLOB NOT NULL,
  expires_mtp INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  ciphertext BLOB NOT NULL
);
```

## 8. RPCs for Wallet UI

Existing trade RPCs remain the settlement ground truth:

- `nft_makeoffer`
- `nft_verifyoffer`
- `nft_takeoffer`
- `nft_listoffers`
- `nft_canceloffer`
- `nft_requestbuy`

New marketplace RPC scaffold:

| RPC | Purpose |
|---|---|
| `nft_marketstatus` | Return enabled flags, index size, disk usage, peer counts, queue depth, PoW floor, Tor mode, and content-host state. |
| `nft_market_publishlisting` | Create and optionally relay a `ZMARKET_LISTING1` for an owned NFT. Requires owner signature and identity signature. |
| `nft_market_submit` | Import a public listing/cancel/mirror envelope from file, clipboard, QR, or peer; validate and index locally. |
| `nft_market_search` | Bounded search over local index by text, token id, collection, price range, seller key, mirror status, expiry, and sort. |
| `nft_market_get` | Return one listing card plus validation state and mirror descriptors. |
| `nft_market_requestbuy` | Create a fresh buyer request for a listing and route it to the seller. Wraps/reuses `nft_requestbuy`. |
| `nft_market_routepoll` | Wallet diagnostic for pending routed buyer requests/offers addressed to this node. |
| `nft_market_mirrors` | List known mirror descriptors for a token/document hash and their local verification state. |
| `nft_market_revalidate` | Re-run expensive validation for one listing or mirror. Useful after reorgs or before buy. |
| `nft_market_forget` | Drop a local listing, seller, mirror, or peer from the local cache without affecting the network. |
| `nft_content_addfile` | Explicitly import one local file for serving. Hash must match the NFT `document_hash`. |
| `nft_content_list` | List explicitly hosted files and served byte totals. |
| `nft_content_removefile` | Stop serving one explicitly hosted file. |

RPC implementation rule: every search, submit, route, mirror, peer-status, and
content-host query must call the C engine facade. RPC code may format JSON and
may call wallet/chain helpers through callbacks, but must not maintain a
parallel C++ index.

`nft_market_search` result shape:

```json
{
  "objects": [
    {
      "listingId": "hex",
      "tokenId": "hex",
      "name": "from local zslp index",
      "ticker": "from local zslp index",
      "group": "hex or empty",
      "priceZat": 123,
      "expiryHeight": 123456,
      "sellerName": "display string",
      "sellerKeyFingerprint": "hex",
      "verifyState": "valid|stale|expired|invalid|pending",
      "mirrorState": "none|unverified|verified|mismatch",
      "routeState": "direct|relay|onion|unknown"
    }
  ],
  "from": 0,
  "count": 50,
  "more": true
}
```

The UI must call `nft_market_revalidate` or `nft_market_get` immediately before
starting a buy, then receive a routed `ZNFTOFFER1`, then call
`nft_verifyoffer`, then call `nft_takeoffer`.

## 9. Spam, DoS, TTL, PoW, and Caps

Layered admission:

1. Transport cap: reject messages above size limits before allocation-heavy work.
2. Parse cap: reject unknown magic/version, wrong network, expired objects,
   oversized strings, too many mirrors, too many route hints, and invalid varints.
3. PoW cap: public objects from peers must satisfy the configured work floor.
4. Signature cap: verify owner/identity signatures before chain reads.
5. Chain validation cap: expensive live NFT checks run in a bounded validation
   queue, not on the P2P receive thread.
6. Relay cap: relay only objects that passed validation or are marked as
   locally trusted imports created by this wallet.

Default caps:

| Cap | Default |
|---|---:|
| Public envelope size | 16 KiB |
| Routed packet size | 64 KiB |
| Mirrors per listing | 8 |
| Route hints per listing | 4 |
| Public listing lifetime | min(`expiryHeight`, 14 days MTP) |
| Route packet TTL | 30 minutes |
| Hop limit | 6 |
| Live listings per seller key | 100 |
| Live listings per token | 1000 |
| Public objects per peer per hour | 500 |
| Bytes per peer per hour | 8 MiB |
| Disk cache | 256 MiB |

Proof-of-work:

```text
powHash = SHA256d("ZMARKET_POW1" || canonicalEnvelopeWithoutPowNonce || workNonce)
accept if leading_zero_bits(powHash) >= max(localFloor, advertisedWorkBits)
```

The work floor can be lower on regtest and higher under attack. The receiver is
free to require more work than the sender advertised. Locally created objects may
bypass PoW for local indexing, but publishing to peers should still attach PoW
so relays can enforce one rule.

GC and scoring:

- Expired objects are removed first.
- Invalid signatures, bad PoW, repeated stale-prevout adverts, and oversized
  payload attempts reduce peer score.
- Low-score peers lose relay privileges before ordinary P2P connectivity.
- Per-seller and per-token caps prune oldest or lowest-work records first.
- Tombstones expire after the referenced listing expiry plus a short safety
  window.

The quota, cache, and peer-scoring code belongs in C:

- `zmarket_peer.{h,c}` owns peer score and token buckets.
- `zmarket_cache.{h,c}` owns validation cache and stale-at-height decisions.
- `zmarket_spider.{h,c}` owns request scheduling and inventory dedupe.
- `zmarket_router.{h,c}` owns route TTL, hop count, and fanout.

The P2P bridge may disconnect or discourage a peer based on C return codes, but
it must not duplicate policy.

## 10. Mirror Link Verification and Content Hosting

Mirror descriptors are links, not hosted bytes:

```text
ZMARKET_MIRROR1
network
tokenId
documentHash
url
contentLength
mime
expiresMtp
mirrorIdentityPubKey optional
mirrorSig optional
```

Verification rules:

- If the token has no on-chain `document_hash`, no mirror can be marked verified.
- A mirror is verified only when fetched bytes hash exactly to the token's
  `document_hash`.
- Fetches are never automatic during spidering. The wallet may verify after an
  explicit user action or a local operator setting.
- Fetches are bounded by declared and configured maximum size.
- No HTML execution, no embedded browser requirement, no script execution, and no
  MIME trust without hash verification.
- `http`, `https`, `ipfs`, and `.onion` URLs can be indexed as strings, but the
  daemon should not become a generic URL fetcher/proxy.

Explicit content hosting:

- `nft_content_addfile { tokenId, path, advertise? }` computes SHA-256 of the
  local file and refuses unless it equals `zslp_gettoken(tokenId).document_hash`.
- The file is copied or hard-linked into a content-addressed private store under
  `<datadir>/nftcontent/<hash>/`.
- Serving is by exact hash path only, for example
  `/nftcontent/<documentHash>`. There is no directory listing and no remote URL
  proxy.
- `nft_content_removefile` deletes the allowlist row and stops serving it.
- A node never hosts a file because it saw a mirror descriptor. Hosting is a
  separate per-file operator action.

Content allowlist hot-path state belongs in `zmarket_content.{h,c}`. The HTTP
server bridge may stream bytes from disk, but the decision "is this hash allowed
to be served" must come from the C allowlist and exact hash metadata.

## 11. Safe Implementation Phases

Phase 0: C types and validators only.

- Extend the existing C `zmarket_record.{h,c}`, `zmarket_policy.{h,c}`, and
  `zmarket_index.{h,c}` modules instead of moving logic into C++.
- Add C canonical encoders/decoders for `ZMARKET_LISTING1`,
  `ZMARKET_CANCEL1`, `ZMARKET_MIRROR1`, and route packet headers.
- Add C signature, PoW, TTL, validation-cache, and size validators.
- No P2P relay, no content hosting.

Phase 1: C hot-path index plus CDBWrapper-backed RPC import/search.

- Implement `nft_market_submit`, `nft_market_search`, `nft_market_get`,
  `nft_marketstatus`, and revalidation as C++ JSON bridges over
  `zmarket_engine_*`.
- Build the in-RAM C read model from C++ store bridge scans.
- Allow file/clipboard/QR import through RPC only.

Phase 2: Publish and spider public adverts.

- Add `NODE_NFTMARKET`, `zmkinv`, `zmkget`, `zmkobj`, and peer caps.
- Relay only validated public objects.
- Keep defaults off.

Phase 3: Routed buy requests and sealed offers.

- Add `zmkroute`.
- Implement `nft_market_requestbuy`.
- Route encrypted `ZMARKET_BUYREQ1` to seller and encrypted `ZNFTOFFER1` back to
  buyer.
- Preserve mandatory `nft_verifyoffer` before `nft_takeoffer`.

Phase 4: Explicit content mirror serving.

- Implement `nft_content_addfile/list/remove`.
- Add hash-only content serving with byte caps.
- Publish `ZMARKET_MIRROR1` only for opted files when requested.

Phase 5: GUI marketplace.

- Use `nft_market_search` for browse/search.
- Use `nft_market_get` and revalidation before buy.
- Use mirror verification badges based on local hash checks.
- Make Tor route mode and content-host mode visible as operator settings.

## 12. Test Plan

Unit tests:

- Add pure C tests for every `src/zmarket/*.c` hot-path module, independent of
  wallet and chain fixtures where possible.
- Canonical encoding is byte-stable and hash-stable.
- Reject non-canonical encodings, wrong network, unknown versions, oversized
  strings, too many mirrors, and expired messages.
- PoW accepts exact target and rejects one-bit-short work.
- Owner signature fails for the wrong `ownerTaddr`.
- Identity signature fails if seller name, price, route hint, mirror descriptor,
  or expiry changes.
- Name normalization produces stable `sellerNameHash` and collision warnings are
  based on key/name pairs, not name uniqueness.

Indexer tests:

- Market store schema version wipe/rebuild.
- Insert, update, cancel, expire, and GC preserve secondary indices.
- Rebuild from the store bridge produces the same search results as live inserts.
- Per-seller, per-token, per-peer, and disk caps prune deterministically.
- Expired route packets are not returned.
- C memindex results match RPC JSON bridge results exactly.

Chain validation tests:

- A listing for a non-NFT token is invalid.
- A listing whose `nftPrevout` is not the live token carrier is stale/invalid.
- A listing becomes stale after the NFT is transferred or canceled.
- Reorg from spent back to live revalidates correctly.
- `nft_verifyoffer` remains mandatory and catches a forged or stale
  `ZNFTOFFER1` before `nft_takeoffer`.

P2P/regtest tests:

- Two opted-in nodes exchange `zmkinv`/`zmkget`/`zmkobj` and converge on the same
  valid listing.
- A non-opted node neither advertises nor requests marketplace objects.
- Bad PoW, bad signature, bad owner binding, and oversized object are not relayed.
- Hop limit and route TTL are enforced.
- Peer score drops after repeated invalid adverts.
- `-nftmarkettor=only` refuses clearnet marketplace route packets.
- Onion route hints are treated as direct hints until ADDRv2 support exists.
- P2P bridge tests assert that malformed payloads are rejected by C
  `zmarket_wire_*`/`zmarket_engine_*` before any C++ chain or wallet callback is
  invoked.

Content tests:

- `nft_content_addfile` rejects hash mismatch and missing `document_hash`.
- Hosted files are served only by exact opted hash.
- Path traversal, directory listing, and remote URL proxy attempts fail.
- Mirror descriptor is marked verified only after hash-matching fetch.
- Spidering a mirror descriptor never fetches or hosts the file automatically.

Wallet/RPC tests:

- `nft_market_publishlisting` creates a locally valid signed listing for an owned
  NFT.
- `nft_market_search` sorting and pagination are stable for price, expiry,
  seller, text, token, and collection filters.
- `nft_market_requestbuy` produces a fresh buyer address, routes a request, and
  receives a buyer-sealed `ZNFTOFFER1`.
- Buy flow still calls `nft_verifyoffer` before `nft_takeoffer`.
- `nft_market_forget` removes only local cache state and does not affect wallet
  ownership or chain state.
- RPC tests assert no C++ static/global container owns marketplace listing,
  spider, route, or validation-cache state outside the C engine handle.

## 13. Key Invariants to Preserve

- Marketplace objects are off-chain. The chain remains the ZSLP ownership and
  `document_hash` source of truth.
- Public listings are not settlement transactions. Settlement is still the
  existing buyer-specific `ZNFTOFFER1` flow.
- Relays never need to be trusted. Buyers verify final offers locally before
  signing.
- Relays and spiders store small signed envelopes, not arbitrary files.
- Content hosting is per-file, explicit, hash-bound, and removable by the local
  operator.
- Seller names are signed display strings, not unique identities.
- Tor is a route option, not a privacy claim unless the node is actually in an
  onion-only market route mode.
- Spidering, routing, indexing, validation cache, peer scoring, and content
  allowlist decisions are C-owned hot paths. C++ and Qt remain bridges.

## 14. Beta7 Onion Identity Rules

### Separate Reusable Identities Per Role

Each marketplace role uses its **own dedicated reusable onion identity**. A node
running multiple roles (market listing, content mirror, social/relay, direct
buyer-seller) maintains separate `.onion` v3 service identities for each, with
independent key material. The `zmarket_onion_set` tracks endpoints tagged with
`zmarket_onion_role` bits (`MARKET`, `CONTENT`, `SOCIAL`, `DIRECT`); routing
selects only endpoints matching the required role.

### One-Time Onions: Short-Lived Direct/Private Only

`ZMARKET_ONION_SCOPE_ONE_TIME` endpoints are **exclusively for short-lived
direct/private routes** between a specific buyer and seller. After a single
successful use, the endpoint transitions to `ZMARKET_ONION_USED` state and is
permanently retired — it can never be chosen again by `zmarket_onion_choose`.
One-time onions must never be used for market listings, content mirroring, or
social relay roles. They require a non-zero `scope_id` binding them to the
specific trade session.

### Deferred: OnionBalance and Shared-Key Replicas

Beta7 **defers** OnionBalance and shared-key `.onion` replica configurations.
Multi-server high availability for onion services is a deployment-time concern
that requires external orchestration (OnionBalance, Tor `HiddenServicePort`
distribution) and is out of scope for the C hot-path engine. The onion module
does not manage replica keys, load balancers, or shared secret material.

### Load Balancing: App-Level Failover Across Signed Endpoints

Load balancing is **app-level failover across multiple signed mirror/endpoint
records**. The `zmarket_onion_set` stores multiple `MIRROR` or `MIRROR_SET`
record-backed endpoints, each carrying a `weight` and `scope_id` for weighted
selection. When one endpoint fails (tracked via `fail_count`), the engine
selects the next-best candidate from the signed set. No media is downloaded
by the indexer — only signed endpoint metadata (host, port, weight, expiry,
role, scope) is tracked in-RAM. Failover scoring uses a deterministic
FNV-1a-based weighted random with failure penalty, seeded per-query to ensure
reproducible selection without requiring persistent state.

### Onion Identity Summary Table

| Scope | Lifecycle | Roles | `scope_id` | Use Case |
|---|---|---|---|---|
| `REUSABLE` | Persistent, operator-managed | MARKET, CONTENT, SOCIAL | Optional | Long-lived market/mirror/relay |
| `ASSET` | Per-asset listing | MARKET, CONTENT | Required | Tied to a specific NFT/collection |
| `SESSION` | Session-bound | Any | Required | Temporary session, survives disconnect |
| `ONE_TIME` | Single-use, then retired | DIRECT only | Required | Private buyer↔seller route |
