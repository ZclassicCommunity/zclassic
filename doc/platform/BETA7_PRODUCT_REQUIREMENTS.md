# ZClassic beta7 platform requirements

Status: owner requirements and implementation contract for beta7. Coin is
ZClassic / ZCL in user-facing text.

This document ties together the beta7 GUI wallet goal: Tor, ZMARKET, ZNAM,
NFT collections, signed offers, and operator-controlled NFT file availability.
It is non-consensus by design.

## Hard rules

1. No ZClassic consensus changes. Do not change block validity, transaction
   validity, proof-of-work, script verification, mempool acceptance, or mining
   rules for ZNAM, ZMARKET, Tor, NFT hosting, or content lookup.
2. Files are never stored on-chain. Blocks may contain existing ZSLP / ZNAM
   bounded OP_RETURN records, hashes, and signatures. They must not contain NFT
   image bytes, media bytes, archives, HTML, chunks, or arbitrary file data.
3. Nodes never host random files. A node must not scan arbitrary directories,
   mirror remote content automatically, host "all NFTs", or become a public
   blob server by default.
4. Hosting is explicit per operator and per object. A node operator may choose
   to host a specific file, including their own NFT image or other NFT media.
   The wallet must show what is hosted and allow unhosting it.
5. Mirrors and market relays are untrusted. Wallets verify signatures, hashes,
   expiry, ownership, and payment/offer validity before showing trust badges or
   allowing a buy action.
6. No central party. Marketplace discovery, indexing, routing, mirror lookup,
   and name resolution must work through local node indexes, signed records,
   peer routing, onion mirrors, and ZNAM identities, not a required server.
7. High performance is a product requirement. The GUI should feel like a local
   marketplace, not a slow remote search page. Nodes can spider and index signed
   offers locally within strict caps.
8. Marketplace spidering, routing, and indexing hot paths are implemented in C.
   C++/Qt code may provide thin bridges, RPCs, and UI models, but the engine that
   parses canonical records, dedupes inventory, routes records, and maintains
   the local market index must be a bounded C library.

## Product target

Beta7 should feel like a native decentralized collectibles wallet:

- Collections tab: view owned NFTs, collections, provenance, local file
  verification, and mirror status.
- Market tab: browse locally indexed signed sell offers, create listings, buy
  atomically, cancel local listings, inspect offer signatures, and see freshness.
- Names tab: register and resolve ZNAM names that bind creator, seller, mirror,
  and market identities to keys and onion endpoints.
- Privacy and Network tab: embedded Tor status, marketplace relay/index mode,
  local onion address, and explicit hosted-file controls.

The wallet may say "decentralized marketplace" only when the path uses signed
offers and local verification. It must not imply that NFT ownership is enforced
by ZClassic consensus.

## ZMARKET yard-sale model

ZMARKET is not a central exchange and not a global authoritative order book. It
is closer to every node operator holding a yard sale in their own yard:

- a seller pre-signs an NFT sell order and chooses whether to publish it from
  their own node/onion service;
- buyers and other nodes can carry signed orders around, gossiping what they
  saw and where they saw it;
- nodes can spider yards, route small signed order records, and index local
  observations for a fast wallet UI;
- a copied order remains useful because its signature and atomic offer blob are
  self-verifying;
- stale, filled, forged, or expired orders fall out during local verification;
- no party is trusted because the buyer's wallet reruns offer verification at
  purchase time.

Tor hidden services are the preferred beta7 transport for this yard-sale model:
operators can run their market yard at an onion address, peers can pass signed
orders over onion routes, and wallets can build a local view of the market
without relying on a central website.

## Node roles

Every role is opt-in except read-only local verification:

| Role | Default | Behavior |
|------|---------|----------|
| Viewer | on | Verify owned NFTs, signed offers, names, manifests, mirrors, and chain anchors. |
| Buyer | on | Browse indexed signed offers and complete atomic buys. |
| Seller | on | Create signed offers for NFTs owned by the wallet. |
| Market relay | off until soak | Route signed offer inventory and offer bodies to peers. |
| Market spider | off until soak | Discover signed offers from peers and known onion feeds, then verify and index locally. |
| Market indexer | on when market enabled | Maintain a local bounded index for fast GUI browse/filter/sort. |
| Content host | off | Serve only operator-selected files over onion by content hash. |
| Mirror announcer | off | Publish signed mirror records for operator-selected hosted files. |

Market relay/spider/index modes can be enabled independently so a node operator
can buy/sell without serving files, serve files without relaying the market, or
index the market without hosting content.

## Signed records

The beta7 platform uses signed records, not trusted servers.

### Asset manifest

An asset manifest describes immutable content:

- schema id and version;
- network (`zclassic-mainnet`, `zclassic-testnet`, or `zclassic-regtest`);
- token id / NFT outpoint / collection id when known;
- creator name or key;
- file list: path, MIME, size, full hash, chunk hashes;
- content root;
- optional chain anchors, such as ZSLP `document_hash` or transaction ids;
- creator signature.

The manifest does not contain mirror URLs. That keeps asset identity stable
when mirrors rotate.

For NFT media, `content root` must use the existing ZSLP content fingerprint
algorithm in `src/zslp/contentfingerprint.{h,cpp}` and the Qt wallet
`ContentEngine`: whole-file SHA-256 for empty/single-chunk files, and the
domain-separated 1 MiB Merkle root only when the file has more than one chunk.
This keeps CLI mint, GUI mint, mirror verification, and `document_hash` badges
byte-identical.

### Mirror record

A mirror record says an operator hosts some content:

- schema id and version;
- asset id / content root;
- onion base URL;
- served file ids or chunk ids;
- expiry time or expiry height;
- mirror operator key;
- optional ZNAM name;
- mirror operator signature.

A mirror record is not proof of truth. It is an invitation to fetch bytes and
verify them against the manifest.

### Mirror set

A mirror set is the artist or owner signed list of preferred mirrors:

- asset id / content root;
- sequence number;
- mirror records or mirror record hashes;
- expiry;
- signer name/key;
- signature.

This is how artists can publish multiple backup onion hosts without putting
stale URLs on-chain.

### Market offer

A market offer is a signed sell, buy, or listing record:

- offer id = hash of canonical offer bytes;
- token id / NFT outpoint;
- price and currency;
- seller payout address;
- buyer constraints when direct offers are used;
- expiry;
- optional manifest id and mirror set id;
- optional ZNAM identity;
- seller signature and atomic offer blob when selling.

The node verifies the offer before indexing or routing it. Invalid offers are
not inserted into the local market index.

## Marketplace spider, routing, and indexing

High-performance UI comes from local indexes, not a central API.

### C engine requirement

The market engine is C-first:

- C modules own spider queues, route tables, dedupe filters, canonical record
  parsers, signature-verification cache keys, and local index update batches.
- C++ daemon code only bridges between existing ZClassic primitives, wallet/RPC
  objects, P2P messages, and the C engine.
- Qt GUI code never owns the market indexer. It reads daemon RPC snapshots and
  subscribes to coarse refresh/status updates.
- Data structures are cache-friendly, bounded, and explicit about ownership:
  arenas/ring buffers for short-lived spider work, hash tables for offer ids and
  mirror ids, and append-only batches for index updates.
- All externally supplied lengths are checked before allocation or parse.
- Canonical record bytes are stored once by hash; indexes point at ids/offsets
  instead of copying large strings.
- The C ABI is stable enough for unit tests and future reuse by a headless
  market node.

### Spidering

Spidering discovers candidate signed records from:

- connected peers via bounded ZMARKET inventory;
- known onion market feeds;
- ZNAM records that advertise market endpoints;
- operator-added seed endpoints;
- previously verified mirrors and sellers.

Spidering must be bounded by TTL, byte caps, per-peer rate limits, signature
checks, and local operator settings. It must never download NFT media just
because an offer references it. Media fetch is explicit user action or explicit
operator hosting action.

### Routing

Routing moves small signed records, not files:

- offer inventory;
- offer bodies;
- mirror record inventory;
- mirror records;
- manifest inventory;
- manifest records.

Routing should prefer Tor/onion paths for beta7 privacy. Clearnet relay remains
operator opt-in and honestly labeled. File chunks are served only by content
hosts that explicitly pinned the file.

### Local index

The node maintains a local market index for the GUI:

- offer id -> verified offer;
- token id / collection id -> active offers;
- seller name/key -> active offers;
- price/floor indexes;
- expiry/freshness indexes;
- mirror health summaries;
- signature verification state;
- last-seen source and routing diagnostics.

The index is local cache. It is not consensus truth. It can be wiped and rebuilt
from signed records plus chain state.

Suggested C module layout:

| File | Purpose |
|------|---------|
| `src/zmarket/zmarket_record.{h,c}` | canonical signed record framing, length checks, ids |
| `src/zmarket/zmarket_spider.{h,c}` | bounded peer/onion spider queue, TTL, backoff |
| `src/zmarket/zmarket_router.{h,c}` | inventory dedupe, route scoring, relay policy |
| `src/zmarket/zmarket_index.{h,c}` | local in-memory/index-batch structures for fast browse |
| `src/zmarket/zmarket_policy.{h,c}` | caps, operator modes, host/relay/index permissions |
| `src/zmarket/zmarket_bridge.{h,cpp}` | thin C++ bridge to CNftOfferBlob, RPC, P2P, wallet |

The C engine never calls consensus validation directly. The bridge supplies
callbacks for chain facts such as "is this NFT UTXO live?", "does this ZNAM
name resolve?", and "does this signature verify under the wallet/daemon key
rules?"

## Content hosting

Content hosting is a separate feature from marketplace routing.

Required policy:

- content host mode is off by default;
- hosted files are selected explicitly by the operator;
- the host serves by content id or chunk hash, not by arbitrary filesystem path;
- hosted records keep a local allowlist of file ids, source paths, content root,
  size, MIME, and expiry;
- remote spidering cannot add a file to the host allowlist;
- a fetched file is not rehosted unless the operator chooses "Host this file";
- unhosting removes the allowlist entry and stops advertising the mirror;
- the GUI shows storage and bandwidth caps before enabling hosting.

The implementation must not expose wallet files, datadir files, logs, params,
configuration files, block files, or arbitrary directories as NFT content.

## GUI behavior

The GUI should be fast and clear:

- Market loads from local index immediately.
- Cards show verified state: offer valid, NFT UTXO live, seller signature valid,
  name binding valid, manifest hash known, mirror health known.
- Buy flow reruns verification before spend.
- Sell flow creates a signed offer and optionally publishes it through the local
  node's relay mode.
- Hosting flow starts from an operator-selected local file and shows exactly
  what will be served.
- Mirror flow supports adding backup onion hosts and signing an updated mirror
  set.
- Remote media is never auto-rendered before hash verification.

## Implementation sequence

1. Freeze these requirements and link them from daemon and GUI plans.
2. Add signed content/mirror protocol spec.
3. Add daemon ZNAM indexer, store, and RPCs.
4. Add ZMARKET publish/browse/info RPCs over the existing bounded offerpool.
5. Add market spider/router/index design and then implementation behind
   operator flags.
6. Add GUI tabs and local index status.
7. Add content host allowlist and onion serving behind explicit operator opt-in.
8. Add multi-node regtest and GUI E2E coverage.

## Release gates

Beta7 cannot ship this platform unless:

- no consensus files are changed for platform behavior;
- tests prove files are not written to chain records;
- tests prove content hosting is allowlist-only;
- tests prove invalid signed offers and forged mirror records do not index;
- tests prove the GUI never auto-hosts or auto-fetches arbitrary media;
- multi-node market browse works without a central server;
- Linux/Windows/macOS release artifacts pass the existing beta release gates.
