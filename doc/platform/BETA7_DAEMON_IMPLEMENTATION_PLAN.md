# ZClassic v2.1.2-beta7 - Daemon Implementation Plan

**Status:** beta7 daemon plan, created 2026-06-09.
**Scope:** `/home/rhett/github/zclassic` only. This is the daemon-side plan for ZNAM, ZMARKET, embedded Tor, and voluntary NFT file availability. The Qt wallet repo is out of scope here.

This file is the coordination point for beta7 daemon implementation. Do not create a parallel beta7 platform plan with a similar name.

---

## 0. Non-negotiable rules

These rules apply to every milestone below:

1. **No ZClassic consensus changes.** ZNAM, ZSLP/NFT, ZMARKET, Tor reachability, and any file-availability feature are non-consensus overlays, local indexes, RPCs, P2P messages, or opt-in services. They must not change block validity, proof of work, script verification, mempool acceptance, or mining rules.
2. **No files are stored on-chain.** The chain may contain small bounded OP_RETURN records, token ids, names, addresses, signatures, and 32-byte fingerprints. NFT images, videos, manifests, and arbitrary file bytes stay off-chain.
3. **Nodes never auto-host arbitrary or random files.** A stock node must never fetch `documentUrl`, scan a cache, mirror IPFS, relay media bytes, or serve files just because it saw an NFT, offer, name, or URL.
4. **Node operators explicitly choose every file/object they host.** This includes their own NFT images. Minting, owning, listing, buying, resolving a ZNAM name, or enabling Tor must not silently publish the related media.
5. **Default posture is non-hosting.** `-nftmarket` is default off in the current daemon branch; embedded Tor is opt-in via `-embeddedtor`; any future NFT file-hosting switch must also be default off and per-object opt-in.
6. **No central marketplace party.** Listing, buying, selling, offer discovery, routing, spidering, and indexing must be possible from the user's own daemon. Any remote peer, seed, archive, or route is untrusted and optional; the local node validates signed offers before storage, display, routing, or purchase.

Repeat the rule when adding code: **no consensus change, no on-chain files, no automatic hosting, explicit operator choice per hosted object.**

---

## 1. Ground truth from the current tree

### ZNAM

Current state:

- `src/znam/znam.{h,c}` and `src/znam/znammsg.{h,cpp}` exist.
- `src/gtest/test_znam.cpp` is wired and the handoff reports 22/22 parser/bridge tests green.
- `doc/platform/ZNAM_DETERMINISM_SPEC.md` is the current authoritative spec.
- `BETA7_HANDOFF.md` says ZNAM indexer/store/RPC/wallet are not started.

Important reconciliation:

- `doc/platform/DECENTRALIZED_PLATFORM_BLUEPRINT.md` still describes an older holding-UTXO ZNAM shape in places.
- The current parser and `ZNAM_DETERMINISM_SPEC.md` use **vin[0] P2PKH signer ownership**.
- Beta7 daemon work must follow `ZNAM_DETERMINISM_SPEC.md` unless the owner explicitly changes that spec.

ZNAM is non-consensus. It must never reject blocks or transactions. Invalid or unauthorized records are ignored by the ZNAM indexer.

### ZMARKET

Current state:

- Offer blob hardening exists in `src/rpc/nftoffer.{h,cpp}` with bounded strings and `NFT_OFFER_MAX_VIN`.
- RAM-only offerpool exists in `src/nft/offerpool.{h,cpp}`.
- Five dedicated NFT marketplace P2P messages exist: `nftinv`, `getnftoffer`, `nftoffer`, `getnftinv`, `nftabort`.
- The P2P handlers are gated by `NftMarketActive()`, require `-nftmarket`, avoid IBD, rate-limit peers, verify offers before insert, and do not route through `CInv`.
- `-nftmarket` is currently default off in `src/init.cpp`.

Missing beta7 surface:

- Publish/browse/get/offerpool RPCs from `doc/nft/MARKETPLACE_DESIGN.md` are not complete as a user-facing ZMARKET surface.
- Name-to-offer binding is not complete: "listed by alice.zcl" must be proven by a signature from the current ZNAM owner key, never by coin co-location.
- The current branch is RAM-offerpool first. The owner requirement expands beta7 to include operator-controlled market spider/routing/index modes so a wallet can compile a high-performance marketplace from its own daemon without trusting a central party.
- Durable local market index storage is not yet implemented. It must be derived, wipeable, bounded, and fed only by verified signed offers.
- Tor/default-on convergence is not ready. Relaying offers over clearnet remains explicit opt-in.

ZMARKET is non-consensus. It adds no on-chain listing beacon and no media channel. It carries bounded signed offer blobs only. Storing a bounded signed offer in a local market index is not file hosting and is not consensus state.

### Embedded Tor

Current state:

- `src/torembed.{h,cpp}` exists and `-embeddedtor` is opt-in.
- T1/T2 and Tor v3 identity work are present, including gtests in `src/gtest/test_torembed.cpp` and `src/gtest/test_torv3_identity.cpp`.
- `init.cpp` sets embedded Tor control/SOCKS ports and an onion-only advertise guard when `-embeddedtor` is active.

Missing beta7/T3 surface:

- Full BIP155 ADDRv2 is not complete. `CNetAddr::SerializationOp` still serializes legacy address bytes; BIP155 sendaddrv2/addrv2 negotiation and peers.dat migration remain blockers.
- `getnetworkinfo` does not yet expose the full Tor state object described in `doc/net/EMBEDDED_TOR_BLUEPRINT.md`.
- The dynhost HTTP beacon is not a safe file or peer transport for beta7. It stays off.

Embedded Tor is transport only. It does not make a node a media host.

### NFT Content And File Availability

Current state:

- ZSLP/NFT stores `document_hash` as a 32-byte fingerprint and `document_url` as a pointer/hint.
- `src/zslp/contentfingerprint.{h,cpp}` exists for content fingerprinting.
- Several NFT docs already say the former ZDC1/on-chain-private-file path was removed.

Hard conclusion:

- **File availability is voluntary.** A hash lets a user recognize correct bytes forever; it does not guarantee that the bytes can be found.
- **The daemon must not auto-fetch or auto-host media.** A node that sees an NFT image hash, URL, offer, or ZNAM CONTENT record hosts nothing unless the operator explicitly adds that object.
- **The operator's own NFT images are not special.** Owning or minting an NFT never implies hosting its image. The operator must explicitly choose to host that image/object too.

---

## 2. Target beta7 architecture

Beta7 daemon architecture has four cooperating but separate surfaces:

1. **ZNAM canonical registry:** confirmed-chain OP_RETURN observer, indexer/store/RPC. Resolves names and ownership locally. No network I/O during resolution.
2. **ZMARKET signed offer market:** opt-in listing/buying/selling RPCs, bounded signed offer validation, operator-controlled spider/routing/relay modes, a local wipeable market index, and optional ZNAM signature binding for human-readable seller identity. No central marketplace party is required or trusted.
3. **Embedded Tor transport:** opt-in daemon reachability over onion. Default off until owner approval. BIP155 is required before onion peer discovery or any default-on market relay claim.
4. **Voluntary NFT file availability:** content-addressed objects served only when an operator explicitly adds each object. No automatic hosting, no random files, no on-chain files, no implicit hosting of an operator's own NFTs.

The four surfaces must not collapse into one another. ZNAM can point at an onion or content fingerprint; ZMARKET can carry a signed offer; Tor can carry connections; file availability can serve selected off-chain bytes. None of those facts authorizes automatic file hosting.

---

## 3. Milestones

### M1 - ZNAM Indexer, Store, RPC

Goal: make ZNAM resolvable from `zclassicd` using deterministic confirmed-chain state.

Deliverables:

- `CZNAMIndexer : CValidationInterface`, modeled on `CZSLPIndexer`.
- `CZNAMStore : CDBWrapper` under `blocks/znam/`, with version stamp, tip marker, name rows, record rows, text rows, owner reverse index, history rows, and LIFO undo.
- `-znamindex` init plumbing, startup catch-up, shutdown, wipe-and-reindex on version bump.
- Owner derivation from `vin[0]` undo data per `ZNAM_DETERMINISM_SPEC.md`: P2PKH or drop.
- Read RPCs: `name_resolve`, `name_info`, `name_list`, `name_history`, `name_listmine`.
- Wallet/build RPCs, if daemon-side wallet scope is accepted: `name_register`, `name_update`, `name_transfer`, `name_renew`, `name_setrecord`, `name_settext`.

Guardrails:

- No ZClassic consensus changes.
- No mempool authority. Confirmed chain only.
- No network fetch during `name_resolve`.
- CONTENT records, if indexed, are opaque values. They do not cause file fetch, file hosting, or media rendering.
- SET_TEXT stays bounded and printable per spec; it is not a file-storage channel.

Tests:

- Parser/bridge tests remain green.
- Indexer/store tests for first-claim ordering, auth, transfer, renew, expiry/grace, SET_TEXT allowlist, P2PKH-or-drop, and reorg undo.
- Cold reindex equals incremental connect/disconnect state.
- RPC tests for not-found, expired/grace, malformed names, pagination, and index-off errors.

Concrete skeleton/API plan:

1. **Header-only prep, no runtime behavior.**
   - Add `src/znam/znamstore.h` and `src/znam/znamindexer.h`.
   - Do not add `src/znam/znamstore.cpp`, `src/znam/znamindexer.cpp`, `-znamindex`, `init.cpp` calls, RPC registration, or wallet spend/build paths in this step.
   - The headers must compile as declarations and document the observer-only contract: confirmed chain only, invalid records ignored/no-op, CONTENT opaque, no file fetch/host side effects.
2. **Store implementation.**
   - Implement `CZNAMStore` over `CDBWrapper` at `GetDataDir()/blocks/znam`.
   - Keys match `ZNAM_DETERMINISM_SPEC.md` section 10: `n`, `r`, `x`, `h`, `o`, `u`, `T`, `V`.
   - Write one LIFO undo stream per connected block. Reorg disconnect must restore name rows, primary records, SET_RECORD rows, SET_TEXT rows, owner reverse rows, history rows, and tip marker exactly.
   - `ApplyRecord(const ZNAMMessage&, ownerAddr, txid, height, txIndex, blockHash)` returns DB commit success. Parser-invalid records never reach it; ownerless or unauthorized records are deterministic no-ops and never block-invalid.
3. **Indexer implementation.**
   - Implement `CZNAMIndexer::ParseTx` to scan outputs in ascending vout order and honor the first `ZNAMParseScript`-accepted script only.
   - `ConnectBlock` skips coinbase and indexes non-coinbase transactions in block order using `(height, txIndex)` as authority.
   - Owner derivation is from confirmed `vin[0].prevout` only. The testable seam `ExtractP2PKHOwnerFromScript` accepts standard transparent P2PKH and drops P2SH, multisig, coinbase/null prevout, non-standard, and unresolved prevout.
   - Startup catch-up, tip hand-off, interrupt/join, and unregister behavior should mirror `CZSLPIndexer`, but remain behind an explicit future `-znamindex` gate.
4. **Read RPC implementation.**
   - Add read-only RPCs after the index is functional: `name_resolve`, `name_info`, `name_list`, `name_history`, `name_listmine`.
   - Every RPC fails closed with an index-off/syncing error when `g_znamIndexer` or its store is unavailable.
   - `name_resolve` performs no network I/O and never fetches CONTENT values. It returns active records only; grace/expired/unregistered names resolve to nothing.
5. **Wallet/build RPC implementation, if accepted.**
   - Builders may use `ZNAMBuild*` bridge helpers and normal transaction creation.
   - Broadcast must not depend on mempool ownership authority. Final authority remains confirmed-chain index state.
   - No wallet spending changes outside explicit name command builders.
6. **Verification gate before enabling.**
   - Keep `src/gtest/test_znam.cpp` parser/bridge tests green.
   - Add store/indexer tests for FIFS, auth no-op, transfer, renew, expiry/grace, SET_TEXT allowlist/delete, owner P2PKH-or-drop, first-parseable-vout selection, CONTENT opacity, reorg LIFO undo, and cold reindex equivalence.
   - Diff review must confirm no consensus, main validation, mempool, wallet spend, network fetch, or file-host path changed.

### M2 - ZMARKET Signed Offers, Local Market Index, Spidering, Routing

Goal: let wallets list, buy, sell, browse, and build a high-performance local marketplace from their own daemon, with no central party and without weakening the non-hosting posture.

Operator-controlled modes:

- **Market off:** default. The daemon may still verify or take a pasted/direct `offerBlob`, but it does not spider, route, relay, serve, or index network offers.
- **Market local/index:** the daemon accepts explicit local imports and wallet-created listings, validates signatures, and stores a bounded local market index for fast GUI queries. No peer relay.
- **Market spider:** the daemon actively asks opted-in peers for offer inventories, fetches unknown bounded offers, validates them, and adds them to the local index. It does not re-announce unless relay is also enabled.
- **Market relay/router:** the daemon serves inventories/offers to peers and routes valid offers onward. This is operator opt-in and remains blocked from default-on until Tor/BIP155/consent gates are satisfied.
- **Market publisher:** a seller explicitly publishes a locally created signed offer. Publishing an offer is not media hosting and does not publish NFT image bytes.

Implementation may collapse these into fewer flags initially, but the user-visible behavior must preserve the distinction: local indexing, spidering, routing/relay, and publishing are explicit operator/user choices.

Deliverables:

- **Signed offer envelope:** wrap the existing `CNftOfferBlob` with routing/index metadata that is bounded and signed or hash-bound. The existing atomic swap blob remains the settlement core.
- **Local market store:** a derived, wipeable, bounded store such as `CMarketStore : CDBWrapper` under a market-specific datadir. It may persist verified signed offers and small metadata needed for fast local browse. It is not consensus, not authoritative, and can be deleted/rebuilt from spidered/imported offers.
- **RAM read model:** a high-performance in-memory market view rebuilt from the local market store and live offerpool, indexed by token id, collection/group id, seller/name proof, price, expiry, first-seen height/time, and liveness status.
- **Publish/import RPCs:** `nft_publishoffer`, `nft_importoffer`, `nft_unpublishoffer` or equivalent. Each re-runs `NftVerify`, checks signature/PoW/TTL/caps, and updates the local market store.
- **Browse/search RPCs:** `nft_browseoffers`, `nft_searchoffers`, `nft_getoffer`, `nft_offerpoolinfo`, `nft_marketstatus`, and `nft_marketroutes` or equivalent. These are the daemon-side GUI surface; no GUI repo changes are part of this task.
- **Buy/sell RPC flow:** existing `nft_makeoffer`, `nft_verifyoffer`, `nft_takeoffer`, `nft_canceloffer`, `nft_requestbuy` remain the settlement primitives. New market RPCs wrap them for listing, publishing, browsing, and local indexing, but money-moving flows still re-run `NftVerify` at buy time.
- **Routing/spider engine:** periodically performs bounded `getnftinv` / `getnftoffer` pulls from opted-in peers, dedupes by full offer hash, verifies before storage, and records route/peer health locally. Spidering must be cancellable, rate-limited, and disabled by default.
- **Router policy:** relay only offers that pass local validation, caps, TTL, and PoW. Do not route media. Do not route arbitrary blobs. Do not route an offer that is dead, expired, over cap, hash-mismatched, structurally invalid, or missing required signatures.
- **CLI argument conversion entries and help text.**
- **Signed-name fields:** optional "listed by <name>" fields such as `znamName`, `znamSignature`, `znamSigExpiry`, or an equivalent adjacent metadata wrapper.

Signed listing rule:

- The offer identity is the full serialized offer hash.
- The "listed by name" badge is valid only when the offer carries a signature over a domain-separated message such as `ZMARKET-offer-v1 || offerHash || name || sigExpiry`.
- The signature verifies against the current ZNAM owner P2PKH address at the verification tip.
- The seller's spending coins are never co-located with the name owner key just to prove identity.

Signed offer validation:

- Deserialize only after enforcing body size caps.
- Compute `offerHash = SHA256(serialized offer/envelope)` and require any advertised id to match.
- Run `NftVerify` under `cs_main` before local-store insert, route, relay, display as buyable, or purchase.
- Verify optional ZNAM seller-name signatures against the current owner at the validation tip.
- Verify optional buyer/seller request signatures for negotiated offers when present.
- Classify failures: structural/cryptographic failures can ban-score; transient state failures such as spent/expired/reorged offers are dropped without treating the peer as malicious.

Caps, PoW, and TTL:

- Keep the existing per-offer body cap and bounded string caps.
- Keep total offer count, total bytes, and per-token caps in RAM.
- Add a disk cap for any local market store; when full, reject new network offers before evicting operator-owned or locally published offers.
- Every network-imported offer must have a short TTL derived from `expiryHeight`, envelope expiry, or both. Expired offers are pruned from RAM and local store.
- Add an optional Hashcash-style PoW field to the signed offer envelope or route metadata before relay default-on. The PoW is non-consensus and only gates local storage/routing. It must be cheap to verify, difficulty-tunable, and covered by tests.
- Per-peer spider budgets: cap inventory count, outstanding fetches, bytes per interval, and failed-verify rate. A peer cannot make the node fill disk or spend unbounded CPU.
- Route records are advisory and local only. They help the daemon choose good peers; they are not proof that an offer is valid.

Local index storage:

- The local market store is a derived cache, not source of truth.
- It stores bounded signed offers and small browse metadata, not media files.
- It can be wiped without losing chain state or wallet funds.
- It must record schema version, disk usage, last prune time, and degraded/rebuild state.
- Startup must prune expired/dead offers before serving GUI browse results.
- Every displayed offer remains subject to live revalidation before buy.

Routing/spider policy:

- Spidering is opt-in and peer-to-peer. There is no project-operated required endpoint.
- `getnftinv` and `nftinv` are hints only. Unknown hashes are fetched only within budget.
- `nftoffer` is accepted only after size cap, deserialize cap, hash match, signature/PoW checks, and `NftVerify`.
- Spidered offers are stored only if they pass local admission policy.
- Relay mode re-announces valid offers to peers that do not appear to know them. Index-only mode does not re-announce.
- Nodes should prefer onion routes once BIP155 is complete, but Tor remains transport and does not change offer validity.

GUI RPC surface, daemon side only:

- `nft_marketstatus`: modes, caps, disk usage, offer counts, spider state, relay state, Tor gate state, and sync/IBD reasons.
- `nft_browseoffers`: paginated, sorted by price/expiry/firstSeen, with filters for token id, group id, seller name, max price, min confirmations, and live-only.
- `nft_searchoffers`: local index search over token/name/ticker/group metadata already known to the daemon; no remote query required.
- `nft_getoffer`: full verified listing details plus current liveness and name-signature status.
- `nft_publishoffer`: publish a wallet-created or imported signed offer according to current mode.
- `nft_unpublishoffer`: stop local publication/routing and optionally issue `nftabort` after chain-confirmed cancel/spend.
- `nft_routeoffer` / `nft_spideroffers` or equivalent debug/admin RPCs can exist, but user-facing GUI should use the status/browse/publish calls.

C hot-path module layout:

Marketplace spidering, routing, indexing, envelope admission, TTL, caps, and PoW checks should be implemented as C hot-path modules with thin C++ daemon bridges. Mirror the current `zslp/slp.c` and `znam/znam.c` pattern: pure C handles protocol bytes and deterministic policy; C++ handles daemon state, locks, LevelDB, P2P sockets, RPC JSON, wallet verification, and ZNAM signature lookup.

Concrete layout:

- `src/zmarket/zmarket.h` / `src/zmarket/zmarket.c`
  - Pure C signed-offer envelope parser and canonical serializer.
  - Enforces field caps, required fields, version, TTL fields, no trailing bytes, and no arbitrary payload field.
  - Computes or accepts the canonical byte span that the C++ bridge hashes as `offerHash`.
- `src/zmarket/zmarket_pow.h` / `src/zmarket/zmarket_pow.c`
  - Pure C Hashcash/PoW verifier over the canonical offer hash or envelope preimage.
  - No chain access and no wall-clock. It receives difficulty/now-height inputs from the bridge.
- `src/zmarket/zmarket_policy.h` / `src/zmarket/zmarket_policy.c`
  - Pure C admission decisions for caps, TTL, route budget, spider budget, per-token counts, and failure classes.
  - Inputs are small POD structs; outputs are enum reasons such as accept, reject_oversize, reject_expired, reject_pow, reject_rate, reject_duplicate.
- `src/zmarket/zmarket_index.h` / `src/zmarket/zmarket_index.c`
  - Pure C compact market read-model primitives: row projection, sortable keys, filter predicates, and pagination over caller-provided arrays.
  - No STL, no LevelDB, no RPC JSON, no file I/O. The C++ bridge owns allocation/storage and calls the C routines for hot filtering/sorting.
- `src/zmarket/zmarket_route.h` / `src/zmarket/zmarket_route.c`
  - Pure C route/spider state transitions over bounded peer/offer counters: inventory admission, request scheduling, retry/backoff, route scoring, and token-bucket math.
  - No `CNode`, no sockets, no `cs_main`; the C++ net bridge maps daemon peers to small C route structs.
- `src/zmarket/zmarketmsg.h` / `src/zmarket/zmarketmsg.cpp`
  - Thin C++ bridge like `znam/znammsg.cpp`.
  - The only translation unit that includes the C headers inside `extern "C"` if needed.
  - Converts between C POD structs and daemon types (`uint256`, `std::string`, `CDataStream`).
- `src/zmarket/zmarketstore.h` / `src/zmarket/zmarketstore.cpp`
  - Thin C++ store bridge using `CDBWrapper`.
  - Persists bounded verified offer envelopes and compact metadata. Delegates admission/filter/sort decisions to the C modules.
- `src/zmarket/zmarketindexer.h` / `src/zmarket/zmarketindexer.cpp`
  - Thin C++ owner of lifecycle, locks, scheduler hooks, and rebuild into RAM.
  - Uses `zmarket_index.c` for hot local browse/search projection.
- `src/rpc/zmarket.cpp`
  - Thin RPC surface that calls the C++ bridge and returns `UniValue`.
- `src/gtest/test_zmarket_*.cpp`
  - GTest wrappers around the C modules and bridge behavior.

C header rules:

- C headers include only C standard headers (`stdint.h`, `stdbool.h`, `stddef.h`, `string.h` when needed) and project C helpers.
- C headers must have `extern "C"` guards for C++ inclusion.
- C modules must not include `main.h`, `net.h`, `uint256.h`, `dbwrapper.h`, wallet headers, `univalue`, Boost, or STL headers.
- C modules must not allocate unbounded memory. Prefer caller-provided buffers/arrays and explicit capacities.
- C modules must return enum status codes and fill caller-provided output structs. No exceptions, no asserts on network input.
- C modules must be deterministic from explicit inputs. No wall-clock reads, no random, no global daemon config.

C++ bridge responsibilities:

- `CDataStream` encode/decode, network message framing, and pre-deserialize body-size checks.
- `uint256` conversion and hashing if the C module only returns canonical byte ranges.
- `NftVerify` under `cs_main` and live UTXO checks.
- ZNAM owner lookup and `signmessage`/`verifymessage` style signature verification.
- `CDBWrapper` persistence and schema/version handling.
- Peer mapping (`CNode` to C route state), scheduler callbacks, locks, logging, and ban-score decisions.
- RPC JSON, help text, CLI conversions, and GUI-facing output shapes.

Build integration:

- Add C headers to `BITCOIN_CORE_H` in `src/Makefile.am`, next to `zslp/slp.h`, `zslp/op_return_push.h`, `znam/znam.h`, and `znam/znammsg.h`.
- Add pure C hot-path files (`zmarket/zmarket.c`, `zmarket/zmarket_pow.c`, `zmarket/zmarket_policy.c`, `zmarket/zmarket_index.c`, `zmarket/zmarket_route.c`) to `libbitcoin_common_a_SOURCES`, next to `zslp/slp.c` and `znam/znam.c`.
- Add C++ bridges (`zmarket/zmarketmsg.cpp`, `zmarket/zmarketstore.cpp`, `zmarket/zmarketindexer.cpp`, `rpc/zmarket.cpp`) to `libbitcoin_server_a_SOURCES`.
- Keep wallet-dependent settlement verification in C++ bridge code guarded by `ENABLE_WALLET`; do not hide the pure C parser/policy modules behind wallet-only compilation unless unavoidable.
- Add GTest sources to `src/Makefile.gtest.include`, for example `gtest/test_zmarket_c.cpp`, `gtest/test_zmarket_policy.cpp`, `gtest/test_zmarket_route.cpp`, `gtest/test_zmarket_store.cpp`, and `gtest/test_zmarket_rpc.cpp`.
- If a C module needs a hash primitive and no C-safe project wrapper exists, pass precomputed hashes from the C++ bridge rather than including C++ crypto classes in C.
- Keep all new C module names under `src/zmarket/` so ZMARKET does not sprawl into `src/nft/` beyond the existing `nft/offerpool` compatibility layer.

Guardrails:

- No ZClassic consensus changes.
- No on-chain listing beacon.
- No files in offer blobs. Offer blobs are bounded structured swap messages only.
- No media bytes, thumbnails, manifests, or arbitrary payload fields in ZMARKET gossip.
- No central party. Wallets query their own daemon's local market index.
- `-nftmarket` remains default off until Tor/BIP155 and operator-consent gates are satisfied.
- A stock node hosts no order book, spiders no market, relays no offers, and serves no files by default.
- Local market indexing is not file hosting. It stores bounded signed offers, not NFT images.

Tests:

- RPC publish rejects invalid, stale, oversized, hash-mismatched, structurally forged, or index-off offers.
- Browse/list APIs are bounded and deterministic.
- Name signature tests: valid owner signature accepted; stale signature rejected; wrong owner rejected; reorg/name-transfer changes validation result correctly.
- Local store tests: wipe/rebuild, schema mismatch, disk cap, TTL prune, dead-vin prune, startup degraded state, and buy-time revalidation.
- PoW tests: missing/weak PoW rejected by relay policy when required; valid PoW accepted; difficulty can be raised without changing consensus.
- Spider tests: inventory caps, fetch budget, dedupe-before-verify, route health, index-only mode does not re-announce, relay mode re-announces only valid offers.
- Multi-node regtest: seller publishes, spider/index node builds a local market, relay relays only when opted in, buyer browses from its own daemon and takes, filled offer self-evicts everywhere that sees the spend.

### M3 - Embedded Tor Opt-In And BIP155 Gate

Goal: make onion transport safe enough to support market relay and future file availability without overclaiming.

Deliverables:

- Keep `-embeddedtor` opt-in. Do not silently enable it.
- Finish BIP155 ADDRv2 stages:
  - version-gated `sendaddrv2` / `addrv2` negotiation;
  - `CNetAddr` / `CAddress` serializer carrying tor v3 32-byte identity;
  - peers.dat/addrman format migration;
  - per-peer `fSendAddrV2` state;
  - canary tests for v3 onion round-trip and addrman retention.
- Expose Tor state in `getnetworkinfo`: compiled/available, enabled, state, bootstrap percent, onion, control/SOCKS ports, inbound onion peers, and gate reasons.
- Keep dynhost HTTP beacon off for beta7. No unauthenticated Tor HTTP server in the wallet-key process.

Guardrails:

- No ZClassic consensus changes.
- Tor does not imply file hosting.
- Tor does not imply market relay. Market relay still requires `-nftmarket=1`.
- Tor does not imply media serving. Future media serving requires an explicit file-host gate and explicit per-object add.
- Default-on market relay is blocked until BIP155 is complete, onion-only relay has soaked, and the operator consent gate exists.

Tests:

- Existing `TorEmbed.*` and `TorV3Identity.*` tests remain green.
- New BIP155 serialization tests prove v3 onions survive wire and peers.dat round-trips.
- Old peers continue to receive legacy address format.
- DEANON guard tests prove the node does not advertise clearnet and onion self-addresses together.

### M4 - Voluntary NFT File Availability Scaffolding

Goal: define the daemon-side shape for making NFT image/file bytes available without turning nodes into automatic media hosts.

Recommended beta7 cut:

- Ship docs and inert/scaffolded RPC shape first.
- Do not serve bytes publicly until BIP155 and Tor hardening are complete.
- If any beta7 byte-serving code is added, keep it behind a new default-off gate and per-object opt-in.

Required model:

- A hosted object is keyed by content fingerprint, normally the NFT `document_hash`.
- An operator adds a local file/object explicitly, for example with a future RPC shape such as:
  - `nft_hostfile_add { "tokenId": "...", "documentHash": "...", "path": "...", "label": "..." }`
  - `nft_hostfile_remove { "documentHash": "..." }`
  - `nft_hostfile_list`
  - `nft_fileavailability { "tokenId": "...", "documentHash": "..." }`
- The daemon streams and hashes the local file before accepting it. If bytes do not match `documentHash`, the object is rejected.
- The daemon never follows `documentUrl` to fetch a file for hosting.
- The daemon never scans a wallet cache and auto-publishes matches.
- The daemon never auto-hosts a minted NFT's image.
- The daemon never auto-hosts an owned NFT's image.
- The daemon never auto-hosts arbitrary/random files found in a directory.

Serving gate, if implemented:

- Requires explicit global opt-in, e.g. a future `-nftfilehost=1`.
- Requires explicit per-object opt-in by RPC/config.
- Requires `-embeddedtor=1` and completed BIP155 if serving to the network.
- Serves only content-addressed chunks for selected hashes.
- Applies size caps, chunk caps, read timeouts, per-peer rate limits, and bounded disk accounting.
- Does not mix with ZMARKET offer gossip. Offers are offers; files are files.
- Logs every add/remove decision and reports the exact selected object count.

Operator posture:

- Stock node: hosts no files, relays no market offers, may index public chain data.
- Market relay: opt-in `-nftmarket`, stores bounded RAM offers, hosts no media.
- File host: opt-in file-host gate plus explicit selected objects. Even the operator's own NFT image must be selected object-by-object.

Tests:

- Add rejects wrong hash, missing file, directory path, symlink escape if disallowed by policy, oversize object, and index-off ambiguity.
- Startup with no file-host config hosts zero objects.
- Minting an NFT hosts zero objects.
- Owning an NFT hosts zero objects.
- Enabling `-embeddedtor` hosts zero objects.
- Enabling `-nftmarket` hosts zero objects.
- Only explicit `nft_hostfile_add` increases hosted count.

### M5 - Integrated Verification And Release Gate

Goal: prove the beta7 daemon surfaces compose without violating the rules in section 0.

Required checks:

- Full daemon build and `zcash-gtest` in the proot build tree.
- ZNAM parser, indexer/store, RPC tests.
- ZMARKET offerpool, P2P, RPC, signed listing tests.
- Tor embed and BIP155 tests.
- File availability negative tests proving no automatic hosting.
- Multi-node regtest:
  - node A registers a ZNAM name;
  - node A makes and publishes a signed offer;
  - opt-in spider/index node builds a local market from peer offers;
  - opt-in relay node routes the offer;
  - buyer browses its own daemon's local market, verifies signature, and takes the offer;
  - no node serves media unless an explicit file-host object was added;
  - disabling market index/spider stops market discovery without breaking direct pasted-offer buy;
  - disabling `-nftmarket` stops offer relay;
  - disabling file-hosting stops all file serving while indexes and market reads still work.

Diff review checklist:

- No consensus or PoW changes.
- No data-carrier size changes.
- No new on-chain file bytes.
- No automatic file fetch/host path.
- Every network-facing payload is bounded before deserialize or before storage.
- Every market offer is signed/hash-bound and revalidated before display as buyable.
- Spidering/routing/indexing modes are operator-controlled and default off unless explicitly approved.
- Every operator role is default-off unless it is read-only indexing.

---

## 4. Decisions To Carry Forward

1. **ZNAM beta7 follows `ZNAM_DETERMINISM_SPEC.md`, not older holding-UTXO text.** Current implementation and handoff point to vin[0] P2PKH ownership.
2. **ZMARKET identity binding is signature-based.** "Listed by alice.zcl" is a signature by the current ZNAM owner key, not a spend from the same coins.
3. **Market participation is mode-based and operator-controlled.** Listing, buying, selling, local indexing, spidering, routing, and relay are separate behaviors even if early implementation shares a flag.
4. **No central marketplace party.** Wallets compile the marketplace from their own daemon's local verified index. Remote peers provide untrusted signed offers only.
5. **ZMARKET hot paths are C modules.** Spidering, routing, indexing, envelope admission, TTL, caps, and PoW policy live in pure C modules; daemon C++ remains a thin bridge for state, locks, P2P, RPC, wallet verification, and storage.
6. **Market relay remains opt-in until Tor/BIP155 and consent gates are done.** `-nftmarket` default off is the right beta7 posture.
7. **Embedded Tor is opt-in transport, not automatic hosting.** `-embeddedtor` does not host files, media, or arbitrary content.
8. **No dynhost HTTP beacon for beta7 file availability.** It stays off until the HTTP parser/demo-handler surface is separately hardened or replaced.
9. **NFT file availability is voluntary and content-addressed.** The daemon can help an operator serve selected verified bytes, but it must never become a crawler, mirror, CDN, or arbitrary file host by default.
10. **Each hosted object requires explicit operator action.** This applies to all objects, including the operator's own minted or owned NFT images.

---

## 5. Open Owner Decisions

- Confirm ZNAM non-consensus policy constants in `ZNAM_DETERMINISM_SPEC.md` before mainnet activation.
- Decide whether beta7 should implement actual file byte serving or only ship the daemon-side plan/scaffold and negative tests. Recommendation: scaffold first; byte serving only after BIP155 and explicit file-host consent are complete.
- Decide final RPC names for file-hosting if it enters beta7. Recommendation: keep names explicit (`nft_hostfile_*`) so operators understand they are choosing hosted files.
- Decide whether ZMARKET signed-name fields live inside the offer blob or as an adjacent publish wrapper. Recommendation: keep the atomic swap blob stable and carry name proof as an adjacent, signed metadata wrapper verified before display.
- Decide final market mode flags. Recommendation: preserve separate semantics for local index, spider, relay/router, and publisher even if implementation starts with fewer flags.
- Decide local market store backend. Recommendation: use `CDBWrapper` plus RAM secondary indexes first to avoid a new dependency; keep the store wipeable and bounded.
- Decide PoW threshold and TTL defaults for network-imported offers. Recommendation: start conservative and tune from soak without changing consensus.
- Decide whether `-znamindex` defaults on in beta7 or stays opt-in until mainnet activation constants are signed off. Recommendation: default off until release criteria are green, then revisit.

---

## 6. Short Rule For Implementers

Before adding any beta7 daemon code, ask:

- Does this change ZClassic consensus, validation, PoW, mempool acceptance, or data-carrier limits? If yes, stop.
- Does this put file bytes on-chain? If yes, stop.
- Does this make a node fetch, mirror, host, or relay arbitrary file bytes automatically? If yes, stop.
- Did the operator explicitly choose this exact file/object to host? If no, do not host it.
- Does this depend on a central marketplace server or trusted indexer? If yes, redesign so the local daemon verifies and indexes signed offers itself.
- Is spidering/routing/indexing enabled by the operator and bounded by caps/TTL/PoW/rate limits? If no, do not start it.
- Does the feature still work as a local index/read path when hosting and market relay are off? It should.

The safe default is always: **index locally, verify deterministically, host nothing unless explicitly selected.**
