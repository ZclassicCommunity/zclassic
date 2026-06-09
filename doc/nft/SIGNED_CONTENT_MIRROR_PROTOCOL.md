# ZClassic NFT Signed Content Manifest and Mirror Protocol

Status: NORMATIVE DESIGN.
Scope: off-chain NFT content discovery, signed content manifests, signed mirror records,
and opt-in onion content hosting for ZClassic NFTs.

This document edits no source. It defines the protocol and the guardrails an implementation
must satisfy before any wallet, daemon, or mirror service handles NFT content bytes.

---

## 1. Hard Invariants

These are blocking. A design or implementation that violates any item does not ship.

1. **No file bytes on-chain.** The chain may contain only the existing ZSLP metadata fields:
   `document_hash` as a 32-byte content anchor and, optionally, a short `document_url`
   pointer or manifest hash. The chain must never contain file chunks, complete files,
   encrypted file payloads, thumbnails, or mirror lists.
2. **No generic node file hosting.** `zclassicd` and ordinary full nodes must not host
   random or arbitrary files. Content serving is a separate, disabled-by-default mirror
   role and serves only locally pinned, hash-verified content objects.
3. **Operator choice is required.** A node or wallet cache must never become public just
   because it viewed, minted, downloaded, or verified an NFT. Hosting requires an explicit
   local operator action that names the content root or manifest and accepts local quotas.
4. **Mirrors are untrusted.** A mirror is only a byte source. Every manifest, chunk, poster,
   and whole file is verified against signed records and SHA-256 chunk/file anchors before
   it is cached as valid or rendered.
5. **Multiple onion mirrors are first-class.** One content object may have many independent
   signed mirror records. Clients support backup `.onion` mirrors and fail over by chunk.
6. **No automatic remote fetch.** The daemon indexer performs no outbound content I/O.
   Wallets and clients fetch remote content only after an explicit user action or explicit
   operator policy.
7. **No consensus changes.** Nothing here changes transaction validity, relay policy,
   mempool acceptance, PoW, or block validation. This is a non-consensus content layer.
8. **Hot paths are C, bounded, and byte-canonical.** Spidering, routing, and indexing of
   signed offers, manifests, mirror records, and mirror bundles must use C-friendly fixed
   record shapes, deterministic canonical bytes, explicit caps, and fail-closed parsers.
   C++/Qt code may call the C engine but must not invent a second parser for routing.
9. **Marketplace routing is not content hosting.** Operators may opt into spidering and
   routing signed NFT buy/sell/list offers without hosting any content. Content hosting
   remains explicit per-file or per-content-root allowlist only.

---

## 2. Roles and Trust Boundaries

- **Minter / publisher:** creates the NFT and signs a content manifest. A publisher
  signature is an attestation by that key, not protocol-guaranteed authenticity.
- **Holder / viewer:** verifies the token's confirmed ZSLP state locally, then verifies
  content bytes against the token's `document_hash`.
- **Mirror operator:** opts in to serving a specific content object over an onion service
  and signs a mirror record for that object.
- **Mirror:** an untrusted transport endpoint. It may be offline, slow, malicious, stale,
  or legally/policy denied by the local operator.
- **Full node indexer:** indexes ZSLP ownership and metadata. It never fetches or serves
  NFT content as part of indexing.
- **Marketplace router / spider:** an opt-in node role that accepts, verifies, TTL-indexes,
  and re-routes signed NFT offer records. It does not custody funds, match orders, settle
  trades, or host media.

The security property is:

```
confirmed token document_hash == signed manifest content_root
signed manifest content_root  == verified Merkle/file hash of downloaded bytes
```

Signatures identify who made a claim. Hashes decide whether bytes match.

---

## 3. On-Chain Binding

For a mirrorable NFT, the ZSLP GENESIS uses the existing fields only:

- `document_hash`: exactly 32 bytes. For signed mirrored content this is the content
  root from the `ZCM1` manifest body.
- `document_url`: optional. Recommended values are:
  - empty, when the manifest is distributed out of band;
  - `zcm1:<64-hex-manifest-body-hash>`, when the chain should name the manifest body;
  - a short `https://` or `http://<onion>/...` locator for the manifest, if it fits the
    existing OP_RETURN budget.

`document_url` is a hint only. It is never fetched by the daemon and never auto-fetched by
the GUI. The authoritative check is always `document_hash == manifest.content_root`.

On-chain mirror lists are forbidden in v1. Backup mirrors are distributed as signed
off-chain mirror records.

---

## 4. Common Encoding Rules

The v1 wire profile uses simple binary records so implementations do not need a JSON or
CBOR canonicalization dependency.

All records are byte-exact:

- Integers are unsigned little-endian: `u8`, `u16le`, `u32le`, `u64le`.
- Hashes are 32 raw bytes, SHA-256 output order.
- Ed25519 public keys are 32 raw bytes; signatures are 64 raw bytes.
- Variable bytes are `u32le length || bytes`, with a field-specific maximum.
- UTF-8 text is stored as variable bytes and must be valid UTF-8, with no NUL bytes and
  no path separators for display filenames. Implementations must not normalize text when
  computing hashes; the exact bytes are signed.
- Vectors are `u32le count || items...`.
- Any unknown nonzero version, duplicate singleton field, trailing bytes, count overflow,
  length overflow, or unsorted vector where sorting is required makes the record invalid.
- Parsers are bounds-checked and fail closed. They must not assert on malformed input.

Domain tags for signatures are ASCII strings:

- Manifest signature domain: `ZCL-ZCM1-MANIFEST-SIGNATURE-V1`
- Mirror record signature domain: `ZCL-ZMR1-MIRROR-SIGNATURE-V1`
- Marketplace offer signature domain: `ZCL-ZOF1-OFFER-SIGNATURE-V1`

For every signed record type:

```
body_hash = SHA256(canonical_body_bytes)
signature_preimage = domain_tag || body_hash
signature = Ed25519_sign(signature_preimage)
```

The body hash excludes signatures, so adding another valid signature does not change the
manifest or mirror record identity.

Signature entries are sorted by `(role, alg, pubkey)` ascending. Duplicate `(role, alg,
pubkey)` entries are invalid.

Signature entry layout:

```
role       u8      1=publisher, 2=publisher-approval, 16=mirror-operator,
                 32=seller-offer, 33=buyer-offer, 34=offer-cancel
alg        u8      1=Ed25519
pubkey     32B
signature  64B
```

---

## 5. C Hot-Path Engine Requirements

The spidering/routing/indexing path for `ZCM1`, `ZMR1`, `ZMB1`, and `ZOF1` records is a
C engine contract.

Required C-engine properties:

- **Parse bytes, not objects.** The C parser takes `(const uint8_t *buf, size_t len)` and
  returns fixed structs containing scalar fields, offsets, lengths, and record hashes.
  No parser result depends on C++ map/vector ordering, JSON object order, locale, Unicode
  normalization, wall clock, filesystem state, or network state.
- **Cap before allocation.** Record length, vector counts, signature counts, text lengths,
  and embedded blob lengths are checked before any allocation or copy. Oversize records
  are dropped before hashing expensive subfields or verifying signatures.
- **Dedupe before verify.** Nodes compute the canonical body hash and reject already-seen
  records before Ed25519 verification or settlement-offer verification.
- **No recursion and no unbounded strings.** All vectors are flat. All variable fields have
  explicit maximums in this document. The hot path does not parse HTML, JSON, XML, SVG,
  URLs beyond fixed onion path components, or arbitrary MIME content.
- **No file I/O in routing parse.** Parsing, validating, indexing, and routing signed
  records does not read or write content files. Content bytes are fetched only by the
  explicit content fetch path and served only by explicit mirror pins.
- **Canonical bytes are the key.** Every routed/indexed record is keyed by
  `SHA256(canonical_body_bytes)`. A semantically equivalent record with different bytes is
  a different record unless the canonical encoder produced the exact same body.
- **Single implementation boundary.** The same C parser and canonical encoder feed daemon
  routing, REST/RPC metadata, GUI marketplace views, and test vectors. C++ wrappers must
  not reinterpret fields independently.
- **Bounded indexes.** Hot-path indexes use fixed-size binary keys:
  `manifest_body_hash`, `content_root`, `mirror_record_hash`, `onion_service_pubkey`,
  `offer_id`, `token_id`, `group_id`, expiry, and price. UI/RPC pages must read through
  bounded secondary indexes, not full scans of all known records.

The C hot path may expose small immutable parsed views to C++ callers, but ownership of the
canonical byte blob and its hash stays with the engine.

Record spidering, if enabled by the operator, is record-only:

- Manifest spidering stores signed `ZCM1` envelopes and indexes by manifest hash, token id,
  and content root.
- Mirror spidering stores signed `ZMR1` envelopes or `ZMB1` bundles and indexes by manifest
  hash, content root, onion service key, and expiry.
- Offer spidering stores signed `ZOF1` envelopes and indexes by token id, group id, price,
  expiry, content root, and manifest hash.
- None of these record spiders fetch chunks, posters, or whole files. None of them add
  content to the hosting allowlist.

---

## 6. Signed Content Manifest (`ZCM1`)

`ZCM1` binds a token, content root, chunk layout, and optional display metadata. It does
not contain file bytes.

### 6.1 Manifest Envelope

```
body_len      u32le
body          body_len bytes, canonical ZCM1 body
sig_count     u32le
signatures    sig_count SignatureEntry values
```

Envelope limits:

- `body_len <= 4 MiB`
- `sig_count <= 16`
- at least one `role=publisher` signature is required for a signed manifest

The manifest identity is:

```
manifest_body_hash = SHA256(body)
```

### 6.2 Manifest Body

Fields appear in exactly this order:

```
magic              4B      "ZCM1"
version            u8      1
chain_id           u8      0=unknown, 1=mainnet, 2=testnet, 3=regtest
token_id           32B     ZSLP genesis txid; all-zero only for pre-mint drafts
content_root       32B     must equal the NFT's on-chain document_hash
root_alg           u8      1=bare_sha256, 2=merkle_sha256_v1
whole_sha256       32B     SHA256 over the complete file bytes
file_size          u64le   exact byte length
chunk_size         u32le   1048576 for merkle_sha256_v1; file_size for bare_sha256
chunk_count        u32le   ceil(file_size / chunk_size), or 1 for an empty file
flags              u32le   bit0=encrypted, bit1=has_poster, bit2=publisher_approved_mirrors_required
media_type         bytes   UTF-8, max 127 bytes, advisory only
display_filename   bytes   UTF-8 basename, max 255 bytes, advisory only
poster_hash        32B     present iff flags bit1, else omitted
chunk_hashes       vector<32B>
```

Rules:

- For an NFT-bound manifest, `token_id` must equal the NFT genesis txid and
  `content_root` must equal the on-chain `document_hash`. If either differs, the
  manifest is not bound to that token.
- A pre-mint draft may use all-zero `token_id`, but clients must display it as
  unbound and must not treat publisher signatures as token-specific.
- `root_alg=bare_sha256` is valid only when `file_size <= 1 MiB`. Then
  `content_root == whole_sha256`. For an empty file, `chunk_count == 0` and
  `chunk_hashes` is empty. For a non-empty file in bare mode, `chunk_count == 1`
  and `chunk_hashes` may be empty. A bare-SHA object can be verified only after
  the complete file is downloaded.
- `root_alg=merkle_sha256_v1` is required for files larger than 1 MiB and recommended
  for any content intended to be mirrored. Then `chunk_size == 1048576`,
  `chunk_hashes.count == chunk_count`, and each chunk is independently verifiable.
- `file_size` may not exceed the v1 interoperable maximum of 64 GiB
  (`chunk_count <= 65536`).
- `media_type` and `display_filename` are untrusted display hints. They must never select
  executable behavior, shell paths, browser rendering, or filesystem write paths.
- The manifest carries no mirror endpoints. Mirrors are added, removed, or replaced by
  independent signed mirror records without changing the NFT's content root.

### 6.3 Merkle Algorithm

For `root_alg=merkle_sha256_v1`:

```
chunk_i  = exact bytes [i * 1048576, min(file_size, (i+1) * 1048576))
leaf_i   = SHA256(0x00 || chunk_i)
parent   = SHA256(0x01 || left || right)
odd node = promoted unchanged to the next level
root     = the single final node
```

The `chunk_hashes` vector stores `leaf_i` values in ascending chunk index order.
The computed Merkle root must equal `content_root`, and the rolling whole-file SHA-256
must equal `whole_sha256`.

Empty files and single-chunk files use `root_alg=bare_sha256` so this protocol
matches `src/zslp/contentfingerprint.{h,cpp}` and the Qt wallet `ContentEngine`
exactly: the on-chain `document_hash` is SHA-256 of the whole file unless there
is more than one 1 MiB chunk, in which case it is the Merkle root.

---

## 7. Signed Mirror Record (`ZMR1`)

`ZMR1` says that an operator intends to serve a specific manifest/content root from a
specific onion service. It does not prove the mirror is honest. It only gives clients an
accountable, signed candidate endpoint whose bytes are still hash-verified.

### 7.1 Mirror Envelope

```
body_len      u32le
body          body_len bytes, canonical ZMR1 body
sig_count     u32le
signatures    sig_count SignatureEntry values
```

Envelope limits:

- `body_len <= 64 KiB`
- `sig_count <= 16`
- exactly one or more `role=mirror-operator` signatures are required
- `role=publisher-approval` signatures are optional and sign the same mirror body hash

The mirror record identity is:

```
mirror_record_hash = SHA256(body)
```

### 7.2 Mirror Body

Fields appear in exactly this order:

```
magic                  4B      "ZMR1"
version                u8      1
chain_id               u8      same values as ZCM1
manifest_body_hash     32B
content_root           32B
mirror_signing_hint    bytes   UTF-8, max 80 bytes, advisory operator label
onion_service_pubkey   32B     v3 onion Ed25519 public key, raw 32-byte value
not_before_unix        u64le   local-time validity hint
expires_unix           u64le   local-time validity hint; 0 means no stated expiry
capabilities           u32le   bit0=chunk_get, bit1=whole_get, bit2=range_get, bit3=poster_get
chunk_size             u32le   must match manifest chunk_size
chunk_count            u32le   must match manifest chunk_count
served_ranges          vector<range>
```

Range layout:

```
start_chunk u32le
chunk_count u32le
```

Rules:

- `manifest_body_hash` and `content_root` must match the selected `ZCM1` manifest.
- `onion_service_pubkey` renders to the mirror's v3 `.onion` address. v1 mirror
  endpoints are onion-only.
- `served_ranges` is sorted by `start_chunk`, non-overlapping, and non-empty. A single
  range `(0, manifest.chunk_count)` means the mirror claims to serve the whole object.
- `capabilities.bit0=chunk_get` is required for Merkle content. `whole_get` and
  `range_get` are optional conveniences.
- If the manifest sets `publisher_approved_mirrors_required`, clients must ignore a mirror
  record unless it contains a valid `role=publisher-approval` signature by a public key
  that also signed the selected manifest.
- Without that flag, clients may still require publisher approval by local policy. A user
  can also explicitly approve a mirror record for local use.
- A mirror record fetched from clearnet is only a candidate. Before downloading content,
  the client must confirm the same `mirror_record_hash` is available from the named onion
  service, unless the operator imported it as a local trusted configuration item.

### 7.3 Canonical Onion Paths

The onion service uses fixed paths. There is no directory listing and no upload endpoint.

```
GET /.well-known/zcl/content/v1/mirrors/<mirror_record_hash_hex>.zmr
GET /.well-known/zcl/content/v1/manifests/<manifest_body_hash_hex>.zcm
GET /.well-known/zcl/content/v1/objects/<content_root_hex>/chunks/<8-hex-index>
GET /.well-known/zcl/content/v1/objects/<content_root_hex>/file
GET /.well-known/zcl/content/v1/objects/<poster_hash_hex>/file
```

Rules:

- Chunk indexes are zero-based, fixed-width eight lowercase hex characters.
- `file` is optional and allowed only when `capabilities.whole_get` is set.
- Chunk responses return exactly the chunk bytes, uncompressed. A mirror must not gzip,
  transcode, resize, watermark, or otherwise transform content bytes.
- HTTP status `404` means not served. `410` means intentionally unpinned. Clients cache
  `410` longer than transient failures.
- Any redirect to clearnet, another onion, a different content root, or a non-canonical
  path is ignored.

---

## 8. Mirror Bundles and Backup Mirrors

A mirror bundle is an untrusted convenience container for many `ZMR1` envelopes. It is not
itself an authority; every contained record is verified independently.

```
magic                 4B      "ZMB1"
version               u8      1
manifest_body_hash    32B
record_count          u32le
records               vector<ZMR1 envelope bytes>
```

Rules:

- `record_count <= 32`
- bundle size `<= 2 MiB`
- every record must match `manifest_body_hash`
- records are sorted by `mirror_record_hash`
- duplicate onion service keys for the same content root are allowed only if the
  `mirror_record_hash` differs by validity window or served ranges; clients keep the newest
  non-expired record by `expires_unix`, then by record hash

Clients may merge candidates from multiple bundles, local operator pins, user imports, and
publisher pages. After validation, the candidate set for one content object is capped at
32 known mirrors and 4 active mirrors.

---

## 9. Decentralized Marketplace Offer Routing (`ZOF1`)

The content/mirror protocol integrates with a decentralized NFT marketplace by routing
signed offer records. Offers are not on-chain records and are not stored in content
manifests. They are signed, TTL-bound, locally indexed, and routable among opted-in nodes
without trusting a central marketplace.

Marketplace routing is independent from content hosting:

- A node may route and index offers without serving any NFT media.
- A content mirror may serve pinned media without routing offers.
- Enabling either role does not enable the other.
- Spidering offers, manifests, or mirror records never imports files into the hosting
  allowlist.

### 9.1 Offer Envelope

`ZOF1` uses the same body/signature envelope pattern:

```
body_len      u32le
body          body_len bytes, canonical ZOF1 body
sig_count     u32le
signatures    sig_count SignatureEntry values
```

Envelope limits:

- `body_len <= 8 KiB`
- complete envelope `<= 12 KiB`
- `sig_count <= 8`
- a sell/listing offer requires at least one `role=seller-offer` signature
- a buy/bid offer requires at least one `role=buyer-offer` signature
- a cancel record requires at least one `role=offer-cancel` signature by the same offer
  key or a key that can prove settlement authority by local policy

The offer identity is:

```
offer_id = SHA256(body)
```

### 9.2 Offer Body

Fields appear in exactly this order:

```
magic                   4B      "ZOF1"
version                 u8      1
chain_id                u8      same values as ZCM1
offer_kind              u8      1=sell_listing, 2=buy_bid, 3=cancel
flags                   u32le   bit0=has_manifest, bit1=has_content_root, bit2=has_name_attestation
token_id                32B     NFT token id the offer concerns
group_id                32B     collection/group id, or all-zero
content_root            32B     NFT content root, or all-zero if not asserted
manifest_body_hash      32B     signed manifest hash, or all-zero if not asserted
price_zat               u64le   ZCL zatoshis; 0 only where offer_kind semantics allow it
quantity                u64le   NFT v1 listings use 1
created_unix            u64le   local-time hint
expires_unix            u64le   required; must be greater than created_unix
ttl_seconds             u32le   expires_unix - created_unix, capped below
settlement_kind         u8      1=existing_zslp_atomic_offer_blob
settlement_hash         32B     SHA256(settlement_blob)
settlement_blob         bytes   max 6144 bytes
route_hint              bytes   UTF-8, max 80 bytes, advisory only
```

Rules:

- `ttl_seconds <= 86400` and recommended default TTL is 21600 seconds. Expired offers are
  not routed, shown, or used for floor calculations.
- `settlement_blob` is the existing bounded atomic-swap offer payload or a future
  owner-approved settlement payload. The routing layer does not settle trades by itself.
- A node must verify `settlement_hash == SHA256(settlement_blob)` before inserting the
  record.
- A node must run the settlement verifier before displaying the offer as actionable.
  Signature validity alone is not enough; the referenced NFT input must still be live and
  the offer must satisfy the existing NFT sell/buy rules.
- `content_root` and `manifest_body_hash`, when nonzero, are indexes and consistency hints.
  They do not make the offer valid unless they match the locally verified NFT metadata.
- `route_hint` is not rendered as trusted text and must not affect routing or settlement.

### 9.3 Spidering, Routing, and Local Indexing

Offer spidering is opt-in per node operator. The default node does not route or index other
people's marketplace offers.

An opted-in router:

1. Receives an `offer_id` inventory or a full `ZOF1` envelope from an onion peer, local RPC,
   or local operator import.
2. Checks length caps and computes `offer_id = SHA256(body)`.
3. Dedupes by `offer_id` before signature or settlement verification.
4. Verifies the required offer signature over the canonical body hash.
5. Drops records outside TTL, above local caps, or denied by token/content/signer policy.
6. Verifies settlement liveness before marking the offer actionable.
7. Inserts only bounded metadata into local indexes: by token id, group id, content root,
   manifest hash, price, expiry, and signer key.
8. Routes inventory for accepted live records to eligible peers under rate limits.

Local offer indexes are derived and disposable. They may be RAM-only or persisted as a
TTL-pruned cache, but they are not consensus state and must be rebuildable from currently
known live records. A central party is not trusted for discovery: any opted-in node can
accept, verify, index, and re-route the same signed bytes.

Routing limits:

- inventory batch `<= 1000 offer_id` values
- get-offer batch `<= 128 offer_id` values
- per-peer accepted offer envelopes per minute: default 120
- per-originator live offers: default 100
- per-token indexed live offers: default 1000
- local offerpool bytes: default 64 MiB
- offer page size returned to UI/RPC: max 100

Offer routing failures never affect content verification. Content mirror failures never
affect offer settlement verification.

### 9.4 Marketplace and Content Boundaries

Marketplace records may reference `content_root`, `manifest_body_hash`, or mirror record
hashes to help buyers find verifiable media, but an offer router must not fetch or host the
content as part of accepting an offer.

If a node operator wants the marketplace node to also serve media for a listed NFT, the
operator must separately pin that exact content object under the content-hosting rules in
this document. No offer, listing, sale, bid, route, or spider event can implicitly add a
file to the mirror allowlist.

---

## 10. Fetch Strategy

The default fetch strategy is conservative and privacy-aware.

1. **Confirm token state.** The client verifies the NFT exists in the confirmed ZSLP ledger.
   For ownership-sensitive UI, use the same confirmation depth rules as the NFT wallet.
2. **Load local content first.** If the complete object or verified chunks already exist in
   the local content-addressed cache, no network request is made.
3. **Resolve the manifest explicitly.** A manifest may come from local cache, a local file,
   a user-pasted onion URL, or an explicit click on a `document_url` hint. The daemon indexer
   does not resolve it.
4. **Verify the manifest.** Check canonical parse, manifest signatures, token binding,
   `content_root == document_hash`, chunk layout, and all local policy deny/allow lists.
5. **Collect mirror records.** Accept only signed `ZMR1` records or `ZMB1` bundles. Validate
   record signatures, optional publisher approval, onion binding, time window, served ranges,
   and local policy.
6. **Select mirrors.** Default mode uses one mirror at a time to avoid telling many mirrors
   what the user is viewing. Fallback uses a different onion when a chunk fails, times out,
   or hashes incorrectly. A user may enable faster multi-mirror mode, capped below.
7. **Fetch by chunk.** For Merkle content, request chunks by index. Verify each chunk length
   and leaf hash before committing it to the local chunk cache. Bad chunks quarantine that
   mirror for the content root.
8. **Verify the final object.** After all chunks are present, recompute the Merkle root and
   whole-file SHA-256. Only then mark the full object verified.
9. **Render only verified bytes.** Posters may render after their own hash verifies. Primary
   content renders only after the required hash check for the display mode has passed.

Fetch failures never weaken verification. They only change which mirror is tried next.

---

## 11. Operator-Controlled Onion Hosting

Content hosting is an explicit mirror role, not ordinary node behavior.

Required controls:

- **Disabled by default.** Installing or running `zclassicd` must not expose any content
  service.
- **Separate consent.** Enabling embedded Tor or onion P2P is not consent to content hosting.
  A content mirror requires its own explicit option and local operator acknowledgement.
- **Separate identity.** The content mirror onion should use a separate onion key from the
  P2P node and from any ZNAM/name onion. Reuse is allowed only after an explicit operator
  acknowledgement because it links roles.
- **Local pins only.** The operator pins a specific `manifest_body_hash` or `content_root`
  and a local verified file/chunk store. The mirror pre-verifies the complete object before
  signing a `ZMR1` record for full-object service.
- **No uploads.** The service has no remote `PUT`, `POST`, import, proxy, or repin API.
  It never accepts content bytes from other peers for hosting.
- **No automatic publishing.** Viewing, downloading, minting, or caching content does not
  publish it. Wallet caches are private unless the operator explicitly imports them into the
  mirror pin set. Marketplace offer spidering also does not publish content and cannot add
  a file to the mirror pin set.
- **No directory listings.** Unknown paths and unknown content roots return `404` without
  revealing the pin set.
- **Local unpin and denylist.** Operators can unpin by manifest hash, content root, token id,
  publisher key, mirror key, or policy tag. Local policy changes do not alter consensus or
  the signed manifest.
- **Short-lived records.** Mirror records should set `expires_unix`. Clients treat expired
  records as stale even if the onion still serves bytes.

The mirror service must only serve canonical paths for pinned records. It is not a web server
for arbitrary local paths.

---

## 12. Abuse Controls

Client-side controls:

- Never auto-fetch `document_url`, manifests, mirror bundles, posters, or media.
- Hide or de-emphasize unsolicited/unverified NFTs by default, consistent with the NFT
  DoS/spam requirements.
- Render all manifest text as plain text. Strip controls for display. Never treat media type
  or filename as HTML, a shell command, a filesystem path, or a plugin selector.
- No browser engine is required or implied. HTML, SVG script execution, active documents,
  and remote subresources are not rendered by this protocol.
- Maintain local deny/allow lists for token id, content root, manifest hash, publisher key,
  mirror key, and onion service key.
- Bad mirrors are locally scored by content root. Hash mismatch is a hard failure for that
  mirror/content pair and should back off longer than transport timeout.

Mirror-side controls:

- GET/HEAD only. Request bodies are rejected.
- No compression or transformation for chunk/file responses.
- Header size is capped. Query strings are ignored or rejected.
- Per-circuit and per-connection token buckets are required; IP bans are ineffective over Tor.
- Idle and header timeouts are short enough to avoid slow-client exhaustion.
- The service must not proxy arbitrary URLs or fetch missing content from the network.
- Offer spidering must not trigger manifest, mirror, poster, chunk, or file fetches unless
  the operator separately enables explicit record spidering or content fetch policy. Record
  spidering stores signed records only; it does not host files.
- The operator's legal/policy denylist is local and advisory; it does not change what other
  clients compute from the signed manifest and content hashes.

Honesty requirement:

Tor onion hosting reduces reliance on clearnet hosts and hides the server IP from clients.
It does not make hosting risk-free, does not make mirrors trusted, and does not make content
authentic. The UI and operator docs must not imply otherwise.

---

## 13. Performance and Size Limits

Interoperable v1 limits:

| Item | Limit |
|---|---:|
| Chunk size | 1 MiB fixed |
| Manifest body | 4 MiB max |
| Mirror record body | 64 KiB max |
| Mirror bundle | 2 MiB max |
| Offer body | 8 KiB max |
| Offer envelope | 12 KiB max |
| Offer settlement blob | 6144 bytes max |
| Offer TTL | 86400 seconds max |
| Offer inventory batch | 1000 ids max |
| Offer get batch | 128 ids max |
| Manifest signatures | 16 max |
| Mirror record signatures | 16 max |
| Offer record signatures | 8 max |
| Known mirrors per content object | 32 max |
| Active mirrors per fetch | 4 max |
| Parallel chunk requests per content object | 4 max |
| In-flight verified content bytes | 16 MiB max |
| Chunk retries before mirror quarantine | 3 |
| Chunk count | 65536 max |
| File size | 64 GiB max in v1 profile |
| Display filename | 255 UTF-8 bytes max |
| Media type | 127 UTF-8 bytes max |

Recommended default client limits:

- Ask for explicit confirmation before fetching more than 2 GiB.
- Ask again before using more than 10 GiB of local content cache.
- Use one mirror at a time unless the user enables multi-mirror acceleration.
- Do not prefetch full videos for gallery display; fetch only the signed poster or requested
  chunks.
- Keep offer browsing page sizes at or below 100 and compute marketplace floor/depth from
  locally verified live offers only.

Recommended mirror defaults:

- Maximum simultaneous content clients: 16.
- Maximum concurrent chunks per client: 4.
- Header timeout: 10 seconds.
- Idle timeout: 30 seconds.
- Per-object pin cap: operator-configurable, default 2 GiB.
- Total pin-store cap: operator-configurable, default 10 GiB.
- Offer routing/spidering does not change pin caps because it stores signed records, not
  file bytes.

Implementations may use lower local limits. Higher limits are local policy, but records that
exceed the v1 interoperable limits are invalid for this protocol version.

---

## 14. Validation Checklist

A compliant implementation must prove these cases:

- On-chain NFT with no `document_hash` is not content-verifiable under this protocol.
- Manifest with `content_root != document_hash` is rejected for that token.
- Manifest with all-zero `token_id` is accepted only as an unbound draft.
- Manifest body hash is stable when signatures are added or reordered canonically.
- Any malformed length, trailing byte, duplicate signature key, or unsorted vector fails
  closed.
- Merkle root uses domain-separated leaves and internal nodes, with odd-node promotion.
- Each chunk is rejected before cache commit if its leaf hash does not match.
- A mirror serving transformed bytes is rejected even if the HTTP status is success.
- A signed mirror record without matching manifest hash/content root is rejected.
- A mirror record from clearnet is not used until the named onion serves the same record,
  unless imported by explicit local operator policy.
- Multiple valid backup onion records are accepted, capped, and fail over by chunk.
- Expired or locally denied mirror records are ignored.
- Enabling onion P2P does not enable content hosting.
- Viewing, minting, downloading, or caching an NFT does not publish it.
- The mirror service refuses upload/proxy/directory-listing behavior.
- The C hot-path parser rejects oversize manifests, mirrors, bundles, and offers before
  allocation-heavy work.
- C and C++ callers produce the same `body_hash` / `offer_id` for the same canonical bytes.
- `ZOF1` offers are dropped when signatures are invalid, TTL is expired, settlement hash
  mismatches, settlement verification fails, or local caps are exceeded.
- Offer routing indexes only metadata and signed bytes; it does not fetch or host content.
- Enabling marketplace spidering does not enable content hosting or add files to the
  mirror allowlist.

---

## 15. Key Decisions

- The chain anchors content with the existing 32-byte `document_hash`; it does not store
  manifests, mirror records, chunks, files, or mirror lists.
- `ZCM1` manifest identity is the SHA-256 of the canonical body, excluding signatures.
- `ZMR1` mirror identity is the SHA-256 of the canonical body, excluding signatures.
- Ed25519 is the v1 signature algorithm for manifests, mirror records, and offer records.
- Large or mirrored content uses the existing 1 MiB SHA-256 Merkle profile with
  domain-separated leaves/internal nodes and odd-node promotion.
- Mirrors are onion-only in v1 and are always untrusted byte sources.
- Backup mirrors are independent signed records or records inside an untrusted bundle.
- Hosting is disabled by default and requires explicit local pinning; no uploads, no
  automatic cache publishing, and no arbitrary local file server mode.
- Spidering/routing/indexing hot paths are C, use fixed canonical byte records, and are
  tightly bounded before allocation or signature verification.
- Decentralized marketplace integration uses signed, TTL-bound `ZOF1` offer records that
  any opted-in node can verify, locally index, and route without trusting a central party.
- Marketplace offer routing is separate from content hosting; no offer activity can
  implicitly host or pin content bytes.
