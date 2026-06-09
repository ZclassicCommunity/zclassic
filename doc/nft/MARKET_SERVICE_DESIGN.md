# MARKET_SERVICE_DESIGN — Derived SQLite Read-Model + DAO + REST NFT Gallery/Marketplace Service Layer

Status: NORMATIVE design for beta7 (scope-gated — see §0 and §12). Owner directive. Companion to `doc/nft/MARKETPLACE_DESIGN.md` (settlement/offerpool) and `doc/nft/NFT_API_REFERENCE.md` (JSON contract).

Coin is **ZClassic / ZCL**. Never emit "ZEC"/"Zcash" in any field, copy, or doc.

---

## 0. Scope Gate (read first)

This is a NEW subsystem (a vendored dependency + a DAO + a REST surface + a new regtest harness) layered on top of a beta7 that already carries the marketplace P1–P7 (offerpool + 5 P2P gossip commands + blob hardening + GUI tab + E2E), the content-defense subsystem + ZDC1 removal, coin-control, the block-index boot cache, and 9 unmerged daemon PRs with master HELD. Therefore:

- **GATE-1 (sequencing).** No SQLite work begins until marketplace **P1–P7 and ZDC1 removal land and build green on all 3 hosts** (linux/glibc-2.31 proot, mingw32, darwin). This subsystem shares the SAME `src/zslp/`+`src/nft/` namespace, the SAME `CValidationInterface` seam (`CZSLPIndexer::ChainTip`), and the SAME `-zslpindex` gate as the marketplace, so it MUST follow, never precede, the offerpool in the merge order.
- **GATE-2 (minimal beta7 down-payment, if forced).** If a beta7 slice is required, the ONLY defensible cut is: depends `sqlite.mk` + the C++11 RAII DAO + the address-projection table/index + a single `GET /rest/nft/owned/<address>` route behind `-nftrest=0` + gtest-only tests. Explicitly **NO FTS5**, **NO full REST catalog surface**, **NO regtest reconciliation proofs** in that cut.
- **Default home is beta8.** The gallery half (P0–P4) is shippable; the marketplace/offers half (P5) is offerpool-gated and lands in the same beta as the offerpool. The "viewing works" beta7 requirement is ALREADY met by the shipped single-call `zslp_listmytokens` + the `zslp_list*` family; this layer only accelerates secondary queries.

---

## 1. Purpose

Make NFT **viewing** (the Qt gallery now, a possible web frontend later) and the future NFT **marketplace** easy to build by introducing a high-performance, derived **SQLite read-model** with a thin C++11 **DAO/repository** layer and a **localhost REST/JSON** read API.

The read-model answers exactly the queries the authoritative leveldb ZSLP key-schema **structurally cannot** serve cheaply (verified against the tree):

- **"All NFTs owned by address X"** — today `CZSLPStore::GetTokensForAddress` (zslpstore.cpp:1122-1142) `Seek`s `BalanceKey(uint256(), "")` = the start of the ENTIRE `'b'` keyspace and scans every balance row of every token, because address is the **trailing** key component. The read-model makes this an `O(log n)` index seek on an address-leading projection.
- **"Newest mints"** — no height-ordered token index exists; `ListTokens` (zslpstore.cpp:1001-1028) returns tokenId (hash) order via `Seek((DB_TOKEN, uint256()))`. The read-model indexes `genesisheight DESC`.
- **"Global newest transfers across all tokens"** — leveldb's `'x'` transfer index is per-token only. The read-model adds a global `(height DESC, seq DESC)` index.
- **Arbitrary-offset pagination beyond `ZSLP_LIST_MAX = 1000`** (zslpstore.h:49) — the leveldb list RPCs clamp `count` to 1000 and do `O(count)` windowed prefix scans.
- **Substring/prefix search on name/ticker** — impossible against leveldb (exact-prefix iteration only). The read-model adds an FTS5 virtual table (post-beta7; see §0/§3.6).
- **(Deferred) "Collection by floor / sort by price"** — price exists ONLY in the RAM offerpool, never on-chain and never in leveldb; this lands when the offerpool lands.

This is a strict **CQRS** split made literal by the codebase shape:

- **WRITE MODEL (sources of truth, untouched):** leveldb `CZSLPStore` (the `'u'`+txid+vout→`CZSLPTokenUtxo` map is **ownership truth**, zslpstore.h class `CZSLPTokenUtxo` "THE SOURCE OF TRUTH for ownership") and the planned RAM offerpool (**offer/price truth**). All Create/Update/Delete actions are REAL chain or gossip actions through the EXISTING validated actors: `zslp_genesis`/`zslp_mint`/`zslp_send` and `nft_makeoffer`/`nft_takeoffer`/`nft_canceloffer`.
- **READ MODEL (this design):** a denormalized, indexed SQLite projection, updated strictly as a CONSEQUENCE of confirmed-chain `ConnectBlock`/`DisconnectBlock` events + offerpool insert/evict. Reads are fast SQLite queries served over REST.

---

## 2. Read-Model / Write-Model Boundary — RELEASE-GATING INVARIANTS

These invariants are **release-gating**: a build that violates any of them MUST NOT ship.

- **INV-1 (SQLite is NEVER a source of truth).** SQLite is a DERIVED, WIPE-AND-REBUILDABLE PROJECTION of (a) the authoritative leveldb `CZSLPStore` ledger and (b) the live RAM offerpool. It is NEVER consensus, NEVER required for validation, NEVER consulted during block acceptance. If `nftcache.sqlite` (plus its `-wal`/`-shm` sidecars) is deleted at any moment, the node loses ZERO ledger/consensus state and rebuilds the cache from the chain + offerpool on next start. Covered by an explicit `rm`-then-rebuild regtest.
- **INV-2 (Zero consensus impact).** No file in this feature touches `src/consensus/`, `src/pow.cpp`, or `CheckBlock`/`ConnectBlock(main.cpp)`/`CheckInputs`/script-verify/acceptance. **No authoritative-store schema or write path is changed** — this design adds NO new `CZSLPStore` index or write primitive (see §5, which is engineered specifically to avoid one). The writer is a pure side-effect appended INSIDE the existing `CZSLPIndexer`, itself a pure `CValidationInterface` observer. Disabling `-zslpindex` disables it entirely with no effect on block acceptance.
- **INV-3 (No new on-chain bytes; no file-smuggling path).** The read layer is GET-only (enforced per-handler, §6). It stores only the 32-byte `documentHash` + off-chain URL already in the ZSLP ledger. It offers NO endpoint that writes chain/ledger state and NO path to put files on-chain. It NEVER fetches/proxies off-chain images and (when offers land) NEVER serves raw `offerHex`.
- **INV-4 (Money decisions never trust a SQLite row).** Any Buy flow re-runs the live `NftVerify` (nftoffer.cpp:232+, with the vin[0]-vs-`pcoinsTip` liveness check at :302-303 `pcoinsTip->GetCoins(...) && coins.IsAvailable(...)` and the `VerifyScript` ALL|ANYONECANPAY signature backstop) before `nft_takeoffer`. A cached offer row is display-only.
- **INV-5 (CRUD mapping).** Read = fast SQLite query. Create/Update/Delete map to REAL actions (mint tx / transfer tx / make-or-cancel offer gossip) through the EXISTING validated wallet/RPC/gossip paths. The REST layer NEVER writes consensus/ledger/offerpool state directly; the projection updates only as a consequence of confirmed events.
- **INV-6 (The projection writer is TOTALLY exception-isolated — release-gating).** No SQLite failure may ever escape into the validation call path. Verified threat: `GetMainSignals().ChainTip(...)` is emitted BARE (no surrounding try/catch) at the end of `ConnectTip` (main.cpp ~3440, after `view.Flush()`/`FlushStateToDisk`/`UpdateTip`) and on the disconnect path. A SQLite write that throws/aborts (ENOSPC on `-wal`/`-shm`, read-only fs, corrupt page) would propagate `ChainTip → ActivateBestChainStep → ActivateBestChain` and crash/destabilize the node AFTER the tip advanced. Therefore the SQLite writer's entire body is wrapped so that on ANY error it (1) swallows + logs, (2) marks the cache **DEGRADED** (clears the serve-gate of §5.5 so REST reports "still indexing" and never serves stale rows), and (3) defers to the standing wipe+rebuild (the INV-1 recovery). It is strictly MORE defensive than the leveldb store (which can itself already throw `dbwrapper_error` out of this same path, dbwrapper.cpp:92-103 — a latent pre-existing fragility this writer must not widen).

---

## 3. SQLite Schema

Location: `GetDataDir()/zslp/nftcache.sqlite` — colocated with the leveldb ZSLP store so a `-reindex`/datadir wipe removes both together. `PRAGMA user_version = NFTCACHE_SCHEMA_VERSION` mirrors the `ZSLP_INDEX_VERSION = 3` discipline (zslpstore.h:64). Compile/open flags in §8.

Monotone-append rows (`tokens`/`transfers`) carry `*_blockhash` of the block that CREATED them, enabling `O(by-block)` deletion on reorg. Owner/address rows are reorg-reverted by **re-deriving the affected outpoints from leveldb** (§5), not maintained-and-reversed.

### 3.1 meta
```sql
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);
-- rows: 'schema_version', 'cursor_height', 'cursor_blockhash', 'degraded'
-- PRAGMA user_version is ALSO set to NFTCACHE_SCHEMA_VERSION.
```
The `(cursor_height, cursor_blockhash)` row is the crash-resume cursor, mirroring `CZSLPStore::ReadTip`/`WriteTip` (zslpstore.h:350-351). It is advanced in the SAME `BEGIN/COMMIT` as the block's row writes, so the ONLY possible skew is leveldb-ahead / SQLite-behind (never the reverse), which §5.3 heals. `degraded` is set by INV-6 to force a rebuild.

### 3.2 tokens (1:1 with CZSLPToken / TokenToJSON)
```sql
CREATE TABLE tokens (
  tokenid           TEXT PRIMARY KEY,
  ticker            TEXT NOT NULL,
  name              TEXT NOT NULL,
  documenturl       TEXT NOT NULL,
  documenthash      TEXT NOT NULL DEFAULT '',   -- '' sentinel when hasDocumentHash=false
  decimals          INTEGER NOT NULL,
  genesisheight     INTEGER NOT NULL,
  genesistime       INTEGER NOT NULL DEFAULT 0, -- joined from block index (CZSLPToken has NO time field)
  totalminted       INTEGER NOT NULL,
  mintbatonvout     INTEGER NOT NULL,
  hasmintbaton      INTEGER NOT NULL,           -- mintBatonVout >= 2
  group_id          TEXT NOT NULL DEFAULT '',   -- non-empty ONLY when group_authorized=1
  group_authorized  INTEGER NOT NULL DEFAULT 0,
  group_claimed     INTEGER NOT NULL DEFAULT 0, -- raw on-chain claim; NEVER membership
  is_nft            INTEGER NOT NULL,           -- (decimals==0 AND totalminted==1)
  created_blockhash TEXT NOT NULL
);
```
Field set and the authorized-vs-claimed group semantics mirror `TokenToJSON` (rpc/zslp.cpp:62-85) **exactly**, including: `documenthash` is `''` when absent (an honest terminal, not an error), and `group` is `''` for a name-squatter (`group_claimed` without `group_authorized`). `is_nft` is precomputed so the REST list filters server-side. `genesistime` is joined from the block index by height (`CZSLPToken` carries `genesisHeight` only — no timestamp).

### 3.3 owners (projection of CZSLPTokenUtxo — ownership truth)
```sql
CREATE TABLE owners (
  txid       TEXT NOT NULL,
  vout       INTEGER NOT NULL,
  tokenid    TEXT NOT NULL,
  address    TEXT NOT NULL,    -- canonical EncodeDestination; '' if undecodable
  amount     INTEGER NOT NULL, -- 0 for a baton
  is_baton   INTEGER NOT NULL,
  height     INTEGER NOT NULL,
  PRIMARY KEY (txid, vout)
);
```
Keyed by `(txid,vout)` like the leveldb `'u'` record. Sole purpose: make "all NFTs owned by X" an indexed lookup (the address-leading `idx_owners_address`). Address strings are copied verbatim from the value of the leveldb `CZSLPTokenUtxo.address` field (itself the indexer's canonical `AddressOfVout`/`EncodeDestination` output) — NEVER re-derived by this layer. Populated/reverted ONLY via §5's per-block re-parse + `GetUtxo` point-read (no per-token `'u'` enumeration exists, so this table is built block-by-block, never by scanning `'u'`).

### 3.4 transfers (projection of CZSLPTransfer — provenance)
```sql
CREATE TABLE transfers (
  txid       TEXT NOT NULL,
  vout       INTEGER NOT NULL,
  tokenid    TEXT NOT NULL,
  blockhash  TEXT NOT NULL,
  height     INTEGER NOT NULL,
  seq        INTEGER NOT NULL,  -- intra-block order; with height gives a total order
  txtype     TEXT NOT NULL,     -- GENESIS / MINT / SEND
  amount     INTEGER NOT NULL,
  address    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (txid, vout)
);
```
`seq` is the DETERMINISTIC block-local append counter as the writer iterates `block.vtx` in order (starting at vtx[1]; coinbase skipped exactly as `ConnectBlock` does at zslpindexer.cpp:292). Because both live indexing and rebuild iterate the SAME `block.vtx` order, `(height, seq)` is identical across incremental-vs-rebuild — the regtest asserts this on the global feed.

### 3.5 collections (header + maintained member_count)
```sql
CREATE TABLE collections (
  group_id       TEXT PRIMARY KEY,
  parent_tokenid TEXT NOT NULL DEFAULT '',
  name           TEXT NOT NULL DEFAULT '',
  member_count   INTEGER NOT NULL DEFAULT 0,  -- AUTHORIZED members only
  is_open        INTEGER NOT NULL DEFAULT 0
);
```
`member_count` counts AUTHORIZED children only. To bound the per-block in-lock cost (§9, PERF should-fix): on **connect** it is maintained by `+1` when an authorized child is added (O(1)); on **disconnect** ONLY it is recomputed from `tokens WHERE group_authorized=1` for the affected `group_id` (re-derive, avoiding aggregate drift on the rare path). A full rebuild recomputes from scratch. This is the bounded compromise between "always recompute" (O(member_count) every block) and "maintain both directions" (drift risk).

### 3.6 FTS5 search (name/ticker) — POST-BETA7 (see §0)
```sql
CREATE VIRTUAL TABLE tokens_fts USING fts5(
  name, ticker,
  content='tokens', content_rowid='rowid'
);
-- kept in sync by AFTER INSERT/UPDATE/DELETE triggers on `tokens`.
-- rebuild via: INSERT INTO tokens_fts(tokens_fts) VALUES('rebuild');
```
External-content FTS5 answers prefix/substring search structurally impossible on leveldb. Requires `SQLITE_ENABLE_FTS5` in the amalgamation build (§8). It is the SOLE feature gated on FTS5: if a builder declines FTS5, `/rest/nft/search` returns `HTTP_NOT_IMPLEMENTED` and the rest of the cache is unaffected. The trigger fan-out runs INSIDE the per-block `BEGIN/COMMIT` (so a crash mid-block is covered by §5.3). FTS5 is **CUT from the beta7 minimal slice** (§0 GATE-2) and added post-beta7.

### 3.7 DEFERRED: offers (NOT created in beta7/beta8-gallery)
Offers are **not** in SQLite (§7). When the offerpool lands, an OPTIONAL in-memory/transient `offers` table MAY be added as a pure cache of the RAM pool for `sort-by-price`/`floor` — with NO change to the durable schema above. Its PK MUST be the **full 32-byte content hash** the gossip layer keys on (`SHA256(body)`), **NOT** the 8-byte/16-hex truncation `CNftOfferBlob::OfferId()` returns today (nftoffer.cpp:121), which is collision-weak for an adversarial pool. The §5 file-smuggling bounds (`LIMITED_STRING`, `vin<=8`, body cap) MUST ship on `CNftOfferBlob` first (today `payoutAddr`/`buyerNftAddr`/`offerHex` are unbounded `std::string`, nftoffer.h:42-45).

### 3.8 Indexes
```sql
CREATE INDEX idx_tokens_height     ON tokens(genesisheight DESC);                          -- newest mints (keyset paginate)
CREATE INDEX idx_tokens_name       ON tokens(name);                                        -- sort=name (else full-table sort)
CREATE INDEX idx_tokens_collection ON tokens(group_id, genesisheight DESC) WHERE group_authorized=1; -- by-collection browse
CREATE INDEX idx_owners_address    ON owners(address, tokenid);                            -- THE owner-query fix (address-leading)
CREATE INDEX idx_owners_tokenid    ON owners(tokenid);                                     -- holders-of-token
CREATE INDEX idx_transfers_token   ON transfers(tokenid, height DESC, seq DESC);           -- per-token provenance
CREATE INDEX idx_transfers_global  ON transfers(height DESC, seq DESC);                    -- global newest-transfers feed
CREATE INDEX idx_transfers_block   ON transfers(blockhash);                                -- delete-by-block on reorg
CREATE INDEX idx_tokens_block      ON tokens(created_blockhash);                           -- delete-by-block on reorg
```

---

## 4. C++11 DAO / Repository Design (no heavyweight ORM)

New files: `src/nft/nftcache.h`, `src/nft/nftcache.cpp` (RAII + repositories), `src/nft/nftrest.cpp` (REST handlers). Wired into `libbitcoin_server_a` in `src/Makefile.am` next to `rest.cpp`/`zslp/*` (precedent: `zslp/zslpindexer.cpp` at Makefile.am:301).

**Hard constraint:** the src tree is locked to C++11 by `configure.ac:68` (`AX_CXX_COMPILE_STDCXX([11],[noext],[mandatory],[nodefault])`). Even though depends compiles C/C++ under gnu17, **src is C++11** — NO `std::optional`, NO `std::string_view`, NO structured bindings, NO generic lambdas. Use empty-string/zero sentinels exactly as `TokenToJSON` does.

### 4.1 Two RAII primitives (non-copyable)
- `class NftCacheDb` — owns `sqlite3*` (opened `sqlite3_open_v2`), `sqlite3_close_v2` in dtor. The single WRITER connection is opened `SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE`, sets `PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=OFF`, `PRAGMA wal_autocheckpoint`, and `sqlite3_busy_timeout`. On open it runs WAL recovery/checkpoint BEFORE the §5.3 reconciliation reads `meta` (so a hard kill yields a consistent, possibly-stale cursor). Each reader gets its OWN connection (`SQLITE_OPEN_READONLY` + WAL).
- `class Stmt` — owns one `sqlite3_stmt*` (prepared once), `sqlite3_finalize` in dtor. Move-only (C++11 move ctor; no copy). Thin wrappers: `bindText`, `bindInt64`, `step`, `columnText`, `columnInt64`. Prepared statements are cached per-connection (`std::map<std::string, Stmt>`), so hot paths never re-parse SQL.

### 4.2 Flat free-function repository (no class hierarchy)
POD row structs mirror the schema (`TokenRow`, `OwnerRow`, `TransferRow`, `CollectionRow`). Repository functions (all parameterized — `sqlite3_bind_*` only, NEVER string concatenation into SQL → injection-proof by construction):

Write side (called ONLY from the indexer, single writer):
- `UpsertToken(db, const CZSLPToken&, int64_t genesisTime, const uint256& createdBlock)`
- `UpsertOwner(db, const CZSLPTokenUtxo&, const uint256& txid, int32_t vout)`
- `DeleteOwner(db, const uint256& txid, int32_t vout)`
- `AppendTransfer(db, const CZSLPTransfer&, int64_t seq)`
- `AddCollectionMember(db, const uint256& groupId)` / `RecomputeCollection(db, const uint256& groupId)` (recompute is disconnect/rebuild only)
- `DeleteTokensForBlock(db, const uint256& blockHash)`, `DeleteTransfersForBlock(db, const uint256& blockHash)`
- `SetCursor(db, int64_t height, const uint256& blockHash)` (same transaction as the row writes)
- `MarkDegraded(db)` (INV-6)

Read side (called on libevent worker threads, each on its own read connection):
- `QueryTokens(db, filter, cursor/from, count, std::vector<TokenRow>&)` (keyset for height feeds)
- `QueryTokenById(db, tokenId, TokenRow&)`
- `QueryTokenHistory(db, tokenId, cursor/from, count, std::vector<TransferRow>&)`
- `QueryOwnedByAddress(db, address, cursor/from, count, std::vector<OwnerRow>&)`
- `QueryCollectionMembers(db, groupId, cursor/from, count, std::vector<TokenRow>&)`
- `SearchTokens(db, ftsQuery, from, count, std::vector<TokenRow>&)` (FTS5; post-beta7)
- `QueryStatus(db, ...)` — cursor height/hash + degraded flag

A `QueryFilter`/`Sort`/`Page` value-struct (plain ints/strings) maps to a parameterized `WHERE/ORDER BY/LIMIT`. **Sort columns are mapped through an allowlist enum** — never echoed into `ORDER BY`. Height-ordered feeds use **keyset/seek pagination** (`WHERE genesisheight < :cursor ORDER BY genesisheight DESC LIMIT :n`) so deep pagination is `O(log n)`, not `O(offset)`.

### 4.3 Threading
- **Single writer, never two interleaved.** Only the `cs_main`-serialized indexer thread writes SQLite. The startup full rebuild (§5.4) runs on the indexer's background catch-up worker and holds the writer EXCLUSIVELY until complete; the live `ChainTip` writer is not registered until the indexer reaches tip (mirroring the indexer's drain-then-register-at-tip discipline, zslpindexer.cpp:207-212). There is never a moment with two interleaved SQLite writers.
- **Per-worker readers.** Each libevent HTTP worker (`DEFAULT_HTTP_THREADS=4`, shared with JSON-RPC) owns its own read-only `NftCacheDb`. `sqlite3` handles are never shared across threads; per-thread connection + WAL is the clean non-blocking pattern. A stray write from a worker is forbidden by construction (workers hold only read connections). NOTE the 4-thread pool is the real concurrency ceiling and is shared with RPC — reader scans carry a bound `LIMIT` and a `sqlite3_progress_handler` budget so a pathological query cannot pin a worker.

---

## 5. Projection Strategy (deterministic pure function of block-data + committed leveldb)

**Single writer, driven from the EXISTING observer — never a second CValidationInterface.** The SQLite writer is invoked from INSIDE `CZSLPIndexer::ConnectBlock` (zslpindexer.cpp:271) and `DisconnectBlock` (:426), AFTER the leveldb store commits (`s->ConnectBlockEnd` at :294 / `s->DisconnectBlock` at :441). Both leveldb and SQLite advance under the SAME `cs_main` hold the validation bus provides, eliminating two-observer reorg divergence. The whole writer body is wrapped per INV-6.

**Single deterministic primitive (resolves the determinism + perf must-fixes).** The set of `(txid, vout)` outpoints a block CREATED or CONSUMED is NOT exposed by any store API (`ApplyTransaction` returns only `bool`; the `'r'` undo log is read-and-erased internally by `CZSLPStore::DisconnectBlock`; the `'u'` index is txid-leading with no per-token enumeration — only `UtxoCount()` full-scans, zslpstore.cpp:304). It IS, however, recoverable at BOTH hook sites because the REAL block is in scope at both: `ChainTip` calls `ConnectBlock(pindex, *pblock)` AND `DisconnectBlock(pindex, *pblock)` (verified zslpindexer.cpp:264-266). Therefore the writer derives its row set by:
1. **Re-parsing the block's txs** with the SAME authoritative `CZSLPIndexer::ParseTx` + `tx.vin` prevout collection (zslpindexer.cpp:312-422) to identify the created outputs and consumed prevouts. This is MECHANICAL outpoint identification, NOT a re-implementation of accept rules (the divergence the design otherwise forbids is about re-deriving WRITE DECISIONS — which token a MINT creates, group authorization, baton gating — and we do NOT do that).
2. **Point-reading the committed leveldb** `GetUtxo(txid, vout)` / `GetToken(tokenId)` (zslpstore.h:429-431) for GROUND TRUTH on each identified outpoint. leveldb has already applied (connect) or already replayed-to-pre-state (disconnect, via its `'r'` undo log, zslpstore.cpp:849-997) before the SQLite hook runs, so a `GetUtxo` hit means "this outpoint is a live token UTXO now" and a miss means "it is not". The SQLite rows are thus a pure function of (block data + committed leveldb).

This needs NO new `CZSLPStore` index, NO new enumeration API, and NO change to the authoritative store (INV-2).

### 5.1 Connect (per block)
Re-parse `block.vtx[1..]` in order. For each identified created output, `GetUtxo` → if present `UpsertOwner` + `AppendTransfer` (with the running `seq`); for the parsed message, `GetToken(parsed.tokenId)` → `UpsertToken` (covers GENESIS metadata and MINT `totalMinted`/baton updates). For each consumed prevout, `DeleteOwner` (covers burns by non-SLP txs too — `ApplyTransaction` burns every spent token UTXO). `AddCollectionMember` for a newly-authorized child. All writes for one block, plus `SetCursor(height, blockhash)`, are wrapped in a single `BEGIN/COMMIT`.

**Idempotence:** the indexer's tip-equality guard (`ReadTip` then `tipHash == blockHash`, zslpindexer.cpp:283) short-circuits the WHOLE `ConnectBlock` body BEFORE the SQLite writer runs, so a re-delivered connect of the current leveldb tip is skipped in lockstep. The leveldb tip guard is AUTHORITATIVE for the live double-apply decision; the SQLite `meta` cursor is a SECONDARY backstop used ONLY at startup (§5.3) — the two cursors are never compared for the live path.

### 5.2 Disconnect (reorg) — re-parse the block + re-read leveldb
On `DisconnectBlock`, leveldb has ALREADY replayed its `'r'` undo log to byte-identical pre-connect state. The SQLite reversal then re-parses the SAME disconnecting `block.vtx` (in scope, verified):
- For each output the block CREATED: `DeleteOwner(txid, vout)` (it no longer exists post-disconnect).
- For each prevout the block CONSUMED: `GetUtxo(prevout)` against the now-reverted leveldb — on a hit (the UTXO is alive again), `UpsertOwner` to RESTORE the owner row that connect had deleted. **This restores consumed-UTXO owner rows, which delete-by-block alone cannot** (the must-fix the consumed-UTXO case exposes).
- For **tokens/transfers** (monotone-append, carry `created_blockhash`/`blockhash`): `DeleteTokensForBlock` + `DeleteTransfersForBlock`.
- For **collections**: `RecomputeCollection` for affected groups (re-derive `member_count`; never maintain-and-reverse on this path).
- `SetCursor` to the previous block. All in one `BEGIN/COMMIT`.

### 5.3 Startup reconciliation — full-rebuild on ANY cursor!=tip mismatch
A crash in the narrow window between the leveldb commit and the SQLite `COMMIT` leaves leveldb at N and SQLite at N-1. The idempotence guard means `ConnectBlock(N)` is NEVER re-delivered, so "self-heals on next ConnectBlock" is **wrong**. At `OpenStore`, BEFORE the cache is marked live (and AFTER WAL recovery, §4.1):
1. Read SQLite `meta` cursor `(cH, cHash)` and leveldb `ReadTip(lH, lHash)`.
2. If `cHash == lHash` (compare HASHES, never special-case "exactly one block behind"): **in sync** — go live.
3. **Otherwise (any mismatch — behind, ahead-by-partial, or stale fork) OR if `degraded` is set: full wipe+rebuild (§5.4).** The bespoke per-block "gap-replay" path is DELETED: it would require the same per-block affected-set primitive and would be a hard-to-soak bespoke code path. The already-mandated, already-tested rebuild path is reused for the crash window. (A future optional fast-path could re-read only `[cH+1..lH]` from disk and replay via §5.1, but it is NOT in scope and the default is full rebuild.)

### 5.4 Versioning / wipe / rebuild (the standing recovery)
`NftCacheDb::Open` checks `PRAGMA user_version` vs `NFTCACHE_SCHEMA_VERSION`. On mismatch — OR when `ZSLP_INDEX_VERSION` bumps (which already wipes leveldb, zslpindexer.cpp:90-104) — OR on the §5.3 reconciliation mismatch — OR on the INV-6 degraded flag: DROP all tables + delete the `.sqlite`/`-wal`/`-shm` sidecars **as a SET** (deleting only the main file while a `-wal` exists resurrects a partial DB) + full rebuild.

**Rebuild is a per-block replay**, because `owners(txid,vout)` has NO enumeration source (`ListTokens`/`ListTransfers`/`GetHoldersForToken`/`GetCollectionMembers` give tokens/transfers/(token,address)-balances/members — none enumerate UTXOs; the only `'u'` traversal is the raw `UtxoCount()` full scan). The rebuild therefore walks the chain block-by-block via `ReadBlockFromDisk` exactly as `RunCatchUp` does (zslpindexer.cpp:196), re-running §5.1 per block, in `cs_main`-yielding 128-block chunks. The schema version is stamped BEFORE the rebuild so a crash mid-rebuild resumes (re-derives the cursor's block forward) rather than re-wipes. Rebuild defers FTS index build to the end via `INSERT INTO tokens_fts(tokens_fts) VALUES('rebuild')` and tunes `PRAGMA synchronous`/batched commits during the pass.

**Cost (stated honestly):** the rebuild is a SECOND full-chain block walk after the leveldb ZSLP rebuild on first `-nftcache` run — bounded but real; the §5.5 gate keeps the gallery honestly unavailable, not broken, during it. The rebuild is sequenced strictly AFTER leveldb `OpenStore` returns and is NOT begun until the leveldb catch-up reports `IsSynced()` (so it reads a complete, stable-tip leveldb, never a mid-catch-up partial — which also closes the `RunCatchUp` cross-chunk reorg window the indexer documents).

### 5.5 Completeness gating
Do NOT serve the cache as authoritative until `CZSLPIndexer::IsSynced()` (zslpindexer.h:80) is true AND the cursor equals the leveldb tip AND `degraded` is unset. `/rest/nft/status` reports cursor height/hash vs `chainActive.Height()`, `IsSynced()`, and `degraded`, so a consumer shows "still indexing" honestly instead of rendering a partial gallery as a misleading empty one. A long rebuild runs on the indexer's background catch-up worker, NEVER inside a REST handler (which would starve the 4 workers).

---

## 6. REST API Surface

Registered as PREFIX handlers into the EXISTING shared libevent server via `RegisterHTTPHandler("/rest/nft/...", false, handler)`, in a new `uri_prefixes[]`-style table in `src/nft/nftrest.cpp` with a `StartNFTREST()`/`StopNFTREST()` pair mirroring `rest.cpp`'s `StartREST`/`StopREST`.

**Routing discipline (release-gating — verified against httpserver.cpp:275-285 first-registered-wins substring match).** Handlers are registered **most-specific-prefix FIRST** so `/rest/nft/tokens/` (with trailing slash) and the point/history routes are not swallowed by `/rest/nft/tokens`. Every handler MUST validate its ENTIRE residual tail: list routes require an EMPTY tail; `/tokens/<id>` and `/tokens/<id>/history` require the id be exactly 64 hex chars; `/owned/<address>` requires a valid base58check t-address; `/collections/<gid>[/members]` require a 64-hex gid. Any unexpected residual path → `RESTERR(HTTP_NOTFOUND)`. The `.json/.bin/.hex` suffix splitting of `rest.cpp` (`ParseDataFormat`) is **NOT adopted** — nftrest emits `application/json` ONLY and the tail is validated as the whole remaining string (no `.`-splitting).

**Common preamble (every handler, in order):**
1. **Method check** — `if (req->GetRequestMethod() != HTTPRequest::GET) return RESTERR(req, HTTP_BADMETHOD, ...)`. This is REQUIRED: `http_request_cb` dispatches GET/POST/PUT/HEAD identically and only rejects `UNKNOWN` (httpserver.cpp:265), so without this an ignored 32 MiB POST body is buffered then dropped — a DoS amplifier and a violation of the GET-only contract.
2. **Host-header check** — reject requests whose `Host` is not `localhost`/`127.0.0.1`/`[::1]` (defeats DNS-rebinding of localhost endpoints; the owned-by-address list is privacy-sensitive).
3. `CheckWarmup()` (not automatic for REST).
4. Strict param validation (`IsHex`/length / base58check; `from`/`count` parsed as strict integers — reject garbage with `RESTERR`, do NOT copy `rest.cpp`'s `strtol`-silent-0). `count` clamped to `[1, 500]`; height feeds prefer keyset cursor over deep `OFFSET`.
5. Serve-gate (§5.5): if not live/degraded → `RESTERR` 503-style "still indexing".
6. Parameterized SQLite SELECT on the per-thread read connection → serialize to the `TokenToJSON` shape (rpc/zslp.cpp:62-85) verbatim → `WriteHeader("Content-Type","application/json")` + `WriteReply(HTTP_OK, ...)`.
7. Catch the `RPC_MISC_ERROR` `UniValue` that `GetZSLPStoreOrThrow` throws when `-zslpindex` is off and translate to `RESTERR` (the RPC try/catch does NOT cover REST handlers).

### 6.1 routes (GET-only, catalog)
| Method | Path | Purpose |
|---|---|---|
| GET | `/rest/nft/tokens` | Paged/sorted/filtered token list. Params: `cursor`/`from`, `count` (clamp [1,500]), `nftonly`, `sort=newest\|name`, `group=<id>`. Uses `idx_tokens_height` (keyset) / `idx_tokens_name` / `idx_tokens_collection`. Removes the 1000-row ceiling. Rows = `TokenToJSON` shape. |
| GET | `/rest/nft/tokens/<id>` | Single token metadata (point lookup; mirrors `zslp_gettoken`). Returns `documenturl` + `documenthash` only; NEVER fetches/proxies the image. |
| GET | `/rest/nft/tokens/<id>/history` | Provenance newest-first, paged (`idx_transfers_token`, keyset); mirrors `zslp_listtransfers`, no 1000-row ceiling. |
| GET | `/rest/nft/owned/<address>` | All NFTs at a t-address (`idx_owners_address`, address-leading) — the query leveldb does worst (`GetTokensForAddress` full-`'b'`-scan). |
| GET | `/rest/nft/collections/<gid>/members` | AUTHORIZED children only (`group_authorized=1`), paged/sortable; mirrors `zslp_listcollectionmembers`. Name-squatters never appear. |
| GET | `/rest/nft/collections/<gid>` | Collection header: parent token + `member_count` + `is_open` (mirrors `zslp_collectioninfo`). |
| GET | `/rest/nft/search?q=` | FTS5 name/ticker search (POST-beta7). `q` length + token-count capped before binding; bound (not interpolated) `MATCH`; in-SQL `LIMIT`. `HTTP_NOT_IMPLEMENTED` if the build omitted FTS5. |
| GET | `/rest/nft/status` | Cursor height/hash vs chain tip + `IsSynced()` + `degraded` — honest "still indexing" signal. |

### 6.2 Deliberately NOT a SQLite-cached route
- `/rest/nft/mytokens` — "my NFTs" stays a THIN pass-through to the existing `zslp_listmytokens` RPC (rpc/zslp.cpp:248). Ownership depends on live wallet keys and must invalidate on `-walletnotify`/new-key import; caching it would go stale. `zslp_listmytokens` already does the wallet-t-addrs × ledger join server-side in one round-trip (the GUI relies on this single-call shape). Must fail-soft (empty list, not 500) when wallet-disabled.

### 6.3 DEFERRED route (post-offerpool, additive, no schema change)
| Method | Path | Purpose |
|---|---|---|
| GET | `/rest/nft/offers` | Browse the network's live offers with sort-by-price / per-collection floor. Reads the RAM offerpool directly and joins catalog rows by `tokenid` at query time. Lists here ONLY to mark the seam (§7). |

### 6.4 POST (writable facade) — OUT OF SCOPE
The Qt GUI keeps calling the existing wallet RPCs directly. A future POST facade would construct a `UniValue` params array and call the EXISTING validated actors — never building a tx — behind its own auth-gated, default-off flag. Not a beta7/beta8-gallery deliverable.

---

## 7. How Live Offers Are Handled

**Offers stay 100% RAM-only; SQLite never persists a durable offer row.** This is the deliberate, lowest-risk, code-correct choice (the explicit recommendation across all proposals and all five review lenses):

1. **Liveness flips on EVERY block.** Status is recomputed as `pcoinsTip->GetCoins(nftOp.hash, c) && c.IsAvailable(nftOp.n)` (nftoffer.cpp:302-303). Persisting offers would force re-running that vin[0] liveness sweep + rewriting rows every block, duplicating the offerpool's own eviction and risking SQLite showing a "live" listing the pool already evicted.
2. **The offerpool is hard-capped and ephemeral by design**, cheap to hold in RAM, rebuilt on restart via getnftinv-on-connect. Durability buys nothing.
3. **A buyer pays on a FRESH `NftVerify`** (re-derives every field + live UTXO + the `VerifyScript` signature backstop), never on a cached row (INV-4). A cached offer row adds zero safety and real staleness risk.

Therefore: SQLite = catalog only; offers are joined at query time from the offerpool. **CRITICAL TIMING:** the offerpool, the 5 P2P gossip commands, `src/nft/offerpool.{h,cpp}`, the file-smuggling bounds (`LIMITED_STRING`, `vin<=8`, body cap), and the full-32-byte offerId DO NOT EXIST yet (verified: no `offerpool` anywhere under `src/`; `CNftOfferBlob` fields are plain unbounded `std::string` at nftoffer.h:42-45; `OfferId()` is an 8-byte/16-hex truncation at nftoffer.cpp:121). So the marketplace browse/floor/sort-by-price feature is **DEFERRED** until the offerpool lands, as a separate thin `/rest/nft/offers` handler over the RAM pool, with **NO SQLite schema change**. The catalog schema makes that future join trivial (`tokens.tokenid` is the join key; price comes from the offerpool's `CNftOfferBlob`, never from SQLite). When that transient cache is built: rows projected ONLY from `NftVerifyResult` (never the advisory blob header), keyed by the full 32-byte content hash, evicted on the same per-block liveness sweep; pool-origin rows use pure `!nftLive => evict` liveness (NEVER local-origin sticky canceled/filled semantics); `offerHex` NEVER stored or served. **Gate (release-gating): the §3.7 blob bounds MUST ship on `CNftOfferBlob` before ANY REST route reads or echoes offer-derived data.**

---

## 8. Build Plan (SQLite via depends)

SQLite is NOT in depends today (`depends/packages/packages.mk:38` = `boost openssl libevent zeromq $(zcash_packages) googletest`; `wallet_packages=bdb` at :41). Prefer a vendored depends static package over a system lib — a system `-lsqlite3` breaks the portable static bundle (the proot Ubuntu 20.04 / glibc-2.31 builder must compile SQLite against the old glibc to preserve the glibc back-compat floor), exactly why bdb/leveldb/libevent are vendored.

1. **`depends/packages/packages.mk:38`** — append `sqlite` to the `packages :=` line.
2. **NEW `depends/packages/sqlite.mk`** — model on `libsodium.mk`/`zeromq.mk`/`bdb.mk`: official sqlite-autoconf amalgamation tarball, sha256-pinned; `--enable-static --disable-shared --disable-readline`; `$(package)_config_opts_linux=--with-pic`; stage only `libsqlite3.a` + `sqlite3.h` + pkgconfig; postprocess `rm -rf bin share`. **Include the darwin `-isysroot` cflags dance** (cf. libevent.mk/zeromq.mk) or the macOS cross-build fails — and note macOS is currently built by an EXTERNAL dev, so this adds a coordination cost. Compile minimal+hardened: `SQLITE_OMIT_LOAD_EXTENSION`, `SQLITE_THREADSAFE=1`, `SQLITE_DEFAULT_FILE_PERMISSIONS=0600`, `SQLITE_ENABLE_FTS5` (post-beta7), shell/CLI disabled.
3. **`configure.ac`** — add `AC_ARG_ENABLE([sqlite])` (clone the zmq toggle at :155), `AC_CHECK_HEADER([sqlite3.h])` + `AC_CHECK_LIB([sqlite3],[sqlite3_open_v2],...)` (clone the zmq block near :692-730), `AM_CONDITIONAL([ENABLE_SQLITE])` (clone :843), and `AC_SUBST(SQLITE_LIBS)`/`AC_SUBST(SQLITE_CFLAGS)`.
4. **`src/Makefile.am`** — append `$(SQLITE_CFLAGS)` to `BITCOIN_INCLUDES` (:24); add `nft/nftcache.cpp` + `nft/nftrest.cpp` to `libbitcoin_server_a_SOURCES` (next to `rest.cpp`:283 / `zslp/zslpindexer.cpp`:301); add `$(SQLITE_LIBS)` to `zclassicd_LDADD` next to `$(EVENT_LIBS)`/`$(ZMQ_LIBS)` and to the gtest binary's LDADD.

The C amalgamation compiles into a C++ lib with NO per-file flags — proven precedent: `zslp/slp.c` inside `libbitcoin_common_a_SOURCES` (Makefile.am:414). The static archive links the same way as bdb/leveldb/libevent under `-all-static` + reduce-exports. **Build cost (stated):** each host's depends tree re-stages (linux/glibc-2.31 proot, mingw32 ~1.4GB, darwin via external dev) — mechanical but not free.

---

## 9. Security Model

- **Bind / default.** Routes ride the ONE shared libevent server, inheriting the localhost-only default bind (`::1`/`127.0.0.1` unless `-rpcallowip` is set) and the `ClientAllowed` ACL (httpserver.cpp:259). Gated by `-nftrest` (default 0).
- **Decoupled flag + public-exposure REFUSAL (release-gating).** `-nftrest` is SEPARATE from `-rest` so NFT views can be enabled without exposing raw block/tx/utxo. KNOWN SHARED-ACL FACT: the built-in `/rest` handlers have NO per-handler auth — they rely solely on the localhost bind + ACL, so opening `-rpcallowip` exposes unauthenticated `/rest` AND `/rest/nft/*` to those subnets. Therefore: **when `-nftrest=1` AND the node is not loopback-only (`-rpcallowip` set), the daemon logs a hard warning and REFUSES to start nftrest unless an explicit `-nftrestpublic` acknowledgement flag is given.** This prevents an operator who merely opened RPC from silently publishing unauthenticated, un-rate-limited NFT endpoints.
- **Public gateway is OUT OF SCOPE.** There is NO CORS and NO per-IP rate-limiting anywhere in `httpserver.cpp`/`rest.cpp`/`httprpc.cpp` (verified). A public read-only gateway is NOT a flag flip — it requires NEW code: its own decoupled bind/allow list, a token or HTTP-auth check (model on `httprpc.cpp`'s `TimingResistantEqual` + `MilliSleep(250)`), per-IP rate limiting, and CORS headers. Ship only as an explicit, authenticated, documented opt-in; never default-on. **Wildcard `Access-Control-Allow-Origin: *` is NEVER emitted and NEVER combined with a non-loopback bind** (DNS-rebinding / drive-by localhost-scraping of a user's owned-NFT list is a privacy leak). Any future web frontend is served same-origin or via the separately-flagged gateway.
- **GET-only + tail validation + Host check** are enforced per-handler in the §6 common preamble (the framework does not enforce them).
- **Injection.** ALL SQL uses prepared statements + `sqlite3_bind_*` — no string concatenation; FTS5 `MATCH` input is bound, not interpolated; sort columns map through an allowlist enum. Structurally injection-proof.
- **DoS.** Inherits the work-queue depth cap (`-rpcworkqueue`, default 16), the 32 MiB body cap (`MAX_SIZE`), and the 30s `-rpcservertimeout`. Every list endpoint hard-clamps `count` to [1,500] and uses keyset pagination (no `O(offset)` deep scans). FTS `q` is length/token-capped with an in-SQL `LIMIT` and a `sqlite3_progress_handler` budget. The one NEW hazard — a long rebuild starving the 4 workers — is mitigated: rebuild runs on the indexer's background catch-up worker (128-block `cs_main`-yielding chunks), and handlers refuse via the §5.5 serve-gate until live.
- **In-lock write cost (bounded).** The per-block SQLite write extends the `cs_main` critical section; it is bounded by the per-block tx count and the per-tx output cap (`ZSLP_SEND_MAX_OUTPUTS_STORE=19`, zslpstore.h:56). `RecomputeCollection` runs on the disconnect/rebuild path only (connect uses O(1) `AddCollectionMember`). A worst-case-block write-count benchmark is a test-plan gate (§11). WAL `wal_autocheckpoint` + a writer `wal_checkpoint(TRUNCATE)` at block boundaries keep `-wal` from growing unboundedly under heavy mint+browse.
- **File-smuggling.** Catalog only; never serves `offerHex` or arbitrary blob bytes; the off-chain image is never fetched/proxied (REST returns `documenturl` + 32-byte `documenthash`, client resolves + integrity-checks on click). When the offers cache lands it MUST assume the §3.7 bounds shipped first.
- **File mode.** `nftcache.sqlite` is `0600` (`SQLITE_DEFAULT_FILE_PERMISSIONS`), under `GetDataDir()/zslp/`. WAL sidecars removed as a set on wipe. `SQLITE_OMIT_LOAD_EXTENSION` closes the loadable-extension RCE vector.

---

## 10. Consensus-Safety Proof (by construction)

1. Nothing in this design touches `src/consensus/`, `src/pow.cpp`, `CheckBlock`/`ConnectBlock(main.cpp)`/`CheckInputs`/script-verify/acceptance. All new code lives in `src/nft/*`, the new depends package, and an in-method hook inside the existing `CZSLPIndexer`. NO authoritative-store schema/index/write primitive is added (§5 is engineered to avoid one).
2. The writer is a pure side-effect of an already-committed, already-validated block. `CZSLPIndexer` is a pure `CValidationInterface` observer (zslpindexer.h:43); `ChainTip` fires AFTER consensus has durably committed (`view.Flush()`/`FlushStateToDisk`/`UpdateTip` precede the bare `GetMainSignals().ChainTip` at main.cpp ~3440). The SQLite write cannot gate, delay, or alter block acceptance. Removing `-zslpindex` disables the whole feature with no consensus effect.
3. INV-6 guarantees a SQLite failure cannot crash/destabilize the node from inside the un-try-wrapped validation path: any error is swallowed, marks degraded, defers to rebuild.
4. SQLite is NEVER the source of truth (INV-1): leveldb `'u'` is ownership truth, the RAM offerpool is offer/price truth; SQLite derives FROM them and is never read back INTO them. `rm`-and-rebuild is the standing recovery.
5. No new on-chain bytes (INV-3): GET-only read layer; stores only the 32-byte `documentHash` + off-chain URL already in the ledger; Create/Update/Delete remain the existing validated paths.
6. Money decisions never trust the cache (INV-4): the Buy path re-runs live `NftVerify` against `pcoinsTip`.

---

## 11. Test Plan

**gtest (unit, DAO + projection) — the realistic beta7 floor:**
- RAII lifecycle: `NftCacheDb` open/close, `Stmt` prepare/finalize, WAL mode set, busy_timeout, 0600 mode.
- Repository CRUD: upsert/delete/query round-trips for tokens/owners/transfers/collections; sort-allowlist rejects unknown columns; pagination clamp + keyset correctness; (post-beta7) FTS5 hit/miss.
- Injection: adversarial `q`, `address`, `tokenid`, `sort` values prove parameterization (no SQL escapes).
- `TokenToJSON`-shape equivalence: a row serialized by the REST path is byte-equal to the RPC `TokenToJSON` for the same token (one-contract guarantee).
- Reorg unit: connect block N (mint+transfer), disconnect N; assert owners re-derived (INCLUDING a consumed-UTXO restoration case via the §5.2 `GetUtxo`-hit path), tokens/transfers deleted-by-block, collection `member_count` recomputed.
- INV-6 fault-injection: a forced SQLite write error during ConnectBlock does NOT throw out of the hook, marks degraded, and the node keeps validating (simulated ENOSPC / read-only fs).
- Per-block write-count benchmark gate: a worst-case block of N SLP txs each with 19 outputs — assert bounded in-lock write count + latency budget.

**regtest (integration) — deferral candidate for the minimal beta7 slice (§0):**
- Mint/transfer/genesis sequence → query `/rest/nft/tokens`, `/owned/<addr>`, `/tokens/<id>/history`, `/collections/<gid>/members`; assert parity with the corresponding `zslp_*` RPCs.
- Reorg round-trip: invalidate/reconsider a block; assert the cache matches a fresh full rebuild from leveldb at every step, INCLUDING `(height, seq)` ordering on the global transfers feed.
- INV-1 proof: `rm nftcache.sqlite{,-wal,-shm}` (all three) mid-run; restart; assert full rebuild and identical query results.
- Crash-window proof: simulate a cursor one block behind leveldb at open; assert §5.3 triggers full rebuild and serves correctly (cursor == tip).
- Schema-version bump: bump `NFTCACHE_SCHEMA_VERSION`; assert DROP+rebuild.
- Method/edge: POST/PUT to a GET route → `HTTP_BADMETHOD`; non-localhost Host → reject; `-nftrest=1` with `-rpcallowip` and no `-nftrestpublic` → refuses to start nftrest.
- `IsSynced()` gate: query during catch-up; assert `/rest/nft/status` reports "still indexing"/degraded and gallery routes degrade honestly.

**headless GUI E2E (per the gui-headless-e2e harness) — deferral candidate:**
- Attach the real wallet bundle to a regtest NFT daemon with `-nftrest=1`; drive the gallery offscreen; vision-review screenshots; assert the single-round-trip `mytokens` shape is preserved and the catalog routes render the grid, by-collection browse, and provenance correctly; assert RPC fallback when the route is absent.

---

## 12. Phased Implementation Plan

See `phasedPlan` (structured). Summary: P0 build/dependency → P1 DAO + schema + version-gate → P2 projection hooks (re-parse-driven connect/disconnect/startup-reconcile/rebuild + INV-6 isolation) → P3 REST routes + `-nftrest` + public-refusal guard → P4 tests → P5 (DEFERRED) offers handler when the offerpool lands. The gallery half (P0–P4) lands in beta8 by default (or the §0 GATE-2 minimal slice in beta7 only if forced, AFTER marketplace P1–P7 + ZDC1 removal are green on all 3 hosts); the marketplace/offers half is a follow-on in the same beta as the offerpool, additive with NO schema change.

---

## 13. Out of Scope (must NOT be attempted in the gallery half)
- Anything offer/marketplace that depends on the unbuilt offerpool + 5 gossip commands + §3.7 bounds.
- The `/rest/nft/offers` handler, sort-by-price/floor, the transient offers cache.
- POST/writable REST.
- A public authenticated/rate-limited/CORS read gateway.
- A web frontend (the REST contract is designed so one can be built later against the same shape).
- Any new `CZSLPStore` index, enumeration API, or write path (the design is deliberately built to need none).