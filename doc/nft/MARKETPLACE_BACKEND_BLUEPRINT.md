# ZClassic NFT Marketplace Backend — Build Blueprint

Status: APPROVAL-READY blueprint (build from this). NON-consensus only. Coin is **ZCL**, never ZEC.
Scope: the high-performance marketplace backend (derived catalog + REST + offer-pool price join + advisory sale detector), phased P4..P8.
Master stays HELD. Each phase is independently shippable and NON-consensus.

Every red-team finding from the PERFORMANCE, SECURITY, CORRECTNESS/CRASH/REORG, and CROSS-BUILD passes is folded
inline below (search for `[FIX-…]` anchors) and tabulated in §9. All file:line anchors were re-verified against the
working tree on 2026-06-08.

---

## 1. Foundation decision

**Chosen: `ram-index-rebuilt-from-store`.** The marketplace catalog is a pure in-RAM, derived, wipe-and-rebuildable
read-model over the authoritative `CZSLPStore` (leveldb/`CDBWrapper`). It is built once at indexer go-live by a single
sequential `'t'`-prefix scan of the store, then kept live by hooks in the ZSLP indexer's connect/disconnect path
(under `cs_main`), and read by the REST layer under its own dedicated lock. **No SQLite, no FTS5, no new on-disk
catalog, no new dependency.** The decisive reasons: (1) the hardest "OpenSea" facet — sort/filter by **price** — must
live in RAM `g_offerPool` by the never-persist-offerHex invariant, so a persisted catalog buys *zero* price capability;
price is always a RAM join at query time regardless of catalog backing. (2) The catalog's only remaining job is stable
secondary orderings (newest, by-name, by-collection, supply) + text search over a **flat** `CZSLPToken` that has only
two short text fields (`name`, `ticker`) — no description, no traits — so FTS5 is wildly over-tooled; a ~50-line
in-RAM inverted index is OpenSea-class for this data. (3) At the realistic ceiling (thousands to low-millions of flat
token rows) one leveldb scan folding into a few `std::map`/`unordered_map` is low-single-digit seconds on the existing
background sync thread. (4) Wipe-and-rebuild becomes **structurally free** — there is no on-disk catalog to corrupt,
version-skew, or orphan; process restart == rebuild == the cleanest possible "derived, not authoritative." (5) Zero new
cross-build surface across linux/mingw/macOS-cross, the invariant most at risk under the SQLite option.

**Rejected:** *vendor-sqlite-fts5* (its headline win — flexible SQL `WHERE` + price sort — is unusable because price
can never be persisted to SQLite; what's left for it is FTS over two short strings, which a tiny inverted index covers,
at the cost of a new 3-target C dependency, a `sqlite.mk`, `packages.mk`/`configure.ac` edits, a persisted format that
fights the wipe-and-rebuildable invariant, and reversing the store authors' deliberate "CDBWrapper instead of sqlite"
decision at `zslpstore.h:11`). *leveldb secondary indices* (strictly worse than RAM at this scale: same hand-rolled
text-index work **plus** an on-disk format to keep crash/reorg-consistent and version-migrate, with no payoff while the
index fits in RAM and rebuilds in seconds). The documented escape hatch if telemetry ever shows token count outgrowing
RAM is a **hybrid** (persist only cold metadata to leveldb, keep hot sorted/text indices in RAM) — a localized later
change; do not pre-build it.

---

## 2. Architecture in one picture

```
                       (authoritative, on-disk leveldb)            (RAM-only price engine, opt-in to GOSSIP)
   chain ──► CZSLPStore (CDBWrapper) ──────────────────────┐       g_offerPool  [#ifdef ENABLE_WALLET]
              ▲  ConnectBlockEnd / DisconnectBlock          │        - BrowseMeta(filter)  → scalars only
              │  (touched-token set emitted here)           │        - FloorByToken()      → floor+depth
   ZSLP indexer (cs_main, single thread)                    │        - Get(hash,blob)      → offerHex (BUY only)
        │  OnConnectBlock(touched) / OnDisconnect(touched)  │            ▲
        ▼  Rebuild(store) at go-live                        │            │ RAM join by tokenId, AFTER releasing
   ┌─────────────────────────────────────────────┐         │            │ cs_catalog, via public methods only
   │  CNftCatalog  (DERIVED read-model, RAM-ONLY) │◄────────┘            │
   │   m_rows / m_byHeight / m_byName / m_bySupply│                      │
   │   m_byCollection / m_invTerms / m_termVocab  │                      │
   │   metadata only: NO price, NO offerHex       │                      │
   └───────────────┬─────────────────────────────┘                      │
        cs_catalog │ (read lock; httpworker threads)                     │
                   ▼                                                     │
   ┌───────────────────────────────────────────────────────────────────┴──┐
   │  nftrest  (GET-only, LOOPBACK-only, peer-IP gated; shares HTTP pool)   │
   │   /nft/health /collections /collection/<id> /item/<id> /search        │
   │   /offers /floor   (metadata + RAM-joined floor/depth)                 │
   │   /nft/offer/<hash> ── the ONLY route that returns offerHex (BUY step) │
   │   item.recentSales  ── ADVISORY sale detector (never feeds floor/sort) │
   └───────────────────────────────┬───────────────────────────────────────┘
                                    ▼
                        local GUI / wallet (only intended client)
```

**Opt-in surface.** A plain node, by default after P4, builds its **own local catalog** from its own chain (`-zslpindex`,
default on) and serves the **loopback** REST to its own GUI — but **hosts nothing extra**: relaying/serving *others'*
offers over the P2P overlay stays behind **`-nftmarket`, flipped to default FALSE in P4**. The catalog *existence* rides
`-zslpindex`; network *exposure* rides `-nftmarket`; REST is loopback-only regardless.

---

## 3. Locked data-model + `nftcatalog.h` C++11 API (red-team must-fixes folded in)

Files: `src/nft/nftcatalog.h`, `src/nft/nftcatalog.cpp`. C++11 (`configure.ac:68` `-std=c++11 noext`):
`boost::optional`/`boost::function`, `std::map`/`std::multimap`/`std::set`/`unordered_map`; **no** `std::optional`/`string_view`.
Module name is **`nftcatalog`** (the task's `nftcache` alias is superseded; the Makefile wiring + symbols pin `nftcatalog`).

### 3a. Containers (RAM-only; metadata only)

All metadata is the flat `CZSLPToken` (verified `zslpstore.h:78-100`): `tokenId, ticker, name, documentUrl, documentHash,
hasDocumentHash, decimals, mintBatonVout, genesisHeight, totalMinted, groupId, hasGroup, groupAuthorized`. There is **no
description, no traits, no mimeType**. The catalog stores a tiny POD per token plus secondary orderings + an inverted
text index. **All small DISPLAY fields live in the row** so a list/search page renders with ZERO store reads and ZERO
`cs_main` (folds in `[FIX-PERF-medium-rest-cs_main]`): only the single `/nft/item` detail route ever reads `documentUrl`/
holders/transfers from the store.

```cpp
struct CNftCatalogRow            // compact projection of CZSLPToken; NO price, NO offerHex, NO bytes
{
    uint256     tokenId;         // key (== CZSLPToken.tokenId, internal little-endian id)
    std::string nameNorm;        // normalizeTerm(name) — for sort/search
    std::string tickerNorm;
    std::string name;            // raw display
    std::string ticker;          // raw display
    int64_t     genesisHeight;   // recency sort key
    int64_t     totalMinted;     // supply sort/range key
    uint8_t     decimals;
    bool        hasGroup;
    bool        groupAuthorized; // only authorized membership is surfaced
    uint256     groupId;         // parent collection genesis id (null if none)
    uint256     documentHash;    // image/document fingerprint, already on-chain display order (see [FIX-CORR-low-dochash])
    bool        hasDocumentHash;

    // INTRUSIVE reverse handles into the colliding-key multimaps (folds in
    // [FIX-PERF-high-erase]). std::multimap iterators stay valid across other
    // insert/erase, so eraseRowLocked() removes this token in O(1)+rebalance
    // instead of equal_range over a key shared by the whole totalMinted==1 NFT
    // population.
    std::multimap<int64_t,uint256>::iterator     heightIt;
    std::multimap<int64_t,uint256>::iterator     supplyIt;
    std::multimap<std::string,uint256>::iterator nameIt;
    std::multimap<uint256,uint256>::iterator     collIt;   // valid iff hasGroup&&groupAuthorized
    bool itersValid;

    CNftCatalogRow()
      : genesisHeight(0), totalMinted(0), decimals(0), hasGroup(false),
        groupAuthorized(false), hasDocumentHash(false), itersValid(false)
    { tokenId.SetNull(); groupId.SetNull(); documentHash.SetNull(); }
};

struct CNftHasher { size_t operator()(const uint256& id) const { return id.GetCheapHash(); } };

// PRIMARY
boost::unordered_map<uint256, CNftCatalogRow, CNftHasher> m_rows;

// SECONDARY ORDERINGS (values are tokenIds; rows fetched from m_rows on materialize)
std::multimap<int64_t, uint256>     m_byHeight;     // genesisHeight -> tokenId (NEWEST: reverse-iterate)
std::multimap<std::string, uint256> m_byName;       // nameNorm      -> tokenId
std::multimap<int64_t, uint256>     m_bySupply;     // totalMinted   -> tokenId

// COLLECTIONS (authorized members only) + INCREMENTAL RAM ROLLUP (folds in [FIX-PERF-medium-collfloor])
std::multimap<uint256, uint256>     m_byCollection; // groupId -> childTokenId
struct CNftCollAgg { size_t memberCount; CNftCollAgg() : memberCount(0) {} };
boost::unordered_map<uint256, CNftCollAgg, CNftHasher> m_collAgg; // groupId -> {memberCount}
// NOTE: collection FLOOR/DEPTH is NOT cached here — it is volatile RAM-offerpool
// state; the REST layer joins it for ONLY the <=100 tokenIds on the page (never a
// whole-pool FloorByToken per page) — see §5 and [FIX-PERF-medium-collfloor].

// TEXT SEARCH — inverted index. Posting sets are sorted vectors (folds in
// [FIX-PERF-medium-catalog-set]): ~3-4x leaner than std::set<uint256>, give a
// sequential std::set_intersection, and better cache locality. Kept sorted on insert.
boost::unordered_map<std::string, std::vector<uint256> > m_invTerms; // term -> sorted {tokenId}
std::set<std::string>                                    m_termVocab; // sorted terms (prefix/type-ahead)
```

### 3b. Public API (`class CNftCatalog`) — the LOCKED, reconciled method set

Both locked sub-specs disagreed on the method set; this reconciles to **one** surface
(folds in `[FIX-CORR-high-apimismatch]`). The catalog never receives a block hash/height — it re-reads token rows from
the store keyed by the **authoritative touched-token vector** the store emits (folds in `[FIX-CORR-critical-touchedset]`).
There is **no** `UpsertToken`-from-inside-`ApplyTransaction`; the only write seam is the indexer block-end hook (§4).

```cpp
static const uint32_t NFT_CATALOG_VERSION = 1;   // bump => wipe+rebuild on next boot

enum NftSort { NFT_SORT_NEWEST=0, NFT_SORT_OLDEST, NFT_SORT_NAME_ASC,
               NFT_SORT_NAME_DESC, NFT_SORT_SUPPLY_ASC, NFT_SORT_SUPPLY_DESC };
               // price/floor sort is NOT here — delegated to g_offerPool at the REST layer.

struct CNftItemFilter {                  // pagination is signed int at the store boundary (see [FIX-XB-low-narrow])
    bool hasGroupId;  uint256 groupId;
    bool hasMinHeight; int64_t minHeight;
    bool hasMaxHeight; int64_t maxHeight;
    bool nftOnly;     NftSort sort;
    int  from;        int     count;     // already clamped by the REST ParsePage helper (§5)
    CNftItemFilter() : hasGroupId(false), hasMinHeight(false), minHeight(0),
                       hasMaxHeight(false), maxHeight(0), nftOnly(false),
                       sort(NFT_SORT_NEWEST), from(0), count(0) { groupId.SetNull(); }
};

struct CNftCollectionView { uint256 groupId; std::string name, ticker; size_t memberCount;
                            int64_t genesisHeight; bool hasDocumentHash; uint256 documentHash;
                            CNftCollectionView() : memberCount(0), genesisHeight(0),
                            hasDocumentHash(false) { groupId.SetNull(); documentHash.SetNull(); } };

class CNftCatalog {
public:
    CNftCatalog();
    ~CNftCatalog();

    void Init(CZSLPStore* store);          // bind only; no scan; no cs_main

    // FULL wipe + deterministic rebuild via ONE raw 't'-prefix CDBIterator scan
    // (NOT paged ListTokens — folds in [FIX-CORR-high-rebuildON2]). Builds into
    // local containers, then swaps under a single cs_catalog hold. See §4 for the
    // OFF-cs_main placement ([FIX-PERF-medium-init-csmain]).
    void Rebuild(CZSLPStore* store);

    // WRITE SEAM (indexer block-end, under cs_main). `touched` is the AUTHORITATIVE
    // set the store emits (genesis id + each MINT tokenId on connect; tokenMods
    // keys + tokenErased on disconnect). The catalog re-reads each via GetToken:
    //   GetToken==true  -> (re)index the refreshed row
    //   GetToken==false -> erase the row from every index (orphan removed)
    // Idempotent. Connect and disconnect share this exact re-derive logic.
    void OnConnectBlock(const std::vector<uint256>& touched);
    void OnDisconnect (const std::vector<uint256>& touched);

    bool IsReady() const;   // reuses g_zslpIndexer->IsSynced() AND a built flag; no 2nd atomic

    // READ API (httpworker/RPC threads; takes cs_catalog; copies out; NO store/offerpool calls inside the lock)
    std::vector<CNftCollectionView> browseCollections(int from, int count) const;
    std::vector<CNftCatalogRow>     browseItems(const CNftItemFilter& f) const;
    boost::optional<CNftCatalogRow> getItem(const uint256& tokenId) const;
    std::vector<uint256>            searchByText(const std::string& q, int from, int count) const;
    std::vector<uint256>            collectionMembers(const uint256& groupId, int from, int count) const;
    bool                            getCollectionAgg(const uint256& groupId, CNftCollAgg& out) const;

    size_t   Size() const;          // O(1) m_rows.size() under cs_catalog — /nft/health uses THIS, never TokenCount()
    int64_t  LastRebuildMs() const; // telemetry (gated out of REST by default — see [FIX-SEC-medium-infoleak])

    // NO Floor/Depth/Price methods — deliberately absent (live in g_offerPool).

private:
    mutable CCriticalSection cs_catalog;
    CZSLPStore* m_store;
    bool        m_built;            // set true at end of a successful Rebuild
    uint32_t    m_version;
    int64_t     m_lastRebuildMs;
    // containers per §3a
    void clearLocked();
    void eraseRowLocked(const uint256& tokenId);   // uses intrusive iterators — O(log n), no equal_range scan
    void insertRowLocked(const CNftCatalogRow& row);
    static std::string normalizeTerm(const std::string& s);  // ONE shared index+query normalizer (lowercase + fold)
    static void tokenize(const std::string& name, const std::string& ticker, std::vector<std::string>& termsOut);
};

extern CNftCatalog* g_nftCatalog;   // pointer (matches g_zslpIndexer); null-checked at EVERY hook+REST site
                                    // ([FIX-XB-low-symbolshape]: chosen over a value object to match the
                                    //  indexer's new/delete lifetime; uniform `if (g_nftCatalog)` guards)
void StartNftCatalog(CZSLPStore* store);   // allocate (empty)
void StopNftCatalog();                      // free (after HTTP workers joined — §7)
```

**Touched-set is authoritative, not a parallel parse** (`[FIX-CORR-critical-touchedset]`, `[FIX-CORR-medium-sendbaton]`):
the only metadata-mutating ZSLP events are **GENESIS** (row create) and **MINT** (`totalMinted`/baton mirror). A **SEND**
changes only balances/UTXOs/transfers, which the catalog does not index, so SEND never triggers an upsert
(`[FIX-PERF-low-sendupsert]`). The store already computes the precise set: on disconnect it builds
`tokenMods` (`zslpstore.cpp:880`) + `tokenErased` (`:881`); on connect it knows the genesis id + each MINT id. §4 exposes
these so the catalog re-reads exactly those rows — no `block.vtx` re-parse, no divergence.

### 3c. Consistency invariants INV-1..6 (corrected to be cheaply checkable)

- **INV-1 (tip parity, structural):** the catalog is a pure function of the store at the current tip — mutated only inside
  the store's connect/disconnect path under `cs_main`. Verified by **full equality only at rebuild**, never per-block
  (folds in `[FIX-CORR-critical-INVcount]` + `[FIX-PERF-high-tokencount]`).
- **INV-2 (every row is a confirmed on-chain event):** every row derives from a `CZSLPToken` the store currently returns
  `GetToken==true` for; the upsert fires after the store commit, so burned/rejected SLP never creates a row.
- **INV-3 (offerHex/price never stored):** the catalog holds zero offer data. A gtest greps `nftcatalog.{h,cpp}` for
  `offerHex`/`priceZat`/`CNftOfferBlob` and asserts absence.
- **INV-4 (deterministic rebuild):** `Rebuild` is a deterministic pure function of the store — same store ⇒ byte-identical
  containers (leveldb `'t'`-key scan order; fixed multimap key→tokenId mapping; single shared `normalizeTerm`).
- **INV-5 (reorg removes orphans):** on disconnect, each affected token is re-derived from the post-undo store; rows whose
  genesis was undone are erased from every index; survivors re-upserted.
- **INV-6 (counts reconcile at rebuild only):** `Size()` is the running `m_rows.size()`; it is compared to a single
  `TokenCount()` taken in the *same* rebuild pass (and optionally via an `nft_catalogverify` RPC for tests) — **never**
  per-block. The inherited startup-window orphan class (a reorg between catch-up chunks before registration,
  `zslpindexer.cpp:149-156`) is honestly **inherited from the store** and clears only on a `ZSLP_INDEX_VERSION`/
  `NFT_CATALOG_VERSION` wipe; `MarkDirty()` is **removed** as dead surface (folds in `[FIX-CORR-medium-selfheal]`).

---

## 4. Indexer hook + init wiring (exact file:line anchors)

### 4a. Store changes — expose the authoritative touched-set (`[FIX-CORR-critical-touchedset]`)

`src/zslp/zslpstore.{h,cpp}`:
- `ConnectBlockEnd(int64_t height, const uint256& blockHash, std::vector<uint256>& touchedOut)` — append the genesis id
  and each MINT tokenId committed in this block to `touchedOut` (the store already knows them as it batches the writes).
- `DisconnectBlock(const uint256& blockHash, int64_t prevHeight, const uint256& prevHash, std::vector<uint256>& touchedOut)`
  — fill `touchedOut` with `tokenMods` keys (`zslpstore.cpp:966-968` loop) + `tokenErased` (`:881`); both are already
  in memory from the undo replay. This is free and authoritative.
- Add a single raw-scan helper for rebuild (`[FIX-CORR-high-rebuildON2]`):
  `void ForEachToken(const boost::function<void(const CZSLPToken&)>& fn) const;` — one `Seek(DB_TOKEN, uint256())` /
  `Next()` to the prefix boundary (the exact `TokenCount()` shape at `zslpstore.cpp:295`), `GetValue` into `CZSLPToken`,
  invoke `fn`. O(N) single pass — **never** the O(N²) paged `ListTokens(from,count)` skip-loop (`zslpstore.cpp:1014`).

### 4b. Indexer hook — `src/zslp/zslpindexer.cpp` (verified anchors)

Add `#include "nft/nftcatalog.h"` to the include block (`[FIX-XB-high-include]`; resolves like `nft/offerpool.h`).

| Concern | File:line (verified) | Insert |
|---|---|---|
| Allocate catalog (empty) | `zslpindexer.cpp` in `StartZSLPIndexer` (after `g_zslpIndexer = new CZSLPIndexer()`) | `g_nftCatalog = new CNftCatalog(); g_nftCatalog->Init(g_zslpIndexer->Store());` |
| Connect upsert (per block, post-commit) | `zslpindexer.cpp:294` `ConnectBlockEnd(...)` now fills `touched`; **new line 295** | `if (g_nftCatalog) g_nftCatalog->OnConnectBlock(touched);` — sync inline, under `cs_main` |
| Disconnect re-derive (per block, post-undo) | `zslpindexer.cpp:441` `s->DisconnectBlock(...)` now fills `touched`; **new line 442** | `if (g_nftCatalog) g_nftCatalog->OnDisconnect(touched);` — sync inline, under `cs_main` |
| Go-live full rebuild | inside `if (atTip)` at `zslpindexer.cpp:207-209`, **after** `RegisterValidationInterface(this)` + `m_synced.store(true)` | see placement note below |
| Free catalog | `StopZSLPIndexer` after `InterruptAndJoinSync()` + `UnregisterValidationInterface`, before `delete g_zslpIndexer` | `delete g_nftCatalog; g_nftCatalog = NULL;` |

**Why block-end, not inside `ApplyTransaction`:** at `ConnectBlockEnd` return, all per-tx batches are committed and
`GetToken` reflects final block state (burned/rejected excluded). Hooking inside `ApplyTransaction` would couple the
authoritative ledger to the read-model, fire mid-block, and force re-deriving accept/burn logic. **Why this funnel:**
`ConnectBlock` is the single funnel for both catch-up (`RunCatchUp`→`ConnectBlock`, `zslpindexer.cpp:201`) and live
(`ChainTip(added)`→`ConnectBlock`, `:264`), both under `cs_main`. It sits *after* the idempotence early-return
(`zslpindexer.cpp:283-284` returns before `:294`), so a re-delivered tip never double-counts.

**Connect/disconnect are SYNC INLINE, not queued.** `OnConnectBlock`/`OnDisconnect` do bounded RAM work (a few
`GetToken` point reads for the touched set + a few map inserts/erases using intrusive iterators) — sub-millisecond,
cheaper than the store writes just done in the same function. A background queue would reintroduce a lagging cursor and
reorg-ordering hazards for no benefit. Crash-mid-block heals by construction: the catalog has no persisted state; the
store's `'T'` tip marker is the truth and the catalog re-derives from wherever the store resumed.

**Go-live rebuild placement — OFF `cs_main`** (`[FIX-PERF-medium-init-csmain]`): under the `if (atTip)` block, register
the validation interface and set `m_synced` while `cs_main` is held; then, **before returning, on the same
`zcl-zslpsync` background thread but after releasing `cs_main`**, call `g_nftCatalog->Rebuild(store)`. `Rebuild` uses
`ForEachToken` (the O(N) raw scan), builds into **local** containers (skipping `documentUrl` — not a catalog field —
and `reserve()`-ing to cut reallocation), and swaps-publishes under one short `cs_catalog` hold. The first live
`ChainTip→OnConnectBlock` cannot run before `RegisterValidationInterface`, and a debug assert in `OnConnectBlock` checks
`IsReady()` to catch any future reordering. The accepted residual is the inherited startup-window orphan class
(self-correcting only on the next version-bump wipe; documented, NON-consensus, gated behind `IsReady()`).

### 4c. init.cpp wiring (verified anchors) + P4 flags + IBD guards

- **Catalog rides the indexer.** No separate init.cpp Start call for the catalog object; it is allocated/freed inside
  `StartZSLPIndexer`/`StopZSLPIndexer`, gated by the existing `-zslpindex` at `init.cpp:3309` (default on). **No new
  `-nftcatalog` flag** (it could only be a no-op-when-index-off).
- **REST registration — race-free window** (`[FIX-CORR-high-restreg]`): call `StartNftREST()` in the window between
  `InitHTTPServer()` (`init.cpp:1508`) and `StartHTTPServer()` (`init.cpp:1516`), beside `StartHTTPRPC`/`StartREST`
  (`init.cpp:1512-1514`). The handler is ready-tolerant (empty until `IsReady()`), so registering before the catalog is
  populated is safe and avoids racing the live worker threads. **Do not** register at `init.cpp:3311`.
- **Teardown — strict reverse** (`[FIX-SEC-low-teardown-uaf]`): `StopNftREST()` (UnregisterHTTPHandler) with the HTTP
  block; crucially `StopHTTPServer()` at `init.cpp:231` calls `workQueue->WaitExit()` which **drains/joins the HTTP
  worker threads** (verified `httpserver.cpp:477-479`). Hard ordering invariant: **join HTTP workers (StopHTTPServer,
  init.cpp:231) → free catalog (inside StopZSLPIndexer, init.cpp:301) → free store.** The handler also checks a shutdown
  flag at entry and 503s if set, so a late worker no-ops instead of dereferencing freed state.
- **P4 flag flip:** `init.cpp:3299` `fNftMarket = GetBoolArg("-nftmarket", true)` → **`false`**; `main.cpp:84`
  `bool fNftMarket = true` → **`false`**. Update the help string `init.cpp:541` to `(default: 0)`.
- **IBD guards** (`[FIX-SEC-high-ibd]`, `[FIX-CORR-low-ibd-lines]` — re-verify lines at edit time, do not hardcode blindly):
  - GETNFTINV solicit, `main.cpp:6328`: `if (NftMarketActive())` → `if (NftMarketActive() && !IsInitialBlockDownload())`.
  - NFTOFFER accept handler, top of body after the `NftMarketActive()` check at `main.cpp:6618`, **before** the
    NftVerify-under-`cs_main` block (`main.cpp:6679`): add `if (IsInitialBlockDownload()) return true; // accept-skip, no Misbehaving`.
  - GETNFTINV/GETNFTOFFER serve (`main.cpp:6512`/`6584`): short-circuit during IBD (don't advertise/serve a stale digest).
  - REST gates every payload on `IsSynced()` and surfaces `ibd=IsInitialBlockDownload()` in `/nft/health`.

---

## 5. REST surface (routes + JSON + security gate + offers join + sale detector)

Files: `src/nft/nftrest.{h,cpp}`. Prefix `"/nft/"`, `exactMatch=false` (the RPC `"/"` handler is `exactMatch=true`, so it
never shadows). One `WriteReply` per path. UTF-8 JSON. All ZCL amounts in **zatoshi integers** under `*Zat` keys (never
float "ZEC"). Pagination uniform: `?from=&count=`, with a single shared clamp helper.

### 5a. The shared request guards (folds in the SECURITY pass)

```cpp
static const size_t NFT_REST_MAX_URI = 512;
static const size_t NFT_REST_MAX_Q   = 128;
static const int    NFT_REST_PAGE_MAX = 100;

// [FIX-SEC-high-page] / [FIX-XB-low-narrow]: ONE shared parser. count==0 means
// DEFAULT PAGE, never "all". Uses ParseInt32 (not atoi — atoi has no error signal).
static bool ParsePage(const std::string& q, int& from, int& count) {
    long f = 0, c = 0;
    if (!GetIntParam(q, "from", f) || !GetIntParam(q, "count", c)) return false; // ParseInt32-backed
    if (f < 0) f = 0; if (f > INT_MAX) f = INT_MAX;
    if (c <= 0 || c > NFT_REST_PAGE_MAX) c = NFT_REST_PAGE_MAX;   // 0 => full page, NEVER all
    from = (int)f; count = (int)c;
    return true;
}

// [FIX-SEC-medium-idparse]: reject garbage ids (SetHex silently zero-fills).
static bool ParseId(const std::string& seg, uint256& out) {
    if (!IsHex(seg) || seg.size() != 64) return false;   // rejects %,/,.,NUL, odd/over-length
    out.SetHex(seg);                                       // apply the SAME byte convention as render
    return true;
}
```

### 5b. Security gate (real symbols; verified)

```cpp
static volatile bool g_nftRestShuttingDown = false;   // [FIX-SEC-low-teardown-uaf]

static void NftRestHandler(HTTPRequest* req, const std::string& strURIPart) {
    if (g_nftRestShuttingDown) { req->WriteReply(HTTP_SERVICE_UNAVAILABLE); return; }

    // (1) METHOD: GET only (httpserver.h:68 enum). HEAD/POST/PUT/UNKNOWN -> 405.
    if (req->GetRequestMethod() != HTTPRequest::GET) { req->WriteReply(HTTP_BAD_METHOD); return; }

    // (2) PEER GATE — kernel SOCKET peer (GetPeer, httpserver.cpp:610), NOT Host header.
    //     [FIX-SEC-high-islocal]: do NOT trust IsLocal() (netbase.cpp:876 admits the
    //     whole 0.0.0.0/8 via GetByte(3)==0, plus mapped-IPv6 edges). Accept ONLY
    //     real loopback.
    CService peer = req->GetPeer();
    bool ok = peer.IsValid() && req->GetPeer().GetPort() != 0 &&
              ( (peer.IsIPv4() && peer.GetByte(3) == 127) ||      // 127.0.0.0/8
                IsExactlyIPv6Loopback(peer) );                    // ::1 only
    if (!ok) { req->WriteReply(HTTP_FORBIDDEN); return; }         // no body echo

    // (3) Anti-DNS-rebinding defense in depth ([FIX-SEC-medium-infoleak]): reject
    //     unless Host is 127.0.0.1 / localhost / [::1] / empty.
    if (!HostIsLoopback(req)) { req->WriteReply(HTTP_FORBIDDEN); return; }

    // (4) SIZE: bound the URI.
    std::string uri = req->GetURI();
    if (uri.size() > NFT_REST_MAX_URI) { req->WriteReply(HTTP_BAD_REQUEST); return; }

    // (5) PARSE: split strURIPart on the FIRST LITERAL '?' BEFORE any decode
    //     ([FIX-SEC-medium-urldecode]); decode query VALUES once via
    //     evhttp_parse_query_str; do NOT url-decode the path id (require clean hex).
    std::string path, query; SplitOnFirstQ(strURIPart, path, query);

    std::string body; int status = HTTP_NOT_FOUND;
    if      (path == "health")                status = HandleHealth(query, body);
    else if (path == "collections")           status = HandleCollections(query, body);
    else if (StartsWith(path,"collection/"))  status = HandleCollection(path.substr(11), query, body);
    else if (StartsWith(path,"item/"))        status = HandleItem(path.substr(5), query, body);
    else if (path == "search")                status = HandleSearch(query, body);   // 400 if no q
    else if (path == "offers")                status = HandleOffers(query, body);   // metadata only
    else if (path == "floor")                 status = HandleFloor(query, body);
    else if (StartsWith(path,"offer/"))       status = HandleOfferFetch(path.substr(6), body); // ONLY offerHex route
    // NO write/POST/PUT route; NO media route (content liability permanently cut).

    if (status != HTTP_OK) { req->WriteReply(status); return; }   // 4xx/5xx: no JSON body, no echo
    req->WriteHeader("Content-Type", "application/json");          // Content-Type only on 200
    req->WriteReply(HTTP_OK, body);
}

bool StartNftREST() { RegisterHTTPHandler("/nft/", false, NftRestHandler); return true; }
void StopNftREST()  { g_nftRestShuttingDown = true; UnregisterHTTPHandler("/nft/", false); }
```

Common 200 envelope: `{ "chain":"main", "indexerSynced":<bool>, "ibd":<bool>, "tipHeight":<int>, "result":<payload> }`.
When `indexerSynced==false`, payloads are empty arrays / null (never partial truth), still 200 so clients poll. `tipHeight`
uses `TRY_LOCK(cs_main)` and reports `-1` on contention (`/nft/health` must never block — `[FIX-PERF-high-health]`).

### 5c. Routes (JSON shapes)

- **GET /nft/health** (exact) — `ok, indexerSynced, ibd, tipHeight, catalogTokens` (= `CNftCatalog::Size()`, O(1),
  **never** `TokenCount()` — `[FIX-PERF-high-health]`), optional debug-gated `catalogRebuildMs`, and (`#ifdef ENABLE_WALLET`)
  `offerPool:{offers,bytes,nftmarket}`; in a no-wallet build the `offerPool` object is omitted and `offersAvailable:false`
  is set (`[FIX-SEC-critical-wallet]`).
- **GET /nft/collections** `?from&count&sort=newest|name` — authorized collections, paginated. Reads the **RAM rollup**
  `m_collAgg[groupId].memberCount` (never `CountCollectionMembers` per collection — `[FIX-PERF-medium-collfloor]`). Floor/
  depth are joined for ONLY the page's collection tokenIds (see §5d), never a whole-pool scan.
- **GET /nft/collection/<groupId>** `?from&count` — one collection + a page of authorized child item-summaries; 404 if unknown.
- **GET /nft/item/<tokenId>** `?holders=N&transfers=N` — full detail. Display fields served straight from the catalog row
  (no store read, no `cs_main`). `holders`/`transfers`/`documentUrl` (the ONLY store reads) are fetched here, clamped ≤100,
  newest-first, plus `recentSales` (advisory, §5e). `isNft = decimals==0 && totalMinted==1`. 404 if unknown.
- **GET /nft/search** `?q=&from&count` — inverted-index AND-of-terms + prefix; empty `q` ⇒ 400; `|q|≤128`, ≤8 terms,
  each term ≥2 chars (`[FIX-PERF-high-search]`, `[FIX-SEC-medium-rate]`). Iterates the **smallest** posting set first,
  tests membership in the others, **stops once `from+count` ordered hits are collected** (no full intersection); prefix
  expansion capped at K vocab terms; floor join only for the emitted slice.
- **GET /nft/offers** `?token=&maxPriceZat=&minExpiry=&from&count` — live offer **metadata** for a token, price-asc, via
  `BrowseMeta` (scalars only, §5d). Each element: `offerHash, priceZat, expiryHeight, serializedBytes, fetchPath`. **No
  offerHex.** `#ifdef ENABLE_WALLET`; no-wallet ⇒ empty + `offersAvailable:false`.
- **GET /nft/floor** `?token=` — per-token floor+depth from the per-token floor cache (O(1)). **The no-token whole-pool
  table is paginated** via a new `FloorByToken(int from,int count)` overload, never an unbounded dump
  (`[FIX-SEC-critical-unbounded]`). `#ifdef ENABLE_WALLET`.
- **GET /nft/offer/<hash>** — the **only** route that returns `offerHex`, via `g_offerPool.Get(hash, blob)` (RAM-only;
  404 if `!Has(hash)`). `#ifdef ENABLE_WALLET`; no-wallet ⇒ 404. Mirrors the wire `GETNFTOFFER→NFTOFFER` exchange.

`tokenId`/`groupId`/`offerHash` rendered **reversed** (display); **`documentHash` rendered with plain `GetHex()`** — it is
already on-chain display order from the parser (`[FIX-CORR-low-dochash]`). Inbound path ids parsed with the SAME reversal
as render so lookups hit; a gtest round-trips render→parse→lookup.

### 5d. Offers RAM-join + the exact offerHex stripping point (`[FIX-SEC-high-offerhexstruct]`, `[FIX-PERF-critical-floor]`)

The catalog stores no price; price is joined from `g_offerPool` at query time, **after releasing `cs_catalog`**, via
public methods only (each takes `cs_pool` internally; never nested under `cs_catalog`). To make offerHex leakage
**structurally impossible** and the join **cheap**, two localized offerpool changes (RAM-only, `#ifdef ENABLE_WALLET`):

1. **`struct COfferPoolMeta { uint256 offerHash, tokenId; int64_t priceZat; uint32_t expiryHeight; size_t serializedBytes; };`**
   and **`std::vector<COfferPoolMeta> COfferPool::BrowseMeta(const COfferPoolFilter&) const;`** — copies ONLY scalars under
   `cs_pool`, **never** `entry.blob`. `/nft/offers`, `/nft/floor`, `/nft/collections`, item/search floor-joins call
   `BrowseMeta`/floor — `offerHex` is not even in their reachable data. The blob-returning `Get()` is reserved for
   `/nft/offer/<hash>`. A gtest greps every non-buy route's JSON for a known offerHex substring (asserts absent) and checks
   `nftrest.cpp` has no `.blob` token outside the single buy handler.
2. **Per-token secondary index inside `COfferPool`** (`[FIX-PERF-critical-floor]`): add
   `std::map<uint256, std::multimap<int64_t,uint256> > m_byToken` (tokenId → price-sorted offerHashes) and
   `std::map<uint256, COfferPoolFloor> m_floorCache` (tokenId → {floor,depth}), maintained **incrementally** in
   `Insert`/`EraseLocked` under `cs_pool`. Then: `Browse(filter.hasTokenId)`/`BrowseMeta` seek the token's sub-map
   directly (k entries, no global sort); per-token floor is O(1); the whole-pool floor table is already materialized
   (paginated, no per-call rebuild). This eliminates the O(N) full-pool scan + per-call `std::map` build that the original
   `FloorByToken()` (`offerpool.cpp:251-280`) and `Browse()` (`:185-223`) do on **every** request. For collection/page
   floor, join ONLY the ≤100 tokenIds on the page against `m_floorCache` — O(page), never O(pool).

**Stripping point (restated):** the `/nft/offers`/floor/collection serializers read `e.offerHash/e.priceZat/
e.expiryHeight/e.serializedBytes` from `COfferPoolMeta` and **never reference `e.blob`**. offerHex therefore never enters
the catalog, never enters any JSON except `/nft/offer/<hash>`, and — being never written — never reaches disk.

### 5e. Advisory sale detector (`item.recentSales`, optional `/nft/sales`) — ADVISORY-only

Reads `CZSLPStore::ListTransfers(tokenId, 0, N, out)` (the authoritative `'x'` transfer log; `{height, txid, vout}`). A pure
read over committed store state; no new index, no new write seam. Emits `{height, txid, vout, looksLikeSale, priceHintZat,
advisory:true}`. **`advisory:true` is hard-coded; the floor/sort path ignores it entirely.** `priceHintZat` is `null` from
the chain (the on-chain SEND carries no price — price lived only in the now-evicted RAM offer) and stays `null` unless a
confidently-matched in-RAM record exists, even then labeled a hint. Rationale: an NFT settlement is structurally a
`ZSLP_MSG_SEND` of qty 1, indistinguishable from a gift, self-transfer, or coincidental template match — so the detector
classifies on shape only (`looksLikeSale`), tags everything `advisory`, and **floor/depth come exclusively from live
`g_offerPool`**. Removing the detector changes no other field.

### 5f. Threading / locking (worker-thread safety) + DoS

Strict lock order (acquire/release, never nested across categories): `cs_catalog` (copy the page's rows out) → **release** →
(item detail only) `cs_main` briefly for bounded store reads (clamped ≤100; never across `WriteReply`) → release → `g_offerPool`
public methods (own `cs_pool`) for floor/offers join → release → build JSON → `WriteReply`. Readers never take `cs_main` on
the list/collection/search hot paths (`[FIX-PERF-medium-rest-cs_main]`: all display fields are in the row). No deadlock:
`cs_main` is never acquired after `cs_pool`/`cs_catalog`; the offerpool is touched only through its self-locking API.
Backpressure: the framework's 4 worker threads + 16-deep work queue (500 when full) + 30s idle timeout, plus per-request
clamps (`count`/`q`/URI), plus a cheap per-process token bucket on `/nft/` returning 429/503 when exceeded
(`[FIX-SEC-medium-rate]` — loopback ≠ trusted; shares the RPC pool, so clamps protect RPC too). `reserve()` the JSON output
to `count * ~300` bytes (`[FIX-PERF-low-reserve]`); every list route is paginated (a tested invariant).

---

## 6. Build integration + cross-build + proot recipe + gtest

**Verdict: NO NEW DEPENDENCY.** Reuses in-tree leveldb/`CDBWrapper` (read-only via `CZSLPStore`) + std/boost already
tree-wide. **No** `depends/packages/sqlite.mk`, **no** `packages.mk` edit, **no** `configure.ac` change (daemon stays
`-std=c++11 noext`, `configure.ac:68`), **no** new `_LDADD`.

### 6a. `src/Makefile.am` — the only build-system change (verified anchors)

```diff
   rpc/nftoffer.h \
   nft/offerpool.h \
+  nft/nftcatalog.h \
+  nft/nftrest.h \
   rpc/protocol.h \           # (header list, after Makefile.am:185)
```
```diff
   rpc/nftoffer.cpp \
   nft/offerpool.cpp \
+  nft/nftcatalog.cpp \
+  nft/nftrest.cpp \
   script/sigcache.cpp \      # (libbitcoin_server_a_SOURCES, after Makefile.am:294)
```

leveldb/`CDBWrapper` already linked: `dbwrapper.cpp` in the server lib (`Makefile.am:274`); `zclassicd_LDADD` has
`$(LIBLEVELDB)`+`$(LIBMEMENV)` (`Makefile.am:480-481`); gtest links the server lib + leveldb
(`Makefile.gtest.include:66`). **Decide nftrest's existence before editing** (`[FIX-XB-low-sources]`): the diffs above list
nftrest as a separate TU — ship both files. If you instead fold REST into `nftcatalog.cpp`, drop the two nftrest lines
(never list a SOURCES entry whose `.cpp` is absent).

### 6b. Cross-build (linux glibc-2.31 proot / mingw / macOS-cross)

Unaffected — no new dependency. The only constraints are C++11 (no `std::optional`/`string_view`; use
`boost::optional`/`boost::function`) and the `#ifdef ENABLE_WALLET` discipline (§6d) so the `--disable-wallet` target links.
Pagination is signed `int` at the store boundary (clamp `size_t`→`int` after the ≤100 clamp) to stay
`-Wall -Wextra`/`--enable-werror`-clean (`[FIX-XB-low-narrow]`).

### 6c. proot build+test recipe — `/home/rhett/zclbuild/focal/build/p4-build-test.sh`

Invocation (verified prun path/binds — `[FIX-XB-high-prun]`):
```bash
cd /home/rhett/zclbuild && ./prun bash /build/p4-build-test.sh
```
prun is `/home/rhett/zclbuild/prun` (NOT `focal/prun`); it binds `focal/build:/build` (so a script at
`focal/build/p4-build-test.sh` is `/build/p4-build-test.sh`), `zclassic:/src/daemon`, `-w /build`. Script: `SRC=/src/daemon/src`,
`DST=/build/daemon/src`. Because `Makefile.am`/`Makefile.gtest.include` change AND `AM_MAINTAINER_MODE([enable])` is on
(`configure.ac:44`), the **correct minimal step is cp the edited `.am` files then plain `make -j`** — maintainer-mode
detects `Makefile.am` newer than `Makefile.in` and reruns automake+config.status (`[FIX-XB-medium-reconfigure]`; drop the
fragile `config.status src/Makefile` line; keep `autogen.sh + configure --enable-tests` only as a guarded fallback if
`Makefile.in` fails to regenerate). cp the touched files (`Makefile.am Makefile.gtest.include init.cpp main.h main.cpp
httpserver.* nft/offerpool.* rpc/nftoffer.* zslp/zslpstore.* zslp/zslpindexer.* nft/nftcatalog.* nft/nftrest.*
gtest/test_nftcatalog.cpp gtest/test_offerpool.cpp gtest/test_nftoffer.cpp`, each `[ -f ] || continue`), `make -j$(nproc) -k`,
assert `src/zclassicd` and `src/zcash-gtest` exist (binary is **zclassicd**, gtest is **zcash-gtest** — never zcashd), then
list+run `--gtest_filter='NftCatalog.*:OfferPool.*:*NftOffer*:*NftVerify*'` and assert `NftCatalog.*` count > 0 (never trust
exit-0).

**Build-matrix MUST** (`[FIX-SEC-critical-wallet]`/`[FIX-CORR-critical-wallet]`): the script builds **both**
`--enable-wallet` and `--disable-wallet` and asserts `zclassicd` links in **both** (catch the no-wallet link break before
ship). The price-join gtest is `#ifdef ENABLE_WALLET`-guarded.

### 6d. `#ifdef ENABLE_WALLET` discipline (the cross-cutting build correctness fix)

`g_offerPool`/`COfferPool*`/`CNftOfferBlob` are all `#ifdef ENABLE_WALLET` (verified `offerpool.h:34`, `offerpool.cpp:17-290`,
`offerpool.h:202`). The catalog (pure `CZSLPStore` read-model) stays **unconditional**. Every offerpool-touching path in
`nftrest.cpp` (the price/floor join, `/nft/offers`, `/nft/floor`, `/nft/offer/<hash>`, the `offerPool` block in
`/nft/health`) is wrapped `#ifdef ENABLE_WALLET`; the no-wallet branch degrades honestly: `floorZat:null`, `offerCount:0`,
`offerPool` omitted, those routes 404/empty with `offersAvailable:false`. Document in `nftcatalog.h` that the catalog is
wallet-independent but the price overlay is wallet-gated.

### 6e. New gtest + registration

New file `src/gtest/test_nftcatalog.cpp` (suite `NftCatalog.*`). Coverage: raw-scan rebuild (the `ForEachToken`/`TokenCount`
shape), inverted-index tokenization + AND-of-terms (smallest-set-first, early-stop) + prefix + a non-ASCII normalization
case, newest-first `m_byHeight` order, per-`groupId` collection multimap + RAM rollup count, **intrusive-iterator erase**
under the `totalMinted==1` collision (proves no equal_range blowup), `OnConnectBlock`/`OnDisconnect` re-derive consistency
from the authoritative touched-set, INV-3 grep (no offerHex/price fields), the read-lock guard, id render→parse→lookup
round-trip, documentHash byte-order, and (`#ifdef ENABLE_WALLET`) a price-join smoke test pulling floor from
`g_offerPool` (never from the catalog). Register in `src/Makefile.gtest.include` after `test_offerpool.cpp` (line 55):
```diff
 	gtest/test_nftoffer.cpp \
 	gtest/test_offerpool.cpp \
+	gtest/test_nftcatalog.cpp \
 	gtest/test_blockindexcache.cpp
```
No `zcash_gtest_LDADD` change (server lib + leveldb already on the link line, `Makefile.gtest.include:66`).

---

## 7. Ordered implementation plan (P4..P8)

Each phase: independently shippable, NON-consensus, master HELD, green L0/L1 + the named gtest/regtest before the next.

### P4 — Opt-in default flip + IBD guards (net-safety foundation)
- **Files:** `src/main.cpp` (`:84` flag, `:6328` solicit, `:6512`/`:6584` serve, `:6618-6679` accept), `src/init.cpp`
  (`:3299` flag, `:541` help).
- **Build:** flip `fNftMarket` default → `false` (both decls); add `&& !IsInitialBlockDownload()` to GETNFTINV solicit;
  add `if (IsInitialBlockDownload()) return true;` (no Misbehaving) to NFTOFFER accept before NftVerify; IBD short-circuit
  the GETNFTINV/GETNFTOFFER serve paths.
- **Proves:** a 2-node regtest where one node is in IBD neither solicits GETNFTINV on verack nor runs NftVerify on inbound
  NFTOFFER (no Misbehaving), and a default node does not relay others' offers until `-nftmarket=1`.

### P5 — Catalog foundation (RAM read-model, no hooks yet)
- **Files:** `src/nft/nftcatalog.{h,cpp}` (new), `src/zslp/zslpstore.{h,cpp}` (add `ForEachToken`), `src/Makefile.am`
  (two header + two source lines — or just nftcatalog if REST folded), `src/gtest/test_nftcatalog.cpp` (new),
  `src/Makefile.gtest.include`.
- **Build:** the data model (§3a), the read API (§3b), `Rebuild` via `ForEachToken` (O(N) raw scan), intrusive-iterator
  erase, sorted-vector inverted index, normalization helper, RAM collection rollup. No indexer hook yet — `Rebuild` is
  driven directly by the test.
- **Proves:** `NftCatalog.*` gtest green (rebuild determinism INV-4, search correctness + bounds, erase under
  `totalMinted==1`, INV-3 grep, normalization, id round-trip, documentHash byte-order).

### P6 — Indexer hook + init wiring (catalog goes live)
- **Files:** `src/zslp/zslpstore.{h,cpp}` (touched-set out-params on `ConnectBlockEnd`/`DisconnectBlock`),
  `src/zslp/zslpindexer.cpp` (include + allocate + `OnConnectBlock`/`OnDisconnect`/`Rebuild` at the §4 anchors + free),
  `src/init.cpp` (catalog rides indexer; no new flag).
- **Build:** the authoritative touched-set, the block-end sync-inline hooks, the OFF-`cs_main` go-live rebuild + ordering
  assert, strict-reverse teardown.
- **Proves:** a regtest that mints GENESIS/MINT then triggers a reorg shows `Size()` reconciles to the store at rebuild
  (INV-1/INV-6), reorg erases orphaned genesis rows (INV-5), and no double-count on a re-delivered tip; `nft_catalogverify`
  RPC (test-only) passes.

### P7 — REST + security gate (loopback read surface)
- **Files:** `src/nft/nftrest.{h,cpp}` (new), `src/init.cpp` (`StartNftREST` in the race-free window `:1508-1516`;
  `StopNftREST` with the HTTP block; ordering invariant join-workers→free-catalog).
- **Build:** the route table, `ParsePage`/`ParseId`, the peer-IP + Host + method gate (strict loopback, not `IsLocal()`),
  the §5f locking, the token bucket, the no-body error path, the shutdown flag.
- **Proves:** gtest/regtest: non-loopback peer (incl. `0.0.0.0/8` and mapped-IPv6) → 403; non-GET → 405; garbage id → 400;
  `count=0`/no-token → bounded default page (never full dump); not-synced → 200 empty; teardown-during-request → 503 no UAF.

### P8 — Offers route + advisory sale detector (price join + buy step)
- **Files:** `src/nft/offerpool.{h,cpp}` (add `COfferPoolMeta`+`BrowseMeta`, the per-token index + floor cache, paginated
  `FloorByToken(from,count)` — all `#ifdef ENABLE_WALLET`), `src/nft/nftrest.{h,cpp}` (`/nft/offers`, `/nft/floor`,
  `/nft/offer/<hash>`, `recentSales`, the `#ifdef ENABLE_WALLET` degrade).
- **Build:** the incremental per-token offerpool index (O(log N + k) join, O(1) floor), the metadata-only stripping point,
  the page-scoped floor join, the advisory detector over `ListTransfers`.
- **Proves:** gtest: offerHex appears in **only** `/nft/offer/<hash>` (grep all other route bodies → absent + no `.blob`
  outside the buy handler); floor/depth match `g_offerPool` for a seeded pool with O(page) work; `recentSales` never alters
  floor; **`--disable-wallet` build links and those routes 404/`offersAvailable:false`.**

---

## 8. Open risks / explicit non-goals

**Permanently cut (non-goals):**
- **Media hosting** — no route ever returns image/document bytes (content liability). `documentUrl`/`documentHash` are
  metadata only.
- **Any write/mutation REST route** — GET-only; the surface does no signing, no offer submission, no mempool action.
- **Persisting offerHex / any offer blob to disk** — offerHex lives only in RAM `g_offerPool`; the catalog/REST store/return
  only offer metadata; the buyer fetches the blob from RAM at buy-time.
- **A persisted on-disk catalog** — the model is RAM-only by decision; wipe-and-rebuild is structural.

**Open risks (with mitigations / deferrals):**
- **Hand-rolled Unicode normalization** — one shared `normalizeTerm` (lowercase + NFKD-ish fold) on both index and query
  side; tested with a non-Latin name. A naive ASCII tolower would mishandle non-Latin names.
- **RAM footprint / rebuild latency at scale** — instrument token count + rebuild ms; the documented escape hatch is the
  **hybrid** (persist cold metadata to leveldb, keep hot indices in RAM) as a localized later change; do not pre-build it.
- **Inherited startup-window orphan class** — a reorg between catch-up chunks before indexer registration
  (`zslpindexer.cpp:149-156`) delivers no DisconnectBlock; the catalog inherits exactly the store's behavior and clears only
  on a `ZSLP_INDEX_VERSION`/`NFT_CATALOG_VERSION` wipe. NON-consensus, vanishingly rare, gated behind `IsReady()`.
- **Per-process REST rate limit precision** — loopback ≠ trusted (any local process + a localhost-rebinding browser); the
  token bucket + Host gate + clamps are defense-in-depth, not a hard quota.
- **Deferred:** the optional `/nft/sales` feed (advisory) beyond `item.recentSales`; an incremental `CZSLPStore` token
  counter (only if a cheap *live* store count is ever needed); the hybrid persist escape hatch.

---

## 9. Must-fix ledger

| ID | Sev | Pass / Component | Finding (short) | Addressed in |
|---|---|---|---|---|
| FIX-PERF-critical-floor | critical | PERF / offers | Browse/FloorByToken are O(N) full-pool scan + per-call map build on every request | §5d per-token `m_byToken` + `m_floorCache` incremental index; page-scoped join |
| FIX-PERF-critical-wallet | critical | PERF / build | offerpool is `#ifdef ENABLE_WALLET`; no-wallet build link-breaks | §6d guard discipline + §6c build matrix |
| FIX-SEC-critical-wallet | critical | SEC / build | same no-wallet link break; degrade honestly | §6d + §5c `offersAvailable:false` + §6c assert links in both |
| FIX-CORR-critical-wallet | critical | CORR / rest | same; price overlay unavailable in ship build | §6d + §6c matrix + nftcatalog.h doc note |
| FIX-SEC-critical-unbounded | critical | SEC / rest | count==0 means "all"; FloorByToken can't paginate | §5a `count==0⇒default page`; §5c paginated `FloorByToken(from,count)`; page-scoped join |
| FIX-CORR-critical-touchedset | critical | CORR / hook | disconnect hook can't get affected set; vtx re-parse diverges | §4a store emits `tokenMods`+`tokenErased`/genesis+MINT ids; §3b authoritative re-read |
| FIX-CORR-critical-INVcount | critical | CORR / catalog | INV-1/6 `Size()==TokenCount()` per-block = O(N) leveldb scan under cs_main | §3c INV reconcile at rebuild only; `Size()`=`m_rows.size()` |
| FIX-PERF-high-tokencount | high | PERF / rest | `/nft/health` + per-block assert call full-scan `TokenCount()` | §5c health uses `CNftCatalog::Size()`; assert gated to rebuild |
| FIX-PERF-high-erase | high | PERF / catalog | equal_range erase on colliding keys (totalMinted==1) is O(total_NFTs) | §3a intrusive multimap iterators in the row; O(log n) erase |
| FIX-PERF-high-search | high | PERF / rest | search builds full intersection + posting sets before paginating | §5c smallest-set-first + early-stop + prefix/term caps |
| FIX-PERF-high-health | high | PERF / rest | `/nft/health` must never block | §5c `Size()` O(1); `TRY_LOCK(cs_main)` tip, -1 on contention |
| FIX-CORR-high-apimismatch | high | CORR / hook | two locked docs disagree on method set | §3b single reconciled API (`OnConnectBlock`/`OnDisconnect`/`Rebuild`) |
| FIX-CORR-high-rebuildON2 | high | CORR / catalog | paged ListTokens rebuild is O(N²) | §4a `ForEachToken` single raw scan; §3b `Rebuild` |
| FIX-CORR-high-restreg | high | CORR / rest | docs disagree on REST registration point; :3311 races workers | §4c register in race-free window `init.cpp:1508-1516` |
| FIX-SEC-high-ibd | high | SEC / hook | IBD guard absent in real code | §4c exact edits at `main.cpp:6328`/`6618`/`6679`/serve; P4 |
| FIX-SEC-high-page | high | SEC / rest | size_t/int mismatch; no shared clamp; atoi | §5a `ParsePage` (ParseInt32, clamp, signed int to store) |
| FIX-SEC-high-offerhexstruct | high | SEC / rest | offerHex leak prevented only by convention | §5d `COfferPoolMeta`/`BrowseMeta` (no blob reachable) + grep gtest |
| FIX-SEC-high-islocal | high | SEC / rest | `IsLocal()` admits 0.0.0.0/8 + mapped-IPv6 | §5b accept only 127.0.0.0/8 + exact ::1 |
| FIX-XB-high-prun | high | XB / build | wrong prun path + in-proot script path | §6c `./prun bash /build/p4-build-test.sh` |
| FIX-XB-high-include | high | XB / hook | zslpindexer.cpp has no nft include | §4b add `#include "nft/nftcatalog.h"` |
| FIX-PERF-medium-init-csmain | medium | PERF / init | rebuild under cs_main stalls validation | §4b go-live rebuild OFF cs_main; swap-publish; skip documentUrl |
| FIX-PERF-medium-rest-csmain | medium | PERF / rest | per-page materialize takes cs_main on workers | §3a display fields in row; §5f cs_main only for item-detail store reads |
| FIX-PERF-medium-collfloor | medium | PERF / offers | collection floor + CountCollectionMembers per page = leveldb scans | §3a RAM rollup `m_collAgg`; §5c read rollup; page-scoped floor join |
| FIX-PERF-medium-catalog-set | medium | PERF / catalog | std::set<uint256> postings are heavy/slow | §3a sorted std::vector postings + set_intersection |
| FIX-CORR-medium-sendbaton | medium | CORR / catalog | over-claim "SEND flips baton → upsert" | §3b only GENESIS/MINT mutate metadata; SEND no upsert |
| FIX-CORR-medium-selfheal | medium | CORR / init | MarkDirty self-heal has no producer | §3b/§3c MarkDirty removed; INV-6 restated honestly |
| FIX-CORR-medium-crashmid | medium | CORR / hook | crash-mid-block heal ordering subtlety | §4b ordering assert; debug `IsReady()` assert in OnConnectBlock |
| FIX-SEC-medium-idparse | medium | SEC / rest | SetHex zero-fills garbage ids | §5a `ParseId` (IsHex + len 64); symmetric byte order |
| FIX-SEC-medium-infoleak | medium | SEC / rest | error-body leak + DNS-rebinding enumeration | §5b no-body 4xx + Host loopback gate; debug-gated telemetry |
| FIX-SEC-medium-rate | medium | SEC / rest | no rate limit; search costly; shared RPC pool | §5c search caps; §5f token bucket 429/503 |
| FIX-SEC-medium-urldecode | medium | SEC / rest | decode-then-split / %00 hazard | §5a split on first literal '?' pre-decode; evhttp_parse_query_str values only |
| FIX-XB-medium-reconfigure | medium | XB / build | `config.status src/Makefile` uses stale Makefile.in | §6c rely on AM_MAINTAINER_MODE: cp + plain `make` |
| FIX-PERF-low-sendupsert | low | PERF / hook | re-upsert on every SEND (unchanged row) | §3b touched-set = GENESIS/MINT only |
| FIX-PERF-low-reserve | low | PERF / rest | JSON body no preallocation guidance | §5f `reserve(count*~300)`; paginate invariant |
| FIX-CORR-low-ibd-lines | low | CORR / hook | IBD guard line numbers imprecise; don't ban | §4c re-verify lines; accept-skip without Misbehaving |
| FIX-CORR-low-dochash | low | CORR / catalog | documentHash byte-order double-reverse | §5c render documentHash plain GetHex(); gtest |
| FIX-SEC-low-teardown-uaf | low | SEC / init | httpworker UAF if catalog freed mid-request | §4c join workers→free catalog→free store; shutdown flag 503 |
| FIX-XB-low-narrow | low | XB / catalog | size_t→int narrowing at store boundary | §3b/§5a signed int after ≤100 clamp; werror-clean |
| FIX-XB-low-symbolshape | low | XB / catalog | g_nftCatalog pointer vs g_offerPool value | §3b keep pointer (matches g_zslpIndexer); uniform null-check |
| FIX-XB-low-sources | low | XB / build | SOURCES lists nftrest.cpp that may not exist | §6a decide nftrest TU before editing; match files-in-commit |

**Count: 39 red-team findings folded in** (5 PERF-critical/high duplicated across SEC+CORR for the wallet-link issue are
listed once per pass where each raised it). By severity-and-source: 6 critical, 12 high, 13 medium, 8 low.
