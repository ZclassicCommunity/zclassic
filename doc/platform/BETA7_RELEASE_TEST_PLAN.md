# ZClassic Beta7 Release Test Plan

Status: release gate plan. Applies before merging beta7 to `master` or cutting
GUI artifacts.
Scope: daemon headless tests, GUI all-in-one tests, and livenet-readiness checks
for Tor, ZSLP/NFT, ZNAM, ZMARKET, voluntary content hosting, ZSOCIAL scaffolding,
and wallet AI integration.

## 1. Release Rules

Beta7 does not ship until these are true:

- no ZClassic consensus behavior changes for beta7 platform features;
- full native daemon build succeeds from a clean tree;
- `zcash-gtest` runs successfully;
- headless regtest/regnet scripts prove the new features compose;
- stock node defaults do not spider, relay, host, publish, or fetch arbitrary
  media;
- every spend, listing publication, buy, unhost, mirror publish, social publish,
  or AI-assisted side effect requires an explicit user/operator action;
- portable Linux, Windows, and macOS GUI release gates pass after daemon changes
  are embedded or packaged.

## 2. Clean Build Gate

Run from a clean beta7 integration checkout. Do not use the contaminated mixed
Windows/Linux build directory.

```bash
cd /home/rhett/github/zclassic

make clean || true
make -C src/snark clean || true
find src -type f \( -name '*.o' -o -name '*.a' -o -name '*.lo' -o -name '*.la' -o -name '*.exe' -o -name 'zclassicd' -o -name 'zclassic-cli' -o -name 'zclassic-tx' -o -name 'zcash-gtest' \) -delete
find src -type d \( -name .deps -o -name .libs \) -prune -exec rm -rf {} +

unset CC CXX CPPFLAGS CXXFLAGS LDFLAGS PKG_CONFIG PKG_CONFIG_LIBDIR PKG_CONFIG_PATH CONFIG_SITE
HOST="$(./depends/config.guess)" ./zcutil/build.sh -j"$(nproc)"

make -C src zcash-gtest_check V=1
file src/zclassicd src/zcash-gtest
```

Assertions:

- `src/zclassicd` and `src/zcash-gtest` are native Linux binaries for the host.
- `evthread_use_pthreads` is available through native libevent pthreads headers.
- No `.exe` or COFF objects remain in the native build tree.
- `git diff --check` stays clean.

## 3. Headless Regtest Matrix

Add a new script once the Worker 2/3 branches are reconciled:

```
qa/zmarket/beta7-headless-regtest.sh
```

Use four isolated nodes:

| Node | Role | Required posture |
|---|---|---|
| A | seller/name/content owner | may create ZNAM, mint NFT, create listing, optionally host exact selected file |
| B | buyer | browses local index and buys only after revalidation |
| C | spider/index | builds local market from signed records, hosts no files |
| D | relay/router | relays signed market/social route records, hosts no files |

Base flags:

```bash
-regtest -server -listen=1 -discover=0 -dnsseed=0 -debug=net -debug=zmarket
```

Feature flags are explicit and tested independently:

```bash
-znamindex=1
-nftmarket=1
-nftmarketspider=1
-nftmarketrelay=1
-nftmarkettor=off|prefer|only
-nftcontenthost=1
-embeddedtor=1
```

The script should skip a subtest with a clear reason when a beta7 RPC or flag is
not implemented yet. It should not silently pass missing functionality.

Before feature tests, verify the source/RPC surface:

```bash
src/zclassicd -regtest -zslpindex=1 -txindex -listen=0 \
  -nuparams=5ba81b19:1 -nuparams=76b809bb:1
src/zclassic-cli -regtest help zslp_genesis
src/zclassic-cli -regtest help nft_makeoffer
src/zclassic-cli -regtest help z_senddatafile
```

Expected:

- ZSLP/NFT RPCs are present when enabled.
- Legacy datachannel RPCs are absent or disabled by default in release mode.
- Missing beta7 RPCs fail the matrix explicitly rather than being ignored.

Restore or port these release tests from `feature/zslp-nft-indexer` if they are
not present in the final integration branch:

- `qa/zslp/zslp-nft-regtest.sh`
- `qa/zslp/nft-sell-regtest.sh`
- `qa/zslp/zdc-xwallet-regtest.sh` as dev/legacy-only, not release-default

## 4. Headless Scenarios

### Defaults

Start one stock regtest node.

Assert:

- market disabled unless explicitly enabled;
- spider queue size is zero;
- relay disabled;
- content hosted count is zero;
- social relay disabled;
- embedded Tor disabled unless explicitly enabled;
- no remote content fetch occurs while listing NFTs.

### ZSLP/NFT Ownership

Use restored or new `qa/zslp/*.sh` scripts to:

- activate required regtest upgrade heights;
- mine spendable transparent funds;
- mint a collection and NFT;
- verify `document_hash` uses the canonical content fingerprint;
- transfer NFT ownership;
- reorg one block and prove index rollback/rebuild behavior.

### ZNAM

On node A:

- register a name;
- set bounded text and route/content records;
- transfer ownership;
- expire/renew if expiry logic exists;
- reorg and confirm deterministic undo.

Assert:

- invalid or unauthorized ZNAM records are ignored, not consensus failures;
- CONTENT values are opaque and trigger no fetch or hosting;
- name-to-market/social badges show valid, expired, transferred, and mismatch
  states.

### ZMARKET Yard Sale

On node A:

- create a public listing record for the owned NFT;
- publish it only through explicit market mode;
- create buyer-specific sealed offer only after a buyer request.

On node C:

- spider signed listing inventory;
- index only valid bounded records;
- do not fetch media;
- do not host content.

On node B:

- browse local market index;
- request buy route;
- re-run `nft_verifyoffer`;
- call settlement/take flow only after explicit confirmation.

Assert:

- filled, stale, expired, forged, wrong-owner, wrong-name, and wrong-content-root
  offers are not displayed as buyable;
- route packets are deduped, TTL bounded, and hop limited;
- Tor-only mode rejects clearnet market routes;
- disabling market flags stops discovery but direct pasted-offer verification
  still works.

Concrete future scripts:

- `qa/zmarket/market-defaults-regtest.py`
- `qa/zmarket/market-submit-search-regtest.py`
- `qa/zmarket/market-relay-spider-regnet.py`

### Content Hosting

On node A:

- enabling market does not host files;
- enabling embedded Tor does not host files;
- minting or owning an NFT does not host files;
- adding an explicit local file with matching content root increases hosted
  count by one;
- wrong hash, missing file, directory path, oversized file, or unknown root is
  rejected;
- unhost removes the allowlist row and mirror announcement.

On nodes B/C/D:

- mirror records are indexed as signed byte-source hints only;
- no node adds content to its hosting allowlist because it saw a mirror/listing;
- fetch/render happens only after explicit user action and hash verification.

Concrete future scripts:

- `qa/zmarket/content-host-defaults-regtest.py`
- `qa/zmarket/content-host-allowlist-regtest.py`
- `qa/zmarket/no-auto-fetch-regtest.py`

### No On-Chain Files

Add:

```
qa/zslp/no-onchain-files-release.sh
```

Assert:

- release daemon starts without datachannel/file-transfer capability;
- `z_senddatafile`, `z_listdatatransfers`, and `z_getdatatransfer` are absent,
  disabled, or clearly legacy/dev-only;
- GUI production Collections UI hides private file send/receive entry points;
- no large file payload hex is broadcast, stored in memos, or logged as a
  transaction payload.

### Onion Endpoints

Without requiring live Tor:

- C tests validate canonical v3 onion host parsing;
- reusable market/content/social endpoints remain independent;
- one-time direct route endpoints retire after success;
- expired endpoints are not chosen;
- mirror failover chooses from signed endpoint sets and does not fetch media in
  the indexer.

With Tor available:

- embedded Tor starts only with explicit flag;
- role-scoped onion status is visible;
- no clearnet self-address is advertised in onion-only posture;
- BIP155/ADDRv2 tests prove v3 onion round-trip once implemented.

Add or extend:

```
qa/rpc-tests/tor_onion_modes.py
```

with cases for `-proxy`, `-onion`, `-onlynet=onion`, and invalid onion network
configuration.

### ZSOCIAL Scaffolding

Assert:

- public social records are bounded signed records only;
- follow lists remain local encrypted wallet data;
- DM route packets are encrypted and require explicit relay mode;
- opening a feed does not fetch media;
- social NFT/listing cards revalidate through ZSLP/ZMARKET.

## 5. AI Assistant Test Gate

AI is a wallet feature, not consensus and not a daemon hot path.

Headless/mock tests must prove:

- no provider credentials are stored in daemon config or sent to daemon RPC;
- wallet keys, seed, spending keys, viewing keys, RPC password, and Tor private
  keys are redacted from AI context;
- read-only AI tools can summarize balances, transactions, NFTs, market rows,
  ZNAM records, mirror health, and sync status;
- write tools create command drafts only;
- spending, broadcasting, listing, hosting, unhosting, publishing, social posting,
  and changing settings require user approval in the GUI;
- AI cannot bypass existing wallet confirmations;
- prompt injection in NFT metadata, social posts, mirror records, or market
  descriptions cannot invoke privileged tools;
- every AI tool call is written to a local audit log with redacted arguments.

## 6. Livenet Readiness

Before public release:

- run an upgraded node on mainnet with beta7 defaults and confirm it behaves as
  an ordinary node unless explicit beta7 modes are enabled;
- sync from genesis or a known clean snapshot and compare height/tip with
  independent peers;
- verify no beta7 indexer stalls initial sync or causes unbounded disk growth;
- verify market/content/social defaults are off;
- verify enabling local market index does not serve files;
- verify livenet buy/sell flows still require final local offer verification;
- run with `-connect=0`/limited peers and confirm startup/shutdown are clean;
- run with wallet encrypted/locked and confirm read-only summaries work while
  money-moving actions stay locked.

## 7. GUI Release Gates

After daemon gates pass:

- Linux portable build through `/home/rhett/zclbuild/build.sh`;
- real-display matrix through `/home/rhett/zclbuild/focal/build/run.sh all`;
- verify `ZQWDMON1` footer on Linux/Windows single files;
- verify glibc floor on Linux bundle;
- verify no stray Qt dynamic deps in Linux static bundle;
- verify Windows stripped daemon is manually embedded;
- verify macOS ships daemon as app sibling, then codesigns after deployment;
- verify first run defaults to no spider, no relay, no hosting, and no AI
  provider configured.

Headless GUI commands to preserve:

```bash
/home/rhett/zclbuild/prun bash -c 'cd /src/wallet/tests && /opt/qt-static/bin/qmake tests.pro && make -j$(nproc) && QT_QPA_PLATFORM=offscreen ./tst_logic'
/home/rhett/github/zcl-qt-wallet/tests/e2e/mocke2e.sh
```

Run widget tests for NFT buy/sell gates, edit-after-verify reset, remote URL
rejection, no auto-fetch, missing-capability UI, legacy file-transport hidden,
and AI provider-disabled behavior.

## 8. Current Cut Blockers

These are blockers until the final beta7 integration branch proves otherwise:

- The local daemon WIP is not a clean source tree and is behind Worker 3's pushed
  beta7 integration branch.
- ZSLP/NFT RPC wiring and QA scripts must be present from source, not stale build
  objects.
- `qa/zslp/*` release scripts must be restored or replaced.
- ZMARKET runtime flags/RPC/store/spider/router/content-host bridges are not yet
  complete in this local checkout.
- ZNAM has parser/builder scaffolding, but no runtime `-znamindex`, RPC,
  lifecycle, reorg tests, or GUI resolver yet.
- Content hosting allowlist exists as C policy/index scaffolding, not a runtime
  byte-serving feature.
- GUI private file transport must be hidden or dev-gated for beta7 release.
- AI assistant implementation must start read-only/session-safe; no persistent
  plaintext credentials and no raw RPC passthrough.
- Cut beta7 only from clean committed daemon and GUI trees after clean rebuilds.

## 9. Robustness Patterns

Use these implementation patterns across beta7:

- REST-shaped RPC resources: `status`, `list`, `get`, `create`, `import`,
  `publish`, `remove`, `revalidate`, and `audit` operations with stable schemas.
- ActiveRecord-style local rows only for GUI/cache/store objects that map cleanly
  to durable rows. Do not put ActiveRecord behavior in consensus paths or C hot
  paths.
- Pure C/POD hot paths for spidering, routing, indexing, record parsing, endpoint
  choice, and content allowlists.
- Command objects for side effects. A command can be previewed, signed by user
  approval, executed, and audited.
- Repository/store adapters for `CDBWrapper`, Qt settings, and encrypted local
  AI credentials.
- Explicit validation objects for caps, signatures, hashes, expiry, ownership,
  route policy, and user permission checks.
- Tests at every boundary: parser unit tests, bridge tests, RPC mock tests,
  headless regtest, GUI widget tests, and release artifact checks.
