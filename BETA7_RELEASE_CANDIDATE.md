# ZClassic Beta7 Release Candidate Handoff

Status: daemon release-candidate handoff.
Candidate branch: `origin/beta7/zmarket-spider-router-index`
Candidate head: resolve at final audit time with
`git rev-parse origin/beta7/zmarket-spider-router-index`.
Latest local ZMARKET/source-gate verified non-doc head:
`3280595b20139b735f28b9f1244d9b360b6367b9`.
Original daemon code candidate:
`97888f616c5be09651508f8b1789ef1e0a4f8111`.
The current head adds only a vendored zlib source tarball, ignore-rule
allowlisting, and source-gate checksum coverage so GitHub Actions clean
checkouts do not fail while fetching zlib.
Base: `origin/master` at `14a83d510ffd109d3fa09bf74ebf8c28854a263f`

## What This Candidate Contains

- Worker 3 integration branch `origin/feature/beta7-platform`:
  - beta7 hardening branches;
  - ZSLP/NFT sources and tests;
  - embedded Tor/Tor v3 identity sources and tests;
  - NFT offerpool/RPC sources and tests;
  - block index cache and wallet performance work.
- Worker 2 ZMARKET C hot-path branch:
  - `src/zmarket/zmarket_record.{h,c}`;
  - `src/zmarket/zmarket_policy.{h,c}`;
  - `src/zmarket/zmarket_index.{h,c}`;
  - `src/zmarket/zmarket_content.{h,c}`;
  - `src/zmarket/zmarket_onion.{h,c}`;
  - `src/zmarket/zmarket_spider.{h,c}`;
  - `src/zmarket/zmarket_router.{h,c}`;
  - `src/gtest/test_zmarket_c.cpp`;
  - `src/gtest/test_zmarket_spider_router.cpp`.
- Clean-checkout dependency source fixes:
  - tracked `depends/sources/tor-73bd405.tar.gz`;
  - SHA256 `178fb8242d5a1066c3535f1328d8b5ef1e4578e318a8e622d6a6732144fa2517`;
  - tracked `depends/sources/zlib-1.3.1.tar.gz`;
  - SHA256 `9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23`.
- Beta7 product, release, AI, social, content mirror, and ZMARKET routing docs.
- `qa/beta7/check-source-gates.sh` for fast static source verification.

## Gates Already Reported Passed

Worker 3 reported on `origin/feature/beta7-platform @ 5c45179bf`:

- clean daemon build;
- `zcash-gtest`: 396/396 test cases across 72 suites;
- no linker, Tor, libevent, or `evthread_use_pthreads` issues.

Worker 2 reported on the ZMARKET integration:

- strict C compile for ZMARKET C modules;
- C++ test compile for ZMARKET tests;
- expanded onion endpoint invariants;
- no file-hosting side effects from spider/router/index modes.

Local static checks on `origin/beta7/zmarket-spider-router-index`:

```bash
qa/beta7/check-source-gates.sh origin/master origin/beta7/zmarket-spider-router-index
git diff --check origin/master..origin/beta7/zmarket-spider-router-index
git diff --name-status origin/master..origin/beta7/zmarket-spider-router-index -- \
  src/consensus src/primitives src/script src/chainparams.cpp src/chainparams.h \
  src/pow.cpp src/pow.h src/coins.cpp src/coins.h src/undo.h
git show origin/beta7/zmarket-spider-router-index:depends/sources/tor-73bd405.tar.gz | sha256sum
git show origin/beta7/zmarket-spider-router-index:depends/sources/zlib-1.3.1.tar.gz | sha256sum
```

Results:

- source gate passed;
- `./src/zcash-gtest --gtest_filter='ZMarket*'` passed: 35/35 tests;
- whitespace diff check passed;
- no direct consensus-path diff in the listed paths;
- Tor and zlib tarball hashes matched;
- PR #132 was opened because branch protection rejects direct pushes to master.

## Required Final Audit Before Master

Agent 3 should perform a read-only final audit on:

```bash
git fetch origin
git rev-parse origin/beta7/zmarket-spider-router-index
qa/beta7/check-source-gates.sh origin/master origin/beta7/zmarket-spider-router-index
./src/zcash-gtest --gtest_filter='ZMarket*'
```

Then run or confirm:

- clean native daemon build from a clean checkout;
- `make -C src zcash-gtest_check V=1`;
- no consensus-sensitive behavior changes;
- `-nftmarket` remains default off;
- content hosting remains default off and allowlist-only;
- AI is docs/GUI-side only and cannot produce daemon/provider side effects;
- GUI legacy private file transport is hidden or dev-gated before beta7 GUI release.

## Protected Master Merge Path

Direct master push is intentionally blocked by GitHub branch protection:

```text
remote: error: GH006: Protected branch update failed for refs/heads/master.
remote: - Changes must be made through a pull request.
```

Use PR #132 (`beta7/zmarket-spider-router-index` -> `master`). Do not squash,
rebase, force-push, or tag during the PR merge path. After GitHub checks pass,
merge only in a way that preserves the beta7 commit history cleanly.

Read-only fast-forward sanity check:

```bash
git fetch origin
CANDIDATE=$(git rev-parse origin/beta7/zmarket-spider-router-index)

git merge-base --is-ancestor origin/master origin/beta7/zmarket-spider-router-index
git diff --name-status origin/master..$CANDIDATE -- \
  src/consensus src/primitives src/script src/chainparams.cpp src/chainparams.h \
  src/pow.cpp src/pow.h src/coins.cpp src/coins.h src/undo.h
```

## GUI Release Track

Daemon master is not the final beta7 release by itself. The GUI wallet still
needs:

- beta7 daemon embedded/package update;
- Linux portable build in `/home/rhett/zclbuild`;
- real-display matrix;
- Windows manual daemon footer embed;
- macOS sibling daemon packaging/codesign;
- AI assistant docs/denylist and provider-disabled defaults;
- legacy on-chain private file transport hidden or dev-gated.

Reference GUI docs:

- `/home/rhett/github/zcl-qt-wallet/docs/BETA7_TOR_ZMARKET_ZNAM_GUI_PLAN.md`
- `/home/rhett/github/zcl-qt-wallet/docs/BETA7_AI_ASSISTANT_GUI_PLAN.md`
