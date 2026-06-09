#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
base_ref="${1:-origin/master}"
candidate_ref="${2:-HEAD}"
tor_sha="178fb8242d5a1066c3535f1328d8b5ef1e4578e318a8e622d6a6732144fa2517"
zlib_sha="9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
failures=0

cd "$repo_root"

pass() {
  printf 'PASS %s\n' "$*"
}

fail() {
  printf 'FAIL %s\n' "$*" >&2
  failures=$((failures + 1))
}

require_file() {
  local path="$1"
  git cat-file -e "$candidate_commit:$path" 2>/dev/null \
    && pass "file exists in candidate: $path" \
    || fail "missing file in candidate: $path"
}

require_tracked() {
  local path="$1"
  git cat-file -e "$candidate_commit:$path" 2>/dev/null \
    && pass "tracked in candidate: $path" \
    || fail "not tracked in candidate: $path"
}

require_text() {
  local path="$1"
  local pattern="$2"
  local alt_pattern="$pattern"
  if [[ "$path" == "src/Makefile.am" && "$pattern" == src/* ]]; then
    alt_pattern="${pattern#src/}"
  fi
  local content
  if ! content="$(git show "$candidate_commit:$path" 2>/dev/null)"; then
    fail "cannot read $path from candidate"
    return
  fi
  if grep -qF "$pattern" <<<"$content" || grep -qF "$alt_pattern" <<<"$content"; then
    pass "$path references $pattern"
  else
    fail "$path missing $pattern"
  fi
}

printf 'Beta7 source gate in %s\n' "$repo_root"

if base_commit="$(git rev-parse --verify "$base_ref^{commit}" 2>/dev/null)"; then
  pass "base ref exists: $base_ref"
else
  fail "base ref missing: $base_ref"
  base_commit=""
fi

if candidate_commit="$(git rev-parse --verify "$candidate_ref^{commit}" 2>/dev/null)"; then
  pass "candidate ref exists: $candidate_ref"
else
  fail "candidate ref missing: $candidate_ref"
  candidate_commit=""
fi

if [[ -n "$base_commit" && -n "$candidate_commit" ]]; then
  if git merge-base --is-ancestor "$base_commit" "$candidate_commit"; then
    pass "$base_ref is ancestor of $candidate_ref"
  else
    fail "$base_ref is not ancestor of $candidate_ref"
  fi
  if git diff --check "$base_commit..$candidate_commit"; then
    pass "git diff --check $base_ref..$candidate_ref"
  else
    fail "git diff --check $base_ref..$candidate_ref"
  fi
else
  fail "cannot run ref diff check without valid base and candidate"
fi

scan_paths=(
  BETA7_HANDOFF.md
  BETA7_RELEASE_CANDIDATE.md
  doc/net/EMBEDDED_TOR_BLUEPRINT.md
  doc/nft
  doc/platform
  doc/ai
  doc/social
  depends/.gitignore
  depends/sources/.gitignore
  src/Makefile.am
  src/Makefile.gtest.include
  src/zmarket
  src/zslp
  src/znam
  src/gtest/test_zmarket_c.cpp
  src/gtest/test_zmarket_spider_router.cpp
  src/gtest/test_zslp_indexer.cpp
  src/gtest/test_zslp_collections.cpp
  src/gtest/test_zslp_vectors.cpp
  src/gtest/test_zslp_wallet.cpp
  src/gtest/test_zslp_fingerprint.cpp
  src/gtest/test_nftoffer.cpp
  src/gtest/test_offerpool.cpp
  src/gtest/test_blockindexcache.cpp
)

if [[ -n "$candidate_commit" ]]; then
  set +e
  conflict_output="$(git grep -n -E '^(<<<<<<<|>>>>>>>|=======$)' "$candidate_commit" -- "${scan_paths[@]}" 2>&1)"
  conflict_rc=$?
  set -e
  if [[ "$conflict_rc" -eq 0 ]]; then
    printf '%s\n' "$conflict_output" >&2
    fail "conflict markers found in candidate"
  elif [[ "$conflict_rc" -eq 1 ]]; then
    pass "no conflict markers in candidate"
  else
    printf '%s\n' "$conflict_output" >&2
    fail "conflict marker scan failed"
  fi
else
  fail "cannot scan conflict markers without valid candidate"
fi

required_files=(
  BETA7_HANDOFF.md
  BETA7_RELEASE_CANDIDATE.md
  doc/net/EMBEDDED_TOR_BLUEPRINT.md
  doc/nft/SIGNED_CONTENT_MIRROR_PROTOCOL.md
  doc/nft/ZMARKET_SPIDER_INDEX_ROUTING_PLAN.md
  doc/platform/BETA7_DAEMON_IMPLEMENTATION_PLAN.md
  doc/platform/BETA7_PRODUCT_REQUIREMENTS.md
  doc/platform/BETA7_RELEASE_TEST_PLAN.md
  doc/ai/WALLET_AI_ASSISTANT_PLAN.md
  doc/social/ZSOCIAL_PROTOCOL.md
  depends/packages/tor.mk
  depends/sources/tor-73bd405.tar.gz
  depends/sources/zlib-1.3.1.tar.gz
  src/torembed.cpp
  src/torembed.h
  src/rpc/zslp.cpp
  src/rpc/nftoffer.cpp
  src/rpc/nftoffer.h
  src/nft/offerpool.cpp
  src/nft/offerpool.h
  src/zslp/slp.c
  src/zslp/slp.h
  src/zslp/contentfingerprint.cpp
  src/zslp/contentfingerprint.h
  src/zslp/zslpindexer.cpp
  src/zslp/zslpindexer.h
  src/znam/znam.c
  src/znam/znam.h
  src/zmarket/zmarket_record.c
  src/zmarket/zmarket_record.h
  src/zmarket/zmarket_policy.c
  src/zmarket/zmarket_policy.h
  src/zmarket/zmarket_index.c
  src/zmarket/zmarket_index.h
  src/zmarket/zmarket_content.c
  src/zmarket/zmarket_content.h
  src/zmarket/zmarket_onion.c
  src/zmarket/zmarket_onion.h
  src/zmarket/zmarket_spider.c
  src/zmarket/zmarket_spider.h
  src/zmarket/zmarket_router.c
  src/zmarket/zmarket_router.h
  src/gtest/test_zmarket_c.cpp
  src/gtest/test_zmarket_spider_router.cpp
  src/gtest/test_zslp_indexer.cpp
  src/gtest/test_zslp_collections.cpp
  src/gtest/test_zslp_vectors.cpp
  src/gtest/test_zslp_wallet.cpp
  src/gtest/test_zslp_fingerprint.cpp
  src/gtest/test_nftoffer.cpp
  src/gtest/test_offerpool.cpp
  src/gtest/test_blockindexcache.cpp
  src/gtest/test_torembed.cpp
  src/gtest/test_torv3_identity.cpp
  src/gtest/test_zslp.cpp
  src/gtest/test_znam.cpp
)

for path in "${required_files[@]}"; do
  require_file "$path"
done

if git cat-file -e "$candidate_commit:depends/sources/tor-73bd405.tar.gz" 2>/dev/null; then
  actual_sha="$(git show "$candidate_commit:depends/sources/tor-73bd405.tar.gz" | sha256sum | awk '{print $1}')"
  [[ "$actual_sha" == "$tor_sha" ]] \
    && pass "tor tarball sha256" \
    || fail "tor tarball sha256 mismatch: $actual_sha"
  require_tracked depends/sources/tor-73bd405.tar.gz
fi

if git cat-file -e "$candidate_commit:depends/sources/zlib-1.3.1.tar.gz" 2>/dev/null; then
  actual_sha="$(git show "$candidate_commit:depends/sources/zlib-1.3.1.tar.gz" | sha256sum | awk '{print $1}')"
  [[ "$actual_sha" == "$zlib_sha" ]] \
    && pass "zlib tarball sha256" \
    || fail "zlib tarball sha256 mismatch: $actual_sha"
  require_tracked depends/sources/zlib-1.3.1.tar.gz
fi

for path in \
  zmarket/zmarket_record.h \
  zmarket/zmarket_record.c \
  zmarket/zmarket_policy.h \
  zmarket/zmarket_policy.c \
  zmarket/zmarket_index.h \
  zmarket/zmarket_index.c \
  zmarket/zmarket_content.h \
  zmarket/zmarket_content.c \
  zmarket/zmarket_onion.h \
  zmarket/zmarket_onion.c \
  zmarket/zmarket_spider.h \
  zmarket/zmarket_spider.c \
  zmarket/zmarket_router.h \
  zmarket/zmarket_router.c \
  zslp/slp.h \
  zslp/slp.c \
  znam/znam.h \
  znam/znam.c; do
  require_text src/Makefile.am "$path"
done

for path in \
  gtest/test_zmarket_c.cpp \
  gtest/test_zmarket_spider_router.cpp \
  gtest/test_zslp_indexer.cpp \
  gtest/test_zslp_collections.cpp \
  gtest/test_zslp_vectors.cpp \
  gtest/test_zslp_wallet.cpp \
  gtest/test_zslp_fingerprint.cpp \
  gtest/test_nftoffer.cpp \
  gtest/test_offerpool.cpp \
  gtest/test_blockindexcache.cpp \
  gtest/test_torembed.cpp \
  gtest/test_torv3_identity.cpp \
  gtest/test_zslp.cpp \
  gtest/test_znam.cpp; do
  require_text src/Makefile.gtest.include "$path"
done

require_text src/main.cpp "bool fNftMarket = false"
require_text src/init.cpp 'fNftMarket = GetBoolArg("-nftmarket", false)'

if [[ -n "$base_commit" && -n "$candidate_commit" ]]; then
  consensus_diff="$(git diff --name-only "$base_commit..$candidate_commit" -- \
    src/consensus \
    src/primitives \
    src/script \
    src/chainparams.cpp \
    src/chainparams.h \
    src/pow.cpp \
    src/pow.h \
    src/coins.cpp \
    src/coins.h \
    src/undo.h)"
  if [[ -z "$consensus_diff" ]]; then
    pass "no direct consensus-path diff versus $base_ref"
  else
    printf '%s\n' "$consensus_diff" >&2
    fail "consensus-path diff versus $base_ref"
  fi
fi

if [[ "$failures" -ne 0 ]]; then
  printf 'Beta7 source gate failed: %d issue(s)\n' "$failures" >&2
  exit 1
fi

printf 'Beta7 source gate passed\n'
