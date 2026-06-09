#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
base_ref="${1:-origin/master}"
tor_sha="178fb8242d5a1066c3535f1328d8b5ef1e4578e318a8e622d6a6732144fa2517"
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
  [[ -f "$path" ]] && pass "file exists: $path" || fail "missing file: $path"
}

require_tracked() {
  local path="$1"
  git ls-files --error-unmatch "$path" >/dev/null 2>&1 \
    && pass "tracked: $path" \
    || fail "not tracked: $path"
}

require_text() {
  local path="$1"
  local pattern="$2"
  local alt_pattern="$pattern"
  if [[ "$path" == "src/Makefile.am" && "$pattern" == src/* ]]; then
    alt_pattern="${pattern#src/}"
  fi
  if grep -qF "$pattern" "$path" || grep -qF "$alt_pattern" "$path"; then
    pass "$path references $pattern"
  else
    fail "$path missing $pattern"
  fi
}

printf 'Beta7 source gate in %s\n' "$repo_root"

if git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  pass "base ref exists: $base_ref"
else
  fail "base ref missing: $base_ref"
fi

if git diff --check; then
  pass "git diff --check"
else
  fail "git diff --check"
fi

scan_paths=(
  BETA7_HANDOFF.md
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
)

if command -v rg >/dev/null 2>&1; then
  if rg -n '^(<<<<<<<|>>>>>>>|=======$)' "${scan_paths[@]}" 2>/dev/null; then
    fail "conflict markers found"
  else
    pass "no conflict markers"
  fi
else
  if grep -RInE '^(<<<<<<<|>>>>>>>|=======$)' "${scan_paths[@]}" 2>/dev/null; then
    fail "conflict markers found"
  else
    pass "no conflict markers"
  fi
fi

required_files=(
  BETA7_HANDOFF.md
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
  src/gtest/test_torembed.cpp
  src/gtest/test_torv3_identity.cpp
  src/gtest/test_zslp.cpp
  src/gtest/test_znam.cpp
)

for path in "${required_files[@]}"; do
  require_file "$path"
done

if [[ -f depends/sources/tor-73bd405.tar.gz ]]; then
  actual_sha="$(sha256sum depends/sources/tor-73bd405.tar.gz | awk '{print $1}')"
  [[ "$actual_sha" == "$tor_sha" ]] \
    && pass "tor tarball sha256" \
    || fail "tor tarball sha256 mismatch: $actual_sha"
  require_tracked depends/sources/tor-73bd405.tar.gz
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
  gtest/test_torembed.cpp \
  gtest/test_torv3_identity.cpp \
  gtest/test_zslp.cpp \
  gtest/test_znam.cpp; do
  require_text src/Makefile.gtest.include "$path"
done

if git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  consensus_diff="$(git diff --name-only "$base_ref"..HEAD -- \
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
