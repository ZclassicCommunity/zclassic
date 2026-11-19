#!/bin/sh
# Local release-candidate CI for macOS (the macOS stages of zcutil/local-ci.sh:
# daemon candidate, wallet-platform tests, wallet bundle). Own machines only.
# Run it ON the Mac; the source arrives as a git bundle, nothing is fetched from
# GitHub.  zcutil/local-ci.sh `macos` copies the bundle and this script over ssh and
# runs it for you.
#
# usage: sh local-ci-macos.sh --bundle <file.bundle> --commit <sha> --out <dir> [dev-tools|daemon|wallet-tests|wallet|all]
#
#   daemon  static macOS daemon with embedded Tor, otool allowlist, --version,
#           regtest smoke, bounded embedded-Tor check  -> <out>/daemon-macos-arm64
#   wallet-tests  Homebrew Qt 5: build the GUI, the logic tests and the widget tests
#           (qmake, offscreen platform) and run them; no daemon needed
#   wallet  pinned static Qt 5.15.19 + the wallet bundle -> <out>/wallet-macos-candidate
#           (needs <out>/daemon-macos-arm64 of the same commit; builds Qt once, ~1 h)
#   all     dev-tools (the check-dev-tools step of local-ci.sh), daemon, wallet-tests, then wallet
#
# Everything lives under $ZCL_CI_ROOT (default ~/work/zc23-localci): work/ (fresh clone per
# run), cache/ (depends sources+built, Qt toolchain).  Other directories are never touched,
# and no daemon other than the one this script started is ever signalled.
# Prerequisites (Homebrew): autoconf automake libtool pkg-config coreutils; for the wallet
# also libsodium (and qt@5 for wallet-tests).  Env: ZCL_CI_JOBS (default 4), ZCL_CI_PORT_BASE (default 41200),
# ZCL_CI_EXPECT_VERSION (default derived from src/clientversion.h).
set -eu

bundle=""; commit=""; out=""; what=daemon
while [ $# -gt 0 ]; do
    case $1 in
        --bundle) bundle=$2; shift 2 ;;
        --commit) commit=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        dev-tools|daemon|wallet-tests|wallet|all) what=$1; shift ;;
        -h|--help) sed -n "2,23p" "$0"; exit 0 ;;
        *) echo "local-ci-macos: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -f "$bundle" ] && [ -n "$commit" ] && [ -n "$out" ] || { sed -n "2,12p" "$0" >&2; exit 2; }
[ "$(uname -s)" = Darwin ] || { echo "local-ci-macos: run this on a Mac" >&2; exit 2; }

ROOT=${ZCL_CI_ROOT:-$HOME/work/zc23-localci}
mkdir -p "$ROOT/work" "$ROOT/cache/depends-sources" "$ROOT/cache/depends-built" "$out"
bundle=$(cd "$(dirname "$bundle")" && pwd)/$(basename "$bundle")
out=$(cd "$out" && pwd)
JOBS=${ZCL_CI_JOBS:-4}
PORT_BASE=${ZCL_CI_PORT_BASE:-41200}
export SOURCES_PATH="$ROOT/cache/depends-sources" BASE_CACHE="$ROOT/cache/depends-built"
# Fixed absolute path so depends/Qt prefixes stay valid between runs.
SRC=$ROOT/work/src

die() { echo "local-ci-macos: $*" >&2; exit 1; }
say() { echo "== local-ci-macos: $*"; }

for t in autoconf automake libtool pkg-config greadlink xcrun shasum otool; do
    command -v "$t" >/dev/null 2>&1 || die "missing prerequisite: $t (brew install autoconf automake libtool pkg-config coreutils)"
done

checkout() {
    case $SRC in "$ROOT"/work/*) ;; *) die "refusing to clean $SRC" ;; esac
    rm -rf "$SRC"
    # The bundle carries the commit under refs/local-ci/* (see local-ci.sh); fetch it into a new repo.
    mkdir -p "$SRC" && git -C "$SRC" init -q
    git -C "$SRC" fetch -q "$bundle" 'refs/local-ci/*:refs/local-ci/*' || die "cannot fetch the bundle"
    git -C "$SRC" checkout -q --detach "$commit"
    [ "$(git -C "$SRC" rev-parse HEAD)" = "$commit" ] || die "checked-out commit differs from $commit"
}

expected_version() {
    if [ -n "${ZCL_CI_EXPECT_VERSION:-}" ]; then printf '%s' "$ZCL_CI_EXPECT_VERSION"; return; fi
    f=src/clientversion.h
    mj=$(sed -n 's/^#define CLIENT_VERSION_MAJOR \([0-9][0-9]*\).*/\1/p' $f)
    mi=$(sed -n 's/^#define CLIENT_VERSION_MINOR \([0-9][0-9]*\).*/\1/p' $f)
    rv=$(sed -n 's/^#define CLIENT_VERSION_REVISION \([0-9][0-9]*\).*/\1/p' $f)
    bd=$(sed -n 's/^#define CLIENT_VERSION_BUILD \([0-9][0-9]*\).*/\1/p' $f)
    printf '%s.%s.%s-beta%s' "$mj" "$mi" "$rv" "$((bd + 1))"
}

# Processes whose command line mentions one of OUR directories (never anyone else's).
leftovers() { ps -axo pid=,command= | grep -F -e "$ROOT" -e "$out" | grep -v grep | grep -F zclassicd || true; }

do_daemon() {
    say "daemon: $commit"
    checkout
    cd "$SRC"
    cand=$out/daemon-macos-arm64; rm -rf "$cand"; mkdir -p "$cand" "$out/logs"
    log=$out/logs/daemon-macos.log
    say "build static macOS daemon with embedded Tor (jobs $JOBS)"
    # "linux" is the native-host target of build-release.sh.
    bash zcutil/build-release.sh linux -j"$JOBS" -k >"$log" 2>&1 || { tail -40 "$log"; die "build failed (log $log)"; }
    host=$(./depends/config.guess)
    cp release/"$host"/zclassic* "$cand"/
    ls -l "$cand"; file "$cand"/zclassic*
    : >"$cand/validation.txt"
    for binary in "$cand"/zclassic*; do otool -L "$binary" | tee -a "$cand/validation.txt"; done
    hard=$(sh zcutil/check-hardening.sh "$cand"/zclassic* 2>&1) && hrc=0 || hrc=1
    echo "$hard" | tee -a "$cand/validation.txt"
    [ "$hrc" -eq 0 ] || die "hardening check failed (zcutil/check-hardening.sh)"
    # Anything outside /usr/lib and /System would be missing on a user's Mac.
    awk '/^[ \t]+\// { print $1 }' "$cand/validation.txt" | sort -u >"$out/dylibs.txt"
    echo "== dylibs linked by the binaries"; cat "$out/dylibs.txt"
    echo "== non-system dylibs (reported)"; grep -Ev '^(/usr/lib/|/System/)' "$out/dylibs.txt" || true
    if grep -E '/opt/homebrew|/usr/local|@rpath|@loader_path' "$out/dylibs.txt"; then die "binary links a non-system dylib"; fi
    want=$(expected_version)
    "$cand/zclassicd" --version | tee -a "$cand/validation.txt" | head -3
    "$cand/zclassicd" --version | grep -F "$want" >/dev/null || die "zclassicd --version does not report $want"
    git rev-parse HEAD >"$cand/SOURCE_COMMIT.txt"
    (cd "$cand" && shasum -a 256 zclassic* >SHA256SUMS.txt && shasum -a 256 -c SHA256SUMS.txt)
    # Zcash parameters: only fetch when missing (the files are shared and verified by fetch-params).
    pdir="$HOME/Library/Application Support/ZcashParams"
    if [ -f "$pdir/sapling-spend.params" ] && [ -f "$pdir/sapling-output.params" ] && [ -f "$pdir/sprout-groth16.params" ]; then
        say "Zcash parameters present"
    else
        say "fetch Zcash parameters"; bash zcutil/fetch-params.sh || die "fetch-params"
    fi
    say "regtest smoke (ports from $PORT_BASE)"
    rm -rf "$out/smoke"
    sh src/c23/test/regtest-smoke.sh --bin "$cand" --work "$out/smoke" --port-base "$PORT_BASE" >"$out/logs/smoke-macos.log" 2>&1 \
        || { tail -30 "$out/logs/smoke-macos.log"; die "regtest smoke failed"; }
    tail -3 "$out/logs/smoke-macos.log"
    say "bounded embedded Tor check"
    rm -rf "$out/tor-check"
    sh zcutil/embedded-tor-check.sh "$cand" "$out/tor-check" 240 >"$out/logs/tor-check-macos.log" 2>&1 \
        || { tail -30 "$out/logs/tor-check-macos.log"; die "embedded Tor check failed"; }
    tail -2 "$out/logs/tor-check-macos.log"
    l=$(leftovers)
    [ -z "$l" ] || { echo "$l"; die "leftover zclassicd of this run"; }
    say "daemon OK: $cand"
}

# Wallet GUI + isolated logic/widget tests with Homebrew Qt 5 (qmake, offscreen platform).
do_wallet_tests() {
    say "wallet-tests: $commit"
    command -v brew >/dev/null 2>&1 && brew --prefix libsodium >/dev/null 2>&1 && brew --prefix qt@5 >/dev/null 2>&1 \
        || die "brew install qt@5 libsodium first"
    checkout
    cd "$SRC/wallet"
    mkdir -p "$out/logs"
    PATH="$(brew --prefix qt@5)/bin:$PATH"; export PATH
    cp "$(brew --prefix libsodium)/lib/libsodium.a" res/libsodium.a
    mkdir -p artifacts/gui artifacts/logic artifacts/widget
    log=$out/logs/wallet-tests-macos.log; : >"$log"
    say "build the GUI and the isolated tests (jobs $JOBS)"
    { (cd artifacts/gui && qmake ../../zcl-qt-wallet.pro CONFIG+=release && make -j"$JOBS") \
        && (cd artifacts/logic && qmake ../../tests/tests.pro CONFIG+=release && make -j"$JOBS") \
        && (cd artifacts/widget && qmake ../../tests/widget/tst_widget.pro CONFIG+=release && make -j"$JOBS"); } >>"$log" 2>&1 \
        || { tail -40 "$log"; die "wallet build failed (log $log)"; }
    say "run the isolated tests"
    export QT_QPA_PLATFORM=offscreen ZCL_SHOTS_DIR="$PWD/artifacts/shots"
    artifacts/logic/tst_logic -o artifacts/logic-results.txt,txt >>"$log" 2>&1 || { tail -40 "$log"; die "tst_logic failed"; }
    artifacts/widget/tst_widget -o artifacts/widget-results.txt,txt >>"$log" 2>&1 || { tail -40 "$log"; die "tst_widget failed"; }
    rm -rf "$out/wallet-tests-macos"; mkdir -p "$out/wallet-tests-macos"
    cp artifacts/logic-results.txt artifacts/widget-results.txt "$out/wallet-tests-macos"/
    git -C "$SRC" rev-parse HEAD >"$out/wallet-tests-macos/SOURCE_COMMIT.txt"
    grep -h '^Totals' artifacts/logic-results.txt artifacts/widget-results.txt
    say "wallet-tests OK: $out/wallet-tests-macos"
}

do_wallet() {
    say "wallet: $commit"
    cand=$out/daemon-macos-arm64
    [ -f "$cand/SOURCE_COMMIT.txt" ] || die "no daemon candidate in $cand (run: daemon)"
    command -v brew >/dev/null 2>&1 && brew --prefix libsodium >/dev/null 2>&1 || die "brew install libsodium first"
    checkout
    cd "$SRC"
    test "$(cat "$cand/SOURCE_COMMIT.txt")" = "$(git rev-parse HEAD)" || die "daemon candidate is for another commit"
    (cd "$cand" && shasum -a 256 -c SHA256SUMS.txt) || die "daemon candidate checksum"
    tc=$ROOT/cache/mac-toolchain-5.15.19
    mkdir -p "$out/logs"
    if [ ! -x "$tc/qt-static/bin/qmake" ]; then
        say "build the pinned static Qt (once; cached in $tc)"
        ZCL_MAC_TOOLCHAIN_DIR=$tc ZCL_MAKE_JOBS=$JOBS sh wallet/contrib/release/macos-toolchain.sh >"$out/logs/macos-toolchain.log" 2>&1 \
            || { tail -30 "$out/logs/macos-toolchain.log"; die "Qt toolchain build failed"; }
    fi
    export ZCL_DAEMON="$cand/zclassicd"
    ZCL_DAEMON_SHA256=$(shasum -a 256 "$ZCL_DAEMON" | cut -d' ' -f1); export ZCL_DAEMON_SHA256
    chmod +x "$ZCL_DAEMON"
    export ZCL_QT_PREFIX="$tc/qt-static"
    sh wallet/contrib/release/macos.sh >"$out/logs/wallet-macos.log" 2>&1 || { tail -40 "$out/logs/wallet-macos.log"; die "macos.sh failed"; }
    rm -rf "$out/wallet-macos-candidate"; mkdir -p "$out/wallet-macos-candidate"
    cp -R wallet/artifacts/release/. "$out/wallet-macos-candidate"/
    git rev-parse HEAD >"$out/wallet-macos-candidate/SOURCE_COMMIT.txt"
    say "wallet OK: $out/wallet-macos-candidate"
}

case $what in
    daemon) do_daemon ;;
    wallet-tests) do_wallet_tests ;;
    wallet) do_wallet ;;
    dev-tools|all) say "dev-tools: $commit"; checkout; cd "$SRC"; mkdir -p "$out/logs"; { make -C zcutil -j"$JOBS" && MAKEFLAGS= make -C zcutil check && zcutil/bin/zcl-dev verify --gates; } >"$out/logs/dev-tools-macos.log" 2>&1 || { tail -40 "$out/logs/dev-tools-macos.log"; die "check-dev-tools failed (log $out/logs/dev-tools-macos.log)"; }; tail -3 "$out/logs/dev-tools-macos.log"; say "dev-tools OK"; [ "$what" = dev-tools ] || { do_daemon; do_wallet_tests; do_wallet; } ;;
esac
