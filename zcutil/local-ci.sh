#!/bin/sh
# Local release-candidate CI: replaces the GitHub Actions jobs on your own machines.
#
# Builds and checks the Linux and Windows daemon candidates, the Linux wallet
# bundle and the full test suite inside an Ubuntu 20.04 (focal) root filesystem
# that is constructed WITHOUT root and WITHOUT a container runtime (bubblewrap +
# an unprivileged user namespace), so the binaries keep the glibc 2.31 floor and
# the GCC 9.3 / mingw-w64 GCC 9.3 toolchain the GitHub "container: ubuntu:20.04"
# jobs used.  macOS candidates are built by zcutil/local-ci-macos.sh on a Mac.
#
# usage: zcutil/local-ci.sh [options] <command> [outdir]
#
#   commands
#     env-setup     create/refresh the focal root filesystem (needs network, once)
#     daemon-linux  Linux daemon candidate      -> <outdir>/daemon-linux-x86_64
#     daemon-win64  Windows daemon candidate    -> <outdir>/daemon-windows-x86_64
#     wallet-linux  Linux wallet bundle         -> <outdir>/wallet-linux-candidate
#                   (consumes <outdir>/daemon-linux-x86_64 of the SAME commit)
#     test          clean test build + every local test; one summary table
#     test-changed  `test` restricted (as --only) to the steps `zcl-dev select` picks for
#                   the commits between ZCL_CI_BASE (default origin/master) and --commit
#     dry           three fake steps through the real step/receipt code, no root filesystem
#     macos         run local-ci-macos.sh on the Mac named by ZCL_CI_MAC (ssh alias)
#     all           daemon-linux daemon-win64 wallet-linux test (+ macos if ZCL_CI_MAC set)
#     shell         interactive shell in the focal environment (for debugging)
#
#   options
#     --commit REV  commit to build (default HEAD of this checkout; it is cloned
#                   fresh, uncommitted changes are NOT included)
#     --tor         also run the Tor two/three-node and addrv2 tests (needs network)
#     --flavor F    test build flavor: debug (checked libstdc++, lock-order checks, as ci.yml),
#                   release (the configuration that ships; unit suites and smoke only) or both (default)
#     --only LIST   comma list of `test` step names to run (see zcl-dev select); the build
#                   always runs; other steps are neither run nor recorded
#     --pick REV    cherry-pick REV on top of the commit in the TEST builds only (repeatable)
#     --jobs N      make parallelism (default min(8, nproc))
#
#   environment
#     ZCL_CI_ENV       focal root filesystem      (default ~/work/zc23-localci-env)
#     ZCL_CI_CACHE     depends/ccache/Qt caches   (default ~/work/zc23-localci-cache)
#     ZCL_CI_OUT       output directory           (default ~/work/zc23-localci-out/<short commit>)
#     ZCL_CI_GOLDEN    c23 golden corpus dir      (default ~/work/zc23-golden/src/test/data/c23_golden if present)
#     ZCL_CI_PREV_BIN  dir with a previous-release zclassicd + zclassic-cli (peer for smoke/matrix)
#     ZCL_CI_MAC       ssh alias of the Mac for `macos`
#     ZCL_CI_EXPECT_VERSION  version string the candidates must report
#                      (default derived from src/clientversion.h: build N -> betaN+1)
#     ZCL_CI_TIMEOUT_<STEP>  wall-clock limit in seconds of one test step (STEP upper case, - and . as _;
#                      e.g. ZCL_CI_TIMEOUT_TREE_ROOT_ASAN); ZCL_CI_STEP_TIMEOUT sets one for all other steps
#     ZCL_CI_LOG_CAP   most bytes kept of one step log (default 268435456); a step that fills it fails
#     ZCL_CI_NOASLR    0 = do not run the sanitizer step under `setarch -R`
#
# Output: logs under <outdir>/logs and <outdir>/test*/logs, and one JSON receipt per step in
# <outdir>/receipts.jsonl (doc/local-ci.md); `zcutil/dev/zcl-dev receipt <step> <outdir>` prints one.
#
# Exit status: 0 only when every requested command and check passed.
# Heavy commands belong behind the host broker, for example:
#   devbuild --wait --project z23 --class normal --cpu-limit 8 zcutil/local-ci.sh all
set -eu

SELF=$(readlink -f "$0")
REPO=$(CDPATH= cd -- "$(dirname "$SELF")/.." && pwd)

# ---------------------------------------------------------------- constants
FOCAL_VER=20.04.5
FOCAL_TGZ=ubuntu-base-$FOCAL_VER-base-amd64.tar.gz
FOCAL_URL=https://cdimage.ubuntu.com/ubuntu-base/releases/20.04/release
FOCAL_SHA256=60e216b60947653dc8989be3821380268315b99b2959c29882781541bfe5a426
DAEMON_PKGS="build-essential libtool autotools-dev automake pkg-config bsdmainutils curl ca-certificates git ccache bison python3"
MINGW_PKGS="g++-mingw-w64-x86-64"
WALLET_PKGS="ca-certificates curl git build-essential perl pkg-config xz-utils libsodium-dev libx11-dev libx11-xcb-dev libxext-dev libxfixes-dev libxi-dev libxrender-dev libxcb1-dev libxcb-util0-dev libxcb-glx0-dev libxcb-keysyms1-dev libxcb-image0-dev libxcb-shm0-dev libxcb-icccm4-dev libxcb-sync-dev libxcb-xfixes0-dev libxcb-shape0-dev libxcb-randr0-dev libxcb-render-util0-dev libxcb-xinerama0-dev libxcb-xkb-dev libxkbcommon-dev libxkbcommon-x11-dev libfontconfig1-dev libfreetype6-dev"
# Test-only extras: tools the shell tests call, and Qt for the wallet logic/widget tests.
TEST_PKGS="file procps iproute2 jq bc rsync strace qtbase5-dev libqt5svg5-dev qttools5-dev-tools fonts-dejavu-core"

die() { echo "local-ci: $*" >&2; exit 1; }
say() { echo "== local-ci: $*"; }

# ---------------------------------------------------------------- receipts
# receipt <stage> <step> <verdict> <seconds> <started-epoch> <logfile>
# appends one JSON line to $RCPT_OUT/receipts.jsonl (no-op when RCPT_OUT is unset).  Fields:
# commit, tree (git tree hash), stage, step, verdict, seconds, started (UTC), os, arch (no host
# name), gcc, mingw, glibc (versions as seen where the step ran), env_names + env_sha256 (the
# names of the build-relevant variables that are set, and a SHA-256 over their NAME=value lines;
# values are never written), log_sha256.  POSIX sh and the usual sha256sum/shasum only.
RCPT_VARS="CONFIGURE_FLAGS DEBUG HOST CC CXX CFLAGS CXXFLAGS CPPFLAGS LDFLAGS MAKEFLAGS ZQW_STATIC_GOMP E2E_NODE_ARGS"

sha256_stdin() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}
json_str() { printf '%s' "$1" | tr -d '\000-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
tool_ver() { if command -v "$1" >/dev/null 2>&1; then "$@" 2>&1 | sed -n 1p; fi; }

receipt() {
    [ -n "${RCPT_OUT:-}" ] || return 0
    r_stage=$1; r_step=$2; r_verdict=$3; r_secs=$4; r_start=$5; r_log=$6
    r_when=$(date -u -d "@$r_start" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$r_start" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
    if [ -n "${RCPT_ENVFILE:-}" ] && [ -f "$RCPT_ENVFILE" ]; then
        r_gcc=$(sed -n 3p "$RCPT_ENVFILE"); r_mingw=$(sed -n 4p "$RCPT_ENVFILE"); r_glibc=$(sed -n 5p "$RCPT_ENVFILE")
    else
        r_gcc=$(tool_ver gcc --version); r_mingw=$(tool_ver x86_64-w64-mingw32-g++ --version); r_glibc=$(tool_ver ldd --version)
    fi
    r_names=$( { for n in $RCPT_VARS; do eval "[ -n \"\${$n+x}\" ]" && echo "$n"; done
                 env | sed -n 's/^\(ZCL_CI_[A-Za-z0-9_]*\)=.*/\1/p'; } | sort -u)
    r_pairs=$(for n in $r_names; do eval "printf '%s=%s\\n' \"$n\" \"\${$n}\""; done)
    r_envsha=$(printf '%s\n' "$r_pairs" | sha256_stdin)
    r_list=""
    for n in $r_names; do r_list="$r_list${r_list:+,}\"$n\""; done
    r_logsha=""
    [ ! -f "$r_log" ] || r_logsha=$(sha256_stdin <"$r_log")
    printf '{"commit":"%s","tree":"%s","stage":"%s","step":"%s","verdict":"%s","seconds":%s,"started":"%s","os":"%s","arch":"%s","gcc":"%s","mingw":"%s","glibc":"%s","env_names":[%s],"env_sha256":"%s","log_sha256":"%s"}\n' \
        "${RCPT_COMMIT:-}" "${RCPT_TREE:-}" "$(json_str "$r_stage")" "$(json_str "$r_step")" "$r_verdict" "$r_secs" "$r_when" \
        "$(uname -s)" "$(uname -m)" "$(json_str "$r_gcc")" "$(json_str "$r_mingw")" "$(json_str "$r_glibc")" \
        "$r_list" "$r_envsha" "$r_logsha" >>"$RCPT_OUT/receipts.jsonl"
}

# ------------------------------------------------------------------- inner
# Everything below `inner_*` runs INSIDE the focal environment as (mapped) root,
# with the clean source clone at /w/src, caches at /cache, outputs at /out.
# They are selected by `local-ci.sh __inner <stage>` and are POSIX sh.

inner_common() {
    export DEBIAN_FRONTEND=noninteractive
    export SOURCES_PATH=/cache/depends-sources BASE_CACHE=/cache/depends-built
    export CCACHE_DIR=/cache/ccache CCACHE_MAXSIZE=20G CCACHE_COMPRESS=1
    mkdir -p "$SOURCES_PATH" "$BASE_CACHE" "$CCACHE_DIR"
    git config --global --add safe.directory /w/src
    cd /w/src
    JOBS=${ZCL_CI_JOBS:-8}
    COMMIT=$(git rev-parse HEAD)
    TD=/out/${ZCL_CI_TESTDIR:-test}; FLAVOR=${ZCL_CI_FLAVOR:-debug}
    RCPT_OUT=/out; RCPT_COMMIT=$COMMIT; RCPT_TREE=$(git rev-parse "HEAD^{tree}")
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

# run <logfile> <cmd...>: tee output, keep the command's exit status.
run_logged() {
    log=$1; shift
    rcf=$(mktemp /tmp/rc.XXXXXX)
    { if "$@"; then echo 0 >"$rcf"; else echo $? >"$rcf"; fi; } 2>&1 | tee -a "$log"
    rc=$(cat "$rcf"); rm -f "$rcf"
    return "$rc"
}

check_fail() { echo "CHECK FAILED: $*" >&2; exit 1; }

# hardening <validation-file> <binary>...: exploit-mitigation check (PIE/RELRO/NX/canary, PE ASLR).
hardening() {
    v=$1; shift
    if out=$(sh zcutil/check-hardening.sh "$@" 2>&1); then echo "$out" | tee -a "$v"
    else echo "$out" | tee -a "$v"; check_fail "hardening check failed (zcutil/check-hardening.sh)"; fi
}

# Windows system-DLL allowlist, identical to the workflow.
WIN_DLL_ALLOW='^(advapi32|bcrypt|crypt32|iphlpapi|kernel32|msvcrt|netapi32|ntdll|ole32|oleaut32|psapi|secur32|shell32|shlwapi|user32|userenv|version|winmm|ws2_32|wtsapi32)\.dll$'

inner_daemon_linux() {
    inner_common
    cand=/out/daemon-linux-x86_64; rm -rf "$cand"; mkdir -p "$cand" /out/logs
    log=/out/logs/daemon-linux.log; : >"$log"
    say "build Linux daemon (jobs $JOBS)"
    export ZQW_STATIC_GOMP=1 CONFIGURE_FLAGS=--disable-man
    run_logged "$log" bash zcutil/build-release.sh linux -j"$JOBS" || check_fail "build-release.sh linux"
    host=$(./depends/config.guess)
    cp release/"$host"/zclassic* "$cand"/
    : >"$cand/validation.txt"
    for binary in "$cand"/zclassic*; do
        "$binary" --help >>"$cand/validation.txt"
        ldd "$binary" >>"$cand/validation.txt"
        highest=$(objdump -T "$binary" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -1)
        echo "$binary: highest $highest" | tee -a "$cand/validation.txt"
        [ "$(printf '%s\nGLIBC_2.31\n' "$highest" | sort -V | tail -1)" = GLIBC_2.31 ] || check_fail "$binary needs $highest (floor GLIBC_2.31)"
    done
    hardening "$cand/validation.txt" "$cand"/zclassic*
    if grep -E 'not found|libgomp' "$cand/validation.txt"; then check_fail "unexpected dynamic dependency (see above)"; fi
    want=$(expected_version)
    "$cand/zclassicd" --version | tee -a "$cand/validation.txt" | head -3
    "$cand/zclassicd" --version | grep -F "$want" >/dev/null || check_fail "zclassicd --version does not report $want"
    printf '%s\n' "$COMMIT" >"$cand/SOURCE_COMMIT.txt"
    (cd "$cand" && sha256sum zclassic* >SHA256SUMS.txt && sha256sum -c SHA256SUMS.txt)
    say "daemon-linux OK: $cand"
}

inner_daemon_win64() {
    inner_common
    cand=/out/daemon-windows-x86_64; rm -rf "$cand"; mkdir -p "$cand" /out/logs
    log=/out/logs/daemon-win64.log; : >"$log"
    say "build static Windows daemon (jobs $JOBS)"
    export CONFIGURE_FLAGS='--disable-man LDFLAGS=-static'
    run_logged "$log" bash zcutil/build-release.sh win64 -j"$JOBS" || check_fail "build-release.sh win64"
    cp release/x86_64-w64-mingw32/*.exe "$cand"/
    : >"$cand/validation.txt"
    for binary in "$cand"/*.exe; do
        x86_64-w64-mingw32-objdump -p "$binary" | awk '/DLL Name:/ { print tolower($3) }' >/tmp/imports.txt
        if grep -Ev "$WIN_DLL_ALLOW" /tmp/imports.txt; then check_fail "unexpected runtime DLL dependency in $binary"; fi
        cat /tmp/imports.txt >>"$cand/validation.txt"
        # Beyond the workflow: exactly one embedded manifest, UTF-8 active code page.
        n=$(grep -a -o '<assembly[ >]' "$binary" | wc -l)
        u=$(grep -a -o 'activeCodePage[^>]*>UTF-8<' "$binary" | wc -l)
        echo "$binary: manifests=$n activeCodePage-UTF-8=$u" | tee -a "$cand/validation.txt"
        [ "$n" -eq 1 ] && [ "$u" -eq 1 ] || check_fail "$binary: expected exactly one manifest with activeCodePage UTF-8"
    done
    hardening "$cand/validation.txt" "$cand"/*.exe
    printf '%s\n' "$COMMIT" >"$cand/SOURCE_COMMIT.txt"
    (cd "$cand" && sha256sum zclassic* >SHA256SUMS.txt && sha256sum -c SHA256SUMS.txt)
    say "daemon-win64 OK: $cand"
}

inner_wallet_linux() {
    inner_common
    daemon=/out/daemon-linux-x86_64
    out=/out/wallet-linux-candidate; rm -rf "$out"; mkdir -p /out/logs
    log=/out/logs/wallet-linux.log; : >"$log"
    [ -f "$daemon/SOURCE_COMMIT.txt" ] || check_fail "no Linux daemon candidate in $daemon (run daemon-linux first)"
    # The same gate the wallet workflow applies.
    test "$(cat "$daemon/SOURCE_COMMIT.txt")" = "$COMMIT" || check_fail "daemon candidate is for another commit"
    (cd "$daemon" && sha256sum -c SHA256SUMS.txt) || check_fail "daemon candidate checksum"
    say "wallet toolchain (static Qt 5.15.19 + OpenSSL, cached in /cache/wallet-linux-toolchain)"
    run_logged "$log" env BUILD_TOOLCHAIN_ONLY=1 sh wallet/contrib/release/linux.sh || check_fail "wallet toolchain"
    export ZCL_DAEMON="$daemon/zclassicd"
    ZCL_DAEMON_SHA256=$(sha256sum "$ZCL_DAEMON" | cut -d' ' -f1); export ZCL_DAEMON_SHA256
    chmod +x "$ZCL_DAEMON" 2>/dev/null || true
    say "build and check the portable Linux wallet bundle"
    run_logged "$log" sh wallet/contrib/release/linux.sh || check_fail "wallet/contrib/release/linux.sh"
    mkdir -p "$out"; cp -a wallet/artifacts/release/. "$out"/
    printf '%s\n' "$COMMIT" >"$out/SOURCE_COMMIT.txt"
    say "wallet-linux OK: $out"
}

# --- test stages ------------------------------------------------------------

inner_test_build() {
    inner_common
    mkdir -p $TD/logs
    log=$TD/logs/build.log; : >"$log"
    export CONFIGURE_FLAGS="--enable-tests --disable-man"
    if [ "$FLAVOR" = debug ]; then
        # As ci.yml: debug depends and --enable-debug (checked C++ library, lock-order checking).
        say "clean DEBUG build with tests (checked library, lock-order checks), jobs $JOBS"; export DEBUG=1
    else
        say "clean RELEASE-configured build with tests (the configuration that ships), jobs $JOBS"
    fi
    t0=$(date +%s)
    if run_logged "$log" ./zcutil/build.sh -j"$JOBS"; then rc=0; else rc=1; fi
    printf 'build-tests\t%s\t%s\n' "$([ $rc -eq 0 ] && echo PASS || echo FAIL)" "$(( $(date +%s) - t0 ))" >>$TD/results.tsv
    receipt "test-build/$FLAVOR" build-tests "$([ $rc -eq 0 ] && echo PASS || echo FAIL)" "$(( $(date +%s) - t0 ))" "$t0" "$log"
    [ $rc -eq 0 ] || exit 1
    say "Zcash parameters"
    t0=$(date +%s)
    if run_logged "$log" ./zcutil/fetch-params.sh; then
        receipt "test-build/$FLAVOR" fetch-params PASS "$(( $(date +%s) - t0 ))" "$t0" "$log"
    else
        printf 'fetch-params\tFAIL\t0\n' >>$TD/results.tsv
        receipt "test-build/$FLAVOR" fetch-params FAIL "$(( $(date +%s) - t0 ))" "$t0" "$log"
        exit 1
    fi
}

# Run a command with address-space randomisation off when the kernel allows it.  Sanitizer
# runtimes can loop on DEADLYSIGNAL when the mmap entropy (vm.mmap_rnd_bits) is higher than
# their shadow-memory layout expects; ZCL_CI_NOASLR=0 turns this off.
noaslr() {
    if [ "${ZCL_CI_NOASLR:-1}" != 0 ] && command -v setarch >/dev/null 2>&1 \
        && setarch "$(uname -m)" -R true >/dev/null 2>&1; then
        setarch "$(uname -m)" -R "$@"
    else
        "$@"
    fi
}

# step <name> <default-timeout-seconds> <cmd...>: run with its own log, record PASS/FAIL/SKIP
# (rc 77 = skip).  Every step has a wall-clock timeout and a log size cap, so a runaway step
# (a hang, or a sanitizer printing forever) fails fast instead of filling the disk.
#   ZCL_CI_TIMEOUT_<NAME>  this step's timeout in seconds (NAME upper case, - and . become _)
#   ZCL_CI_STEP_TIMEOUT    timeout for every step without a ZCL_CI_TIMEOUT_<NAME>
#   ZCL_CI_LOG_CAP         most bytes kept of a step log (default 268435456 = 256 MiB)
step() {
    name=$1; dflt=$2; shift 2
    if [ -n "${ZCL_CI_ONLY:-}" ]; then
        case ",$ZCL_CI_ONLY," in *",$name,"*) ;; *) return 0 ;; esac
    fi
    key=$(printf '%s' "$name" | tr 'a-z.-' 'A-Z__')
    eval "limit=\${ZCL_CI_TIMEOUT_$key:-\${ZCL_CI_STEP_TIMEOUT:-$dflt}}"
    cap=${ZCL_CI_LOG_CAP:-268435456}
    log=$TD/logs/$name.log; rcf=$TD/logs/$name.rc
    t0=$(date +%s)
    rm -f "$rcf"
    set +e
    # head -c ends the pipe at the cap: the step then dies of SIGPIPE on its next write.
    # STEP_RUN is `sh /ci/local-ci.sh __inner` inside the rootfs; `dry` points it at this checkout.
    { timeout -k 30 "$limit" ${STEP_RUN:-sh /ci/local-ci.sh __inner} "$@" 2>&1; echo $? >"$rcf"; } | head -c "$cap" >"$log"
    rc=$(cat "$rcf" 2>/dev/null); [ -n "$rc" ] || rc=1
    set -e
    secs=$(( $(date +%s) - t0 ))
    note=
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then note="timed out after ${limit}s"; rc=124
    elif [ "$(wc -c <"$log")" -ge "$cap" ]; then note="log reached the $cap byte cap"; [ "$rc" -ne 0 ] || rc=1
    fi
    [ -z "$note" ] || printf '\nlocal-ci: step %s: %s (rc %s)\n' "$name" "$note" "$rc" >>"$log"
    rm -f "$rcf"
    st=PASS
    [ "$rc" -eq 0 ] || st=FAIL
    [ "$rc" -ne 77 ] || st=SKIP
    printf '%s\t%s\t%s\n' "$name" "$st" "$secs" >>$TD/results.tsv
    receipt "test-run/$FLAVOR" "$name" "$st" "$secs" "$t0" "$log"
    echo "[$st] $name (${secs}s, rc $rc${note:+, $note})"
}

# Each of these is a function so `step` can run it in a subshell with set -e off.
t_devtools() { make -C zcutil/dev check; }
t_vendor()   { make -C src check-c23-vendor; }
t_toolsvendor() { sh src/c23/tools/check-vendor.sh zcutil/tools/Z23_SOURCE.tsv; }
t_jsonq()    { make -C zcutil/tools check; }   # builds zcutil/bin/jsonq (host cc) and runs its fixture test; the shell tests need it
t_lint()     { make -C zcutil/lint check && make -C zcutil/lint lint; }
t_norust()   { make -C src check-c23-no-rust; }
t_torsyms()  { make -C src check-c23-tor-symbols TOR_LIBDIR="/w/src/depends/$HOST/lib"; }
t_treeroot() {
    cc -std=c2x -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -Isrc \
        src/zcash/tree_root.c src/test/tree_root_c_tests.c -o /tmp/tree-root-test && { unset LD_PRELOAD; noaslr /tmp/tree-root-test; }
}
t_testbitcoin() { ./src/test/test_bitcoin; }
t_gtest()       { ./src/zcash-gtest; }
t_c23linked() {
    [ -d /golden ] || { echo "no golden corpus (set ZCL_CI_GOLDEN)"; return 77; }
    sh src/c23/test/run.sh --out $TD/c23 --linked src/libzcl_c23.a --deps "/w/src/depends/$HOST" --golden /golden
}
t_smoke() {
    rm -rf $TD/smoke
    if [ -d /prev ]; then
        sh src/c23/test/regtest-smoke.sh --bin /w/src/src --work $TD/smoke --peer-bin /prev --port-base 38232
    else
        sh src/c23/test/regtest-smoke.sh --bin /w/src/src --work $TD/smoke --port-base 38232
    fi
}
t_matrix() {
    rm -rf $TD/matrix
    if [ -d /prev ]; then peer="--peer-bin /prev"; else peer=""; fi
    # shellcheck disable=SC2086
    sh qa/rpc-tests/wallet_matrix.sh --bin /w/src/src --work $TD/matrix --only 1,2,3,4,5,6,7,8,9 --base 30000 $peer
}
t_txutil()      { sh qa/rpc-tests/zclassic_tx_util.sh /w/src/src; }
t_badhome()     { sh qa/rpc-tests/startup_bad_home.sh /w/src/src; }
t_tokenguard()  { sh qa/rpc-tests/wallet_tokenguard.sh /w/src/src; }
t_tokenguard_sapling() { E2E_NODE_ARGS="-nuparams=5ba81b19:1 -nuparams=76b809bb:1" sh qa/rpc-tests/wallet_tokenguard.sh /w/src/src; }
t_zslp()        { sh qa/rpc-tests/zslp_index.sh /w/src/src; }
t_tor() { # <script> [args]  -- uses the release candidate when present
    s=$1; shift
    bindir=/w/src/src; [ -x /out/daemon-linux-x86_64/zclassicd ] && bindir=/out/daemon-linux-x86_64
    sh "src/c23/tor/$s" "$bindir" default "$@"
}
t_wallet_qt() {
    # The wallet needs Qt 5.14+ (Qt::endl); focal's distro Qt is 5.12.  Use the pinned static Qt 5.15 of the
    # wallet bundle toolchain when it exists, else the distro qmake.
    qmake=qmake; qp=""
    if [ -x /w/src/wallet/artifacts/linux-build/qt-static/bin/qmake ]; then qmake=/w/src/wallet/artifacts/linux-build/qt-static/bin/qmake; qp=QTPLUGIN.platforms=qoffscreen; fi
    command -v "$qmake" >/dev/null || { echo "no Qt in the environment"; return 77; }
    cd wallet
    cp /usr/lib/x86_64-linux-gnu/libsodium.a res/libsodium.a
    mkdir -p artifacts/logic artifacts/widget
    (cd artifacts/logic && $qmake ../../tests/tests.pro CONFIG+=release $qp && make -j4)
    (cd artifacts/widget && $qmake ../../tests/widget/tst_widget.pro CONFIG+=release $qp && make -j4)
    export QT_QPA_PLATFORM=offscreen ZCL_SHOTS_DIR="$PWD/artifacts/shots"
    artifacts/logic/tst_logic -o artifacts/logic-results.txt,txt
    artifacts/widget/tst_widget -o artifacts/widget-results.txt,txt
}

inner_test_run() {
    inner_common
    HOST=$(./depends/config.guess)
    mkdir -p $TD/logs
    step check-dev-tools 600 t_devtools
    step check-c23-vendor 1800 t_vendor
    step check-tools-vendor 300 t_toolsvendor
    step build-jsonq 600 t_jsonq
    step zcl-lint 600 t_lint
    step check-c23-no-rust 1800 t_norust
    step check-c23-tor-symbols 1800 t_torsyms
    step test_bitcoin-full 7200 t_testbitcoin
    step zcash-gtest-full 7200 t_gtest
    step regtest-smoke 3600 t_smoke
    step zclassic-tx-util 600 t_txutil
    step startup-bad-home 300 t_badhome
    if [ "$FLAVOR" = release ]; then return 0; fi   # release flavor: unit suites + smoke only
    step tree-root-asan 900 t_treeroot
    step c23-run-linked 7200 t_c23linked
    step wallet_matrix-1-9 10800 t_matrix
    step wallet_tokenguard 3600 t_tokenguard
    step wallet_tokenguard-sapling 3600 t_tokenguard_sapling
    step zslp_index 3600 t_zslp
    step wallet-qt-logic-widget 7200 t_wallet_qt
}

inner_test_tor() {
    inner_common
    mkdir -p $TD/logs
    step tor-twonode 3600 t_tor twonode.sh
    step tor-threenode 3600 t_tor threenode.sh
    step tor-addrv2gossip 3600 t_tor addrv2gossip.sh
}
# (steps run as `local-ci.sh __inner <t_function> [args]` so `timeout` can wrap them)
# Fake steps for `dry` (plumbing check, no root filesystem).
t_dry_pass() { echo "dry pass"; }
t_dry_fail() { echo "dry fail"; return 1; }
t_dry_skip() { echo "dry skip"; return 77; }

# ------------------------------------------------------------------- outer
OUTER_ONLY=1
if [ "${1:-}" = "__inner" ]; then
    OUTER_ONLY=0
    case ${2:-} in
        daemon-linux) inner_daemon_linux ;;
        daemon-win64) inner_daemon_win64 ;;
        wallet-linux) inner_wallet_linux ;;
        test-build)   inner_test_build ;;
        test-run)     inner_test_run ;;
        test-tor)     inner_test_tor ;;
        t_dry_*) fn=$2; shift 2; "$fn" "$@"; exit $? ;;
        t_*) fn=$2; shift 2; inner_common; HOST=$(./depends/config.guess); "$fn" "$@"; exit $? ;;
        *) die "unknown inner stage ${2:-}" ;;
    esac
    exit 0
fi

EXTRA_BINDS=""; PICKS=""; FLAVOR=both; FLAVOR_CUR=debug; TESTDIR=test
COMMIT_REV=HEAD; TOR=0; JOBS=${ZCL_CI_JOBS:-}
while [ $# -gt 0 ]; do
    case $1 in
        --commit) COMMIT_REV=$2; shift 2 ;;
        --tor) TOR=1; shift ;;
        --flavor) FLAVOR=$2; shift 2 ;;
        --only) case $2 in ""|*[!A-Za-z0-9_.,-]*) die "--only takes a comma list of step names" ;; esac; ZCL_CI_ONLY=$2; export ZCL_CI_ONLY; shift 2 ;;
        --pick) PICKS="$PICKS $2"; shift 2 ;;
        --jobs) JOBS=$2; shift 2 ;;
        -h|--help) sed -n '2,/^set -eu/p' "$SELF" | sed '$d'; exit 0 ;;
        -*) die "unknown option $1" ;;
        *) break ;;
    esac
done
CMD=${1:-}; [ -n "$CMD" ] || { sed -n '2,/^set -eu/p' "$SELF" | sed '$d'; exit 2; }
# --only (or an inherited ZCL_CI_ONLY): every name must be a step, or a typo would run nothing and pass.
if [ -n "${ZCL_CI_ONLY:-}" ]; then
    case $ZCL_CI_ONLY in *[!A-Za-z0-9_.,-]*) die "ZCL_CI_ONLY takes a comma list of step names" ;; esac
    for n in $(printf '%s' "$ZCL_CI_ONLY" | tr ',' ' '); do
        grep -q "^ *step $n " "$SELF" || die "--only: $n is not a step of local-ci.sh"
    done
fi
ENVDIR=${ZCL_CI_ENV:-$HOME/work/zc23-localci-env}
CACHE=${ZCL_CI_CACHE:-$HOME/work/zc23-localci-cache}
if [ -z "$JOBS" ]; then JOBS=$(getconf _NPROCESSORS_ONLN); [ "$JOBS" -le 8 ] || JOBS=8; fi
COMMIT=$(git -C "$REPO" rev-parse --verify "$COMMIT_REV^{commit}") || die "cannot resolve $COMMIT_REV"
SHORT=$(printf '%s' "$COMMIT" | cut -c1-9)
OUT=${2:-${ZCL_CI_OUT:-$HOME/work/zc23-localci-out/$SHORT}}
mkdir -p "$OUT" "$CACHE"; OUT=$(CDPATH= cd -- "$OUT" && pwd); CACHE=$(CDPATH= cd -- "$CACHE" && pwd)
GOLDEN=${ZCL_CI_GOLDEN:-}
[ -n "$GOLDEN" ] || { [ -d "$HOME/work/zc23-golden/src/test/data/c23_golden" ] && GOLDEN=$HOME/work/zc23-golden/src/test/data/c23_golden; } || true

need_env() {
    [ -f "$ENVDIR/etc/os-release" ] && grep -q 'VERSION_ID="20.04"' "$ENVDIR/etc/os-release" \
        || die "focal environment missing at $ENVDIR; run: zcutil/local-ci.sh env-setup"
    [ -x "$ENVDIR/usr/bin/gcc" ] || die "$ENVDIR has no compiler; run: zcutil/local-ci.sh env-setup"
    command -v bwrap >/dev/null || die "bubblewrap (bwrap) is required on this host"
}

# enter <workdir> <net: host|none> <cmd...>
# The focal tree is the root; it is bound read-write so apt works, builds never
# touch it (everything lives in /w, /cache, /out).  One uid is mapped (0 inside =
# you outside), so files created inside are owned by you on the host.
enter() {
    w=$1; net=$2; shift 2
    [ "$net" = none ] && netarg=--unshare-net || netarg=--share-net
    extra=${EXTRA_BINDS:-}
    [ -z "$GOLDEN" ] || extra="$extra --ro-bind $GOLDEN /golden"
    [ -z "${ZCL_CI_PREV_BIN:-}" ] || extra="$extra --ro-bind $ZCL_CI_PREV_BIN /prev"
    mkdir -p "$CACHE/zcash-params" "$CACHE/home-tmp"
    # step limits and the log cap reach the steps (--clearenv drops everything else)
    passenv=""
    for kv in $(env | grep -E '^ZCL_CI_(TIMEOUT_[A-Z0-9_]+|STEP_TIMEOUT|LOG_CAP|NOASLR)=[0-9A-Za-z]*$' || true); do
        passenv="$passenv --setenv ${kv%%=*} ${kv#*=}"
    done
    if [ ! -e "$CACHE/zcash-params/.seeded" ]; then
        # Reuse an existing parameter set instead of re-downloading ~900 MB.
        if [ -d "$HOME/.zcash-params" ]; then cp -n "$HOME"/.zcash-params/* "$CACHE/zcash-params/" 2>/dev/null || true; fi
        : >"$CACHE/zcash-params/.seeded"
    fi
    # shellcheck disable=SC2086
    # --clearenv: host variables such as TMPDIR (devbuild points it at a host-only scratch
    # directory), TMP, CCACHE_DIR must not leak into the environment.
    exec bwrap --clearenv --unshare-user --uid 0 --gid 0 --unshare-pid --unshare-ipc --unshare-uts $netarg --die-with-parent \
        --bind "$ENVDIR" / --dev /dev --proc /proc --bind "$w/tmp" /tmp \
        --ro-bind /etc/resolv.conf /etc/resolv.conf \
        --bind "$w" /w --bind "$CACHE" /cache --bind "$OUT" /out \
        --bind "$CACHE/zcash-params" /root/.zcash-params \
        --ro-bind "$SELF" /ci/local-ci.sh $extra \
        --setenv HOME /root --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        --setenv TMPDIR /tmp --setenv TMP /tmp --setenv TEMP /tmp --setenv LANG C.UTF-8 --setenv TERM "${TERM:-dumb}" \
        $passenv \
        --setenv ZCL_CI_TESTDIR "$TESTDIR" --setenv ZCL_CI_FLAVOR "$FLAVOR_CUR" \
        --setenv ZCL_CI_JOBS "$JOBS" --setenv ZCL_CI_EXPECT_VERSION "${ZCL_CI_EXPECT_VERSION:-}" \
        --setenv ZCL_CI_ONLY "${ZCL_CI_ONLY:-}" \
        --chdir /w "$@"
}

# prepare_src <job>: fresh clone of the requested commit into $OUT/work/<job>/src
prepare_src() {
    job=$1; w=$OUT/work/$job
    case $w in "$OUT"/work/*) ;; *) die "refusing to clean $w" ;; esac
    rm -rf "$w"; mkdir -p "$w/tmp"
    git clone -q --no-hardlinks --no-checkout "$REPO" "$w/src"
    git -C "$w/src" checkout -q --detach "$COMMIT"
    [ "$(git -C "$w/src" rev-parse HEAD)" = "$COMMIT" ] || die "checkout mismatch"
    # --pick: extra commits applied on top, for the test builds only (e.g. a test-harness fix
    # not yet in the release branch).  They are listed in $OUT/test*/PICKS.txt.
    case $job in
        test|test-release)
            for p in $PICKS; do
                git -C "$w/src" -c user.name=local-ci -c user.email=local-ci@localhost cherry-pick -x "$p" >/dev/null \
                    || die "cherry-pick of $p failed"
            done ;;
    esac
    if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no 2>/dev/null)" ] && [ "$COMMIT_REV" = HEAD ]; then
        echo "local-ci: note: the working tree has uncommitted changes; building committed $SHORT only" >&2
    fi
}

# stage <src-dir-name> <net> <inner-stage> [keep]: (fresh clone unless keep) and run
# one inner stage in the focal environment.  The cache lock keeps two local-ci runs
# from writing the shared depends/ccache/toolchain caches at the same time.
stage() {
    srcname=$1; net=$2; inner=$3; mode=${4:-clone}
    need_env
    say "$inner @ $SHORT (jobs $JOBS, out $OUT)"
    [ "$mode" = keep ] || prepare_src "$srcname"
    w=$OUT/work/$srcname
    [ -d "$w/src/.git" ] || die "no source clone in $w (run the test build stage first)"
    t0=$(date +%s)
    # not `rc`: that name belongs to the callers (do_test, all), which sum up failures
    st_rc=0
    {
        if [ "$net" = host ] && command -v flock >/dev/null; then flock 9; fi
        ( enter "$w" "$net" sh /ci/local-ci.sh __inner "$inner" )
    } 9>"$CACHE/.lock" || st_rc=$?
    echo "== local-ci: $inner finished in $(( $(date +%s) - t0 ))s (rc $st_rc)"
    case $inner in
        daemon-linux|daemon-win64|wallet-linux)
            RCPT_OUT=$OUT; RCPT_COMMIT=$COMMIT; RCPT_TREE=$(git -C "$REPO" rev-parse "$COMMIT^{tree}")
            RCPT_ENVFILE=$ENVDIR/root/ZCL-CI-ENV.txt
            receipt stage "$inner" "$([ "$st_rc" -eq 0 ] && echo PASS || echo FAIL)" "$(( $(date +%s) - t0 ))" "$t0" "$OUT/logs/$inner.log" ;;
    esac
    return $st_rc
}

# do_dry: three fake steps through the real step() and receipt() code, no root filesystem.
# Used to check the plumbing (--only filter, results.tsv, receipts.jsonl) in seconds.
do_dry() {
    TD=$OUT/dry; FLAVOR=debug; STEP_RUN="sh $SELF __inner"
    mkdir -p "$TD/logs"; : >"$TD/results.tsv"
    RCPT_OUT=$OUT; RCPT_COMMIT=$COMMIT; RCPT_TREE=$(git -C "$REPO" rev-parse "$COMMIT^{tree}"); RCPT_ENVFILE=
    step dry-pass 60 t_dry_pass
    step dry-fail 60 t_dry_fail
    step dry-skip 60 t_dry_skip
    say "dry results in $TD/results.tsv, receipts in $OUT/receipts.jsonl"
}

# do_test_changed: `test` restricted to the steps zcl-dev select maps from the diff.
do_test_changed() {
    zd=$REPO/zcutil/dev/zcl-dev
    [ -x "$zd" ] || make -C "$REPO/zcutil/dev" >/dev/null || die "cannot build zcutil/dev/zcl-dev"
    base=${ZCL_CI_BASE:-origin/master}
    names=$(git -C "$REPO" diff --name-only "$base...$COMMIT") || die "git diff $base...$COMMIT failed"
    sel=$(printf '%s\n' "$names" | "$zd" -C "$REPO" select --steps --stdin) || die "zcl-dev select failed"
    say "zcl-dev select ($base...$SHORT): $sel"
    stages=$(printf '%s\n' "$names" | "$zd" -C "$REPO" select --stdin | sed -n 's/^stages: //p')
    [ -z "$stages" ] || say "also needed, run separately: $stages"
    case $sel in
        NONE) say "no test step selected"; return 0 ;;
        ALL) ZCL_CI_ONLY=; export ZCL_CI_ONLY ;;
        *) ZCL_CI_ONLY=$sel; export ZCL_CI_ONLY ;;
    esac
    do_test
}

do_env_setup() {
    command -v bwrap >/dev/null || die "bubblewrap (bwrap) is required"
    command -v cc >/dev/null || die "a host C compiler is required (builds the chown shim)"
    unshare -Ur true 2>/dev/null || die "unprivileged user namespaces are disabled on this host"
    mkdir -p "$ENVDIR" "$CACHE/env-dl"
    dl=$CACHE/env-dl
    if [ ! -f "$ENVDIR/etc/os-release" ]; then
        say "download $FOCAL_TGZ"
        [ -f "$dl/$FOCAL_TGZ" ] || curl --fail --location --retry 3 -o "$dl/$FOCAL_TGZ" "$FOCAL_URL/$FOCAL_TGZ"
        curl --fail --location --retry 3 -o "$dl/SHA256SUMS" "$FOCAL_URL/SHA256SUMS"
        printf '%s  %s\n' "$FOCAL_SHA256" "$FOCAL_TGZ" >"$dl/pinned.sha256"
        (cd "$dl" && sha256sum -c pinned.sha256) || die "tarball does not match the pinned SHA-256"
        pub=$(awk -v f="*$FOCAL_TGZ" '$2 == f { print $1 }' "$dl/SHA256SUMS")
        [ "$pub" = "$FOCAL_SHA256" ] || die "published SHA256SUMS disagrees with the pinned checksum ($pub)"
        say "unpack into $ENVDIR"
        tar -xzf "$dl/$FOCAL_TGZ" -C "$ENVDIR" --no-same-owner
    fi
    # Single-uid user namespaces make chown to any other owner fail with EINVAL,
    # which dpkg needs for a handful of packages.  A two-function shim makes those
    # calls succeed; ownership is meaningless in this single-user build root.
    mkdir -p "$ENVDIR/usr/local/lib"
    cat >"$dl/nochown.c" <<'EOF'
#include <sys/types.h>
int chown(const char *p, uid_t u, gid_t g) { (void)p; (void)u; (void)g; return 0; }
int lchown(const char *p, uid_t u, gid_t g) { (void)p; (void)u; (void)g; return 0; }
int fchown(int f, uid_t u, gid_t g) { (void)f; (void)u; (void)g; return 0; }
int fchownat(int d, const char *p, uid_t u, gid_t g, int fl) { (void)d; (void)p; (void)u; (void)g; (void)fl; return 0; }
EOF
    cc -O2 -shared -fPIC -o "$ENVDIR/usr/local/lib/zcl-nochown.so" "$dl/nochown.c"
    # tar run as (mapped) root restores the archive owner, which a one-uid namespace refuses.
    mkdir -p "$ENVDIR/usr/local/bin"
    printf '#!/bin/sh
exec /bin/tar "$@" --no-same-owner
' >"$ENVDIR/usr/local/bin/tar"
    chmod 755 "$ENVDIR/usr/local/bin/tar"
    mkdir -p "$ENVDIR/etc/apt/apt.conf.d" "$ENVDIR/root" "$ENVDIR/ci" "$ENVDIR/w" "$ENVDIR/cache" "$ENVDIR/out"
    echo 'APT::Sandbox::User "root";' >"$ENVDIR/etc/apt/apt.conf.d/99zc-localci"
    cat >"$ENVDIR/root/zc-install.sh" <<EOF
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y $DAEMON_PKGS
apt-get install -y $MINGW_PKGS
update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
apt-get install -y $WALLET_PKGS
apt-get install -y --no-install-recommends $TEST_PKGS
{ echo "focal root filesystem: ubuntu-base $FOCAL_VER, sha256 $FOCAL_SHA256"; date -u +"built %Y-%m-%dT%H:%M:%SZ";
  gcc --version | head -1; x86_64-w64-mingw32-g++ --version | head -1; ldd --version | head -1;
  dpkg-query -W -f='\${Package} \${Version}\n' | sort; } >/root/ZCL-CI-ENV.txt
EOF
    say "apt-get install inside the focal environment (this takes a while the first time)"
    mkdir -p "$CACHE/env-tmp"
    # shellcheck disable=SC2046
    bwrap --clearenv --unshare-user --uid 0 --gid 0 --unshare-pid --unshare-ipc --unshare-uts --share-net --die-with-parent \
        --bind "$ENVDIR" / --dev /dev --proc /proc --bind "$CACHE/env-tmp" /tmp \
        --ro-bind /etc/resolv.conf /etc/resolv.conf \
        --setenv HOME /root --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        --setenv LD_PRELOAD /usr/local/lib/zcl-nochown.so --chdir / sh /root/zc-install.sh
    say "environment ready:"; head -5 "$ENVDIR/root/ZCL-CI-ENV.txt"
}

summary_test() {
    r=$OUT/$TESTDIR/results.tsv
    [ -f "$r" ] || { echo "no test results"; return 1; }
    echo; echo "== test summary, $FLAVOR_CUR build ($OUT/$TESTDIR, logs in $OUT/$TESTDIR/logs)"
    printf '%-34s %-6s %8s\n' STEP RESULT SECONDS
    awk -F'\t' '{ printf "%-34s %-6s %8s\n", $1, $2, $3 }' "$r"
    nfail=$(awk -F'\t' '$2 == "FAIL"' "$r" | wc -l)
    nskip=$(awk -F'\t' '$2 == "SKIP"' "$r" | wc -l)
    echo "-- $(wc -l <"$r") steps, $nfail failed, $nskip skipped"
    [ "$nfail" -eq 0 ]
}

do_test() {
    rc=0
    case $FLAVOR in both) fl="debug release" ;; debug|release) fl=$FLAVOR ;; *) die "--flavor must be debug, release or both" ;; esac
    for FLAVOR_CUR in $fl; do
        if [ "$FLAVOR_CUR" = debug ]; then TESTDIR=test; else TESTDIR=test-release; fi
        mkdir -p "$OUT/$TESTDIR/logs"; rm -f "$OUT/$TESTDIR/results.tsv"; : >"$OUT/$TESTDIR/results.tsv"
        printf '%s\n' $PICKS >"$OUT/$TESTDIR/PICKS.txt"
        # Reuse one clean clone for the build and the run stages (and the Tor stage).
        if ! stage "$TESTDIR" host test-build; then summary_test || true; rc=1; continue; fi
        # Mount the wallet bundle's static Qt 5.15 + OpenSSL (if built) where the wallet tests expect them.
        tc=$CACHE/wallet-linux-toolchain
        if [ -x "$tc/qt-static/bin/qmake" ]; then
            lb=$OUT/work/$TESTDIR/src/wallet/artifacts/linux-build; mkdir -p "$lb/qt-static" "$lb/openssl"
            EXTRA_BINDS="--ro-bind $tc/qt-static /w/src/wallet/artifacts/linux-build/qt-static --ro-bind $tc/openssl /w/src/wallet/artifacts/linux-build/openssl"
        fi
        stage "$TESTDIR" none test-run keep || rc=1
        EXTRA_BINDS=""
        if [ "$TOR" = 1 ] && [ "$FLAVOR_CUR" = debug ]; then stage "$TESTDIR" host test-tor keep || rc=1; fi
        summary_test || rc=1
    done
    return $rc
}

cmd_one() {
    case $1 in
        env-setup) do_env_setup ;;
        daemon-linux) stage daemon-linux host daemon-linux ;;
        daemon-win64) stage daemon-win64 host daemon-win64 ;;
        wallet-linux)
            # The static Qt/OpenSSL toolchain lives in the cache and is mounted over the
            # directories linux.sh builds into (the GitHub job cached the same two paths).
            mkdir -p "$CACHE/wallet-linux-toolchain/qt-static" "$CACHE/wallet-linux-toolchain/openssl"
            prepare_src wallet-linux
            lb=$OUT/work/wallet-linux/src/wallet/artifacts/linux-build
            mkdir -p "$lb/qt-static" "$lb/openssl"
            EXTRA_BINDS="--bind $CACHE/wallet-linux-toolchain/qt-static /w/src/wallet/artifacts/linux-build/qt-static --bind $CACHE/wallet-linux-toolchain/openssl /w/src/wallet/artifacts/linux-build/openssl"
            stage wallet-linux host wallet-linux keep ;;
        test) do_test ;;
        test-changed) do_test_changed ;;
        dry) do_dry ;;
        macos) do_macos ;;
        retry-step) need_env; [ -n "${RETRY_FN:-}" ] || die "usage: RETRY_FN=t_treeroot local-ci.sh retry-step"; stage test none "$RETRY_FN" keep ;;
        clean) rm -rf "${OUT:?}/work"; say "removed $OUT/work" ;;
        shell) need_env; prepare_src shell; ( enter "$OUT/work/shell" host sh -c 'cd /w/src; exec bash -i' ) ;;
        *) die "unknown command $1" ;;
    esac
}

do_macos() {
    mac=${ZCL_CI_MAC:-}; [ -n "$mac" ] || die "set ZCL_CI_MAC to the ssh alias of the Mac"
    b=$OUT/source-$SHORT.bundle
    # Bundle exactly this commit (under a temporary local ref), so the Mac needs no GitHub access.
    git -C "$REPO" update-ref "refs/local-ci/$SHORT" "$COMMIT"
    brc=0
    git -C "$REPO" bundle create "$b" "refs/local-ci/$SHORT" >/dev/null 2>&1 || brc=$?
    git -C "$REPO" update-ref -d "refs/local-ci/$SHORT"
    [ "$brc" -eq 0 ] || die "git bundle failed"
    rd=${ZCL_CI_MAC_DIR:-work/zc23-localci}
    ssh "$mac" "mkdir -p $rd/in" && scp -q "$b" "$mac:$rd/in/source.bundle" && scp -q "$REPO/zcutil/local-ci-macos.sh" "$mac:$rd/in/local-ci-macos.sh"
    ssh "$mac" "cd $rd && sh in/local-ci-macos.sh --bundle in/source.bundle --commit $COMMIT --out out-$SHORT ${ZCL_CI_MAC_ARGS:-daemon}"
    mkdir -p "$OUT/macos" && scp -q -r "$mac:$rd/out-$SHORT/." "$OUT/macos/"
    say "macOS artifacts copied to $OUT/macos"
}

case $CMD in
    all)
        rc=0
        for c in daemon-linux daemon-win64 wallet-linux test; do cmd_one "$c" || rc=1; done
        if [ -n "${ZCL_CI_MAC:-}" ]; then cmd_one macos || rc=1; fi
        [ $rc -eq 0 ] && say "ALL PASSED ($OUT)" || say "FAILED (see above)"
        exit $rc ;;
    *) cmd_one "$CMD" ;;
esac
