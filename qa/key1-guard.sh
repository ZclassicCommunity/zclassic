#!/bin/sh
# Build and run the KEY-1 guard (qa/key1-guard.c) on this checkout, then prove it bites:
# copies of the three guarded wallet files get a poisoned line and the guard must fail on each.
# POSIX sh and a C23 compiler only. usage: qa/key1-guard.sh [source root]
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=${1:-$(CDPATH= cd -- "$here/.." && pwd)}
cc=${CC:-cc}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fails=0

$cc -std=c2x -O2 -Wall -Wextra -Werror -o "$work/key1-guard" "$here/key1-guard.c"
guard="$work/key1-guard"

"$guard" --root "$root" --self-test
"$guard" --root "$root"

# Negative cases on a scratch copy of the guarded files.
mkdir -p "$work/r/src/wallet" "$work/r/qa"
cp "$root/src/wallet/wallet.h" "$root/src/wallet/walletdb.cpp" "$root/src/wallet/rpcwallet.cpp" "$work/r/src/wallet/"
cp "$root/qa/key1-walletdb-baseline.txt" "$work/r/qa/"
"$guard" --root "$work/r" >/dev/null || { echo "FAIL pristine copy rejected" >&2; exit 1; }

expect_fail() {   # <name>
    if "$guard" --root "$work/r" >"$work/out" 2>&1; then
        echo "FAIL $1: guard accepted the poisoned copy" >&2; fails=$((fails + 1))
    elif grep -q 'denylisted' "$work/out"; then
        echo "PASS $1 (guard rejected it: $(grep -m1 'denylisted' "$work/out" | sed 's/^ *//'))"
    else
        echo "FAIL $1: guard failed without naming a denylisted token" >&2; cat "$work/out" >&2; fails=$((fails + 1))
    fi
    cp "$root/src/wallet/wallet.h" "$root/src/wallet/walletdb.cpp" "$root/src/wallet/rpcwallet.cpp" "$work/r/src/wallet/"
}

# The SerializationOp of CWalletTx is the first one after its class line
awk '
    /class CWalletTx/ { armed = 1 }
    armed && /SerializationOp[(]/ { sop = 1 }
    { print }
    sop && index($0, "{") { print "        READWRITE(vchPrivKey);"; sop = 0; armed = 0 }' \
    "$root/src/wallet/wallet.h" > "$work/r/src/wallet/wallet.h"
expect_fail "key serialized by CWalletTx"

awk '
    /class SproutNoteData/ { armed = 1 }
    armed && /SerializationOp[(]/ { sop = 1 }
    { print }
    sop && index($0, "{") { print "        READWRITE(nsk);"; sop = 0; armed = 0 }' \
    "$root/src/wallet/wallet.h" > "$work/r/src/wallet/wallet.h"
expect_fail "nsk serialized by SproutNoteData"

printf '%s\n' 'bool CWalletDB::WriteEvil(const CKey& k) { return Write(std::string("evil"), k); }' >> "$work/r/src/wallet/walletdb.cpp"
expect_fail "new key write in walletdb.cpp"

# A NUL byte in walletdb.cpp must not hide what follows it.
printf '\0\n%s\n' 'bool CWalletDB::WriteEvil2(const CKey& k) { return Write(std::string("evil2"), k); }' >> "$work/r/src/wallet/walletdb.cpp"
expect_fail "key write after a NUL byte in walletdb.cpp"

awk '
    /^UniValue getwalletsummary\(/ { armed = 1 }
    { print }
    armed && /^\{/ { print "    result.push_back(Pair(\"seed\", HexStr(seed)));"; armed = 0 }' \
    "$root/src/wallet/rpcwallet.cpp" > "$work/r/src/wallet/rpcwallet.cpp"
expect_fail "seed emitted by getwalletsummary"

[ "$fails" -eq 0 ] && { echo "key1-guard: all checks passed"; exit 0; }
echo "key1-guard: $fails check(s) failed" >&2
exit 1
