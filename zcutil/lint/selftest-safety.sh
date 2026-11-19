#!/bin/sh
# Selftest of the safety rules secretlog, testiso, shellport and wallclock against throw-away git repositories.
# usage: selftest-safety.sh <zcl-lint binary>
# Copyright 2026 Rhett Creighton - MIT (zclassicd)
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
[ -x "$bin" ] || { echo "selftest-safety: $bin is not built" >&2; exit 2; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/zcl-lint-safety.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT INT TERM
fails=0; n=0
ok() { n=$((n + 1)); }
bad() { fails=$((fails + 1)); echo "FAIL selftest-safety: $*" >&2; }
newrepo() {
    r=$tmp/$1; mkdir -p "$r/zcutil/lint"; cd "$r" || exit 2
    git init -q . && git config user.email t@example.invalid && git config user.name t
}
track() { git add -A >/dev/null 2>&1; }
run() {
    want=$1; pat=$2; shift 2
    out=$("$bin" --root . "$@" 2>&1); rc=$?
    ok
    [ "$rc" = "$want" ] || bad "zcl-lint $*: rc=$rc want $want ($out)"
    [ -z "$pat" ] || printf '%s\n' "$out" | grep -q -- "$pat" || bad "zcl-lint $*: output lacks '$pat': $out"
}

# ---- secretlog: custody. A clean tree passes with an empty baseline; each violation is named with file:line ----
newrepo secret
mkdir -p src wallet/src src/test
cat > src/ok.cpp <<'EOF'
void f(const CKeyID &id, int n) {
    LogPrintf("key id %s seed node %d\n", id.ToString(), n);   // "seed" and CKey only in the string
    printf("CKey and strWalletPass in a literal\n");
    // LogPrintf("%s", strWalletPass);
    unsigned seeded = 1; (void)seeded;
}
EOF
printf 'void g() { LogPrintf("x"); }\n' > wallet/src/clean.cpp
printf 'void t(CKey k) { printf("%%s", HexStr(k).c_str()); }\n' > src/test/skipped.cpp
track
run 0 'created (0 paths, 0)' secretlog --update-baseline
run 0 'ok (0 paths, 0)' secretlog
cat > wallet/src/leak.cpp <<'EOF'
void a(const SecureString &strWalletPass) {
    LogPrintf("unlock with %s\n", strWalletPass.c_str());
}
void b(const CKey &key) {
    LogPrint("wallet", "priv %s\n",
             HexStr(key.begin(), key.end()));
    std::cout << "dumped " << EncodeSecret(key) << std::endl;
}
void c(const std::string &mnemonic, int walletSeed, const CKey &key) {
    fprintf(stderr, "%s %d\n", mnemonic.c_str(), walletSeed);
    LogPrintf("%s\n", HexStr(key));
    LogPrintf("%s\n", GetPrivKey());
    qDebug() << "x"; LogPrintf("ok %s\n", mnemonic.c_str()); // log-ok: test of the override
}
void d(const std::string &strWalletPass, int x) {
    cerr << strWalletPass;
    std::cerr << SproutSpendingKey(x);
}
EOF
track
run 1 'wallet/src/leak.cpp: 8 new' secretlog
out=$("$bin" --root . secretlog 2>&1)
for l in 2 5 7 10 11 12 16 17; do
    ok; printf '%s\n' "$out" | grep -q "wallet/src/leak.cpp:$l: secret" || bad "secretlog: leak.cpp:$l not reported: $out"
done
ok; printf '%s\n' "$out" | grep -q 'leak.cpp:13' && bad "secretlog: log-ok line was flagged"
run 1 'NOT updated' secretlog --update-baseline
rm wallet/src/leak.cpp; track
run 0 'ok (0 paths, 0)' secretlog

newrepo secrethollow
printf 'int x;\n' > main.c; track
run 2 'hollow scan' secretlog
run 2 'hollow scan' secretlog --update-baseline

# ---- testiso ----
newrepo iso
mkdir -p qa/rpc-tests src/test
cat > qa/rpc-tests/good.sh <<'EOF'
#!/bin/sh
d=$(mktemp -d /tmp/good.XXXXXX)
t=${TMPDIR:-/tmp}
# /tmp/commented-out is ignored
zclassicd -datadir="$d" -port=$PORT -rpcport=$RPC &
zclassicd -datadir="$HOME/.zclassic" \
    -rpcport=$RPC &
zclassicd -port=8033 -datadir=$d  # iso-ok: fixture exemption
EOF
printf 'TEST(a, b) { std::string p = GetDataDir(); }\n' > src/test/good.cpp
track
run 0 'created (0 paths, 0)' testiso --update-baseline
cat > qa/rpc-tests/bad.sh <<'EOF'
#!/bin/sh
cp x /tmp/fixture.dat
zclassicd -daemon -port=18233 -rpcport=18232
echo y > ~/.zclassic/zclassic.conf
zclassicd -datadir=$d
zclassicd -listen=0 \
    -conf=$HOME/.zclassic/zclassic.conf
case $x in
*) cp f /tmp/x ;;
esac
EOF
printf 'void t() { fopen("/tmp/x.dat", "w"); const char *d = "%%APPDATA%%/Zclassic"; }
' > src/test/bad.cpp
track
run 1 'qa/rpc-tests/bad.sh:datadir: 2 new' testiso
run 1 'qa/rpc-tests/bad.sh:port: 1 new' testiso
run 1 'qa/rpc-tests/bad.sh:tmp: 2 new' testiso
run 1 'src/test/bad.cpp:datadir: 1 new' testiso
run 1 'src/test/bad.cpp:tmp: 1 new' testiso
run 1 'NOT updated' testiso --update-baseline
mkdir -p qa/lib; cp qa/rpc-tests/bad.sh qa/lib/lease.sh; track
run 1 'qa/lib/lease.sh:tmp' testiso
ok; "$bin" --root . testiso 2>&1 | grep -q 'qa/lib/lease.sh:port' && bad "testiso: port flagged outside qa/rpc-tests"
rm qa/lib/lease.sh qa/rpc-tests/bad.sh src/test/bad.cpp; track
run 0 'ok (0 paths, 0)' testiso

# ---- shellport ----
newrepo port
cat > a.sh <<'EOF'
#!/bin/sh
set -o pipefail
sed -i 's/a/b/' f
sed -i.bak s/a/b/ f
sed -n 1p f
n=$(nproc)
n=$(nproc 2>/dev/null || sysctl -n hw.ncpu)
echo "nproc ss timeout stat -c in a string"
# sed -i in a comment
stat -c %s f
stat -f %z f
ss -ltn | grep 8033
readlink -f x && readlink x
date -d yesterday +%s
date +%s
cat f | grep -P '\d+'
timeout 5 sleep 1
command -v nproc
ps | grep -q foo
grep -q foo f || true
cat f | grep -q bar
x=ss; echo $x
make -j"$(nproc)"
x="$(readlink -f $0)"
[ -n "$(ss -ltn)" ] && echo "literal ss nproc"
cat <<'DATA'
sed -i evil f
DATA
cat <<\ESC
stat -c %s f
ESC
sed -i s/q/r/ g
EOF
cat > c.sh <<'EOF'
#!/bin/sh
cat <<'X'
set -o pipefail
X
ps | grep -q foo
EOF
cat > b.sh <<'EOF'
#!/bin/sh
ps | grep -q foo
nproc  # port-ok: guarded by command -v
EOF
track
run 1 'no baseline' shellport
run 0 'created' shellport --update-baseline
out=$("$bin" --root . shellport 2>&1)
ok
printf '%s\n' "$out" | grep -q 'ok (' || bad "shellport: not ok after baseline: $out"
grep -v '^#' zcutil/lint/shellport.txt | sort > got.txt
cat > want.txt <<'EOF'
a.sh:date-d	1
a.sh:grep-P	1
a.sh:nproc	3
a.sh:pipefail-grep-q	2
a.sh:readlink-f	2
a.sh:sed-i	3
a.sh:ss	2
a.sh:stat-c	1
a.sh:timeout	1
EOF
ok; cmp -s got.txt want.txt || { bad "shellport kinds differ"; diff want.txt got.txt >&2; }
printf 'nproc\n' >> b.sh; track
run 1 'b.sh:nproc: 1 new' shellport
rm a.sh b.sh; printf '#!/bin/sh\necho ok\n' > c.sh; track
run 0 'can be lowered' shellport

# ---- wallclock ----
newrepo clock
mkdir -p qa src/test
cat > qa/t.sh <<'EOF'
#!/bin/sh
while [ $i -lt 10 ]; do i=$((i + 1)); done
[ $elapsed -lt 5 ] || exit 1
[ "$took" -gt 3 ] && exit 1
[ $((SECONDS - start)) -ge 9 ]  # real-clock: bounded wait
echo "elapsed $elapsed"
echo "took $(( $(date +%s) - t0 ))s z->z"
EOF
cat > src/test/t.cpp <<'EOF'
TEST(a, b) {
    EXPECT_LT(duration, 5);
    BOOST_CHECK(GetTime() - start < 10);
    BOOST_CHECK(
        std::chrono::steady_clock::now() - t0 < s);
    EXPECT_EQ(x, 1);
    BOOST_CHECK(GetTime() - start < 10); // real-clock: mocked
    BOOST_CHECK(GetTime() - n < 1); // real-clock: x
    BOOST_CHECK(GetTime() - n < 2);
    BOOST_CHECK_MESSAGE(nTime <= GetAdjustedTime(), "now " << GetTime());
    // EXPECT_LT(elapsed, 3);
    auto elapsed = now() - t0;
    SetMockTime(100);
}
EOF
track
run 0 'created (2 paths, 6)' wallclock --update-baseline
printf 'EXPECT_GT(elapsed, 1);\n' >> src/test/t.cpp; track
run 1 'src/test/t.cpp: 5, baseline 4 (rose)' wallclock
run 1 'NOT updated' wallclock --update-baseline

newrepo clockhollow
printf 'int x;\n' > main.c; track
run 2 'hollow scan' wallclock

echo "selftest-safety: $((n - fails))/$n checks passed"
[ "$fails" = 0 ]
