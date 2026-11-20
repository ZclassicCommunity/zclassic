#!/bin/sh
# Test for contrib/zmq/zmq_sub.c: compiles it (warnings are errors), publishes one message per
# topic from a throwaway libzmq publisher on a loopback port, and checks what it prints.
# usage: test-zmq-sub.sh <libzmq prefix: has include/zmq.h and lib/libzmq.a> [port]
# Exit 77 (skip) when the prefix has no libzmq. The depends prefix qualifies, for example
# depends/x86_64-unknown-linux-gnu.
set -u
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prefix=${1:-}
port=${2:-28990}
cc=${CC:-cc}
[ -f "$prefix/include/zmq.h" ] || { echo "SKIP no libzmq under '$prefix'"; exit 77; }
work=$(mktemp -d)
pid=""
trap '[ -z "$pid" ] || kill "$pid" 2>/dev/null; rm -rf "$work"' EXIT HUP INT TERM

link() { # <source> <out>
    if [ -f "$prefix/lib/libzmq.a" ]; then
        # libzmq.a needs the C++ runtime and the sodium/pthread libraries it was built with
        $cc -std=c2x -O2 -Wall -Wextra -Werror -I"$prefix/include" "$1" -o "$2" \
            "$prefix/lib/libzmq.a" -lstdc++ -lpthread -lrt -lm 2>&1
    else
        $cc -std=c2x -O2 -Wall -Wextra -Werror -I"$prefix/include" "$1" -L"$prefix/lib" -lzmq -o "$2" 2>&1
    fi
}

cat > "$work/pub.c" <<'EOF'
#define _POSIX_C_SOURCE 200809L
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <zmq.h>
static void send3(void *s, const char *topic, const void *body, size_t n, unsigned seq)
{
    unsigned char sq[4] = {seq & 255, (seq >> 8) & 255, (seq >> 16) & 255, (seq >> 24) & 255};
    zmq_send(s, topic, strlen(topic), ZMQ_SNDMORE);
    zmq_send(s, body, n, ZMQ_SNDMORE);
    zmq_send(s, sq, 4, 0);
}
int main(int argc, char **argv)
{
    void *c = zmq_ctx_new(), *s = zmq_socket(c, ZMQ_PUB);
    if (argc < 2 || zmq_bind(s, argv[1]) != 0) return 1;
    unsigned char hash[32], raw[100];
    for (int i = 0; i < 32; i++) hash[i] = (unsigned char)i;
    for (int i = 0; i < 100; i++) raw[i] = (unsigned char)(0xa0 + i % 16);
    for (int round = 0; round < 40; round++) {       // a SUB joins late: repeat until it is killed
        send3(s, "hashblock", hash, 32, 258);
        send3(s, "hashtx", hash, 32, 3);
        send3(s, "rawblock", raw, 100, 4);
        send3(s, "rawtx", raw, 100, 70000);
        nanosleep(&(struct timespec){0, 100000000}, NULL);
    }
    return 0;
}
EOF

link "$here/zmq_sub.c" "$work/zmq_sub" || { echo "FAIL zmq_sub.c does not build"; exit 1; }
link "$work/pub.c" "$work/pub" || { echo "FAIL publisher does not build"; exit 1; }
echo "PASS zmq_sub.c builds without warnings"

"$work/pub" "tcp://127.0.0.1:$port" &
pid=$!
sleep 0.5
if command -v timeout >/dev/null 2>&1; then
    timeout 3 "$work/zmq_sub" "tcp://127.0.0.1:$port" > "$work/out" 2>"$work/err"
else
    "$work/zmq_sub" "tcp://127.0.0.1:$port" > "$work/out" 2>"$work/err" &
    sp=$!; sleep 3; kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null
fi

h=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
r80=$(i=0; while [ $i -lt 80 ]; do printf '%02x' $((0xa0 + i % 16)); i=$((i + 1)); done)
r100=$(i=0; while [ $i -lt 100 ]; do printf '%02x' $((0xa0 + i % 16)); i=$((i + 1)); done)
fails=0
want() { # <heading line> <hex line>
    if grep -q -x -F -- "$1" "$work/out" && grep -q -x -F -- "$2" "$work/out"; then echo "PASS $1"
    else echo "FAIL missing: $1 / $2" >&2; fails=$((fails + 1)); fi
}
want "- HASH BLOCK (258) -" "$h"
want "- HASH TX  (3) -" "$h"
want "- RAW BLOCK HEADER (4) -" "$r80"
want "- RAW TX (70000) -" "$r100"
[ "$fails" -eq 0 ] && { echo "zmq_sub: all tests passed"; exit 0; }
cat "$work/err" >&2
exit 1
