#!/bin/sh
# Fixture test for the vendored jsonq. usage: test-jsonq.sh [path/to/jsonq]
q=${1:-$(dirname "$0")/../bin/jsonq}
[ -x "$q" ] || { echo "test-jsonq: $q not built (make -C zcutil/tools)" >&2; exit 2; }
fails=0; n=0
# t "<json>" <want-rc> "<want-stdout>" jsonq-args...
t() {
    json=$1; wrc=$2; wout=$3; shift 3
    n=$((n + 1))
    out=$(printf "%s" "$json" | "$q" "$@" 2>/dev/null); rc=$?
    if { [ "$wrc" = nz ] && [ "$rc" = 0 ]; } || { [ "$wrc" != nz ] && [ "$rc" != "$wrc" ]; } || { [ "$wrc" = 0 ] && [ "$out" != "$wout" ]; }; then
        echo "FAIL #$n: jsonq $* on $json: rc=$rc out=[$out], want rc=$wrc out=[$wout]" >&2
        fails=$((fails + 1))
    fi
}
DOC="{\"a\":{\"b\":[1,{\"c\":\"x\u00e9y\"},true,null]},\"n\":12345678901234567890,\"f\":1.5e3,\"s\":\"hi\",\"e\":[],\"o\":{}}"
# objects, arrays, nested paths
t "$DOC" 0 "hi" get s
t "$DOC" 0 "hi" get .s
t "$DOC" 0 "true" get a.b[2]
t "$DOC" 0 "null" get a.b[3]
t "$DOC" 0 "[]" get e
t "$DOC" 0 "4" count a.b
t "$DOC" 0 "0" count o
t "$DOC" 1 "" count s
t "$DOC" 0 "object" type a
t "$DOC" 0 "number" type n
t "$DOC" 0 "b" keys a
t "$DOC" 0 "" has a.b[3]
t "$DOC" 1 "" has zz
t "$DOC" 1 "" get zz
t "$DOC" 1 "" get a.b[9]
t "$DOC" 0 "" eq s hi
t "$DOC" 1 "" eq s no
t "[{\"x\":1},{\"x\":2}]" 0 "2" get "[1].x"
t "[{\"x\":1},{\"x\":2}]" 0 "2" count .
# unicode escapes and surrogate pairs
t "$DOC" 0 "xéy" get a.b[1].c
t "{\"a\":\"\ud83d\ude00\"}" 0 "😀" get a
t "{\"a\":\"\ud83d\"}" nz "" get a
# large numbers and exponents are printed verbatim, not rounded
t "$DOC" 0 "12345678901234567890" get n
t "$DOC" 0 "1.5e3" get f
# json-rpc envelope
t "{\"result\":{\"x\":1},\"error\":null}" 0 "{\"x\":1}" unwrap
t "{\"result\":1,\"error\":{\"code\":1}}" 2 "" unwrap
# malformed input must fail non-zero
t "{bad" 2 "" get a
t "" 2 "" get a
t "{\"a\":1} x" 2 "" get a
t "{\"a\":" 2 "" get a
t "[1,2" 2 "" count .
t "{\"a\":\"unterminated}" 2 "" get a
t "{\"a\":01}" 2 "" get a
t "{\"a\":\"\x\"}" 2 "" get a
# usage errors
t "{}" 2 "" frobnicate a
echo "test-jsonq: $((n - fails))/$n passed"
[ "$fails" = 0 ]
