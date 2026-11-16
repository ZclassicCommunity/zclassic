#!/bin/sh
# TEST-ONLY: every case of `compat_smoke <dir> --abort-case N` must end the
# process abnormally (abort(): exit status 3 on Windows UCRT, SIGABRT 134
# elsewhere) after printing the expected "librustzcash (C23):" or
# "zc23_sprout_prove:" message, as librustzcash panics (panic = 'abort').
# usage: run-abort-cases.sh <compat_smoke binary> <params-dir>
set -u
bin=$1; dir=$2; fail=0
for n in 1 2 3 4 5 6 7 8 9 10; do
    msg=$("$bin" "$dir" --abort-case "$n" 2>&1 >/dev/null)
    rc=$?
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 99 ]; then
        echo "FAIL abort-case $n: exit $rc (no abort)"; fail=1
    elif ! printf '%s' "$msg" | grep -q 'librustzcash (C23):\|zc23_sprout_prove:'; then
        echo "FAIL abort-case $n: exit $rc without the panic message: $msg"; fail=1
    else
        echo "PASS abort-case $n: exit $rc: $(printf '%s' "$msg" | grep -m1 'librustzcash (C23):\|zc23_sprout_prove:')"
    fi
done
exit "$fail"
