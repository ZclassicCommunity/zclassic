#!/bin/sh
# Copyright (c) 2026 The Zclassic developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Run phgr13_diff over N shards in parallel and sum the class tables:
#   run_shards.sh <binary> <N> <outdir> <vk> <g1.json> <g2.json> <blocks|-> [mutated]
set -eu
bin=$1; n=$2; out=$3; shift 3
mkdir -p "$out"
k=0
pids=""
while [ "$k" -lt "$n" ]; do
    PHGR13_SHARD="$k/$n" OMP_NUM_THREADS=1 stdbuf -oL "$bin" all "$@" > "$out/shard.$k.log" 2>&1 &
    pids="$pids $!"
    k=$((k + 1))
done
status=0
for p in $pids; do wait "$p" || status=1; done
cat "$out"/shard.*.log | grep -E '^(CANDIDATE|Z23RAW)-DISAGREE' > "$out/disagreements.txt" || true
cat "$out"/shard.*.log | awk '
    /^class / { t = 1; next }
    /^TOTAL/ { t = 0 }
    t && NF == 5 { c[$1] += $2; a[$1] += $3; d[$1] += $4; z[$1] += $5 }
    END {
        printf "%-34s %9s %9s %9s %9s\n", "class", "cases", "ref-acc", "cand-dis", "z23raw-dis"
        for (k in c) { printf "%-34s %9d %9d %9d %9d\n", k, c[k], a[k], d[k], z[k]; C += c[k]; D += d[k]; Z += z[k] }
        printf "TOTAL cases=%d candidate-disagreements=%d z23raw-disagreements=%d\n", C, D, Z
    }' | sort > "$out/summary.txt"
grep -h '^scan:\|^vk:\|^point' "$out/shard.0.log" >> "$out/summary.txt" || true
echo "shard-exit-status=$status" >> "$out/summary.txt"
cat "$out/summary.txt"
