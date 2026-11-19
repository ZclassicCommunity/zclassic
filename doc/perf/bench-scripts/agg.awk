# Aggregates zclassicd -debug=bench lines from debug.log.
# Run: awk -v WINDOW=900 -f agg.awk debug.log
# Each bench line has the form "  - <stage>: <ms>ms [<s>s]" (Connect N transactions and
# Verify N txins carry a count, which is folded into the stage name).
# Prints one row per stage: stage, samples, mean_ms, total_ms, share_of_connect_block_pct.
# Also prints blocks connected, height range, and blocks per second over WINDOW.
BEGIN { FS = "\n" }
/UpdateTip: new best=/ {
    h = $0; sub(/.*height=/, "", h); sub(/[^0-9].*/, "", h); h = h + 0
    if (first_h == "" || h < first_h) first_h = h
    if (h > last_h) last_h = h
}
/- [A-Za-z]/ && /: [0-9.]+ms/ {
    line = $0
    i = index(line, "- ")
    rest = substr(line, i + 2)
    j = index(rest, ": ")
    if (j == 0) next
    name = substr(rest, 1, j - 1)
    gsub(/[0-9]+ /, "", name)
    val = substr(rest, j + 2)
    k = index(val, "ms")
    if (k == 0) next
    ms = substr(val, 1, k - 1) + 0
    cnt[name]++
    sum[name] += ms
    order[++n] = name
}
END {
    seen = ""
    for (r = 1; r <= n; r++) {
        s = order[r]
        if (index("|" seen "|", "|" s "|") > 0) continue
        seen = seen "|" s
        names[++m] = s
    }
    cb = sum["Connect block"]
    printf "stage\tsamples\tmean_ms\ttotal_ms\tpct_of_connect_block\n"
    for (q = 1; q <= m; q++) {
        s = names[q]
        pct = cb > 0 ? 100 * sum[s] / cb : 0
        printf "%s\t%d\t%.3f\t%.1f\t%.2f\n", s, cnt[s], sum[s] / cnt[s], sum[s], pct
    }
    blocks = cnt["Connect block"] + 0
    printf "blocks_connected\t%d\nheight_first\t%s\nheight_last\t%s\n", blocks, first_h, last_h
    if (WINDOW > 0) printf "blocks_per_second_over_window\t%.3f\n", blocks / WINDOW
    if (cb > 0) printf "blocks_per_second_connect_time_only\t%.3f\n", blocks / (cb / 1000.0)
}
