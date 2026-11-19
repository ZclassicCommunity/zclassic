# zcl-dev timings

Which local-ci steps dominate, which got slower, and how much of the picture is missing. One C file, libc only, `-std=gnu17`.

```sh
zcutil/bin/zcl-dev timings [--json] [--step NAME] <outdir>...
zcutil/bin/zcl-dev timings ~/work/zc23-localci-out/*/        # read-only; never writes into the directories
```

## Input

Each `<outdir>` is a `zcutil/local-ci.sh` output directory ([doc/local-ci.md](../../../doc/local-ci.md)):

- `results.tsv`: `<step> TAB <PASS|FAIL|SKIP> TAB <seconds>`. local-ci writes it to `<outdir>/test/results.tsv` (debug flavor) and `<outdir>/test-release/results.tsv` (release flavor); `<outdir>/results.tsv` is read too. Every one that exists is read.
- `receipts.jsonl`: one flat JSON object per line, in finishing order; only `step`, `verdict` and `seconds` are used (a strict flat-field scan: a line that is not one flat `{...}` object (no nested object, keys read only outside strings) with those three fields is corrupt).

## Output

A header `read R of D outdirs`, then one row per step sorted by median seconds, slowest first: timed runs, pass rate, skipped runs, min, median and max seconds. When more than one outdir has the step, the last outdir's time is compared with the median of the earlier ones and `SLOWER` is printed when it is at least 1.5 times and 5 seconds longer. Outdirs are taken in argument order as oldest first; the tool does not sort them by date.

## Never zero

A missing or corrupt file is printed as `unavailable: <path>: <reason>` and never counted as 0 seconds or as a pass. A file with one bad line is dropped whole, not half-counted. Statistics come from `results.tsv`; when it is unusable but `receipts.jsonl` is readable, from the receipts. An outdir with neither is not "read".

When both files of an outdir are readable and the last verdict of a step differs between them, the tool prints `MISMATCH <outdir>: step <name> results.tsv=<V> receipts.jsonl=<V>`. Receipts also cover stages and build steps that `results.tsv` lacks; only steps in both are compared.

Exit codes: 0 data read, 1 a MISMATCH, 2 nothing readable (hollow) or bad arguments.

## Coverage limits

- Seconds are wall-clock under whatever load the host had; the same step can swing several times between runs on a busy host. A median over few outdirs is a hint, not a benchmark.
- PASS and FAIL runs both feed the seconds (a step that fails early looks fast); SKIP rows have no time.
- Only what local-ci recorded is here: no per-test timings inside a step, no log parsing.
- `--json` prints the same data as one object (`outdirs_total`, `outdirs_read`, `unavailable`, `mismatch`, `steps`).

`make -C zcutil/dev/timings check` runs `--selftest` and compares golden outputs over `test/fixture` (three good outdirs, one without receipts, one corrupt line, a MISMATCH, all unreadable). The driver is `test/timings_test.c` (C, for the same shell-lines reason as flaky); `UPDATE=1 zcutil/bin/timings_test zcutil/bin/zcl-dev-timings zcutil/dev/timings/test` rewrites the goldens.

## Empty files and flavors

- A `results.tsv` with no step rows (local-ci creates it empty before the build stage, so an early failure leaves exactly that) is listed as `unavailable: <path>: empty (no step rows)`, not read as a zero-step success; the outdir then falls back to `receipts.jsonl`, or counts as unreadable when there is none.
- Debug (`test/`) and release (`test-release/`) rows are kept apart. Receipts carry the flavor in their stage (`test-run/<flavor>` and `test-build/<flavor>`). A step that has rows for both flavors is printed once per flavor as `name [debug]` and `name [release]` (JSON adds a `flavor` field), SLOWER compares only within a flavor, and MISMATCH compares a `results.tsv` row only with receipts of the same flavor. A root `results.tsv` or a receipt with another stage has no flavor: it matches any flavor, and joins the first row of its step (so with both flavors present its row is attributed to whichever came first).
