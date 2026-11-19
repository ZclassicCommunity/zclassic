# zcl-dev flaky

Repeat one command N times, each run in its own directory, and say whether it is stable. One C file, libc and POSIX only, built with `-std=gnu17` (also compiles as `-std=c2x`).

```sh
zcutil/bin/zcl-dev flaky -n N [--jobs J<=4] [--timeout SECS] [--keep] [--json] -- <argv...>
zcutil/bin/zcl-dev flaky -n 20 -- sh qa/rpc-tests/backupwallet_atomic.sh --bin build/src --work @WORK@
```

- `-n N` runs `argv` N times (1 to 1000). `--jobs J` runs up to J at once (1 to 4, default 1). `--timeout SECS` (default 900) kills a run that takes longer and counts it as a failure.
- Run k gets a fresh directory `zcutil/gen/flaky/<UTC stamp>-<pid>/run-<k>/` (the root is `ZCL_FLAKY_OUT` when set; `zcutil/gen/` is git-ignored). The child gets `TMPDIR=<that directory>` and `ZCL_FLAKY_RUN=<k>` added to its environment, and runs with stdin closed. In `argv` the token `@WORK@` is replaced by the run directory and `@RUN@` by k; give qa scripts that take `--work` the value `--work @WORK@`.
- Stdout and stderr of a run go to `run-<k>/log`. Every run is its own process group, killed on timeout and again when the run ends, so nothing a run leaves behind outlives it. A run whose log passes 256 MiB is killed and counted as a failure (the check runs every 20 ms; `ZCL_FLAKY_LOG_CAP=<bytes>` lowers the cap for tests).
- Because each run has its own process group, a terminal Ctrl-C never reaches it. The runner therefore catches SIGINT, SIGTERM and SIGHUP itself: it kills every running group, reaps them, prints `INTERRUPTED: signal N; killed K running group(s); partial logs kept under <dir>` and exits 2. Only SIGKILL of the runner itself (which cannot be caught) can leave runs behind; the per-run `--timeout` dies with the runner then.
- Verdict: `PASS` (all runs passed), `FLAKY` (some failed), `FAILING` (all failed), `BROKEN` (the command could not start, for example a missing binary). The report gives counts, min/median/max seconds, the exit codes seen (`timeout` for a killed run), the first failing log and the run directory.
- A passing run's directory is deleted unless `--keep` is given; failing runs always stay. When every run passed and `--keep` is absent, the report says `run directory: removed ...` (JSON: `"dir":null`) instead of naming a path that no longer exists. `--json` prints the same report as one JSON object.
- Exit: 0 PASS, 1 FLAKY or FAILING, 2 BROKEN, INTERRUPTED or bad arguments.

## Ports

This tool never chooses a port and never derives one from a PID. qa scripts lease their own ports through `qa/lib/isolation.sh` ([qa/lib/README.md](../../../qa/lib/README.md)), which is why `--jobs` greater than 1 is safe for them. A command that binds fixed ports will collide under `--jobs`; run it with `--jobs 1`.

## Limits

- POSIX only (process groups, `fork`). On Windows it prints `UNAVAILABLE` and exits 2; the mingw build exists so `zcl-dev help` lists it everywhere.
- The timeout is wall-clock seconds on the host as loaded; a loaded host can turn a slow pass into a timeout failure. Read the log before blaming the test.
- A verdict from N runs is evidence, not proof: PASS after 3 runs does not make a 1-in-50 flake go away.

`make -C zcutil/dev/flaky check` runs `--selftest` (argument parsing, substitution, median, verdict) and `test/flaky_test.c` (a C driver, because the shell-lines ratchet leaves no room for a test script; always-pass, always-fail, fails on runs 2 and 5, missing binary, timeout kill, `@WORK@`, `--jobs 3`, log cap, and SIGINT/SIGTERM/SIGHUP leaving no child alive).
