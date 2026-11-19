# zcutil/lint: zcl-lint ratchet gates

`zcl-lint` is one small C program (libc only, `-std=gnu17`) that holds the line on a few things without a
framework. Its rule logic is derived from three Z23 lint gates (see the header of `zcl-lint.c` and `NOTICE`).

```sh
make -C zcutil/lint            # builds zcutil/bin/zcl-lint
make -C zcutil/lint check      # selftest of every rule against throw-away fixture repositories
make -C zcutil/lint lint       # all rules on this tree (also: make -C src lint-fast)
zcutil/bin/zcl-lint <rule>|all [--update-baseline]
```

| rule | what it counts, per path | baseline |
|---|---|---|
| `no-new-jq` | lines that mention `jq` in shell scripts | `no-new-jq.txt` |
| `no-new-bash` | bash shebang plus bashism lines (`[[`, `<(`, arrays, `${v//x}`, `echo -e` ...) in shell scripts | `no-new-bash.txt` |
| `banned-str` | calls to `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets` in non-vendored C/C++ (comments and strings ignored; `lint-ok:` on the line exempts it) | `banned-str.txt` |
| `md-links` | relative links in tracked `*.md` that do not resolve to a tracked file, and same-file `#anchors` with no heading | `md-links.txt` |
| `vendor` | every `Z23_SOURCE.tsv` manifest must match its vendored tree (delegates to `check-vendor.sh`) | none: hard check |

A baseline row is `<path><TAB><count>`. The gate fails when a count rises or a path appears that is not listed.
When a count falls it passes and says so: run `zcl-lint <rule> --update-baseline` to lower the baseline
(it refuses while anything rose, and only creates a file that does not exist). Baselines can only shrink.

`no-python` runs `zcutil/check-no-python.sh` (skipped when absent) and `all` runs every rule in `rules.def` order.
Vendored and third-party trees (`src/c23/vendor`, `src/c23/services/vendor`, `zcutil/tools/vendor`,
`src/secp256k1`, `src/leveldb`, `src/univalue`, `depends`, `wallet/src/3rdparty`, `src/pow/tromp`) are out of
scope for the style rules.

## Source layout and adding a rule

`zcl-lint.c` is only the driver. Each rule is one file under `rules/` plus one `LINT_RULE(name, fn, has_baseline)` row in
`rules.def`; `lintlib.{c,h}` hold what rules share: tracked-file iteration (`git ls-files -z`), the single vendored-tree exclusion
list, C/C++ and sh comment and string stripping, baseline read/write and the ratchet, and the hollow-scan floor.
A rule that scans nothing fails: exit 2 and "hollow scan", never a pass. Exit codes: 0 clean, 1 findings, 2 usage, internal error
or hollow scan. `make -C zcutil/lint check` runs the fixture selftest and `lintlib_test.c`.

## Safety rules (secretlog, testiso, shellport, wallclock)

`secretlog` (custody) flags log and print calls in `src/` and `wallet/src/` whose arguments name a secret (`CKey`, `strWalletPass`, `seed`, `mnemonic`, `HexStr(key`, ...); override a line with `log-ok: reason` in a comment. The baseline is expected to be empty, and every row is a finding to review, not to hide.
`testiso` reads `qa/`, `src/test` and `src/gtest` for literal `/tmp/`, default datadirs without `-datadir=`, and fixed `-port=`/`-rpcport=` in `qa/rpc-tests/*.sh` (`iso-ok: reason` in a comment: `//`, `/* */` or `#`).
`shellport` flags `sed -i`, `stat -c`, `nproc`, `ss`, `readlink -f`, `date -d`, `grep -P`, `timeout` and `| grep -q` under `set -o pipefail` (`# port-ok: reason`). `wallclock` flags assertions decided by elapsed real time (`real-clock: reason`).
`testiso`, `shellport` and `wallclock` baselines use rows `<path>:<kind><TAB><count>` where a path has several kinds. `selftest-safety.sh` holds their fixtures.
