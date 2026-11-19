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

`all` also runs `zcutil/check-no-python.sh` when that script exists (the no-python gate lives elsewhere).
Vendored and third-party trees (`src/c23/vendor`, `src/c23/services/vendor`, `zcutil/tools/vendor`,
`src/secp256k1`, `src/leveldb`, `src/univalue`, `depends`, `wallet/src/3rdparty`, `src/pow/tromp`) are out of
scope for the style rules.
