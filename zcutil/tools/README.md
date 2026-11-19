# zcutil/tools: developer tools built from vendored Z23 code

Everything under `vendor/` is copied byte for byte from the Z23 repository at the commit recorded in
`Z23_SOURCE.tsv` (one manifest for all of it; `vendor-files.txt` lists the paths, `revendor.sh <z23-repo>
<commit>` rewrites the tree and the manifest). The licence is Apache-2.0 (`LICENSE.z23`, `NOTICE`); never
edit anything under `vendor/`. Verify with `make -C src check-tools-vendor`
(`sh src/c23/tools/check-vendor.sh zcutil/tools/Z23_SOURCE.tsv`).

| tool | built from | used by |
|---|---|---|
| `zcutil/bin/jsonq` | `vendor/tools/jsonq*.c`, `zjsonp`, `zutf8` (`make -C zcutil/tools`) | the shell tests, through `qa/rpc-tests/jsonq_lib.sh` |
| `zcutil/bin/zcl-run` | `vendor/tools/process_group_exec.c`, `-include stdbool.h` (built on first use by `qa/lib/isolation.sh`) | test scripts: daemons in their own process group |
| glob matcher | `vendor/platform/.../glob_match.h` | `zcutil/dev/zcl-dev` (impact rules) |

```sh
make -C zcutil/tools          # builds zcutil/bin/jsonq (host cc, -std=gnu17)
make -C zcutil/tools check    # fixture test (test-jsonq.sh)
make -C zcutil/tools CC=x86_64-w64-mingw32-gcc EXEEXT=.exe    # Windows cross build
```

```sh
printf '%s' "$json" | zcutil/bin/jsonq get result.items[1].id    # value; exit 1 if missing, 2 if malformed
printf '%s' "$json" | zcutil/bin/jsonq count result              # elements or keys
```

`jsonq_lib.sh` offers `jget`, `jgetd`, `jlen`, `jraw`, `jhas` and builds jsonq on first use. Filters that need
select, sort_by, arithmetic or string interpolation still use jq.

To move to a newer Z23 commit run `revendor.sh`, then the checker.
