# zcutil/tools: developer tools built from vendored Z23 code

`jsonq` is a small JSON path query tool (no jq, no Python, libc only). Its sources under `vendor/` are
copied byte for byte from the Z23 repository at the commit recorded in `Z23_SOURCE.tsv`
(`jsonq.c`, `jsonq_standalone.c`, `multicall.h`, the `zjsonp` pull parser and the `zutf8` validator).
The licence is Apache-2.0 (`LICENSE.z23`, `NOTICE`); never edit anything under `vendor/`.

```sh
make -C zcutil/tools          # builds zcutil/bin/jsonq (host cc, -std=gnu17)
make -C zcutil/tools check    # fixture test (test-jsonq.sh)
make -C zcutil/tools CC=x86_64-w64-mingw32-gcc EXEEXT=.exe    # Windows cross build
sh src/c23/tools/check-vendor.sh zcutil/tools/Z23_SOURCE.tsv  # source identity (make -C src check-tools-vendor)
```

```sh
printf '%s' "$json" | zcutil/bin/jsonq get result.items[1].id    # value; exit 1 if missing, 2 if malformed
printf '%s' "$json" | zcutil/bin/jsonq count result              # elements or keys
```

The shell tests use it through `qa/rpc-tests/jsonq_lib.sh` (`jget`, `jgetd`, `jlen`, `jraw`, `jhas`), which builds
it on first use. Filters that need select, sort_by, arithmetic or string interpolation still use jq.

To move to a newer Z23 commit: copy the seven files from the new commit, update the rows of `Z23_SOURCE.tsv`
(path, Z23 path, git blob sha1, commit, `unsealed`) and the `# z23_commit=` header, then run the checker.
