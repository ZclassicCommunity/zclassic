# zcutil agent rules

Imports the root contract: [../AGENTS.md](../AGENTS.md). Local CI: [doc/local-ci.md](../doc/local-ci.md). Developer tools: [dev/](dev/), [lint/README.md](lint/README.md), [tools/README.md](tools/README.md).

- Build and release scripts (`build.sh`, `build-release.sh`, `local-ci.sh`) produce the shipped binaries. `HOST` is an environment variable, never an argument; release candidates build in the focal root filesystem (GCC 9, glibc 2.31), never on the host toolchain.
- CI is own-machine only: `local-ci.sh` and `local-ci-macos.sh`. Never add or dispatch GitHub Actions; `check-no-python.sh` fails when hosted-CI files or Python come back.
- No Python and no new bash. Glue is POSIX `sh` or C (`zcl-lint no-new-bash` counts bashisms and may only shrink); an existing bash script is not a reason to write another.
- A step added to `local-ci.sh` needs a row in `dev/impact.rules`, and a new gate script under `qa/` needs both; `zcl-dev check-rules` fails otherwise.
- `tools/vendor/` is verbatim Z23: change it only with `tools/revendor.sh`, then `sh src/c23/tools/check-vendor.sh zcutil/tools/Z23_SOURCE.tsv`. Developer tools are C with libc only, built `-std=gnu17`, and must not use C23-only syntax.
- Built tools land in `zcutil/bin/` and generated documents in `zcutil/gen/`; both are ignored, never commit them.
- A ratchet baseline (`lint/*.txt`) only shrinks; never edit one upward and never hide a finding to pass.

Tests: `make -C zcutil && make -C zcutil check` (every tool selftest), `zcutil/bin/zcl-lint all`, `zcutil/bin/zcl-dev check-rules`, `zcutil/bin/zcl-dev check-docs`, then `zcutil/local-ci.sh --commit <sha> --only check-dev-tools,zcl-lint,check-no-python test <outdir>`.
