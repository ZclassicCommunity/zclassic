# contrib agent rules

Imports the root contract: [../AGENTS.md](../AGENTS.md). Contents: `devtools/` (maintainer scripts), `seeds/` (fixed-seed generator), `zmq/` (subscriber example), `init/` (service files), `examples/zclassic.conf`.

- Helpers here are POSIX `sh` or C with libc only; no Python, no new bash, no network fetches at build time.
- `seeds/generate-seeds.c` turns `nodes_main.txt` and `nodes_test.txt` into `src/chainparamsseeds.h`, which is a consensus-adjacent input (peer bootstrap, not validation). A regenerated header is reviewed line by line and the CI step `seed-generator` must pass.
- `devtools/check-oversize-grandfather.sh` proves the oversize table byte-for-byte; keep it passing and never update its expected blob ids to match an edit ([../src/consensus/AGENTS.md](../src/consensus/AGENTS.md)).
- Service files in `init/` and the sample config use placeholders; never add a real credential, peer or path.
- `contrib/` is outside the impact rules (only `wallet/contrib/` has one); a script CI should run is wired into a `local-ci.sh` step.

Tests: `sh contrib/seeds/test-generate-seeds.sh <repo-root>`, `sh contrib/zmq/test-zmq-sub.sh <depends-prefix> <port>`, `sh contrib/devtools/check-oversize-grandfather.sh`, then `zcutil/local-ci.sh --commit <sha> --only seed-generator,zmq-sub-example test <outdir>`.
