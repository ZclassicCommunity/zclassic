# qa/lib: test isolation

Test scripts must not collide on ports and must not leave daemons behind, on Linux,
macOS and Windows (Git Bash). One line at the top of a script does both:

    . "$(dirname "$0")/../lib/isolation.sh"

* `iso_base VAR "$explicit" N` sets `VAR` to the explicit base (`--base`, env) when one
  was given, else to the first port of a leased block of N consecutive free ports.
  `iso_rebase VAR N STEP` moves to a fresh block between scenarios.
* Leases come from `zcutil/dev/zcl-port.c` (built on first use into `zcutil/bin/`, which
  is git-ignored): bind-tested on 127.0.0.1 and 0.0.0.0, one `O_EXCL` file per port,
  range 20000-32000 (below every OS ephemeral range, above the node ports), owner pid
  recorded, stale owners reclaimed. No cleanup trap is needed for ports.
  `zcutil/dev/zcl-port-stress.sh` is the stress test (16 workers x 50 rounds x 8 ports).
* Start daemons as `$ZCL_RUN zclassicd ... &` (or `start_node LOG cmd...`): `zcl-run` is
  Z23's `process_group_exec.c` (vendored verbatim, `zcutil/tools/`): `setsid` on POSIX, a
  kill-on-close Job Object on Windows. `kill_node PID` kills the node and its group on
  every platform; on Windows `isolation.sh` also routes `kill -9` through `taskkill /T`.
* A detached reaper (`iso-reaper.sh`, its own session) waits for the script to end by
  any means, including `kill -9`, then kills everything tagged `ZCL_ISO_TAG=<this run>`
  (read from `/proc/*/environ`, or `ps -E` on macOS), which includes `-daemon` children,
  and releases the leases. `ZCL_ISO_NOREAP=1` turns it off.

`ZCL_ISO_BIN=<dir>` overrides the tool directory; `CC` the compiler. The tools are plain
gnu17 C; `zcl-run` needs `-include stdbool.h` (the vendored file is not edited).
