# src/c23/tor: embedded Tor for zclassicd

A small C library that runs the Tor built into the daemon binary, on a thread
of the daemon (`in_process`) or as a child process, and reports its loopback
Socks port, control port and cookie path. Behind a configure switch and a
runtime flag, both default off; nothing in this directory changes consensus or
clearnet behaviour.

| File | Role |
|---|---|
| `zcl_tor_embed.h`, `zcl_tor_embed.c` | public API: start, wait for bootstrap, stop, control client, torrc |
| `zcl_tor_inproc.h`, `zcl_tor_inproc.c` | in-process mode: `tor_run_main` on a thread, owner channel, join |
| `zcl_tor_dispatch.c` | the Tor child entry point (`tor_run_main`) for child mode |
| `zcl_tor_proc.h`, `zcl_tor_proc_posix.c`, `zcl_tor_proc_win.c` | child process layer: `posix_spawn` and socketpair; `CreateProcessW` and a kill-on-close job object |
| `keyfile.h`, `keyfile.c` | owner-only secret files: atomic write, tighten, read, private directory. Always built into `zclassicd` (onion key file) |
| `zcl_tor_selftest.c`, `build_selftest.sh` | proof program (Linux) |
| `zcl_tor_selftest_win.c`, `build_selftest_win.sh`, `zcl_tor_win.rc`, `zcl_tor_win.manifest` | proof program (Windows, mingw-w64 cross-build; child mode) |
| `twonode.sh`, `privacy_check.sh` | two `zclassicd` regtest nodes over an onion service; strace check that only Tor reaches the network |
| `threenode.sh`, `addrv2gossip.sh`, `oldpeer.sh` | three nodes dialling each other by onion; onion address gossip (C learns B from A, clearnet peers never get our onion, beta 12 loads the peers.dat); an old peer next to the new node |
| `WIRING.md` | how `zclassicd` uses the library: options, startup, shutdown, in-process or child |

Only `zcl_tor_dispatch.c` and `zcl_tor_inproc.c` include `tor_api.h`.

## Attribution

The design follows the Z23 node's embedded Tor, (c) 2026 Rhett Creighton,
Apache License 2.0 (Z23 `core/modules/net/src/tor_config_log.c` (Z23 tree), <!-- doc-path-ok -->
`tor_integration.c`):

- The torrc body (loopback `SocksPort`, `DataDirectory`, notice log to a file,
  `Schedulers KISTLite,Vanilla`, optional `DisableNetwork 1`) is Z23's, with
  the changes listed in `zcl_tor_embed.c` (auto ports, cookie authentication,
  `ControlPortWriteToFile`, `ClientOnly`).
- The "Tor exits when its owner goes away" policy and the stock embedding API
  calls (`tor_main_configuration_new`, `set_command_line`, `tor_run_main`,
  `__OwningControllerFD`) are Z23's approach.

No Z23 source file was copied; the code here is new and is MIT-licensed like
zclassicd. Tor itself is linked from the depends package (see
`doc/tor-provenance.md`: same pinned fork revision as Z23, BSD-3-Clause Tor
code, no GPL option so Equi-X is not built).

## Process model

Two modes, chosen per start with `zcl_tor_embed_opts.in_process`
(`-embeddedtormode=inprocess|child` in the daemon; `child` is the Linux default and `inprocess` the default elsewhere).

**In-process.** `tor_run_main` runs on a thread of the daemon, as in Z23. Tor
is told `__DisableSignalHandlers 1` and `--quiet`, and logs to
`<datadir>/tor/tor.log`. It is stopped with control `SIGNAL HALT` and, on
POSIX, by closing an owner socketpair (`__OwningControllerFD`); the thread is
then joined. One in-process Tor per process: a second start is refused before
any file is touched. What Tor does to process-wide state (libevent allocator
and log hooks, OpenSSL init) is listed at the top of `zcl_tor_inproc.c` and in
`WIRING.md`. Tor itself leaves one eventfd open and 0.5 to 1.4 kB allocated
per run (LeakSanitizer; nothing is reported without Tor or in child mode).

**Child.** The daemon re-executes its own binary with `--zcl-embedded-tor`. Tor therefore
shares no heap, OpenSSL or libevent state with the daemon, and a Tor crash
cannot take the node down. The parent keeps a socketpair end; Tor is given the
other end as `__OwningControllerFD`, so when the parent dies for any reason
(including `kill -9`) the kernel closes the pair and Tor exits. On Windows a
job object with kill-on-close does the same, plus `__OwningControllerProcess`.

## Security notes

- No shell is invoked. No secret is in argv: argv holds paths, a descriptor
  number and the parent pid. The control cookie is read from its 0600 file
  and never logged; buffers holding it are wiped.
- `SocksPort` and `ControlPort` are `127.0.0.1:auto`. The library refuses a
  control-port file that is not loopback. No DNSPort, no ORPort, no exit role.
- `<datadir>/tor` is 0700, torrc 0600, cookie 0600 (Tor creates it with
  `CookieAuthFileGroupReadable 0`).
- Datadir paths with control characters are refused (no torrc injection); other
  special characters are quoted and escaped.
- The child closes all inherited descriptors except the owner channel before
  Tor starts, so descriptors the daemon leaked at `exec` do not reach Tor.
- The child is in its own process group, so a terminal Ctrl-C reaches the
  daemon only; the daemon stops Tor in an orderly way.

## Build and test

    make -C depends HOST=x86_64-pc-linux-gnu WITH_EMBEDDED_TOR=1 -j8 tor
    devbuild --wait sh src/c23/tor/build_selftest.sh          # -Wall -Wextra -Werror -O2
    SAN=1 OUT=zcl_tor_selftest_asan devbuild --wait sh src/c23/tor/build_selftest.sh
    devbuild --wait src/c23/tor/zcl_tor_selftest all          # offline + kill -9 parent + in-process
    devbuild --wait src/c23/tor/zcl_tor_selftest online       # real Tor network, isolated datadir

The daemon (see `WIRING.md`):

    ./configure --with-embedded-tor ...                       # after the depends line above
    src/test/test_bitcoin --run_test=embeddedtor_tests,torcontrol_tests
    sh src/c23/tor/twonode.sh src inprocess strace            # two regtest nodes, real Tor network
    sh src/c23/tor/twonode.sh src child strace

The self-test uses a fresh temporary directory (`$TMPDIR`) and removes it on
success; on failure it keeps it and prints the path.
