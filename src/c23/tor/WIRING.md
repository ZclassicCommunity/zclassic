# How zcl_tor_embed is wired into zclassicd

Build: depends builds Tor by default (`make -C depends NO_EMBEDDED_TOR=1` skips it);
`./configure` links it by default when present (`--with-embedded-tor=yes` fails when
missing, `--without-embedded-tor` skips it). Run: `-embeddedtor=1` (default off),
`-embeddedtormode=inprocess|child` (default `child` on Linux, `inprocess` elsewhere). Without the configure
switch nothing Tor-related is compiled or linked except `keyfile.c`, and
`-embeddedtor=1` is refused at startup.

## Files

| Where | What |
|---|---|
| `configure.ac` | `--with-embedded-tor`, `TOR_LIBS`, `ENABLE_EMBEDDED_TOR` |
| `src/Makefile.am` | `libzcl_tor.a` (not the vendored core `libzcl_c23.a`): always `keyfile.c`; with embedded Tor also `zcl_tor_embed.c`, `zcl_tor_dispatch.c`, `zcl_tor_inproc.c`, `zcl_tor_proc_{posix,win}.c`. `ZCL_TOR_LIBS` follows `libbitcoin_server.a` in `zclassicd`, `test_bitcoin` and `zcash-gtest` |
| `src/embeddedtor.{h,cpp}` | C++ wrapper: `StartEmbeddedTor`, `StopEmbeddedTor`, ports, mode parsing; stubs when not built in |
| `src/bitcoind.cpp` | `EmbeddedTorDispatch` first thing in `main()` (the child-mode Tor process) |
| `src/init.cpp` | option checks (Step 3), start and proxy setup (Step 6), stop in `Shutdown()` |
| `src/torcontrol.cpp` | control target, SOCKS proxy discovery, owner-only onion key file |
| `src/httpserver.{h,cpp}` | `RestoreLibeventLogging()` |

## Startup (`init.cpp`)

1. Step 3: `-embeddedtor=1` in a build without it, a bad `-embeddedtormode`, or
   `-onion=0` together with `-embeddedtor` stops startup with an error. A node
   that asked for Tor never continues without it.
2. Step 6, after `-proxy` and `-onion` are processed and while the datadir
   lock is held: `StartEmbeddedTor(GetDataDir())`. Tor's state is in
   `<datadir>/tor` (0700), its SOCKS and control listeners are
   `127.0.0.1:auto`, and the control port uses cookie authentication with a
   0600 cookie. A start failure is an `InitError`.
3. `-onion` not given: the onion proxy becomes the embedded SOCKS port and
   onion becomes reachable. An explicit `-onion=<ip:port>` is left alone.
4. Onion-only node (`-onlynet` leaves IPv4 and IPv6 limited) without `-proxy`:
   the name proxy also becomes the embedded SOCKS port. From then on host
   names (DNS seeds, `-addnode`, `-seednode`, `-connect`) are passed to Tor as
   names; `ThreadDNSAddressSeed` adds the seeds as one-shot peers through the
   proxy instead of calling the resolver.
5. `StartTorControl` (unchanged trigger: `-listenonion`, default on) connects
   to the embedded control port unless `-torcontrol` was given, authenticates
   with SAFECOOKIE, and creates or re-creates the v3 onion service for the P2P
   port from `<datadir>/onion_v3_private_key`. The address is announced with
   `AddLocal(..., LOCAL_MANUAL)`.

## Shutdown

`Shutdown()` calls `StopEmbeddedTor()` after `StopNode()` and
`StopTorControl()`. It is a no-op when Tor was not started, so it also covers
an `AppInit2()` that failed after Step 6 (`AppInit` always calls `Shutdown()`).
Stop is: control `SIGNAL HALT`, close the owner channel, then (child) SIGTERM
and SIGKILL, or (in-process) join the Tor thread. If the daemon dies without
running `Shutdown()`, a child Tor sees EOF on its owner channel and exits; an
in-process Tor dies with the process.

## `torcontrol.cpp` changes that apply with or without embedded Tor

- The onion key is written with `zcl_keyfile_write` (0600, temp file, fsync,
  rename) instead of `fopen(..., "wb")` under the process umask. On startup an
  existing key file is passed through `zcl_keyfile_tighten`, so a 0644 file
  from an older version becomes 0600; a symlink or a file that is not a
  regular file owned by the user is not used and a new key is requested.
- The onion proxy is no longer the literal `127.0.0.1:9050`. After
  authentication the controller asks Tor (`GETINFO net/listeners/socks`) and
  uses the first TCP listener. If Tor reports none, it falls back to the
  `-torcontrol` host with port 9050, which for the default `-torcontrol` is the
  old value. `-onion` still wins, as before.

## In-process or child

Both modes are built in and chosen at runtime. `child` is the default on Linux, `inprocess` elsewhere.

Checked for the in-process mode:

- Same libraries: Tor is built by depends against the same OpenSSL 3.5.9 and
  libevent 2.1.12 static archives the daemon links, so there is one copy of
  each in the binary and no version or symbol clash. `zclassicd`,
  `test_bitcoin` link without duplicate symbols.
- libevent process-wide hooks: Tor calls `event_set_mem_functions` (its
  allocator wrappers sit on the C library heap, so blocks cross over safely;
  an allocation failure aborts instead of returning NULL) and
  `event_set_log_callback` (the daemon re-installs its own callback after
  start and after stop).
- OpenSSL: Tor's init is additive (`OPENSSL_init_ssl`); at exit it calls
  `CONF_modules_unload`, and the daemon loads no configuration modules
  (`OPENSSL_no_config`). The daemon installs no custom RAND method or engine.
- Signals: `__DisableSignalHandlers 1`, so SIGTERM/SIGINT/SIGHUP stay with the
  daemon (asserted by the self-test).
- Tor leaves one eventfd open and 0.5 to 1.4 kB allocated per
  `tor_run_main` (seen in the self-test under ASan). The daemon starts Tor
  once per process, so this does not grow.

What the in-process mode gives up: there is no process boundary. A failed
assertion in Tor aborts the node, and a memory-safety bug in Tor is a bug in
the process that holds the wallet. `-embeddedtormode=child` keeps Tor in its
own address space (the binary re-executed with `--zcl-embedded-tor`).

## Not done

- v3 onion addresses in `addr` gossip (BIP155 `addrv2`): a P2P protocol
  change, separate review. Until then onion peers are learned from
  `-addnode`/`-connect`/`-seednode` only.
- Windows and macOS: the library has Windows code and its self-test
  cross-builds, but `zclassicd` with embedded Tor has only been built and run
  on Linux.
- `-embeddedtor` does not change which addresses the node listens on. An
  onion-only node should also set `-bind=127.0.0.1`.
