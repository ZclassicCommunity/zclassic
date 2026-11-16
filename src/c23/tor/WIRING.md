# Wiring zcl_tor_embed into zclassicd

This unit adds the library and its proof program only. Nothing here is linked
into `zclassicd` yet, and no daemon file is edited. The later units make the
three changes below.

## 1. `main()` dispatch (three lines, first thing in `main`)

The Tor child is the daemon binary itself, started as
`zclassicd --zcl-embedded-tor <fd|-> <tor args...>`. `main()` must hand that
case to Tor before anything else runs (before argument parsing, logging,
`SetupEnvironment`, signal setup or any thread):

```c
#include "c23/tor/zcl_tor_embed.h"
...
int main(int argc, char* argv[])
{
    int torrc = zcl_tor_embed_dispatch(argc, argv);   /* line 1 */
    if (torrc >= 0)                                    /* line 2 */
        return torrc;                                  /* line 3 */
    ...existing main...
}
```

`zcl_tor_embed_dispatch` returns -1 (and does nothing) unless `argv[1]` is the
private argument, so the clearnet path is byte-for-byte unchanged when the
feature is off. In the child it closes every inherited descriptor except the
owner channel, then runs `tor_run_main`. On Windows it re-reads the command
line as UTF-16, so keep a narrow `main` or use `wmain`; both work.

Link `zcl_tor_dispatch.c` against `libtor.a` and the depends archives (see
`build_selftest.sh` for the exact order; add `-levent_pthreads` on POSIX).
Only `zcl_tor_dispatch.c` includes `tor_api.h`.

## 2. Starting and stopping Tor (later unit, `init.cpp`)

```c
zcl_tor_embed_opts o = {0};
o.datadir = GetDataDir().string().c_str();   /* UTF-8; Tor state in <datadir>/tor */
zcl_tor_embed *tor;
char err[256];
if (zcl_tor_embed_start(&o, &tor, err, sizeof err) != 0) { /* log err, continue clearnet */ }
const zcl_tor_embed_info *i = zcl_tor_embed_info_get(tor);
/* i->socks_port  -> SetProxy(NET_ONION, "127.0.0.1", i->socks_port)
 * i->control_port, i->cookie_path -> torcontrol.cpp (-torcontrol=127.0.0.1:port)
 * zcl_tor_embed_wait_bootstrap(tor, 120000, &pct, err, sizeof err) when needed
 */
...
zcl_tor_embed_stop(tor, 0);    /* idempotent; also done by zcl_tor_embed_free */
```

`start` returns once the control port is open and authenticated and (network
enabled) the Socks listener is known. Both ports are chosen by Tor
(`127.0.0.1:auto`) and are loopback only. Bootstrap is separate because it
needs the network and can take a minute.

Do not call `start` before the datadir lock is held, and call `stop` before
`Shutdown` releases it, so a second daemon cannot share `<datadir>/tor`.

## 3. Onion key file (later unit, `src/torcontrol.cpp`)

`torcontrol.cpp` lines 396-407 write the onion private key with the process
umask. Replace that write with:

```c
#include "c23/tor/keyfile.h"
char kerr[256];
if (zcl_keyfile_write(private_key_path_utf8, key.data(), key.size(), kerr, sizeof kerr) != 0)
    LogPrintf("tor: could not save onion key: %s\n", kerr);
```

and, on startup when the key file already exists, tighten a key written by an
older version before reading it:

```c
int t = zcl_keyfile_tighten(private_key_path_utf8, kerr, sizeof kerr);
/* 0 ok, 1 absent, <0 refuse to use the key and log kerr */
```

`zcl_keyfile_write` writes a temp file next to the target (0600), fsyncs,
renames over the target and fsyncs the directory, so a crash leaves either the
old key or the new key, never a partial one. On Windows the file gets a
protected ACL with one entry, the current user.

## Not done in this unit

- No `init.cpp`, `torcontrol.cpp`, `Makefile.am` or `depends` edits.
- `-embeddedtor` flag and its default-off wiring.
- Replacing `torcontrol.cpp`'s PROTOCOLINFO/SAFECOOKIE client with the
  library's plain cookie client is not needed: the daemon keeps its own client
  and only reads `i->control_port` and `i->cookie_path`.
