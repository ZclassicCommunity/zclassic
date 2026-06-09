# Embedded Tor (dynhost fork) — ZClassic Daemon Build Blueprint

> Coin = **ZCL / ZClassic** — never "ZEC"/"Zcash" in any user-facing string.
> Daemon = **C++11 `noext`** (no `std::optional`/`string_view`; no C11 `_Atomic` in C++ TUs).
> Tor C library code stays **C**. NON-CONSENSUS throughout. `master` is HELD — commit only on owner go.
> gtest binary = `zcash-gtest`. Build is **serialized** (one proot at a time), human-driven.

---

## ⚠️ OWNER CONFIRM — two decisions that need your sign-off before T2+

The delivery **shape** matches your "compile-in dynhost" preference. Two substantive items deviate
from the simplest reading of the brief and need an explicit yes/no:

**OWNER CONFIRM #1 — P2P does NOT ride the dynhost no-SOCKS callback; it rides a conventional
HiddenServicePort + a real localhost SocksPort.** Your ideal was "no SOCKS, requests as C
callbacks." Ground truth from the fork (verified): dynhost is **HTTP request/response only** —
`dynhost_webserver.c` ships one reply then `RELAY_COMMAND_END` (stream closed per response),
`dynhost_client.h` is "HTTP GET to .onion", `dynhost.c` sets `real_port=0` (no local TCP backend).
There is **no persistent bidirectional byte-stream primitive**, so the long-lived binary
Bitcoin/Zcash wire protocol (`CMessageHeader` + `pchMessageStart` + the `CNode` loop) cannot ride
it. We therefore keep `libtor.a` compiled-in (your shape), but drive it with a torrc/control-port
flow that reuses the daemon's **existing** `torcontrol.cpp`/`netbase` SOCKS path — which already
creates a v3 onion mapped to the P2P port, self-advertises it, and dials `.onion` peers. We get the
goal (every wallet's node onion-reachable behind any NAT/CGNAT, IP hidden, no separate tor install)
by reusing proven code instead of inventing a fragile new transport seam. dynhost's no-SOCKS HTTP
callback is retained only as an **optional phase-2 beacon** (peer discovery), exactly how
`zclassic-c` uses it. **Tradeoff: there IS a localhost-only SOCKS, but it is 127.0.0.1-bound and
never user-visible.** If you require literally zero SOCKS, that means forking dynhost to add a
bidirectional stream + a brand-new non-socket transport seam in `net.cpp`/`netbase.cpp` — a large,
security-sensitive rewrite of the networking core for no UX gain. Recommend: approve the
HiddenServicePort+SocksPort shape.

**OWNER CONFIRM #2 — default privacy posture ships OPT-IN (`standard`), promote later.** The
locked posture is **hybrid-clearnet+onion**, but the red-team is unanimous that defaulting *on*
silently turns every wallet into a Tor node (bandwidth/battery/employer-network/SmartScreen-AV
surprise) AND that hybrid-by-default can be a *privacy regression* for a user who thinks "I turned
on Tor" (clearnet outbound + tx-origin still leak; onion only protects the advertised inbound
identity). Per the project's proven NAT-PMP opt-in-then-promote pattern, ship **one compiled
default `DEFAULT_TORMODE = standard`** and promote to `hybrid` only after the promote-criteria in §6
are met. **All plumbing assumes `hybrid` works; only the default macro is conservative.** Confirm.

---

## 1. Decision

**Delivery shape — compile-in `libtor.a` (your preference, confirmed feasible).** We vendor the
dynhost fork (`RhettCreighton/tor`, the `dynhost` line at commit `73bd405`, Tor 0.4.9.x) as a
depends package that builds **only the consolidated `libtor.a`** (not the `tor` binary), and link it
into `zclassicd`. Decisive reasons: the embed API is stock (`tor_api.h` → `tor_run_main` on a
thread), the single-archive target already exists (`Makefile.am:144` → `scripts/build/combine_libs`),
and the daemon's two heavy deps are already vendored at exactly Tor's floors (OpenSSL 1.1.1w,
libevent 2.1.12). A bundled prebuilt `tor` binary was rejected: compile-in cross-builds fine, a
stock binary can't expose the dynhost beacon, and a child process re-introduces a Gatekeeper/AV/
signing burden harder than static linking. **Honest cross-build verdict: FEASIBLE on all three, but
NOT symmetric** — Linux is straightforward; mingw is medium (one link-ordering pass + add
`-luserenv`); **macOS is UNPROVEN until a Mac actually builds it** (the project ships macOS as a
*native arm64 build on a rented Mac*, not a Linux→darwin cross — see §4, this corrects the recon).

**P2P stream model.** Inbound: Tor terminates the rendezvous stream for `HiddenServicePort 8033`
onto `127.0.0.1:8033`, the daemon's normal P2P accept socket — it sees an ordinary loopback inbound
`CNode`, **zero `net.cpp` change**; the *advertised* inbound self-address is the `.onion` via
`AddLocal`. Outbound: existing `netbase` SOCKS5 (`ATYP=DOMAINNAME`) through a **real localhost
SocksPort**, the proxy set authoritatively by us (NOT the hardcoded `9050` in `auth_cb`). One
sentence: **P2P rides a conventional HiddenServicePort→loopback mapping for inbound + a localhost
SOCKS5 dial for outbound, reusing the daemon's proven onion addressing with no new transport seam —
but onion peers cannot find each other until BIP155 ADDRv2 is implemented (see §3, the redesign
blocker).**

**Default privacy posture.** Tri-state `-tormode={standard|hybrid|private}`. **Compiled default =
`standard` (opt-in), promote to `hybrid` per §6.** `hybrid` = clearnet outbound for speed + onion
inbound advertised (reachable, *not* anonymous; tx-origin still on clearnet unless onion-tx-relay is
added). `private` = `-onlynet=onion`, all traffic through Tor, IP hidden (the only tier that earns a
"private" claim). The honest constraint is surfaced everywhere: **never appear private while on
clearnet.**

---

## 2. Architecture in one picture

```
                         ┌──────────────────────────  zclassicd (one process)  ──────────────────────────┐
                         │                                                                                │
  clearnet peers  ◄──────┼─ net.cpp P2P listener  0.0.0.0:8033  (hybrid: outbound dial speed; inbound)    │
  (IPv4/IPv6)            │        ▲                                                                        │
                         │        │ loopback inbound (looks like 127.0.0.1 CNode)                          │
                         │        │                                                                        │
                         │   ┌────┴───────────────┐        ┌──────────────────────────────────────────┐   │
   onion peers   ◄═══════╪═══│ embedded Tor thread│◄══════►│ torcontrol.cpp (EXISTING, control-port)  │   │
   (NET_ONION,           │   │ tor_run_main()     │ ctrl    │  ADD_ONION v3 → CService(onion,8033)     │   │
    via 3-hop circuits)  │   │  • HiddenServicePort│ :ctrl  │  → AddLocal(LOCAL_MANUAL)  [inbound id]  │   │
                         │   │    8033→127.0.0.1:  │        │  → SetProxy(NET_ONION, embedded SOCKS)   │   │
                         │   │    8033 (INBOUND)   │        └──────────────────────────────────────────┘   │
                         │   │  • SocksPort 127.0. │              ▲ outbound .onion dials                  │
                         │   │    0.1:<derived>    │──────────────┘ (netbase Socks5 DOMAINNAME)            │
                         │   │    (OUTBOUND)       │                                                        │
                         │   │  • [phase-2] dynhost│  optional no-SOCKS HTTP beacon (peer discovery only)  │
                         │   │    HTTP callback :80│  ── OFF in MVP; hostile-input hardened before on      │
                         │   └─────────────────────┘                                                       │
                         │   embedtor.cpp = extern"C" glue: thread, torrc, bootstrap-state telemetry,      │
                         │                  DEANON GUARD (suppress clearnet self-advertise when onion up)  │
                         └────────────────────────────────────────────────────────────────────────────────┘

 Where clearnet still fits:  standard = clearnet only.  hybrid = clearnet OUTBOUND (fast IBD) +
   clearnet inbound bind, but advertised inbound id = .onion ONLY (clearnet self-advert suppressed).
 What's opt-in / default:    DEFAULT_TORMODE = standard (opt-in).  -tormode=hybrid|private = user choice.
   dynhost HTTP beacon = OFF by default (never started in MVP).  -onlynet=onion = the private tier.
```

---

## 3. Locked C++ integration (files · lifecycle · P2P · args · RPC) — red-team folded INLINE

### 3.0 Load-bearing ground truth (verified against the live tree)

- **No daemon symbol renaming needed.** Daemon SHA3 is the C++-mangled class `SHA3_256` +
  `KeccakF` (`src/crypto/sha3.cpp`); Tor's are plain-C `sha3_256`/`sha3_512`. `set_socket_nonblocking`/
  `scheduler_init` do not exist in `src/` (the daemon's is CamelCase `SetSocketNonBlocking`,
  `netbase.cpp`). Verify clean link (no `--allow-multiple-definition`) per target; that is all.
- **`auth_cb` hardcodes the proxy port `9050`** (`src/torcontrol.cpp:543`, confirmed). The "reuse
  torcontrol unchanged" claim is FALSE for the proxy port — we must set `NET_ONION` proxy ourselves
  (FIX in §3.4). The control flow (`ADD_ONION` at `:556`) is reused; the proxy wiring is not.
- **CNetAddr serializes only `FLATDATA(ip)` (16 bytes)** (`src/netbase.h:114`, confirmed) and never
  `torv3_addr` (`src/netbase.h:45`). v3 onions go on the wire / into `peers.dat` as 16 zero bytes →
  **onion peers cannot gossip** (BIP155 blocker, §3.3). `torv3_addr` IS load-bearing in
  `GetNetwork`/`IsRoutable`/`GetReachabilityFrom` but NOT in serialization, `operator<`, `GetKey`,
  `GetGroup`, `GetHash`.
- **Five clearnet `AddLocal` paths**, only some gated on `fDiscover`: `net.cpp` LOCAL_BIND/LOCAL_IF
  (gated, OK); `init.cpp:2205` `AddLocal(-externalip, LOCAL_MANUAL)` (**ungated**, confirmed);
  `mapport.cpp:220` `AddLocal(extService, LOCAL_UPNP)` from NAT-PMP/PCP (**independent, ungated**,
  confirmed). `-discover=0` alone does NOT close the deanon (§3.4 DEANON GUARD).
- **`init.cpp` ordering** (confirmed): `-onlynet` parse `SetLimited` at `:2103-2114`; `NET_ONION`
  limited at `:2131`; `StartMapPort` at `:2197`; `StartTorControl` at `:3290`; `StartNode` at
  `:3306`. A reservation comment for the embeddedtor flag already exists at `:3297`.
- **`HaveNameProxy()` only true via `SetNameProxy`**, called only in the `-proxy` branch
  (`netbase.cpp:589/573`, confirmed). `-onlynet=onion` + onion-only proxy leaves DNS seeding on the
  OS resolver → DNS leak (§3.4).

### 3.1 New files

| File | Lang | Purpose |
|---|---|---|
| `src/torembed.h` | C++11 | Public interface: lifecycle + state accessors. **No `_Atomic`-bearing includes.** |
| `src/torembed.cpp` | C++11 | The **only** `extern "C"` TU touching Tor. Thread, torrc writer, bootstrap telemetry, proxy wiring, DEANON GUARD. Stubs to no-op when `!ENABLE_TOR`. |
| `src/torembed_beacon.c` | **C** | OPTIONAL phase-2 dynhost beacon glue (uses `_Atomic`). **Not compiled in MVP.** |
| `depends/packages/zlib.mk` | make | Mandatory Tor dep, not currently vendored. |
| `depends/packages/tor.mk` | make | Builds **only** `libtor.a` from the vendored fork tarball. |
| `src/gtest/test_torembed.cpp` | C++11 | Build-integration smoke test + ZCL-name-leak guard + (T3) BIP155 round-trip canary. |
| `depends/sources/tor-73bd405.tar.gz` | — | Vendored fork tree (checked in / reproducible). |
| `doc/tor-attribution.md` + `doc/tor-maintenance.md` | docs | Licenses + the rebase/CVE runbook (§7). |

### 3.2 `src/torembed.h` (C++11-safe interface)

```cpp
// Copyright (c) 2026 The ZClassic developers — MIT.
// Embedded Tor (dynhost fork) lifecycle glue for in-process v3 onion P2P reachability.
#ifndef ZCLASSIC_TOREMBED_H
#define ZCLASSIC_TOREMBED_H
#include <string>
#include <cstdint>

enum EmbeddedTorState {
    EMBEDTOR_DISABLED = 0, EMBEDTOR_BOOTSTRAP = 1, EMBEDTOR_READY = 2,
    EMBEDTOR_PUBLISHED = 3, EMBEDTOR_REACHABLE = 4, EMBEDTOR_FAILED = 5
};

bool TorEmbedAvailable();                 // ENABLE_TOR compiled in
std::string TorEmbedProviderVersion();    // "tor 0.4.9.x" — surfaced to RPC for CVE triage

bool StartEmbeddedTor(const std::string& datadir, uint16_t p2pPort); // non-blocking, idempotent
void InterruptEmbeddedTor();              // from Interrupt()
void StopEmbeddedTor();                   // bounded join from Shutdown()

EmbeddedTorState GetEmbeddedTorState();
int  GetEmbeddedTorBootstrapPct();        // 0..100; -1 unknown
std::string GetEmbeddedTorOnion();        // "" until READY
uint16_t GetEmbeddedTorControlPort();
uint16_t GetEmbeddedTorSocksPort();
int  GetEmbeddedTorInboundOnionPeers();   // for RPC tor.inbound_onion_peers
#endif
```

`enum`/`uint16_t`/`std::string` only — no `<stdatomic.h>`. State held in `std::atomic<int>` +
`CCriticalSection`-guarded `std::string` (legal in C++11; the `_Atomic` C wrapper stays in the `.c`
beacon TU, MVP-excluded).

### 3.3 The torrc `torembed.cpp` writes — and the BIP155 redesign blocker

torrc (single HS — see FIX below; do NOT run both HiddenServiceDir *and* ADD_ONION):
```
DataDirectory        <datadir>/tor
Log notice file      <datadir>/tor/tor.log
ControlPort          127.0.0.1:<ctrlPort>          # for the existing torcontrol.cpp flow
CookieAuthentication 1
SocksPort            127.0.0.1:<socksPort>         # REAL outbound, localhost-only
```

**FIX (P2P-correctness medium — conflated persistence):** use **Route A only**. torcontrol's
`ADD_ONION NEW:ED25519-V3` (`torcontrol.cpp:556`) creates the HS and caches the key in
`onion_v3_private_key` (`:521`,`:735`). Do **NOT** also declare `HiddenServiceDir`/
`HiddenServicePort` in torrc — that creates a *second, independent* onion identity (descriptor war,
advertise-mismatch on restart). One mechanism: ADD_ONION + the key cache. Verify restart-stability
with a gtest that captures the onion, restarts, asserts identical.

`<socksPort>`/`<ctrlPort>` derived from `p2pPort` (e.g. `+11966`/`+1018`), **127.0.0.1-bound only**,
with real collision-retry (regtest/multi-instance). Persistent dir created `0700`, key file `0600`
explicitly — not via umask (deanon-medium: local-user key disclosure).

#### ⛔ REDESIGN BLOCKER — onion peers cannot gossip until BIP155 ADDRv2 ships (T3 scope)

`CNetAddr::SerializationOp` emits only the 16 zero bytes for v3 onions (`netbase.h:114`, verified).
Consequence chain (all verified): on the wire / in `peers.dat` the onion is dropped; on receipt it
deserializes all-zero → `IsRoutable()==false` → silently discarded by the addr handler. **The
design's "onion peers propagate via addr relay" premise is FALSE in this codebase** — the original
onion-code author documented exactly this ("v3 addresses won't gossip via addr messages, needs
BIP155"). Worse, in-memory: `operator<` `memcmp`s the zeroed `ip[16]` → **every distinct v3 onion
compares EQUAL** → `addrman` holds at most ONE onion; `GetKey`/`GetGroup`/`GetHash` all read zeroed
`ip` → no onion diversity, false connection-dedup, eclipse amplifier.

**This is a T3 blocker, not a tweak.** Minimum scope (all NON-consensus, local serialization +
P2P-message only):
1. **BIP155 wire format**: version-gated `CNetAddr`/`CAddress` serializer emitting network-tagged,
   length-prefixed ADDRv2 (carrying the 32-byte `torv3_addr`) to peers that sent `sendaddrv2`;
   legacy 16-byte format otherwise. Add `addrv2`/`sendaddrv2` P2P messages + receive handling.
2. **`peers.dat` (CAddrMan) format bump** to persist `torv3_addr` (guard deserialization of old
   files).
3. **Make `torv3_addr` load-bearing in identity**: `operator==/!=/<`, `GetKey()` (emit tagged
   32-byte pubkey), `GetGroup()` (derive from `torv3_addr`, finer than the 4-bit onion grouping —
   eclipse fix), `GetHash()` for v3.
4. **Canary gtest** (ships in T3): round-trip a v3 `CAddress` through `CDataStream`, assert
   `ToStringIP()` unchanged; two distinct onions must be `!=` with distinct `GetKey`/`GetHash` and
   both survive `addrman.Add`. **All fail today** — this is the fix's litmus.

Until BIP155 lands, onion peering is **`-addnode`/`-seednode`-only**; drop "propagates via addr
relay" from any copy.

### 3.4 Lifecycle, P2P path, DEANON GUARD, proxy wiring (the security core)

**Start ordering (`init.cpp`, around `:3297` reservation):**
```cpp
if (GetBoolArg("-embeddedtor", DEFAULT_EMBEDDED_TOR)) {        // expanded from -tormode
    StartEmbeddedTor(GetDataDir().string(), GetListenPort());  // non-blocking
    // FIX (P2P-correctness high — double-tor / control conflict): HARD-set, not soft-set.
    if (mapArgs.count("-torcontrol") || mapArgs.count("-onion"))
        return InitError(_("-embeddedtor is mutually exclusive with -torcontrol/-onion"));
    mapArgs["-torcontrol"] = strprintf("127.0.0.1:%u", GetEmbeddedTorControlPort()); // HARD set
}
if (GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION)) StartTorControl(threadGroup, scheduler); // :3290
StartNode(threadGroup, scheduler);                                                             // :3306
```

**FIX (deanon CRITICAL #2 / P2P-correctness critical — proxy port wrong + async race).**
`auth_cb` would set `NET_ONION → 127.0.0.1:9050` (wrong; ours is `<socksPort>`). Because `auth_cb`'s
proxy branch only fires when `-onion` is empty, the clean close is to make **`embedtor.cpp` set the
proxy itself, synchronously, before `StartNode`**, and leave `-onion` UNSET so `auth_cb` skips its
9050 branch (but still does `ADD_ONION`):
```cpp
// In StartEmbeddedTor, once the SocksPort is confirmed bound (NOT after full bootstrap):
SetProxy(NET_ONION, proxyType(CService("127.0.0.1", socksPort), /*randomize=*/true));
SetLimited(NET_ONION, false);
assert(GetProxy(NET_ONION, p) && p.proxy.GetPort() == GetEmbeddedTorSocksPort()); // log+assert
```
For the **private tier** also `SetNameProxy(CService("127.0.0.1", socksPort))` so DNS seeding /
`ConnectSocketByName` take the tor path (closes the DNS-leak CRITICAL) and **block outbound until
`state>=PUBLISHED`** (queue dials; never fail-open to clearnet during the 30–180s bootstrap window).

**DEANON GUARD (deanon CRITICAL #1 — single chokepoint, do NOT rely on `-discover=0`):**
When onion is active (`hybrid`/`private`), make `AddLocal()` (`net.cpp:216`) **reject any
non-`NET_ONION` address regardless of `nScore`/score class** via a process-wide
`fOnionExclusiveAdvertise` flag set in `init.cpp` AppInit2. This is ONE chokepoint that
`-externalip` (`init.cpp:2205`), NAT-PMP (`mapport.cpp:220`), and any future caller cannot bypass.
Additionally: refuse `StartMapPort`/force `-natpmp=0` with an `InitWarning` and ignore `-externalip`
with an `InitWarning` when onion-active. **Test (CRITICAL):** boot with `embeddedtor+natpmp+
externalip`, assert `mapLocalHost` contains ONLY the onion — any clearnet entry = test failure.

**Inbound P2P-peer network tagging (P2P-correctness medium — RPC counter is structurally wrong).**
Inbound onion peers arrive on `127.0.0.1` (the HS→loopback map), so `CNode.addr.GetNetwork()` reads
`ipv4`/unroutable, NOT `onion` → "helping N peers over Tor" would read ~0. **FIX:** add
`bool fInboundOnion` to `CNode`, set at accept time when the inbound socket is the tor-mapped local
port; source `getpeerinfo.network` and `tor.inbound_onion_peers` from that flag, not from `addr`.

**Signal-handler collision (deanon/lifecycle CRITICAL).** The daemon installs sigaction for
SIGTERM/SIGINT/SIGHUP + `SIG_IGN` SIGPIPE (`init.cpp:1569-1584`). Tor's `tor_run_main` →
`handle_signals()` overwrites those process-globals. **FIX:** prevent Tor from grabbing signals
(embed-config toggle; if the fork lacks one, patch `handle_signals` to no-op when embedded —
attribute to the fork); drive Tor shutdown **only** via `tor_shutdown_event_loop_and_exit()` from
`StopEmbeddedTor`; the daemon stays the sole signal owner; re-install + verify the daemon's handlers
after `StartEmbeddedTor`. Test: SIGTERM during active bootstrap still triggers a clean leveldb
flush.

**Stop ordering (`init.cpp` Interrupt/Shutdown).** `Interrupt(): InterruptTorControl();
InterruptEmbeddedTor();` then `Shutdown(): StopTorControl(); StopEmbeddedTor();`. **FIX
(lifecycle medium — UAF / dirty-DB):** tell Tor to exit and fully join it **before** the
wallet/chainstate flush, so a Tor hang can never block or interleave with the leveldb close (this
repo has a documented dirty-DB reindex hazard). Bounded join (~5s with shutdown-event retries); on
timeout do **not** detach-and-continue into teardown of shared libevent/openssl globals — `_exit()`
after the DB flush instead. Never convert a clean quit into a corrupting force-kill. On
bootstrap-failure: `RemoveLocal(onion)` runs and the guard is re-evaluated atomically (single code
path computes the advertise set) **before** any clearnet-inbound re-advertise — never advertise both
at once.

**dynhost beacon OFF in MVP (deanon HIGH + maintenance CRITICAL).** Do **not** start the dynhost
`:80` service or register any handler in the MVP. The fork's `dynhost_webserver_handle_request`
falls through to built-in demo pages (calculator/blog/MVC, ~3,800 LOC) when no external handler is
set — an unauthenticated public HTTP server with hand-rolled C parsers (`parse_http_request` has a
`size_t` underflow → OOB read) **inside the wallet-key process**. MVP: never invoke it; the P2P
onion is the ONLY hidden service published. Phase-2 enabling requires: exclude the demo handlers
from `libtor.a` (or patch to bare-404 fallthrough), length-bound all parsers (no
`strstr`/`strchr`/`strlen` on non-NUL network buffers — explicit lengths / `tor_memmem`), libFuzzer
on `parse_http_request`/`parse_form_field`, request-size clamp, and reuse the P2P key (no second
uncorrelated onion).

### 3.5 Reusing torcontrol UNCHANGED (the parts that ARE reused)
`torcontrol.cpp:510-526` onion→`CService(onion, GetListenPort())`→`AddLocal(LOCAL_MANUAL)`;
`:556` `ADD_ONION NEW:ED25519-V3`; `:706-711` `RemoveLocal` on disconnect; `:735` key cache;
`:750-789` thread/start/stop. Only the **proxy-port** wiring is taken over by `embedtor.cpp`
(§3.4). `netbase.cpp:603-637` proxy dial and `:45-67` v3 SHA3 checksum are reused as-is.

### 3.6 Args + defaults + help (ZCL never ZEC)

One high-level tri-state expands into proven low-level args (logged on every coercion):

| `-tormode=` | expands to | inbound advertised | outbound | embedded tor |
|---|---|---|---|---|
| `standard` *(DEFAULT)* | `-listen=1`, tor OFF | clearnet IP | clearnet | not started |
| `hybrid` | `-listen=1` + tor ON + `fOnionExclusiveAdvertise` | **.onion only** | clearnet (speed) | started |
| `private` | tor ON + `-onlynet=onion` + name+onion proxy → embedded SOCKS | .onion only | **all via tor** | started |

Conflict rules: explicit legacy args **downgrade, never silently upgrade**; `private` + non-onion
`-onlynet` ⇒ `InitError` (don't boot a promise we can't keep); `-listenonion=0` forces `standard`;
`-embeddedtor` is mutually exclusive with `-torcontrol`/`-onion` (§3.4). `DEFAULT_TORMODE` is the
**one** macro that controls opt-in vs hybrid-default (reconciles the two locks). Help strings: "Run
Tor inside ZCL so your node is reachable over a private .onion behind any router or NAT, with no
separate Tor install … Hybrid keeps clearnet for fast outbound; your advertised inbound address is
the .onion. This does not hide your own IP for outbound traffic — use -onlynet=onion for that."
Never "Zcash"/"ZEC".

### 3.7 RPC fields (frozen GUI contract)

`getnetworkinfo` → new top-level `tor` object (build site `rpc/net.cpp:470-491`):
```jsonc
"tor": {
  "enabled": true, "mode": "hybrid",
  "state": "reachable",            // disabled|bootstrapping|ready|published|reachable|failed
  "bootstrap_pct": 100,
  "onion": "abc...xyz.onion", "onion_port": 8033,
  "reachable": true,               // INBOUND: descriptor_published AND a verified inbound onion path
  "descriptor_published": true,
  "inbound_onion_peers": 3,        // from CNode.fInboundOnion (§3.4), NOT addr.GetNetwork()
  "provider_version": "tor 0.4.9.x" // CVE triage (maintenance LOW)
}
```
Types explicit (bools/ints/strings; `onion` is "" not null before ready). `networks[onion].reachable`
keeps meaning **outbound** dialability; `tor.reachable` means **inbound** — document the split.
`getpeerinfo` → per-peer `"network": "ipv4"|"ipv6"|"onion"` sourced from `fInboundOnion` for inbound
onion peers (loopback addr would mislabel them).

**Honest reachability gate (deanon-paramount, NAT-PMP pattern).** `tor.reachable==true` iff
`descriptor_published` AND inbound reachability is *proven*. Because a stranger may never dial early
in rollout (chicken-and-egg), prove it with a **self-reachability probe**: after publish, the daemon
dials its OWN `.onion` through its own SocksPort and confirms a P2P version handshake — latches
`reachable` promptly without waiting for a stranger. Monitor `tor.log` **continuously** for
descriptor-expiry/republish-failure/circuit loss and revert `reachable→published→bootstrapping` —
never leave a stale latched `reachable`. Until proven, GUI says "Your private address is ready;
verifying other peers can reach you" (calm, not a broken-looking indefinite spinner).

---

## 4. Locked build / cross-build plan + proot recipe + gtest

### 4.0 Verified feasibility findings
- **`libtor.a` is one archive** (`Makefile.am:144` + `scripts/build/combine_libs`).
- **Tor ships NO `configure`** → `tor.mk` runs `./autogen.sh`; proot needs `autoconf automake
  libtool pkg-config`.
- **Daemon detects deps via `pkg-config --static`** but Tor has no `.pc` → detect via `AC_CHECK_HEADER`
  + explicit `-ltor`; stage `libtor.a`+headers into `$(host_prefix)/{lib,include}`.
- **EQUIX/hashx is a PHANTOM risk** (red-team P2P/cross LOW, verified): EQUIX is gated on
  `BUILD_MODULE_POW` which requires `--enable-gpl` (`configure.ac:422`); `tor.mk` does NOT pass it →
  EQUIX never compiled, never in `libtor.a`. Assert `nm libtor.a | grep -i equix` is EMPTY (and note
  Tor's PoW module is **GPL** — a license conflict with the MIT/Apache daemon; do not enable).
- **`no-err` removal is the only openssl blocker** (Tor references `ERR_*` unconditionally in
  `tortls_openssl.c`/`crypto_openssl_mgt.c`); other strips audited SAFE (`no-engine` self-handled,
  `no-comp/no-asm/no-scrypt/no-chacha/no-poly1305` safe, EC present). Forces an openssl rebuild +
  daemon relink **per target** (3 cycles).

### 4.1 `depends/packages/zlib.mk` — ONE pinned recipe (resolves the conflicting-hash defect)
```make
package=zlib
$(package)_version=1.3.1
$(package)_download_path=https://zlib.net/fossils
$(package)_file_name=zlib-$($(package)_version).tar.gz
$(package)_sha256_hash=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23  # .tar.gz (verify w/ sha256sum)
# zlib configure is NOT autotools / ignores --host → drive per target.
define $(package)_config_cmds
  CHOST=$(host) CC="$($(package)_cc)" AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" \
  CFLAGS="$($(package)_cflags) $($(package)_cppflags) -fPIC" ./configure --static --prefix=$(host_prefix)
endef
define $(package)_build_cmds
  $(MAKE) libz.a
endef
define $(package)_stage_cmds
  $(MAKE) install DESTDIR=$($(package)_staging_dir)
endef
# mingw32: ./configure can't cross → win32/Makefile.gcc
define $(package)_config_cmds_mingw32
  true
endef
define $(package)_build_cmds_mingw32
  $(MAKE) -f win32/Makefile.gcc PREFIX=$(host)- CC=$(host)-gcc AR=$(host)-ar RANLIB=$(host)-ranlib CFLAGS="-fPIC -O2" libz.a
endef
define $(package)_stage_cmds_mingw32
  $(MAKE) -f win32/Makefile.gcc PREFIX=$(host)- \
    BINARY_PATH=$($(package)_staging_dir)$(host_prefix)/bin \
    INCLUDE_PATH=$($(package)_staging_dir)$(host_prefix)/include \
    LIBRARY_PATH=$($(package)_staging_dir)$(host_prefix)/lib install
endef
```
> Darwin-native (see §4.4): zlib builds natively on the Mac; the `-isysroot` is already in the
> native CFLAGS — no special handling.

### 4.2 `depends/packages/tor.mk` — build only `libtor.a`, demo handlers stripped
```make
package=tor
$(package)_version=73bd405
# Vendor the fork tree directly (no upstream URL). Place depends/sources/tor-73bd405.tar.gz and
# OMIT download_path (funcs.mk skips download when the source file exists). Pin the sha256 of THAT
# exact tarball; document the exact `git archive` + git version for reproducibility (or check in tree).
$(package)_file_name=tor-$($(package)_version).tar.gz
$(package)_sha256_hash=PUT_SHA256_OF_VENDORED_TARBALL_HERE
$(package)_dependencies=openssl libevent zlib

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-static-tor --enable-pic
  $(package)_config_opts+=--with-openssl-dir=$(host_prefix) --with-libevent-dir=$(host_prefix) --with-zlib-dir=$(host_prefix)
  $(package)_config_opts+=--enable-static-openssl --enable-static-libevent --enable-static-zlib
  $(package)_config_opts+=--disable-unittests --disable-asciidoc --disable-manpage --disable-html-manual
  $(package)_config_opts+=--disable-system-torrc --disable-systemd --disable-seccomp --disable-lzma --disable-zstd
  $(package)_config_opts+=--disable-module-relay --disable-module-dirauth --disable-tool-name-check
  # NOTE: do NOT pass --enable-gpl (keeps EQUIX/PoW out; avoids GPL-vs-MIT/Apache conflict).
endef
define $(package)_preprocess_cmds
  ./autogen.sh
endef
define $(package)_config_cmds
  $($(package)_autoconf)
endef
define $(package)_build_cmds
  $(MAKE) libtor.a          # consolidated archive; demo dynhost handlers excluded from include.am
endef
define $(package)_stage_cmds
  mkdir -p $($(package)_staging_dir)$(host_prefix)/lib $($(package)_staging_dir)$(host_prefix)/include && \
  cp libtor.a $($(package)_staging_dir)$(host_prefix)/lib/ && \
  cp $($(package)_extract_dir)/src/feature/api/tor_api.h $($(package)_staging_dir)$(host_prefix)/include/
endef
# Cross-from-Linux only: combine_libs' apple_symdef_fix runs only on a Darwin HOST; re-index here.
# (On a native Mac build this is a no-op / native ranlib — see §4.4.)
define $(package)_postprocess_cmds
  $(host)-ranlib lib/libtor.a 2>/dev/null || ranlib lib/libtor.a
endef
```
**Minimize divergence (maintenance HIGH):** for the MVP the conventional path needs ZERO dynhost
code — build `libtor.a` from upstream-stable + only the embed/symbol-fix commit, and **drop the
dynhost demo feature commits** from the MVP archive. Smaller archive, far cheaper rebase, smaller
attack surface; nothing the MVP needs is lost.

### 4.3 Edits to existing depends/build files
- `depends/packages/packages.mk:38` → append `zlib tor` (zlib before tor).
- `depends/packages/openssl.mk:37` → **delete** `$(package)_config_opts+=no-err`. Re-verify the
  daemon still builds/runs **per target** before adding libtor (isolate the variable).
- `src/Makefile.am`: add `torembed.cpp` after `torcontrol.cpp` (`:297`), `torembed.h` after
  `torcontrol.h` (`:211`); insert `$(TOR_LIBS)` at the **top** of the second `zclassicd_LDADD` block
  (`:484`) **before** `$(SSL_LIBS)/$(CRYPTO_LIBS)/$(EVENT_*)`, append `$(ZLIB_LIBS)` +
  `$(TOR_SYSTEM_LIBS)` last. `Makefile.gtest.include`: add `gtest/test_torembed.cpp` + the same
  `$(TOR_LIBS) $(ZLIB_LIBS) $(TOR_SYSTEM_LIBS)` to `zcash_gtest_LDADD`.
- `configure.ac`: `--enable-tor` (default yes) near `:106`; header-only detection after `:701`
  (`AC_CHECK_HEADER([tor_api.h])`, `TOR_LIBS=-ltor`, `ZLIB_LIBS=-lz`); **mingw `TOR_SYSTEM_LIBS=
  -luserenv` ONLY** (the daemon already links ws2_32/iphlpapi/shlwapi/gdi32/crypt32 at `:263-267`
  and bcrypt at `:287` — do NOT duplicate; recon over-listed); `AC_DEFINE([ENABLE_TOR])` +
  `AM_CONDITIONAL`. Optional early-fail: `AC_CHECK_LIB([tor],[tor_api_get_provider_version], …)`
  with the openssl/libevent/zlib closure on `LIBS`.

### 4.4 Per-target feasibility (honest)
1. **Linux x86_64 / glibc2.31 (proot) — STRAIGHTFORWARD.** Reuse vendored libevent/openssl, add
   zlib+tor, drop `no-err`, `--enable-pic`. Pre-req: `autoconf automake libtool pkg-config` in the
   focal proot.
2. **mingw x86_64-w64-mingw32 — MEDIUM.** `bwin32=cross` auto; one link-ordering settling pass
   (libtor before EVENT/SSL/CRYPTO); add **only** `-luserenv`. gtest run skipped (can't exec the
   `.exe` in the proot) → stop after the `nm` symbol-proof on the `.exe`. **Packaging risk:** the
   Windows `.exe` is shipped UNSIGNED; a Tor-containing unsigned wallet raises SmartScreen/AV
   false-positive risk → keep embeddedtor default OFF on Windows for the first release; prioritize an
   Authenticode cert before any Windows default-on.
3. **macOS — UNPROVEN until a Mac builds it (CORRECTS the recon).** The project ships macOS as a
   **native arm64 build on a rented Mac** (Mach-O arm64, macdeployqt+codesign+hdiutil), **NOT** a
   Linux→`x86_64-apple-darwin11` cross — this host has no `xcrun`, `depends/x86_64-apple-darwin11/lib`
   is empty, and `darwin.mk` calls `xcrun` unconditionally. So: write a **Mac-NATIVE** `tor.mk` pass
   (host `arm64-apple-darwin*`), let `combine_libs` run natively (`apple_symdef_fix` fires on its
   own — **drop the `$(host)-ranlib` postprocess on Darwin**), and add a step to
   `BETA*_MACOS_HANDOFF.md`: build the tor depends pkg on the Mac, then the daemon, then
   `codesign --force` the larger `zclassicd` **last** (after any load-command rewrite), per the
   existing post-macdeployqt re-sign recipe. Treat macOS as UNPROVEN — not "hardest-but-feasible" —
   until a Mac produces `libtor.a`.

**Symbol-coexistence verification (per target, before trusting the link):**
`nm -A --defined-only` across `libbitcoin*.a libtor.a libevent*.a libcrypto.a libssl.a libz.a` and
diff for ANY symbol defined in >1 archive (not just the 4 named). Confirm both sides agree on the
OpenSSL 1.1.1w + libevent 2.1.12 ABI (vendored — pin). Runtime smoke test exercising both the
daemon's SHA3/secp paths and Tor's crypto in one process.

**Binary-size accounting (don't ship blind):** baseline `zclassicd` ~14M; `libtor.a` ~28M (archive).
After `strip -s` + `--gc-sections`, expect the **live closure** (likely +4–8M), not the full
archive. Record `size`/`strip` delta with-vs-without tor; confirm the ZQWDMON1 single-file footer
round-trips on the larger embedded daemon and the extract-cache content-addressing still keys; put
the number in release notes.

### 4.5 proot recipe — `/home/rhett/zclbuild/focal/build/p5-tor-build-test.sh`
Mirrors p3/p4 but, because this touches `depends/`+`configure.ac`+`Makefile.am`, it: (0) checks
`autoconf/automake/libtool/pkg-config` present; (1) asserts `depends/sources/tor-73bd405.tar.gz`
exists; (2) cp's changed build files; (3) rebuilds `openssl zlib tor` (openssl forced by `no-err`
removal) **and asserts `nm libtor.a | grep -i equix` is EMPTY** + `libtor.a`/`tor_api.h` staged;
(4) re-`autogen.sh` + reconfigure `--enable-tests --enable-tor`; (5) build, assert `zclassicd`
(never `zcashd`) + `--version` says ZClassic; (6) **`nm zclassicd | grep tor_run_main`** proves
libtor linked into the daemon (not just gtest); (7) assert `TorEmbed.*` gtest count ≥1 (never trust
exit-0); (8) run `TorEmbed.*`; (9) spot-run the existing suite (no regression from `no-err` removal).
**Per-target gate:** after openssl rebuilds, relink the daemon **without** tor and run gtest first to
prove `no-err` removal didn't regress the baseline, **then** add libtor.

### 4.6 gtest — `src/gtest/test_torembed.cpp`
T1 build-proof: `TorEmbedAvailable()` true, `TorEmbedProviderVersion()` contains "tor", and a
`NoZcashCoinNameLeak` test (`find("ZEC")==npos`). T3 ships the **BIP155 canary** (§3.3) in the same
file. Disabled-build path asserts the stubs.

---

## 5. UX / privacy surface + GUI handoff

**Daemon honest-copy semantics** (GUI may restyle, must NOT strengthen the claim):
- `standard` — "Standard: fastest sync, no Tor. Your node's IP is visible to peers, like most software."
- `hybrid` — "Helping the ZCL network: your wallet accepts connections over Tor so others can reach
  you behind any router. This does not hide your own IP — choose Private for that."
- `private` — "Private: your wallet reaches the ZCL network through Tor and your IP address stays
  hidden. Connecting and syncing are a little slower."

**Bootstrap states** (non-blocking; P2P never waits): `disabled → bootstrapping(0–100%) → ready →
published → reachable` (+`failed`). `reachable` only via the self-reachability probe (§3.7). Stable
log lines under the `tor` category: `tor: bootstrap NN%`, `tor: private address ready <x.onion>`,
`tor: hidden service descriptor published`, `tor: inbound reachability verified — reachable`,
`tor: bootstrap failed after <N>s — <mode consequence>`.

**GUI handoff (separate Qt repo `/home/rhett/github/zcl-qt-wallet` — note only, not built here):**
1. Settings: 3-way "Network privacy" (Standard/Hybrid/Private) → writes `-tormode` to config +
   restart (init-time arg). Default reflects daemon `DEFAULT_TORMODE`. Each shows the §5 one-liner
   verbatim.
2. Status badge: poll `getnetworkinfo` (existing cadence); gray(disabled) → amber(`bootstrapping`,
   %) → amber "verifying" (`ready`/`published`) → green "Reachable via Tor — strengthening the ZCL
   network" (`reachable`) → red(`failed`). Green-lock "Private" only when `mode=="private"`. Never
   green while on clearnet.
3. "Strengthening the network" panel: `tor.onion` + copy button (only when `state≥ready`);
   "You're serving N peers over Tor" from `tor.inbound_onion_peers` (frame as contribution, matching
   the existing "you're serving" panel).
4. Bootstrap copy: "Establishing your private network address… up to a minute the first time" →
   "Your private address is ready; verifying other peers can reach you" → honest failure line. Note
   later boots are fast (persistent key).
5. No SOCKS/control/port config ever exposed; everything driven by `-tormode`. **First-run consent
   moment before any hybrid default-on promotion** ("Help strengthen the ZCL network over Tor? This
   accepts incoming connections and uses some bandwidth") — never silent-on.

---

## 6. Ordered build plan (each independently shippable · NON-consensus · master HELD)

> **Default stays `standard` (opt-in) through every T below.** Hybrid promotion is a SEPARATE gated
> decision after T1–T6 + field data (criteria at the end).

**T1 — Vendor + link `libtor.a`, build green on Linux.**
Files: `depends/packages/{zlib.mk,tor.mk}`, `depends/sources/tor-73bd405.tar.gz`,
`packages.mk:38`, `openssl.mk:37` (drop `no-err`), `configure.ac` (detect + `--enable-tor`),
`src/Makefile.am` (sources+link), `src/torembed.{h,cpp}` (stub-able), `src/gtest/test_torembed.cpp`,
`Makefile.gtest.include`, `p5-tor-build-test.sh`.
Build: `libtor.a` only; daemon relink. Proves: `nm zclassicd | grep tor_run_main` resolves;
`TorEmbed.*` gtest registered+green; existing suite unregressed after `no-err`; `nm libtor.a` has no
EQUIX; symbol-coexistence diff clean. Record stripped size delta + ZQWDMON1 round-trip.

**T2 — Bring up the onion service + advertise + DEANON GUARD + lifecycle.**
Files: `src/torembed.cpp` (thread, torrc, bootstrap telemetry, `SetProxy(NET_ONION)` synchronous,
signal-handling toggle, bounded-join-before-DB-flush), `src/init.cpp` (`-embeddedtor` start before
`StartTorControl`; HARD-set `-torcontrol`; mutual-exclusion `InitError`;
`fOnionExclusiveAdvertise`; refuse `StartMapPort`/ignore `-externalip` when onion-active),
`src/net.cpp` (`AddLocal` chokepoint honors `fOnionExclusiveAdvertise`).
Build: Linux. Proves: regtest node comes up with a stable `.onion` (restart → identical onion);
**deanon test** — boot `embeddedtor+natpmp+externalip`, assert `mapLocalHost` = onion ONLY;
SIGTERM during bootstrap → clean leveldb flush.

**T3 — BIP155 ADDRv2 + P2P inbound/outbound over tor on regtest (REDESIGN BLOCKER).**
Files: `src/netbase.{h,cpp}` (version-gated `CNetAddr`/`CAddress` serializer; `torv3_addr` in
`operator==/!=/<`, `GetKey`/`GetGroup`/`GetHash`), `src/protocol.h`/`src/main.cpp`/`src/net.{h,cpp}`
(`addrv2`/`sendaddrv2` messages + handler; `CAddrMan` peers.dat format bump; `CNode.fInboundOnion`
at accept; peer-network-aware stall/timeout multiplier for onion RTT).
Build: Linux. Proves: BIP155 canary gtest (round-trip a v3 `CAddress`, two distinct onions `!=`
with distinct `GetKey`/`GetHash`, both survive `addrman.Add`); a regtest two-node onion handshake +
addr-relay of the onion; IBD over onion-only tolerates the stall timeout. **Without T3, onion peers
are islands — this is the gate that makes the feature actually work.**

**T4 — Privacy-posture args + honest reachability + name proxy + RPC fields + onion seeds.**
Files: `src/init.cpp` (`-tormode` expansion + conflict rules; `private` ⇒ `SetNameProxy` + block
outbound until published; `-onlynet=onion` enforced; onion-seed `-addnode` injection at the
bootstrap-pin block `:2587` once seeds exist), `src/torembed.cpp` (self-reachability probe;
continuous `tor.log` monitor for descriptor expiry → state revert), `src/rpc/net.cpp`
(`getnetworkinfo.tor` object incl. `provider_version`; `getpeerinfo.network` from `fInboundOnion`),
`src/chainparams.cpp` (the two bootstrap servers' v3 `.onion` seeds).
Build: Linux. Proves: `private` mode does NO `getaddrinfo` for a DNS seed (`HaveNameProxy()==true`),
refuses to start / loud-degrades with zero onion peers; `getnetworkinfo.tor` shape matches the
frozen contract; reachable latches only after the self-probe; DNS-leak test green.

**T5 — mingw + macOS cross/native build.**
Files: `tor.mk`/`zlib.mk` per-target stanzas; `configure.ac` `TOR_SYSTEM_LIBS=-luserenv` (mingw);
`p5-tor-build-test.sh` host variants; `BETA*_MACOS_HANDOFF.md` Mac-native steps + final
`codesign --force`.
Build: mingw (proot) then macOS (rented Mac, native arm64). Proves: mingw `.exe` has Tor symbols
(`nm`), one link-ordering pass settles, `-luserenv` appended; **macOS produces `libtor.a` natively**
(drop `$(host)-ranlib`), daemon links, re-sign recipe verified. macOS stays UNPROVEN until this
passes.

**T6 — GUI handoff.**
Files: none in this repo (note to `/home/rhett/github/zcl-qt-wallet`). Deliver the frozen RPC
contract + §5 copy + the first-run consent requirement + the badge/probe semantics. Proves: GUI can
render gray→amber(%)→green→red honestly off `tor.state`/`bootstrap_pct`/`reachable` and show the
onion + "serving N peers" without strengthening the claim.

**Hybrid-default promotion criteria (separate owner decision, after T1–T6):** Tor rebased onto a
**stable** release (no alpha to end users); demo handlers stripped; DEANON GUARD E2E-proven;
self-reachability probe live; ≥N weeks opt-in field data with no deanon/crash/dirty-DB reports;
Authenticode cert for Windows; onion seeds live so the chicken-and-egg is closed. Flip the single
`DEFAULT_TORMODE` macro + add the GUI first-run consent moment.

---

## 7. Open risks / non-goals

**Tor-fork security-update strategy (CRITICAL maintenance liability).** `73bd405` is **Tor
0.4.9.2-alpha-dev** (~2025-04). **Do NOT ship an alpha in-process inside a money daemon listening on
a public .onion.** Before any default-on: **rebase the fork onto the latest STABLE Tor line.** Then
institutionalize: `tor.mk` records the upstream stable tag + the exact (small, ~14-commit)
dynhost/embed patch list; a quarterly/on-TROVE-advisory rebase checklist in `doc/tor-maintenance.md`
(pull stable, rebase patches, re-run p5 on all 3 targets, ship); subscribe to tor-announce/TROVE;
surface `provider_version` in RPC so support maps users to CVEs. A static-linked Tor CVE = a full
3-target re-release + GUI bundle refresh + updater prompt — there is no `apt upgrade tor`. **If
quarterly rebases can't be sustained, keep the feature opt-in permanently** (blast radius = users who
chose it). Minimize divergence: build MVP `libtor.a` from upstream-stable + only the embed/symbol
fix, dropping the dynhost demo commits (smaller, cheaper rebase, fewer attack-surface lines).

**Deanon posture (paramount).** The onion only protects the **advertised inbound identity**. `hybrid`
still puts the real IP on every clearnet dial/inbound and tx-origin on clearnet — it is
**reachability, not anonymity**, and the copy says so. Only `private` (`-onlynet=onion` + name+onion
proxy + outbound blocked until published) hides the IP. Folded fixes: single-chokepoint
`AddLocal` guard (beats `-externalip`/NAT-PMP bypass), authoritative non-9050 proxy port,
`SetNameProxy` to kill DNS-seed leaks, signal-handler ownership, RemoveLocal-before-clearnet-fallback,
0600/0700 key perms. Consider (post-T4) onion-preferred tx relay so `hybrid` doesn't leak tx-origin.

**Eclipse (onion-only).** The 4-bit onion `GetGroup` is an eclipse amplifier; T3 widens it from
`torv3_addr`, and `private` pins trusted onion anchor seeds — but onion-only diversity is inherently
weaker than clearnet. Gate `private` behind "≥N reachable onion peers."

**Non-goals (explicit):** the dynhost no-SOCKS HTTP beacon as P2P transport (rejected — HTTP
one-shot); a bundled prebuilt `tor` binary (rejected); adopting the C23 `zclassic-c` rewrite
(reference-only); enabling Tor's GPL PoW/EQUIX module (license conflict); macOS Linux-cross (the
project builds macOS natively on a Mac); shipping an alpha Tor (rebase to stable first).

**Honest open gap:** macOS is **UNPROVEN** until a Mac actually builds `libtor.a`; treat the macOS
line item as "needs a Mac iteration," not "done."

---

## 8. Must-fix ledger

| # | Sev | Area | Issue | Addressed in |
|---|---|---|---|---|
| 1 | CRIT | Deanon | Clearnet IP co-advertised (`-externalip` `init.cpp:2205` + NAT-PMP `mapport.cpp:220` bypass `-discover=0`) | §3.4 single-chokepoint `AddLocal` guard + refuse MapPort/`-externalip`; T2 test |
| 2 | CRIT | Deanon/Net | `auth_cb` hardcodes proxy `9050` (`torcontrol.cpp:543`); embedded SOCKS is non-9050 | §3.4 `embedtor.cpp` sets `NET_ONION` proxy itself + assert; `-onion` unset |
| 3 | CRIT | Deanon | DNS-seed leak: no `SetNameProxy` in onion-only (`netbase.cpp:589`) | §3.4 `SetNameProxy` for `private`; T4 no-getaddrinfo test |
| 4 | CRIT | Lifecycle | Tor `handle_signals()` clobbers daemon SIGTERM/INT/HUP → dirty-DB risk | §3.4 disable Tor signal grab; daemon sole owner; T2 SIGTERM test |
| 5 | CRIT | P2P | v3 onion serializes as 16 zero bytes (`netbase.h:114`) → no gossip, addrman holds 1 onion | §3.3 BIP155 ADDRv2 + `torv3_addr` identity (T3, REDESIGN BLOCKER) |
| 6 | CRIT | P2P | Outbound onion proxy set async by `auth_cb` → isolation/origin-leak window | §3.4 synchronous `SetProxy` before `StartNode`; block outbound until published |
| 7 | CRIT | P2P | Cold start: no onion seeds, DNS can't return onion, pin injects only clearnet | §3.3/§6 T4 onion seeds in chainparams + bootstrap-pin `-addnode`; gate `private` |
| 8 | CRIT | Cross-build | macOS plan targets a Linux-cross path the project doesn't use (native Mac arm64) | §4.4 Mac-NATIVE `tor.mk`; macOS UNPROVEN until a Mac builds it |
| 9 | CRIT | Maint | Shipping an ALPHA Tor in-process, no update path | §7 rebase to STABLE before default-on; maintenance runbook; `provider_version` |
| 10 | CRIT | Maint | dynhost demo handlers = unauth public HTTP server in wallet process | §3.4 beacon OFF in MVP; §4.2 strip demo handlers; fuzz before phase-2 |
| 11 | HIGH | Deanon | dynhost HTTP parsers OOB read (`size_t` underflow) | §3.4 beacon OFF MVP; length-bound + libFuzzer before phase-2 |
| 12 | HIGH | P2P | Onion eclipse amplifier (4-bit `GetGroup`) | §3.3 widen group from `torv3_addr`; §7 pin anchors; gate `private` |
| 13 | HIGH | Deanon/UX | Hybrid-default = privacy regression (clearnet outbound + tx-origin) | §1/§6 OPT-IN default; consider onion-tx-relay; honest copy §5 |
| 14 | HIGH | Net | Double-tor/control conflict (`assert(!gBase)`, soft-set ignored) | §3.4 HARD-set `-torcontrol`; `InitError` on `-torcontrol`/`-onion` clash |
| 15 | HIGH | Net | Onion RTT trips IBD/block stall timeouts | §3.4/T3 peer-network-aware timeout multiplier; clearnet primary for IBD |
| 16 | HIGH | Net | `private` partitioned from clearnet-only network | §6 sequenced rollout; gate `private` on ≥N onion peers; hybrid as bridge |
| 17 | HIGH | Build | zlib conflicting sha256 / `.tar.gz` vs `.tar.xz` | §4.1 one pinned `.tar.gz` recipe; verify before build |
| 18 | HIGH | Build | `no-err` removal cascade (3-target rebuild + relink) | §4.3 per-target gate: relink+gtest WITHOUT tor first |
| 19 | HIGH | Maint | Single-maintainer fork bus factor / private-API churn | §7 `doc/tor-maintenance.md` runbook; minimize divergence (drop dynhost MVP) |
| 20 | MED | Lifecycle | Bounded-join detach → UAF on shared libevent/openssl globals | §3.4 join before DB flush; `_exit()` after flush on timeout |
| 21 | MED | Deanon | Key file perms / datadir-clone duplicate onion | §3.3 `0700`/`0600` explicit; doc identity in backup; detect concurrent use |
| 22 | MED | Build | extern "C" header order (`dynhost_webserver.h` lacks `<stdint.h>`) | §3.2/§4.6 MVP includes only self-contained `tor_api.h`; ints first if needed |
| 23 | MED | Build | Symbol-coexistence under-verified beyond SHA3 | §4.4 `nm -A --defined-only` cross-archive diff per target |
| 24 | MED | UX | reachable can latch then rot (descriptor expiry); chicken-and-egg | §3.7 self-reachability probe + continuous monitor + revert |
| 25 | MED | P2P | inbound onion peer mislabeled (loopback addr) → counter wrong | §3.4 `CNode.fInboundOnion` sources RPC, not `addr.GetNetwork()` |
| 26 | MED | Build | Single-file bundle size / ZQWDMON1 round-trip on larger daemon | §4.4 measure stripped delta + verify footer/extract-cache |
| 27 | MED | Pkg | Unsigned Tor-containing Windows `.exe` vs SmartScreen/AV | §4.4 default OFF on Windows first; Authenticode cert before default-on |
| 28 | MED | Build | `file://` source path / non-reproducible `git archive` hash | §4.2 vendor tarball in `depends/sources`, omit download_path, pin its sha |
| 29 | LOW | Build | EQUIX/hashx cross risk is a PHANTOM (gated on `--enable-gpl`) | §4.0/§4.2 don't pass `--enable-gpl`; assert `nm libtor.a` no EQUIX |
| 30 | LOW | Build | Header-only detection misses stale `libtor.a` | §4.3 file-exists guards in `tor.mk` + p5; optional `AC_CHECK_LIB` on real symbol |
| 31 | LOW | Maint | No `provider_version` in RPC for CVE triage; license-file churn | §3.7 `tor.provider_version`; §4.3 release-checklist license assertion |

---

### Attribution
Tor original: **BSD-3-Clause, © 2001–2019 The Tor Project / Roger Dingledine / Nick Mathewson** —
carry `LICENSE-BSD` + `NOTICE`. dynhost additions + the ported wrapper pattern (from
`github.com/RhettCreighton/zclassic-c`): **Apache-2.0, © 2025–2026 Rhett Creighton** (per-file
`SPDX-License-Identifier: Apache-2.0`). Both referenced from `doc/tor-attribution.md`; release
checklist asserts they are present in the staged tarball and that the precise upstream-stable rebase
tag is recorded (version→CVE mapping).
