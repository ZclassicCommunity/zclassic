TOR SUPPORT IN ZCASH
====================

This document has been relocated to https://zcash.readthedocs.io/en/latest/rtd_pages/tor.html

The source for this document is available at https://gitlab.com/zcash-docs/zcash-docs/blob/master/source/rtd_pages/tor.rst
EMBEDDED TOR (ZCLASSIC, COMPILED IN, OFF UNLESS ASKED FOR)
===========================================================

Release builds carry their own Tor: depends builds it for linux, mingw32 and
darwin hosts (leave it out with `NO_EMBEDDED_TOR=1`), and `./configure`
links it when depends provided it (`--with-embedded-tor=yes` fails when it is
missing, `--without-embedded-tor` leaves it out). It is off unless asked for:

    zclassicd -embeddedtor=1 -onlynet=onion -bind=127.0.0.1

- Tor's state is in `<datadir>/tor`. Its SOCKS and control ports are loopback
  ports chosen at start (no fixed 9050/9051); the control port uses cookie
  authentication.
- .onion peers are reached through it, and the node's own v3 onion service
  for the P2P port is created from `<datadir>/onion_v3_private_key` (mode
  0600) and announced as a local address.
- With `-onlynet=onion` and no `-proxy`, host names (DNS seeds, `-addnode`,
  `-seednode`, `-connect`) are handed to Tor and never to the system resolver.
- `-embeddedtormode=child` (default on Linux) runs Tor as a separate process, so a
  Tor bug cannot touch the process that holds the wallet and a Tor crash costs only
  the onion side; `-embeddedtormode=inprocess` (default elsewhere, where the
  binary cannot re-launch itself) runs Tor on a thread of zclassicd.
- If Tor cannot be started the node refuses to start.
- Fail-soft restart: if Tor exits later (crash, OOM kill of the child, a port
  clash) the node keeps running, validating and serving its clearnet peers.
  Tor is stopped and started again in place after 5 s, 15 s, 45 s, 135 s,
  then every 300 s; a run of 30 s resets the delay to 5 s. The log gets one
  line, `tor: embedded Tor stopped (fault=<token>); restarting in <n>s, node
  keeps running`, with a fixed token read from the tail of Tor's log
  (`exited`, `port_in_use`, `config_invalid`, `datadir`). In inprocess mode
  Tor shares libevent and OpenSSL state with the node, so it is restarted at
  most 3 times per process, then given up (`failed:start_limit`) until the
  node is restarted; it is also given up at once if an in-process Tor does
  not stop within 15 s, so two never run side by side. Child mode has no
  limit.
- While Tor is down the proxies it served (onion, and on an onion-only node
  also IPv4, IPv6 and host names) point at a fence (127.0.0.1 port 0) that
  the node refuses to connect to before opening any socket: those
  connections fail closed, nothing goes out in clear, and no local process
  can stand in for the old SOCKS port, whatever low ports the OS lets
  unprivileged processes bind (Windows, macOS, containers). An onion-only
  node therefore has no peers until Tor is back. The control
  client waits for the embedded Tor and never falls back to another Tor on
  the default control port. After a restart the proxies move to the new
  SOCKS port, the control client reconnects to the new control port at once
  and re-creates the onion service from `<datadir>/onion_v3_private_key`, so
  the onion address is unchanged.
- A shutdown that arrives while a restart is starting Tor waits for that
  start to finish or time out (at most 30 s) before the node exits.
- `getnetworkinfo` has a `torstatus` field when `-embeddedtor` is on:
  `running`, `restarting`, or `failed:<token>`.

Details: `src/c23/tor/WIRING.md`, `src/c23/tor/README.md`,
`doc/tor-provenance.md`.

With or without embedded Tor, the onion key file is now written owner-only,
and the onion proxy is taken from the running Tor (`GETINFO
net/listeners/socks`) instead of assuming 127.0.0.1:9050.

ONION ADDRESS GOSSIP (ADDRV2, A SUBSET OF BIP155)
=================================================

So that nodes can find each other over Tor without a fixed list, the node
speaks the Tor v3 part of BIP155. Nothing here is consensus, and nothing
changes for peers that do not know it.

Wire
----

- After a peer's `version`, and before our `verack`, we send `sendaddrv2`
  (empty). Older zclassicd and Z23 ignore an unknown command after `version`
  (zclassicd: `ProcessMessage` logs "Unknown command" under `-debug=net` and
  carries on; Z23: `msg_dispatch_popped_message` only disconnects an unknown
  command received before `version`), so the protocol version is not bumped.
- A peer that sent `sendaddrv2` (honoured only between its `version` and its
  `verack`) is sent `addrv2` instead of `addr`: per entry time (u32), services
  (compact size), network id, address (compact size length + bytes), port
  (u16, big endian); at most 1000 entries and 512 bytes per address. Network
  ids: IPV4 (1, 4 bytes), IPV6 (2, 16), TORV2 (3, 10, ignored), TORV3 (4, 32).
  A known id with the wrong length fails the message (reject, no ban score);
  unknown ids (I2P, CJDNS, later ones) are skipped; more than 1000 entries
  scores 20 like `addr`.
- Every other peer gets exactly the legacy `addr` stream, byte for byte; a
  Tor v3 address is never put in it. `addrv2` from a peer that did not
  negotiate it is ignored without a ban score, as in Bitcoin Core.

Storage
-------

`peers.dat` is unchanged, so it stays readable by beta 12 and older (their
reader does not refuse an unknown layout, it would misparse 32-byte entries
instead, so a format bump is not safe for a downgrade). The Tor v3 addresses
live in a second address table, kept only in memory and in
`<datadir>/onion_peers.dat` (own magic, version, checksum), created once an
onion address has been learned and never opened by an older node. The same
bucket rules apply: group is `NET_ONION` plus the leading bits of the key,
the source group is the peer that told us (its v3 address, its clearnet
address, or 127.0.0.1 for a peer that came in through our onion service, so
all of those share one source group and cannot fill the table together).
The choice of the next candidate is made by bucket (an occupied bucket
first, then an entry in it), so a source group confined to a few buckets
cannot outweigh the others by its number of entries, and a peer may add
only a rationed number of v3 addresses it was not asked for (a token
bucket: 100 to start, one more every 10 s, at most 1000; the answer to our
own `getaddr` is not rationed).
Addresses are stored only while the onion network is reachable (a Tor proxy
is set and `-onlynet` allows it).

Self-advertisement and privacy
------------------------------

- Our onion address is sent only to peers on the onion side: peers we
  reached through the Tor proxy, and peers that reached us through the onion
  service, and only to those that negotiated `addrv2`. It is never sent to a
  clearnet peer, in `addr`, `addrv2`, or in `version`.
- Our clearnet addresses are never sent to an onion peer (they get the
  unroutable 0.0.0.0 in `version`, no self-advertisement, and the address
  they report for us is not used for discovery).
- Nothing is advertised before the service is up: the address enters the
  local address table only after `ADD_ONION` succeeded (or `-externalip` was
  given). It is queued from the message handler on its next pass.
- To tell onion inbound peers from local ones, a node that runs an onion
  service through the embedded Tor or a `-torcontrol` on this machine
  (loopback address) gets a second loopback listener, the P2P port + 1, and
  `ADD_ONION` points at it (`-bind=<addr>=onion` chooses another address and
  port; it can also be written in `zclassic.conf`). Connections accepted
  there are onion peers. Without it (a Tor found at the default control
  port, a `-torcontrol` on another host or in another network namespace,
  whose Tor could not reach a loopback port of this process, or a failed
  bind) the service targets the P2P port as before and such peers are not
  recognised. A peer on the main listener that comes from a loopback or
  unroutable address while an onion address is known is then of unknown side:
  it gets no local address at all (0.0.0.0 in `version`, no self-advertisement),
  so the clearnet address of this machine is never linked to the onion service.
- Relay of a learned v3 address goes only to addrv2 peers. `getaddr` answers
  include the v3 entries for every peer that negotiated `addrv2`, clearnet
  or onion, as Core's answer spans all networks the peer parses: the entries
  are public by nature and a clearnet node with a Tor proxy can use them. A
  legacy peer gets the legacy answer.

Dialling
--------

An onion-only node (`-onlynet=onion`) picks its next outbound candidate from
the onion table when it has entries; a node with several networks one time
in four, and whenever its clearnet table is empty. The usual checks apply
(limited network, local address, one outbound per group), so an onion-only
node never dials a clearnet address and a node without a Tor proxy never
selects an onion one.

Tests: `src/test/addrv2_tests.cpp`, `src/c23/tor/addrv2gossip.sh` (A and B
know each other, C knows only A and learns B by gossip; a clearnet link to A
is never sent A's onion; beta 12 loads the resulting peers.dat),
`src/c23/tor/oldpeer.sh` (a beta 12 peer next to the base and the new node).

Not done (follow-ups for an onion service on by default)
--------------------------------------------------------

- Tor stays off unless `-embeddedtor=1` is given. Fail-soft restart (see
  above, tests `src/test/torwatch_tests.cpp`, `qa/rpc-tests/tor_restart.sh`)
  was the prerequisite for turning it on by default; that decision is still
  open.
- Platform defaults: which of `inprocess` and `child` Windows and macOS use,
  the datadir `tor/` layout on a read-only or shared datadir, and the first-run
  prompt in the GUI.
- A `getnodeaddresses`-style RPC and a `getpeerinfo` field for the onion
  side, so the onion table is observable without reading logs.
- Bucket sizing of the onion table (it uses the same 1024 x 64 as the main
  table, much more than the onion network needs).
