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
  Tor bug cannot touch the process that holds the wallet and a Tor crash becomes a
  clean shutdown; `-embeddedtormode=inprocess` (default elsewhere, where the
  binary cannot re-launch itself) runs Tor on a thread of zclassicd.
- If Tor cannot be started the node refuses to start.

Details: `src/c23/tor/WIRING.md`, `src/c23/tor/README.md`,
`doc/tor-provenance.md`.

With or without embedded Tor, the onion key file is now written owner-only,
and the onion proxy is taken from the running Tor (`GETINFO
net/listeners/socks`) instead of assuming 127.0.0.1:9050.
