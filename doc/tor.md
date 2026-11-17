TOR SUPPORT IN ZCASH
====================

This document has been relocated to https://zcash.readthedocs.io/en/latest/rtd_pages/tor.html

The source for this document is available at https://gitlab.com/zcash-docs/zcash-docs/blob/master/source/rtd_pages/tor.rst
EMBEDDED TOR (ZCLASSIC, OPT-IN)
===============================

A zclassicd configured with `--with-embedded-tor` (depends built with
`WITH_EMBEDDED_TOR=1`) carries its own Tor. It is off unless asked for:

    zclassicd -embeddedtor=1 -onlynet=onion -bind=127.0.0.1

- Tor's state is in `<datadir>/tor`. Its SOCKS and control ports are loopback
  ports chosen at start (no fixed 9050/9051); the control port uses cookie
  authentication.
- .onion peers are reached through it, and the node's own v3 onion service
  for the P2P port is created from `<datadir>/onion_v3_private_key` (mode
  0600) and announced as a local address.
- With `-onlynet=onion` and no `-proxy`, host names (DNS seeds, `-addnode`,
  `-seednode`, `-connect`) are handed to Tor and never to the system resolver.
- `-embeddedtormode=inprocess` (default) runs Tor on a thread of zclassicd;
  `-embeddedtormode=child` runs it as a separate process.
- If Tor cannot be started the node refuses to start.

Details: `src/c23/tor/WIRING.md`, `src/c23/tor/README.md`,
`doc/tor-provenance.md`.

With or without embedded Tor, the onion key file is now written owner-only,
and the onion proxy is taken from the running Tor (`GETINFO
net/listeners/socks`) instead of assuming 127.0.0.1:9050.
