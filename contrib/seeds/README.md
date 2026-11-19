### Seeds ###

Utility to generate the fixed seed lists compiled into the client
(see [src/chainparamsseeds.h](/src/chainparamsseeds.h)).

`nodes_main.txt` and `nodes_test.txt` hold one node per line (IPv4, IPv6, `host:port`,
`[ipv6]:port`, a 16-character Tor v2 `.onion`, or the old `0xDDBBCCAA` little-endian
IPv4 form; `#` starts a comment). `generate-seeds.c` (C23, no dependencies) turns them
into the header:

	cc -std=c2x -O2 -Wall -Wextra -o generate-seeds contrib/seeds/generate-seeds.c
	./generate-seeds contrib/seeds > src/chainparamsseeds.h

`test-generate-seeds.sh` checks that the shipped header regenerates byte for byte and that
every address form (and each kind of malformed line) behaves as documented; `make check`
runs it. Tor v3 onions do not fit the 16-byte `SeedSpec6` and are rejected by the generator.

The former `makeseeds.py` filtered Bitcoin seed lists (sipa.be `seeds.txt`, Bitcoin
user-agent and version rules, DNS ASN lookups); it had no use for this network and was removed.
