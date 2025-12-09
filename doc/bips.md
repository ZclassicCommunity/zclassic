BIPs that are implemented by Zclassic (up-to-date up to **v2.1.2**):

* Numerous historic BIPs were present in **v1.0.0** at launch; see [the protocol spec](https://github.com/zcash/zips/blob/master/protocol/protocol.pdf) for details.
* [`BIP 111`](https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki): `NODE_BLOOM` service bit added, but only enforced for peer versions `>=170004` as of **v1.1.0** ([PR #2814](https://github.com/zcash/zcash/pull/2814)).
* [`BIP 155`](https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki): `addrv2` message support for Tor v3 (.onion) addresses, added in **v2.1.2** on branch `feature/bip-155`. Protocol version 170012. See [BIP-155-IMPLEMENTATION-PLAN.md](BIP-155-IMPLEMENTATION-PLAN.md) for details.
