(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Peer-aware auto-finalization (reduced chain-split risk)
-------------------------------------------------------

ZClassic auto-finalizes a block once it is `-maxreorgdepth` (default 10) deep and a
delay has passed, after which the node refuses any reorg before it. That protects
against deep history rewrites but, on its own, can permanently split the network if a
partition or deep reorg outlasts the delay (each side finalizes a different block and
never reconciles). It is also unsafe for a freshly bootstrapped node, which would
otherwise finalize the chain it just imported from a peer before ever checking it
against the live network.

This release adds **peer-aware finalization** (`-finalizationrequirepeers`, **default
on**): before finalizing a block, a node now requires the live network to corroborate
the chain — at least `-finalizationminpeers` (default 2) independent outbound peers
(distinct address groups) building on it, a live (received this session) best header at
the required depth, and no peer advertising a higher-work chain that forks below it.
If those are not met (a network partition, or being on a minority/forged fork), the
node simply does not finalize and stays a flexible longest-chain follower, so it
converges with the majority instead of splitting. It only ever *delays* finalization —
it never finalizes a block a prior version would not, never changes block validity, and
is fully compatible with peers that do not run it; it is **local policy, not a consensus
change.**

Operator notes: a node with fewer than `-finalizationminpeers` independent outbound
peers will not auto-finalize (it behaves like a plain longest-chain node, which is
safe). `getblockchaininfo` now reports a `finalization_hold` object (and, for
bootstrapped nodes, `bootstrap_validation.tip_hold`) so a sustained hold is visible; a
throttled log warning is emitted while finalization is held. Set
`-finalizationrequirepeers=0` to restore the previous unconditional behavior.

A freshly bootstrapped node additionally holds finalization until the live network
confirms its imported tip (durable across restart), so it can never pin itself to a
bootstrap server's minority/forged fork.

`-txindex` now defaults to on
-----------------------------

The default for `-txindex` has changed from `0` (off) to `1` (on) for all fresh
nodes. A bootstrap snapshot ships a txindex'd `chainstate/`, and the receiving
node must open it with a matching `-txindex` setting; defaulting to on keeps
bootstrap-imported nodes and normally-synced nodes consistent (and avoids a
confusing `You need to rebuild the database using -reindex to change -txindex`
failure for a fresh node that imports a snapshot).

This applies to **every** fresh install, including nodes that never bootstrap
and sync from genesis. The tradeoff is increased default disk usage and write
I/O to maintain the full transaction index. Operators who do not need the
transaction index (used by the `getrawtransaction` RPC) and want the old
behavior can pass `-txindex=0`. Note that a chainstate imported from a ZClassic
bootstrap snapshot is txindex'd, so `-txindex=0` is only appropriate for a node
that syncs from genesis; importing a txindex'd snapshot into a `-txindex=0` node
will fail to open the database. `-txindex` is incompatible with `-prune`: a pruned
node automatically disables the transaction index (it soft-sets `-txindex=0`), and
passing `-prune` together with an explicit `-txindex=1` is rejected at startup.


Automatic download of `zclassic.conf` has been removed
------------------------------------------------------

Previous releases, on a fresh datadir with no configuration file, downloaded a
default `zclassic.conf` over HTTP (from Arweave) during startup. That behavior —
and the bundled HTTP/`libcurl` dependency it relied on — has been removed along
with the old Arweave/HTTP bootstrap. A fresh node now starts with built-in
defaults and never fetches a config file over the network. To customize a node,
create `zclassic.conf` in the datadir yourself (or pass options on the command
line / via `-conf=`); see the example configuration and the `-conf` documentation.



libsnark is gone: Sprout PHGR13 proofs are verified by the C23 core
--------------------------------------------------------------------

The old Sprout JoinSplit proofs (PHGR13, before Sapling) used to be checked with libsnark,
a 19,000-line C++ library that also pulled in libgmp and OpenMP. They are now checked by
the same C23 code that checks Sapling and Sprout-Groth16 proofs. The accept/reject verdict
for every proof is unchanged (see `doc/c23-phgr13.md` for the evidence), and so is the
chain: no consensus rule changed.

What you notice:

- `sprout-proving.key` (910 MB) is no longer needed, downloaded or checked at startup. The
  required parameter files are now about 780 MB instead of 1.7 GB. An existing copy is
  harmless and can be deleted.
- Verification of the pre-Sapling part of the chain is several times faster.
- The binary no longer depends on libgmp or the OpenMP runtime (libgomp).
- A node can no longer *create* a PHGR13 JoinSplit. That is only ever possible on a chain
  that has not activated Sapling (regtest, private test chains); on mainnet nothing changes.
  There the operation fails with "Sprout PHGR13 proofs can no longer be created". Receiving,
  validating and relaying such transactions and blocks works as before.
- The undocumented `-savesproutr1cs` option is removed.


OpenSSL 3.5.9 LTS replaces OpenSSL 1.1.1w
-----------------------------------------

The bundled OpenSSL (used for wallet encryption and by the embedded Tor's TLS) moves
from 1.1.1w, which is out of upstream support, to the 3.5.9 LTS release, still linked
statically and now built with its assembly code. Engines, loadable modules, the legacy
provider and the command-line tools are not built. Encrypted `wallet.dat` files stay
compatible in both directions: a wallet encrypted by an older release unlocks in this one,
and a wallet whose passphrase was changed or whose keys were added here unlocks in an
older release. OpenSSL 3 is licensed under Apache-2.0 (see `THIRD-PARTY-LICENSES`).

RPC tuning errors and the LevelDB file budget
---------------------------------------------

- `-rpcthreads` outside 1..256, `-rpcworkqueue` outside 1..65536 and `-rpcservertimeout`
  outside 1..86400 (including non-numeric values, which parse as 0) now stop start-up with an
  explanatory error. Earlier releases clamped them silently.
- The per-database LevelDB open-file budget now counts each optional index store: one more
  database for `-zslpindex` and one more for `-znamindex` (up to four instead of two). A
  `-dbmaxopenfiles` value above what the file descriptor soft limit allows is lowered to that
  budget with a log warning. This matters mainly on 32-bit POSIX builds with a soft limit of 1024.
- A peer-visible P2P change, not a consensus change: an `inv` or `getdata` entry with an
  unknown type no longer aborts processing of the whole message (formatting it for the log used
  to throw). The unknown entry is ignored and the remaining entries are handled, as in Bitcoin
  Core. Such messages no longer produce a per-message exception line in the log.
