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

