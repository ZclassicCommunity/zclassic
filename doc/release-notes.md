(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

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
will fail to open the database. `-txindex` remains incompatible with `-prune`.

