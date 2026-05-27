# Bootstrap Snapshots

ZClassic can bootstrap a new node faster by importing `blocks/` and
`chainstate/` from a trusted, already-synced node before the databases are
opened. This is native daemon startup behavior.

The imported snapshot contains only:

- `blocks/`
- `chainstate/`

It must not contain `wallet.dat`, `zclassic.conf`, peers, logs, or wallet
database files.

### Match the snapshot's `-txindex` setting

The `chainstate/` database records whether the source node was built with
`-txindex`. The receiving node must start with the **same** `-txindex` setting
as the node that produced the snapshot. If they differ, the daemon refuses to
open the imported database and exits with:

```text
You need to rebuild the database using -reindex to change -txindex.
```

If you do not know how the snapshot was produced, prefer matching the serving
node. ZClassic infrastructure snapshots are typically built with `txindex=1`,
so set `txindex=1` in the receiving node's `zclassic.conf` (or pass
`-txindex`) before importing. Changing `-txindex` afterwards requires a full
`-reindex`, which discards the speed benefit of the snapshot.

## Import From A Prepared Datadir

Create the source from a stopped node or a filesystem snapshot of a synced node.
Copying LevelDB while `zclassicd` is writing can produce an unusable snapshot.

On the receiving node, start with:

```bash
./src/zclassicd \
    -datadir="$HOME/.zclassic" \
    -bootstrapdatadir=/path/to/prepared-snapshot
```

The daemon copies the source into a staging directory first. It refuses to
overwrite existing `blocks/` or `chainstate/` unless `-bootstrapforce` is set:

```bash
./src/zclassicd \
    -datadir="$HOME/.zclassic" \
    -bootstrapdatadir=/path/to/prepared-snapshot \
    -bootstrapforce
```

With `-bootstrapforce`, existing chain data is moved into
`bootstrap-backup-<timestamp>/` before the staged import is installed. Wallet
files and configuration files are not moved.

The daemon rejects unsafe source entries such as symlinks, special files, and
anything other than regular files and directories under `blocks/` and
`chainstate/`.

## Anchor

The binary includes a fast-sync anchor tied to the mainnet checkpoint at height
`2879438`:

```text
000007e8fccb9e4831c7d7376a283b016ead6166491f951f4f083dbe366992b2
```

At startup the daemon verifies that this anchor is present in the checkpoint
set and that its SHA-256 and SHA3-256 anchor digests match the compiled values.
After importing the files, normal database verification and peer sync resume
from the snapshot tip.

Treat snapshots as trusted input. The compiled anchor prevents importing a
snapshot for the wrong chain point, and the receiver verifies every file hash
advertised by the serving peer, but the serving peer still chooses the snapshot
contents. Use `-bootstrappeer` only with a peer you control or otherwise trust.

## Network Service Direction

This branch has the first node-to-node network pieces:

- `NODE_BOOTSTRAP` service advertisement.
- `-bootstrapserve` and `-bootstrapsourcedir=<dir>` startup options.
- `getbsman` / `bsman` P2P messages for requesting and serving the snapshot
  manifest tied to the compiled anchor.
- `getbschk` / `bschk` P2P messages for bounded chunk reads from files listed
  in the manifest.
- `-bootstrappeer=<host>` client option for a fresh datadir. It connects to one
  `NODE_BOOTSTRAP` peer before block databases are opened, validates the
  manifest, downloads chunks into staging, verifies per-file SHA-256 hashes,
  and installs only `blocks/` and `chainstate/`.

`-bootstrappeer` accepts either `host` or `host:port`. When no port is given it
uses the network default P2P port (mainnet `8033`). If the serving node listens
on a non-default port, give it explicitly, e.g.
`-bootstrappeer=192.0.2.10:8033`.

Start a serving node with:

```bash
./src/zclassicd \
    -bootstrapserve \
    -bootstrapsourcedir=/path/to/prepared-snapshot
```

Download progress is written to the log as it runs. The daemon does not write
`debug.log` by default, so pass `-printtoconsole` or `-debuglogfile` to watch
the transfer:

```bash
./src/zclassicd \
    -datadir="$HOME/.zclassic-fresh" \
    -bootstrappeer=192.0.2.10:8033 \
    -printtoconsole
```

The node-to-node path does not install chain files through normal block relay
after LevelDB is open. It runs as a pre-database bootstrap phase:

- A serving node exposes an immutable prepared snapshot directory.
- A bootstrapping node requests a manifest for the compiled anchor. The
  manifest lists safe relative files under `blocks/` and `chainstate/`, with
  file sizes and SHA-256 hashes.
- The receiver downloads fixed-size 512 KiB chunks into a staging directory and
  verifies every completed file against the manifest SHA-256 hash.
- The receiver installs only into a fresh chain datadir. Peer bootstrap never
  overwrites or backs up existing `blocks/`, `chainstate/`, `bootstrap.dat`, or
  legacy root `blk*.dat` files.
- After install, the daemon opens the databases and uses normal validation from
  that point forward.

This follows the same broad model as Bitcoin AssumeUTXO, Geth snap sync, Cosmos
state sync, and Mithril-certified snapshots: fast state acquisition first,
normal validation after the trusted hash point.

For public serving, prefer a stopped-node copy or filesystem snapshot owned by a
different administrative user. The daemon preflights the manifest before
advertising `NODE_BOOTSTRAP` and refuses chunk reads if a listed file changes
size or modification time after the manifest is built.
