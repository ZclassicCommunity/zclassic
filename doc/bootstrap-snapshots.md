# Bootstrap Snapshots

ZClassic can bootstrap a new node faster by importing `blocks/` and
`chainstate/` from a trusted, already-synced node before the databases are
opened. This is native daemon startup behavior.

The imported snapshot contains only:

- `blocks/`
- `chainstate/`

It must not contain `wallet.dat`, `zclassic.conf`, peers, logs, or wallet
database files.

## Choosing how to sync: full validation vs. fast sync

ZClassic gives you two ways to bring a fresh node up to the chain tip. **You
never have to trust anyone — full validation from genesis is always available**
and is the recovery path if a bootstrap peer (including the project's own) is
ever compromised.

### Option A — Full validation (trustless, zero trust in any peer)

Sync the entire chain from genesis, validating every block yourself. This is the
most secure option and trusts no snapshot, no serving peer, and no project
infrastructure — only the consensus rules compiled into the open-source binary.

```bash
./src/zclassicd -datadir="$HOME/.zclassic" -bootstrap=0
```

`-bootstrap=0` disables the snapshot/param fast-sync entirely; the node fetches
zk-SNARK params the classic way (`zcutil/fetch-params.sh`) and performs a normal
initial block download, checking proof-of-work and re-deriving the UTXO set from
genesis. Slower, but it depends on no one.

**If you fast-synced and later want to verify it yourself**, re-derive the whole
chainstate from the block data on the next start:

```bash
./src/zclassicd -checkblocks=0 -checklevel=4   # verify every block at startup
# or, to rebuild blocks + chainstate from scratch:
./src/zclassicd -reindex
```

`-checkblocks=0` re-verifies *all* blocks (default only re-checks the most recent
`288`), and `-checklevel=4` is the most thorough level. This turns a fast-synced
node into a fully self-verified one without re-downloading the chain.

### Option B — Fast sync (faster start, with a trust note)

Import a prepared chain snapshot, then sync forward normally. This is the default
on a fresh datadir. It is much faster, but read the trust model below: until the
snapshot carries a compiled chainstate commitment (see *Roadmap to trustless
fast sync*), the serving peer is trusted for the contents of the imported UTXO
set. Use a peer you trust, or use Option A.

```bash
./src/zclassicd                                   # default: fast-sync from a bootstrap peer
./src/zclassicd -bootstrappeer=192.0.2.10:8033    # choose the peer explicitly
./src/zclassicd -bootstrapdatadir=/path/to/snap   # import from a local prepared dir
```

The default fast-sync is best-effort: if no bootstrap peer is reachable the node
silently falls back to Option A (normal sync from genesis), so a compromised or
offline bootstrap peer can never *prevent* you from syncing trustlessly.

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

### Fast-sync trust model: snapshot peers are trusted like the binary

> **Important:** The post-import `VerifyDB` pass only re-checks the most recent
> blocks. UTXOs in the imported `chainstate/` that are deeper than `-checkblocks`
> (default `288`) blocks below the tip are **not** re-derived from block data —
> they are trusted as-is from the snapshot peer.

Because of this, **a snapshot peer must be trusted at the same level as the
binary itself.** A malicious snapshot could embed spendable but bogus UTXOs that
are older than the `-checkblocks` horizon, and they would pass validation: the
verification pass never revisits chainstate entries below that depth, so it would
not detect them. The per-file SHA-256 checks only confirm that you received the
bytes the serving peer advertised — they say nothing about whether those bytes
describe a legitimate chain history.

A cautious operator can reduce this exposure when bootstrapping for the first
time by:

- raising `-checkblocks` (up to `0`, which checks all blocks) and/or
  `-checklevel` so more of the imported chainstate is re-verified against block
  data, at the cost of a longer startup; or
- only bootstrapping from a peer or operator they trust to have produced the
  snapshot honestly; or
- simply using full validation (`-bootstrap=0`), which trusts no one.

### No single point of trust

The project's bootstrap peer is a *convenience*, never a *requirement*. By
design:

- **Full validation (`-bootstrap=0`) is always available** and trusts only the
  open-source binary. If the project's bootstrap IP were ever compromised, every
  user can still sync the chain trustlessly — nothing about the security of the
  network depends on that server being honest.
- The default fast-sync **falls back to full validation** if the bootstrap peer
  is unreachable, so a compromised peer cannot strand a fresh node.
- A fast-synced node can be **converted to fully self-verified after the fact**
  with `-checkblocks=0 -checklevel=4` or `-reindex` (see *Choosing how to sync*).

### Roadmap to trustless fast sync

The goal is for fast sync to require trusting *no* peer — only the
publicly-reviewable binary, the same as full validation. Two pieces get us
there:

1. **Compiled chainstate commitment.** In addition to the block hash, the binary
   pins a hash of the entire UTXO set at the anchor height (the same
   `hash_serialized` value reported by the `gettxoutsetinfo` RPC). After import,
   the node recomputes this hash over the imported `chainstate/` and **rejects
   the snapshot if it does not match.** A malicious or compromised peer then
   cannot substitute a forged UTXO set: the bytes either reproduce the compiled
   commitment or the snapshot is thrown away. This reduces fast-sync trust to the
   binary itself — exactly the assumeutxo model. The commitment field exists in
   the anchor; once a value is compiled in for a release, this check activates
   automatically (it is skipped while the field is unset, preserving today's
   behavior).

   To generate the value for a release, load the prepared snapshot at the anchor
   height and read `gettxoutsetinfo`'s `hash_serialized`; that string is the
   compiled commitment.

2. **Decentralized peer discovery.** Rather than depending on a hardcoded IP, a
   fresh node can discover other nodes advertising the `NODE_BOOTSTRAP` service
   bit through the normal DNS seeds and `getaddr` peer exchange, and fast-sync
   from any of them. Combined with the compiled commitment above, this is safe
   even from an untrusted peer, because the content is verified against the
   binary regardless of *who* served it. Multiple `-bootstrappeer` entries are
   accepted and tried in order, and anyone can run a serving node
   (`-bootstrapserve`) to add capacity to the network.

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

## Zcash Parameters Over P2P

A fresh node needs the zk-SNARK parameter files (`sapling-*.params`,
`sprout-groth16.params`, and the sprout keys) before it can start. Instead of
running `zcutil/fetch-params.sh` against an external download, a node started
with `-bootstrappeer=<host>` automatically fetches any missing parameters from
that peer over the P2P protocol, then continues with the snapshot import.

The expected SHA-256 of every parameter file is compiled into the binary (the
same hashes enforced at startup), so the serving peer is untrusted: only file
content matching a compiled hash is installed. A serving node (`-bootstrapserve`)
answers `getbspman`/`getbspchk` from its own params directory, subject to the
same per-IP serve quota as snapshots.

## Serving Limits (Bandwidth Abuse)

A serving node caps how much one IP can download per rolling 24-hour window:

- `-bootstrapservemaxbytesperday=<n>` — bytes one address may download before it
  is throttled. Default `107374182400` (100 GiB), which still allows several
  full snapshot downloads per IP per day. `0` disables the cap.
- `-bootstrapservethrottlekbps=<n>` — the rate (KiB/s) to serve an address that
  is over its daily cap. Default `1024` (1 MiB/s). `0` stops serving that
  address until its window resets, instead of slowing it down.

Throttling is enforced without blocking the network thread: an over-cap address
is simply served at most one chunk per scheduled interval, so other peers are
unaffected. The cap is tracked per IP, so opening multiple connections from one
address does not raise its limit. Whitelisted peers (`-whitelist`) bypass the
quota.

For public serving, prefer a stopped-node copy or filesystem snapshot owned by a
different administrative user. The daemon preflights the manifest before
advertising `NODE_BOOTSTRAP` and refuses chunk reads if a listed file changes
size or modification time after the manifest is built.
