# Bootstrap snapshot protocol and resumable download

How a fresh node fetches the chain snapshot from a bootstrap peer (`src/bootstrap.cpp`,
`src/bootstrap_resume.{h,cpp}`, `src/init.cpp`), what is trusted, and how an interrupted
download is continued.

## Wire protocol (unchanged by resumable download)

Bootstrap peers are ordinary nodes that advertise service bit `NODE_BOOTSTRAP` (`1 << 24`) and
run with `-bootstrapserve`. They listen on the normal P2P port (8035 for the public bootstrap
nodes). The client opens a plain TCP connection and speaks the usual framing (magic, 12-byte
command, length, checksum) outside the `CNode` machinery:

| Step | Client sends | Server answers |
| --- | --- | --- |
| handshake | `version` (services, `NODE_BOOTSTRAP` in addrYou) | `version`, then `verack` after the client's `verack` |
| manifest | `getbsman` (empty) | `bsman` (the manifest) |
| chunk | `getbschk` {file index, offset, length} | `bschk` {file index, offset, data} or `reject` |

* **Manifest** (`CBootstrapSnapshotManifest`): version 1 (compiled-anchor snapshot), 2 (a peer's
  own self-snapshot, `-bootstrapmode=trustless` only, carries its chainstate commitment) or 3
  (anchor-pinned chainstate plus a growing block bundle `anchor+1..nBlockTipHeight`); network,
  anchor height/hash, the compiled anchor string hashes, total bytes, `nChunkSize` (always
  1 MiB) and the file list: path (under `blocks/` or `chainstate/`), size, SHA-256 of the whole
  file. The server builds it from every regular file of its serve directory, `chainstate/`
  first, then `blocks/`, each lexicographically.
* **Chunks** are 1 MiB, requested at offsets that are multiples of 1 MiB with length
  `min(1 MiB, size - offset)`; the server rejects anything else, and a request at *any* aligned
  offset of any file is answered. That is what makes continuing inside a file possible with
  servers that have been deployed for months.
* **Pipelining**: the client keeps 16 chunk requests in flight per connection (the server queues
  at most 32 per peer). Replies come back in request order.
* **Parallelism**: `-bootstrapstreams` (default 4, max 16) connections to the same peer, each
  doing its own handshake and fetching the manifest again; a stream whose manifest is not
  byte-identical to the validated master manifest is refused.
* **Timeouts**: 60 s per message; a stream that moves less than 32 KiB/s over a 60 s window is
  dropped.
* **Server limits** (all optional, whitelisted peers bypass them): 100 GiB per address per 24 h
  then 1 MiB/s (`-bootstrapservemaxbytesperday`, `-bootstrapservethrottlekbps`);
  `-bootstrapservemaxtotalkbps` (aggregate rate, 1 s window); `-bootstrapservemaxpeers`
  (connections served within the last second, so a 4-stream client uses 4); and the node's
  normal inbound-connection limit with its eviction policy, which prefers to drop the network
  group that holds the most connections: the four streams of one client.

## What is trusted

Nothing the peer says is trusted until the end.

1. `ValidateBootstrapSnapshotManifest` checks the manifest shape (network, anchor identity
   against the compiled anchors, safe relative paths, no duplicates, sizes add up, caps of
   32 GiB per file and 200 GiB in total).
2. Every file is verified against its manifest SHA-256 when its last chunk arrives, and renamed
   from `<file>.part` to its final name only after `fsync` + a matching hash.
3. After the files are moved into the datadir, `VerifyImportedBootstrapAnchor` (init.cpp)
   checks the imported tip against the compiled anchor and recomputes the chainstate
   commitment (`hash_serialized`) against the compiled value; a mismatch deletes the import.
   A v3 block bundle is validated by the node's own forward block validation. The compiled
   commitment is what makes the per-file hashes (which the peer chose) irrelevant to safety.

## Promotion

`BootstrapFromPeer`: connect, handshake, fetch and validate the manifest, pick the staging
directory, download, (resumed runs only) re-verify every staged file, optionally retain an
auto-serve copy, write the durable anchor-pending marker, then rename `staging/blocks` and
`staging/chainstate` into the datadir and remove the staging directory. The next stage of init
opens the databases and runs the commitment check above.

## Resuming after an interruption

Staging directory: `<datadir>/bootstrap-peer-staging-<16 hex>`, where the name is derived from
the snapshot *anchor* (network, anchor height and hash, the compiled anchor string hashes, and
for a v2 self-snapshot its own commitment) and **not** from the file list or the v3 bundle tip,
because a growing server changes those continuously. The directory holds a marker
`.z23-staging` (anchor identity and the manifest id the directory was last used with).

On start, with the manifest the peer serves now:

| Staging directory | Action |
| --- | --- |
| absent | create it and write the marker |
| marker missing/garbled, or another anchor | delete it, start clean |
| same anchor, same manifest | reuse |
| same anchor, different manifest (server grew or rebuilt) | reuse; every file is judged against the *new* manifest |

Every other `bootstrap-peer-staging-*` directory (older per-epoch names, other snapshots) is
deleted. Reuse means `BootstrapResumeScan` classifies each manifest file:

* final file with the right size **and** SHA-256: kept (hashing runs on 4 threads; on the
  test host 3.00 GiB were re-verified in 1.4 s from the page cache, and 10.43 GiB in 2.7 s);
* final file with the wrong size or hash: deleted, fetched again;
* `<file>.part`: continued from its last whole 1 MiB chunk (`BootstrapResumeOffset`; a torn
  trailing chunk is fetched again, a `.part` as long as the file still re-requests its last
  chunk so that it passes through the normal verify-and-rename path; shorter than a chunk or
  longer than the file: deleted);
* anything the manifest does not name: deleted. Symlinks, special files and a directory where a
  manifest file belongs are deleted too (a symlink is unlinked, never followed, and its target is
  left alone), so a damaged or planted entry costs a re-fetch of that file instead of failing
  every later attempt.

A resumed `.part` is only ever as trusted as a freshly downloaded file: the whole-file hash
decides. If it does not match, the file is deleted and fetched from byte 0 (a second failure
means the peer serves bytes that contradict its own manifest and ends the attempt).
Runs that reused staged files verify them once more right before the install.

### Crash safety

A file counts as complete only after `fsync` + hash verification + atomic rename; `.part` files
are `fsync`ed every 16 chunks. Whatever instant the process dies at, the next start
re-derives the state from disk and re-verifies it, so no marker beyond the staging marker is
needed: a half-written marker only costs a clean start, a half-renamed file does not exist, a
torn `.part` fails its hash and is fetched again. The install step keeps its existing recovery
(the durable pending marker plus the "marker without chain data" rule in init.cpp).

### Streams

Files are claimed lazily from one shared queue (largest first), so the streams balance
themselves. A stream that fails hands its unfinished files back (their `.part` keeps what was
written), waits 1 s doubling to 30 s with +-25 % jitter and reconnects; the others never stop.
There is no demotion to fewer streams. Fatal conditions end the attempt (staging is kept):
local I/O errors, a file failing its hash twice, a changed manifest, shutdown, five minutes
without a byte, a whole-attempt rate (all streams together) under 32 KiB/s over five
minutes, or three failures in a row before a single byte arrived while no stream had
connected or been served (a dead peer: fail over to the next one quickly; a server that is
full and refuses one stream while the others are served is not a dead peer, that stream just
keeps backing off). A blocked receive notices shutdown or the end of the attempt within a
quarter of a second, and one message cannot take longer than its timeout plus the time its
bytes need at 16 KiB/s, so a peer that trickles bytes cannot hold the attempt. A peer given
as a host name behind a name proxy (`-proxy`, embedded Tor) is reconnected by name for every
stream, as for the first connection. The init loop then tries the next attempt or peer,
which resumes from the same staging directory. The kept directory is removed when bootstrap
is turned off (`-bootstrap=0`) or conflicts with `-reindex`, `-reindex-chainstate` or
`-loadblock`, when stub recovery has used up its attempts, and once the chain is real; when a
run falls back to normal sync the log names the kept directory.

Before this change the downloader aborted all streams on the first stream error and retried
over a *single* connection for the rest of the run (`BootstrapFromPeer` fell back to
`DownloadBootstrapSnapshot` on one socket): that, not server-side slot accounting (the
`-bootstrapservemaxpeers` accounting ages out a closed connection after one second), is why
a single timeout cost a third of the throughput.

## After the import

A v3 snapshot bundles blocks above the anchor. `LoadBlockIndexDB` loads their headers (the best
known header is the bundle tip), but `RewindBlockIndex` used to reset the best header to the
active tip, which is the anchor at that point, so `getblockchaininfo` showed `headers` at the
anchor height while the bundled blocks were being connected. It now resets the best header only
when that header is one of the entries it deletes, and `getblockchaininfo` never reports fewer
`headers` than `blocks`. Out-of-order blocks beyond the tip are still parked and unparked
exactly as before, but the "deep reorg" log lines for blocks that fork off at the tip itself
(no reorg involved) are debug-level (`-debug=park`).

## Numbers

Sizes are printed in binary units (`GiB`, `MiB/s`): the 11.2 GB (decimal) snapshot is
10.43 GiB. The wallet parses `Bootstrap snapshot: NN%  X / Y GiB  Z MiB/s  (N streams)` and
still accepts the old `GB` / `MB/s` spelling (`wallet/src/bootstrapprogress.h`).
