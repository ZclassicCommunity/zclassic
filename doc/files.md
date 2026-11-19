# Data Directory Files

This document has been relocated to https://zcash.readthedocs.io/en/latest/rtd_pages/files.html

The source for this document is available at https://gitlab.com/zcash-docs/zcash-docs/blob/master/source/rtd_pages/files.rst

## Peer state files

`peers.dat` holds the learned peer addresses and `banlist.dat` the banned peers and subnets.
Both are written to a temporary name, committed and renamed into place, so a crash leaves
the old file. Neither can stop the node from starting.

- `banlist.dat`: magic `ZBAN`, version, network magic, entries (subnet, ban-until time),
  checksum. A ban made by `setban` or for misbehaviour is written within about 5 seconds
  and at shutdown, and reloaded at start-up (bans that have ended are dropped). A file that
  fails any check, or belongs to another network, is moved to `banlist.dat.bad` and the node
  starts with an empty list. Older releases ignore the file.
- `peers.dat`: format unchanged, older releases read it. If it fails its checksum or cannot
  be decoded, it is moved to `peers.dat.corrupt` and the complete address records it still
  holds are kept (at most 5000). Those come back as "new" addresses: the tried flag and
  success time of a file of unknown integrity are not trusted. A file of another network is
  left in place and not salvaged. The log line `peers.dat: ..., salvaged N of M addresses`
  reports the outcome.
