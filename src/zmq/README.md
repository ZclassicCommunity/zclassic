# src/zmq: ZeroMQ notifications

The optional publish-only ZeroMQ interface that announces new blocks and transactions to local subscribers; it exists only in builds with `ENABLE_ZMQ`.

## What lives here

- `zmqnotificationinterface.cpp`, `zmqnotificationinterface.h`: `CZMQNotificationInterface`, a `CValidationInterface` (`SyncTransaction`, `UpdatedBlockTip`, `BlockChecked`) created by `CreateWithArguments` from the `-zmqpub*` options.
- `zmqabstractnotifier.cpp`, `zmqabstractnotifier.h`: `CZMQAbstractNotifier` and its factory.
- `zmqpublishnotifier.cpp`, `zmqpublishnotifier.h`: the publishers for hash and raw blocks and transactions; each message is multipart (command, data, per-notifier sequence number).
- `zmqconfig.h`: the `ENABLE_ZMQ` guard and `zmqError`.

Options: `-zmqpubhashblock`, `-zmqpubhashtx`, `-zmqpubrawblock`, `-zmqpubrawtx`, each with an address (see `src/init.cpp`).

## Traps

- The channel is read-only, unauthenticated and best effort; a subscriber must validate what it receives, because data may be stale or incomplete.
- A block replayed at start-up after a crash must still produce one notification per block; `qa/rpc-tests/replay_blocknotify.sh` covers `-blocknotify` and the ZMQ hash notification.
- Builds without libzmq compile none of this; keep every use behind `ENABLE_ZMQ`.

## Tests

CI step `zmq-sub-example` runs `contrib/zmq/test-zmq-sub.sh` against the subscriber example `contrib/zmq/zmq_sub.c`; `qa/rpc-tests/replay_blocknotify.sh` covers replayed blocks. List steps with `zcutil/bin/zcl-dev t-list`.

## Related

Manual: [doc/zmq.md](../../doc/zmq.md). Rules: [../AGENTS.md](../AGENTS.md).
