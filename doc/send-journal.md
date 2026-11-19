# Send journal: "send once" for z_sendmany

`z_sendmany "from" [recipients] ( minconf ) ( fee ) ( "idempotency_key" )`

With a key (1 to 128 characters of `[A-Za-z0-9._:-]`) a repeated call with the same request returns the
same operation id and never builds a second transaction, also after a restart of the node. The same
key with another request is the error `idempotency key reused with different parameters`. Without a
key nothing here runs and nothing changes. `z_mergetoaddress` and `z_shieldcoinbase` do not take a key.

## What is stored

One `sendonce` record per key in wallet.dat: key = `"sendonce"` + SHA-256(key); value = record
version, SHA-256 of the canonical request, state, operation id, txid, expiry height, start / built /
update times, and (after a failed broadcast of a built transaction) an error code and a message of at
most 200 characters. Never the key, an address, an amount or a memo.

A wallet.dat reader that does not know the record type skips it (`ReadKeyValue` ignores unknown
types; backupwallet copies the whole file). Binaries from before this change open
such a wallet.dat, report the same balances, never touch the records, and the current binary reads
them again afterwards (`qa/rpc-tests/wallet_send_once.sh`, scenario 9).

Each write is followed by `DB_ENV->log_flush`, because the wallet environment commits with
`DB_TXN_WRITE_NOSYNC`.

## Canonical request

SHA-256 over this serialization (compact-size prefixed strings, little-endian integers):

    "z23-sendonce-request-v1"
    from address, as given
    int32 minconf        (the value the call resolved; the default is hashed as its value)
    int64 fee, zatoshis  (likewise)
    uint32 number of recipients
    per recipient, in the order given: address, int64 amount in zatoshis, memo hex lower-cased ("" if none)

The order of the recipients is part of the request.

## States

| state in wallet.dat | written | resolved (when looked at) |
|---|---|---|
| STARTED | before the operation is queued | operation live: `started`. Operation gone (restart, cancelled): `released`, record erased |
| BUILT | after `Build()`, before broadcast; the transaction is added to the wallet right after | in a block or the mempool: `committed` (record becomes COMMITTED). Else `outcome_unknown` until the tip is more than 20 blocks past the expiry height (7 days after the build if no expiry height), then `expired` (record becomes EXPIRED) |
| COMMITTED | after `sendrawtransaction` succeeded | in a block or the mempool: `committed`. In neither and the same expiry rule: `expired` |
| EXPIRED | by resolution | `expired`: the key is released |

Failure before `Build()`: the record is erased (key released). Failure after BUILT (the broadcast
failed): BUILT stays and stores the error.

A call with a key whose record is `started`, `outcome_unknown` or `committed` and the same request
returns the stored operation id; with `outcome_unknown` it first offers the stored transaction to the
mempool again. With another request it is an error. `released` and `expired` keys proceed as new.

`z_getoperationstatus` and `z_getoperationresult` answer for an id that is no longer in the in-memory
queue from the journal (a restart; `z_getoperationresult` does not consume these). `z_listsendjournal`
lists the records read-only. Records resolved to COMMITTED or EXPIRED are pruned after 90 days, and
beyond the newest 10000.

## Crash points (regtest `-testcrashpoint=<name>[:n]`)

`sendonce-after-started`, `sendonce-after-built-record` (BUILT on disk, transaction not yet in the
wallet), `sendonce-after-built` (transaction in the wallet, not broadcast), `sendonce-after-broadcast`
(broadcast, COMMITTED not written).
