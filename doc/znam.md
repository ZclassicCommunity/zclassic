# ZNAM names in zclassicd

ZNAM is the on-chain name protocol of the Z23 node. A name (`alice`) is registered by a transaction that carries a
record in an `OP_RETURN` output; the name then points at an address. zclassicd can read those records, resolve a name
to an address for you to check, and build the registration, update and transfer transactions.

This is an overlay protocol. Nothing here is consensus: a node that knows nothing about names validates every block
exactly as before, and everything below is **off unless you start the daemon with `-znamindex=1`**. With the index off
the daemon behaves as it did; the new `znam_*` commands exist and answer "disabled".

The rule set is Z23's current one, implemented bug for bug (the owner's decision: no ZNAM history exists on mainnet, so
there is nothing to stay compatible with except Z23 itself). Where Z23's behaviour looks ambiguous or unintended it is
implemented as written and listed in [section 9](#9-ambiguous-or-unintended-in-z23-notes-for-the-owner).

Citations are `file:line` in the Z23 repository at commit `5e21cefb3` (the pin of `src/c23/services/Z23_SOURCE.tsv`). Every
file cited was compared with Z23 `origin/main` (`83931c0e3`, 2026-11-17): the git blob ids are identical.

## 1. Using it

```
zclassicd -znamindex=1            # builds <datadir>/znamindex in the background; needs the full block files (not -prune)
zclassic-cli znam_getindexinfo    # {"enabled": true, "synced": ..., "names": ...}
zclassic-cli znam_register alice t1... "" t1OwnerAddr    # owner address optional
zclassic-cli znam_resolve alice                           # an address for YOU to check; never a payment
zclassic-cli znam_getname alice                           # owner, records, every change with block and signer
zclassic-cli znam_update alice zs1...
zclassic-cli znam_transfer alice t1NewOwner
zclassic-cli znam_listnames "" 0 100
zclassic-cli znam_listmine
```

| command | what it does |
|---|---|
| `znam_getindexinfo` | progress and counters; `{"enabled": false}` when the index is off |
| `znam_resolve "name" ( "type" recentblocks )` | local lookup: the address, the block and transaction that set it, a `changed_recently` flag and warnings |
| `znam_getname "name"` | the full record: owner, primary target, SET_RECORD and SET_TEXT records, history, expiry |
| `znam_listnames ( "owner" skip count )` | names in name order, optionally only those of one owner address |
| `znam_listmine` | the names whose owner key is in this wallet |
| `znam_register "name" "target" ( "type" "owner" )` | REGISTER |
| `znam_update "name" "target" ( "type" )` | UPDATE of the primary target (owner only) |
| `znam_transfer "name" "newowner"` | TRANSFER (owner only) |

Every command except `znam_getindexinfo` refuses with a clear error while the index is off. `znam_resolve` and the three wallet commands also refuse
while the index has not caught up to the chain tip (a stale index can miss the UPDATE that moved a name or the REGISTER
that took it); `znam_getname` and `znam_listnames` answer with what the index has, and `znam_getname` says whether it is
synced.
`-znamindexstart=<n>` sets the first block the index reads; the default is 0, so no registration can be missed.

`z_sendmany` and `sendtoaddress` are **not** changed and never take a name. Paying a name is two steps: resolve it
(`znam_resolve`), then pay the address that comes back (section 6).

## 2. The rules (Z23)

### 2.1 Wire format

An `OP_RETURN` script made of pushes (`znam.c:1-17, 92-130`, `znam.h:15-20`, `overlay_codec.c:18-131`,
`op_return_push.h`):

| field | content |
|---|---|
| 0 | `ZNAM` (4 bytes), the lokad id |
| 1 | version, 1 byte, must be `1` |
| 2 | command, 1 byte, `1..6` |
| 3 | name, 1..63 bytes, must pass `znam_validate_name` |
| 4.. | by command: REGISTER, UPDATE, SET_RECORD: type (1 byte, `1..7`) and value (1..128 bytes). TRANSFER: new owner (1..63 bytes). RENEW: nothing. SET_TEXT: key (1..32 bytes) and value (0..128 bytes) |

Types: 1 onion, 2 z-address, 3 t-address, 4 bitcoin, 5 litecoin, 6 dogecoin, 7 content hash (`znam.h:32-39`).

A push is `OP_0` (empty), a direct length byte `1..75`, `OP_PUSHDATA1` or `OP_PUSHDATA2`; anything else, or a push
past the end of the script, fails the parse (`op_return_push.h:read_push`). **Bytes after the last field are accepted**
(see A1).

A builder never emits a script longer than `MAX_OP_RETURN_RELAY` = 223 bytes, because a longer one does not relay
(`znam.c:145-157`); a maximal SET_TEXT (63+32+128) is 237 bytes and is refused by the builder.

### 2.2 Which output carries the message

Z23 takes **one** message per transaction: the **first output whose script starts with `OP_RETURN`, at any position**
(`explorer_index.c:497-508`, `index_first_op_return_output`; `index_op_return` 449-473 hands exactly that script to the
overlay registry, `explorer_index_overlays.c:354-381`). A second `OP_RETURN` is never read. The wallet builders put the
record at `vout[0]` (`zslp_command_service.c:266-307`). The value of the output is not checked. A malformed record is
dropped without a log line (`explorer_index_overlays.c:285-293`).

### 2.3 Name syntax

`znam_validate_name` (`znam.c:24-37`): 1 to 63 bytes, each `a-z`, `0-9` or `-`, first and last byte not `-`.

* No case folding: `Alice` is not a name; the parser drops a record that carries it (`znam.c:78-90`) and the resolver
  answers `NAME_MALFORMED` for it (`name_resolver.c:116-119`).
* No Unicode. Every byte above 0x7f fails, so a look-alike letter of another script can never be part of a name.
* Nothing reserved, no minimum length (one character names exist), no punycode special case (`xn--...` is an ordinary
  ASCII name), no confusable policy inside ASCII (`a1ice` and `alice` are two names).
* A name that looks like an address is possible; that is why this implementation never takes a bare string as a name
  (section 6).

### 2.4 Who owns a name

The owner of a name is the address of the output that the transaction's **first input** spends
(`explorer_index_overlays.c:55-84`, `explorer_index.c:395-406`, `standard.c:91-119`):

* the first input must not be the coinbase null prevout, and the spent output must be an exact P2PKH script (25 bytes) or
  an exact P2SH script (23 bytes). A bare public key output, a multisig, or anything else has no owner, and the message is
  ignored (REGISTER, UPDATE, TRANSFER, SET_RECORD, SET_TEXT; RENEW needs no owner);
* the owner is rendered as a **P2PKH address** with the chain's P2PKH prefix, **for both forms** (`DEST_KEY_ID` at
  `explorer_index_overlays.c:69-72`): a P2SH spend yields the P2PKH text of the script hash (A3);
* only the first input matters. Other inputs may belong to anyone, and are not looked at.

So owning a name means controlling the key behind the first input's output. Nothing in the record names the signer.

### 2.5 The commands

All are evaluated in `apply_znam` (`explorer_index_overlays.c:209-260`), after `znam_validate_name` (line 220).

| command | rule | Z23 |
|---|---|---|
| REGISTER | needs an owner; the name must not exist; creates the name with `owner`, the primary target, `reg_height` = block height, `expiry` = height + 210240 | `:88-109` |
| UPDATE | name exists, owner equals the stored owner; replaces the primary target (type and value) | `:111-125` |
| TRANSFER | name exists, owner equals the stored owner; stores `new_owner` **verbatim as the new owner text** | `:127-140` |
| SET_RECORD | name exists, owner equals the stored owner; upserts the address record of that type | `:142-156` |
| SET_TEXT | name exists, owner equals the stored owner; upserts the text record (an empty value is stored, it does not delete) | `:158-170` |
| RENEW | name exists; **anyone**; `expiry` = max(expiry, height) + 210240; sets `last_update_txid` | `:172-186` |

After the model's own validation (`models/znam.c:155-183`: type `1..7`, owner and target non-empty, non-negative
heights): a field that is empty as a C string (the first byte is NUL) makes the model refuse the write, so the message is
dropped (A9).

SET_TEXT with key `zid` also feeds Z23's identity projection (`explorer_index_overlays.c:201-206`); that feed is **not**
implemented here (A11).

### 2.6 Ordering, conflicts

Messages are applied in **block order, transaction order within the block** (`explorer_index.c:649-651`,
`index_tx_projections` 538-560). That order is the whole first-come-first-served rule: the first REGISTER of a name in
chain order wins (`explorer_index_overlays.c:95-96`), and the rest are ignored. Within one block, whichever REGISTER the
miner placed first wins. A transaction can use outputs created earlier in the same block, so a REGISTER and an UPDATE by
the same owner may share a block; an UPDATE placed before the REGISTER finds no name.

There is no fee, bond or burn: a ZNAM transaction pays its ordinary network fee and the output carries value 0. There is
no limit on names per owner and no reservation of any name.

The web registration form of Z23 has a proof-of-work gate and a CSRF token (`name_site_controller.c:283-345`). They are
properties of that HTML form, not of the protocol; the index applies no such rule.

### 2.7 Expiry and renewal

`ZNAM_REGISTRATION_TERM_BLOCKS` = 210240 (`znam.h:52-58`) sets `expiry_height` at registration and moves it on RENEW.
Nothing reads it back: **resolution does not reap expired names** (the header says so, `znam.h:52-58`;
`name_resolver.c:106-160` never tests it). The value is bookkeeping. zclassicd reports `expiryheight` and an `expired`
flag, and warns, but still resolves an expired name, as Z23 does.

### 2.8 What a name resolves to

`name_resolve` (`name_resolver.c:106-160`):

* no type asked: the primary target (the last REGISTER or UPDATE);
* a type asked: the primary target when its type matches, else the SET_RECORD address record of that type, and for
  `onion` also the SET_TEXT record `onion`.

Z23 never checks that a target is an address of its declared type, or an address at all (`name_controller.c:262-282`
checks only the name and the type token). zclassicd therefore decides **payable** itself, at resolution time: only a
`t-address` record that decodes as a P2PKH or P2SH address of this chain, or a `z-address` record that decodes as a
Sapling or Sprout address, and whose canonical re-encoding equals the stored text exactly, is offered for payment.

### 2.9 Reorganisation

Z23 applies a block to its name tables on the way in and has no step for a block that leaves the chain: the only reset is
a full truncate and re-walk (`explorer_index.c:410-442`, `boot_index.c:431`). On mainnet the projection runs in the
catch-up pass, not on connect (`sync_controller_blocks.c:738-754`). A registration in an abandoned block therefore stays
in Z23's table. **zclassicd does not copy that**: the index is unwound block by block (section 4).

## 3. What was implemented where

| | files | what |
|---|---|---|
| **vendored verbatim** | `src/c23/services/vendor/contexts/naming/modules/znam/{include/znam/znam.h,src/znam.c}` | Z23's parser, validator and builders. Added to `vendor-files.txt`, `Z23_SOURCE.tsv`; `check-vendor.sh` (with `Z23_REPO`) passes. The overlay codec and push helpers it uses were already vendored. |
| **glue (zclassicd-owned C)** | `src/c23/services/glue/zcl_znam_index.{h,c}`, `glue/script/standard.h` | `zcl_znam_parse_message`, `zcl_znam_build` forward to the vendored code. `zcl_znam_owner_hash` and `zcl_znam_evaluate` are a C port of `apply_znam` and `utxo_classify_script` with the SQL removed; the Z23 line of each rule is in the comments. `standard.h` supplies `MAX_OP_RETURN_RELAY` (223) to the vendored builder. |
| **new C++** | `src/znam/znamindex.{h,cpp}`, `znamservice.{h,cpp}`, `znamresolve.{h,cpp}`, `src/rpc/znam.cpp`, `main.cpp` (`ReadBlockUndoFromDisk`, read only), `init.cpp` (two options) | the index, its worker, resolution, the RPCs |
| **GUI** | `wallet/src/namesmodel.*`, `namepaybox.*`, `namesview.*`, `sendtab.cpp`, `mainwindow.*` | Pay-to name box, Names window |
| **tests** | `src/test/znam_tests.cpp`, `qa/rpc-tests/znam_index.sh`, `src/c23/services/tools/znamscript.c`, `wallet/tests/tst_names.cpp`, `wallet/tests/widget/tst_widget.cpp` | section 8 |

## 4. The index

`-znamindex=1` keeps a LevelDB store under `<datadir>/znamindex` (the `KV` interface and `LevelKV` of the ZSLP index are
reused). Keys: `n<name>` the current entry (owner, primary target, registration height and txid, Z23's
`last_update_txid`, expiry, and where the thing a payer relies on last changed), `o<owner>\0<name>` (owner to names),
`r<name>\0<type>` address records, `t<name>\0<key>` text records, `e<name>\0<height><txindex>` the history, `u<block>` the
undo record, `mbest`, `mstat`, `mver`.

* **One block, one atomic batch.** Every block is applied as one `WriteBatch` together with its undo record (the first-seen
  original of every key the block touched) and the new best block. A crash leaves the store at an exact block boundary.
* **Reorg safe.** A reconcile worker compares its best block with `chainActive` and connects or disconnects until they
  agree; it does not trust notifications. Disconnecting a block replays its undo record and restores the exact prior
  bytes (tested byte for byte, section 8).
* **Background initial scan.** Blocks are read from the block files; the undo data (`rev*.dat`) is read **only for a
  block that contains a ZNAM message**, because the owner is the address of the first input's spent output. The worker
  never holds `cs_main` while reading or writing its store.
* **Owner from the undo data**, not from a second index of every output: the undo record of a connected block holds the
  spent output of every input, including outputs created earlier in the same block.
* **Off by default.** With the flag off nothing is created, started or read; the new commands answer "disabled".
  `-prune` is refused with the flag on.

## 5. Not implemented

* The commands RENEW, SET_RECORD and SET_TEXT have no wallet RPC; the index applies them when they appear on chain.
* The identity feed of SET_TEXT `zid` (A11).
* Mempool-level name state: the index is confirmed chain only. The wallet commands refuse if the mempool already holds a
  transaction for the same name.

## 6. Paying to a name

The daemon only resolves. `znam_resolve` answers from the local index; nothing is sent to any peer, so which names you look
up is not observable.

```
{ "name": "shop", "resolved": true,
  "address": "t1...", "type": "t-address", "kind": "transparent", "payable": true,
  "set_height": 812345, "set_txid": "...", "set_by_record": false,
  "blocks_since_change": 3, "changed_recently": true, "recent_change_blocks": 100,
  "owner": "t1...", "registered_height": 700000, "registered_txid": "...",
  "expiry_height": 910240, "expired": false,
  "warnings": ["this name's address or owner changed 3 block(s) ago (block 812345): confirm the address ..."],
  "records": [ ... every record with its own height and txid ... ] }
```

`changed_recently` is true when the answer rests on a REGISTER, UPDATE or TRANSFER (or the SET_RECORD used) within the
last `recentblocks` blocks (default 100, about four hours). RENEW and SET_TEXT do not count: they cannot redirect a
payment. The answer also says which block and transaction set it, so the payer can look them up.

The GUI (`Send` tab):

* an entry is a name only when it starts with `@`. `@` occurs in no ZClassic address, so a name cannot be taken for an
  address nor an address for a name. After the `@`: exactly Z23's syntax. ASCII upper case is folded to lower case (the
  registry has no upper case names, so `@Alice` can only mean `@alice`). **Every non-ASCII character is rejected with a
  message** (look-alike letters, full-width forms, zero-width characters, no-break spaces); nothing is normalised into
  a name;
* the box under the field resolves it through `znam_resolve`, shows the **full address**, the registration height and
  owner, and when the address or owner changed within the window, or the name is itself newer than the window, a boxed red
  warning;
* the user ticks "this is the address I mean to pay" (a stronger wording when there is a warning). Until then the entry
  is not an address and sending is refused with that reason;
* the transaction is built with the **address**, exactly as if it had been pasted: `z_sendmany` receives the address and
  an ordinary memo; no name appears in it. Just before sending, the node is asked again, and if the address or the
  setting transaction differs, or the node cannot answer, nothing is sent and the confirmation is cleared;
* if the node has no name index, the lookup fails, or the name does not resolve, the box says so and the field is what it
  always was (an `@name` is simply not a valid address).

A small Names window (rail button, only when the index is on) lists the names this wallet owns and can register one or
change where one points.

## 7. Security notes

**Squatting and front-running.** A REGISTER in the mempool is public, and a miner orders transactions as it likes: anyone
who sees your registration can send the same name with a higher fee and win it, and nothing in the protocol (no commit and
reveal, no fee, no auction) prevents that. The wallet command refuses a name that is already registered or already waiting
in the mempool, which stops you from racing yourself, not anyone else. Do not announce a name before it is confirmed.
Short and common names will be squatted. A name taken from you is not recoverable.

**Look-alike names.** Unicode confusables cannot occur: a name is ASCII and the GUI rejects the rest. Inside ASCII the
usual pairs remain (`l`/`1`, `o`/`0`, `rn`/`m`, `-` placement, `xn--` labels shown as is). The defence is not guessing at
them but showing what matters: the full address, the owner, the registration age. A name registered within the window is
flagged, because a brand-new name is the usual shape of a look-alike. Confirm a new name's address with the recipient.

**A compromised owner key.** Whoever controls the owner's key can UPDATE or TRANSFER the name and redirect payments; the
chain cannot tell. That is why the answer carries the block and transaction that set the address and the
`changed_recently` flag, and why the GUI makes a recent change the loudest thing on the screen. The window is a signal, not
a guarantee: an attacker who waits it out is not flagged. For a large payment, confirm the address through another channel
whatever the flag says.

**Privacy of resolving.** Resolution reads the local index only. No DNS, no peer query, no third party learns what you look
up. The registration itself is public chain data, and so is the link between a name and its owner address.

**Wrong address types.** A name can carry any text; only a canonical, valid address of this chain is ever offered for
payment (section 2.8).

**Trust.** The index is derived from the chain, never authoritative: delete `<datadir>/znamindex` and it is rebuilt. It does
not touch consensus, the coins view or `wallet.dat`.

## 8. Tests

* `src/test/znam_tests.cpp` (`test_bitcoin --run_test=znam_tests`, 16 cases): the wire format against a hand-assembled
  vector, name syntax (case, Unicode look-alikes, NUL, length), every parser refusal, the owner rules (P2PKH, P2SH, P2PK,
  multisig), register/update/transfer/renew, no-owner, **same-block ordering in both orders**, records and text, the
  first-OP_RETURN-at-any-position rule, transfer to a non-address, exact undo of every block, atomic batches (a block
  refused whole when its owners cannot be read), an independent model of Z23's rules compared with the index over random
  chains with random reorgs, and resolution (look-alike names, payable selection, the recent-change window to the block,
  expiry).
* `qa/rpc-tests/znam_index.sh` (regtest, 95 checks): see its header. Registrations, conflicts in one block, invalid records
  ignored, **resolve then send to the resolved address**, reorg one block at a time against snapshots, a longer peer chain,
  restart, a second node, kill -9 and clean-stop interrupted builds, a build from block 0, `-reindex`, and the flag-off RPC
  list against an unmodified zclassicd (only the eight `znam_*` commands are new, the help of every other command is
  byte-identical).
* `wallet/tests/tst_names.cpp` (30 cases, no daemon): the Pay-to grammar and its look-alike cases, reading the daemon's
  replies, the warnings, and the `NamePayBox` widget (confirmation gating, stale replies, recheck). One more case in
  `wallet/tests/widget/tst_widget.cpp` drives the real Send tab.

## 9. Ambiguous or unintended in Z23 (notes for the owner)

Implemented as Z23 does it; none is changed here.

* **A1. Trailing bytes are accepted.** `znam_parse` never calls `overlay_reader_finish` (`znam.c:11-17`), unlike ZDIR
  (`zdir.h:36`). The comment says registrations are "live on mainnet", which contradicts "no records exist on mainnet".
  Decide whether the parser should become strict before any record exists.
* **A2. No normalisation, no confusable policy, no reserved names, one-character names.** See 2.3.
* **A3. A P2SH-funded record is owned by the P2PKH text of the script hash.** `explorer_index_overlays.c:69-72` always uses
  `DEST_KEY_ID`. A name registered from a P2SH input can never be changed (no key hashes to the script hash), and a
  later TRANSFER to a real P2SH address string (`t3...`) also never matches.
* **A4. Only the first input counts.** A transaction that merely has an owner's coin first is a valid owner transaction;
  other inputs may belong to anyone. Wallets that reorder inputs (privacy mixers, coin-selection libraries) can change
  the owner of a record without meaning to.
* **A5. TRANSFER stores any text** of 1-63 bytes (`name_controller.c:563-567` checks only the length). A transfer to a
  mistyped address, a P2SH address or a z-address orphans the name permanently. zclassicd's `znam_transfer` refuses
  everything but a valid P2PKH address; a transfer already on chain is honoured as written.
* **A6. `last_update_txid` is overwritten by RENEW** (`explorer_index_overlays.c:184`), which anyone can send. Z23's own
  "changed since registration" history flag (`name_resolver.c:208`) therefore turns true for a name nobody changed.
  SET_RECORD and SET_TEXT do not set it, although they change what the name resolves to. zclassicd keeps Z23's field and
  adds its own "last change" (REGISTER, UPDATE, TRANSFER, and the record used) for the warning.
* **A7. Expiry is never enforced** and RENEW is permissionless. The term is decoration (2.7).
* **A8. Targets are never validated** against their type or as addresses; a typed `t-address` record can hold any text.
* **A9. C-string semantics.** Fields are copied into fixed buffers and stored as C strings: an embedded NUL truncates the
  value, and a value empty after truncation is refused by the model as "save failed" (`models/znam.c:166-178`). A target
  that begins with a NUL byte makes a REGISTER silently not register. Same in zclassicd.
* **A10. SET_TEXT with an empty value** is stored as an empty row, not a deletion (`models/znam.c:551-582`); the resolver
  treats empty as absent (`name_resolver.c:151-155`).
* **A11. SET_TEXT `zid`** also feeds the identity projection (`explorer_index_overlays.c:201-206`); not implemented here.
* **A12. No reorg handling in Z23's tables** (2.9). A registration in an orphaned block stays; a name can be "taken" by a
  block that is no longer part of the chain, and the same name could then be registered again on the real chain without
  effect in Z23's table. zclassicd unwinds. The two will disagree after any reorg that touches a name.
* **A13. Mainnet projection runs in catch-up**, not on connect (`sync_controller_blocks.c:738-754`), so Z23's name state
  can trail the tip. zclassicd's worker follows the tip and refuses to answer while behind.
* **A14. The first OP_RETURN wins, wherever it is**, so a ZNAM record behind another OP_RETURN is invisible
  (`explorer_index.c:497-508`). The ZSLP wallet guard documents the same ambiguity for SLP.
* **A15. The OP_RETURN value is not checked**, nor is anything else about the carrying transaction: a coinbase can carry a
  RENEW, and any output value is accepted.
* **A16. The registration form's proof of work** (`name_site_controller.c:316-345`) is not part of the protocol, so it
  protects only that form.
* **A17. Resolution exposes only what the registry says.** There is no pay-to-name in Z23: `msg_send_named`
  (`messaging_controller.c:535-616`) copies the primary target into a message recipient string without checking its type.
