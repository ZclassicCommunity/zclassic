# ZSOCIAL Wallet-Native Social Protocol Plan

Status: beta7 design scaffold. Non-consensus. Default off.
Scope: decentralized social records carried by the same signed-gossip and Tor
routing foundation as ZMARKET. This document does not authorize file hosting,
on-chain social data, or GUI-side spidering.

## 1. Hard Rules

- No ZClassic consensus changes.
- No social records are required on-chain.
- No file bytes, thumbnails, avatars, banners, videos, HTML, SVG, or arbitrary
  media bytes are stored in social records.
- Social indexing never fetches media. Attachments are content roots, manifest
  hashes, NFT token ids, or market listing ids only.
- Content hosting remains explicit per object through the NFT content allowlist.
- The Qt wallet is a thin client. The daemon owns parsing, routing, indexing,
  moderation decisions, and Tor state; the GUI reads RPC snapshots.
- The C hot path owns record admission, dedupe, expiry, route metadata, caps,
  spam checks, and local indexes.

## 2. Identity

Each wallet social profile uses keys separate from spend keys:

- `social_pubkey`: public profile/post signing key.
- `dm_prekey`: recipient key material for encrypted message requests.
- `route_key`: optional onion route identity or reply-route key.
- optional ZNAM proof: current ZNAM owner signs a name-to-social binding.

The ZNAM binding is a badge, not source of truth:

```
domain = "ZCL-ZSOCIAL-NAME-BINDING-V1"
message = domain || name || social_pubkey || profile_hash || expiry
```

The wallet must show valid, expired, transferred, and mismatch states. Publishing
a ZNAM onion or social endpoint is a public linkage decision.

## 3. Record Types

All records are signed, bounded, expiring, and keyed by canonical body hash.

| Record | Purpose |
|---|---|
| `ZSOC_PROFILE1` | display name, bio, avatar/banner content roots, DM prekey bundle hash, feed/onion hints, sequence, expiry |
| `ZSOC_POST1` | author key, sequence, created/expiry, reply/root/quote refs, bounded text or encrypted body, tags, content roots, NFT/listing refs |
| `ZSOC_FEEDHEAD1` | signed compact list of recent post hashes so clients can fetch an author feed without global search |
| `ZSOC_DELETE1` | advisory signed tombstone for local indexes |
| `ZSOC_MODLIST1` | signed block/label list for keys, names, content roots, tags, listings, or post hashes |
| `ZSOC_DM_ROUTE1` | encrypted DM route packet carried by ZMARKET/Tor routing |

Unknown future record types are ignored unless the user imports them explicitly.

## 4. Privacy Defaults

- Follow lists are local wallet data, encrypted at rest, and never gossiped by
  default.
- Feed fetching uses Tor route preference, batching, jitter, and optional decoy
  author fetches once routing is ready.
- Public follow records are deferred. They leak the social graph.
- No read receipts by default.
- No automatic contact discovery from wallet addresses or transaction history.
- A gallery post can reference NFTs, manifests, mirrors, and listing ids, but
  the wallet verifies ownership/listings locally before showing badges.

Tor helps transport privacy, but it does not erase graph leakage from public
posts, timing, ZNAM bindings, galleries, or repeated marketplace activity.

## 5. Direct Messages

DMs use encrypted route packets instead of public posts:

- Relays see packet hash, size class, TTL, hop count, PoW, and recipient key
  hash only.
- Payload uses ephemeral key agreement plus AEAD to the recipient DM prekey.
- Sender identity, reply route, read state, and message body are inside
  ciphertext.
- Unknown senders land in message requests and require stricter PoW/rate limits.
- One-time onion reply routes are allowed for DMs and short-lived negotiations.
  They retire after successful use.

## 6. Moderation And Spam

Moderation is local-first:

- local blocklists for keys, names, tags, content roots, post hashes, listing
  ids, and onion endpoints;
- optional signed curator lists;
- no global takedown authority;
- relays may enforce their own local deny policy before routing.

Spam resistance:

- size caps before parse;
- dedupe before signature verification;
- TTL/expiry pruning;
- per-peer and per-author quotas;
- PoW for public posts and unknown-sender DMs;
- stricter treatment for anonymous/unbound keys;
- validation cache keyed by record hash and local chain/name tip where relevant.

## 7. Daemon And GUI Surface

Daemon-side future RPC shape:

- `social_status`
- `social_profile_get`
- `social_profile_publish`
- `social_post_create`
- `social_post_import`
- `social_feed_search`
- `social_dm_send`
- `social_dm_requests`
- `social_block_add`
- `social_block_list`

GUI tabs may show profiles, feeds, galleries, DMs, and moderation settings, but
must not spider, route, or index independently. Opening a feed or NFT card must
not fetch media until the user asks for verified media.

## 8. Beta7 Cut

Ship:

- protocol docs;
- C parser/index scaffolding;
- local identity and encrypted follow-list design;
- optional ZNAM badge verification design;
- local moderation model;
- NFT/gallery/listing reference model.

Defer:

- public default-on social relay;
- public follow graph;
- rich full-text search at network scale;
- group/circle key rotation;
- cover traffic and decoy policy;
- BIP155-based onion discovery;
- automatic media fetching or any social-triggered hosting.
