# entmoot-lite

A browser client for [Entmoot](https://github.com/jerryfane/entmoot) groups with no dependencies. It connects
straight to an `entmootd` node over libp2p **WebRTC-direct**, with no signaling server, relay or CDN. It is one
ES module, small enough to go inside a Bitcoin inscription, and it runs inside ord's
`<iframe sandbox="allow-scripts">` under ord's content CSP: an opaque origin with no storage, no Workers and no WASM.

| file | raw | brotli |
|---|---|---|
| `dist/entmoot-lite.js` (the whole client) | 18.0 KB | **7.3 KB** |

The budget is 30 KB brotli. `npm run size` fails the build above it. For comparison, the js-libp2p probe this replaces
was 132 KB brotli.

## API

```js
import { join } from './entmoot-lite.js'

const g = await join({
  addr: '/ip4/…/udp/…/webrtc-direct/certhash/u…/p2p/12D3KooW…', // node's address, e.g. invite.allowed_multiaddrs
  groupId: 'bLF0…=',                                          // base64 group id
  key,                                                         // 32-byte Ed25519 seed (Uint8Array or base64), never stored
  invite,                                                      // target-bound invite JSON for this key; omit if already a member
  onerror                                                      // optional: errors in live processing (default console.error)
})
g.on('world/#', (msg) => console.log(msg.text, msg))   // live, verified; "+" / "#" topic wildcards
await g.publish('world/chat', 'hello')                 // signs + gossips; resolves with the message id
const last = await g.history('world/#', 20)            // newest 20 stored messages, verified, oldest first
g.close()
```

- `msg` is the Entmoot message JSON (`id`, `author`, `timestamp`, `topics`, `content`, `roster_head`, `signature`, …)
  plus `text`, the content decoded as UTF-8.
- `g.me` holds `{entmoot_pubkey, member_id, peer_id}`.
- `g.rosterHead` is the checkpoint id that new messages cite.
- `g.roster()` returns the raw `/entmoot/membership/1` reply.
- `g.conn.version` is the WebRTC-direct ufrag scheme that was used (1 or 2).
- `onerror(e)` receives errors that happen while live traffic is processed: a throwing `on()` handler, an RPC that
  fails to decode, or a failure inside the client. Delivery continues afterwards. A message that fails its signature
  check is not an error and is dropped quietly, but a check that cannot run (for example a broken WebCrypto) is
  reported rather than read as "unverified".

**Inlining it in a page** (an inscription is one file): put the module in `<script type=module>`, or import it from
a `blob:` URL.
- **Classic `<script>` also works:** if the page turns it into a classic `<script>` by dropping the final `export`,
  the client's internals stay inside one function scope. Only `EL` (and `join`/`match`/`verify` if the `export`
  line is kept as a declaration) becomes page-visible.
- **Why this matters:** an earlier build put every minified internal at the top level. A page that set
  `window.G = group` overwrote one of them, and every signature check then failed quietly, so no live messages or
  history came through.

The key and the invite are passed in, and the client never stores them. One Ed25519 key serves as the libp2p
identity, the Entmoot author key and the member id, the same as in `entmootd`.

## What it implements

Only what Entmoot needs, in `src/`:

- **`webrtc.js`**: the WebRTC-direct dialer.
  - It infers the server's SDP answer from the multiaddr, using go-libp2p's `serverSDP` template.
  - ICE ufrag, spec v1: the `libp2p+webrtc+v1/<rand>` ufrag/pwd munge.
  - ICE ufrag, spec v2: if the browser refuses a munged SDP (Chromium's `WebRTC-NoSdpMangleUfrag`), the client keeps
    its own credentials and puts its ICE password in the server ufrag as `libp2p+webrtc+v2/<pwd>`. go-libp2p ≥ v0.49
    accepts both.
  - The Noise prologue is `libp2p-webrtc-noise:` ‖ our DTLS fingerprint multihash ‖ the server certhash.
  - libp2p streams map one-to-one onto data channels, framed as varint-prefixed protobuf `{flag, message}` with
    FIN/FIN_ACK/STOP_SENDING/RESET. No yamux is needed. The two halves of a stream close independently, and a peer's
    RESET ends only our read half. Text (non-binary) messages, frames above the 16 KiB WebRTC message limit,
    overlong varints and malformed protobuf end the stream with an error before anything is allocated for them.
  - multistream-select 1.0.0, in both directions.
- **`noise.js`**: `Noise_XX_25519_ChaChaPoly_SHA256`. The browser is the responder, as the WebRTC spec requires. It
  checks the libp2p static-key signature and that the remote key matches the `/p2p/` peer id. It refuses short
  handshake messages and low-order X25519 keys (an all-zero shared secret).
- **`crypto.js`**:
  - **Operations on secret keys:** Ed25519 signing and X25519 key generation/agreement run only on the browser's
    native WebCrypto Ed25519/X25519. There is no JS fallback for secret keys.
    - **Missing support:** if the browser lacks either algorithm (WebCrypto reports `NotSupportedError`), `join()`
      fails with "entmoot-lite needs native WebCrypto Ed25519 and X25519 (Chrome/Edge 137+, Firefox 130+,
      Safari 17+)".
    - **Other WebCrypto errors** (e.g. `OperationError`) propagate unchanged.
  - **Ed25519 verify:** always the JS implementation, cofactorless and rejecting non-canonical S like Go, so that
    every browser accepts exactly what Go accepts. Verifying involves no secret.
  - **ChaCha20-Poly1305** (RFC 8439): in JS.
  - **SHA-256, SHA-512 and HMAC:** come from WebCrypto.
- **`pb.js`**: a hand-written protobuf encoder/decoder (varint and length-delimited fields only). Clients:
  - identify: answered, advertising `/meshsub/1.1.0`; without it GossipSub never adds us as a peer;
  - the gossipsub RPC: SUBSCRIBE, GRAFT, PUBLISH with a StrictSign signature, and IWANT in reply to IHAVE.
- **`entmoot.js`**:
  - Go `canonical.Encode`, including Go's handling of lone UTF-16 surrogates, which become U+FFFD;
  - message ids and signatures, both v2 (`entmoot/message/v2\0`) and legacy v0 (no prefix, no member id);
  - roster record signing (`entmoot/membership-record/v3\0`);
  - member id, and the topic name `/entmoot/group/2/<b64url sha256("entmoot/topic/v2\0"‖gid)>`;
  - the pubsub message id `sha256("entmoot/pubsub-envelope/v2\0"‖data)`;
  - topic patterns, and Go's `ValidTopic` for publishing.
- **`index.js`**: `join()` uses these Entmoot protocols:
  - `/entmoot/membership/1`: the roster, with checkpoint and record pages walked to completion.
    - **Am I a member?** The client asks without the invite. The node answers a capability-less request only for a
      key that its own roster projection counts as a member (joins, rekeys, removals, bans: Go's rules exactly), so
      the client does not fold the roster itself.
    - **Before joining:** the invite authorizes the roster read.
  - `/entmoot/membership-push/1`: a self-signed `join` record carrying the invite, exactly as `entmootd join` sends
    it.
    - **Timestamp:** above the canonical checkpoint and every record the node holds, like the node's own record
      writer (`membership/group.go`). Otherwise a browser clock that is behind gets the record refused as stale.
    - **Confirmation:** the join counts only once the node serves us as a member.
  - `/entmoot/history/2`:
    - **`list`:** pages are walked. An expired snapshot token is dropped and the walk retried, and a changed
      snapshot restarts the walk, as in Go's keeper sync.
    - **`bodies`:** in batches of 64. A truncated reply (`has_more`) is continued with the ids not yet served.
    - **Filtering:** only bodies we asked for, belonging to this group, are kept.
  - GossipSub on the group topic. We subscribe only once we are on the roster, because the node drops SUBSCRIBEs
    from non-members. The browser therefore receives live messages right after an invite join, with no reconnect
    (compare entmoot#247). Whenever the node announces its subscription to the group topic again (it re-added our
    peer id as a gossipsub peer), we send SUBSCRIBE and GRAFT again; see Limits, "Reload with the same key".
  - **Cleanup:** if `join()` fails after dialing, it closes the connection.

Every message it delivers, from history or live, is checked:
- the id is recomputed from the canonical bytes;
- the Ed25519 signature is verified;
- the member id is re-derived from the key;
- the group id must match.

### Trust boundary

The client trusts the node it dials, which is authenticated by certhash, the Noise handshake and the peer id, for
everything a signature cannot show:
- **Authors:** it does not check that an author was a roster member when they wrote, or that `roster_head` names a
  real checkpoint.
- **Roster:** it does not verify checkpoint or record signatures, or recompute the roster.
- **v0 messages:** legacy messages are accepted on their signature alone. The node's conversion-commitment proof
  is not checked.

A dishonest node can therefore replay or withhold messages, and serve messages that are authentic but were written
by non-members. It cannot forge a message under someone else's key.

## Browser support

- **Tested:** Chromium 159 (Playwright headless), inside `<iframe sandbox="allow-scripts">` with ord's CSP and an
  opaque origin, using both WebRTC-direct v1 (munged ufrag) and v2 (`--force-fieldtrials=WebRTC-NoSdpMangleUfrag/Enabled/`).
- **Requirements:**
  - `RTCPeerConnection`, BigInt, ES2022, `String.prototype.toWellFormed`;
  - WebCrypto `subtle` with SHA-256/512, HMAC, and native **Ed25519** and **X25519**.
  - **Minimum versions** (stable, per MDN/caniuse): Ed25519 needs Chrome/Edge 137, Firefox 129, Safari 17;
    X25519 needs Chrome/Edge 133, Firefox 130, Safari 17. Together: **Chrome/Edge 137+, Firefox 130+, Safari 17+**.
    Older browsers are refused with the error above.
  - **Secure context:** `subtle` needs one. A sandboxed frame under an https page such as ordinals.com qualifies,
    and so does http://localhost.
- **Untested:** Firefox and Safari. They should satisfy the API requirements [INFERENCE]. Whether each accepts a munged
  ufrag, or how it reports refusing one, has not been checked: the v2 fallback triggers on a
  `setLocalDescription` error.

## Node requirements

`entmootd` with a webrtc-direct listener, from entmoot main with
[#252](https://github.com/jerryfane/entmoot/pull/252). With #252, `invite create` fills in the node's `/certhash` when
`-bootstrap` names this node. See Entmoot's
[Browser Peers Over WebRTC-Direct](https://github.com/jerryfane/entmoot/blob/main/docs/concepts/connectivity-profiles.md#browser-peers-over-webrtc-direct)
for the setup:

```sh
entmootd -p2p-listen /ip4/0.0.0.0/udp/4002/webrtc-direct -p2p-announce /ip4/PUBLIC_IP/udp/4002/webrtc-direct serve
entmootd invite create -group GID -target-pubkey <browser key> -bootstrap /ip4/PUBLIC_IP/udp/4002/webrtc-direct/p2p/<node peer id>
```

The dial address is the invite's `allowed_multiaddrs` entry that contains `/webrtc-direct/certhash/`.

## Tests

```sh
npm ci
npm test           # node:test unit tests
npm run size       # build dist/ and enforce the 30 KB brotli budget
ENTMOOTD=/path/to/entmootd E2E_DIR=/tmp/el-e2e E2E_PUBLIC_IP=<your public IPv4> npm run e2e   # browser end-to-end against a real node (see e2e/run.mjs)
```

**Unit tests** (`test/`), run by CI on every push:
- **Crypto:**
  - RFC 8032 (Ed25519), RFC 7748 (X25519), RFC 8439 (ChaCha20, Poly1305, AEAD) and RFC 4231 (HMAC) vectors;
  - cross-checks against `node:crypto` on random keys;
  - rejection of non-canonical signatures.
- **Golden data:**
  - `test/golden.json` (written by the e2e run with `E2E_GOLDEN=test/golden.json`): messages and roster
    checkpoint/records produced by a real `entmootd` (entmoot main 281b884). This includes messages the browser
    authored and the node accepted and stored. Our canonical bytes must reproduce Go's ids, Go's signatures must
    verify over them, and member ids and peer ids must match the node's.
  - `test/golden-go.json` (written by `test/gen/golden-go.go` with entmoot's own Go code): a legacy v0 message,
    and a message whose topic held a lone surrogate.
- **Native-only secret keys:**
  - signing and Noise DH go through WebCrypto Ed25519/X25519, checked against RFC vectors and `node:crypto`;
  - without native support they refuse with the browser requirement, and `join()` fails with it;
  - an injected `OperationError` propagates unchanged.
- **Wire:**
  - protobuf bytes;
  - multiaddr parsing → inferred SDP;
  - stream framing (split prefix/frame messages, chunking, FIN/FIN_ACK);
  - the Noise XX responder against an independent initiator written with `node:crypto`, including failure when the
    prologues differ.
- **Hostile peers** (`test/hostile.test.js`), where anything that could spin the thread runs in a child process
  with a deadline:
  - text (non-binary) data-channel messages, including `"2147483647"`;
  - overlong and oversized frame varints;
  - malformed protobuf and frames;
  - RESET and close-without-FIN;
  - channels that close before they open;
  - a seeded fuzz of random and mutated frames;
  - low-order and truncated Noise keys.
- **Join, membership, history and publish** (`test/join.test.js`), against a scripted fake `entmootd`
  (`test/fake-node.js`) that runs the real dialer, Noise and multistream code over in-memory data channels:
  - roster paging and rekeys;
  - the join timestamp floor;
  - cleanup when `join()` fails;
  - truncated and foreign history bodies;
  - expired snapshots;
  - topic validation;
  - closing streams that fail negotiation;
  - live delivery on the node-opened `/meshsub` stream, which continues after a throwing handler or an undecodable
    RPC; a failure inside verification reaches `onerror`.
- **The built module** (`test/dist.test.js`): `dist/entmoot-lite.js` inlined as a classic script.
  - **Scope:** it adds no globals besides its API.
  - **Name clashes:** verification still passes after the page overwrites every one- and two-letter global name.

**End-to-end** (`e2e/run.mjs`):
- **Node setup:**
  - starts `entmootd` with its own data dir and UDP port 47210 (never `~/.entmoot`), and creates the identity and a
    private group on first run;
  - mints target-bound invites using the plain `-bootstrap` address;
  - reads the dial address, including the certhash, from the invite.
- **Page setup:** serves the built module with ord's CSP inside `<iframe sandbox="allow-scripts">` in headless
  Chromium.
- **Phases:**
  1. **invite**: join with an invite, read history, receive a live message that the node publishes, and publish a
     message that the node must store;
  2. **member**: the same key with no invite, as a roster member;
  3. **v2**: a fresh key, with Chromium refusing SDP munging.
- **Cleanup:** stops the node at the end, and writes `last-e2e.json` into the data dir.

## Membership for an inscription (design; not built yet)

A sandboxed inscription has an opaque origin and no storage, so it cannot keep a key between visits. The proposed
flow:

1. **Fresh key per visit.** The page creates an Ed25519 key in memory (`crypto.getRandomValues`). It lives only for
   that page view.
2. **Wallet attestation.** The page asks the visitor's wallet (Xverse, through its injected provider) to sign a
   BIP-322 message such as:
   `join <world> with key <pub base64> until block <h>`
   Here `<world>` is the group id (or a name bound to it), `<pub>` is the fresh key, and `<h>` is a near block height
   that caps how long the attestation is good for.
3. **Admission by a lighthouse/admin node.** The page sends `{address, message, signature, pub}` to a node that is an
   Entmoot admin of the group. The node:
   - verifies the BIP-322 signature for `address`;
   - checks that `address` currently holds an Ordibot inscription. This needs an ord index: a local `ord server`,
     queried at `/address/<addr>` or `/inscriptions` filtered by the collection's parent/ids;
   - checks that the current block is ≤ `h`;
   - mints a target-bound invite for `pub` (max_uses 1, short validity) and returns it, or applies the join record
     itself.
4. **Join.** The page calls `join({addr, groupId, key, invite})`, which is today's API. The member record names the
   per-visit key. Expiry and cleanup: the node removes or bans keys whose attestation height has passed (a `remove`
   record). A later visit gets a new key and repeats the flow.

**What the node side needs** (none of it exists yet):
- an admission endpoint the browser can reach;
- a BIP-322 verifier;
- an ord lookup for Ordibot ownership;
- admin rights in the group, to mint invites or sign records;
- a sweeper that removes expired per-visit members.

The endpoint must be reachable under ord's CSP. CSP `connect-src` blocks fetch/XHR to other origins. One way around
this is to carry admission over the same WebRTC-direct connection as a new libp2p protocol, e.g.
`/entmoot/admission/1`, which CSP does not govern.

**Unverified:**
- Whether Xverse's injected provider (`window.XverseProviders` / sats-connect) is present and usable inside an
  `<iframe sandbox="allow-scripts">` on ordinals.com: the frame has an opaque origin, and extensions may not inject
  into it or may refuse to talk to it.
- Whether the wallet popup can open from a sandbox that has no `allow-popups`.
- Whether WebRTC is allowed by every ord deployment. CSP does not cover `RTCPeerConnection` in current browsers, and
  this was tested on Chromium only.
- How the Ordibot ownership check should treat inscriptions in transit, i.e. which block height counts.

## Limits

- **One node connection, no reconnect.** The client talks to one node and does not mesh with other peers. If that
  node restarts or the connection drops, the page goes quiet: no live messages in or out until the page calls
  `join` again (in practice: reloads). There is no automatic reconnect.
- **Reload with the same key: up to ~35 s without live messages.** One key is one libp2p peer id. If a page goes
  away without closing its connection (crash, killed tab) and the same key joins again, the node keeps the old
  connection until it times out, and in the meantime delivers nothing live to the new page (measured 34.6–35.5 s
  on entmootd v1.5.102). When the old connection dies, the node drops the subscription the new page sent and
  announces its own again; the client then subscribes again, and live delivery resumes. Messages published to the
  group during the gap are in history, but not delivered live. A node-side fix (prefer the newest connection of a
  peer id) is pending. Before the re-subscribe, the new page got no live messages for the rest of its session.
- **History only goes one way.** The node's own `/entmoot/history/2`, `/entmoot/peer-records/1` and membership pulls
  to the browser are refused with multistream `na`. This is safe: the node skips the peer. Nothing else can catch up
  from the browser.
- **History lists every id.** `history(pattern, n)` lists every stored message id (≤ 1024 per page) before fetching
  bodies newest-first. Cost grows with the size of the group's history, not with `n`.
- **Roster is not verified locally.** Membership is the node's answer; see Trust boundary.
- **Limited gossip.** Gossip controls cover only SUBSCRIBE, GRAFT and IWANT. There is no IDONTWANT, PRUNE handling
  or peer scoring.
- **Unbounded de-duplication.** The set of message ids already seen is not bounded for the lifetime of a page.
- **Open invites are not supported.** They are redeemed over HTTP (entmoot#249). Target-bound invites work over
  libp2p.
- **The node's group policy applies to the browser too.** For example, `preset:standard` allows 6 messages/min and
  8 KB of content.

## License

MIT © Jerry Fanelli
