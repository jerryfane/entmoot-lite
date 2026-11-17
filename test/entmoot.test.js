// Golden tests: messages and roster entries produced by a real entmootd (test/golden.json,
// captured by `E2E_GOLDEN=test/golden.json npm run e2e`). Our canonical bytes must hash to the
// ids Go computed and verify under the signatures Go made, which only holds if they are
// byte-identical to Go's canonical.Encode output.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { canon, signingBytes, sign, verify, memberId, pubsubTopic, match } from '../src/entmoot.js'
import { sha256, edVerify, edPublic } from '../src/crypto.js'
import { peerIdBytes } from '../src/webrtc.js'
import { b58, b64, unb64 } from '../src/util.js'

const golden = JSON.parse(readFileSync(new URL('./golden.json', import.meta.url)))
const idOf = async (domain, o) => b64(await sha256(signingBytes(domain, o)))

test('golden messages: id, signature and member id match the node', async () => {
  assert.ok(golden.messages.length >= 5)
  const founder = golden.roster.checkpoints[0].founder.member_id
  assert.ok(golden.messages.some((m) => m.author.member_id === founder), 'has node-authored messages')
  assert.ok(golden.messages.some((m) => m.author.member_id !== founder), 'has browser-authored messages the node stored')
  for (const m of golden.messages) {
    assert.equal(await idOf('message/v2', m), m.id)
    assert.ok(await verify(m), m.id)
  }
})

test('golden messages: tampering breaks verification', async () => {
  const m = structuredClone(golden.messages[0])
  m.content = b64(new TextEncoder().encode('forged'))
  assert.equal(await verify(m), false)
  const n = structuredClone(golden.messages[0]); n.timestamp++
  assert.equal(await verify(n), false)
})

test('golden roster: checkpoint and records hash and verify like Go', async () => {
  for (const cp of golden.roster.checkpoints) {
    assert.equal(await idOf('membership-checkpoint/v3', cp), cp.id)
    assert.ok(await edVerify(unb64(cp.signer.entmoot_pubkey), signingBytes('membership-checkpoint/v3', cp), unb64(cp.signature)))
  }
  assert.equal(golden.roster.canonical, golden.roster.checkpoints.at(-1).id)
  for (const r of golden.roster.records) {
    assert.equal(await idOf('membership-record/v3', r), r.id)
    assert.ok(await edVerify(unb64(r.actor.entmoot_pubkey), signingBytes('membership-record/v3', r), unb64(r.signature)))
  }
})

test('identity derivations match the node (member id, libp2p peer id)', async () => {
  for (const n of [golden.roster.checkpoints[0].founder, ...golden.roster.records.map((r) => r.actor)]) {
    const pub = unb64(n.entmoot_pubkey)
    assert.equal(await memberId(pub), n.member_id)
    assert.equal(b58(peerIdBytes(pub)), n.peer_id)
  }
})

test('gossipsub topic name for a group', async () => {
  // from the earlier js-libp2p probe, which read it off the node: group Qpag1jNY...
  assert.equal(await pubsubTopic('Qpag1jNYjOl3Z+am7st1Dc2ZEVAlr6nwz9P8yv7qPSs='), '/entmoot/group/2/wYdDn17zdKmoq1PujrKJDjM-ArU6M2pHo6n-HDzU1Lo')
})

test('sign() reproduces the canonical layout a Go node accepts', async () => {
  const seed = new Uint8Array(32).fill(7)
  const pub = await edPublic(seed)
  const author = { entmoot_pubkey: b64(pub), member_id: await memberId(pub), peer_id: b58(peerIdBytes(pub)) }
  const m = await sign('message/v2', { version: 2, group_id: golden.group, author, timestamp: 1, topics: ['a/b'], content: 'aGk=', roster_head: golden.roster.canonical }, seed)
  assert.ok(await verify(m))
  assert.equal(new TextDecoder().decode(signingBytes('message/v2', m)),
    `entmoot/message/v2\0{"author":{"entmoot_pubkey":"${author.entmoot_pubkey}","member_id":"${author.member_id}","peer_id":"${author.peer_id}"},"content":"aGk=","group_id":"${golden.group}","id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","roster_head":"${golden.roster.canonical}","timestamp":1,"topics":["a/b"],"version":2}`)
})

test('canonical: sorted keys, no HTML escaping, Go escapes U+2028/9, undefined dropped', () => {
  assert.equal(canon({ b: 1, a: ['<&>', { d: undefined, c: '\u2028' }] }), '{"a":["<&>",{"c":"\\u2028"}],"b":1}')
})

test('topic patterns', () => {
  assert.ok(match('world/#', 'world'))
  assert.ok(match('world/#', 'world/chat/x'))
  assert.ok(match('world/+', 'world/chat'))
  assert.ok(!match('world/+', 'world/chat/x'))
  assert.ok(match('world/chat', 'world/chat'))
  assert.ok(!match('world/chat', 'world/chatter'))
  assert.ok(match('#', 'anything/here'))
})

test('verify: malformed messages are false, not exceptions', async () => {
  const m = golden.messages[0]
  for (const bad of [null, {}, { ...m, author: null }, { ...m, signature: '%%%' }, { ...m, author: { ...m.author, entmoot_pubkey: 'AAAA' } }, { ...m, version: 3 }, { ...m, signature: undefined }]) {
    assert.equal(await verify(bad), false, JSON.stringify(bad)?.slice(0, 60))
  }
})

test('verify: an internal failure throws instead of reading as "unverified"', async () => {
  const s = crypto.subtle; const orig = s.digest
  s.digest = function (alg, ...a) { return alg === 'SHA-512' ? Promise.reject(new DOMException('injected', 'OperationError')) : orig.call(this, alg, ...a) }
  try {
    await assert.rejects(verify(golden.messages[0]), (e) => e.name === 'OperationError')
  } finally { s.digest = orig }
})

// test/golden-go.json: written by entmoot's own Go code (test/gen/golden-go.go).
const goldenGo = JSON.parse(readFileSync(new URL('./golden-go.json', import.meta.url)))

test('legacy v0 messages (no domain prefix, no member id) verify like Go', async () => {
  const m = goldenGo.legacy
  assert.ok(await verify(m))
  assert.equal(await verify({ ...m, timestamp: m.timestamp + 1 }), false)
  assert.equal(await verify({ ...m, version: 1 }), false, 'unknown versions are refused like Go')
})

test('canonical form maps lone surrogates to U+FFFD like Go', async () => {
  // what a JS page holds before sending: JSON.parse of the escape Go received
  const local = { ...goldenGo.surrogate, topics: [JSON.parse(`"${goldenGo.surrogate_sent_topic}"`)] }
  assert.equal(local.topics[0], 'a\ud800b')
  assert.ok(await verify(local))
})
