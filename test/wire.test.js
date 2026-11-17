// Protobuf, multiaddr/SDP, stream framing and the Noise XX responder (checked against an
// independent initiator written with node:crypto).
import test from 'node:test'
import assert from 'node:assert/strict'
import nc from 'node:crypto'
import { pb, unpb } from '../src/pb.js'
import { parseAddr, serverSdp, Stream, peerIdBytes } from '../src/webrtc.js'
import { respond, pubProto } from '../src/noise.js'
import { edPublic } from '../src/crypto.js'
import { b58, unb58, varint } from '../src/util.js'

const hx = (b) => Buffer.from(b).toString('hex')

test('protobuf encode matches protoc wire bytes', () => {
  // gossipsub RPC{subscriptions:[{subscribe:true, topicid:"t"}]} as encoded by go-libp2p-pubsub
  assert.equal(hx(pb([[1, pb([[1, true], [2, 't']])]])), '0a0508011201' + '74')
  // libp2p PublicKey{Type: Ed25519, Data: 32 x 0x01}
  assert.equal(hx(pubProto(new Uint8Array(32).fill(1))), '08011220' + '01'.repeat(32))
  assert.equal(hx(pb([[3, 300], [4, undefined], [5, [new Uint8Array([1]), 'a']]])), '18ac02' + '2a0101' + '2a0161')
  assert.equal(hx(varint(16384)), '808001')
})

test('protobuf decode, repeated fields, skips fixed64/32', () => {
  const b = Uint8Array.from(Buffer.from('08960110001a03616263' + '09' + '00'.repeat(8) + '1a0178' + '25' + '00'.repeat(4), 'hex'))
  const m = unpb(b)
  assert.deepEqual(m[1], [150])
  assert.deepEqual(m[2], [0])
  assert.deepEqual(m[3].map((x) => Buffer.from(x).toString()), ['abc', 'x'])
  assert.throws(() => unpb(Uint8Array.of(0x0a, 5, 1)))
})

test('peer id and base58 round trip (RFC 8032 key 1)', async () => {
  const pub = await edPublic(Uint8Array.from(Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex')))
  const id = b58(peerIdBytes(pub))
  assert.match(id, /^12D3KooW/)
  assert.deepEqual(unb58(id), peerIdBytes(pub))
  assert.equal(b58(Uint8Array.of(0, 0, 1)), '112')
  assert.deepEqual(unb58('112'), Uint8Array.of(0, 0, 1))
})

test('multiaddr parsing and inferred server SDP (go-libp2p serverSDP)', () => {
  const a = parseAddr('/ip4/37.27.59.89/udp/47210/webrtc-direct/certhash/uEiAJS2cu2uX5E2vzLLMSFHD5lHvd50Db69laL0jnWzencg/p2p/12D3KooWJ61gg9gh7XUi2CHUK8JpcCBto2F1edC2LcQRT4WUgWLC')
  assert.equal(a.ip, '37.27.59.89'); assert.equal(a.port, 47210); assert.equal(a.hash.length, 34)
  const sdp = serverSdp(a, 'libp2p+webrtc+v1/abc')
  assert.match(sdp, /\r\na=ice-lite\r\n/)
  assert.match(sdp, /a=ice-ufrag:libp2p\+webrtc\+v1\/abc\r\na=ice-pwd:libp2p\+webrtc\+v1\/abc/)
  assert.match(sdp, /a=fingerprint:sha-256 09:4B:67:2E:DA:E5:F9:13:6B:F3:2C:B3:12:14:70:F9:94:7B:DD:E7:40:DB:EB:D9:5A:2F:48:E7:5B:37:A7:72\r\n/)
  assert.match(sdp, /m=application 47210 UDP\/DTLS\/SCTP webrtc-datachannel/)
  assert.match(sdp, /a=candidate:1 1 UDP 1 37\.27\.59\.89 47210 typ host\r\na=end-of-candidates\r\n$/)
  assert.throws(() => parseAddr('/ip4/1.2.3.4/tcp/1/p2p/12D3KooWJ61gg9gh7XUi2CHUK8JpcCBto2F1edC2LcQRT4WUgWLC'))
})

// A fake RTCDataChannel pair: what one side sends, the other receives as message events.
function pair () {
  const mk = () => ({ readyState: 'open', sent: [], send (d) { this.peer.onmessage?.({ data: d.slice().buffer }) }, close () { this.readyState = 'closed'; this.onclose?.() } })
  const a = mk(); const b = mk(); a.peer = b; b.peer = a
  return [a, b]
}

test('stream framing: split prefix/frame messages, FIN/FIN_ACK half-close', async () => {
  const [da, db] = pair()
  const sa = new Stream(da); const sb = new Stream(db)
  // go-libp2p writes the varint prefix and the frame as two SCTP messages
  const frame = pb([[2, Buffer.from('hello')]])
  db.onmessage({ data: varint(frame.length).buffer })
  db.onmessage({ data: frame.slice().buffer })
  assert.equal(Buffer.from(await sb.read(5)).toString(), 'hello')
  sa.write(new Uint8Array(40000).fill(9)) // chunked under the 16 KiB message limit
  sa.end()
  const all = await sb.all()
  assert.equal(all.length, 40000)
  assert.equal(sb.fin, true)
  sb.end() // our FIN -> their FIN_ACK; both halves done closes the channel
  assert.equal(da.readyState, 'closed')
})

// Independent Noise XX initiator (the server side in WebRTC-direct), built on node:crypto.
async function initiator (io, prologue, identity) {
  const H = (...b) => nc.createHash('sha256').update(Buffer.concat(b)).digest()
  const HM = (k, d) => nc.createHmac('sha256', k).update(d).digest()
  let h = Buffer.from('Noise_XX_25519_ChaChaPoly_SHA256'); let ck = h; let k = null; let n = 0
  const mix = (d) => { h = H(h, d) }
  const mixKey = (ikm) => { const t = HM(ck, ikm); ck = HM(t, Buffer.of(1)); k = HM(t, Buffer.concat([ck, Buffer.of(2)])); n = 0 }
  const nonce = () => { const b = Buffer.alloc(12); b.writeUInt32LE(n++, 4); return b }
  const encrypt = (p) => {
    if (!k) { mix(p); return p }
    const c = nc.createCipheriv('chacha20-poly1305', k, nonce(), { authTagLength: 16 }); c.setAAD(h)
    const out = Buffer.concat([c.update(p), c.final(), c.getAuthTag()]); mix(out); return out
  }
  const decrypt = (c) => {
    if (!k) { mix(c); return c }
    const d = nc.createDecipheriv('chacha20-poly1305', k, nonce(), { authTagLength: 16 }); d.setAAD(h); d.setAuthTag(c.subarray(-16))
    const out = Buffer.concat([d.update(c.subarray(0, -16)), d.final()]); mix(c); return out
  }
  const raw = (key) => key.export({ format: 'der', type: key.type === 'private' ? 'pkcs8' : 'spki' }).subarray(-32)
  const dh = (priv, pubRaw) => nc.diffieHellman({ privateKey: priv, publicKey: nc.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), pubRaw]), format: 'der', type: 'spki' }) })
  mix(prologue)
  const e = nc.generateKeyPairSync('x25519'); const s = nc.generateKeyPairSync('x25519')
  mix(raw(e.publicKey)); encrypt(Buffer.alloc(0))
  io.write(raw(e.publicKey))
  const m2 = Buffer.from(await io.read())
  const re = m2.subarray(0, 32); mix(re); mixKey(dh(e.privateKey, re))
  const rs = decrypt(m2.subarray(32, 80)); mixKey(dh(e.privateKey, rs))
  const payload = unpb(decrypt(m2.subarray(80)))
  const rkey = unpb(payload[1][0])[2][0]
  const okSig = nc.verify(null, Buffer.concat([Buffer.from('noise-libp2p-static-key:'), rs]), nc.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), rkey]), format: 'der', type: 'spki' }), payload[2][0])
  const cs = encrypt(raw(s.publicKey)); mixKey(dh(s.privateKey, re))
  const myPub = raw(identity.publicKey)
  const sig = nc.sign(null, Buffer.concat([Buffer.from('noise-libp2p-static-key:'), raw(s.publicKey)]), identity.privateKey)
  io.write(Buffer.concat([cs, encrypt(Buffer.from(pb([[1, pubProto(myPub)], [2, sig]])))]))
  return { okSig, rkey, h }
}

test('noise XX responder interoperates with an independent initiator', async () => {
  const q = [[], []]; const w = [[], []]
  const chan = (i) => ({
    write: (m) => { const o = 1 - i; w[o].length ? w[o].shift()(m) : q[o].push(m) },
    read: () => q[i].length ? Promise.resolve(q[i].shift()) : new Promise((resolve) => w[i].push(resolve))
  })
  const seed = nc.randomBytes(32); const pub = await edPublic(seed)
  const server = nc.generateKeyPairSync('ed25519')
  const prologue = Buffer.from('libp2p-webrtc-noise:test')
  const [rpub, init] = await Promise.all([respond(chan(0), prologue, seed, pub), initiator(chan(1), prologue, server)])
  assert.ok(init.okSig, 'initiator verified our identity signature')
  assert.equal(hx(init.rkey), hx(pub))
  assert.equal(hx(rpub), hx(server.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)))
  // a different prologue (e.g. a DTLS fingerprint mismatch) must fail the handshake: the side
  // that notices throws, the other would wait for a message that never comes
  await assert.rejects(Promise.race([respond(chan(0), Buffer.from('other'), seed, pub), initiator(chan(1), prologue, server)]))
})
