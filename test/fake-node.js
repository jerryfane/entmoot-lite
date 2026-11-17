// Test doubles: an in-memory RTCDataChannel/RTCPeerConnection pair and a scriptable fake
// entmootd behind it (Noise initiator from node:crypto, multistream, Entmoot sync protocols).
// It lets join()/dial() run unmodified in node:test.
import nc from 'node:crypto'
import { Stream } from '../src/webrtc.js'
import { pb, unpb } from '../src/pb.js'
import { b58, b64, b64url, cat, dec, enc } from '../src/util.js'

const raw32 = (key) => key.export({ format: 'der', type: key.type === 'private' ? 'pkcs8' : 'spki' }).subarray(-32)
const edPubKey = (b) => nc.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), b]), format: 'der', type: 'spki' })
const xPubKey = (b) => nc.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), b]), format: 'der', type: 'spki' })
export const tick = () => new Promise((resolve) => setTimeout(resolve, 0))
/** Resolve with v, or with 'pending' if p has not settled within ms. */
export const settled = (p, ms = 300) => Promise.race([p.then((v) => ({ v }), (e) => ({ e })), new Promise((resolve) => setTimeout(() => resolve('pending'), ms))])

/** Two connected fake data channels. Handler exceptions are collected, as a browser reports them. */
export function dcPair ({ open = true } = {}) {
  const errors = []
  const mk = () => ({
    readyState: 'connecting',
    sent: [],
    fire (name, ev) { try { this['on' + name]?.(ev) } catch (e) { errors.push(e) } },
    send (d) {
      if (this.readyState !== 'open') throw Error('InvalidStateError')
      const copy = new Uint8Array(d).slice().buffer
      this.sent.push(new Uint8Array(copy))
      queueMicrotask(() => this.peer.readyState === 'open' && this.peer.fire('message', { data: copy }))
    },
    close () {
      for (const c of [this, this.peer]) {
        if (c.readyState === 'closed') continue
        c.readyState = 'closed'
        queueMicrotask(() => c.fire('close'))
      }
    }
  })
  const a = mk(); const b = mk(); a.peer = b; b.peer = a
  if (open) setTimeout(() => { for (const c of [a, b]) if (c.readyState === 'connecting') { c.readyState = 'open'; c.fire('open') } })
  return [a, b, errors]
}

/** Responder-facing Noise XX initiator (the server role in WebRTC-direct). */
export async function initiator (io, prologue, identity, { ephemeral } = {}) {
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
  const dh = (priv, pubRaw) => nc.diffieHellman({ privateKey: priv, publicKey: xPubKey(pubRaw) })
  mix(prologue)
  const e = nc.generateKeyPairSync('x25519'); const s = nc.generateKeyPairSync('x25519')
  const epub = ephemeral ?? raw32(e.publicKey)
  mix(epub); encrypt(Buffer.alloc(0))
  io.write(epub)
  const m2 = Buffer.from(await io.read())
  const re = m2.subarray(0, 32); mix(re); mixKey(dh(e.privateKey, re))
  const rs = decrypt(m2.subarray(32, 80)); mixKey(dh(e.privateKey, rs))
  const payload = unpb(decrypt(m2.subarray(80)))
  const rkey = unpb(payload[1][0])[2][0]
  const okSig = nc.verify(null, Buffer.concat([Buffer.from('noise-libp2p-static-key:'), rs]), edPubKey(rkey), payload[2][0])
  const cs = encrypt(raw32(s.publicKey)); mixKey(dh(s.privateKey, re))
  const sig = nc.sign(null, Buffer.concat([Buffer.from('noise-libp2p-static-key:'), raw32(s.publicKey)]), identity.privateKey)
  io.write(Buffer.concat([cs, encrypt(Buffer.from(pb([[1, pb([[1, 1], [2, raw32(identity.publicKey)]])], [2, sig]])))]))
  return { okSig, rkey }
}

/** Noise message framing (2-byte big-endian length) over a Stream. */
export const noiseIO = (st) => ({
  read: async () => { const l = await st.read(2); return (await st.read(l[0] << 8 | l[1])).slice() },
  write: (m) => st.write(cat(Uint8Array.of(m.length >> 8, m.length & 255), m))
})

const line = (s) => { const b = enc(s + '\n'); return cat(Uint8Array.of(b.length), b) }

/**
 * A fake entmootd. `node.handlers[protocol](request, node)` answers one JSON request (return the
 * reply object); `node.raw[protocol](stream)` takes over a stream. Installs globalThis.RTCPeerConnection.
 */
export function fakeNode () {
  const identity = nc.generateKeyPairSync('ed25519')
  const pub = raw32(identity.publicKey)
  const certhash = nc.randomBytes(32)
  const peer = b58(cat(Uint8Array.of(0, 36, 8, 1, 18, 32), pub))
  const node = {
    identity,
    peer,
    addr: `/ip4/127.0.0.1/udp/1/webrtc-direct/certhash/u${b64url(cat(Uint8Array.of(0x12, 32), certhash))}/p2p/${peer}`,
    handlers: {},
    raw: {},
    channels: [], // server ends of client-opened channels, with the protocol they asked for
    errors: [],
    requests: [],
    closed: false,
    clientPub: null
  }
  async function serveNoise (st) {
    await st.opened
    const fp = node.pc.localDescription.sdp.match(/a=fingerprint:sha-256 (\S+)/)[1].replace(/:/g, '')
    const prologue = cat(enc('libp2p-webrtc-noise:'), Uint8Array.of(0x12, 32), Buffer.from(fp, 'hex'), Uint8Array.of(0x12, 32), certhash)
    const r = await initiator(noiseIO(st), prologue, identity)
    node.clientPub = r.rkey
  }
  async function serve (st, rec) {
    await st.opened
    if (dec(await st.lp()) !== '/multistream/1.0.0\n') return
    st.write(line('/multistream/1.0.0'))
    for (;;) {
      const proto = dec(await st.lp()).slice(0, -1)
      rec.proto = proto
      if (node.raw[proto]) { st.write(line(proto)); return node.raw[proto](st) }
      if (!node.handlers[proto]) { st.write(line('na')); continue }
      st.write(line(proto))
      const req = JSON.parse(dec(await st.all()))
      node.requests.push({ proto, req })
      st.write(enc(JSON.stringify(await node.handlers[proto](req, node)) + '\n'))
      st.end()
      return
    }
  }
  globalThis.RTCPeerConnection = class {
    constructor () { node.pc = this; this.connectionState = 'new' }
    createDataChannel (label, init = {}) {
      const [a, b, errors] = dcPair()
      node.errors = errors
      const st = new Stream(b)
      if (init.negotiated) serveNoise(st).catch((e) => node.errors.push(e))
      else { const rec = { dc: b, client: a }; node.channels.push(rec); serve(st, rec).catch((e) => node.errors.push(e)) }
      return a
    }

    async createOffer () { return { type: 'offer', sdp: `v=0\r\na=ice-ufrag:abcd\r\na=ice-pwd:${'p'.repeat(24)}\r\na=fingerprint:sha-256 ${[...nc.randomBytes(32)].map((x) => x.toString(16).padStart(2, '0')).join(':')}\r\n` } }
    async setLocalDescription (d) { this.localDescription = d }
    async setRemoteDescription (d) { this.remoteDescription = d }
    close () { node.closed = true; this.connectionState = 'closed' }
  }
  return node
}

/** Ed25519 key helpers for tests. */
export function edKey (seed = nc.randomBytes(32)) {
  const priv = nc.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' })
  return { seed: new Uint8Array(seed), pub: raw32(nc.createPublicKey(priv)), priv }
}
export const memberOf = (pub) => b64(nc.createHash('sha256').update(Buffer.concat([Buffer.from('entmoot/member/v2\0'), pub])).digest())
