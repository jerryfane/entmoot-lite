// Noise_XX_25519_ChaChaPoly_SHA256 as the libp2p WebRTC-direct spec uses it: the browser (dialer)
// is the Noise RESPONDER, the server initiates. Only the handshake runs; the WebRTC connection
// is already encrypted by DTLS and Noise just binds both libp2p identities to the DTLS
// fingerprints through the prologue.
import { random, sha256, hmac, x25519, seal, open, edSign, edVerify } from './crypto.js'
import { pb, unpb } from './pb.js'
import { cat, enc } from './util.js'

const NAME = enc('Noise_XX_25519_ChaChaPoly_SHA256') // exactly 32 bytes: h = name
const SIG_PREFIX = enc('noise-libp2p-static-key:')
/** libp2p PublicKey protobuf for an Ed25519 key (KeyType Ed25519 = 1). */
export const pubProto = (pub) => pb([[1, 1], [2, pub]])

class Sym {
  constructor () { this.h = NAME; this.ck = NAME; this.k = null }
  async mix (data) { this.h = await sha256(cat(this.h, data)) }
  async mixKey (ikm) {
    const t = await hmac(this.ck, ikm)
    this.ck = await hmac(t, Uint8Array.of(1))
    this.k = await hmac(t, cat(this.ck, Uint8Array.of(2)))
    this.n = 0
  }

  nonce () { const n = new Uint8Array(12); new DataView(n.buffer).setUint32(4, this.n++, true); return n }
  async enc (p) { const c = this.k ? seal(this.k, this.nonce(), this.h, p) : p; await this.mix(c); return c }
  async dec (c) { const p = this.k ? open(this.k, this.nonce(), this.h, c) : c; await this.mix(c); return p }
}

/**
 * Run the responder side over `io` ({read(): Promise<Uint8Array> one Noise message,
 * write(Uint8Array) one Noise message}). `seed` is the libp2p Ed25519 identity seed.
 * Resolves with the remote libp2p Ed25519 public key (32 bytes) after checking its signature.
 */
export async function respond (io, prologue, seed, pub) {
  const s = new Sym()
  await s.mix(prologue)
  const sk = random(32); const spub = x25519(sk)
  const ek = random(32); const epub = x25519(ek)
  // <- e
  const m1 = await io.read()
  const re = m1.subarray(0, 32)
  await s.mix(re)
  await s.dec(m1.subarray(32))
  // -> e, ee, s, es, payload
  await s.mix(epub)
  await s.mixKey(x25519(ek, re))
  const cs = await s.enc(spub)
  await s.mixKey(x25519(sk, re))
  const payload = pb([[1, pubProto(pub)], [2, await edSign(seed, cat(SIG_PREFIX, spub))]])
  io.write(cat(epub, cs, await s.enc(payload)))
  // <- s, se, payload
  const m3 = await io.read()
  const rs = await s.dec(m3.subarray(0, 48))
  await s.mixKey(x25519(ek, rs))
  const p = unpb(await s.dec(m3.subarray(48)))
  const key = unpb(p[1][0])
  const rpub = key[2]?.[0]
  if (key[1]?.[0] !== 1 || !rpub || !await edVerify(rpub, cat(SIG_PREFIX, rs), p[2][0])) throw Error('noise: bad remote identity')
  return rpub
}
