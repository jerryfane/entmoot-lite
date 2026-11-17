import test from 'node:test'
import assert from 'node:assert/strict'
import nc from 'node:crypto'
import * as C from '../src/crypto.js'
const { xKeyPair, edPublic, edSign, edVerify, seal, open, poly1305, chacha20, hmac, sha256 } = C

const h = (s) => Uint8Array.from(Buffer.from(s.replace(/\s/g, ''), 'hex'))
const hx = (b) => Buffer.from(b).toString('hex')

// RFC 8032 section 7.1, TEST 1-3
const ED = [
  ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
  ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
    '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
  ['c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
    '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a']
]

test('ed25519 RFC 8032 vectors', async () => {
  for (const [sk, pk, msg, sig] of ED) {
    assert.equal(hx(await edPublic(h(sk))), pk)
    assert.equal(hx(await edSign(h(sk), h(msg))), sig)
    assert.ok(await edVerify(h(pk), h(msg), h(sig)))
    const bad = h(sig); bad[5] ^= 1
    assert.equal(await edVerify(h(pk), h(msg), bad), false)
    assert.equal(await edVerify(h(pk), h(msg + '00'), h(sig)), false)
  }
})

test('ed25519 matches node:crypto on random keys', async () => {
  for (let i = 0; i < 8; i++) {
    const seed = nc.randomBytes(32); const msg = nc.randomBytes(i * 37)
    const key = nc.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' })
    const pub = nc.createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(12)
    assert.equal(hx(await edPublic(seed)), hx(pub))
    const sig = await edSign(seed, msg)
    assert.equal(hx(sig), hx(nc.sign(null, msg, key)))
    assert.ok(await edVerify(pub, msg, sig))
  }
})

test('ed25519 rejects non-canonical S and bad points', async () => {
  const [sk, pk, , sig] = ED[0]
  const s = h(sig)
  // S + L (still < 2^256) must be rejected like Go does
  let S = 0n; for (let i = 63; i >= 32; i--) S = S << 8n | BigInt(s[i])
  S += 2n ** 252n + 27742317777372353535851937790883648493n
  for (let i = 32; i < 64; i++, S >>= 8n) s[i] = Number(S & 255n)
  assert.equal(await edVerify(h(pk), new Uint8Array(0), s), false)
  assert.equal(await edVerify(new Uint8Array(32).fill(255), new Uint8Array(0), h(sig)), false)
  assert.ok(sk)
})

test('xKeyPair (native X25519) agrees with node:crypto and refuses low-order keys', async () => {
  for (let i = 0; i < 4; i++) {
    const k = await xKeyPair(); const b = nc.generateKeyPairSync('x25519')
    const pkb = b.publicKey.export({ format: 'der', type: 'spki' }).subarray(12)
    const ours = nc.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), k.pub]), format: 'der', type: 'spki' })
    assert.equal(hx(await k.dh(pkb)), hx(nc.diffieHellman({ privateKey: b.privateKey, publicKey: ours })))
  }
  const k = await xKeyPair()
  await assert.rejects(k.dh(new Uint8Array(32))) // u = 0: all-zero shared secret
  await assert.rejects(k.dh(new Uint8Array(31)))
})

test('poly1305 RFC 8439 2.5.2', () => {
  assert.equal(hx(poly1305(h('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b'), new TextEncoder().encode('Cryptographic Forum Research Group'))),
    'a8061dc1305136c6c22b8baf0c0127a9')
})

test('chacha20 RFC 8439 2.4.2', () => {
  const key = h('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
  const nonce = h('000000000000004a00000000')
  const pt = new TextEncoder().encode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
  assert.equal(hx(chacha20(key, nonce, pt, 1)),
    '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d')
})

test('chacha20-poly1305 RFC 8439 2.8.2 and node:crypto interop', () => {
  const key = h('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
  const nonce = h('070000004041424344454647')
  const aad = h('50515253c0c1c2c3c4c5c6c7')
  const pt = new TextEncoder().encode("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
  const ct = seal(key, nonce, aad, pt)
  assert.equal(hx(ct.subarray(-16)), '1ae10b594f09e26a7e902ecbd0600691')
  assert.equal(hx(ct.subarray(0, 16)), 'd31a8d34648e60db7b86afbc53ef7ec2')
  assert.deepEqual(open(key, nonce, aad, ct), pt)
  ct[3] ^= 1
  assert.throws(() => open(key, nonce, aad, ct))
  for (const n of [0, 1, 15, 16, 17, 64, 65, 300]) {
    const k = nc.randomBytes(32); const iv = nc.randomBytes(12); const ad = nc.randomBytes(n % 33); const m = nc.randomBytes(n)
    const c = nc.createCipheriv('chacha20-poly1305', k, iv, { authTagLength: 16 }); c.setAAD(ad)
    const want = Buffer.concat([c.update(m), c.final(), c.getAuthTag()])
    assert.equal(hx(seal(k, iv, ad, m)), hx(want))
  }
})

test('hmac / sha256 via WebCrypto', async () => {
  assert.equal(hx(await sha256(new TextEncoder().encode('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  // RFC 4231 test case 2
  assert.equal(hx(await hmac(new TextEncoder().encode('Jefe'), new TextEncoder().encode('what do ya want for nothing?'))),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')
})

// Secret-key operations run only on native WebCrypto Ed25519/X25519.
async function spying (fn) {
  const calls = []
  const s = crypto.subtle
  const orig = { sign: s.sign, deriveBits: s.deriveBits }
  s.sign = function (alg, ...a) { calls.push('sign:' + (alg.name || alg)); return orig.sign.call(this, alg, ...a) }
  s.deriveBits = function (alg, ...a) { calls.push('deriveBits:' + (alg.name || alg)); return orig.deriveBits.call(this, alg, ...a) }
  try { await fn() } finally { Object.assign(s, orig) }
  return calls
}
/** Run fn with subtle[method] rejecting `err` for algorithm alg. */
async function withFailing (method, alg, err, fn) {
  const s = crypto.subtle; const orig = s[method]
  s[method] = function (...a) { if (a.some((x) => (x?.name || x) === alg)) return Promise.reject(err); return orig.apply(this, a) }
  try { return await fn() } finally { s[method] = orig }
}
const unsupported = () => new DOMException('Unrecognized algorithm name', 'NotSupportedError')

test('edSign uses WebCrypto Ed25519', async () => {
  const [sk, , msg, sig] = ED[1]
  let out
  const calls = await spying(async () => { out = await edSign(h(sk), h(msg)) })
  assert.ok(calls.includes('sign:Ed25519'), calls.join())
  assert.equal(hx(out), sig)
})

test('secret-key ops refuse without native Ed25519 / X25519 (no JS fallback)', async () => {
  const [sk, , msg] = ED[1]
  const needs = (e) => e.message === C.NEEDS_NATIVE && /Chrome\/Edge 137\+, Firefox 130\+, Safari 17\+/.test(e.message)
  await withFailing('importKey', 'Ed25519', unsupported(), async () => {
    await assert.rejects(edSign(h(sk), h(msg)), needs)
    await assert.rejects(edPublic(h(sk)), needs)
  })
  await withFailing('generateKey', 'X25519', unsupported(), () => assert.rejects(xKeyPair(), needs))
})

test('operational WebCrypto errors propagate unchanged', async () => {
  const [sk, , msg] = ED[1]
  const opErr = () => new DOMException('injected', 'OperationError')
  const isOp = (e) => e.name === 'OperationError' && e.message === 'injected'
  await withFailing('importKey', 'Ed25519', opErr(), () => assert.rejects(edSign(h(sk), h(msg)), isOp))
  await withFailing('sign', 'Ed25519', opErr(), () => assert.rejects(edSign(h(sk), h(msg)), isOp))
  await withFailing('generateKey', 'X25519', opErr(), () => assert.rejects(xKeyPair(), isOp))
  const k = await xKeyPair()
  const peer = nc.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(12)
  await withFailing('deriveBits', 'X25519', opErr(), () => assert.rejects(k.dh(peer), isOp))
})

test('noise handshake DH runs on WebCrypto X25519 when available', async () => {
  const { respond } = await import('../src/noise.js')
  const calls = await spying(async () => {
    // a valid ephemeral, then nothing: we only need the responder's own DH steps
    const peer = nc.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(12)
    let n = 0
    await Promise.race([respond({ read: async () => n++ ? new Promise(() => {}) : peer, write () {} }, new Uint8Array(0), h(ED[0][0]), h(ED[0][1])), new Promise((resolve) => setTimeout(resolve, 500))])
  })
  assert.ok(calls.includes('deriveBits:X25519'), calls.join())
})
