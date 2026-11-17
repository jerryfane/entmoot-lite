// Minimal crypto for entmoot-lite. Hashes and HMAC come from WebCrypto (SHA-256/512 and
// HMAC-SHA256 are available in every browser with WebRTC). Operations on secret keys (Ed25519
// signing, X25519 key agreement) use WebCrypto's native Ed25519/X25519 when the browser has them
// (Chrome/Edge 137+, Firefox 130+, Safari 17+); otherwise they fall back to the small BigInt code
// below (RFC 7748, RFC 8032), which runs a fixed number of steps but, being BigInt, is NOT
// constant-time. Ed25519 verification (public data) and ChaCha20-Poly1305 (RFC 8439) are JS.
import { cat, unb64 } from './util.js'

const subtle = crypto.subtle
export const random = (n) => crypto.getRandomValues(new Uint8Array(n))
export const sha256 = async (b) => new Uint8Array(await subtle.digest('SHA-256', b))
const sha512 = async (...b) => new Uint8Array(await subtle.digest('SHA-512', cat(...b)))
export const hmac = async (key, data) =>
  new Uint8Array(await subtle.sign('HMAC', await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), data))

// ---- field / scalar arithmetic over 2^255-19 -------------------------------------------------
const P = 2n ** 255n - 19n
const N = 2n ** 252n + 27742317777372353535851937790883648493n
const mod = (a, m = P) => { const r = a % m; return r < 0n ? r + m : r }
const pow = (b, e, m = P) => { let r = 1n; b = mod(b, m); for (; e > 0n; e >>= 1n, b = b * b % m) if (e & 1n) r = r * b % m; return r }
const inv = (a) => pow(a, P - 2n)
const le2n = (b) => { let n = 0n; for (let i = b.length; i--;) n = n << 8n | BigInt(b[i]); return n }
const n2le = (n) => { const b = new Uint8Array(32); for (let i = 0; i < 32; i++, n >>= 8n) b[i] = Number(n & 255n); return b }

// ---- X25519 (RFC 7748 Montgomery ladder, branch-free conditional swap) ---------------------
export function x25519 (k, u = Uint8Array.of(9)) {
  const s = le2n(k.slice(0, 32)) & ~7n & ~(1n << 255n) | 1n << 254n
  const x1 = le2n(u.length < 32 ? cat(u, new Uint8Array(32 - u.length)) : u) & (1n << 255n) - 1n
  let [x2, z2, x3, z3, sw] = [1n, 0n, x1, 1n, 0n]
  const cswap = (m) => { m = -m & (1n << 256n) - 1n; let t = m & (x2 ^ x3); x2 ^= t; x3 ^= t; t = m & (z2 ^ z3); z2 ^= t; z3 ^= t }
  for (let t = 254n; t >= 0n; t--) {
    const b = s >> t & 1n
    cswap(b ^ sw)
    sw = b
    const A = x2 + z2; const AA = A * A % P; const B = x2 - z2; const BB = B * B % P; const E = AA - BB
    const C = x3 + z3; const D = x3 - z3; const DA = D * A % P; const CB = C * B % P
    x3 = (DA + CB) ** 2n % P; z3 = mod(x1 * (DA - CB) ** 2n); x2 = mod(AA * BB); z2 = mod(E * (AA + 121665n * E))
  }
  cswap(sw)
  return n2le(mod(x2 * inv(z2)))
}

/**
 * Ephemeral X25519 key pair {pub, dh(peerPub)}. dh rejects malformed and low-order peer keys
 * (an all-zero shared secret), as Noise requires.
 */
export async function xKeyPair () {
  let pub; let dh
  try {
    const k = await subtle.generateKey('X25519', false, ['deriveBits'])
    pub = new Uint8Array(await subtle.exportKey('raw', k.publicKey))
    dh = async (p) => new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: await subtle.importKey('raw', p, 'X25519', false, []) }, k.privateKey, 256))
  } catch {
    const sk = random(32)
    pub = x25519(sk)
    dh = async (p) => x25519(sk, p)
  }
  return {
    pub,
    async dh (p) {
      const r = p?.length === 32 && await dh(p)
      if (!r || r.every((x) => !x)) throw Error('x25519: bad public key')
      return r
    }
  }
}

// ---- Ed25519 (RFC 8032, extended coordinates, cofactorless verify like Go) -------------------
const D = mod(-121665n * inv(121666n))
const I = pow(2n, (P - 1n) / 4n) // sqrt(-1)
const G = [15112221349535400772501151409588531511454012693041857206046113283949847762202n, 46316835694926478169428394003475163141307993866256225615783033603165251855960n, 1n]
G[3] = G[0] * G[1] % P
const ZERO = [0n, 1n, 1n, 0n]
function add ([X1, Y1, Z1, T1], [X2, Y2, Z2, T2]) {
  const A = (Y1 - X1) * (Y2 - X2) % P; const B = (Y1 + X1) * (Y2 + X2) % P
  const C = 2n * D * T1 * T2 % P; const Dd = 2n * Z1 * Z2 % P
  const E = B - A; const F = Dd - C; const Gg = Dd + C; const H = B + A
  return [E * F % P, Gg * H % P, F * Gg % P, E * H % P]
}
/** n·pt; with steps, always runs that many add/double rounds and selects without skipping work */
function mul (pt, n, steps = 0) {
  let r = ZERO
  for (let i = 0; n > 0n || i < steps; i++, n >>= 1n, pt = add(pt, pt)) { const s = add(r, pt); r = [r, s][Number(n & 1n)] }
  return r
}
function encode ([X, Y, Z]) { const zi = inv(Z); const x = mod(X * zi); const b = n2le(mod(Y * zi)); b[31] |= Number(x & 1n) << 7; return b }
function decode (b) {
  const y = le2n(b) & (1n << 255n) - 1n
  if (y >= P) throw Error('bad point')
  const u = mod(y * y - 1n); const v = mod(D * y * y + 1n)
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n))
  if (mod(v * x * x) !== u) { if (mod(v * x * x) !== mod(-u)) throw Error('bad point'); x = x * I % P }
  if ((x & 1n) !== BigInt(b[31] >> 7)) { if (!x) throw Error('bad point'); x = P - x }
  return [x, y, 1n, x * y % P]
}
const hashN = async (...b) => mod(le2n(await sha512(...b)), N)
async function expand (seed) {
  const h = await sha512(seed)
  const a = le2n(h.slice(0, 32)) & ~7n & ~(1n << 255n) | 1n << 254n
  return { a, prefix: h.slice(32), pub: encode(mul(G, a, 256)) }
}
// A WebCrypto Ed25519 key for the seed (RFC 8410 PKCS#8 wrapping), or undefined if unsupported.
const PKCS8 = Uint8Array.of(48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32)
const edKey = (seed) => subtle.importKey('pkcs8', cat(PKCS8, seed), 'Ed25519', true, ['sign']).catch(() => {})
/** Ed25519 public key (32 bytes) of a 32-byte seed. */
export async function edPublic (seed) {
  const k = await edKey(seed)
  return k ? unb64((await subtle.exportKey('jwk', k)).x) : (await expand(seed)).pub
}
/** Ed25519 signature (64 bytes) of msg with a 32-byte seed. */
export async function edSign (seed, msg) {
  const k = await edKey(seed)
  if (k) return new Uint8Array(await subtle.sign('Ed25519', k, msg))
  const { a, prefix, pub } = await expand(seed)
  const r = await hashN(prefix, msg)
  const R = encode(mul(G, r, 256))
  return cat(R, n2le(mod(r + await hashN(R, pub, msg) * a, N)))
}
/** Ed25519 verify; false on any malformed input. */
export async function edVerify (pub, msg, sig) {
  try {
    if (sig.length !== 64 || pub.length !== 32) return false
    const S = le2n(sig.slice(32))
    if (S >= N) return false
    const A = decode(pub); const R = sig.slice(0, 32)
    const k = await hashN(R, pub, msg)
    const chk = encode(add(mul(G, S), mul([P - A[0], A[1], A[2], P - A[3]], k)))
    return chk.every((x, i) => x === R[i])
  } catch { return false }
}

// ---- ChaCha20-Poly1305 (RFC 8439) -------------------------------------------------------------
function chachaBlock (key, counter, nonce) {
  const s = new Uint32Array(16); const k = new DataView(key.buffer, key.byteOffset); const nv = new DataView(nonce.buffer, nonce.byteOffset)
  s.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574])
  for (let i = 0; i < 8; i++) s[4 + i] = k.getUint32(i * 4, true)
  s[12] = counter
  for (let i = 0; i < 3; i++) s[13 + i] = nv.getUint32(i * 4, true)
  const x = s.slice()
  const q = (a, b, c, d) => {
    for (const [p, r, o, t] of [[a, b, d, 16], [c, d, b, 12], [a, b, d, 8], [c, d, b, 7]]) { x[p] += x[r]; x[o] = (x[o] ^ x[p]) << t | (x[o] ^ x[p]) >>> 32 - t }
  }
  for (let i = 0; i < 10; i++) { q(0, 4, 8, 12); q(1, 5, 9, 13); q(2, 6, 10, 14); q(3, 7, 11, 15); q(0, 5, 10, 15); q(1, 6, 11, 12); q(2, 7, 8, 13); q(3, 4, 9, 14) }
  for (let i = 0; i < 16; i++) x[i] += s[i]
  return new Uint8Array(x.buffer)
}
export function chacha20 (key, nonce, data, counter = 1) {
  const out = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i += 64) {
    const ks = chachaBlock(key, counter++, nonce)
    for (let j = 0; j < 64 && i + j < data.length; j++) out[i + j] = data[i + j] ^ ks[j]
  }
  return out
}
export function poly1305 (key, msg) {
  const r = le2n(key.slice(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn; const p = 2n ** 130n - 5n
  let acc = 0n
  for (let i = 0; i < msg.length; i += 16) {
    const blk = msg.slice(i, i + 16)
    acc = (acc + le2n(blk) + (1n << BigInt(8 * blk.length))) * r % p
  }
  return n2le(acc + le2n(key.slice(16, 32))).slice(0, 16)
}
function tag (key, nonce, aad, ct) {
  const pad = (b) => new Uint8Array((16 - b.length % 16) % 16)
  const len = new DataView(new ArrayBuffer(16)); len.setUint32(0, aad.length, true); len.setUint32(8, ct.length, true)
  return poly1305(chachaBlock(key, 0, nonce), cat(aad, pad(aad), ct, pad(ct), new Uint8Array(len.buffer)))
}
export const seal = (key, nonce, aad, pt) => { const ct = chacha20(key, nonce, pt); return cat(ct, tag(key, nonce, aad, ct)) }
export function open (key, nonce, aad, data) {
  const ct = data.slice(0, -16); const t = tag(key, nonce, aad, ct)
  if (data.length < 16 || t.some((x, i) => x !== data[data.length - 16 + i])) throw Error('decrypt failed')
  return chacha20(key, nonce, ct)
}
