// Byte helpers shared by every layer.
export const enc = (s) => new TextEncoder().encode(s)
export const dec = (b) => new TextDecoder().decode(b)
export const cat = (...a) => {
  const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0))
  let i = 0
  for (const x of a) { o.set(x, i); i += x.length }
  return o
}
export const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])
export const b64 = (b) => btoa(String.fromCharCode(...b))
export const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
export const b64url = (b) => b64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
export const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('')

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
export function b58 (b) {
  let n = 0n
  for (const x of b) n = n * 256n + BigInt(x)
  let s = ''
  for (; n; n /= 58n) s = B58[Number(n % 58n)] + s
  for (let i = 0; b[i] === 0; i++) s = '1' + s
  return s
}
export function unb58 (s) {
  let n = 0n
  for (const c of s) { const v = B58.indexOf(c); if (v < 0) throw Error('bad base58'); n = n * 58n + BigInt(v) }
  const o = []
  for (; n; n >>= 8n) o.unshift(Number(n & 255n))
  for (let i = 0; s[i] === '1'; i++) o.unshift(0)
  return Uint8Array.from(o)
}

export function varint (n) {
  const o = []
  for (; n > 127; n = Math.floor(n / 128)) o.push(n & 127 | 128)
  o.push(n)
  return Uint8Array.from(o)
}
/** unsigned-varint length prefix */
export const lp = (b) => cat(varint(b.length), b)
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
