// Entmoot message layer: Go canonical JSON, ids, signatures, topic names and patterns.
import { sha256, edSign, edVerify } from './crypto.js'
import { b64, b64url, cat, enc, unb64 } from './util.js'

export const ZERO = b64(new Uint8Array(32))

/**
 * pkg/entmoot/canonical.Encode on a value that already went through Go's json.Marshal
 * (so omitempty is applied): keys sorted at every level, compact, no HTML escaping.
 * JSON.stringify matches Go's string escaping except U+2028/U+2029, which Go escapes.
 */
export function canon (v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join() + ']'
  if (v && typeof v === 'object') return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => str(k) + ':' + canon(v[k])).join() + '}'
  return typeof v === 'string' ? str(v) : JSON.stringify(v)
}
const str = (s) => JSON.stringify(s).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029')

/** Bytes that are hashed (id) and signed: domain prefix + canonical form with id zeroed, no signature. */
export function signingBytes (domain, obj) {
  const o = { ...obj, id: ZERO }
  delete o.signature
  return cat(enc(`entmoot/${domain}\0`), enc(canon(o)))
}

/** Fill id and signature (messages: domain "message/v2"; roster records: "membership-record/v3"). */
export async function sign (domain, obj, seed) {
  const bytes = signingBytes(domain, obj)
  obj.id = b64(await sha256(bytes))
  obj.signature = b64(await edSign(seed, bytes))
  return obj
}

/** Check id, Ed25519 signature and member id of a received message. */
export async function verify (m) {
  try {
    const pub = unb64(m.author.entmoot_pubkey)
    const bytes = signingBytes('message/v2', m)
    return m.id === b64(await sha256(bytes)) && m.author.member_id === await memberId(pub) &&
      await edVerify(pub, bytes, unb64(m.signature))
  } catch { return false }
}

export const memberId = async (pub) => b64(await sha256(cat(enc('entmoot/member/v2\0'), pub)))
export const pubsubTopic = async (groupId) => '/entmoot/group/2/' + b64url(await sha256(cat(enc('entmoot/topic/v2\0'), unb64(groupId))))

/** Entmoot topic pattern match: "+" one segment, trailing "#" any rest (incl. none). */
export function match (pattern, topic) {
  const p = pattern.split('/'); const t = topic.split('/')
  for (let i = 0; i < p.length; i++) {
    if (p[i] === '#') return true
    if (i >= t.length || (p[i] !== '+' && p[i] !== t[i])) return false
  }
  return p.length === t.length
}
