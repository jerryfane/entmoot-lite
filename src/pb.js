// Hand-rolled protobuf (proto2/3 wire format): only varints and length-delimited fields.
import { cat, enc, uvarint, varint } from './util.js'

/**
 * Encode fields in the given order: pb([[1, bytes|string|number|bool|array], ...]).
 * Arrays encode repeated fields; undefined/null are skipped. Go marshals in field-number
 * order, so callers list fields ascending to stay byte-identical where signatures depend on it.
 */
export function pb (fields) {
  const out = []
  for (const [f, v] of fields) {
    for (const x of Array.isArray(v) ? v : [v]) {
      if (x == null) continue
      if (typeof x === 'number' || typeof x === 'boolean') out.push(varint(f << 3), varint(+x))
      else { const b = typeof x === 'string' ? enc(x) : x; out.push(varint(f << 3 | 2), varint(b.length), b) }
    }
  }
  return cat(...out)
}

/** Decode to {field: [values]}; varints as numbers, length-delimited as Uint8Array. Throws on malformed input. */
export function unpb (b) {
  const o = {}
  let i = 0
  const vi = () => { const v = uvarint(b, i, Number.MAX_SAFE_INTEGER); if (!v) throw Error('pb truncated'); i = v[1]; return v[0] }
  while (i < b.length) {
    const k = vi(); const t = k % 8
    let v
    if (t === 0) v = vi()
    else if (t === 2) { const n = vi(); v = b.subarray(i, i += n) } else if (t === 1 || t === 5) i += t === 1 ? 8 : 4
    else throw Error('pb wire type ' + t)
    if (i > b.length) throw Error('pb truncated')
    if (v !== undefined) (o[(k - t) / 8] ||= []).push(v)
  }
  return o
}
