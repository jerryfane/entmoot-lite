// Hostile-peer input: stream framing, varints, protobuf and the Noise responder. Anything that
// could spin the JS thread runs in a child process with a deadline, so a hang fails the test
// instead of freezing the runner.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { Stream } from '../src/webrtc.js'
import { respond } from '../src/noise.js'
import { pb, unpb } from '../src/pb.js'
import { varint, cat } from '../src/util.js'
import { dcPair, settled, tick } from './fake-node.js'

const SRC = new URL('../src/', import.meta.url).href
/** Run an ES module body in a child node with a deadline; returns its stdout. */
function child (body, ms = 8000) {
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', body], { timeout: ms, encoding: 'utf8' })
  assert.notEqual(r.signal, 'SIGTERM', 'child hung (killed after ' + ms + ' ms)')
  assert.equal(r.status, 0, r.stderr)
  return r.stdout.trim()
}
const frame = (fields) => { const b = pb(fields); return cat(varint(b.length), b) }
const fakeDC = () => ({ readyState: 'open', sent: [], send (d) { this.sent.push(new Uint8Array(d)) }, close () { this.readyState = 'closed'; this.onclose?.() } })
const deliver = (dc, bytes) => { try { dc.onmessage({ data: Uint8Array.from(bytes).buffer }) } catch {} }

test('a text data-channel message ends the stream before any allocation', async () => {
  // binaryType only affects binary messages; new Uint8Array('1000') would be 1000 zero bytes
  const dc = fakeDC(); const st = new Stream(dc)
  const pending = st.read(1)
  try { dc.onmessage({ data: '1000' }) } catch {}
  assert.ok((await settled(pending)).e, 'reader rejected')
  assert.equal(dc.readyState, 'closed')
})

test('a huge numeric text message does not allocate or stall', () => {
  const out = child(`
    import { Stream } from '${SRC}webrtc.js'
    const dc = { readyState: 'open', send () {}, close () { this.readyState = 'closed'; this.onclose?.() } }
    const st = new Stream(dc)
    const t = performance.now()
    try { dc.onmessage({ data: '2147483647' }) } catch {}
    console.log(dc.readyState, performance.now() - t < 50)`)
  assert.equal(out, 'closed true')
})

test('overlong frame-length varint does not hang the thread', () => {
  const out = child(`
    import { Stream } from '${SRC}webrtc.js'
    const dc = { readyState: 'open', send () {}, close () { this.readyState = 'closed'; this.onclose?.() } }
    const st = new Stream(dc)
    // 300 continuation bytes then a final one: the multiplier overflows to Infinity and
    // 0 * Infinity makes the length NaN, so subarray(i + n) keeps the whole input
    const b = new Uint8Array(301).fill(0x80); b[300] = 1
    try { dc.onmessage({ data: b.buffer }) } catch {}
    const r = await Promise.race([st.read(1).then(() => 'data', (e) => 'rejected'), new Promise((r) => setTimeout(() => r('pending'), 200))])
    console.log(r, dc.readyState)`)
  assert.equal(out, 'rejected closed')
})

test('frames above the 16 KiB WebRTC message limit end the stream', async () => {
  const dc = fakeDC(); const st = new Stream(dc)
  deliver(dc, varint(16385))
  assert.ok((await settled(st.read(1))).e, 'reader rejected')
  assert.equal(dc.readyState, 'closed')
})

test('a malformed frame terminates the stream and rejects the pending reader', async () => {
  const dc = fakeDC(); const st = new Stream(dc)
  const pending = st.read(1)
  deliver(dc, [2, 0x0f, 0x00]) // length 2, protobuf wire type 7
  assert.ok((await settled(pending)).e, 'reader rejected')
  assert.equal(dc.readyState, 'closed')
  deliver(dc, frame([[2, Uint8Array.of(1)]])) // later frames are not parsed behind the poisoned prefix
  assert.ok((await settled(st.read(1))).e)
})

test('remote RESET ends only the read half; our write half stays usable', async () => {
  const dc = fakeDC(); const st = new Stream(dc)
  deliver(dc, frame([[1, 2]]))
  assert.ok((await settled(st.read(1))).e, 'read fails after reset')
  assert.equal(dc.readyState, 'open')
  st.write(Uint8Array.of(7))
  assert.equal(dc.sent.length, 1, 'response still sent')
  st.end() // our FIN; the remote's FIN_ACK completes the write half
  deliver(dc, frame([[1, 3]]))
  assert.equal(dc.readyState, 'closed')
})

test('clean FIN delivers buffered data, then EOF', async () => {
  const dc = fakeDC(); const st = new Stream(dc)
  deliver(dc, cat(frame([[2, Uint8Array.of(1, 2)]]), frame([[1, 0]])))
  assert.deepEqual([...await st.all()], [1, 2])
  assert.deepEqual([...dc.sent.at(-1)], [...frame([[1, 3]])], 'FIN_ACK sent')
})

test('a channel closed without FIN is an error, not EOF', async () => {
  const dc = fakeDC(); const st = new Stream(dc)
  deliver(dc, frame([[2, Uint8Array.of(1)]]))
  dc.close()
  assert.ok((await settled(st.all())).e)
})

test('opening rejects when the channel closes before it opens', async () => {
  const [a] = dcPair({ open: false })
  const st = new Stream(a)
  a.close()
  await tick()
  assert.ok((await settled(st.opened)).e, 'opened rejected')
  const closed = { readyState: 'closed', send () {}, close () {} }
  assert.ok((await settled(new Stream(closed).opened)).e, 'already-closed channel')
})

test('length-prefixed messages inside a stream are bounded', async () => {
  const dc = fakeDC(); const st = new Stream(dc)
  deliver(dc, frame([[2, new Uint8Array(12).fill(0xff)]]))
  assert.ok((await settled(st.lp())).e, 'overlong varint rejected')
  const dc2 = fakeDC(); const st2 = new Stream(dc2)
  deliver(dc2, frame([[2, varint(2 << 20)]]))
  assert.ok((await settled(st2.lp())).e, 'message above the limit rejected')
})

test('protobuf decoder rejects truncated and overlong input', () => {
  assert.throws(() => unpb(Uint8Array.of(0x09)), /truncated/) // fixed64 without its 8 bytes
  assert.throws(() => unpb(Uint8Array.of(0x08, 0x80)), /truncated/)
  assert.throws(() => unpb(new Uint8Array(20).fill(0xff)))
  assert.throws(() => unpb(Uint8Array.of(0x0a, 5, 1)), /truncated/)
})

test('fuzz: random and mutated frames never hang the stream or the decoder', () => {
  const out = child(`
    import { Stream } from '${SRC}webrtc.js'
    import { pb, unpb } from '${SRC}pb.js'
    let seed = 1
    const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n }
    const bytes = (n) => Uint8Array.from({ length: n }, () => rnd(4) ? rnd(256) : 0x80 + rnd(128))
    const valid = () => { const b = pb([[1, rnd(4)], [2, bytes(rnd(40))]]); return Uint8Array.of(b.length, ...b) }
    let ok = 0; let threw = 0
    for (let i = 0; i < 3000; i++) {
      let input = i % 3 === 0 ? bytes(rnd(400)) : valid()
      if (i % 3 === 1) { input = input.slice(); for (let j = rnd(4); j >= 0; j--) input[rnd(input.length)] = rnd(256) }
      if (i % 7 === 0) input = new Uint8Array(150 + rnd(100)).fill(0x80 + rnd(128))
      try { unpb(input); ok++ } catch { threw++ }
      const dc = { readyState: 'open', send () {}, close () { this.readyState = 'closed'; this.onclose?.() } }
      const st = new Stream(dc)
      for (let k = 0; k < input.length; k += 1 + rnd(64)) { try { dc.onmessage({ data: input.slice(k, k + 1 + rnd(64)).buffer }) } catch { threw++ } }
    }
    console.log('done', ok + threw > 0)`, 20000)
  assert.equal(out, 'done true')
})

const io = (msgs) => {
  const written = []
  return { written, read: async () => { if (!msgs.length) return new Promise(() => {}); return msgs.shift() }, write: (m) => written.push(m) }
}
test('noise responder rejects a low-order ephemeral key before answering', async () => {
  const seed = new Uint8Array(32).fill(3)
  const ch = io([new Uint8Array(32)]) // u = 0: X25519 output is all zeros
  assert.ok((await settled(respond(ch, Uint8Array.of(), seed, new Uint8Array(32)), 2000)).e)
  assert.equal(ch.written.length, 0)
})

test('noise responder rejects a truncated first message', async () => {
  const ch = io([new Uint8Array(10).fill(9)])
  assert.ok((await settled(respond(ch, Uint8Array.of(), new Uint8Array(32).fill(3), new Uint8Array(32)), 2000)).e)
  assert.equal(ch.written.length, 0)
})
