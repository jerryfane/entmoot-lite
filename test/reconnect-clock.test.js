// join()'s reconnect loop: backoff (fake timers), offline calls, close() at every stage, removal, pings,
// attempt deadlines, publish racing a drop, the whole catch-up backlog, and no timers left after close().
import test from 'node:test'
import assert from 'node:assert/strict'
import { join } from '../src/index.js'
import { clock } from '../src/clock.js'
import { GROUP, until, msg, member } from './member-node.js'

const real = { ...clock }
test.afterEach(() => Object.assign(clock, real))
/** backoff waits end at once (and are logged); other timers (pings, deadlines) are real */
const instantBackoff = () => {
  const log = []
  clock.timer = (ms, fn, kind) => {
    if (kind !== 'backoff') return real.timer(ms, fn, kind)
    log.push(ms)
    queueMicrotask(fn)
    return () => {}
  }
  return log
}
const tick = (ms = 50) => new Promise((resolve) => setTimeout(resolve, ms))

test('reconnect: backoff is 1 2 5 10 s then every 30 s', async () => {
  const { me, node } = member()
  const Real = globalThis.RTCPeerConnection
  const log = instantBackoff()
  let reconnects = 0
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onreconnect: () => reconnects++, onerror: () => {} })
  globalThis.RTCPeerConnection = class { constructor () { if (log.length >= 6) return new Real(); throw Error('no route to the node') } }
  try {
    node.drop()
    await until(() => reconnects === 1)
    assert.deepEqual(log, [1000, 2000, 5000, 10000, 30000, 30000])
  } finally { globalThis.RTCPeerConnection = Real; g.close() }
})

test('reconnect: offline publish rejects and close stops reconnecting', async () => {
  const { me, node } = member()
  let wake
  clock.timer = (ms, fn, kind) => { if (kind === 'backoff') { wake = fn; return () => {} } return real.timer(ms, fn, kind) }
  let reconnects = 0
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onreconnect: () => reconnects++ })
  const pc = node.pc
  node.drop()
  await until(() => wake)
  assert.equal(g.connected, false)
  await assert.rejects(g.publish('t/a', 'hi'), (e) => e.code === 'offline')
  await assert.rejects(g.history('t/#'), (e) => e.code === 'offline')
  g.close()
  wake()
  await tick()
  assert.equal(node.pc, pc, 'no new dial')
  assert.equal(reconnects, 0)
})

test('reconnect: a removed member stops trying and reports it', async () => {
  const { me, node } = member()
  const log = instantBackoff()
  const errors = []
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onerror: (e) => errors.push(e) })
  node.members.clear()
  node.drop()
  await until(() => errors.length)
  assert.match(errors[0].message, /no longer a member/)
  await tick()
  assert.deepEqual(log, [1000])
  g.close()
})

test('reconnect: a node that stops answering pings is dialed again', async () => {
  const { me, node } = member()
  instantBackoff()
  clock.pingMs = 20; clock.pingWaitMs = 50
  const pings = []
  // a live node echoes; a restarted one (same port, session gone) never answers on the old connection
  let silent = false
  node.raw['/ipfs/ping/1.0.0'] = async (s) => { const b = await s.read(32); pings.push(node.pc); if (!silent) s.write(b.slice()) }
  let reconnects = 0
  const errors = []
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onreconnect: () => reconnects++, onerror: (e) => errors.push(e.message) })
  try {
    await until(() => pings.length >= 3)
    assert.equal(reconnects, 0, 'answered pings keep the connection')
    const first = node.pc
    silent = true
    await until(() => reconnects === 1)
    assert.notEqual(node.pc, first)
    assert.ok(errors.includes('the node stopped answering; reconnecting'))
  } finally { g.close() }
})

test('review P1: close during a reconnect attempt cancels it and the connection never comes back', async () => {
  const { me, node } = member()
  instantBackoff()
  let reconnects = 0
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onerror: () => {}, onreconnect: () => reconnects++ })
  // the rejoin's membership request hangs until we let it through
  const answer = node.handlers['/entmoot/membership/1']
  let release; const gate = new Promise((resolve) => { release = resolve })
  let asked = 0
  node.handlers['/entmoot/membership/1'] = async (req) => { asked++; await gate; return answer(req) }
  const first = node.pc
  node.drop()
  await until(() => asked === 1, 5000)
  const candidate = node.pc
  assert.notEqual(candidate, first)
  g.close()
  release()
  await tick(100)
  assert.equal(g.connected, false, 'close() is final')
  assert.equal(candidate.connectionState, 'closed', 'the candidate connection was closed')
  assert.equal(reconnects, 0)
})

test('review P1: a reconnect attempt whose membership request never answers is abandoned and retried', async () => {
  const { me, node } = member()
  instantBackoff()
  clock.attemptMs = 300
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onerror: () => {} })
  const answer = node.handlers['/entmoot/membership/1']
  let asked = 0
  node.handlers['/entmoot/membership/1'] = (req) => ++asked === 1 ? new Promise(() => {}) : answer(req) // first rejoin: silence
  const attempts = []
  const Real = globalThis.RTCPeerConnection
  globalThis.RTCPeerConnection = class extends Real { constructor (...a) { super(...a); attempts.push(this) } }
  try {
    node.drop()
    await until(() => g.connected && attempts.length >= 2, 10000).catch(() => {})
    assert.ok(attempts.length >= 2, 'another attempt after the first one timed out')
    assert.equal(attempts[0].connectionState, 'closed', 'the abandoned attempt was closed')
    assert.equal(g.connected, true)
  } finally { globalThis.RTCPeerConnection = Real; g.close() }
})

test('review P2: publish racing a drop during its last signature rejects instead of resolving unsent', async () => {
  const { me, node } = member()
  clock.timer = (ms, fn, kind) => kind === 'backoff' ? () => {} : real.timer(ms, fn, kind) // stay offline after the drop
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onerror: () => {} })
  const subtle = globalThis.crypto.subtle
  const sign = subtle.sign
  let ed = 0
  subtle.sign = function (alg, ...a) {
    // publish signs twice with Ed25519: the message, then the gossipsub envelope; drop during the second
    if ((alg?.name || alg) === 'Ed25519' && ++ed === 2) node.drop()
    return sign.call(this, alg, ...a)
  }
  try {
    await assert.rejects(g.publish('t/a', 'hi'), (e) => e.code === 'offline')
  } finally { subtle.sign = sign; g.close() }
})

test('review P2: catch-up delivers the whole missed backlog, not just 512', { timeout: 120000 }, async () => {
  const { me, node } = member()
  instantBackoff()
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onerror: () => {} })
  const got = []
  g.on('t/#', (m) => got.push(m))
  const missed = []
  for (let i = 0; i < 520; i++) missed.push(await msg('missed'))
  // stored while the client is away (pushed before the reconnect can list history)
  node.drop()
  node.messages.push(...missed)
  await until(() => got.length >= 520, 100000).catch(() => {})
  assert.equal(got.length, 520)
  assert.ok(got.every((m) => m.late))
  g.close()
})

test('review P3: close leaves no pending timers for backoff or ping', async () => {
  const { me, node } = member()
  const Real = globalThis.RTCPeerConnection
  const realSet = globalThis.setTimeout; const realClear = globalThis.clearTimeout
  const live = new Map() // long timers (≥ 1 s) not yet fired or cleared
  globalThis.setTimeout = (fn, ms, ...a) => {
    const t = realSet(() => { live.delete(t); fn(...a) }, ms)
    if (ms >= 1000) live.set(t, ms)
    return t
  }
  globalThis.clearTimeout = (t) => { live.delete(t); realClear(t) }
  try {
    // connected: the keepalive is waiting for its next ping
    const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onerror: () => {} })
    await tick()
    g.close()
    await tick()
    assert.deepEqual([...live.values()], [], 'no timers after close() while connected')
    // reconnecting: the backoff is waiting
    const h = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onerror: () => {} })
    globalThis.RTCPeerConnection = class { constructor () { throw Error('no route') } }
    node.drop()
    await tick()
    h.close()
    await tick()
    assert.deepEqual([...live.values()], [], 'no timers after close() while reconnecting')
  } finally {
    globalThis.setTimeout = realSet; globalThis.clearTimeout = realClear
    globalThis.RTCPeerConnection = Real
  }
})

test('reconnect: another session with the same key keeps taking the connection, so stop with code replaced', async () => {
  const { me, node } = member()
  instantBackoff()
  // the node closes every connection of this key right after it is set up (another tab keeps taking it)
  let dials = 0
  const Real = globalThis.RTCPeerConnection
  globalThis.RTCPeerConnection = class extends Real { constructor (...a) { super(...a); dials++; setTimeout(() => node.pc === this && node.drop(), 30) } }
  const errors = []
  try {
    const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onerror: (e) => errors.push(e) })
    await until(() => errors.some((e) => e.code === 'replaced'), 5000).catch(() => {})
    const at = dials
    await tick(300)
    assert.ok(errors.some((e) => e.code === 'replaced'), 'stopped with code replaced')
    assert.equal(at, 3, 'three short-lived connections')
    assert.equal(dials, at, 'no more dials after replaced')
    assert.equal(g.connected, false)
    assert.equal(g.stopped?.code, 'replaced')
    await assert.rejects(g.publish('t/a', 'hi'), (e) => e.code === 'replaced')
    g.close()
  } finally { globalThis.RTCPeerConnection = Real }
})
