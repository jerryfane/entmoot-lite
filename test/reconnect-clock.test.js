// join()'s reconnect loop with a fake clock: backoff, offline publishes, close() and removal stop it.
import test from 'node:test'
import assert from 'node:assert/strict'
import { join } from '../src/index.js'
import { clock } from '../src/clock.js'
import { GROUP, until, member } from './member-node.js'

const realSleep = clock.sleep
test.afterEach(() => { clock.sleep = realSleep })

test('reconnect: backoff is 1 2 5 10 s then every 30 s', async () => {
  const { me, node } = member()
  const Real = globalThis.RTCPeerConnection
  const sleeps = []
  clock.sleep = async (ms) => {
    sleeps.push(ms)
    if (sleeps.length === 6) globalThis.RTCPeerConnection = Real // the node is reachable again
  }
  let reconnects = 0
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onreconnect: () => reconnects++ })
  globalThis.RTCPeerConnection = class { constructor () { throw Error('no route to the node') } }
  node.drop()
  await until(() => reconnects === 1)
  assert.deepEqual(sleeps, [1000, 2000, 5000, 10000, 30000, 30000])
  g.close()
})

test('reconnect: offline publish rejects and close stops reconnecting', async () => {
  const { me, node } = member()
  let wake
  clock.sleep = () => new Promise((resolve) => { wake = resolve })
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
  await new Promise((resolve) => setTimeout(resolve, 50))
  assert.equal(node.pc, pc, 'no new dial')
  assert.equal(reconnects, 0)
})

test('reconnect: a removed member stops trying and reports it', async () => {
  const { me, node } = member()
  const sleeps = []
  clock.sleep = async (ms) => { sleeps.push(ms) }
  const errors = []
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onerror: (e) => errors.push(e) })
  node.members.clear()
  node.drop()
  await until(() => errors.length)
  assert.match(errors[0].message, /no longer a member/)
  await new Promise((resolve) => setTimeout(resolve, 50))
  assert.deepEqual(sleeps, [1000])
  g.close()
})

test('reconnect: a node that stops answering pings is dialed again', async () => {
  const { me, node } = member()
  clock.sleep = async () => {}
  const { pingMs, pingWaitMs } = clock
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
  } finally {
    clock.pingMs = pingMs; clock.pingWaitMs = pingWaitMs
    g.close()
  }
})
