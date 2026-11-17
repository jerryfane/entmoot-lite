// join() after its connection to the node drops: it dials again, subscribes again, delivers the
// messages it missed once, then live messages again. Real clock (the first attempt waits 1 s).
import test from 'node:test'
import assert from 'node:assert/strict'
import { join } from '../src/index.js'
import { GROUP, msg, until, member } from './member-node.js'

test('reconnect: a dropped connection is dialed again and delivers missed then live messages', async () => {
  const { me, node } = member()
  let reconnects = 0
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, onreconnect: () => reconnects++ })
  const got = []
  g.on('t/#', (m) => got.push(m))
  const before = await msg('live before the drop')
  node.messages.push(before)
  await node.live(before)
  await until(() => got.length === 1)

  const firstPc = node.pc
  node.drop()
  const missed = await msg('stored while we were away')
  node.messages.push(missed)
  await until(() => reconnects === 1, 5000) // the first attempt waits 1 s
  assert.notEqual(node.pc, firstPc, 'a new connection')
  assert.equal(g.connected, true)
  assert.ok(node.subscribed.includes(node.pc), 'subscribed on the new connection')
  assert.deepEqual(got.map((m) => [m.text, !!m.late]), [['live before the drop 1', false], ['stored while we were away 2', true]])

  const after = await msg('live after the reconnect')
  await node.live(after)
  await until(() => got.length === 3)
  assert.equal(got[2].text, 'live after the reconnect 3')
  assert.equal(got[2].late, undefined)
  g.close()
})
