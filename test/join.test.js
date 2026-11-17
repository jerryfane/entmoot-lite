// join()/dial() against the fake entmootd in fake-node.js: membership paging, join timestamps,
// cleanup on failure, history paging and binding, publish validation, stream negotiation.
import test from 'node:test'
import assert from 'node:assert/strict'
import { join } from '../src/index.js'
import { dial } from '../src/webrtc.js'
import { sign } from '../src/entmoot.js'
import { b64 } from '../src/util.js'
import { fakeNode, edKey, memberOf, tick } from './fake-node.js'

const GROUP = b64(new Uint8Array(32).fill(5))
const CP = b64(new Uint8Array(32).fill(6))
const author = edKey()
const authorInfo = { entmoot_pubkey: b64(author.pub), member_id: memberOf(author.pub), peer_id: 'x' }
const msg = (i, group = GROUP) => sign('message/v2', { version: 2, group_id: group, author: authorInfo, timestamp: 1000 + i, topics: ['t/a'], content: b64(Buffer.from('m' + i)), roster_head: CP }, author.seed)
const after = (r, ts, id) => !ts || r.timestamp > ts || (r.timestamp === ts && r.id > id)

/** A fake node with a one-checkpoint roster and Entmoot sync handlers mirroring Go's. */
function setup ({ members = [], cpMembers = members, records = [], perPage = 512, cpTimestamp = 1000, messages = [] } = {}) {
  const node = fakeNode()
  const st = { members: new Set(members), records, messages, pushed: [] }
  node.state = st
  const isMember = () => st.members.has(memberOf(node.clientPub))
  const authorized = (req) => isMember() || req.capability
  node.handlers['/entmoot/membership/1'] = (req) => {
    if (!authorized(req)) return { version: 1, request_id: req.request_id, error: 'unauthorized' }
    const pending = st.records.filter((r) => after(r, req.after_timestamp, req.after_id))
    const page = pending.slice(0, Math.min(perPage, req.limit || 512))
    return {
      version: 1,
      request_id: req.request_id,
      group_id: GROUP,
      checkpoints: req.have_checkpoint === CP ? undefined : [{ id: CP, sequence: 0, timestamp: cpTimestamp, members: cpMembers.map((member_id) => ({ member_id })) }],
      records: page,
      canonical: CP,
      canonical_sequence: 0,
      next_timestamp: page.at(-1)?.timestamp,
      next_id: page.at(-1)?.id,
      complete: page.length === pending.length
    }
  }
  node.handlers['/entmoot/membership-push/1'] = (req) => {
    st.pushed.push(req.record)
    const floor = Math.max(cpTimestamp, ...st.records.map((r) => r.timestamp))
    if (req.record.timestamp <= floor) return { version: 1, request_id: req.request_id, error: 'malformed', reason: 'stale record' }
    st.records.push(req.record)
    st.members.add(req.record.subject.member_id)
    return { version: 1, request_id: req.request_id, applied: true }
  }
  node.handlers['/entmoot/history/2'] = (req) => {
    if (!isMember()) return { version: 2, request_id: req.request_id, error: 'unauthorized' }
    if (req.mode === 'list') return { version: 2, request_id: req.request_id, ids: st.messages.map((m) => m.id) }
    return node.bodies ? node.bodies(req) : { version: 2, request_id: req.request_id, messages: st.messages.filter((m) => req.ids.includes(m.id)) }
  }
  node.raw['/meshsub/1.1.0'] = async (s) => { for (;;) node.rpc = await s.lp() }
  return node
}
const record = (i, ts) => ({ id: b64(new Uint8Array(32).fill(i)), kind: 'join', timestamp: ts, subject: { member_id: 'someone' + i } })
const invite = { group_id: GROUP }

test('membership: decided by the node, roster paged to completion', async () => {
  const me = edKey()
  // our join is on the third page of records; the first page alone does not show it
  const node = setup({ members: [memberOf(me.pub)], cpMembers: [], records: [record(1, 1001), record(2, 1002), { ...record(3, 1003), subject: { member_id: memberOf(me.pub) } }], perPage: 1 })
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed })
  assert.equal((await g.roster()).records.length, 3)
  assert.equal(node.state.pushed.length, 0, 'an existing member pushes no join record')
  g.close()
})

test('membership: a rekeyed-in member does not push a needless join', async () => {
  const me = edKey()
  // our key entered by a rekey record (subject = us), which the node's roster honours
  const node = setup({ members: [memberOf(me.pub)], cpMembers: [], records: [{ ...record(1, 1001), kind: 'rekey', subject: { member_id: memberOf(me.pub) } }] })
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, invite })
  assert.equal(node.state.pushed.length, 0)
  g.close()
})

test('join record timestamp is floored above the checkpoint and newest record', async () => {
  const me = edKey()
  const ahead = Date.now() + 120000 // node clock / checkpoint ahead of the browser clock
  const node = setup({ cpTimestamp: ahead - 10, records: [record(1, ahead)] })
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed, invite })
  assert.equal(node.state.pushed.length, 1)
  assert.equal(node.state.pushed[0].timestamp, ahead + 1)
  g.close()
})

test('join closes the connection when it fails after dialing', async () => {
  const node = setup()
  await assert.rejects(join({ addr: node.addr, groupId: GROUP, key: edKey().seed }))
  assert.equal(node.closed, true)
})

test('history: follows truncated bodies replies (has_more) to the end', async () => {
  const me = edKey()
  const messages = await Promise.all([0, 1, 2, 3, 4].map((i) => msg(i)))
  const node = setup({ members: [memberOf(me.pub)], messages })
  node.bodies = (req) => ({ version: 2, request_id: req.request_id, messages: messages.filter((m) => req.ids.includes(m.id)).slice(0, 2), has_more: req.ids.length > 2 })
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed })
  const h = await g.history('#', 50)
  assert.deepEqual(h.map((m) => m.text), ['m0', 'm1', 'm2', 'm3', 'm4'])
  g.close()
})

test('history: drops bodies from another group or not requested', async () => {
  const me = edKey()
  const mine = await msg(0)
  const foreign = await msg(1, b64(new Uint8Array(32).fill(9)))
  const unasked = await msg(2)
  const node = setup({ members: [memberOf(me.pub)], messages: [mine] })
  node.bodies = (req) => ({ version: 2, request_id: req.request_id, messages: [mine, foreign, unasked] })
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed })
  assert.deepEqual((await g.history('#', 50)).map((m) => m.id), [mine.id])
  g.close()
})

test('history: restarts listing after snapshot_expired', async () => {
  const me = edKey()
  const messages = [await msg(0)]
  const node = setup({ members: [memberOf(me.pub)], messages })
  const list = node.handlers['/entmoot/history/2']
  let first = true
  node.handlers['/entmoot/history/2'] = (req) => {
    if (req.mode === 'list' && first) { first = false; return { version: 2, request_id: req.request_id, ids: ['stale'], error: 'snapshot_expired', snapshot_changed: true } }
    return list(req)
  }
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed })
  assert.deepEqual((await g.history('#', 50)).map((m) => m.text), ['m0'])
  g.close()
})

test('publish refuses topics Go would not accept', async () => {
  const me = edKey()
  const node = setup({ members: [memberOf(me.pub)] })
  const g = await join({ addr: node.addr, groupId: GROUP, key: me.seed })
  for (const t of ['a\ud800b', 'a b', 'a//b', 'a/+', '#', '']) await assert.rejects(g.publish(t, 'x'), /topic/, JSON.stringify(t))
  await g.publish('a/b', 'x')
  g.close()
})

test('conn.stream closes the channel when the protocol is refused', async () => {
  const node = fakeNode()
  const me = edKey()
  const conn = await dial(node.addr, me.seed, me.pub, {})
  await assert.rejects(conn.stream('/nope/1'), /refused/)
  await tick()
  assert.equal(node.channels.at(-1).client.readyState, 'closed')
  conn.close()
})
