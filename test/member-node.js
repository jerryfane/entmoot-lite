// A fake entmootd (test/fake-node.js) where one key is a member, with stored messages and a way to drop the
// client's connection, for the reconnect tests.
import { sign, pubsubTopic } from '../src/entmoot.js'
import { pb, unpb } from '../src/pb.js'
import { b64, enc, lp } from '../src/util.js'
import { fakeNode, edKey, memberOf } from './fake-node.js'

export const GROUP = b64(new Uint8Array(32).fill(11))
const CP = b64(new Uint8Array(32).fill(12))
const author = edKey()
const authorInfo = { entmoot_pubkey: b64(author.pub), member_id: memberOf(author.pub), peer_id: 'x' }
let n = 0
/** a signed message on t/a from another member, timestamped now; its text ends in a running number */
export const msg = (text) => sign('message/v2', { version: 2, group_id: GROUP, author: authorInfo, timestamp: Date.now(), topics: ['t/a'], content: b64(Buffer.from(text + ' ' + ++n)), roster_head: CP }, author.seed)
const gossip = async (m) => lp(pb([[2, pb([[2, enc(JSON.stringify(m))], [4, await pubsubTopic(GROUP)]])]]))
export const until = async (fn, ms = 3000) => { for (const end = Date.now() + ms; !fn(); await new Promise((resolve) => setTimeout(resolve, 5))) if (Date.now() > end) throw Error('timed out: ' + fn) }

/**
 * A fake node where `me` is a member. node.messages: stored messages; node.members: member ids;
 * node.subscribed: connections on which the client sent SUBSCRIBE; node.drop(): its current
 * connection fails; node.live(m): gossip m to the client on the current connection.
 */
export function member () {
  const me = edKey()
  const node = fakeNode()
  node.members = new Set([memberOf(me.pub)])
  node.messages = []
  node.subscribed = []
  const isMember = () => node.members.has(memberOf(node.clientPub))
  node.handlers['/entmoot/membership/1'] = (req) => isMember()
    ? { version: 1, request_id: req.request_id, group_id: GROUP, checkpoints: [{ id: CP, sequence: 0, timestamp: 1000, members: [] }], records: [], canonical: CP, complete: true }
    : { version: 1, request_id: req.request_id, error: 'unauthorized' }
  node.handlers['/entmoot/history/2'] = (req) => req.mode === 'list'
    ? { version: 2, request_id: req.request_id, ids: node.messages.map((m) => m.id) }
    : { version: 2, request_id: req.request_id, messages: node.messages.filter((m) => req.ids.includes(m.id)) }
  node.raw['/meshsub/1.1.0'] = async (s) => { const pc = node.pc; for (;;) if (unpb(await s.lp())[1]) node.subscribed.push(pc) }
  node.drop = () => { node.pc.connectionState = 'failed'; node.pc.onconnectionstatechange() }
  node.live = async (m) => (await node.pc.openToClient('/meshsub/1.1.0')).write(await gossip(m))
  return { me, node }
}
