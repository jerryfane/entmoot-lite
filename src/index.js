// entmoot-lite: join an Entmoot group from a browser over libp2p WebRTC-direct.
//   const g = await join({ addr, groupId, key, invite })
//   g.on('world/#', (msg) => ...); await g.publish('world/chat', 'hi'); await g.history('world/chat', 20); g.close()
import { edPublic, edSign, random, sha256 } from './crypto.js'
import { dial, peerIdBytes } from './webrtc.js'
import { pb, unpb } from './pb.js'
import { sign, verify, memberId, pubsubTopic, match } from './entmoot.js'
import { b58, b64, cat, dec, enc, hex, lp, unb64 } from './util.js'

export { verify, match }
const MESHSUB = '/meshsub/1.1.0'
const PUBSUB_SIG = enc('libp2p-pubsub:')

/**
 * @param {object} o
 * @param {string} o.addr     node multiaddr /ip4/../udp/../webrtc-direct/certhash/../p2p/..
 * @param {string} o.groupId  base64 group id
 * @param {Uint8Array|string} o.key  32-byte Ed25519 seed (or base64 of it); never stored
 * @param {object} [o.invite] target-bound invite (BootstrapCapability JSON) for this key
 */
export async function join ({ addr, groupId, key, invite, timeout }) {
  const seed = typeof key === 'string' ? unb64(key) : key
  const pub = await edPublic(seed)
  const me = { entmoot_pubkey: b64(pub), member_id: await memberId(pub), peer_id: b58(peerIdBytes(pub)) }
  const topic = await pubsubTopic(groupId)
  const subs = []; const seen = new Set(); let out
  let seq = BigInt(Date.now()) * 1000000n

  const emit = async (data) => {
    const mid = hex(await sha256(cat(enc('entmoot/pubsub-envelope/v2\0'), data)))
    if (seen.has(mid)) return
    seen.add(mid)
    let m
    try { m = JSON.parse(dec(data)) } catch { return }
    if (m.group_id !== groupId || !await verify(m)) return
    for (const [p, fn] of subs) if (m.topics?.some((t) => match(p, t))) fn(decode(m))
  }
  const onRpc = async (b) => {
    const r = unpb(b)
    for (const raw of r[2] || []) { const m = unpb(raw); if (dec(m[4]?.[0] || []) === topic && m[2]) await emit(m[2][0]) }
    // answer gossip (IHAVE) with IWANT for messages not seen yet
    const want = []
    for (const c of r[3] || []) for (const ih of unpb(c)[1] || []) for (const id of unpb(ih)[2] || []) if (!seen.has(hex(id))) want.push(id)
    if (want.length) send([[3, pb([[2, pb([[1, want]])]])]])
  }
  const send = (fields) => out?.write(lp(pb(fields)))

  const conn = await dial(addr, seed, pub, {
    // identify: tell the node we speak gossipsub, or it never adds us as a pubsub peer
    '/ipfs/id/1.0.0': (st) => { st.write(lp(pb([[1, pb([[1, 1], [2, pub]])], [3, ['/ipfs/id/1.0.0', MESHSUB]], [5, 'ipfs/0.1.0'], [6, 'entmoot-lite/0.1']]))); st.end() },
    [MESHSUB]: async (st) => { for (;;) await onRpc(await st.lp()) }
  }, timeout)

  // Entmoot sync protocols: one JSON line, half-close, one JSON reply.
  const rpc = async (proto, req) => {
    const st = await conn.stream(proto, enc(JSON.stringify({ request_id: b64(random(9)), group_id: groupId, ...req }) + '\n'))
    st.end()
    const r = JSON.parse(dec(await st.all()))
    if (r.error) throw Error(`${proto}: ${r.error}${r.reason ? ' (' + r.reason + ')' : ''}`)
    return r
  }
  // The invite authorizes sync requests until we are on the roster; afterwards membership does.
  let cap = invite
  const roster = () => rpc('/entmoot/membership/1', { version: 1, capability: cap, limit: 512 })

  let r = await roster()
  const isMember = () => {
    const cp = r.checkpoints?.at(-1)
    let ok = !!cp?.members.some((x) => x.member_id === me.member_id)
    for (const rec of r.records || []) if (rec.subject?.member_id === me.member_id) ok = rec.kind === 'join' || (ok && !/leave|remove/.test(rec.kind))
    return ok
  }
  if (!isMember()) {
    if (!invite) throw Error('not a member of this group and no invite given')
    const record = await sign('membership-record/v3', {
      version: 3, group_id: groupId, kind: 'join', actor: me, subject: me, invite, invite_nonce: Array(32).fill(0), timestamp: Date.now()
    }, seed)
    await rpc('/entmoot/membership-push/1', { version: 1, capability: invite, record })
    r = await roster()
  }
  cap = undefined

  // GossipSub: subscribe only now that we are on the roster (the node drops non-member SUBSCRIBEs)
  out = await conn.stream(MESHSUB)
  send([[1, pb([[1, true], [2, topic]])], [3, pb([[3, pb([[1, topic]])]])]])

  const g = {
    me,
    conn,
    topic,
    /** roster checkpoint id cited by new messages */
    get rosterHead () { return r.canonical },
    /** refresh and return the raw /entmoot/membership/1 reply (checkpoints, records, canonical) */
    async roster () { return (r = await roster()) },
    /** call fn(msg) for every verified live message whose topics match pattern ("+", "#" wildcards) */
    on (pattern, fn) { subs.push([pattern, fn]); return g },
    /** sign and gossip a message; resolves with its id */
    async publish (t, content) {
      const m = await sign('message/v2', {
        version: 2, group_id: groupId, author: me, timestamp: Date.now(), topics: [t],
        content: b64(typeof content === 'string' ? enc(content) : content) || undefined, roster_head: r.canonical
      }, seed)
      const data = enc(JSON.stringify(m))
      const sn = new Uint8Array(8); new DataView(sn.buffer).setBigUint64(0, ++seq)
      const fields = [[1, peerIdBytes(pub)], [2, data], [3, sn], [4, topic]]
      seen.add(hex(await sha256(cat(enc('entmoot/pubsub-envelope/v2\0'), data))))
      send([[2, pb([...fields, [5, await edSign(seed, cat(PUBSUB_SIG, pb(fields)))]])]])
      return m.id
    },
    /** newest n verified stored messages matching pattern, oldest first */
    async history (pattern, n = 50) {
      const ids = []; let page = {}
      do {
        page = await rpc('/entmoot/history/2', {
          version: 2, mode: 'list', limit: 1024, snapshot_token: page.snapshot_token, generation: page.generation,
          after_timestamp_ms: page.next_timestamp_ms, after_author_member_id: page.next_author_member_id, after_message_id: page.next_message_id
        })
        ids.push(...page.ids || [])
      } while (page.has_more)
      const got = []
      for (let end = ids.length; end > 0 && got.length < n; end -= 64) {
        const b = await rpc('/entmoot/history/2', { version: 2, mode: 'bodies', ids: ids.slice(Math.max(0, end - 64), end) })
        for (const m of b.messages || []) if (m.topics?.some((t) => match(pattern, t)) && await verify(m)) got.push(decode(m))
      }
      return got.sort((a, b) => a.timestamp - b.timestamp).slice(-n)
    },
    close () { conn.close() }
  }
  return g
}

const decode = (m) => ({ ...m, text: m.content ? dec(unb64(m.content)) : '' })
