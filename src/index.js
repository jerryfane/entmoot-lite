// entmoot-lite: join an Entmoot group from a browser over libp2p WebRTC-direct.
//   const g = await join({ addr, groupId, key, invite })
//   g.on('world/#', (msg) => ...); await g.publish('world/chat', 'hi'); await g.history('world/chat', 20); g.close()
import { edPublic, edSign, random, sha256 } from './crypto.js'
import { dial, peerIdBytes } from './webrtc.js'
import { pb, unpb } from './pb.js'
import { sign, verify, memberId, pubsubTopic, match, validTopic } from './entmoot.js'
import { b58, b64, cat, dec, enc, hex, lp, unb64 } from './util.js'

export { verify, match }
const MESHSUB = '/meshsub/1.1.0'
const PUBSUB_SIG = enc('libp2p-pubsub:')
const HISTORY = '/entmoot/history/2'

/**
 * @param {object} o
 * @param {string} o.addr     node multiaddr /ip4/../udp/../webrtc-direct/certhash/../p2p/..
 * @param {string} o.groupId  base64 group id
 * @param {Uint8Array|string} o.key  32-byte Ed25519 seed (or base64 of it); never stored
 * @param {object} [o.invite] target-bound invite (BootstrapCapability JSON) for this key
 * @param {(e: Error) => void} [o.onerror] errors while processing live traffic (a throwing
 *   on() handler, a failure inside the client); the connection keeps running. Default console.error.
 */
export async function join ({ addr, groupId, key, invite, timeout, onerror = (e) => console.error('entmoot-lite:', e) }) {
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
    if (m?.group_id !== groupId || !await verify(m)) return
    for (const [p, fn] of subs) if (m.topics?.some((t) => match(p, t))) try { fn(decode(m)) } catch (e) { onerror(e) }
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
    // one bad RPC (or a bug) must not end live delivery silently: report it and keep reading
    [MESHSUB]: async (st) => { for (;;) { const b = await st.lp(); try { await onRpc(b) } catch (e) { onerror(e) } } }
  }, timeout)

  // Entmoot sync protocols: one JSON line, half-close, one JSON reply. Errors carry the reply.
  const rpc = async (proto, req) => {
    const st = await conn.stream(proto, enc(JSON.stringify({ request_id: b64(random(9)), group_id: groupId, ...req }) + '\n'))
    st.end()
    const r = JSON.parse(dec(await st.all()))
    if (r.error) throw Object.assign(Error(`${proto}: ${r.error}${r.reason ? ' (' + r.reason + ')' : ''}`), { res: r })
    return r
  }
  /** the whole /entmoot/membership/1 answer: checkpoint and record pages walked to completion */
  const roster = async (capability) => {
    const cps = new Map(); const recs = new Map(); let r = {}
    do {
      const last = [...cps.values()].at(-1); const before = cps.size + recs.size
      r = await rpc('/entmoot/membership/1', {
        version: 1, capability, limit: 512, have_sequence: last?.sequence || undefined, have_checkpoint: last?.id, after_timestamp: r.next_timestamp, after_id: r.next_id
      })
      for (const c of r.checkpoints || []) cps.set(c.id, c)
      for (const x of r.records || []) recs.set(x.id, x)
      if (!r.complete && cps.size + recs.size === before) throw Error('membership: paging made no progress')
    } while (!r.complete)
    return { ...r, checkpoints: [...cps.values()], records: [...recs.values()] }
  }
  // Whether we are a member is the node's own Go roster projection (joins, rekeys, removals,
  // bans): it serves membership to a member's key without a capability, and to no one else.
  const asMember = () => roster().catch((e) => { if (/unauthorized|not_member/.test(e.res?.error)) return null; throw e })

  try {
    let r = await asMember()
    if (!r) {
      if (!invite) throw Error('not a member of this group and no invite given')
      // As the node's own record writer does (membership/group.go): land after the canonical
      // checkpoint and every record it holds, or the record is refused as stale.
      const held = await roster(invite)
      const cp = held.checkpoints.find((c) => c.id === held.canonical)
      const floor = Math.max(cp?.timestamp || 0, ...held.records.map((x) => x.timestamp))
      const record = await sign('membership-record/v3', {
        version: 3, group_id: groupId, kind: 'join', actor: me, subject: me, invite, invite_nonce: Array(32).fill(0), timestamp: Math.max(Date.now(), floor + 1)
      }, seed)
      await rpc('/entmoot/membership-push/1', { version: 1, capability: invite, record })
      r = await asMember()
      if (!r) throw Error('join record not applied by the node')
    }

    // GossipSub: subscribe only now that we are on the roster (the node drops non-member SUBSCRIBEs)
    out = await conn.stream(MESHSUB)
    send([[1, pb([[1, true], [2, topic]])], [3, pb([[3, pb([[1, topic]])]])]])

    /** message ids of the group's stored history, oldest first (whole list; see README limits) */
    const listIds = async () => {
      let ids = []; let req = {}
      for (let retries = 0; ;) {
        let page
        try {
          page = await rpc(HISTORY, { version: 2, mode: 'list', limit: 1024, ...req })
        } catch (e) {
          // like Go's keeper sync: drop the expired token; a changed snapshot restarts the walk
          if (e.res?.error !== 'snapshot_expired' || ++retries > 3) throw e
          req = e.res.snapshot_changed ? (ids = [], {}) : { ...req, snapshot_token: undefined }
          continue
        }
        ids.push(...page.ids || [])
        if (!page.has_more) return ids
        if (!page.ids?.length) throw Error('history: paging made no progress')
        req = {
          snapshot_token: page.snapshot_token, generation: page.generation,
          after_timestamp_ms: page.next_timestamp_ms, after_author_member_id: page.next_author_member_id, after_message_id: page.next_message_id
        }
      }
    }

    const g = {
      me,
      conn,
      topic,
      /** roster checkpoint id cited by new messages */
      get rosterHead () { return r.canonical },
      /** refresh and return the /entmoot/membership/1 answer (all checkpoints and records, canonical) */
      async roster () { return (r = await roster()) },
      /** call fn(msg) for every verified live message whose topics match pattern ("+", "#" wildcards) */
      on (pattern, fn) { subs.push([pattern, fn]); return g },
      /** sign and gossip a message; resolves with its id */
      async publish (t, content) {
        if (!validTopic(t)) throw Error('invalid topic: ' + JSON.stringify(t))
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
      /** newest n verified stored messages of this group matching pattern, oldest first */
      async history (pattern, n = 50) {
        const ids = await listIds()
        const got = new Map()
        for (let end = ids.length; end > 0 && got.size < n; end -= 64) {
          let want = ids.slice(Math.max(0, end - 64), end)
          while (want.length) {
            const b = await rpc(HISTORY, { version: 2, mode: 'bodies', ids: want })
            // only bodies we asked for, of this group; a truncated reply (has_more) is continued
            const done = new Set(b.missing)
            for (const m of b.messages || []) {
              if (!want.includes(m.id) || done.has(m.id)) continue
              done.add(m.id)
              if (m.group_id === groupId && m.topics?.some((t) => match(pattern, t)) && await verify(m)) got.set(m.id, decode(m))
            }
            const rest = want.filter((id) => !done.has(id))
            if (!b.has_more || rest.length === want.length) break
            want = rest
          }
        }
        return [...got.values()].sort((a, b) => a.timestamp - b.timestamp).slice(-n)
      },
      close () { conn.close() }
    }
    return g
  } catch (e) {
    conn.close()
    throw e
  }
}

const decode = (m) => ({ ...m, text: m.content ? dec(unb64(m.content)) : '' })
