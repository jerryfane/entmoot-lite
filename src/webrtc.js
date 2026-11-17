// libp2p WebRTC-direct dialer (browser -> server, no signaling) and per-data-channel streams.
// Spec: https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md (+ webrtc.md framing).
import { random } from './crypto.js'
import { respond, pubProto } from './noise.js'
import { pb, unpb } from './pb.js'
import { cat, enc, dec, eq, lp, unb58, unb64, hex, uvarint } from './util.js'

const LIMIT = 16384 // SDP max-message-size: no frame from the peer can be larger
const MAX = LIMIT - 8 // payload per frame we send, minus pb + varint overhead
const ICE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const iceStr = () => [...random(32)].map((x) => ICE[x % 62]).join('')

/** Parse /ip4|ip6/<ip>/udp/<port>/webrtc-direct/certhash/<multibase>/p2p/<peer>. */
export function parseAddr (addr) {
  const m = addr.match(/^\/ip([46])\/([^/]+)\/udp\/(\d+)\/webrtc-direct\/certhash\/u([^/]+)(?:\/certhash\/[^/]+)*\/p2p\/(\w+)$/)
  if (!m) throw Error('unsupported multiaddr ' + addr)
  const hash = unb64(m[4])
  if (hash[0] !== 0x12 || hash[1] !== 32) throw Error('certhash must be sha2-256')
  return { ipv: m[1], ip: m[2], port: +m[3], hash, peer: m[5] }
}

/** The answer a libp2p server would give, inferred from its multiaddr (go-libp2p serverSDP). */
export const serverSdp = ({ ipv, ip, port, hash }, ufrag) => [
  'v=0', `o=- 0 0 IN IP${ipv} ${ip}`, 's=-', 't=0 0', 'a=ice-lite',
  `m=application ${port} UDP/DTLS/SCTP webrtc-datachannel`, `c=IN IP${ipv} ${ip}`, 'a=mid:0', 'a=ice-options:ice2',
  `a=ice-ufrag:${ufrag}`, `a=ice-pwd:${ufrag}`,
  'a=fingerprint:sha-256 ' + hex(hash.subarray(2)).toUpperCase().match(/../g).join(':'),
  'a=setup:passive', 'a=sctp-port:5000', 'a=max-message-size:16384',
  `a=candidate:1 1 UDP 1 ${ip} ${port} typ host`, 'a=end-of-candidates', ''
].join('\r\n')

/**
 * A libp2p stream on one RTCDataChannel: a byte stream of varint-length-prefixed pb
 * {flag=1, message=2} frames (go-libp2p writes prefix and frame as separate SCTP messages).
 * Read half: `eof` after the peer's FIN, `err` after RESET, a malformed frame or a close
 * without FIN. Write half: `wr` once the peer acknowledged our FIN or sent STOP_SENDING.
 * The channel closes when both halves are done.
 */
export class Stream {
  constructor (dc) {
    this.dc = dc; this.raw = this.buf = new Uint8Array(0); this.wake = () => {}
    dc.binaryType = 'arraybuffer'
    this.opened = new Promise((resolve, reject) => {
      if (dc.readyState === 'open') resolve()
      else if (dc.readyState !== 'connecting') reject(Error('channel closed'))
      dc.onopen = resolve
      dc.onerror = dc.onclose = () => { reject(Error('channel closed')); if (!this.eof) this.fail(Error('channel closed')); this.wake() }
    })
    this.opened.catch(() => {}) // awaited by whoever needs it; a channel nobody waits on may just close
    dc.onmessage = (e) => {
      if (dc.readyState === 'closed') return
      // libp2p sends only binary frames; binaryType does not cover text messages, and
      // new Uint8Array('2147483647') would allocate 2 GB, so anything else ends the stream
      if (!(e.data instanceof ArrayBuffer)) return this.fail(Error('non-binary message'))
      try {
        let b = cat(this.raw, new Uint8Array(e.data)); let v
        while ((v = uvarint(b, 0, LIMIT)) && b.length >= v[0] + v[1]) {
          const m = unpb(b.subarray(v[1], v[0] + v[1])); b = b.subarray(v[0] + v[1])
          if (m[2] && !this.eof && !this.err) this.buf = cat(this.buf, m[2][0])
          const f = m[1]?.[0]
          if (f === 0) { this.eof = true; this.frame([[1, 3]]) } // FIN -> FIN_ACK
          if (f === 2) this.err ||= Error('stream reset') // the peer abandoned its send half only
          if (f === 1 || f === 3) this.wr = true // STOP_SENDING / FIN_ACK
        }
        this.raw = b
        if ((this.eof || this.err) && this.wr) this.close()
      } catch (err) { this.fail(err) }
      this.wake()
    }
  }

  fail (e) { this.err ||= e; this.close(); this.wake() }
  frame (fields) { if (this.dc.readyState === 'open') this.dc.send(lp(pb(fields))) }
  write (b) { for (let i = 0; i < b.length; i += MAX) this.frame([[2, b.subarray(i, i + MAX)]]) }
  /** close our write half (FIN); the data channel closes once the remote acknowledges. */
  end () { this.frame([[1, 0]]) }
  close () { if (this.dc.readyState !== 'closed') this.dc.close() }
  async more () {
    if (this.err) throw this.err
    if (this.eof) throw Error('stream ended')
    await new Promise((resolve) => { this.wake = resolve })
  }

  async read (n) {
    while (this.buf.length < n) await this.more()
    const o = this.buf.subarray(0, n); this.buf = this.buf.subarray(n); return o
  }

  /** one unsigned-varint length-prefixed message of at most max bytes */
  async lp (max = 1 << 20) {
    try {
      let v
      while (!(v = uvarint(this.buf, 0, max))) await this.more()
      this.buf = this.buf.subarray(v[1])
      return await this.read(v[0])
    } catch (e) { this.fail(e); throw e }
  }

  /** everything up to the peer's FIN; a reset or a close without FIN rejects */
  async all () {
    while (!this.eof) await this.more()
    const o = this.buf; this.buf = new Uint8Array(0); return o
  }
}

// ---- multistream-select 1.0.0 ------------------------------------------------------------------
const MSS = '/multistream/1.0.0'
const line = (s) => lp(enc(s + '\n'))
const readLine = async (st) => dec(await st.lp()).slice(0, -1)
/** Header + protocol, pipelined with optional first payload; resolves once the remote agrees. */
export async function select (st, proto, first = new Uint8Array(0)) {
  st.write(cat(line(MSS), line(proto), first))
  if (await readLine(st) !== MSS || await readLine(st) !== proto) throw Error('protocol refused: ' + proto)
}
async function accept (st, handlers) {
  if (await readLine(st) !== MSS) return st.close()
  st.write(line(MSS))
  for (;;) {
    const p = await readLine(st)
    if (handlers[p]) { st.write(line(p)); return handlers[p](st) }
    st.write(line('na'))
  }
}

/**
 * Dial a libp2p WebRTC-direct multiaddr with Ed25519 identity `seed`/`pub`.
 * `handlers` maps protocol ids to fn(stream) for streams the server opens to us.
 * `signal` (AbortSignal): aborting it closes the RTCPeerConnection at once, during the dial too, and the
 * dial rejects; the dial owns its connection and timer from the start, so nothing outlives an abort.
 */
export async function dial (addr, seed, pub, handlers, timeout = 20000, signal) {
  const a = parseAddr(addr)
  if (signal?.aborted) throw signal.reason ?? Error('dial aborted')
  const pc = new RTCPeerConnection()
  let ended
  const conn = {
    pc,
    version: 1, // WebRTC-direct ufrag scheme used (2 when the browser refuses SDP munging)
    /** resolves once the connection is gone: ICE failed or disconnected, the node closed it, or close() */
    closed: new Promise((resolve) => { ended = resolve }),
    async stream (proto, first) {
      const st = new Stream(pc.createDataChannel(''))
      try {
        await st.opened
        await select(st, proto, first)
        return st
      } catch (e) { st.close(); throw e }
    },
    // pc.close() fires no connectionstatechange, so a local close ends `closed` itself
    close () { pc.close(); ended() }
  }
  pc.onconnectionstatechange = () => /failed|closed|disconnected/.test(pc.connectionState) && ended()
  let timer; let onAbort
  try {
    return await Promise.race([
      connect(),
      new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(Error('dial timeout')), timeout)
        onAbort = () => reject(signal.reason ?? Error('dial aborted'))
        signal?.addEventListener('abort', onAbort, { once: true })
      })
    ])
  } catch (e) { conn.close(); throw e } finally { clearTimeout(timer); signal?.removeEventListener('abort', onAbort) }

  async function connect () {
    const hs = new Stream(pc.createDataChannel('', { negotiated: true, id: 0 }))
    let authed
    const ready = new Promise((resolve) => { authed = resolve })
    pc.ondatachannel = (e) => { const st = new Stream(e.channel); Promise.all([st.opened, ready]).then(() => accept(st, handlers)).catch(() => st.close()) }
    const offer = await pc.createOffer()
    // v1: munge our ufrag+pwd to one "libp2p+webrtc+v1/" value the server reads from STUN.
    // v2 (browsers that refuse munged ufrags): keep ours, send our pwd inside the server ufrag.
    let ufrag = 'libp2p+webrtc+v1/' + iceStr()
    try {
      await pc.setLocalDescription({ type: 'offer', sdp: offer.sdp.replace(/(a=ice-(ufrag|pwd)):.*/g, '$1:' + ufrag) })
    } catch {
      await pc.setLocalDescription(offer)
      ufrag = 'libp2p+webrtc+v2/' + offer.sdp.match(/a=ice-pwd:(\S+)/)[1]
      conn.version = 2
    }
    await pc.setRemoteDescription({ type: 'answer', sdp: serverSdp(a, ufrag) })
    const fp = pc.localDescription.sdp.match(/a=fingerprint:sha-256 (\S+)/i)[1].replace(/:/g, '')
    const prologue = cat(enc('libp2p-webrtc-noise:'), Uint8Array.of(0x12, 32), Uint8Array.from(fp.match(/../g), (h) => parseInt(h, 16)), a.hash)
    await hs.opened
    // Noise frames carry a 2-byte big-endian length inside the stream.
    const io = {
      read: async () => { const l = await hs.read(2); return (await hs.read(l[0] << 8 | l[1])).slice() },
      write: (m) => hs.write(cat(Uint8Array.of(m.length >> 8, m.length & 255), m))
    }
    const rpub = await respond(io, prologue, seed, pub)
    if (!eq(peerIdBytes(rpub), unb58(a.peer))) throw Error('noise: peer id mismatch')
    hs.close()
    authed()
    return conn
  }
}

/** libp2p peer id bytes (identity multihash of the PublicKey protobuf). */
export const peerIdBytes = (pub) => cat(Uint8Array.of(0, 36), pubProto(pub))
