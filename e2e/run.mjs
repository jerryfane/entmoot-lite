// Browser end-to-end test against a real entmootd over WebRTC-direct.
//
//   ENTMOOTD=/path/to/entmootd node e2e/run.mjs
//
// Env (defaults in brackets):
//   ENTMOOTD        entmootd binary built from entmoot main with entmoot#252 (required)
//   E2E_DIR         node data dir [/root/fleet-tools/state/ordinals-lab/entmoot-webrtc/lite-e2e]
//   E2E_PORT        UDP port of the webrtc-direct listener [47210]
//   E2E_PUBLIC_IP   address announced and dialed [37.27.59.89]
//   E2E_LOG_LEVEL   entmootd -log-level [info]
//   E2E_GOLDEN      if set, write node-produced messages + roster to this path (test/golden.json)
//   PLAYWRIGHT      playwright module [/root/ordstudio/frontend/node_modules/playwright/index.mjs]
//
// It starts entmootd with its own data dir (never ~/.entmoot), creating the identity and a
// private test group on first use, and mints a target-bound invite for a fresh browser key with
// the plain -bootstrap /ip4/<ip>/udp/<port>/webrtc-direct/p2p/<id>; entmootd (entmoot#252) adds
// its /certhash, and the browser dials the address read from the invite. The page serves
// dist/entmoot-lite.js with ord's content CSP inside <iframe sandbox="allow-scripts"> in headless
// Chromium. Phases:
//   invite  join with the invite, read history, receive a live message the node publishes,
//           publish one that the node must store
//   member  same key, no invite (now on the roster): same checks
//   v2      Chromium with the WebRTC-NoSdpMangleUfrag field trial, so the dialer must use the
//           "libp2p+webrtc+v2/" ufrag scheme instead of munging the SDP: same checks
// Exits non-zero on any failure and always stops the node.
import { spawn, execFileSync } from 'node:child_process'
import { createServer } from 'node:http'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { randomBytes, createPrivateKey, createPublicKey } from 'node:crypto'

const env = process.env
const BIN = env.ENTMOOTD
const DIR = env.E2E_DIR || '/root/fleet-tools/state/ordinals-lab/entmoot-webrtc/lite-e2e'
const PORT = +(env.E2E_PORT || 47210)
const IP = env.E2E_PUBLIC_IP || '37.27.59.89'
const PW = env.PLAYWRIGHT || '/root/ordstudio/frontend/node_modules/playwright/index.mjs'
const ROOT = new URL('..', import.meta.url).pathname
const CSP = "default-src 'self' 'unsafe-eval' 'unsafe-inline' data: blob:"
if (!BIN) throw Error('set ENTMOOTD to an entmootd binary')
if (DIR.includes('/.entmoot')) throw Error('refusing to use a real entmoot data dir')
mkdirSync(DIR, { recursive: true })

const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a)
const base = ['-identity', `${DIR}/identity.json`, '-data', DIR, '-log-level', env.E2E_LOG_LEVEL || 'info',
  '-p2p-listen', `/ip4/0.0.0.0/udp/${PORT}/webrtc-direct`, '-p2p-announce', `/ip4/${IP}/udp/${PORT}/webrtc-direct`, '-listen-port', String(PORT + 1)]
const cli = (...a) => execFileSync('nice', ['-n', '10', 'timeout', '60', BIN, ...base, ...a], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
const fail = (m) => { throw Error(m) }
const until = async (fn, ms, what) => {
  for (const end = Date.now() + ms; Date.now() < end; await new Promise((resolve) => setTimeout(resolve, 100))) { const v = await fn(); if (v) return v }
  fail('timed out waiting for ' + what)
}

// ---- node ------------------------------------------------------------------------------------
if (!existsSync(`${DIR}/group-create.json`)) {
  cli('default-moot', 'decline')
  writeFileSync(`${DIR}/group-create.json`, cli('-allow-new-identity', 'group', 'create', '-name', 'lite-e2e'))
}
const created = JSON.parse(readFileSync(`${DIR}/group-create.json`, 'utf8'))
const GROUP = created.group_id
const BOOTSTRAP = `/ip4/${IP}/udp/${PORT}/webrtc-direct/p2p/${created.founder.peer_id}`

const node = spawn('nice', ['-n', '10', 'timeout', '900', BIN, ...base, 'serve', '-group', GROUP], { stdio: ['ignore', 'pipe', 'pipe'] })
let nodeLog = ''
node.stdout.on('data', (d) => { nodeLog += d })
node.stderr.on('data', (d) => { nodeLog += d })
const stopNode = () => { if (node.exitCode === null) node.kill('SIGTERM') }
process.on('exit', stopNode)
await until(() => nodeLog.includes('"event":"serving"'), 60000, 'entmootd serving').catch((e) => { console.log(nodeLog); stopNode(); throw e })
log('entmootd serving group', GROUP)
const publish = (text) => JSON.parse(cli('publish', '-group', GROUP, '-topic', 'world/chat', '-content', text))
const stored = () => cli('query', '-group', GROUP, '-limit', '200').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
publish('history seed ' + new Date().toISOString())

// ---- browser key + invite --------------------------------------------------------------------
function key () {
  const seed = randomBytes(32)
  const pub = createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' }))
    .export({ format: 'der', type: 'spki' }).subarray(12)
  const invite = JSON.parse(cli('invite', 'create', '-group', GROUP, '-target-pubkey', pub.toString('base64'), '-bootstrap', BOOTSTRAP))
  const addr = invite.allowed_multiaddrs?.find((a) => a.includes('/webrtc-direct/certhash/'))
  if (!addr) fail(`invite has no webrtc-direct address with /certhash (needs entmoot#252): ${JSON.stringify(invite.allowed_multiaddrs)}`)
  return { seed: seed.toString('base64'), invite, addr }
}

// ---- page server (ord-like: CSP on content, sandboxed frame) ---------------------------------
const lib = readFileSync(`${ROOT}dist/entmoot-lite.js`, 'utf8')
let cfg
const page = () => `<!doctype html><meta charset=utf-8><script type=text/plain id=lib>${lib.replace(/<\//g, '<\\/')}</script>
<script type=module>
const cfg = ${JSON.stringify(cfg)}
const R = window.R = { origin: self.origin, steps: [], live: [], errors: [] }
const t0 = performance.now(); const step = (s, x) => R.steps.push({ s, ms: Math.round(performance.now() - t0), ...x })
try {
  const { join } = await import(URL.createObjectURL(new Blob([document.getElementById('lib').textContent], { type: 'text/javascript' })))
  const g = window.G = await join(cfg)
  step('joined', { peer: g.me.peer_id, rosterHead: g.rosterHead, webrtcDirect: 'v' + g.conn.version })
  g.on('world/#', (m) => R.live.push({ id: m.id, text: m.text, ms: Math.round(performance.now() - t0) }))
  const h = await g.history('world/#', 50)
  R.history = h.map((m) => ({ id: m.id, text: m.text, ts: m.timestamp }))
  if (cfg.golden) R.golden = { messages: h.map(({ text, ...m }) => m), roster: await g.roster() }
  step('history', { n: h.length })
  R.published = await g.publish('world/chat', cfg.say)
  step('published', { id: R.published })
} catch (e) { R.errors.push(String(e && e.stack || e)) }
R.done = true
</script>`
const server = createServer((req, res) => {
  if (req.url === '/') return res.end('<!doctype html><iframe sandbox="allow-scripts" src="/content/e2e.html" style="width:100vw;height:90vh;border:0"></iframe>')
  if (req.url === '/content/e2e.html') { res.setHeader('content-security-policy', CSP); res.setHeader('content-type', 'text/html; charset=utf-8'); return res.end(page()) }
  res.statusCode = 404; res.end()
})
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))

// ---- phases ----------------------------------------------------------------------------------
const pw = await import(PW)
const browsers = []
const results = {}
async function phase (name, who, { withInvite, args = [], golden, version = 1, engine = 'chromium' }) {
  const browser = await pw[engine].launch({ args })
  browsers.push(browser)
  const say = `hello from entmoot-lite (${name}) ${randomBytes(4).toString('hex')}`
  cfg = { addr: who.addr, groupId: GROUP, key: who.seed, invite: withInvite ? who.invite : undefined, say, golden }
  const p = await browser.newPage()
  const errs = []
  p.on('pageerror', (e) => errs.push('pageerror: ' + e.message))
  p.on('console', (m) => m.type() === 'error' && errs.push('console: ' + m.text()))
  await p.goto(`http://127.0.0.1:${server.address().port}/`)
  const frame = await until(() => p.frames().find((f) => f.url().endsWith('/content/e2e.html')), 10000, 'frame')
  const R = () => frame.evaluate(() => window.R)
  await until(async () => (await R())?.done, 60000, name + ' browser steps')
  let r = await R()
  if (r.errors.length) fail(`${name}: ${r.errors.join('\n')}`)
  const sent = publish(`live from node (${name}) ${randomBytes(4).toString('hex')}`)
  const t = Date.now()
  await until(async () => (await R()).live.some((m) => m.id === sent.message_id), 20000, name + ' live message')
  const liveMs = Date.now() - t
  await until(() => stored().some((m) => m.message_id === r.published), 20000, name + ' browser message stored by node')
  r = await R()
  await frame.evaluate(() => window.G.close())
  await browser.close()
  results[name] = { browser: `${engine} ${browser.version()}`, origin: r.origin, steps: r.steps, history: r.history.length, lastHistory: r.history.slice(-3).map((m) => m.text), liveMs, live: r.live.map((m) => m.text), published: r.published, storedByNode: true, pageErrors: errs }
  log(name, JSON.stringify(results[name]))
  if (r.origin !== 'null') fail('frame origin is not opaque: ' + r.origin)
  if (r.steps[0].webrtcDirect !== 'v' + version) fail(`${name}: expected WebRTC-direct v${version}, got ${r.steps[0].webrtcDirect}`)
  if (golden) writeFileSync(golden, JSON.stringify({ captured: new Date().toISOString(), entmootd: 'entmoot main 281b884 (#252)', group: GROUP, ...r.golden }, null, 1) + '\n')
}
let code = 0
try {
  const a = key()
  log('dial address from invite', a.addr)
  await phase('invite', a, { withInvite: true })
  await phase('member', a, { withInvite: false, golden: env.E2E_GOLDEN })
  await phase('v2', key(), { withInvite: true, version: 2, args: ['--force-fieldtrials=WebRTC-NoSdpMangleUfrag/Enabled/'] })
  log('E2E OK')
} catch (e) {
  code = 1
  log('E2E FAILED', e.message)
  console.log(nodeLog.split('\n').slice(-30).join('\n'))
} finally {
  writeFileSync(`${DIR}/last-e2e.json`, JSON.stringify({ at: new Date().toISOString(), ok: !code, group: GROUP, results }, null, 1))
  for (const b of browsers) await b.close().catch(() => {})
  server.close()
  stopNode()
}
process.exit(code)
