// The built module must keep its internals private even when a page inlines it as a classic
// <script> (export dropped, as the live-node test page did). There, `window.G = group` overwrote
// the bundle's top-level `G` (Ed25519 field exponentiation): every live message and history body
// then failed verification and was dropped without an error.
import test from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { readFileSync } from 'node:fs'

const dist = readFileSync(new URL('../dist/entmoot-lite.js', import.meta.url), 'utf8')
const golden = JSON.parse(readFileSync(new URL('./golden.json', import.meta.url)))

/** The bundle as a classic script: `export` statements turned into a page global, as live.html did. */
function classic () {
  const exp = dist.match(/export\s*(?:const\s*)?\{([^}]*)\}(=EL)?;\s*$/)
  assert.ok(exp, 'bundle ends with its exports')
  const names = exp[1].split(',').map((x) => x.trim().split(/\s+as\s+/))
  const pairs = names.map(([a, b = a]) => `${b}:${exp[2] ? 'EL.' + a : a}`)
  return dist.slice(0, exp.index) + `;window.LIB={${pairs.join(',')}};`
}

test('inlined as a classic script, the bundle defines no globals besides its public API', () => {
  const ctx = vm.createContext({ crypto, TextEncoder, TextDecoder, atob, btoa, console })
  ctx.window = ctx
  const before = new Set(Object.getOwnPropertyNames(ctx))
  vm.runInContext(classic(), ctx)
  const added = Object.getOwnPropertyNames(ctx).filter((k) => !before.has(k))
  assert.deepEqual(added, ['LIB'])
})

test('page globals with short names do not break verification', async () => {
  const ctx = vm.createContext({ crypto, TextEncoder, TextDecoder, atob, btoa, console })
  ctx.window = ctx
  vm.runInContext(classic(), ctx)
  ctx.goldenMessage = golden.messages[0]
  assert.equal(await vm.runInContext('LIB.verify(goldenMessage)', ctx), true)
  // a page that assigns window.G, window.R, window.H ... (any one or two-letter name)
  const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$'
  for (const a of letters) { ctx[a] = { clobbered: true }; for (const b of letters + '0123456789') ctx[a + b] = { clobbered: true } }
  assert.equal(await vm.runInContext('LIB.verify(goldenMessage)', ctx), true)
})
