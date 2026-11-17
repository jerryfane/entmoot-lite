// Bundle src/ into one minified ES module: dist/entmoot-lite.js
//
// The whole bundle runs inside one function scope; only the public names (join, match, verify)
// are top-level, and only as exports. Pages that inline the module and turn it into a classic
// <script> (dropping `export`) would otherwise turn every minified internal into a global that the
// page can overwrite by accident: a page's `window.G = group` replaced the Ed25519 field
// exponentiation and every signature then failed to verify.
import { build } from 'esbuild'
import { writeFileSync } from 'node:fs'

const out = new URL('../dist/entmoot-lite.js', import.meta.url).pathname
const { outputFiles: [file] } = await build({
  entryPoints: [new URL('../src/index.js', import.meta.url).pathname],
  write: false,
  outfile: out,
  bundle: true,
  format: 'iife',
  globalName: 'EL',
  minify: true,
  target: 'es2022',
  legalComments: 'none'
})
// esbuild: `var EL=(()=>{...})();` -> a const binding inside the module, then the exports
const body = file.text.trim().replace(/^var EL=/, 'const EL=').replace(/;?$/, ';')
if (!body.startsWith('const EL=(()=>{')) throw Error('unexpected esbuild iife output')
writeFileSync(out, `// entmoot-lite (MIT) https://github.com/jerryfane/entmoot-lite
${body}export const{join,match,verify}=EL;
`)
