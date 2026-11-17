// Bundle src/ into one minified ES module: dist/entmoot-lite.js
import { build } from 'esbuild'

await build({
  entryPoints: [new URL('../src/index.js', import.meta.url).pathname],
  outfile: new URL('../dist/entmoot-lite.js', import.meta.url).pathname,
  bundle: true,
  format: 'esm',
  minify: true,
  target: 'es2022',
  legalComments: 'none',
  banner: { js: '// entmoot-lite (MIT) https://github.com/jerryfane/entmoot-lite' }
})
