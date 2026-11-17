// Fail when the built client exceeds the inscription budget (30 KB brotli).
import { readFileSync } from 'node:fs'
import { brotliCompressSync, constants } from 'node:zlib'

const LIMIT = 30 * 1024
const file = new URL('../dist/entmoot-lite.js', import.meta.url)
const raw = readFileSync(file)
const br = brotliCompressSync(raw, { params: { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_MODE]: constants.BROTLI_MODE_TEXT } })
console.log(`dist/entmoot-lite.js raw ${raw.length} bytes, brotli ${br.length} bytes (limit ${LIMIT})`)
if (br.length > LIMIT) {
  console.error('over the 30 KB brotli budget')
  process.exit(1)
}
