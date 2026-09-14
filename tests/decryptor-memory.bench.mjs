// Optional Linux/Node benchmark; excluded from the routine test suite.
// node --expose-gc tests/decryptor-memory.bench.mjs [source.html] [MiB]
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(process.argv[2] || new URL('../monosafe.html', import.meta.url), 'utf8');
const sizeMiB = Number(process.argv[3] || 8);
assert.ok(Number.isInteger(sizeMiB) && sizeMiB >= 1 && sizeMiB <= 32, 'use 1–32 MiB');
const context = vm.createContext({ Uint8Array, TextDecoder, atob });
for (const [start, end] of [
    ['function base64ToArray(', 'function deriveKey('],
    ['function extractDecryptedFile(', 'function download(']
]) {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0 && source.indexOf(end, offset) > offset);
    vm.runInContext(source.slice(offset, source.indexOf(end, offset)), context);
}
const name = 'private-zażółć-🔐.bin';
const content = Buffer.alloc(sizeMiB * 1024 * 1024);
for (let i = 0; i < content.length; i++) content[i] = i % 256;
const encoded = Buffer.concat([Buffer.from(name + '/'), content]).toString('base64');
global.gc?.();
const before = process.memoryUsage().rss;
const start = performance.now();
const decoded = context.base64ToArray(encoded);
const decodedAt = performance.now();
const file = context.extractDecryptedFile(decoded.buffer);
const extractedAt = performance.now();
const peak = process.resourceUsage().maxRSS * 1024;
assert.equal(file.name, name);
assert.deepEqual(file.content, new Uint8Array(content));
console.log(JSON.stringify({
    node: process.version, platform: process.platform, sizeMiB,
    decodeMs: +(decodedAt - start).toFixed(1),
    extractMs: +(extractedAt - decodedAt).toFixed(1),
    totalMs: +(extractedAt - start).toFixed(1),
    beforeRssMiB: +(before / 1024 ** 2).toFixed(1),
    peakRssMiB: +(peak / 1024 ** 2).toFixed(1)
}));
