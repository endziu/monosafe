import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const outputs = [
    ['index.html', 'monosafe.html'],
    ['monosafe.html', 'monosafe.html'],
    ['CNAME', 'CNAME']
];

for (const staleOutput of [false, true]) {
    test(`make build ${staleOutput ? 'replaces stale output' : 'creates the distribution from scratch'}`, t => {
        const directory = mkdtempSync(join(tmpdir(), 'monosafe-build-'));
        t.after(() => rmSync(directory, { recursive: true, force: true }));
        for (const name of ['Makefile', 'monosafe.html', 'CNAME']) {
            copyFileSync(new URL('../' + name, import.meta.url), join(directory, name));
        }
        const dist = join(directory, 'dist');
        if (staleOutput) {
            mkdirSync(dist);
            for (const [name] of outputs) writeFileSync(join(dist, name), 'stale output');
        }

        execFileSync('make', ['build'], { cwd: directory, timeout: 30000, stdio: 'pipe' });

        assert.deepEqual(readdirSync(dist).sort(), outputs.map(([name]) => name).sort());
        for (const [output, input] of outputs) {
            assert.deepEqual(readFileSync(join(dist, output)), readFileSync(join(directory, input)),
                `dist/${output} exactly matches ${input}`);
        }
    });
}
