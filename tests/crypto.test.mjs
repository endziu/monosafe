import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { test } from 'node:test';
import {
    source, bytes, filename, password, containerNamePattern, DOWNLOAD_CLEANUP_DELAY,
    page, artifact, assertRecovered, assertCryptoProfile, sharingNavigator, settle, embeddedPayload
} from './harness.mjs';

// ---- download lifecycle ----

test('downloads retain the object URL briefly, then revoke it and remove the anchor, in both flows', async () => {
    const html = await artifact(source);
    for (const [document, operation, namePattern] of [
        [source, 'runEncrypt', containerNamePattern], [html, 'runDecrypt', new RegExp('^' + filename.replace(/[.]/g, '\\.') + '$')]
    ]) {
        const instance = page(document, password, password, { download: 'native' });
        await instance.run(operation);
        assert.equal(instance.anchors.length, 1, operation);
        const [anchor] = instance.anchors;
        assert.equal(anchor.clicked.length, 1, operation);
        assert.match(anchor.clicked[0].download, namePattern, operation);
        assert.equal(instance.urls.created.length, 1, operation);
        assert.equal(anchor.clicked[0].href, instance.urls.created[0].url, operation);
        assert.ok(instance.timers.includes(DOWNLOAD_CLEANUP_DELAY), operation + ' schedules delayed cleanup');
        assert.deepEqual(instance.urls.revoked, [], operation + ' keeps the URL live after initiation');
        assert.deepEqual(instance.body.children, [anchor], operation + ' keeps the anchor attached after initiation');
        instance.advanceTimers();
        assert.deepEqual(instance.urls.revoked, [instance.urls.created[0].url], operation);
        assert.deepEqual(instance.body.children, [], operation + ' removes the temporary anchor');
        assert.equal(instance.status.textContent, 'Download started: ' + anchor.clicked[0].download, operation);
    }
});

test('status announces progress before key derivation and download start after, with fixed button labels', async () => {
    const html = await artifact(source);
    for (const [document, operation, verb] of [[source, 'runEncrypt', 'Encrypting'], [html, 'runDecrypt', 'Decrypting']]) {
        const instance = page(document);
        await instance.run(operation);
        assert.equal(instance.derivationStatuses.length, 1, operation);
        assert.match(instance.derivationStatuses[0], new RegExp('^' + verb + '.*may take a few seconds', 's'), operation);
        const name = operation === 'runEncrypt' ? instance.downloads[0][0] : instance.downloads[0][0].name;
        assert.equal(instance.status.textContent, 'Download started: ' + name, operation);
        assert.doesNotMatch(instance.statuses.join('\n'), /\bsaved\b/i, operation);
        assert.equal(instance.status.dataset.tone, 'info', operation);
        assert.deepEqual([...instance.observedButtonValues], [instance.buttonLabel], operation + ' never rewrites the button label');
    }
});

test('primary action labels are a fixed neutral Encrypt / Decrypt', async () => {
    assert.match(source, /<input id="encrypt-button" type="submit" value="Encrypt">/);
    assert.match(await artifact(source), /<input id="decrypt-button" type="submit" value="Decrypt">/);
});

// ---- crypto profile ----

test('new artifacts use the fixed cryptographic profile and a 96-bit IV', async () => {
    const encryptor = page(source);
    await encryptor.run('submit');
    const html = new TextDecoder().decode(encryptor.downloads[0][1]);
    const decryptor = page(html);
    const payload = JSON.parse(decryptor.fields.data.textContent);
    assert.equal(payload.iv.length, 12);
    await decryptor.run('submit');
    assertRecovered(decryptor);
    for (const instance of [encryptor, decryptor]) {
        assertCryptoProfile(instance);
    }
});

test('each encryption uses a fresh salt and IV from WebCrypto randomness', async () => {
    const encryptor = page(source);
    const payloads = [];
    for (let attempt = 0; attempt < 2; attempt++) {
        const previousRandomCalls = encryptor.randomValues.length;
        // Keep the password and plaintext identical, including across repeated submissions.
        await encryptor.run('submit');
        assert.equal(encryptor.downloads.length, attempt + 1);
        const html = new TextDecoder().decode(encryptor.downloads[attempt][1]);
        const payload = JSON.parse(page(html).fields.data.textContent);
        const freshRandomValues = encryptor.randomValues.slice(previousRandomCalls);
        for (const [field, length] of [['salt', 16], ['iv', 12]]) {
            assert.equal(payload[field].length, length, `${field} has the required byte length`);
            assert.ok(freshRandomValues.some(value =>
                value.length === length && value.every((byte, index) => byte === payload[field][index])
            ), `${field} comes from getRandomValues during this encryption`);
        }
        assert.deepEqual(Array.from(encryptor.derivations[attempt].salt), payload.salt,
            'key derivation uses the serialized salt');
        assert.deepEqual(Array.from(encryptor.operations[attempt].iv), payload.iv,
            'encryption uses the serialized IV');
        payloads.push(payload);
    }
    assert.notDeepEqual(payloads[0].salt, payloads[1].salt, 'repeated encryption gets a fresh salt');
    assert.notDeepEqual(payloads[0].iv, payloads[1].iv, 'repeated encryption gets a fresh IV');
    assert.notEqual(payloads[0].encrypted, payloads[1].encrypted,
        'identical inputs produce different ciphertext');
});

test('new artifacts use stronger PBKDF2 and preserve filename and binary bytes', async () => {
    const html = await artifact(source);
    assert.ok(!html.includes(filename));
    assert.ok(!html.includes(password));
    const decryptor = page(html);
    await decryptor.run('runDecrypt');
    assertRecovered(decryptor);
    assert.equal(decryptor.derivations[0].iterations, 600000);
    assert.equal(decryptor.derivations[0].hash.name, 'SHA-256');
});

// ---- roundtrip and validation ----

test('form submissions encrypt and decrypt without navigating', async () => {
    const encryptor = page(source);
    assert.equal(encryptor.form.style.display, 'grid');
    await encryptor.run('submit');
    assert.equal(encryptor.downloads.length, 1);
    assert.match(encryptor.downloads[0][0], containerNamePattern);
    const decryptor = page(new TextDecoder().decode(encryptor.downloads[0][1]));
    assert.equal(decryptor.form.style.display, 'grid');
    await decryptor.run('submit');
    assertRecovered(decryptor);
});

test('blank passwords are rejected before file reading or key derivation', async () => {
    const encryptor = page(source, '');
    await encryptor.run('runEncrypt');
    assert.match(encryptor.status.textContent, /enter.*passphrase/i);
    assert.equal(encryptor.reads, 0);
    assert.equal(encryptor.derivations.length, 0);
    assert.equal(encryptor.downloads.length, 0);
});

test('file-read failures preserve diagnostics and restore the encrypt button', async () => {
    for (const readError of [
        new DOMException('Read failed', 'NotReadableError'),
        new DOMException('Cannot read input file.')
    ]) {
        const encryptor = page(source, password, password, { readError });
        await encryptor.run('runEncrypt');
        assert.equal(encryptor.status.textContent, 'Encryption failed: ' + readError.message);
        assert.equal(encryptor.button.value, 'Encrypt');
        assert.equal(encryptor.derivations.length, 0);
        assert.equal(encryptor.downloads.length, 0);
    }
});

test('both encryption password inputs are required', () => {
    const markup = source.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
    for (const id of ['password', 'password_repeated']) {
        const input = markup.match(new RegExp(`<input\\b[^>]*type="password"[^>]*\\bid="${id}"[^>]*>`));
        assert.ok(input, id + ' input exists');
        assert.match(input[0], /\brequired\b/, id + ' is required');
    }
});

test('mismatched passwords are rejected before reading', async () => {
    const encryptor = page(source, password, 'different');
    await encryptor.run('runEncrypt');
    assert.match(encryptor.status.textContent, /Passwords must match/);
    assert.equal(encryptor.reads, 0);
    assert.equal(encryptor.downloads.length, 0);
});

test('wrong passwords and modified ciphertext are rejected', async () => {
    const html = await artifact(source);
    const wrong = page(html, 'wrong');
    await wrong.run('runDecrypt');
    assert.match(wrong.status.textContent, /Wrong password or corrupted file/);
    assert.equal(wrong.downloads.length, 0);
    const tampered = html.replace(/("encrypted":")([A-Za-z0-9+/])/, (_, prefix, first) => prefix + (first === 'A' ? 'B' : 'A'));
    const corrupt = page(tampered);
    await corrupt.run('runDecrypt');
    assert.match(corrupt.status.textContent, /Wrong password or corrupted file/);
    assert.equal(corrupt.downloads.length, 0);
});

for (const [name, secret] of [['legacy-password', password], ['legacy-empty', '']]) {
    test(`${name} artifact still decrypts`, async () => {
        const decryptor = page(readFileSync(new URL(`fixtures/${name}.html`, import.meta.url), 'utf8'), secret);
        await decryptor.run('runDecrypt');
        // Legacy decryptors predate the download-started status.
        assertRecovered(decryptor, '');
    });
}

// ---- malformed payloads ----

for (const [label, payload] of [
    ['invalid JSON', '{'],
    ['invalid base64', JSON.stringify({ salt: [1], iv: [1], encrypted: '!' })],
    ['null payload', 'null'],
    ['missing fields', '{}']
]) {
    test(`malformed payload recovers: ${label}`, async () => {
        const html = await artifact(source);
        const decryptor = page(embeddedPayload(html, payload));
        await decryptor.run('runDecrypt');
        assert.match(decryptor.status.textContent, /Decryption failed:/);
        assert.equal(decryptor.button.value, 'Decrypt');
        assert.equal(decryptor.downloads.length, 0);
        decryptor.fields.data.textContent = html.match(/<script id="data"[^>]*>([\s\S]*?)<\/script>/)[1];
        await decryptor.run('runDecrypt');
        assertRecovered(decryptor);
    });
}

test('payload profile-looking fields cannot override the decryptor profile', async () => {
    const html = await artifact(source);
    const original = JSON.parse(page(html).fields.data.textContent);
    const overrides = {
        kdf: 'HKDF', hash: 'SHA-1', iterations: 1,
        keySize: 256, cipher: 'AES-CBC', ivLength: 16,
        name: 'AES-CBC', length: 256,
        algorithm: { name: 'HKDF', hash: 'SHA-1', iterations: 1 },
        profile: { kdf: 'HKDF', hash: 'SHA-1', iterations: 1, keySize: 256, cipher: 'AES-CBC', ivLength: 16 }
    };
    for (const [field, value] of Object.entries(overrides)) {
        const decryptor = page(embeddedPayload(html, JSON.stringify({ ...original, [field]: value })));
        await decryptor.run('submit');
        assertRecovered(decryptor);
        assertCryptoProfile(decryptor, field);
    }
});

// ---- crypto environment ----

test('WebCrypto context failures return before reading or derivation in both paths', async () => {
    const html = await artifact(source);
    for (const [document, operation] of [[source, 'runEncrypt'], [html, 'runDecrypt']]) {
        for (const window of [
            { isSecureContext: false }, { isSecureContext: false, crypto: undefined },
            { isSecureContext: true, crypto: undefined }, { isSecureContext: true, crypto: {} }
        ]) {
            const instance = page(document, password, password, { window });
            await instance.run(operation);
            assert.match(instance.status.textContent, window.isSecureContext === false ? /insecure context.*HTTPS/i : /does not support the Web Crypto API/);
            assert.equal(instance.reads, 0);
            assert.equal(instance.derivations.length, 0);
            assert.equal(instance.downloads.length, 0);
        }
    }
});

test('working WebCrypto accepts secure and unspecified contexts and webkitSubtle decryptors', async () => {
    for (const window of [{}, { isSecureContext: true }]) {
        const encryptor = page(source, password, password, { window });
        await encryptor.run('runEncrypt');
        const html = new TextDecoder().decode(encryptor.downloads[0][1]);
        const decryptor = page(html, password, password, { window });
        await decryptor.run('runDecrypt');
        assertRecovered(decryptor);
        const fallback = page(html, password, password, { window: { ...window, crypto: { webkitSubtle: webcrypto.subtle } } });
        await fallback.run('runDecrypt');
        assertRecovered(fallback);
    }
});

// ---- edge case roundtrips ----

test('nonempty whitespace passwords roundtrip exactly as entered', async () => {
    const secret = '   ';
    const encryptor = page(source, secret);
    await encryptor.run('runEncrypt');
    const html = new TextDecoder().decode(encryptor.downloads[0][1]);
    const decryptor = page(html, secret);
    await decryptor.run('runDecrypt');
    assertRecovered(decryptor);
});

test('a 1 MiB binary file roundtrips with a Unicode filename', async () => {
    const content = Uint8Array.from({ length: 1024 * 1024 }, (_, i) => i % 256);
    const name = 'zażółć-東京-🔐.bin';
    const encryptor = page(source, password, password, { bytes: content, filename: name });
    await encryptor.run('runEncrypt');
    const decryptor = page(new TextDecoder().decode(encryptor.downloads[0][1]));
    await decryptor.run('runDecrypt');
    assert.equal(decryptor.status.textContent, 'Download started: ' + name);
    assert.equal(decryptor.downloads.length, 1);
    const file = decryptor.downloads[0][0];
    assert.equal(file.name, name);
    assert.deepEqual(file.content, content);
    assert.deepEqual(new Uint8Array(await new Blob([file.content]).arrayBuffer()), content);
});

test('an empty file roundtrips with its Unicode filename', async () => {
    const html = await artifact(source, { bytes: new Uint8Array(0), filename: 'empty-🔐.bin' });
    const decryptor = page(html);
    await decryptor.run('submit');
    assert.equal(decryptor.status.textContent, 'Download started: empty-🔐.bin');
    assert.equal(decryptor.downloads.length, 1);
    assert.equal(decryptor.downloads[0][0].name, 'empty-🔐.bin');
    assert.deepEqual(decryptor.downloads[0][0].content, new Uint8Array(0));
});

test('empty file content and malformed decrypted headers are handled', async () => {
    const html = await artifact(source);
    const decryptor = page(html);
    const emptyFile = decryptor.context.extractDecryptedFile(new TextEncoder().encode('empty-🔐.bin/').buffer);
    assert.equal(emptyFile.name, 'empty-🔐.bin');
    assert.equal(emptyFile.content.length, 0);
    // Exercise extraction failure after real, successful authenticated decryption.
    const encryptor = page(source);
    encryptor.context.prependFilename = () => new TextEncoder().encode('missing separator');
    await encryptor.run('runEncrypt');
    const invalid = page(new TextDecoder().decode(encryptor.downloads[0][1]));
    await invalid.run('runDecrypt');
    assert.match(invalid.status.textContent, /Decryption failed: Decrypted data is corrupted/);
    assert.equal(invalid.button.value, 'Decrypt');
    assert.equal(invalid.downloads.length, 0);
});

// ---- delayed / async recovery ----

for (const outcome of ['success', 'failure']) {
    test(`a delayed file read keeps encryption busy until ${outcome}`, async () => {
        const started = Promise.withResolvers();
        const completion = Promise.withResolvers();
        let delay = true;
        const encryptor = page(source, password, password, {
            beforeRead: () => {
                if (!delay) return;
                started.resolve();
                return completion.promise;
            }
        });
        const running = encryptor.run('submit');
        await started.promise;
        try {
            assert.equal(encryptor.button.disabled, true);
            assert.equal(encryptor.button.value, 'Encrypt');
            assert.match(encryptor.status.textContent, /^Encrypting/);
            assert.equal(encryptor.status.dataset.tone, 'info');
            assert.equal(encryptor.derivations.length, 0);
            assert.equal(encryptor.downloads.length, 0);
            if (outcome === 'failure') completion.reject(new DOMException('Delayed read failed', 'NotReadableError'));
        } finally {
            completion.resolve();
            await running;
        }
        assert.equal(encryptor.button.disabled, false);
        if (outcome === 'failure') {
            assert.equal(encryptor.status.textContent, 'Encryption failed: Delayed read failed');
            assert.equal(encryptor.status.dataset.tone, 'error');
            assert.equal(encryptor.downloads.length, 0);
            delay = false;
            await encryptor.run('submit');
        }
        assert.equal(encryptor.downloads.length, 1);
        const decryptor = page(new TextDecoder().decode(encryptor.downloads[0][1]));
        await decryptor.run('submit');
        assertRecovered(decryptor);
    });
}

for (const direction of ['encrypt', 'decrypt']) {
    for (const stage of ['importKey', 'deriveKey', direction]) {
        test(`${direction} recovers from a delayed ${stage} rejection without exposing stale results`, async () => {
            const message = 'A private message 🔐';
            const html = direction === 'encrypt' ? source : await artifact(source, { source: 'message', message });
            const started = Promise.withResolvers();
            const completion = Promise.withResolvers();
            const sharing = sharingNavigator();
            let fail = false;
            const instance = page(html, password, password, {
                window: { navigator: sharing.navigator },
                beforeCrypto: method => {
                    if (!fail || method !== stage) return;
                    started.resolve();
                    return completion.promise;
                }
            });
            await instance.run('submit');
            if (direction === 'encrypt') assert.equal(instance.fields['encrypt-result'].hidden, false);
            else assert.equal(instance.fields['decrypted-message'].textContent, message);
            fail = true;
            const running = instance.run('submit');
            await started.promise;
            try {
                assert.equal(instance.button.disabled, true);
                assert.equal(instance.button.value, direction === 'encrypt' ? 'Encrypt' : 'Decrypt');
                assert.match(instance.status.textContent, /^(Encrypting|Decrypting)/);
                assert.equal(instance.status.dataset.tone, 'info');
                assert.equal(instance.downloads.length, 0);
                if (direction === 'encrypt') {
                    assert.equal(instance.fields['encrypt-result'].hidden, true);
                    instance.fields['save-button'].dispatch('click');
                    instance.fields['share-button'].dispatch('click');
                    assert.equal(instance.downloads.length, 0);
                    assert.equal(sharing.shares.length, 0);
                } else {
                    assert.equal(instance.fields['decrypted-message'].textContent, '');
                    assert.equal(instance.fields['decrypted-message'].hidden, true);
                }
                completion.reject(new DOMException('Injected ' + stage + ' failure', 'OperationError'));
            } finally {
                completion.resolve();
                await running;
            }
            assert.equal(instance.button.disabled, false);
            assert.equal(instance.status.textContent, direction === 'encrypt'
                ? 'Encryption failed: Injected ' + stage + ' failure'
                : 'Decryption failed: Wrong password or corrupted file.');
            assert.equal(instance.status.dataset.tone, 'error');
            assert.equal(instance.downloads.length, 0);
            if (direction === 'encrypt') {
                assert.equal(instance.fields['encrypt-result'].hidden, true);
                instance.fields['save-button'].dispatch('click');
                instance.fields['share-button'].dispatch('click');
                assert.equal(instance.downloads.length, 0);
                assert.equal(sharing.shares.length, 0);
            } else {
                assert.equal(instance.fields['decrypted-message'].textContent, '');
                assert.equal(instance.fields['decrypted-message'].hidden, true);
            }

            fail = false;
            await instance.run('submit');
            assert.equal(instance.status.dataset.tone, 'info');
            if (direction === 'encrypt') {
                assert.equal(instance.fields['encrypt-result'].hidden, false);
                instance.fields['save-button'].dispatch('click');
                assert.equal(instance.downloads.length, 1);
                assert.notEqual(instance.downloads[0][0], sharing.checks[0].files[0].name);
                const recovered = page(new TextDecoder().decode(instance.downloads[0][1]));
                await recovered.run('submit');
                assertRecovered(recovered);
            } else {
                assert.equal(instance.status.textContent, 'Message decrypted.');
                assert.equal(instance.fields['decrypted-message'].hidden, false);
                assert.equal(instance.fields['decrypted-message'].textContent, message);
            }
        });
    }
}