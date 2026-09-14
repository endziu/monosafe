import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import vm from 'node:vm';
import { test } from 'node:test';

const source = readFileSync(new URL('../monosafe.html', import.meta.url), 'utf8');
const bytes = Uint8Array.of(0, 255, 47, 128, 10);
const filename = 'private-zażółć.bin';
const containerNamePattern = /^monosafe-[a-zA-Z0-9_-]+\.html$/;
const password = ' long unique test passphrase 🔐 ';

function page(html, secret = password, repeated = secret, options = {}) {
    function eventTarget(properties = {}) {
        const listeners = {};
        return Object.assign(properties, {
            addEventListener(type, callback) { (listeners[type] ||= []).push(callback); },
            dispatch(type, event) { for (const callback of listeners[type] || []) callback(event); },
            getAttribute(name) { return this[name]; },
            setAttribute(name, value) { this[name] = value; }
        });
    }
    const status = { textContent: '' };
    const button = { disabled: false, value: html.includes('id="data"') ? 'Decrypt file' : 'Encrypt file' };
    const form = eventTarget({ style: {} });
    const fields = {
        password: eventTarget({ value: secret, id: 'password', type: 'password' }),
        'password-toggle': eventTarget({ 'aria-controls': 'password' }),
        'password-repeated-toggle': eventTarget({ 'aria-controls': 'password_repeated' }),
        'encrypt-form': form, 'decrypt-form': form,
        'encrypt-button': button, 'decrypt-button': button,
        'encrypt-status': status, 'decrypt-status': status,
        'page-style': { textContent: '' },
        password_hint: { value: options.hint || '' },
        'source-file': eventTarget({ checked: options.source !== 'message' }),
        'source-message': eventTarget({ checked: options.source === 'message' }),
        'file-source': { hidden: false },
        'message-source': { hidden: true },
        message: { value: options.message || '' },
        'password-hint': { textContent: '', hidden: true },
        'password-strength': { dataset: {} }, 'password-strength-label': { textContent: 'password strength', setAttribute(name, value) { this[name] = value; } }, password_repeated: eventTarget({ value: repeated, id: 'password_repeated', type: 'password' }),
        'password-strength-status': { textContent: '' },
        'password-match-status': { textContent: '' },
        'password-match': { dataset: {} },
        'password-match-label': { textContent: 'passwords match', setAttribute(name, value) { this[name] = value; } },
        file: { files: [{ name: options.filename || filename }] },
        data: { textContent: html.match(/<script id="data"[^>]*>([\s\S]*?)<\/script>/)?.[1] }
    };
    const downloads = [];
    const derivations = [];
    const keyAlgorithms = [];
    const operations = [];
    const timerErrors = [];
    let reads = 0;
    const context = vm.createContext({
        TextEncoder, TextDecoder, Uint8Array, Blob, DOMException, atob,
        setTimeout: callback => setTimeout(() => {
            try { callback(); } catch (error) { timerErrors.push(error); }
        }, 0),
        window: eventTarget({ crypto: {
            getRandomValues: array => webcrypto.getRandomValues(array),
            subtle: new Proxy(webcrypto.subtle, {
                get(target, key) {
                    if (key === 'deriveKey') return (...args) => {
                        derivations.push(args[0]);
                        keyAlgorithms.push(args[2]);
                        return target.deriveKey(...args);
                    };
                    if (key === 'encrypt' || key === 'decrypt') return (...args) => {
                        operations.push(args[0]);
                        return target[key](...args);
                    };
                    return target[key].bind(target);
                }
            })
        }, ...options.window }),
        document: {
            getElementById: id => {
                const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '<script>');
                assert.ok(html.includes(`id="${id}"`) && (id === 'data' || markup.includes(`id="${id}"`)), `element #${id} exists in markup`);
                return fields[id];
            },
            querySelector: selector => ({
                '.status': status, 'input[type=submit]': button, form,
                'input[type=password]': fields.password, style: { textContent: '' }
            })[selector]
        },
        FileReader: class {
            abort() { this.error = null; }
            readAsArrayBuffer() {
                reads++;
                if (Object.hasOwn(options, 'readError')) {
                    this.error = options.readError;
                    this.onerror();
                    return;
                }
                this.result = (options.bytes || bytes).buffer;
                this.onload();
            }
        }
    });
    for (const match of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
        if (!match[1].includes('application/json')) vm.runInContext(match[2], context);
    }
    context.download = (...args) => downloads.push(args);
    return {
        context, status, button, fields, form, downloads, derivations, keyAlgorithms, operations, timerErrors, get reads() { return reads; },
        async run(name) {
            if (name === 'submit') {
                let prevented = false;
                form.dispatch('submit', { preventDefault() { prevented = true; } });
                assert.ok(prevented, 'form submission prevents navigation');
            } else context[name]();
            const deadline = Date.now() + 10000;
            while (button.disabled && !timerErrors.length && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
            assert.deepEqual(timerErrors, [], 'no exceptions escape timer callbacks');
            assert.ok(!button.disabled, 'operation completes');
        }
    };
}

async function artifact(options = {}) {
    const encryptor = page(source, password, password, options);
    await encryptor.run('runEncrypt');
    assert.equal(encryptor.status.textContent, '');
    assert.equal(encryptor.downloads.length, 1);
    assert.equal(encryptor.derivations[0].iterations, 600000);
    assert.equal(encryptor.derivations[0].hash.name, 'SHA-256');
    return new TextDecoder().decode(encryptor.downloads[0][1]);
}

function assertCryptoProfile(instance, message) {
    assert.equal(instance.derivations[0].name, 'PBKDF2', message);
    assert.equal(instance.derivations[0].hash.name, 'SHA-256', message);
    assert.equal(instance.derivations[0].iterations, 600000, message);
    assert.equal(instance.keyAlgorithms[0].name, 'AES-GCM', message);
    assert.equal(instance.keyAlgorithms[0].length, 128, message);
    assert.equal(instance.operations[0].name, 'AES-GCM', message);
    assert.equal(instance.operations[0].iv.byteLength, 12, message);
    assert.equal(Object.hasOwn(instance.operations[0], 'length'), false, message);
}

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

function assertRecovered(decryptor) {
    assert.equal(decryptor.status.textContent, '');
    assert.equal(decryptor.downloads.length, 1);
    assert.equal(decryptor.downloads[0][0].name, filename);
    assert.deepEqual(decryptor.downloads[0][0].content, bytes);
}

test('blank passwords are rejected before file reading or key derivation', async () => {
    const encryptor = page(source, '');
    await encryptor.run('runEncrypt');
    assert.match(encryptor.status.textContent, /enter.*passphrase/i);
    assert.equal(encryptor.reads, 0);
    assert.equal(encryptor.derivations.length, 0);
    assert.equal(encryptor.downloads.length, 0);
});

test('file-read failures preserve diagnostics and restore the encrypt button', async () => {
    for (const [readError, detail] of [
        [new DOMException('The file is no longer accessible.', 'NotReadableError'), 'The file is no longer accessible.'],
        [new DOMException('', 'NotReadableError'), 'NotReadableError'],
        [null, 'Cannot read input file.']
    ]) {
        const encryptor = page(source, password, password, { readError });
        await encryptor.run('runEncrypt');
        assert.equal(encryptor.status.textContent, 'Encryption failed: ' + detail);
        assert.equal(encryptor.button.value, 'Encrypt file');
        assert.equal(encryptor.derivations.length, 0);
        assert.equal(encryptor.downloads.length, 0);
    }
});

test('both encryption password inputs are required', () => {
    for (const id of ['password', 'password_repeated']) {
        assert.match(source.match(new RegExp(`<input[^>]*id="${id}"[^>]*>`))[0], /\brequired\b/);
    }
});

test('mismatched passwords are rejected before reading', async () => {
    const encryptor = page(source, password, 'different');
    await encryptor.run('runEncrypt');
    assert.match(encryptor.status.textContent, /Passwords must match/);
    assert.equal(encryptor.reads, 0);
    assert.equal(encryptor.downloads.length, 0);
});

test('creator and generated decryptor markup contain no inline behavior', async () => {
    for (const html of [source, await artifact()]) {
        const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
        assert.doesNotMatch(markup, /\son\w+\s*=/i);
        assert.doesNotMatch(markup, /\saction\s*=\s*["']\s*javascript:/i);
    }
});

test('password toggle clicks affect only the controlled input and preserve values', () => {
    const { fields } = page(source);
    for (const [id, inputId, otherId, label] of [
        ['password-toggle', 'password', 'password_repeated', 'password'],
        ['password-repeated-toggle', 'password_repeated', 'password', 'repeated password']
    ]) {
        const toggle = fields[id];
        for (const [type, pressed, action] of [['text', 'true', 'Hide'], ['password', 'false', 'Show']]) {
            toggle.dispatch('click');
            assert.equal(fields[inputId].type, type);
            assert.equal(fields[inputId].value, password);
            assert.equal(fields[otherId].type, 'password');
            assert.equal(toggle.getAttribute('aria-pressed'), pressed);
            assert.equal(toggle.getAttribute('aria-label'), action + ' ' + label);
        }
    }
});

test('file and message containers have fresh neutral names and keep original names encrypted', async () => {
    for (const options of [{}, { source: 'message', message: 'Private café meeting 🔐' }]) {
        const originalName = options.source === 'message' ? 'message.txt' : filename;
        const encryptor = page(source, password, password, options);
        const names = [];
        for (let attempt = 0; attempt < 2; attempt++) {
            await encryptor.run('submit');
            assert.equal(encryptor.status.textContent, '');
            assert.equal(encryptor.downloads.length, attempt + 1);
            const [name, buffer] = encryptor.downloads[attempt];
            assert.match(name, containerNamePattern);
            names.push(name);
            const html = new TextDecoder().decode(buffer);
            const wrapper = html.replace(/("encrypted":")[^"]*"/, '$1"');
            assert.ok(!wrapper.includes(originalName), 'wrapper does not disclose the original filename');
            const decryptor = page(html);
            await decryptor.run('submit');
            assert.equal(decryptor.status.textContent, '');
            assert.equal(decryptor.downloads.length, 1);
            assert.equal(decryptor.downloads[0][0].name, originalName);
            assert.deepEqual(decryptor.downloads[0][0].content,
                options.source === 'message' ? new TextEncoder().encode(options.message) : bytes);
        }
        assert.notEqual(names[0], names[1], 'each encryption gets a fresh container name');
    }
});

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

test('new artifacts use stronger PBKDF2 and preserve filename and binary bytes', async () => {
    const html = await artifact();
    assert.ok(!html.includes(filename));
    assert.ok(!html.includes(password));
    const decryptor = page(html);
    await decryptor.run('runDecrypt');
    assertRecovered(decryptor);
    assert.equal(decryptor.derivations[0].iterations, 600000);
    assert.equal(decryptor.derivations[0].hash.name, 'SHA-256');
});

test('text messages encrypt without file reading and decrypt as message.txt', async () => {
    const message = 'Meet at 19:30 by the café.\nBring the 🔐 key.';
    const encryptor = page(source, password, password, { source: 'message', message });
    assert.equal(encryptor.fields['file-source'].hidden, true);
    assert.equal(encryptor.fields['message-source'].hidden, false);

    await encryptor.run('runEncrypt');

    assert.equal(encryptor.reads, 0);
    assert.equal(encryptor.downloads.length, 1);
    assert.match(encryptor.downloads[0][0], containerNamePattern);
    const html = new TextDecoder().decode(encryptor.downloads[0][1]);
    assert.ok(!html.includes(message));

    const decryptor = page(html);
    await decryptor.run('runDecrypt');
    assert.equal(decryptor.downloads[0][0].name, 'message.txt');
    assert.equal(new TextDecoder().decode(decryptor.downloads[0][0].content), message);
});

test('empty text messages are rejected before key derivation', async () => {
    const encryptor = page(source, password, password, { source: 'message' });
    await encryptor.run('runEncrypt');
    assert.match(encryptor.status.textContent, /write a text message/i);
    assert.equal(encryptor.reads, 0);
    assert.equal(encryptor.derivations.length, 0);
    assert.equal(encryptor.downloads.length, 0);
});

test('optional hints appear before password entry and preserve Unicode and line breaks', async () => {
    const hint = 'The title of the song we heard in Italy\nZażółć 🎵';
    const html = await artifact({ hint: '  ' + hint + '  ' });
    const decryptor = page(html, '');
    assert.equal(decryptor.fields['password-hint'].textContent, 'Password hint: ' + hint);
    assert.equal(decryptor.fields['password-hint'].hidden, false);
    assert.equal(decryptor.derivations.length, 0);
    assert.match(html, /aria-describedby="password-hint"/);
    decryptor.fields.password.value = password;
    await decryptor.run('runDecrypt');
    assertRecovered(decryptor);
});

test('omitted and whitespace-only hints stay hidden and do not affect decryption', async () => {
    for (const hint of ['', '  \n\t ']) {
        const html = await artifact({ hint });
        const payload = JSON.parse(html.match(/<script id="data"[^>]*>([\s\S]*?)<\/script>/)[1]);
        assert.equal(Object.hasOwn(payload, 'hint'), false);
        const decryptor = page(html);
        assert.equal(decryptor.fields['password-hint'].hidden, true);
        assert.equal(decryptor.fields['password-hint'].textContent, '');
        await decryptor.run('runDecrypt');
        assertRecovered(decryptor);
    }
});

test('hint markup and replacement tokens stay literal without injecting executable HTML', async () => {
    const hint = '</script><script>throw new Error("injected")</script><img src=x onerror=alert(1)> & " $& $` $\' {{___PAYLOAD___}}';
    const html = await artifact({ hint });
    assert.equal([...html.matchAll(/<script\b/gi)].length, 2);
    assert.ok(!html.includes('<img'));
    const decryptor = page(html);
    assert.equal(decryptor.fields['password-hint'].textContent, 'Password hint: ' + hint);
    assert.equal(decryptor.fields['password-hint'].hidden, false);
    await decryptor.run('runDecrypt');
    assertRecovered(decryptor);
});

test('payload profile-looking fields cannot override the decryptor profile', async () => {
    const html = await artifact();
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

test('wrong passwords and modified ciphertext are rejected', async () => {
    const html = await artifact();
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
        assertRecovered(decryptor);
    });
}

test('strength estimates handle empty, weak, moderate, and long passwords', () => {
    const { context } = page(source);
    for (const value of ['', 'short', 'Password123!', 'aaaaaaaaaaaaaaaaaaaa', 'abcabcabcabcabcabc', '12345678901234567890']) {
        assert.equal(context.passwordStrength(value), value ? 'low' : 'empty', value);
    }
    assert.equal(context.passwordStrength('MapleRiver7'), 'medium');
    assert.equal(context.passwordStrength('cedar orbit velvet harbor'), 'high');
    assert.equal(context.passwordStrength('N8!rV2#pL9@xQ4$z'), 'high');
});

test('indicator updates and resets without changing password input', () => {
    const { context } = page(source);
    const input = context.document.getElementById('password');
    for (const [value, level] of [['short', 'low'], ['MapleRiver7', 'medium'], ['cedar orbit velvet harbor', 'high'], ['', 'empty']]) {
        input.value = value;
        context.updatePasswordStrength();
        assert.equal(context.document.getElementById('password-strength').dataset.level, level);
        assert.equal(input.value, value);
        assert.equal(context.document.getElementById('password-strength-label').textContent, 'password strength');
        assert.equal(context.document.getElementById('password-strength-status').textContent, 'Password strength: ' + (level === 'empty' ? 'not entered' : level));
    }
});

function embeddedPayload(html, payload) {
    return html.replace(/(<script id="data"[^>]*>)[\s\S]*?(<\/script>)/, (_, open, close) => open + payload + close);
}

for (const [label, payload] of [
    ['invalid JSON', '{'],
    ['invalid base64', JSON.stringify({ salt: [1], iv: [1], encrypted: '!' })],
    ['null payload', 'null'],
    ['missing fields', '{}']
]) {
    test(`malformed payload recovers: ${label}`, async () => {
        const html = await artifact();
        const decryptor = page(embeddedPayload(html, payload));
        await decryptor.run('runDecrypt');
        assert.match(decryptor.status.textContent, /Decryption failed:/);
        assert.equal(decryptor.button.value, 'Decrypt file');
        assert.equal(decryptor.downloads.length, 0);
        decryptor.fields.data.textContent = html.match(/<script id="data"[^>]*>([\s\S]*?)<\/script>/)[1];
        await decryptor.run('runDecrypt');
        assertRecovered(decryptor);
    });
}

test('strength estimates reject sequences, truncated repetitions and combined common patterns', () => {
    const { context } = page(source);
    for (const value of [
        'abcdefghijklmnopqrst', '1234567890abcdefghij', 'Password1Password1Pa',
        'myname19851985myname', 'abcdefghij', 'zyxwvutsrqponmlkjihgf',
        '9876543210jihgfedcba', 'qwertyuiopasdfghjkl', 'poiuytrewqlkjhgfdsa',
        'sunflowerSUNFLOWERsun', 'welcome123admin456', 'P@ssword1P@ssword1Pa',
        'abcd-efgh-ijkl-mnop', 'ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴ',
        '12567834vxq'
    ]) assert.equal(context.passwordStrength(value), 'low', value);
});

test('strength boundaries retain long varied passphrases and random lowercase passwords', () => {
    const { context } = page(source);
    const lowercase = 'vnrqkzpmxbjtwfhsuacdg';
    for (const [value, level] of [
        [lowercase.slice(0, 9), 'low'], [lowercase.slice(0, 10), 'medium'],
        [lowercase.slice(0, 19), 'medium'], [lowercase.slice(0, 20), 'high'],
        ['vxqjznrktpmwcsfhbdgu', 'high'],
        ['N8!rV2#pL9@xQ4$', 'medium'], ['N8!rV2#pL9@xQ4$z', 'high'],
        ['cedar orbit velvet harbor', 'high'], ['glacier marmot lantern orchard', 'high'],
        ['                    ', 'low']
    ]) assert.equal(context.passwordStrength(value), level, value);
});

test('live status markup describes inputs and keeps visible labels out of announcements', () => {
    for (const [input, name, label] of [
        ['password', 'strength', 'password strength'], ['password_repeated', 'match', 'passwords match']
    ]) {
        assert.match(source.match(new RegExp(`<input[^>]*id="${input}"[^>]*>`))[0], new RegExp(`aria-describedby="password-${name}-status"`));
        const status = source.match(new RegExp(`<span[^>]*id="password-${name}-status"[^>]*>`))[0];
        assert.match(status, /role="status"/);
        assert.match(status, /aria-atomic="true"/);
        assert.match(status, /class="visually-hidden"/);
        assert.match(source, new RegExp(`<span id="password-${name}-label" aria-hidden="true">${label}</span>`));
    }
});

test('input, change, pageshow and form reset update meaningful live text', async () => {
    const { context, fields, form } = page(source, '', '');
    assert.equal(fields['password-strength-status'].textContent, 'Password strength: not entered');
    assert.equal(fields['password-match-status'].textContent, 'Passwords not entered');
    for (const event of ['input', 'change', 'pageshow']) {
        fields.password.value = 'cedar orbit velvet harbor';
        fields.password_repeated.value = '';
        if (event === 'pageshow') context.window.dispatch(event);
        else fields.password.dispatch(event);
        assert.equal(fields['password-strength-status'].textContent, 'Password strength: high');
        assert.equal(fields['password-match-status'].textContent, 'Repeat password to check for a match');
        fields.password_repeated.value = 'different';
        if (event === 'pageshow') context.window.dispatch(event);
        else fields.password_repeated.dispatch(event);
        assert.equal(fields['password-match-status'].textContent, 'Passwords do not match');
        fields.password_repeated.value = fields.password.value;
        if (event === 'pageshow') context.window.dispatch(event);
        else fields.password_repeated.dispatch(event);
        assert.equal(fields['password-match-status'].textContent, 'Passwords match');
        assert.equal(fields['password-match'].dataset.match, 'true');
        assert.equal(fields.password.value, 'cedar orbit velvet harbor');
        assert.equal(fields.password_repeated.value, fields.password.value);
    }
    fields.password.value = '';
    fields.password.dispatch('input');
    assert.equal(fields['password-match-status'].textContent, 'Enter a password to check for a match');
    form.dispatch('reset');
    fields.password_repeated.value = '';
    await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(fields['password-strength-status'].textContent, 'Password strength: not entered');
    assert.equal(fields['password-match-status'].textContent, 'Passwords not entered');
    assert.equal(fields['password-match'].dataset.match, 'false');
    assert.equal(fields['password-strength-label'].textContent, 'password strength');
    assert.equal(fields['password-match-label'].textContent, 'passwords match');
});

test('WebCrypto context failures return before reading or derivation in both paths', async () => {
    const html = await artifact();
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
    assert.equal(decryptor.status.textContent, '');
    assert.equal(decryptor.downloads.length, 1);
    const file = decryptor.downloads[0][0];
    assert.equal(file.name, name);
    assert.deepEqual(file.content, content);
    assert.deepEqual(new Uint8Array(await new Blob([file.content]).arrayBuffer()), content);
});

test('an empty file roundtrips with its Unicode filename', async () => {
    const html = await artifact({ bytes: new Uint8Array(0), filename: 'empty-🔐.bin' });
    const decryptor = page(html);
    await decryptor.run('submit');
    assert.equal(decryptor.status.textContent, '');
    assert.equal(decryptor.downloads.length, 1);
    assert.equal(decryptor.downloads[0][0].name, 'empty-🔐.bin');
    assert.deepEqual(decryptor.downloads[0][0].content, new Uint8Array(0));
});

test('empty file content and malformed decrypted headers are handled', async () => {
    const html = await artifact();
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
    assert.equal(invalid.button.value, 'Decrypt file');
    assert.equal(invalid.downloads.length, 0);
});
