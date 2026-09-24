import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
    source, password, filename, bytes, containerNamePattern,
    page, artifact, assertRecovered, settle,
    markupOf, stylesheet, elementText, describedBy
} from './harness.mjs';

// ---- markup & accessibility structure ----

test('operation feedback stays in a persistent atomic live region on both pages', async () => {
    for (const html of [source, await artifact(source)]) {
        const markup = markupOf(html);
        const region = markup.match(/<p\b[^>]*id="(?:encrypt|decrypt)-status"[^>]*>/)[0];
        assert.match(region, /role="status"/);
        assert.match(region, /aria-live="polite"/);
        assert.match(region, /aria-atomic="true"/);
        assert.doesNotMatch(region, /\bhidden\b|aria-hidden|style=/);
        const css = stylesheet(markup);
        for (const [, declarations] of css.matchAll(/\.status(?::empty)?\s*\{([^}]+)\}/g)) {
            assert.doesNotMatch(declarations, /display:\s*none|visibility:\s*hidden/);
        }
    }
});

test('creator and generated decryptor markup contain no inline behavior', async () => {
    for (const html of [source, await artifact(source)]) {
        const markup = markupOf(html);
        for (const match of markup.matchAll(/<(input|button|a|textarea)\b[^>]*>/g)) {
            assert.doesNotMatch(match[0], /\bon(blur|change|click|focus|input|key|submit)\s*=/i,
                `no inline handler in <${match[1]}>`);
        }
    }
});

test('password toggles on both pages have stable names, expose state and preserve independent input values', async () => {
    for (const html of [source, await artifact(source)]) {
        const instance = page(html);
        const pairs = html.includes('id="encrypt-form"')
            ? [['Password', 'Show password'], ['Repeat password', 'Show repeated password']]
            : [['Password', 'Show password']];
        for (const [inputLabel, buttonName] of pairs) {
            const input = instance.fields[inputLabel === 'Password' ? 'password' : 'password_repeated'];
            input.value = inputLabel + '-value';
            const button = inputLabel === 'Password' ? instance.fields['password-toggle'] : instance.fields['password-repeated-toggle'];
            assert.match(button['aria-label'] || button.getAttribute('aria-label') || '', new RegExp('^' + buttonName));
            for (const [event, type, pressed] of [['click', 'text', 'true'], ['click', 'password', 'false']]) {
                button.dispatch(event);
                assert.equal(input.type, type);
                assert.equal(button['aria-pressed'], pressed);
            }
            assert.equal(input.value, inputLabel + '-value');
        }
    }
});

test('both pages declare English and give password fields visible associated labels and feedback', async () => {
    for (const html of [source, await artifact(source)]) {
        const markup = markupOf(html);
        assert.match(markup, /<html\s+lang="en">/);
        for (const input of markup.matchAll(/<input\b[^>]*type="password"[^>]*>/g)) {
            const id = input[0].match(/\bid="([^"]+)"/)[1];
            const label = markup.match(new RegExp(`<label\\b([^>]*\\bfor="${id}"[^>]*)>([^<]+)</label>`));
            assert.ok(label, `#${id} has a persistent label`);
            assert.doesNotMatch(label[1], /visually-hidden|\bhidden\b|aria-hidden|style=/);
            assert.equal(label[2], id === 'password' ? 'Password' : 'Repeat password');
            assert.doesNotMatch(input[0], /aria-label=|placeholder=/);
            const feedback = describedBy(markup, id);
            assert.ok(feedback.includes(markup.includes('id="encrypt-form"') ? 'encrypt-status' : 'decrypt-status'));
            for (const target of feedback) assert.ok(markup.includes(`id="${target}"`), `${target} exists`);
        }
    }
});

// ---- creator UI ----

test('the creator offers accessible icon controls beside its title', () => {
    const markup = markupOf(source);
    const title = markup.match(/<h1>([\s\S]*?)<\/h1>/)?.[1];
    assert.match(title, /^MonoSafe\s+<a\b/);
    assert.match(title, /<a\b[^>]*class="icon-button"[^>]*href="monosafe\.html"[^>]*\bdownload="monosafe\.html"[^>]*aria-label="Download MonoSafe for offline use"[^>]*>/);
    assert.match(title, /<button\b[^>]*id="help-button"[^>]*aria-label="Help"[^>]*>/);
    assert.match(title, /<svg\b[^>]*aria-hidden="true"[^>]*>/);
});

test('the help icon opens a concise modal', () => {
    const instance = page(source);
    const { fields } = instance;
    assert.match(markupOf(source), /<dialog id="help-dialog" aria-labelledby="help-title">/);
    assert.match(elementText(source, 'help-dialog'), /Everything stays on your computer/);
    assert.equal(fields['help-dialog'].open, undefined);
    fields['help-button'].dispatch('click');
    assert.equal(fields['help-dialog'].open, true);
    fields['help-close'].dispatch('click');
    assert.equal(fields['help-dialog'].open, false);
});

test('primary button text meets AA contrast in both stylesheets, including hover', async () => {
    function luminance(color) {
        const hex = color === 'white' ? 'ffffff' : color.replace('#', '');
        assert.match(hex, /^[0-9a-f]{6}$/i, 'expected an opaque RGB color');
        const channels = hex.match(/../g).map(channel => {
            const value = parseInt(channel, 16) / 255;
            return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
        });
        return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
    }
    for (const html of [source, await artifact(source)]) {
        const css = stylesheet(html);
        const normal = css.match(/input\[type=submit\]\s*\{([^}]+)\}/)[1];
        const foreground = normal.match(/\bcolor:\s*([^;]+);/)[1];
        for (const state of ['', ':hover']) {
            const rule = css.match(new RegExp(`input\\[type=submit\\]${state}\\s*\\{([^}]+)\\}`))[1];
            const background = rule.match(/\bbackground:\s*([^;]+);/)[1];
            const [lighter, darker] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
            const ratio = (lighter + 0.05) / (darker + 0.05);
            assert.ok(ratio >= 4.5, `${state || 'normal'} contrast ${ratio.toFixed(2)}:1 must be at least 4.5:1`);
        }
    }
});

test('creator hint copy briefly discloses visibility and mutability before hint entry', () => {
    const note = elementText(source, 'password-hint-note');
    assert.match(note, /public and editable/i);
    assert.match(note, /don't put secrets here/i);
    assert.ok(describedBy(source, 'password_hint').includes('password-hint-note'));
    assert.ok(source.indexOf('id="password-hint-note"') < source.indexOf('id="password_hint"'), 'note precedes the hint input');
});

// ---- source switching & reset ----

test('source changes toggle the visible input without clearing content or starting encryption', () => {
    const message = 'Keep this draft 🔐';
    const encryptor = page(source, password, password, { message });
    const { fields } = encryptor;
    const selectedFile = fields.file.files[0];
    assert.equal(fields['file-source'].hidden, false);
    assert.equal(fields['message-source'].hidden, true);

    for (const selected of ['message', 'file', 'message']) {
        encryptor.selectSource(selected);
        assert.equal(fields['file-source'].hidden, selected === 'message');
        assert.equal(fields['message-source'].hidden, selected === 'file');
        assert.equal(fields.file.files[0], selectedFile, 'the selected file is preserved');
        assert.equal(fields.message.value, message, 'the message draft is preserved');
        assert.equal(fields.password.value, password);
        assert.equal(fields.password_repeated.value, password);
        assert.equal(encryptor.reads, 0);
        assert.equal(encryptor.derivations.length, 0);
        assert.equal(encryptor.downloads.length, 0);
    }
});

test('submitting after a source change encrypts only the selected content', async () => {
    const message = 'Encrypt this message, not the selected file. 🔐';
    const encryptor = page(source, password, password, { message });
    for (const [attempt, selected] of ['message', 'file', 'message'].entries()) {
        encryptor.selectSource(selected);
        const previousReads = encryptor.reads;
        await encryptor.run('submit');
        assert.equal(encryptor.reads - previousReads, selected === 'file' ? 1 : 0);
        assert.equal(encryptor.downloads.length, attempt + 1);
        const decryptor = page(new TextDecoder().decode(encryptor.downloads[attempt][1]));
        await decryptor.run('submit');
        if (selected === 'message') {
            assert.equal(decryptor.fields['decrypted-message'].textContent, message);
            assert.equal(decryptor.fields['decrypted-message'].hidden, false);
            assert.equal(decryptor.downloads.length, 0);
        } else {
            assertRecovered(decryptor);
            assert.equal(decryptor.fields['decrypted-message'].hidden, true);
        }
    }
});

test('form reset restores the file source after native control values are reset', async () => {
    const encryptor = page(source, password, password, { message: 'Discard this draft' });
    const { fields, form } = encryptor;
    encryptor.selectSource('message');
    assert.equal(fields['file-source'].hidden, true);
    assert.equal(fields['message-source'].hidden, false);

    form.dispatch('reset');
    // The browser restores defaults after the reset event, without radio change events.
    fields['source-file'].checked = true;
    fields['source-message'].checked = false;
    fields.file.files = [];
    fields.message.value = '';
    fields.password.value = '';
    fields.password_repeated.value = '';
    await settle();
    assert.deepEqual(encryptor.timerErrors, []);
    assert.equal(fields['file-source'].hidden, false);
    assert.equal(fields['message-source'].hidden, true);
    assert.equal(encryptor.reads, 0);
    assert.equal(encryptor.derivations.length, 0);
    assert.equal(encryptor.downloads.length, 0);

    fields.password.value = password;
    fields.password_repeated.value = password;
    await encryptor.run('submit');
    assert.equal(encryptor.status.textContent, 'Select a file first.');
    assert.equal(encryptor.reads, 0);
    assert.equal(encryptor.derivations.length, 0);
    assert.equal(encryptor.downloads.length, 0);
});

// ---- message display ----

test('text messages display literally without downloading and clear on a failed retry', async () => {
    const message = 'Meet at 19:30 by the café.\nBring the 🔐 key. <img src=x onerror=alert(1)> </script>';
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
    assert.equal(decryptor.downloads.length, 0);
    assert.equal(decryptor.fields['decrypted-message'].textContent, message);
    assert.equal(decryptor.fields['decrypted-message'].hidden, false);
    assert.equal(decryptor.status.textContent, 'Message decrypted.');
    decryptor.fields.password.value = 'wrong password';
    await decryptor.run('runDecrypt');
    assert.equal(decryptor.fields['decrypted-message'].textContent, '');
    assert.equal(decryptor.fields['decrypted-message'].hidden, true);
    assert.equal(decryptor.downloads.length, 0);
});

test('messages up to 1,000 characters display inline; longer messages download intact', async () => {
    for (const length of [1000, 1001]) {
        const message = '🔐'.repeat(length - 1) + '\n';
        const decryptor = page(await artifact(source, { source: 'message', message }));
        await decryptor.run('runDecrypt');
        const output = decryptor.fields['decrypted-message'];
        if (length === 1000) {
            assert.equal(output.textContent, message);
            assert.equal(output.hidden, false);
            assert.equal(decryptor.downloads.length, 0);
        } else {
            assert.equal(output.textContent, '');
            assert.equal(output.hidden, true);
            assert.equal(decryptor.downloads.length, 1);
            assert.equal(decryptor.downloads[0][0].name, 'message.txt');
            assert.equal(new TextDecoder().decode(decryptor.downloads[0][0].content), message);
            assert.equal(decryptor.status.textContent, 'Download started: message.txt');
        }
    }
});

test('a file named message.txt remains a file download', async () => {
    const decryptor = page(await artifact(source, { filename: 'message.txt' }));
    await decryptor.run('runDecrypt');
    assert.equal(decryptor.downloads[0][0].name, 'message.txt');
    assert.deepEqual(decryptor.downloads[0][0].content, bytes);
    assert.equal(decryptor.fields['decrypted-message'].hidden, true);
});

test('empty text messages are rejected before key derivation', async () => {
    const encryptor = page(source, password, password, { source: 'message' });
    await encryptor.run('runEncrypt');
    assert.match(encryptor.status.textContent, /write a text message/i);
    assert.equal(encryptor.reads, 0);
    assert.equal(encryptor.derivations.length, 0);
    assert.equal(encryptor.downloads.length, 0);
});

// ---- hints ----

test('optional hints appear before password entry and preserve Unicode and line breaks', async () => {
    const hint = 'The title of the song we heard in Italy\nZażółć 🎵\r\n\tשלום 東京';
    const html = await artifact(source, { hint: '  ' + hint + '  ' });
    const decryptor = page(html, '');
    assert.equal(decryptor.fields['password-hint'].textContent, 'Password hint: ' + hint);
    assert.equal(decryptor.fields['password-hint'].hidden, false);
    assert.equal(decryptor.derivations.length, 0);
    assert.ok(describedBy(html, 'password').includes('password-hint'));
    decryptor.fields.password.value = password;
    await decryptor.run('runDecrypt');
    assertRecovered(decryptor);
});

test('omitted and whitespace-only hints stay hidden and do not affect decryption', async () => {
    for (const hint of ['', '  \n\t ']) {
        const html = await artifact(source, { hint });
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
    const html = await artifact(source, { hint });
    assert.equal([...html.matchAll(/<script\b/gi)].length, 2);
    assert.ok(!html.includes('<img'));
    const decryptor = page(html);
    assert.equal(decryptor.fields['password-hint'].textContent, 'Password hint: ' + hint);
    assert.equal(decryptor.fields['password-hint'].hidden, false);
    await decryptor.run('runDecrypt');
    assertRecovered(decryptor);
});

// ---- file & message containers ----

test('file and message containers have fresh neutral names and keep original names encrypted', async () => {
    const names = [];
    for (const options of [{}, { source: 'message', message: 'Hello' }]) {
        const encryptor = page(source, password, password, options);
        for (let attempt = 0; attempt < 2; attempt++) {
            await encryptor.run('submit');
            assert.equal(encryptor.downloads.length, attempt + 1);
            const [name, buffer] = encryptor.downloads[attempt];
            assert.match(name, containerNamePattern);
            assert.equal(encryptor.status.textContent, 'Download started: ' + name);
            const html = new TextDecoder().decode(buffer);
            assert.ok(!html.includes(name));
            const wrapper = html.replace(/("encrypted":")[^"]*"/, '$1"');
            const decryptor = page(html);
            await decryptor.run('submit');
            if (options.source === 'message') {
                assert.equal(decryptor.status.textContent, 'Message decrypted.');
            } else {
                assertRecovered(decryptor);
            }
            names.push(name);
        }
        assert.notEqual(names[0], names[1], 'each encryption gets a fresh container name');
    }
});

// ---- generated decryptor ----

test('generated decryptor discloses that only the encrypted content is authenticated, not the page', async () => {
    const html = await artifact(source);
    const notice = elementText(html, 'trust-notice');
    assert.match(notice, /encrypted contents are protected against tampering/i);
    assert.match(notice, /this page and its hint are not/i);
    assert.match(notice, /only open files you trust/i);
    assert.match(notice, /unique password/i);
    assert.doesNotMatch(markupOf(html), /Enter the password to decrypt this file/);
    assert.doesNotMatch(notice, /\bCSP\b|content security policy|checksum|prevent/i);
    for (const id of ['password-hint', 'trust-notice']) {
        assert.ok(describedBy(html, 'password').includes(id));
    }
    const decryptor = page(html);
    await decryptor.run('runDecrypt');
    assertRecovered(decryptor);
});