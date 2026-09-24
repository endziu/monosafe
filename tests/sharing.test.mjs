import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
    source, password, containerNamePattern, bytes, filename,
    page, assertRecovered, sharingNavigator, settle
} from './harness.mjs';

test('where files can be shared, encrypting offers Share and Download instead of downloading', async () => {
    const sharing = sharingNavigator();
    const encryptor = page(source, password, password, { window: { navigator: sharing.navigator } });
    assert.equal(encryptor.fields['encrypt-result'].hidden, true);
    await encryptor.run('runEncrypt');
    assert.equal(encryptor.downloads.length, 0);
    assert.equal(encryptor.fields['encrypt-result'].hidden, false);
    const [file] = sharing.checks[0].files;
    assert.match(file.name, containerNamePattern);
    assert.equal(file.type, 'text/html');
    assert.equal(encryptor.status.textContent, 'Encrypted: ' + file.name + '. Share it or download it.');
    assert.equal(encryptor.status.dataset.tone, 'info');
    const decryptor = page(new TextDecoder().decode(await file.arrayBuffer()));
    await decryptor.run('runDecrypt');
    assertRecovered(decryptor);
});

test('Share sends only the container and a neutral title, never the password or hint', async () => {
    const hint = 'hint-that-must-not-travel';
    const sharing = sharingNavigator();
    const encryptor = page(source, password, password, { hint, window: { navigator: sharing.navigator } });
    await encryptor.run('runEncrypt');
    encryptor.fields['share-button'].dispatch('click');
    await settle();
    assert.equal(sharing.shares.length, 1);
    const [data] = sharing.shares;
    assert.deepEqual(Object.keys(data).sort(), ['files', 'title']);
    assert.deepEqual(data.files, sharing.checks[0].files);
    assert.ok(!data.title.includes(password) && !data.title.includes(hint));
    assert.equal(encryptor.status.textContent, 'Shared: ' + data.files[0].name);
    assert.equal(encryptor.status.dataset.tone, 'info');
});

test('dismissing the share sheet is silent; other share failures point to Download', async () => {
    const dismissed = sharingNavigator({ share: () => Promise.reject(new DOMException('Share canceled', 'AbortError')) });
    const encryptor = page(source, password, password, { window: { navigator: dismissed.navigator } });
    await encryptor.run('runEncrypt');
    const before = encryptor.status.textContent;
    encryptor.fields['share-button'].dispatch('click');
    await settle();
    assert.equal(encryptor.status.textContent, before);
    assert.equal(encryptor.fields['encrypt-result'].hidden, false);

    const denied = sharingNavigator({ share: () => Promise.reject(new DOMException('Permission denied', 'NotAllowedError')) });
    const failing = page(source, password, password, { window: { navigator: denied.navigator } });
    await failing.run('runEncrypt');
    failing.fields['share-button'].dispatch('click');
    await settle();
    assert.equal(failing.status.textContent, 'Sharing failed: Permission denied. Use Download instead.');
    assert.equal(failing.status.dataset.tone, 'error');
    assert.equal(failing.fields['encrypt-result'].hidden, false);
});

// ---- late share outcomes ----

for (const outcome of ['success', 'failure']) {
    test(`a late share ${outcome} cannot replace a newer encryption result`, async () => {
        const completion = Promise.withResolvers();
        const sharing = sharingNavigator({ share: () => completion.promise });
        const encryptor = page(source, password, password, { window: { navigator: sharing.navigator } });
        await encryptor.run('submit');
        encryptor.fields['share-button'].dispatch('click');
        await encryptor.run('submit');
        const status = encryptor.status.textContent;
        const currentFile = sharing.checks[1].files[0];
        assert.notEqual(sharing.shares[0].files[0], currentFile);

        if (outcome === 'success') completion.resolve();
        else completion.reject(new DOMException('Permission denied', 'NotAllowedError'));
        await settle();

        assert.equal(encryptor.status.textContent, status);
        assert.equal(encryptor.status.dataset.tone, 'info');
        assert.equal(encryptor.fields['encrypt-result'].hidden, false);
        encryptor.fields['save-button'].dispatch('click');
        assert.equal(encryptor.downloads[0][0], currentFile.name);
    });
}

for (const outcome of ['success', 'failure']) {
    test(`a late share ${outcome} cannot replace a newer download status`, async () => {
        const completion = Promise.withResolvers();
        const sharing = sharingNavigator({ share: () => completion.promise });
        const encryptor = page(source, password, password, { window: { navigator: sharing.navigator } });
        await encryptor.run('submit');
        encryptor.fields['share-button'].dispatch('click');
        encryptor.fields['save-button'].dispatch('click');
        const status = 'Download started: ' + encryptor.downloads[0][0];
        assert.equal(encryptor.status.textContent, status);

        if (outcome === 'success') completion.resolve();
        else completion.reject(new DOMException('Permission denied', 'NotAllowedError'));
        await settle();

        assert.equal(encryptor.status.textContent, status);
        assert.equal(encryptor.status.dataset.tone, 'info');
        assert.equal(encryptor.downloads.length, 1);
    });
}

for (const outcome of ['success', 'failure']) {
    for (const state of ['pending read', 'read failure', 'validation failure']) {
        test(`a late share ${outcome} preserves a newer ${state} and cannot restore old actions`, async () => {
            const share = Promise.withResolvers();
            const started = Promise.withResolvers();
            const read = Promise.withResolvers();
            const sharing = sharingNavigator({ share: () => share.promise });
            let delay = false;
            const encryptor = page(source, password, password, {
                window: { navigator: sharing.navigator },
                beforeRead: () => {
                    if (!delay) return;
                    started.resolve();
                    return read.promise;
                }
            });
            await encryptor.run('submit');
            encryptor.fields['share-button'].dispatch('click');
            delay = true;
            if (state === 'validation failure') encryptor.fields.password_repeated.value = 'different';
            const running = encryptor.run('submit');
            try {
                if (state === 'validation failure') await running;
                else {
                    await started.promise;
                    if (state === 'read failure') {
                        read.reject(new DOMException('Input unavailable', 'NotReadableError'));
                        await running;
                    }
                }
                const expected = {
                    'pending read': 'Encrypting… This may take a few seconds.',
                    'read failure': 'Encryption failed: Input unavailable',
                    'validation failure': 'Passwords must match.'
                }[state];
                assert.equal(encryptor.status.textContent, expected);
                if (outcome === 'success') share.resolve();
                else share.reject(new DOMException('Permission denied', 'NotAllowedError'));
                await settle();

                assert.equal(encryptor.status.textContent, expected);
                assert.equal(encryptor.status.dataset.tone, state === 'pending read' ? 'info' : 'error');
                assert.equal(encryptor.button.disabled, state === 'pending read');
                assert.equal(encryptor.fields['encrypt-result'].hidden, true);
                encryptor.fields['save-button'].dispatch('click');
                encryptor.fields['share-button'].dispatch('click');
                assert.equal(encryptor.downloads.length, 0);
                assert.equal(sharing.shares.length, 1);
            } finally {
                share.resolve();
                read.resolve();
                await running;
            }
        });
    }
}

// ---- download & re-encryption ----

test('Download saves the same container that Share offers', async () => {
    const sharing = sharingNavigator();
    const encryptor = page(source, password, password, { window: { navigator: sharing.navigator } });
    await encryptor.run('runEncrypt');
    encryptor.fields['save-button'].dispatch('click');
    const [file] = sharing.checks[0].files;
    assert.equal(encryptor.downloads.length, 1);
    assert.equal(encryptor.downloads[0][0], file.name);
    assert.deepEqual(new Uint8Array(encryptor.downloads[0][1]), new Uint8Array(await file.arrayBuffer()));
    assert.equal(encryptor.status.textContent, 'Download started: ' + file.name);
});

test('without file sharing, encrypting downloads immediately as before', async () => {
    const refusing = sharingNavigator({ canShare: () => false });
    const shareOnly = { share: () => Promise.resolve() };
    for (const [label, navigator] of [['canShare false', refusing.navigator], ['no canShare', shareOnly], ['no navigator', undefined]]) {
        const encryptor = page(source, password, password, { window: { navigator } });
        await encryptor.run('runEncrypt');
        assert.equal(encryptor.downloads.length, 1, label);
        assert.match(encryptor.downloads[0][0], containerNamePattern, label);
        assert.equal(encryptor.fields['encrypt-result'].hidden, true, label);
        assert.equal(encryptor.status.textContent, 'Download started: ' + encryptor.downloads[0][0], label);
    }
});

test('re-encrypting hides Share and Download until the new container is ready', async () => {
    const sharing = sharingNavigator();
    const encryptor = page(source, password, password, { window: { navigator: sharing.navigator } });
    await encryptor.run('runEncrypt');
    const visibility = [];
    encryptor.fields['encrypt-result'] = {
        get hidden() { return visibility[visibility.length - 1]; },
        set hidden(value) { visibility.push(value); }
    };
    await encryptor.run('runEncrypt');
    assert.deepEqual(visibility, [true, false]);
    encryptor.fields['share-button'].dispatch('click');
    await settle();
    const [first, second] = sharing.checks.map(check => check.files[0]);
    assert.notEqual(first.name, second.name);
    assert.equal(sharing.shares[0].files[0], second);
});