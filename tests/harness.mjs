import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import vm from 'node:vm';

// --------------- shared constants ---------------
export const source = readFileSync(new URL('../monosafe.html', import.meta.url), 'utf8');
export const bytes = Uint8Array.of(0, 255, 47, 128, 10);
export const filename = 'private-zażółć.bin';
export const containerNamePattern = /^monosafe-[0-9a-f]{32}\.html$/;
export const password = ' long unique test passphrase 🔐 ';
export const DOWNLOAD_CLEANUP_DELAY = 10000;

// --------------- markup helpers ---------------
export function markupOf(html) {
    return html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
}

export function stylesheet(html) {
    return html.match(/<style\b[^>]*>([\s\S]*?)<\/style>/)?.[1] || '';
}

export function elementText(html, id) {
    const markup = markupOf(html);
    const match = markup.match(new RegExp(`<(\\w+)[^>]*\\sid="${id}"[^>]*>([\\s\\S]*?)</\\1>`));
    assert.ok(match, `#${id} exists in markup`);
    return match[2].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}

export function describedBy(html, id) {
    const input = html.match(new RegExp(`<(?:input|textarea)[^>]*\\sid="${id}"[^>]*>`))[0];
    return (input.match(/aria-describedby="([^"]*)"/)?.[1] || '').split(/\s+/);
}

export function embeddedPayload(html, payload) {
    return html.replace(/(<script id="data"[^>]*>)[\s\S]*?(<\/script>)/, (_, open, close) => open + payload + close);
}

// --------------- page harness ---------------
export function page(html, secret = password, repeated = secret, options = {}) {
    const markup = markupOf(html);
    function attributes(id) {
        const tag = markup.match(new RegExp(`<[^>]+\\bid="${id}"[^>]*>`));
        return Object.fromEntries([...(tag?.[0] || '').matchAll(/([\w-]+)="([^"]*)"/g)]
            .map(([, name, value]) => [name, value]));
    }
    function eventTarget(properties = {}) {
        const listeners = {};
        return Object.assign(properties, {
            addEventListener(type, callback) { (listeners[type] ||= []).push(callback); },
            dispatch(type, event) { for (const callback of listeners[type] || []) callback.call(this, event); },
            getAttribute(name) { return this[name]; },
            setAttribute(name, value) { this[name] = value; }
        });
    }
    const statuses = [];
    const status = {
        dataset: {},
        get textContent() { return statuses.length ? statuses[statuses.length - 1] : ''; },
        set textContent(value) { statuses.push(value); }
    };
    const buttonLabel = html.includes('id="encrypt-form"') ? 'Encrypt' : 'Decrypt';
    const observedButtonValues = new Set([buttonLabel]);
    let buttonValue = buttonLabel;
    let completionCallback = null;
    const button = {
        _disabled: false,
        get disabled() { return this._disabled; },
        set disabled(value) {
            this._disabled = value;
            if (!value && completionCallback) {
                const cb = completionCallback;
                completionCallback = null;
                cb();
            }
        },
        get value() { return buttonValue; },
        set value(value) { buttonValue = value; observedButtonValues.add(value); }
    };
    const form = eventTarget({ style: {} });
    const fields = {
        password: eventTarget({ value: secret, id: 'password', type: 'password' }),
        'password-toggle': eventTarget(attributes('password-toggle')),
        'password-repeated-toggle': eventTarget(attributes('password-repeated-toggle')),
        'help-button': eventTarget(attributes('help-button')),
        'help-close': eventTarget(attributes('help-close')),
        'help-dialog': eventTarget({ showModal() { this.open = true; }, close() { this.open = false; } }),
        'encrypt-form': form, 'decrypt-form': form,
        'encrypt-button': button, 'decrypt-button': button,
        'encrypt-status': status, 'decrypt-status': status,
        'encrypt-result': { hidden: true },
        'share-button': eventTarget(), 'save-button': eventTarget(),
        'page-style': { textContent: stylesheet(html) },
        password_hint: { value: options.hint || '' },
        'source-file': eventTarget({ checked: options.source !== 'message' }),
        'source-message': eventTarget({ checked: options.source === 'message' }),
        'file-source': { hidden: false },
        'message-source': { hidden: true },
        message: { value: options.message || '' },
        'password-hint': { textContent: '', hidden: true },
        'decrypted-message': { textContent: '', hidden: true },
        'password-strength': { dataset: {} },
        password_repeated: eventTarget({ value: repeated, id: 'password_repeated', type: 'password' }),
        'password-strength-status': { textContent: '' },
        'password-match-status': { textContent: '' },
        'password-match': { dataset: {} },
        file: { files: [{ name: options.filename || filename }] },
        data: { textContent: html.match(/<script id="data"[^>]*>([\s\S]*?)<\/script>/)?.[1] }
    };
    const downloads = [];
    const randomValues = [];
    const derivations = [];
    const derivationStatuses = [];
    const keyAlgorithms = [];
    const operations = [];
    const timerErrors = [];
    const timers = [];
    // Timers of one second or more are held until the test advances them; shorter ones run at once.
    const pendingTimers = [];
    const urls = { created: [], revoked: [] };
    const anchors = [];
    const body = {
        children: [],
        appendChild(node) { body.children.push(node); node.parentNode = body; return node; },
        removeChild(node) {
            const index = body.children.indexOf(node);
            assert.notEqual(index, -1, 'removed node is attached to body');
            body.children.splice(index, 1);
            node.parentNode = null;
            return node;
        }
    };
    let reads = 0;
    const context = vm.createContext({
        TextEncoder, TextDecoder, Uint8Array, Blob, File, DOMException, atob,
        setTimeout: (callback, delay) => {
            timers.push(delay);
            const guarded = () => {
                try { callback(); } catch (error) { timerErrors.push(error); }
            };
            if (delay >= 1000) pendingTimers.push(guarded);
            else setTimeout(guarded, 0);
        },
        window: eventTarget({ URL: {
            createObjectURL: blob => {
                const url = 'blob:monosafe/' + urls.created.length;
                urls.created.push({ url, blob });
                return url;
            },
            revokeObjectURL: url => urls.revoked.push(url)
        }, crypto: {
            getRandomValues: array => {
                const result = webcrypto.getRandomValues(array);
                randomValues.push(Array.from(result));
                return result;
            },
            // Hooks can delay or reject browser API calls; successful calls still use real WebCrypto.
            subtle: new Proxy(webcrypto.subtle, {
                get(target, key) {
                    if (key === 'deriveKey') return async (...args) => {
                        derivations.push(args[0]);
                        derivationStatuses.push(status.textContent);
                        keyAlgorithms.push(args[2]);
                        await options.beforeCrypto?.(key);
                        return target.deriveKey(...args);
                    };
                    if (key === 'encrypt' || key === 'decrypt') return async (...args) => {
                        operations.push(args[0]);
                        await options.beforeCrypto?.(key);
                        return target[key](...args);
                    };
                    if (key === 'importKey') return async (...args) => {
                        await options.beforeCrypto?.(key);
                        return target[key](...args);
                    };
                    return target[key].bind(target);
                }
            })
        }, ...options.window }),
        document: {
            body,
            createElement(tag) {
                assert.equal(tag, 'a');
                const anchor = { tag, parentNode: null, clicked: [], click() {
                    assert.equal(this.parentNode, body, 'anchor is attached when clicked');
                    assert.ok(!urls.revoked.includes(this.href), 'object URL is still live when clicked');
                    this.clicked.push({ href: this.href, download: this.download });
                } };
                anchors.push(anchor);
                return anchor;
            },
            getElementById: id => {
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
                const complete = () => {
                    if (Object.hasOwn(options, 'readError')) {
                        this.error = options.readError;
                        this.onerror();
                        return;
                    }
                    this.result = (options.bytes || bytes).buffer;
                    this.onload();
                };
                if (options.beforeRead) {
                    Promise.resolve().then(options.beforeRead).then(complete, error => {
                        this.error = error;
                        this.onerror();
                    });
                } else complete();
            }
        }
    });
    for (const match of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
        if (!match[1].includes('application/json')) vm.runInContext(match[2], context);
    }
    if (options.download !== 'native') context.download = (...args) => downloads.push(args);
    return {
        context, status, statuses, button, buttonLabel, observedButtonValues, fields, form, downloads, derivations, derivationStatuses,
        randomValues, keyAlgorithms, operations, timerErrors, timers, urls, anchors, body, get reads() { return reads; },
        selectSource(name) {
            assert.ok(name === 'file' || name === 'message');
            fields['source-file'].checked = name === 'file';
            fields['source-message'].checked = name === 'message';
            fields['source-' + name].dispatch('change');
        },
        async run(name) {
            if (name === 'submit') {
                let prevented = false;
                form.dispatch('submit', { preventDefault() { prevented = true; } });
                assert.ok(prevented, 'form submission prevents navigation');
            } else context[name]();
            // Await the button being re-enabled, or resolve immediately for sync
            // validation failures that never disable it.
            const done = Promise.withResolvers();
            const deadline = setTimeout(() => done.resolve(), 10000);
            completionCallback = () => { clearTimeout(deadline); done.resolve(); };
            if (!button.disabled) done.resolve();
            await done.promise;
            clearTimeout(deadline);
            assert.deepEqual(timerErrors, [], 'no exceptions escape timer callbacks');
            assert.ok(!button.disabled, 'operation completes');
        },
        advanceTimers() {
            for (const callback of pendingTimers.splice(0)) callback();
            assert.deepEqual(timerErrors, [], 'no exceptions escape timer callbacks');
        }
    };
}

// A navigator that can share files; canShare and share outcomes are configurable per test.
export function sharingNavigator({ canShare = () => true, share = () => Promise.resolve() } = {}) {
    const checks = [];
    const shares = [];
    const navigator = {
        canShare(data) { checks.push(data); return canShare(data); },
        share(data) { shares.push(data); return share(data); }
    };
    return { navigator, checks, shares };
}

export async function settle() {
    await new Promise(resolve => setTimeout(resolve, 0));
}

// --------------- reusable test artifacts ---------------
export async function artifact(source, options = {}) {
    const encryptor = page(source, password, password, options);
    await encryptor.run('runEncrypt');
    assert.equal(encryptor.downloads.length, 1);
    assert.equal(encryptor.status.textContent, 'Download started: ' + encryptor.downloads[0][0]);
    assert.equal(encryptor.derivations[0].iterations, 600000);
    assert.equal(encryptor.derivations[0].hash.name, 'SHA-256');
    return new TextDecoder().decode(encryptor.downloads[0][1]);
}

export function assertRecovered(decryptor, status = 'Download started: ' + filename) {
    assert.equal(decryptor.status.textContent, status);
    assert.equal(decryptor.downloads.length, 1);
    assert.equal(decryptor.downloads[0][0].name, filename);
    assert.deepEqual(decryptor.downloads[0][0].content, bytes);
}

export function assertCryptoProfile(instance, message) {
    assert.equal(instance.derivations[0].name, 'PBKDF2', message);
    assert.equal(instance.derivations[0].hash.name, 'SHA-256', message);
    assert.equal(instance.derivations[0].iterations, 600000, message);
    assert.equal(instance.keyAlgorithms[0].name, 'AES-GCM', message);
    assert.equal(instance.keyAlgorithms[0].length, 128, message);
    assert.equal(instance.operations[0].name, 'AES-GCM', message);
    assert.equal(instance.operations[0].iv.byteLength, 12, message);
    assert.equal(Object.hasOwn(instance.operations[0], 'length'), false, message);
}