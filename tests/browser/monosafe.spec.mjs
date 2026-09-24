import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { test as base, expect } from '@playwright/test';

const creatorUrl = new URL('../../monosafe.html', import.meta.url).href;
const password = 'cedar orbit velvet harbor 🔐';
const containerNamePattern = /^monosafe-[0-9a-f]{32}\.html$/;

const test = base.extend({
    page: async ({ page }, use) => {
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await use(page);
        expect(errors, 'no uncaught browser errors').toEqual([]);
    }
});

test.beforeEach(async ({ context, page }) => {
    // WebKit's offline emulation also blocks file:// navigation. Block network requests instead.
    await context.route(/^https?:\/\//, route => route.abort('internetdisconnected'));
    await context.routeWebSocket(/.*/, socket => socket.close());
    await page.goto(creatorUrl);
});

async function enterPasswords(page) {
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByLabel('Repeat password', { exact: true }).fill(password);
}

async function checkPasswordToggle(page, label, buttonName) {
    const input = page.getByLabel(label, { exact: true });
    const button = page.getByRole('button', { name: buttonName, exact: true });
    const value = await input.inputValue();
    await button.focus();
    for (const [key, type, pressed] of [['Space', 'text', 'true'], ['Enter', 'password', 'false']]) {
        await page.keyboard.press(key);
        await expect(input).toHaveAttribute('type', type);
        await expect(input).toHaveValue(value);
        await expect(button).toHaveAttribute('aria-pressed', pressed);
        await expect(button).toBeFocused();
    }
}

async function encryptAndOpen(page, testInfo) {
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
    await expect(page.locator('#encrypt-status')).toHaveText(/^(Download started:|Encrypted:)/);
    // Exercise native download behavior whether or not the browser offers file sharing.
    const save = page.getByRole('button', { name: 'Download', exact: true });
    if (await save.isVisible()) await save.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(containerNamePattern);
    const path = testInfo.outputPath(download.suggestedFilename());
    await download.saveAs(path);
    await page.goto(pathToFileURL(path).href);
    await expect(page.getByRole('button', { name: 'Decrypt', exact: true })).toBeVisible();
}

test('Help and password visibility controls work from the keyboard without submitting', async ({ page }) => {
    const help = page.getByRole('button', { name: 'Help', exact: true });
    await help.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog', { name: 'MonoSafe', exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toBeHidden();
    await expect(help).toBeFocused();

    await enterPasswords(page);
    await checkPasswordToggle(page, 'Password', 'Show password');
    await checkPasswordToggle(page, 'Repeat password', 'Show repeated password');
    await expect(page.locator('#encrypt-status')).toBeEmpty();
});

test('native required-field validation prevents submission until both passwords are entered', async ({ page }) => {
    await page.getByRole('radio', { name: 'Text message', exact: true }).check();
    await page.getByLabel('Text message to encrypt', { exact: true }).fill('A private message');
    for (const label of ['Password', 'Repeat password']) {
        await page.getByRole('button', { name: 'Encrypt', exact: true }).click();
        const input = page.getByLabel(label, { exact: true });
        expect(await input.evaluate(element => element.validity.valueMissing)).toBe(true);
        await expect(input).toBeFocused();
        await expect(page.locator('#encrypt-status')).toBeEmpty();
        await input.fill(password);
    }
});

test('source switching preserves inputs and native reset restores file mode', async ({ page }) => {
    const file = page.getByLabel('File to encrypt', { exact: true });
    const message = page.getByLabel('Text message to encrypt', { exact: true });
    await expect(file).toBeVisible();
    await expect(message).toBeHidden();
    await file.setInputFiles({ name: 'example.txt', mimeType: 'text/plain', buffer: Buffer.from('Keep this file') });
    await page.getByRole('radio', { name: 'Text message', exact: true }).check();
    await expect(file).toBeHidden();
    await expect(message).toBeVisible();
    await message.fill('Keep this draft');
    await page.getByRole('radio', { name: 'File', exact: true }).check();
    await expect(file).toBeVisible();
    await expect(message).toBeHidden();
    expect(await file.evaluate(input => input.files[0].name)).toBe('example.txt');
    await page.getByRole('radio', { name: 'Text message', exact: true }).check();
    await expect(message).toHaveValue('Keep this draft');

    // There is no reset button; invoke the native DOM API, not an application helper.
    await page.locator('#encrypt-form').evaluate(form => form.reset());
    await expect(page.getByRole('radio', { name: 'File', exact: true })).toBeChecked();
    await expect(file).toBeVisible();
    await expect(file).toHaveValue('');
    await expect(message).toBeHidden();
    await expect(message).toHaveValue('');
});

test('a short message and public hint display literally without downloading the plaintext', async ({ page }, testInfo) => {
    const message = 'Meet at the café. 🔐\n<img src=x onerror=alert(1)> </script> &';
    const hint = 'Public hint: <img src=x onerror=alert(1)> 🎵';
    await page.getByRole('radio', { name: 'Text message', exact: true }).check();
    await page.getByLabel('Text message to encrypt', { exact: true }).fill(message);
    await enterPasswords(page);
    await page.getByText('Add password hint (optional)', { exact: true }).click();
    await page.getByLabel('Password hint', { exact: true }).fill(hint);
    await encryptAndOpen(page, testInfo);

    await expect(page.locator('#password-hint')).toHaveText('Password hint: ' + hint);
    await expect(page.locator('#password-hint img')).toHaveCount(0);
    const downloads = [];
    page.on('download', download => downloads.push(download));
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Decrypt', exact: true }).click();
    await expect(page.locator('#decrypt-status')).toHaveText('Message decrypted.');
    const output = page.locator('#decrypted-message');
    await expect(output).toBeVisible();
    expect(await output.textContent()).toBe(message);
    await expect(output.locator('img, script')).toHaveCount(0);
    expect(downloads).toHaveLength(0);
});

test('a local file encrypts and downloads intact after a wrong-password retry, entirely offline', async ({ page }, testInfo) => {
    const filename = 'zażółć-東京-🔐.bin';
    const content = Buffer.from([0, 255, 47, 128, 10, 0, 13]);
    await page.getByLabel('File to encrypt', { exact: true }).setInputFiles({
        name: filename, mimeType: 'application/octet-stream', buffer: content
    });
    await enterPasswords(page);
    await encryptAndOpen(page, testInfo);

    const downloads = [];
    page.on('download', download => downloads.push(download));
    await page.getByLabel('Password', { exact: true }).fill('wrong password');
    await page.getByRole('button', { name: 'Decrypt', exact: true }).click();
    await expect(page.locator('#decrypt-status')).toContainText('Wrong password or corrupted file');
    expect(downloads).toHaveLength(0);
    await expect(page.getByRole('button', { name: 'Decrypt', exact: true })).toBeEnabled();

    await page.getByLabel('Password', { exact: true }).fill(password);
    await checkPasswordToggle(page, 'Password', 'Show password');
    await expect(page.locator('#decrypt-status')).toContainText('Wrong password or corrupted file');
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Decrypt', exact: true }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe(filename);
    const recoveredPath = testInfo.outputPath('recovered.bin');
    await download.saveAs(recoveredPath);
    expect(await readFile(recoveredPath)).toEqual(content);
    await expect(page.locator('#decrypt-status')).toHaveText('Download started: ' + filename);
});
