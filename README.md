# MonoSafe

Turn any file or text message into a single, password-protected HTML file that decrypts itself in the browser.

No accounts, no servers, no installs. Everything happens on your own computer.

## How it works

**To lock something:**

1. Open `monosafe.html` in your browser. If you're using the hosted page, choose **Download MonoSafe for offline use** first, then open the downloaded `monosafe.html` whenever you need it.
2. Pick a file, or write a message.
3. Choose a strong passphrase (and optionally a hint for the recipient).
4. Click **Encrypt** and save the HTML file it gives you. Where your device can share files (most phones, Safari on macOS, Chrome or Edge on Windows and ChromeOS), you get **Share…** and **Download** buttons instead. **Share…** opens the system share sheet so you can send the file straight to email, Slack, Discord or another app. Send the passphrase another way.

**To unlock it:**

1. Open that HTML file in any browser.
2. Type the passphrase and click **Decrypt**.
3. The original file downloads. Text messages up to 1,000 characters appear directly on the page; longer messages download as `message.txt`.

The encrypted file is self-contained: whoever receives it needs nothing but a browser and the passphrase.

## Good to know

- Works in any modern browser; the decryptor also works in browsers going back to about 2015.
- Your passphrase is the only thing protecting the file. Make it long and unique.
- Anyone who has the file can try to guess the passphrase, so don't share it alongside the file.
- Password hints are not encrypted. Anyone who opens the file can read the hint, and anyone can change it without the passphrase, so never put a secret in it.
- The encrypted content is protected against tampering, but the HTML page around it is not. Someone could replace that page with a look-alike that captures the passphrase, and nothing in the file can stop that. Only open encrypted files from a source you trust, and use a different passphrase for each one.
- The original filename is encrypted too and restored after decryption. New HTML containers use neutral, random names such as `monosafe-<random-token>.html` for both files and messages.
- Very large files can be slow or run out of memory in the browser. It works best for documents, photos, and other everyday files.

## Development

Use Node.js 24 or newer and GNU Make in a Unix-like environment. The routine
`make test` suite uses Node's built-in test runner; no npm dependencies are needed.

```
make test     # run application tests and isolated build checks
make build    # build the dist/ folder
make deploy   # publish with surge (requires the Surge CLI)
```

GitHub Actions runs `make test` on Node.js 24 and 26 for pull requests and
pushes to `main`. Build tests verify both HTML copies and `CNAME`, including
replacement of stale output, in temporary directories without touching your
local `dist/`.

### Browser smoke tests

Install the development dependency and Playwright's browsers once:

```sh
npm ci
npx playwright install chromium firefox webkit
make test-browser
```

On supported Linux distributions, use `npx playwright install --with-deps`
to install required system libraries too. This may require administrator
privileges. For a single browser, run
`npm run test:browser -- --project=chromium`. On unsupported distributions such
as Arch Linux, WebKit may lack compatible libraries; use a supported environment
or the Ubuntu CI job for the full matrix.

The five smoke tests run in Chromium, Firefox, and WebKit. They open the creator
and generated HTML as local files with HTTP(S) and WebSocket requests blocked,
use real WebCrypto and downloads, and cover file recovery, wrong-password retries, literal message
and hint display, source switching/reset, keyboard controls, and native form
validation. No OS share sheet is automated; the existing Node suite covers its
API outcomes.

A separate GitHub Actions job runs all three browsers on Ubuntu. Failed runs
retain traces and screenshots in the `browser-test-failures` artifact for seven
days. Locally, inspect a trace with `npx playwright show-trace <path-to-trace.zip>`
under `test-results/`.

Browser checks do not establish screen-reader announcements or replace manual
accessibility testing. Also follow the
[manual accessibility checks](tests/accessibility-manual.md).

## Credits

MonoSafe is based on [PolySafe](https://github.com/fmeum/polysafe) by Fabian Henneke.

## License

MIT. See [LICENSE](LICENSE).
