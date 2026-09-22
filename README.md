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

```
make test     # run the tests
make build    # build the dist/ folder
make deploy   # publish with surge
```

## Credits

MonoSafe is based on [PolySafe](https://github.com/fmeum/polysafe) by Fabian Henneke.

## License

MIT. See [LICENSE](LICENSE).
