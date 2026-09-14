# MonoSafe

Turn any file or text message into a single, password-protected HTML file that decrypts itself in the browser.

No accounts, no servers, no installs. Everything happens on your own computer.

## How it works

**To lock something:**

1. Open `monosafe.html` in your browser.
2. Pick a file, or write a message.
3. Choose a strong passphrase (and optionally a hint for the recipient).
4. Click **Encrypt** and save the HTML file it gives you.

**To unlock it:**

1. Open that HTML file in any browser.
2. Type the passphrase and click **Decrypt**.
3. The original file downloads.

The encrypted file is self-contained: whoever receives it needs nothing but a browser and the passphrase.

## Good to know

- Works in any modern browser; the decryptor also works in browsers going back to about 2015.
- Your passphrase is the only thing protecting the file. Make it long and unique.
- Anyone who has the file can try to guess the passphrase, so don't share it alongside the file.
- The filename is encrypted too. Rename the HTML file if you want to keep the original name secret.
- Very large files can be slow or run out of memory in the browser. It works best for documents, photos, and other everyday files.

## Development

```
make test     # run the tests
make build    # build the dist/ folder
make deploy   # publish with surge
```

## Credits

MonoSafe is based on [PolySafe](https://github.com/fmeum/polysafe) by Fabian Henneke. This is an independent project by [endziu](https://github.com/endziu), not affiliated with the original author.

## License

MIT. See [LICENSE](LICENSE).
