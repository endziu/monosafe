# MonoSafe hardening spec handoff

Use this document as the source context for `/skill:to-spec`. Produce one spec for the **hardening and accessibility release** described below. Keep later product features out of this spec.

## Product context

MonoSafe turns one file or plaintext message into a password-protected, self-decrypting HTML file. Encryption and decryption happen locally in the browser. The generated artifact contains its own decryptor, so it remains usable independently of future website changes.

The minimal product interface is:

1. Choose a file or enter a message.
2. Enter a passphrase and optionally a public hint.
3. Download one encrypted HTML artifact.
4. Open that artifact, enter the passphrase, and recover the content.

Preserve these product constraints:

- one directly usable source HTML file;
- one self-contained generated HTML artifact;
- no server, account, network request, telemetry, persistent storage, external runtime dependency, or mandatory build step;
- operation from a local `file://` page in supported browsers;
- one primary action on each screen;
- generated decryptor code remains conservative enough for the existing compatibility promise;
- previously generated artifacts remain autonomous and the legacy fixtures continue to decrypt.

## Problem to solve

The core cryptography and round-trip behavior work, but several correctness, privacy, accessibility, and feedback details weaken the product promise:

- The optional hint is stored outside the ciphertext, but the interface and README do not tell users that anyone with the artifact can read or alter it.
- The encrypted payload is authenticated, but the executable HTML wrapper is not. A modified wrapper can capture a passphrase. Recipients need an accurate trust warning, especially because offline artifacts look inherently trustworthy.
- The creator revokes its object URL immediately after initiating a download, which can race with the browser. Temporary download anchors are not removed.
- The outer artifact filename repeats the original filename, exposing metadata that users may reasonably believe is encrypted.
- Long key derivation is conveyed only through a changing button value, and successful download initiation has no visible or assistive feedback.
- Password fields rely on placeholders as visible labels. The documents lack a language declaration. The primary button contrast fails WCAG AA for normal text. Match and complexity indicators rely too heavily on color, while two live regions can announce on every password keystroke.
- The decryptor lacks the creator's password-visibility control.
- Small defects and dead code make the security-sensitive implementation harder to maintain.
- Crypto profile values are duplicated between creator and generated decryptor source, making a future parameter change a multi-location edit.

## Intended user-visible outcome

After this release:

- A sender understands that a hint is public before adding one.
- A recipient understands that the HTML artifact is executable and should come from a trusted source, and that a unique passphrase limits harm from reuse.
- Download initiation is reliable and explicitly announced without claiming that the browser saved the file successfully.
- The downloaded container has a neutral randomized MonoSafe filename; the original filename remains inside the ciphertext and is restored after decryption.
- Encryption and decryption announce that work is in progress and may take a few seconds.
- Password inputs have persistent visible labels, usable visibility controls, and concise, non-noisy accessible feedback.
- Complexity and password-match states are visible as text as well as color.
- The primary controls meet WCAG AA contrast requirements.
- Existing artifact round trips and legacy artifact decryption continue to work.

## Accepted implementation decisions

Treat these as settled decisions for the spec:

1. **Public hint disclosure**
   - Describe the hint as visible to anyone who opens the artifact.
   - Document that it is neither secret nor protected from modification by the payload authentication.
   - Continue rendering it strictly as plaintext.

2. **Wrapper trust disclosure**
   - Explain the distinction between authenticated encrypted content and an unauthenticated executable wrapper.
   - Recommend a unique passphrase for each artifact.
   - Present this as an honest limitation, not as a claim that documentation technically prevents wrapper tampering.

3. **Reliable download lifecycle**
   - Retain object URLs long enough for the browser to begin the download.
   - Revoke each URL and remove its temporary anchor afterward in both creator and decryptor flows.
   - Report `Download started: <name>` rather than `Saved`, because the page cannot observe whether saving completed.

4. **Private container naming**
   - New encrypted artifacts receive a neutral randomized name in the form `monosafe-<random-token>.html` or an equivalently short, non-identifying form.
   - Generate the token locally with the existing cryptographically secure random source.
   - Preserve the original filename only in encrypted content for restoration after decryption.

5. **Crypto cleanup**
   - New artifacts use a 96-bit random AES-GCM IV.
   - Remove fields that are not members of AES-GCM operation parameters; key size remains a property of key derivation.
   - Keep algorithm choices internal and fixed. Do not expose cryptographic settings to users.
   - Keep the crypto profile in one authoritative creator-side definition and emit fixed values into each generated decryptor. Do not make iteration count or algorithm selection attacker-controlled through unvalidated payload fields.

6. **Progress and completion feedback**
   - Use the existing status region to announce encryption/decryption progress and that the operation can take a few seconds.
   - Announce successful download initiation as a non-error state.
   - Use neutral primary action labels: `Encrypt` and `Decrypt`.

7. **Accessibility baseline**
   - Declare the document language in both creator and generated decryptor.
   - Add persistent visible labels for password fields.
   - Meet WCAG AA text contrast for primary controls.
   - Show textual complexity and password-match values; color may remain supplementary.
   - Avoid multiple announcements per password keystroke. Consolidate or debounce assistive status updates while keeping immediate visual feedback.
   - Add an accessible password-visibility control to the decryptor.
   - A toggle button should expose one coherent state model rather than conflicting dynamic labels and pressed state.

8. **Focused maintenance cleanup**
   - Remove the shadowed invalid file-reading declaration.
   - Correct the misspelled filename-prefixing name.
   - Remove unreachable and redundant password-pattern entries.
   - Read known elements by stable identifiers.
   - Preserve the underlying file-reader error when available.
   - Use event listeners rather than inline JavaScript handlers or JavaScript form actions.
   - Apply naming cleanup only in code already touched by this work; avoid repository-wide churn.

9. **Source architecture**
   - Keep the directly usable single HTML source.
   - Prefer narrow internal seams and one source of truth over a new assembly pipeline.
   - Sharing truly identical crypto-profile or download-lifecycle behavior is useful; forcing encrypt and decrypt behavior through a configurable abstraction is not required.

## Testing seam

Use the existing browser-page simulation and complete round trip as the primary testing seam:

1. Load the creator.
2. Encrypt representative input.
3. Capture the generated HTML artifact.
4. Load that artifact as its own page.
5. Decrypt and assert externally visible status, filename, and recovered bytes or text.

Test behavior through this seam rather than asserting the shape of internal helper functions. Extend the harness only enough to observe timers, object-URL revocation, temporary-anchor removal, visibility controls, accessible state, and status messages.

The spec should require coverage for:

- a 96-bit IV in newly generated artifacts;
- unchanged file, Unicode filename, empty-file, text-message, wrong-password, corrupted-payload, and legacy-artifact behavior;
- public-hint disclosure and safe plaintext rendering;
- neutral container filenames with restoration of the encrypted original filename;
- delayed URL revocation and anchor cleanup in both flows;
- progress and download-started status transitions;
- creator and decryptor password visibility;
- language declarations, visible labels, textual match/complexity state, reduced live-region noise, and compliant primary-button contrast;
- secure-context and unavailable-Web-Crypto failures.

Manual accessibility checks may supplement automated markup and contrast assertions, but routine tests must remain dependency-free.

## Explicitly out of scope

Keep these out of this hardening spec:

- generated passphrases;
- displaying decrypted messages in-page or copying them to the clipboard;
- drag-and-drop or paste support;
- payload/encrypted-envelope versioning;
- trusted import and decryption through the official creator page;
- multiple files, folders, archive generation, compression, or large-file streaming;
- cloud storage, sharing links, accounts, recovery, analytics, expiry, revocation, or self-destruction;
- rich-text rendering or automatic previews;
- public-key recipient management or user-selectable crypto parameters;
- a framework, third-party library, external font, CDN, service worker, PWA requirement, or source-assembly build pipeline;
- a light theme or broader visual redesign;
- automatic form reset after download initiation;
- a new filename-header format solely to handle slash characters;
- claims that CSP or an internal checksum can authenticate a wrapper that an attacker can replace wholesale.

These can be considered in separate future specs. The likely sequence after hardening is generated passphrases, in-page plaintext message reveal, a versioned encrypted envelope, and finally trusted artifact import.

## Notes for specification quality

- Frame the problem and solution from sender and recipient perspectives.
- Keep the spec cohesive: this release repairs and clarifies the existing core workflow; it does not broaden that workflow.
- Use exhaustive user stories for affected success, error, keyboard, assistive-technology, privacy, and compatibility cases.
- Record the decisions above rather than reopening them.
- Keep exact file paths and code snippets out of the resulting published spec.
