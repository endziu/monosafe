# Password accessibility spot check

Run this manual keyboard and screen-reader check in addition to `make test`.
The page simulation cannot establish actual focus behavior or screen-reader
announcements.

Record the browser, screen reader, versions, date, and results in the PR or
issue when performing this check.

1. Open `monosafe.html` locally with a screen reader running. Using only the
   keyboard, choose **Text message** and enter a short test message. Tab through
   both password fields, their visibility buttons, the optional hint, and
   **Encrypt**. Verify logical focus order, visible focus, and persistent
   **Password** / **Repeat password** labels.
2. Enter `short`, then `MapleRiver7`, then `cedar orbit velvet harbor`. Verify
   visible and spoken strength feedback changes to low, medium, and high.
   Enter a different repeated password, then a matching one. Verify both
   mismatch and match are expressed as text and announced. Clear both fields
   and check the empty-state feedback.
3. Activate each visibility button with Space and Enter. Verify it changes
   only its associated field, preserves its value, and does not submit the
   form. The accessible name stays **Show password** or **Show repeated
   password**; the pressed state changes with visibility. Verify focus stays
   on the button.
4. Submit with mismatched passwords. Verify the error is announced. Submit
   again without changing either password and verify the same error is
   announced again. Correct the passwords, add a nonsecret test hint, and
   submit again. Verify **Encrypting…**
   and **Download started: …** are announced, and **Encrypt** keeps its name.
5. Open the downloaded HTML locally. Verify the **Password** label, hint,
   trust notice, and visibility toggle are accessible by keyboard and screen
   reader. Repeat the Space/Enter visibility check. Enter a wrong password
   and submit twice without changing it, then retry with the correct one.
   Verify the error is announced on both failed attempts. Verify progress
   and download-start messages are announced and the decrypted message is
   recovered.
6. At a narrow viewport and 200% zoom, verify labels, textual feedback, and
   focus indicators remain readable without overlap or clipping on both pages.

Password complexity feedback remains in the creator, where the password is
chosen. If per-keystroke announcements are disruptive, record the behavior
in the PR or issue before changing announcement timing.
