# Phishing Shield for Gmail

A Chrome extension (Manifest V3) that detects phishing emails in Gmail,
flags them in the inbox and in the opened message, and tells you **not to
open risky links** — with a warning first if you try.

> Heuristic protection, not a guarantee. A green result is not proof an
> email is safe, and a flag is not proof it is phishing. If in doubt, go
> to the official site or app directly — never via a link in a
> suspicious email.

## What it does

- **Opened email — do-not-open banner.** A HIGH-scoring message gets a
  red banner above the body: “⛔ DO NOT OPEN LINKS, REPLY, OR DOWNLOAD
  ATTACHMENTS”, with its score (0–100) and the exact reasons. A
  SUSPICIOUS message gets an amber caution banner. SAFE messages get
  no banner.
- **Inbox list — flags.** Rows with strong pressure language from a
  support-like sender get a 🚩 flag. List view has no sender domain or
  links, so this is deliberately conservative — the full check runs
  when you open the message.
- **Link guard.** Clicking a risky link inside a flagged message opens
  a warning modal showing the real destination first. “Go back (safe)”
  is the default; “Open anyway” is explicitly not recommended.
- **Popup.** Click the extension icon to turn protection on/off and
  see scanned / flagged / risky-clicks-turned-back counts.

## What it checks

| Signal | Example |
| --- | --- |
| Sender impersonation | Display name “PayPal Support”, sent from `paypa1-support.net` |
| Lookalike domains | `paypa1.com`, `paypal-secure.com`, punycode (`xn--`) domains |
| Link text vs. destination | Text says `paypal.com`, link goes to `evil.example` |
| URL shorteners, raw IP links | `bit.ly/…`, `http://192.168.0.5/login` |
| Reply-To mismatch | Sender domain ≠ Reply-To domain |
| Urgency / threats | “URGENT: account will be suspended within 24 hours” |
| Credential requests | “Enter your password / share your OTP” |
| Risky attachments | `.exe`, `.html`, `.zip`, `.iso`, and friends |
| Free-mail support pose | A “support/security team” writing from `gmail.com` |

Scoring: **SAFE < 30, SUSPICIOUS 30–59, HIGH ≥ 60** (HIGH = do not open).

## Install (load unpacked)

1. Open Chrome → `chrome://extensions` → turn on **Developer mode**.
2. Click **Load unpacked** and select this folder.
3. Open Gmail (`https://mail.google.com`). Open a suspicious-looking
   email — the banner appears above its body if it scores SUSPICIOUS
   or HIGH. Click the extension icon for the on/off toggle and stats.
4. To remove it: `chrome://extensions` → Remove.

No build step, no Chrome Web Store listing yet — this is a local,
unpacked install.

## Privacy

All checks run **locally in your browser**. No email content, sender,
link, or subject is sent to any server, by this extension or by the
detector. The only data stored is in `chrome.storage.local` on your
machine: the on/off toggle and the three counters shown in the popup.

## Testing

```bash
npm test
```

17 tests, 0 failures (Node ≥ 18, no dependencies):

- `tests/detector.test.js` — 10 fixtures in `tests/fixtures.json`
  (legit PayPal/newsletter SAFE; spoof PayPal HIGH; link mismatch
  HIGH; shortener, lookalike, Reply-To + urgency, urgency +
  credential request, risky attachment, IP login link SUSPICIOUS),
  plus direct link checks (mismatch, punycode, matching official link)
  and the free-mail support-pose check.
- `tests/manifest.test.js` — manifest is MV3 and targets Gmail, and
  every file it references actually exists (the classic “load unpacked
  fails” catch).

### Not yet verified in a live Gmail session

Unit and packaging tests are green, but a live Gmail check needs a
real Chrome profile signed into Gmail, which this sandbox cannot do.
Before relying on it, please do this one manual pass after loading
unpacked:

1. Open a known-legit email (e.g. a real PayPal receipt) — expect no
   banner.
2. Open or forward yourself a test phishing-style email (spoofed
   brand sender + mismatched link + urgent wording) — expect the red
   banner and the link-warning modal on click.
3. Check the inbox list — expect 🚩 only on strong pressure-language
   rows, not on ordinary mail.

If Gmail changes its page structure, the content script fails silently
by design (it never breaks Gmail) — a missing banner after a Gmail
redesign means the selectors in `src/content.js` need updating, not
that the detector broke.

## Project layout

```
manifest.json          MV3 manifest (Gmail host, storage permission)
popup/                 Extension popup (toggle + stats)
src/detector.js        Pure-JS phishing engine (also used by tests)
src/content.js         Gmail scanning, banners, flags, link guard
src/content.css        Banner / flag / modal styles
icons/                 Shield icons (regenerate: python3 scripts/generate-icons.py)
tests/                 Node tests + fixtures
```

## Limitations

- Heuristic only: clever new phishing that avoids every signal above
  will score low. Gmail's own spam/phishing filters are still your
  first line of defence.
- List-view flags are conservative by design (no sender domain or
  links are visible there).
- Brand list covers common impersonation targets (PayPal, Google,
  Microsoft, Apple, Amazon, Netflix, banks, …). A brand not in
  `src/detector.js` `BRANDS` won't get impersonation checks.

## License

MIT — see `LICENSE`.
