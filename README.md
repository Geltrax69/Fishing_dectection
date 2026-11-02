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
  SUSPICIOUS message gets an amber caution banner. Low-scoring messages
  get a compact green “No obvious risks” status instead of an alarm banner.
- **Inbox list — status on every row.** Gray “Not fully checked” means
  only the preview has been checked. Amber “Flagged” indicates suspicious
  preview signals; red “Do not open links” indicates high risk. When a
  message has been opened, its result is reused for matching sender/subject
  rows in the same tab. A green check never verifies identity or guarantees
  safety. Preview checks use the sender address when Gmail exposes it;
  message bodies and link destinations need the opened-message check.
- **Clean inbox.** On by default: hide snippet text and attachment chips
  so rows emphasize sender and subject. Dates, selection, stars and Gmail
  actions remain available. Turn it off in the popup to restore previews.
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

After updating this folder, click the extension's **Reload** button on
`chrome://extensions`, then refresh Gmail. Version 0.2.0 adds the visible
email statuses and Clean inbox option. No upload or reinstall is needed.

Version 0.2.1 fixes an AWS invoice false positive: `aws.com` is included
in the Amazon domain list, and the AWS abbreviation is recognized.
Source: [AWS Billing notification sender documentation](https://docs.aws.amazon.com/notifications/latest/userguide/managed-notifications-bcm.html).
Unknown-domain warnings now explicitly acknowledge that our domain list
may be incomplete. Brand names match words rather than unrelated substrings.
Known domains still undergo message-text and deceptive-link checks; the
extension does not authenticate sender addresses or read SPF/DKIM/DMARC results.

No build step, no Chrome Web Store listing yet — this is a local,
unpacked install.

## Privacy

All checks run **locally in your browser**. No email content, sender,
link, or subject is sent to any server, by this extension or by the
detector. The only data stored is in `chrome.storage.local` on your
machine: the protection and clean-inbox preferences and the three counters
shown in the popup. Opened-message results are held only in the current
tab's memory (up to 500 sender/subject matches) and clear on refresh.

## Testing

```bash
npm test
```

25 tests, 0 failures (Node ≥ 18; unit tests need no installed dependencies):

- `tests/detector.test.js` — 10 fixtures in `tests/fixtures.json`
  (legit PayPal/newsletter SAFE; spoof PayPal HIGH; link mismatch
  HIGH; shortener, lookalike, Reply-To + urgency, urgency +
  credential request, risky attachment, IP login link SUSPICIOUS),
  plus direct link checks (mismatch, punycode, matching official link)
  and the free-mail support-pose check. Eight additional regressions cover
  the documented AWS invoice sender, the AWS abbreviation, three fake AWS
  domains, deceptive links from a known sender, unrelated brand substrings,
  and uncertainty in unknown-domain explanations.
- `tests/manifest.test.js` — manifest is MV3 and targets Gmail, and
  every file it references actually exists (the classic “load unpacked
  fails” catch).

### Browser integration tests

```bash
npm install
npx playwright install chromium
npm run test:browser
```

Verified on November 2, 2026 using the unpacked extension in Chromium
with synthetic Gmail markup: popup loading, no banner on legitimate mail,
HIGH and SUSPICIOUS banners, link interception and safe dismissal,
statuses on every row, checked-result reuse, popup counters, live clean-view
switching, recycled Gmail row updates, and protection toggling without reload.
Screenshots are saved to `test-results/high-risk.png` and
`test-results/link-warning.png`. Clean-view previews are in
`test-results/clean-inbox.png` and `test-results/clean-inbox-narrow.png`.
No real account or outgoing email is used.

The punycode unit-test fixture was corrected to use a valid IDN URL;
all 25 unit/packaging tests pass. The browser suite also checks that an AWS
invoice gets no false impersonation banner in the opened message or inbox.

### Not yet verified in a live Gmail session

Unit, packaging and synthetic browser tests are green. A live Gmail
check still requires manually loading the extension in your signed-in
Chrome profile and refreshing Gmail.
Before relying on it, please do this one manual pass after loading
unpacked:

1. Open a known-legit email (e.g. a real PayPal receipt) — expect no
   banner.
2. Open or forward yourself a test phishing-style email (spoofed
   brand sender + mismatched link + urgent wording) — expect the red
   banner and the link-warning modal on click.
3. Check the inbox list — expect a small status on every row. Unopened
   ordinary mail should show “Not fully checked”, not a verified-safe claim.

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
