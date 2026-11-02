# Phishing Shield for Gmail

**Current version: 0.2.1 — an experimental Chrome extension for Gmail.**

Phishing Shield adds visible email-check statuses, local phishing heuristics,
link warnings, and an optional cleaner inbox layout. It runs in Gmail on the web
using Chrome Manifest V3. No server, API key, Google Cloud project, or build step
is required for the current version.

> This is a warning tool, not an email-authentication service. A green status
> does not prove an email is safe, and a flag does not prove it is phishing.
> Keep Gmail's own protections enabled. For sensitive actions, open the company's
> usual website or app directly rather than following an email link.

## Install in Chrome

### Download the extension

Choose either method:

- **Without Git:** open [this repository](https://github.com/Geltrax69/Fishing_dectection),
  choose **Code → Download ZIP**, then extract the ZIP to a permanent folder.
- **With Git:** run:

  ```bash
  git clone https://github.com/Geltrax69/Fishing_dectection.git
  cd Fishing_dectection
  ```

### Load the folder

1. Open `chrome://extensions` in Chrome's address bar.
2. Turn on **Developer mode** at the top right.
3. Click **Load unpacked**.
4. Select the extracted or cloned folder that directly contains `manifest.json`.
   Select the whole folder, not the ZIP, `manifest.json`, or `src` folder.
5. Confirm that **Phishing Shield for Gmail**, version **0.2.1**, appears and is enabled.
6. Open or refresh [Gmail](https://mail.google.com).
7. Open Chrome's Extensions menu (the puzzle-piece icon) and pin Phishing Shield
   if you want quick access to its popup.

You do **not** need `npm install` to use the extension. Dependencies are only
needed for browser testing. Keep the installed folder in place: Chrome loads
this unpacked extension from that location. There is no Chrome Web Store listing yet.

### Update an existing installation

1. Update the same folder: run `git pull --ff-only` from a clean clone, or replace
   its contents with the newly extracted download.
2. Open `chrome://extensions` and click **Reload** on Phishing Shield.
3. Refresh every Gmail tab where you want the updated scripts to run.

Updating files alone does not update an already-open Gmail tab. You do not need
to upload anything or reinstall the extension.

To uninstall, click **Remove** on its card in `chrome://extensions`.

## How to use it

Every supported inbox row receives a small status beside its subject:

| Status | Meaning | Suggested action |
| --- | --- | --- |
| Gray: **Not fully checked** | Only the available sender/subject/preview information was checked. | Open the message for body and link checks; the gray icon is not a threat verdict. |
| Green: **No obvious risks** | The opened-message heuristic score was below the warning threshold. | Continue using normal caution; sender identity and link reputation are not verified. |
| Amber: **Flagged** | Suspicious signals crossed the warning threshold, or the inbox pressure-language rule matched. | Read the reasons in the opened message and check the sender and destinations independently. |
| Red: **Do not open links** | Strong or combined heuristic signals produced a high score. | Avoid links, replies, and downloads until you verify the request through another channel. |

On narrow windows, row badges show just their icons. Hover over a badge for its
explanation. Opened suspicious messages show an amber or red banner with reasons.

The popup provides:

- **Protection:** turn scanning and warnings on or off.
- **Clean inbox:** on by default; hide snippet text and attachment chips so rows
  emphasize sender and subject. Gmail's dates, selection, stars, and actions remain.
  Attachment chips are hidden, not removed from the message.
- **Counters:** opened-message scans, flagged scans, and link warnings dismissed
  through “Go back” or the backdrop. Counts are not unique email counts, can grow
  after rescans, and are best-effort rather than an audit log.

For links identified as risky inside a flagged message, a normal click shows a
warning with the destination. **Go back** cancels that attempt; **Open anyway**
opens the URL. The extension does not prevent every way of opening a link and
does not inspect or block attachment downloads.

## How it works

1. Chrome injects `src/detector.js`, `src/content.js`, and `src/content.css` only on
   `https://mail.google.com/*`.
2. The content script observes Gmail's page for message bodies and inbox rows.
   Checks are scheduled after a short delay as Gmail changes its content.
3. Inbox checks use available sender details, subject, and snippet. An opened
   message supplies its sender, display name, conversation subject, body text,
   and visible link text/destinations to the detector.
4. The detector assigns points using local rules. The content script adds
   badges, warning banners, and link-click handlers based on the result.
5. Up to 500 opened-message results are kept in tab memory and reused for inbox
   rows with matching sender/subject. Refreshing the tab clears this cache.
   This is not a verified per-message history; matching sender/subject pairs can collide.

### Current checks and their coverage

| Signal | Current behavior |
| --- | --- |
| Brand impersonation | Compare recognized brand words in the sender's display name against a small domain list. Unknown brands receive no brand-specific check. |
| Lookalike domains | Use string similarity and simple domain rules; also flag punycode URLs. These rules can misclassify legitimate international domains. |
| Deceptive link text | Compare a domain shown in link text with the destination hostname. |
| Shorteners and IP URLs | Add risk points for recognized shortening services and raw IPv4 destinations. |
| Urgency and credentials | Match English pressure-language and password/OTP-request patterns. |
| Free-mail support name | Add points when a free mailbox uses a support/security-style display name. |
| Plain-HTTP login URL | Add points for login-like destinations served over HTTP. |
| Reply-To mismatch | Supported by the detector when supplied as input; the Gmail content script currently does **not** extract Reply-To. |
| Risky attachment extensions | Supported by the detector when filenames are supplied; the Gmail content script currently does **not** extract attachment filenames or scan files. |

The internal levels are **SAFE < 30**, **SUSPICIOUS 30–59**, and **HIGH ≥ 60**,
with scores capped at 100. “SAFE” is an internal label for a low score, not a
safety guarantee. **40/100 is not a 40% probability of phishing.** The weights
have not been calibrated against a representative real-world email dataset.

### AWS false-positive fix in 0.2.1

The earlier domain list recognized Amazon but omitted `aws.com`. It therefore
incorrectly flagged an AWS invoice solely because it came from that domain.
Version 0.2.1 adds `aws.com` for Amazon, recognizes the AWS abbreviation, and makes
unknown-domain explanations acknowledge that the list may be incomplete.
[AWS documents `invoicing@aws.com` as a billing sender](https://docs.aws.amazon.com/notifications/latest/userguide/managed-notifications-bcm.html).

This fixes the missing-domain rule; it does not authenticate any particular
invoice. Known brand domains still undergo message-text and deceptive-link checks.

## What is missing / current limitations

- **No sender authentication:** the extension does not read or verify SPF, DKIM,
  DMARC, or Gmail authentication results. A displayed From address can be spoofed.
- **Incomplete brand coverage:** subsidiaries, regional domains, legitimate
  marketing providers, and new brands may be missing. A famous name is not proof of identity.
- **No live link reputation:** there is no Safe Browsing, Web Risk, or other
  threat-intelligence lookup. Redirect chains and shortened destinations are not resolved.
- **Simplistic scoring:** one weak signal can cause a warning; repeated or related
  links can inflate scores. Legitimate newsletters and security notices can be flagged.
- **Incomplete message coverage:** previews are not full scans. Images, QR codes,
  attachments, hidden content, and most non-English phishing are not analyzed.
- **DOM dependence:** Gmail class names and rendering can change. The script can
  miss content or stop displaying statuses without an obvious error. A missing badge
  is not evidence that an email was checked.
- **Limited click interception:** warnings cover handled ordinary link clicks in
  flagged bodies, not every browser navigation, context-menu action, or download.
- **No measured real-world accuracy:** passing tests establish expected behavior
  for the included examples, not a detection rate across real inboxes.
- **No complete live-Gmail validation:** user screenshots confirmed installation,
  visible statuses, and the AWS false positive. The corrected AWS case passes
  synthetic tests; a full signed-in Gmail validation remains outstanding.

## Planned improvements — not implemented yet

These are proposals, not features in version 0.2.1:

| Priority | Improvement | What it needs |
| --- | --- | --- |
| 1 | Calibrate scoring: separate weak clues from strong evidence, avoid counting the same evidence repeatedly, and show findings by category. | A labeled evaluation set and regression tests. |
| 1 | Add a representative evaluation set and report false positives, missed phishing, precision, and recall. Keep tuning and evaluation data separate. | Legitimate and phishing samples with suitable usage rights, reliable labels, and personal information removed. |
| 2 | Maintain a sourced, versioned brand-domain registry covering aliases, subsidiaries, and regions; improve domain parsing with a public suffix list. | Official sources, review dates, and tests for lookalikes and legitimate variants. |
| 2 | Add optional sender-authentication checks based on Gmail's trusted results, including domain alignment. | A Google Cloud project, Gmail API configuration, an extension OAuth client, user authorization, and correct message/account mapping. |
| 3 | Add optional malicious-URL reputation checks while preserving local-only defaults. | A provider and API configuration, clear privacy disclosure, explicit opt-in, error handling, and suitable licensing. |
| 3 | Extract Reply-To and attachment filenames reliably, improve international text handling, and detect more navigation paths. | Gmail integration work and browser regressions. Filenames alone cannot establish file safety. |
| 3 | Add scan-health reporting and broader real-Gmail compatibility tests. | Multiple inbox layouts, account types, themes, and controlled manual validation. |

Sender-authentication passes must not bypass deceptive-link or content checks.
Google notes that authentication alone does not establish that a message is safe:
[Gmail authentication guidance](https://support.google.com/mail/answer/180707).
The [Gmail message API](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get)
can retrieve message metadata with authorization.

For optional URL reputation, [Google Safe Browsing](https://developers.google.com/safe-browsing)
is intended for non-commercial use; Google directs commercial use to Web Risk.
The [Safe Browsing Lookup API](https://developers.google.com/safe-browsing/v4/lookup-api)
sends URLs to Google's servers, so an integration must explain that URLs may
contain private identifiers or tokens. No such integration is enabled or present
in this release. Do not commit API keys or OAuth tokens to this repository.

## Privacy and permissions

All current checks run **locally in your browser**. This extension sends no email
body, sender, subject, or URL to a server. There is no analytics or remote model.

- `chrome.storage.local` holds the protection/clean-inbox preferences and counters.
- Opened-message results remain in the current tab's memory, not persistent storage.
- The manifest requests `storage` and access to Gmail pages. There is no Gmail API
  access, OAuth connection, reputation-service key, or cloud account requirement.

## Testing and development

Node.js 18 or newer is required for the test commands.

### Unit and packaging checks

```bash
npm test
```

These need no installed dependencies. **25 tests passed on November 2, 2026.**
They cover the included detector fixtures, AWS false-positive regressions,
lookalike AWS senders, deceptive links from known domains, brand-word boundaries,
uncertainty in explanations, and extension packaging.

### Browser integration checks

```bash
npm ci
npx playwright install chromium
npm run test:browser
```

The browser suite loads the actual unpacked extension in an isolated Chromium
profile against **synthetic Gmail markup**, not a signed-in account. It checks
statuses, banners, link warnings, counters, both toggles, recycled rows, and the
AWS invoice regression. These checks passed on November 2, 2026.

Screenshots are generated in `test-results/`, which is ignored by Git. They are
local test artifacts, not screenshots of a real Gmail account.

### Manual Gmail check after loading or updating

1. Refresh Gmail and confirm each supported row has a status.
2. Open an ordinary message: expect a compact status and no alarm banner if
   its contents do not trigger the rules.
3. Check a controlled phishing-style sample with a mismatched link: expect a
   warning and verify that **Go back** prevents navigation. Do not use live malicious links.
4. Toggle **Clean inbox** and **Protection** and confirm Gmail updates.
5. For an invoice, verify it independently through the provider's normal console.
   Report false positives with the displayed reasons; redact personal information.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| “Manifest file is missing” | Extract the ZIP and select the folder directly containing `manifest.json`. |
| No icons after installation | Enable the extension and protection, then refresh Gmail. Confirm you are using `mail.google.com`. |
| Old interface after an update | Reload the extension in `chrome://extensions`, then refresh Gmail. |
| A legitimate email is flagged | Read the exact reasons. Check sender authentication and the request independently; report the false positive instead of trusting all mail with that brand name. |
| Counters stay at zero in the inbox | The scan counter tracks opened-message checks, not all inbox preview checks. |
| Previews or attachment chips disappeared | Turn off **Clean inbox** in the popup. |
| An extension error appears | Open its **Errors** panel on `chrome://extensions` and share the error text with private details removed. |

## Project layout

```text
manifest.json             MV3 configuration, Gmail access, popup and assets
src/detector.js           Pure JavaScript heuristic engine
src/content.js            Gmail extraction, statuses, banners and link guard
src/content.css           Injected styles and clean-inbox rules
popup/                    Protection, clean-inbox control and counters
icons/                    Extension icons
scripts/generate-icons.py Icon generation helper
tests/detector.test.js     Detector regressions
tests/fixtures.json        Synthetic detector examples
tests/manifest.test.js     Manifest and packaging checks
tests/browser.cjs          Chromium extension integration checks
```

## License

MIT — see [LICENSE](LICENSE).
