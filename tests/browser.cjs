// Real Chromium extension test against synthetic Gmail markup; no account required.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const { mkdtemp, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

(async () => {
  const root = path.resolve(__dirname, '..');
  const profile = await mkdtemp(path.join(tmpdir(), 'phishing-shield-'));
  const context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${root}`, `--load-extension=${root}`],
  });
  context.setDefaultTimeout(5000);
  try {
    // Unpacked extension IDs are derived from their absolute path.
    const id = [...crypto.createHash('sha256').update(root).digest('hex').slice(0, 32)]
      .map(c => String.fromCharCode(97 + parseInt(c, 16))).join('');
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${id}/popup/popup.html`);
    await popup.locator('#status.on').waitFor();
    console.log('PASS: extension loads and popup defaults to ON');

    const page = await context.newPage();
    await page.route('**/*', route => route.fulfill({ contentType: 'text/html', body: '<html><body><main id="fixture"></main></body></html>' }));
    await page.goto('https://mail.google.com/mail/u/0/#inbox');
    async function fixture(html) {
      await page.locator('#fixture').evaluate((el, html) => { el.innerHTML = html; }, html);
    }
    const message = (sender, name, body) => `<h2 class="hP">Message</h2><div class="adn"><span class="gD" email="${sender}">${name}</span><div><div class="a3s">${body}</div></div></div>`;
    await fixture(message('receipt@paypal.com', 'PayPal', 'Your receipt. <a href="https://paypal.com/home">paypal.com</a>'));
    await page.locator('[data-phishing-shield-done]').waitFor();
    assert.equal(await page.locator('.phishing-shield-banner').count(), 0);
    await page.locator('.phishing-shield-message-status.phishing-shield-safe').waitFor();
    console.log('PASS: legitimate message gets a green status without an alarm banner');

    await fixture(message('fraud@paypa1-support.net', 'PayPal Support', 'URGENT: verify your account immediately. Enter your password. <a href="https://evil.example/login">paypal.com</a>'));
    await page.locator('.phishing-shield-banner').waitFor();
    assert.match(await page.locator('.phishing-shield-banner').innerText(), /100\/100 \(HIGH\)/);
    await page.screenshot({ path: path.join(root, 'test-results/high-risk.png') });
    await page.locator('.a3s a').click();
    await page.locator('[role="dialog"]').waitFor();
    assert.match(await page.locator('.phishing-shield-url').innerText(), /evil\.example/);
    await page.screenshot({ path: path.join(root, 'test-results/link-warning.png') });
    await page.locator('.phishing-shield-safe').click();
    assert.equal(await page.locator('[role="dialog"]').count(), 0);
    assert.equal(page.url(), 'https://mail.google.com/mail/u/0/#inbox');
    console.log('PASS: HIGH banner, real-destination warning, safe dismissal without navigation');

    await fixture(message('news@example.com', 'Newsletter', '<a href="https://bit.ly/example">Read more</a>'));
    await page.locator('.phishing-shield-banner.phishing-shield-suspicious').waitFor();
    console.log('PASS: suspicious message gets amber banner');

    await fixture(`<style>
      body { font: 14px Arial, sans-serif; margin: 32px; color: #202124; background: #f6f8fc; }
      table { border-collapse: collapse; width: 100%; background: white; table-layout: fixed; }
      td { border-bottom: 1px solid #e8eaed; padding: 18px 14px; }
      td:first-child { width: 180px; } td:last-child { width: 70px; color: #5f6368; text-align: right; }
      .y2 { color: #5f6368; } h1 { font-size: 22px; margin: 0 0 24px; }
    </style><h1>Inbox</h1><table>
      <tr class="zA"><td class="yW"><span class="zF" email="security@example.com">Security Support</span></td><td><div class="y6"><span class="bog">URGENT: account suspended, verify your account immediately</span><span class="y2"> — Enter your password</span></div></td><td>4:23 PM</td></tr>
      <tr class="zA"><td class="yW"><span class="zF" email="friend@example.com">Friend</span></td><td><div class="y6"><span class="bog">Lunch tomorrow?</span><span class="y2"> — How about the usual place?</span></div><div class="brd">menu.pdf</div></td><td>2:45 PM</td></tr>
      <tr class="zA"><td class="yW"><span class="zF" email="receipt@paypal.com">PayPal</span></td><td><div class="y6"><span class="bog">Message</span><span class="y2"> — Your receipt.</span></div></td><td>1:05 PM</td></tr>
      <tr class="zA"><td class="yW"><span class="zF" email="fraud@paypa1-support.net">PayPal Support</span></td><td><div class="y6"><span class="bog">Message</span><span class="y2"> — Verify now.</span></div></td><td>12:30 PM</td></tr>
    </table>`);
    await page.locator('.phishing-shield-list-flag').first().waitFor();
    assert.equal(await page.locator('.phishing-shield-row-status').count(), 4);
    assert.equal(await page.locator('.phishing-shield-row-status.phishing-shield-unchecked').count(), 1);
    assert.equal(await page.locator('.phishing-shield-row-status.phishing-shield-safe').count(), 1);
    assert.equal(await page.locator('.phishing-shield-row-status.phishing-shield-high').count(), 1);
    assert.equal(await page.locator('.y2').first().isVisible(), false);
    assert.equal(await page.locator('.brd').isVisible(), false);
    await page.screenshot({ path: path.join(root, 'test-results/clean-inbox.png') });
    await page.setViewportSize({ width: 600, height: 700 });
    await page.screenshot({ path: path.join(root, 'test-results/clean-inbox-narrow.png') });
    await page.setViewportSize({ width: 1280, height: 720 });
    console.log('PASS: every row has a status, full checks persist in this tab, previews and attachment chips hidden');

    await popup.reload();
    console.log('Popup counters:', await popup.locator('.stats').innerText());
    await popup.locator('#scanned').filter({ hasText: '3' }).waitFor();
    assert.equal(await popup.locator('#flagged').innerText(), '2');
    assert.equal(await popup.locator('#blocked').innerText(), '1');
    await popup.locator('#cleanInbox').uncheck();
    await page.waitForFunction(() => !document.documentElement.classList.contains('phishing-shield-clean'));
    assert.equal(await page.locator('.y2').first().isVisible(), true);
    await popup.locator('#cleanInbox').check();
    await page.waitForFunction(() => document.documentElement.classList.contains('phishing-shield-clean'));
    await popup.screenshot({ path: path.join(root, 'test-results/popup.png') });
    console.log('PASS: clean inbox toggle applies live in Gmail');

    // Gmail can recycle existing rows; a changed subject must update its status.
    await page.locator('tr.zA').nth(1).locator('.bog').evaluate(el => { el.textContent = 'URGENT: enter your password immediately'; });
    await page.locator('tr.zA').nth(1).locator('.phishing-shield-suspicious').waitFor();
    assert.equal(await page.locator('.phishing-shield-row-status').count(), 4);
    await popup.locator('label.toggle').click();
    await popup.locator('#status.off').waitFor();
    await page.waitForFunction(() => document.querySelectorAll('.phishing-shield-status').length === 0);
    await fixture(message('fraud@paypa1-support.net', 'PayPal Support', 'URGENT: enter your password immediately.'));
    await page.waitForTimeout(900);
    assert.equal(await page.locator('.phishing-shield-banner').count(), 0);
    await popup.locator('label.toggle').click();
    await page.locator('.phishing-shield-banner').waitFor();
    console.log('PASS: recycled row updates, no duplicate badges, OFF removes statuses, ON rescans existing messages');

    await fixture(message('invoicing@aws.com', 'Amazon Web Services', 'Your GST invoice is available in the Bills section. <a href="https://console.aws.amazon.com/billing/home#/bills">https://console.aws.amazon.com/billing/home#/bills</a>'));
    await page.locator('.phishing-shield-message-status.phishing-shield-safe').waitFor();
    assert.equal(await page.locator('.phishing-shield-banner').count(), 0);
    await page.screenshot({ path: path.join(root, 'test-results/aws-invoice.png') });
    await fixture('<table><tr class="zA"><td class="yW"><span email="invoicing@aws.com">Amazon Web Services</span></td><td><div class="y6"><span class="bog">Message</span></div></td></tr></table>');
    await page.locator('.phishing-shield-row-status.phishing-shield-safe').waitFor();
    console.log('PASS: documented AWS sender has no false alarm in opened message or inbox');
  } finally {
    await context.close();
    await rm(profile, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
