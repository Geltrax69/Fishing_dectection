// Detector tests — run with: npm test
// Covers the fixtures in tests/fixtures.json plus direct link checks.
// No network, no Chrome APIs: the detector is pure JS.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { analyzeEmail, analyzeLink } = require('../src/detector.js');
const fixtures = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures.json'), 'utf8'));

const awsInvoice = {
  from: 'invoicing@aws.com',
  displayName: 'Amazon Web Services',
  subject: 'Amazon Web Services GST Invoice Available',
  bodyText: 'Greetings from Amazon Web Services. Your GST invoices can be downloaded from the Bills section of the Billing & Cost Management console.',
  links: [{ text: 'https://console.aws.amazon.com/billing/home#/bills', href: 'https://console.aws.amazon.com/billing/home#/bills' }],
};

test('AWS invoice from documented aws.com sender does not get an impersonation warning', () => {
  const result = analyzeEmail(awsInvoice);
  assert.equal(result.score, 0);
  assert.equal(result.level, 'SAFE');
  assert.deepEqual(result.reasons, []);
});

test('AWS abbreviation is recognized for both known and unknown sender domains', () => {
  assert.equal(analyzeEmail({ ...awsInvoice, displayName: 'AWS Billing' }).score, 0);
  assert.equal(analyzeEmail({ ...awsInvoice, displayName: 'AWS Billing', from: 'invoicing@unknown.example' }).level, 'SUSPICIOUS');
});

for (const domain of ['aws.com.evil.example', 'fakeaws.com', 'aws-billing.example']) {
  test(`AWS lookalike ${domain} is not accepted as a known brand domain`, () => {
    const result = analyzeEmail({ ...awsInvoice, from: `invoicing@${domain}` });
    assert.equal(result.level, 'SUSPICIOUS');
    assert.ok(result.reasons.length);
  });
}

test('known AWS sender does not bypass deceptive-link or credential checks', () => {
  const result = analyzeEmail({ ...awsInvoice,
    bodyText: 'Enter your password immediately.',
    links: [{ text: 'console.aws.amazon.com', href: 'https://evil.example/login' }],
  });
  assert.equal(result.level, 'HIGH');
  assert.equal(result.riskyLinks.length, 1);
});

test('brand words do not match unrelated names such as Pineapple or Drawstring', () => {
  for (const displayName of ['Pineapple Newsletter', 'Drawstring Store']) {
    assert.equal(analyzeEmail({ from: 'news@example.com', displayName }).score, 0);
  }
});

test('unknown domain warning admits the brand list may be incomplete', () => {
  const result = analyzeEmail({ ...awsInvoice, from: 'invoicing@unlisted.example' });
  assert.ok(result.reasons.some(reason => reason.includes('list may be incomplete')));
  assert.ok(result.reasons.every(reason => !reason.includes('not an official')));
});

for (const fixture of fixtures) {
  test(`fixture: ${fixture.name} -> ${fixture.expectedLevel}`, () => {
    const result = analyzeEmail(fixture.email);
    assert.equal(result.level, fixture.expectedLevel);
    assert.ok(result.score >= 0 && result.score <= 100, 'score must be 0-100');
    if (fixture.expectedDoNotOpen) assert.equal(result.doNotOpen, true);
    if (fixture.expectedReasonContains) {
      assert.ok(
        result.reasons.some((r) => r.toLowerCase().includes(fixture.expectedReasonContains)),
        `expected a reason containing "${fixture.expectedReasonContains}", got: ${result.reasons.join(' | ')}`
      );
    }
    if (fixture.expectedLevel === 'SAFE') assert.equal(result.reasons.length, 0);
  });
}

test('analyzeLink: text-vs-destination mismatch is risky', () => {
  const r = analyzeLink({ text: 'paypal.com', href: 'https://evil.example/login' });
  assert.ok(r.isRisky);
  assert.ok(r.reasons.some((x) => x.includes('actually goes to')));
});

test('analyzeLink: punycode domain is risky', () => {
  const href = 'https://xn--bcher-kva.example/login';
  assert.equal(new URL(href).hostname, 'xn--bcher-kva.example');
  const r = analyzeLink({ text: 'Click', href });
  assert.ok(r.isRisky);
});

test('analyzeLink: matching official link is not risky', () => {
  const r = analyzeLink({ text: 'paypal.com', href: 'https://www.paypal.com/home' });
  assert.equal(r.isRisky, false);
  assert.equal(r.score, 0);
});

test('analyzeEmail: free-mail sender posing as support is flagged', () => {
  const r = analyzeEmail({
    from: 'Security Team <someone@gmail.com>',
    subject: 'Account security',
    bodyText: 'Hello.',
    links: [],
  });
  assert.ok(r.score >= 20);
  assert.ok(r.reasons.some((x) => x.includes('free mailbox')));
});
