// Detector tests — run with: npm test
// Covers the fixtures in tests/fixtures.json plus direct link checks.
// No network, no Chrome APIs: the detector is pure JS.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { analyzeEmail, analyzeLink } = require('../src/detector.js');
const fixtures = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures.json'), 'utf8'));

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
  const r = analyzeLink({ text: 'Click', href: 'https://xn--paypl-7va.example/login' });
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
