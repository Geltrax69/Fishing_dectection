// Extension packaging smoke tests: manifest parses, and every file it
// references actually exists. This catches the classic "load unpacked
// fails because a file is missing" error before it reaches Chrome.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));

test('manifest is MV3 and targets Gmail', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.ok(manifest.content_scripts[0].matches.includes('https://mail.google.com/*'));
});

test('every file referenced by the manifest exists', () => {
  const files = new Set();
  const cs = manifest.content_scripts[0];
  cs.js.forEach((f) => files.add(f));
  cs.css.forEach((f) => files.add(f));
  files.add(manifest.action.default_popup);
  Object.values(manifest.icons).forEach((f) => files.add(f));
  Object.values(manifest.action.default_icon).forEach((f) => files.add(f));
  for (const f of files) {
    assert.ok(fs.existsSync(path.join(root, f)), `missing file referenced by manifest: ${f}`);
  }
});

test('popup.html references files that exist', () => {
  const html = fs.readFileSync(path.join(root, 'popup/popup.html'), 'utf8');
  assert.ok(html.includes('popup.css'));
  assert.ok(html.includes('popup.js'));
  assert.ok(fs.existsSync(path.join(root, 'popup/popup.css')));
  assert.ok(fs.existsSync(path.join(root, 'popup/popup.js')));
});
