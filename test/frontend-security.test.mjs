import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const appSource = fs.readFileSync(path.join(root, 'public', 'app.js'), 'utf8');
const htmlSource = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');

test('frontend keeps untrusted data out of executable DOM sinks and browser storage', () => {
  assert.doesNotMatch(appSource, /\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln)\b/);
  assert.doesNotMatch(appSource, /\b(?:eval|Function)\s*\(/);
  assert.doesNotMatch(appSource, /\b(?:localStorage|sessionStorage)\b/);
  assert.doesNotMatch(appSource, /initDataUnsafe/);
  assert.match(appSource, /textContent/);
  assert.match(appSource, /createElement/);
  assert.match(htmlSource, /telegram\.org\/js\/telegram-web-app\.js/);
});
