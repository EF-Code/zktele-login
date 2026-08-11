import test from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const artifactDir = path.join(root, 'node_modules', 'zk-tele-auth', 'artifacts', 'telegram_auth');
const expected = {
  'telegram_auth.json': 'e3ad952dbb4d9bcaa3437388b6d2fa3f9282528f63603ae003170b58462ccb98',
  'telegram_auth.r1cs': '3b6c81c767792c45f310a8290b237c9287db325142181cecd58bcdffb00d29da',
  'telegram_auth.wasm': '3f2fae4712f02ffcf26f78a3cb193f915f28d43baa47de171c32055e5681a2bd',
  'telegram_auth_final.zkey': '851a997955f29931242c507156b46956747dca399ff4d0d50ccd9d008693ed9d',
  'telegram_auth_vkey.json': 'cc1e1084f9d7fa39ed722c0a51e17b0c32c6e91bf37bfba8850c7f21c4637d9d',
};

test('pinned issuer-bound artifact set has reviewed hashes and seven signals', () => {
  for (const [name, digest] of Object.entries(expected)) {
    const file = path.join(artifactDir, name);
    assert.equal(fs.existsSync(file), true, `missing ${name}`);
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'), digest, name);
  }
  const circuit = JSON.parse(fs.readFileSync(path.join(artifactDir, 'telegram_auth.json'), 'utf8'));
  assert.equal(circuit.publicInputs, 7);
  assert.match(circuit.vkeySha256, /^[0-9a-f]{64}$/);
});
