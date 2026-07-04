// Byte-compat + round-trip tests for the age mlkem768x25519 container.
// KATs are frozen from python-onlykey#90 (verified byte-identical), so this runs
// standalone with `node --test test/age-format.test.mjs`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'module';
import { createHash } from 'crypto';
const require = createRequire(import.meta.url);
const A = require('../src/plugins/age/age-format.js');

const pat = (n, f) => Uint8Array.from({ length: n }, (_, i) => f(i));
const hex = (u) => Buffer.from(u).toString('hex');

test('HPKE seal byte-identical to python-onlykey#90 (KAT)', () => {
  const ss = pat(32, i => i), enc = pat(1120, i => i % 251), fk = pat(16, i => 0xa0 + i);
  assert.equal(hex(A.sealFileKey(ss, enc, fk)),
    '70ffb256bc81bb83124ce0de89455ee90722f35fb9cd0d67e2d6bf55c49b5a5b');
});
test('bech32 recipient byte-identical to #90 (KAT) + round-trip', () => {
  const pk = pat(1216, i => (i * 7 + 3) % 256);
  const r = A.encodeRecipient(pk);
  assert.ok(r.startsWith('age1onlykey1'));
  assert.equal(createHash('sha256').update(r).digest('hex'),
    '447d855ca1e3a7d041ae8fcda05003a12908d142d5bda28060cdca6bfedbf989');
  assert.equal(hex(A.decodeRecipient(r)), hex(pk));
});
test('HPKE seal/open round-trips', () => {
  const ss = pat(32, i => (i * 3) % 256), enc = pat(1120, i => i % 97), fk = pat(16, i => i + 1);
  assert.equal(hex(A.openFileKey(ss, enc, A.sealFileKey(ss, enc, fk))), hex(fk));
});
test('age file build/open round-trips (multi-chunk STREAM + MAC)', () => {
  const fileKey = A.randomBytes(16);
  const stanza = { tag: A.STANZA_TAG, args: [A.b64(pat(1120, i => i % 251))], body: pat(32, i => 0x10 + i) };
  const pt = new TextEncoder().encode('mlkem768x25519 ✅ '.repeat(6000)); // > 64 KiB
  const file = A.buildAgeFile([stanza], fileKey, pt);
  assert.equal(hex(A.openAgeFile(file, fileKey)), hex(pt));
});
test('header MAC rejects tampering', () => {
  const fileKey = A.randomBytes(16);
  const stanza = { tag: A.STANZA_TAG, args: [A.b64(pat(1120, i => i))], body: pat(32, i => i) };
  const file = A.buildAgeFile([stanza], fileKey, new TextEncoder().encode('hi'));
  const t = Uint8Array.from(file); t[60] ^= 1;
  assert.throws(() => A.openAgeFile(t, fileKey), /MAC/);
});
