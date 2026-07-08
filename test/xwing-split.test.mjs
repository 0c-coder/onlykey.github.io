// Hardware-free proof of the split-custody X-Wing crypto used by the web app.
//
// Verifies that a STANDARD X-Wing sender (noble ml_kem768_x25519) encapsulating
// to an OnlyKey recipient can be decapsulated by splitting the work between the
// "device" (X25519 half; sk_X never leaves) and the "browser" (ML-KEM half;
// ct_M never sent to the device) — reproducing the exact shared secret.
//
// Run: node --test test/xwing-split.test.mjs   (needs @noble/* dev-deps)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import { ml_kem768_x25519 as XW } from '@noble/post-quantum/hybrid.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

const require = createRequire(import.meta.url);
const xw = require('../src/onlykey-fido2/onlykey/xwing.js');

const info = (s) => new TextEncoder().encode(s);
const eqB = (a, b) => Buffer.from(a).equals(Buffer.from(b));

// Stand-in for the firmware's per-label derivation + domain separation.
function deviceDerive(webDerivKey, label) {
  const sk_X = hkdf(sha256, webDerivKey, info(label), info('onlykey/xwing/x25519/v1'), 32);
  const mlkem_seed = hkdf(sha256, sk_X, new Uint8Array(0), info('onlykey/xwing/mlkem768-seed/v1'), 32);
  return { sk_X, mlkem_seed };
}

test('recipient is a valid 1216-byte X-Wing pubkey', () => {
  const { sk_X, mlkem_seed } = deviceDerive(randomBytes(32), 'age:personal');
  const rec = xw.buildRecipientPubkey(x25519.getPublicKey(sk_X), mlkem_seed);
  assert.equal(rec.length, 1216);
});

test('split decaps reproduces standard-encaps shared secret', () => {
  const webKey = randomBytes(32), label = 'age:personal';
  const { sk_X, mlkem_seed } = deviceDerive(webKey, label);
  const pk_X = x25519.getPublicKey(sk_X);
  const recipient = xw.buildRecipientPubkey(pk_X, mlkem_seed);

  // standard sender
  const { cipherText, sharedSecret } = XW.encapsulate(recipient);
  assert.equal(cipherText.length, 1120);

  // device does X25519, browser does ML-KEM
  const ss_X = x25519.getSharedSecret(sk_X, xw.ctX(cipherText));
  const ss = xw.xwingSplitDecapsulate(ss_X, cipherText, pk_X, mlkem_seed);
  assert.ok(eqB(ss, sharedSecret));
});

test('domain separation: mlkem_seed never equals sk_X', () => {
  const { sk_X, mlkem_seed } = deviceDerive(randomBytes(32), 'age:x');
  assert.ok(!eqB(mlkem_seed, sk_X));
});

test('deterministic per (web key, label)', () => {
  const k = randomBytes(32);
  const a = deviceDerive(k, 'age:same'), b = deviceDerive(k, 'age:same');
  assert.ok(eqB(a.sk_X, b.sk_X) && eqB(a.mlkem_seed, b.mlkem_seed));
});

test('cannot decrypt without the device (no ss_X)', () => {
  const { sk_X, mlkem_seed } = deviceDerive(randomBytes(32), 'age:y');
  const pk_X = x25519.getPublicKey(sk_X);
  const recipient = xw.buildRecipientPubkey(pk_X, mlkem_seed);
  const { cipherText, sharedSecret } = XW.encapsulate(recipient);
  const ssZero = xw.xwingSplitDecapsulate(new Uint8Array(32), cipherText, pk_X, mlkem_seed);
  assert.ok(!eqB(ssZero, sharedSecret));
});
