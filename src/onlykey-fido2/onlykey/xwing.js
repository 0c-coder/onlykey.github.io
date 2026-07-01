// xwing.js — ML-KEM-768 + X-Wing (age `mlkem768x25519`) crypto for the OnlyKey
// onlyagent web app, using the SPLIT-CUSTODY model:
//
//   * X25519 half stays on the OnlyKey  (device computes ss_X = X25519(sk_X, ct_X),
//     sk_X never leaves — this is the existing DERIVE_SHAREDSEC / ECDH primitive).
//   * ML-KEM half runs here in the browser: the device hands us a 32-byte
//     `mlkem_seed`, we expand it to the ML-KEM keypair and decapsulate the
//     1088-byte ct_M locally, so the big ciphertext never goes to the device.
//
// Every device round-trip is <= 64 bytes. Decryption still REQUIRES the OnlyKey
// (no ss_X without it). The recipient is a STANDARD X-Wing public key, so normal
// age encryptors interoperate. See src/plugins/age/INTEGRATION.md for the spec.
//
// Verified against @noble/post-quantum by test/xwing-split.test.mjs (the split
// decapsulation reproduces standard-encaps shared secret, byte-for-byte).
//
// Deps: npm i @noble/post-quantum @noble/curves @noble/hashes   (>= 0.6)

'use strict';

const { ml_kem768_x25519 } = require('@noble/post-quantum/hybrid.js');
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
const { x25519 } = require('@noble/curves/ed25519.js');
const { shake256, sha3_256 } = require('@noble/hashes/sha3.js');
const { concatBytes } = require('@noble/hashes/utils.js');

// draft-connolly-cfrg-xwing-kem-09 combiner label "\.//^\"
const XWING_LABEL = new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);

const SIZES = {
  KEYTYPE_MLKEM768: 5,
  KEYTYPE_XWING: 6,
  MLKEM: { pk: 1184, ct: 1088, ss: 32 },
  XWING: { pk: 1216, ct: 1120, ss: 32, seed: 32 },
  X25519: { pk: 32, ct: 32, ss: 32 },
};

// ---- ML-KEM key material from the 32-byte device seed --------------------
// Pinned expansion (must match firmware): SHAKE256(mlkem_seed, 64) -> (d||z),
// then ML-KEM KeyGen_internal.
function mlkemKeypairFromSeed(mlkemSeed /* Uint8Array(32) */) {
  if (mlkemSeed.length !== 32) throw new Error('mlkem_seed must be 32 bytes');
  const seed64 = shake256(mlkemSeed, { dkLen: 64 });
  return ml_kem768.keygen(seed64); // { publicKey (1184), secretKey (2400) }
}

// ---- Recipient (X-Wing public key = pk_M || pk_X) ------------------------
// Build from what the device returns for DERIVE_PUBLIC_KEY: [pk_X | mlkem_seed].
function buildRecipientPubkey(pkX /* 32 */, mlkemSeed /* 32 */) {
  if (pkX.length !== 32) throw new Error('pk_X must be 32 bytes');
  const { publicKey: pkM } = mlkemKeypairFromSeed(mlkemSeed);
  return concatBytes(pkM, pkX); // 1216
}

// ---- Encapsulation (host side; no device needed) -------------------------
// Standard X-Wing encaps to a recipient's 1216-byte public key.
function xwingEncapsulate(recipientPk /* 1216 */) {
  if (recipientPk.length !== SIZES.XWING.pk)
    throw new Error('X-Wing pubkey must be 1216 bytes, got ' + recipientPk.length);
  const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(recipientPk);
  return { ciphertext: cipherText, sharedSecret }; // ct 1120, ss 32
}

// ---- Split decapsulation (browser half) ----------------------------------
// Inputs:
//   ssX        : 32-byte X25519 shared secret returned by the device (ss_X)
//   ciphertext : 1120-byte X-Wing ct (ct_M || ct_X) from the age stanza
//   pkX        : 32-byte recipient X25519 public (from the recipient)
//   mlkemSeed  : 32-byte ML-KEM seed returned by the device
// Returns the 32-byte X-Wing shared secret. ct_M never leaves the browser.
function xwingSplitDecapsulate(ssX, ciphertext, pkX, mlkemSeed) {
  if (ssX.length !== 32) throw new Error('ss_X must be 32 bytes');
  if (ciphertext.length !== SIZES.XWING.ct)
    throw new Error('X-Wing ct must be 1120 bytes, got ' + ciphertext.length);
  const ctM = ciphertext.slice(0, SIZES.MLKEM.ct);
  const ctX = ciphertext.slice(SIZES.MLKEM.ct, SIZES.XWING.ct);
  const { secretKey: skM } = mlkemKeypairFromSeed(mlkemSeed);
  const ssM = ml_kem768.decapsulate(ctM, skM); // ML-KEM decaps in the browser
  return sha3_256(concatBytes(ssM, ssX, ctX, pkX, XWING_LABEL));
}

// Convenience: pull ct_X out of a stanza ciphertext (what the device needs).
function ctX(ciphertext) {
  return ciphertext.slice(SIZES.MLKEM.ct, SIZES.XWING.ct);
}

module.exports = {
  SIZES,
  XWING_LABEL,
  mlkemKeypairFromSeed,
  buildRecipientPubkey,
  xwingEncapsulate,
  xwingSplitDecapsulate,
  ctX,
};
