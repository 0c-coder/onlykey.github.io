// xwing.js — ML-KEM-768 + X-Wing encapsulation and age `mlkem768x25519`
// stanza helpers for the OnlyKey onlyagent web app.
//
// Pure JS, no device required. This is the half of the protocol the HOST runs:
// the browser ENCAPSULATES to a recipient's public key to produce
//   { sharedSecret(32B), ciphertext }
// and the OnlyKey later DECAPSULATES that ciphertext (see onlykey-pqc.js).
//
// Sizes (must match firmware libraries#29 / python-onlykey#90):
//   ML-KEM-768 : pk 1184, ct 1088, ss 32
//   X-Wing     : pk 1216 (= mlkem.pk 1184 || x25519.pk 32), ct 1120 (= 1088 || 32), ss 32
//
// Deps:  npm i @noble/post-quantum @noble/hashes
// Recent @noble/post-quantum ships X-Wing with the draft-09 combiner built in
// (KEM_ID 0x647A). If your version lacks it, see combineXWing() below.

'use strict';

const { ml_kem768 } = require('@noble/post-quantum/ml-kem');
let xwing = null;
try { xwing = require('@noble/post-quantum/xwing').xwing; } catch (e) { /* fallback below */ }

const SIZES = {
  MLKEM768: { keytype: 5, pk: 1184, ct: 1088, ss: 32 },
  XWING:    { keytype: 6, pk: 1216, ct: 1120, ss: 32 },
};

// ---- ML-KEM-768 ----------------------------------------------------------
function mlkemEncapsulate(recipientPk /* Uint8Array(1184) */) {
  if (recipientPk.length !== SIZES.MLKEM768.pk)
    throw new Error('ML-KEM-768 pubkey must be 1184 bytes, got ' + recipientPk.length);
  // @noble returns { cipherText, sharedSecret }
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(recipientPk);
  return { ciphertext: cipherText, sharedSecret }; // ct 1088, ss 32
}

// ---- X-Wing (hybrid ML-KEM-768 + X25519) ---------------------------------
// Preferred: library-provided X-Wing (handles the draft-09 SHA3-256 combiner
// with label 0x5c2e2f2f5e5c internally).
function xwingEncapsulate(recipientPk /* Uint8Array(1216) */) {
  if (recipientPk.length !== SIZES.XWING.pk)
    throw new Error('X-Wing pubkey must be 1216 bytes, got ' + recipientPk.length);
  if (xwing && xwing.encapsulate) {
    const { cipherText, sharedSecret } = xwing.encapsulate(recipientPk);
    return { ciphertext: cipherText, sharedSecret }; // ct 1120, ss 32
  }
  // TODO(firmware): only used if @noble/post-quantum has no xwing module.
  // Implement draft-connolly-cfrg-xwing-kem-09 combiner here and VERIFY the byte
  // layout against python-onlykey#90 tests/test_age_wire.py before trusting it.
  throw new Error('X-Wing not available in @noble/post-quantum; upgrade the package.');
}

function encapsulate(keytype, recipientPk) {
  if (keytype === SIZES.MLKEM768.keytype) return mlkemEncapsulate(recipientPk);
  if (keytype === SIZES.XWING.keytype)    return xwingEncapsulate(recipientPk);
  throw new Error('Unknown PQC keytype ' + keytype);
}

// ---- age `mlkem768x25519` recipient encoding -----------------------------
// age recipients are bech32-ish "age1..." strings in stock age; the OnlyKey
// plugin in #90 defines its own recipient label. Keep the raw-pubkey <-> string
// mapping in ONE place and make it match #90 exactly.
// TODO(verify #90): confirm the exact recipient/stanza encoding (bech32 HRP,
// stanza tag "mlkem768x25519", and the HPKE wrap: KEM 0x647A / KDF 0x0001
// (HKDF-SHA256) / AEAD 0x0003 (ChaCha20Poly1305)) before interop.
function recipientToPubkey(recipientStr) {
  // TODO(verify #90): decode "age1..."/onlykey recipient -> Uint8Array pubkey.
  throw new Error('recipientToPubkey: implement per python-onlykey#90 encoding');
}
function pubkeyToRecipient(keytype, pk) {
  // TODO(verify #90): encode pubkey -> recipient string.
  throw new Error('pubkeyToRecipient: implement per python-onlykey#90 encoding');
}

module.exports = {
  SIZES,
  encapsulate,
  mlkemEncapsulate,
  xwingEncapsulate,
  recipientToPubkey,
  pubkeyToRecipient,
};
