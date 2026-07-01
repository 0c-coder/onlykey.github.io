// age-pqc.js — onlyagent plugin: PQC (age `mlkem768x25519`) encrypt/decrypt,
// split-custody model (device does X25519, browser does ML-KEM). See
// src/plugins/age/INTEGRATION.md and onlykey-fido2/onlykey/{xwing,onlykey-pqc}.js.
//
// Wiring (architect.js DI, like the other plugins in src/plugins/*):
//   consumes: ["app", "window", "onlykeyApi", "onlykeyPqc"]
//
// Crypto path (KEM) is implemented + unit-tested (test/xwing-split.test.mjs).
// The age CONTAINER layer (header/stanza framing, HPKE wrap, ChaCha20-Poly1305
// payload, HMAC) is the remaining plumbing and must byte-match the age
// `mlkem768x25519` format used by python-onlykey#90 — kept isolated below.

'use strict';

const xwing = require('../../onlykey-fido2/onlykey/xwing.js');

module.exports = function (imports) {
  const { onlykeyPqc } = imports;

  // ---- recipient string <-> raw X-Wing pubkey ----------------------------
  // NOTE: string form must match the canonical age `mlkem768x25519` recipient
  // encoding (bech32 age1…). Until pinned, use base64 of the raw 1216-byte key.
  function encodeRecipient(pk /* 1216 */) {
    return 'onlykey-mlkem768x25519:' + Buffer.from(pk).toString('base64');
  }
  function decodeRecipient(str) {
    const b64 = String(str).split(':').pop();
    const pk = Uint8Array.from(Buffer.from(b64, 'base64'));
    if (pk.length !== xwing.SIZES.XWING.pk)
      throw new Error('recipient pubkey must be 1216 bytes, got ' + pk.length);
    return pk;
  }
  function pkXfromRecipient(pk /* 1216 */) {
    return pk.slice(xwing.SIZES.MLKEM.pk, xwing.SIZES.XWING.pk); // trailing 32B
  }

  // Publish a recipient others can encrypt to (no secrets leave the device).
  // `label` is the derivation identity (e.g. "age:personal") — not a slot.
  async function exportRecipient(label) {
    const { recipientPk } = await onlykeyPqc.getRecipient(label);
    return encodeRecipient(recipientPk);
  }

  // Encrypt to a recipient. Pure host-side (like `age -r <recipient>`), no device.
  async function encryptToRecipient(recipient, plaintext /* Uint8Array */) {
    const pk = decodeRecipient(recipient);
    const { ciphertext, sharedSecret } = xwing.xwingEncapsulate(pk); // ct 1120, ss 32
    // sharedSecret wraps the age file key via the HPKE suite
    //   (KEM 0x647A / KDF 0x0001 HKDF-SHA256 / AEAD 0x0003 ChaCha20-Poly1305).
    return assembleAgeFile(ciphertext, sharedSecret, plaintext);
  }

  // Decrypt: the device re-derives sk_X from `label` and returns ss_X; the
  // browser does the ML-KEM half and combines. `label` matches exportRecipient.
  async function decryptFile(ageBytes, label, recipient) {
    const stanzaCt = parseStanzaCiphertext(ageBytes);      // 1120-byte X-Wing ct
    const pkX = pkXfromRecipient(decodeRecipient(recipient));
    const sharedSecret = await onlykeyPqc.decapsulate(label, stanzaCt, pkX); // button press
    return openAgeFile(ageBytes, sharedSecret);
  }

  // ---- age container layer (TODO: byte-match age mlkem768x25519 / #90) -----
  function assembleAgeFile(/* ciphertext, sharedSecret, plaintext */) {
    throw new Error('assembleAgeFile: implement age header/stanza + ChaCha payload per #90');
  }
  function parseStanzaCiphertext(/* ageBytes */) {
    throw new Error('parseStanzaCiphertext: implement age header parse per #90');
  }
  function openAgeFile(/* ageBytes, sharedSecret */) {
    throw new Error('openAgeFile: implement age payload decrypt per #90');
  }

  return { exportRecipient, encryptToRecipient, decryptFile,
           encodeRecipient, decodeRecipient, pkXfromRecipient };
};
