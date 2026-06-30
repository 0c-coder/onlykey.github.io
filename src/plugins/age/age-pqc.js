// age-pqc.js — onlyagent plugin: PQC (age `mlkem768x25519`) encrypt/decrypt.
//
// Wiring (architect.js DI, like the other plugins in src/plugins/*):
//   consumes: ["app", "window", "onlykeyApi", "onlykeyPqc"]
// Add an `age.page.html` next to this file and register the plugin in
// src/plugins.js (copy how encrypt/decrypt are registered).
//
// Flow:
//   - exportRecipient(slot, keytype): read device pubkey -> shareable recipient.
//   - encryptToRecipient(recipient, data): HOST-side KEM encapsulate (xwing.js) +
//     age stanza wrap. No device needed to ENCRYPT to someone.
//   - decryptFile(ageBytes, slot, keytype): pull the stanza ciphertext, ask the
//     DEVICE to decapsulate it, then unwrap the file key and decrypt the body.

'use strict';

const xwing = require('../../onlykey-fido2/onlykey/xwing.js');

module.exports = function (imports) {
  const { onlykeyPqc } = imports;

  // Publish a recipient others can encrypt to (no secrets leave the device).
  // `label` is the derivation identity (e.g. "age:personal") — not a slot.
  async function exportRecipient(label, keytype) {
    const pk = await onlykeyPqc.getPubKey(label, keytype);
    return xwing.pubkeyToRecipient(keytype, pk); // TODO(verify #90) encoding
  }

  // Encrypt a file to a recipient. Pure host-side; matches `age -r <recipient>`.
  async function encryptToRecipient(recipient, plaintext /* Uint8Array */) {
    const { keytype, pk } = xwing.recipientToPubkey(recipient); // TODO(verify #90)
    const { ciphertext, sharedSecret } = xwing.encapsulate(keytype, pk);
    // TODO(verify #90): derive the age file key and wrap it via HPKE
    //   (KEM 0x647A / KDF 0x0001 HKDF-SHA256 / AEAD 0x0003 ChaCha20Poly1305),
    //   emit the `mlkem768x25519` stanza, then ChaCha20Poly1305 the payload.
    //   Build this to byte-match python-onlykey#90's age output.
    return { stanzaCiphertext: ciphertext, sharedSecret /* ...assemble age file */ };
  }

  // Decrypt a file: the device re-derives the private key from `label` and does
  // the decapsulation. `label` is the same identity used to export the recipient.
  async function decryptFile(ageBytes, label, keytype) {
    // TODO(verify #90): parse the age header, find the `mlkem768x25519` stanza and
    // extract its KEM ciphertext (1088/1120 B).
    const stanzaCiphertext = parseStanzaCiphertext(ageBytes, keytype);
    const sharedSecret = await onlykeyPqc.decapsulate(label, keytype, stanzaCiphertext); // device button press
    // TODO(verify #90): HKDF(sharedSecret) -> unwrap file key -> ChaCha20Poly1305
    //   decrypt the payload. Mirror python-onlykey#90 exactly.
    return decryptBody(ageBytes, sharedSecret);
  }

  function parseStanzaCiphertext(/* ageBytes, keytype */) {
    throw new Error('parseStanzaCiphertext: implement age header parse per #90');
  }
  function decryptBody(/* ageBytes, sharedSecret */) {
    throw new Error('decryptBody: implement age payload decrypt per #90');
  }

  return { exportRecipient, encryptToRecipient, decryptFile };
};
