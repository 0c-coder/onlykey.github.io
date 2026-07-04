'use strict';
const xwing = require('../../onlykey-fido2/onlykey/xwing.js');
const age = require('./age-format.js');

module.exports = function (imports) {
  const { onlykeyPqc } = imports;

  async function exportRecipient(label) {
    const { recipientPk } = await onlykeyPqc.getRecipient(label);
    return age.encodeRecipient(recipientPk);
  }

  async function encryptToRecipient(recipient, plaintext /* Uint8Array */) {
    const pk = age.decodeRecipient(recipient);
    const { ciphertext, sharedSecret } = xwing.xwingEncapsulate(pk);      // ct 1120, ss 32
    const fileKey = age.randomBytes(age.FILE_KEY_LEN);                    // 16
    const body = age.sealFileKey(sharedSecret, ciphertext, fileKey);      // HPKE seal -> 32
    const stanza = { tag: age.STANZA_TAG, args: [age.b64(ciphertext)], body };
    return age.buildAgeFile([stanza], fileKey, plaintext);
  }

  async function decryptFile(ageBytes, label, recipient) {
    const { stanzas } = age.parseAgeFile(ageBytes);
    const st = stanzas.find((s) => s.tag === age.STANZA_TAG);
    if (!st || st.args.length !== 1) throw new Error('no mlkem768x25519 stanza');
    const ciphertext = age.unb64(st.args[0]);
    if (ciphertext.length !== xwing.SIZES.XWING.ct)
      throw new Error('stanza ct must be 1120 bytes, got ' + ciphertext.length);
    if (st.body.length !== age.SEALED_BODY_LEN)
      throw new Error('stanza body must be 32 bytes, got ' + st.body.length);
    const pkX = recipient
      ? age.decodeRecipient(recipient).slice(xwing.SIZES.MLKEM.pk, xwing.SIZES.XWING.pk)
      : (await onlykeyPqc.getRecipient(label)).pkX;
    const sharedSecret = await onlykeyPqc.decapsulate(label, ciphertext, pkX); // device + button
    const fileKey = age.openFileKey(sharedSecret, ciphertext, st.body);        // HPKE open -> 16
    return age.openAgeFile(ageBytes, fileKey);
  }

  return { exportRecipient, encryptToRecipient, decryptFile };
};
