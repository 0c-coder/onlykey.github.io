// onlykey-pqc.js — device wrappers for split-custody X-Wing on the web app.
//
// Model (see src/plugins/age/INTEGRATION.md): the OnlyKey keeps the X25519 half
// (sk_X never leaves) and hands the browser a 32-byte ML-KEM seed. Every device
// round-trip is <= 64 bytes; the 1088-byte ML-KEM ciphertext is decapsulated in
// the browser (xwing.js). Decryption still requires the device for ss_X.
//
// Reuses the EXISTING FIDO2 derive flow (bridge_to_onlykey / ok_extension.cpp):
//   ctaphid_via_webauthn(OKCONNECT, optype, keytype, enc_resp, data)
//     optype : DERIVE_PUBLIC_KEY = 1  -> device returns [ pk_X(32) | mlkem_seed(32) ]
//              DERIVE_SHAREDSEC  = 2  -> device returns [ ss_X(32) | mlkem_seed(32) ]
//              (…_REQ_PRESS = 3/4 require a button press)
//     keytype: wire byte 5 for X-Wing  (firmware opt2++ -> KEYTYPE_XWING = 6)
//     data   : derivation label  [+ ct_X (32B) for DERIVE_SHAREDSEC]
//   enc_resp = ENCRYPT_RESP so the 64-byte reply is wrapped in the transit key.

'use strict';

const xwing = require('./xwing.js');

module.exports = function (imports, onlykeyApi) {
  const OKCONNECT = 228;
  const DERIVE_PUBLIC_KEY = 1;
  const DERIVE_SHAREDSEC_REQ_PRESS = 4; // decrypt needs a touch
  const ENCRYPT_RESP = 1;
  const WIRE_KEYTYPE_XWING = 5;          // -> KEYTYPE_XWING(6) after firmware opt2++
  const SEED = 32;

  const enc = (s) => new TextEncoder().encode(s);
  function concat(a, b) {
    const out = new Uint8Array(a.length + (b ? b.length : 0));
    out.set(a, 0); if (b) out.set(b, a.length);
    return out;
  }
  function labelBytes(label) {
    if (typeof label !== 'string' || !label.length)
      throw new Error('PQC identity needs a non-empty derivation label');
    return enc(label);
  }

  // Low-level: one derive round-trip; resolves to the raw 64-byte device reply.
  function derive64(optype, data, timeoutMs) {
    return new Promise((resolve, reject) => {
      onlykeyApi.ctaphid_via_webauthn(
        OKCONNECT, optype, WIRE_KEYTYPE_XWING, ENCRYPT_RESP,
        data, timeoutMs || 6000,
        (err, out) => {
          if (err) return reject(err);
          if (!out || out.length < 64)
            return reject(new Error('short PQC reply: got ' + (out && out.length)));
          resolve(Uint8Array.from(out.slice(0, 64)));
        }
      );
    });
  }

  // Export a recipient for an identity label.
  // Returns the 1216-byte X-Wing recipient pubkey and the pk_X needed for decaps.
  async function getRecipient(label) {
    const r = await derive64(DERIVE_PUBLIC_KEY, labelBytes(label));
    const pkX = r.slice(0, SEED);
    const mlkemSeed = r.slice(SEED, 64);
    return {
      recipientPk: xwing.buildRecipientPubkey(pkX, mlkemSeed), // 1216
      pkX,                                                     // needed by decapsulate()
    };
  }

  // Decapsulate an X-Wing ciphertext for `label`. Requires a button press.
  //   ciphertext : 1120-byte stanza ct (ct_M || ct_X)
  //   pkX        : recipient X25519 public (from getRecipient / the recipient string)
  // Returns the 32-byte X-Wing shared secret.
  async function decapsulate(label, ciphertext, pkX) {
    if (ciphertext.length !== xwing.SIZES.XWING.ct)
      throw new Error('X-Wing ct must be 1120 bytes, got ' + ciphertext.length);
    const ctX = xwing.ctX(ciphertext);                 // 32B is all the device sees
    const data = concat(labelBytes(label), ctX);
    const r = await derive64(DERIVE_SHAREDSEC_REQ_PRESS, data, 30000);
    const ssX = r.slice(0, SEED);
    const mlkemSeed = r.slice(SEED, 64);
    return xwing.xwingSplitDecapsulate(ssX, ciphertext, pkX, mlkemSeed);
  }

  return {
    KEYTYPE_XWING: 6,
    WIRE_KEYTYPE_XWING,
    getRecipient,
    decapsulate,
    // pure-crypto helpers re-exported for the age plugin
    buildRecipientPubkey: xwing.buildRecipientPubkey,
    xwingEncapsulate: xwing.xwingEncapsulate,
    SIZES: xwing.SIZES,
  };
};
