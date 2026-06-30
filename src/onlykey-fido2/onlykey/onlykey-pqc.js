// onlykey-pqc.js — device-side PQC operations for the OnlyKey onlyagent web app.
// Module factory:  const onlykeyPqc = require('./onlykey/onlykey-pqc.js')(imports, onlykeyApi);
//
// IMPORTANT: the web/FIDO2 path has NO key slots. The OnlyKey has one reserved
// web-derivation key that derives an unlimited number of per-identity keys (the
// same mechanism the SSH/GPG/age agent already uses). A key is identified by a
// derivation LABEL (the identity), not a slot number — and nothing is stored on
// device; the keypair is reproduced on demand from (reserved key + label).
//
// This reuses the EXISTING derive flow (see index.js):
//   encode_ctaphid_request_as_keyhandle(OKCONNECT, optype, keytype, enc_resp, data)
//     optype : DERIVE_PUBLIC_KEY = 1   (return the derived public key)
//              DERIVE_SHARED_SECRET = 2 (return a 32-byte shared secret)
//     keytype: NACL=0 P256R1=1 P256K1=2 CURVE25519=3  +  MLKEM768=5  XWING=6
//     data   : the derivation input (identity keyhandle) [+ KEM ciphertext]
//
// Why the 32-byte derived secret "just works":
//   - XWING (6): X-Wing's private key IS a 32-byte seed; the device expands it
//     (SHAKE256) into the ML-KEM-768 + X25519 keypair. Same 32 bytes the
//     CURVE25519 path already derives -> zero new key material.
//   - MLKEM768 (5): device expands the 32-byte derived secret to ML-KEM's 64-byte
//     (d||z) seed, then KeyGen_internal. Deterministic. Pin the exact expansion
//     to python-onlykey#90 / firmware libraries#29.
// The host (xwing.js) only ever touches the PUBLIC key; the private key never
// leaves the device and is re-derived each call.

'use strict';

module.exports = function (imports, onlykeyApi) {
  const OKCONNECT = 228;
  const DERIVE_PUBLIC_KEY   = 1;
  const DERIVE_SHARED_SECRET = 2; // KEM decapsulation reuses this optype
  const NO_ENCRYPT_RESP = 0, ENCRYPT_RESP = 1;

  const KEYTYPE    = { MLKEM768: 5, XWING: 6 };
  const PUBKEY_LEN = { 5: 1184, 6: 1216 };
  const CT_LEN     = { 5: 1088, 6: 1120 };
  const SS_LEN     = 32;

  function assertKeytype(kt) {
    if (kt !== KEYTYPE.MLKEM768 && kt !== KEYTYPE.XWING)
      throw new Error('keytype must be 5 (ML-KEM-768) or 6 (X-Wing), got ' + kt);
  }

  // Build the derivation input ("keyhandle data") for an identity label. The ECC
  // path already does this for SSH/age identities — reuse that exact encoder so a
  // given label maps to the same derived key across algorithms.
  // TODO(verify #90/agent): point this at the existing identity->keyhandle encoder
  // (the SLIP-0010/derivation-path packing the agent uses), not a new format.
  function deriveInput(label) {
    if (typeof label !== 'string' || !label.length)
      throw new Error('PQC key needs a non-empty derivation label (identity)');
    throw new Error('deriveInput: reuse the agent identity->keyhandle encoder');
  }

  // Derive + return a PQC public key for an identity. Single derive request;
  // response is large (1184/1216 B) and comes back over the existing multi-packet
  // poll path that onlykey-api uses for big replies.
  async function getPubKey(label, keytype) {
    assertKeytype(keytype);
    const want = PUBKEY_LEN[keytype];
    const data = deriveInput(label);
    return new Promise((resolve, reject) => {
      // Reuses the same transport index.js uses for DERIVE_PUBLIC_KEY.
      onlykeyApi.ctaphid_via_webauthn(
        OKCONNECT, DERIVE_PUBLIC_KEY, keytype, NO_ENCRYPT_RESP,
        data, 6000,
        function (err, out) {
          if (err) return reject(err);
          if (!out || out.length < want)
            return reject(new Error('short pubkey: got ' + (out && out.length)));
          resolve(Uint8Array.from(out.slice(0, want)));
        }
      );
    });
  }

  // KEM decapsulation = "derive shared secret" with the ciphertext as input.
  // The device derives the private key from (reserved key + label), decapsulates
  // the ciphertext (1088/1120 B) after a button press, and returns 32 bytes.
  // The ciphertext is large, so this must go through the encrypted/chunked
  // transit path (same one onlykey-pgp.js `u2fSignBuffer` uses) — prefer to export
  // and reuse that sender rather than duplicate it.
  async function decapsulate(label, keytype, ciphertext /* Uint8Array */) {
    assertKeytype(keytype);
    if (ciphertext.length !== CT_LEN[keytype])
      throw new Error('ciphertext must be ' + CT_LEN[keytype] + 'B for keytype ' + keytype);
    const data = concat(deriveInput(label), ciphertext);
    // TODO(integration): send OKCONNECT + DERIVE_SHARED_SECRET + keytype + data via
    // the shared chunked+AES-GCM sender, ENCRYPT_RESP so the 32-byte secret comes
    // back encrypted; resolve to the 32-byte shared secret.
    throw new Error('decapsulate: wire to shared chunked sender (DERIVE_SHARED_SECRET)');
  }

  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }

  // No generate()/no slots: derived keys are stateless. A key "exists" the moment
  // you pick a label; getPubKey(label, keytype) reproduces it. Unlimited identities.
  return { KEYTYPE, PUBKEY_LEN, CT_LEN, SS_LEN, getPubKey, decapsulate };
};
