/**
 * onlykey-openpgp-pqc.js — OnlyKey composite PQC PGP delegation for openpgp.js
 * ---------------------------------------------------------------------------
 * Companion to onlykey-openpgp.js (classical RSA/ECC). This wires the IETF
 * OpenPGP-PQC composite keys (draft-ietf-openpgp-pqc) to the loaded key on the
 * device (firmware libraries PR #31, KEYTYPE_PQC_PGP = 7):
 *
 *   pqc_mldsa_ed25519 (algo 107) — sign  = Ed25519(64) + ML-DSA-65(3309)
 *   pqc_mlkem_x25519  (algo 105) — decrypt: device does X25519 + ML-KEM decaps;
 *                                  openpgp.js does the KMAC256("OpenPGPCompositeKDFv1")
 *                                  combine + AES key-unwrap.
 *
 * Uses the composite openpgp.js build (0c-coder/openpgpjs onlykey-hardware-hooks
 * @ pqc) which exposes:
 *     openpgp.setHardwareHooks({ signer, ecdh, mlkemDecaps })
 *     openpgp.createHardwarePrivateKey(publicKey)
 *
 * Device I/O is provided by the caller as thin callbacks over the SAME OnlyKey
 * HID transport used elsewhere (OKSIGN=237, OKDECRYPT=240). The wire framing
 * matches okpqc.cpp exactly:
 *     signEcc(digest)  -> OKSIGN  payload [0x00] + digest  -> 64-byte  Ed25519 sig
 *     signPqc(digest)  -> OKSIGN  payload [0x01] + digest  -> 3309-byte ML-DSA sig
 *     x25519(point)    -> OKDECRYPT payload 32-byte point  -> 32-byte shared secret
 *     mlkemDecaps(ct)  -> OKDECRYPT payload 1088-byte ct   -> 32-byte key share
 *
 * Single composite hardware key per session (the common case). For mixed
 * software+hardware sessions, refine isDeviceKey() with a keyID compare.
 *
 * CommonJS (require) or browser global (window.onlykeyOpenPGPpqc).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.onlykeyOpenPGPpqc = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function toU8(x) {
    if (x instanceof Uint8Array) return x;
    if (Array.isArray(x)) return Uint8Array.from(x);
    if (x && x.length != null) return Uint8Array.from(x);
    throw new Error('cannot coerce device result to bytes');
  }

  // Promisify a kbpgp-style `fn(bytes, cb)` device wrapper (cb(resultBytes)).
  function call(fn, arg) {
    return new Promise(function (resolve, reject) {
      try {
        fn(toU8(arg), function (result) {
          if (result == null) return reject(new Error('OnlyKey returned no data'));
          resolve(toU8(result));
        });
      } catch (e) { reject(e); }
    });
  }

  // expected on-device output sizes (validate before handing back to openpgp.js)
  var ED25519_SIG = 64, MLDSA_SIG = 3309, SS = 32;

  /**
   * Register composite PQC hardware hooks.
   * @param {object} opts
   * @param {object} opts.openpgp        the composite openpgp.js namespace
   * @param {function} opts.signEcc      (digest, cb) => cb(64-byte Ed25519 sig)
   * @param {function} opts.signPqc      (digest, cb) => cb(3309-byte ML-DSA-65 sig)
   * @param {function} opts.x25519       (point32, cb) => cb(32-byte shared secret)
   * @param {function} opts.mlkemDecaps  (ct1088, cb) => cb(32-byte key share)
   * @param {function} [opts.signEccClassical] optional: classical ed25519 for non-composite keys
   */
  function registerHooks(opts) {
    var openpgp = opts.openpgp;
    if (!openpgp || typeof openpgp.setHardwareHooks !== 'function') {
      throw new Error('registerHooks: composite openpgp.js with setHardwareHooks required');
    }
    var P = openpgp.enums.publicKey;

    openpgp.setHardwareHooks({
      // ---- composite signing (algo 107): return both halves --------------
      async signer(algo, hashAlgo, hashed, publicKeyParams) {
        hashed = toU8(hashed);
        if (algo === P.pqc_mldsa_ed25519) {
          if (!opts.signEcc || !opts.signPqc) return null;
          var ecc = await call(opts.signEcc, hashed);      // OKSIGN [0]+digest
          var pqc = await call(opts.signPqc, hashed);       // OKSIGN [1]+digest
          if (ecc.length !== ED25519_SIG) throw new Error('bad Ed25519 sig len ' + ecc.length);
          if (pqc.length !== MLDSA_SIG) throw new Error('bad ML-DSA sig len ' + pqc.length);
          // openpgp.js composite serializer expects { eccSignature, mldsaSignature }.
          return { eccSignature: ecc, mldsaSignature: pqc };
        }
        // optional classical ed25519 fallthrough (e.g. a legacy signing subkey)
        if ((algo === P.ed25519 || algo === P.eddsaLegacy) && opts.signEccClassical) {
          var raw = await call(opts.signEccClassical, hashed);
          if (algo === P.ed25519) return { RS: raw };
          return { r: raw.subarray(0, 32), s: raw.subarray(32, 64) };
        }
        return null; // software path
      },

      // ---- ECC (X25519) half of composite decryption --------------------
      // openpgp.js composite decaps calls recomputeSharedSecret(x25519, V, ...)
      // which routes here; it does the SHA3-256 ecc key-share itself afterwards.
      async ecdh(algo, ephemeralPublicKey, publicKeyParams) {
        if (algo !== P.x25519 && algo !== P.ecdh) return null;
        if (!opts.x25519) return null;
        var ss = await call(opts.x25519, toU8(ephemeralPublicKey)); // OKDECRYPT 32B
        if (ss.length !== SS) throw new Error('bad X25519 ss len ' + ss.length);
        return ss;
      },

      // ---- ML-KEM half of composite decryption --------------------------
      // returns the ML-KEM key share; openpgp.js does the KMAC256 combine +
      // AES key-unwrap. mlkemCipherText is the 1088-byte ML-KEM ciphertext.
      async mlkemDecaps(algo, mlkemCipherText, mlkemSecretKey) {
        if (algo !== P.pqc_mlkem_x25519) return null;
        if (!opts.mlkemDecaps) return null;
        var share = await call(opts.mlkemDecaps, toU8(mlkemCipherText)); // OKDECRYPT 1088B
        if (share.length !== SS) throw new Error('bad ML-KEM share len ' + share.length);
        return share;
      }
    });
    return openpgp;
  }

  /**
   * Build a hardware-backed composite PrivateKey from the device's armored
   * composite PUBLIC key (algo 105 subkey + algo 107 primary). Operations route
   * to the device via the hooks above.
   */
  async function buildHardwareKey(openpgp, armoredPublicKey) {
    var pub = await openpgp.readKey({ armoredKey: armoredPublicKey });
    return openpgp.createHardwarePrivateKey(pub);
  }

  // --- convenience wrappers ---------------------------------------------------
  async function okSign(openpgp, hwKey, text, o) {
    o = o || {};
    var message = await openpgp.createMessage({ text: text });
    return openpgp.sign({ message, signingKeys: hwKey,
      format: o.format || 'armored', detached: !!o.detached });
  }

  async function okDecrypt(openpgp, hwKey, armoredMessage, o) {
    o = o || {};
    var message = await openpgp.readMessage({ armoredMessage: armoredMessage });
    return openpgp.decrypt({ message, decryptionKeys: hwKey,
      verificationKeys: o.verificationKeys, format: o.format || 'utf8' });
  }

  return {
    registerHooks: registerHooks,
    clearHooks: function (openpgp) { openpgp.clearHardwareHooks(); },
    buildHardwareKey: buildHardwareKey,
    okSign: okSign,
    okDecrypt: okDecrypt
  };
}));
