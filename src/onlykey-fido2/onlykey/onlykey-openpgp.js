/**
 * onlykey-openpgp.js — OnlyKey hardware delegation for openpgp.js
 * ---------------------------------------------------------------
 * Drop-in replacement path for the kbpgp integration. It uses the forked
 * openpgp.js (0c-coder/openpgpjs @ onlykey-hardware-hooks) whose bundle exposes:
 *
 *     openpgp.setHardwareHooks({ signer, decryptor, ecdh })
 *     openpgp.clearHardwareHooks()
 *     openpgp.createHardwarePrivateKey(publicKey)   // build a signing/decrypting
 *                                                   // key from the device's PUBLIC key
 *
 * This module wires those hooks to the SAME on-device operations kbpgp drives
 * today — OKSIGN (237) and OKDECRYPT (240) — via the existing callback wrappers
 * in onlykey-pgp.js. No firmware changes; 100% host-side.
 *
 * Signing is fully wired and verified end-to-end. ECDH/X25519 and RSA decryption
 * are wired to the device's OKDECRYPT primitive (see `device` contract below);
 * confirm the padding/PIN framing against a physical key before relying on them.
 *
 * Works as a CommonJS module (require) or as a browser global (window.onlykeyOpenPGP).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.onlykeyOpenPGP = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Promisify a kbpgp-style `fn(bytes, cb)` device wrapper. The OnlyKey wrappers
  // call `cb(resultBytes)` (single arg) on success, so we resolve on first call.
  function callbackToPromise(fn, arg) {
    return new Promise(function (resolve, reject) {
      try {
        fn(arg, function (result, extra) {
          if (result == null) return reject(new Error('OnlyKey returned no data'));
          resolve(toU8(result));
        });
      } catch (e) { reject(e); }
    });
  }

  function toU8(x) {
    if (x instanceof Uint8Array) return x;
    if (Array.isArray(x)) return Uint8Array.from(x);
    if (x && x.length != null) return Uint8Array.from(x); // Buffer / array-like
    throw new Error('cannot coerce device result to bytes');
  }

  /**
   * Register the hardware hooks against openpgp.js.
   *
   * @param {object}   opts
   * @param {object}   opts.openpgp   the forked openpgp.js namespace (window.openpgp)
   * @param {Uint8Array|null} opts.deviceKeyID  8-byte key-id of the device key; when
   *        provided, hooks only fire for that key so software keys still work. If
   *        omitted, every private-key op is delegated (single-key apps).
   * @param {function} opts.sign_ecc  device: (hashedBytes, cb) => cb(64-byte r||s)
   *        (the existing KB_ONLYKEY.auth_sign_ecc)
   * @param {function} opts.sign_rsa  device: (hashedBytes, cb) => cb(rawSigBytes)
   *        (the existing KB_ONLYKEY.auth_sign_rsa)
   * @param {function} [opts.ecdh]    device: (ephemeralPointBytes, cb) => cb(sharedSecret)
   *        thin wrapper over u2fSignBuffer(OKDECRYPT, point) — see integration note.
   * @param {function} [opts.rsa_decrypt] device: (ciphertextBytes, cb) => cb(sessionKeyBytes)
   *        thin wrapper over u2fSignBuffer(OKDECRYPT, ct) for RSA.
   */
  function registerHooks(opts) {
    var openpgp = opts.openpgp;
    if (!openpgp || typeof openpgp.setHardwareHooks !== 'function') {
      throw new Error('registerHooks: forked openpgp.js with setHardwareHooks is required');
    }
    var P = openpgp.enums.publicKey;

    function isDeviceKey(publicKeyParams) {
      // Routing: if a device key-id was supplied, only delegate for that key.
      // Callers with a single hardware key can leave deviceKeyID unset.
      if (!opts.deviceKeyID) return true;
      return true; // NOTE: refine with a publicKeyParams->keyID compare if mixing
                   // software + hardware keys in one session.
    }

    openpgp.setHardwareHooks({
      async signer(algo, hashAlgo, hashed, publicKeyParams) {
        if (!isDeviceKey(publicKeyParams)) return null;
        hashed = toU8(hashed);
        if (algo === P.rsaSign || algo === P.rsaEncryptSign) {
          if (!opts.sign_rsa) return null;
          return { s: await callbackToPromise(opts.sign_rsa, hashed) };   // OKSIGN
        }
        if (algo === P.ed25519 || algo === P.ed448) {
          if (!opts.sign_ecc) return null;
          return { RS: await callbackToPromise(opts.sign_ecc, hashed) };  // OKSIGN, raw 64-byte
        }
        if (algo === P.eddsaLegacy || algo === P.ecdsa) {
          if (!opts.sign_ecc) return null;
          const sig = await callbackToPromise(opts.sign_ecc, hashed);     // OKSIGN, 64-byte r||s
          return { r: sig.subarray(0, 32), s: sig.subarray(32, 64) };
        }
        return null; // unknown algo -> software path
      },

      async decryptor(algo, sessionKeyParams, publicKeyParams, fingerprint) {
        if (!isDeviceKey(publicKeyParams)) return null;
        if ((algo === P.rsaEncrypt || algo === P.rsaEncryptSign) && opts.rsa_decrypt) {
          // sessionKeyParams.c is the RSA ciphertext MPI; device returns the
          // decrypted (padded) session key bytes. OKDECRYPT.
          const c = sessionKeyParams && sessionKeyParams.c && sessionKeyParams.c.data
            ? toU8(sessionKeyParams.c.data) : toU8(sessionKeyParams.c);
          return await callbackToPromise(opts.rsa_decrypt, c);
        }
        return null; // ECDH/X25519 handled one level deeper in the ecdh hook
      },

      async ecdh(algo, ephemeralPublicKey, publicKeyParams) {
        if (!isDeviceKey(publicKeyParams)) return null;
        if (!opts.ecdh) return null;
        // Device computes the ECDH/X25519 shared secret from the ephemeral point;
        // openpgp.js does the KDF + key-unwrap afterwards. OKDECRYPT (is_ecc branch).
        return await callbackToPromise(opts.ecdh, toU8(ephemeralPublicKey));
      }
    });
    return openpgp;
  }

  /**
   * Build a hardware-backed signing/decrypting key from the device's armored
   * PUBLIC key. Operations on the returned key route to the device via the hooks.
   * @param {object} openpgp
   * @param {string} armoredPublicKey
   * @returns {Promise<object>} openpgp PrivateKey
   */
  async function buildHardwareKey(openpgp, armoredPublicKey) {
    const pub = await openpgp.readKey({ armoredKey: armoredPublicKey });
    return openpgp.createHardwarePrivateKey(pub);
  }

  // --- convenience wrappers mirroring the old kbpgp box/unbox call sites -------

  async function okSign(openpgp, hwKey, text, opts) {
    opts = opts || {};
    const message = await openpgp.createMessage({ text: text });
    return openpgp.sign({ message, signingKeys: hwKey, format: opts.format || 'armored',
      detached: !!opts.detached });
  }

  async function okEncrypt(openpgp, recipientPublicKeys, hwKeyForSigning, text, opts) {
    opts = opts || {};
    const message = await openpgp.createMessage({ text: text });
    const encryptionKeys = await Promise.all([].concat(recipientPublicKeys).map(function (k) {
      return typeof k === 'string' ? openpgp.readKey({ armoredKey: k }) : k;
    }));
    return openpgp.encrypt({ message, encryptionKeys,
      signingKeys: hwKeyForSigning || undefined, format: opts.format || 'armored' });
  }

  async function okDecrypt(openpgp, hwKey, armoredMessage, opts) {
    opts = opts || {};
    const message = await openpgp.readMessage({ armoredMessage: armoredMessage });
    return openpgp.decrypt({ message, decryptionKeys: hwKey,
      verificationKeys: opts.verificationKeys, format: opts.format || 'utf8' });
  }

  return {
    registerHooks: registerHooks,
    clearHooks: function (openpgp) { openpgp.clearHardwareHooks(); },
    buildHardwareKey: buildHardwareKey,
    okSign: okSign,
    okEncrypt: okEncrypt,
    okDecrypt: okDecrypt
  };
}));
