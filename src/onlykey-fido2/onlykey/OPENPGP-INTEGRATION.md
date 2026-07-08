# openpgp.js hardware integration (OnlyKey web app)

This adds a **host-side openpgp.js path** alongside the existing kbpgp integration,
so the OnlyKey web app can sign/encrypt/decrypt through the forked openpgp.js while
the private key stays on the device. No firmware changes — it drives the same
**OKSIGN (237)** and **OKDECRYPT (240)** operations kbpgp already uses.

It is added *alongside* kbpgp (kbpgp is untouched) so nothing breaks while this is
tested. Flip the app to the openpgp path per-feature once validated.

## Files added (`src/onlykey-fido2/onlykey/`)
- **`openpgp.js`** — the forked openpgp.js browser bundle (IIFE, global `openpgp`).
  Built from `0c-coder/openpgpjs @ onlykey-hardware-hooks` (v6.3.1 base). This build
  exposes three fork-only symbols on the global: `openpgp.setHardwareHooks`,
  `openpgp.clearHardwareHooks`, `openpgp.createHardwarePrivateKey`.
- **`onlykey-openpgp.js`** — the glue: registers the hooks against the device
  wrappers and provides `buildHardwareKey` + `okSign` / `okEncrypt` / `okDecrypt`.

## How it works
openpgp.js refuses to sign/decrypt unless it holds an *unlocked private key*. A
hardware key has none, so `createHardwarePrivateKey(devicePublicKey)` builds a
PrivateKey from the device's **real public key** (correct fingerprint / key-id) with
placeholder private params, marked decrypted. openpgp.js then enters its crypto
functions, the registered hook fires, and the real op runs on the device. The
placeholder params are never read. (This replaces kbpgp's placeholder key + the
`custom_keyid` patches — the key-id is now correct automatically.)

## Wiring (3 steps)

### 1. Load the scripts
In `src/index-src.html` (or wherever kbpgp is loaded), add **before** app init:
```html
<script src="onlykey-fido2/onlykey/openpgp.js"></script>          <!-- window.openpgp -->
<script src="onlykey-fido2/onlykey/onlykey-openpgp.js"></script>  <!-- window.onlykeyOpenPGP -->
```
(Or `require('./onlykey/openpgp.js')` / `require('./onlykey/onlykey-openpgp.js')` in
`plugin.js` if you prefer the module path — the glue supports both.)

### 2. Expose two thin device primitives for the decrypt paths
The existing `KB_ONLYKEY.auth_sign_ecc` / `auth_sign_rsa` are reused directly for
signing. For **ECDH/X25519** and **RSA** decryption the glue needs the raw OKDECRYPT
primitive, which today is buried inside `auth_decrypt`. Add these two wrappers next to
it in `onlykey-pgp.js` (they mirror the `is_ecc` / RSA branches of `auth_decrypt`):
```js
// ECDH/X25519: device returns the shared secret from the ephemeral point (32 bytes in)
KB_ONLYKEY.auth_ecdh = function (point, cb) {
  if (!onlykeyApi.init) throw new Error('OK NOT CONNECTED');
  var pin_hash = sha256(point);
  pin = [get_pin(pin_hash[0]), get_pin(pin_hash[15]), get_pin(pin_hash[31])];
  return u2fSignBuffer(OKDECRYPT, Array.from(point), cb);
};
// RSA: device returns the decrypted (padded) session key
KB_ONLYKEY.auth_rsa_decrypt = function (ct, cb) {
  if (!onlykeyApi.init) throw new Error('OK NOT CONNECTED');
  var pin_hash = sha256(ct);
  pin = [get_pin(pin_hash[0]), get_pin(pin_hash[15]), get_pin(pin_hash[31])];
  return u2fSignBuffer(OKDECRYPT, Array.from(ct), cb);
};
```
> Signing is verified end-to-end. The two decrypt primitives above follow the same
> PIN/padding pattern as `auth_decrypt`; confirm against a physical key (the exact
> slice offsets for RSA padding may need the same `ct.slice(12,…)` treatment
> `auth_decrypt` applies) before switching the decrypt UI over.

### 3. Register hooks + build the key
Once the device is connected and you have its **armored public key** (the app already
fetches it via `onlykeyApi.request_pgp_pubkey()`):
```js
var openpgp = window.openpgp;
onlykeyOpenPGP.registerHooks({
  openpgp: openpgp,
  sign_ecc: KB_ONLYKEY.auth_sign_ecc,       // OKSIGN, 64-byte r||s
  sign_rsa: KB_ONLYKEY.auth_sign_rsa,       // OKSIGN, raw signature
  ecdh: KB_ONLYKEY.auth_ecdh,               // OKDECRYPT, shared secret
  rsa_decrypt: KB_ONLYKEY.auth_rsa_decrypt  // OKDECRYPT, RSA session key
});

var devicePub = (await onlykeyApi.request_pgp_pubkey()).value;   // armored
var hwKey = await onlykeyOpenPGP.buildHardwareKey(openpgp, devicePub);

// sign (verified path):
var sigArmored = await onlykeyOpenPGP.okSign(openpgp, hwKey, "hello", { detached: true });
// encrypt to a recipient, signed by the device:
var ct = await onlykeyOpenPGP.okEncrypt(openpgp, recipientArmoredPub, hwKey, "secret");
// decrypt a message addressed to the device:
var pt = await onlykeyOpenPGP.okDecrypt(openpgp, hwKey, armoredMessage);
```

## Verification done here
- The fork bundle exposes the three symbols (checked in `dist/openpgp.js`).
- `createHardwarePrivateKey(pub)` → PrivateKey with matching fingerprint,
  `keyPacket.isDecrypted() === true`.
- **End-to-end sign:** built the hardware key from a public key only, registered a
  `signer` hook emulating the device (Ed25519 over the digest), `openpgp.sign` routed
  through the hook, and the resulting signature **verifies** against the public key —
  both directly and through the `onlykey-openpgp.js` glue (`okSign`).

## Still to validate on hardware
- ECDH/X25519 decrypt and RSA decrypt round-trips against a physical OnlyKey (the
  device-primitive framing in step 2).
- Wiring the app UI buttons to the openpgp path and A/B-ing against kbpgp output.

## Build provenance
Bundle built from the fork branch with the browser (IIFE) target:
```
git clone -b onlykey-hardware-hooks https://github.com/0c-coder/openpgpjs
cd openpgpjs && npm ci
# src/index.js re-exports the fork symbols; then:
npm run build -- --config-build-only=dist   # -> dist/openpgp.js (window.openpgp)
```
(The committed `openpgp.js` here is the non-minified IIFE build; swap in
`dist/openpgp.min.js` for production once you run a full `npm run build`.)


---

## Composite PQC PGP (IETF OpenPGP-PQC, algo 105/107)

This branch upgrades `openpgp.js` to the composite PQC build (OpenPGP.js v6 with
`draft-ietf-openpgp-pqc`) and adds `onlykey-openpgp-pqc.js`, which delegates the
IETF composite keys loaded on the device (firmware `feature/pqc-pgp-slots`,
`KEYTYPE_PQC_PGP = 7`):

- **Sign** `pqc_mldsa_ed25519` (107): the `signer` hook returns
  `{ eccSignature: Ed25519(64), mldsaSignature: ML-DSA-65(3309) }`. Device does
  each half; `openpgp.js` serializes the composite signature.
- **Decrypt** `pqc_mlkem_x25519` (105): the `ecdh` hook returns the X25519 shared
  secret and the `mlkemDecaps` hook returns the ML-KEM key share; `openpgp.js`
  does the `KMAC256("OpenPGPCompositeKDFv1")` combine + AES key-unwrap.

Device callbacks map to the firmware wire protocol (okpqc.cpp):

    signEcc(digest)  -> OKSIGN  [0x00]+digest  -> 64 B   Ed25519 sig
    signPqc(digest)  -> OKSIGN  [0x01]+digest  -> 3309 B ML-DSA-65 sig
    x25519(point)    -> OKDECRYPT 32-B point   -> 32 B   shared secret
    mlkemDecaps(ct)  -> OKDECRYPT 1088-B ct    -> 32 B   ML-KEM key share

Key loading (160-byte composite seed blob into an RSA slot via `OKSETPRIV 0x67`)
is done by the host CLI (`python-onlykey` `feature/pqc-composite`), not the browser.

**Host stack note:** this is the IETF OpenPGP-PQC format (matches Sequoia /
openpgp.js), NOT GnuPG's LibrePGP hybrid — GnuPG will not interoperate with these
keys. UNTESTED end-to-end; validate against a flashed device.
