# age / PQC scaffold for the OnlyKey web app (onlyagent)

Target repo: `0c-coder/onlykey.github.io`, branch `heroku-deploy`.
Goal: mirror the `age` PQC feature added in `trustcrypto/python-onlykey#90`
(+ firmware `trustcrypto/libraries#29`) in the browser WebCrypt/onlyagent app.

This is a **scaffold**: the JS-side encapsulation + age stanza format are real and
testable; the device round-trip (getpubkey / decapsulate over the FIDO2 keyhandle
path) has ONE integration decision that must be confirmed against the firmware —
flagged as `TODO(firmware)` below.

## What PQC means here
KEM (encryption), not signatures. Two key types:

| keytype            | id | pubkey | ciphertext | shared secret |
|--------------------|----|--------|-----------|---------------|
| `KEYTYPE_MLKEM768` | 5  | 1184 B | 1088 B    | 32 B          |
| `KEYTYPE_XWING`    | 6  | 1216 B | 1120 B    | 32 B          |

**No slots on the web path.** The OnlyKey has one reserved web-derivation key that
derives unlimited per-identity keys (the same mechanism the SSH/GPG/age agent
already uses). A key is named by a derivation LABEL (the identity), nothing is
stored on device, and the keypair is re-derived on demand from
(reserved key + label). So PQC reuses the existing derive flow, just with new
keytype bytes 5/6.

Existing derive flow (index.js), unchanged except keytype:
`encode_ctaphid_request_as_keyhandle(OKCONNECT=228, optype, keytype, enc_resp, data)`
- optype: `DERIVE_PUBLIC_KEY=1` (get pubkey), `DERIVE_SHARED_SECRET=2` (get 32-byte
  secret — KEM **decapsulation reuses this**, with the ciphertext as input)
- keytype: `NACL=0 P256R1=1 P256K1=2 CURVE25519=3` + `MLKEM768=5` `XWING=6`
- data: the identity keyhandle [+ KEM ciphertext for decapsulation]

Why the 32-byte derived secret carries over: per identity the device already
produces a 32-byte derived secret (for ECC that 32 bytes *is* the key).
- **X-Wing (6)**: its private key IS a 32-byte seed — the device SHAKE256-expands
  it into the ML-KEM-768 + X25519 keypair. Same 32 bytes the `CURVE25519` path
  derives, zero new key material. (X-Wing keeps an X25519 half, so it's literally
  your existing derived X25519 key + an ML-KEM key from the same seed.)
- **ML-KEM-768 (5)**: expand the 32-byte secret to ML-KEM's 64-byte `(d||z)` seed,
  then `KeyGen_internal`. Pin the exact expansion to #90 / firmware.

The **host runs encapsulation** (xwing.js, public key only); the **device only
decapsulates** after a button press. X-Wing combiner constants (from #90,
draft-connolly-cfrg-xwing-kem-09): `KEM_ID=0x647A`, `KDF_ID=0x0001`,
`AEAD_ID=0x0003`, label `5c2e2f2f5e5c`.

## Files in this scaffold
- `xwing.js` — ML-KEM-768 + X-Wing **encapsulation** and the age `mlkem768x25519`
  stanza helpers. Pure JS, no device needed. Unit-testable against #90 vectors.
- `onlykey-pqc.js` — device wrappers (`getPubKey`, `decapsulate`) built on the
  existing `onlykeyApi.ctaphid_via_webauthn` / `u2fSignBuffer` plumbing.
- `age-pqc.js` — the onlyagent plugin: export recipient, encrypt to a recipient,
  decrypt a file by asking the device to decapsulate.

## Install
```
npm install @noble/post-quantum @noble/curves @noble/hashes
```
(tweetnacl is already a dep and can supply X25519 if you prefer it over @noble/curves.)

## Where each file goes
- `xwing.js`        -> `src/onlykey-fido2/onlykey/xwing.js`
- `onlykey-pqc.js`  -> `src/onlykey-fido2/onlykey/onlykey-pqc.js`
- `age-pqc.js`      -> `src/plugins/age/age-pqc.js`  (+ an `age.page.html` like the
  other plugins, and register it in `src/plugins.js`)

## Edits to existing files
1. `src/onlykey-fido2/plugin.js`
   - add to `provides`: `"onlykeyPqc"`
   - `const onlykeyPqc = require('./onlykey/onlykey-pqc.js')(imports, onlykeyApi);`
   - `register(null, { ..., onlykeyPqc });`
2. `src/onlykey-fido2/onlykey/onlykey-pgp.js`
   - the binary `is_ecc` / `slotid()+100` scheme only distinguishes RSA vs ECC.
     PQC needs to carry (keytype, slot) explicitly — see `onlykey-pqc.js` and
     `TODO(firmware)` below. No change needed if PQC uses its own code path.
3. `package.json` — add the `@noble/*` deps above.
4. `docs/index.html` CSP — no change needed (all crypto is local; device I/O is
   WebAuthn, which CSP does not gate). Only touch CSP if you add new fetch origins.

## TODO(verify) — the remaining unknowns (no slot framing needed)
There's no slot to encode on the web path — it's the existing derive flow with
keytype 5/6 — so the earlier "slot byte" worry is gone. What still must be matched
to `python-onlykey#90` / firmware `libraries#29` (byte-exact ref:
`tests/test_age_wire.py`):
1. **deriveInput(label)** — reuse the agent's existing identity→keyhandle encoder
   (the derivation-path packing used for SSH/age identities); don't invent a new
   format.
2. **decapsulation op** — confirm KEM decaps uses `DERIVE_SHARED_SECRET=2` with the
   ciphertext appended to the derivation data (vs a dedicated optype), and that the
   32-byte secret returns with `ENCRYPT_RESP`.
3. **ML-KEM-768 seed expansion** — the device-side 32→64 byte `(d||z)` derivation
   for keytype 5 (X-Wing's 32-byte seed needs none).
4. **age stanza/recipient encoding + HPKE wrap** — match #90's `mlkem768x25519`
   stanza and the HPKE suite (`KEM 0x647A / KDF 0x0001 / AEAD 0x0003`).

## Test path
1. `npm install` + `bash BUILD.sh` builds to `docs/`.
2. Unit-test `xwing.js` encapsulation against #90's KAT/wire vectors (no device).
3. With a PQC-firmware OnlyKey: generate a key, export recipient, encrypt a file,
   decrypt it (device button press), diff plaintext.
