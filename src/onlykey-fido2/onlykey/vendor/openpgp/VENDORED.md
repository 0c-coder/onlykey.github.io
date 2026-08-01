# Vendored openpgp.js (PQC-aware fork)

Unmodified copy, vendored directly into the source tree rather than pulled
in as an npm runtime dependency - same "push the official file into the
repo unmodified for verification, modify from there in git if needed"
principle already used for `../nacl.js`/`../forge.js`/
`../kbpgp-2.1.0.ok.ecc.js` and the `../@noble/` packages.

Needed for the composite PGP-PQC feature (ML-KEM-768 + ML-DSA-65 +
X25519 + Ed25519, maintainer TC-11): key generation, PGP message framing,
and the composite-KEM combine/AES-keywrap math for
`pqc_mlkem_x25519`/`pqc_mldsa_ed25519` (IETF OpenPGP-PQC draft algos 105/107).

## Provenance

This is **not** stock upstream OpenPGP.js - no release of real OpenPGP.js
supports the composite PQC algorithms yet. There is no "official pristine
upstream" to point at instead: this exact file (header: "OpenPGP.js v6.0.0
- 2026-07-06") is the project-specific fork already used by
`python-onlykey/onlykey/openpgp_bridge/bridge.js` (the Node bridge behind
the CLI's `onlykey-cli pgp` commands), so it's the right "official file"
to vendor per this project's principle.

Copied byte-for-byte, unmodified, from
`python-onlykey/onlykey/openpgp_bridge/openpgp.js` (confirmed via `diff`
at vendor time - identical).

## Why no webpack resolve.alias is needed

Unlike the `@noble/*` vendor packages, this is a single self-contained
UMD-style bundle (`var openpgp = (function (exports) {...})({})`) with
no external `require()`/`import` statements at all (confirmed via grep) -
it doesn't even depend on the `@noble/*` vendor tree, since the fork
implements its own PQC primitives internally. Load it like any other
same-directory vendored file (`nacl.js`/`forge.js`) - no build-config
changes required.

## Hardware-hook API (the reason this fork exists)

The fork adds a first-class, purpose-built hook API for routing
private-key operations to an external device instead of holding real key
material in the browser - confirmed via direct read, not assumed:

- `openpgp.setHardwareHooks({ signer, decryptor, ecdh, mlkemDecaps })` -
  registers one or more hooks (`openpgp.js:8747`). Each hook may return
  `null`/`undefined` to fall through to the software path.
- `openpgp.clearHardwareHooks()` - reverts to pure software (`:8753`).
- `openpgp.createHardwarePrivateKey(publicKey)` - builds a `PrivateKey`
  from a real `PublicKey` (correct fingerprint/key-id/algorithm) whose
  secret packets are marked "decrypted" with placeholder private params
  tagged `isHardwareBacked: true` (`:22197`). This is what lets normal
  `openpgp.decrypt()`/`sign()`/`verify()` calls transparently route through
  the hooks - no manual PGP-packet surgery needed on the app side.

`hooks.ecdh`/`hooks.mlkemDecaps` are gated on the `isHardwareBacked`
marker; `hooks.signer` fires unconditionally whenever registered. See
`composite_pgp.js` (sibling of this vendor dir's parent) for how this app
wires these hooks to the device transport.
