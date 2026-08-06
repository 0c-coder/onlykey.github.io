# Vendored openpgp.js (PQC-aware fork)

Unmodified copy, vendored directly into the source tree rather than pulled
in as an npm runtime dependency - same "push the official file into the
repo unmodified for verification, modify from there in git if needed"
principle already used for `../nacl.js`/`../forge.js`/
`../kbpgp-2.1.0.ok.ecc.js` and the `../@noble/` packages.

Needed for the composite PGP-PQC feature (ML-KEM-768 + ML-DSA-65 +
X25519 + Ed25519, maintainer TC-11): key generation, PGP message framing,
and the composite-KEM combine/AES-keywrap math for
`pqc_mlkem_x25519`/`pqc_mldsa_ed25519`.

## LOCAL MODIFICATION: conformance with draft-ietf-openpgp-pqc-10 (2026-08-06)

**This copy is no longer byte-identical to the fork as received.** The
fork implemented an **earlier revision** of the PQC draft in three
places, and all three are corrected here. The revision now targeted is
**draft-ietf-openpgp-pqc-10**, named rather than called "the IETF draft" —
saying which revision is the whole point, because the previous version of
this note said "IETF OpenPGP-PQC draft algos 105/107" and that sentence,
being wrong and confident, is why nobody re-checked for months.

### 1. Algorithm codepoints (`enums.publicKey`)

| algorithm | was | now |
|---|---|---|
| `pqc_mldsa_ed25519` | 107 | **30** |
| `pqc_mlkem_x25519`  | 105 | **35** |

IANA's OpenPGP Public Key Algorithms registry assigns 30 and 35. 105 and
107 sit in the **private/experimental range** (100–110), which means "no
other implementation is expected to understand this".

### 2. ECC key share (`encaps$1` / `decaps$1`)

The X25519 key share **is the raw shared secret**. The fork hashed it as
`SHA3-256(ss ‖ ct ‖ recipientPub)` first.

### 3. Key combiner (`multiKeyCombine`)

```
KEK = SHA3-256( mlkemKeyShare ‖ ecdhKeyShare ‖ ecdhCipherText ‖
                ecdhPublicKey ‖ algId ‖ domSep ‖ len(domSep) )
```

The fork used `KMAC256` keyed on the two shares, over data that also
carried `mlkemCipherText` and `mlkemPublicKey`, with the domain separator
as the KMAC personalization. The ML-KEM ciphertext and public key are no
longer inputs at all.

### Why this had to happen before a release

None of it is a re-tagging. The algorithm ID is an input to the combiner,
and the combiner and key share determine the KEK — so keys and messages
made under the old scheme cannot be read under the new one, in either
direction. Correcting it after a release would orphan every key real
users had generated.

### What did NOT change

**Nothing on the device.** The firmware stores four raw seeds and returns
raw ML-KEM and X25519 shared secrets; it never sees an OpenPGP algorithm
ID, and every hash and combine happens host-side. `hooks.ecdh` fires
inside `recomputeSharedSecret()`, one level below the key-share layer, so
the device contract is untouched. Measured: the composite kit suites pass
unchanged against this tree.

Also unchanged: the composite **signature** path, which was already
conformant — only the codepoint was wrong there.

### Verified against an independent implementation

rpgp 0.20 (`draft-pqc`), Rust/RustCrypto, which has never seen this code.
All four directions pass — it parses the key, decrypts what we encrypt,
we decrypt what it encrypts, and it verifies our composite signatures.
Before these changes it could not parse our keys at all. Harness:
`onlykey/pqc-rust/interop/`. Background:
`onlykey-testing/FINDING-pqc-private-algorithm-ids.md`.

Keep this file and `python-onlykey/onlykey/openpgp_bridge/openpgp.js` in
step — they are required to stay **byte-identical** (verified by `md5sum`
at edit time), and `onlykey-testing/03-gui/05-composite-blob` is what
notices when the three codebases drift apart on the blob layout.

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
