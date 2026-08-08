# Vendored @noble crypto packages

Unmodified copies, vendored directly into the source tree rather than
pulled in as npm runtime dependencies - same "push the official file into
the repo unmodified for verification, modify from there in git if needed"
principle already used for `../nacl.js`/`../forge.js`/`../kbpgp-2.1.0.ok.ecc.js`
in the parent directory.

Needed for the derived (label-based) X-Wing PQC feature (`../../age_pqc.js`,
`../../age_file.js`): ML-KEM-768 (post-quantum), SHA3-256/SHAKE256,
and ChaCha20-Poly1305 - none of which the already-vendored `forge.js`/`nacl.js`
provide (confirmed empirically, not assumed - see commit history /
`onlykey-testing/TEST-PLAN.md`'s TC-18/TC-19 notes).

`@noble/curves` is vendored too, but not for X25519 - `nacl.js` already
covers the X25519 operations this app's own code needs
(`nacl.scalarMult`/`nacl.scalarMult.base`/`nacl.randomBytes`), confirmed
by reading `onlykey-testing/lib/age_pqc.js`'s actual `x25519.*` call sites
before vendoring anything. It's required because `@noble/post-quantum`
has its own internal transitive dependency on it: `ml-kem.js` imports
`_crystals.js`, which imports `@noble/curves/abstract/fft.js` (used for
the NTT/polynomial math inside ML-KEM, unrelated to elliptic curves at
all - just a shared math utility the noble family happens to keep in the
`curves` package). Confirmed via a real webpack build - `_crystals.js`
failed to resolve until this was vendored and aliased.

## Provenance

Copied byte-for-byte from the exact versions already installed and proven
correct in `onlykey-testing` (`../../../../../onlykey-testing/node_modules/@noble/...`,
cross-checked against the Python reference implementation via
`onlykey-testing/test/fixtures/derived-xwing-vector.json` and
`onlykey-testing/test/05-age-pqc-derived.test.js`):

| Package             | Version | Source                                              |
|----------------------|---------|-----------------------------------------------------|
| `@noble/hashes`       | 2.2.0   | https://www.npmjs.com/package/@noble/hashes         |
| `@noble/post-quantum` | 0.6.1   | https://www.npmjs.com/package/@noble/post-quantum   |
| `@noble/ciphers`      | 2.2.0   | https://www.npmjs.com/package/@noble/ciphers        |
| `@noble/curves`       | 2.2.0   | https://www.npmjs.com/package/@noble/curves         |

Diffed identical against the npm-installed copies at vendor time (no
modifications). To re-verify: `npm pack @noble/hashes@2.2.0` (etc.), extract,
and `diff -r` against the corresponding folder here.

## Why webpack needs a small resolve alias

`@noble/post-quantum` imports `@noble/hashes/sha3.js` and `@noble/hashes/
utils.js` (from `ml-kem.js`) and `@noble/curves/abstract/fft.js` (from
`_crystals.js`, transitively via `ml-kem.js`) via bare specifiers -
`@noble/ciphers` and the rest of `@noble/hashes`/`@noble/curves` are each
internally self-contained (`@noble/curves`'s other cross-package imports
are all back into its own already-vendored/aliased `@noble/hashes`).
Since none of these packages are declared in `package.json`/installed via
npm, `webpack.config.js` has a `resolve.alias` entry pointing the
`@noble/hashes`, `@noble/post-quantum`, `@noble/ciphers`, and
`@noble/curves` bare specifiers at these vendored folders - the only
non-`src/`-tree change this required, and it doesn't touch the vendored
files themselves.
