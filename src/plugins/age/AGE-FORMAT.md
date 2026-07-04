# age `mlkem768x25519` container format (browser)

`age-format.js` implements the age file container so the web app can produce and
consume `.age` files **without the `age` binary** (which the python plugin relies
on). The HPKE file‑key wrap and the recipient encoding are **byte‑identical to
python‑onlykey#90** (`age_plugin/{cli,protocol,xwing}.py`) — verified by frozen
known‑answer vectors in `test/age-format.test.mjs`, cross‑checked against the #90
Python during development.

## Recipient / identity
- Recipient string = `bech32("age1onlykey", pk)` where `pk` is the 1216‑byte
  X‑Wing public key (`pk_M(1184) || pk_X(32)`). Charset/checksum match #90's
  `cli.py`. (Identity is the OnlyKey derivation label, not a bech32 slot string —
  the web app has no slots.)

## Stanza
```
-> mlkem768x25519 <base64_nopad(enc)>      enc = 1120‑byte X‑Wing ct (ct_M||ct_X)
<base64_nopad(body)>                       body = 32‑byte HPKE‑sealed file key
```
Body wrapping and unpadded base64 follow #90's `Stanza.encode`.

## File‑key wrap — HPKE base (RFC 9180), X‑Wing KEM
Suite: **KEM 0x647A (X‑Wing) / KDF 0x0001 (HKDF‑SHA256) / AEAD 0x0003
(ChaCha20‑Poly1305)**. `kem_context = enc`; `info = ""`. The age **file key is 16
bytes**; sealed body = 16 + 16‑byte tag = 32 bytes.
- `seal = ChaCha20Poly1305(key).encrypt(base_nonce, file_key)` where `(key,
  base_nonce)` come from `KeyScheduleBase(ExtractAndExpand(ss, enc))`.
- The X‑Wing shared secret `ss` comes from the split‑custody decap (device X25519
  + browser ML‑KEM); combiner label is **last**:
  `SHA3-256(ss_M || ss_X || ct_X || pk_X || 0x5c2e2f2f5e5c)`.

## age v1 file (header + MAC + payload)
Standard age v1 (the part `age` normally does):
- Header = `age-encryption.org/v1\n` + stanzas + `---`.
- Header MAC = `HMAC-SHA256(HKDF(file_key, salt="", info="header"), header_through_"---")`,
  written as `--- <base64_nopad(mac)>`.
- Payload = 16‑byte random `nonce`, then ChaCha20‑Poly1305 **STREAM**: 64 KiB
  plaintext chunks, key = `HKDF(file_key, salt=nonce, info="payload")`, 12‑byte
  nonce = 11‑byte big‑endian chunk counter `||` last‑chunk flag (`0x01`/`0x00`).

## Wiring
`age-pqc.js` calls: `encodeRecipient` (export), `xwing.xwingEncapsulate` +
`sealFileKey` + `buildAgeFile` (encrypt), `parseAgeFile` +
`onlykeyPqc.decapsulate` + `openFileKey` + `openAgeFile` (decrypt).

## Tests (`test/age-format.test.mjs`, `npm run test:age`)
1. HPKE seal KAT == #90. 2. bech32 recipient KAT == #90 (+ round‑trip).
3. HPKE seal/open round‑trip. 4. age build/open round‑trip (multi‑chunk STREAM).
5. header‑MAC tamper rejection. (Full KEM↔container e2e also passes with the
shipped `xwing.js`.)

## Deps
`@noble/post-quantum @noble/curves @noble/hashes @noble/ciphers` (added to
`package.json`).
