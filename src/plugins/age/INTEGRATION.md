# Web-app PQC over the FIDO2 derive path — pinned spec

**Scope:** X-Wing (`mlkem768x25519`) age encryption for the OnlyKey web app
(`onlykey.github.io`) over the existing FIDO2/CTAP keyhandle derive flow
(`fido2/ok_extension.cpp`), plus the small firmware primitive it needs.
**Out of scope:** the CLI slot-based model (`python-onlykey#90` / firmware
`#29`) — it is a separate, intentionally-incompatible custody model and is NOT
addressed here.

## 1. Model — split X-Wing custody

X-Wing decapsulation is:

```
ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWingLabel )
  ss_M = ML-KEM-768.Decaps(sk_M, ct_M)     # ct_M = 1088 B
  ss_X = X25519(sk_X, ct_X)                # ct_X = 32 B   (this is ECDH)
  XWingLabel = 0x5c 2e 2f 2f 5e 5c         # draft-connolly-cfrg-xwing-kem-09
```

Custody split:
- **X25519 half stays on the device.** `sk_X` is label-derived; the device
  computes `ss_X` and never releases `sk_X`. (Exactly today's `DERIVE_SHAREDSEC`.)
- **ML-KEM half runs in the browser.** The device hands the browser a 32-byte
  `mlkem_seed`; the browser expands it to `sk_M`, decapsulates the 1088-byte
  `ct_M` locally, and never sends `ct_M` to the device.

Every device round-trip is ≤ 64 bytes. Decryption requires the OnlyKey (no
`ss_X` without it). The recipient string is a **standard** X-Wing pubkey — only
private-key custody is split, so standard age encryptors interoperate.

## 2. Constants

```
KEYTYPE_MLKEM768 = 5           # firmware okcore.h
KEYTYPE_XWING    = 6
# Wire keytype in the keyhandle follows the existing "+1" convention
# (firmware bridge_to_onlykey does opt2++), so:
WIRE_KEYTYPE_XWING = KEYTYPE_XWING - 1 = 5     # NACL=0,P256R1=1,P256K1=2,CURVE25519=3,XWING=5
sizes:  pk_M 1184 | pk_X 32 | pk 1216 | ct_M 1088 | ct_X 32 | ct 1120 | ss 32 | seed 32
HPKE (unchanged, from #90): KEM_ID 0x647A | KDF_ID 0x0001 | AEAD_ID 0x0003
```

## 3. Key derivation (firmware) — MUST be domain-separated

`sk_X` is already `HKDF(web_derivation_key, label_data)` (the existing
`okcrypto_derive_key(KEYTYPE_CURVE25519, additional_data, RESERVED_KEY_WEB_DERIVATION)`).
Derive the ML-KEM seed **one-way from `sk_X`** so it can never leak `sk_X`:

```
mlkem_seed = HKDF-SHA256(
    IKM  = sk_X,                       # the label-derived X25519 private
    salt = "",                         # (empty)
    info = "onlykey/xwing/mlkem768-seed/v1",
    L    = 32
)
```

Properties:
- `mlkem_seed` depends only on `sk_X`, i.e. only on `(web_derivation_key, label)`
  — **constant per label**, independent of the per-message `ct_X`. So `pk_M`
  (and the recipient string) is stable.
- HKDF is one-way, so a browser holding `mlkem_seed` learns nothing about `sk_X`.
- `mlkem_seed != sk_X` by construction (distinct `info`), so returning it never
  discloses the X25519 private.

> Alternative (equivalent): derive both independently from
> `web_derivation_key` with `info="…/x25519/v1"` and `info="…/mlkem768-seed/v1"`.
> Either is fine; pick one and pin it.

## 4. Firmware change (`fido2/ok_extension.cpp`, `bridge_to_onlykey`)

Add an X-Wing branch to the derive dispatch (the `opt2 == KEYTYPE_*` block,
~lines 214–229) and to `DERIVE_SHAREDSEC` (~243–287):

**DERIVE_PUBLIC_KEY, keytype X-Wing** → return 64 bytes:
```
[ pk_X (32) ][ mlkem_seed (32) ]
   pk_X       = Curve25519 public of the label-derived sk_X   (existing)
   mlkem_seed = HKDF(sk_X, "onlykey/xwing/mlkem768-seed/v1")
```
(No user presence required — public material only.)

**DERIVE_SHAREDSEC, keytype X-Wing** → input `ct_X` (the 32-byte X25519 ephemeral
from the age stanza), return 64 bytes:
```
[ ss_X (32) ][ mlkem_seed (32) ]
   ss_X       = okcrypto_shared_secret(ct_X, sk_X)   (existing ECDH)
   mlkem_seed = HKDF(sk_X, "onlykey/xwing/mlkem768-seed/v1")
```
Use `DERIVE_SHAREDSEC_REQ_PRESS` (button) for actual decryption.

Both responses go out via `send_transport_response(..., opt3, ...)` with
`opt3 = ENCRYPT_RESP`, so the 64 bytes are AES-encrypted under the per-session
`transit_key` established at OKCONNECT (ECDH → SHA-256). `sk_X`, `sk_M`, and
`web_derivation_key` never leave the device.

## 5. Wire format

Request keyhandle (existing layout, `bridge_to_onlykey`):
```
keyh[0]      = OKCONNECT bridge cmd
keyh[1]=opt1 = DERIVE_PUBLIC_KEY(1) | DERIVE_SHAREDSEC(2) | *_REQ_PRESS(3/4)
keyh[2]=opt2 = WIRE_KEYTYPE_XWING (5)      # firmware opt2++ -> KEYTYPE_XWING(6)
keyh[3]=opt3 = ENCRYPT_RESP (1)
client_handle+9      = app transit public (32)   # OKCONNECT session
client_handle+43     = label_data (32)           # identity/derivation input
client_handle+43+32  = input_pubkey = ct_X (32)  # only for DERIVE_SHAREDSEC
```
Response (encrypted under `transit_key`): the 64-byte payload above.

## 6. Browser (`onlykey.github.io`)

**Recipient / identity (once):**
```
(pk_X, mlkem_seed) = device.DERIVE_PUBLIC_KEY(label, XWING)
seed64             = SHAKE256(mlkem_seed, 64)          # (d||z) for ML-KEM
{ pk_M, _ }        = ml_kem768.keygen(seed64)          # noble keygen_internal
recipient          = encodeRecipient( pk_M || pk_X )   # standard mlkem768x25519
```

**Encrypt** (no device): standard X-Wing `Encaps(recipientPk)` — already in
`xwing.js`.

**Decrypt a stanza** `-> mlkem768x25519 <b64(ct)>` where `ct = ct_M(1088)||ct_X(32)`:
```
(ss_X, mlkem_seed) = device.DERIVE_SHAREDSEC_REQ_PRESS(label, XWING, ct_X)  # button
seed64  = SHAKE256(mlkem_seed, 64)
{ _, sk_M } = ml_kem768.keygen(seed64)
ss_M    = ml_kem768.decapsulate(ct_M, sk_M)            # 1088 B stays in browser
ss      = SHA3-256( ss_M || ss_X || ct_X || pk_X || 0x5c2e2f2f5e5c )
file_key = HPKE-open(ss, ct, aead_body)               # KEM 0x647A/KDF 0x0001/AEAD 0x0003
```
`ct_M` never leaves the browser; only the 32-byte `ct_X` goes to the device.

## 7. Pinned — must match byte-exactly (firmware ⇄ browser)

1. `mlkem_seed = HKDF-SHA256(sk_X, info="onlykey/xwing/mlkem768-seed/v1", L=32)`.
2. `sk_X` = the existing `RESERVED_KEY_WEB_DERIVATION` Curve25519 derivation.
3. ML-KEM seed expansion: `SHAKE256(mlkem_seed, 64)` → ML-KEM `keygen_internal`.
4. X-Wing combiner: `SHA3-256(ss_M||ss_X||ct_X||pk_X||0x5c2e2f2f5e5c)` (draft-09).
5. HPKE suite `0x647A / 0x0001 / 0x0003`; stanza tag `mlkem768x25519`.
6. Wire keytype byte = 5 (→ `KEYTYPE_XWING` after `opt2++`).
7. 64-byte response order: `[first-32][second-32]` = `[ss_X|pk_X][mlkem_seed]`.

## 8. Security posture

- **Classical security is device-bound.** No decryption without the OnlyKey:
  `ss_X` requires `sk_X`, which never leaves. Browser compromise + `mlkem_seed`
  alone cannot decrypt.
- **Post-quantum security is device-gated.** `mlkem_seed` lives in the browser
  only while the OnlyKey is connected/unlocked for that origin (the existing
  WebCrypt "private web" posture). A browser fully compromised *while unlocked*
  can harvest `mlkem_seed`; that is the accepted trade for browser PQC.
- `web_derivation_key` and `sk_X` never leave the device; `mlkem_seed` is
  one-way-separated from `sk_X`.
