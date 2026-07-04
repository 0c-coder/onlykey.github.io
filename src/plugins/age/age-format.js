// age-format.js -- age `mlkem768x25519` container framing for the OnlyKey web app.
// Byte-matches python-onlykey#90 (age_plugin/{cli,protocol,xwing}.py) + the age v1
// file format (str4d/age): bech32 recipient, HPKE file-key wrap, header MAC,
// ChaCha20-Poly1305 STREAM payload. Pure host code; the KEM lives in xwing.js.

'use strict';

const { chacha20poly1305 } = require('@noble/ciphers/chacha.js');
const { hmac } = require('@noble/hashes/hmac.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const { concatBytes, utf8ToBytes } = require('@noble/hashes/utils.js');

const FILE_KEY_LEN = 16;       // age v1 file key
const XWING_CT_LEN = 1120;     // stanza arg
const SEALED_BODY_LEN = 32;    // 16-byte file key + 16-byte AEAD tag
const RECIPIENT_HRP = 'age1onlykey';
const STANZA_TAG = 'mlkem768x25519';
const CHUNK = 65536;

const te = utf8ToBytes;
function u8(...b) { return Uint8Array.from(b); }
function b64(bytes) { return Buffer.from(bytes).toString('base64').replace(/=+$/, ''); }
function unb64(str) { return Uint8Array.from(Buffer.from(str, 'base64')); }
function eq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
function indexOfSub(buf, sub, from) {
  outer: for (let i = from || 0; i <= buf.length - sub.length; i++) {
    for (let j = 0; j < sub.length; j++) if (buf[i + j] !== sub[j]) continue outer;
    return i;
  }
  return -1;
}

// ---- bech32 (port of cli.py) --------------------------------------------
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) chk ^= ((b >>> i) & 1) ? GEN[i] : 0;
  }
  return chk >>> 0;
}
function hrpExpand(hrp) {
  const o = [];
  for (const c of hrp) o.push(c.charCodeAt(0) >> 5);
  o.push(0);
  for (const c of hrp) o.push(c.charCodeAt(0) & 31);
  return o;
}
function createChecksum(hrp, data) {
  const values = hrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ 1;
  const out = [];
  for (let i = 0; i < 6; i++) out.push((mod >>> (5 * (5 - i))) & 31);
  return out;
}
function verifyChecksum(hrp, data) { return polymod(hrpExpand(hrp).concat(data)) === 1; }
function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0; const ret = []; const maxv = (1 << to) - 1;
  for (const value of data) {
    if (value < 0 || (value >> from)) return null;
    acc = (acc << from) | value; bits += from;
    while (bits >= to) { bits -= to; ret.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits) ret.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) return null;
  return ret;
}
function bech32Encode(hrp, data) {
  const values = convertBits(Array.from(data), 8, 5, true);
  const chk = createChecksum(hrp, values);
  return hrp + '1' + values.concat(chk).map((d) => CHARSET[d]).join('');
}
function bech32Decode(bech) {
  bech = bech.toLowerCase();
  const pos = bech.lastIndexOf('1');
  if (pos < 1 || pos + 7 > bech.length) return [null, null];
  const hrp = bech.slice(0, pos);
  const data = [];
  for (const ch of bech.slice(pos + 1)) { const d = CHARSET.indexOf(ch); if (d === -1) return [null, null]; data.push(d); }
  if (!verifyChecksum(hrp, data)) return [null, null];
  const decoded = convertBits(data.slice(0, -6), 5, 8, false);
  if (decoded === null) return [null, null];
  return [hrp, Uint8Array.from(decoded)];
}

function encodeRecipient(pk) {
  if (pk.length !== 1216) throw new Error('recipient pubkey must be 1216 bytes, got ' + pk.length);
  return bech32Encode(RECIPIENT_HRP, pk);
}
function decodeRecipient(str) {
  const [hrp, data] = bech32Decode(String(str));
  if (hrp !== RECIPIENT_HRP || !data) throw new Error('invalid OnlyKey recipient: ' + str);
  if (data.length !== 1216) throw new Error('recipient must decode to 1216 bytes, got ' + data.length);
  return data;
}

// ---- HPKE base (X-Wing KEM / HKDF-SHA256 / ChaCha20-Poly1305), port of xwing.py
const SUITE_KEM = concatBytes(te('KEM'), u8(0x64, 0x7a));
const SUITE_HPKE = concatBytes(te('HPKE'), u8(0x64, 0x7a, 0x00, 0x01, 0x00, 0x03));
function i2osp(n, len) { const b = new Uint8Array(len); let x = n; for (let i = len - 1; i >= 0; i--) { b[i] = x & 0xff; x = Math.floor(x / 256); } return b; }
function hkdfExtract(salt, ikm) { if (!salt || salt.length === 0) salt = new Uint8Array(32); return hmac(sha256, salt, ikm); }
function hkdfExpand(prk, info, len) {
  const n = Math.ceil(len / 32); let t = new Uint8Array(0); const out = [];
  for (let i = 1; i <= n; i++) { t = hmac(sha256, prk, concatBytes(t, info, u8(i))); out.push(t); }
  return concatBytes(...out).slice(0, len);
}
function labeledExtract(salt, label, ikm, suite) { return hkdfExtract(salt, concatBytes(te('HPKE-v1'), suite, label, ikm)); }
function labeledExpand(prk, label, info, len, suite) { return hkdfExpand(prk, concatBytes(i2osp(len, 2), te('HPKE-v1'), suite, label, info), len); }
function extractAndExpand(ss, kemCtx) {
  const prk = labeledExtract(new Uint8Array(0), te('shared_secret'), ss, SUITE_KEM);
  return labeledExpand(prk, te('context'), kemCtx, 32, SUITE_KEM);
}
function keyScheduleBase(ss, info) {
  const pih = labeledExtract(new Uint8Array(0), te('psk_id_hash'), new Uint8Array(0), SUITE_HPKE);
  const ih = labeledExtract(new Uint8Array(0), te('info_hash'), info, SUITE_HPKE);
  const ksCtx = concatBytes(u8(0), pih, ih);
  const secret = labeledExtract(ss, te('secret'), new Uint8Array(0), SUITE_HPKE);
  const key = labeledExpand(secret, te('key'), ksCtx, 32, SUITE_HPKE);
  const baseNonce = labeledExpand(secret, te('base_nonce'), ksCtx, 12, SUITE_HPKE);
  return { key, baseNonce };
}
function sealFileKey(ss, enc, fileKey, info) {
  const hss = extractAndExpand(ss, enc);
  const { key, baseNonce } = keyScheduleBase(hss, info || new Uint8Array(0));
  return chacha20poly1305(key, baseNonce).encrypt(fileKey); // 32 bytes
}
function openFileKey(ss, enc, body, info) {
  const hss = extractAndExpand(ss, enc);
  const { key, baseNonce } = keyScheduleBase(hss, info || new Uint8Array(0));
  return chacha20poly1305(key, baseNonce).decrypt(body); // 16 bytes
}

// ---- age stanza ---------------------------------------------------------
function encodeStanza(tag, args, body) {
  let line = '-> ' + [tag].concat(args).join(' ') + '\n';
  const e = b64(body);
  const lines = [];
  for (let i = 0; i < e.length; i += 64) lines.push(e.slice(i, i + 64));
  if (lines.length && lines[lines.length - 1].length === 64) lines.push('');
  return line + lines.join('\n') + '\n';
}

// ---- age v1 STREAM payload ----------------------------------------------
function streamNonce(counter, last) {
  const n = new Uint8Array(12); let c = counter;
  for (let i = 10; i >= 0; i--) { n[i] = c & 0xff; c = Math.floor(c / 256); }
  n[11] = last ? 1 : 0;
  return n;
}
function streamEncrypt(key, pt) {
  const out = []; const n = Math.max(1, Math.ceil(pt.length / CHUNK));
  for (let i = 0; i < n; i++) {
    const chunk = pt.slice(i * CHUNK, (i + 1) * CHUNK);
    out.push(chacha20poly1305(key, streamNonce(i, i === n - 1)).encrypt(chunk));
  }
  return concatBytes(...out);
}
function streamDecrypt(key, body) {
  const EC = CHUNK + 16; const out = []; let off = 0, i = 0;
  for (;;) {
    const remaining = body.length - off;
    const last = remaining <= EC;
    const clen = last ? remaining : EC;
    out.push(chacha20poly1305(key, streamNonce(i, last)).decrypt(body.slice(off, off + clen)));
    off += clen; i++;
    if (last) break;
  }
  return concatBytes(...out);
}

// ---- age file (header + MAC + payload) ----------------------------------
function hkdf(fileKey, salt, info) {
  const prk = hkdfExtract(salt, fileKey);
  return hkdfExpand(prk, info, 32);
}
function randomBytes(n) {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
    const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b;
  }
  return require('crypto').randomBytes(n);
}
function buildAgeFile(stanzas, fileKey, plaintext, nonce16) {
  let header = 'age-encryption.org/v1\n';
  for (const s of stanzas) header += encodeStanza(s.tag, s.args, s.body);
  header += '---';
  const macKey = hkdf(fileKey, new Uint8Array(0), te('header'));
  const mac = hmac(sha256, macKey, te(header));
  const headerFull = header + ' ' + b64(mac) + '\n';
  const nonce = nonce16 || randomBytes(16);
  const payloadKey = hkdf(fileKey, Uint8Array.from(nonce), te('payload'));
  const payload = streamEncrypt(payloadKey, plaintext);
  return concatBytes(te(headerFull), Uint8Array.from(nonce), payload);
}
function parseAgeFile(bytes) {
  const dashIdx = indexOfSub(bytes, te('\n---'), 0); // "\n---"
  if (dashIdx < 0) throw new Error('age: no header MAC line');
  const macInput = bytes.slice(0, dashIdx + 4);       // through "---"
  const nlIdx = indexOfSub(bytes, te('\n'), dashIdx + 4);
  if (nlIdx < 0) throw new Error('age: truncated MAC line');
  const macVal = unb64(Buffer.from(bytes.slice(dashIdx + 5, nlIdx)).toString('latin1')); // skip space at +4
  const headerText = Buffer.from(bytes.slice(0, dashIdx)).toString('latin1');
  const payload = bytes.slice(nlIdx + 1);
  const nonce = payload.slice(0, 16);
  const ciphertext = payload.slice(16);
  // parse stanzas
  const lines = headerText.split('\n');
  if (lines[0] !== 'age-encryption.org/v1') throw new Error('age: bad version line');
  const stanzas = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].startsWith('-> ')) continue;
    const parts = lines[i].slice(3).split(' ');
    const tag = parts[0], args = parts.slice(1);
    const bodyLines = [];
    let j = i + 1;
    for (; j < lines.length; j++) {
      if (lines[j].length === 64) { bodyLines.push(lines[j]); }
      else { if (lines[j].length) bodyLines.push(lines[j]); break; }
    }
    stanzas.push({ tag, args, body: bodyLines.length ? unb64(bodyLines.join('')) : new Uint8Array(0) });
    i = j;
  }
  return { stanzas, macInput, macVal, nonce, ciphertext };
}
function openAgeFile(bytes, fileKey) {
  const p = parseAgeFile(bytes);
  const macKey = hkdf(fileKey, new Uint8Array(0), te('header'));
  const mac = hmac(sha256, macKey, p.macInput);
  if (!eq(mac, p.macVal)) throw new Error('age: header MAC verification failed');
  const payloadKey = hkdf(fileKey, p.nonce, te('payload'));
  return streamDecrypt(payloadKey, p.ciphertext);
}

module.exports = {
  FILE_KEY_LEN, XWING_CT_LEN, SEALED_BODY_LEN, STANZA_TAG,
  encodeRecipient, decodeRecipient,
  sealFileKey, openFileKey,
  encodeStanza, buildAgeFile, parseAgeFile, openAgeFile,
  bech32Encode, bech32Decode,
  randomBytes, b64, unb64,
};
