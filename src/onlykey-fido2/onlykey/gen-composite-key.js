/**
 * gen-composite-key.js — generate an IETF OpenPGP-PQC composite key and emit the
 * 160-byte OnlyKey seed blob + armored public key for testing.
 *
 *   node gen-composite-key.js ./openpgp.js  "Name <email>"
 *
 * Output: writes composite-pubkey.asc (import into the web app / recipients) and
 * prints the 160-byte blob hex to load with:  onlykey-cli setpqc RSA1 <hex>
 *
 * Blob layout (matches onlykey/pqc.py + okpqc.h):
 *   [0:32]   Ed25519 secret     (sign, ecc half)   <- primary  privateParams.eccSecretKey
 *   [32:64]  ML-DSA-65 seed     (sign, pqc half)   <- primary  privateParams.mldsaSeed
 *   [64:96]  X25519 secret      (decrypt, ecc half)<- subkey   privateParams.eccSecretKey
 *   [96:160] ML-KEM-768 seed    (decrypt, pqc half)<- subkey   privateParams.mlkemSeed
 */
const fs = require('fs');
const path = require('path');
// The bundle is a browser IIFE (`var openpgp = (function(){...})()`), not CommonJS.
// Try require() first; fall back to eval-loading the IIFE and capturing `openpgp`.
function loadOpenPGP(p) {
  let m;
  try { m = require(p); } catch (e) { m = null; }
  if (m && typeof m.generateKey === 'function') return m;
  const code = fs.readFileSync(p, 'utf8');
  return new Function(code + '\n;return openpgp;')();
}
const openpgp = loadOpenPGP(path.resolve(process.argv[2] || './openpgp.js'));

const uid = process.argv[3] || 'OnlyKey PQC Test <pqc@onlykey.io>';
const m = uid.match(/^(.*?)\s*<(.+?)>\s*$/);
const userIDs = [ m ? { name: m[1], email: m[2] } : { name: uid } ];

function hex(u8) { return Buffer.from(u8).toString('hex'); }
function need(u8, n, label) {
  if (!u8) throw new Error('missing ' + label);
  if (u8.length !== n) throw new Error(label + ' must be ' + n + ' bytes, got ' + u8.length);
  return Buffer.from(u8);
}

(async () => {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'pqc', userIDs, format: 'armored', config: { v6Keys: true }
  });

  const priv = await openpgp.readKey({ armoredKey: privateKey });
  const primary = priv.keyPacket;                       // pqc_mldsa_ed25519
  const subkey  = priv.subkeys[0].keyPacket;            // pqc_mlkem_x25519
  const pp = primary.privateParams, sp = subkey.privateParams;

  const ed25519  = need(pp.eccSecretKey, 32, 'primary eccSecretKey (Ed25519)');
  const mldsa    = need(pp.mldsaSeed,    32, 'primary mldsaSeed');
  const x25519   = need(sp.eccSecretKey, 32, 'subkey eccSecretKey (X25519)');
  const mlkem    = need(sp.mlkemSeed,    64, 'subkey mlkemSeed');

  const blob = Buffer.concat([ed25519, mldsa, x25519, mlkem]);
  if (blob.length !== 160) throw new Error('blob is ' + blob.length + ' bytes, expected 160');

  fs.writeFileSync('composite-pubkey.asc', publicKey);
  fs.writeFileSync('composite-privkey.asc', privateKey);
  fs.writeFileSync('composite-blob.hex', blob.toString('hex') + '\n');

  console.log('fingerprint :', priv.getFingerprint());
  console.log('primary algo:', primary.algorithm, ' subkey algo:', subkey.algorithm);
  console.log('blob (160B) :', blob.toString('hex'));
  console.log('\nwrote composite-pubkey.asc, composite-privkey.asc, composite-blob.hex');
  console.log('load with   : onlykey-cli setpqc RSA1 composite-blob.hex');
})().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
