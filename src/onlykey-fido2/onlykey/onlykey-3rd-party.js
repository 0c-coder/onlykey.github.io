module.exports = function(imports, onlykeyApi) {
    /* global TextEncoder */
    // var $ = require("jquery");
    var nacl = imports.nacl;
    var forge = imports.forge;
    var EventEmitter = require("events").EventEmitter;
    
    var console = imports.console;

    var extras = require("./onlykey.extra.js")(imports);
    var {
        // wait,
        async_sha256,
        hexStrToDec,
        bytes2string,
        // noop,
        // getstringlen,
        // mkchallenge,
        bytes2b64,
        // getOS,
        // ctap_error_codes,
        // getAllUrlParams,
        aesgcm_decrypt,
        // Needed by the composite_sign/composite_decrypt payload encryption
        // below; was commented out while nothing in this file sent encrypted
        // data to the device.
        aesgcm_encrypt,
        digestBuff,
        digestArray,
        arrayBufToBase64UrlDecode,
        arrayBufToBase64UrlEncode,
    } = extras;

    var window = imports.window;

    var OKCMD = {
        OKCONNECT: 228
    };

    var KEYTYPE = {
        NACL: 0,
        P256R1: 1, //encrypt/decrypt
        P256K1: 2, //sign/verify
        CURVE25519: 3
    };

    var KEYACTION = {
        DERIVE_PUBLIC_KEY: 1,
        DERIVE_SHARED_SECRET: 2,
        DERIVE_PUBLIC_KEY_REQ_PRESS: 3,
        DERIVE_SHARED_SECRET_REQ_PRESS: 4
    };

    // Uint8Array.from() is NOT a string encoder. Given a string it treats it as
    // an iterable of characters and coerces each with Number(), which is NaN
    // for any letter and stores as 0 - so every passphrase collapsed to a run
    // of zero bytes whose only distinguishing feature was its LENGTH, and two
    // different passphrases of equal length derived the SAME key. Confirmed
    // three ways (language level, Node shim against the device, and the real
    // browser page): "spike-label" and "other-label" produced an identical
    // derived key, while a different-length control differed.
    //
    // password-generator.js and vault.js both pass $("#phrase").val() straight
    // in, so this was directly user-facing. Encoding the text properly changes
    // every previously derived key; the maintainer has confirmed that is
    // acceptable because nothing depends on those keys yet.
    function derivationInputBytes(additional_d) {
        if (typeof additional_d === 'string') return new TextEncoder().encode(additional_d);
        return Uint8Array.from(additional_d);
    }

    function decode_key(b64_key) {
        var key = b64_key.split(".");

        if (key.length == 2) {
            return Uint8Array.from([].concat([0x04], arrayBufToBase64UrlDecode(key[0]), arrayBufToBase64UrlDecode(key[1])));
        }
        else {
            return arrayBufToBase64UrlDecode(b64_key);
        }
    }

    function encode_key(uint8array_key) {
        if (uint8array_key.length == 32) {
            return arrayBufToBase64UrlEncode(uint8array_key);
        }
        else if (uint8array_key.length == 65) {
            if (uint8array_key[0] == 0x04)
                return arrayBufToBase64UrlEncode(uint8array_key.slice(1, 33)) + "." + arrayBufToBase64UrlEncode(uint8array_key.slice(33, 66));

        }
        throw "Unknown Key Type to Encode";
    }

    function build_AESGCM(raw_secret) {
        return new Promise(async resolve => {
            var derivedKey = await window.crypto.subtle.importKey('raw', Uint8Array.from(raw_secret), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
            resolve(await window.crypto.subtle.exportKey('jwk', derivedKey).then(({ k }) => k));
        });
    }

    function EPUB_TO_ONLYKEY_ECDH_P256(ePub, callback) {
        var xdecoded = arrayBufToBase64UrlDecode(ePub.split(".")[0]);
        var ydecoded = arrayBufToBase64UrlDecode(ePub.split(".")[1]);
        
        var publicKeyRawBuffer = Uint8Array.from([].concat(Array.from(xdecoded)).concat(Array.from(ydecoded)).concat([4]));
        
        if (callback)
            callback(publicKeyRawBuffer);
            
        return publicKeyRawBuffer;
        /*
        var publicKeyRawBuffer = new Uint8Array(65);
        var h = -1;
        for (var i in xdecoded) {
            h++;
            publicKeyRawBuffer[h] = xdecoded[i];
        }
        for (var j in ydecoded) {
            h++;
            publicKeyRawBuffer[h] = ydecoded[j];
        }

        if (publicKeyRawBuffer[0] == 0) {
            publicKeyRawBuffer = Array.from(publicKeyRawBuffer)
            publicKeyRawBuffer.unshift()
            publicKeyRawBuffer = Uint8Array.from(publicKeyRawBuffer);
        }
        console.log("epub to raw", ePub, publicKeyRawBuffer)
        if (callback)
            callback(publicKeyRawBuffer)

        return publicKeyRawBuffer;
        */
    }

    async function ONLYKEY_ECDH_P256_to_EPUB(publicKeyRawBuffer, callback) {
        //https://stackoverflow.com/questions/56846930/how-to-convert-raw-representations-of-ecdh-key-pair-into-a-json-web-key

        //
        var orig_publicKeyRawBuffer = Uint8Array.from(publicKeyRawBuffer);

        //console.log("publicKeyRawBuffer  B", publicKeyRawBuffer)
        // publicKeyRawBuffer = Array.from(publicKeyRawBuffer)
        // publicKeyRawBuffer.unshift(publicKeyRawBuffer.pop());
        // publicKeyRawBuffer = Uint8Array.from(publicKeyRawBuffer)

        //console.log("publicKeyRawBuffer  F", publicKeyRawBuffer)

        if (false) {
            var $importedPubKey = await imports.window.crypto.subtle.importKey(
                'raw', orig_publicKeyRawBuffer, {
                    name: 'ECDH',
                    namedCurve: 'P-256'
                },
                true, []
            ).catch(function(err) {
                console.error(err);
            }).then(function(importedPubKey) {
                exportKey(importedPubKey)
            });
        }
        else {
            var x = publicKeyRawBuffer.slice(1, 33);
            var y = publicKeyRawBuffer.slice(33, 66);

            imports.window.crypto.subtle.importKey(
                'jwk', {
                    kty: "EC",
                    crv: "P-256",
                    x: arrayBufToBase64UrlEncode(x),
                    y: arrayBufToBase64UrlEncode(y)
                }, {
                    name: 'ECDH',
                    namedCurve: 'P-256'
                },
                true, []
            ).catch(function(err) {
                console.error(err);
            }).then(function(importedPubKey) {
                if (importedPubKey)
                    exportKey(importedPubKey)
            });
        }

        function exportKey(importedPubKey) {

            window.crypto.subtle.exportKey(
                    "jwk", //can be "jwk" (public or private), "raw" (public only), "spki" (public only), or "pkcs8" (private only)
                    importedPubKey //can be a publicKey or privateKey, as long as extractable was true
                )
                .then(function(keydata) {

                    var OK_SEA_epub = keydata.x + '.' + keydata.y;

                    console.log("raw to epub", OK_SEA_epub, orig_publicKeyRawBuffer)

                    if (callback)
                        callback(OK_SEA_epub);

                })
                .catch(function(err) {
                    console.error(err);
                });

        }

    }

    function onlykey() {

        var api = new EventEmitter();

        var appKey;

        api.connect = async function(cb) {
            var delay = 0;


            console.log("-------------------------------------------");
            // msg("Requesting OnlyKey Secure Connection (" + getOS() + ")");
            api.emit("status", "Requesting OnlyKey Secure Connection");

            var cmd = OKCMD.OKCONNECT;

            var message = [255, 255, 255, 255, OKCMD.OKCONNECT]; //Add header and message type
            var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
            var timePart = currentEpochTime.match(/.{2}/g).map(hexStrToDec);
            Array.prototype.push.apply(message, timePart);
            appKey = nacl.box.keyPair();
            Array.prototype.push.apply(message, appKey.publicKey);
            var env = [onlykeyApi.browser.charCodeAt(0), onlykeyApi.os.charCodeAt(0)];
            Array.prototype.push.apply(message, env);
            var encryptedkeyHandle = Uint8Array.from(message); // Not encrypted as this is the initial key exchange

            var enc_resp = 1;
            await onlykeyApi.ctaphid_via_webauthn(cmd, null, null, null, encryptedkeyHandle, 6000).then(async(response) => {

                if (!response.data) {
                    // msg("Problem setting time on onlykey");
                    api.emit("status", "Problem setting time on onlykey");
                    return;
                }
                response = response.data;

                var okPub = response.slice(0, 32);
                console.info("Onlykey transit public", okPub);
                
                var encrypted_response = false;
                if (enc_resp == 1) {
                    // Decrypt with transit_key
                    var transit_key = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);
                    console.info("Onlykey transit public", okPub);
                    console.info("App transit public", appKey.publicKey);
                    console.info("Transit shared secret", transit_key);
                    transit_key = await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                    console.info("AES Key", transit_key);
                    var encrypted = response.slice(32, response.length);
                    encrypted_response = await aesgcm_decrypt(encrypted, transit_key);
                }
                
                //   transit_key = await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                //   console.info("App AES Key", transit_key);
                //   var encrypted  = response.slice(32, response.length);
                //   onlykey_api.FWversion = bytes2string(response.slice(32+8, 32+20));
                //   response = await aesgcm_decrypt(encrypted, transit_key);
                //   onlykey_api.OKversion = response[32+19] == 99 ? 'Color' : 'Go';

                var FWversion = bytes2string(response.slice(32 + 8, 32 + 19));
                var OKversion = response[32 + 19] == 99 ? 'Color' : 'Go';
                var sharedsec = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);

                //msg("message -> " + message)
                // msg("OnlyKey " + OKversion + " " + FWversion + " connection established\n");
                api.emit("status", "OnlyKey: Connection Established, Hardware "+OKversion+", Firmware " + FWversion + ", Time Set!");

                async_sha256(sharedsec).then((key) => {
                    console.log("AES Key", bytes2b64(key));
                    if (typeof cb === 'function') cb(null);
                });
            });


        }

        api.derive_public_key = async function(additional_d, keytype, press_required, cb) {

            console.log("-------------------------------------------");
            // msg("Requesting OnlyKey Derive Public Key");
            api.emit("status", "OnlyKey: Requesting Derived Public Key");

            var cmd = OKCMD.OKCONNECT;
            //Add header and message type
            var message = [255, 255, 255, 255, OKCMD.OKCONNECT];

            //Add current epoch time
            var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
            var timePart = currentEpochTime.match(/.{2}/g).map(hexStrToDec);
            Array.prototype.push.apply(message, timePart);

            //Add transit pubkey
            appKey = nacl.box.keyPair();
            Array.prototype.push.apply(message, appKey.publicKey);

            //Add Browser and OS codes
            var env = [onlykeyApi.browser.charCodeAt(0), onlykeyApi.os.charCodeAt(0)];
            Array.prototype.push.apply(message, env);

            //Add additional data for key derivation
            var dataHash;
            if (!additional_d) {
                // SHA256 hash of empty buffer
                dataHash = await digestArray(Uint8Array.from(new Uint8Array(32)));
            }
            else {
                // SHA256 hash of input data
                dataHash = await digestArray(derivationInputBytes(additional_d)); //sha256 = 32 bytes
            }
            Array.prototype.push.apply(message, dataHash);

            var keyAction = press_required ? KEYACTION.DERIVE_PUBLIC_KEY_REQ_PRESS : KEYACTION.DERIVE_PUBLIC_KEY;

            var enc_resp = 1;
            await onlykeyApi.ctaphid_via_webauthn(cmd, keyAction, keytype, enc_resp, message, 60000).then(async(response) => {

                if (!response.data) {
                    // msg("Problem setting time on onlykey");
                    api.emit("status", "OnlyKey: Problem Requesting Derived Public Key");
                    // api.emit("error", "");
                    return;
                }
                response = response.data;

                // Public ECC key will be an uncompressed ECC key, 65 bytes for P256, 32 bytes for NACL/CURVE25519 
                var sharedPub;
                var okPub = response.slice(0, 32);

                var encrypted_response = false;
                if (enc_resp == 1) {
                    // Decrypt with transit_key
                    var transit_key = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);
                    console.info("Onlykey transit public", okPub);
                    console.info("App transit public", appKey.publicKey);
                    console.info("Transit shared secret", transit_key);
                    transit_key = Uint8Array.from(transit_key); //await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                    console.info("AES Key", transit_key);
                    var encrypted = response.slice(32, response.length);
                    encrypted_response = await aesgcm_decrypt(encrypted, transit_key);
                }

                // OnlyKey version and model info
                var FWversion = bytes2string(response.slice(8, 19));
                var OKversion = response[19] == 99 ? 'Color' : 'Go';

                // Public ECC key will be an uncompressed ECC key, 65 bytes for P256, 32 bytes for NACL/CURVE25519 
                if (keytype == KEYTYPE.CURVE25519 || keytype == KEYTYPE.NACL) {
                    sharedPub = encrypted_response.slice(encrypted_response.length - (32), encrypted_response.length);
                }
                else {
                    sharedPub = encrypted_response.slice(encrypted_response.length - (65), encrypted_response.length);
                }
                // msg("OnlyKey Derive Public Key Complete");

                api.emit("status", "OnlyKey: Requested Derived Public Key Complete");
                console.info("sharedPub", encode_key(sharedPub), sharedPub);


                if (keytype == KEYTYPE.P256R1) { //KEYTYPE_P256R1
                    ONLYKEY_ECDH_P256_to_EPUB(sharedPub, function(epub) {
                        if (typeof cb === 'function') cb(null, epub);
                    })
                }
                else if (keytype == KEYTYPE.CURVE25519 || keytype == KEYTYPE.NACL) { //KEYTYPE_CURVE25519
                    // var eccKey_Pub = elliptic_curve25519.keyFromPublic(sharedPub).getPublic().encode("hex");
                    if (typeof cb === 'function') cb(null, encode_key(sharedPub));
                }

            });
            
        }

        api.derive_shared_secret = async function(additional_d, pubkey, keytype, press_required, cb) {
            
            if(keytype == KEYTYPE.P256R1 || keytype == KEYTYPE.P256K1)
                pubkey = EPUB_TO_ONLYKEY_ECDH_P256(pubkey);
            if (keytype == KEYTYPE.CURVE25519 || keytype == KEYTYPE.NACL) 
                pubkey = decode_key(pubkey);
            console.log("-------------------------------------------");
            // msg("Requesting OnlyKey Shared Secret");
            api.emit("status", "OnlyKey: Requesting Shared Secret");

            var cmd = OKCMD.OKCONNECT;
            //Add header and message type
            var message = [255, 255, 255, 255, OKCMD.OKCONNECT];

            //Add current epoch time
            var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
            var timePart = currentEpochTime.match(/.{2}/g).map(hexStrToDec);
            Array.prototype.push.apply(message, timePart);

            //Add transit pubkey
            appKey = nacl.box.keyPair();
            Array.prototype.push.apply(message, appKey.publicKey);

            //Add Browser and OS codes
            var env = [onlykeyApi.browser.charCodeAt(0), onlykeyApi.os.charCodeAt(0)];
            Array.prototype.push.apply(message, env);

            var dataHash;
            //Add additional data for key derivation
            if (!additional_d) {
                // SHA256 hash of empty buffer
                dataHash = await digestArray(Uint8Array.from(new Uint8Array(32)));
            }
            else {
                // SHA256 hash of input data
                dataHash = await digestArray(derivationInputBytes(additional_d));
            }
            Array.prototype.push.apply(message, dataHash);
            //msg("additional data hash -> " + dataHash)

            //Add input public key for shared secret computation 
            Array.prototype.push.apply(message, pubkey);
            //msg("input pubkey -> " + pubkey)
            //msg("full message -> " + message)

            var keyAction = press_required ? KEYACTION.DERIVE_SHARED_SECRET_REQ_PRESS : KEYACTION.DERIVE_SHARED_SECRET;

            var enc_resp = 1;
            await onlykeyApi.ctaphid_via_webauthn(cmd, keyAction, keytype, enc_resp, message, 60000).then(async(response) => {

                if (!response.data) {
                    // msg("Problem setting time on onlykey");
                    api.emit("status", "OnlyKey: Problem Requesting Shared Secret");
                    return;
                }
                response = response.data;

                var sharedPub;
                var okPub = response.slice(0, 32);

                var encrypted_response = false;
                if (enc_resp == 1) {
                    // Decrypt with transit_key
                    var transit_key = nacl.box.before(Uint8Array.from(okPub), appKey.secretKey);
                    console.info("Transit shared secret", transit_key);
                    transit_key = Uint8Array.from(transit_key); //await digestBuff(Uint8Array.from(transit_key)); //AES256 key sha256 hash of shared secret
                    console.info("AES Key", transit_key);
                    var encrypted = response.slice(32, response.length);
                    encrypted_response = await aesgcm_decrypt(encrypted, transit_key);
                }

                var FWversion = bytes2string(encrypted_response.slice(8, 19));
                var OKversion = encrypted_response[19] == 99 ? 'Color' : 'Go';

                // Public ECC key will be an uncompressed ECC key, 65 bytes for P256, 32 bytes for NACL/CURVE25519 
                if (keytype == KEYTYPE.NACL || keytype == KEYTYPE.CURVE25519) {
                    sharedPub = encrypted_response.slice(encrypted_response.length - (32 + 32), encrypted_response.length - 32);
                }
                else {
                    sharedPub = encrypted_response.slice(encrypted_response.length - (32 + 65), encrypted_response.length - 32);
                }
                //Private ECC key will be 32 bytes for all supported ECC key types
                var sharedsec = encrypted_response.slice(encrypted_response.length - 32, encrypted_response.length);

                console.info("sharedPub", encode_key(sharedPub), sharedPub);
                console.info("sharedsec", encode_key(sharedsec), sharedsec);

                // msg("OnlyKey Shared Secret Completed\n");
                api.emit("status", "OnlyKey: Shared Secret Complete");

                var _k; //key to export in AESGCM hex;

                if (keytype == KEYTYPE.P256R1 || keytype == KEYTYPE.P256K1) {

                    _k = await build_AESGCM(sharedsec);

                    // var ssHex = hex_encode(sharedsec)
                    // console.log("ONLYLEY: shared secret hex", ssHex)
                    console.log("ONLYLEY: derivedBits raw => " , Uint8Array.from(sharedsec));
                    console.log("derivedBits -> AES-GCM =", _k);

                    if (typeof cb === 'function') cb(null, _k, encode_key(sharedPub));
                }
                else if (keytype == KEYTYPE.CURVE25519 || keytype == KEYTYPE.NACL) {
                    // var ssHex = hex_encode(sharedsec)
                    // console.log("ONLYLEY: shared secret hex", ssHex)
                    console.log("ONLYLEY: derivedBits raw => " , Uint8Array.from(sharedsec));
                    console.log("derivedBits -> AES-GCM =", _k);
                    _k = await build_AESGCM(sharedsec);
                    if (typeof cb === 'function') cb(null, _k, encode_key(sharedPub));
                }

            });
        };
        
        // ---- Derived (label-based) X-Wing split custody ---------------------
        //
        // The device half of age-derive.js's encrypt/decrypt. sk_X (X25519)
        // never leaves the device: it returns pk_X plus the ML-KEM-768 seed,
        // and the host expands the seed and does the post-quantum half itself.
        // Same derivation the CLI performs (age-plugin-onlykey --derived,
        // python-onlykey's derived_xwing.py), so a label used on one side
        // produces the same key on the other - that equivalence is what
        // TC-18/TC-19 test.
        //
        // Ported from onlykey-testing's lib/fido2/client.js deriveXwing(),
        // which is the same protocol proven against real hardware (TC-09/10),
        // rather than re-derived from the firmware a second time.
        //
        // Two wire details are easy to get wrong and are load-bearing:
        //
        //   * opt2 is 5, not KEYTYPE_XWING's 6. ok_extension.cpp does `opt2++`
        //     before comparing, so the value on the wire is one less.
        //   * the label is hashed to 32 bytes exactly like derive_public_key
        //     hashes its input, and the CLI hashes the same way
        //     (sha256(label)). Sending raw label bytes would derive a
        //     different key with no error, surfacing much later as "no
        //     identity matched any of the recipients".
        var XWING_WIRE_KEYTYPE = 5;

        // Response layout, confirmed live rather than only read off the
        // firmware:
        //   [ device transit pubkey(32) | status string, NUL-terminated
        //     ("UNLOCKEDvX.Y.Z-xxxx\0", variable length) | payload(64) ]
        // With enc_resp set, everything after the transit pubkey is AES-GCM
        // encrypted as one blob ("encrypt everything except transit public" -
        // ok_extension.cpp forces any truthy opt3 to that mode). The status
        // string's length varies with the firmware version, so the NUL is
        // located rather than a fixed offset assumed.
        async function xwing_derive(label, ctX, press_required) {
            var message = [255, 255, 255, 255, OKCMD.OKCONNECT];

            var currentEpochTime = Math.round(new Date().getTime() / 1000.0).toString(16);
            Array.prototype.push.apply(message, currentEpochTime.match(/.{2}/g).map(hexStrToDec));

            appKey = nacl.box.keyPair();
            Array.prototype.push.apply(message, appKey.publicKey);

            var env = [onlykeyApi.browser.charCodeAt(0), onlykeyApi.os.charCodeAt(0)];
            Array.prototype.push.apply(message, env);

            var labelHash = await digestArray(derivationInputBytes(label));
            Array.prototype.push.apply(message, labelHash);
            if (ctX) Array.prototype.push.apply(message, Array.from(ctX));

            var keyAction = ctX
                ? (press_required ? KEYACTION.DERIVE_SHARED_SECRET_REQ_PRESS : KEYACTION.DERIVE_SHARED_SECRET)
                : (press_required ? KEYACTION.DERIVE_PUBLIC_KEY_REQ_PRESS : KEYACTION.DERIVE_PUBLIC_KEY);

            var enc_resp = 1;
            var response = await onlykeyApi.ctaphid_via_webauthn(
                OKCMD.OKCONNECT, keyAction, XWING_WIRE_KEYTYPE, enc_resp, message, 60000
            );

            if (!response || !response.data) {
                throw new Error(response && response.error ? response.error : 'no response from OnlyKey');
            }
            var data = response.data;

            var okPub = data.slice(0, 32);
            var transit_key = Uint8Array.from(nacl.box.before(Uint8Array.from(okPub), appKey.secretKey));
            var tail = await aesgcm_decrypt(data.slice(32, data.length), transit_key);
            tail = Array.from(tail);

            var nulAt = tail.indexOf(0);
            if (nulAt === -1) throw new Error('X-Wing derive: no NUL-terminated status string in response');
            var payload = tail.slice(nulAt + 1);
            if (payload.length !== 64) {
                throw new Error('X-Wing derive: expected 64 bytes after the status string, got ' + payload.length);
            }

            return {
                pkOrSsX: Uint8Array.from(payload.slice(0, 32)),
                mlkemSeed: Uint8Array.from(payload.slice(32, 64)),
                status: bytes2string(tail.slice(0, nulAt)),
            };
        }

        // cb(error, pk_X, mlkemSeed) - the recipient half. age-derive.js feeds
        // both straight into age_pqc.js's buildRecipient().
        api.derive_xwing_recipient = async function(label, press_required, cb) {
            api.emit("status", "OnlyKey: Requesting Derived X-Wing Recipient");
            try {
                var r = await xwing_derive(label, null, press_required);
                api.emit("status", "OnlyKey: Derived X-Wing Recipient Complete");
                if (typeof cb === 'function') cb(null, r.pkOrSsX, r.mlkemSeed);
            }
            catch (e) {
                api.emit("status", "OnlyKey: Problem Requesting Derived X-Wing Recipient");
                if (typeof cb === 'function') cb(e.message || e);
            }
        };

        // cb(error, ss_X) - decapsulation. Same call with ct_X appended; the
        // device returns the X25519 shared secret in the slot pk_X occupies
        // above, which is why both share one implementation.
        api.derive_xwing_decap = async function(label, ctX, press_required, cb) {
            api.emit("status", "OnlyKey: Requesting Derived X-Wing Decapsulation");
            try {
                var r = await xwing_derive(label, ctX, press_required);
                api.emit("status", "OnlyKey: Derived X-Wing Decapsulation Complete");
                if (typeof cb === 'function') cb(null, r.pkOrSsX);
            }
            catch (e) {
                api.emit("status", "OnlyKey: Problem Requesting Derived X-Wing Decapsulation");
                if (typeof cb === 'function') cb(e.message || e);
            }
        };

        // ---- Composite PGP-PQC (ML-DSA-65 + Ed25519 / ML-KEM-768 + X25519) --
        //
        // The device half of the pgp-pqc page. composite_pgp.js wires these to
        // the vendored openpgp.js fork's hardware hooks, so ordinary
        // openpgp.sign()/decrypt() calls route private-key operations to the
        // key. Ported from onlykey-testing's lib/fido2/composite.js, which is
        // the same protocol proven against hardware in TC-11.
        //
        // Unlike the derive calls these return promises rather than taking a
        // callback, because that is what composite_pgp.js's hooks await.
        //
        // The one thing that differs from the Node original: there is no
        // SEREMU channel here to inject the three challenge digits. In the
        // browser the user reads them off the device and presses the buttons,
        // so this simply polls until the device produces the answer.
        var OKSIGN = 237;
        var OKDECRYPT = 240;
        var OKPING = 243;
        var HALF_ECC = 0;
        var HALF_PQC = 1;
        var ED25519_SIG_LEN = 64;
        var MLDSA_SIG_LEN = 3309;

        // The firmware reports status and failures as plain ASCII through the
        // SAME response path as real data ("Error incorrect challenge was
        // entered", ...), so a response has to be classified rather than just
        // measured. Returns the text when the payload is entirely printable,
        // otherwise null. Safe because a genuine signature being all-printable
        // is not a practical possibility - (95/256)^64 for the Ed25519 half.
        function as_device_message(data) {
            if (!data || !data.length) return null;
            var text = '';
            for (var i = 0; i < data.length; i++) text += String.fromCharCode(data[i]);
            text = text.replace(/\0+$/, '');
            return /^[\x20-\x7e]+$/.test(text) ? text : null;
        }

        // Polls OKPING, accumulating chunks until `expected` bytes have
        // arrived. Reassembly is required because a response larger than one
        // WebAuthn assertion (512 bytes - ctap.cpp's sigder[514] less a status
        // byte and the size test) is served in pieces by
        // send_stored_response(). An ML-DSA-65 signature is 3309 bytes, so it
        // takes seven polls. Callers that expect a small response pass no
        // `expected` and take the first non-status payload.
        //
        // A status string arriving AFTER chunks have started means the buffer
        // is gone (wiped or exhausted) and the response will never complete -
        // reported rather than silently returning a truncated signature.
        async function poll_for_response(expected, maxMs) {
            var deadline = Date.now() + (maxMs || 120000);
            var parts = [];
            var total = 0;
            var lastMessage = null;

            while (Date.now() < deadline) {
                var resp = await onlykeyApi.ctaphid_via_webauthn(OKPING, 0, 0, 0, new Uint8Array(), 10000);
                if (resp && resp.data && resp.data.length) {
                    var msg = as_device_message(resp.data);
                    if (msg) {
                        if (total > 0) break;
                        lastMessage = msg;
                    }
                    else {
                        parts.push(Array.from(resp.data));
                        total += resp.data.length;
                        if (!expected || total >= expected) {
                            var out = [].concat.apply([], parts);
                            return Uint8Array.from(expected ? out.slice(0, expected) : out);
                        }
                        continue; // more to collect - poll again immediately
                    }
                }
                await new Promise(function(r) { setTimeout(r, 150); });
            }
            if (total > 0) {
                throw new Error('Incomplete composite response: got ' + total + ' of ' + expected +
                    ' bytes in ' + parts.length + ' chunk(s)' +
                    (lastMessage ? ' - last device message: "' + lastMessage + '"' : ''));
            }
            throw new Error('No composite response' +
                (lastMessage ? ' - last device message: "' + lastMessage + '"' : ''));
        }

        // Sends the payload to the device, chunked.
        //
        // A WebAuthn keyhandle carries at most 255 bytes including a 10-byte
        // header, so anything larger has to go in pieces - an ML-KEM-768
        // ciphertext is 1088 bytes and an ML-DSA digest payload is well over
        // the limit too. Sending it in one call throws "Max size exceeded"
        // out of encode_ctaphid_request_as_keyhandle(), which surfaces on the
        // page as "Error decrypting message: Max size exceeded" (confirmed
        // live, TC-11).
        //
        // The framing is onlykey-pgp.js's u2fSignBuffer(), reused rather than
        // reinvented because it is what the classic RSA path has always used
        // and what the firmware's OKSIGN/OKDECRYPT dispatch already expects:
        // 228-byte chunks, opt2 set only on the FINAL chunk, opt3 carrying an
        // incrementing packet number. Each chunk is encrypted on its own -
        // the firmware decrypts per packet and reassembles in packet_buffer,
        // so encrypting the whole payload once would not survive the split.
        //
        // opt2 is what tells the device the input is complete; without it the
        // device keeps waiting for more and never primes the challenge.
        var COMPOSITE_MAX_PACKET = 228; // 57 (OK packet size) * 4, under 255 - header

        async function prime_composite(cmd, slot, payload) {
            var bytes = Array.from(payload);
            var packetnum = 0;
            var last = null;
            while (bytes.length > 0) {
                var chunk = bytes.slice(0, COMPOSITE_MAX_PACKET);
                bytes = bytes.slice(COMPOSITE_MAX_PACKET);
                var finalPacket = bytes.length === 0 ? 1 : 0;
                packetnum++;
                var encrypted = await aesgcm_encrypt(chunk, onlykeyApi.sharedsec);
                last = await onlykeyApi.ctaphid_via_webauthn(
                    cmd, slot, finalPacket, packetnum, encrypted, 10000
                );
            }
            return last;
        }

        // One half of a composite signature. `half` selects Ed25519 (0) or
        // ML-DSA-65 (1); `digest` goes to the device UNCHANGED - the ML-DSA
        // half's FIPS 204 empty-context framing is applied firmware-side by
        // okpqc.cpp, not here.
        api.composite_sign = async function(slot, half, digest) {
            api.emit("status", "OnlyKey: Signing (" + (half === HALF_PQC ? "ML-DSA-65" : "Ed25519") + ") - confirm on the device");
            var payload = new Uint8Array(1 + digest.length);
            payload[0] = half;
            payload.set(Uint8Array.from(digest), 1);
            await prime_composite(OKSIGN, slot, payload);
            var expected = half === HALF_ECC ? ED25519_SIG_LEN : MLDSA_SIG_LEN;
            var sig = await poll_for_response(expected);
            api.emit("status", "OnlyKey: Signature complete");
            return sig;
        };

        // The device half of composite decryption. okpqc_decrypt() infers
        // which half is being asked for purely from the input size - 32 bytes
        // is the X25519 ephemeral point, 1088 the ML-KEM-768 ciphertext - so
        // unlike signing there is no selector byte.
        api.composite_decrypt = async function(slot, data) {
            api.emit("status", "OnlyKey: Decrypting - confirm on the device");
            await prime_composite(OKDECRYPT, slot, Uint8Array.from(data));
            var out = await poll_for_response(null);
            api.emit("status", "OnlyKey: Decryption complete");
            return out;
        };

        api.encode_key = encode_key;
        api.decode_key = decode_key;
        api.build_AESGCM = build_AESGCM;
        api.nacl = nacl;
        api.forge = forge;

        return api;
    }



    return onlykey;
};
