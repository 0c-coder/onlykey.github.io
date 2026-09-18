//change   _template_  to your plugin name

// Two routes, not one. The old single "pgp-pqc" page stacked Encrypt,
// Decrypt, Sign and Verify; those are now the PQC-PGP mode of the Encrypt
// page (key block + Encrypt + Sign) and of the Decrypt page (Decrypt +
// Verify). Signing is an outbound act and verifying an inbound one, which is
// the same split classic PGP already uses on the encrypt and decrypt pages.
//
// No icon and no title: app-src.html renders a header link only for entries
// that have one, so these keep their own /app/<name>.html and their own
// route while the top nav stays Encrypt | Decrypt | Search.
//
// NOTE: /app/pgp-pqc.html is gone. Anything pointing at it wants
// /app/pqc-encrypt.html or /app/pqc-decrypt.html now.
var pagesList = {
    "pqc-encrypt": {
        sort: 32
    },
    "pqc-decrypt": {
        sort: 33
    }
};

module.exports = {
    pagesList: pagesList,
    consumes: ["app"],
    provides: ["plugin_pgp-pqc"],
    setup: function(options, imports, register) {

        // Deferred to setup-call time, not module-require time - same
        // reason as age-derive.js's identical comment: webpack.config.js's
        // getPagesList() requires this whole plugin module directly under
        // plain Node (to read pagesList before any bundling happens).
        // openpgp_loader.js's raw-loader! inline-loader require only
        // resolves under webpack, and composite_pgp.js only makes sense
        // once openpgp is loadable, so both must stay deferred.
        var init = false;
        var openpgp = require("../../onlykey-fido2/onlykey/openpgp_loader.js");
        var compositePgp = require("../../onlykey-fido2/onlykey/composite_pgp.js");
        var modeTabs = require("../pages/mode-tabs.js");
        var page = {
            init: function(app, $page, pathname) {
                init = true;


                page.setup(app, $page, pathname);
            },
            setup: function(app, $page, pathname) {
                if (!init)
                    return page.init(app, $page, pathname);

                // See password-generator.js's comment on this same call -
                // onlykey3rd() takes no arguments in the currently-bundled
                // library version, kept only to match history.js's call.
                var onlykey3rd = app.onlykey3rd;
                var ok = onlykey3rd(1, 0);
                var $ = app.$;

                // Mirror the device's own progress into whichever status line
                // belongs to the operation in flight.
                //
                // Without this a composite operation shows one unchanging
                // string for its whole duration, and these are not quick: an
                // ML-KEM-768 ciphertext is 1088 bytes = 5 WebAuthn ceremonies
                // just to send, and ML-DSA-65 signing costs the device around
                // ten seconds before the first response byte exists. A frozen
                // line for that long reads as a hang, and anything watching the
                // page for progress cannot tell a working device from a wedged
                // one. The `ok` api emits "status" throughout - surface it.
                var activeStatusEl = null;
                function runWithStatus(elId, initial, fn) {
                    activeStatusEl = elId;
                    $("#" + elId).text(initial);
                    return Promise.resolve()
                        .then(fn)
                        .then(function(r) { activeStatusEl = null; return r; },
                              function(e) { activeStatusEl = null; throw e; });
                }
                ok.on("status", function(text) {
                    if (activeStatusEl) $("#" + activeStatusEl).text(text);
                });

                function currentSlot() {
                    var slot = parseInt($("#pgp_slot").val(), 10);
                    if (!(slot >= 1 && slot <= 4)) {
                        throw new Error("slot must be 1-4 (RSA slots) - the slot the composite key was loaded into via `onlykey-cli setpqc`");
                    }
                    return slot;
                }

                function currentPublicKey() {
                    // `|| ""` because one setup serves both the PQC-PGP
                    // encrypt and decrypt views. The message below is the
                    // right answer either way - no key is no key, whether the
                    // field is empty or absent.
                    var armored = ($("#pgp_public_key").val() || "").trim();
                    if (!armored) throw new Error("no public key - generate one, or paste an existing composite public key");
                    return openpgp.readKey({ armoredKey: armored });
                }

                // Builds the hardware-backed PrivateKey object for the
                // current public key and wires this feature's device hooks
                // for the given slot. Called fresh before every decrypt/
                // sign action (cheap - createHardwarePrivateKey does no
                // device I/O, it just marks placeholder secret fields) so
                // the slot field is always honored even if the user
                // changes it between actions.
                function hardwareKeyForCurrentSlot() {
                    var slot = currentSlot();
                    return currentPublicKey().then(function(pub) {
                        compositePgp.registerCompositeHooks(openpgp, ok, slot);
                        return { pub: pub, hwKey: openpgp.createHardwarePrivateKey(pub) };
                    });
                }

                // Test-only hook (this plugin only loads under
                // plugins-devel.js, never in production - see plugins-
                // devel.js's own guard against accidental production
                // inclusion). onlykey-testing/test/17-gui-composite-pgp.js
                // needs to construct a sign() call with an EXPLICIT,
                // pre-agreed `date` so its Node-side dry-run challenge-
                // digit capture (composite_pgp_challenge.js) computes the
                // NO TEST HOOK IS ATTACHED TO `window` HERE, deliberately.
                //
                // This page used to export { openpgp, compositePgp,
                // hardwareKeyForCurrentSlot, ok } as a global test-hook object
                // for a harness that wanted to pin a signing date. That handed
                // the live `ok` transport - composite_sign and
                // composite_decrypt against whatever slot is loaded - to every
                // script running in this origin. The three-button confirmation
                // is the only thing that stood between a hostile script and a
                // device signature, and a user approving a prompt they did not
                // knowingly cause is exactly the case it cannot defend.
                //
                // Gating it on `process.env.NODE_ENV === "production"` would not
                // have helped: BUILD.sh with no argument runs `build-site`
                // (NODE_ENV=development), and that is the build committed to
                // docs/ and served. The hook would have shipped anyway.
                //
                // A harness that needs these objects should reach them the way
                // the rest of the kit does - load the modules directly - rather
                // than have the page publish them. See
                // onlykey-testing/test/05-security/02-shipped-bundle-clean.

                // ---- key creation is NOT in this app -----------------------
                //
                // Generating a composite key, assembling the `setpqc` command
                // and downloading the 160-byte private blob all used to live
                // here. They are gone: composite key creation is a
                // command-line operation.
                //
                // The reasoning is not tidiness. Generating a key in a browser
                // means the private half exists in a JS heap in a tab, and the
                // handoff then asks the user to carry it to the device by hand
                // - through the clipboard, or a file on disk, or a command in
                // shell history. None of those is a place a private key should
                // be. `onlykey-cli loadpqc` and `setpqc` already do this
                // against the device's config mode over the vendor interface,
                // which a browser cannot reach anyway.
                //
                // So this page needs no key material and no explanation of
                // any: a recipient's PUBLIC key to encrypt to, and a slot
                // number naming a key the device already holds.
                function currentSlot() {
                    var n = parseInt($("#pgp_slot").val(), 10);
                    return (n >= 1 && n <= 4) ? n : 1;
                }

                // Host-only: encrypt to the composite public key. No
                // device involved - encryption only ever needs the
                // recipient's PUBLIC key.
                $("#pgp_encrypt").off('click').click(function() {
                    $("#pgp_encrypt_status").text("Encrypting...");
                    $("#pgp_ciphertext_out").val("");
                    var plaintext = $("#pgp_plaintext").val();
                    currentPublicKey()
                        .then(function(pub) {
                            return openpgp.createMessage({ text: plaintext }).then(function(message) {
                                return openpgp.encrypt({ message: message, encryptionKeys: pub, format: 'armored' });
                            });
                        })
                        .then(function(armoredCiphertext) {
                            $("#pgp_ciphertext_out").val(armoredCiphertext);
                            $("#pgp_encrypt_status").text("Done.");
                        })
                        .catch(function(err) {
                            $("#pgp_encrypt_status").text("ERROR: " + (err && err.message ? err.message : err));
                        });
                });

                // Device-backed: decrypt an armored composite-PGP message.
                // hooks.ecdh/hooks.mlkemDecaps (registered above) route the
                // X25519 and ML-KEM-768 shares through the device; openpgp
                // does the SHA3-256 key combine and RFC 3394 unwrap itself.
                // The two shares are fetched in separate device operations, so
                // this raises the three-button challenge TWICE - once per half
                // - not once.
                $("#pgp_decrypt").off('click').click(function() {
                    $("#pgp_plaintext_out").val("");
                    var armoredCiphertext = $("#pgp_ciphertext_in").val().trim();
                    runWithStatus("pgp_decrypt_status",
                        "Decrypting (confirm the challenge PIN on your OnlyKey)...",
                        function() {
                            return Promise.all([hardwareKeyForCurrentSlot(), openpgp.readMessage({ armoredMessage: armoredCiphertext })])
                                .then(function(results) {
                                    var hwKey = results[0].hwKey;
                                    var message = results[1];
                                    return openpgp.decrypt({ message: message, decryptionKeys: hwKey, format: 'utf8' });
                                });
                        })
                        .then(function(result) {
                            $("#pgp_plaintext_out").val(result.data);
                            $("#pgp_decrypt_status").text("Done.");
                        })
                        .catch(function(err) {
                            $("#pgp_decrypt_status").text("ERROR: " + (err && err.message ? err.message : err));
                        });
                });

                // Device-backed: sign plaintext with the composite key.
                // hooks.signer (registered above) fires ONCE and drives
                // BOTH halves sequentially - expect the challenge PIN to
                // be confirmed on-device TWICE (once for the Ed25519 half,
                // once for the ML-DSA-65 half). See composite_pgp.js's
                // registerCompositeHooks() comment for why this needs two
                // separate device confirmations rather than one.
                $("#pgp_sign").off('click').click(function() {
                    $("#pgp_signature_out").val("");
                    var plaintext = $("#pgp_sign_plaintext").val();
                    runWithStatus("pgp_sign_status",
                        "Signing (confirm the challenge PIN on your OnlyKey - TWICE, once per key half)...",
                        function() {
                            return Promise.all([hardwareKeyForCurrentSlot(), openpgp.createCleartextMessage({ text: plaintext })])
                                .then(function(results) {
                                    var hwKey = results[0].hwKey;
                                    var message = results[1];
                                    return openpgp.sign({ message: message, signingKeys: hwKey, format: 'armored' });
                                });
                        })
                        .then(function(armoredSignedMessage) {
                            $("#pgp_signature_out").val(armoredSignedMessage);
                            $("#pgp_sign_status").text("Done.");
                        })
                        .catch(function(err) {
                            $("#pgp_sign_status").text("ERROR: " + (err && err.message ? err.message : err));
                        });
                });

                // Host-only: verify a signed cleartext message against the
                // composite public key. No device involved.
                $("#pgp_verify").off('click').click(function() {
                    $("#pgp_verify_status").text("Verifying...");
                    var armoredSignedMessage = $("#pgp_verify_in").val().trim();
                    currentPublicKey()
                        .then(function(pub) {
                            return openpgp.readCleartextMessage({ cleartextMessage: armoredSignedMessage }).then(function(message) {
                                return openpgp.verify({ message: message, verificationKeys: pub });
                            });
                        })
                        .then(function(verifyResult) {
                            return verifyResult.signatures[0].verified.then(function() {
                                $("#pgp_verify_status").text("Signature VALID.");
                            });
                        })
                        .catch(function(err) {
                            $("#pgp_verify_status").text("Signature INVALID / ERROR: " + (err && err.message ? err.message : err));
                        });
                });
            }
        };

        // Two routes, one setup - see the note on pagesList at the top of this
        // file, and the matching split in age-derive.js. Encrypt keeps the key
        // block, Encrypt and Sign; Decrypt keeps a trimmed key block, Decrypt
        // and Verify. Every handler binds by id, so each view wires only the
        // controls it actually has.
        pagesList["pqc-encrypt"] = {
            view: modeTabs("encrypt", "pqc-encrypt") +
                require("./pqc-encrypt.page.html").default,
            init: page.init,
            setup: page.setup
        };

        pagesList["pqc-decrypt"] = {
            view: modeTabs("decrypt", "pqc-decrypt") +
                require("./pqc-decrypt.page.html").default,
            init: page.init,
            setup: page.setup
        };

        register(null, {
            "plugin_pgp-pqc": {
                pagesList: pagesList
            }
        });


    }
};
