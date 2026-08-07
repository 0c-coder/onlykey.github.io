//change   _template_  to your plugin name

var pagesList = {
    "pgp-pqc": {
        sort: 33,
        icon: "fa-lock",
        //   title: "PGP-PQC"
    }
};

function bytesToHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
    return out;
}

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
        var page = {
            view: require("./pgp-pqc.page.html").default,
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
                    var armored = $("#pgp_public_key").val().trim();
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
                // exact same digest the real on-device signing operation
                // will - openpgp.js embeds a wall-clock creation timestamp
                // in what gets hashed by default, and using two different
                // implicit `new Date()` calls (one for the capture, one for
                // the real click) risks a digest mismatch, which would
                // send WRONG challenge-PIN digits to a device with a
                // self-destruct PIN configured. Exposing the already-
                // loaded openpgp/compositePgp instances (not re-requiring a
                // second copy) and this page's own hardwareKeyForCurrentSlot
                // lets the test build an identical, date-pinned sign call
                // instead of guessing.
                // Also exposes the real `ok` transport object (test-only,
                // same guard as above). v6 signatures embed a mandatory
                // random salt in the hashed data (OpenPGP crypto-refresh),
                // so the digest openpgp.js hashes is DIFFERENT on every
                // sign() call even with a pinned `date` - confirmed live,
                // this session: a separate dry-run-then-precompute-digits
                // pass (the pattern this test hook was originally built
                // for) can never predict the real digest for a v6 key, no
                // matter how carefully the date is pinned. The test needs
                // `ok` directly so it can wrap composite_sign itself and
                // capture each real digest the instant it's computed,
                // inside the one real sign() call that needs it.
                window.__pgpPqcTestHooks = {
                    openpgp: openpgp,
                    compositePgp: compositePgp,
                    hardwareKeyForCurrentSlot: hardwareKeyForCurrentSlot,
                    ok: ok
                };

                // ---- handoff to the command line -------------------------
                //
                // This page cannot load the key itself, so the last step is a
                // command the user runs. Assembling that command here, from
                // the blob and slot the page already holds, removes the two
                // ways a hand-built one goes wrong: a truncated paste of 320
                // hex characters, and a slot that does not match the one the
                // decrypt and sign sections below will use.
                function currentSlot() {
                    var n = parseInt($("#pgp_slot").val(), 10);
                    return (n >= 1 && n <= 4) ? n : 1;
                }

                function refreshSetpqcCommand() {
                    var hex = $("#pgp_blob_hex").val().trim();
                    if (!hex) {
                        $("#pgp_setpqc_cmd").val("");
                        return;
                    }
                    $("#pgp_setpqc_cmd").val(
                        "onlykey-cli setpqc RSA" + currentSlot() + " " + hex);
                }

                // The slot is an input the user can change AFTER generating, so
                // the command has to follow it; a displayed command still
                // naming the old slot would load the key where nothing looks
                // for it. Namespaced (`input.pqc`) so the .off() cannot detach
                // a handler some other part of the page put on this field.
                $("#pgp_slot").off('input.pqc').on('input.pqc', refreshSetpqcCommand);

                $("#pgp_copy_cmd").off('click').click(function() {
                    var cmd = $("#pgp_setpqc_cmd").val();
                    if (!cmd) {
                        $("#pgp_handoff_status").text("Generate a key first.");
                        return;
                    }
                    // navigator.clipboard is unavailable on insecure origins
                    // and in some embedded webviews; falling back to selecting
                    // the field means the button always does something useful
                    // rather than failing silently.
                    var done = function() { $("#pgp_handoff_status").text("Command copied."); };
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(cmd).then(done, function() {
                            $("#pgp_setpqc_cmd").select();
                            $("#pgp_handoff_status").text("Could not copy - the command is selected, press Ctrl+C.");
                        });
                    } else {
                        $("#pgp_setpqc_cmd").select();
                        $("#pgp_handoff_status").text("Select-and-copy: the command is selected, press Ctrl+C.");
                    }
                });

                $("#pgp_download_blob").off('click').click(function() {
                    var hex = $("#pgp_blob_hex").val().trim();
                    if (!hex) {
                        $("#pgp_handoff_status").text("Generate a key first.");
                        return;
                    }
                    // Written as HEX TEXT rather than raw bytes on purpose:
                    // `setpqc` tries a file as hex first and falls back to raw,
                    // so hex works either way and stays greppable/diffable. The
                    // trailing newline is deliberate too - cli.py strips it.
                    var blob = new Blob([hex + "\n"], { type: "text/plain" });
                    var url = URL.createObjectURL(blob);
                    var a = document.createElement("a");
                    a.href = url;
                    a.download = "onlykey-composite-pqc.hex";
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    // Revoking immediately can cancel the download in some
                    // browsers; one turn of the event loop is enough.
                    setTimeout(function() { URL.revokeObjectURL(url); }, 0);
                    $("#pgp_handoff_status").text(
                        "Saved onlykey-composite-pqc.hex - this file is PRIVATE key material. "
                        + "Load it with: onlykey-cli setpqc RSA" + currentSlot()
                        + " onlykey-composite-pqc.hex, then delete it.");
                });

                // Generate a fresh composite key locally (host-side,
                // ephemeral) and show its public key + 160-byte blob. The
                // blob is for the user to load via `onlykey-cli setpqc`
                // (TC-11 step 2) - this app never loads it itself, since
                // OKSETPRIV isn't reachable over the browser's WebAuthn
                // transport (confirmed by direct firmware read - see the
                // implementation plan). Local private material is
                // discarded once this function returns; nothing here keeps
                // it around.
                // .off('click') first: setup() re-runs (and re-registers
                // every handler below) each time the SPA router revisits
                // this page after `init` has already run once - without
                // this, jQuery's .click() shorthand is additive, so a
                // second visit fires generate/encrypt/etc TWICE
                // concurrently, and whichever async call resolves last
                // silently wins the DOM write race. Confirmed live: this
                // is exactly what made TC-11's GUI test intermittently
                // decrypt/encrypt against a key that didn't match the one
                // actually shown in #pgp_public_key.
                $("#pgp_generate").off('click').click(function() {
                    $("#pgp_generate_status").text("Generating...");
                    // Clear stale output before starting - a caller polling
                    // these fields for "generation finished" (e.g. the GUI
                    // test) would otherwise see leftover values from a
                    // previous generate and stop waiting immediately,
                    // capturing a key that doesn't match what this call
                    // ultimately produces.
                    $("#pgp_public_key").val("");
                    $("#pgp_blob_hex").val("");
                    $("#pgp_setpqc_cmd").val("");
                    $("#pgp_handoff_status").text("");
                    var userId = $("#pgp_user_email").val().trim();
                    compositePgp.generateCompositeKey(openpgp, userId ? { userId: { email: userId } } : {})
                        .then(function(result) {
                            $("#pgp_public_key").val(result.armoredPublicKey);
                            $("#pgp_blob_hex").val(bytesToHex(result.blob));
                            refreshSetpqcCommand();
                            $("#pgp_generate_status").text(
                                "Generated. Put the OnlyKey in config mode, then run the command below "
                                + "(or download the blob and pass the filename instead).");
                        })
                        .catch(function(err) {
                            $("#pgp_generate_status").text("ERROR: " + (err && err.message ? err.message : err));
                        });
                });

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
                // does the KMAC combine + unwrap itself. Requires the
                // challenge PIN confirmed once on-device.
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

        pagesList["pgp-pqc"] = page;

        register(null, {
            "plugin_pgp-pqc": {
                pagesList: pagesList
            }
        });


    }
};
