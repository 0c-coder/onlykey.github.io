//change   _template_  to your plugin name

var pagesList = {
    "age-derive": {
        sort: 34,
        icon: "fa-lock",
        //   title: "Chat"
    }
};

function b64ToBytes(b64) {
    var bin = atob(b64.trim());
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}

function bytesToB64(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

module.exports = {
    pagesList: pagesList,
    consumes: ["app"],
    provides: ["plugin_age-derive"],
    setup: function(options, imports, register) {

        // Deferred to setup-call time, not module-require time - matching
        // the ./age-derive.page.html require just below. webpack.config.js's
        // getPagesList() requires this whole plugin module directly under
        // plain Node (to read pagesList before any bundling happens), which
        // has no knowledge of the @noble/* resolve.alias entries webpack
        // itself uses - a top-level require() of age_pqc.js/age_file.js
        // there would throw MODULE_NOT_FOUND before webpack ever runs.
        var init = false;
        var agePqc = require("../../onlykey-fido2/onlykey/age_pqc.js");
        var ageFile = require("../../onlykey-fido2/onlykey/age_file.js");
        var page = {
            view: require("./age-derive.page.html").default,
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

                // press_required=false requests the non-REQ_PRESS "derived
                // keys per site without touch" path (same device setting
                // password-generator.js relies on), matching this
                // feature's non-interactive encrypt/decrypt flow.
                var press_required = false;

                // Show the 3-digit challenge code the device will ask for when
                // web derived keys are set to Challenge Code mode. onlykey-3rd-
                // party.js emits it right before the WebAuthn prompt goes up and
                // emits null to clear it once the derive returns.
                ok.on("challenge", function(code) {
                    var box = document.getElementById("challenge_code_box");
                    var out = document.getElementById("challenge_code");
                    if (!box || !out) return;
                    if (code && code.length) {
                        out.textContent = code.join("  ");
                        box.style.display = "block";
                    } else {
                        box.style.display = "none";
                    }
                });

                function currentLabel() {
                    return $("#label").val();
                }

                $("#label").on("input", function() {
                    var label = currentLabel();
                    $("#identity_out").val(label ? agePqc.encodeIdentity(label) : "");
                });

                $("#encrypt_start").click(function() {
                    var label = currentLabel();
                    var plaintext = $("#plaintext").val();
                    $("#age_file_out").val("");
                    ok.derive_xwing_recipient(label, press_required, function(error, pkX, mlkemSeed) {
                        if (error) {
                            $("#age_file_out").val("ERROR: " + error);
                            return;
                        }
                        var recipientPk = agePqc.buildRecipient(pkX, mlkemSeed);
                        var encaps = agePqc.xwingEncapsHost(recipientPk);
                        var fileBytes = ageFile.encryptAgeFile(
                            new TextEncoder().encode(plaintext),
                            { ciphertext: encaps.ciphertext, sharedSecret: encaps.sharedSecret }
                        );
                        $("#age_file_out").val(bytesToB64(fileBytes));
                        $("#identity_out").val(agePqc.encodeIdentity(label));
                    });
                });

                $("#decrypt_start").click(function() {
                    var label = currentLabel();
                    $("#decrypted_out").val("");
                    var fileBytes;
                    try {
                        fileBytes = b64ToBytes($("#decrypt_file_in").val());
                    } catch (e) {
                        $("#decrypted_out").val("ERROR: invalid base64: " + e.message);
                        return;
                    }

                    ageFile.decryptAgeFile(fileBytes, function(ciphertext) {
                        return new Promise(function(resolve, reject) {
                            ok.derive_xwing_recipient(label, press_required, function(error, pkX, mlkemSeed) {
                                if (error) { reject(new Error(error)); return; }
                                var ctX = agePqc.ctXOf(ciphertext);
                                ok.derive_xwing_decap(label, ctX, press_required, function(error2, ssX) {
                                    if (error2) { reject(new Error(error2)); return; }
                                    try {
                                        resolve(agePqc.splitDecapsulate(ssX, ciphertext, pkX, mlkemSeed));
                                    } catch (e) {
                                        reject(e);
                                    }
                                });
                            });
                        });
                    }).then(function(plaintextBytes) {
                        $("#decrypted_out").val(new TextDecoder().decode(plaintextBytes));
                    }).catch(function(err) {
                        $("#decrypted_out").val("ERROR: " + (err && err.message ? err.message : err));
                    });
                });
            }
        };

        pagesList["age-derive"] = page;

        register(null, {
            "plugin_age-derive": {
                pagesList: pagesList
            }
        });


    }
};
