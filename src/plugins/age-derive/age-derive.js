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

                // The REQ_PRESS opcode variants are gone - one label, one key -
                // and there is no press_required argument any more. Whether a
                // confirmation is required now follows from what is being
                // asked for: a public key never needs one, a shared secret
                // always does, and the device enforces that itself.
                //
                // The challenge code is no longer precomputed here either. The
                // device hashes the reassembled label and ciphertext and shows
                // the digits itself; this listener stays for the event, but
                // nothing emits a code on the derived path now.
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
                    // The device returns the whole 1216-byte recipient now,
                    // so there is nothing to assemble from halves here.
                    ok.derive_xwing_recipient(label, function(error, recipientPk) {
                        if (error) {
                            $("#age_file_out").val("ERROR: " + error);
                            return;
                        }
                        var encaps = agePqc.xwingEncapsHost(recipientPk);
                        window.__probe = window.__probe || {};
                        window.__probe.encapSS = Array.from(encaps.sharedSecret).map(function(b){return ('0'+b.toString(16)).slice(-2);}).join('');
                        window.__probe.recipient4 = Array.from(recipientPk.slice(0,4)).join(',');
                        window.__probe.ctEnc = Array.from(encaps.ciphertext.slice(0,4)).join(',') + '|' + Array.from(encaps.ciphertext.slice(-4)).join(',') + '|len' + encaps.ciphertext.length;
                        console.log('[XWTRACE] encap ss', window.__probe.encapSS.slice(0,16), 'recipient[0..3]', window.__probe.recipient4, 'ct', window.__probe.ctEnc);
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
                            // One call, and no host-side ML-KEM. The device
                            // takes the whole X-Wing ciphertext and returns the
                            // finished 32-byte shared secret, so the recipient
                            // lookup that used to be needed here (to feed pk_X
                            // and the seed into splitDecapsulate) is gone.
                            console.log('[XWTRACE] decap ct',
                                Array.from(ciphertext.slice(0,4)).join(',') + '|' +
                                Array.from(ciphertext.slice(-4)).join(',') + '|len' + ciphertext.length,
                                'encapWas', window.__probe && window.__probe.ctEnc);
                            ok.derive_xwing_decap(label, ciphertext, function(error, ss) {
                                if (error) { reject(new Error(error)); return; }
                                resolve(ss);
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
