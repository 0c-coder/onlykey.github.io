//change   _template_  to your plugin name

// Two routes, not one. The old single "age-derive" page carried the encrypt
// and decrypt halves stacked on top of each other; they are now the AGE mode
// of the Encrypt page and the AGE mode of the Decrypt page respectively.
//
// No icon and no title on either: app-src.html renders a header link only for
// entries that have one, so these still get their own /app/<name>.html and
// their own route, but the top nav stays Encrypt | Decrypt | Search. The
// selector rendered by mode-tabs.js is how you reach them.
//
// NOTE: /app/age-derive.html is gone. Anything pointing at it - test briefs,
// bookmarks - wants /app/age-encrypt.html or /app/age-decrypt.html now.
var pagesList = {
    "age-encrypt": {
        sort: 34
    },
    "age-decrypt": {
        sort: 35
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
        // the ./age-*.page.html requires at the bottom. webpack.config.js's
        // getPagesList() requires this whole plugin module directly under
        // plain Node (to read pagesList before any bundling happens), which
        // has no knowledge of the @noble/* resolve.alias entries webpack
        // itself uses - a top-level require() of age_pqc.js/age_file.js
        // there would throw MODULE_NOT_FOUND before webpack ever runs.
        var init = false;
        var agePqc = require("../../onlykey-fido2/onlykey/age_pqc.js");
        var ageFile = require("../../onlykey-fido2/onlykey/age_file.js");
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

                // The REQ_PRESS opcode variants are gone - one label, one key -
                // and there is no press_required argument any more. Whether a
                // confirmation is required now follows from what is being
                // asked for: a public key never needs one, a shared secret
                // always does, and the device enforces that itself.
                //
                // The challenge code comes from the library, which computes it
                // from the same [label32 | ct1120] the device hashes. It is
                // emitted before the chunks go out and cleared when the
                // operation ends, so the box is only ever showing a code for
                // the request currently in front of the user. An empty array
                // means there is no code to show right now - the request is
                // over, or the digest failed - not that no code is wanted; the
                // box hides rather than leaving stale digits up.
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

        // One setup for both routes. Every handler binds by id through jQuery,
        // and a selector that matches nothing binds nothing, so the encrypt
        // view simply never wires #decrypt_start and vice versa. The crypto
        // paths are byte-for-byte the ones the hardware brief exercised - the
        // split is in the markup, not in the handlers.
        pagesList["age-encrypt"] = {
            view: modeTabs("encrypt", "age-encrypt") +
                require("./age-encrypt.page.html").default,
            init: page.init,
            setup: page.setup
        };

        pagesList["age-decrypt"] = {
            view: modeTabs("decrypt", "age-decrypt") +
                require("./age-decrypt.page.html").default,
            init: page.init,
            setup: page.setup
        };

        register(null, {
            "plugin_age-derive": {
                pagesList: pagesList
            }
        });

    }
};
