//change   _template_  to your plugin name  

var pagesList = {
    "password-generator": {
        sort:35,
        icon: "fa-key",
        //   title: "Chat"
    }
};


module.exports = {
    pagesList: pagesList,
    consumes: ["app"],
    provides: ["plugin_password-generator"],
    setup: function(options, imports, register) {

        var init = false;
        var page = {
            view: require("./password-generator.page.html").default,
            init: function(app, $page, pathname) {
                init = true;


                page.setup(app, $page, pathname);
            },
            setup: function(app, $page, pathname) {
                if (!init)
                    return page.init(app, $page, pathname);


                // node-onlykey's onlykey3rd() constructor (function
                // onlykey(), onlykey-3rd-party.js) takes no arguments in the
                // currently-bundled library version - keytype/press_required
                // are per-call arguments on derive_public_key/
                // derive_shared_secret themselves, not bound at construction.
                // The `onlykey3rd(1, 0)` call below is a harmless no-op
                // (extra args to a zero-arg function), kept only to match
                // history.js's still-working call for consistency.
                var onlykey3rd = app.onlykey3rd;
                var ok = onlykey3rd(1, 0);
                var $ = app.$;

                // KEYTYPE.P256R1 = 1 - the only keytype for which
                // derive_public_key()/derive_shared_secret() do a real
                // ECDH derivation (P256, via ONLYKEY_ECDH_P256_to_EPUB /
                // EPUB_TO_ONLYKEY_ECDH_P256), matching this two-step
                // pubkey -> shared-secret pattern. press_required=false
                // requests the non-REQ_PRESS "derived keys per site
                // without touch" path (device setting gated behind
                // derived_key_challenge_mode bit 3).
                var KEYTYPE_P256R1 = 1;
                var press_required = false;

                $("#onlykey_start").click(async function() {
                    var phrase = $("#phrase").val();
                    ok.derive_public_key(phrase, KEYTYPE_P256R1, press_required, function(error, phrasePubkey) {
                        if (error) return; // e.g. CTAP2_ERR_EXTENSION_NOT_SUPPORTED when blocked
                        ok.derive_shared_secret(phrase, phrasePubkey, KEYTYPE_P256R1, press_required, async function(error, phrasePubkeySecret) {
                            if (error) return;
                            $("#phrase_out").val(phrasePubkeySecret);
                        });
                    });
                });
            }
        };

        pagesList["password-generator"] = page;
        
        register(null, {
            "plugin_password-generator": {
                pagesList: pagesList
            }
        });


    }
};