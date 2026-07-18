/**
 * OnlyAgent Vault — hardware-encrypted credential manager.
 *
 * Ported from onlykey-proxy PWA (js/vault.js, js/crypto.js, js/session-cache.js).
 * Secrets are AES-256-GCM encrypted with a NON-EXTRACTABLE key derived from an
 * OnlyKey ECDH shared secret (physical touch required). IndexedDB stores only
 * ciphertext. Session cache holds CryptoKey objects in memory with TTL policies.
 */

var pagesList = {
    "vault": {
        sort: 36,
        icon: "fa-shield",
        title: "Vault"
    }
};

// ── WebCrypto (HKDF → AES-256-GCM, non-extractable) ────────────────────

var OKCrypto = {
    HKDF_INFO: new TextEncoder().encode("onlyagent-vault-v1"),

    deriveAesKey: async function(sharedSecret) {
        var ikm = await crypto.subtle.importKey(
            "raw", sharedSecret, { name: "HKDF" }, false, ["deriveKey"]
        );
        return crypto.subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: this.HKDF_INFO },
            ikm,
            { name: "AES-GCM", length: 256 },
            false, // NON-EXTRACTABLE
            ["encrypt", "decrypt"]
        );
    },

    encrypt: async function(aesKey, plaintext) {
        var nonce = crypto.getRandomValues(new Uint8Array(12));
        var ct = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce }, aesKey,
            new TextEncoder().encode(plaintext)
        );
        var out = new Uint8Array(12 + ct.byteLength);
        out.set(nonce);
        out.set(new Uint8Array(ct), 12);
        var s = "";
        for (var i = 0; i < out.length; i++) s += String.fromCharCode(out[i]);
        return btoa(s);
    },

    decrypt: async function(aesKey, b64) {
        var raw = Uint8Array.from(atob(b64), function(c) { return c.charCodeAt(0); });
        if (raw.length < 28) throw new Error("Blob too short");
        var pt = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: raw.slice(0, 12) }, aesKey, raw.slice(12)
        );
        return new TextDecoder().decode(pt);
    }
};

// ── IndexedDB ciphertext store ──────────────────────────────────────────

var OKVault = (function() {
    var DB_NAME = "onlyagent-vault";
    var DB_VERSION = 1;
    var STORE_NAME = "credentials";

    function openDB() {
        return new Promise(function(resolve, reject) {
            var req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = function() {
                var db = req.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME, { keyPath: "serviceId" });
                }
            };
            req.onsuccess = function() { resolve(req.result); };
            req.onerror = function() { reject(req.error); };
        });
    }

    return {
        put: async function(entry) {
            var now = Date.now();
            var record = Object.assign({}, entry, {
                updatedAt: now,
                createdAt: entry.createdAt || now
            });
            var db = await openDB();
            return new Promise(function(resolve, reject) {
                var t = db.transaction(STORE_NAME, "readwrite");
                t.objectStore(STORE_NAME).put(record);
                t.oncomplete = function() { resolve(record); };
                t.onerror = function() { reject(t.error); };
            });
        },

        get: async function(serviceId) {
            var db = await openDB();
            return new Promise(function(resolve, reject) {
                var t = db.transaction(STORE_NAME, "readonly");
                var req = t.objectStore(STORE_NAME).get(serviceId);
                req.onsuccess = function() { resolve(req.result || null); };
                req.onerror = function() { reject(req.error); };
            });
        },

        remove: async function(serviceId) {
            var db = await openDB();
            return new Promise(function(resolve, reject) {
                var t = db.transaction(STORE_NAME, "readwrite");
                t.objectStore(STORE_NAME).delete(serviceId);
                t.oncomplete = function() { resolve(); };
                t.onerror = function() { reject(t.error); };
            });
        },

        list: async function() {
            var db = await openDB();
            return new Promise(function(resolve, reject) {
                var t = db.transaction(STORE_NAME, "readonly");
                var req = t.objectStore(STORE_NAME).getAll();
                req.onsuccess = function() { resolve(req.result || []); };
                req.onerror = function() { reject(req.error); };
            });
        },

        exportJSON: async function() {
            var entries = await this.list();
            return JSON.stringify({
                version: 1,
                exportedAt: new Date().toISOString(),
                credentials: entries
            }, null, 2);
        },

        importJSON: async function(json, force) {
            var data = JSON.parse(json);
            if (!data.credentials || !Array.isArray(data.credentials)) {
                throw new Error("Invalid vault export format");
            }
            var existing = await this.list();
            var existingIds = {};
            existing.forEach(function(e) { existingIds[e.serviceId] = true; });
            var imported = 0, skipped = 0;
            for (var i = 0; i < data.credentials.length; i++) {
                var entry = data.credentials[i];
                if (!entry.serviceId || !entry.encrypted) { skipped++; continue; }
                if (existingIds[entry.serviceId] && !force) { skipped++; continue; }
                await this.put(entry);
                imported++;
            }
            return { imported: imported, skipped: skipped, total: data.credentials.length };
        }
    };
})();

// ── Session cache (TTL-cached non-extractable CryptoKeys) ───────────────

var OKSessionCache = (function() {
    var _cache = new Map();
    var _policies = new Map();
    var _defaultPolicy = "session:30m";
    var _reaperInterval = null;

    function parsePolicy(policyStr) {
        if (!policyStr || policyStr === "always") {
            return { ttlMs: 0, sliding: false, noCache: true };
        }
        if (policyStr === "startup") {
            return { ttlMs: 0, sliding: false, noCache: false };
        }
        var match = policyStr.match(/^session:(\d+)(m|h)$/);
        if (!match) {
            return { ttlMs: 0, sliding: false, noCache: true };
        }
        var value = parseInt(match[1], 10);
        var ttlMs = match[2] === "h" ? value * 3600000 : value * 60000;
        return { ttlMs: ttlMs, sliding: ttlMs <= 3600000, noCache: false };
    }

    return {
        getPolicy: function(serviceId) {
            return _policies.get(serviceId) || _defaultPolicy;
        },

        setPolicy: function(serviceId, policy) {
            _policies.set(serviceId, policy);
            if (policy === "always") _cache.delete(serviceId);
        },

        get: function(serviceId) {
            var entry = _cache.get(serviceId);
            if (!entry) return null;
            if (entry.ttlMs > 0) {
                var ref = entry.sliding ? entry.lastUsedAt : entry.createdAt;
                if (Date.now() - ref > entry.ttlMs) {
                    _cache.delete(serviceId);
                    return null;
                }
            }
            entry.lastUsedAt = Date.now();
            return entry.aesKey;
        },

        put: function(serviceId, aesKey) {
            var policyStr = this.getPolicy(serviceId);
            var parsed = parsePolicy(policyStr);
            if (parsed.noCache) return;
            var now = Date.now();
            _cache.set(serviceId, {
                aesKey: aesKey,
                createdAt: now,
                lastUsedAt: now,
                policy: policyStr,
                ttlMs: parsed.ttlMs,
                sliding: parsed.sliding
            });
        },

        evict: function(serviceId) { _cache.delete(serviceId); },
        clear: function() { _cache.clear(); },

        status: function() {
            var now = Date.now();
            var entries = [];
            _cache.forEach(function(entry, serviceId) {
                var ref = entry.sliding ? entry.lastUsedAt : entry.createdAt;
                var remaining = entry.ttlMs > 0 ? Math.max(0, entry.ttlMs - (now - ref)) : Infinity;
                entries.push({
                    serviceId: serviceId,
                    policy: entry.policy,
                    remainingFormatted: remaining === Infinity
                        ? "until close" : Math.ceil(remaining / 60000) + "m"
                });
            });
            return entries;
        },

        reap: function() {
            var now = Date.now();
            var expired = [];
            _cache.forEach(function(entry, serviceId) {
                if (entry.ttlMs > 0) {
                    var ref = entry.sliding ? entry.lastUsedAt : entry.createdAt;
                    if (now - ref > entry.ttlMs) expired.push(serviceId);
                }
            });
            expired.forEach(function(id) { _cache.delete(id); });
        },

        startReaper: function() {
            if (_reaperInterval) return;
            var self = this;
            _reaperInterval = setInterval(function() { self.reap(); }, 30000);
        }
    };
})();

// ── Plugin module ───────────────────────────────────────────────────────

module.exports = {
    pagesList: pagesList,
    consumes: ["app"],
    provides: ["plugin_vault"],
    setup: function(options, imports, register) {

        var init = false;
        var page = {
            view: require("./vault.page.html").default,
            init: function(app, $page, pathname) {
                init = true;
                page.setup(app, $page, pathname);
            },
            setup: function(app, $page, pathname) {
                if (!init)
                    return page.init(app, $page, pathname);

                var $ = app.$;
                var onlykey3rd = app.onlykey3rd;
                var ok = onlykey3rd();

                ok.on("status", function(msg) { log(msg); });
                ok.on("error", function(err) { log("OnlyKey error: " + err); });

                function log(msg) {
                    var div = document.createElement("div");
                    div.textContent = msg;
                    var el = document.getElementById("messages");
                    if (el) {
                        el.appendChild(div);
                        el.scrollTop = el.scrollHeight;
                    }
                }

                function esc(s) {
                    var d = document.createElement("div");
                    d.textContent = String(s);
                    return d.innerHTML;
                }

                function toBytes(secret) {
                    if (secret instanceof Uint8Array) return secret;
                    if (Array.isArray(secret)) return new Uint8Array(secret);
                    var s = String(secret);
                    if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) {
                        var out = new Uint8Array(s.length / 2);
                        for (var i = 0; i < out.length; i++) {
                            out[i] = parseInt(s.substr(i * 2, 2), 16);
                        }
                        return out;
                    }
                    return new TextEncoder().encode(s);
                }

                // Derive (or fetch cached) per-service AES key.
                // OnlyKey ECDH: deterministic per (device, serviceId). Touch required.
                function deriveAesKey(serviceId) {
                    var cached = OKSessionCache.get(serviceId);
                    if (cached) return Promise.resolve(cached);

                    var phrase = "vault:" + serviceId;
                    log("Touch your OnlyKey to authorize \"" + serviceId + "\"...");

                    return new Promise(function(resolve, reject) {
                        ok.derive_public_key(phrase, 1, false, function(err, pubkey) {
                            if (err) return reject(new Error("derive_public_key: " + err));
                            ok.derive_shared_secret(phrase, pubkey, 1, true, function(err2, secret) {
                                if (err2) return reject(new Error("derive_shared_secret: " + err2));
                                resolve(secret);
                            });
                        });
                    }).then(function(secret) {
                        var bytes = toBytes(secret);
                        return OKCrypto.deriveAesKey(bytes).then(function(aesKey) {
                            bytes.fill(0);
                            OKSessionCache.put(serviceId, aesKey);
                            renderSessions();
                            return aesKey;
                        });
                    });
                }

                async function renderVault() {
                    var entries = await OKVault.list();
                    var $list = $page.find("#vault_list");
                    if (entries.length === 0) {
                        $list.html('<p class="text-muted">No credentials stored yet.</p>');
                        return;
                    }
                    var html = entries.map(function(e) {
                        var hasSession = !!OKSessionCache.get(e.serviceId);
                        return '<fieldset class="vault-entry" data-service="' + esc(e.serviceId) + '">' +
                            '<input readonly type="text" value="' + esc(e.serviceId) +
                            ' · ' + esc(e.policy || "session:30m") +
                            (hasSession ? ' · session active' : '') + '" />' +
                            '<button type="button" class="btn-secondary vault-copy-blob">Copy blob</button>' +
                            '<button type="button" class="btn-secondary vault-copy-secret">Copy secret (touch)</button>' +
                            '<button type="button" class="btn-danger vault-delete">Delete</button>' +
                            '</fieldset>';
                    }).join("");
                    $list.html(html);
                }

                function renderSessions() {
                    var entries = OKSessionCache.status();
                    var $s = $page.find("#vault_sessions");
                    if (entries.length === 0) {
                        $s.html('<p class="text-muted">No active sessions — next use requires touch.</p>');
                        return;
                    }
                    var html = entries.map(function(e) {
                        return '<p>' + esc(e.serviceId) + ' — ' + esc(e.remainingFormatted) +
                            ' (' + esc(e.policy) + ')</p>';
                    }).join("");
                    $s.html(html);
                }

                // ── Add credential ──
                $page.find("#vault_add_btn").off("click").on("click", async function() {
                    var serviceId = $page.find("#vault_service").val().trim();
                    var secret = $page.find("#vault_secret").val();
                    var policy = $page.find("#vault_policy").val();
                    if (!serviceId || !secret) {
                        log("Service name and secret are required");
                        return;
                    }
                    try {
                        OKSessionCache.setPolicy(serviceId, policy);
                        var aesKey = await deriveAesKey(serviceId);
                        var encrypted = await OKCrypto.encrypt(aesKey, secret);
                        await OKVault.put({
                            serviceId: serviceId,
                            encrypted: encrypted,
                            policy: policy
                        });
                        $page.find("#vault_secret").val("");
                        $page.find("#vault_add_result").val(encrypted).removeClass("startHidden");
                        log('Encrypted and stored "' + serviceId + '" — plaintext cleared');
                        renderVault();
                    } catch (err) {
                        log("Error: " + err.message);
                    }
                });

                // ── Credential list actions (delegated) ──
                $page.find("#vault_list").off("click").on("click", "button", async function() {
                    var serviceId = $(this).closest(".vault-entry").attr("data-service");
                    var entry = await OKVault.get(serviceId);
                    if (!entry) return;

                    if ($(this).hasClass("vault-copy-blob")) {
                        await navigator.clipboard.writeText(entry.encrypted);
                        log('Copied encrypted blob for "' + serviceId + '"');
                    } else if ($(this).hasClass("vault-copy-secret")) {
                        try {
                            var aesKey = await deriveAesKey(serviceId);
                            var plaintext = await OKCrypto.decrypt(aesKey, entry.encrypted);
                            await navigator.clipboard.writeText(plaintext);
                            plaintext = null;
                            log('Secret for "' + serviceId + '" copied to clipboard');
                        } catch (err) {
                            log("Decrypt error: " + err.message);
                        }
                    } else if ($(this).hasClass("vault-delete")) {
                        await OKVault.remove(serviceId);
                        OKSessionCache.evict(serviceId);
                        log('Deleted "' + serviceId + '"');
                        renderVault();
                        renderSessions();
                    }
                });

                // ── Sessions / export / import ──
                $page.find("#vault_lock_all").off("click").on("click", function() {
                    OKSessionCache.clear();
                    log("All sessions locked");
                    renderSessions();
                    renderVault();
                });

                $page.find("#vault_export").off("click").on("click", async function() {
                    var json = await OKVault.exportJSON();
                    var blob = new Blob([json], { type: "application/json" });
                    var a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = "onlyagent-vault-export.json";
                    a.click();
                    URL.revokeObjectURL(a.href);
                    log("Vault exported (ciphertext only — safe to store anywhere)");
                });

                $page.find("#vault_import_btn").off("click").on("click", function() {
                    $page.find("#vault_import_file").trigger("click");
                });

                $page.find("#vault_import_file").off("change").on("change", async function(ev) {
                    var file = ev.target.files[0];
                    if (!file) return;
                    try {
                        var text = await file.text();
                        var result = await OKVault.importJSON(text);
                        log("Imported " + result.imported + ", skipped " + result.skipped);
                        var entries = await OKVault.list();
                        entries.forEach(function(e) {
                            if (e.policy) OKSessionCache.setPolicy(e.serviceId, e.policy);
                        });
                        renderVault();
                    } catch (err) {
                        log("Import error: " + err.message);
                    }
                    ev.target.value = "";
                });

                // ── Init ──
                OKSessionCache.startReaper();
                OKVault.list().then(function(entries) {
                    entries.forEach(function(e) {
                        if (e.policy) OKSessionCache.setPolicy(e.serviceId, e.policy);
                    });
                    renderVault();
                    renderSessions();
                    log("Vault loaded: " + entries.length + " credential(s)");
                });
                setInterval(renderSessions, 10000);
            }
        };

        pagesList["vault"] = page;

        register(null, {
            "plugin_vault": {
                pagesList: pagesList
            }
        });
    }
};
