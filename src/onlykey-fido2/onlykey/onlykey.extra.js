// ---- transit framing state (module singleton, NOT per-instance) ----------
//
// This file is a FACTORY: every `require("./onlykey.extra.js")(imports)` runs
// the function below again and hands back a fresh $exports. onlykey-api.js
// calls it twice, onlykey-pgp.js once and onlykey-3rd-party.js once, so there
// are four independent copies of everything declared inside it.
//
// The framing state must not be one of them. It describes the DEVICE SESSION -
// which scheme the firmware on the other end speaks, and where its host->device
// counter has got to - and there is exactly one of those. Declared inside the
// factory, transit_select() in onlykey-api.js's copy set v2 = true while
// onlykey-3rd-party.js's copy stayed at its `false` default, so the whole
// derive/composite path silently framed v1 at a v2 device: transit_seal() fell
// through to aesgcm_encrypt(), transit_open() to aesgcm_decrypt(), and
// transit_framed() understated every expected length by 20 bytes.
//
// The first symptom was "Cannot read properties of null (reading 'map')" out of
// the age-derive encrypt - aesgcm_encrypt([]) produces an empty hex string and
// ''.match(/.{2}/g) is null - which says nothing about framing at all. Measured
// on hardware 2026-09-16 against v3.0.5-test, with the connect banner reporting
// "Transit framing: v2" from the other copy at the same time.
//
// Hoisted here, all four copies share one object.
var TRANSIT_V2_MIN = [3, 0, 5];
var transit = { v2: false, ctrOut: 0 };

module.exports = function(imports) {

  /* global TextEncoder */

  var console = imports.console;

  var forge = imports.forge;// require("./forge.js");

  var $exports = {};

  $exports.sha256 = function(s) {
    var md = forge.md.sha256.create();
    md.update($exports.bytes2string(s));
    return Array.from(md.digest().toHex().match(/.{2}/g).map($exports.hexStrToDec));
  };

  $exports.async_sha256 = async function(s) {
    var hash = await imports.window.crypto.subtle.digest({
      name: 'SHA-256'
    }, new TextEncoder().encode(s));
    hash = $exports.buf2hex(hash);
    hash = Array.from(hash.match(/.{2}/g).map($exports.hexStrToDec));
    return hash;
  };

  $exports.wait = ms => new Promise(resolve => setTimeout(resolve, ms));

  $exports.digestMessage = async function(message) {
    const msgUint8 = new TextEncoder().encode(message); // encode as (utf-8) Uint8Array
    const hashBuffer = await imports.window.crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
    return hashHex;
  };

  $exports.digestBuff = async function(buff) {
    const msgUint8 = buff;
    const hashBuffer = await imports.window.crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
    return hashHex;
  };

  $exports.digestArray = async function(buff) {
    const msgUint8 = buff;
    const hashBuffer = await imports.window.crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
    return hashArray;
  };

  $exports.arrayBufToBase64UrlDecode = function(ba64) {
    var binary = $exports.u2f_unb64(ba64);
    var bytes = [];
    for (var i = 0; i < binary.length; i++) {
      bytes.push(binary.charCodeAt(i));
    }

    return new Uint8Array(bytes);
  }

  $exports.arrayBufToBase64UrlEncode = function(buf) {
    var binary = '';
    var bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return imports.window.btoa(binary)
      .replace(/\//g, '_')
      .replace(/=/g, '')
      .replace(/\+/g, '-');
  }

  $exports.buf2hex = function(buffer) {
    // buffer is an ArrayBuffer
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
  };

  $exports.string2bytes = function string2bytes(s) {
    var len = s.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) bytes[i] = s.charCodeAt(i);
    return bytes;
  };

  $exports.u2f_unb64 = function u2f_unb64(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    return imports.window.atob(s + '==='.slice((s.length + 3) % 4));
  };

  $exports.IntToByteArray = function(int) {
    var byteArray = [0, 0, 0, 0];
    for (var index = 0; index < 4; index++) {
      var byte = int & 0xff;
      byteArray[(3 - index)] = byte;
      int = (int - byte) / 256;
    }
    return byteArray;
  };

  $exports.hexStrToDec = function hexStrToDec(hexStr) {
    return ~~(new Number('0x' + hexStr).toString(10));
  };

  $exports.mkchallenge = function mkchallenge(challenge) {
    var s = [];
    for (var i = 0; i < 32; i++) s[i] = String.fromCharCode(challenge[i]);
    return $exports.u2f_b64(s.join());
  };

  $exports.u2f_b64 = function u2f_b64(s) {
    return imports.window.btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  $exports.noop = function noop() {};

  $exports.bytes2string = function bytes2string(bytes) {
    var ret = Array.from(bytes).map(function chr(c) {
      return String.fromCharCode(c);
    }).join('');
    return ret;
  };

  $exports.getstringlen = function getstringlen(bytes) {
    for (var i = 1; i <= bytes.length; i++) {
      // console.info("getstringlen ", i);
      if ((bytes[i] > 122 || bytes[i] < 97) && bytes[i] != 32) return i;
    }
  };

  $exports.bytes2b64 = function bytes2b64(bytes) {
    return $exports.u2f_b64($exports.bytes2string(bytes));
  };

  //todo: move getAllUrlParams to pages plugin
  $exports.getAllUrlParams = function getAllUrlParams(url) {
    // get query string from url (optional) or window
    var queryString = url ? url.split('?')[1] : imports.window.location.search.slice(1);
    // we'll store the parameters here
    var obj = {
      "#": imports.window.location.hash.split('#')[1] // add the hash
    };
    // if query string exists
    if (queryString) {
      // stuff after # is not part of query string, so get rid of it
      queryString = queryString.split('#')[0];
      // split our query string into its component parts
      var arr = queryString.split('&');
      for (var i = 0; i < arr.length; i++) {
        // separate the keys and the values
        var a = arr[i].split('=');
        // set parameter name and value (use 'true' if empty)
        var paramName = a[0];
        var paramValue = typeof(a[1]) === 'undefined' ? true : a[1];

        // (optional) keep case consistent
        //paramName = paramName.toLowerCase();
        //if (typeof paramValue === 'string') paramValue = paramValue.toLowerCase();

        // if the paramName ends with square brackets, e.g. colors[] or colors[2]
        if (paramName.match(/\[(\d+)?\]$/)) {
          // create key if it doesn't exist
          var key = paramName.replace(/\[(\d+)?\]/, '');
          if (!obj[key]) obj[key] = [];
          // if it's an indexed array e.g. colors[2]
          if (paramName.match(/\[\d+\]$/)) {
            // get the index value and add the entry at the appropriate position
            var index = /\[(\d+)\]/.exec(paramName)[1];
            obj[key][index] = paramValue;
          }
          else {
            // otherwise add the value to the end of the array
            obj[key].push(paramValue);
          }
        }
        else {
          // we're dealing with a string
          if (!obj[paramName]) {
            // if it doesn't exist, create property
            obj[paramName] = paramValue;
          }
          else if (obj[paramName] && typeof obj[paramName] === 'string') {
            // if property does exist and it's a string, convert it to an array
            obj[paramName] = [obj[paramName]];
            obj[paramName].push(paramValue);
          }
          else {
            // otherwise add the property
            obj[paramName].push(paramValue);
          }
        }
      }
    }
    return obj;
  }

  $exports.getOS = function getOS() {
    if (typeof window == "undefined" || window.navigator.userAgent == "NODE") {
      os = "Node";
      return os;
    }
    var userAgent = imports.window.navigator.userAgent,
      platform = imports.window.navigator.platform,
      macosPlatforms = ['Macintosh', 'MacIntel', 'MacPPC', 'Mac68K'],
      windowsPlatforms = ['Win32', 'Win64', 'Windows', 'WinCE'],
      iosPlatforms = ['iPhone', 'iPad', 'iPod'],
      os = null;

    if (macosPlatforms.indexOf(platform) !== -1) {
      os = 'Mac OS';
    }
    else if (iosPlatforms.indexOf(platform) !== -1) {
      os = 'iOS';
    }
    else if (windowsPlatforms.indexOf(platform) !== -1) {
      os = 'Windows';
    }
    else if (/Android/.test(userAgent)) {
      os = 'Android';
    }
    else if (!os && /Linux/.test(platform)) {
      os = 'Linux';
    }

    return os;
  }
  
  
  $exports.getBrowser = function getBrowser() {
    
    if(typeof window == "undefined"){
      browser = "Node";
      return browser;
    }
    var vendor = window.navigator.vendor,
      browser = 'Google';

    if (vendor.indexOf('Apple') > -1) {
      browser = 'Apple';
    }

    return browser;
  }


  $exports.ctap_error_codes = {
    0x00: 'CTAP1_SUCCESS',
    0x01: 'CTAP1_ERR_INVALID_COMMAND',
    0x02: 'CTAP1_ERR_INVALID_PARAMETER',
    0x03: 'CTAP1_ERR_INVALID_LENGTH',
    0x04: 'CTAP1_ERR_INVALID_SEQ',
    0x05: 'CTAP1_ERR_TIMEOUT',
    0x06: 'CTAP1_ERR_CHANNEL_BUSY',
    0x0A: 'CTAP1_ERR_LOCK_REQUIRED',
    0x0B: 'CTAP1_ERR_INVALID_CHANNEL',

    0x10: 'CTAP2_ERR_CBOR_PARSING',
    0x11: 'CTAP2_ERR_CBOR_UNEXPECTED_TYPE',
    0x12: 'CTAP2_ERR_INVALID_CBOR',
    0x13: 'CTAP2_ERR_INVALID_CBOR_TYPE',
    0x14: 'CTAP2_ERR_MISSING_PARAMETER',
    0x15: 'CTAP2_ERR_LIMIT_EXCEEDED',
    0x16: 'CTAP2_ERR_UNSUPPORTED_EXTENSION',
    0x17: 'CTAP2_ERR_TOO_MANY_ELEMENTS',
    0x18: 'CTAP2_ERR_EXTENSION_NOT_SUPPORTED',
    0x19: 'CTAP2_ERR_CREDENTIAL_EXCLUDED',
    0x20: 'CTAP2_ERR_CREDENTIAL_NOT_VALID',
    0x21: 'CTAP2_ERR_PROCESSING',
    0x22: 'CTAP2_ERR_INVALID_CREDENTIAL',
    0x23: 'CTAP2_ERR_USER_ACTION_PENDING',
    0x24: 'CTAP2_ERR_OPERATION_PENDING',
    0x25: 'CTAP2_ERR_NO_OPERATIONS',
    0x26: 'CTAP2_ERR_UNSUPPORTED_ALGORITHM',
    0x27: 'CTAP2_ERR_OPERATION_DENIED',
    0x28: 'CTAP2_ERR_KEY_STORE_FULL',
    0x29: 'CTAP2_ERR_NOT_BUSY',
    0x2A: 'CTAP2_ERR_NO_OPERATION_PENDING',
    0x2B: 'CTAP2_ERR_UNSUPPORTED_OPTION',
    0x2C: 'CTAP2_ERR_INVALID_OPTION',
    0x2D: 'CTAP2_ERR_KEEPALIVE_CANCEL',
    0x2E: 'CTAP2_ERR_NO_CREDENTIALS',
    0x2F: 'CTAP2_ERR_USER_ACTION_TIMEOUT',
    0x30: 'CTAP2_ERR_NOT_ALLOWED',
    0x31: 'CTAP2_ERR_PIN_INVALID',
    0x32: 'CTAP2_ERR_PIN_BLOCKED',
    0x33: 'CTAP2_ERR_PIN_AUTH_INVALID',
    0x34: 'CTAP2_ERR_PIN_AUTH_BLOCKED',
    0x35: 'CTAP2_ERR_PIN_NOT_SET',
    0x36: 'CTAP2_ERR_PIN_REQUIRED',
    0x37: 'CTAP2_ERR_PIN_POLICY_VIOLATION',
    0x38: 'CTAP2_ERR_PIN_TOKEN_EXPIRED',
    0x39: 'CTAP2_ERR_REQUEST_TOO_LARGE',
  };


  // ---- FIDO2 transit framing -------------------------------------------
  //
  // v1 (aesgcm_encrypt / aesgcm_decrypt below) is AES-GCM under the transit
  // key with `counter` pinned at 0 - an all-zero IV on every message of a
  // session, in both directions - and tagLength 0, i.e. no authentication at
  // all. Same key and same IV means the same keystream, so any two messages in
  // a session XOR to the XOR of their plaintexts, and the device's own status
  // string is available in the clear from the plain OKCONNECT response to seed
  // it. A derived X-Wing shared secret is 32 bytes and starts at keystream
  // offset zero.
  //
  // v2 frames every message as
  //
  //     [counter big-endian(4)][ciphertext(n)][tag(16)]
  //
  // with IV = [dir(1)][counter(4)][zero(7)], dir 0 device->host and 1
  // host->device so the two directions can never collide on an IV. The counter
  // travels on the wire rather than being tracked on both sides: Windows 10
  // 1903 delivers every FIDO2 request twice, and a derive request rekeys the
  // device mid-session, so any receiver-side counter would drift and then fail
  // every message after the drift.
  //
  // v1 is kept because it is what older firmware speaks. transit_select() picks
  // the scheme from the firmware version, which the host learns from the plain
  // OKCONNECT response - that one is NOT encrypted (opt3 is 0 on that request),
  // so it is readable before any of this applies.
  var counter = 0;   // v1 only. Deliberately never incremented; see above.

  // TRANSIT_V2_MIN and `transit` live at module scope - see the top of this
  // file. Every copy of $exports points at the same object on purpose.
  $exports.transit = transit;

  /** Pick v1 or v2 from a firmware version string like "v3.0.5-prod". */
  $exports.transit_select = function transit_select(fwversion) {
    var m = /v?(\d+)\.(\d+)\.(\d+)/.exec(String(fwversion || ''));
    transit.v2 = false;
    if (m) {
      var got = [+m[1], +m[2], +m[3]];
      for (var i = 0; i < 3; i++) {
        if (got[i] !== TRANSIT_V2_MIN[i]) { transit.v2 = got[i] > TRANSIT_V2_MIN[i]; break; }
        if (i === 2) transit.v2 = true;
      }
    }
    transit.ctrOut = 0;
    console.info('Transit framing:', transit.v2 ? 'v2 (counter + tag)' : 'v1 (legacy)');
    return transit.v2;
  };

  /** Wire length of a message whose plaintext is n bytes. Callers that have to
   *  state an expected response size up front - poll_for_response() checks the
   *  chunk shape against it - need the FRAMED size, not the plaintext size. */
  $exports.transit_framed = function transit_framed(n) {
    return transit.v2 ? n + 4 + 16 : n;
  };

  /** Restart the counter. MUST be called wherever the transit key is replaced -
   *  which includes every derive, because a derive request is itself an
   *  OKCONNECT and the device rolls its key on each one. */
  $exports.transit_reset = function transit_reset() {
    transit.ctrOut = 0;
  };

  function transit_iv(dir, ctr) {
    return Uint8Array.from([
      dir,
      (ctr >>> 24) & 0xff, (ctr >>> 16) & 0xff, (ctr >>> 8) & 0xff, ctr & 0xff,
      0, 0, 0, 0, 0, 0, 0
    ]);
  }

  function bytesFromHex(hex) {
    if (!hex) return [];
    return hex.match(/.{2}/g).map($exports.hexStrToDec);
  }

  /**
   * Seal a host->device message. Returns [counter(4)][ciphertext][tag(16)].
   * Falls back to v1 against older firmware.
   */
  $exports.transit_seal = function transit_seal(plaintext, shared_sec) {
    if (!transit.v2) return $exports.aesgcm_encrypt(plaintext, shared_sec);
    return new Promise(resolve => {
      forge.options.usePureJavaScript = true;
      var ctr = transit.ctrOut++;
      var key = $exports.sha256(shared_sec); //AES256 key sha256 hash of shared secret
      var cipher = forge.cipher.createCipher('AES-GCM', key);
      cipher.start({ iv: transit_iv(1, ctr), tagLength: 128 });
      cipher.update(forge.util.createBuffer(Uint8Array.from(plaintext)));
      cipher.finish();
      var frame = [(ctr >>> 24) & 0xff, (ctr >>> 16) & 0xff, (ctr >>> 8) & 0xff, ctr & 0xff];
      resolve(frame.concat(bytesFromHex(cipher.output.toHex()),
                           bytesFromHex(cipher.mode.tag.toHex())));
    });
  };

  /**
   * Open a device->host message. Throws if the tag does not verify - the bytes
   * did not come from something holding the transit key, and there is no
   * partial acceptance.
   */
  $exports.transit_open = function transit_open(frame, shared_sec) {
    if (!transit.v2) return $exports.aesgcm_decrypt(frame, shared_sec);
    return new Promise((resolve, reject) => {
      forge.options.usePureJavaScript = true;
      frame = Array.from(frame);
      if (frame.length < 20) {
        return reject(new Error('transit: frame too short (' + frame.length + ' bytes)'));
      }
      var ctr = ((frame[0] << 24) >>> 0) + (frame[1] << 16) + (frame[2] << 8) + frame[3];
      var ct = frame.slice(4, frame.length - 16);
      var tag = frame.slice(frame.length - 16);
      var key = $exports.sha256(shared_sec);
      var decipher = forge.cipher.createDecipher('AES-GCM', key);
      decipher.start({
        iv: transit_iv(0, ctr),
        tagLength: 128,
        tag: forge.util.createBuffer(Uint8Array.from(tag))
      });
      if (ct.length) decipher.update(forge.util.createBuffer(Uint8Array.from(ct)));
      if (!decipher.finish()) {
        return reject(new Error('transit: message failed authentication'));
      }
      resolve(bytesFromHex(decipher.output.toHex()));
    });
  };

  /**
   * Perform AES_256_GCM decryption using NACL shared secret
   * @param {Array} encrypted
   * @return {Array}
   */
  $exports.aesgcm_decrypt = function aesgcm_decrypt(encrypted, shared_sec) {
    return new Promise(resolve => {
      forge.options.usePureJavaScript = true;
      var key = $exports.sha256(shared_sec); //AES256 key sha256 hash of shared secret
      //console.log("Key", key);
      var iv = $exports.IntToByteArray(counter);
      while (iv.length < 12) iv.push(0);
      iv = Uint8Array.from(iv);
      //console.log("IV", iv);
      var decipher = forge.cipher.createDecipher('AES-GCM', key);
      decipher.start({
        iv: iv,
        tagLength: 0, // optional, defaults to 128 bits
      });
      //console.log("Encrypted", encrypted);
      var buffer = forge.util.createBuffer(Uint8Array.from(encrypted));
      //console.log("Encrypted length", buffer.length());
      //console.log(buffer);
      decipher.update(buffer);
      decipher.finish();
      var plaintext = decipher.output.toHex();
      //console.log("Plaintext", plaintext);
      //console.log("Decrypted AES-GCM Hex", forge.util.bytesToHex(decrypted).match(/.{2}/g).map(hexStrToDec));
      //encrypted = forge.util.bytesToHex(decrypted).match(/.{2}/g).map(hexStrToDec);
      // bytesFromHex, not .match().map(): forge returns '' for a zero-length
      // input and ''.match(/.{2}/g) is null, so the bare form threw
      // "Cannot read properties of null (reading 'map')" - a message that
      // points nowhere near the actual problem. An empty message decrypts to
      // an empty message.
      resolve(bytesFromHex(plaintext));
    });
  };

  /**
   * Perform AES_256_GCM encryption using NACL shared secret
   * @param {Array} plaintext
   * @return {Array}
   */
  $exports.aesgcm_encrypt = function aesgcm_encrypt(plaintext, shared_sec) {
    return new Promise(resolve => {
      forge.options.usePureJavaScript = true;
      var key = $exports.sha256(shared_sec); //AES256 key sha256 hash of shared secret
      //console.log("Key", key);
      var iv = $exports.IntToByteArray(counter);
      while (iv.length < 12) iv.push(0);
      iv = Uint8Array.from(iv);
      //console.log("IV", iv);
      //Counter used as IV, unique for each message
      var cipher = forge.cipher.createCipher('AES-GCM', key);
      cipher.start({
        iv: iv, // should be a 12-byte binary-encoded string or byte buffer
        tagLength: 0
      });
      //console.log("Plaintext", plaintext);
      cipher.update(forge.util.createBuffer(Uint8Array.from(plaintext)));
      cipher.finish();
      var ciphertext = cipher.output;
      ciphertext = ciphertext.toHex();
      // See aesgcm_decrypt above. poll_for_response() seals an EMPTY payload
      // for its OKPING, so this path is reached on every poll of a v1 session.
      resolve(bytesFromHex(ciphertext));
    });
  };


  return $exports;
};
