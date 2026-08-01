// Loads the vendored PQC-aware openpgp.js fork (see vendor/openpgp/VENDORED.md).
//
// That file is a plain script - `var openpgp = (function(exports){...})({})`
// - not a CommonJS module (no `module.exports`), so a normal `require()`
// only gets webpack's empty default export. python-onlykey's own
// openpgp_bridge/bridge.js already works around this the same way, via
// Node's `fs.readFileSync` + `new Function(source + ';return openpgp;')()`.
// This does the same trick with the source pulled in via raw-loader
// instead, so it also works inside a browser bundle (no `fs`).
const openpgpSource = require('raw-loader!./vendor/openpgp/openpgp.js').default;
const openpgp = new Function(openpgpSource + '\n;return openpgp;')();

module.exports = openpgp;
