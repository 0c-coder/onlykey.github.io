// The mode selector that sits at the top of every encrypt and decrypt view.
//
// The top nav is two entries - Encrypt and Decrypt - plus Search. Which
// KIND of encrypt (a message, a file, composite PGP-PQC, derived age) is
// chosen here instead, so the transport is a detail inside the task rather
// than seven sibling links in the header.
//
// These are real hrefs to real routes, not a JS show/hide. pages.js takes
// over every <a> it sees inserted into the DOM, so a click swaps the view
// client-side with no page load, and the URL still deep-links and the back
// button still works. A tab that JS cannot reach is a tab that breaks when
// JS fails; this one degrades to a plain link.
//
// Kept plain CommonJS with no loaders: webpack.config.js's getPagesList()
// requires the plugin tree under bare Node to read the page list before the
// bundle exists, so anything reachable from a plugin's module scope has to
// run there too.

var GROUPS = {
    encrypt: [
        ["encrypt", "Message"],
        ["encrypt-file", "File"],
        ["pqc-encrypt", "PQC-PGP"],
        ["age-encrypt", "AGE"]
    ],
    decrypt: [
        ["decrypt", "Message"],
        ["decrypt-file", "File"],
        ["pqc-decrypt", "PQC-PGP"],
        ["age-decrypt", "AGE"]
    ]
};

/**
 * @param {string} group  "encrypt" or "decrypt"
 * @param {string} active the route name of the view this strip is rendered on
 * @returns {string} the strip's HTML, to prepend to a view
 */
function modeTabs(group, active) {
    var items = GROUPS[group] || [];
    var html = '<nav class="oa-modes" aria-label="' + group + ' method">';
    for (var i = 0; i < items.length; i++) {
        var href = items[i][0];
        var label = items[i][1];
        html += '<a href="./' + href + '"' +
            (href === active ? ' class="active" aria-current="page"' : '') +
            '>' + label + '</a>';
    }
    return html + '</nav>';
}

module.exports = modeTabs;
module.exports.GROUPS = GROUPS;
