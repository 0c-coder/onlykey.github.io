if (!!(process.env.NODE_ENV === "production")) {
  console.log("ERROR! ------------- LOADING DEVEL PLUGINS GOT INCLUDED SOMEHOW IN PRODUCTION! ------------- ERROR!");
  throw (new Error("ERROR! ------------- LOADING DEVEL PLUGINS GOT INCLUDED SOMEHOW IN PRODUCTION! ------------- ERROR!"));
  return;
}

//just in case this file gets included somehow in production
console.log("WARNING! ------------- LOADING DEVEL PLUGINS! ------------- WARNING!");

module.exports = [];

/* debug console emitter */
module.exports.push(require("./plugins/console/console_debug.js"));

  

/* vault: prerelease, development builds only */
module.exports.push(require("./plugins/vault/vault.js"));
