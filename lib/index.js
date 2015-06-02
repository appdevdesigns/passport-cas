/**
 * Module dependencies.
 */
var cas = require('./passport-cas.js');


/**
 * Expose `CasStrategy` directly from package.
 */
exports = module.exports = cas.Strategy;

/**
 * Export constructors.
 */
exports.Strategy = cas.Strategy;
exports.PgtServer = cas.PgtServer;
