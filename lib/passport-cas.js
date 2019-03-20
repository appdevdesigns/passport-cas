/**
 * Module dependencies.
 */
var url = require('url')
  , util = require('util')
  , Strategy = require('passport-strategy')
  , CAS = require('cas');


/**
 * Creates an instance of `CasStrategy`.
 *
 * CAS stands for Central Authentication Service, and is a single sign-on
 * solution for the web.
 *
 * Authentication is done by redirecting the user to the CAS login page. The
 * user will return with a ticket in the querystring. This ticket is then
 * validated by the application against the CAS server to obtain the username 
 * and profile.
 *
 * (CAS optionally allows the application to obtain tickets for 3rd party 
 * services on behalf of the user. This requires the use of a PGT callback
 * server, which can be run with the PgtServer() function also from this
 * module.)
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(username, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `casURL`            URL of the CAS server (e.g. https://signin.example.com/cas)
 *   - `pgtURL`            Optional. URL of the PGT callback server (e.g. https://callback.example.com)
 *   - `sessionKey`        Optional. The name to use for storing CAS information within the `req.session` object. Default is 'cas'.
 *   - `propertyMap`       Optional. A basic key-value object for mapping extended user attributes from CAS to passport's profile format.
 *   - `passReqToCallback` Optional. When `true`, `req` is the first argument to the verify callback (default: `false`)
 *   - `sslCA`             Optional. SSL CA bundle to use to validate the PGT server.
 *
 * Example:
 *
 *     var CasStrategy = require('passport-cas2').Strategy;
 *     var cas = new CasStrategy({
 *        casURL: 'https://signin.example.com/cas',
 *        propertyMap: { 
 *          id: 'guid',
 *          givenName: 'givenname',
 *          familyName: 'surname',
 *          emails: 'defaultmail'
 *        }
 *     }, 
 *     function(username, profile, done) {
 *        User.findOrCreate(..., function(err, user) {
 *          done(err, user);
 *        });
 *     });
 *     passport.use(cas);
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function CasStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};
    
  if (!verify) { throw new TypeError('CasStrategy requires a verify callback'); }
  if (!options.casURL) { throw new TypeError('CasStrategy requires a casURL option'); }
  
  Strategy.call(this);
  this.name = 'cas';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
  
  this.casBaseUrl = options.casURL;
  this.casPgtUrl = options.pgtURL || undefined;
  this.casPropertyMap = options.propertyMap || {};
  this.casSessionKey = options.sessionKey || 'cas';
  
  this.cas = new CAS({
    base_url: this.casBaseUrl,
    version: 2,
    external_pgt_url: this.casPgtUrl,
    ssl_cert: options.sslCert,
    ssl_key: options.sslKey,
    ssl_ca: options.sslCA
  });
  
}

/**
 * Inherit from `Strategy`.
 */
util.inherits(CasStrategy, Strategy);

/**
 * Authenticate request by validating a ticket with the CAS server.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
CasStrategy.prototype.authenticate = function(req, options) {
  if (!req._passport) { return this.error(new Error('passport.initialize() middleware not in use')); }
  options = options || {};
  
  var self = this;
  var reqURL = url.parse(req.originalUrl || req.url, true);
  var service;
  
  // `ticket` is present if user is already authenticated/authorized by CAS
  var ticket = reqURL.query['ticket'];
  
  // The `service` string is the current URL, minus the ticket
  delete reqURL.query['ticket'];
  service = url.format({
    protocol: req.headers['x-forwarded-proto'] || req.headers['x-proxied-protocol'] || req.protocol || 'http',
    host: req.headers['x-forwarded-host'] || req.headers.host || reqURL.host,
    pathname: req.headers['x-proxied-request-uri'] || reqURL.pathname,
    query: reqURL.query
  });
  
  if (!ticket) {
    // Redirect to CAS server for authentication
    self.redirect(self.casBaseUrl + '/login?service=' + encodeURIComponent(service), 307);
  }
  else {
    // User has returned from CAS site with a ticket
    self.cas.validate(ticket, function(err, status, username, extended) {
      
      // Ticket validation failed
      if (err) {
        var date = new Date();
        var token = Math.round(date.getTime() / 60000);
        if (req.query['_cas_retry'] != token) {
            // There was a CAS error. A common cause is when an old
            // `ticket` portion of the querystring remains after the
            // session times out and the user refreshes the page.
            // So remove the `ticket` and try again.
            var url = (req.originalUrl || req.url)
                .replace(/_cas_retry=\d+&?/, '')
                .replace(/([?&])ticket=[\w.-]+/, '$1_cas_retry='+token);
            self.redirect(url, 307);
        } else {
            // Already retried. There is no way to recover from this.
            self.fail(err);
        }
      }
      
      // Validation successful
      else {
        // The provided `verify` callback will call this on completion
        function verified(err, user, info) {
          if (err) { return self.error(err); }
          if (!user) { return self.fail(info); }
          self.success(user, info);
        }
        
        req.session[self.casSessionKey] = {};
        
        if (self.casPgtUrl) {
          req.session[self.casSessionKey].PGTIOU = extended.PGTIOU;
        }
        
        var attributes = extended.attributes;
        var profile = {
          provider: 'CAS',
          id: extended.id || username,
          displayName: attributes.displayName || username,
          name: {
            familyName: null,
            givenName: null,
            middleName: null
          },
          emails: []
        };
        
        // Map relevant extended attributes returned by CAS into the profile
        for (var key in profile) {
          if (key == 'name') {
            for (var subKey in profile[key]) {
              var mappedKey = self.casPropertyMap[subKey] || subKey;
              var value = attributes[mappedKey];
              if (Array.isArray(value)) {
                profile.name[subKey] = value[0];
              } else {
                profile.name[subKey] = value;
              }
              delete attributes[mappedKey];
            }
          } 
          else if (key == 'emails') {
            var mappedKey = self.casPropertyMap.emails || 'emails';
            var emails = attributes[mappedKey];
            if (Array.isArray(emails)) {
              if (typeof emails[0] == 'object') {
                profile.emails = emails;
              }
              else {
                for (var i=0; i<emails.length; i++) {
                  profile.emails.push({
                    'value': emails[i],
                    'type': 'default'
                  });
                }
              }
            }
            else {
              profile.emails = [emails];
            }
            delete attributes[mappedKey];
          }
          else {
            var mappedKey = self.casPropertyMap[key] || key;
            var value = attributes[mappedKey];
            if (Array.isArray(value)) {
              profile[key] = value[0];
            } 
            else if (value) {
              profile[key] = value;
            }
            delete attributes[mappedKey];
          }
        }
        // Add remaining attributes to the profile object
        for (var key in attributes) {
          profile[key] = attributes[key];
        }
        
        if (self._passReqToCallback) {
          self._verify(req, username, profile, verified);
        } else {
          self._verify(username, profile, verified);
        }
      }
        
    }, service);
  }
};


/**
 * Log the user out of the application site, and also out of CAS.
 *
 * @param (Object) req
 * @param (Object) res
 * @param {String} returnUrl
 * @api public
 */
CasStrategy.prototype.logout = function(req, res, returnUrl) {
  req.logout();
  if (returnUrl) {
    this.cas.logout(req, res, returnUrl, true);
  } else {
    this.cas.logout(req, res);
  }
};


/**
 * Request a CAS ticket for accessing a service on behalf of the logged in user.
 * This ticket is to be added to the service's query string.
 *
 * Example:
 *
 *      var serviceURL = 'http://example.com/get/my/data';
 *      cas.getProxyTicket(req, serviceURL, function(err, ticket) {
 *          if (!err) {
 *              serviceURL += '?ticket=' + ticket;
 *              request(serviceURL, ... ); // request the service
 *          }
 *      });
 *
 * @param {Object} req
 *      HTTPRequest object from Connect/Express
 * @param {String} targetService
 *      The URL of service being requested on behalf of the user
 * @param {Function} done
 *      Completion callback with signature `fn(err, ticket)`
 * @api public
 */
CasStrategy.prototype.getProxyTicket = function(req, targetService, done) {
  var err, pgtiou;
  if (!req.session) {
    err = new Error('Session is not found');
  }
  else if (!req.session[this.casSessionKey]) {
    err = new Error('User is not authenticated with CAS');
  }
  else {
    pgtiou = req.session[this.casSessionKey].PGTIOU;
    if (!pgtiou) {
      err = new Error('PGTIOU token not found. Make sure pgtURL option is correct, and the CAS server allows proxies.');
    }
  }
  
  if (err) {
    return done(err);
  }
  else {
    this.cas.getProxyTicket(pgtiou, targetService, function(err, PT) {
      done(err, PT);
    });
  }
}



/**
 * Expose `CasStrategy`.
 */
module.exports.Strategy = CasStrategy;



/**
 * Start a CAS PGT callback server. PGT stands for proxy granting ticket.
 *
 * This is the server needed to obtain CAS tickets for 3rd party services on
 * behalf of the user. It is typically run as a separate process from the
 * application. Multiple applications may share the same PGT callback server.
 * 
 * @param {String} casURL
 *      The URL of the CAS server.
 * @param {String} pgtURL
 *      The URL of this PGT callback server. It must use HTTPS and be accessible
 *      by the CAS server over the network.
 *      The 3rd party services you request may need to whitelist this URL.
 * @param {String} serverCertificate
 *      The SSL certificate for this PGT callback server.
 * @param {String} serverKey
 *      The key for the SSL certificate.
 * @param {Array} serverCA
 *      Optional array of SSL CA and intermediate CA certificates
 * @api public
 */
function PgtServer(casURL, pgtURL, serverCertificate, serverKey, serverCA) {
  var parsedURL = url.parse(pgtURL);
  var cas = new CAS({
    base_url: casURL,
    version: 2.0,
    pgt_server: true,
    pgt_host: parsedURL.hostname,
    pgt_port: parsedURL.port,
    ssl_key: serverKey,
    ssl_cert: serverCertificate,
    ssl_ca: serverCA || null
  });
}


/**
 * Expose `PgtServer`.
 */
module.exports.PgtServer = PgtServer;
 
