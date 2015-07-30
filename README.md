# passport-cas2
CAS 2.0 strategy for Passport.js authentication

[Passport](http://passportjs.org/) strategy for authenticating with the 
[CAS](https://wiki.jasig.org/display/CAS/Home) single sign-on service.

This module lets you authenticate using CAS in your Node.js applications.
Suitable for any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-cas2
    
## Usage

#### Configure Strategy

The CAS authentication strategy authenticates users against a CAS server where
they have an account. The strategy requires a `verify` callback, which
accepts a validated username (and possibly also a user profile) and calls `done`
providing a user object.

```javascript
    var CasStrategy = require('passport-cas2').Strategy;
    
    passport.use(new CasStrategy({
      casURL: 'https://signin.example.com/cas'
    }, 
    // This is the `verify` callback
    function(username, profile, done) {
      User.findOrCreate({ ... }, function(err, user) {
        done(err, user);
      });
    });
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'cas'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```javascript
    app.get('/auth/cas',
      passport.authenticate('cas', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });
```

#### Profile Fields

Some CAS servers may provide extended user attributes in addition to just
the username. These will be added to the `profile` object that is passed to 
the `verify` callback, though the exact format will vary depending on the CAS
provider.

You should customise the `verify` callback to fit your CAS server's attributes
format. Alternatively, you can specify a `propertyMap` object during 
initialization, to have the profile more or less sorted out by the time it
gets to the `verify` callback.

```javascript
    passport.use(new CasStrategy({
      casURL: 'https://signin.example.com/cas',
      propertyMap: { 
        id: 'guid',
        givenName: 'givenname',
        familyName: 'surname',
        emails: 'defaultmail'
      }
    }, 
    function(username, profile, done) {
      User.findOrCreate({ id: profile.id }, function(err, user) {
        user.name = profile.name.givenName + ' ' + profile.name.familyName;
        done(err, user);
      });
    });
```

#### CAS Logout

Passport already provides a method to end the user's session in your 
application, but if you rely on that alone users can automatically be logged in 
again without needing to re-enter their credentials. This is because their 
session with the CAS server would still be active, independent of your 
application.

To log the user out of the CAS server, use the `logout` function from this 
module instead. It will redirect the user to the CAS server, and they will 
return to your specified URL in a logged out state.

```javascript
    var cas = new CasStrategy({
      casURL: 'https://signin.example.com/cas'
    }, 
    function(username, profile, done) {
      User.findOrCreate({ ... }, function(err, user) {
        done(err, user);
      });
    });
    passport.use(cas);
    
    app.get('/logout', function(req, res) {
      var returnURL = 'http://example.com/';
      cas.logout(req, res, returnURL);
    });
```

## Proxy Authorization

CAS allows the application to obtain authorization for 3rd party 
services (that also the same CAS server) on behalf of the user. This requires
the use of a PGT callback server, which can be run with the `PgtServer` function
also from this module.

#### PGT Callback Server

This is the server needed to obtain CAS tickets for 3rd party services on
behalf of the user. It is typically run as a separate process from the
application. Multiple applications may share the same PGT callback server. Note
that it must use HTTPS and be accessible by the CAS server over the network.
The 3rd party services you request may need to add this URL as a trusted proxy
as well.

```javascript
    var PgtServer = require('passport-cas2').PgtServer;
    PgtServer(
        'https://signin.example.com/cas',
        'https://myserver.example.com:1337',
        mySSLCertificate,
        mySSLKey
    );
```
    
#### Configuring the Application

```javascript
    var cas = new CasStrategy({
      casURL: 'https://signin.example.com/cas',
      pgtURL: 'https://myserver.example.com:1337'
    }, 
    function(username, profile, done) {
      User.findOrCreate({ ... }, function(err, user) {
        done(err, user);
      });
    });
    passport.use(cas);
```

#### Obtaining Authorization

First, you get a CAS proxy ticket for the user. Then you append that ticket to
the service's URL query string. The service should then behave as if the user 
has logged in to it directly via CAS.
    
```javascript
    var serviceURL = 'http://service.example.com/get/my/data';
    cas.getProxyTicket(req, serviceURL, function(err, ticket) {
      if (!err) {
        serviceURL += '?ticket=' + ticket;
        request(serviceURL, ... ); // request the service
      }
    });
```

## License

[The MIT License](http://opensource.org/licenses/MIT)
