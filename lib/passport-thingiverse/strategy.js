/**
 * Module dependencies.
 */
var util = require('util')
  , OAuthStrategy = require('passport-oauth').OAuthStrategy;


/**
 * `Strategy` constructor.
 *
 * The Thingiverse authentication strategy authenticates requests by delegating to
 * Thingiverse using the OAuth protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `err` should be set.
 *
 * Options:
 *   - `clientID`     identifies client to Thingiverse
 *   - `clientSecret`  secret used to establish ownership of the consumer key
 *   - `callbackURL`     URL to which Thingiverse will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     passport.use(new ThingiverseStrategy({
 *         consumerKey: 'consumer-key',
 *         consumerSecret: 'consumer-secret'
 *         callbackURL: 'https://www.example.net/auth/thingiverse/callback'
 *       },
 *       function(token, tokenSecret, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

function Strategy(options, verify) {
  options = options || {};
  options.accessTokenURL = options.accessTokenURL || 'https://www.thingiverse.com/login/oauth/access_token';
  options.userAuthorizationURL = options.userAuthorizationURL || 'https://www.thingiverse.com/login/oauth/authorize';
  options.sessionKey = options.sessionKey || 'oauth:thingiverse';

  OAuthStrategy.call(this, options, verify);
  this.name = 'thingiverse';
}

/**
 * Inherit from `OAuthStrategy`.
 */
util.inherits(Strategy, OAuthStrategy);

/**
 * Retrieve user profile from Thingiverse.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id (Thingiverse id)`
 *   - `name (Thingiverse name)`
 *   - `email (Thingiverse email)`
 *
 * @param {String} token
 * @param {String} tokenSecret
 * @param {Object} params
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(token, tokenSecret, params, done) {
this._oauth.get('https://api.thingiverse.com/users/me', token, tokenSecret, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }
    
    try {
      var json = JSON.parse(body);
      
      var profile = { provider: 'thingiverse' };
      profile.id = json.user.id;
      profile.name = json.user.name;
      profile.email = json.user.email;
      
      profile._raw = body;
      profile._json = json;
      
      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
