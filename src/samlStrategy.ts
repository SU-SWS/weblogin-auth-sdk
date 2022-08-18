const util = require('util');
import { Strategy } from 'passport-saml';
import idps from './lib/idps';
import { attrmap } from './lib/attributes';

/*
  An extension of the Passport SAML SamlStrategy for Stanford.
*/
function SamlStrategy (options, verify) {
  // some sensible defaults
  options.protocol = options.protocol || 'https://';
  options.signatureAlgorithm = options.signatureAlgorithm || 'sha256';
  options.identifierFormat =
    options.identifierFormat ||
    'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
  options.acceptedClockSkewMs = options.acceptedClockSkewMs || 60000;
  options.attributeConsumingServiceIndex =
    options.attributeConsumingServiceIndex || false;
  options.forceAuthn = options.forceAuthn || false;
  options.skipRequestCompression = options.skipRequestCompression || false;

  if (options.disableRequestedAuthnContext === undefined) {
    options.disableRequestedAuthnContext = true;
  }

  if (options.validatedInResponseTo === undefined) {
    options.validateInResponseTo = true;
  }

  if (options.entityID) {
    options.issuer = options.entityID;
  }

  if (options.entityId) {
    options.issuer = options.entityId;
  }

  if (options.idp) {
    if (idps[options.idp]) {
      options.entryPoint = idps[options.idp].entryPoint;
      options.cert = idps[options.idp].cert;
    } else {
      throw new Error('Unknown IdP: ' + options.idp);
    }
  }

  if (!options.entryPoint || !options.cert) {
    console.warn('No IdP defined - defaulting to ' + idps.dev.entityID);
    options.entryPoint = idps.dev.entryPoint;
    options.cert = idps.dev.cert;
  }

  if (!options.issuer) {
    throw new Error('No entityId defined!');
  }

  // having either both an encryption cert and private key is valid
  // having neither an encryption cert nor a private key is also valid
  // having only one or the other is NOT valid
  if (!options.decryptionCert && options.decryptionPvk) {
    throw new Error(
      'Only a private key was defined; a public cert is also required'
    );
  }

  if (options.decryptionCert && !options.decryptionPvk) {
    throw new Error(
      'Only a public cert was defined; a private key is also required'
    );
  }

  if (!options.loginPath) {
    throw new Error('No loginPath defined!');
  }

  this.loginPath = options.loginPath;

  // set up an attribute mapper
  this.attributeMapper = attrmap(options.attributeMap);

  // call the parent method before setting the SamlStrategy name,
  // otherwise the name will always be 'saml'
  new Strategy(
    {...this,
      ...options},
    function (req, profile, done) {
      req.session.SamlStrategy = this.name;
      this.attributeMapper(profile, done);
    }.bind(this)
  );

  // set the name of this SamlStrategy to either the name passed in
  // via the options, or the short name of the idp.
  //
  // if neither is set, the name will be 'suSAML'

  this.name = options.name || options.idp || 'suSAML';
};

util.inherits(SamlStrategy, Strategy);

SamlStrategy.prototype.protect = function protect() {
  return function (req, res, next) {
    if (req.isAuthenticated() && req.session.SamlStrategy === this.name) {
      return next();
    } else {
      if (req.session) {
        req.session.SamlStrategy = this.name;
        req.session.returnTo = req.url;
      } else {
        console.warn('passport-stanford: No session property on request!');
      }
      res.redirect(this.loginPath);
    }
  }.bind(this);
};

SamlStrategy.prototype.return = function _return(url) {
  return function (req, res) {
    if (req.session && req.session.returnTo) {
      url = req.session.returnTo;
      delete req.session.returnTo;
    }
    res.redirect(url || '/');
  };
};

SamlStrategy.prototype.metadata = function metadata() {
  return function (req, res) {
    res.type('application/xml');
    res
      .status(200)
      .send(
        this.generateServiceProviderMetadata(this._saml.options.decryptionCert)
      );
  }.bind(this);
};

export default SamlStrategy;
