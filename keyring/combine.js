var Keyring = require("./index");
var utils = require("../utils");
var consts = require("../consts");
var Fifo = require("../fifo");
var Filter = require("./filters");
var async = require("async");

var p = utils.proxy;

utils.extend(Keyring.prototype, {
	getSelfSignedSubkeys : function(keyId, filter, fields) {
		return this.getSubkeys(keyId, filter, fields).map(p(this, function(subkeyInfo, next, skip) {
			_newestSignature(this.getSubkeySignatures(keyId, subkeyInfo.id, { issuer: keyId, verified: true, sigtype: consts.SIG.SUBKEY }, [ "date", "expires", "revoked", "security" ]), function(err, signatureInfo) {
				if(err)
					next(err);
				else if(signatureInfo == null)
					skip();
				else
					next(null, utils.extend({}, subkeyInfo, { expires: signatureInfo.expires, revoked: signatureInfo.revoked }));
			});
		}));
	},

	getSelfSignedSubkey : function(keyId, id, callback, fields) {
		this.getSubkey(keyId, id, p(this, function(err, subkeyInfo) {
			if(err || subkeyInfo == null)
				return callback(err, subkeyInfo);

			_newestSignature(this.getSubkeySignatures(keyId, id, { issuer: keyId, verified: true, sigtype: consts.SIG.SUBKEY }, [ "date", "expires", "revoked", "security" ]), function(err, signatureInfo) {
				if(err || signatureInfo == null)
					return callback(err, null);

				callback(null, utils.extend({}, subkeyInfo, { expires: signatureInfo.expires, revoked: signatureInfo.revoked }));
			});
		}), fields);
	},

	getSelfSignedIdentities : function(keyId, filter, fields) {
		return this.getIdentities(keyId, filter, fields).map(p(this, function(identityInfo, next, skip) {
			_newestSignature(this.getIdentitySignatures(keyId, identityInfo.id, { issuer: keyId, verified: true, sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ] }, [ "date", "expires", "revoked", "security" ]), function(err, signatureInfo) {
				if(err)
					next(err);
				else if(signatureInfo == null)
					skip();
				else
					next(null, utils.extend({}, identityInfo, { expires: signatureInfo.expires, revoked: signatureInfo.revoked }));
			});
		}));
	},

	getSelfSignedIdentity : function(keyId, id, callback, fields) {
		this.getIdentity(keyId, id, p(this, function(err, identityInfo) {
			if(err || identityInfo == null)
				return callback(err, identityInfo);

			_newestSignature(this.getIdentitySignatures(keyId, id, { issuer: keyId, verified: true }, [ "date", "expires", "revoked", "security" ]), function(err, signatureInfo) {
				if(err || signatureInfo == null)
					return callback(err, null);

				callback(null, utils.extend({}, identityInfo, { expires: signatureInfo.expires, revoked: signatureInfo.revoked }));
			});
		}), fields);
	},

	getSelfSignedAttributes : function(keyId, filter, fields) {
		return this.getAttributes(keyId, filter, fields).map(p(this, function(attributeInfo, next, skip) {
			_newestSignature(this.getAttributeSignatures(keyId, attributeInfo.id, { issuer: keyId, verified: true, sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ] }, [ "date", "expires", "revoked", "security" ]), function(err, signatureInfo) {
				if(err)
					next(err);
				else if(signatureInfo == null)
					skip();
				else
					next(null, utils.extend({}, attributeInfo, { expires: signatureInfo.expires, revoked: signatureInfo.revoked }));
			});
		}));
	},

	getSelfSignedAttribute : function(keyId, id, callback, fields) {
		this.getAttribute(keyId, id, p(this, function(err, attributeInfo) {
			if(err || attributeInfo == null)
				return callback(err, attributeInfo);

			_newestSignature(this.getAttributeSignatures(keyId, id, { issuer: keyId, verified: true }, [ "date", "expires", "revoked", "security" ]), function(err, signatureInfo) {
				if(err || signatureInfo == null)
					return callback(err, null);

				callback(null, utils.extend({}, attributeInfo, { expires: signatureInfo.expires, revoked: signatureInfo.revoked }));
			});
		}), fields);
	},

	/**
	 * Gets the primary ID for the given key. If no primary ID is set or the set primary ID is non-public and not
	 * contained in the given keyring, returns another ID of the key that can be displayed.
	*/
	getPrimaryIdentity : function(keyId, callback, fields) {
		this.getKey(keyId, p(this, function(err, keyInfo) {
			if(err)
				return callback(err);

			if(keyInfo.primary_identity != null)
			{
				this.getSelfSignedIdentity(keyId, keyInfo.primary_identity, p(this, function(err, identityInfo) {
					if(err)
						return callback(err);
					else if(identityInfo == null)
						findOther.call(this);
					else
						callback(null, identityInfo);
				}), fields)
			}
			else
				findOther.call(this);

			function findOther() {
				// TODO: Read only one
				this.getSelfSignedIdentities(keyId, null, fields).forEachSeries(p(this, function(identityInfo, next) {
					callback(null, identityInfo);
				}), function(err) {
					callback(err, null);
				});
			}
		}), [ "primary_identity"]);
	},

	/**
	 * Finds an active subkey that supports the given flag, i.e. one that supports encryption, signing
	 * or authentication.
	 * @param keyId {String} The key ID in whose subkeys to search
	 * @param flag {Number} A flag from {@link consts.KEYFLAG}.
	 * @param callback {Function(Error e, Object keyInfo)} keyInfo is the id info of the subkey or the key itself, or
	 *                                                     null if no key was found.
	 * @param [fields] {Array}
	 */
	getKeyWithFlag : function(keyId, flag, callback, fields) {
		var id = null;
		var filter = { issuer: keyId, verified: true, sigtype: [ consts.SIG.KEY, consts.SIG.SUBKEY, consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ] };
		var now = new Date().getTime();

		var isPkalgoRelatedFlag = ([ consts.KEYFLAG.SIGN, consts.KEYFLAG.ENCRYPT_COMM, consts.KEYFLAG.ENCRYPT_FILES, consts.KEYFLAG.AUTH ].indexOf(flag) != -1);
		var sigDate = null;
		var supports = null;

		this.getSubkeys(keyId, null, [ "id", "pkalgo" ]).forEachSeries(function(subkeyInfo, next) {
			if(isPkalgoRelatedFlag && consts.PKALGO_KEYFLAGS[subkeyInfo.pkalgo] && consts.PKALGO_KEYFLAGS[subkeyInfo.pkalgo].indexOf(flag) == -1)
				return next(); // pkalgo does not support this flag

			sigDate = null;
			supports = isPkalgoRelatedFlag ? 2 : true; // For signing, encryption and authentication, default to true unless overridden by signature
			this.getSubkeySignatures(keyId, subkeyInfo.id, filter, [ "date", "hashedSubPackets", "expires", "revoked" ]).forEachSeries(function(signatureInfo, next) {
				if(signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_FLAGS] && (sigDate == null || signatureInfo.date.getTime() > sigDate))
				{
					if(signatureInfo.expires && signatureInfo.expires.getTime() < now || signatureInfo.revoked) {
						// An expired signature did specify the flag, so do not default to true anymore
						if(supports === 2)
							supports = false;
					} else {
						supports = signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_FLAGS][0].value[flag];
						sigDate = signatureInfo.date.getTime();
					}
				}
				next();
			}, function(err) {
				if(err)
					return next(err);

				if(supports)
					this.getSubkey(keyId, subkeyInfo.id, callback, fields);
				else
					next();
			}.bind(this));
		}.bind(this), function(err) {
			if(err)
				return callback(err);

			// No supporting subkey found, check main key

			var fields2 = [ ].concat(fields);
			if(fields2.indexOf("id") == -1)
				fields2.push("id");
			if(fields2.indexOf("pkalgo") == -1)
				fields2.push("pkalgo");

			this.getKey(keyId, function(err, keyInfo) {
				if(err)
					return callback(err);

				if(isPkalgoRelatedFlag && consts.PKALGO_KEYFLAGS[keyInfo.pkalgo] && consts.PKALGO_KEYFLAGS[keyInfo.pkalgo].indexOf(flag) == -1)
					return callback(null); // Pkalgo does not support flag

				sigDate = null;
				supports = (isPkalgoRelatedFlag || flag == consts.KEYFLAG.CERT) ? 2 : false;

				var signatures = Fifo.fromArraySingle([
					this.getKeySignatures(keyId, filter, [ "date", "hashedSubPackets", "expires", "revoked" ]),
					this.getIdentityList(keyId).map(function(identityId, next) { next(null, this.getIdentitySignatures(keyId, identityId, filter, [ "date", "hashedSubPackets", "expires", "revoked" ])); }.bind(this)),
					this.getAttributeList(keyId).map(function(attributeId, next) { next(null, this.getAttributeSignatures(keyId, attributeId, filter, [ "date", "hashedSubPackets", "expires", "revoked" ])); }.bind(this))
				]).recursive();

				signatures.forEachSeries(function(signatureInfo, next) {
					if(signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_FLAGS] && (sigDate == null || signatureInfo.date.getTime() > sigDate))
					{
						if(signatureInfo.expires && signatureInfo.expires.getTime() < now || signatureInfo.revoked) {
							// An expired signature did specify the flag, so do not default to true anymore
							if(supports === 2)
								supports = false;
						} else {
							supports = signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_FLAGS][0].value[flag];
							sigDate = signatureInfo.date.getTime();
						}
					}
					next();
				}, function(err) {
					if(err)
						return callback(err);

					if(supports)
						callback(null, keyInfo);
					else
						callback(null, null);
				});
			}.bind(this), fields2);
		}.bind(this));
	}
});

function _newestSignature(signatureFifo, callback) {
	var newest = null;

	signatureFifo.forEachSeries(function(signatureInfo, next) {
		if(newest == null || signatureInfo.date.getTime() > newest.date.getTime())
			newest = signatureInfo;
		next();
	}, function(err) {
		callback(err, newest);
	});
}