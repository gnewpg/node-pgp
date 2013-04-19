var Keyring = require("./index");
var utils = require("../utils");
var async = require("async");
var consts = require("../consts");

/*
 * This is complicated. For each key, there may be several owner trust entries, representing a trust signature
 * chain, with the following fields:
 * - keyPath: The issuers of the signatures in signaturePath
 * - signaturePath: The trust signature chain
 * - regexp: An array of regexps that have been defined in the trust signature chain
 * - amount: A float between 0 and 1, 1 for full trust (120), 0.5 for partial trust (60)
 * - level: An integer, defining the remaining maximum size for the chain of trust
 * Somewhere, there an initial trust that is set by the user.
 * - Let’s say the user has given initial trust to a key "gnewpg". keyPath, signaturePath and regexp are
 *   empty arrays, amount is 1, level is 255 (max).
 * - "gnewpg" tsigns "gswot" with amount=60, level=2, no regexp. This adds an owner trust entry to the "gswot"
 *   key, with the following values: {keyPath: [ "gnewpg" ], signaturePath: [ "sig1" ], regexp: [ ], amount: 0.5, level: 1}
 * - "gnewpg" tsigns "gswot" another time, this time with amount=60, level=2, regexp=abc. This adds another
 *   owner trust entry to the "gswot" key, with the following values: {keyPath: [ "gnewpg" ], signaturePath: [ "sig2" ], regexp: [ "abc" ], amount: 0.5, level: 1}
 * - "gswot" tsigns "cdauth" with amount=120, level=1, regexp=def. This adds two owner trust entries to the
 *   "cdauth" key, as there are two trust chains from "gnewpg" to "cdauth". The values are:
 *   {keyPath: [ "gnewpg", "gswot" ], signaturePath: [ "sig1", "sig3" ], regexp: [ "def" ], amount: 0.5, level: 0}
 *   {keyPath: [ "gnewpg", "gswot" ], signaturePath: [ "sig2", "sig3" ], regexp: [ "abc", "def" ], amount: 0.5, level: 0}
 *   Note that as the second entry has conflicting regexps, it does not actually set any trust. Also note
 *   how the trust amounts have been multiplied by each other (0.5 * 1). Also note that level is 0 because
 *   the previous entries of the signature chains both had level=1 and it is decreased by 1 in each step.
 * - "cdauth" tsigns "tdauth" with amount=90, level=1, no regexp. This does not add any owner trust records,
 *   as "cdauth" is only owner-trusted with level-0 signature chains.
 * - "gswot" tsigns "gnewpg" with amount=90, level=1, no regexp. This does not add any owner trust records,
 *   as "gnewpg" is already in the trust chain of all owner trust records of "gswot"
 *
 * Now there is the identity trust. When a key with an owner-trust record signs an identity or attribute,
 * this is what happens:
 * - Only owner-trust records are considered where all regexps match the signed identity (or, in case of
 *   an attribute, where there are no regexps)
 * - For each signature issuer, the owner-trust record with the highest trust amount counts. Actually,
 *   the owner-trust ^ 1.5 is used, because this makes it necessary to get three signatures from a partially-trusted
 *   key in order to be fully trusted.
 * - The trust on the name of an identity and on an attribute will be the sum of the owner trust amounts of
 *   all the keys that have signed it with CERT_0, CERT_2 or CERT_3, only counting one signature for each issuer
 * - The trust on the e-mail adrress of an identity will be the sum of the owner trust amounts of all the keys
 *   that have signed it with CERT_0, CERT_1, CERT_2 or CERT_3, only counting one signature for each issuer
 */

utils.extend(Keyring.prototype, {
	trustKey : function(keyId, callback) {
		this._getOwnerTrustInfo(keyId, { keyPath: new Keyring.Filter.Equals([ ]) }, [ ]).forEachSeries(function(it, next) {
			// Is already trusted
			callback(null);
		}, function(err) {
			if(err)
				return callback(err);

			this.__addOwnerTrustInfo(keyId, { keyPath: [ ], signaturePath: [ ], regexp: [ ], amount: 1, level: 255 }, callback);
		}.bind(this));
	},

	untrustKey : function(keyId, callback) {
		this._removeKeyTrust(keyId).forEachSeries(function(trustInfo, next) {
			this.__ownerTrustChanged(trustInfo.key, next);
		}.bind(this), callback);
	},

	/**
	 * Called when a trust signature is verified. Extends all the trust chains that exist for the key
	 * with the new signature.
	 */
	__addOwnerTrustSignature : function(onKeyId, signatureInfo, callback) {
		this._getOwnerTrustInfo(signatureInfo.issuer, { level: new Keyring.Filter.GreaterThan(0) }, [ "keyPath", "signaturePath", "regexp", "amount", "level" ]).forEachSeries(function(trustInfo, next) {
			this.__addSignatureToTrustPath(onKeyId, trustInfo, signatureInfo, next);
		}.bind(this), callback);
	},

	/**
	 * Creates trust chains for a signature. Recursively re-invokes itself for trust signatures that
	 * the signed key has issued, avoiding recursive loops and stopping when the trust level is 0.
	 */
	__addSignatureToTrustPath : function(onKeyId, trustInfo, signatureInfo, callback) {
		var level = signatureInfo.hashedSubPackets[consts.SIGSUBPKT.TRUST][0].value.level;
		var regexp = signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REGEXP] ? signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REGEXP][0].value : null;

		// Trust amount 120 (full trust): factor 1, trust amount 60 (partial trust): factor 0.5
		var factor = signatureInfo.hashedSubPackets[consts.SIGSUBPKT.TRUST][0].value.amount / 120;
		if(factor > 1)
			factor = 1;
		if(factor == 0)
			return callback(null);

		var thisTrust = {
			keyPath: trustInfo.keyPath.concat([ signatureInfo.issuer ]),
			signaturePath: trustInfo.signaturePath.concat([ signatureInfo.id ]),
			regexp: trustInfo.regexp.concat(regexp ? [ regexp ] : [ ]),
			amount: trustInfo.amount*factor,
			level: Math.min(trustInfo.level-1, level)
		};

		this.__addOwnerTrustInfo(onKeyId, thisTrust, callback);
	},

	/**
	 * Wrapper for _addOwnerTrustInfo() that updates the trust paths after adding.
	 */
	__addOwnerTrustInfo : function(keyId, trustInfo, callback) {
		this._addOwnerTrustInfo(keyId, trustInfo, function(err) {
			if(err)
				return callback(err);

			this.__ownerTrustChanged(keyId, function(err) {
				if(err || trustInfo.level == 0)
					return callback(err);

				if(trustInfo.level == 0)
					return callback();

				var trustSigFilter = { verified: true, trustSignature: true, revoked: null, expired: new Keyring.Filter.Not(new Keyring.Filter.LessThan(new Date())), sigtype: [ consts.SIG.KEY, consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ] };
				this.getKeySignatureListByIssuer(keyId, trustSigFilter).concat(this.getIdentitySignatureListByIssuer(keyId, trustSigFilter), this.getAttributeSignatureListByIssuer(keyId, trustSigFilter)).forEachSeries(function(signatureRecord, next) {
					// Avoid recursive trust chains
					if(signatureRecord.keyId == keyId || trustInfo.keyPath.indexOf(signatureRecord.keyId) != -1)
						return next();

					this.getSignatureById(signatureRecord.signatureId, function(err, signatureInfo) {
						if(err)
							return next(err);

						this.__addSignatureToTrustPath(signatureRecord.keyId, trustInfo, signatureInfo, next);
					}.bind(this), [ "id", "issuer", "hashedSubPackets" ]);
				}.bind(this), callback);
			}.bind(this));
		}.bind(this));
	},

	/**
	 * Called when a trust signature is removed/revoked/expires. Removes all trust chains that involve
	 * this signature.
	 */
	__removeOwnerTrustSignature : function(signatureId, callback) {
		var keysChecked = { };
		this._removeOwnerTrustBySignature(signatureId, callback).forEachSeries(function(trustInfo, next) {
			if(keysChecked[trustInfo.key])
				return next();

			keysChecked[trustInfo.key] = true;
			this.__ownerTrustChanged(trustInfo.key, next);
		}.bind(this), callback);
	},

	/**
	 * Called when the owner trust of a key has changed. Recalculates the trust in all identities and
	 * attributes that this key has signed.
	 */
	__ownerTrustChanged : function(keyId, callback) {
		async.series([
			function(next) {
				var identitiesChecked = { };
				this.getIdentitySignatureListByIssuer(keyId, { verified: true, sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ]}).forEachSeries(function(signatureRecord, next) {
					if(identitiesChecked[signatureRecord.identityId])
						return next();

					identitiesChecked[signatureRecord.identityId] = true;
					this.__updateIdentityTrust(signatureRecord.keyId, signatureRecord.identityId, next);
				}.bind(this), next);
			}.bind(this),
			function(next) {
				var attributesChecked = { };
				this.getAttributeSignatureListByIssuer(keyId, { verified: true, sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_2, consts.SIG.CERT_3 ]}).forEachSeries(function(signatureRecord, next) {
					if(attributesChecked[signatureRecord.attributeId])
						return next();

					attributesChecked[signatureRecord.attributeId] = true;
					this.__updateAttributeTrust(signatureRecord.keyId, signatureRecord.attributeId, next);
				}.bind(this), next);
			}.bind(this)
		], callback);
	},

	/**
	 * Calculates the owner trust of a given key. If onId is given, regexp trusts are also considered if
	 * they match the expression.
	 */
	__getOwnerTrust : function(keyId, onId, callback) {
		this._getOwnerTrustInfo(keyId, null, [ "keyPath", "regexp", "amount" ]).toArraySingle(function(err, trustRecords) {
			if(err)
				return callback(err);

			var ret = 0;

			outer: for(var i=0; i<trustRecords.length; i++) {
				// Filter by regexp
				for(var j=0; j<trustRecords[i].regexp.length; j++) {
					if(onId == null || !onId.match(new RegExp("^"+trustRecords[i].regexp[j]+"$"))) {
						continue outer;
					}
				}

				if(trustRecords[i].amount > ret)
					ret = trustRecords[i].amount;

				if(ret == 1)
					break;
			}

			callback(null, ret);
		});
	},

	__updateIdentityTrust : function(keyId, identityId, callback) {
		var trustName = { };
		var trustEmail = { };
		this.getIdentitySignatures(keyId, identityId, { verified: true, revoked: null, expired: new Keyring.Filter.Not(new Keyring.Filter.LessThan(new Date())), sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ] }, [ "issuer", "sigtype" ]).forEachSeries(function(signatureInfo, next) {
			this.__getOwnerTrust(signatureInfo.issuer, identityId, function(err, ownerTrust) {
				if(err)
					return next(err);

				if(signatureInfo.sigtype != consts.SIG.CERT_1 && (!trustName[signatureInfo.issuer] || trustName[signatureInfo.issuer] < ownerTrust))
					trustName[signatureInfo.issuer] = ownerTrust;

				if(!trustEmail[signatureInfo.issuer] || trustEmail[signatureInfo.issuer] < ownerTrust)
					trustEmail[signatureInfo.issuer] = ownerTrust;

				next();
			});
		}.bind(this), function(err) {
			if(err)
				return callback(err);

			var update = { nameTrust : 0, emailTrust : 0 };
			for(var i in trustName)
				update.nameTrust += Math.pow(trustName[i], 1.5);
			for(var i in trustEmail)
				update.emailTrust += Math.pow(trustEmail[i], 1.5);

			update.nameTrust = Math.round(update.nameTrust*100)/100;
			update.emailTrust = Math.round(update.emailTrust*100)/100;

			this._updateIdentity(keyId, identityId, update, callback);
		}.bind(this));
	},

	__updateAttributeTrust : function(keyId, attributeId, callback) {
		var trust = { };
		this.getAttributeSignatures(keyId, attributeId, { verified: true, revoked: null, expired: new Keyring.Filter.Not(new Keyring.Filter.LessThan(new Date())), sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_2, consts.SIG.CERT_3 ] }, [ "issuer", "sigtype" ]).forEachSeries(function(signatureInfo, next) {
			this.__getOwnerTrust(signatureInfo.issuer, null, function(err, ownerTrust) {
				if(err)
					return next(err);

				if(!trust[signatureInfo.issuer] || trust[signatureInfo.issuer] < ownerTrust)
					trust[signatureInfo.issuer] = ownerTrust;

				next();
			});
		}.bind(this), function(err) {
			if(err)
				return callback(err);

			var update = { trust : 0 };
			for(var i in trust)
				update.trust += Math.pow(trust[i], 1.5);
			update.trust = Math.round(update.trust*100)/100;

			this._updateAttribute(keyId, attributeId, update, callback);
		}.bind(this));
	}
});

function __getNotImplementedFifo() {
	var ret = new Fifo();
	ret._end(new Error("Not implemented."));
	return ret;
}