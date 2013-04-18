var Keyring = require("./index");
var utils = require("../utils");
var signing = require("../signing");
var consts = require("../consts");
var packetContent = require("../packetContent");
var Fifo = require("../fifo");
var Filter = require("./filters");
var async = require("async");

/*
 * These are the relations that need to be calculated:
 * 1. Verify all kinds of signatures. For this, the signed key (plus the signed subkey, identity or attribute) and the issuer key need to be available.
 *    The signed key can be assumed to be available as else the signature wouldn't be there. This check needs to be done in the following cases:
 *     a) A signature is added. Verify it if the issuer key is available.
 *     b) A public key is added. Verify all unverified signatures issued by this key.
 * 2. Check if a key has been revoked. For this, it needs to be checked whether the key contains validated key revocation signatures. These are valid
 *    if the signature has been issued by the key itself, or it has been issued by a key whose fingerprint is set in a key or certification signature
 *    that contains a hashed sub-packet of the type SIGSUBPKT.REV_KEY. The revocation or expiration status of such a signature is irrelevant, as that
 *    would make revoking a revocation possible, which is not intended. This check needs to be done in the following cases:
 *     a) a revocation signature is verified by check 1. The key is revoked if the issuer is authorised.
 *     b) a key or certification signature is verified that contains a revocation key authorisation. Check 2a is re-run on all revocation signatures of the key.
 * 3. Check if a subkey has been revoked. This is the case if the key contains (verified) subkey revocation signatures. A subkey revocation signature is
 *    valid if it has been issued by a key that has also signed the key with a subkey binding signature ("parent key"), or by a key that has been authorised
 *    by the parent key to make revocations for it as described in check 2. A subkey revocation signature only revokes the subkey binding signature, not
 *    the key itself! (As that would make it possible for anyone to revoke a key by just signing it with a subkey binding signature.) It also revokes subkey
 *    binding signatures that have been made on a later date than the revocation signature. This check needs to be done in the following cases:
 *     a) a subkey revocation signature is verified by check 1. The subkey binding signature is revoked if the issuer is authorised.
 *     b) a subkey binding signature is verified by check 1. Check 3a is rerun on all subkey revocation signatures of the key.
 *     c) a key or certification signature is verified that contains a revocation key authorisation. All subkey revocation signatures of all keys that
 *        contain a subkey binding signature of this key are checked again by check 3a.
 * 4. Check if a key or certification signature has been revoked. This is the case if the same key, identity or attribute contains a verified signature
 *    of the type SIG.CERT_REVOKE. Such a signature is valid if it has been issued by the same key that issued the signature that is being revoked, [or
 *    by a key that is authorised by that key to make revocations for it (as described in check 2)]. [A signature revocation signature may contain the hash
 *    of the signature it revokes in the SIGSUBPKT.SIGTARGET sub-packet, in that case it only revokes that specific signature.] Else it revokes all signatures
 *    issued by the same key on the same object on a date earlier than that of the revocation signature. SIGSUBPKT.REVOCABLE can prevent signatures
 *    from being revoked.
 *    TODO: Implement the hash thing.
 *    This check needs to be done when:
 *     a) a signature revocation signature is verified. If the issuer is authorised and the signature being revoked are available, the revocation is performed
 *     b) any key or certification signature is _uploaded_. Search all verified signature revocation signatures if they revoke it.
 *     [c) a key or certification signature is verified that contains a revocation key authorisation. All signatures that have been made by this key need
 *        to be checked by check 4b.]
 * 5. Check the expiration date of a key. v3 keys contain an expiration date themselves, this is the default value. It can be overridden by making
 *    a v4 self-signature with the expiration date set in the SIGSUBPKT.KEY_EXPIRE sub-packet. The self-signature with the newest date that specifies
 *    a key expiration date is the relevant one. Subkey binding signatures can also contain a key expiration date. As we do not store subkeys and
 *    keys separately, in our database, we will set the expiration date of _all_ subkey binding signatures for the subkey by the same key to the
 *    key expiration date specified in the newest one of them (instead of setting the expiration date of the subkey itself). This check needs to be
 *    performed when:
 *     a) a self-signature is verified (check 1) that sets a key expiration date.
 *     b) a subkey binding signature is verified
 * 6. Check the primary identity of a key. This is set by the SIGSUBPKT.PRIMARY_UID subpacket in a self-signature of an identity. The one from the
 *    most recent self-signature counts. This check needs to be performed when:
 *     a) a self-signature is verified (check 1) that sets the primary ID.
 * 7. TODO: Check if there are any signatures that contain the sub packet consts.SIGSUBPKT.REV_KEY where the sensitive flag is set to true. These
 *    signatures may only be made public if there is a revocation signature by the key specified there.
 *     a) a signature with such a sensitive sub-packet is _uploaded_. If there are no revocation signatures issued by the specified authorised revoker on
 *        the key itself, its subkeys, its identities and its attributes, mark the signature as sensitive.
 *     b) a key is revoked by check 2 or 3 [or 4]. Check if the revoker has been authorised using a sensitive revocation authorisation signature, if so
 *        mark it as non-sensitive.
 * 8. Make sure that the security level of a key is inherited to the signatures it makes.
 *     a) A signature is verified. Set its security level to the lowest among its own and that of the key.
 * 9. Calculate the trust of keys, identities and attributes. TODO: Handle signature expiration and revocation
 *     a) A certification signature is verified, revoked or removed. Recalculate the trust of the signed
 *        identity or attribute.
 *     b) A key or certification signature is verified, revoked or removed that contains a trust amount.
 *        Recalculate the owner trust of the signed key.
 *     c) The owner trust of a key changes. Apply the effects of this on all the keys, identities and
 *        attributes that have been signed by the key.
*/

utils.extend(Keyring.prototype, {

	//////////////////////////////////////////////////////////////////////////////////////////////
	/// Handlers ///
	////////////////

	/**
	 * @param [remove]
	 */
	__keySignatureVerified : function(keyId, signatureInfo, callback, remove) {
		var checks = [ ];

		// Check 2a
		if(signatureInfo.sigtype == consts.SIG.KEY_REVOK)
			checks.push(this.__checkKeyRevocationStatus.bind(this, keyId, remove));

		// Check 2b, 3c
		if([ consts.SIG.KEY, consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ].indexOf(signatureInfo.sigtype) != -1 && signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REV_KEY])
		{
			checks.push(this.__checkKeyRevocationStatus.bind(this, keyId, remove));
			checks.push(function(next) {
				this.getSubkeyList(keyId).forEachSeries(function(subkeyId, next) {
					this.__checkSubkeyRevocationStatus(keyId, subkeyId, remove, next);
				}.bind(this), next);
			}.bind(this));
		}

		if([ consts.SIG.KEY, consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3, consts.SIG.CERT_REVOK, consts.SIG.KEY_BY_SUBKEY ].indexOf(signatureInfo.sigtype) != -1)
		{
			// Check 4a, 4b
			checks.push(this.__checkSignatureRevocationStatus.bind(this, keyId, remove));

			// Check 5a, 6a
			if(signatureInfo.issuer == keyId && (signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE] || signatureInfo.hashedSubPackets[consts.SIGSUBPKT.PRIMARY_UID]))
				checks.push(this.__checkSelfSignatures.bind(this, keyId));
		}

		// Check 9b
		if([ consts.SIG.KEY, consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ].indexOf(signatureInfo.sigtype) != -1 && signatureInfo.trustSignature)
			checks.push(remove ? this.__removeOwnerTrustSignature.bind(this, signatureInfo.id) : this.__addOwnerTrustSignature.bind(this, keyId, signatureInfo));

		async.series(checks, callback);
	},

	__keySignatureRemoved : function(keyId, signatureInfo, callback) {
		this.__keySignatureVerified(keyId, signatureInfo, callback, true);
	},

	__subkeySignatureVerified : function(keyId, subkeyId, signatureInfo, callback) {
		var checks = [ ];

		// Check 3a, 3b
		checks.push(this.__checkSubkeyRevocationStatus.bind(this, keyId, subkeyId, false));

		// Check 5b
		if(signatureInfo.sigtype == consts.SIG.SUBKEY && signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE])
			checks.push(this.__checkSubkeyExpiration.bind(this, keyId, subkeyId));

		async.series(checks, callback);
	},

	__subkeySignatureRemoved : function(keyId, subkeyId, signatureInfo, callback) {
		this.__subkeySignatureVerified(keyId, subkeyId, signatureInfo, callback);
	},

	__identitySignatureVerified : function(keyId, identityId, signatureInfo, callback) {
		var checks = [ this.__keySignatureVerified.bind(this, keyId, signatureInfo) ];

		// Check 9a
		if([ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ].indexOf(signatureInfo.sigtype) != -1)
			checks.push(this.__updateIdentityTrust.bind(this, keyId, identityId));

		async.series(checks, callback);
	},

	__identitySignatureRemoved : function(keyId, identityId, signatureInfo, callback) {
		this.__identitySignatureVerified(keyId, identityId, signatureInfo, callback);
	},

	__attributeSignatureVerified : function(keyId, attributeId, signatureInfo, callback) {
		var checks = [ this.__keySignatureVerified.bind(this, keyId, signatureInfo) ];

		// Check 9a
		if([ consts.SIG.CERT_0, consts.SIG.CERT_2, consts.SIG.CERT_3 ].indexOf(signatureInfo.sigtype) != -1)
			checks.push(this.__updateAttributeTrust.bind(this, keyId, attributeId));

		async.series(checks, callback);
	},

	__attributeSignatureRemoved : function(keyId, attributeId, signatureInfo, callback) {
		this.__attributeSignatureVerified(keyId, attributeId, signatureInfo, callback);
	},

	__keyAdded : function(keyId, callback) {
		async.series([
			function(next) {
				this.getKeySignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
					async.waterfall([
						function(next3) {
							this.getKeySignature(sig.keyId, sig.signatureId, next3, [ "binary", "issuer", "security" ]);
						}.bind(this),
						function(signatureInfo, next3) {
							signing.verifyKeySignature(this, sig.keyId, signatureInfo, function(err, verified){ next3(err, signatureInfo, verified); });
						}.bind(this),
						function(signatureInfo, verified, next3) {
							if(!verified)
								this.removeKeySignature(sig.keyId, sig.signatureId, next3);
							else
							{
								this._updateKeySignature(sig.keyId, sig.signatureId, { verified: signatureInfo.verified, security: signatureInfo.security }, function(err) {
									if(err)
										return next3(err);
									this.__keySignatureVerified(sig.keyId, signatureInfo, next3);
								}.bind(this));
							}
						}.bind(this)
					], next2);
				}.bind(this), next);
			}.bind(this),
			function(next) {
				this.getSubkeySignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
					async.waterfall([
						function(next3) {
							this.getSubkeySignature(sig.keyId, sig.subkeyId, sig.signatureId, next3, [ "binary", "issuer", "security" ]);
						}.bind(this),
						function(signatureInfo, next3) {
							signing.verifySubkeySignature(this, sig.keyId, sig.subkeyId, signatureInfo, function(err, verified){ next3(err, signatureInfo, verified); });
						}.bind(this),
						function(signatureInfo, verified, next3) {
							if(!verified)
								this.removeSubkeySignature(sig.keyId, sig.subkeyId, sig.signatureId, next3);
							else
							{
								this._updateSubkeySignature(sig.keyId, sig.subkeyId, sig.signatureId, { verified: signatureInfo.verified, security: signatureInfo.security }, function(err) {
									if(err)
										return next3(err);
									this.__subkeySignatureVerified(sig.keyId, sig.subkeyId, signatureInfo, next3);
								}.bind(this));
							}
						}.bind(this)
					], next2);
				}.bind(this), next);
			}.bind(this),
			function(next) {
				this.getIdentitySignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
					async.waterfall([
						function(next3) {
							this.getIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, next3, [ "binary", "issuer", "security" ]);
						}.bind(this),
						function(signatureInfo, next3) {
							signing.verifyIdentitySignature(this, sig.keyId, sig.identityId, signatureInfo, function(err, verified){ next3(err, signatureInfo, verified); });
						}.bind(this),
						function(signatureInfo, verified, next3) {
							if(!verified)
								this.removeIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, next3);
							else
							{
								this._updateIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, { verified: signatureInfo.verified, security: signatureInfo.security }, function(err) {
									if(err)
										return next3(err);
									this.__identitySignatureVerified(sig.keyId, sig.identityId, signatureInfo, next3);
								}.bind(this));
							}
						}.bind(this)
					], next2);
				}.bind(this), next);
			}.bind(this),
			function(next) {
				this.getAttributeSignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
					async.waterfall([
						function(next3) {
							this.getAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, next3, [ "binary", "issuer", "security" ]);
						}.bind(this),
						function(signatureInfo, next3) {
							signing.verifyAttributeSignature(this, sig.keyId, sig.attributeId, signatureInfo, function(err, verified){ next3(err, signatureInfo, verified); });
						}.bind(this),
						function(signatureInfo, verified, next3) {
							if(!verified)
								this.removeAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, next3);
							else
							{
								this._updateAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, { verified: signatureInfo.verified, security: signatureInfo.security }, function(err) {
									if(err)
										return next3(err);
									this.__attributeSignatureVerified(sig.keyId, sig.attributeId, signatureInfo, next3);
								}.bind(this));
							}
						}.bind(this)
					], next2);
				}.bind(this), next);
			}.bind(this)
		], callback);
	},

	//////////////////////////////////////////////////////////////////////////////////////////////
	/// Revocation ///
	//////////////////

	/**
	 * Check if the key with the ID issuerId has been authorised to revoke the key with the ID keyId
	 * using a signature.
	 */
	__isAuthorisedRevoker : function(keyId, issuerId, callback) {
		var fifos = [ ];
		var fingerprint = null;
		async.series([
			function(next) {
				this.getKey(issuerId, function(err, keyInfo) {
					if(err)
						next(err);
					else if(keyInfo == null)
						callback(null, false);
					else
					{
						fingerprint = keyInfo.fingerprint;
						next();
					}
				}.bind(this), [ "fingerprint" ]);
			}.bind(this),
			function(next) {
				fifos.push(this.getKeySignatures(keyId, { sigtype: consts.SIG.KEY, verified: true }, [ "hashedSubPackets" ]));
				next();
			}.bind(this),
			function(next) {
				this.getIdentityList(keyId).forEachSeries(function(identityId, next) {
					fifos.push(this.getIdentitySignatures(keyId, identityId, { sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], verified: true }, [ "hashedSubPackets" ]));
					next();
				}.bind(this), next);
			}.bind(this),
			function(next) {
				this.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
					fifos.push(this.getAttributeSignatures(keyId, attributeId, { sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], verified: true }, [ "hashedSubPackets" ]));
					next();
				}.bind(this), next);
			}.bind(this),
			function(next) {
				Fifo.concat(fifos).forEachSeries(function(signatureInfo, next) {
					if(signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REV_KEY])
					{
						for(var i=0; i<signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REV_KEY].length; i++)
						{
							if(signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REV_KEY][i].value == fingerprint)
								callback(null, true);
							else
								next();
						}
					}
				}.bind(this), next);
			}.bind(this)
		], function(err) {
			callback(err, false);
		});
	},

	__checkKeyRevocationStatus : function(keyId, remove, callback) {
		this.getKeySignatures(keyId, { sigtype: consts.SIG.KEY_REVOK, verified: true }, [ "id", "issuer" ]).forEachSeries(function(signatureInfo, next) {
			async.waterfall([
				function(next) {
					if(signatureInfo.issuer == keyId)
						next(null, true);
					else
						this.__isAuthorisedRevoker(keyId, signatureInfo.issuer, next);
				}.bind(this),
				function(authorised, next) {
					if(authorised)
						this._updateKey(keyId, { revoked: signatureInfo.id }, callback);
					else
						next();
				}.bind(this)
			], next);
		}.bind(this), function(err) {
			if(err || !remove)
				return callback(err);

			this._updateKey(keyId, { revoked: null }, callback);
		}.bind(this));
	},

	__checkSubkeyRevocationStatus : function(keyId, subkeyId, remove, callback) {
		async.series([
			function(next) {
				if(remove)
				{
					this.getSubkeySignatures(keyId, subkeyId, { sigtype: consts.SIG.SUBKEY, revoked: new Filter.Not(new Filter.Equals(null)) }, [ "id" ], function(signatureInfo, next) {
						this._updateSubkeySignature(keyId, subkeyId, signatureInfo.id, { revoked: null }, next);
					}.bind(this), next);
				}
				else
					next();
			}.bind(this),
			function(next) {
				this.getSubkeySignatures(keyId, subkeyId, { sigtype: consts.SIG.SUBKEY_REVOK, verified: true }, [ "id", "issuer", "date" ]).forEachSeries(function(signatureInfo, next) {
					async.waterfall([
						function(next) {
							if(signatureInfo.issuer == keyId)
								next(null, true);
							else
								this.__isAuthorisedRevoker(keyring, keyId, signatureInfo.issuer, next);
						}.bind(this),
						function(authorised, next) {
							if(authorised)
							{
								this.getSubkeySignatures(keyId, subkeyId, { sigtype: consts.SIG.SUBKEY }, [ "id" ]).forEachSeries(function(signatureInfo2, next) {
									this._updateSubkeySignature(keyId, subkeyId, signatureInfo2.id, { revoked: signatureInfo.id }, next);
								}.bind(this), next);
							}
							else
								next();
						}.bind(this)
					], next);
				}.bind(this), next);
			}.bind(this)
		], callback);
	},

	// Check 4: Find verified revocation signatures on the specified key and its sub-objects and revoke all earlier signatures by the same issuer on the same object
	__checkSignatureRevocationStatus : function(keyId, remove, callback) {
		async.series([
			function(next) {
				if(remove)
					this.__resetSignatureRevocationStatus(keyId, next);
				else
					next();
			}.bind(this),
			function(next) {
				this.getKeySignatures(keyId, { verified: true, sigtype: consts.SIG.CERT_REVOK }, [ "id", "issuer", "date" ]).forEachSeries(function(revSignatureInfo, next) {
					this.getKeySignatures(keyId, { issuer: revSignatureInfo.issuer, sigtype: [ consts.SIG.KEY, consts.SIG.KEY_BY_SUBKEY ], date: new Filter.LessThan(revSignatureInfo.date) }, [ "id", "hashedSubPackets" ]).forEachSeries(function(signatureInfo, next) {
						if(!signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE] || !signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE][0].value)
							this._updateKeySignature(keyId, signatureInfo.id, { revoked: revSignatureInfo.id }, next);
						else
							next();
					}.bind(this), next);
				}.bind(this), next);
			}.bind(this),
			function(next) {
				this.getIdentityList(keyId).forEachSeries(function(identityId, next) {
					this.getIdentitySignatures(keyId, identityId, { verified: true, sigtype: consts.SIG.CERT_REVOK }, [ "id", "issuer", "date" ]).forEachSeries(function(revSignatureInfo, next) {
						this.getIdentitySignatures(keyId, identityId, { issuer: revSignatureInfo.issuer, sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], date: new Filter.LessThan(revSignatureInfo.date) }, [ "id", "hashedSubPackets" ]).forEachSeries(function(signatureInfo, next) {
							if(!signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE] || !signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE][0].value)
								this._updateIdentitySignature(keyId, identityId, signatureInfo.id, { revoked: revSignatureInfo.id }, next);
							else
								next();
						}.bind(this), next);
					}.bind(this), next);
				}.bind(this), next);
			}.bind(this),
			function(next) {
				this.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
					this.getAttributeSignatures(keyId, attributeId, { verified: true, sigtype: consts.SIG.CERT_REVOK }, [ "id", "issuer", "date" ]).forEachSeries(function(revSignatureInfo, next) {
						this.getAttributeSignatures(keyId, attributeId, { issuer: revSignatureInfo.issuer, sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], date: new Filter.LessThan(revSignatureInfo.date) }, [ "id", "hashedSubPackets" ]).forEachSeries(function(signatureInfo, next) {
							if(!signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE] || !signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE][0].value)
								this._updateAttributeSignature(keyId, attributeId, signatureInfo.id, { revoked: revSignatureInfo.id }, next);
							else
								next();
						}.bind(this), next);
					}.bind(this), next);
				}.bind(this), next);
			}.bind(this)
		], callback);
	},

	__resetSignatureRevocationStatus : function(keyId, callback) {
		async.series([
			function(next) {
				this.getKeySignatures(keyId, { sigtype: [ consts.SIG.KEY, consts.SIG.KEY_BY_SUBKEY ], revoked: new Filter.Not(new Filter.Equals(null)) }, [ "id" ]).forEachSeries(function(signatureInfo, next) {
					this._updateKeySignature(keyId, signatureInfo.id, { revoked: null }, next);
				}.bind(this), next);
			}.bind(this),
			function(next) {
				this.getIdentityList(keyId).forEachSeries(function(identityId, next) {
					this.getIdentitySignatures(keyId, identityId, { sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], revoked: new Filter.Not(new Filter.Equals(null)) }, [ "id" ]).forEachSeries(function(signatureInfo, next) {
						this._updateIdentitySignature(keyId, identityId, signatureInfo.id, { revoked: null }, next);
					}.bind(this), next);
				}.bind(this), next);
			}.bind(this),
			function(next) {
				this.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
					this.getAttributeSignatures(keyId, attributeId, { sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], revoked: new Filter.Not(new Filter.Equals(null)) }, [ "id" ]).forEachSeries(function(signatureInfo, next) {
						this._updateAttributeSignature(keyId, attributeId, signatureInfo.id, { revoked: null }, next);
					}.bind(this), next);
				}.bind(this), next);
			}.bind(this)
		], callback);
	},

	//////////////////////////////////////////////////////////////////////////////////////////////
	/// Expiration ///
	//////////////////

	// Check 5a, 6: Check self-signatures for expiration date and primary id
	__checkSelfSignatures : function(keyId, callback) {
		this.getKey(keyId, function(err, keyInfo) {
			if(err)
				return callback(err);

			packetContent.getPublicKeyPacketInfo(keyInfo.binary, function(err, keyInfoOrig) {
				if(err)
					return callback(err);

				var expire = keyInfoOrig.expires;
				var expireDate = -1;
				var primary = null;
				var primaryDate = -1;

				function checkExpire(signatureInfo, next) {
					if(signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE] && signatureInfo.date && signatureInfo.date.getTime() > expireDate)
					{
						if(signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE][0] == 0)
							expire = null;
						else
							expire = new Date(keyInfo.date.getTime() + signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE][0].value*1000);
						expireDate = signatureInfo.date.getTime();
					}
					next();
				}

				function checkPrimaryAndExpire(identityId, signatureInfo, next) {
					if(signatureInfo.hashedSubPackets[consts.SIGSUBPKT.PRIMARY_UID] && signatureInfo.hashedSubPackets[consts.SIGSUBPKT.PRIMARY_UID][0].value && signatureInfo.date && signatureInfo.date.getTime() > primaryDate)
					{
						primary = identityId;
						primaryDate = signatureInfo.date.getTime();
					}
					checkExpire(signatureInfo, next);
				}

				var filter = { verified: true, issuer: keyId, sigtype: [ consts.SIG.KEY, consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ] };

				async.series([
					function(next) {
						this.getKeySignatures(keyId, filter, [ "hashedSubPackets", "date" ]).forEachSeries(checkExpire, next);
					}.bind(this),
					function(next) {
						this.getIdentityList(keyId).forEachSeries(function(identityId, next) {
							this.getIdentitySignatures(keyId, identityId, filter, [ "hashedSubPackets", "date" ]).forEachSeries(async.apply(checkPrimaryAndExpire, identityId), next);
						}.bind(this), next);
					}.bind(this),
					function(next) {
						this.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
							this.getAttributeSignatures(keyId, attributeId, filter, [ "hashedSubPackets", "date" ]).forEachSeries(checkExpire, next);
						}.bind(this), next);
					}.bind(this)
				], function(err) {
					if(err)
						return callback(err);

					this._updateKey(keyId, { expires: expire, primary_identity: primary }, callback);
				}.bind(this));
			}.bind(this));
		}.bind(this), [ "binary", "date" ]);
	},

	__checkSubkeyExpiration : function(keyId, subkeyId, callback) {
		this.getSubkey(keyId, subkeyId, function(err, subkeyInfo) {
			if(err)
				return callback(err);

			var expire = null;
			var expireDate = -1;

			this.getSubkeySignatures(keyId, subkeyId, { verified: true, sigtype: consts.SIG.SUBKEY }, [ "date", "hashedSubPackets" ]).forEachSeries(function(signatureInfo, next) {
				if(signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE] && signatureInfo.date && signatureInfo.date.getTime() > expireDate)
				{
					if(signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE][0].value == 0)
						expire = null;
					else
						expire = new Date(subkeyInfo.date.getTime() + signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE][0].value*1000);
					expireDate = signatureInfo.date.getTime();
				}

				next();
			}, function(err) {
				if(err)
					return callback(err);

				this.getSubkeySignatures(keyId, subkeyId, { sigtype: consts.SIG.SUBKEY }, [ "id", "binary", "expires" ]).forEachSeries(function(signatureInfo, next) {
					packetContent.getSignaturePacketInfo(signatureInfo.binary, function(err, signatureInfoOrig) {
						if(err)
							return next(err);

						var updates = { };

						if(signatureInfoOrig.expires != null && (expire == null || signatureInfoOrig.expires.getTime() > expire.getTime()))
							updates.expires = signatureInfoOrig.expires;
						else
							updates.expires = expire;

						this._updateSubkeySignature(keyId, subkeyId, signatureInfo.id, updates, next);
					}.bind(this));
				}.bind(this), callback);
			}.bind(this));
		}.bind(this), [ "date" ]);
	}
});