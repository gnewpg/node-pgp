var utils = require("./utils");
var consts = require("./consts");
var signing = require("./signing");
var Filter = require("./keyringFilters");

var p = utils.proxy;

module.exports = Keyring;
module.exports._filter = _filter;
module.exports.Filter = Filter;

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
 *    the key itself! (As that would make it possible for anyone to revoke a key by just signing it with a subkey binding signature.) This check needs
 *    to be done in the following cases:
 *     a) a subkey revocation signature is verified by check 1. The subkey binding signature is revoked if the issuer is authorised.
 *     b) a subkey binding signature is verified by check 1. Check 3a is rerun on all subkey revocation signatures of the key.
 *     c) a key or certification signature is verified that contains a revocation key authorisation. All subkey revocation signatures of all keys that
 *        contain a subkey binding signature of this key are checked again by check 3a.
 * 4. Check if a key or certification signature has been revoked. This is the case if the same key, identity or attribute contains a verified signature
 *    of the type SIG.CERT_REVOKE. Such a signature is valid if it has been issued by the same key that issued the signature that is being revoked, [or
 *    by a key that is authorised by that key to make revocations for it (as described in check 2)]. [A signature revocation signature may contain the hash
 *    of the signature it revokes in the SIGSUBPKT.SIGTARGET sub-packet, in that case it only revokes that specific signature.] Else it revokes all signatures
 *    issued by the same key on the same object on a date earlier than that of the revocation signature. SIGSUBPKT.REVOCABLE can prevent signatures
 *    from being revoked. This check needs to be done when:
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
*/

function Keyring() {
}

Keyring.prototype = {
	getKeyList : function(filter) { return _ef(); },

	getKeys : function(filter) {
		return _getItems(this.getKeyList(filter), p(this, this.getKey));
	},

	keyExists : function(id, callback) { _e(callback) },

	getKey : function(id, callback) { _e(callback); },

	addKey : function(keyInfo, callback) {
		_add(
			async.apply(p(this, this.keyExists), keyInfo.id),
			async.apply(p(this, this._addKey), keyInfo),
			async.apply(p(this, this.removeKey), keyInfo.id),
			[
				async.apply(_verifySignaturesByKey, this, keyInfo.id )
			],
			callback
		);
	},

	_addKey : function(keyInfo, callback) { _e(callback); },

	_updateKey : function(id, fields, callback) { _e(callback); },

	removeKey : function(id, callback) {
		this._removeKey(id, callback);
	},

	_removeKey : function(id, callback) { _e(callback); },

	getSubkeyList : function(keyId, filter) { return _ef(); },

	getSubkeys : function(keyId, filter) {
		return _getItems(this.getSubkeyList(keyId, filter), async.apply(p(this, this.getSubkey), keyId));
	},

	subkeyExists : function(keyId, id, callback) { _e(callback); },

	getSubkey : function(keyId, id, callback) { _e(callback); },

	addSubkey : function(keyId, subkeyInfo, callback) {
		_add(
			async.apply(p(this, this.subkeyExists), keyId, subkeyInfo.id),
			async.apply(p(this, this._addSubkey), keyId, subkeyInfo),
			async.apply(p(this, this.removeSubkey), keyId, subkeyInfo.id),
			[
				async.apply(_verifySignaturesByKey, this, subkeyInfo.id )
			],
			callback
		);
	},

	_addSubkey : function(keyId, subkeyInfo, callback) { _e(callback); },

	_updateSubkey : function(keyId, subkeyId, fields, callback) { _e(callback); },

	removeSubkey : function(keyId, subkeyId, callback) {
		this._removeSubkey(keyId, subkeyId, callback);
	},

	_removeSubkey : function(keyId, subkeyId, callback) { _e(callback); },

	getParentKeyList : function(subkeyId) { _e(callback); },

	getParentKeys : function(subkeyId) {
		return _getItems(this.getParentKeyList(subkeyId), p(this, this.getKey));
	},

	getIdentityList : function(keyId, filter) { return _ef(); },

	getIdentities : function(keyId, filter) {
		return _getItems(this.getIdentityList(keyId, filter), async.apply(p(this, this.getIdentity), keyId));
	},

	identityExists : function(keyId, id, callback) { _e(callback); },

	getIdentity : function(keyId, id, callback) { _e(callback); },

	addIdentity : function(keyId, identityInfo, callback) {
		this._addIdentity(keyId, identityInfo, callback);
	},

	_addIdentity : function(keyId, identityInfo, callback) { _e(callback); },

	_updateIdentity : function(keyId, identityId, fields, callback) { _e(callback); },

	removeIdentity : function(keyId, id, callback) {
		this._removeIdentity(keyId, id, callback);
	},

	_removeIdentity : function(keyId, id, callback) { _e(callback); },

	getAttributeList : function(keyId, filter) { return _ef(); },

	getAttributes : function(keyId, filter) {
		return _getItems(this.getAttributeList(keyId, filter), async.apply(p(this, this.getIdentity), keyId));
	},

	attributeExists : function(keyId, id, callback) { _e(callback); },

	getAttribute : function(keyId, id, callback) { _e(callback); },

	addAttribute : function(keyId, attributeInfo, callback) {
		this._addAttribute(keyId, attributeInfo, callback);
	},

	_addAttribute : function(keyId, attributeInfo, callback) { _e(callback); },

	_updateAttribute : function(keyId, attributeId, fields, callback) { _e(callback); },

	removeAttribute : function(keyId, id, callback) {
		this._removeAttribute(keyId, id, callback);
	},

	_removeAttribute : function(keyId, id, callback) { _e(callback); },

	getKeySignatureList : function(keyId, filter) { return _ef(); },

	getKeySignatures : function(keyId, filter) {
		return _getItems(this.getKeySignatureList(keyId, filter), async.apply(p(this, this.getKeySignature), keyId));
	},

	getKeySignatureListByIssuer : function(issuerId, filter) {
		filter = utils.extend({ }, filter, { issuer: issuerId });

		var ret = new Fifo();
		this.getKeyList().forEachSeries(p(this, function(keyId, next) {
			this.getKeySignatureList(keyId, filter).forEachSeries(function(signatureId, next2) {
				ret._add({ key: keyId, signature: signatureId });
				next2();
			}, next);
		}), p(ret, ret._end));
		return ret;
	},

	keySignatureExists : function(keyId, id, callback) { _e(callback); },

	getKeySignature : function(keyId, id, callback) { _e(callback); },

	addKeySignature : function(keyId, signatureInfo, callback) {
		signing.verifyKeySignature(this, keyId, signatureInfo, p(this, function(err, verified) {
			if(err)
				callback(err);
			else if(verified === null)
				this._addKeySignature(keyId, signatureInfo, callback);
			else if(!verified)
				callback(new Error("Invalid signature."));
			else
			{
				_keySignatureVerified(this, keyId, signatureInfo, p(this, function(err) {
					if(err)
						callback(err);
					else
					{
						this._addKeySignature(keyId, signatureInfo, callback);
						callback();
					}
				}));
			}
		}));
	},

	_addKeySignature : function(keyId, signatureInfo, callback) { _e(callback); },

	_updateKeySignature : function(keyId, signatureId, callback) { _e(callback); },

	removeKeySignature : function(keyId, id, callback) {
		this.getKeySignature(keyId, id, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				async.apply(p(this, this._removeKeySignature), keyId, id),
				async.apply(_keySignatureRemoved, keyId, signatureInfo)
			], callback);
		});
	},

	_removeKeySignature : function(keyId, id, callback) { _e(callback); },

	getSubkeySignatureList : function(keyId, subkeyId, filter) { return _ef(); },

	getSubkeySignatures : function(keyId, subkeyId, filter) {
		return _getItems(this.getSubkeySignatureList(keyId, subkeyId, filter), async.apply(p(this, this.getSubkeySignature), keyId, subkeyId));
	},

	getSubkeySignatureListByIssuer : function(issuerId, filter) {
		filter = utils.extend({ }, filter, { issuer: issuerId });

		var ret = new Fifo();
		this.getKeyList().forEachSeries(p(this, function(keyId, next) {
			this.getSubkeyList(keyId).forEachSeries(p(this, function(subkeyId, next2) {
				this.getSubkeySignatureList(keyId, subkeyId, filter).forEachSeries(function(signatureId, next3) {
					ret._add({ keyId : keyId, subkeyId : subkeyId, signatureId : signatureId });
					next3();
				}, next2);
			}), next);
		}), p(ret, ret._end));
		return ret;
	},

	subkeySignatureExists : function(keyId, subkeyId, id, callback) { _e(callback); },

	getSubkeySignature : function(keyId, subkeyId, id, callback) { _e(callback); },

	addSubkeySignature : function(keyId, subkeyId, signatureInfo, callback) {
		signing.verifySubkeySignature(this, keyId, subkeyId, signatureInfo, p(this, function(err, verified) {
			if(err)
				callback(err);
			else if(verified === null)
				this._addSubkeySignature(keyId, subkeyId, signatureInfo, callback);
			else if(!verified)
				callback(new Error("Invalid signature."));
			else
			{
				_subkeySignatureVerified(this, keyId, subkeyId, signatureInfo, p(this, function(err) {
					if(err)
						callback(err);
					else
					{
						this._addSubkeySignature(keyId, subkeyId, signatureInfo, callback);
						callback();
					}
				}));
			}
		}));
	},

	_addSubkeySignature : function(keyId, subkeyId, signatureInfo, callback) { _e(callback); },

	_updateSubkeySignature : function(keyId, subkeyId, signatureId, callback) { _e(callback); },

	removeSubkeySignature : function(keyId, subkeyId, id, callback) {
		this.getSubkeySignature(keyId, subkeyId, id, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				async.apply(p(this, this._removeSubkeySignature), keyId, subkeyId, id),
				async.apply(_subkeySignatureRemoved, keyId, subkeyId, signatureInfo)
			], callback);
		});
	},

	_removeSubkeySignature : function(keyId, subkeyId, id, callback) { _e(callback); },

	getIdentitySignatureList : function(keyId, identityId, filter) { return _ef(); },

	getIdentitySignatures : function(keyId, identityId, filter) {
		return _getItems(this.getIdentitySignatureList(keyId, identityId, filter), async.apply(p(this, this.getIdentitySignature), keyId, identityId));
	},

	getIdentitySignatureListByIssuer : function(issuer, filter) {
		filter = utils.extend({ }, filter, { issuer: issuerId });

		var ret = new Fifo();
		this.getKeyList().forEachSeries(p(this, function(keyId, next) {
			this.getIdentityList(keyId).forEachSeries(p(this, function(identityId, next2) {
				this.getIdentitySignatureList(keyId, identityId, filter).forEachSeries(function(signatureId, next3) {
					ret._add({ keyId : keyId, identityId : identityId, signatureId : signatureId });
					next3();
				}, next2);
			}), next);
		}), p(ret, ret._end));
		return ret;
	},

	identitySignatureExists : function(keyId, identityId, id, callback) { _e(callback); },

	getIdentitySignature : function(keyId, identityId, id, callback) { _e(callback); },

	addIdentitySignature : function(keyId, identityId, signatureInfo, callback) {
		signing.verifyIdentitySignature(this, keyId, identityId, signatureInfo, p(this, function(err, verified) {
			if(err)
				callback(err);
			else if(verified === null)
				this._addIdentitySignature(keyId, identityId, signatureInfo, callback);
			else if(!verified)
				callback(new Error("Invalid signature."));
			else
			{
				_identitySignatureVerified(this, keyId, identityId, signatureInfo, p(this, function(err) {
					if(err)
						callback(err);
					else
					{
						this._addIdentitySignature(keyId, identityId, signatureInfo, callback);
						callback();
					}
				}));
			}
		}));
	},

	_addIdentitySignature : function(keyId, identityId, signatureInfo, callback) { _e(callback); },

	_updateIdentitySignature : function(keyId, identityId, signatureId, callback) { _e(callback); },

	removeIdentitySignature : function(keyId, identityId, id, callback) {
		this.getIdentitySignature(keyId, identityId, id, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				async.apply(p(this, this._removeIdentitySignature), keyId, identityId, id),
				async.apply(_identitySignatureRemoved, keyId, identityId, signatureInfo)
			], callback);
		});
	},

	_removeIdentitySignature : function(keyId, identityId, id, callback) { _e(callback); },

	getAttributeSignatureList : function(keyId, attributeId, filter) { return _ef(); },

	getAttributeSignatures : function(keyId, attributeId, filter) {
		return _getItems(this.getAttributeSignatureList(keyId, attributeId, filter), async.apply(p(this, this.getAttributeSignature), keyId, attributeId));
	},

	getAttributeSignatureListByIssuer : function(issuerId, filter) {
		filter = utils.extend({ }, filter, { issuer: issuerId });

		var ret = new Fifo();
		this.getKeyList().forEachSeries(p(this, function(keyId, next) {
			this.getAttributeList(keyId).forEachSeries(p(this, function(attributeId, next2) {
				this.getAttributeSignatureList(keyId, attributeId, filter).forEachSeries(function(attributeId, next3) {
					ret._add({ keyId : keyId, attributeId : attributeId, signatureId : signatureId });
					next3();
				}, next2);
			}), next);
		}), p(ret, ret._end));
		return ret;
	},

	attributeSignatureExists : function(keyId, attributeId, id, callback) { _e(callback); },

	getAttributeSignature : function(keyId, attributeId, id, callback) { _e(callback); },

	addAttributeSignature : function(keyId, attributeId, signatureInfo, callback) {
		signing.verifyAttributeSignature(this, keyId, attributeId, signatureInfo, p(this, function(err, verified) {
			if(err)
				callback(err);
			else if(verified === null)
				this._addAttributeSignature(keyId, attributeId, signatureInfo, callback);
			else if(!verified)
				callback(new Error("Invalid signature."));
			else
			{
				_attributeSignatureVerified(this, keyId, attributeId, signatureInfo, p(this, function(err) {
					if(err)
						callback(err);
					else
					{
						this._addAttributeSignature(keyId, attributeId, signatureInfo, callback);
						callback();
					}
				}));
			}
		}));
	},

	_addAttributeSignature : function(keyId, attributeId, signatureInfo, callback) { _e(callback); },

	_updateAttributeSignature : function(keyId, attributeId, signatureId, callback) { _e(callback); },

	removeAttributeSignature : function(keyId, attributeId, id, callback) {
		this.getAttributeSignature(keyId, attributeId, id, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				async.apply(p(this, this._removeIdentitySignature), keyId, attributeId, id),
				async.apply(_attributeSignatureRemoved, keyId, attributeId, signatureInfo)
			], callback);
		});
	},

	_removeAttributeSignature : function(keyId, attributeId, id, callback) { _e(callback); },

	saveChanges : function(callback) { _e(callback); },

	revertChanges : function(callback) { _e(callback); },

	importKeys : function(keyData, callback, acceptLocal) {
		var t = this;

		var imported = {
			keys : [ ],
			failed : [ ]
		};

		function add(addTo, infoObj, err, next) {
			if(err)
			{
				infoObj.err = err;
				imported.failed.push(err);
				next();
				return null;
			}
			else
			{
				addTo.push(infoObj);
				next();
				return infoObj.id;
			}
		}

		var lastKeyId = null;
		var lastSubkeyId = null;
		var lastIdentityId = null;
		var lastAttributeId = null;

		var lastKeyImported = null;
		var lastSubkeyImported = null;
		var lastIdentityImported = null;
		var lastAttributeImported = null;

		packets.splitPackets(keyData).forEachSeries(function(tag, header, body, next) {
			getPacketInfo(tag, body, function(err, info) {
				if(err)
					return callback(err);

				switch(tag) {
					case consts.PKT.PUBLIC_KEY:
						lastKeyId = info.id;
						lastKeyImported = { type: tag, id: info.id, signatures: [ ], subkeys: [ ], identities: [ ], attributes: [ ] };
						lastSubkeyId = lastIdentityId = lastAttributeId = null;
						t.addKey(info, function(err) {
							lastKeyId = add(imported.keys, lastKeyImported, err, next);
						});
						break;
					case consts.PKT.PUBLIC_SUBKEY:
						lastSubkeyId = info.id;
						lastSubkeyImported = { type: tag, id: info.id, signatures: [ ] };
						lastIdentityId = lastAttributeId = null;

						if(lastKeyId == null)
							lastSubkeyId = add(null, lastSubkeyImported, new Error("Subkey without key."), next);
						else
						{
							t.addSubkey(lastKeyId, info, function(err) {
								lastSubkeyId = add(lastKeyImported.subkeys, lastSubkeyImported, err, next);
							});
						}

						break;
					case consts.PKT.USER_ID:
						lastIdentityId = info.id;
						lastIdentityImported = { type: tag, id: info.id, signatures: [ ] };
						lastSubkeyId = lastAttributeId = null;

						if(lastKeyId == null)
							lastIdentityId = add(null, lastIdentityImported, new Error("Identity without key."), next);
						else
						{
							t.addIdentity(lastKeyId, info, function(err) {
								lastIdentityId = add(lastKeyImported.identities, lastIdentityImported, err, next);
							});
						}

						break;
					case consts.PKT.ATTRIBUTE:
						lastAttributeId = info.id;
						lastAttributeImported = { type: tag, id: info.id, signatures: [ ] };
						lastSubkeyId = lastIdentityId = null;

						if(lastKeyId == null)
							lastAttributeId = add(null, lastAttributeImported, new Error("Attribute without key."), next);
						else
						{
							t.addAttribute(lastKeyId, info, function(err) {
								lastAttributeId = add(lastKeyImported.attributes, lastAttributeImported, err, next);
							});
						}

						break;
					case consts.PKT.SIGNATURE:
						var lastSignatureImported = { type: tag, id: info.id, issuer: info.issuer, date: info.date, sigtype: info.sigtype };

						if(!acceptLocal && !info.exportable)
							add(null, lastSignatureImported, new Error("Signature is not exportable."), next);
						else if(lastSubkeyId != null)
						{
							t.addSubkeySignature(lastKeyId, lastSubkeyId, info, function(err) {
								add(lastSubkeyImported.signatures, lastSignatureImported, err, next);
							});
						}
						else if(lastIdentityId != null)
						{
							t.addIdentitySignature(lastKeyId, lastIdentityId, info, function(err) {
								add(lastIdentityImported.signatures, lastSignatureImported, err, next);
							});
						}
						else if(lastAttributeId != null)
						{
							t.addAttributeSignature(lastKeyId, lastAttributeId, info, function(err) {
								add(lastAttributeImported.signatures, lastSignatureImported, err, next);
							});
						}
						else if(lastKeyId != null)
						{
							t.addKeySignature(lastKeyId, info, function(err) {
								add(lastKeyImported.signatures, lastSignatureImported, err, next);
							});
						}
						else
							add(null, lastSignatureImported, new Error("Signature without object."), next);

						break;
					default:
						add(null, { type: tag }, new Error("Unknown packet type."), next);
						break;
				}
			});
		}, function(err) {
			if(err)
				callback(err);
			else
				callback(null, imported);
		});
	},

	exportKey : function(keyId, selection) {
		var ret = new BufferedStream();

		if(selection == null)
			selection = { };

		var opts = [
			{ tag : consts.PKT.SIGNATURE, list : t.getKeySignatureList, get : t.getKeySignature, selection: selection.signatures },
			{ tag : consts.PKT.USER_ID, list : t.getIdentityList, get : t.getIdentity, selection: selection.identities, sub : [
				{ tag : consts.PKT.SIGNATURE, list : t.getIdentitySignatureList, get : t.getIdentitySignature, selection: selection.signatures }
			] },
			{ tag : consts.PKT.ATTRIBUTE, list : t.getAttributeList, get : t.getAttribute, selection: selection.attributes, sub : [
				{ tag : consts.PKT.SIGNATURE, list : t.getAttributeSignatureList, get : t.getAttributeSignature, selection: selection.signatures }
			] },
			{ tag : consts.PKT.PUBLIC_SUBKEY, list : t.getSubkeyList, get : t.getSubkeyList, selection: selection.subkeys, sub : [
				{ tag: consts.PKT.SIGNATURE, list : t.getSubkeySignatureList, get : t.getSubkeySignature, selection: selection.signatures }
			] }
		];

		function goThroughList(opts, args, callback) {
			async.forEachSeries(opts || [ ], function(opt, next2) {
				opt.list.apply(t, args).forEachSeries(function(id, next1) {
					var args2 = args.concat([ id ]);
					opt.get.apply(t, args2.concat([ function(err, info) {
						if(err)
							return next1(err);

						if(opt.selection == null || opt.selection[info.id])
						{
							ret._sendData(packets.generatePacket(opt.tag, info.binary));

							if(opt.sub)
								return goThroughList(opt.sub, args2, next2);
						}

						next2();
					} ]));
				}, callback);
			}, callback);
		}

		goThroughList(opts, [ ], function(err) {
			ret._endData(err);
		});

		return ret;
	}
};

function _e(callback) {
	callback(new Error("Not implemented."));
}

function _ef() {
	var ret = new Fifo();
	ret._end(new Error("Not implemented."));
	return ret;
}

function _getItems(list, getItem) {
	var ret = new Fifo();
	list.forEachSeries(function(id, next) {
		getItem(id, function(err, item) {
			if(err)
				next(err);
			else
			{
				ret._add(item);
				next();
			}
		})
	}, p(ret, ret._end));
	return ret;
}

function _filter(list, filter) {
	if(filter == null)
		return list;

	var ret = new Fifo();
	list.forEachSeries(function(item, next) {
		for(var i in filter)
		{
			if(!Filter.get(filter[i]).check(item[i]))
			{
				next();
				return;
			}
			ret._add(item);
		}
		next();
	}, p(ret, ret._end));
	return ret;
}

function _add(existsFunc, addFunc, removeFunc, funcs, callback) {
	existsFunc(function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			addFunc(function(err) {
				if(err)
					finish(err);
				else
				{
					async.forEachSeries(funcs, function(func, next) {
						func(next);
					}, finish);
				}
			});
		}
	});

	function finish(err) {
		if(err)
		{
			removeFunc();
			callback(err);
		}
		else
			callback(null);
	}
}

function _keySignatureVerified(keyring, keyId, signatureInfo, callback, remove) {
	var checks = [ ];

	// Check 2a
	if(signatureInfo.sigtype == pgp.consts.SIG.KEY_REVOK)
		checks.push(async.apply(_checkKeyRevocationStatus, keyring, keyId, remove));

	// Check 2b, 3c
	if([ pgp.consts.SIG.KEY, pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ].indexOf(signatureInfo.sigtype) != -1 && signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY])
	{
		checks.push(async.apply(_checkKeyRevocationStatus, keyring, keyId, remove));
		keyring.getSubkeyList(keyId).forEachSeries(function(subkeyId, next2) {
			checks.push(async.apply(_checkSubkeyRevocationStatus, keyring, keyId, subkeyId, remove));
			next2();
		}, next);
	}

	if([ pgp.consts.SIG.KEY, pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3, pgp.consts.SIG.CERT_REVOK, pgp.consts.SIG.KEY_BY_SUBKEY ].indexOf(signatureInfo.sigtype) != -1)
	{
		// Check 4a, 4b
		checks.push(async.apply(_checkSignatureRevocationStatus, keyring, keyId, remove));

		// Check 5a, 6a
		if(signatureInfo.issuer == keyId && (signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE] || signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.PRIMARY_UID]))
			checks.push(async.apply(_checkSelfSignatures, keyring, keyId));
	}

	async.series(checks, callback);
}

function _keySignatureRemoved(keyring, keyId, signatureInfo, callback) {
	_keySignatureVerified(keyring, keyId, signatureInfo, callback, true);
}

function _subkeySignatureVerified(keyring, keyId, subkeyId, signatureInfo, callback) {
	var checks = [ ];

	// Check 3a, 3b
	if(signatureInfo.sigtype == pgp.consts.SIG.SUBKEY_REVOK)
		checks.push(async.apply(_checkSubkeyRevocationStatus, keyring, keyId, subkeyId));

	// Check 5b
	if(signatureInfo.sigtype == pgp.consts.SIG.SUBKEY && signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE])
		checks.push(async.apply(_checkSubkeyExpiration, keyId, subkeyId));

	async.series(checks, callback);
}

function _subkeySignatureRemoved(keyring, keyId, subkeyId, signatureInfo, callback) {
	_subkeySignatureVerified(keyring, keyId, subkeyId, signatureInfo, callback);
}

function _identitySignatureVerified(keyring, keyId, identityId, signatureInfo, callback) {
	_keySignatureVerified(keyring, keyId, signatureInfo, callback);
}

function _identitySignatureRemoved(keyring, keyId, identityId, signatureInfo, callback) {
	_keySignatureRemoved(keyring, keyId, signatureInfo, callback);
}

function _attributeSignatureVerified(keyring, keyId, attributeId, signatureInfo, callback) {
	_keySignatureVerified(keyring, keyId, signatureInfo, callback);
}

function _attributeSignatureRemoved(keyring, keyId, attributeId, signatureInfo, callback) {
	_keySignatureRemoved(keyring, keyId, signatureInfo, callback);
}

function _verifySignaturesByKey(keyring, keyId, callback) {
	async.series([
		function(next) {
			keyring.getKeySignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
				async.waterfall([
					function(next3) {
						keyring.getKeySignature(sig.keyId, sig.signatureId, next3);
					},
					function(signatureInfo, next3) {
						signing.verifyKeySignature(this, sig.keyId, signatureInfo, async.apply(next3, signatureInfo));
					},
					function(signatureInfo, verified, next3) {
						if(!verified)
							keyring.removeKeySignature(sig.keyId, sig.signatureId, next3);
						else
							_keySignatureVerified(keyring, sig.keyId, signatureInfo, next3);
					}
				], next2);
			}, next);
		},
		function(next) {
			keyring.getSubkeySignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
				async.waterfall([
					function(next3) {
						keyring.getSubkeySignature(sig.keyId, sig.subkeyId, sig.signatureId, next3);
					},
					function(signatureInfo, next3) {
						signing.verifySubkeySignature(this, sig.keyId, sig.subkeyId, signatureInfo, async.apply(next3, signatureInfo));
					},
					function(signatureInfo, verified, next3) {
						if(!verified)
							keyring.removeSubkeySignature(sig.keyId, sig.subkeyId, sig.signatureId, next3);
						else
							_subkeySignatureVerified(keyring, sig.keyId, sig.subkeyId, signatureInfo, next3);
					}
				], next2);
			}, next);
		},
		function(next) {
			keyring.getIdentitySignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
				async.waterfall([
					function(next3) {
						keyring.getIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, next3);
					},
					function(signatureInfo, next3) {
						signing.verifyIdentitySignature(this, keyId, sig.identityId, signatureInfo, async.apply(next3, signatureInfo));
					},
					function(signatureInfo, verified, next3) {
						if(!verified)
							keyring.removeIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, next3);
						else
							_identitySignatureVerified(keyring, sig.keyId, sig.identityId, signatureInfo, next3);
					}
				], next2);
			}, next);
		},
		function(next) {
			keyring.getAttributeSignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
				async.waterfall([
					function(next3) {
						keyring.getAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, next3);
					},
					function(signatureInfo, next3) {
						signing.verifyAttributeSignature(this, keyId, sig.attributeId, signatureInfo, async.apply(next3, signatureInfo));
					},
					function(signatureInfo, verified, next3) {
						if(!verified)
							keyring.removeAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, next3);
						else
							_attributeSignatureVerified(keyring, sig.keyId, sig.attributeId, signatureInfo, next3);
					}
				], next2);
			}, next);
		}
	], callback);
}

function _checkKeyRevocationStatus(keyring, keyId, callback, remove) {
	keyring.getKeySignatures(keyId, { sigtype: pgp.consts.SIG.KEY_REVOK, verified: true }).forEachSeries(function(signatureInfo, next) {
		async.waterfall([
			function(next) {
				if(signatureInfo.issuer == keyId)
					next(null, true);
				else
					_isAuthorisedRevoker(keyring, keyId, signatureInfo.issuer, next);
			},
			function(authorised, next) {
				if(authorised)
					keyring._updateKey(keyId, { revoked: signatureInfo.id }, callback);
				else
					next();
			},
			function(next) {
				if(remove)
					keyring._updateKey(keyId, { revoked: null }, next);
				else
					next();
			}
		], next);
	}, callback);
}

function _checkSubkeyRevocationStatus(keyring, keyId, subkeyId, callback) {
	keyring.getSubkeySignatures(keyId, subkeyId, { sigtype: pgp.consts.SIG.SUBKEY_REVOK, verified: true }).forEachSeries(function(signatureInfo, next) {
		async.waterfall([
			function(next) {
				if(signatureInfo.issuer == keyId)
					next(null, true);
				else
					_isAuthorisedRevoker(keyring, keyId, signatureInfo.issuer, next);
			},
			function(authorised, next) {
				if(authorised)
					keyring._updateSubkey(keyId, subkeyId, { revoked: signatureInfo.id }, callback);
				else
					next();
			},
			function(next) {
				if(remove)
					keyring._updateSubkey(keyId, subkeyId, { revoked: null }, next);
				else
					next();
			}
		], next);
	}, callback);
}

function _isAuthorisedRevoker(keyring, keyId, issuerId, callback) {
	var fifos = [ ];
	var issuerInfo = null;
	async.series([
		function(next) {
			keyring.getKey(issuerId, function(err, keyInfo) {
				if(err)
					next(err);
				else if(keyInfo == null)
					callback(null, false);
				else
				{
					issuerInfo = keyInfo;
					next();
				}
			});
		},
		function(next) {
			fifos.push(keyring.getKeySignatures(keyId, { sigtype: pgp.consts.SIG.KEY, verified: true }));
			next();
		},
		function(next) {
			keyring.getIdentityList(keyId).forEachSeries(function(identityId, next) {
				fifos.push(keyring.getIdentitySignatures(keyId, identityId, { sigtype: [ pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ], verified: true }));
				next();
			}, next);
		},
		function(next) {
			keyring.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
				fifos.push(keyring.getAttributeSignatures(keyId, attributeId, { sigtype: [ pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ], verified: true }));
				next();
			}, next);
		},
		function(next) {
			Fifo.concat(fifos).forEachSeries(function(signatureInfo, next) {
				if(signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY])
				{
					for(var i=0; i<signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY].length; i++)
					{
						if(signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REV_KEY][i].value == issuerInfo.fingerprint)
							callback(null, true);
						else
							next();
					}
				}
			}, next);
		}
	], function(err) {
		callback(err, false);
	});
}

// Check 4: Find verified revocation signatures on the specified key and its sub-objects and revoke all earlier signatures by the same issuer on the same object
function _checkSignatureRevocationStatus(keyring, keyId, callback, remove) {
	async.series([
		function(next) {
			if(remove)
				_resetSignatureRevocationStatus(keyring, keyId, next);
			else
				next();
		},
		function(next) {
			keyring.getKeySignatures(keyId, { verified: true, sigtype: pgp.consts.SIG.CERT_REVOK }).forEachSeries(function(revSignatureInfo, next) {
				keyring.getKeySignatures(keyId, { issuer: revSignatureInfo.issuer, sigtype: [ pgp.consts.SIG.KEY, pgp.consts.SIG.KEY_BY_SUBKEY ], date: new Filter.LessThan(revSignatureInfo.date) }).forEachSeries(function(signatureInfo, next) {
					if(!signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REVOCABLE] || !signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REVOCABLE][0].value)
						keyring._updateKeySignature(keyId, signatureInfo.id, { revoked: revSignatureInfo.id }, next);
					else
						next();
				}, next);
			}, next);
		},
		function(next) {
			keyring.getIdentityList(keyId).forEachSeries(function(identityId, next) {
				keyring.getIdentitySignatures(keyId, identityId, { verified: true, sigtype: pgp.consts.SIG.CERT_REVOK }).forEachSeries(function(revSignatureInfo, next) {
					keyring.getIdentitySignatures(keyId, identityId, { issuer: revSignatureInfo.issuer, sigtype: [ pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ], date: new Filter.LessThan(revSignatureInfo.date) }).forEachSeries(function(signatureInfo, next) {
						if(!signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REVOCABLE] || !signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REVOCABLE][0].value)
							keyring._updateIdentitySignature(keyId, identityId, signatureId, { revoked: revSignatureInfo.id }, next);
						else
							next();
					}, next);
				}, next);
			}, next);
		},
		function(next) {
			keyring.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
				keyring.getAttributeSignatures(keyId, attributeId, { verified: true, sigtype: pgp.consts.SIG.CERT_REVOK }).forEachSeries(function(revSignatureInfo, next) {
					keyring.getAttributeSignatures(keyId, attributeId, { issuer: revSignatureInfo.issuer, sigtype: [ pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ], date: new Filter.LessThan(revSignatureInfo.date) }).forEachSeries(function(signatureInfo, next) {
						if(!signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REVOCABLE] || !signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.REVOCABLE][0].value)
							keyring._updateAttributeSignature(keyId, attributeId, signatureId, { revoked: revSignatureInfo.id }, next);
						else
							next();
					}, next);
				}, next);
			}, next);
		}
	], callback);
}

function _resetSignatureRevocationStatus(keyring, keyId, callback) {
	async.series([
		function(next) {
			keyring.getKeySignatures(keyId, { sigtype: [ pgp.consts.SIG.KEY, pgp.consts.SIG.KEY_BY_SUBKEY ] }).forEachSeries(function(signatureInfo, next) {
				if(signatureInfo.revoked)
					keyring._updateKeySignature(keyId, signatureInfo.id, { revoked: null }, next);
				else
					next();
			}, next);
		},
		function(next) {
			keyring.getIdentityList(keyId, function(identityId, next) {
				keyring.getIdentitySignatures(keyId, identityId, { sigtype: [ pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ] }).forEachSeries(function(signatureInfo, next) {
					if(signatureInfo.revoked)
						keyring._updateIdentitySignature(keyId, identityId, signatureInfo.id, { revoked: null }, next);
					else
						next();
				}, next);
			}, next);
		},
		function(next) {
			keyring.getAttributeList(keyId, function(attributeId, next) {
				keyring.getAttributeSignatures(keyId, attributeId, { sigtype: [ pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ] }).forEachSeries(function(signatureInfo, next) {
					if(signatureInfo.revoked)
						keyring._updateAttributeSignature(keyId, attributeId, signatureInfo.id, { revoked: null }, next);
					else
						next();
				}, next);
			}, next);
		}
	], callback);
}

function _getAllSignatures(keyring, keyId, filter) {
	var ret = new Fifo();
	async.series([
		function(next) {
			keyring.getKeySignatures(keyId, filter).forEachSeries(function(signatureInfo, next) {
				ret._add(signatureInfo);
				next();
			}, next);
		},
		function(next) {
			keyring.getIdentityList(keyId).forEachSeries(function(identityId, next) {
				keyring.getIdentitySignatures(keyId, identityId, filter).forEachSeries(function(signatureInfo, next) {
					ret._add(signatureInfo);
					next();
				}, next);
			}, next);
		},
		function(next) {
			keyring.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
				keyring.getAttributeSignatures(keyId, attributeId, filter).forEachSeries(function(signatureInfo, next) {
					ret._add(signatureInfo);
					next();
				}, next);
			}, next);
		}
	], p(ret, ret._end));
	return ret;
}

// Check 5a, 6: Check self-signatures for expiration date and primary id
function _checkSelfSignatures(keyring, keyId, callback) {
	keyring.getKey(keyId, function(err, keyInfo) {
		if(err)
			return callback(err);

		var updates = { };
		if(typeof keyInfo.expiresOrig == "undefined")
		{
			keyInfo.expiresOrig = keyInfo.expires;
			updates.expiresOrig = keyInfo.expiresOrig;
		}

		var expire = keyInfo.expiresOrig;
		var expireDate = -1;
		var primary = null;
		var primaryDate = -1;

		function checkExpire(signatureInfo, next) {
			if(signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE] && signatureInfo.date && signatureInfo.date.getTime() > expireDate)
			{
				if(signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE][0] == 0)
					expire = null;
				else
					expire = new Date(keyInfo.date.getTime() + signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE][0].value*1000);
				expireDate = signatureInfo.date.getTime();
			}
			next();
		}

		function checkPrimaryAndExpire(identityId, signatureInfo, next) {
			if(signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.PRIMARY_UID] && signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.PRIMARY_UID][0].value && signatureInfo.date && signatureInfo.date.getTime() > primaryDate)
			{
				primary = identityId;
				primaryDate = signatureInfo.date.getTime();
			}
			checkExpire(signatureInfo, next);
		}

		async.series([
			function(next) {
				keyring.getKeySignatures(keyId, filter).forEachSeries(checkExpire, next);
			},
			function(next) {
				keyring.getIdentityList(keyId).forEachSeries(function(identityId, next) {
					keyring.getIdentitySignatures(keyId, identityId, filter).forEachSeries(async.apply(checkPrimaryAndExpire, identityId), next);
				}, next);
			},
			function(next) {
				keyring.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
					keyring.getAttributeSignatures(keyId, attributeId, filter).forEachSeries(checkExpire, next);
				}, next);
			}
		], function(err) {
			if(err)
				return callback(err);

			updates.expires = expire;
			updates.primary_identity = primary;

			keyring._updateKey(keyId, updates, callback);
		});
	});
}

function _checkSubkeyExpiration(keyring, keyId, subkeyId, callback) {
	keyring.getSubkey(keyId, subkeyId, function(err, subkeyInfo) {
		if(err)
			return callback(err);

		var expire = null;
		var expireDate = -1;

		keyring.getSubkeySignatures(keyId, subkeyId, { verified: true, sigtype: pgp.consts.SIG.SUBKEY }).forEachSeries(function(signatureInfo, next) {
			if(signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE] && signatureInfo.date && signatureInfo.date.getTime() > expireDate)
			{
				if(signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE][0].value == 0)
					expire = null;
				else
					expire = new Date(subkeyInfo.date.getTime() + signatureInfo.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE][0].value*1000);
				expireDate = signatureInfo.date.getTime();
			}

			next();
		}, function(err) {
			if(err)
				return callback(err);

			keyring.getSubkeySignatures(keyId, subkeyId, { sigtype: pgp.consts.SIG.SUBKEY }).forEachSeries(function(signatureInfo, next) {
				var updates = { };
				if(typeof signatureInfo.expiresOrig == "undefined")
				{
					signatureInfo.expiresOrig = signatureInfo.expires;
					updates.expiresOrig = signatureInfo.expiresOrig;
				}

				if(signatureInfo.expiresOrig != null && (expire == null || signatureInfo.expiresOrig.getTime() > expire.getTime()))
					updates.expires = signatureInfo.expiresOrig;
				else
					updates.expires = expire;

				keyring._updateSubkeySignature(keyId, subkeyId, signatureInfo.id, updates, next);
			}, callback);
		});
	});
}