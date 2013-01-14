var utils = require("./utils");
var signing = require("./signing");
var consts = require("./consts");
var packets = require("./packets");
var packetContent = require("./packetContent");
var Fifo = require("./fifo");
var Filter = require("./keyringFilters");
var async = require("async");
var formats = require("./formats");
var BufferedStream = require("./bufferedStream");

var p = utils.proxy;

module.exports = Keyring;
module.exports._filter = _filter;
module.exports._strip = _strip;
module.exports.Filter = Filter;

function Keyring() {
}

Keyring.prototype = {
	getKeyList : function(filter) { return _ef(); },

	getKeys : function(filter, fields) {
		return _getItems(this.getKeyList(filter), p(this, this.getKey), fields);
	},

	keyExists : function(id, callback) { _e(callback) },

	getKey : function(id, callback, fields) { _e(callback); },

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

	getSubkeys : function(keyId, filter, fields) {
		return _getItems(this.getSubkeyList(keyId, filter), async.apply(p(this, this.getSubkey), keyId), fields);
	},

	subkeyExists : function(keyId, id, callback) { _e(callback); },

	getSubkey : function(keyId, id, callback, fields) { _e(callback); },

	getSelfSignedSubkeys : function(keyId, filter, fields) {
		return Fifo.map(this.getSubkeys(keyId, filter, fields), p(this, function(subkeyInfo, next, skip) {
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

	getParentKeys : function(subkeyId, fields) {
		return _getItems(this.getParentKeyList(subkeyId), p(this, this.getKey), fields);
	},

	getIdentityList : function(keyId, filter) { return _ef(); },

	getIdentities : function(keyId, filter, fields) {
		return _getItems(this.getIdentityList(keyId, filter), async.apply(p(this, this.getIdentity), keyId), fields);
	},

	identityExists : function(keyId, id, callback) { _e(callback); },

	getIdentity : function(keyId, id, callback, fields) { _e(callback); },

	getSelfSignedIdentities : function(keyId, filter, fields) {
		return Fifo.map(this.getIdentities(keyId, filter, fields), p(this, function(identityInfo, next, skip) {
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

	addIdentity : function(keyId, identityInfo, callback) {
		_add(
			async.apply(p(this, this.identityExists), keyId, identityInfo.id),
			async.apply(p(this, this._addIdentity), keyId, identityInfo),
			async.apply(p(this, this.removeIdentity), keyId, identityInfo.id),
			[ ],
			callback
		);
	},

	_addIdentity : function(keyId, identityInfo, callback) { _e(callback); },

	_updateIdentity : function(keyId, identityId, fields, callback) { _e(callback); },

	removeIdentity : function(keyId, id, callback) {
		this._removeIdentity(keyId, id, callback);
	},

	_removeIdentity : function(keyId, id, callback) { _e(callback); },

	getAttributeList : function(keyId, filter) { return _ef(); },

	getAttributes : function(keyId, filter, fields) {
		return _getItems(this.getAttributeList(keyId, filter), async.apply(p(this, this.getIdentity), keyId), fields);
	},

	attributeExists : function(keyId, id, callback) { _e(callback); },

	getAttribute : function(keyId, id, callback, fields) { _e(callback); },

	getSelfSignedAttributes : function(keyId, filter, fields) {
		return Fifo.map(this.getAttributes(keyId, filter, fields), p(this, function(attributeInfo, next, skip) {
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

	addAttribute : function(keyId, attributeInfo, callback) {
		_add(
			async.apply(p(this, this.attributeExists), keyId, attributeInfo.id),
			async.apply(p(this, this._addAttribute), keyId, attributeInfo),
			async.apply(p(this, this.removeAttribute), keyId, attributeInfo.id),
			[ ],
			callback
		);
	},

	_addAttribute : function(keyId, attributeInfo, callback) { _e(callback); },

	_updateAttribute : function(keyId, attributeId, fields, callback) { _e(callback); },

	removeAttribute : function(keyId, id, callback) {
		this._removeAttribute(keyId, id, callback);
	},

	_removeAttribute : function(keyId, id, callback) { _e(callback); },

	getKeySignatureList : function(keyId, filter) { return _ef(); },

	getKeySignatures : function(keyId, filter, fields) {
		return _getItems(this.getKeySignatureList(keyId, filter), async.apply(p(this, this.getKeySignature), keyId), fields);
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

	getKeySignature : function(keyId, id, callback, fields) { _e(callback); },

	addKeySignature : function(keyId, signatureInfo, callback) {
		_add(
			async.apply(p(this, this.keySignatureExists), keyId, signatureInfo.id),
			async.apply(p(this, this._addKeySignature), keyId, signatureInfo),
			async.apply(p(this, this.removeKeySignature), keyId, signatureInfo.id),
			[
				async.apply(signing.verifyKeySignature, this, keyId, signatureInfo),
				p(this, function(verified, next) {
					if(verified == null)
						next();
					else if(!verified)
						next(new Error("Invalid signature."));
					else
					{
						async.series([
							async.apply(p(this, this._updateKeySignature), keyId, signatureInfo.id, { verified: signatureInfo.verified, security: signatureInfo.security }),
							async.apply(_keySignatureVerified, this, keyId, signatureInfo)
						], next);
					}
				})
			],
			callback
		);
	},

	_addKeySignature : function(keyId, signatureInfo, callback) { _e(callback); },

	_updateKeySignature : function(keyId, signatureId, fields, callback) { _e(callback); },

	removeKeySignature : function(keyId, id, callback) {
		this.getKeySignature(keyId, id, p(this, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				async.apply(p(this, this._removeKeySignature), keyId, id),
				async.apply(_keySignatureRemoved, this, keyId, signatureInfo)
			], callback);
		}));
	},

	_removeKeySignature : function(keyId, id, callback) { _e(callback); },

	getSubkeySignatureList : function(keyId, subkeyId, filter) { return _ef(); },

	getSubkeySignatures : function(keyId, subkeyId, filter, fields) {
		return _getItems(this.getSubkeySignatureList(keyId, subkeyId, filter), async.apply(p(this, this.getSubkeySignature), keyId, subkeyId), fields);
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

	getSubkeySignature : function(keyId, subkeyId, id, callback, fields) { _e(callback); },

	addSubkeySignature : function(keyId, subkeyId, signatureInfo, callback) {
		_add(
			async.apply(p(this, this.subkeySignatureExists), keyId, subkeyId, signatureInfo.id),
			async.apply(p(this, this._addSubkeySignature), keyId, subkeyId, signatureInfo),
			async.apply(p(this, this.removeSubkeySignature), keyId, subkeyId, signatureInfo.id),
			[
				async.apply(signing.verifySubkeySignature, this, keyId, subkeyId, signatureInfo),
				p(this, function(verified, next) {
					if(verified == null)
						next();
					else if(!verified)
						next(new Error("Invalid signature."));
					else
					{
						async.series([
							async.apply(p(this, this._updateSubkeySignature), keyId, subkeyId, signatureInfo.id, { verified: signatureInfo.verified, security: signatureInfo.security }),
							async.apply(_subkeySignatureVerified, this, keyId, subkeyId, signatureInfo)
						], next);
					}
				})
			],
			callback
		);
	},

	_addSubkeySignature : function(keyId, subkeyId, signatureInfo, callback) { _e(callback); },

	_updateSubkeySignature : function(keyId, subkeyId, signatureId, fields, callback) { _e(callback); },

	removeSubkeySignature : function(keyId, subkeyId, id, callback) {
		this.getSubkeySignature(keyId, subkeyId, id, p(this, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				async.apply(p(this, this._removeSubkeySignature), keyId, subkeyId, id),
				async.apply(_subkeySignatureRemoved, this, keyId, subkeyId, signatureInfo)
			], callback);
		}));
	},

	_removeSubkeySignature : function(keyId, subkeyId, id, callback) { _e(callback); },

	getIdentitySignatureList : function(keyId, identityId, filter) { return _ef(); },

	getIdentitySignatures : function(keyId, identityId, filter, fields) {
		return _getItems(this.getIdentitySignatureList(keyId, identityId, filter), async.apply(p(this, this.getIdentitySignature), keyId, identityId), fields);
	},

	getIdentitySignatureListByIssuer : function(issuerId, filter) {
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

	getIdentitySignature : function(keyId, identityId, id, callback, fields) { _e(callback); },

	addIdentitySignature : function(keyId, identityId, signatureInfo, callback) {
		_add(
			async.apply(p(this, this.identitySignatureExists), keyId, identityId, signatureInfo.id),
			async.apply(p(this, this._addIdentitySignature), keyId, identityId, signatureInfo),
			async.apply(p(this, this.removeIdentitySignature), keyId, identityId, signatureInfo.id),
			[
				async.apply(signing.verifyIdentitySignature, this, keyId, identityId, signatureInfo),
				p(this, function(verified, next) {
					if(verified == null)
						next();
					else if(!verified)
						next(new Error("Invalid signature."));
					else
					{
						async.series([
							async.apply(p(this, this._updateIdentitySignature), keyId, identityId, signatureInfo.id, { verified: signatureInfo.verified, security: signatureInfo.security }),
							async.apply(_identitySignatureVerified, this, keyId, identityId, signatureInfo)
						], next);
					}
				})
			],
			callback
		);
	},

	_addIdentitySignature : function(keyId, identityId, signatureInfo, callback) { _e(callback); },

	_updateIdentitySignature : function(keyId, identityId, signatureId, fields, callback) { _e(callback); },

	removeIdentitySignature : function(keyId, identityId, id, callback) {
		this.getIdentitySignature(keyId, identityId, id, p(this, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				async.apply(p(this, this._removeIdentitySignature), keyId, identityId, id),
				async.apply(_identitySignatureRemoved, this, keyId, identityId, signatureInfo)
			], callback);
		}));
	},

	_removeIdentitySignature : function(keyId, identityId, id, callback) { _e(callback); },

	getAttributeSignatureList : function(keyId, attributeId, filter) { return _ef(); },

	getAttributeSignatures : function(keyId, attributeId, filter, fields) {
		return _getItems(this.getAttributeSignatureList(keyId, attributeId, filter), async.apply(p(this, this.getAttributeSignature), keyId, attributeId), fields);
	},

	getAttributeSignatureListByIssuer : function(issuerId, filter) {
		filter = utils.extend({ }, filter, { issuer: issuerId });

		var ret = new Fifo();
		this.getKeyList().forEachSeries(p(this, function(keyId, next) {
			this.getAttributeList(keyId).forEachSeries(p(this, function(attributeId, next2) {
				this.getAttributeSignatureList(keyId, attributeId, filter).forEachSeries(function(signatureId, next3) {
					ret._add({ keyId : keyId, attributeId : attributeId, signatureId : signatureId });
					next3();
				}, next2);
			}), next);
		}), p(ret, ret._end));
		return ret;
	},

	attributeSignatureExists : function(keyId, attributeId, id, callback) { _e(callback); },

	getAttributeSignature : function(keyId, attributeId, id, callback, fields) { _e(callback); },

	addAttributeSignature : function(keyId, attributeId, signatureInfo, callback) {
		_add(
			async.apply(p(this, this.attributeSignatureExists), keyId, attributeId, signatureInfo.id),
			async.apply(p(this, this._addAttributeSignature), keyId, attributeId, signatureInfo),
			async.apply(p(this, this.removeAttributeSignature), keyId, attributeId, signatureInfo.id),
			[
				async.apply(signing.verifyAttributeSignature, this, keyId, attributeId, signatureInfo),
				p(this, function(verified, next) {
					if(verified == null)
						next();
					else if(!verified)
						next(new Error("Invalid signature."));
					else
					{
						async.series([
							async.apply(p(this, this._updateAttributeSignature), keyId, attributeId, signatureInfo.id, { verified: signatureInfo.verified, security: signatureInfo.security }),
							async.apply(_attributeSignatureVerified, this, keyId, attributeId, signatureInfo)
						], next);
					}
				})
			],
			callback
		);
	},

	_addAttributeSignature : function(keyId, attributeId, signatureInfo, callback) { _e(callback); },

	_updateAttributeSignature : function(keyId, attributeId, signatureId, fields, callback) { _e(callback); },

	removeAttributeSignature : function(keyId, attributeId, id, callback) {
		this.getAttributeSignature(keyId, attributeId, id, p(this, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				async.apply(p(this, this._removeAttributeSignature), keyId, attributeId, id),
				async.apply(_attributeSignatureRemoved, this, keyId, attributeId, signatureInfo)
			], callback);
		}));
	},

	_removeAttributeSignature : function(keyId, attributeId, id, callback) { _e(callback); },

	getSignatureById : function(signatureId, callback, fields) { _e(callback); },

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
				imported.failed.push(infoObj);
				process.nextTick(next);
				return null;
			}
			else
			{
				addTo.push(infoObj);
				process.nextTick(next);
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

		packets.splitPackets(formats.decodeKeyFormat(keyData)).forEachSeries(function(tag, header, body, next) {
			switch(tag) {
				case consts.PKT.PUBLIC_KEY:
					lastKeyId = null;
				case consts.PKT.PUBLIC_SUBKEY:
				case consts.PKT.USER_ID:
				case consts.PKT.ATTRIBUTE:
					lastSubkeyId = lastIdentityId = lastAttributeId = null;
			}

			packetContent.getPacketInfo(tag, body, function(err, info) {
				if(err)
					return add(null, { type: tag }, new Error("Errorneous packet."), next);

				switch(tag) {
					case consts.PKT.PUBLIC_KEY:
						lastKeyImported = { type: tag, id: info.id, signatures: [ ], subkeys: [ ], identities: [ ], attributes: [ ] };
						t.addKey(info, function(err) {
							lastKeyId = add(imported.keys, lastKeyImported, err, next);
						});
						break;
					case consts.PKT.PUBLIC_SUBKEY:
						lastSubkeyImported = { type: tag, id: info.id, signatures: [ ] };

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
						lastIdentityImported = { type: tag, id: info.id, signatures: [ ] };

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
						lastAttributeImported = { type: tag, id: info.id, signatures: [ ] };

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
		var t = this;

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
			{ tag : consts.PKT.PUBLIC_SUBKEY, list : t.getSubkeyList, get : t.getSubkey, selection: selection.subkeys, sub : [
				{ tag: consts.PKT.SIGNATURE, list : t.getSubkeySignatureList, get : t.getSubkeySignature, selection: selection.signatures }
			] }
		];

		function goThroughList(opts, args, callback) {
			async.forEachSeries(opts || [ ], function(opt, next) {
				opt.list.apply(t, args).forEachSeries(function(id, next) {
					var args2 = args.concat([ id ]);
					opt.get.apply(t, args2.concat([ function(err, info) {
						if(err)
							return next(err);

						if(opt.selection == null || opt.selection[info.id])
						{
							ret._sendData(packets.generatePacket(opt.tag, info.binary));

							if(opt.sub)
								return goThroughList(opt.sub, args2, next);
						}

						next();
					}, [ "id", "binary" ] ]));
				}, next);
			}, callback);
		}

		t.getKey(keyId, function(err, keyInfo) {
			if(err)
				return ret._endData(err);
			if(keyInfo == null)
				return ret._endData(new Error("Key "+keyId+" does not exist."));

			ret._sendData(packets.generatePacket(consts.PKT.PUBLIC_KEY, keyInfo.binary));

			goThroughList(opts, [ keyId ], function(err) {
				ret._endData(err);
			});
		}, [ "binary" ]);

		return ret;
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
				this.getIdentity(keyId, keyInfo.primary_identity, p(this, function(err, identityInfo) {
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
				this.getIdentities(keyId, null, fields).forEachSeries(p(this, function(identityInfo, next) {
					callback(null, identityInfo);
				}), function(err) {
					callback(err, null);
				});
			}
		}), [ "primary_identity"]);
	},

	search : function(searchString) {
		var ret = [ ];

		var searchInIdentities = true;

		if([ 10, 18, 34, 42 ].indexOf(searchString.length) != -1 && searchString.match(/^0x/i))
		{
			searchString = searchString.substring(2);
			searchInIdentities = false;
		}

		var addPrimaryIdentity = p(this, function(fifo) {
			return Fifo.map(fifo, p(this, function(keyInfo, cb) {
				this.getPrimaryIdentity(keyInfo.id, function(err, identityInfo) {
					if(err)
						return cb(err);
					keyInfo.identity = identityInfo;
					cb(null, keyInfo);
				}, [ "id", "name", "email" ]);
			}));
		});

		if(searchString.length == 8)
			ret.push(addPrimaryIdentity(this.searchByShortKeyId(searchString)));
		else if(searchString.length == 16)
			ret.push(addPrimaryIdentity(this.searchByLongKeyId(searchString)));
		else if(searchString.length == 32 || searchString.length == 40)
			ret.push(addPrimaryIdentity(this.searchByFingerprint(searchString)));

		if(searchInIdentities)
			ret.push(this.searchIdentities(searchString));

		return Fifo.concat(ret);
	},

	searchIdentities : function(searchString) {
		var ret = new Fifo();

		this.getKeys(null, [ "id", "revoked", "expires" ]).forEachSeries(p(this, function(keyInfo, next) {
			this.getSelfSignedIdentities(keyInfo.id, { id : new Filter.ContainsIgnoreCase(searchString) }, [ "id", "name", "email", "expires", "revoked", "security" ]).forEachSeries(p(this, function(identityInfo, next) {
				ret._add(utils.extend(keyInfo, { identity: identityInfo }));
				next();
			}), next);
		}), p(ret, ret._end));

		return ret;
	},

	searchByShortKeyId : function(keyId) {
		var keys = this.getKeys({ id: new Filter.ShortKeyId(keyId) }, [ "id", "revoked", "expires" ]);
		var subkeys = new Fifo();

		this.getKeys(null, [ "id", "revoked", "expires" ]).forEachSeries(p(this, function(keyInfo, next) {
			this.getSelfSignedSubkeys(keyInfo.id, { id : new Filter.ShortKeyId(keyId) }, [ "id", "revoked", "expires", "security" ]).forEachSeries(function(subkeyInfo, next) {
				subkeys.add(utils.extend(keyInfo, { subkey: subkeyInfo }));
				next();
			}, next);
		}), p(subkeys, subkeys._end));

		return Fifo.concat([ keys, subkeys ]);
	},

	searchByLongKeyId : function(keyId) {
		keyId = keyId.toUpperCase();

		var keys = this.getKeys({ id: keyId }, [ "id", "revoked", "expires" ]);
		var subkeys = new Fifo();

		this.getKeys(null, [ "id", "revoked", "expires" ]).forEachSeries(p(this, function(keyInfo, next) {
			this.getSelfSignedSubkeys(keyInfo.id, { id : keyId }, [ "id", "revoked", "expires", "security" ]).forEachSeries(function(subkeyInfo, next) {
				subkeys.add(utils.extend(keyInfo, { subkey: subkeyInfo }));
				next();
			}, next);
		}), p(subkeys, subkeys._end));

		return Fifo.concat([ keys, subkeys ]);
	},

	searchByFingerprint : function(keyId) {
		keyId = keyId.toUpperCase();

		var keys = this.getKeys({ fingerprint: keyId }, [ "id", "revoked", "expires" ]);
		var subkeys = new Fifo();

		this.getKeys(null, [ "id", "revoked", "expires" ]).forEachSeries(p(this, function(keyInfo, next) {
			this.getSelfSignedSubkeys(keyInfo.id, { fingerprint: keyId }, [ "id", "revoked", "expires", "security" ]).forEachSeries(function(subkeyInfo, next) {
				subkeys.add(utils.extend(keyInfo, { subkey: subkeyInfo }));
				next();
			}, next);
		}), p(subkeys, subkeys._end));

		return Fifo.concat([ keys, subkeys ]);
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

function _getItems(list, getItem, fields) {
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
		}, fields);
	}, p(ret, ret._end));
	return ret;
}

function _filter(list, filter) {
	if(filter == null || Object.keys(filter).length == 0)
		return list;

	return Fifo.grep(list, function(item, callback) {
		for(var i in filter)
		{
			if(!Filter.get(filter[i]).check(item[i]))
				return callback(null, false);
		}
		callback(null, true);
	});
}

function _strip(item, fieldList) {
	if(fieldList == null)
		return item;

	var newItem = { };
	for(var i=0; i<fieldList.length; i++)
		newItem[fieldList[i]] = item[fieldList[i]];
	return newItem;
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
					async.waterfall(funcs, finish);
			});
		}
	});

	function finish(err) {
		if(err)
		{
			removeFunc(function(err) {
				if(err)
					console.warn("Error while removing errorneous object: ", err);
			});
			callback(err);
		}
		else
			callback(null);
	}
}

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
*/

/**
 * @param [remove]
 */
function _keySignatureVerified(keyring, keyId, signatureInfo, callback, remove) {
	var checks = [ ];

	// Check 2a
	if(signatureInfo.sigtype == consts.SIG.KEY_REVOK)
		checks.push(async.apply(_checkKeyRevocationStatus, keyring, keyId, remove));

	// Check 2b, 3c
	if([ consts.SIG.KEY, consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ].indexOf(signatureInfo.sigtype) != -1 && signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REV_KEY])
	{
		checks.push(async.apply(_checkKeyRevocationStatus, keyring, keyId, remove));
		keyring.getSubkeyList(keyId).forEachSeries(function(subkeyId, next2) {
			checks.push(async.apply(_checkSubkeyRevocationStatus, keyring, keyId, subkeyId, remove));
			next2();
		}, next);
	}

	if([ consts.SIG.KEY, consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3, consts.SIG.CERT_REVOK, consts.SIG.KEY_BY_SUBKEY ].indexOf(signatureInfo.sigtype) != -1)
	{
		// Check 4a, 4b
		checks.push(async.apply(_checkSignatureRevocationStatus, keyring, keyId, remove));

		// Check 5a, 6a
		if(signatureInfo.issuer == keyId && (signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE] || signatureInfo.hashedSubPackets[consts.SIGSUBPKT.PRIMARY_UID]))
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
	checks.push(async.apply(_checkSubkeyRevocationStatus, keyring, keyId, subkeyId, false));

	// Check 5b
	if(signatureInfo.sigtype == consts.SIG.SUBKEY && signatureInfo.hashedSubPackets[consts.SIGSUBPKT.KEY_EXPIRE])
		checks.push(async.apply(_checkSubkeyExpiration, keyring, keyId, subkeyId));

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
						keyring.getKeySignature(sig.keyId, sig.signatureId, next3, [ "binary", "issuer", "security" ]);
					},
					function(signatureInfo, next3) {
						signing.verifyKeySignature(keyring, sig.keyId, signatureInfo, function(err, verified){ next3(err, signatureInfo, verified); });
					},
					function(signatureInfo, verified, next3) {
						if(!verified)
							keyring.removeKeySignature(sig.keyId, sig.signatureId, next3);
						else
						{
							keyring._updateKeySignature(sig.keyId, sig.signatureId, { verified: signatureInfo.verified, security: signatureInfo.security }, function(err) {
								if(err)
									return next3(err);
								_keySignatureVerified(keyring, sig.keyId, signatureInfo, next3);
							});
						}
					}
				], next2);
			}, next);
		},
		function(next) {
			keyring.getSubkeySignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
				async.waterfall([
					function(next3) {
						keyring.getSubkeySignature(sig.keyId, sig.subkeyId, sig.signatureId, next3, [ "binary", "issuer", "security" ]);
					},
					function(signatureInfo, next3) {
						signing.verifySubkeySignature(keyring, sig.keyId, sig.subkeyId, signatureInfo, function(err, verified){ next3(err, signatureInfo, verified); });
					},
					function(signatureInfo, verified, next3) {
						if(!verified)
							keyring.removeSubkeySignature(sig.keyId, sig.subkeyId, sig.signatureId, next3);
						else
						{
							keyring._updateSubkeySignature(sig.keyId, sig.subkeyId, sig.signatureId, { verified: signatureInfo.verified, security: signatureInfo.security }, function(err) {
								if(err)
									return next3(err);
								_subkeySignatureVerified(keyring, sig.keyId, sig.subkeyId, signatureInfo, next3);
							});
						}
					}
				], next2);
			}, next);
		},
		function(next) {
			keyring.getIdentitySignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
				async.waterfall([
					function(next3) {
						keyring.getIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, next3, [ "binary", "issuer", "security" ]);
					},
					function(signatureInfo, next3) {
						signing.verifyIdentitySignature(keyring, sig.keyId, sig.identityId, signatureInfo, function(err, verified){ next3(err, signatureInfo, verified); });
					},
					function(signatureInfo, verified, next3) {
						if(!verified)
							keyring.removeIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, next3);
						else
						{
							keyring._updateIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, { verified: signatureInfo.verified, security: signatureInfo.security }, function(err) {
								if(err)
									return next3(err);
								_identitySignatureVerified(keyring, sig.keyId, sig.identityId, signatureInfo, next3);
							});
						}
					}
				], next2);
			}, next);
		},
		function(next) {
			keyring.getAttributeSignatureListByIssuer(keyId, { verified: false }).forEachSeries(function(sig, next2) {
				async.waterfall([
					function(next3) {
						keyring.getAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, next3, [ "binary", "issuer", "security" ]);
					},
					function(signatureInfo, next3) {
						signing.verifyAttributeSignature(keyring, sig.keyId, sig.attributeId, signatureInfo, function(err, verified){ next3(err, signatureInfo, verified); });
					},
					function(signatureInfo, verified, next3) {
						if(!verified)
							keyring.removeAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, next3);
						else
						{
							keyring._updateAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, { verified: signatureInfo.verified, security: signatureInfo.security }, function(err) {
								if(err)
									return next3(err);
								_attributeSignatureVerified(keyring, sig.keyId, sig.attributeId, signatureInfo, next3);
							});
						}
					}
				], next2);
			}, next);
		}
	], callback);
}

function _checkKeyRevocationStatus(keyring, keyId, remove, callback) {
	keyring.getKeySignatures(keyId, { sigtype: consts.SIG.KEY_REVOK, verified: true }, [ "id", "issuer" ]).forEachSeries(function(signatureInfo, next) {
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
			}
		], next);
	}, function(err) {
		if(err || !remove)
			return callback(err);

		keyring._updateKey(keyId, { revoked: null }, callback);
	});
}

function _checkSubkeyRevocationStatus(keyring, keyId, subkeyId, remove, callback) {
	async.series([
		function(next) {
			if(remove)
			{
				keyring.getSubkeySignatures(keyId, subkeyId, { sigtype: consts.SIG.SUBKEY, revoked: new Filter.Not(new Filter.Equals(null)) }, [ "id" ], function(signatureInfo, next) {
					keyring._updateSubkeySignature(keyId, subkeyId, signatureInfo.id, { revoked: null }, next);
				}, next);
			}
			else
				next();
		},
		function(next) {
			keyring.getSubkeySignatures(keyId, subkeyId, { sigtype: consts.SIG.SUBKEY_REVOK, verified: true }, [ "id", "issuer", "date" ]).forEachSeries(function(signatureInfo, next) {
				async.waterfall([
					function(next) {
						if(signatureInfo.issuer == keyId)
							next(null, true);
						else
							_isAuthorisedRevoker(keyring, keyId, signatureInfo.issuer, next);
					},
					function(authorised, next) {
						if(authorised)
						{
							keyring.getSubkeySignatures(keyId, subkeyId, { sigtype: consts.SIG.SUBKEY }, [ "id" ]).forEachSeries(function(signatureInfo2, next) {
								keyring._updateSubkeySignature(keyId, subkeyId, signatureInfo2.id, { revoked: signatureInfo.id }, next);
							}, next);
						}
						else
							next();
					}
				], next);
			}, next);
		}
	], callback);
}

function _isAuthorisedRevoker(keyring, keyId, issuerId, callback) {
	var fifos = [ ];
	var fingerprint = null;
	async.series([
		function(next) {
			keyring.getKey(issuerId, function(err, keyInfo) {
				if(err)
					next(err);
				else if(keyInfo == null)
					callback(null, false);
				else
				{
					fingerprint = keyInfo.fingerprint;
					next();
				}
			}, [ "fingerprint" ]);
		},
		function(next) {
			fifos.push(keyring.getKeySignatures(keyId, { sigtype: consts.SIG.KEY, verified: true }, [ "hashedSubPackets" ]));
			next();
		},
		function(next) {
			keyring.getIdentityList(keyId).forEachSeries(function(identityId, next) {
				fifos.push(keyring.getIdentitySignatures(keyId, identityId, { sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], verified: true }, [ "hashedSubPackets" ]));
				next();
			}, next);
		},
		function(next) {
			keyring.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
				fifos.push(keyring.getAttributeSignatures(keyId, attributeId, { sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], verified: true }, [ "hashedSubPackets" ]));
				next();
			}, next);
		},
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
			}, next);
		}
	], function(err) {
		callback(err, false);
	});
}

// Check 4: Find verified revocation signatures on the specified key and its sub-objects and revoke all earlier signatures by the same issuer on the same object
function _checkSignatureRevocationStatus(keyring, keyId, remove, callback) {
	async.series([
		function(next) {
			if(remove)
				_resetSignatureRevocationStatus(keyring, keyId, next);
			else
				next();
		},
		function(next) {
			keyring.getKeySignatures(keyId, { verified: true, sigtype: consts.SIG.CERT_REVOK }, [ "id", "issuer", "date" ]).forEachSeries(function(revSignatureInfo, next) {
				keyring.getKeySignatures(keyId, { issuer: revSignatureInfo.issuer, sigtype: [ consts.SIG.KEY, consts.SIG.KEY_BY_SUBKEY ], date: new Filter.LessThan(revSignatureInfo.date) }, [ "id", "hashedSubPackets" ]).forEachSeries(function(signatureInfo, next) {
					if(!signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE] || !signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE][0].value)
						keyring._updateKeySignature(keyId, signatureInfo.id, { revoked: revSignatureInfo.id }, next);
					else
						next();
				}, next);
			}, next);
		},
		function(next) {
			keyring.getIdentityList(keyId).forEachSeries(function(identityId, next) {
				keyring.getIdentitySignatures(keyId, identityId, { verified: true, sigtype: consts.SIG.CERT_REVOK }, [ "id", "issuer", "date" ]).forEachSeries(function(revSignatureInfo, next) {
					keyring.getIdentitySignatures(keyId, identityId, { issuer: revSignatureInfo.issuer, sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], date: new Filter.LessThan(revSignatureInfo.date) }, [ "id", "hashedSubPackets" ]).forEachSeries(function(signatureInfo, next) {
						if(!signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE] || !signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE][0].value)
							keyring._updateIdentitySignature(keyId, identityId, signatureInfo.id, { revoked: revSignatureInfo.id }, next);
						else
							next();
					}, next);
				}, next);
			}, next);
		},
		function(next) {
			keyring.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
				keyring.getAttributeSignatures(keyId, attributeId, { verified: true, sigtype: consts.SIG.CERT_REVOK }, [ "id", "issuer", "date" ]).forEachSeries(function(revSignatureInfo, next) {
					keyring.getAttributeSignatures(keyId, attributeId, { issuer: revSignatureInfo.issuer, sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], date: new Filter.LessThan(revSignatureInfo.date) }, [ "id", "hashedSubPackets" ]).forEachSeries(function(signatureInfo, next) {
						if(!signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE] || !signatureInfo.hashedSubPackets[consts.SIGSUBPKT.REVOCABLE][0].value)
							keyring._updateAttributeSignature(keyId, attributeId, signatureInfo.id, { revoked: revSignatureInfo.id }, next);
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
			keyring.getKeySignatures(keyId, { sigtype: [ consts.SIG.KEY, consts.SIG.KEY_BY_SUBKEY ], revoked: new Filter.Not(new Filter.Equals(null)) }, [ "id" ]).forEachSeries(function(signatureInfo, next) {
				keyring._updateKeySignature(keyId, signatureInfo.id, { revoked: null }, next);
			}, next);
		},
		function(next) {
			keyring.getIdentityList(keyId).forEachSeries(function(identityId, next) {
				keyring.getIdentitySignatures(keyId, identityId, { sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], revoked: new Filter.Not(new Filter.Equals(null)) }, [ "id" ]).forEachSeries(function(signatureInfo, next) {
					keyring._updateIdentitySignature(keyId, identityId, signatureInfo.id, { revoked: null }, next);
				}, next);
			}, next);
		},
		function(next) {
			keyring.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
				keyring.getAttributeSignatures(keyId, attributeId, { sigtype: [ consts.SIG.CERT_0, consts.SIG.CERT_1, consts.SIG.CERT_2, consts.SIG.CERT_3 ], revoked: new Filter.Not(new Filter.Equals(null)) }, [ "id" ]).forEachSeries(function(signatureInfo, next) {
					keyring._updateAttributeSignature(keyId, attributeId, signatureInfo.id, { revoked: null }, next);
				}, next);
			}, next);
		}
	], callback);
}

// Check 5a, 6: Check self-signatures for expiration date and primary id
function _checkSelfSignatures(keyring, keyId, callback) {
	keyring.getKey(keyId, function(err, keyInfo) {
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
					keyring.getKeySignatures(keyId, filter, [ "hashedSubPackets", "date" ]).forEachSeries(checkExpire, next);
				},
				function(next) {
					keyring.getIdentityList(keyId).forEachSeries(function(identityId, next) {
						keyring.getIdentitySignatures(keyId, identityId, filter, [ "hashedSubPackets", "date" ]).forEachSeries(async.apply(checkPrimaryAndExpire, identityId), next);
					}, next);
				},
				function(next) {
					keyring.getAttributeList(keyId).forEachSeries(function(attributeId, next) {
						keyring.getAttributeSignatures(keyId, attributeId, filter, [ "hashedSubPackets", "date" ]).forEachSeries(checkExpire, next);
					}, next);
				}
			], function(err) {
				if(err)
					return callback(err);

				keyring._updateKey(keyId, { expires: expire, primary_identity: primary }, callback);
			});
		});
	}, [ "binary", "date" ]);
}

function _checkSubkeyExpiration(keyring, keyId, subkeyId, callback) {
	keyring.getSubkey(keyId, subkeyId, function(err, subkeyInfo) {
		if(err)
			return callback(err);

		var expire = null;
		var expireDate = -1;

		keyring.getSubkeySignatures(keyId, subkeyId, { verified: true, sigtype: consts.SIG.SUBKEY }, [ "date", "hashedSubPackets" ]).forEachSeries(function(signatureInfo, next) {
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

			keyring.getSubkeySignatures(keyId, subkeyId, { sigtype: consts.SIG.SUBKEY }, [ "id", "binary", "expires" ]).forEachSeries(function(signatureInfo, next) {
				packetContent.getSignaturePacketInfo(signatureInfo.binary, function(err, signatureInfoOrig) {
					if(err)
						return next(err);

					var updates = { };

					if(signatureInfoOrig.expires != null && (expire == null || signatureInfoOrig.expires.getTime() > expire.getTime()))
						updates.expires = signatureInfoOrig.expires;
					else
						updates.expires = expire;

					keyring._updateSubkeySignature(keyId, subkeyId, signatureInfo.id, updates, next);
				});
			}, callback);
		});
	}, [ "date" ]);
}

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