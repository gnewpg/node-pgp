var Keyring = require("./index");
var utils = require("../utils");
var signing = require("../signing");
var async = require("async");

utils.extend(Keyring.prototype, {
	addKey : function(keyInfo, callback) {
		_add(
			this.keyExists.bind(this, keyInfo.id),
			this._addKey.bind(this, keyInfo),
			this.removeKey.bind(this, keyInfo.id),
			this.__keyAdded.bind(this, keyInfo.id),
			callback
		);
	},

	removeKey : function(id, callback) {
		this._removeKey(id, callback);
	},

	addSubkey : function(keyId, subkeyInfo, callback) {
		_add(
			this.subkeyExists.bind(this, keyId, subkeyInfo.id),
			this._addSubkey.bind(this, keyId, subkeyInfo),
			this.removeSubkey.bind(this, keyId, subkeyInfo.id),
			this.__keyAdded.bind(this, subkeyInfo.id),
			callback
		);
	},

	removeSubkey : function(keyId, subkeyId, callback) {
		this._removeSubkey(keyId, subkeyId, callback);
	},

	addIdentity : function(keyId, identityInfo, callback) {
		_add(
			this.identityExists.bind(this, keyId, identityInfo.id),
			this._addIdentity.bind(this, keyId, identityInfo),
			this.removeIdentity.bind(this, keyId, identityInfo.id),
			null,
			callback
		);
	},

	removeIdentity : function(keyId, id, callback) {
		this._removeIdentity(keyId, id, callback);
	},

	addAttribute : function(keyId, attributeInfo, callback) {
		_add(
			this.attributeExists.bind(this, keyId, attributeInfo.id),
			this._addAttribute.bind(this, keyId, attributeInfo),
			this.removeAttribute.bind(this, keyId, attributeInfo.id),
			null,
			callback
		);
	},

	removeAttribute : function(keyId, id, callback) {
		this._removeAttribute(keyId, id, callback);
	},

	addKeySignature : function(keyId, signatureInfo, callback) {
		_add(
			this.keySignatureExists.bind(this, keyId, signatureInfo.id),
			this._addKeySignature.bind(this, keyId, signatureInfo),
			this.removeKeySignature.bind(this, keyId, signatureInfo.id),
			function(next) {
				signing.verifyKeySignature(this, keyId, signatureInfo, function(err, verified) {
					if(err || verified === false)
						next(err || new Error("Invalid signature."));
					else if(verified == null)
						next();
					else {
						async.series([
							this._updateKeySignature.bind(this, keyId, signatureInfo.id, { verified: signatureInfo.verified, security: signatureInfo.security }),
							this.__keySignatureVerified.bind(this, keyId, signatureInfo)
						], next);
					}
				}.bind(this));
			}.bind(this),
			callback
		);
	},

	removeKeySignature : function(keyId, id, callback) {
		this.getKeySignature(keyId, id, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				this._removeKeySignature.bind(this, keyId, id),
				this.__keySignatureRemoved.bind(this, keyId, signatureInfo)
			], callback);
		}.bind(this));
	},

	addSubkeySignature : function(keyId, subkeyId, signatureInfo, callback) {
		_add(
			this.subkeySignatureExists.bind(this, keyId, subkeyId, signatureInfo.id),
			this._addSubkeySignature.bind(this, keyId, subkeyId, signatureInfo),
			this.removeSubkeySignature.bind(this, keyId, subkeyId, signatureInfo.id),
			function(next) {
				signing.verifySubkeySignature(this, keyId, subkeyId, signatureInfo, function(err, verified) {
					if(err || verified === false)
						next(err || new Error("Invalid signature."));
					else if(verified == null)
						next();
					else {
						async.series([
							this._updateSubkeySignature.bind(this, keyId, subkeyId, signatureInfo.id, { verified: signatureInfo.verified, security: signatureInfo.security }),
							this.__subkeySignatureVerified.bind(this, keyId, subkeyId, signatureInfo)
						], next);
					}
				}.bind(this));
			}.bind(this),
			callback
		);
	},

	removeSubkeySignature : function(keyId, subkeyId, id, callback) {
		this.getSubkeySignature(keyId, subkeyId, id, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				this._removeSubkeySignature.bind(this, keyId, subkeyId, id),
				this.__subkeySignatureRemoved.bind(this, keyId, subkeyId, signatureInfo)
			], callback);
		}.bind(this));
	},

	addIdentitySignature : function(keyId, identityId, signatureInfo, callback) {
		_add(
			this.identitySignatureExists.bind(this, keyId, identityId, signatureInfo.id),
			this._addIdentitySignature.bind(this, keyId, identityId, signatureInfo),
			this.removeIdentitySignature.bind(this, keyId, identityId, signatureInfo.id),
			function(next) {
				signing.verifyIdentitySignature(this, keyId, identityId, signatureInfo, function(err, verified) {
					if(err || verified === false)
						next(err || new Error("Invalid signature."));
					else if(verified == null)
						next();
					else {
						async.series([
							this._updateIdentitySignature.bind(this, keyId, identityId, signatureInfo.id, { verified: signatureInfo.verified, security: signatureInfo.security }),
							this.__identitySignatureVerified.bind(this, keyId, identityId, signatureInfo)
						], next);
					}
				}.bind(this));
			}.bind(this),
			callback
		);
	},

	removeIdentitySignature : function(keyId, identityId, id, callback) {
		this.getIdentitySignature(keyId, identityId, id, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				this._removeIdentitySignature.bind(this, keyId, identityId, id),
				this.__identitySignatureRemoved.bind(this, keyId, identityId, signatureInfo)
			], callback);
		}.bind(this));
	},

	addAttributeSignature : function(keyId, attributeId, signatureInfo, callback) {
		_add(
			this.attributeSignatureExists.bind(this, keyId, attributeId, signatureInfo.id),
			this._addAttributeSignature.bind(this, keyId, attributeId, signatureInfo),
			this.removeAttributeSignature.bind(this, keyId, attributeId, signatureInfo.id),
			function(next) {
				signing.verifyAttributeSignature(this, keyId, attributeId, signatureInfo, function(err, verified) {
					if(err || verified === false)
						next(err || new Error("Invalid signature."));
					else if(verified == null)
						next();
					else {
						async.series([
							this._updateAttributeSignature.bind(this, keyId, attributeId, signatureInfo.id, { verified: signatureInfo.verified, security: signatureInfo.security }),
							this.__attributeSignatureVerified.bind(this, keyId, attributeId, signatureInfo)
						], next);
					}
				}.bind(this));
			}.bind(this),
			callback
		);
	},

	removeAttributeSignature : function(keyId, attributeId, id, callback) {
		this.getAttributeSignature(keyId, attributeId, id, function(err, signatureInfo) {
			if(err)
				return callback(err);

			async.series([
				this._removeAttributeSignature.bind(this, keyId, attributeId, id),
				this.__attributeSignatureRemoved.bind(this, keyId, attributeId, signatureInfo)
			], callback);
		}.bind(this));
	}
});

function _add(existsFunc, addFunc, removeFunc, func, callback) {
	existsFunc(function(err, exists) {
		if(err)
			callback(err);
		else if(exists)
			callback(null);
		else
		{
			addFunc(function(err) {
				if(err || !func)
					finish(err);
				else
					func(finish);
			});
		}
	}, true); // The true parameter is a hack for subkeyExists() in node-pgp-postgres and *Exists() in gnewpg

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