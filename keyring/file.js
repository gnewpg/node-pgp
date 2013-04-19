var util = require("util");
var Keyring = require("../keyring");
var Fifo = require("../fifo");
var fs = require("fs");
var BufferedStream = require("../bufferedStream");
var consts = require("../consts");
var utils = require("../utils");
var async = require("async");

function getStreamKeyring(stream, callback) {
	var ret = new _KeyringStream(stream);
	ret.importKeys(stream, function(err) {
		if(err)
			callback(err);
		else
			callback(null, ret);
	});
}

function getFileKeyring(fname, callback, create) {
	var ret = new _KeyringFile(fname);
	async.waterfall([
		function(next) {
			if(create)
				fs.exists(fname, function(exists) { next(null, exists); });
			else
				next(null, true);
		},
		function(doRead, next) {
			if(doRead)
				ret.revertChanges(next);
			else
				next();
		}
	], function(err) {
		if(err)
			callback(err);
		else
			callback(null, ret);
	});
}

function _KeyringStream(stream) {
	_KeyringStream.super_.call(this);

	this._clear();
}

util.inherits(_KeyringStream, Keyring);

utils.extend(_KeyringStream.prototype, {
	getKeyList : function(filter) {
		return _getList(filter, this._keys);
	},

	keyExists : function(id, callback) {
		_exists(callback, this._keys, id);
	},

	getKey : function(id, callback, fields) {
		_get(callback, fields, this._keys, id);
	},

	_addKey : function(keyInfo, callback) {
		_add(callback, keyInfo, this._keys);
	},

	_updateKey : function(id, fields, callback) {
		_update(callback, fields, this._keys, id);
	},

	_removeKey : function(id, callback) {
		_remove(callback, this._keys, id);
	},

	getSubkeyList : function(keyId, filter) {
		return _getList(filter, this._subkeys, keyId);
	},

	subkeyExists : function(keyId, id, callback) {
		_exists(callback, this._subkeys, keyId, id);
	},

	getSubkey : function(keyId, id, callback, fields) {
		_get(callback, fields, this._subkeys, keyId, id);
	},

	_addSubkey : function(keyId, subkeyInfo, callback) {
		_add(callback, subkeyInfo, this._subkeys, keyId);
	},

	_updateSubkey : function(keyId, id, fields, callback) {
		_update(callback, fields, this._subkeys, keyId, id);
	},

	_removeSubkey : function(keyId, id, callback)
	{
		_remove(callback, this._subkeys, keyId, id);
	},

	getParentKeyList : function(subkeyId) {
		var ret = new Fifo();
		for(var i in this._keys)
		{
			if(this._subkeys[i] && this._subkeys[i][subkeyId])
				ret._add(i);
		}
		ret._end();
		return ret;
	},

	getIdentityList : function(keyId, filter) {
		return _getList(filter, this._identities, keyId);
	},

	identityExists : function(keyId, id, callback) {
		_exists(callback, this._identities, keyId, id);
	},

	getIdentity : function(keyId, id, callback, fields) {
		_get(callback, fields, this._identities, keyId, id);
	},

	_addIdentity : function(keyId, identityInfo, callback) {
		_add(callback, identityInfo, this._identities, keyId);
	},

	_updateIdentity : function(keyId, id, fields, callback) {
		_update(callback, fields, this._identities, keyId, id);
	},

	_removeIdentity : function(keyId, id, callback) {
		_remove(callback, this._identities, keyId, id);
	},

	getAttributeList : function(keyId, filter) {
		return _getList(filter, this._attributes, keyId);
	},

	attributeExists : function(keyId, id, callback) {
		_exists(callback, this._attributes, keyId, id);
	},

	getAttribute : function(keyId, id, callback, fields) {
		_get(callback, fields, this._attributes, keyId, id);
	},

	_addAttribute : function(keyId, attributeInfo, callback) {
		_add(callback, attributeInfo, this._attributes, keyId);
	},

	_updateAttribute : function(keyId, id, fields, callback) {
		_update(callback, fields, this._attributes, keyId, id);
	},

	_removeAttribute : function(keyId, id, callback) {
		_remove(callback, this._attributes, keyId, id);
	},

	getKeySignatureList : function(keyId, filter) {
		return _getList(filter, this._keySignatures, keyId);
	},

	keySignatureExists : function(keyId, id, callback) {
		_exists(callback, this._keySignatures, keyId, id);
	},

	getKeySignature : function(keyId, id, callback, fields) {
		_get(callback, fields, this._keySignatures, keyId, id);
	},

	_addKeySignature : function(keyId, signatureInfo, callback) {
		_add(callback, signatureInfo, this._keySignatures, keyId);
	},

	_updateKeySignature : function(keyId, id, fields, callback) {
		_update(callback, fields, this._keySignatures, keyId, id);
	},

	_removeKeySignature : function(keyId, id, callback) {
		_remove(callback, this._keySignatures, keyId, id);
	},

	getSubkeySignatureList : function(keyId, subkeyId, filter) {
		return _getList(filter, this._subkeySignatures, keyId, subkeyId);
	},

	subkeySignatureExists : function(keyId, subkeyId, id, callback) {
		_exists(callback, this._subkeySignatures, keyId, subkeyId, id);
	},

	getSubkeySignature : function(keyId, subkeyId, id, callback, fields) {
		_get(callback, fields, this._subkeySignatures, keyId, subkeyId, id);
	},

	_addSubkeySignature : function(keyId, subkeyId, signatureInfo, callback) {
		_add(callback, signatureInfo, this._subkeySignatures, keyId, subkeyId);
	},

	_updateSubkeySignature : function(keyId, subkeyId, id, fields, callback) {
		_update(callback, fields, this._subkeySignatures, keyId, subkeyId, id);
	},

	_removeSubkeySignature : function(keyId, subkeyId, id, callback) {
		_remove(callback, this._subkeySignatures, keyId, subkeyId, id);
	},

	getIdentitySignatureList : function(keyId, identityId, filter) {
		return _getList(filter, this._identitySignatures, keyId, identityId);
	},

	identitySignatureExists : function(keyId, identityId, id, callback) {
		_exists(callback, this._identitySignatures, keyId, identityId, id);
	},

	getIdentitySignature : function(keyId, identityId, id, callback, fields) {
		_get(callback, fields, this._identitySignatures, keyId, identityId, id);
	},

	_addIdentitySignature : function(keyId, identityId, signatureInfo, callback) {
		_add(callback, signatureInfo, this._identitySignatures, keyId, identityId);
	},

	_updateIdentitySignature : function(keyId, identityId, id, fields, callback) {
		_update(callback, fields, this._identitySignatures, keyId, identityId, id);
	},

	_removeIdentitySignature : function(keyId, identityId, id, callback) {
		_remove(callback, this._identitySignatures, keyId, identityId, id);
	},

	getAttributeSignatureList : function(keyId, attributeId, filter) {
		return _getList(filter, this._attributeSignatures, keyId, attributeId);
	},

	attributeSignatureExists : function(keyId, attributeId, id, callback) {
		_exists(callback, this._attributeSignatures, keyId, attributeId, id);
	},

	getAttributeSignature : function(keyId, attributeId, id, callback, fields) {
		_get(callback, fields, this._attributeSignatures, keyId, attributeId, id);
	},

	_addAttributeSignature : function(keyId, attributeId, signatureInfo, callback) {
		_add(callback, signatureInfo, this._attributeSignatures, keyId, attributeId);
	},

	_updateAttributeSignature : function(keyId, attributeId, id, fields, callback) {
		_update(callback, fields, this._attributeSignatures, keyId, attributeId, id);
	},

	_removeAttributeSignature : function(keyId, attributeId, id, callback) {
		_remove(callback, this._attributeSignatures, keyId, attributeId, id);
	},

	getSignatureById : function(signatureId, callback, fields) {
		for(var keyId in this._keys)
		{
			if(this._keySignatures[keyId] && this._keySignatures[keyId][signatureId] && this._keySignatures[keyId][signatureId].verified)
				return callback(null, utils.extend(Keyring._strip(this._keySignatures[keyId][signatureId], fields), { key: keyId }));

			for(var subkeyId in this._subkeySignatures[keyId] || { })
			{
				if(this._subkeySignatures[keyId][subkeyId][signatureId] && this._subkeySignatures[keyId][subkeyId][signatureId].verified)
					return callback(null, utils.extend(Keyring._strip(this._subkeySignatures[keyId][subkeyId][signatureId], fields), { key: keyId, subkey: subkeyId }));
			}

			for(var identityId in this._identitySignatures[keyId] || { })
			{
				if(this._identitySignatures[keyId][identityId][signatureId] && this._identitySignatures[keyId][identityId][signatureId].verified)
					return callback(null, utils.extend(Keyring._strip(this._identitySignatures[keyId][identityId][signatureId], fields), { key: keyId, identity: identityId }));
			}

			for(var attributeId in this._attributeSignatures[keyId] || { })
			{
				if(this._attributeSignatures[keyId][attributeId][signatureId] && this._attributeSignatures[keyId][attributeId][signatureId].verified)
					return callback(null, utils.extend(Keyring._strip(this._attributeSignatures[keyId][attributeId][signatureId], fields), { key: keyId, attribute: attributeId }));
			}
		}

		callback(null, null);
	},

	_clear : function() {
		this._keys = { };
		this._subkeys = { };
		this._identities = { };
		this._attributes = { };
		this._keySignatures = { };
		this._subkeySignatures = { };
		this._identitySignatures = { };
		this._attributeSignatures = { };
		this._ownerTrust = { };
	},

	_getOwnerTrustInfo : function(keyId, filter, fields) {
		return Keyring._filter(new Fifo.fromArraySingle(this._ownerTrust[keyId] || [ ]), filter).map(function(it, next) {
			next(null, Keyring._strip(it, fields));
		});
	},

	_addOwnerTrustInfo : function(keyId, trustInfo, callback) {
		if(!this._ownerTrust[keyId])
			this._ownerTrust[keyId] = [ ];
		this._ownerTrust[keyId].push(trustInfo);
		callback(null);
	},

	_removeOwnerTrustBySignature : function(signatureId) {
		var ret = [ ];
		for(var i in this._ownerTrust) {
			for(var j=0; j<this._ownerTrust[i].length; j++) {
				if(this._ownerTrust[i][j].signaturePath.indexOf(signatureId) != -1) {
					ret.push(utils.extend({ key: i }, this._ownerTrust[i][j]));
					this._ownerTrust[i] = this._ownerTrust[i].slice(0, j).concat(this._ownerTrust[i].slice(j+1));
					j--;
				}
			}
		}
		return Fifo.fromArraySingle(ret);
	},

	_removeKeyTrust : function(keyId) {
		if(!this._ownerTrust[keyId])
			return Fifo.fromArraySingle([ ]);

		var ret = [ ];

		for(var i=0; i<this._ownerTrust[keyId].length; i++) {
			if(this._ownerTrust[keyId][i].signaturePath.length == 0) {
				ret.push(utils.extend({ key: keyId }, this._ownerTrust[keyId][i]));
				this._ownerTrust[keyId] = this._ownerTrust[keyId].slice(0, i).concat(this._ownerTrust[keyId].slice(i+1));
				i--;
			}
		}

		for(var i in this._ownerTrust) {
			for(var j=0; j<this._ownerTrust[i].length; j++) {
				if(this._ownerTrust[i][j].keyPath[0] == keyId) {
					ret.push(utils.extend({ key: i }, this._ownerTrust[i][j]));
					this._ownerTrust[i] = this._ownerTrust[i].slice(0, j).concat(this._ownerTrust[i].slice(j+1));
					j--;
				}
			}
		}

		return Fifo.fromArraySingle(ret);
	}
});

function _KeyringFile(filename) {
	_KeyringFile.super_.call(this);

	this._filename = filename;
}

util.inherits(_KeyringFile, _KeyringStream);

utils.extend(_KeyringFile.prototype, {
	saveChanges : function(callback) {
		var t = this;
		var stream = fs.createWriteStream(this._filename);

		t.getKeyList().forEachSeries(function(keyId, next) {
			t.exportKey(keyId).whilst(function(data, next) {
				stream.write(data);
				next();
			}, next);
		}, function(err) {
			stream.end();
			callback(err);
		});
	},

	revertChanges : function(callback) {
		this._clear();
		this.importKeys(fs.createReadStream(this._filename), callback);
	}
});

function _getItem(obj, args, make) {
	for(var i=0; i<args.length; i++) {
		if(obj[args[i]] == null)
		{
			if(make)
				obj[args[i]] = { };
			else
				return null;
		}
		obj = obj[args[i]];
	}
	return obj;
}

function _getList(filter, obj, idx) {
	obj = _getItem(obj, utils.toProperArray(arguments).slice(2));

	var fifo = new Fifo();
	for(var i in obj)
		fifo._add(obj[i]);
	fifo._end();

	return Keyring._filter(fifo, filter).map(function(item, callback) {
		callback(null, item.id);
	});
}

function _exists(callback, obj, idx) {
	callback(null, _getItem(obj, utils.toProperArray(arguments).slice(2)) != null);
}

function _get(callback, fields, obj, idx) {
	obj = _getItem(obj, utils.toProperArray(arguments).slice(3));

	if(obj == null)
		callback(null, null);
	else
		callback(null, Keyring._strip(obj, fields));
}

function _add(callback, item, obj, idx) {
	obj = _getItem(obj, utils.toProperArray(arguments).slice(3), true);

	obj[item.id] = item;
	callback(null);
}

function _update(callback, fields, obj, idx) {
	obj = _getItem(obj, utils.toProperArray(arguments).slice(3));

	if(obj == null)
		callback(new Error("Item not found."));
	else
	{
		utils.extend(obj, fields);
		callback(null);
	}
}

function _remove(callback, obj, idx) {
	obj = _getItem(obj, utils.toProperArray(arguments).slice(2, -1));

	var idx = arguments[arguments.length-1];
	if(obj && obj[idx] != null)
	{
		delete obj[idx];
		callback(null);
	}
	else
		callback(new Error("Item not found."));
}

exports.getStreamKeyring = getStreamKeyring;
exports.getFileKeyring = getFileKeyring;