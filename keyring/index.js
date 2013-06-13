var utils = require("../utils");
var Filter = require("./filters");
var async = require("async");
var Fifo = require("../fifo");

var p = utils.proxy;

module.exports = Keyring;
module.exports._filter = _filter;
module.exports._strip = _strip;
module.exports.Filter = Filter;

function Keyring() {
}

Keyring.prototype = {
	getKeyList : function(filter) {
		return __getNotImplementedFifo();
	},

	getKeys : function(filter, fields) {
		return __getItems(this.getKeyList(filter), p(this, this.getKey), fields);
	},

	keyExists : function(id, callback) {
		callback(new Error("Not implemented."))
	},

	getKey : function(id, callback, fields) {
		callback(new Error("Not implemented."));
	},

	addKey : function(keyInfo, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_addKey : function(keyInfo, callback) {
		callback(new Error("Not implemented."));
	},

	_updateKey : function(id, fields, callback) {
		callback(new Error("Not implemented."));
	},

	removeKey : function(id, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_removeKey : function(id, callback) {
		callback(new Error("Not implemented."));
	},

	getSubkeyList : function(keyId, filter) {
		return __getNotImplementedFifo();
	},

	getSubkeys : function(keyId, filter, fields) {
		return __getItems(this.getSubkeyList(keyId, filter), async.apply(p(this, this.getSubkey), keyId), fields);
	},

	subkeyExists : function(keyId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getSubkey : function(keyId, id, callback, fields) {
		callback(new Error("Not implemented."));
	},

	getSelfSignedSubkeys : function(keyId, filter, fields) {
		throw new Error("Implemented in keyring/combine.js");
	},

	getSelfSignedSubkey : function(keyId, id, callback, fields) {
		throw new Error("Implemented in keyring/combine.js");
	},

	addSubkey : function(keyId, subkeyInfo, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_addSubkey : function(keyId, subkeyInfo, callback) {
		callback(new Error("Not implemented."));
	},

	_updateSubkey : function(keyId, subkeyId, fields, callback) {
		callback(new Error("Not implemented."));
	},

	removeSubkey : function(keyId, subkeyId, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_removeSubkey : function(keyId, subkeyId, callback) {
		callback(new Error("Not implemented."));
	},

	getParentKeyList : function(subkeyId) {
		callback(new Error("Not implemented."));
	},

	getParentKeys : function(subkeyId, fields) {
		return __getItems(this.getParentKeyList(subkeyId), p(this, this.getKey), fields);
	},

	getIdentityList : function(keyId, filter) {
		return __getNotImplementedFifo();
	},

	getIdentities : function(keyId, filter, fields) {
		return __getItems(this.getIdentityList(keyId, filter), async.apply(p(this, this.getIdentity), keyId), fields);
	},

	identityExists : function(keyId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getIdentity : function(keyId, id, callback, fields) {
		callback(new Error("Not implemented."));
	},

	getSelfSignedIdentities : function(keyId, filter, fields) {
		throw new Error("Implemented in keyring/combine.js");
	},

	getSelfSignedIdentity : function(keyId, id, callback, fields) {
		throw new Error("Implemented in keyring/combine.js");
	},

	addIdentity : function(keyId, identityInfo, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_addIdentity : function(keyId, identityInfo, callback) {
		callback(new Error("Not implemented."));
	},

	_updateIdentity : function(keyId, identityId, fields, callback) {
		callback(new Error("Not implemented."));
	},

	removeIdentity : function(keyId, id, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_removeIdentity : function(keyId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getAttributeList : function(keyId, filter) {
		return __getNotImplementedFifo();
	},

	getAttributes : function(keyId, filter, fields) {
		return __getItems(this.getAttributeList(keyId, filter), async.apply(p(this, this.getIdentity), keyId), fields);
	},

	attributeExists : function(keyId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getAttribute : function(keyId, id, callback, fields) {
		callback(new Error("Not implemented."));
	},

	getSelfSignedAttributes : function(keyId, filter, fields) {
		throw new Error("Implemented in keyring/combine.js");
	},

	getSelfSignedAttribute : function(keyId, id, callback, fields) {
		throw new Error("Implemented in keyring/combine.js");
	},

	addAttribute : function(keyId, attributeInfo, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_addAttribute : function(keyId, attributeInfo, callback) {
		callback(new Error("Not implemented."));
	},

	_updateAttribute : function(keyId, attributeId, fields, callback) {
		callback(new Error("Not implemented."));
	},

	removeAttribute : function(keyId, id, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_removeAttribute : function(keyId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getKeySignatureList : function(keyId, filter) {
		return __getNotImplementedFifo();
	},

	getKeySignatures : function(keyId, filter, fields) {
		return __getItems(this.getKeySignatureList(keyId, filter), async.apply(p(this, this.getKeySignature), keyId), fields);
	},

	getKeySignatureListByIssuer : function(issuerId, filter) {
		filter = utils.extend({ }, filter, { issuer: issuerId });

		var ret = new Fifo();
		this.getKeyList().forEachSeries(p(this, function(keyId, next) {
			this.getKeySignatureList(keyId, filter).forEachSeries(function(signatureId, next2) {
				ret._add({ keyId: keyId, signatureId: signatureId });
				next2();
			}, next);
		}), p(ret, ret._end));
		return ret;
	},

	keySignatureExists : function(keyId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getKeySignature : function(keyId, id, callback, fields) {
		callback(new Error("Not implemented."));
	},

	addKeySignature : function(keyId, signatureInfo, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_addKeySignature : function(keyId, signatureInfo, callback) {
		callback(new Error("Not implemented."));
	},

	_updateKeySignature : function(keyId, signatureId, fields, callback) {
		callback(new Error("Not implemented."));
	},

	removeKeySignature : function(keyId, id, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_removeKeySignature : function(keyId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getSubkeySignatureList : function(keyId, subkeyId, filter) {
		return __getNotImplementedFifo();
	},

	getSubkeySignatures : function(keyId, subkeyId, filter, fields) {
		return __getItems(this.getSubkeySignatureList(keyId, subkeyId, filter), async.apply(p(this, this.getSubkeySignature), keyId, subkeyId), fields);
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

	subkeySignatureExists : function(keyId, subkeyId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getSubkeySignature : function(keyId, subkeyId, id, callback, fields) {
		callback(new Error("Not implemented."));
	},

	addSubkeySignature : function(keyId, subkeyId, signatureInfo, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_addSubkeySignature : function(keyId, subkeyId, signatureInfo, callback) {
		callback(new Error("Not implemented."));
	},

	_updateSubkeySignature : function(keyId, subkeyId, signatureId, fields, callback) {
		callback(new Error("Not implemented."));
	},

	removeSubkeySignature : function(keyId, subkeyId, id, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_removeSubkeySignature : function(keyId, subkeyId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getIdentitySignatureList : function(keyId, identityId, filter) {
		return __getNotImplementedFifo();
	},

	getIdentitySignatures : function(keyId, identityId, filter, fields) {
		return __getItems(this.getIdentitySignatureList(keyId, identityId, filter), async.apply(p(this, this.getIdentitySignature), keyId, identityId), fields);
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

	identitySignatureExists : function(keyId, identityId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getIdentitySignature : function(keyId, identityId, id, callback, fields) {
		callback(new Error("Not implemented."));
	},

	addIdentitySignature : function(keyId, identityId, signatureInfo, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_addIdentitySignature : function(keyId, identityId, signatureInfo, callback) {
		callback(new Error("Not implemented."));
	},

	_updateIdentitySignature : function(keyId, identityId, signatureId, fields, callback) {
		callback(new Error("Not implemented."));
	},

	removeIdentitySignature : function(keyId, identityId, id, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_removeIdentitySignature : function(keyId, identityId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getAttributeSignatureList : function(keyId, attributeId, filter) {
		return __getNotImplementedFifo();
	},

	getAttributeSignatures : function(keyId, attributeId, filter, fields) {
		return __getItems(this.getAttributeSignatureList(keyId, attributeId, filter), async.apply(p(this, this.getAttributeSignature), keyId, attributeId), fields);
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

	attributeSignatureExists : function(keyId, attributeId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getAttributeSignature : function(keyId, attributeId, id, callback, fields) {
		callback(new Error("Not implemented."));
	},

	addAttributeSignature : function(keyId, attributeId, signatureInfo, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_addAttributeSignature : function(keyId, attributeId, signatureInfo, callback) {
		callback(new Error("Not implemented."));
	},

	_updateAttributeSignature : function(keyId, attributeId, signatureId, fields, callback) {
		callback(new Error("Not implemented."));
	},

	removeAttributeSignature : function(keyId, attributeId, id, callback) {
		throw new Error("Implemented in keyring/addRemove.js");
	},

	_removeAttributeSignature : function(keyId, attributeId, id, callback) {
		callback(new Error("Not implemented."));
	},

	getSignatureById : function(signatureId, callback, fields) {
		callback(new Error("Not implemented."));
	},

	getAllSignatures : function(keyId, filter, fields) {
		return Fifo.fromArraySingle([
			this.getKeySignatures(keyId, filter, fields),
			this.getIdentityList(keyId).map(function(identityId, next) { next(null, this.getIdentitySignatures(keyId, identityId, filter, fields));}.bind(this)),
			this.getAttributeList(keyId).map(function(attributeId, next) { next(null, this.getAttributeSignatures(keyId, attributeId, filter, fields));}.bind(this))
		]).recursive();
	},

	saveChanges : function(callback) {
		callback(new Error("Not implemented."));
	},

	revertChanges : function(callback) {
		callback(new Error("Not implemented."));
	},

	/**
	 * Closes all handles and connections that were opened for this keyring. The keyring object
	 * is not usable afterwards.
	 */
	done : function() {
	},

	importKeys : function(keyData, callback, acceptLocal) {
		throw new Error("Implemented in keyring/importExport.js");
	},

	exportKey : function(keyId, selection) {
		throw new Error("Implemented in keyring/importExport.js");
	},

	/**
	 * Gets the primary ID for the given key. If no primary ID is set or the set primary ID is non-public and not
	 * contained in the given keyring, returns another ID of the key that can be displayed.
	*/
	getPrimaryIdentity : function(keyId, callback, fields) {
		throw new Error("Implemented in keyring/combine.js");
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
		throw new Error("Implemented in keyring/combine.js");
	},

	search : function(searchString) {
		throw new Error("Implemented in keyring/search.js");
	},

	searchIdentities : function(searchString) {
		throw new Error("Implemented in keyring/combine.js");
	},

	searchByShortKeyId : function(keyId) {
		throw new Error("Implemented in keyring/combine.js");
	},

	searchByLongKeyId : function(keyId) {
		throw new Error("Implemented in keyring/combine.js");
	},

	searchByFingerprint : function(keyId) {
		throw new Error("Implemented in keyring/combine.js");
	},

	/**
	 * Trust all signatures and trust signatures issued by the given key.
	 */
	trustKey : function(keyId, callback) {
		throw new Error("Implemented in keyring/trust.js");
	},

	untrustKey : function(keyId, callback) {
		throw new Error("Implemented in keyring/trust.js");
	},

	_getOwnerTrustInfo : function(keyId, filter, fields) {
		return __getNotImplementedFifo();
	},

	_addOwnerTrustInfo : function(keyId, trustInfo, callback) {
		callback(new Error("Not implemented."));
	},

	/**
	 * Removes all owner trust records that contain the given signature in their signature chain.
	 * Returns those records.
	 */
	_removeOwnerTrustBySignature : function(signatureId) {
		return __getNotImplementedFifo();
	},

	/**
	 * Removes the initial key trust records for that key (that is, a trust record with an empty key
	 * path) and all trust records that have that key at the start of their key path. Returns
	 * the deleted records.
	 */
	_removeKeyTrust : function(keyId) {
		return __getNotImplementedFifo();
	}
};

function __getNotImplementedFifo() {
	var ret = new Fifo();
	ret._end(new Error("Not implemented."));
	return ret;
}

function __getItems(list, getItem, fields) {
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

/**
 * Applies a filter on a list
 * @param list {Fifo}
 * @param filter {Object} An object containing Filter objects (see keyring/filters.js)
 * @return {Fifo} The filtered list
 */
function _filter(list, filter) {
	if(filter == null || Object.keys(filter).length == 0)
		return list;

	return list.grep(function(item, callback) {
		for(var i in filter)
		{
			if(!Filter.get(filter[i]).check(item[i]))
				return callback(null, false);
		}
		callback(null, true);
	});
}

/**
 * Removes the non-requested fields from an item.
 * @param item {Object}
 * @param fieldList {Array}
 * @return {Object}
 */
function _strip(item, fieldList) {
	if(fieldList == null)
		return item;

	var newItem = { };
	for(var i=0; i<fieldList.length; i++)
		newItem[fieldList[i]] = item[fieldList[i]];
	return newItem;
}

require("./addRemove");
require("./search");
require("./importExport");
require("./combine");
require("./signatureRelations");
require("./trust");