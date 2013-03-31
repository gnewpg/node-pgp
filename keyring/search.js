var Keyring = require("./index");
var utils = require("../utils");
var Fifo = require("../fifo");
var Filter = require("./filters");
var async = require("async");

var p = utils.proxy;

utils.extend(Keyring.prototype, {
	search : function(searchString) {
		var ret = [ ];

		var searchInIdentities = true;

		if([ 10, 18, 34, 42 ].indexOf(searchString.length) != -1 && searchString.match(/^0x/i))
		{
			searchString = searchString.substring(2);
			searchInIdentities = false;
		}

		var addPrimaryIdentity = p(this, function(fifo) {
			return fifo.map(p(this, function(keyInfo, cb) {
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
});