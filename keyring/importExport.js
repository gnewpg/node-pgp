var Keyring = require("./index");
var utils = require("../utils");
var consts = require("../consts");
var packets = require("../packets");
var packetContent = require("../packetContent");
var async = require("async");
var formats = require("../formats");
var BufferedStream = require("../bufferedStream");

utils.extend(Keyring.prototype, {
	importKeys : function(keyData, callback, acceptLocal) {
		var t = this;

		var imported = {
			keys : [ ],
			failed : [ ]
		};

		function add(addTo, infoObj, next) {
			addTo.push(infoObj);
			setImmediate(next);
		}

		function addError(infoObj, err, next) {
			infoObj.err = err;
			imported.failed.push(infoObj);
			setImmediate(next);
		}

		var lastKeyId = null;
		var lastSubkeyId = null;
		var lastIdentityId = null;
		var lastAttributeId = null;

		var lastKeyImported = null;
		var lastSubkeyImported = null;
		var lastIdentityImported = null;
		var lastAttributeImported = null;

		var cleanEmptyKey = function(callback) {
			if(lastKeyId == null)
				return callback(null);

			_listEmpty(this.getKeySignatureList(lastKeyId, { issuer: lastKeyId, verified: true }).concat(this.getSubkeyList(lastKeyId), this.getIdentityList(lastKeyId), this.getAttributeList(lastKeyId)), function(err, empty) {
				if(err)
					return callback(err);
				if(!empty) {
					lastKeyId = null;
					return add(imported.keys, lastKeyImported, callback);
				}

				this.removeKey(lastKeyId, function(err) {
					if(err)
						return callback(err);

					lastKeyId = null;
					addError(lastKeyImported, new Error("Key without self-signatures"), callback);
				});
			}.bind(this));
		}.bind(this);

		var cleanEmptySubkey = function(callback) {
			if(lastSubkeyId == null)
				return callback(null);

			_listEmpty(this.getSubkeySignatureList(lastKeyId, lastSubkeyId, { issuer: lastKeyId, verified: true }), function(err, empty) {
				if(err)
					return callback(err);
				if(!empty) {
					lastSubkeyId = null;
					return add(lastKeyImported.subkeys, lastSubkeyImported, callback);
				}

				this.removeSubkey(lastKeyId, lastSubkeyId, function(err) {
					if(err)
						return callback(err);

					lastSubkeyId = null;
					addError(lastSubkeyImported, new Error("Subkey without signatures"), callback);
				});
			}.bind(this));
		}.bind(this);

		var cleanEmptyIdentity = function(callback) {
			if(lastIdentityId == null)
				return callback(null);

			_listEmpty(this.getIdentitySignatureList(lastKeyId, lastIdentityId, { issuer: lastKeyId, verified: true }), function(err, empty) {
				if(err)
					return callback(err);
				if(!empty) {
					lastIdentityId = null;
					return add(lastKeyImported.identities, lastIdentityImported, callback);
				}

				this.removeIdentity(lastKeyId, lastIdentityId, function(err) {
					if(err)
						return callback(err);

					lastIdentityId = null;
					addError(lastIdentityImported, new Error("Identity without self-signatures"), callback);
				});
			}.bind(this));
		}.bind(this);

		var cleanEmptyAttribute = function(callback) {
			if(lastAttributeId == null)
				return callback(null);

			_listEmpty(this.getAttributeSignatureList(lastKeyId, lastAttributeId, { issuer: lastKeyId, verified: true }), function(err, empty) {
				if(err)
					return callback(err);
				if(!empty) {
					lastAttributeId = null;
					return add(lastKeyImported.attributes, lastAttributeImported, callback);
				}

				this.removeAttribute(lastKeyId, lastAttributeId, function(err) {
					if(err)
						return callback(err);

					lastAttributeId = null;
					addError(lastAttributeImported, new Error("Attribute without self-signatures"), callback);
				});
			}.bind(this));
		}.bind(this);

		packets.splitPackets(formats.decodeKeyFormat(keyData)).forEachSeries(function(tag, header, body, next) {
			var cleanups = [ ];
			switch(tag) {
				case consts.PKT.PUBLIC_KEY:
					cleanups.push(cleanEmptyKey);
				case consts.PKT.PUBLIC_SUBKEY:
				case consts.PKT.USER_ID:
				case consts.PKT.ATTRIBUTE:
					cleanups.unshift(cleanEmptySubkey, cleanEmptyIdentity, cleanEmptyAttribute);
			}

			async.series(cleanups, function(err) {
				if(err)
					return callback(err);

				packetContent.getPacketInfo(tag, body, function(err, info) {
					if(err)
						return addError({ type: tag }, new Error("Errorneous packet."), next);

					switch(tag) {
						case consts.PKT.PUBLIC_KEY:
							lastKeyImported = { type: tag, id: info.id, signatures: [ ], subkeys: [ ], identities: [ ], attributes: [ ] };
							t.addKey(info, function(err) {
								if(err)
									addError(lastKeyImported, err, next);
								else {
									lastKeyId = info.id;
									next();
								}
							});
							break;
						case consts.PKT.PUBLIC_SUBKEY:
							lastSubkeyImported = { type: tag, id: info.id, signatures: [ ] };

							if(lastKeyId == null)
								addError(lastSubkeyImported, new Error("Subkey without key."), next);
							else
							{
								t.addSubkey(lastKeyId, info, function(err) {
									if(err)
										addError(lastSubkeyImported, err, next);
									else {
										lastSubkeyId = info.id;
										next();
									}
								});
							}

							break;
						case consts.PKT.USER_ID:
							lastIdentityImported = { type: tag, id: info.id, signatures: [ ] };

							if(lastKeyId == null)
								addError(lastIdentityImported, new Error("Identity without key."), next);
							else
							{
								t.addIdentity(lastKeyId, info, function(err) {
									if(err)
										addError(lastIdentityImported, err, next);
									else {
										lastIdentityId = info.id;
										next();
									}
								});
							}

							break;
						case consts.PKT.ATTRIBUTE:
							lastAttributeImported = { type: tag, id: info.id, signatures: [ ] };

							if(lastKeyId == null)
								addError(lastAttributeImported, new Error("Attribute without key."), next);
							else
							{
								t.addAttribute(lastKeyId, info, function(err) {
									if(err)
										addError(lastAttributeImported, err, next);
									else {
										lastAttributeId = info.id;
										next();
									}
								});
							}

							break;
						case consts.PKT.SIGNATURE:
							var lastSignatureImported = { type: tag, id: info.id, issuer: info.issuer, date: info.date, sigtype: info.sigtype };

							if(!acceptLocal && !info.exportable)
								addError(lastSignatureImported, new Error("Signature is not exportable."), next);
							else if(lastSubkeyId != null)
							{
								t.addSubkeySignature(lastKeyId, lastSubkeyId, info, function(err) {
									if(err)
										addError(lastSignatureImported, err, next);
									else
										add(lastSubkeyImported.signatures, lastSignatureImported, next);
								});
							}
							else if(lastIdentityId != null)
							{
								t.addIdentitySignature(lastKeyId, lastIdentityId, info, function(err) {
									if(err)
										addError(lastSignatureImported, err, next);
									else
										add(lastIdentityImported.signatures, lastSignatureImported, next);
								});
							}
							else if(lastAttributeId != null)
							{
								t.addAttributeSignature(lastKeyId, lastAttributeId, info, function(err) {
									if(err)
										addError(lastSignatureImported, err, next);
									else
										add(lastAttributeImported.signatures, lastSignatureImported, next);
								});
							}
							else if(lastKeyId != null)
							{
								t.addKeySignature(lastKeyId, info, function(err) {
									if(err)
										addError(lastSignatureImported, err, next);
									else
										add(lastKeyImported.signatures, lastSignatureImported, next);
								});
							}
							else
								addError(lastSignatureImported, new Error("Signature without object."), next);

							break;
						default:
							addError({ type: tag }, new Error("Unknown packet type."), next);
							break;
					}
				});
			}.bind(this));
		}, function(err) {
			if(err)
				callback(err);
			else
			{
				async.series([ cleanEmptySubkey, cleanEmptyIdentity, cleanEmptyAttribute, cleanEmptyKey ], function(err) {
					if(err)
						callback(err);
					else
						callback(null, imported);
				});
			}
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
	}
});

function _listEmpty(list, callback) {
	list.forEachSeries(function() {
		callback(null, false);
	}, function(err) {
		if(err)
			return callback(err);
		callback(null, true);
	});
}