var pgp = require("..");
var fs = require("fs");
var async = require("async");

var ID_CDAUTH = "299C33F4F76ADFE9";
var ID_TDAUTH = "B183D07CBD57A7B3";
var ID_V3 = "FFD1B4AC7C19FD19";

exports.nonexistantKeyring = function(test) {
	test.expect(2);

	pgp.keyringFile.getFileKeyring("keyring2.tmp", function(err, keyring) {
		test.ok(err != null);
		test.ok(keyring == null);
		test.done();
	});
};

exports.cdauth = function(test) {
	var expect = 2;

	pgp.keyringFile.getFileKeyring("keyring.tmp", function(err, keyring) {
		test.ifError(err);

		expect += exports.cdauth.testKeyring(test, keyring, function(err) {
			test.ifError(err);
			//console.log(keyring);

			test.expect(expect);
			test.done();

			fs.unlinkSync("keyring.tmp");
		});
	}, true);
};

exports.cdauth.testKeyring = function(test, keyring, callback) {
	async.series([
		function(next) { // Import key F76ADFE9 (Candid Dauth old)
			keyring.importKeys(fs.createReadStream(__dirname+"/cdauth_old.pgp"), function(err, imported) {
				test.ifError(err);
				test.equals(imported.failed.length, 0);
				next();
			});
		},
		function(next) { // Check if key is there and revoked
			keyring.getKey(ID_CDAUTH, function(err, keyInfo) {
				test.ifError(err);
				test.ok(keyInfo != null);

				test.ok(keyInfo.revoked != null);

				next();
			});
		},
		function(next) { // Verify the number of identities and the number of revoked identities
			keyring.getIdentityList(ID_CDAUTH).toArraySingle(function(err, identities) {
				test.ifError(err);
				test.equals(identities.length, 18);

				var revoked = 0;
				async.forEachSeries(identities, function(identityId, next) {
					keyring.getIdentitySignatures(ID_CDAUTH, identityId, { sigtype: [ pgp.consts.SIG.CERT_0, pgp.consts.SIG.CERT_1, pgp.consts.SIG.CERT_2, pgp.consts.SIG.CERT_3 ] }, [ "revoked" ]).forEachSeries(function(signatureInfo, next) {
						if(signatureInfo.revoked)
							revoked++;
						next();
					}, next);
				}, function(err) {
					test.ifError(err);
					test.equals(revoked, 6);
					next();
				});
			});
		},
		function(next) { // Verify the number of attributes
			keyring.getAttributeList(ID_CDAUTH).toArraySingle(function(err, attributes) {
				test.ifError(err);
				test.equals(attributes.length, 2);

				next();
			});
		},
		function(next) { // Make sure that all identity self-signatures have been verified
			keyring.getIdentitySignatureListByIssuer(ID_CDAUTH).forEachSeries(function(sig, next) {
				keyring.getIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, function(err, sigInfo) {
					test.ifError(err); // 25 times
					test.ok(sigInfo.verified); // 25 times

					next();
				});
			}, next);
		},
		function(next) { // Make sure that all attribute self-signatures have been verified
			keyring.getAttributeSignatureListByIssuer(ID_CDAUTH).forEachSeries(function(sig, next) {
				keyring.getAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, function(err, sigInfo) {
					test.ifError(err); // 2 times
					test.ok(sigInfo.verified); // 2 times

					next();
				});
			}, next);
		},
		function(next) { // Make sure that all identity non-self-signatures have not been verified
			keyring.getIdentitySignatureListByIssuer(ID_TDAUTH).forEachSeries(function(sig, next) {
				if(sig.keyId != ID_CDAUTH)
					return next();

				keyring.getIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, function(err, sigInfo) {
					test.ifError(err); // 18 times
					test.ok(!sigInfo.verified); // 18 times

					next();
				});
			}, next);
		},
		function(next) { // Make sure that all attribute non-self-signatures have not been verified
			keyring.getAttributeSignatureListByIssuer(ID_TDAUTH).forEachSeries(function(sig, next) {
				if(sig.keyId != ID_CDAUTH)
					return next();

				keyring.getAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, function(err, sigInfo) {
					test.ifError(err); // 2 times
					test.ok(!sigInfo.verified); // 2 times

					next();
				});
			}, next);
		},
		function(next) { // Import key tdauth_old
			keyring.importKeys(fs.createReadStream(__dirname+"/tdauth_old.asc"), function(err, imported) {
				test.ifError(err);
				//console.log(imported.failed);
				test.equals(imported.failed.length, 0);
				next();
			});
		},
		function(next) { // Check that tdauth key was imported
			keyring.getKey(ID_TDAUTH, function(err, key) {
				test.ifError(err);
				test.ok(key != null);
				test.equals(key.fingerprint, "49C3BF3B50447C4DB6137369B183D07CBD57A7B3");
				next();
			});
		},
		function(next) { // Check that all identity signatures on cdauth_old have been verified
			var no = 0;
			keyring.getIdentityList(ID_CDAUTH, null, [ "id" ]).forEachSeries(function(identityId, next) {
				keyring.getIdentitySignatureList(ID_CDAUTH, identityId, { verified: true }).toArraySingle(function(err, signatures) {
					test.ifError(err); // 18 times

					no += signatures.length;
					next();
				});
			}, function(err) {
				test.ifError(err);
				test.equals(no, 43);
				next();
			});
		},
		function(next) { // Check that all attribute signatures on cdauth_old have been verified
			var no = 0;
			keyring.getAttributeList(ID_CDAUTH, null, [ "id" ]).forEachSeries(function(attributeId, next) {
				keyring.getAttributeSignatureList(ID_CDAUTH, attributeId, { verified: true }).toArraySingle(function(err, signatures) {
					test.ifError(err); // 2 times

					no += signatures.length;
					next();
				});
			}, function(err) {
				test.ifError(err);
				test.equals(no, 4);
				next();
			});
		},
		function(next) { // Commit changes
			keyring.saveChanges(next);
		},
		function(next) { // Import v3 key
			keyring.importKeys(fs.createReadStream(__dirname+"/v3key.pgp"), function(err, imported) {
				test.ifError(err);

				var expectedImport = [
					{ type: pgp.consts.PKT.PUBLIC_KEY, id: ID_V3, signatures: [ ], subkeys: [ ], identities: [
						{ type: pgp.consts.PKT.USER_ID, id: "David Engel <david@sw.ods.com>", signatures: [
							{ type: pgp.consts.PKT.SIGNATURE, id: "A8H5G+11VKIEJ8mZPu5gwfdQOEM", issuer: ID_V3, date: new Date(856682460000), sigtype: 0x10 }
						] },
						{ type: pgp.consts.PKT.USER_ID, id: "David Engel <david@debian.org>", signatures: [
							{ type: pgp.consts.PKT.SIGNATURE, id: "5zVQJ0tuHFELd6+aBVcu5LDjScA", issuer: ID_V3, date: new Date(856682530000), sigtype: 0x10 }
						] },
						{ type: pgp.consts.PKT.USER_ID, id: "David Engel <dlengel@home.com>", signatures: [
							{ type: pgp.consts.PKT.SIGNATURE, id: "Xf20+l7zUNMeoAm+jhe7adGO8F4", issuer: ID_V3, date: new Date(951772637000), sigtype: 0x10 }
						] },
						{ type: pgp.consts.PKT.USER_ID, id: "David Engel <david@ods.com>", signatures: [
							{ type: pgp.consts.PKT.SIGNATURE, id: "KScaCchkXZkQ7uzMH0uYZI+NI5I", issuer: ID_V3, date: new Date(896193073000), sigtype: 0x10 }
						] },
						{ type: pgp.consts.PKT.USER_ID, id: "David Engel <david@intrusion.com>", signatures: [
							{ type: pgp.consts.PKT.SIGNATURE, id: "XrJrGDVU4ZHOHAZMtp17ZGBDjTo", issuer: ID_V3, date: new Date(957538728000), sigtype: 0x10 }
						] }
					], attributes: [ ] }
				];

				test.equals(imported.failed.length, 0);
				test.same(imported.keys, expectedImport);

				next();
			});
		},
		function(next) { // Check v3 key fingerprint
			keyring.getKey(ID_V3, function(err, key) {
				test.ifError(err);
				test.ok(key != null);
				test.equals(key.fingerprint, "910B9712D9DFC8F5F9FE152D73686F78");
				test.equals(key.date.getTime(), 856682460000);
				test.equals(key.size, 1024);

				next();
			});
		},
		function(next) { // Revert adding of v3 key
			keyring.revertChanges(next);
		},
		function(next) { // Check that cdauth-old and tdauth-old are still there and that the v3 key is gone
			keyring.keyExists(ID_CDAUTH, function(err, exists) {
				test.ifError(err);
				test.ok(exists);

				keyring.keyExists(ID_TDAUTH, function(err, exists) {
					test.ifError(err);
					test.ok(exists);

					keyring.keyExists(ID_V3, function(err, exists) {
						test.ifError(err);
						test.ok(!exists);

						next();
					});
				});
			});
		},
		function(next) { // Search for key by short id
			keyring.search("0xF76ADFE9").toArraySingle(function(err, items) {
				test.ifError(err);

				test.equals(items.length, 1);
				test.equals(items[0].id, ID_CDAUTH);
				test.ok(items[0].revoked != null);

				next();
			});
		},
		function(next) { // Search for key by id
			keyring.search("Candid Dauth").toArraySingle(function(err, items) {
				test.ifError(err);

				test.equals(items.length, 18);

				next();
			});
		},
		function(next) { // Search for key by email
			keyring.search("games@cdauth.de").toArraySingle(function(err, items) {
				test.ifError(err);
				test.equals(items.length, 1);
				test.ok(items[0].identity.revoked != null);

				// Test getSignatureById
				keyring.getSignatureById(items[0].identity.revoked, function(err, signatureInfo) {
					test.ifError(err);

					test.equals(signatureInfo.key, ID_CDAUTH);
					test.equals(signatureInfo.identity, "Candid Dauth <games@cdauth.de>");
					test.equals(Object.keys(signatureInfo).length, 2);

					next();
				}, [ ]);
			})
		}
	], callback);

	return 161;
};