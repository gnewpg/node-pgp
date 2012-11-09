var pgp = require("..");
var fs = require("fs");
var async = require("async");

var ID_CDAUTH = "299C33F4F76ADFE9";
var ID_TDAUTH = "B183D07CBD57A7B3";

exports.nonexistantKeyring = function(test) {
	test.expect(2);

	pgp.keyringFile.getFileKeyring("keyring2.tmp", function(err, keyring) {
		test.ok(err != null);
		test.ok(keyring == null);
		test.done();
	});
};

exports.cdauth = function(test) {
	test.expect(136);

	pgp.keyringFile.getFileKeyring("keyring.tmp", function(err, keyring) {
		test.ifError(err);

		async.series([
			function(next) { // Import key F76ADFE9 (Candid Dauth old)
				keyring.importKeys(fs.createReadStream("cdauth_old.pgp"), function(err, imported) {
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
						// 25 signatures

						test.ifError(err);
						test.ok(sigInfo.verified);

						next();
					});
				}, next);
			},
			function(next) { // Make sure that all attribute self-signatures have been verified
				keyring.getAttributeSignatureListByIssuer(ID_CDAUTH).forEachSeries(function(sig, next) {
					keyring.getAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, function(err, sigInfo) {
						// 2 signatures

						test.ifError(err);
						test.ok(sigInfo.verified);

						next();
					});
				}, next);
			},
			function(next) { // Make sure that all identity non-self-signatures have not been verified
				keyring.getIdentitySignatureListByIssuer(ID_TDAUTH).forEachSeries(function(sig, next) {
					if(sig.keyId != ID_CDAUTH)
						return next();

					keyring.getIdentitySignature(sig.keyId, sig.identityId, sig.signatureId, function(err, sigInfo) {
						// 18 signatures

						test.ifError(err);
						test.ok(!sigInfo.verified);

						next();
					});
				}, next);
			},
			function(next) { // Make sure that all attribute non-self-signatures have not been verified
				keyring.getAttributeSignatureListByIssuer(ID_TDAUTH).forEachSeries(function(sig, next) {
					if(sig.keyId != ID_CDAUTH)
						return next();

					keyring.getAttributeSignature(sig.keyId, sig.attributeId, sig.signatureId, function(err, sigInfo) {
						// 2 signatures

						test.ifError(err);
						test.ok(!sigInfo.verified);

						next();
					});
				}, next);
			},
			function(next) { // Import key tdauth_old
				keyring.importKeys(fs.createReadStream("tdauth_old.asc"), function(err, imported) {
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
						// 18 identities
						test.ifError(err);

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
						// 2 attributes
						test.ifError(err);

						no += signatures.length;
						next();
					});
				}, function(err) {
					test.ifError(err);
					test.equals(no, 4);
					next();
				});
			}
		], function(err) {
			test.ifError(err);
			//console.log(keyring);
			test.done();
		});
	}, true);
};

/*exports.v3key = function(test) {
	test.expect(1);
	pgp.keyringFile.getStreamKeyring(fs.createReadStream("v3key.pgp"), function(err, keyring) {
		test.ifError(err);

		console.log(keyring);
	});
};*/