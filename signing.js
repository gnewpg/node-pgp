var config = require("./config.json");
var child_process = require("child_process");
var packets = require("./packets")
var utils = require("./utils");
var fs = require("fs");
var consts = require("./consts");
var BufferedStream = require("./bufferedStream");
var async = require("async");

function verifySignature(keyring, callback) {
	utils.getTempFilename(function(err, fname) {
		if(err) { callback(err); return; }

		fs.open(fname, "w", 0600, function(err, fd) {
			if(err) { callback(err); return; }
			
			fs.write(fd, keyring, 0, keyring.length, null, function(err) {
				if(err) { callback(err); return; }
				
				fs.close(fd, function(err) {
					if(err) { callback(err); return; }

					var gpg = child_process.spawn(config.gpg, [ "--with-colons", "--no-default-keyring", "--keyring", fname, "--check-sigs" ]);
					new BufferedStream(gpg.stdout).readUntilEnd(function(err, stdout) {
						if(err) { callback(err); return; }
						
						stdout = stdout.toString("utf8");
						var success = !!(stdout.match(/^(sig|rev):!:/m) && !stdout.match(/^(sig|rev):[^!]/m));

						fs.unlink(fname, function(err) {
							if(err)
								console.log("Error removing temporary file "+fname+".", err);

							callback(null, success);
						});
					});
				});
			});
		});
	});
}

function verifyXYSignature(keyring, keyId, signatureInfo, callback, getSubObject, subObjectType)
{
	if(signatureInfo.issuer == null)
		return callback(null, false);

	var buffers = [ ];
	var issuerSecurity = null;

	async.series([
		function(next) {
			keyring.getKey(signatureInfo.issuer, function(err, issuerInfo) {
				if(err)
					next(err);
				else if(issuerInfo == null)
					callback(null, null);
				else
				{
					buffers.push(packets.generatePacket(consts.PKT.PUBLIC_KEY, issuerInfo.binary));
					issuerSecurity = issuerInfo.security;
					next();
				}
			});
		},
		function(next) {
			if(signatureInfo.issuer == keyId)
				return next();

			keyring.getKey(keyId, function(err, keyInfo) {
				if(err)
					return next(err);

				buffers.push(packets.generatePacket(consts.PKT.PUBLIC_KEY, keyInfo.binary));
				next();
			});
		},
		function(next) {
			if(getSubObject == null)
				return next();

			getSubObject(function(err, subInfo) {
				if(err)
					return next(err);

				buffers.push(packets.generatePacket(subObjectType, subInfo.binary));
				next();
			});
		}
	], function(err) {
		if(err)
			return callback(err);

		buffers.push(packets.generatePacket(consts.PKT.SIGNATURE, signatureInfo.binary));

		verifySignature(Buffer.concat(buffers), function(err, verified) {
			if(verified)
			{
				signatureInfo.verified = true;
				signatureInfo.security = Math.min(signatureInfo.security, issuerSecurity);
			}

			callback(err, verified);
		});
	});
}

function verifyKeySignature(keyring, keyId, signatureInfo, callback) {
	verifyXYSignature(keyring, keyId, signatureInfo, callback);
}

function verifySubkeySignature(keyring, keyId, subkeyId, signatureInfo, callback) {
	verifyXYSignature(keyring, keyId, signatureInfo, callback, async.apply(utils.proxy(keyring, keyring.getSubkey), keyId, subkeyId), consts.PKT.PUBLIC_SUBKEY);
}

function verifyIdentitySignature(keyring, keyId, identityId, signatureInfo, callback) {
	verifyXYSignature(keyring, keyId, signatureInfo, callback, async.apply(utils.proxy(keyring, keyring.getIdentity), keyId, identityId), consts.PKT.USER_ID);
}

function verifyAttributeSignature(keyring, keyId, attributeId, signatureInfo, callback) {
	verifyXYSignature(keyring, keyId, signatureInfo, callback, async.apply(utils.proxy(keyring, keyring.getAttribute), keyId, attributeId), consts.PKT.ATTRIBUTE);
}

function detachedSignText(text, privateKey, callback) {
	utils.getTempFilename(function(err, fname) {
		if(err) { callback(err); return; }
		
		fs.writeFile(fname, privateKey, function(err) {
			if(err)
				return unlink(err);
			
			var gpg = child_process.spawn(config.gpg, [ "--no-default-keyring", "--digest-algo", "SHA512", "--secret-keyring", fname, "--output", "-", "--detach-sign" ]);
			gpg.stdin.end(text, "utf8");
			var stderr = new BufferedStream(gpg.stderr);
			new BufferedStream(gpg.stdout).readUntilEnd(function(err, signature) {
				if(!err && signature.length == 0)
				{
					stderr.readUntilEnd(function(err, stderrData) {
						unlink(new Error("Signing failed" + (stderrData ? ": "+stderrData : "")));
					});
				}
				else
					unlink(err, signature);
			});
		});
		
		function unlink() {
			/*fs.unlink(fname, function(err) {
				if(err)
					console.log("Error removing temporary file "+fname+".", err);
			});*/
			console.log(fname);
			callback.apply(null, arguments);
		}
	});
}

exports.verifyKeySignature = verifyKeySignature;
exports.verifySubkeySignature = verifySubkeySignature;
exports.verifyIdentitySignature = verifyIdentitySignature;
exports.verifyAttributeSignature = verifyAttributeSignature;
exports.detachedSignText = detachedSignText;