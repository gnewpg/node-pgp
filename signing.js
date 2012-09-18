var config = require("./config");
var child_process = require("child_process");
var packets = require("./packets")
var utils = require("./utils");
var fs = require("fs");
var consts = require("./consts");
var BufferedStream = require("./bufferedStream");

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
					new BufferedStream(gpg.stdout).read(-1, function(err, stdout) {
						if(err) { callback(err); return; }
						
						stdout = stdout.toString("utf8");
						var success = !!(stdout.match(/^sig:!:/m) && !stdout.match(/^sig:[^!]/m));
						
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

function verifyXYSignature(callback, keyBody, signatureBody, issuerKeyBody, subObjectBody, subObjectType)
{
	var buffers = [ ];
	buffers.push(packets.generatePacket(consts.PKT.PUBLIC_KEY, keyBody));
	if(subObjectBody)
		buffers.push(packets.generatePacket(subObjectType, keyBody));
	buffers.push(packets.generatePacket(consts.PKT.SIGNATURE, keyBody));
	if(issuerKeyBody)
		buffers.push(packets.generatePacket(consts.PKT.PUBLIC_KEY, keyBody));
	
	verifySignature(Buffer.concat(buffers), callback);
}


function verifyKeySignature(keyBody, signature, issuerKeyBody, callback) {
	verifyXYSignature(callback, keyBody, signature, issuerKeyBody);
}

function verifySubkeySignature(keyBody, subkeyBody, signature, issuerKeyBody, callback) {
	verifyXYSignature(callback, keyBody, signature, issuerKeyBody, subkeyBody, consts.PKT.PUBLIC_SUBKEY);
	
}

function verifyIdentitySignature(keyBody, idBody, signature, issuerKeyBody, callback) {
	verifyXYSignature(callback, keyBody, signature, issuerKeyBody, idBody, consts.PKT.USER_ID);
}

function verifyAttributeSignature(keyBody, attributeBody, signature, issuerKeyBody, callback) {
	verifyXYSignature(callback, keyBody, signature, issuerKeyBody, attributeBody, consts.PKT.ATTRIBUTE);
}

exports.verifyKeySignature = verifyKeySignature;
exports.verifySubkeySignature = verifySubkeySignature;
exports.verifyIdentitySignature = verifyIdentitySignature;
exports.verifyAttributeSignature = verifyAttributeSignature;