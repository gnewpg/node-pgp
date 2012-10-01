var crypto = require("crypto");
var fs = require("fs");
var packetContent = require("./packetContent");
var packets = require("./packets");
var utils = require("./utils");

function _encodeMPIAsDER(mpi) { // See http://luca.ntop.org/Teaching/Appunti/asn1.html
	var length = mpi.buffer.length;
	var lengthBytes;
	if(length < 128)
		lengthBytes = 1;
	else if(length < 256)
		lengthBytes = 2;
	else
		lengthBytes = 3; // Maximum length 65535 bytes, that is by far enough for our purposes

	var ret = new Buffer(mpi.buffer.length+lengthBytes+1);
	ret.writeUInt8(2, 0);
	if(length < 127)
		ret.writeUInt8(length, 1);
	else if(length < 256)
	{
		ret.writeUInt8(0x81, 1);
		ret.writeUInt8(length, 2);
	}
	else
	{
		ret.writeUInt8(0x82, 1);
		ret.writeUInt16BE(length, 2);
	}
	
	mpi.buffer.copy(ret, lengthBytes+1);
	
	return ret;
}

function _encodeRSAKey(n, e) { // See ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
	var ret = "-----BEGIN RSA PUBLIC KEY-----\r\n";
	
	var buffer = Buffer.concat([ _encodeMPIAsDER(n), _encodeMPIAsDER(e) ]);
	for(var i=0; i<buffer.length; i+=48)
		ret += buffer.slice(i, Math.min(i+48, buffer.length)).toString("base64")+"\r\n";
	
	ret += "-----END RSA PUBLIC KEY-----\r\n";
	
	return ret;
}

function _verifyRSASignature(n, e, data, signature) {
	var verifier = crypto.createVerify("RSA-SHA1");
	verifier.update(data);
	
	return verifier.verify(_encodeRSAKey(n, e), signature);
}

var key = fs.readFileSync('/home/cdauth/gpg11/test');
var keyInfo = null;
var idInfo = null;
var sigInfo = null;

packets.splitPackets(key).forEachSeries(function(type, header, body, cb) {
	if(keyInfo == null)
	{
		packetContent.getPublicKeyPacketInfo(body, function(err, info) {
			keyInfo = info;
			cb();
		});
	}
	else if(idInfo == null)
	{
		packetContent.getIdentityPacketInfo(body, function(err, info) {
			idInfo = info;
			cb();
		});
	}
	else
	{
		packetContent.getSignaturePacketInfo(body, function(err, info) {
			sigInfo = info;
			cb();
		});
	}
}, function(err) {
	var keyData = new Buffer(keyInfo.binary.length+3);
	keyData.writeUInt8(0x99, 0);
	keyData.writeUInt16BE(keyInfo.binary.length, 1);
	keyInfo.binary.copy(keyData, 3);
	
	var certData = new Buffer(idInfo.binary.length+5);
	certData.writeUInt8(0xB4, 0);
	certData.writeUInt32BE(idInfo.binary.length, 1);
	idInfo.binary.copy(certData, 5);
	
	var trailer = new Buffer(6);
	trailer.writeUInt8(0x04, 0);
	trailer.writeUInt8(0xff, 1);
	trailer.writeUInt32BE(sigInfo.hashedPart.length, 2);
	
	var data = Buffer.concat([ keyData, certData, sigInfo.hashedPart, trailer ]);
	fs.writeFileSync("/home/cdauth/gpg11/signedData", data, "binary");
	fs.writeFileSync("/home/cdauth/gpg11/rsaKey", _encodeRSAKey(keyInfo.keyParts.n, keyInfo.keyParts.e));
	console.log(utils.hash(data, "sha1", "hex"));
	
	console.log(_verifyRSASignature(keyInfo.keyParts.n, keyInfo.keyParts.e, data, sigInfo.signature));
});