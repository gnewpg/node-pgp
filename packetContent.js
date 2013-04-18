var basicTypes = require("./basicTypes");
var BufferedStream = require("./bufferedStream");
var consts = require("./consts");
var utils = require("./utils");

function getPacketInfo(tag, body, callback) {
	switch(tag)
	{
		case consts.PKT.PUBLIC_KEY:
			getPublicKeyPacketInfo(body, callback);
			break;
		case consts.PKT.PUBLIC_SUBKEY:
			getPublicSubkeyPacketInfo(body, callback);
			break;
		case consts.PKT.USER_ID:
			getIdentityPacketInfo(body, callback);
			break;
		case consts.PKT.ATTRIBUTE:
			getAttributePacketInfo(body, callback);
			break;
		case consts.PKT.SIGNATURE:
			getSignaturePacketInfo(body, callback);
			break;
		default:
			callback(null, { pkt: tag });
	}
}

function getPublicKeyPacketInfo(body, callback)
{
	var ret = {
		pkt: consts.PKT.PUBLIC_KEY,
		id: null,
		binary : body,
		version : body.readUInt8(0),
		versionSecurity : null,
		expires : null,
		date : null,
		pkalgo : null,
		keyParts : null,
		fingerprint : null,
		size : null,
		sizeSecurity : null,
		security : null
	};
	
	if(ret.version == 3 || ret.version == 2)
	{
		ret.versionSecurity = consts.SECURITY.BAD;
		ret.date = new Date(body.readUInt32BE(1)*1000);
		
		var expires = body.readUInt16BE(5);
		if(expires)
			ret.expires = new Date(ret.date.getTime() + expires*86400000);
		
		ret.pkalgo = body.readUInt8(7);
		if(ret.pkalgo != consts.PKALGO.RSA_ES && ret.pkalgo == consts.PKALGO.RSA_E && ret.pkalgo != consts.PKALGO.RSA_S)
			return callback(new Error("Unknown public key algorithm "+ret.pkalgo));
		
		var keyParts = basicTypes.splitMPIs(body.slice(8), 2);
		ret.keyParts = { n : keyParts[0], e : keyParts[1] };
		ret.size = ret.keyParts.n.length;

		ret.key = body.slice(8, 8+keyParts.bytes);

		ret.id = ret.keyParts.n.buffer.toString("hex", ret.keyParts.n.buffer.length-8).toUpperCase();
		ret.fingerprint = utils.hash(Buffer.concat([ ret.keyParts.n.buffer, ret.keyParts.e.buffer ]), "md5", "hex").toUpperCase();
	}
	else if(ret.version == 4)
	{
		ret.versionSecurity = consts.SECURITY.GOOD;
		ret.date = new Date(body.readUInt32BE(1)*1000);
		ret.pkalgo = body.readUInt8(5);

		var keyParts = null;
		if(ret.pkalgo == consts.PKALGO.RSA_ES || ret.pkalgo == consts.PKALGO.RSA_E || ret.pkalgo == consts.PKALGO.RSA_S)
		{
			keyParts = basicTypes.splitMPIs(body.slice(6), 2);
			ret.keyParts = { n : keyParts[0], e : keyParts[1] };
			ret.size = ret.keyParts.n.length;
		}
		else if(ret.pkalgo == consts.PKALGO.ELGAMAL_E)
		{
			keyParts = basicTypes.splitMPIs(body.slice(6), 3);
			ret.keyParts = { p : keyParts[0], g : keyParts[1], y : keyParts[2] };
			ret.size = ret.keyParts.p.length;
		}
		else if(ret.pkalgo == consts.PKALGO.DSA)
		{
			keyParts = basicTypes.splitMPIs(body.slice(6), 4);
			ret.keyParts = { p : keyParts[0], q : keyParts[1], g : keyParts[2], y : keyParts[3] };
			ret.size = ret.keyParts.p.length;
		}
		else
			return callback(new Error("Unknown public key algorithm "+ret.pkalgo));

		ret.key = body.slice(6, 6+keyParts.bytes);
		
		var fingerprintData = new Buffer(body.length + 3);
		fingerprintData.writeUInt8(0x99, 0);
		fingerprintData.writeUInt16BE(body.length, 1);
		body.copy(fingerprintData, 3);
		ret.fingerprint = utils.hash(fingerprintData, "sha1", "hex").toUpperCase();
		ret.id = ret.fingerprint.substring(ret.fingerprint.length-16);
	}
	else
	{
		callback(new Error("Unknown key version "+ret.version+"."));
		return;
	}
	
	if(ret.size < 1024)
		ret.sizeSecurity = consts.SECURITY.BAD;
	else if(ret.size < 2048)
		ret.sizeSecurity = consts.SECURITY.MEDIUM;
	else
		ret.sizeSecurity = consts.SECURITY.GOOD;
	ret.security = Math.min(ret.sizeSecurity, ret.versionSecurity);
	
	callback(null, ret);
}

function getPublicSubkeyPacketInfo(body, callback)
{
	getPublicKeyPacketInfo(body, function(err, info) {
		if(err) { callback(err); return; }
		
		info.pkt = consts.PKT.PUBLIC_SUBKEY;
		callback(null, info);
	});
}

function getIdentityPacketInfo(body, callback)
{
	var content = body.toString("utf8")
	var name = content;
	var email = null;
	var comment = null;
	var m = name.match(/^(.*) <(.*)>$/);
	if(m)
	{
		name = m[1];
		email = m[2];
	}
	m = name.match(/^(.*) \((.*)\)$/);
	if(m)
	{
		name = m[1];
		comment = m[2];
	}

	callback(null, {
		pkt: consts.PKT.USER_ID,
		name : name,
		email : email,
		comment : comment,
		binary : body,
		id : content,
		nameTrust : 0,
		emailTrust : 0
	});
}

function getAttributePacketInfo(body, callback)
{
	var ret = {
		pkt : consts.PKT.ATTRIBUTE,
		id : utils.hash(body, "sha1", "base64").substring(0, 27),
		subPackets : [ ],
		binary : body,
		trust : 0
	};

	var stream = new BufferedStream(body);
	
	var readon = function() {
		basicTypes.read125OctetNumber(stream, function(err, subPacketLength) {
			if(err)
			{
				if(err.NOFIRSTBYTE)
					callback(null, ret);
				else
					callback(err);
				return;
			}
			
			stream.read(subPacketLength, function(err, subPacket) {
				if(err) { callback(err); return; }
				
				ret.subPackets.push(getAttributeSubPacketInfo(subPacket.readUInt8(0), subPacket.slice(1)));
				readon();
			});
		});
	};
	readon();
}

function getAttributeSubPacketInfo(type, body) {
	var ret = { binary: body, type: type };
	if(type == consts.ATTRSUBPKT.IMAGE)
	{
		var headerLength = body.readUInt16LE(0); // This has to be Little Endian!
		var header = body.slice(2, 2+headerLength);
		ret.image = body.slice(headerLength);

		var headerVersion = header.readUInt8(0);
		if(headerVersion == 1)
			ret.imageType = header.readUInt8(1);
	}
	return ret;
}

function getSignaturePacketInfo(body, callback)
{
	var ret = {
		pkt : consts.PKT.SIGNATURE,
		id : utils.hash(body, "sha1", "base64").substring(0, 27),
		sigtype : null,
		date : null,
		issuer : null,
		pkalgo : null,
		hashalgo : null,
		version : null,
		binary : body,
		hashedSubPackets : { },
		unhashedSubPackets : { },
		exportable : true,
		expires : null,
		hashedPart : null, // The part of the signature that is concatenated to the data that is to be signed when creating the hash
		first2HashBytes : null, // The first two bytes of the hash as 16-bit unsigned integer
		signature : null, // The signature as buffer object
		hashalgoSecurity : null,
		security : null,
		verified : false,
		trustSignature : false
	};

	var byte1 = body.readUInt8(0);
	if(byte1 == 3)
	{ // Version 3 signature
		var hashedLength = body.readUInt8(1); // Must be 5 according to spec
		ret.hashedPart = body.slice(2, 2+hashedLength);

		ret.sigtype = ret.hashedPart.readUInt8(0);
		ret.date = new Date(ret.hashedPart.readUInt32BE(1)*1000);
		
		var rest = body.slice(2+hashedLength);

		ret.issuer = rest.toString("hex", 0, 8).toUpperCase();
		ret.pkalgo = rest.readUInt8(8);
		ret.hashalgo = rest.readUInt8(9);
		ret.version = 3;

		ret.first2HashBytes = rest.readUInt16BE(10);
		ret.signature = rest.slice(12);

		callback(null, ret);
	}
	else if(byte1 == 4)
	{ // Version 4 signature
		ret.sigtype = body.readUInt8(1);
		ret.pkalgo = body.readUInt8(2);
		ret.hashalgo = body.readUInt8(3);
		ret.version = 4;
		
		var hashedSubPacketsLength = body.readUInt16BE(4);
		var hashedSubPackets = body.slice(6, 6+hashedSubPacketsLength);
		var unhashedSubPacketsLength = body.readUInt16BE(6+hashedSubPacketsLength);
		var unhashedSubPackets = body.slice(8+hashedSubPacketsLength, 8+hashedSubPacketsLength+unhashedSubPacketsLength);
		
		ret.hashedPart = body.slice(0, 6+hashedSubPacketsLength);
		ret.first2HashBytes = body.readUInt16BE(8+hashedSubPacketsLength+unhashedSubPacketsLength);
		ret.signature = body.slice(10+hashedSubPacketsLength+unhashedSubPacketsLength);
		
		extractSignatureSubPackets(hashedSubPackets, function(err, info1) {
			if(err) { callback(err); return; }
			
			ret.hashedSubPackets = info1;

			extractSignatureSubPackets(unhashedSubPackets, function(err, info2) {
				if(err) { callback(err); return; }
				
				ret.unhashedSubPackets = info2;
				
				if(ret.hashedSubPackets[consts.SIGSUBPKT.SIG_CREATED])
					ret.date = ret.hashedSubPackets[consts.SIGSUBPKT.SIG_CREATED][0].value;
				if(ret.hashedSubPackets[consts.SIGSUBPKT.ISSUER])
					ret.issuer = ret.hashedSubPackets[consts.SIGSUBPKT.ISSUER][0].value;
				else if(ret.unhashedSubPackets[consts.SIGSUBPKT.ISSUER])
					ret.issuer = ret.unhashedSubPackets[consts.SIGSUBPKT.ISSUER][0].value;
				if(ret.hashedSubPackets[consts.SIGSUBPKT.EXPORTABLE] && !ret.hashedSubPackets[consts.SIGSUBPKT.EXPORTABLE][0].value)
					ret.exportable = false;
				if(ret.hashedSubPackets[consts.SIGSUBPKT.SIG_EXPIRE] && ret.date)
					ret.expires = new Date(ret.date.getTime() + (ret.hashedSubPackets[consts.SIGSUBPKT.SIG_EXPIRE][0].value*1000));
				if(ret.hashedSubPackets[consts.SIGSUBPKT.TRUST] && ret.hashedSubPackets[consts.SIGSUBPKT.TRUST][0].value.level > 0 && ret.hashedSubPackets[consts.SIGSUBPKT.TRUST][0].value.amount > 0)
					ret.trustSignature = true;

				callback(null, ret);
			});
		});
	}
	else
		callback(new Error("Unknown signature version "+byte1+"."));
	
	if([ consts.HASHALGO.RIPEMD160, consts.HASHALGO.SHA256, consts.HASHALGO.SHA384, consts.HASHALGO.SHA512, consts.HASHALGO.SHA224 ].indexOf(ret.hashalgo) != -1)
		ret.hashalgoSecurity = consts.SECURITY.GOOD;
	else if(ret.hashalgo == consts.HASHALGO.SHA1)
		ret.hashalgoSecurity = consts.SECURITY.MEDIUM;
	else if(ret.hashalgo == consts.HASHALGO.MD5)
		ret.hashalgoSecurity = consts.SECURITY.BAD;
	else
		ret.hashalgoSecurity = consts.SECURITY.UNKOWN;
	ret.security = ret.hashalgoSecurity;
}

function extractSignatureSubPackets(body, callback)
{
	var stream = new BufferedStream(body);
	
	var subPackets = { };
	
	var readon = function() {
		basicTypes.read125OctetNumber(stream, function(err, number) {
			if(err)
			{
				if(err.NOFIRSTBYTE)
					callback(null, subPackets);
				else
					callback(err);
				return;
			}
			
			if(number == 0)
			{
				readon();
				return;
			}
			
			stream.read(number, function(err, data2) {
				if(err) { callback(err); return; }

				var type = data2.readUInt8(0);
				var p = { critical : !!(type & consts.SIGSUBPKT.FLAG_CRITICAL), value: null, rawValue: data2.slice(1) };
				if(p.critical)
					type = type^consts.SIGSUBPKT.FLAG_CRITICAL;

				p.value = getValueForSignatureSubPacket(type, p.rawValue);

				if(!subPackets[type])
					subPackets[type] = [ ];
				subPackets[type].unshift(p);
				
				readon();
			});
		})
	};
	readon();
}

function getValueForSignatureSubPacket(type, binary) {
	switch(type)
	{
		case consts.SIGSUBPKT.SIG_CREATED:
			return new Date(binary.readUInt32BE(0)*1000);
		case consts.SIGSUBPKT.SIG_EXPIRE:
			return binary.readUInt32BE(0);
		case consts.SIGSUBPKT.EXPORTABLE:
		case consts.SIGSUBPKT.PRIMARY_UID:
		case consts.SIGSUBPKT.REVOCABLE:
			return !!binary.readUInt8(0);
		case consts.SIGSUBPKT.TRUST:
			return { level: binary.readUInt8(0), amount: binary.readUInt8(1) };
		case consts.SIGSUBPKT.REGEXP:
			var regexp = binary.toString("utf8", 0, binary.length);
			var idx = regexp.indexOf("\0");
			return (idx == -1 ? regexp : regexp.substr(0, idx));
		case consts.SIGSUBPKT.KEY_EXPIRE:
			return binary.readUInt32BE(0);
		case consts.SIGSUBPKT.PREF_SYM:
		case consts.SIGSUBPKT.PREF_HASH:
		case consts.SIGSUBPKT.PREF_COMPR:
			var prefs = [ ];
			for(var i=0; i<binary.length; i++)
				prefs.push(binary.readUInt8(i));
			return prefs;
		case consts.SIGSUBPKT.REV_KEY:
			var flags = binary.readUInt8(0);
			if(!(flags & 0x80))
				return null;
			return {
				sensitive : !!(flags & 0x40),
				pubkeyAlgo : binary.readUInt8(1),
				fingerprint : binary.toString("hex", 2, 22).toUpperCase()
			};
		case consts.SIGSUBPKT.ISSUER:
			return binary.toString("hex", 0, 8).toUpperCase();
		case consts.SIGSUBPKT.NOTATION:
			var flags = binary.readUInt32BE(0);
			var readable = !!(flags & 0x80000000);
			var nameLength = binary.readUInt16BE(1);
			var valueLength = binary.readUInt16BE(3);
			return {
				name: binary.toString("utf8", 5, 5+nameLength),
				value : readable ? binary.toString("utf8", 5+nameLength, 5+nameLength+valueLength) : binary.slice(5+nameLength, 5+nameLength+valueLength),
				flags : flags
			};
		case consts.SIGSUBPKT.KS_FLAGS:
			return { noModify : !!(binary.readUInt8(0) & 0x80) };
		case consts.SIGSUBPKT.PREF_KS:
		case consts.SIGSUBPKT.POLICY:
		case consts.SIGSUBPKT.SIGNERS_UID:
			return binary.toString("utf8", 0);
		case consts.SIGSUBPKT.KEY_FLAGS:
			var byte1 = binary.readUInt8(0);
			var ret = { };
			for(var i in consts.KEYFLAG)
				ret[consts.KEYFLAG[i]] = !!(byte1 & consts.KEYFLAG[i]);
			return ret;
		case consts.SIGSUBPKT.REVOC_REASON:
			return { code: binary.readUInt8(0), explanation: binary.toString("utf8", 1) };
		case consts.SIGSUBPKT.FEATURES:
			var byte1 = binary.readUInt8(0);
			var ret = { };
			for(var i in consts.FORMATS)
				ret[consts.FORMATS[i]] = !!(byte1 & consts.FORMATS[i]);
			return ret;
		//case consts.SIGSUBPKT.SIGNATURE:
	}
}

exports.getPacketInfo = getPacketInfo;
exports.getPublicKeyPacketInfo = getPublicKeyPacketInfo;
exports.getPublicSubkeyPacketInfo = getPublicSubkeyPacketInfo;
exports.getAttributePacketInfo = getAttributePacketInfo;
exports.getIdentityPacketInfo = getIdentityPacketInfo;
exports.getSignaturePacketInfo = getSignaturePacketInfo;