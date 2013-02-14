var pgp = require("..");
var async = require("async");

var TESTKEY1 = "\x99\x01\xa2\x04PW7\x9c\x11\x04\x00\x93\\:\xb9\xdf\x110A\xc9\x89\xcc\x88\x84_\xd0\
\xd3\x14\xec9\xa7\xaf  ;6\xbd[J\x9c\xeb{\x80\xf9qy\xd4\x8f\xc6\x06\xa8\xfe\x10\x97g\"\x11J\xbd\xb9\
&r\x0b\xdc\x7f4\x98\x85\xff\x8e\x86N\xf9\xc0F\xb0\xb0\xb9]BR\x9c\xb4\xd4\x10\x18'(\xa1Q\x0a\xa1\xc2\
fM=\xc7ds\xd4R\xf2\xcft\xf1\xbdt\xc6s\xd4\xb5.p2\xaej6!I\x14\xcf\xcc\xa4m?\x9eaO\xc1N\x91\xfb\x1d\
\xca\xcf\xd2c|\x1f\x00\xa0\xcf\x19\xab\x82\x0ar\x85\xa91\x0cq\xdb|\xb8\x0c\x00\xd64\xa9\x97\x04\x00\
\x84M&9\xf8\xa4\x008\"d\xf3<x-\xeb\xbd\x89\x12_\xd1\xfb\x1a,..\x0a\xe4\x1e\xf0a\xbeM9\x19+{\x92\xbf\
\xb6*;\xc8\x82M\x19\xaf\x96\xcaCf\xcf\xb1\x84\x0c\xa2\xfd\xa3\xd4\x9f\x89~\xb8\xad\xeb9\xf7\xbe\x0c\
\xf70\xd4\xfe\xe0\x19\x01^q\x92\xb2\xbb\xaa_\xc1[\x17\xd1\xfe\xdc&\x97C\xa8\xee\xcb\x97\x88>M/\xd71\
\xe0~\xb6\xc6i\x0a\x03\x89\x14vLE\x14\x14\xb0\xfd\xaa\xba\x0ev\xcd\xffh\xd6\xad\xac\x00\x03\xfd\x12\
\x0c\xb4\xb0\xb8\xf3\xc2\xf2M\xef\xedQ(\xf3\xf2C\xac\x07\xcb\x83\x0eK\xd3\x9ax\xbb\xe3H\x041,Mq\xe6\
\x1aL|\xe3\xe0n>\x83\xd6i\x0c=\x9b\xeba,\xa1\xc9J\xdelF\xb9VI\xdfxfr;\xd9E\xa4\xad{Q\xc9gS)02\xbc\x82\
\x82\xfe\x1a\x1c\xeb\xdcB{\x1dk\xd3[#\xb1\xb8s\x90,\xe1\xe6\x9d\xcb\x91\xbc\x91\x17\xfc\x07\xb1^\x11v\
\xf8\xd4\x07@\x8a\x97;\x82'\xe0|\x02\xc6\x15\xc1\x0fp,\xb4\x1bblablabla <bla@example.com>\x88h\x04\x13\
\x11\x02\x00(\x02\x1b\x03\x06\x0b\x09\x08\x07\x03\x02\x06\x15\x08\x02\x09\x0a\x0b\x04\x16\x02\x03\x01\
\x02\x1e\x01\x02\x17\x80\x05\x02PW\x9f$\x05\x09\x00\x0a\xf3\x88\x00\x0a\x09\x10;C\x85\xadw\x12FA\x08\
\xdc\x00\xa0\x9786!r\x08\xc2^R\x904\x90Q\x9a C\xf96pc\x00\x9c\x0a+_{{h\x82\xd6\xc0\x0e\x06I\xfd U\xa0\
B\x0a\xd2m";

var TESTKEY2 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
Version: GnuPG v2.0.19 (GNU/Linux)\n\
\n\
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\n\
SAAAAAEAAABIAAAAAQAAAFZlci4xLjAuMDAwADIwMTE6MDY6MjYgMTI6NTI6NTkA\n\
JwCaggUAAQAAAOoCAACdggUAAQAAAPICAAAiiAMAAQAAAAIAAAAniAMAAQAAAGQA\n\
AAAAkAcABAAAADAyMjEDkAIAFAAAAPoCAAAEkAIAFAAAAA4DAAABkQcABAAAAAEC\n\
AwACkQUAAQAAACIDAAABkgoAAQAAACoDAAACkgUAAQAAADIDAAAEkgoAAQAAADoD\n\
AAAFkgUAAQAAAEIDAAAGkgUAAQAAAEoDAAAHkgMAAQAAAAIAAAAIkgMAAQAAAAAA\n\
AAAJkgMAAQAAABgAAAAKkgUAAQAAAFIDAAAAoAcABAAAADAxMDABoAMAAQAAAAEA\n\
AAACoAkAAQAAAGQAAAADoAkAAQAAAEoAAAAFoAQAAQAAAGoDAAAVogUAAQAAAFoD\n\
AAAXogMAAQAAAAIAAAAAowcAAQAAAAMAAAABowcAAQAAAAEAAAABpAMAAQAAAAAA\n\
AAACpAMAAQAAAAAAAAADpAMAAQAAAAAAAAAEpAUAAQAAAGIDAAAFpAMAAQAAACYA\n\
AAAGpAMAAQAAAAAAAAAHpAMAAQAAAAAAAAAIpAMAAQAAAAAAAAAJpAMAAQAAAAAA\n\
AAAKpAMAAQAAAAAAAAALpAcABAAAAAAAAAAMpAMAAQAAAAAAAAAAAAAACgAAAAIP\n\
AABuAQAAZAAAADIwMTE6MDY6MjYgMTI6NTI6NTkAMjAxMTowNjoyNiAxMjo1Mjo1\n\
OQByqTkAAGAeAHfe//8Y/P//dwEAAGQAAAAAAAAAIAAAAHcBAABkAAAAAAAAAAAA\n\
AACaAQAAZAAAAAAAAAAAAAAA9gQAAAAEAAACAAEAAgAEAAAAUjk4AAIABwAEAAAA\n\
MDEwMAAAAAAGAAMBAwABAAAABgAAABoBBQABAAAA1gMAABsBBQABAAAA3gMAACgB\n\
AwABAAAAAgAAAAECBAABAAAA5gMAAAICBAABAAAA2woAAAAAAABIAAAAAQAAAEgA\n\
AAABAAAA/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQN\n\
DAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/\n\
2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy\n\
MjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCABeAIADASIAAhEBAxEB/8QAHwAAAQUB\n\
AQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQID\n\
AAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0\n\
NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKT\n\
lJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl\n\
5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL\n\
/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHB\n\
CSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpj\n\
ZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3\n\
uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIR\n\
AxEAPwD04LRtqbZ7Uba9K5zEO2onAJwTyOasSYRCTVR8AnuCKyqVOm5pCPURpNvX\n\
vSo5CBscGqTuzYKqcd8imLcE7gWwF9fSvLlVcKlonVypx1NNJVbjnIOKmxxXBeIP\n\
HNrpPmW9tIkkyryQu4Bvzrz++8f69duNl46L6IoFd8KzS9455U77Hv4GaXbXh2k+\n\
PdYs5gZbwyJjlZADXqvh/wAWadrgSKOdRclQShGOfato1VIzlBxN0LS7al28Uu2q\n\
uQRgU4CnhacFouBHilC1Jt9qa8kcbAO6qT0BNQ5pK7Y0g8ujZVry6Qpgc0uYqxlX\n\
CkzYLYUDOKgZUK7y4I7Vbn8t5JV3HJ46Vz2u3AtIEtoQSTk56VjUkopysaR10Fa8\n\
GcArt9q5bxRrp07T9tuwE8xKnnlR/k1qpMFjUgdeCDXnviMSzeIJUcjlwFGfYVwx\n\
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\n\
VgXEvmzMx9a1Lw+VbceorFY9TQkTUfQVDglverKz1U/gp8Q3SgVRkacb55JxVuAj\n\
t6VDDGOpANWgAcAcU7CIZF+fk45pGUg8dDU86okaswJOKhiVnUkH7tcclaTRnY//\n\
2QD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIs\n\
IxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIy\n\
MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAAR\n\
CABKAGQDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL\n\
/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0Kx\n\
wRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNk\n\
ZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5\n\
usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEB\n\
AQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAEC\n\
AxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygp\n\
KjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImK\n\
kpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk\n\
5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD08IaNlWPLpGUIpY9BXo8xzWKk\n\
m0EKec1XeYAcc54qV2L8gck8VRmHJJlGQTxXDiajcbnTTjYtibaB0J9KlM8SKWkd\n\
YwO7HFchrniJNDsN+A9yw+RCf1NeS6v4j1LVZ2a4unK/3QeBU0K00ryHOCex9DW+\n\
oWd0xWC6ikYdlYGrm2vmKz1CazdZIpXDqcghsEV6v4L+In22eOw1RgGbCpKfX0Nd\n\
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\n\
=3S6M\n\
-----END PGP PUBLIC KEY BLOCK-----";

exports.test125Octets = function(test) {
	var vals = [ 0 , 10, 112, 192, 2051, 8383, 8384, 9102134 ];
	test.expect(vals.length*2);
	async.forEachSeries(vals, function(it, next) {
		var bin = pgp.basicTypes.encode125OctetNumber(it);
		pgp.basicTypes.read125OctetNumber(bin, function(err, number) {
			test.ifError(err);
			test.equal(number, it);

			next();
		});
	}, function() {
		test.done();
	});
};

exports.headers = function(test) {
	var tag = 10;
	var bodyLengths = [ 0 , 10, 112, 192, 2051, 8383, 8384, 9102134 ];
	test.expect(bodyLengths.length*8);

	async.forEachSeries([ false, true ], function(newHeaders, next) {
		async.forEachSeries(bodyLengths, function(it, next) {
			var header = pgp.packets.generateHeader(tag, it, newHeaders);
			pgp.packets.getHeaderInfo(header, function(err, tag1, packetLength, header1) {
				test.ifError(err);
				
				test.equals(tag1, tag);
				test.equals(packetLength, it);
				test.equals(header1.toString(), header.toString());

				next();
			});
		}, next);
	}, function() {
		test.done();
	});
};

exports.key1 = function(test) {
	test.expect(23);
	
	var key = null, id = null, sig = null;

	var split = pgp.packets.splitPackets(new Buffer(TESTKEY1, "binary"));
	readNext();
	
	function readNext() {
		split.next(function(err, tag, header, body) {
			if(err === true)
			{
				end();
				return;
			}

			test.ifError(err);
			
			if(key == null)
				key = body;
			else if(id == null)
				id = body;
			else
				sig = body;

			readNext();
		});
	}
	
	function end() {
		pgp.packetContent.getPublicKeyPacketInfo(key, function(err, info) {
			test.ifError(err);

			test.equals(info.version, 4);
			test.equals(info.pkalgo, 17);
			test.equals(info.date.getTime(), 1347893148000);
			test.equals(info.expires, null);
			test.equals(info.id, "3B4385AD77124641");
			
			pgp.packetContent.getIdentityPacketInfo(id, function(err, info) {
				test.ifError(err);
				
				test.equals(info.name, "blablabla");
				test.equals(info.id, "blablabla <bla@example.com>");
				test.equals(info.comment, null);
				test.equals(info.email, "bla@example.com");

				pgp.packetContent.getSignaturePacketInfo(sig, function(err, info) {
					test.ifError(err);

					test.equals(info.date.getTime(), 1347919652000);
					test.equals(info.pkalgo, 17);
					test.equals(info.version, 4);
					test.equals(info.hashalgo, 2);
					test.ok(info.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_FLAGS][0].value[pgp.consts.KEYFLAG.CERT]);
					test.ok(info.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_FLAGS][0].value[pgp.consts.KEYFLAG.SIGN]);
					test.equals(info.issuer, "3B4385AD77124641");
					test.equals(info.hashedSubPackets[pgp.consts.SIGSUBPKT.KEY_EXPIRE][0].value, 717704);

					test.done();
				});
			});
		});
	}
};

exports.base64 = function(test) {
	test.expect(6);

	var data1 = TESTKEY2.split(/\r\n|\n/).slice(3, -1).join("\n");
	
	var stream = pgp.basicTypes.getBase64EncodingStream(pgp.basicTypes.getBase64DecodingStream(data1));
	
	stream.readUntilEnd(function(err, data) {
		test.ifError(err);
		
		test.equals(data1.replace(/\s/g, ""), data.toString("utf8").replace(/\s/g, ""));
		
		stream = pgp.basicTypes.getBase64EncodingStream(pgp.basicTypes.getBase64DecodingStream(data1, 4));
		stream.readUntilEnd(function(err, data) {
			test.ifError(err);
			
			test.equals(data1.replace(/\s/g, ""), data.toString("utf8").replace(/\s/g, ""));
			stream = pgp.basicTypes.getBase64EncodingStream(pgp.basicTypes.getBase64DecodingStream(data1, 20));
			stream.readUntilEnd(function(err, data) {
				test.ifError(err);
				
				test.equals(data1.replace(/\s/g, ""), data.toString("utf8").replace(/\s/g, ""));
				
				test.done();
			});
		});
	});
};

exports.decodeKeyFormat = function(test) {
	test.expect(4);
	
	pgp.formats.decodeKeyFormat(TESTKEY2).readUntilEnd(function(err, data) {
		test.ifError(err);
		test.equals(pgp.utils.hash(data, "sha1", "base64"), "W/c5mHH2N/MTxMXIMUIm11VtYLE=");
		
		pgp.formats.decodeKeyFormat(TESTKEY1).readUntilEnd(function(err, data) {
			test.ifError(err);
			test.equals(pgp.utils.hash(data, "sha1", "base64"), "nUf/XAd/Id/kpJ/aX62rlvYU9/s=");
			
			test.done();
		});
	});
};

exports.armor = function(test) {
	test.expect(2);
	
	pgp.formats.dearmor(pgp.formats.enarmor(TESTKEY1, pgp.consts.ARMORED_MESSAGE.PUBLIC_KEY)).readUntilEnd(function(err, data) {
		test.ifError(err);
		test.equals(TESTKEY1.toString("binary"), data.toString("binary"));
		
		test.done();
	});
};

exports.key2 = function(test) {
	test.expect(29);
	var split = pgp.packets.splitPackets(pgp.formats.dearmor(TESTKEY2));
	next();

	function next() {
		split.next(function(err, tag, header, body) {
			if(err === true)
			{
				test.done();
				return;
			}
			
			test.ifError(err);
			next();
		});
	}
};