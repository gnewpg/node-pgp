This project is work in progress. One day it is supposed to be a native
JavaScript OpenPGP implementation following 
[RFC 4880](http://tools.ietf.org/html/rfc4880).

This page describes what is supported already.

Functions
=========

PGP data
--------

OpenPGP data can come in two different formats: in binary or “ASCII-armored”
using base-64. These methods allow working with the different formats.

### formats.decodeKeyFormat(data) ###

This method converts the input data to the binary format, automatically
detecting the format of the input data. `data` can be a Readable Stream, a
Buffer, or a String. The function returns a [`BufferedStream`](#bufferedstream),
see below how to work with that.

	pgp.formats.decodeKeyFormat(fs.createReadStream("/tmp/test.asc")).readUntilEnd(function(err, data) {
	if(err)
			; // An error occurred
		else
			; // data is a Buffer with the data in binary format
	});

### formats.dearmor(data) ###

Converts the input data from armored ASCII to the binary format. `data` can be
a Readable Stream, a Buffer, or a String. The function returns a
[`BufferedStream`](#bufferedstream).

	pgp.formats.dearmor(fs.createReadStream("/tmp/test.asc")).readUntilEnd(function(err, data) {
		if(err)
			console.warn("An error occurred", err);
		else
			; // data is a Buffer with the data in binary format
	});

### formats.enarmor(data, messageType) ###

Converts the input data from binary format to armored ASCII format. `data` can
be a Readable Stream, a Buffer, or a String. `messageType` is one of [`pgp.consts.ARMORED_MESSAGE`](#armored-message-type).
The function returns a [`BufferedStream`](#bufferedstream).

	pgp.formats.enarmor(fs.createReadStream("/tmp/test.pgp"), pgp.consts.ARMORED_MESSAGE).readUntilEnd(function(err, data) {
		if(err)
			console.warn("An error occurred", err);
		else
			; // data is a Buffer with the armored data encoded in UTF-8
	});


PGP packets
-----------

OpenPGP data is made of multiple packets, which represent objects like a public
key, a user ID that belongs to a key, a signature, or even the raw data that is
being signed. These functions deal with those packets.

### packets.splitPackets(data) ###

This method splits OpenPGP data into its packets. `data` can be a Readable
Stream, a Buffer or a String containing the binary data to split. The method
returns a [`Fifo`](#fifo) object, see below how to use that.

	var split = packets.splitPackets(fs.createReadStream("/tmp/test.pgp"));
	iterate();
	function iterate() {
		split.next(function(err, type, header, body) {
			if(err ### true)
				; // All packets have been processed
			else if(err)
				console.warn("An error occurred", err);
			else {
				// type is the packet type, one of consts.PKT, see below
				// header is a Buffer containing the packet header
				// body is a Buffer containing the packet body
				
				iterate();
			}
		});
	}

### packets.generatePacket(type, body) ###

This method creates a PGP packet. `type` is one of [`consts.PKT`](#packet-type)
(see below), `body` is a Buffer containing the packet body. The method returns
a Buffer with the generated packet.

	var keyBody,identityBody,signatureBody; // All of type Buffer
	var completeKey = Buffer.concat([
		pgp.packets.generatePacket(pgp.consts.PKT.PUBLIC_KEY, keyBody),
		pgp.packets.generatePacket(pgp.consts.PKT.USER_ID, identityBody),
		pgp.packets.generatePacket(pgp.consts.PKT.SIGNATURE, signatureBody)
	]);

### packetContent.getPublicKeyPacketInfo(packetBody, callback) ###

This method gets information about a public key packet. `packetBody` is a
Buffer containing the body of a public key packet. The `callback(err, info)`
function receives an info object with the following content:

* `pkt`: `consts.PKT.PUBLIC_KEY`
* `id`: The long ID of the key, a 16-digit hex number as upper-case String
* `binary`: `packetBody`
* `version`: The body packet version, either 3 or 4
* `expires`: `null` or a Date object indicating the expiration date of the key.
  Note that only v3 keys can have this defined in the key itself, and it can be
  overridden by self-signatures.
* `date`: A Date object indicating when the key was created.
* `pkalgo`: One of [`consts.PKALGO`](#public-key-algorithm)
* `keyParts`: An object containing the relevant key parts as Buffer objects
  Algorithm specific, might contain the values `n`, `e`, `p`, `q`, `g` and `y`
* `fingerprint`: The fingerprint, a 32-digit hex number as upper-case String

### packetContent.getPublicSubkeyPacketInfo(packetBody, callback) ###

This method gets information about a public subkey packet. Everything is the
same as with `getPublicKeyPacketInfo`, only `pkt` is `consts.PKT.PUBLIC_SUBKEY`.

### packetContent.getIdentityPacketInfo(packetBody, callback) ###

This method gets information about an identity (user ID) packet. `packetBody` is
a Buffer containing the body of the packet. `callback(err, info)` receives the
following info object:

* `pkt`: `consts.PKT.USER_ID`
* `name` : The name part of the ID as String
* `email` : The e-mail part of the ID as String
* `comment` : The comment part of the ID as String
* `binary` : `packetBody`
* `id` : The whole ID as String

### packetContent.getAttributePacketInfo(packetBody, callback) ###

This method gets information about an attribute packet. Attribute packets
contain of several sub-packets, which can only be JPEG images.
`callback(err, info)` receives the following info object:

* `pkt`: `consts.PKT.ATTRIBUTE`,
* `id`: An ID string to use for the attribute. This is a hash of the packet
  body. Not part of the OpenPGP standard.
* `subPackets` : An array of objects:
	* `type`: The sub-packet type, one of [`consts.ATTRSUBPKT`](#attribute-sub-packets)
	* `binary`: A buffer object with the body of the sub-packet
	* `image`; If `type` is `consts.ATTRSUBPKT.IMAGE`, this is a Buffer with the
	  image data.
	* `imageType`: If `type` is `consts.ATTRSUBPKT.IMAGE`, this is  the image
	  type, one of [`consts.IMAGETYPE`](#attribute-sub-packet-image-types)
	* `binary`: `packetBody`

### packetContent.getSignaturePacketType(packetBody, callback) ###

This method gets information about a signature packet. The `callback(err, info)`
function receives the following info object:

* `pkt`: `consts.PKT.SIGNATURE`,
* `id` : An ID string created from a hash of this signature. Not part of the
  OpenPGP standard.
* `sigtype`: The signature type, one of `consts.SIGTYPE`(#signature-type).
* `date`: A Date object when the signature was issued
* `issuer`: The long ID of the issuer key. A 16-digit upper-case hex string.
* `pkalgo`: The public key algorithm, one of `consts.PKALGO`(#public-key-algorithm)
* `hashalgo`: The hash algorithm, one of `consts.HASHALGO`(#hash-algorithm)
* `version`: The signature packet version, 3 or 4
* `binary`: `packetBody`
* `hashedSubPackets`: An object with the hashed sub-packets
   (see [the RFC](http://tools.ietf.org/html/rfc4880#section-5.2.3.1)). The keys
   are the sub-packet types (one of `consts.SIGSUBPKT`(#signature-sub-packet-type)),
   the values are arrays of objects with the following keys:
	* `critical`: A boolean, if true, the whole signature should be ignored if
	  the software does not know how to handle this sub-packet type.
	* `rawValue`: A Buffer with the body of the sub-packet
	* `value`: The body of the sub-packet mapped to an appropriate JavaScript
	  type, or null if no mapped value is known.
* `unhashedSubPackets`: Like `hashedSubPackets`, but these packets are not
  hashed by the signature, so their content is not reliable, even after the
  signature has been verified.
* `exportable`: A boolean indicating whether this signature may be exported.
* `expires`: A Date object when this signature expires or null if it does not.
* `hashedPart`: A Buffer with the hashed part of the signature. This part is
  used by the algorithm for making the signature.
* `first2HashBytes`: The first two bytes of the hash as 16-bit unsigned integer
* `signature`: A Buffer object with the actual signature part of the signature

Concepts
========

Types
-----

### BufferedStream ###

This class makes reading from a Readable Stream predictable by providing methods
that ensure that a specified number of bytes is returned at once.

Objects of this class are returned by several functions of this library. The
following methods can be used to read content from the stream. Note that all
of them only read a , you can
use the following methods to read its content:

#### read(bytes, callback, strict) ####

Reads the specified number of bytes from the stream. If `strict` is set to true
(which is the default value), an error is produced when the stream ends before
the number of bytes is available. If it is set to false, in that case, it will
returned a reduced number of bytes containing the rest of the stream.

	var stream; // Of type BufferedStream
	stream.read(5, function(err, data) {
		if(err)
			console.warn("There has been an error. Maybe the stream has ended and less than 5 bytes are available.");
		else
			; // data.length == 5
	});
	stream.read(5, function(err, data) {
		if(err)
			console.warn("There has been an error.");
		else if(data.length < 5)
			; // The stream has ended. data contains the very last bytes of it.
		else
			; // data.length == 5

#### readUntilEnd(callback) ####

Waits until the stream has ended and then calls the callback function with the
whole amount of data.

	var stream; // Of type BufferedStream
	stream.readUntilEnd(function(err, data) {
		if(err)
			console.warn("An error occurred", err);
		else
			; // data contains the whole data
	});

#### readLine(callback) ####

Reads a line from the stream. The line-break is included in the provided data.

	var stream; // Of type BufferedStream
	stream.readLine(function(err, data) {
		if(err)
			console.warn("An error occurred", err);
		else if(data.toString("utf8").indexOf("\n") == -1)
			; // This is the last line of the stream
		else
			; // data contains a line ended with a line-break
	});

#### readArbitrary(callback) ####

Reads an arbitrary amount of data from the stream, at least 1 byte. All data
that is currently available in the stream buffer will be passed to the callback
function. This example passes all data from the stream to a writable stream.

	var stream; // Of type BufferedStream
	var writableStream;
	readOn();
	function readOn() {
		stream.readArbitrary(err, data) {
			if(err)
				console.warn("There has been an error", err);
			else if(data.length == 0)
				writableStream.end(); // The stream has ended
			else {
				writableStream.write(data);
				readOn();
			}
		};
	}

#### whilst(iterator, callback) ####

This function works like the `whilst()` method from the `async` library. It calls
the `iterator` function with an arbitrary amount of data multiple times until the
end of the stream is reached. Then, the `callback` function is called once with
a possible error message.

	var stream; // Of type BufferedStream
	stream.whilst(function(data, callback) {
		// Do something with the data chunk, maybe something asynchronous
		var error; // A possible error that happened during the processing of the data
		if(error)
			callback(error); // Stops the reading and calls the second callback function with the error
		else
			callback(); // Reads the next chunk or calls the second callback function if the stream has ended
	}, function(err) {
		// The stream has ended or an error occurred
	});


### Fifo ###

Objects of this type represent a queue of items.

There are two ways to read the items. The probably simpler one works similar to
the `forEachSeries()` method from the `async` library:

	var fifo; // Of type Fifo
	fifo.forEachSeries(function(item, callback) {
		// Do something with item, maybe something asynchronous
		var error; // A possible error that happened during the processing of the item
		if(error)
			callback(error); // Breaks the loop and calls the second callback function with the error
		else
			callback(); // Loops to the next item, or calls the second callback function without an error if no items are left
	}, function(err) {
		// The loop has ended
	});

The other method reads each item manually by using the `next` function:

	var fifo; // Of type Fifo
	readNext();
	function readNext() {
		fifo.next(function(err, item) {
			if(err === true)
				; // No items left
			else if(err)
				console.log("An error occurred", err);
			else
			{
				// Do something with item.

				readNext();
			}
		});
	}


Constants
---------

### Packet type ###

`pgp.consts.PKT` contains the numbers representing packet types.

	NONE          : 0,
	PUBKEY_ENC    : 1,  /* Public key encrypted packet. */
	SIGNATURE     : 2,  /* Secret key encrypted packet. */
	SYMKEY_ENC    : 3,  /* Session key packet. */
	ONEPASS_SIG   : 4,  /* One pass sig packet. */
	SECRET_KEY    : 5,  /* Secret key. */
	PUBLIC_KEY    : 6,  /* Public key. */
	SECRET_SUBKEY : 7,  /* Secret subkey. */
	COMPRESSED    : 8,  /* Compressed data packet. */
	ENCRYPTED     : 9,  /* Conventional encrypted data. */
	MARKER        : 10, /* Marker packet. */
	PLAINTEXT     : 11, /* Literal data packet. */
	RING_TRUST    : 12, /* Keyring trust packet. */
	USER_ID       : 13, /* User id packet. */
	PUBLIC_SUBKEY : 14, /* Public subkey. */
	OLD_COMMENT   : 16, /* Comment packet from an OpenPGP draft. */
	ATTRIBUTE     : 17, /* PGP's attribute packet. */
	ENCRYPTED_MDC : 18, /* Integrity protected encrypted data. */
	MDC           : 19, /* Manipulation detection code packet. */
	COMMENT       : 61, /* new comment packet (GnuPG specific). */
	GPG_CONTROL   : 63  /* internal control packet (GnuPG specific). */

### Signature type ###

`pgp.consts.SIG` contains the numbers representing signature types.

	BINARY        : 0x00, /* Signature of a binary document. */
	TEXT          : 0x01, /* Signature of a canonical text document. */
	STANDALONE    : 0x02, /* Standalone signature. */
	CERT_0        : 0x10, /* Generic certification of a User ID and Public-Key packet. */
	CERT_1        : 0x11, /* Persona certification of a User ID and Public-Key packet. */
	CERT_2        : 0x12, /* Casual certification of a User ID and Public-Key packet. */
	CERT_3        : 0x13, /* Positive certification of a User ID and Public-Key packet. */
	SUBKEY        : 0x18, /* Subkey Binding Signature */
	KEY_BY_SUBKEY : 0x19, /* Primary Key Binding Signature */
	KEY           : 0x1F, /* Signature directly on a key */
	KEY_REVOK     : 0x20, /* Key revocation signature */
	SUBKEY_REVOK  : 0x28, /* Subkey revocation signature */
	CERT_REVOK    : 0x30, /* Certification revocation signature */
	TIMESTAMP     : 0x40, /* Timestamp signature. */
	THIRDPARTY    : 0x50, /* Third-Party Confirmation signature. */

### Signature sub-packet type ###

`pgp.consts.SIGSUBPKT` contains the numbers representing signature sub-packet
types.

	NONE          :  0,
	SIG_CREATED   :  2, /* Signature creation time. */
	SIG_EXPIRE    :  3, /* Signature expiration time. */
	EXPORTABLE    :  4, /* Exportable. */
	TRUST         :  5, /* Trust signature. */
	REGEXP        :  6, /* Regular expression. */
	REVOCABLE     :  7, /* Revocable. */
	KEY_EXPIRE    :  9, /* Key expiration time. */
	ARR           : 10, /* Additional recipient request. */
	PREF_SYM      : 11, /* Preferred symmetric algorithms. */
	REV_KEY       : 12, /* Revocation key. */
	ISSUER        : 16, /* Issuer key ID. */
	NOTATION      : 20, /* Notation data. */
	PREF_HASH     : 21, /* Preferred hash algorithms. */
	PREF_COMPR    : 22, /* Preferred compression algorithms. */
	KS_FLAGS      : 23, /* Key server preferences. */
	PREF_KS       : 24, /* Preferred key server. */
	PRIMARY_UID   : 25, /* Primary user id. */
	POLICY        : 26, /* Policy URL. */
	KEY_FLAGS     : 27, /* Key flags. */
	SIGNERS_UID   : 28, /* Signer's user id. */
	REVOC_REASON  : 29, /* Reason for revocation. */
	FEATURES      : 30, /* Feature flags. */
	SIGTARGET     : 31, /* Signature target */
	SIGNATURE     : 32, /* Embedded signature. */

	FLAG_CRITICAL : 128

### Public key algorithm ###

`pgp.consts.PKALGO` contains the numbers representing public key algorithms.

	RSA_ES        : 1, /* RSA (Encrypt or Sign) */
	RSA_E         : 2, /* RSA Encrypt-Only */
	RSA_S         : 3, /* RSA Sign-Only */
	ELGAMAL_E     : 16, /* Elgamal (Encrypt-Only) */
	DSA           : 17 /* DSA (Digital Signature Algorithm) */

### Hash algorithm ###

`pgp.consts.HASHALGO` contains the numbers representing public key algorithms.

	MD5           : 1,
	SHA1          : 2,
	RIPEMD160     : 3,
	SHA256        : 8,
	SHA384        : 9,
	SHA512        : 10,
	SHA224        : 11

### Attribute sub-packets ###

`pgp.consts.ATTRSUBPKT` contains the numbers representing attribute sub-packet
types.

	IMAGE         : 1

### Attribute sub-packet image types ###

`pgp.consts.IMAGETYPE` contains the numbers representing attribute sub-packet
image types.

	JPEG          : 1

### Armored message type ###

`pgp.consts.ARMORED_MESSAGE` contains the types that ASCII-armored PGP messages
can have.

	MESSAGE       : "MESSAGE",
	PUBLIC_KEY    : "PUBLIC KEY BLOCK",
	PRIVATE_KEY   : "PRIVATE KEY BLOCK",
	SIGNATURE     : "SIGNATURE"