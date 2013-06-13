This project is work in progress. One day it is supposed to be a native
JavaScript OpenPGP implementation following 
[RFC 4880](http://tools.ietf.org/html/rfc4880).

This page describes what is supported already.

API documentation
=================

* [Keyring](#keyring)
  * [Open a keyring file](#open-a-keyring-file)
  * [Access keys and their sub-objects](#access-keys-and-their-sub-objects)
  * [Add and remove objects](#add-and-remove-objects)
  * [Save changes](#save-changes)
  * [Web of trust](#web-of-trust)
* [BufferedStream](#bufferedstream)
* [Fifo](#fifo)
* [Filter](#filter)
* [Object info](#object-info)
  * [Public key info](#public-key-info)
  * [Public subkey info](#public-subkey-info)
  * [User ID info](#user-id-info)
  * [Attribute info](#attribute-info)
  * [Signature info](#signature-info)
* [Constants](#constants)
* [Format conversion functions](#format-conversion-functions)


Types
=====

Keyring
-------

The Keyring class represents a collection of keys and can be used to access
information about them. node-pgp ships a simple implementation of a keyring
class reading keys from a file, storing them in memory and saving changes
back to the file. There are other implementations, such as
[node-pgp-postgres](https://github.com/cdauth/node-pgp-postgres).

### Open a keyring file ###

In order to create a keyring object from a file, use the following code:

```javascript
var filename = "/tmp/keyring.pgp";
var create = true; // Create the file if it does not exist?
pgp.keyringFile.getFileKeyring(filename, function(err, keyring) {
	// keyring is the Keyring object
}, create);
```

When you are finished using a Keyring object, you should call `keyring.done()`,
so that all file handles (or database connections) are closed.

### Access keys and their sub-objects ###

The hierarchy of objects is as follows:

* Public key
	* Signature
	* Public subkey
		* Signature
	* Identity
		* Signature
	* Attribute
		* Signature

Each object is referenced by an ID that is unique within the context of its parent
object. Keys and subkeys are referenced by their long ID, a 16-digit uppercase hexadecimal
number. Identities are referenced by the string of their identity. Attributes and signatures
are referenced by a 27-character alphanumeric checksum of their content.

#### get*List() ####

* `Keyring.getKeyList([filter])`
* `Keyring.getKeySignatureList(keyId[, filter])`
* `Keyring.getSubkeyList(keyId[, filter])`
* `Keyring.getSubkeySignatureList(keyId, subkeyId[, filter])`
* `Keyring.getIdentityList(keyId[, filter])`
* `Keyring.getIdentitySignatureList(keyId, identityId[, filter])`
* `Keyring.getAttributeList(keyId[, filter])`
* `Keyring.getAttributeSignatureList(keyId, attributeId[, filter])`
* `Keyring.getParentKeyList(subkeyId)`

Returns a [Fifo](#fifo) object with the IDs of the existing objects, optionally filtered
by a [Filter](#filter).

#### get*s() ####

* `Keyring.getKeys([filter, [fields]])`
* `Keyring.getKeySignatures(keyId, [filter, [fields]])`
* `Keyring.getSubkeys(keyId, [filter, [fields]])`
* `Keyring.getSubkeySignatures(keyId, subkeyId, [filter, [fields]])`
* `Keyring.getIdentities(keyId, [filter, [fields]])`
* `Keyring.getIdentitySignatures(keyId, identityId, [filter, [fields]])`
* `Keyring.getAttributes(keyId, [filter, [fields]])`
* `Keyring.getAttributeSignatures(keyId, attributeId, [filter, [fields]])`
* `Keyring.getParentKeys(subkeyId)`
* `Keyring.getAllSignatures(keyId, filter, fields)`

Returns a [Fifo](#fifo) object with the existing object [infos](#object-info), optionally
only those that match the given [Filter](#filter). If a `fields` array is specified, the
object info objects will only contain those properties. This might improve performance
with some keyring implementations.

`getAllSignatures()` returns all signatures of the key itself and of all its sub-objects.

#### getSelfSigned*s() ####

* `Keyring.getSelfSignedSubkeys(keyId[, filter[, fields]])`
* `Keyring.getSelfSignedIdentities(keyId[, filter[, fields]])`
* `Keyring.getSelfSignedAttributes(keyId[, filter[, fields]])`

Same as above, but additionally returns these additional properties from the most recent
self-signature: `expires`, `revoked`, `security`. Objects that do not contain a self-signature
are not returned.

#### *exists() ####

* `Keyring.keyExists(keyId, callback)`
* `Keyring.keySignatureExists(keyId, signatureId, callback)`
* `Keyring.subkeyExists(keyId, subkeyId, callback)`
* `Keyring.subkeySignatureExists(keyId, subkeyId, signatureId, callback)`
* `Keyring.identityExists(keyId, identityId, callback)`
* `Keyring.identitySignatureExists(keyId, identityId, signatureId, callback)`
* `Keyring.attributeExists(keyId, attributeId, callback)`
* `Keyring.attributeSignatureExists(keyId, attributeId, signatureId, callback)`

Calls the `callback(err, exists)` function with a boolean to indicate whether an object with
the given ID exists.

#### get*() ####

* `Keyring.getKey(keyId, callback[, fields])`
* `Keyring.getKeySignature(keyId, signatureId, callback[, fields])`
* `Keyring.getSubkey(keyId, subkeyId, callback[, fields])`
* `Keyring.getSubkeySignature(keyId, subkeyId, signatureId, callback[, fields])`
* `Keyring.getIdentity(keyId, identityId, callback[, fields])`
* `Keyring.getIdentitySignature(keyId, identityId, signatureId, callback[, fields])`
* `Keyring.getAttribute(keyId, attributeId, callback[, fields])`
* `Keyring.getAttributeSignature(keyId, attributeId, signatureId, callback[, fields])`
* `Keyring.getSignatureById(signatureId, callback[, fields])`
* `Keyring.getPrimaryIdentity(keyId, callback[, fields])`

Calls the `callback(err, objectInfo)` function with an [info object](#object-info) for
the object with the specified ID. If the object does not exist, `null` is passed instead.
By specifying the `fields` array, you can limit the properties that the info object will
contain, which might increase performance with some keyring implementations.

Note that `getSignatureById()` only returns verified signatures.

`getPrimaryIdentity()` finds the primary identity of the key or null if the key does not
contain any identities at all.

#### getSelfSigned*() ####

* `Keyring.getSelfSignedSubkey(keyId, subkeyId, callback[, fields])`
* `Keyring.getSelfSignedIdentity(keyId, identityId, callback[, fields])`
* `Keyring.getSelfSignedAttribute(keyId, attributeId, callback[, fields])`

Same as above, but additionally returns these additional properties from the most recent
self-signature: `expires`, `revoked`, `security`. Objects that do not contain a self-signature
are not returned.

#### get*SignatureListByIsser() ####

* `Keyring.getKeySignatureListByIssuer(issuerKeyId[, filter])`
* `Keyring.getSubkeySignatureListByIssuer(issuerKeyId[, filter])`
* `Keyring.getIdentitySignatureListByIssuer(issuerKeyId[, filter])`
* `Keyring.getAttributeSignatureListByIssuer(issuerKeyId[, filter])`

Finds signatures allegedly issued by the given key, optionally only those that match the given
[filter](#filter). To only get those signatures that have really been issued by the given key,
use `{ verified: true }` as filter. Returns a [Fifo](#fifo) object.

The objects returned contain the following properties, depending on the context: `keyId`,
`signatureId`, `subkeyId`, `identityId`, `attributeId`.

#### search() ####

* `Keyring.search(searchString)`
* `Keyring.searchIdentities(searchString)`
* `Keyring.searchByShortKeyId(shortKeyId)`
* `Keyring.searchByLongKeyId(longKeyId)`
* `Keyring.searchByFingerprint(fingerprint)`

Searches the keyring for the given strings. `search()` unites all other search methods.

A [Fifo](#fifo) object is returned that contains [key info](#public-key-info) objects, optionally
with an additional `subkey` or `identity` object containing the [info object](#object-info) of the
matched subkey or identity.

#### exportKey() ####

* `Keyring.exportKey(keyId[, selection])`

Exports the given key in binary format, returned as a [BufferedStream](#bufferedStream).
With the `selection` object, you can skip sub-objects during the export. Its format is
`{ identities: { }, attributes: { }, subkeys: { }, signatures: { } }`, where the properties
are objects mapping object IDs to booleans that indicate whether the objects should be exported.
If `selection.attributes` is undefined, all attributes are exported, if it is an empty object,
no attributes are exported.

### Add and remove objects ###

Changes made to the keyring are not written to the underlying data storage (such as a file
or a database) unless the save function is called.

#### add*() ####

* `Keyring.addKey(keyInfo, callback)`
* `Keyring.addKeySignature(keyId, signatureInfo, callback)`
* `Keyring.addSubkey(keyId, subkeyInfo, callback)`
* `Keyring.addSubkeySignature(keyId, subkeyId, signatureInfo, callback)`
* `Keyring.addIdentity(keyId, identityInfo, callback)`
* `Keyring.addIdentitySignature(keyId, identityId, signatureInfo, callback)`
* `Keyring.addAttribute(keyId, attributeInfo, callback)`
* `Keyring.addAttributeSignature(keyId, attributeId, signatureInfo, callback)`

Adds the object with the given [info](#object-info) to the keyring and then calls
the `callback(err)` function.

#### remove*() ####

* `Keyring.removeKey(keyId, callback)`
* `Keyring.removeKeySignature(keyId, signatureId, callback)`
* `Keyring.removeSubkey(keyId, subkeyId, callback)`
* `Keyring.removeSubkeySignature(keyId, subkeyId, signatureId, callback)`
* `Keyring.removeIdentity(keyId, identityId, callback)`
* `Keyring.removeIdentitySignature(keyId, identityId, signatureId, callback)`
* `Keyring.removeAttribute(keyId, attributeId, callback)`
* `Keyring.removeAttributeSignature(keyId, attributeId, signatureId, callback)`

Removes the object with the given ID from the keyring and then calls the `callback(err)`
function. If the item does not exist, an error *might* be raised.

#### importKeys() ####

* `Keyring.importKeys(keyData, callback[, acceptLocal])`

Imports the given keys to the keyring. `keyData` is a [BufferedStream](#bufferedstream) with
keys in binary format. After the import, `callback(err, imported)` is called, where `imported`
is an object of the format `{ keys: [ ], failed: [ ] }`, `keys` containing an array of objects
with some information about the imported keys and `failed` containing an array of objects with
some information about the objects that failed to import.

If `acceptLocal` is set to `true`, local signature are not skipped.

### Save changes ###

* `Keyring.saveChanges(callback)`
* `Keyring.revertChanges(callback)`

Saves or reverts the changes made to the keyring and then calls `callback(err)`.

### Web of trust ###

* `Keyring.trust(keyId, callback)`
* `Keyring.untrustKey(keyId, callback)`

Trusts/untrusts the given key ID and then calls `callback(err)`. If a key is trusted,
all the signatures made by it will be trusted and so the identities and attributes that
it has signed. Also, trust signatures made by it will be trusted, so a chain of trust can
be built.


BufferedStream
--------------

This class makes reading from a Readable Stream predictable by providing methods
that ensure that a specified number of bytes is returned at once.

Objects of this class are returned by several functions of this library. The
following methods can be used to read content from the stream. Note that all
of them only read a , you can
use the following methods to read its content:

### read(bytes, callback, strict) ###

Reads the specified number of bytes from the stream. If `strict` is set to true
(which is the default value), an error is produced when the stream ends before
the number of bytes is available. If it is set to false, in that case, it will
returned a reduced number of bytes containing the rest of the stream.

```javascript
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
}, false);
```

### readUntilEnd(callback) ###

Waits until the stream has ended and then calls the callback function with the
whole amount of data.

```javascript
var stream; // Of type BufferedStream
stream.readUntilEnd(function(err, data) {
	if(err)
		console.warn("An error occurred", err);
	else
		; // data contains the whole data
});
```

### readLine(callback) ###

Reads a line from the stream. The line-break is included in the provided data.

```javascript
var stream; // Of type BufferedStream
stream.readLine(function(err, data) {
	if(err)
		console.warn("An error occurred", err);
	else if(data.toString("utf8").indexOf("\n") == -1)
		; // This is the last line of the stream
	else
		; // data contains a line ended with a line-break
});
```

### readArbitrary(callback) ###

Reads an arbitrary amount of data from the stream, at least 1 byte. All data
that is currently available in the stream buffer will be passed to the callback
function. This example passes all data from the stream to a writable stream.

```javascript
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
```

### whilst(iterator, callback) ###

This function works like the `whilst()` method from the `async` library. It calls
the `iterator` function with an arbitrary amount of data multiple times until the
end of the stream is reached. Then, the `callback` function is called once with
a possible error message.

```javascript
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
```


Fifo
----

Objects of this type represent a queue of items.

There are two ways to read the items. The probably simpler one works similar to
the `forEachSeries()` method from the `async` library:

```javascript
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
```

The other method reads each item manually by using the `next` function:

```javascript
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
```


Filter
------

Filters are used to filter objects by their properties. To get all version 4 keys with either
2048 or 4096 bits for example, use the following filter:

```javascript
{ version: 4, size: [ 2048, 4096 ] }
```

The keys of the filter object are the properties to filter by, the values are the values to match.
There are different classes that you can use instead of specifying the values directly:

* `new pgp.Keyring.Filter.Equals("test")`: Matches `"test"`
* `new pgp.Keyring.Filter.ArrayContains("test")`: Matches arrays that contain `"test"`
* `new pgp.Keyring.Filter.EqualsIgnoreCase("test")`: Matches `"test"`, `"TEST"`, `"tEsT"` and so on
* `new pgp.Keyring.Filter.ContainsIgnoreCase("test")`: Matches arrays that contain `"test"`, `"TEST"`,
  `tEsT` and so on
* `new pgp.Keyring.Filter.ShortKeyId("0A1B2C3D")`: Matches long key IDs like `"000000000A1B2C3D"`
* `new pgp.Keyring.Filter.LessThan(5)`: Matches numbers less than 5
* `new pgp.Keyring.Filter.LessThanOrEqual(5)`: Matches numbers less than or equal 5
* `new pgp.Keyring.Filter.GreaterThan(5)`: Matches numbers greater than 5
* `new pgp.Keyring.Filter.GreaterThanOrEqual(5)`: Matches numbers greater than or equal
* `new pgp.Keyring.Filter.Not(new pgp.Keyring.Filter.Equals("test"))`: Matches everything but `"test"`
* `new pgp.Keyring.Filter.Or(new pgp.Keyring.Filter.Equals("test1"), new pgp.Keyring.Filter.Equals("test2"),
  new pgp.Keyring.Filter.Equals("test3")`: Matches `"test1"`, `"test2"`, `"test3"`
* `new pgp.Keyring.Filter.And(new pgp.Keyring.Filter.Equals("test1"), new pgp.Keyring.Filter.Equals("test2"),
  new pgp.keyring.Filter.Equals("test3")`: Matches nothing

For example, to look up all version 4 keys with a key size 2048 or greater, use the following filter:

```javascript
{ version: 4, size: new pgp.Keyring.Filter.GreaterThanOrEqual(2048) }
```


Object info
-----------

### Public key info ###

Objects of this type may contain the following properties:

* `pkt`: `consts.PKT.PUBLIC_KEY`
* `id`: The long ID of the key, a 16-digit hex number as upper-case String
* `binary`: The binary packet content containing this key (Buffer)
* `version`: The key version, either 3 or 4
* `versionSecurity`: How secure the key version makes this key, one of [`consts.SECURITY`](#security-level)
* `expires`: `null` or a Date object indicating the expiration date of the key.
  Note that only v3 keys can have this defined in the key itself, and it can be
  overridden by self-signatures.
* `date`: A Date object indicating when the key was created.
* `pkalgo`: One of [`consts.PKALGO`](#public-key-algorithm)
* `keyParts`: An object containing the relevant key parts as [MPI](#mpi) objects
  Algorithm specific, might contain the values `n`, `e`, `p`, `q`, `g` and `y`
* `fingerprint`: The fingerprint, a 32-digit hex number as upper-case String
* `size`: The key size in bits
* `sizeSecurity`: How secure the size makes this key, one of [`consts.SECURITY`](#security-level)
* `security`: The overall security of this key’s properties, one of [`consts.SECURITY`](#security-level)


### Public subkey info ###

Objects of this type may contain the same properties as [public keys](#public-key-info),
except that `pkt` is `consts.PKT.PUBLIC_SUBKEY`.


### User ID info ###

Objects of this type may contain the following properties:

* `pkt`: `consts.PKT.USER_ID`
* `name` : The name part of the ID as String
* `email` : The e-mail part of the ID as String
* `comment` : The comment part of the ID as String
* `binary` : The binary packet content containing this identity (Buffer)
* `id` : The whole ID as String
* `nameTrust` : How reliable it is that this key belongs to a person with the name of
  this identity, where 1.0 is considered to be reliable.
* `emailTrust` : How reliable it is that this key belongs to the person who own the
  e-mail address of this identity, where 1.0 is considered to be reliable.


### Attribute info ###

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
* `binary` : The binary packet content containing this attribute (Buffer)
* `trust` : How reliable it is that this key belongs to the person who is depicted
  on this picture, where 1.0 is considered to be reliable.


### Signature info ###

* `pkt`: `consts.PKT.SIGNATURE`,
* `id` : An ID string created from a hash of this signature. Not part of the
  OpenPGP standard.
* `sigtype`: The signature type, one of [`consts.SIGTYPE`](#signature-type).
* `date`: A Date object when the signature was issued
* `issuer`: The long ID of the issuer key. A 16-digit upper-case hex string.
* `pkalgo`: The public key algorithm, one of [`consts.PKALGO`](#public-key-algorithm)
* `hashalgo`: The hash algorithm, one of [`consts.HASHALGO`](#hash-algorithm)
* `version`: The signature packet version, 3 or 4
* `binary`: The binary packet content containing this attribute (Buffer)
* `hashedSubPackets`: An object with the hashed sub-packets
   (see [the RFC](http://tools.ietf.org/html/rfc4880#section-5.2.3.1)). The keys
   are the sub-packet types (one of [`consts.SIGSUBPKT`](#signature-sub-packet-type)),
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
* `hashalgoSecurity`: The security of the hash algorithm used in this signature,
  one of [`consts.SECURITY`](#security-level)
* `security`: The overall security of this signatures parameters, one of
  [`consts.SECURITY`](#security-level)
* `verified`: Whether it has been verified that this signature has actually been
  issued by its issuer (Boolean)
* `trustSignature`: Whether this signature is a trust signature (Boolean)


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

### Security level ###

`pgp.consts.SECURITY` defines level to indicate the security of key parameters.

	UNKNOWN      : -1,
	UNACCEPTABLE : 0,
	BAD          : 1,
	MEDIUM       : 2,
	GOOD         : 3


Format conversion functions
===========================

OpenPGP data can come in two different formats: in binary or “ASCII-armored”
using base-64. These methods allow working with the different formats.

## formats.decodeKeyFormat(data) ##

This method converts the input data to the binary format, automatically
detecting the format of the input data. `data` can be a Readable Stream, a
Buffer, or a String. The function returns a [`BufferedStream`](#bufferedstream),
see below how to work with that.

```javascript
pgp.formats.decodeKeyFormat(fs.createReadStream("/tmp/test.asc")).readUntilEnd(function(err, data) {
if(err)
		; // An error occurred
	else
		; // data is a Buffer with the data in binary format
});
```

## formats.dearmor(data) ##

Converts the input data from armored ASCII to the binary format. `data` can be
a Readable Stream, a Buffer, or a String. The function returns a
[`BufferedStream`](#bufferedstream).

```javascript
pgp.formats.dearmor(fs.createReadStream("/tmp/test.asc")).readUntilEnd(function(err, data) {
	if(err)
		console.warn("An error occurred", err);
	else
		; // data is a Buffer with the data in binary format
});
```

## formats.enarmor(data, messageType) ##

Converts the input data from binary format to armored ASCII format. `data` can
be a Readable Stream, a Buffer, or a String. `messageType` is one of [`pgp.consts.ARMORED_MESSAGE`](#armored-message-type).
The function returns a [`BufferedStream`](#bufferedstream).

```javascript
pgp.formats.enarmor(fs.createReadStream("/tmp/test.pgp"), pgp.consts.ARMORED_MESSAGE).readUntilEnd(function(err, data) {
	if(err)
		console.warn("An error occurred", err);
	else
		; // data is a Buffer with the armored data encoded in UTF-8
});
```
