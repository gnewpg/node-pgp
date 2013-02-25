// Packet classes (copied from gnupg)
exports.PKT = {
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
};

// Signature types
exports.SIG = {
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
};

// V4 signatures sub packets (copied from gnupg)
exports.SIGSUBPKT = {
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
};

// The flags of the first byte of a KEY_FLAGS (27) v4 signature sub packet
exports.KEYFLAG = {
	CERT          : 0x01, /* This key may be used to certify other keys. */
	SIGN          : 0x02, /* This key may be used to sign data. */
	ENCRYPT_COMM  : 0x04, /* This key may be used to encrypt communications. */
	ENCRYPT_FILES : 0x08, /* This key may be used to encrypt storage. */
	PRIV_SPLIT    : 0x10, /* The private component of this key may have been split by a secret-sharing mechanism. */
	AUTH          : 0x20, /* This key may be used for authentication. */
	MULT_PERS     : 0x80  /* The private component of this key may be in the possession of more than one person. */
};

// The flags of the first byte of the FEATURES (30) v4 signature sub packet
exports.FEATURES = {
	MOD_DETECT    : 0x01, /* Modification Detection (packets 18 and 19) */
};

// Attribute subpacket types
exports.ATTRSUBPKT = {
	IMAGE         : 1
};

// Attribute subpacket image types
exports.IMAGETYPE = {
	JPEG          : 1
};

// Public key algorithms
exports.PKALGO = {
	RSA_ES        : 1, /* RSA (Encrypt or Sign) */
	RSA_E         : 2, /* RSA Encrypt-Only */
	RSA_S         : 3, /* RSA Sign-Only */
	ELGAMAL_E     : 16, /* Elgamal (Encrypt-Only) */
	DSA           : 17 /* DSA (Digital Signature Algorithm) */
};

// Which public key algorithms support encryption, signing or authentication
exports.PKALGO_KEYFLAGS = {
	1: [ exports.KEYFLAG.SIGN, exports.KEYFLAG.ENCRYPT_COMM, exports.KEYFLAG.ENCRYPT_FILES, exports.KEYFLAG.AUTH ],
	2: [ exports.KEYFLAG.ENCRYPT_COMM, exports.KEYFLAG.ENCRYPT_FILES ],
	3: [ exports.KEYFLAG.SIGN, exports.KEYFLAG.AUTH ],
	16: [ exports.KEYFLAG.ENCRYPT_COMM, exports.KEYFLAG.ENCRYPT_FILES ],
	17: [ exports.KEYFLAG.SIGN, exports.KEYFLAG.AUTH ]
};

// Hash algorithms
exports.HASHALGO = {
	MD5           : 1,
	SHA1          : 2,
	RIPEMD160     : 3,
	SHA256        : 8,
	SHA384        : 9,
	SHA512        : 10,
	SHA224        : 11
};

// Armored message type
exports.ARMORED_MESSAGE = {
	MESSAGE       : "MESSAGE",
	PUBLIC_KEY    : "PUBLIC KEY BLOCK",
	PRIVATE_KEY   : "PRIVATE KEY BLOCK",
	SIGNATURE     : "SIGNATURE"
};

exports.SECURITY = {
	UNKNOWN : -1,
	UNACCEPTABLE : 0,
	BAD : 1,
	MEDIUM : 2,
	GOOD : 3
};