/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * This code is originally derived from software contributed to
 * The NetBSD Foundation by Alistair Crooks (agc@netbsd.org), and
 * carried further by Ribose Inc (https://www.ribose.com).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef REPGP_DEF_H_
#define REPGP_DEF_H_

/************************************/
/* Packet Tags - RFC4880, 4.2 */
/************************************/

/** Packet Tag - Bit 7 Mask (this bit is always set).
 * The first byte of a packet is the "Packet Tag".  It always
 * has bit 7 set.  This is the mask for it.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_ALWAYS_SET 0x80

/** Packet Tag - New Format Flag.
 * Bit 6 of the Packet Tag is the packet format indicator.
 * If it is set, the new format is used, if cleared the
 * old format is used.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_NEW_FORMAT 0x40

/** Old Packet Format: Mask for content tag.
 * In the old packet format bits 5 to 2 (including)
 * are the content tag.  This is the mask to apply
 * to the packet tag.  Note that you need to
 * shift by #PGP_PTAG_OF_CONTENT_TAG_SHIFT bits.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_OF_CONTENT_TAG_MASK 0x3c
/** Old Packet Format: Offset for the content tag.
 * As described at #PGP_PTAG_OF_CONTENT_TAG_MASK the
 * content tag needs to be shifted after being masked
 * out from the Packet Tag.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_OF_CONTENT_TAG_SHIFT 2
/** Old Packet Format: Mask for length type.
 * Bits 1 and 0 of the packet tag are the length type
 * in the old packet format.
 *
 * See #pgp_ptag_of_lt_t for the meaning of the values.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_OF_LENGTH_TYPE_MASK 0x03

/**
 * Maximal length of the OID in hex representation.
 *
 * \see RFC4880 bis01 - 9.2 ECC Curve OID
 */
#define MAX_CURVE_OID_HEX_LEN 9U

/* Maximum block size for symmetric crypto */
#define PGP_MAX_BLOCK_SIZE 16

/* Maximum key size for symmetric crypto */
#define PGP_MAX_KEY_SIZE 32

/* Salt size for hashing */
#define PGP_SALT_SIZE 8

/* Size of the fingerprint */
#define PGP_FINGERPRINT_SIZE 20

/* Maximum length of the packet header */
#define PGP_MAX_HEADER_SIZE 6

/* Nonce (IV) len for AEAD/EAX */
#define PGP_AEAD_EAX_NONCE_LEN 16

/* Maximum AEAD nonce length */
#define PGP_AEAD_MAX_NONCE_LEN 16

/* Authentication tag len for AEAD/EAX */
#define PGP_AEAD_EAX_TAG_LEN 16

/* Maximum AEAD tag length */
#define PGP_AEAD_MAX_TAG_LEN 16

/* Maximum authenticated data length for AEAD */
#define PGP_AEAD_MAX_AD_LEN 32

/** Old Packet Format Lengths.
 * Defines the meanings of the 2 bits for length type in the
 * old packet format.
 *
 * \see RFC4880 4.2.1
 */
typedef enum {
    PGP_PTAG_OLD_LEN_1 = 0x00,            /* Packet has a 1 byte length -
                                           * header is 2 bytes long. */
    PGP_PTAG_OLD_LEN_2 = 0x01,            /* Packet has a 2 byte length -
                                           * header is 3 bytes long. */
    PGP_PTAG_OLD_LEN_4 = 0x02,            /* Packet has a 4 byte
                                           * length - header is 5 bytes
                                           * long. */
    PGP_PTAG_OLD_LEN_INDETERMINATE = 0x03 /* Packet has a
                                           * indeterminate length. */
} pgp_ptag_of_lt_t;

/** New Packet Format: Mask for content tag.
 * In the new packet format the 6 rightmost bits
 * are the content tag.  This is the mask to apply
 * to the packet tag.  Note that you need to
 * shift by #PGP_PTAG_NF_CONTENT_TAG_SHIFT bits.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_NF_CONTENT_TAG_MASK 0x3f
/** New Packet Format: Offset for the content tag.
 * As described at #PGP_PTAG_NF_CONTENT_TAG_MASK the
 * content tag needs to be shifted after being masked
 * out from the Packet Tag.
 *
 * \see RFC4880 4.2
 */
#define PGP_PTAG_NF_CONTENT_TAG_SHIFT 0

#define MDC_PKT_TAG 0xd3
#define MDC_V1_SIZE 22

enum {
    PGP_REVOCATION_NO_REASON = 0,
    PGP_REVOCATION_SUPERSEDED = 1,
    PGP_REVOCATION_COMPROMISED = 2,
    PGP_REVOCATION_RETIRED = 3,
    PGP_REVOCATION_NO_LONGER_VALID = 0x20
};

/* PTag Content Tags */
/***************************/

/** Package Tags (aka Content Tags) and signature subpacket types.
 * This enumerates all rfc-defined packet tag values and the
 * signature subpacket type values that we understand.
 *
 * \see RFC4880 4.3
 * \see RFC4880 5.2.3.1
 */
typedef enum {
    PGP_PTAG_CT_RESERVED = 0,        /* Reserved - a packet tag must
                                      * not have this value */
    PGP_PTAG_CT_PK_SESSION_KEY = 1,  /* Public-Key Encrypted Session
                                      * Key Packet */
    PGP_PTAG_CT_SIGNATURE = 2,       /* Signature Packet */
    PGP_PTAG_CT_SK_SESSION_KEY = 3,  /* Symmetric-Key Encrypted Session
                                      * Key Packet */
    PGP_PTAG_CT_1_PASS_SIG = 4,      /* One-Pass Signature
                                      * Packet */
    PGP_PTAG_CT_SECRET_KEY = 5,      /* Secret Key Packet */
    PGP_PTAG_CT_PUBLIC_KEY = 6,      /* Public Key Packet */
    PGP_PTAG_CT_SECRET_SUBKEY = 7,   /* Secret Subkey Packet */
    PGP_PTAG_CT_COMPRESSED = 8,      /* Compressed Data Packet */
    PGP_PTAG_CT_SE_DATA = 9,         /* Symmetrically Encrypted Data Packet */
    PGP_PTAG_CT_MARKER = 10,         /* Marker Packet */
    PGP_PTAG_CT_LITDATA = 11,        /* Literal Data Packet */
    PGP_PTAG_CT_TRUST = 12,          /* Trust Packet */
    PGP_PTAG_CT_USER_ID = 13,        /* User ID Packet */
    PGP_PTAG_CT_PUBLIC_SUBKEY = 14,  /* Public Subkey Packet */
    PGP_PTAG_CT_RESERVED2 = 15,      /* reserved */
    PGP_PTAG_CT_RESERVED3 = 16,      /* reserved */
    PGP_PTAG_CT_USER_ATTR = 17,      /* User Attribute Packet */
    PGP_PTAG_CT_SE_IP_DATA = 18,     /* Sym. Encrypted and Integrity
                                      * Protected Data Packet */
    PGP_PTAG_CT_MDC = 19,            /* Modification Detection Code Packet */
    PGP_PTAG_CT_AEAD_ENCRYPTED = 20, /* AEAD Encrypted Data Packet, RFC 4880bis */

    PGP_PARSER_PTAG = 0x100, /* Internal Use: The packet is the "Packet
                              * Tag" itself - used when callback sends
                              * back the PTag. */
    PGP_PTAG_RAW_SS = 0x101, /* Internal Use: content is raw sig subtag */
    PGP_PTAG_SS_ALL = 0x102, /* Internal Use: select all subtags */
    PGP_PARSER_PACKET_END = 0x103,

    /* signature subpackets (0x200-2ff) (type+0x200) */
    PGP_PTAG_SIG_SUBPKT_BASE = 0x200,        /* Base for signature
                                              * subpacket types - All
                                              * signature type values
                                              * are relative to this
                                              * value. */
    PGP_PTAG_SS_CREATION_TIME = 0x200 + 2,   /* signature creation time */
    PGP_PTAG_SS_EXPIRATION_TIME = 0x200 + 3, /* signature
                                              * expiration time */

    PGP_PTAG_SS_EXPORT_CERT = 0x200 + 4,         /* exportable certification */
    PGP_PTAG_SS_TRUST = 0x200 + 5,               /* trust signature */
    PGP_PTAG_SS_REGEXP = 0x200 + 6,              /* regular expression */
    PGP_PTAG_SS_REVOCABLE = 0x200 + 7,           /* revocable */
    PGP_PTAG_SS_KEY_EXPIRY = 0x200 + 9,          /* key expiration
                                                  * time */
    PGP_PTAG_SS_RESERVED = 0x200 + 10,           /* reserved */
    PGP_PTAG_SS_PREFERRED_SKA = 0x200 + 11,      /* preferred symmetric
                                                  * algs */
    PGP_PTAG_SS_REVOCATION_KEY = 0x200 + 12,     /* revocation key */
    PGP_PTAG_SS_ISSUER_KEY_ID = 0x200 + 16,      /* issuer key ID */
    PGP_PTAG_SS_NOTATION_DATA = 0x200 + 20,      /* notation data */
    PGP_PTAG_SS_PREFERRED_HASH = 0x200 + 21,     /* preferred hash
                                                  * algs */
    PGP_PTAG_SS_PREF_COMPRESS = 0x200 + 22,      /* preferred
                                                  * compression
                                                  * algorithms */
    PGP_PTAG_SS_KEYSERV_PREFS = 0x200 + 23,      /* key server
                                                  * preferences */
    PGP_PTAG_SS_PREF_KEYSERV = 0x200 + 24,       /* Preferred Key
                                                  * Server */
    PGP_PTAG_SS_PRIMARY_USER_ID = 0x200 + 25,    /* primary User ID */
    PGP_PTAG_SS_POLICY_URI = 0x200 + 26,         /* Policy URI */
    PGP_PTAG_SS_KEY_FLAGS = 0x200 + 27,          /* key flags */
    PGP_PTAG_SS_SIGNERS_USER_ID = 0x200 + 28,    /* Signer's User ID */
    PGP_PTAG_SS_REVOCATION_REASON = 0x200 + 29,  /* reason for
                                                  * revocation */
    PGP_PTAG_SS_FEATURES = 0x200 + 30,           /* features */
    PGP_PTAG_SS_SIGNATURE_TARGET = 0x200 + 31,   /* signature target */
    PGP_PTAG_SS_EMBEDDED_SIGNATURE = 0x200 + 32, /* embedded signature */
    PGP_PTAG_SS_ISSUER_FPR = 0x200 + 33,

    PGP_PTAG_SS_USERDEFINED00 = 0x200 + 100, /* internal or
                                              * user-defined */
    PGP_PTAG_SS_USERDEFINED01 = 0x200 + 101,
    PGP_PTAG_SS_USERDEFINED02 = 0x200 + 102,
    PGP_PTAG_SS_USERDEFINED03 = 0x200 + 103,
    PGP_PTAG_SS_USERDEFINED04 = 0x200 + 104,
    PGP_PTAG_SS_USERDEFINED05 = 0x200 + 105,
    PGP_PTAG_SS_USERDEFINED06 = 0x200 + 106,
    PGP_PTAG_SS_USERDEFINED07 = 0x200 + 107,
    PGP_PTAG_SS_USERDEFINED08 = 0x200 + 108,
    PGP_PTAG_SS_USERDEFINED09 = 0x200 + 109,
    PGP_PTAG_SS_USERDEFINED10 = 0x200 + 110,

    /* pseudo content types */
    PGP_PTAG_CT_LITDATA_HEADER = 0x300,
    PGP_PTAG_CT_LITDATA_BODY = 0x300 + 1,
    PGP_PTAG_CT_SIGNATURE_HEADER = 0x300 + 2,
    PGP_PTAG_CT_SIGNATURE_FOOTER = 0x300 + 3,
    PGP_PTAG_CT_ARMOR_HEADER = 0x300 + 4,
    PGP_PTAG_CT_ARMOR_TRAILER = 0x300 + 5,
    PGP_PTAG_CT_SIGNED_CLEARTEXT_HEADER = 0x300 + 6,
    PGP_PTAG_CT_SIGNED_CLEARTEXT_BODY = 0x300 + 7,
    PGP_PTAG_CT_SIGNED_CLEARTEXT_TRAILER = 0x300 + 8,
    PGP_PTAG_CT_UNARMORED_TEXT = 0x300 + 9,
    PGP_PTAG_CT_SE_DATA_HEADER = 0x300 + 12,
    PGP_PTAG_CT_SE_DATA_BODY = 0x300 + 13,
    PGP_PTAG_CT_SE_IP_DATA_HEADER = 0x300 + 14,
    PGP_PTAG_CT_SE_IP_DATA_BODY = 0x300 + 15,
    PGP_PTAG_CT_ENCRYPTED_PK_SESSION_KEY = 0x300 + 16,

    /* commands to the callback */
    PGP_GET_PASSWORD = 0x400,
    PGP_GET_SECKEY = 0x400 + 1,

    /* Errors */
    PGP_PARSER_ERROR = 0x500,      /* Internal Use: Parser Error */
    PGP_PARSER_ERRCODE = 0x500 + 1 /* Internal Use: Parser Error
                                    * with errcode returned */
} pgp_content_enum;

/** Public Key Algorithm Numbers.
 * OpenPGP assigns a unique Algorithm Number to each algorithm that is part of OpenPGP.
 *
 * This lists algorithm numbers for public key algorithms.
 *
 * \see RFC4880 9.1
 */
typedef enum {
    PGP_PKA_NOTHING = 0,          /* No PKA */
    PGP_PKA_RSA = 1,              /* RSA (Encrypt or Sign) */
    PGP_PKA_RSA_ENCRYPT_ONLY = 2, /* RSA Encrypt-Only (deprecated -
                                   * \see RFC4880 13.5) */
    PGP_PKA_RSA_SIGN_ONLY = 3,    /* RSA Sign-Only (deprecated -
                                   * \see RFC4880 13.5) */
    PGP_PKA_ELGAMAL = 16,         /* Elgamal (Encrypt-Only) */
    PGP_PKA_DSA = 17,             /* DSA (Digital Signature Algorithm) */
    PGP_PKA_ECDH = 18,            /* ECDH public key algorithm */
    PGP_PKA_ECDSA = 19,           /* ECDSA public key algorithm [FIPS186-3] */
    PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN =
      20,                     /* Deprecated. Reserved (formerly Elgamal Encrypt or Sign) */
    PGP_PKA_RESERVED_DH = 21, /* Reserved for Diffie-Hellman
                               * (X9.42, as defined for
                               * IETF-S/MIME) */
    PGP_PKA_EDDSA = 22,       /* EdDSA from draft-ietf-openpgp-rfc4880bis */
    PGP_PKA_SM2 = 99,         /* SM2 encryption/signature schemes */

    PGP_PKA_PRIVATE00 = 100, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE01 = 101, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE02 = 102, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE03 = 103, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE04 = 104, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE05 = 105, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE06 = 106, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE07 = 107, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE08 = 108, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE09 = 109, /* Private/Experimental Algorithm */
    PGP_PKA_PRIVATE10 = 110  /* Private/Experimental Algorithm */
} pgp_pubkey_alg_t;

/**
 * Enumeration of elliptic curves used by PGP.
 *
 * \see RFC4880-bis01 9.2. ECC Curve OID
 *
 * Values in this enum correspond to order in ec_curve array (in ec.c)
 */
typedef enum {
    PGP_CURVE_UNKNOWN = 0,
    PGP_CURVE_NIST_P_256,
    PGP_CURVE_NIST_P_384,
    PGP_CURVE_NIST_P_521,
    PGP_CURVE_ED25519,

    PGP_CURVE_SM2_P_256,

    // Keep always last one
    PGP_CURVE_MAX
} pgp_curve_t;

/** Symmetric Key Algorithm Numbers.
 * OpenPGP assigns a unique Algorithm Number to each algorithm that is
 * part of OpenPGP.
 *
 * This lists algorithm numbers for symmetric key algorithms.
 *
 * \see RFC4880 9.2
 */
typedef enum {
    PGP_SA_PLAINTEXT = 0,     /* Plaintext or unencrypted data */
    PGP_SA_IDEA = 1,          /* IDEA */
    PGP_SA_TRIPLEDES = 2,     /* TripleDES */
    PGP_SA_CAST5 = 3,         /* CAST5 */
    PGP_SA_BLOWFISH = 4,      /* Blowfish */
    PGP_SA_AES_128 = 7,       /* AES with 128-bit key (AES) */
    PGP_SA_AES_192 = 8,       /* AES with 192-bit key */
    PGP_SA_AES_256 = 9,       /* AES with 256-bit key */
    PGP_SA_TWOFISH = 10,      /* Twofish with 256-bit key (TWOFISH) */
    PGP_SA_CAMELLIA_128 = 11, /* Camellia with 128-bit key (CAMELLIA) */
    PGP_SA_CAMELLIA_192 = 12, /* Camellia with 192-bit key */
    PGP_SA_CAMELLIA_256 = 13, /* Camellia with 256-bit key */

    PGP_SA_SM4 = 105, /* RNP extension - SM4 */
    PGP_SA_UNKNOWN = 255
} pgp_symm_alg_t;

typedef enum {
    PGP_CIPHER_MODE_NONE = 0,
    PGP_CIPHER_MODE_CFB = 1,
    PGP_CIPHER_MODE_CBC = 2,
    PGP_CIPHER_MODE_OCB = 3,
} pgp_cipher_mode_t;

typedef enum { PGP_AEAD_NONE = 0, PGP_AEAD_EAX = 1, PGP_AEAD_OCB = 2 } pgp_aead_alg_t;

/** s2k_usage_t
 */
typedef enum {
    PGP_S2KU_NONE = 0,
    PGP_S2KU_ENCRYPTED_AND_HASHED = 254,
    PGP_S2KU_ENCRYPTED = 255
} pgp_s2k_usage_t;

/** s2k_specifier_t
 */
typedef enum {
    PGP_S2KS_SIMPLE = 0,
    PGP_S2KS_SALTED = 1,
    PGP_S2KS_ITERATED_AND_SALTED = 3
} pgp_s2k_specifier_t;

/** Signature Type.
 * OpenPGP defines different signature types that allow giving
 * different meanings to signatures.  Signature types include 0x10 for
 * generitc User ID certifications (used when Ben signs Weasel's key),
 * Subkey binding signatures, document signatures, key revocations,
 * etc.
 *
 * Different types are used in different places, and most make only
 * sense in their intended location (for instance a subkey binding has
 * no place on a UserID).
 *
 * \see RFC4880 5.2.1
 */
typedef enum {
    PGP_SIG_BINARY = 0x00,     /* Signature of a binary document */
    PGP_SIG_TEXT = 0x01,       /* Signature of a canonical text document */
    PGP_SIG_STANDALONE = 0x02, /* Standalone signature */

    PGP_CERT_GENERIC = 0x10,  /* Generic certification of a User ID and
                               * Public Key packet */
    PGP_CERT_PERSONA = 0x11,  /* Persona certification of a User ID and
                               * Public Key packet */
    PGP_CERT_CASUAL = 0x12,   /* Casual certification of a User ID and
                               * Public Key packet */
    PGP_CERT_POSITIVE = 0x13, /* Positive certification of a
                               * User ID and Public Key packet */

    PGP_SIG_SUBKEY = 0x18,  /* Subkey Binding Signature */
    PGP_SIG_PRIMARY = 0x19, /* Primary Key Binding Signature */
    PGP_SIG_DIRECT = 0x1f,  /* Signature directly on a key */

    PGP_SIG_REV_KEY = 0x20,    /* Key revocation signature */
    PGP_SIG_REV_SUBKEY = 0x28, /* Subkey revocation signature */
    PGP_SIG_REV_CERT = 0x30,   /* Certification revocation signature */

    PGP_SIG_TIMESTAMP = 0x40, /* Timestamp signature */

    PGP_SIG_3RD_PARTY = 0x50 /* Third-Party Confirmation signature */
} pgp_sig_type_t;

/** Signature Subpacket Type
 * Signature subpackets contains additional information about the signature
 *
 * \see RFC4880 5.2.3.1-5.2.3.26
 */

typedef enum {
    PGP_SIG_SUBPKT_CREATION_TIME = 2,       /* signature creation time */
    PGP_SIG_SUBPKT_EXPIRATION_TIME = 3,     /* signature expiration time */
    PGP_SIG_SUBPKT_EXPORT_CERT = 4,         /* exportable certification */
    PGP_SIG_SUBPKT_TRUST = 5,               /* trust signature */
    PGP_SIG_SUBPKT_REGEXP = 6,              /* regular expression */
    PGP_SIG_SUBPKT_REVOCABLE = 7,           /* revocable */
    PGP_SIG_SUBPKT_KEY_EXPIRY = 9,          /* key expiration time */
    PGP_SIG_SUBPKT_RESERVED = 10,           /* reserved */
    PGP_SIG_SUBPKT_PREFERRED_SKA = 11,      /* preferred symmetric algs */
    PGP_SIG_SUBPKT_REVOCATION_KEY = 12,     /* revocation key */
    PGP_SIG_SUBPKT_ISSUER_KEY_ID = 16,      /* issuer key ID */
    PGP_SIG_SUBPKT_NOTATION_DATA = 20,      /* notation data */
    PGP_SIG_SUBPKT_PREFERRED_HASH = 21,     /* preferred hash algs */
    PGP_SIG_SUBPKT_PREF_COMPRESS = 22,      /* preferred compression algorithms */
    PGP_SIG_SUBPKT_KEYSERV_PREFS = 23,      /* key server preferences */
    PGP_SIG_SUBPKT_PREF_KEYSERV = 24,       /* preferred key Server */
    PGP_SIG_SUBPKT_PRIMARY_USER_ID = 25,    /* primary user ID */
    PGP_SIG_SUBPKT_POLICY_URI = 26,         /* policy URI */
    PGP_SIG_SUBPKT_KEY_FLAGS = 27,          /* key flags */
    PGP_SIG_SUBPKT_SIGNERS_USER_ID = 28,    /* signer's user ID */
    PGP_SIG_SUBPKT_REVOCATION_REASON = 29,  /* reason for revocation */
    PGP_SIG_SUBPKT_FEATURES = 30,           /* features */
    PGP_SIG_SUBPKT_SIGNATURE_TARGET = 31,   /* signature target */
    PGP_SIG_SUBPKT_EMBEDDED_SIGNATURE = 32, /* embedded signature */
    PGP_SIG_SUBPKT_ISSUER_FPR = 33,         /* issuer fingerprint */
    PGP_SIG_SUBPKT_PREFERRED_AEAD = 34      /* preferred AEAD algorithms */
} pgp_sig_subpacket_type_t;

/** Key Flags
 *
 * \see RFC4880 5.2.3.21
 */
typedef enum {
    PGP_KF_CERTIFY = 0x01,         /* This key may be used to certify other keys. */
    PGP_KF_SIGN = 0x02,            /* This key may be used to sign data. */
    PGP_KF_ENCRYPT_COMMS = 0x04,   /* This key may be used to encrypt communications. */
    PGP_KF_ENCRYPT_STORAGE = 0x08, /* This key may be used to encrypt storage. */
    PGP_KF_SPLIT = 0x10,           /* The private component of this key may have been split
                                            by a secret-sharing mechanism. */
    PGP_KF_AUTH = 0x20,            /* This key may be used for authentication. */
    PGP_KF_SHARED = 0x80,          /* The private component of this key may be in the
                                            possession of more than one person. */
    /* pseudo flags */
    PGP_KF_NONE = 0x00,
    PGP_KF_ENCRYPT = PGP_KF_ENCRYPT_COMMS | PGP_KF_ENCRYPT_STORAGE,
} pgp_key_flags_t;

/** Types of Compression */
typedef enum {
    PGP_C_NONE = 0,
    PGP_C_ZIP = 1,
    PGP_C_ZLIB = 2,
    PGP_C_BZIP2 = 3,
    PGP_C_UNKNOWN = 255
} pgp_compression_type_t;

enum { PGP_SE_IP_DATA_VERSION = 1, PGP_PKSK_V3 = 3, PGP_SKSK_V4 = 4, PGP_SKSK_V5 = 5 };

/** Version.
 * OpenPGP has two different protocol versions: version 3 and version 4.
 *
 * \see RFC4880 5.2
 */
typedef enum {
    PGP_V2 = 2, /* Version 2 (essentially the same as v3) */
    PGP_V3 = 3, /* Version 3 */
    PGP_V4 = 4  /* Version 4 */
} pgp_version_t;

typedef enum pgp_op_t {
    PGP_OP_UNKNOWN = 0,
    PGP_OP_ADD_SUBKEY = 1,  /* adding a subkey, primary key password required */
    PGP_OP_SIGN = 2,        /* signing file or data */
    PGP_OP_DECRYPT = 3,     /* decrypting file or data */
    PGP_OP_UNLOCK = 4,      /* unlocking a key with pgp_key_unlock */
    PGP_OP_PROTECT = 5,     /* adding protection to a key */
    PGP_OP_UNPROTECT = 6,   /* removing protection from a (locked) key */
    PGP_OP_DECRYPT_SYM = 7, /* symmetric decryption */
    PGP_OP_ENCRYPT_SYM = 8, /* symmetric encryption */
    PGP_OP_VERIFY = 9       /* signature verification */
} pgp_op_t;

/** Hashing Algorithm Numbers.
 * OpenPGP assigns a unique Algorithm Number to each algorithm that is
 * part of OpenPGP.
 *
 * This lists algorithm numbers for hash algorithms.
 *
 * \see RFC4880 9.4
 */
typedef enum {
    PGP_HASH_UNKNOWN = 0, /* used to indicate errors */
    PGP_HASH_MD5 = 1,     /* MD5 */
    PGP_HASH_SHA1 = 2,    /* SHA-1 */
    PGP_HASH_RIPEMD = 3,  /* RIPEMD160 */

    PGP_HASH_SHA256 = 8,  /* SHA256 */
    PGP_HASH_SHA384 = 9,  /* SHA384 */
    PGP_HASH_SHA512 = 10, /* SHA512 */
    PGP_HASH_SHA224 = 11, /* SHA224 */

    /* Private range */
    PGP_HASH_SM3 = 105,  /* SM3 */
    PGP_HASH_CRC24 = 106 /* CRC24 */
} pgp_hash_alg_t;

#endif
