#ifndef __RNP_REPGP_DEF__
#define __RNP_REPGP_DEF__

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
    PGP_PTAG_CT_RESERVED = 0,       /* Reserved - a packet tag must
                                     * not have this value */
    PGP_PTAG_CT_PK_SESSION_KEY = 1, /* Public-Key Encrypted Session
                                     * Key Packet */
    PGP_PTAG_CT_SIGNATURE = 2,      /* Signature Packet */
    PGP_PTAG_CT_SK_SESSION_KEY = 3, /* Symmetric-Key Encrypted Session
                                     * Key Packet */
    PGP_PTAG_CT_1_PASS_SIG = 4,     /* One-Pass Signature
                                     * Packet */
    PGP_PTAG_CT_SECRET_KEY = 5,     /* Secret Key Packet */
    PGP_PTAG_CT_PUBLIC_KEY = 6,     /* Public Key Packet */
    PGP_PTAG_CT_SECRET_SUBKEY = 7,  /* Secret Subkey Packet */
    PGP_PTAG_CT_COMPRESSED = 8,     /* Compressed Data Packet */
    PGP_PTAG_CT_SE_DATA = 9,        /* Symmetrically Encrypted Data Packet */
    PGP_PTAG_CT_MARKER = 10,        /* Marker Packet */
    PGP_PTAG_CT_LITDATA = 11,       /* Literal Data Packet */
    PGP_PTAG_CT_TRUST = 12,         /* Trust Packet */
    PGP_PTAG_CT_USER_ID = 13,       /* User ID Packet */
    PGP_PTAG_CT_PUBLIC_SUBKEY = 14, /* Public Subkey Packet */
    PGP_PTAG_CT_RESERVED2 = 15,     /* reserved */
    PGP_PTAG_CT_RESERVED3 = 16,     /* reserved */
    PGP_PTAG_CT_USER_ATTR = 17,     /* User Attribute Packet */
    PGP_PTAG_CT_SE_IP_DATA = 18,    /* Sym. Encrypted and Integrity
                                     * Protected Data Packet */
    PGP_PTAG_CT_MDC = 19,           /* Modification Detection Code Packet */

    PGP_PARSER_PTAG = 0x100, /* Internal Use: The packet is the "Packet
                              * Tag" itself - used when callback sends
                              * back the PTag. */
    PGP_PTAG_RAW_SS = 0x101, /* Internal Use: content is raw sig subtag */
    PGP_PTAG_SS_ALL = 0x102, /* Internal Use: select all subtags */
    PGP_PARSER_PACKET_END = 0x103,

    /* signature subpackets (0x200-2ff) (type+0x200) */
    /* only those we can parse are listed here */
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
    PGP_PTAG_CT_ARMOUR_HEADER = 0x300 + 4,
    PGP_PTAG_CT_ARMOUR_TRAILER = 0x300 + 5,
    PGP_PTAG_CT_SIGNED_CLEARTEXT_HEADER = 0x300 + 6,
    PGP_PTAG_CT_SIGNED_CLEARTEXT_BODY = 0x300 + 7,
    PGP_PTAG_CT_SIGNED_CLEARTEXT_TRAILER = 0x300 + 8,
    PGP_PTAG_CT_UNARMOURED_TEXT = 0x300 + 9,
    PGP_PTAG_CT_ENCRYPTED_SECRET_KEY = 0x300 + 10, /* In this case the
                                                    * algorithm specific
                                                    * fields will not be
                                                    * initialised */
    PGP_PTAG_CT_ENCRYPTED_SECRET_SUBKEY = 0x300 + 11,
    PGP_PTAG_CT_SE_DATA_HEADER = 0x300 + 12,
    PGP_PTAG_CT_SE_DATA_BODY = 0x300 + 13,
    PGP_PTAG_CT_SE_IP_DATA_HEADER = 0x300 + 14,
    PGP_PTAG_CT_SE_IP_DATA_BODY = 0x300 + 15,
    PGP_PTAG_CT_ENCRYPTED_PK_SESSION_KEY = 0x300 + 16,

    /* commands to the callback */
    PGP_GET_PASSPHRASE = 0x400,
    PGP_GET_SECKEY = 0x400 + 1,

    /* Errors */
    PGP_PARSER_ERROR = 0x500,      /* Internal Use: Parser Error */
    PGP_PARSER_ERRCODE = 0x500 + 1 /* Internal Use: Parser Error
                                    * with errcode returned */
} pgp_content_enum;

#endif