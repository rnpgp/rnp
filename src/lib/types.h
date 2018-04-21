/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009 The NetBSD Foundation, Inc.
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
/*
 * Copyright (c) 2005-2008 Nominet UK (www.nic.uk)
 * All rights reserved.
 * Contributors: Ben Laurie, Rachel Willmer. The Contributors have asserted
 * their moral rights under the UK Copyright Design and Patents Act 1988 to
 * be recorded as the authors of this copyright work.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef TYPES_H_
#define TYPES_H_

#include <stdint.h>
#include <rnp/rnp_def.h>
#include "memory.h"
#include "defs.h"
#include "errors.h"
#include "memory.h"
#include "list.h"
#include "crypto/common.h"

#define PGP_KEY_ID_SIZE 8
#define PGP_FINGERPRINT_HEX_SIZE (PGP_FINGERPRINT_SIZE * 3) + 1

/* SHA1 Hash Size */
#define PGP_SHA1_HASH_SIZE 20
#define PGP_CHECKHASH_SIZE PGP_SHA1_HASH_SIZE

/* Maximum AEAD tag length */
#define PGP_AEAD_MAX_TAG_LEN 16

/* Maximum authenticated data length for AEAD */
#define PGP_AEAD_MAX_AD_LEN 32

/* Maximum length of the packet header */
#define PGP_MAX_HEADER_SIZE 6

/** General-use structure for variable-length data
 */

typedef struct {
    size_t   len;
    uint8_t *contents;
    uint8_t  mmapped; /* contents need an munmap(2) */
} pgp_data_t;

typedef struct pgp_io_t {
    FILE *outs; /* output file stream */
    FILE *errs; /* file stream to put error messages */
    FILE *res;  /* file stream to put results */
} pgp_io_t;

/** pgp_map_t
 */
typedef struct {
    int         type;
    const char *string;
} pgp_map_t;

/** pgp_errcode_name_map_t */
typedef pgp_map_t pgp_errcode_name_map_t;

typedef struct pgp_crypt_t pgp_crypt_t;

/** pgp_hash_t */
typedef struct pgp_hash_t pgp_hash_t;

/** Revocation Reason type */
typedef uint8_t pgp_ss_rr_code_t;

/** pgp_packet_t */
typedef struct pgp_packet_t pgp_packet_t;

/** Writer flags */
typedef enum { PGP_WF_DUMMY } pgp_writer_flags_t;

/**
 * \ingroup Create
 * Contains the required information about how to write
 */
typedef struct pgp_output_t pgp_output_t;

/** Structure to hold one error code */
typedef struct {
    pgp_errcode_t errcode;
} pgp_parser_errcode_t;

/** pgp_fingerprint_t */
typedef struct pgp_fingerprint_t {
    uint8_t  fingerprint[PGP_FINGERPRINT_SIZE];
    unsigned length;
} pgp_fingerprint_t;

/** Structure to hold one packet tag.
 * \see RFC4880 4.2
 */
typedef struct {
    unsigned new_format;            /* Whether this packet tag is new
                                     * (1) or old format (0) */
    unsigned type;                  /* content_tag value - See
                                     * #pgp_content_enum for meanings */
    pgp_ptag_of_lt_t length_type;   /* Length type (#pgp_ptag_of_lt_t)
                                     * - only if this packet tag is old
                                     * format.  Set to 0 if new format. */
    unsigned length; /* The length of the packet.  This value
                 * is set when we read and compute the length
                 * information, not at the same moment we
                 * create the packet tag structure. Only
     * defined if #readc is set. */ /* XXX: Ben, is this correct? */
    unsigned position;              /* The position (within the
                                     * current reader) of the packet */
    unsigned size;                  /* number of bits */
} pgp_ptag_t;

/**
 * Type to keep public/secret key mpis without any openpgp-dependent data.
 */
typedef struct pgp_key_material_t {
    pgp_pubkey_alg_t alg;    /* algorithm of the key */
    bool             secret; /* secret part of the key material is populated */

    union {
        pgp_rsa_key_t rsa;
        pgp_dsa_key_t dsa;
        pgp_eg_key_t  eg;
        pgp_ec_key_t  ecc;
    };
} pgp_key_material_t;

/**
 * Type to keep signature without any openpgp-dependent data.
 */
typedef struct pgp_signature_material_t {
    union {
        pgp_rsa_signature_t rsa;
        pgp_dsa_signature_t dsa;
        pgp_ec_signature_t  ecc;
        pgp_eg_signature_t  eg;
    };
} pgp_signature_material_t;

/**
 * Type to keep pk-encrypted data without any openpgp-dependent data.
 */
typedef struct pgp_encrypted_material_t {
    union {
        pgp_rsa_encrypted_t  rsa;
        pgp_eg_encrypted_t   eg;
        pgp_sm2_encrypted_t  sm2;
        pgp_ecdh_encrypted_t ecdh;
    };
} pgp_encrypted_material_t;

/** Structure to hold a pgp public key */
typedef struct pgp_pubkey_t {
    pgp_version_t version; /* version of the key (v3, v4...) */
    time_t        creation;
    time_t        expiration; /* v4 expiration time (not always set, see SS_KEY_EXPIRY) */
    /* validity period of the key in days since
     * creation.  A value of 0 has a special meaning
     * indicating this key does not expire.  Only used with
     * v3 keys.  */
    unsigned         days_valid; /* v3 validity time */
    pgp_pubkey_alg_t alg;        /* Public Key Algorithm type */
    union {
        pgp_dsa_key_t        dsa;     /* A DSA key */
        pgp_rsa_pubkey_t     rsa;     /* An RSA public key */
        pgp_elgamal_pubkey_t elgamal; /* An ElGamal public key */
        /*TODO: This field is common to ECC signing algorithms only. Change it to ec_sign*/
        pgp_ecc_pubkey_t  ecc;  /* An ECC public key */
        pgp_ecdh_pubkey_t ecdh; /* Public Key Parameters for ECDH */
    } key;                      /* Public Key Parameters */
} pgp_pubkey_t;

typedef struct pgp_key_t pgp_key_t;

typedef struct pgp_s2k_t {
    pgp_s2k_usage_t usage;

    /* below fields may not all be valid, depending on the usage field above */
    pgp_s2k_specifier_t specifier;
    pgp_hash_alg_t      hash_alg;
    uint8_t             salt[PGP_SALT_SIZE];
    unsigned            iterations;
} pgp_s2k_t;

typedef struct pgp_key_protection_t {
    pgp_s2k_t         s2k;         /* string-to-key kdf params */
    pgp_symm_alg_t    symm_alg;    /* symmetric alg */
    pgp_cipher_mode_t cipher_mode; /* block cipher mode */
    uint8_t           iv[PGP_MAX_BLOCK_SIZE];
} pgp_key_protection_t;

/** pgp_seckey_t
 */
typedef struct pgp_seckey_t {
    /* Note: Keep this as the first field. */
    pgp_pubkey_t pubkey; /* public key */

    pgp_key_protection_t protection;

    /* This indicates the current state of the key union below.
     * If false, the key union contains valid secret key material
     * and is immediately available for operations.
     * If true, the key union does not contain any valid secret
     * key material and must be decrypted prior to use.
     */
    bool encrypted;

    /*************************************************************
     * Note: Consider all fields below to be invalid/unpopulated *
     * unless this seckey has been decrypted.                    *
     *************************************************************/
    union {
        pgp_rsa_seckey_t     rsa;
        pgp_elgamal_seckey_t elgamal;
        pgp_ecc_seckey_t     ecc;
    } key;

    unsigned checksum;
    uint8_t  checkhash[PGP_CHECKHASH_SIZE];
} pgp_seckey_t;

/** Struct to hold a key packet. May contain public or private key/subkey */
typedef struct pgp_key_pkt_t {
    int              tag;           /* packet tag: public key/subkey or private key/subkey */
    pgp_version_t    version;       /* Key packet version */
    uint32_t         creation_time; /* Key creation time */
    pgp_pubkey_alg_t alg;
    uint16_t         v3_days; /* v2/v3 validity time */

    uint8_t *hashed_data; /* key's hashed data used for signature calculation */
    size_t   hashed_len;

    pgp_key_material_t material;

    /* secret key data, if available. sec_len == 0, sec_data == NULL for public key/subkey */
    pgp_key_protection_t sec_protection;
    uint8_t *            sec_data;
    size_t               sec_len;
} pgp_key_pkt_t;

/** Struct to hold userid or userattr packet. We don't parse userattr now, just storing the
 *  binary blob as it is. It may be distinguished by tag field.
 */
typedef struct pgp_userid_pkt_t {
    int      tag;
    uint8_t *uid;
    size_t   uid_len;
} pgp_userid_pkt_t;

/** Struct to hold a signature packet.
 *
 * \see RFC4880 5.2.2
 * \see RFC4880 5.2.3
 */
typedef struct pgp_sig_info_t {
    pgp_version_t  version; /* signature version number */
    pgp_sig_type_t type;    /* signature type value */

    /* **Note**: the following 3 fields are only valid if
     * their corresponding bitfields are 1 (see below). */
    time_t  creation;                   /* creation time of the signature */
    time_t  expiration;                 /* number of seconds it's valid for */
    uint8_t signer_id[PGP_KEY_ID_SIZE]; /* Eight-octet key ID
                                         * of signer */
    pgp_fingerprint_t signer_fpr;       /* signer fingerprint (length is 0 if not set) */
    pgp_pubkey_alg_t  key_alg;          /* public key algorithm number */
    pgp_hash_alg_t    hash_alg;         /* hashing algorithm number */
    union {
        pgp_rsa_sig_t       rsa;     /* An RSA Signature */
        pgp_dsa_signature_t dsa;     /* A DSA Signature */
        pgp_elgamal_sig_t   elgamal; /* deprecated */
        pgp_ecc_sig_t       ecc;     /* An ECC signature - ECDSA, SM2, or EdDSA */
        pgp_data_t          unknown; /* private or experimental */
    } sig;                           /* signature params */
    size_t   v4_hashlen;
    uint8_t *v4_hashed;

    /* These are here because:
     *   creation_set
     *   - v3 sig pkts have an explicit creation time field
     *   - v4 sig pkts MAY specify the creation time via a sigsubpkt
     *   expiration_set
     *   - v3 sig pkts have no expiration
     *   - v4 sig pkts MAY have an expiration via a sigsubpkt
     *   signer_id_set
     *   - v3 sig pkts have an explicit signer id field
     *   - v4 sig pkts MAY specify the signer id via a sigsubpkt
     */
    unsigned creation_set : 1;
    unsigned signer_id_set : 1;
    unsigned expiration_set : 1;
} pgp_sig_info_t;

/** Struct used when parsing a signature */
typedef struct pgp_sig_t {
    pgp_sig_info_t info; /* The signature information */
    /* The following fields are only used while parsing the signature */
    uint8_t     hash2[2];     /* high 2 bytes of hashed value */
    size_t      v4_hashstart; /* only valid if accumulate is set */
    pgp_hash_t *hash;         /* the hash filled in for the data so far */
} pgp_sig_t;

/* Signature subpacket, see 5.2.3.1 in RFC 4880 and RFC 4880 bis 02 */
typedef struct pgp_sig_subpkt_t {
    pgp_sig_subpacket_type_t type;         /* type of the subpacket */
    unsigned                 len;          /* length of the data */
    uint8_t *                data;         /* raw subpacket data, excluding the header */
    unsigned                 critical : 1; /* critical flag */
    unsigned                 hashed : 1;   /* whether subpacket is hashed or not */
    unsigned                 parsed : 1;   /* whether subpacket was successfully parsed */
    union {
        uint32_t create; /* 5.2.3.4.   Signature Creation Time */
        uint32_t expiry; /* 5.2.3.6.   Key Expiration Time */
                         /* 5.2.3.10.  Signature Expiration Time */
        bool exportable; /* 5.2.3.11.  Exportable Certification */
        struct {
            uint8_t level;
            uint8_t amount;
        } trust; /* 5.2.3.13.  Trust Signature */
        struct {
            const char *str;
            unsigned    len;
        } regexp;       /* 5.2.3.14.  Regular Expression */
        bool revocable; /* 5.2.3.12.  Revocable */
        struct {
            uint8_t *arr;
            unsigned len;
        } preferred; /* 5.2.3.7.  Preferred Symmetric Algorithms */
                     /* 5.2.3.8.  Preferred Hash Algorithms */
                     /* 5.2.3.9.  Preferred Compression Algorithms */
        struct {
            uint8_t class;
            pgp_pubkey_alg_t pkalg;
            uint8_t *        fp;
        } revocation_key; /* 5.2.3.15.  Revocation Key */
        uint8_t *issuer;  /* 5.2.3.5.   Issuer */
        struct {
            uint8_t     flags[4];
            unsigned    nlen;
            unsigned    vlen;
            const char *name;
            const char *value;
        } notation; /* 5.2.3.16.  Notation Data */
        struct {
            bool no_modify;
        } ks_prefs; /* 5.2.3.17.  Key Server Preferences */
        struct {
            const char *uri;
            unsigned    len;
        } preferred_ks;   /* 5.2.3.18.  Preferred Key Server */
        bool primary_uid; /* 5.2.3.19.  Primary User ID */
        struct {
            const char *uri;
            unsigned    len;
        } policy;          /* 5.2.3.20.  Policy URI */
        uint8_t key_flags; /* 5.2.3.21.  Key Flags */
        struct {
            const char *uid;
            unsigned    len;
        } signer; /* 5.2.3.22.  Signer's User ID */
        struct {
            uint8_t     code;
            const char *str;
            unsigned    len;
        } revocation_reason; /* 5.2.3.23.  Reason for Revocation */
        struct {
            bool mdc;
            bool aead;
            bool key_v5;
        } features; /* 5.2.3.24.  Features */
        struct {
            pgp_pubkey_alg_t pkalg;
            pgp_hash_alg_t   halg;
            uint8_t *        hash;
            unsigned         hlen;
        } sig_target; /* 5.2.3.25.  Signature Target */
        struct {
            uint8_t  version;
            uint8_t *fp;
            unsigned len;
        } issuer_fp; /* 5.2.3.27.  Issuer Fingerprint, RFC 4880 bis 02 */
    } fields;        /* parsed contents of the subpacket */
} pgp_sig_subpkt_t;

typedef struct pgp_signature_t {
    pgp_version_t version;
    /* common v3 and v4 fields */
    pgp_sig_type_t   type;
    pgp_pubkey_alg_t palg;
    pgp_hash_alg_t   halg;
    uint8_t          lbits[2];
    uint8_t *        hashed_data;
    size_t           hashed_len;

    pgp_signature_material_t material;

    /* v3 - only fields */
    uint32_t creation_time;
    uint8_t  signer[PGP_KEY_ID_SIZE];

    /* v4 - only fields */
    list subpkts;
} pgp_signature_t;

/** The raw bytes of a signature subpacket */

typedef struct pgp_ss_raw_t {
    pgp_content_enum tag;
    size_t           length;
    uint8_t *        raw;
} pgp_ss_raw_t;

/** Signature Subpacket : Trust Level */

typedef struct pgp_ss_trust_t {
    uint8_t level;  /* Trust Level */
    uint8_t amount; /* Amount */
} pgp_ss_trust_t;

/** Signature Subpacket : Notation Data */
typedef struct pgp_ss_notation_t {
    pgp_data_t flags;
    pgp_data_t name;
    pgp_data_t value;
} pgp_ss_notation_t;

/** Signature Subpacket : Signature Target */
typedef struct pgp_ss_sig_target_t {
    pgp_pubkey_alg_t pka_alg;
    pgp_hash_alg_t   hash_alg;
    pgp_data_t       hash;
} pgp_ss_sig_target_t;

/** pgp_rawpacket_t */
typedef struct pgp_rawpacket_t {
    pgp_content_enum tag;
    size_t           length;
    uint8_t *        raw;
} pgp_rawpacket_t;

typedef enum {
    /* first octet */
    PGP_KEY_SERVER_NO_MODIFY = 0x80
} pgp_key_server_prefs_t;

/** pgp_one_pass_sig_t */
typedef struct pgp_one_pass_sig_t {
    uint8_t          version;
    pgp_sig_type_t   type;
    pgp_hash_alg_t   halg;
    pgp_pubkey_alg_t palg;
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    unsigned         nested;
} pgp_one_pass_sig_t;

typedef struct pgp_literal_hdr_t {
    uint8_t  format;
    char     fname[256];
    uint8_t  fname_len;
    uint32_t timestamp;
} pgp_literal_hdr_t;

/** Signature Subpacket : Revocation Key */
typedef struct {
    uint8_t class;
    uint8_t algid;
    uint8_t fingerprint[PGP_FINGERPRINT_SIZE];
} pgp_ss_revocation_key_t;

/** Signature Subpacket : Revocation Reason */
typedef struct {
    uint8_t code;
    char *  reason;
} pgp_ss_revocation_t;

/** litdata_type_t */
typedef enum {
    PGP_LDT_BINARY = 'b',
    PGP_LDT_TEXT = 't',
    PGP_LDT_UTF8 = 'u',
    PGP_LDT_LOCAL = 'l',
    PGP_LDT_LOCAL2 = '1'
} pgp_litdata_enum;

/** pgp_header_var_t */
typedef struct {
    char *key;
    char *value;
} pgp_header_var_t;

/** pgp_headers_t */
typedef struct {
    pgp_header_var_t *headers;
    unsigned          headerc;
} pgp_headers_t;

/** pgp_armor_header_t */
typedef struct {
    const char *  type;
    pgp_headers_t headers;
} pgp_armor_header_t;

/** pgp_fixed_body_t */
typedef struct pgp_fixed_body_t {
    unsigned length;
    uint8_t  data[8192]; /* \todo fix hard-coded value? */
} pgp_fixed_body_t;

/** pgp_dyn_body_t */
typedef struct pgp_dyn_body_t {
    unsigned length;
    uint8_t *data;
} pgp_dyn_body_t;

/** public-key encrypted session key packet */
typedef struct pgp_pk_sesskey_t {
    unsigned         version;
    uint8_t          key_id[PGP_KEY_ID_SIZE];
    pgp_pubkey_alg_t alg;

    pgp_encrypted_material_t material;
} pgp_pk_sesskey_t;

/** pkp_sk_sesskey_t */
typedef struct {
    unsigned       version;
    pgp_symm_alg_t alg;
    pgp_s2k_t      s2k;
    uint8_t        enckey[PGP_MAX_KEY_SIZE + PGP_AEAD_MAX_TAG_LEN + 1];
    unsigned       enckeylen;
    /* v5 specific fields */
    pgp_aead_alg_t aalg;
    uint8_t        iv[PGP_MAX_BLOCK_SIZE];
    unsigned       ivlen;
} pgp_sk_sesskey_t;

/** pgp_seckey_password_t */
typedef struct {
    const pgp_seckey_t *seckey;
    char **             password; /* point somewhere that gets filled
                                   * in to work around constness of
                                   * content */
} pgp_seckey_password_t;

/** pgp_parser_union_content_t */
typedef union {
    const char *            error;
    pgp_parser_errcode_t    errcode;
    pgp_ptag_t              ptag;
    pgp_pubkey_t            pubkey;
    pgp_data_t              trust;
    uint8_t *               userid;
    pgp_data_t              userattr;
    pgp_sig_t               sig;
    pgp_ss_raw_t            ss_raw;
    pgp_ss_trust_t          ss_trust;
    unsigned                ss_revocable;
    time_t                  ss_time;
    uint8_t                 ss_issuer[PGP_KEY_ID_SIZE];
    pgp_ss_notation_t       ss_notation;
    pgp_rawpacket_t         packet;
    pgp_data_t              ss_skapref;
    pgp_data_t              ss_hashpref;
    pgp_data_t              ss_zpref;
    pgp_data_t              ss_key_flags;
    pgp_data_t              ss_key_server_prefs;
    unsigned                ss_primary_userid;
    char *                  ss_regexp;
    char *                  ss_policy;
    char *                  ss_keyserv;
    pgp_ss_revocation_key_t ss_revocation_key;
    pgp_data_t              ss_userdef;
    pgp_data_t              ss_unknown;
    pgp_data_t              ss_features;
    pgp_ss_sig_target_t     ss_sig_target;
    pgp_data_t              ss_embedded_sig;
    pgp_data_t              ss_issuer_fpr;
    pgp_ss_revocation_t     ss_revocation;
    pgp_seckey_t            seckey;
    uint8_t *               ss_signer;
    pgp_armor_header_t      armor_header;
    const char *            armor_trailer;
    pgp_dyn_body_t          unarmored_text;
    pgp_seckey_password_t   skey_password;
} pgp_contents_t;

/** pgp_packet_t */
struct pgp_packet_t {
    pgp_content_enum tag;      /* type of contents */
    uint8_t          critical; /* for sig subpackets */
    pgp_contents_t   u;        /* union for contents */
};

/** pgp_keydata_key_t
 */
typedef union {
    pgp_pubkey_t pubkey;
    pgp_seckey_t seckey;
} pgp_keydata_key_t;

/* sigpacket_t */
typedef struct sigpacket_t {
    uint8_t **       userid;
    pgp_rawpacket_t *packet;
} sigpacket_t;

/* user revocation info */
typedef struct pgp_revoke_t {
    uint32_t uid;    /* index in uid array */
    uint8_t  code;   /* revocation code */
    char *   reason; /* c'mon, spill the beans */
} pgp_revoke_t;

typedef struct pgp_user_prefs_t {
    // preferred symmetric algs (pgp_symm_alg_t)
    DYNARRAY(uint8_t, symm_alg);
    // preferred hash algs (pgp_hash_alg_t)
    DYNARRAY(uint8_t, hash_alg);
    // preferred compression algs (pgp_compression_type_t)
    DYNARRAY(uint8_t, compress_alg);
    // key server preferences (pgp_key_server_prefs_t)
    DYNARRAY(uint8_t, key_server_pref);
    // preferred key server
    uint8_t *key_server;
} pgp_user_prefs_t;

/** signature subpackets */
typedef struct pgp_subsig_t {
    uint32_t         uid;         /* index in userid array in key */
    pgp_sig_t        sig;         /* trust signature */
    uint8_t          trustlevel;  /* level of trust */
    uint8_t          trustamount; /* amount of trust */
    uint8_t          key_flags;   /* key flags */
    pgp_user_prefs_t prefs;       /* user preferences */
} pgp_subsig_t;

/* structure used to hold context of key generation */
typedef struct rnp_keygen_crypto_params_t {
    // Asymmteric algorithm that user requesed key for
    pgp_pubkey_alg_t key_alg;
    // Hash to be used for key signature
    pgp_hash_alg_t hash_alg;
    // Pointer to initialized RNG engine
    rng_t *rng;
    union {
        struct ecc_t {
            pgp_curve_t curve;
        } ecc;
        struct rsa_t {
            uint32_t modulus_bit_len;
        } rsa;
        struct dsa_t {
            size_t p_bitlen;
            size_t q_bitlen;
        } dsa;
        struct elgamal_t {
            size_t key_bitlen;
        } elgamal;
    };
} rnp_keygen_crypto_params_t;

typedef struct rnp_selfsig_cert_info {
    uint8_t          userid[MAX_ID_LENGTH]; /* userid, required */
    uint8_t          key_flags;             /* key flags */
    uint32_t         key_expiration;        /* key expiration time (sec), 0 = no expiration */
    pgp_user_prefs_t prefs;                 /* user preferences, optional */
    unsigned         primary : 1;           /* mark this as the primary user id */
} rnp_selfsig_cert_info;

typedef struct rnp_selfsig_binding_info {
    uint8_t  key_flags;
    uint32_t key_expiration;
} rnp_selfsig_binding_info;

typedef struct rnp_keygen_primary_desc_t {
    rnp_keygen_crypto_params_t crypto;
    rnp_selfsig_cert_info      cert;
} rnp_keygen_primary_desc_t;

typedef struct rnp_keygen_subkey_desc_t {
    rnp_keygen_crypto_params_t crypto;
    rnp_selfsig_binding_info   binding;
} rnp_keygen_subkey_desc_t;

typedef struct rnp_key_protection_params_t {
    pgp_symm_alg_t    symm_alg;
    pgp_cipher_mode_t cipher_mode;
    unsigned          iterations;
    pgp_hash_alg_t    hash_alg;
} rnp_key_protection_params_t;

#endif /* TYPES_H_ */
