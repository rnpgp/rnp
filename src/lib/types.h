/*
 * Copyright (c) 2017-2021, [Ribose Inc](https://www.ribose.com).
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
#include <string>
#include <vector>
#include <array>
#include <cstring>
#include <type_traits>

#include <rnp/rnp_def.h>
#include "crypto/common.h"
#include "sec_profile.hpp"

/* SHA1 Hash Size */
#define PGP_SHA1_HASH_SIZE 20

/* Maximum length of the packet header */
#define PGP_MAX_HEADER_SIZE 6

/* Maximum supported userid length */
#define MAX_ID_LENGTH 128

/* Maximum supported password length */
#define MAX_PASSWORD_LENGTH 256

class id_str_pair {
  public:
    int         id;
    const char *str;

    /**
     * @brief Lookup constant pair array for the specified id or string value.
     *        Note: array must be finished with NULL string to stop the lookup.
     *
     * @param pair pointer to the const array with pairs.
     * @param id identifier to search for
     * @param notfound value to return if identifier is not found.
     * @return string, representing the identifier.
     */
    static const char *lookup(const id_str_pair pair[],
                              int               id,
                              const char *      notfound = "unknown");
    static int         lookup(const id_str_pair pair[], const char *str, int notfound = 0);
    static int         lookup(const id_str_pair           pair[],
                              const std::vector<uint8_t> &bytes,
                              int                         notfound = 0);
    static int         lookup(const id_str_pair                 pair[],
                              const std::basic_string<uint8_t> &bytes,
                              int                               notfound = 0);
};

/** pgp_fingerprint_t */
typedef struct pgp_fingerprint_t {
    uint8_t  fingerprint[PGP_FINGERPRINT_SIZE];
    unsigned length;
    bool     operator==(const pgp_fingerprint_t &src) const;
    bool     operator!=(const pgp_fingerprint_t &src) const;
} pgp_fingerprint_t;

typedef std::array<uint8_t, PGP_KEY_GRIP_SIZE> pgp_sig_id_t;

namespace std {
template <> struct hash<pgp_fingerprint_t> {
    std::size_t
    operator()(pgp_fingerprint_t const &fp) const noexcept
    {
        /* since fingerprint value is hash itself, we may use its low bytes */
        size_t res = 0;
        static_assert(sizeof(fp.fingerprint) == PGP_FINGERPRINT_SIZE,
                      "pgp_fingerprint_t size mismatch");
        static_assert(PGP_FINGERPRINT_SIZE >= sizeof(res), "pgp_fingerprint_t size mismatch");
        std::memcpy(&res, fp.fingerprint, sizeof(res));
        return res;
    }
};

template <> struct hash<pgp_sig_id_t> {
    std::size_t
    operator()(pgp_sig_id_t const &sigid) const noexcept
    {
        /* since signature id value is hash itself, we may use its low bytes */
        size_t res = 0;
        static_assert(std::tuple_size<pgp_sig_id_t>::value >= sizeof(res),
                      "pgp_sig_id_t size mismatch");
        std::memcpy(&res, sigid.data(), sizeof(res));
        return res;
    }
};
}; // namespace std

typedef std::array<uint8_t, PGP_KEY_GRIP_SIZE> pgp_key_grip_t;

typedef std::array<uint8_t, PGP_KEY_ID_SIZE> pgp_key_id_t;

namespace rnp {
class rnp_exception : public std::exception {
    rnp_result_t code_;

  public:
    rnp_exception(rnp_result_t code = RNP_ERROR_GENERIC) : code_(code){};
    virtual const char *
    what() const throw()
    {
        return "rnp_exception";
    };
    rnp_result_t
    code() const
    {
        return code_;
    };
};
} // namespace rnp

/* validity information for the signature/key/userid */
typedef struct pgp_validity_t {
    bool validated{}; /* item was validated */
    bool valid{};     /* item is valid by signature/key checks and calculations.
                         Still may be revoked or expired. */
    bool expired{};   /* item is expired */

    void mark_valid();
    void reset();
} pgp_validity_t;

/**
 * Type to keep public/secret key mpis without any openpgp-dependent data.
 */
typedef struct pgp_key_material_t {
    pgp_pubkey_alg_t alg;      /* algorithm of the key */
    bool             secret;   /* secret part of the key material is populated */
    pgp_validity_t   validity; /* key material validation status */

    union {
        pgp_rsa_key_t rsa;
        pgp_dsa_key_t dsa;
        pgp_eg_key_t  eg;
        pgp_ec_key_t  ec;
    };

    size_t bits() const;
    size_t qbits() const;
    void   validate(rnp::SecurityContext &ctx, bool reset = true);
    bool   valid() const;
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

typedef struct pgp_s2k_t {
    pgp_s2k_usage_t usage{};

    /* below fields may not all be valid, depending on the usage field above */
    pgp_s2k_specifier_t specifier{};
    pgp_hash_alg_t      hash_alg{};
    uint8_t             salt[PGP_SALT_SIZE];
    unsigned            iterations{};
    /* GnuPG custom s2k data */
    pgp_s2k_gpg_extension_t gpg_ext_num{};
    uint8_t                 gpg_serial_len{};
    uint8_t                 gpg_serial[16];
    /* Experimental s2k data */
    std::vector<uint8_t> experimental{};
} pgp_s2k_t;

typedef struct pgp_key_protection_t {
    pgp_s2k_t         s2k{};         /* string-to-key kdf params */
    pgp_symm_alg_t    symm_alg{};    /* symmetric alg */
    pgp_cipher_mode_t cipher_mode{}; /* block cipher mode */
    uint8_t           iv[PGP_MAX_BLOCK_SIZE];
} pgp_key_protection_t;

typedef struct pgp_key_pkt_t    pgp_key_pkt_t;
typedef struct pgp_userid_pkt_t pgp_userid_pkt_t;
typedef struct pgp_signature_t  pgp_signature_t;

/* Signature subpacket, see 5.2.3.1 in RFC 4880 and RFC 4880 bis 02 */
typedef struct pgp_sig_subpkt_t {
    pgp_sig_subpacket_type_t type;         /* type of the subpacket */
    size_t                   len;          /* length of the data */
    uint8_t *                data;         /* raw subpacket data, excluding the header */
    bool                     critical : 1; /* critical flag */
    bool                     hashed : 1;   /* whether subpacket is hashed or not */
    bool                     parsed : 1;   /* whether subpacket was successfully parsed */
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
            uint8_t          klass;
            pgp_pubkey_alg_t pkalg;
            uint8_t *        fp;
        } revocation_key; /* 5.2.3.15.  Revocation Key */
        uint8_t *issuer;  /* 5.2.3.5.   Issuer */
        struct {
            uint8_t        flags[4];
            unsigned       nlen;
            unsigned       vlen;
            bool           human;
            const uint8_t *name;
            const uint8_t *value;
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
            pgp_revocation_type_t code;
            const char *          str;
            unsigned              len;
        } revocation_reason; /* 5.2.3.23.  Reason for Revocation */
        uint8_t features;    /* 5.2.3.24.  Features */
        struct {
            pgp_pubkey_alg_t pkalg;
            pgp_hash_alg_t   halg;
            uint8_t *        hash;
            unsigned         hlen;
        } sig_target;         /* 5.2.3.25.  Signature Target */
        pgp_signature_t *sig; /* 5.2.3.27. Embedded Signature */
        struct {
            uint8_t  version;
            uint8_t *fp;
            unsigned len;
        } issuer_fp; /* 5.2.3.28.  Issuer Fingerprint, RFC 4880 bis 04 */
    } fields;        /* parsed contents of the subpacket */

    pgp_sig_subpkt_t()
        : type(PGP_SIG_SUBPKT_UNKNOWN), len(0), data(NULL), critical(false), hashed(false),
          parsed(false), fields({}){};
    pgp_sig_subpkt_t(const pgp_sig_subpkt_t &src);
    pgp_sig_subpkt_t(pgp_sig_subpkt_t &&src);
    pgp_sig_subpkt_t &operator=(pgp_sig_subpkt_t &&src);
    pgp_sig_subpkt_t &operator=(const pgp_sig_subpkt_t &src);
    ~pgp_sig_subpkt_t();
    bool parse();
} pgp_sig_subpkt_t;

typedef struct pgp_one_pass_sig_t pgp_one_pass_sig_t;

typedef enum {
    /* first octet */
    PGP_KEY_SERVER_NO_MODIFY = 0x80
} pgp_key_server_prefs_t;

typedef struct pgp_literal_hdr_t {
    uint8_t  format;
    char     fname[256];
    uint8_t  fname_len;
    uint32_t timestamp;
} pgp_literal_hdr_t;

typedef struct pgp_aead_hdr_t {
    int            version{};                  /* version of the AEAD packet */
    pgp_symm_alg_t ealg;                       /* underlying symmetric algorithm */
    pgp_aead_alg_t aalg;                       /* AEAD algorithm, i.e. EAX, OCB, etc */
    int            csize{};                    /* chunk size bits */
    uint8_t        iv[PGP_AEAD_MAX_NONCE_LEN]; /* initial vector for the message */
    size_t         ivlen{};                    /* iv length */

    pgp_aead_hdr_t() : ealg(PGP_SA_UNKNOWN), aalg(PGP_AEAD_NONE)
    {
    }
} pgp_aead_hdr_t;

/** litdata_type_t */
typedef enum {
    PGP_LDT_BINARY = 'b',
    PGP_LDT_TEXT = 't',
    PGP_LDT_UTF8 = 'u',
    PGP_LDT_LOCAL = 'l',
    PGP_LDT_LOCAL2 = '1'
} pgp_litdata_enum;

/* user revocation info */
typedef struct pgp_subsig_t pgp_subsig_t;

typedef struct pgp_revoke_t {
    uint32_t              uid{};   /* index in uid array */
    pgp_revocation_type_t code{};  /* revocation code */
    std::string           reason;  /* revocation reason */
    pgp_sig_id_t          sigid{}; /* id of the corresponding subsig */

    pgp_revoke_t() = default;
    pgp_revoke_t(pgp_subsig_t &sig);
} pgp_revoke_t;

typedef struct pgp_user_prefs_t {
    // preferred symmetric algs (pgp_symm_alg_t)
    std::vector<uint8_t> symm_algs{};
    // preferred hash algs (pgp_hash_alg_t)
    std::vector<uint8_t> hash_algs{};
    // preferred compression algs (pgp_compression_type_t)
    std::vector<uint8_t> z_algs{};
    // key server preferences (pgp_key_server_prefs_t)
    std::vector<uint8_t> ks_prefs{};
    // preferred key server
    std::string key_server{};

    void set_symm_algs(const std::vector<uint8_t> &algs);
    void add_symm_alg(pgp_symm_alg_t alg);
    void set_hash_algs(const std::vector<uint8_t> &algs);
    void add_hash_alg(pgp_hash_alg_t alg);
    void set_z_algs(const std::vector<uint8_t> &algs);
    void add_z_alg(pgp_compression_type_t alg);
    void set_ks_prefs(const std::vector<uint8_t> &prefs);
    void add_ks_pref(pgp_key_server_prefs_t pref);
} pgp_user_prefs_t;

struct rnp_keygen_ecc_params_t {
    pgp_curve_t curve;
};

struct rnp_keygen_rsa_params_t {
    uint32_t modulus_bit_len;
};

struct rnp_keygen_dsa_params_t {
    size_t p_bitlen;
    size_t q_bitlen;
};

struct rnp_keygen_elgamal_params_t {
    size_t key_bitlen;
};

/* structure used to hold context of key generation */
namespace rnp {
class SecurityContext;
}

typedef struct rnp_keygen_crypto_params_t {
    // Asymmteric algorithm that user requesed key for
    pgp_pubkey_alg_t key_alg;
    // Hash to be used for key signature
    pgp_hash_alg_t hash_alg;
    // Pointer to security context
    rnp::SecurityContext *ctx;
    union {
        struct rnp_keygen_ecc_params_t     ecc;
        struct rnp_keygen_rsa_params_t     rsa;
        struct rnp_keygen_dsa_params_t     dsa;
        struct rnp_keygen_elgamal_params_t elgamal;
    };
} rnp_keygen_crypto_params_t;

typedef struct rnp_selfsig_cert_info_t {
    std::string      userid;           /* userid, required */
    uint8_t          key_flags{};      /* key flags */
    uint32_t         key_expiration{}; /* key expiration time (sec), 0 = no expiration */
    pgp_user_prefs_t prefs{};          /* user preferences, optional */
    bool             primary;          /* mark this as the primary user id */

    /**
     * @brief Populate uid and sig packet with data stored in this struct.
     *        At some point we should get rid of it.
     */
    void populate(pgp_userid_pkt_t &uid, pgp_signature_t &sig);
} rnp_selfsig_cert_info_t;

typedef struct rnp_selfsig_binding_info_t {
    uint8_t  key_flags;
    uint32_t key_expiration;
} rnp_selfsig_binding_info_t;

typedef struct rnp_keygen_primary_desc_t {
    rnp_keygen_crypto_params_t crypto{};
    rnp_selfsig_cert_info_t    cert{};
} rnp_keygen_primary_desc_t;

typedef struct rnp_keygen_subkey_desc_t {
    rnp_keygen_crypto_params_t crypto;
    rnp_selfsig_binding_info_t binding;
} rnp_keygen_subkey_desc_t;

typedef struct rnp_key_protection_params_t {
    pgp_symm_alg_t    symm_alg;
    pgp_cipher_mode_t cipher_mode;
    unsigned          iterations;
    pgp_hash_alg_t    hash_alg;
} rnp_key_protection_params_t;

#endif /* TYPES_H_ */
