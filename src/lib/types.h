/*
 * Copyright (c) 2017-2024, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TYPES_H_
#define TYPES_H_

#include <stdint.h>
#include <string>
#include <vector>
#include <array>
#include <cstring>
#include <stdexcept>
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
};

typedef std::array<uint8_t, PGP_KEY_ID_SIZE>   pgp_key_id_t;
typedef std::array<uint8_t, PGP_KEY_GRIP_SIZE> pgp_key_grip_t;

/** pgp_fingerprint_t */
typedef struct pgp_fingerprint_t {
    uint8_t  fingerprint[PGP_MAX_FINGERPRINT_SIZE];
    unsigned length;
    bool     operator==(const pgp_fingerprint_t &src) const;
    bool     operator!=(const pgp_fingerprint_t &src) const;

    pgp_fingerprint_t() = default;
    pgp_fingerprint_t(const std::vector<uint8_t> &src)
    {
        if (!size_valid(src.size())) {
            throw std::invalid_argument("src");
        }
        memcpy(fingerprint, src.data(), src.size());
        length = src.size();
    }

    static bool
    size_valid(size_t size)
    {
        return (size == PGP_FINGERPRINT_V4_SIZE) || (size == PGP_FINGERPRINT_V3_SIZE) ||
               (size == PGP_FINGERPRINT_V5_SIZE);
    }

    pgp_key_id_t keyid() const;
} pgp_fingerprint_t;

typedef std::array<uint8_t, PGP_KEY_GRIP_SIZE> pgp_sig_id_t;

namespace std {
template <> struct hash<pgp_fingerprint_t> {
    std::size_t
    operator()(pgp_fingerprint_t const &fp) const noexcept
    {
        /* since fingerprint value is hash itself, we may use its low bytes */
        size_t res = 0;
        static_assert(sizeof(fp.fingerprint) == PGP_MAX_FINGERPRINT_SIZE,
                      "pgp_fingerprint_t size mismatch");
        static_assert(PGP_MAX_FINGERPRINT_SIZE >= sizeof(res),
                      "pgp_fingerprint_t size mismatch");
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
 * Type to keep signature without any openpgp-dependent data.
 */
typedef struct pgp_signature_material_t {
    union {
        pgp::rsa::Signature rsa;
        pgp::dsa::Signature dsa;
        pgp::ec::Signature  ecc;
        pgp::eg::Signature  eg;
    };
#if defined(ENABLE_CRYPTO_REFRESH)
    pgp_ed25519_signature_t ed25519; // non-trivial type cannot be member in union
#endif
#if defined(ENABLE_PQC)
    pgp_dilithium_exdsa_signature_t
                                dilithium_exdsa; // non-trivial type cannot be member in union
    pgp_sphincsplus_signature_t sphincsplus;     // non-trivial type cannot be member in union
#endif
    pgp_hash_alg_t halg;
} pgp_signature_material_t;

/**
 * Type to keep pk-encrypted data without any openpgp-dependent data.
 */
typedef struct pgp_encrypted_material_t {
    union {
        pgp::rsa::Encrypted  rsa;
        pgp::eg::Encrypted   eg;
        pgp_sm2_encrypted_t  sm2;
        pgp_ecdh_encrypted_t ecdh;
    };
#if defined(ENABLE_CRYPTO_REFRESH)
    pgp_x25519_encrypted_t x25519; // non-trivial type cannot be member in union
#endif
#if defined(ENABLE_PQC)
    pgp_kyber_ecdh_encrypted_t kyber_ecdh; // non-trivial type cannot be member in union
#endif
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

typedef struct pgp_key_pkt_t      pgp_key_pkt_t;
typedef struct pgp_userid_pkt_t   pgp_userid_pkt_t;
typedef struct pgp_signature_t    pgp_signature_t;
typedef struct pgp_one_pass_sig_t pgp_one_pass_sig_t;

typedef enum {
    /* first octet */
    PGP_KEY_SERVER_NO_MODIFY = 0x80
} pgp_key_server_prefs_t;

typedef struct pgp_literal_hdr_t {
    uint8_t  format{};
    char     fname[256]{};
    uint8_t  fname_len{};
    uint32_t timestamp{};
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

#ifdef ENABLE_CRYPTO_REFRESH
typedef struct pgp_seipdv2_hdr_t {
    pgp_seipd_version_t version;                    /* version of the SEIPD packet */
    pgp_symm_alg_t      cipher_alg;                 /* underlying symmetric algorithm */
    pgp_aead_alg_t      aead_alg;                   /* AEAD algorithm, i.e. EAX, OCB, etc */
    uint8_t             chunk_size_octet;           /* chunk size octet */
    uint8_t             salt[PGP_SEIPDV2_SALT_LEN]; /* SEIPDv2 salt value */
} pgp_seipdv2_hdr_t;
#endif

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

typedef struct rnp_key_protection_params_t {
    pgp_symm_alg_t    symm_alg;
    pgp_cipher_mode_t cipher_mode;
    unsigned          iterations;
    pgp_hash_alg_t    hash_alg;
} rnp_key_protection_params_t;

#endif /* TYPES_H_ */
