/*
 * Copyright (c) 2017-2020, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
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

#include <memory>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include "config.h"

#include <librepgp/stream-packet.h>
#include "key_store_pgp.h"
#include "key_store_g10.h"

#include "crypto/common.h"
#include "crypto/mem.h"
#include "crypto/cipher.hpp"
#include "pgp-key.h"
#include "g10_sexp.hpp"

#define G10_CBC_IV_SIZE 16

#define G10_OCB_NONCE_SIZE 12

#define G10_SHA1_HASH_SIZE 20

#define G10_PROTECTED_AT_SIZE 15

typedef struct format_info {
    pgp_symm_alg_t    cipher;
    pgp_cipher_mode_t cipher_mode;
    pgp_hash_alg_t    hash_alg;
    size_t            cipher_block_size;
    const char *      g10_type;
    size_t            iv_size;
} format_info;

static bool g10_calculated_hash(const pgp_key_pkt_t &key,
                                const char *         protected_at,
                                uint8_t *            checksum);

static const format_info formats[] = {{PGP_SA_AES_128,
                                       PGP_CIPHER_MODE_CBC,
                                       PGP_HASH_SHA1,
                                       16,
                                       "openpgp-s2k3-sha1-aes-cbc",
                                       G10_CBC_IV_SIZE},
                                      {PGP_SA_AES_256,
                                       PGP_CIPHER_MODE_CBC,
                                       PGP_HASH_SHA1,
                                       16,
                                       "openpgp-s2k3-sha1-aes256-cbc",
                                       G10_CBC_IV_SIZE},
                                      {PGP_SA_AES_128,
                                       PGP_CIPHER_MODE_OCB,
                                       PGP_HASH_SHA1,
                                       16,
                                       "openpgp-s2k3-ocb-aes",
                                       G10_OCB_NONCE_SIZE}};

static const id_str_pair g10_alg_aliases[] = {
  {PGP_PKA_RSA, "rsa"},
  {PGP_PKA_RSA, "openpgp-rsa"},
  {PGP_PKA_RSA, "oid.1.2.840.113549.1.1.1"},
  {PGP_PKA_RSA, "oid.1.2.840.113549.1.1.1"},
  {PGP_PKA_ELGAMAL, "elg"},
  {PGP_PKA_ELGAMAL, "elgamal"},
  {PGP_PKA_ELGAMAL, "openpgp-elg"},
  {PGP_PKA_ELGAMAL, "openpgp-elg-sig"},
  {PGP_PKA_DSA, "dsa"},
  {PGP_PKA_DSA, "openpgp-dsa"},
  {PGP_PKA_ECDSA, "ecc"},
  {PGP_PKA_ECDSA, "ecdsa"},
  {PGP_PKA_ECDH, "ecdh"},
  {PGP_PKA_EDDSA, "eddsa"},
  {0, NULL},
};

static const id_str_pair g10_curve_aliases[] = {
  {PGP_CURVE_NIST_P_256, "NIST P-256"},
  {PGP_CURVE_NIST_P_256, "1.2.840.10045.3.1.7"},
  {PGP_CURVE_NIST_P_256, "prime256v1"},
  {PGP_CURVE_NIST_P_256, "secp256r1"},
  {PGP_CURVE_NIST_P_256, "nistp256"},
  {PGP_CURVE_NIST_P_384, "NIST P-384"},
  {PGP_CURVE_NIST_P_384, "secp384r1"},
  {PGP_CURVE_NIST_P_384, "1.3.132.0.34"},
  {PGP_CURVE_NIST_P_384, "nistp384"},
  {PGP_CURVE_NIST_P_521, "NIST P-521"},
  {PGP_CURVE_NIST_P_521, "secp521r1"},
  {PGP_CURVE_NIST_P_521, "1.3.132.0.35"},
  {PGP_CURVE_NIST_P_521, "nistp521"},
  {PGP_CURVE_25519, "Curve25519"},
  {PGP_CURVE_25519, "1.3.6.1.4.1.3029.1.5.1"},
  {PGP_CURVE_ED25519, "Ed25519"},
  {PGP_CURVE_ED25519, "1.3.6.1.4.1.11591.15.1"},
  {PGP_CURVE_BP256, "brainpoolP256r1"},
  {PGP_CURVE_BP256, "1.3.36.3.3.2.8.1.1.7"},
  {PGP_CURVE_BP384, "brainpoolP384r1"},
  {PGP_CURVE_BP384, "1.3.36.3.3.2.8.1.1.11"},
  {PGP_CURVE_BP512, "brainpoolP512r1"},
  {PGP_CURVE_BP512, "1.3.36.3.3.2.8.1.1.13"},
  {PGP_CURVE_P256K1, "secp256k1"},
  {PGP_CURVE_P256K1, "1.3.132.0.10"},
  {0, NULL},
};

static const id_str_pair g10_curve_names[] = {
  {PGP_CURVE_NIST_P_256, "NIST P-256"},
  {PGP_CURVE_NIST_P_384, "NIST P-384"},
  {PGP_CURVE_NIST_P_521, "NIST P-521"},
  {PGP_CURVE_ED25519, "Ed25519"},
  {PGP_CURVE_25519, "Curve25519"},
  {PGP_CURVE_BP256, "brainpoolP256r1"},
  {PGP_CURVE_BP384, "brainpoolP384r1"},
  {PGP_CURVE_BP512, "brainpoolP512r1"},
  {PGP_CURVE_P256K1, "secp256k1"},
  {0, NULL},
};

static const format_info *
find_format(pgp_symm_alg_t cipher, pgp_cipher_mode_t mode, pgp_hash_alg_t hash_alg)
{
    for (size_t i = 0; i < ARRAY_SIZE(formats); i++) {
        if (formats[i].cipher == cipher && formats[i].cipher_mode == mode &&
            formats[i].hash_alg == hash_alg) {
            return &formats[i];
        }
    }
    return NULL;
}

static const format_info *
parse_format(const char *format, size_t format_len)
{
    for (size_t i = 0; i < ARRAY_SIZE(formats); i++) {
        if (strlen(formats[i].g10_type) == format_len &&
            !strncmp(formats[i].g10_type, format, format_len)) {
            return &formats[i];
        }
    }
    return NULL;
}

void
s_exp_t::add(std::unique_ptr<s_exp_element_t> sptr)
{
    elements_.push_back(std::move(sptr));
}

void
s_exp_t::add(const std::string &str)
{
    add(std::unique_ptr<s_exp_block_t>(new s_exp_block_t(str)));
}

void
s_exp_t::add(const uint8_t *data, size_t size)
{
    add(std::unique_ptr<s_exp_block_t>(new s_exp_block_t(data, size)));
}

void
s_exp_t::add(unsigned u)
{
    add(std::unique_ptr<s_exp_block_t>(new s_exp_block_t(u)));
}

s_exp_t &
s_exp_t::add_sub()
{
    s_exp_t *res = new s_exp_t();
    add(std::unique_ptr<s_exp_t>(res));
    return *res;
}

/*
 * Parse G10 S-exp.
 *
 * Supported format: (1:a2:ab(3:asd1:a))
 * It should be parsed to:
 *   - a
 *   - ab
 *   + - asd
 *     - a
 *
 */

bool
s_exp_t::parse(const char **r_bytes, size_t *r_length, size_t depth)
{
    size_t      length = *r_length;
    const char *bytes = *r_bytes;

    if (!bytes || !length) {
        RNP_LOG("empty s-exp");
        return true;
    }

    if (depth > SXP_MAX_DEPTH) {
        RNP_LOG("sxp maximum recursion depth exceeded");
        return false;
    }

    if (*bytes != '(') { // doesn't start from (
        return false;
    }

    bytes++;
    length--;

    do {
        if (!length) { // unexpected end
            RNP_LOG("s-exp finished before ')'");
            return false;
        }

        if (*bytes == '(') {
            s_exp_t &newsexp = add_sub();
            if (!newsexp.parse(&bytes, &length, depth + 1)) {
                return false;
            }
            if (!length) {
                RNP_LOG("No space for closing ) left.");
                return false;
            }
            continue;
        }

        size_t len = 0;
        size_t chars = 0;
        while (length > 1) {
            if ((*bytes < '0') || (*bytes > '9')) {
                break;
            }
            len = len * 10 + (long) (*bytes - '0');
            length--;
            bytes++;
            /* no reason to read more then 8 chars */
            if (++chars > 8) {
                break;
            }
        }

        if (!chars) {
            RNP_LOG("s-exp contains empty len");
            return false;
        }

        if (*bytes != ':') { // doesn't contain :
            RNP_LOG("s-exp doesn't contain ':'");
            return false;
        }

        bytes++;
        length--;

        if (!len || len >= length) {
            RNP_LOG("zero or too large len, len: %zu, length: %zu", len, length);
            return false;
        }

        add((uint8_t *) bytes, len);
        bytes += len;
        length -= len;
    } while (*bytes != ')');

    bytes++;
    length--;
    *r_bytes = bytes;
    *r_length = length;
    return true;
}

void
s_exp_t::clear()
{
    elements_.clear();
}

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

s_exp_block_t::s_exp_block_t(const pgp_mpi_t &mpi) : s_exp_element_t(true)
{
    size_t len = mpi_bytes(&mpi);
    size_t idx;
    for (idx = 0; (idx < len) && !mpi.mpi[idx]; idx++)
        ;

    if (idx >= len) {
        bytes_ = {0};
        return;
    }
    if (mpi.mpi[idx] & 0x80) {
        bytes_ = std::vector<uint8_t>(len - idx + 1);
        bytes_[0] = 0;
        memcpy(bytes_.data() + 1, mpi.mpi + idx, len - idx);
        return;
    }
    bytes_ = std::vector<uint8_t>(mpi.mpi + idx, mpi.mpi + len);
}

s_exp_block_t::s_exp_block_t(unsigned u) : s_exp_element_t(true)
{
    char s[sizeof(STR(UINT_MAX)) + 1];
    snprintf(s, sizeof(s), "%u", u);
    bytes_ = std::vector<uint8_t>((uint8_t *) s, (uint8_t *) (s + strlen(s)));
}

unsigned
s_exp_block_t::as_unsigned() const noexcept
{
    char s[sizeof(STR(UINT_MAX)) + 1] = {0};
    if (bytes_.empty() || bytes_.size() >= sizeof(s)) {
        return UINT_MAX;
    }

    memcpy(s, bytes_.data(), bytes_.size());
    return (unsigned) atoi(s);
}

s_exp_t *
s_exp_t::lookup_var(const std::string &name) noexcept
{
    for (auto &ptr : elements_) {
        if (ptr->is_block()) {
            continue;
        }
        s_exp_t &sub_el = dynamic_cast<s_exp_t &>(*ptr.get());
        if ((sub_el.size() < 2) || !sub_el.at(0).is_block()) {
            RNP_LOG("Expected sub-s-exp with 2 first blocks");
            return NULL;
        }
        s_exp_block_t &name_el = dynamic_cast<s_exp_block_t &>(sub_el.at(0));
        if (name_el.bytes().size() != name.size()) {
            continue;
        }
        if (!memcmp(name_el.bytes().data(), name.data(), name.size())) {
            return &sub_el;
        }
    }
    RNP_LOG("Haven't got variable '%s'", name.c_str());
    return NULL;
}

s_exp_block_t *
s_exp_t::lookup_var_data(const std::string &name) noexcept
{
    s_exp_t *var = lookup_var(name);
    if (!var) {
        return NULL;
    }

    if (!var->at(1).is_block()) {
        RNP_LOG("Expected block value");
        return NULL;
    }

    return dynamic_cast<s_exp_block_t *>(&var->at(1));
}

bool
s_exp_t::read_mpi(const std::string &name, pgp_mpi_t &val) noexcept
{
    s_exp_block_t *data = lookup_var_data(name);
    if (!data) {
        return false;
    }

    /* strip leading zero */
    const auto &bytes = data->bytes();
    if ((bytes.size() > 1) && !bytes[0] && (bytes[1] & 0x80)) {
        return mem2mpi(&val, bytes.data() + 1, bytes.size() - 1);
    }
    return mem2mpi(&val, bytes.data(), bytes.size());
}

bool
s_exp_t::read_curve(const std::string &name, pgp_ec_key_t &key) noexcept
{
    s_exp_block_t *data = lookup_var_data(name);
    if (!data) {
        return false;
    }

    const auto &bytes = data->bytes();
    pgp_curve_t curve = static_cast<pgp_curve_t>(
      id_str_pair::lookup(g10_curve_aliases, data->bytes(), PGP_CURVE_UNKNOWN));
    if (curve != PGP_CURVE_UNKNOWN) {
        key.curve = curve;
        return true;
    }
    RNP_LOG("Unknown curve: %.*s", (int) bytes.size(), (char *) bytes.data());
    return false;
}

void
s_exp_t::add_mpi(const std::string &name, const pgp_mpi_t &val)
{
    s_exp_t &sub_s_exp = add_sub();
    sub_s_exp.add(name);
    sub_s_exp.add(std::unique_ptr<s_exp_block_t>(new s_exp_block_t(val)));
}

void
s_exp_t::add_curve(const std::string &name, const pgp_ec_key_t &key)
{
    const char *curve = id_str_pair::lookup(g10_curve_names, key.curve, NULL);
    if (!curve) {
        RNP_LOG("unknown curve");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    s_exp_t *psub_s_exp = &add_sub();
    psub_s_exp->add(name);
    psub_s_exp->add(curve);

    if ((key.curve != PGP_CURVE_ED25519) && (key.curve != PGP_CURVE_25519)) {
        return;
    }

    psub_s_exp = &add_sub();
    psub_s_exp->add("flags");
    psub_s_exp->add((key.curve == PGP_CURVE_ED25519) ? "eddsa" : "djb-tweak");
}

static bool
parse_pubkey(pgp_key_pkt_t &pubkey, s_exp_t &s_exp, pgp_pubkey_alg_t alg)
{
    pubkey.version = PGP_V4;
    pubkey.alg = alg;
    pubkey.material.alg = alg;
    switch (alg) {
    case PGP_PKA_DSA:
        if (!s_exp.read_mpi("p", pubkey.material.dsa.p) ||
            !s_exp.read_mpi("q", pubkey.material.dsa.q) ||
            !s_exp.read_mpi("g", pubkey.material.dsa.g) ||
            !s_exp.read_mpi("y", pubkey.material.dsa.y)) {
            return false;
        }
        break;

    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!s_exp.read_mpi("n", pubkey.material.rsa.n) ||
            !s_exp.read_mpi("e", pubkey.material.rsa.e)) {
            return false;
        }
        break;

    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!s_exp.read_mpi("p", pubkey.material.eg.p) ||
            !s_exp.read_mpi("g", pubkey.material.eg.g) ||
            !s_exp.read_mpi("y", pubkey.material.eg.y)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        if (!s_exp.read_curve("curve", pubkey.material.ec) ||
            !s_exp.read_mpi("q", pubkey.material.ec.p)) {
            return false;
        }
        if (pubkey.material.ec.curve == PGP_CURVE_ED25519) {
            /* need to adjust it here since 'ecc' key type defaults to ECDSA */
            pubkey.alg = PGP_PKA_EDDSA;
            pubkey.material.alg = PGP_PKA_EDDSA;
        }
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) alg);
        return false;
    }

    return true;
}

static bool
parse_seckey(pgp_key_pkt_t &seckey, s_exp_t &s_exp, pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_DSA:
        if (!s_exp.read_mpi("x", seckey.material.dsa.x)) {
            return false;
        }
        break;
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!s_exp.read_mpi("d", seckey.material.rsa.d) ||
            !s_exp.read_mpi("p", seckey.material.rsa.p) ||
            !s_exp.read_mpi("q", seckey.material.rsa.q) ||
            !s_exp.read_mpi("u", seckey.material.rsa.u)) {
            return false;
        }
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!s_exp.read_mpi("x", seckey.material.eg.x)) {
            return false;
        }
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        if (!s_exp.read_mpi("d", seckey.material.ec.x)) {
            return false;
        }
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) alg);
        return false;
    }

    seckey.material.secret = true;
    return true;
}

static bool
decrypt_protected_section(const std::vector<uint8_t> &encrypted_data,
                          const pgp_key_pkt_t &       seckey,
                          const std::string &         password,
                          s_exp_t &                   r_s_exp)
{
    const format_info *     info = NULL;
    unsigned                keysize = 0;
    uint8_t                 derived_key[PGP_MAX_KEY_SIZE];
    uint8_t *               decrypted_data = NULL;
    size_t                  decrypted_data_len = 0;
    size_t                  output_written = 0;
    size_t                  input_consumed = 0;
    std::unique_ptr<Cipher> dec;
    bool                    ret = false;

    const char *decrypted_bytes;
    size_t      s_exp_len;

    // sanity checks
    const pgp_key_protection_t &prot = seckey.sec_protection;
    keysize = pgp_key_size(prot.symm_alg);
    if (!keysize) {
        RNP_LOG("parse_seckey: unknown symmetric algo");
        goto done;
    }
    // find the protection format in our table
    info = find_format(prot.symm_alg, prot.cipher_mode, prot.s2k.hash_alg);
    if (!info) {
        RNP_LOG("Unsupported format, alg: %d, chiper_mode: %d, hash: %d",
                prot.symm_alg,
                prot.cipher_mode,
                prot.s2k.hash_alg);
        goto done;
    }

    // derive the key
    if (pgp_s2k_iterated(prot.s2k.hash_alg,
                         derived_key,
                         keysize,
                         password.c_str(),
                         prot.s2k.salt,
                         prot.s2k.iterations)) {
        RNP_LOG("pgp_s2k_iterated failed");
        goto done;
    }

    // decrypt
    decrypted_data = (uint8_t *) malloc(encrypted_data.size());
    if (decrypted_data == NULL) {
        RNP_LOG("can't allocate memory");
        goto done;
    }
    dec = Cipher::decryption(info->cipher, info->cipher_mode, 0, true);
    if (!dec || !dec->set_key(derived_key, keysize) || !dec->set_iv(prot.iv, info->iv_size)) {
        goto done;
    }
    if (!dec->finish(decrypted_data,
                     encrypted_data.size(),
                     &output_written,
                     encrypted_data.data(),
                     encrypted_data.size(),
                     &input_consumed)) {
        goto done;
    }
    decrypted_data_len = output_written;
    s_exp_len = decrypted_data_len;
    decrypted_bytes = (const char *) decrypted_data;

    // parse and validate the decrypted s-exp
    if (!r_s_exp.parse(&decrypted_bytes, &s_exp_len)) {
        goto done;
    }
    if (!r_s_exp.size() || r_s_exp.at(0).is_block()) {
        RNP_LOG("Hasn't got sub s-exp with key data.");
        goto done;
    }
    ret = true;
done:
    if (!ret) {
        r_s_exp.clear();
    }
    secure_clear(decrypted_data, decrypted_data_len);
    free(decrypted_data);
    return ret;
}

static bool
parse_protected_seckey(pgp_key_pkt_t &seckey, s_exp_t &s_exp, const char *password)
{
    // find and validate the protected section
    s_exp_t *protected_key = s_exp.lookup_var("protected");
    if (!protected_key) {
        RNP_LOG("missing protected section");
        return false;
    }
    if (protected_key->size() != 4 || !protected_key->at(1).is_block() ||
        protected_key->at(2).is_block() || !protected_key->at(3).is_block()) {
        RNP_LOG("Wrong protected format, expected: (protected mode (parms) "
                "encrypted_octet_string)\n");
        return false;
    }

    // lookup the protection format
    auto &             fmt_bt = (dynamic_cast<s_exp_block_t &>(protected_key->at(1))).bytes();
    const format_info *format = parse_format((const char *) fmt_bt.data(), fmt_bt.size());
    if (!format) {
        RNP_LOG("Unsupported protected mode: '%.*s'\n",
                (int) fmt_bt.size(),
                (const char *) fmt_bt.data());
        return false;
    }

    // fill in some fields based on the lookup above
    pgp_key_protection_t &prot = seckey.sec_protection;
    prot.symm_alg = format->cipher;
    prot.cipher_mode = format->cipher_mode;
    prot.s2k.hash_alg = format->hash_alg;

    // locate and validate the protection parameters
    s_exp_t &params = dynamic_cast<s_exp_t &>(protected_key->at(2));
    if (params.size() != 2 || params.at(0).is_block() || !params.at(1).is_block()) {
        RNP_LOG("Wrong params format, expected: ((hash salt no_of_iterations) iv)\n");
        return false;
    }

    // locate and validate the (hash salt no_of_iterations) exp
    s_exp_t &alg = dynamic_cast<s_exp_t &>(params.at(0));
    if (alg.size() != 3 || !alg.at(0).is_block() || !alg.at(1).is_block() ||
        !alg.at(2).is_block()) {
        RNP_LOG("Wrong params sub-level format, expected: (hash salt no_of_iterations)\n");
        return false;
    }
    auto &hash_bt = (dynamic_cast<s_exp_block_t &>(alg.at(0))).bytes();
    if ((hash_bt.size() != 4) || memcmp("sha1", hash_bt.data(), 4)) {
        RNP_LOG("Wrong hashing algorithm, should be sha1 but %.*s\n",
                (int) hash_bt.size(),
                (const char *) hash_bt.data());
        return false;
    }

    // fill in some constant values
    prot.s2k.hash_alg = PGP_HASH_SHA1;
    prot.s2k.usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    prot.s2k.specifier = PGP_S2KS_ITERATED_AND_SALTED;

    // check salt size
    auto &salt_bt = (dynamic_cast<s_exp_block_t &>(alg.at(1))).bytes();
    if (salt_bt.size() != PGP_SALT_SIZE) {
        RNP_LOG("Wrong salt size, should be %d but %d\n", PGP_SALT_SIZE, (int) salt_bt.size());
        return false;
    }

    // salt
    memcpy(prot.s2k.salt, salt_bt.data(), salt_bt.size());
    // s2k iterations
    auto &iter = dynamic_cast<s_exp_block_t &>(alg.at(2));
    prot.s2k.iterations = iter.as_unsigned();
    if (prot.s2k.iterations == UINT_MAX) {
        RNP_LOG("Wrong numbers of iteration, %.*s\n",
                (int) iter.bytes().size(),
                (const char *) iter.bytes().data());
        return false;
    }

    // iv
    auto &iv_bt = (dynamic_cast<s_exp_block_t &>(params.at(1))).bytes();
    if (iv_bt.size() != format->iv_size) {
        RNP_LOG("Wrong nonce size, should be %zu but %zu\n", format->iv_size, iv_bt.size());
        return false;
    }
    memcpy(prot.iv, iv_bt.data(), iv_bt.size());

    // we're all done if no password was provided (decryption not requested)
    if (!password) {
        seckey.material.secret = false;
        return true;
    }

    // password was provided, so decrypt
    auto &  enc_bt = (dynamic_cast<s_exp_block_t &>(protected_key->at(3))).bytes();
    s_exp_t decrypted_s_exp;
    if (!decrypt_protected_section(enc_bt, seckey, password, decrypted_s_exp)) {
        return false;
    }
    // see if we have a protected-at section
    char           protected_at[G10_PROTECTED_AT_SIZE] = {0};
    s_exp_block_t *protected_at_data = s_exp.lookup_var_data("protected-at");
    if (protected_at_data) {
        if (protected_at_data->bytes().size() != G10_PROTECTED_AT_SIZE) {
            RNP_LOG("protected-at has wrong length: %zu, expected, %d\n",
                    protected_at_data->bytes().size(),
                    G10_PROTECTED_AT_SIZE);
            return false;
        }
        memcpy(
          protected_at, protected_at_data->bytes().data(), protected_at_data->bytes().size());
    }
    // parse MPIs
    if (!parse_seckey(seckey, dynamic_cast<s_exp_t &>(decrypted_s_exp.at(0)), seckey.alg)) {
        RNP_LOG("failed to parse seckey");
        return false;
    }
    // check hash, if present
    if (decrypted_s_exp.size() > 1) {
        if (decrypted_s_exp.at(1).is_block()) {
            RNP_LOG("Wrong hash block type.");
            return false;
        }
        auto &sub_el = dynamic_cast<s_exp_t &>(decrypted_s_exp.at(1));
        if (sub_el.size() < 3 || !sub_el.at(0).is_block() || !sub_el.at(1).is_block() ||
            !sub_el.at(2).is_block()) {
            RNP_LOG("Wrong hash block structure.");
            return false;
        }

        auto &hkey = (dynamic_cast<s_exp_block_t &>(sub_el.at(0))).bytes();
        if ((hkey.size() != 4) || memcmp("hash", hkey.data(), 4)) {
            RNP_LOG("Has got wrong hash block at encrypted key data.");
            return false;
        }
        auto &halg = (dynamic_cast<s_exp_block_t &>(sub_el.at(1))).bytes();
        if ((halg.size() != 4) || memcmp("sha1", halg.data(), 4)) {
            RNP_LOG("Supported only sha1 hash at encrypted private key.");
            return false;
        }
        uint8_t checkhash[G10_SHA1_HASH_SIZE];
        if (!g10_calculated_hash(seckey, protected_at, checkhash)) {
            RNP_LOG("failed to calculate hash");
            return false;
        }
        auto &hval = (dynamic_cast<s_exp_block_t &>(sub_el.at(2))).bytes();
        if (hval.size() != G10_SHA1_HASH_SIZE ||
            memcmp(checkhash, hval.data(), G10_SHA1_HASH_SIZE)) {
            RNP_LOG("Incorrect hash at encrypted private key.");
            return false;
        }
    }
    seckey.material.secret = true;
    return true;
}

static bool
g10_parse_seckey(pgp_key_pkt_t &seckey,
                 const uint8_t *data,
                 size_t         data_len,
                 const char *   password)
{
    s_exp_t     s_exp;
    const char *bytes = (const char *) data;
    if (!s_exp.parse(&bytes, &data_len)) {
        RNP_LOG("Failed to parse s-exp.");
        return false;
    }

    /* expected format:
     *  (<type>
     *    (<algo>
     *	   (x <mpi>)
     *	   (y <mpi>)
     *    )
     *  )
     */

    if (s_exp.size() != 2 || !s_exp.at(0).is_block() || s_exp.at(1).is_block()) {
        RNP_LOG("Wrong format, expected: (<type> (...))");
        return false;
    }

    bool  is_protected = false;
    auto &name = (dynamic_cast<s_exp_block_t &>(s_exp.at(0))).bytes();
    if ((name.size() == 11) && !memcmp("private-key", name.data(), name.size())) {
        is_protected = false;
    } else if ((name.size() == 21) &&
               !memcmp("protected-private-key", name.data(), name.size())) {
        is_protected = true;
    } else {
        RNP_LOG("Unsupported top-level block: '%.*s'",
                (int) name.size(),
                (const char *) name.data());
        return false;
    }

    s_exp_t &alg_s_exp = dynamic_cast<s_exp_t &>(s_exp.at(1));
    if (alg_s_exp.size() < 2) {
        RNP_LOG("Wrong count of algorithm-level elements: %zu", alg_s_exp.size());
        return false;
    }

    if (!alg_s_exp.at(0).is_block()) {
        RNP_LOG("Expected block with algorithm name, but has s-exp");
        return false;
    }

    auto &           alg_bt = (dynamic_cast<s_exp_block_t &>(alg_s_exp.at(0))).bytes();
    pgp_pubkey_alg_t alg = static_cast<pgp_pubkey_alg_t>(
      id_str_pair::lookup(g10_alg_aliases, alg_bt, PGP_PKA_NOTHING));
    if (alg == PGP_PKA_NOTHING) {
        RNP_LOG(
          "Unsupported algorithm: '%.*s'", (int) alg_bt.size(), (const char *) alg_bt.data());
        return false;
    }

    bool ret = false;
    if (!parse_pubkey(seckey, alg_s_exp, alg)) {
        RNP_LOG("failed to parse pubkey");
        goto done;
    }

    if (is_protected) {
        if (!parse_protected_seckey(seckey, alg_s_exp, password)) {
            goto done;
        }
    } else {
        seckey.sec_protection.s2k.usage = PGP_S2KU_NONE;
        seckey.sec_protection.symm_alg = PGP_SA_PLAINTEXT;
        seckey.sec_protection.s2k.hash_alg = PGP_HASH_UNKNOWN;
        if (!parse_seckey(seckey, alg_s_exp, alg)) {
            RNP_LOG("failed to parse seckey");
            goto done;
        }
    }
    ret = true;
done:
    if (!ret) {
        seckey = pgp_key_pkt_t();
    }
    return ret;
}

pgp_key_pkt_t *
g10_decrypt_seckey(const uint8_t *      data,
                   size_t               data_len,
                   const pgp_key_pkt_t *pubkey,
                   const char *         password)
{
    if (!password) {
        return NULL;
    }

    auto seckey = std::unique_ptr<pgp_key_pkt_t>(pubkey ? new pgp_key_pkt_t(*pubkey, false) :
                                                          new pgp_key_pkt_t());
    if (!g10_parse_seckey(*seckey, data, data_len, password)) {
        return NULL;
    }
    return seckey.release();
}

static bool
copy_secret_fields(pgp_key_pkt_t &dst, const pgp_key_pkt_t &src)
{
    switch (src.alg) {
    case PGP_PKA_DSA:
        dst.material.dsa.x = src.material.dsa.x;
        break;
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        dst.material.rsa.d = src.material.rsa.d;
        dst.material.rsa.p = src.material.rsa.p;
        dst.material.rsa.q = src.material.rsa.q;
        dst.material.rsa.u = src.material.rsa.u;
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        dst.material.eg.x = src.material.eg.x;
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        dst.material.ec.x = src.material.ec.x;
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) src.alg);
        return false;
    }

    dst.material.secret = src.material.secret;
    dst.sec_protection = src.sec_protection;
    dst.tag = is_subkey_pkt(dst.tag) ? PGP_PKT_SECRET_SUBKEY : PGP_PKT_SECRET_KEY;
    return true;
}

bool
rnp_key_store_g10_from_src(rnp_key_store_t *         key_store,
                           pgp_source_t *            src,
                           const pgp_key_provider_t *key_provider)
{
    const pgp_key_t *pubkey = NULL;
    pgp_key_t        key;
    pgp_key_pkt_t    seckey;
    pgp_source_t     memsrc = {};
    bool             ret = false;

    if (read_mem_src(&memsrc, src)) {
        goto done;
    }

    /* parse secret key: fills material and sec_protection only */
    if (!g10_parse_seckey(
          seckey, (uint8_t *) mem_src_get_memory(&memsrc), memsrc.size, NULL)) {
        goto done;
    }

    /* copy public key fields if any */
    if (key_provider) {
        pgp_key_search_t search = {.type = PGP_KEY_SEARCH_GRIP};
        if (!rnp_key_store_get_key_grip(&seckey.material, search.by.grip)) {
            goto done;
        }

        pgp_key_request_ctx_t req_ctx;
        memset(&req_ctx, 0, sizeof(req_ctx));
        req_ctx.op = PGP_OP_MERGE_INFO;
        req_ctx.secret = false;
        req_ctx.search = search;

        if (!(pubkey = pgp_request_key(key_provider, &req_ctx))) {
            goto done;
        }

        /* public key packet has some more info then the secret part */
        try {
            key = pgp_key_t(*pubkey, true);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            goto done;
        }

        if (!copy_secret_fields(key.pkt(), seckey)) {
            goto done;
        }
    } else {
        key.set_pkt(std::move(seckey));
    }

    try {
        key.set_rawpkt(pgp_rawpacket_t(
          (uint8_t *) mem_src_get_memory(&memsrc), memsrc.size, PGP_PKT_RESERVED));
    } catch (const std::exception &e) {
        RNP_LOG("failed to add packet: %s", e.what());
        goto done;
    }
    key.format = PGP_KEY_STORE_G10;
    if (!rnp_key_store_add_key(key_store, &key)) {
        goto done;
    }
    ret = true;
done:
    src_close(&memsrc);
    return ret;
}

#define MAX_SIZE_T_LEN ((3 * sizeof(size_t) * CHAR_BIT / 8) + 2)

bool
s_exp_block_t::write(pgp_dest_t &dst) const noexcept
{
    char   blen[MAX_SIZE_T_LEN + 1] = {0};
    size_t len = snprintf(blen, sizeof(blen), "%zu:", bytes_.size());
    dst_write(&dst, blen, len);
    dst_write(&dst, bytes_.data(), bytes_.size());
    return dst.werr == RNP_SUCCESS;
}

/*
 * Write G10 S-exp to buffer
 *
 * Supported format: (1:a2:ab(3:asd1:a))
 */
bool
s_exp_t::write(pgp_dest_t &dst) const noexcept
{
    dst_write(&dst, "(", 1);
    if (dst.werr) {
        return false;
    }

    for (auto &ptr : elements_) {
        if (!ptr->write(dst)) {
            return false;
        }
    }

    dst_write(&dst, ")", 1);
    return !dst.werr;
}

void
s_exp_t::add_pubkey(const pgp_key_pkt_t &key)
{
    switch (key.alg) {
    case PGP_PKA_DSA:
        add("dsa");
        add_mpi("p", key.material.dsa.p);
        add_mpi("q", key.material.dsa.q);
        add_mpi("g", key.material.dsa.g);
        add_mpi("y", key.material.dsa.y);
        break;
    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA:
        add("rsa");
        add_mpi("n", key.material.rsa.n);
        add_mpi("e", key.material.rsa.e);
        break;
    case PGP_PKA_ELGAMAL:
        add("elg");
        add_mpi("p", key.material.eg.p);
        add_mpi("g", key.material.eg.g);
        add_mpi("y", key.material.eg.y);
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
        add("ecc");
        add_curve("curve", key.material.ec);
        add_mpi("q", key.material.ec.p);
        break;
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) key.alg);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

void
s_exp_t::add_seckey(const pgp_key_pkt_t &key)
{
    switch (key.alg) {
    case PGP_PKA_DSA:
        add_mpi("x", key.material.dsa.x);
        break;
    case PGP_PKA_RSA_SIGN_ONLY:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA:
        add_mpi("d", key.material.rsa.d);
        add_mpi("p", key.material.rsa.p);
        add_mpi("q", key.material.rsa.q);
        add_mpi("u", key.material.rsa.u);
        break;
    case PGP_PKA_ELGAMAL:
        add_mpi("x", key.material.eg.x);
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA: {
        add_mpi("d", key.material.ec.x);
        break;
    }
    default:
        RNP_LOG("Unsupported public key algorithm: %d", (int) key.alg);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

rnp::secure_vector<uint8_t>
s_exp_t::write_padded(size_t padblock) const
{
    pgp_dest_t raw = {0};
    if (init_mem_dest(&raw, NULL, 0)) {
        RNP_LOG("mem dst alloc failed");
        throw rnp::rnp_exception(RNP_ERROR_OUT_OF_MEMORY);
    }
    mem_dest_secure_memory(&raw, true);

    try {
        if (!write(raw)) {
            RNP_LOG("failed to serialize s_exp");
            throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
        }

        // add padding!
        size_t padding = padblock - raw.writeb % padblock;
        for (size_t i = 0; i < padding; i++) {
            dst_write(&raw, "X", 1);
        }
        if (raw.werr) {
            RNP_LOG("failed to write padding");
            throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
        }

        uint8_t *                   mem = (uint8_t *) mem_dest_get_memory(&raw);
        rnp::secure_vector<uint8_t> res(mem, mem + raw.writeb);
        dst_close(&raw, true);
        return res;
    } catch (const std::exception &e) {
        dst_close(&raw, true);
        throw;
    }
}

void
s_exp_t::add_protected_seckey(pgp_key_pkt_t &seckey, const std::string &password)
{
    pgp_key_protection_t &prot = seckey.sec_protection;
    if (prot.s2k.specifier != PGP_S2KS_ITERATED_AND_SALTED) {
        RNP_LOG("Bad s2k specifier: %d", (int) prot.s2k.specifier);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    const format_info *format =
      find_format(prot.symm_alg, prot.cipher_mode, prot.s2k.hash_alg);
    if (!format) {
        RNP_LOG("Unknown protection format.");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    // randomize IV and salt
    rng_t rng = {0};
    if (!rng_init(&rng, RNG_SYSTEM) || !rng_get_data(&rng, prot.iv, sizeof(prot.iv)) ||
        !rng_get_data(&rng, prot.s2k.salt, sizeof(prot.s2k.salt))) {
        rng_destroy(&rng);
        RNP_LOG("iv generation failed");
        throw rnp::rnp_exception(RNP_ERROR_RNG);
    }
    rng_destroy(&rng);

    // write seckey
    s_exp_t  raw_s_exp;
    s_exp_t *psub_s_exp = &raw_s_exp.add_sub();
    psub_s_exp->add_seckey(seckey);

    // calculate hash
    time_t now;
    time(&now);
    char    protected_at[G10_PROTECTED_AT_SIZE + 1];
    uint8_t checksum[G10_SHA1_HASH_SIZE];
    // TODO: how critical is it if we have a skewed timestamp here due to y2k38 problem?
    strftime(protected_at, sizeof(protected_at), "%Y%m%dT%H%M%S", gmtime(&now));
    if (!g10_calculated_hash(seckey, protected_at, checksum)) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    psub_s_exp = &raw_s_exp.add_sub();
    psub_s_exp->add("hash");
    psub_s_exp->add("sha1");
    psub_s_exp->add(checksum, sizeof(checksum));

    /* write raw secret key to the memory */
    rnp::secure_vector<uint8_t> rawkey = raw_s_exp.write_padded(format->cipher_block_size);

    /* derive encrypting key */
    unsigned keysize = pgp_key_size(prot.symm_alg);
    if (!keysize) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    rnp::secure_array<uint8_t, PGP_MAX_KEY_SIZE> derived_key;
    if (pgp_s2k_iterated(format->hash_alg,
                         derived_key.data(),
                         keysize,
                         password.c_str(),
                         prot.s2k.salt,
                         prot.s2k.iterations)) {
        RNP_LOG("s2k key derivation failed");
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    /* encrypt raw key */
    std::unique_ptr<Cipher> enc(
      Cipher::encryption(format->cipher, format->cipher_mode, 0, true));
    if (!enc || !enc->set_key(derived_key.data(), keysize) ||
        !enc->set_iv(prot.iv, format->iv_size)) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    size_t               output_written, input_consumed;
    std::vector<uint8_t> enckey(rawkey.size());

    if (!enc->finish(enckey.data(),
                     enckey.size(),
                     &output_written,
                     rawkey.data(),
                     rawkey.size(),
                     &input_consumed)) {
        RNP_LOG("Encryption failed");
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    /* build s_exp with encrypted key */
    psub_s_exp = &add_sub();
    psub_s_exp->add("protected");
    psub_s_exp->add(format->g10_type);
    /* protection params: s2k, iv */
    s_exp_t *psub_sub_s_exp = &psub_s_exp->add_sub();
    /* s2k params: hash, salt, iterations */
    s_exp_t *psub_sub_sub_s_exp = &psub_sub_s_exp->add_sub();
    psub_sub_sub_s_exp->add("sha1");
    psub_sub_sub_s_exp->add(prot.s2k.salt, PGP_SALT_SIZE);
    psub_sub_sub_s_exp->add(prot.s2k.iterations);
    psub_sub_s_exp->add(prot.iv, format->iv_size);
    /* encrypted key data itself */
    psub_s_exp->add(enckey.data(), enckey.size());
    /* protected-at */
    psub_s_exp = &add_sub();
    psub_s_exp->add("protected-at");
    psub_s_exp->add((uint8_t *) protected_at, G10_PROTECTED_AT_SIZE);
}

bool
g10_write_seckey(pgp_dest_t *dst, pgp_key_pkt_t *seckey, const char *password)
{
    bool is_protected = true;

    switch (seckey->sec_protection.s2k.usage) {
    case PGP_S2KU_NONE:
        is_protected = false;
        break;
    case PGP_S2KU_ENCRYPTED_AND_HASHED:
        is_protected = true;
        // TODO: these are forced for now, until openpgp-native is implemented
        seckey->sec_protection.symm_alg = PGP_SA_AES_128;
        seckey->sec_protection.cipher_mode = PGP_CIPHER_MODE_CBC;
        seckey->sec_protection.s2k.hash_alg = PGP_HASH_SHA1;
        break;
    default:
        RNP_LOG("unsupported s2k usage");
        return false;
    }

    try {
        s_exp_t s_exp;
        s_exp.add(is_protected ? "protected-private-key" : "private-key");
        s_exp_t &pkey = s_exp.add_sub();
        pkey.add_pubkey(*seckey);

        if (is_protected) {
            pkey.add_protected_seckey(*seckey, password);
        } else {
            pkey.add_seckey(*seckey);
        }
        return s_exp.write(*dst) && !dst->werr;
    } catch (const std::exception &e) {
        RNP_LOG("Failed to write g10 key: %s", e.what());
        return false;
    }
}

static bool
g10_calculated_hash(const pgp_key_pkt_t &key, const char *protected_at, uint8_t *checksum)
{
    pgp_dest_t memdst = {};
    try {
        /* populate s_exp */
        s_exp_t s_exp;
        s_exp.add_pubkey(key);
        s_exp.add_seckey(key);
        s_exp_t &s_sub_exp = s_exp.add_sub();
        s_sub_exp.add("protected-at");
        s_sub_exp.add((uint8_t *) protected_at, G10_PROTECTED_AT_SIZE);
        /* write it to memdst */
        if (init_mem_dest(&memdst, NULL, 0)) {
            return false;
        }
        mem_dest_secure_memory(&memdst, true);
        if (!s_exp.write(memdst)) {
            RNP_LOG("Failed to write s_exp");
            dst_close(&memdst, true);
            return false;
        }
        rnp::Hash hash(PGP_HASH_SHA1);
        hash.add(mem_dest_get_memory(&memdst), memdst.writeb);
        hash.finish(checksum);
        dst_close(&memdst, true);
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("Failed to build s_exp: %s", e.what());
        dst_close(&memdst, true);
        return false;
    }
}

bool
rnp_key_store_g10_key_to_dst(pgp_key_t *key, pgp_dest_t *dest)
{
    if (key->format != PGP_KEY_STORE_G10) {
        RNP_LOG("incorrect format: %d", key->format);
        return false;
    }
    pgp_rawpacket_t &packet = key->rawpkt();
    dst_write(dest, packet.raw.data(), packet.raw.size());
    return dest->werr == RNP_SUCCESS;
}
