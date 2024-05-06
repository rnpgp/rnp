/*
 * Copyright (c) 2023, [MTG AG](https://www.mtg.de).
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

#include "sphincsplus.h"
#include <cassert>
#include "logging.h"
#include "types.h"

namespace {
Botan::Sphincs_Parameter_Set
rnp_sphincsplus_alg_to_botan_param(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_SPHINCSPLUS_SHAKE_128f:
        return Botan::Sphincs_Parameter_Set::Sphincs128Fast;
    case PGP_PKA_SPHINCSPLUS_SHAKE_128s:
        return Botan::Sphincs_Parameter_Set::Sphincs128Small;
    case PGP_PKA_SPHINCSPLUS_SHAKE_256s:
        return Botan::Sphincs_Parameter_Set::Sphincs256Small;
    default:
        RNP_LOG("invalid algorithm ID given");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}
} // namespace

pgp_sphincsplus_public_key_t::pgp_sphincsplus_public_key_t(const uint8_t *  key_encoded,
                                                           size_t           key_encoded_len,
                                                           pgp_pubkey_alg_t alg)
    : key_encoded_(key_encoded, key_encoded + key_encoded_len), pk_alg_(alg),
      is_initialized_(true)
{
}

pgp_sphincsplus_public_key_t::pgp_sphincsplus_public_key_t(
  std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t alg)
    : key_encoded_(key_encoded), pk_alg_(alg), is_initialized_(true)
{
}

pgp_sphincsplus_private_key_t::pgp_sphincsplus_private_key_t(const uint8_t *  key_encoded,
                                                             size_t           key_encoded_len,
                                                             pgp_pubkey_alg_t alg)
    : key_encoded_(key_encoded, key_encoded + key_encoded_len), pk_alg_(alg),
      is_initialized_(true)
{
}

pgp_sphincsplus_private_key_t::pgp_sphincsplus_private_key_t(
  std::vector<uint8_t> const &key_encoded, pgp_pubkey_alg_t alg)
    : key_encoded_(Botan::secure_vector<uint8_t>(key_encoded.begin(), key_encoded.end())),
      pk_alg_(alg), is_initialized_(true)
{
}

rnp_result_t
pgp_sphincsplus_private_key_t::sign(rnp::RNG *                   rng,
                                    pgp_sphincsplus_signature_t *sig,
                                    const uint8_t *              msg,
                                    size_t                       msg_len) const
{
    assert(is_initialized_);
    auto priv_key = botan_key();

    auto signer = Botan::PK_Signer(priv_key, *rng->obj(), "");
    sig->sig = signer.sign_message(msg, msg_len, *rng->obj());

    return RNP_SUCCESS;
}

Botan::SphincsPlus_PublicKey
pgp_sphincsplus_public_key_t::botan_key() const
{
    return Botan::SphincsPlus_PublicKey(key_encoded_,
                                        rnp_sphincsplus_alg_to_botan_param(this->pk_alg_),
                                        Botan::Sphincs_Hash_Type::Shake256);
}

Botan::SphincsPlus_PrivateKey
pgp_sphincsplus_private_key_t::botan_key() const
{
    Botan::secure_vector<uint8_t> priv_sv(key_encoded_.data(),
                                          key_encoded_.data() + key_encoded_.size());
    return Botan::SphincsPlus_PrivateKey(priv_sv,
                                         rnp_sphincsplus_alg_to_botan_param(this->pk_alg_),
                                         Botan::Sphincs_Hash_Type::Shake256);
}

rnp_result_t
pgp_sphincsplus_public_key_t::verify(const pgp_sphincsplus_signature_t *sig,
                                     const uint8_t *                    msg,
                                     size_t                             msg_len) const
{
    assert(is_initialized_);
    auto pub_key = botan_key();

    auto verificator = Botan::PK_Verifier(pub_key, "");
    if (verificator.verify_message(msg, msg_len, sig->sig.data(), sig->sig.size())) {
        return RNP_SUCCESS;
    }
    return RNP_ERROR_SIGNATURE_INVALID;
}

std::pair<pgp_sphincsplus_public_key_t, pgp_sphincsplus_private_key_t>
sphincsplus_generate_keypair(rnp::RNG *rng, pgp_pubkey_alg_t alg)
{
    Botan::SphincsPlus_PrivateKey priv_key(*rng->obj(),
                                           rnp_sphincsplus_alg_to_botan_param(alg),
                                           Botan::Sphincs_Hash_Type::Shake256);

    std::unique_ptr<Botan::Public_Key> pub_key = priv_key.public_key();
    Botan::secure_vector<uint8_t>      priv_bits = priv_key.private_key_bits();
    return std::make_pair(
      pgp_sphincsplus_public_key_t(pub_key->public_key_bits(), alg),
      pgp_sphincsplus_private_key_t(priv_bits.data(), priv_bits.size(), alg));
}

rnp_result_t
pgp_sphincsplus_generate(rnp::RNG *rng, pgp_sphincsplus_key_t *material, pgp_pubkey_alg_t alg)
{
    auto keypair = sphincsplus_generate_keypair(rng, alg);
    material->pub = keypair.first;
    material->priv = keypair.second;

    return RNP_SUCCESS;
}

bool
pgp_sphincsplus_public_key_t::validate_signature_hash_requirements(
  pgp_hash_alg_t hash_alg) const
{
    /* check if key is allowed with the hash algorithm */
    return sphincsplus_hash_allowed(pk_alg_, hash_alg);
}

bool
pgp_sphincsplus_public_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }

    auto key = botan_key();
    return key.check_key(*(rng->obj()), false);
}

bool
pgp_sphincsplus_private_key_t::is_valid(rnp::RNG *rng) const
{
    if (!is_initialized_) {
        return false;
    }

    auto key = botan_key();
    return key.check_key(*(rng->obj()), false);
}

rnp_result_t
sphincsplus_validate_key(rnp::RNG *rng, const pgp_sphincsplus_key_t *key, bool secret)
{
    bool valid;

    valid = key->pub.is_valid(rng);
    if (secret) {
        valid = valid && key->priv.is_valid(rng);
    }
    if (!valid) {
        return RNP_ERROR_GENERIC;
    }

    return RNP_SUCCESS;
}

size_t
sphincsplus_privkey_size(pgp_pubkey_alg_t alg)
{
    return 2 * sphincsplus_pubkey_size(alg);
}

size_t
sphincsplus_pubkey_size(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_SPHINCSPLUS_SHAKE_128f:
        return 32;
    case PGP_PKA_SPHINCSPLUS_SHAKE_128s:
        return 32;
    case PGP_PKA_SPHINCSPLUS_SHAKE_256s:
        return 64;
    default:
        RNP_LOG("invalid algorithm ID given");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

size_t
sphincsplus_signature_size(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_SPHINCSPLUS_SHAKE_128f:
        return 17088;
    case PGP_PKA_SPHINCSPLUS_SHAKE_128s:
        return 7856;
    case PGP_PKA_SPHINCSPLUS_SHAKE_256s:
        return 29792;
    default:
        RNP_LOG("invalid algorithm ID given");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

bool
sphincsplus_hash_allowed(pgp_pubkey_alg_t pk_alg, pgp_hash_alg_t hash_alg)
{
    switch (pk_alg) {
    case PGP_PKA_SPHINCSPLUS_SHAKE_128f:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_SPHINCSPLUS_SHAKE_128s:
        return hash_alg == PGP_HASH_SHA3_256;
    case PGP_PKA_SPHINCSPLUS_SHAKE_256s:
        return hash_alg == PGP_HASH_SHA3_512;
    default:
        RNP_LOG("invalid algorithm ID given");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

pgp_hash_alg_t
sphincsplus_default_hash_alg(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_SPHINCSPLUS_SHAKE_128f:
        return PGP_HASH_SHA3_256;
    case PGP_PKA_SPHINCSPLUS_SHAKE_128s:
        return PGP_HASH_SHA3_256;
    case PGP_PKA_SPHINCSPLUS_SHAKE_256s:
        return PGP_HASH_SHA3_512;
    default:
        RNP_LOG("invalid algorithm ID given");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}
