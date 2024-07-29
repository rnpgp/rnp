/*
 * Copyright (c) 2024 [Ribose Inc](https://www.ribose.com).
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

#include "key_material.hpp"
#include "librepgp/stream-packet.h"
#include "logging.h"
#include "utils.h"
#include "config.h"
#include <cassert>

namespace {
void
grip_hash_mpi(rnp::Hash &hash, const pgp::mpi &val, const char name, bool lzero = true)
{
    size_t len = val.bytes();
    size_t idx = 0;
    for (idx = 0; (idx < len) && !val.mpi[idx]; idx++)
        ;

    if (name) {
        size_t hlen = idx >= len ? 0 : len - idx;
        if ((len > idx) && lzero && (val.mpi[idx] & 0x80)) {
            hlen++;
        }

        char buf[26] = {0};
        snprintf(buf, sizeof(buf), "(1:%c%zu:", name, hlen);
        hash.add(buf, strlen(buf));
    }

    if (idx < len) {
        /* gcrypt prepends mpis with zero if higher bit is set */
        if (lzero && (val.mpi[idx] & 0x80)) {
            uint8_t zero = 0;
            hash.add(&zero, 1);
        }
        hash.add(val.mpi + idx, len - idx);
    }
    if (name) {
        hash.add(")", 1);
    }
}

void
grip_hash_ecc_hex(rnp::Hash &hash, const char *hex, char name)
{
    pgp::mpi mpi = {};
    mpi.len = rnp::hex_decode(hex, mpi.mpi, sizeof(mpi.mpi));
    if (!mpi.len) {
        RNP_LOG("wrong hex mpi");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    /* libgcrypt doesn't add leading zero when hashes ecc mpis */
    return grip_hash_mpi(hash, mpi, name, false);
}

void
grip_hash_ec(rnp::Hash &hash, const pgp_ec_key_t &key)
{
    const ec_curve_desc_t *desc = get_curve_desc(key.curve);
    if (!desc) {
        RNP_LOG("unknown curve %d", (int) key.curve);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    /* build uncompressed point from gx and gy */
    pgp::mpi g = {};
    g.mpi[0] = 0x04;
    g.len = 1;
    size_t len = rnp::hex_decode(desc->gx, g.mpi + g.len, sizeof(g.mpi) - g.len);
    if (!len) {
        RNP_LOG("wrong x mpi");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    g.len += len;
    len = rnp::hex_decode(desc->gy, g.mpi + g.len, sizeof(g.mpi) - g.len);
    if (!len) {
        RNP_LOG("wrong y mpi");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    g.len += len;

    /* p, a, b, g, n, q */
    grip_hash_ecc_hex(hash, desc->p, 'p');
    grip_hash_ecc_hex(hash, desc->a, 'a');
    grip_hash_ecc_hex(hash, desc->b, 'b');
    grip_hash_mpi(hash, g, 'g', false);
    grip_hash_ecc_hex(hash, desc->n, 'n');

    if ((key.curve == PGP_CURVE_ED25519) || (key.curve == PGP_CURVE_25519)) {
        if (g.len < 1) {
            RNP_LOG("wrong 25519 p");
            throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
        }
        g.len = key.p.len - 1;
        memcpy(g.mpi, key.p.mpi + 1, g.len);
        grip_hash_mpi(hash, g, 'q', false);
    } else {
        grip_hash_mpi(hash, key.p, 'q', false);
    }
}
} // namespace

namespace pgp {

KeyMaterial::~KeyMaterial()
{
}

pgp_pubkey_alg_t
KeyMaterial::alg() const noexcept
{
    return alg_;
}

bool
KeyMaterial::secret() const noexcept
{
    return secret_;
}

bool
KeyMaterial::valid() const
{
    return validity_.validated && validity_.valid;
}

bool
KeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    return alg_ == value.alg_;
}

void
KeyMaterial::validate(rnp::SecurityContext &ctx, bool reset)
{
    if (!reset && validity_.validated) {
        return;
    }
    validity_.reset();
#ifdef FUZZERS_ENABLED
    /* do not timeout on large keys during fuzzing */
    validity_.valid = true;
#else
    validity_.valid = validate_material(ctx, reset);
#endif
    validity_.validated = true;
}

const pgp_validity_t &
KeyMaterial::validity() const noexcept
{
    return validity_;
}

void
KeyMaterial::set_validity(const pgp_validity_t &val)
{
    validity_ = val;
}

void
KeyMaterial::reset_validity()
{
    validity_.reset();
}

void
KeyMaterial::clear_secret()
{
    secret_ = false;
}

bool
KeyMaterial::finish_generate()
{
    validity_.mark_valid();
    secret_ = true;
    return true;
}

bool
KeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    RNP_LOG("key generation not implemented for PK alg: %d", alg_);
    return false;
}

rnp_result_t
KeyMaterial::encrypt(rnp::SecurityContext &    ctx,
                     pgp_encrypted_material_t &out,
                     const uint8_t *           data,
                     size_t                    len) const
{
    return RNP_ERROR_NOT_SUPPORTED;
}

rnp_result_t
KeyMaterial::decrypt(rnp::SecurityContext &          ctx,
                     uint8_t *                       out,
                     size_t &                        out_len,
                     const pgp_encrypted_material_t &in) const
{
    return RNP_ERROR_NOT_SUPPORTED;
}

rnp_result_t
KeyMaterial::verify(const rnp::SecurityContext &       ctx,
                    const pgp_signature_material_t &   sig,
                    const rnp::secure_vector<uint8_t> &hash) const
{
    return RNP_ERROR_NOT_SUPPORTED;
}

rnp_result_t
KeyMaterial::sign(rnp::SecurityContext &             ctx,
                  pgp_signature_material_t &         sig,
                  const rnp::secure_vector<uint8_t> &hash) const
{
    return RNP_ERROR_NOT_SUPPORTED;
}

pgp_hash_alg_t
KeyMaterial::adjust_hash(pgp_hash_alg_t hash) const
{
    return hash;
}

bool
KeyMaterial::sig_hash_allowed(pgp_hash_alg_t hash) const
{
    return true;
}

pgp_curve_t
KeyMaterial::curve() const noexcept
{
    return PGP_CURVE_UNKNOWN;
}

pgp_key_grip_t
KeyMaterial::grip() const
{
    auto hash = rnp::Hash::create(PGP_HASH_SHA1);
    grip_update(*hash);
    pgp_key_grip_t res;
    hash->finish(res.data());
    return res;
}

std::unique_ptr<KeyMaterial>
KeyMaterial::create(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return std::unique_ptr<KeyMaterial>(new RSAKeyMaterial(alg));
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return std::unique_ptr<KeyMaterial>(new EGKeyMaterial(alg));
    case PGP_PKA_DSA:
        return std::unique_ptr<KeyMaterial>(new DSAKeyMaterial());
    case PGP_PKA_ECDH:
        return std::unique_ptr<KeyMaterial>(new ECDHKeyMaterial());
    case PGP_PKA_ECDSA:
        return std::unique_ptr<KeyMaterial>(new ECDSAKeyMaterial());
    case PGP_PKA_EDDSA:
        return std::unique_ptr<KeyMaterial>(new EDDSAKeyMaterial());
#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_PKA_ED25519:
        return std::unique_ptr<KeyMaterial>(new Ed25519KeyMaterial());
    case PGP_PKA_X25519:
        return std::unique_ptr<KeyMaterial>(new X25519KeyMaterial());
#endif
    case PGP_PKA_SM2:
        return std::unique_ptr<KeyMaterial>(new SM2KeyMaterial());
#if defined(ENABLE_PQC)
    case PGP_PKA_KYBER768_X25519:
        FALLTHROUGH_STATEMENT;
    // TODO add case PGP_PKA_KYBER1024_X448
    case PGP_PKA_KYBER768_P256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER1024_P384:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER768_BP256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER1024_BP384:
        return std::unique_ptr<KeyMaterial>(new KyberKeyMaterial(alg));
    case PGP_PKA_DILITHIUM3_ED25519:
        FALLTHROUGH_STATEMENT;
    // TODO: add case PGP_PKA_DILITHIUM5_ED448
    case PGP_PKA_DILITHIUM3_P256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM5_P384:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM3_BP256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM5_BP384:
        return std::unique_ptr<KeyMaterial>(new DilithiumKeyMaterial(alg));
    case PGP_PKA_SPHINCSPLUS_SHA2:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_SPHINCSPLUS_SHAKE:
        return std::unique_ptr<KeyMaterial>(new SphincsPlusKeyMaterial(alg));
#endif
    default:
        return nullptr;
    }
}

std::unique_ptr<KeyMaterial>
KeyMaterial::create(pgp_pubkey_alg_t alg, const pgp_rsa_key_t &key)
{
    return std::unique_ptr<pgp::KeyMaterial>(new pgp::RSAKeyMaterial(alg, key));
}

std::unique_ptr<KeyMaterial>
KeyMaterial::create(const pgp_dsa_key_t &key)
{
    return std::unique_ptr<pgp::KeyMaterial>(new pgp::DSAKeyMaterial(key));
}

std::unique_ptr<KeyMaterial>
KeyMaterial::create(pgp_pubkey_alg_t alg, const pgp_eg_key_t &key)
{
    return std::unique_ptr<pgp::KeyMaterial>(new pgp::EGKeyMaterial(alg, key));
}

std::unique_ptr<KeyMaterial>
KeyMaterial::create(pgp_pubkey_alg_t alg, const pgp_ec_key_t &key)
{
    switch (alg) {
    case PGP_PKA_ECDSA:
        return std::unique_ptr<pgp::KeyMaterial>(new pgp::ECDSAKeyMaterial(key));
    case PGP_PKA_ECDH:
        return std::unique_ptr<pgp::KeyMaterial>(new pgp::ECDHKeyMaterial(key));
    case PGP_PKA_EDDSA:
        return std::unique_ptr<pgp::KeyMaterial>(new pgp::EDDSAKeyMaterial(key));
    case PGP_PKA_SM2:
        return std::unique_ptr<pgp::KeyMaterial>(new pgp::SM2KeyMaterial(key));
    default:
        throw std::invalid_argument("Invalid EC algorithm.");
    }
}

std::unique_ptr<KeyMaterial>
RSAKeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new RSAKeyMaterial(*this));
}

void
RSAKeyMaterial::grip_update(rnp::Hash &hash) const
{
    /* keygrip is subjectKeyHash from pkcs#15 for RSA. */
    grip_hash_mpi(hash, key_.n, '\0');
}

bool
RSAKeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    return !rsa_validate_key(&ctx.rng, &key_, secret_);
}

bool
RSAKeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    auto key = dynamic_cast<const RSAKeyMaterial *>(&value);
    if (!key || !KeyMaterial::equals(value)) {
        return false;
    }
    return (key->key_.n == key_.n) && (key->key_.e == key_.e);
}

void
RSAKeyMaterial::clear_secret()
{
    key_.clear_secret();
    KeyMaterial::clear_secret();
}

bool
RSAKeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    secret_ = false;
    return pkt.get(key_.n) && pkt.get(key_.e);
}

bool
RSAKeyMaterial::parse_secret(pgp_packet_body_t &pkt) noexcept
{
    if (!pkt.get(key_.d) || !pkt.get(key_.p) || !pkt.get(key_.q) || !pkt.get(key_.u)) {
        RNP_LOG("failed to parse rsa secret key data");
        return false;
    }
    secret_ = true;
    return true;
}

void
RSAKeyMaterial::write(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.n);
    pkt.add(key_.e);
}

void
RSAKeyMaterial::write_secret(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.d);
    pkt.add(key_.p);
    pkt.add(key_.q);
    pkt.add(key_.u);
}

bool
RSAKeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    /* We do not generate PGP_PKA_RSA_ENCRYPT_ONLY or PGP_PKA_RSA_SIGN_ONLY keys */
    if (alg_ != PGP_PKA_RSA) {
        RNP_LOG("Unsupported algorithm for key generation: %d", alg_);
        return false;
    }
    if (rsa_generate(&params.ctx->rng, &key_, params.rsa.modulus_bit_len)) {
        RNP_LOG("failed to generate RSA key");
        return false;
    }
    return finish_generate();
}

rnp_result_t
RSAKeyMaterial::encrypt(rnp::SecurityContext &    ctx,
                        pgp_encrypted_material_t &out,
                        const uint8_t *           data,
                        size_t                    len) const
{
    return rsa_encrypt_pkcs1(&ctx.rng, &out.rsa, data, len, &key_);
}

rnp_result_t
RSAKeyMaterial::decrypt(rnp::SecurityContext &          ctx,
                        uint8_t *                       out,
                        size_t &                        out_len,
                        const pgp_encrypted_material_t &in) const
{
    if ((alg() != PGP_PKA_RSA) && (alg() != PGP_PKA_RSA_ENCRYPT_ONLY)) {
        RNP_LOG("Non-encrypting RSA algorithm: %d\n", alg());
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return rsa_decrypt_pkcs1(&ctx.rng, out, &out_len, &in.rsa, &key_);
}

rnp_result_t
RSAKeyMaterial::verify(const rnp::SecurityContext &       ctx,
                       const pgp_signature_material_t &   sig,
                       const rnp::secure_vector<uint8_t> &hash) const
{
    if (alg() == PGP_PKA_RSA_ENCRYPT_ONLY) {
        RNP_LOG("RSA encrypt-only signature considered as invalid.");
        return RNP_ERROR_SIGNATURE_INVALID;
    }
    return rsa_verify_pkcs1(&sig.rsa, sig.halg, hash.data(), hash.size(), &key_);
}

rnp_result_t
RSAKeyMaterial::sign(rnp::SecurityContext &             ctx,
                     pgp_signature_material_t &         sig,
                     const rnp::secure_vector<uint8_t> &hash) const
{
    return rsa_sign_pkcs1(&ctx.rng, &sig.rsa, sig.halg, hash.data(), hash.size(), &key_);
}

void
RSAKeyMaterial::set_secret(const mpi &d, const mpi &p, const mpi &q, const mpi &u)
{
    key_.d = d;
    key_.p = p;
    key_.q = q;
    key_.u = u;
    secret_ = true;
}

size_t
RSAKeyMaterial::bits() const noexcept
{
    return 8 * key_.n.bytes();
}

const mpi &
RSAKeyMaterial::n() const noexcept
{
    return key_.n;
}

const mpi &
RSAKeyMaterial::e() const noexcept
{
    return key_.e;
}

const mpi &
RSAKeyMaterial::d() const noexcept
{
    return key_.d;
}

const mpi &
RSAKeyMaterial::p() const noexcept
{
    return key_.p;
}

const mpi &
RSAKeyMaterial::q() const noexcept
{
    return key_.q;
}

const mpi &
RSAKeyMaterial::u() const noexcept
{
    return key_.u;
}

std::unique_ptr<KeyMaterial>
DSAKeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new DSAKeyMaterial(*this));
}

void
DSAKeyMaterial::grip_update(rnp::Hash &hash) const
{
    grip_hash_mpi(hash, key_.p, 'p');
    grip_hash_mpi(hash, key_.q, 'q');
    grip_hash_mpi(hash, key_.g, 'g');
    grip_hash_mpi(hash, key_.y, 'y');
}

bool
DSAKeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    return !dsa_validate_key(&ctx.rng, &key_, secret_);
}

bool
DSAKeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    auto key = dynamic_cast<const DSAKeyMaterial *>(&value);
    if (!key || !KeyMaterial::equals(value)) {
        return false;
    }
    return (key->key_.p == key_.p) && (key->key_.q == key_.q) && (key->key_.g == key_.g) &&
           (key->key_.y == key_.y);
}

void
DSAKeyMaterial::clear_secret()
{
    key_.clear_secret();
    KeyMaterial::clear_secret();
}

bool
DSAKeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    secret_ = false;
    return pkt.get(key_.p) && pkt.get(key_.q) && pkt.get(key_.g) && pkt.get(key_.y);
}

bool
DSAKeyMaterial::parse_secret(pgp_packet_body_t &pkt) noexcept
{
    if (!pkt.get(key_.x)) {
        RNP_LOG("failed to parse dsa secret key data");
        return false;
    }
    secret_ = true;
    return true;
}

void
DSAKeyMaterial::write(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.p);
    pkt.add(key_.q);
    pkt.add(key_.g);
    pkt.add(key_.y);
}

void
DSAKeyMaterial::write_secret(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.x);
}

bool
DSAKeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    if (dsa_generate(&params.ctx->rng, &key_, params.dsa.p_bitlen, params.dsa.q_bitlen)) {
        RNP_LOG("failed to generate DSA key");
        return false;
    }
    return finish_generate();
}

rnp_result_t
DSAKeyMaterial::verify(const rnp::SecurityContext &       ctx,
                       const pgp_signature_material_t &   sig,
                       const rnp::secure_vector<uint8_t> &hash) const
{
    return dsa_verify(&sig.dsa, hash.data(), hash.size(), &key_);
}

rnp_result_t
DSAKeyMaterial::sign(rnp::SecurityContext &             ctx,
                     pgp_signature_material_t &         sig,
                     const rnp::secure_vector<uint8_t> &hash) const
{
    return dsa_sign(&ctx.rng, &sig.dsa, hash.data(), hash.size(), &key_);
}

pgp_hash_alg_t
DSAKeyMaterial::adjust_hash(pgp_hash_alg_t hash) const
{
    pgp_hash_alg_t hash_min = dsa_get_min_hash(key_.q.bits());
    if (rnp::Hash::size(hash) < rnp::Hash::size(hash_min)) {
        return hash_min;
    }
    return hash;
}

void
DSAKeyMaterial::set_secret(const mpi &x)
{
    key_.x = x;
    secret_ = true;
}

size_t
DSAKeyMaterial::bits() const noexcept
{
    return 8 * key_.p.bytes();
}

size_t
DSAKeyMaterial::qbits() const noexcept
{
    return 8 * key_.q.bytes();
}

const mpi &
DSAKeyMaterial::p() const noexcept
{
    return key_.p;
}

const mpi &
DSAKeyMaterial::q() const noexcept
{
    return key_.q;
}

const mpi &
DSAKeyMaterial::g() const noexcept
{
    return key_.g;
}

const mpi &
DSAKeyMaterial::y() const noexcept
{
    return key_.y;
}

const mpi &
DSAKeyMaterial::x() const noexcept
{
    return key_.x;
}

std::unique_ptr<KeyMaterial>
EGKeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new EGKeyMaterial(*this));
}

void
EGKeyMaterial::grip_update(rnp::Hash &hash) const
{
    grip_hash_mpi(hash, key_.p, 'p');
    grip_hash_mpi(hash, key_.g, 'g');
    grip_hash_mpi(hash, key_.y, 'y');
}

bool
EGKeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    return elgamal_validate_key(&key_, secret_);
}

bool
EGKeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    auto key = dynamic_cast<const EGKeyMaterial *>(&value);
    if (!key || !KeyMaterial::equals(value)) {
        return false;
    }
    return (key->key_.p == key_.p) && (key->key_.g == key_.g) && (key->key_.y == key_.y);
}

void
EGKeyMaterial::clear_secret()
{
    key_.clear_secret();
    KeyMaterial::clear_secret();
}

bool
EGKeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    secret_ = false;
    return pkt.get(key_.p) && pkt.get(key_.g) && pkt.get(key_.y);
}

bool
EGKeyMaterial::parse_secret(pgp_packet_body_t &pkt) noexcept
{
    if (!pkt.get(key_.x)) {
        RNP_LOG("failed to parse eg secret key data");
        return false;
    }
    secret_ = true;
    return true;
}

void
EGKeyMaterial::write(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.p);
    pkt.add(key_.g);
    pkt.add(key_.y);
}

void
EGKeyMaterial::write_secret(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.x);
}

bool
EGKeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    /* We do not generate PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN keys */
    if (alg_ != PGP_PKA_ELGAMAL) {
        RNP_LOG("Unsupported algorithm for key generation: %d", alg_);
        return false;
    }
    if (elgamal_generate(&params.ctx->rng, &key_, params.elgamal.key_bitlen)) {
        RNP_LOG("failed to generate ElGamal key");
        return false;
    }
    return finish_generate();
}

rnp_result_t
EGKeyMaterial::encrypt(rnp::SecurityContext &    ctx,
                       pgp_encrypted_material_t &out,
                       const uint8_t *           data,
                       size_t                    len) const
{
    return elgamal_encrypt_pkcs1(&ctx.rng, &out.eg, data, len, &key_);
}

rnp_result_t
EGKeyMaterial::decrypt(rnp::SecurityContext &          ctx,
                       uint8_t *                       out,
                       size_t &                        out_len,
                       const pgp_encrypted_material_t &in) const
{
    return elgamal_decrypt_pkcs1(&ctx.rng, out, &out_len, &in.eg, &key_);
}

rnp_result_t
EGKeyMaterial::verify(const rnp::SecurityContext &       ctx,
                      const pgp_signature_material_t &   sig,
                      const rnp::secure_vector<uint8_t> &hash) const
{
    RNP_LOG("ElGamal signatures are considered as invalid.");
    return RNP_ERROR_SIGNATURE_INVALID;
}

void
EGKeyMaterial::set_secret(const mpi &x)
{
    key_.x = x;
    secret_ = true;
}

size_t
EGKeyMaterial::bits() const noexcept
{
    return 8 * key_.y.bytes();
}

const mpi &
EGKeyMaterial::p() const noexcept
{
    return key_.p;
}

const mpi &
EGKeyMaterial::g() const noexcept
{
    return key_.g;
}

const mpi &
EGKeyMaterial::y() const noexcept
{
    return key_.y;
}

const mpi &
EGKeyMaterial::x() const noexcept
{
    return key_.x;
}

void
ECKeyMaterial::grip_update(rnp::Hash &hash) const
{
    grip_hash_ec(hash, key_);
}

bool
ECKeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    auto key = dynamic_cast<const ECKeyMaterial *>(&value);
    if (!key || !KeyMaterial::equals(value)) {
        return false;
    }
    return (key->key_.curve == key_.curve) && (key->key_.p == key_.p);
}

void
ECKeyMaterial::clear_secret()
{
    key_.clear_secret();
    KeyMaterial::clear_secret();
}

rnp_result_t
ECKeyMaterial::check_curve(size_t hash_len) const
{
    const ec_curve_desc_t *curve = get_curve_desc(key_.curve);
    if (!curve) {
        RNP_LOG("Unknown curve");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (!curve_supported(key_.curve)) {
        RNP_LOG("EC sign: curve %s is not supported.", curve->pgp_name);
        return RNP_ERROR_NOT_SUPPORTED;
    }
    /* "-2" because ECDSA on P-521 must work with SHA-512 digest */
    if (BITS_TO_BYTES(curve->bitlen) - 2 > hash_len) {
        RNP_LOG("Message hash too small");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    return RNP_SUCCESS;
}

bool
ECKeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    secret_ = false;
    if (!pkt.get(key_.curve) || !pkt.get(key_.p)) {
        return false;
    }
    return true;
}

bool
ECKeyMaterial::parse_secret(pgp_packet_body_t &pkt) noexcept
{
    if (!pkt.get(key_.x)) {
        RNP_LOG("failed to parse ecc secret key data");
        return false;
    }
    secret_ = true;
    return true;
}

void
ECKeyMaterial::write(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.curve);
    pkt.add(key_.p);
}

void
ECKeyMaterial::write_secret(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.x);
}

bool
ECKeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    if (!curve_supported(params.ecc.curve)) {
        RNP_LOG("EC generate: curve %d is not supported.", params.ecc.curve);
        return false;
    }
    if (ec_generate(&params.ctx->rng, &key_, alg_, params.ecc.curve)) {
        RNP_LOG("failed to generate EC key");
        return false;
    }
    key_.curve = params.ecc.curve;
    return finish_generate();
}

void
ECKeyMaterial::set_secret(const mpi &x)
{
    key_.x = x;
    secret_ = true;
}

size_t
ECKeyMaterial::bits() const noexcept
{
    auto curve_desc = get_curve_desc(key_.curve);
    return curve_desc ? curve_desc->bitlen : 0;
}

pgp_curve_t
ECKeyMaterial::curve() const noexcept
{
    return key_.curve;
}

const mpi &
ECKeyMaterial::p() const noexcept
{
    return key_.p;
}

const mpi &
ECKeyMaterial::x() const noexcept
{
    return key_.x;
}

bool
ECDSAKeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    if (!curve_supported(key_.curve)) {
        /* allow to import key if curve is not supported */
        RNP_LOG("ECDSA validate: curve %d is not supported.", key_.curve);
        return true;
    }
    return !ecdsa_validate_key(&ctx.rng, &key_, secret_);
}

std::unique_ptr<KeyMaterial>
ECDSAKeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new ECDSAKeyMaterial(*this));
}

rnp_result_t
ECDSAKeyMaterial::verify(const rnp::SecurityContext &       ctx,
                         const pgp_signature_material_t &   sig,
                         const rnp::secure_vector<uint8_t> &hash) const
{
    if (!curve_supported(key_.curve)) {
        RNP_LOG("Curve %d is not supported.", key_.curve);
        return RNP_ERROR_NOT_SUPPORTED;
    }
    return ecdsa_verify(&sig.ecc, sig.halg, hash.data(), hash.size(), &key_);
}

rnp_result_t
ECDSAKeyMaterial::sign(rnp::SecurityContext &             ctx,
                       pgp_signature_material_t &         sig,
                       const rnp::secure_vector<uint8_t> &hash) const
{
    auto ret = check_curve(hash.size());
    if (ret) {
        return ret;
    }
    return ecdsa_sign(&ctx.rng, &sig.ecc, sig.halg, hash.data(), hash.size(), &key_);
}

pgp_hash_alg_t
ECDSAKeyMaterial::adjust_hash(pgp_hash_alg_t hash) const
{
    pgp_hash_alg_t hash_min = ecdsa_get_min_hash(key_.curve);
    if (rnp::Hash::size(hash) < rnp::Hash::size(hash_min)) {
        return hash_min;
    }
    return hash;
}

bool
ECDHKeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    if (!curve_supported(key_.curve)) {
        /* allow to import key if curve is not supported */
        RNP_LOG("ECDH validate: curve %d is not supported.", key_.curve);
        return true;
    }
    return !ecdh_validate_key(&ctx.rng, &key_, secret_);
}

std::unique_ptr<KeyMaterial>
ECDHKeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new ECDHKeyMaterial(*this));
}

bool
ECDHKeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    if (!ECKeyMaterial::parse(pkt)) {
        return false;
    }
    /* Additional ECDH fields */
    /* Read KDF parameters. At the moment should be 0x03 0x01 halg ealg */
    uint8_t len = 0, halg = 0, walg = 0;
    if (!pkt.get(len) || (len != 3)) {
        return false;
    }
    if (!pkt.get(len) || (len != 1)) {
        return false;
    }
    if (!pkt.get(halg) || !pkt.get(walg)) {
        return false;
    }
    key_.kdf_hash_alg = (pgp_hash_alg_t) halg;
    key_.key_wrap_alg = (pgp_symm_alg_t) walg;
    return true;
}

void
ECDHKeyMaterial::write(pgp_packet_body_t &pkt) const
{
    ECKeyMaterial::write(pkt);
    pkt.add_byte(3);
    pkt.add_byte(1);
    pkt.add_byte(key_.kdf_hash_alg);
    pkt.add_byte(key_.key_wrap_alg);
}

bool
ECDHKeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    if (!ecdh_set_params(&key_, params.ecc.curve)) {
        RNP_LOG("Unsupported curve [ID=%d]", params.ecc.curve);
        return false;
    }
    /* Special case for x25519*/
    if (params.ecc.curve == PGP_CURVE_25519) {
        if (x25519_generate(&params.ctx->rng, &key_)) {
            RNP_LOG("failed to generate x25519 key");
            return false;
        }
        key_.curve = params.ecc.curve;
        return finish_generate();
        ;
    }
    /* Fallback to default EC generation for other cases */
    return ECKeyMaterial::generate(params);
}

rnp_result_t
ECDHKeyMaterial::encrypt(rnp::SecurityContext &    ctx,
                         pgp_encrypted_material_t &out,
                         const uint8_t *           data,
                         size_t                    len) const
{
    if (!curve_supported(key_.curve)) {
        RNP_LOG("ECDH encrypt: curve %d is not supported.", key_.curve);
        return RNP_ERROR_NOT_SUPPORTED;
    }
    assert(out.ecdh.fp);
    return ecdh_encrypt_pkcs5(&ctx.rng, &out.ecdh, data, len, &key_, *out.ecdh.fp);
}

rnp_result_t
ECDHKeyMaterial::decrypt(rnp::SecurityContext &          ctx,
                         uint8_t *                       out,
                         size_t &                        out_len,
                         const pgp_encrypted_material_t &in) const
{
    if (!curve_supported(key_.curve)) {
        RNP_LOG("ECDH decrypt: curve %d is not supported.", key_.curve);
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if ((key_.curve == PGP_CURVE_25519) && !x25519_bits_tweaked()) {
        RNP_LOG("Warning: bits of 25519 secret key are not tweaked.");
    }
    return ecdh_decrypt_pkcs5(out, &out_len, &in.ecdh, &key_, *in.ecdh.fp);
}

pgp_hash_alg_t
ECDHKeyMaterial::kdf_hash_alg() const noexcept
{
    return key_.kdf_hash_alg;
}

pgp_symm_alg_t
ECDHKeyMaterial::key_wrap_alg() const noexcept
{
    return key_.key_wrap_alg;
}

bool
ECDHKeyMaterial::x25519_bits_tweaked() const noexcept
{
    return (key_.curve == PGP_CURVE_25519) && ::x25519_bits_tweaked(key_);
}

bool
ECDHKeyMaterial::x25519_tweak_bits() noexcept
{
    return (key_.curve == PGP_CURVE_25519) && ::x25519_tweak_bits(key_);
}

bool
EDDSAKeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    return !eddsa_validate_key(&ctx.rng, &key_, secret_);
}

std::unique_ptr<KeyMaterial>
EDDSAKeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new EDDSAKeyMaterial(*this));
}

bool
EDDSAKeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    if (eddsa_generate(&params.ctx->rng, &key_)) {
        RNP_LOG("failed to generate EDDSA key");
        return false;
    }
    return finish_generate();
}

rnp_result_t
EDDSAKeyMaterial::verify(const rnp::SecurityContext &       ctx,
                         const pgp_signature_material_t &   sig,
                         const rnp::secure_vector<uint8_t> &hash) const
{
    return eddsa_verify(&sig.ecc, hash.data(), hash.size(), &key_);
}

rnp_result_t
EDDSAKeyMaterial::sign(rnp::SecurityContext &             ctx,
                       pgp_signature_material_t &         sig,
                       const rnp::secure_vector<uint8_t> &hash) const
{
    return eddsa_sign(&ctx.rng, &sig.ecc, hash.data(), hash.size(), &key_);
}

bool
SM2KeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
#if defined(ENABLE_SM2)
    return !sm2_validate_key(&ctx.rng, &key_, secret_);
#else
    RNP_LOG("SM2 key validation is not available.");
    return false;
#endif
}

std::unique_ptr<KeyMaterial>
SM2KeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new SM2KeyMaterial(*this));
}

rnp_result_t
SM2KeyMaterial::encrypt(rnp::SecurityContext &    ctx,
                        pgp_encrypted_material_t &out,
                        const uint8_t *           data,
                        size_t                    len) const
{
#if defined(ENABLE_SM2)
    return sm2_encrypt(&ctx.rng, &out.sm2, data, len, PGP_HASH_SM3, &key_);
#else
    RNP_LOG("sm2_encrypt is not available");
    return RNP_ERROR_NOT_IMPLEMENTED;
#endif
}

rnp_result_t
SM2KeyMaterial::decrypt(rnp::SecurityContext &          ctx,
                        uint8_t *                       out,
                        size_t &                        out_len,
                        const pgp_encrypted_material_t &in) const
{
#if defined(ENABLE_SM2)
    return sm2_decrypt(out, &out_len, &in.sm2, &key_);
#else
    RNP_LOG("SM2 decryption is not available.");
    return RNP_ERROR_NOT_IMPLEMENTED;
#endif
}

rnp_result_t
SM2KeyMaterial::verify(const rnp::SecurityContext &       ctx,
                       const pgp_signature_material_t &   sig,
                       const rnp::secure_vector<uint8_t> &hash) const
{
#if defined(ENABLE_SM2)
    return sm2_verify(&sig.ecc, sig.halg, hash.data(), hash.size(), &key_);
#else
    RNP_LOG("SM2 verification is not available.");
    return RNP_ERROR_NOT_IMPLEMENTED;
#endif
}

rnp_result_t
SM2KeyMaterial::sign(rnp::SecurityContext &             ctx,
                     pgp_signature_material_t &         sig,
                     const rnp::secure_vector<uint8_t> &hash) const
{
#if defined(ENABLE_SM2)
    auto ret = check_curve(hash.size());
    if (ret) {
        return ret;
    }
    return sm2_sign(&ctx.rng, &sig.ecc, sig.halg, hash.data(), hash.size(), &key_);
#else
    RNP_LOG("SM2 signing is not available.");
    return RNP_ERROR_NOT_IMPLEMENTED;
#endif
}

void
SM2KeyMaterial::compute_za(rnp::Hash &hash) const
{
#if defined(ENABLE_SM2)
    auto res = sm2_compute_za(key_, hash);
    if (res) {
        RNP_LOG("failed to compute SM2 ZA field");
        throw rnp::rnp_exception(res);
    }
#else
    RNP_LOG("SM2 ZA computation not available");
    throw rnp::rnp_exception(RNP_ERROR_NOT_IMPLEMENTED);
#endif
}

#if defined(ENABLE_CRYPTO_REFRESH)
std::unique_ptr<KeyMaterial>
Ed25519KeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new Ed25519KeyMaterial(*this));
}

void
Ed25519KeyMaterial::grip_update(rnp::Hash &hash) const
{
    // TODO: if GnuPG would ever support v6, check whether this works correctly.
    hash.add(pub());
}

bool
Ed25519KeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    return !ed25519_validate_key_native(&ctx.rng, &key_, secret_);
}

bool
Ed25519KeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    auto key = dynamic_cast<const Ed25519KeyMaterial *>(&value);
    if (!key || !KeyMaterial::equals(value)) {
        return false;
    }
    return key->key_.pub == key_.pub;
}

void
Ed25519KeyMaterial::clear_secret()
{
    key_.clear_secret();
    KeyMaterial::clear_secret();
}

bool
Ed25519KeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    secret_ = false;
    auto                 ec_desc = get_curve_desc(PGP_CURVE_ED25519);
    std::vector<uint8_t> buf(BITS_TO_BYTES(ec_desc->bitlen));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse Ed25519 public key data");
        return false;
    }
    key_.pub = buf;
    return true;
}

bool
Ed25519KeyMaterial::parse_secret(pgp_packet_body_t &pkt) noexcept
{
    auto                 ec_desc = get_curve_desc(PGP_CURVE_ED25519);
    std::vector<uint8_t> buf(BITS_TO_BYTES(ec_desc->bitlen));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse Ed25519 secret key data");
        return false;
    }
    key_.priv = buf;
    secret_ = true;
    return true;
}

void
Ed25519KeyMaterial::write(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.pub);
}

void
Ed25519KeyMaterial::write_secret(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.priv);
}

bool
Ed25519KeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    if (generate_ed25519_native(&params.ctx->rng, key_.priv, key_.pub)) {
        RNP_LOG("failed to generate ED25519 key");
        return false;
    }
    return finish_generate();
}

rnp_result_t
Ed25519KeyMaterial::verify(const rnp::SecurityContext &       ctx,
                           const pgp_signature_material_t &   sig,
                           const rnp::secure_vector<uint8_t> &hash) const
{
    return ed25519_verify_native(sig.ed25519.sig, key_.pub, hash.data(), hash.size());
}

rnp_result_t
Ed25519KeyMaterial::sign(rnp::SecurityContext &             ctx,
                         pgp_signature_material_t &         sig,
                         const rnp::secure_vector<uint8_t> &hash) const
{
    return ed25519_sign_native(&ctx.rng, sig.ed25519.sig, key_.priv, hash.data(), hash.size());
}

size_t
Ed25519KeyMaterial::bits() const noexcept
{
    return 255;
}

pgp_curve_t
Ed25519KeyMaterial::curve() const noexcept
{
    return PGP_CURVE_ED25519;
}

const std::vector<uint8_t> &
Ed25519KeyMaterial::pub() const noexcept
{
    return key_.pub;
}

const std::vector<uint8_t> &
Ed25519KeyMaterial::priv() const noexcept
{
    return key_.priv;
}

std::unique_ptr<KeyMaterial>
X25519KeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new X25519KeyMaterial(*this));
}

void
X25519KeyMaterial::grip_update(rnp::Hash &hash) const
{
    // TODO: if GnuPG would ever support v6, check whether this works correctly.
    hash.add(pub());
}

bool
X25519KeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    return !x25519_validate_key_native(&ctx.rng, &key_, secret_);
}

bool
X25519KeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    auto key = dynamic_cast<const X25519KeyMaterial *>(&value);
    if (!key || !KeyMaterial::equals(value)) {
        return false;
    }
    return key->key_.pub == key_.pub;
}

void
X25519KeyMaterial::clear_secret()
{
    key_.clear_secret();
    KeyMaterial::clear_secret();
}

bool
X25519KeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    secret_ = false;
    auto                 ec_desc = get_curve_desc(PGP_CURVE_25519);
    std::vector<uint8_t> buf(BITS_TO_BYTES(ec_desc->bitlen));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse X25519 public key data");
        return false;
    }
    key_.pub = buf;
    return true;
}

bool
X25519KeyMaterial::parse_secret(pgp_packet_body_t &pkt) noexcept
{
    auto                 ec_desc = get_curve_desc(PGP_CURVE_25519);
    std::vector<uint8_t> buf(BITS_TO_BYTES(ec_desc->bitlen));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse X25519 secret key data");
        return false;
    }
    key_.priv = buf;
    secret_ = true;
    return true;
}

void
X25519KeyMaterial::write(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.pub);
}

void
X25519KeyMaterial::write_secret(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.priv);
}

bool
X25519KeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    if (generate_x25519_native(&params.ctx->rng, key_.priv, key_.pub)) {
        RNP_LOG("failed to generate X25519 key");
        return false;
    }
    return finish_generate();
}

rnp_result_t
X25519KeyMaterial::encrypt(rnp::SecurityContext &    ctx,
                           pgp_encrypted_material_t &out,
                           const uint8_t *           data,
                           size_t                    len) const
{
    return x25519_native_encrypt(&ctx.rng, key_.pub, data, len, &out.x25519);
}

rnp_result_t
X25519KeyMaterial::decrypt(rnp::SecurityContext &          ctx,
                           uint8_t *                       out,
                           size_t &                        out_len,
                           const pgp_encrypted_material_t &in) const
{
    return x25519_native_decrypt(&ctx.rng, key_, &in.x25519, out, &out_len);
}

size_t
X25519KeyMaterial::bits() const noexcept
{
    return 255;
}

pgp_curve_t
X25519KeyMaterial::curve() const noexcept
{
    return PGP_CURVE_25519;
}

const std::vector<uint8_t> &
X25519KeyMaterial::pub() const noexcept
{
    return key_.pub;
}

const std::vector<uint8_t> &
X25519KeyMaterial::priv() const noexcept
{
    return key_.priv;
}
#endif

#if defined(ENABLE_PQC)
std::unique_ptr<KeyMaterial>
KyberKeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new KyberKeyMaterial(*this));
}

void
KyberKeyMaterial::grip_update(rnp::Hash &hash) const
{
    hash.add(pub().get_encoded());
}

bool
KyberKeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    return !kyber_ecdh_validate_key(&ctx.rng, &key_, secret_);
}

bool
KyberKeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    auto key = dynamic_cast<const KyberKeyMaterial *>(&value);
    if (!key || !KeyMaterial::equals(value)) {
        return false;
    }
    return key->key_.pub == key_.pub;
}

void
KyberKeyMaterial::clear_secret()
{
    key_.priv.secure_clear();
    KeyMaterial::clear_secret();
}

bool
KyberKeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    secret_ = false;
    std::vector<uint8_t> buf(pgp_kyber_ecdh_composite_public_key_t::encoded_size(alg()));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse mlkem-ecdh public key data");
        return false;
    }
    key_.pub = pgp_kyber_ecdh_composite_public_key_t(buf, alg());
    return true;
}

bool
KyberKeyMaterial::parse_secret(pgp_packet_body_t &pkt) noexcept
{
    std::vector<uint8_t> buf(pgp_kyber_ecdh_composite_private_key_t::encoded_size(alg()));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse mkem-ecdh secret key data");
        return false;
    }
    key_.priv = pgp_kyber_ecdh_composite_private_key_t(buf.data(), buf.size(), alg());
    secret_ = true;
    return true;
}

void
KyberKeyMaterial::write(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.pub.get_encoded());
}

void
KyberKeyMaterial::write_secret(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.priv.get_encoded());
}

bool
KyberKeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    if (pgp_kyber_ecdh_composite_key_t::gen_keypair(&params.ctx->rng, &key_, alg_)) {
        RNP_LOG("failed to generate MLKEM-ECDH-composite key for PK alg %d", alg_);
        return false;
    }
    return finish_generate();
}

rnp_result_t
KyberKeyMaterial::encrypt(rnp::SecurityContext &    ctx,
                          pgp_encrypted_material_t &out,
                          const uint8_t *           data,
                          size_t                    len) const
{
    return key_.pub.encrypt(&ctx.rng, &out.kyber_ecdh, data, len);
}

rnp_result_t
KyberKeyMaterial::decrypt(rnp::SecurityContext &          ctx,
                          uint8_t *                       out,
                          size_t &                        out_len,
                          const pgp_encrypted_material_t &in) const
{
    return key_.priv.decrypt(&ctx.rng, out, &out_len, &in.kyber_ecdh);
}

size_t
KyberKeyMaterial::bits() const noexcept
{
    return 8 * pub().get_encoded().size(); /* public key length */
}

const pgp_kyber_ecdh_composite_public_key_t &
KyberKeyMaterial::pub() const noexcept
{
    return key_.pub;
}

const pgp_kyber_ecdh_composite_private_key_t &
KyberKeyMaterial::priv() const noexcept
{
    return key_.priv;
}

std::unique_ptr<KeyMaterial>
DilithiumKeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new DilithiumKeyMaterial(*this));
}

void
DilithiumKeyMaterial::grip_update(rnp::Hash &hash) const
{
    hash.add(pub().get_encoded());
}

bool
DilithiumKeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    return !dilithium_exdsa_validate_key(&ctx.rng, &key_, secret_);
}

bool
DilithiumKeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    auto key = dynamic_cast<const DilithiumKeyMaterial *>(&value);
    if (!key || !KeyMaterial::equals(value)) {
        return false;
    }
    return key->key_.pub == key_.pub;
}

void
DilithiumKeyMaterial::clear_secret()
{
    key_.priv.secure_clear();
    KeyMaterial::clear_secret();
}

bool
DilithiumKeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    secret_ = false;
    std::vector<uint8_t> buf(pgp_dilithium_exdsa_composite_public_key_t::encoded_size(alg()));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse mldsa-ecdsa/eddsa public key data");
        return false;
    }
    key_.pub = pgp_dilithium_exdsa_composite_public_key_t(buf, alg());
    return true;
}

bool
DilithiumKeyMaterial::parse_secret(pgp_packet_body_t &pkt) noexcept
{
    std::vector<uint8_t> buf(pgp_dilithium_exdsa_composite_private_key_t::encoded_size(alg()));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse mldsa-ecdsa/eddsa secret key data");
        return false;
    }
    key_.priv = pgp_dilithium_exdsa_composite_private_key_t(buf.data(), buf.size(), alg());
    secret_ = true;
    return true;
}

void
DilithiumKeyMaterial::write(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.pub.get_encoded());
}

void
DilithiumKeyMaterial::write_secret(pgp_packet_body_t &pkt) const
{
    pkt.add(key_.priv.get_encoded());
}

bool
DilithiumKeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    if (pgp_dilithium_exdsa_composite_key_t::gen_keypair(&params.ctx->rng, &key_, alg_)) {
        RNP_LOG("failed to generate mldsa-ecdsa/eddsa-composite key for PK alg %d", alg_);
        return false;
    }
    return finish_generate();
}

rnp_result_t
DilithiumKeyMaterial::verify(const rnp::SecurityContext &       ctx,
                             const pgp_signature_material_t &   sig,
                             const rnp::secure_vector<uint8_t> &hash) const
{
    return key_.pub.verify(&sig.dilithium_exdsa, sig.halg, hash.data(), hash.size());
}

rnp_result_t
DilithiumKeyMaterial::sign(rnp::SecurityContext &             ctx,
                           pgp_signature_material_t &         sig,
                           const rnp::secure_vector<uint8_t> &hash) const
{
    return key_.priv.sign(&ctx.rng, &sig.dilithium_exdsa, sig.halg, hash.data(), hash.size());
}

pgp_hash_alg_t
DilithiumKeyMaterial::adjust_hash(pgp_hash_alg_t hash) const
{
    return dilithium_default_hash_alg();
}

size_t
DilithiumKeyMaterial::bits() const noexcept
{
    return 8 * pub().get_encoded().size(); /* public key length*/
}

const pgp_dilithium_exdsa_composite_public_key_t &
DilithiumKeyMaterial::pub() const noexcept
{
    return key_.pub;
}

const pgp_dilithium_exdsa_composite_private_key_t &
DilithiumKeyMaterial::priv() const noexcept
{
    return key_.priv;
}

std::unique_ptr<KeyMaterial>
SphincsPlusKeyMaterial::clone()
{
    return std::unique_ptr<KeyMaterial>(new SphincsPlusKeyMaterial(*this));
}

void
SphincsPlusKeyMaterial::grip_update(rnp::Hash &hash) const
{
    hash.add(pub().get_encoded());
}

bool
SphincsPlusKeyMaterial::validate_material(rnp::SecurityContext &ctx, bool reset)
{
    return !sphincsplus_validate_key(&ctx.rng, &key_, secret_);
}

bool
SphincsPlusKeyMaterial::equals(const KeyMaterial &value) const noexcept
{
    auto key = dynamic_cast<const SphincsPlusKeyMaterial *>(&value);
    if (!key || !KeyMaterial::equals(value)) {
        return false;
    }
    return key->key_.pub == key_.pub;
}

void
SphincsPlusKeyMaterial::clear_secret()
{
    key_.priv.secure_clear();
    KeyMaterial::clear_secret();
}

bool
SphincsPlusKeyMaterial::parse(pgp_packet_body_t &pkt) noexcept
{
    secret_ = false;
    uint8_t bt = 0;
    if (!pkt.get(bt)) {
        RNP_LOG("failed to parse SLH-DSA public key data");
        return false;
    }
    sphincsplus_parameter_t param = (sphincsplus_parameter_t) bt;
    std::vector<uint8_t>    buf(sphincsplus_pubkey_size(param));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse SLH-DSA public key data");
        return false;
    }
    key_.pub = pgp_sphincsplus_public_key_t(buf, param, alg());
    return true;
}

bool
SphincsPlusKeyMaterial::parse_secret(pgp_packet_body_t &pkt) noexcept
{
    uint8_t bt = 0;
    if (!pkt.get(bt)) {
        RNP_LOG("failed to parse SLH-DSA secret key data");
        return false;
    }
    sphincsplus_parameter_t param = (sphincsplus_parameter_t) bt;
    std::vector<uint8_t>    buf(sphincsplus_privkey_size(param));
    if (!pkt.get(buf.data(), buf.size())) {
        RNP_LOG("failed to parse SLH-DSA secret key data");
        return false;
    }
    key_.priv = pgp_sphincsplus_private_key_t(buf, param, alg());
    secret_ = true;
    return true;
}

void
SphincsPlusKeyMaterial::write(pgp_packet_body_t &pkt) const
{
    pkt.add_byte((uint8_t) key_.pub.param());
    pkt.add(key_.pub.get_encoded());
}

void
SphincsPlusKeyMaterial::write_secret(pgp_packet_body_t &pkt) const
{
    pkt.add_byte((uint8_t) key_.priv.param());
    pkt.add(key_.priv.get_encoded());
}

bool
SphincsPlusKeyMaterial::generate(const rnp_keygen_crypto_params_t &params)
{
    if (pgp_sphincsplus_generate(&params.ctx->rng, &key_, params.sphincsplus.param, alg_)) {
        RNP_LOG("failed to generate SLH-DSA key for PK alg %d", alg_);
        return false;
    }
    return finish_generate();
}

rnp_result_t
SphincsPlusKeyMaterial::verify(const rnp::SecurityContext &       ctx,
                               const pgp_signature_material_t &   sig,
                               const rnp::secure_vector<uint8_t> &hash) const
{
    return key_.pub.verify(&sig.sphincsplus, hash.data(), hash.size());
}

rnp_result_t
SphincsPlusKeyMaterial::sign(rnp::SecurityContext &             ctx,
                             pgp_signature_material_t &         sig,
                             const rnp::secure_vector<uint8_t> &hash) const
{
    return key_.priv.sign(&ctx.rng, &sig.sphincsplus, hash.data(), hash.size());
}

pgp_hash_alg_t
SphincsPlusKeyMaterial::adjust_hash(pgp_hash_alg_t hash) const
{
    return sphincsplus_default_hash_alg(alg_, key_.pub.param());
}

bool
SphincsPlusKeyMaterial::sig_hash_allowed(pgp_hash_alg_t hash) const
{
    return key_.pub.validate_signature_hash_requirements(hash);
}

size_t
SphincsPlusKeyMaterial::bits() const noexcept
{
    return 8 * pub().get_encoded().size(); /* public key length */
}

const pgp_sphincsplus_public_key_t &
SphincsPlusKeyMaterial::pub() const noexcept
{
    return key_.pub;
}

const pgp_sphincsplus_private_key_t &
SphincsPlusKeyMaterial::priv() const noexcept
{
    return key_.priv;
}
#endif

} // namespace pgp
