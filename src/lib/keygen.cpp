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

#include "keygen.hpp"
#include <cassert>
#include "librekey/key_store_g10.h"

namespace rnp {
KeygenParams::KeygenParams(pgp_pubkey_alg_t alg, SecurityContext &ctx)
    : alg_(alg), hash_(PGP_HASH_UNKNOWN), version_(PGP_V4), ctx_(ctx)
{
    key_params_ = pgp::KeyParams::create(alg);
}

void
KeygenParams::check_defaults() noexcept
{
    if (hash_ == PGP_HASH_UNKNOWN) {
        hash_ = alg_ == PGP_PKA_SM2 ? PGP_HASH_SM3 : DEFAULT_PGP_HASH_ALG;
    }
    pgp_hash_alg_t min_hash = key_params_->min_hash();
    if (rnp::Hash::size(hash_) < rnp::Hash::size(min_hash)) {
        hash_ = min_hash;
    }
    key_params_->check_defaults();
}

static const id_str_pair pubkey_alg_map[] = {{PGP_PKA_RSA, "RSA (Encrypt or Sign)"},
                                             {PGP_PKA_RSA_ENCRYPT_ONLY, "RSA Encrypt-Only"},
                                             {PGP_PKA_RSA_SIGN_ONLY, "RSA Sign-Only"},
                                             {PGP_PKA_ELGAMAL, "Elgamal (Encrypt-Only)"},
                                             {PGP_PKA_DSA, "DSA"},
                                             {PGP_PKA_ECDH, "ECDH"},
                                             {PGP_PKA_ECDSA, "ECDSA"},
                                             {PGP_PKA_EDDSA, "EdDSA"},
                                             {PGP_PKA_SM2, "SM2"},
#if defined(ENABLE_CRYPTO_REFRESH)
                                             {PGP_PKA_ED25519, "ED25519"},
                                             {PGP_PKA_X25519, "X25519"},
#endif
#if defined(ENABLE_PQC)
                                             {PGP_PKA_KYBER768_X25519, "ML-KEM-768_X25519"},
                                             //{PGP_PKA_KYBER1024_X448, "Kyber-X448"},
                                             {PGP_PKA_KYBER768_P256, "ML-KEM-768_P256"},
                                             {PGP_PKA_KYBER1024_P384, "ML-KEM-1024_P384"},
                                             {PGP_PKA_KYBER768_BP256, "ML-KEM-768_BP256"},
                                             {PGP_PKA_KYBER1024_BP384, "ML-KEM-1024_BP384"},
                                             {PGP_PKA_DILITHIUM3_ED25519, "ML-DSA-65_ED25519"},
                                             //{PGP_PKA_DILITHIUM5_ED448, "Dilithium-ED448"},
                                             {PGP_PKA_DILITHIUM3_P256, "ML-DSA-65_P256"},
                                             {PGP_PKA_DILITHIUM5_P384, "ML-DSA-87_P384"},
                                             {PGP_PKA_DILITHIUM3_BP256, "ML-DSA-65_BP256"},
                                             {PGP_PKA_DILITHIUM5_BP384, "ML-DSA-87_BP384"},
                                             {PGP_PKA_SPHINCSPLUS_SHA2, "SLH-DSA-SHA2"},
                                             {PGP_PKA_SPHINCSPLUS_SHAKE, "SLH-DSA-SHAKE"},
#endif
                                             {0, NULL}};

static uint8_t
pk_alg_default_flags(pgp_pubkey_alg_t alg)
{
    // just use the full capabilities as the ultimate fallback
    return pgp_pk_alg_capabilities(alg);
}

bool
KeygenParams::generate(pgp_key_pkt_t &seckey, bool primary)
{
    /* populate pgp key structure */
    seckey = {};
    seckey.version = version();
    seckey.creation_time = ctx().time();
    seckey.alg = alg();
    seckey.material = pgp::KeyMaterial::create(alg());
    if (!seckey.material) {
        RNP_LOG("Unsupported key algorithm: %d", alg());
        return false;
    }
    seckey.tag = primary ? PGP_PKT_SECRET_KEY : PGP_PKT_SECRET_SUBKEY;

    if (!seckey.material->generate(ctx(), key_params())) {
        return false;
    }

    seckey.sec_protection.s2k.usage = PGP_S2KU_NONE;
    /* fill the sec_data/sec_len */
    if (encrypt_secret_key(&seckey, NULL, ctx().rng)) {
        RNP_LOG("failed to fill sec_data");
        return false;
    }
    return true;
}

static bool
load_generated_g10_key(pgp_key_t *           dst,
                       pgp_key_pkt_t *       newkey,
                       pgp_key_t *           primary_key,
                       pgp_key_t *           pubkey,
                       rnp::SecurityContext &ctx)
{
    // this should generally be zeroed
    assert(dst->type() == 0);
    // if a primary is provided, make sure it's actually a primary key
    assert(!primary_key || primary_key->is_primary());
    // if a pubkey is provided, make sure it's actually a public key
    assert(!pubkey || pubkey->is_public());
    // G10 always needs pubkey here
    assert(pubkey);

    // this would be better on the stack but the key store does not allow it
    std::unique_ptr<rnp::KeyStore> key_store(new (std::nothrow) rnp::KeyStore(ctx));
    if (!key_store) {
        return false;
    }
    /* Write g10 seckey */
    rnp::MemoryDest memdst(NULL, 0);
    if (!g10_write_seckey(&memdst.dst(), newkey, NULL, ctx)) {
        RNP_LOG("failed to write generated seckey");
        return false;
    }

    std::vector<pgp_key_t *> key_ptrs; /* holds primary and pubkey, when used */
    // if this is a subkey, add the primary in first
    if (primary_key) {
        key_ptrs.push_back(primary_key);
    }
    // G10 needs the pubkey for copying some attributes (key version, creation time, etc)
    key_ptrs.push_back(pubkey);

    rnp::MemorySource memsrc(memdst.memory(), memdst.writeb(), false);
    rnp::KeyProvider  prov(rnp_key_provider_key_ptr_list, &key_ptrs);
    if (!key_store.get()->load_g10(memsrc.src(), &prov)) {
        return false;
    }
    if (key_store.get()->key_count() != 1) {
        return false;
    }
    // if a primary key is provided, it should match the sub with regards to type
    assert(!primary_key || (primary_key->is_secret() == key_store->keys.front().is_secret()));
    *dst = pgp_key_t(key_store->keys.front());
    return true;
}

static std::string
default_uid(const KeygenParams &params)
{
    char uid[MAX_ID_LENGTH] = {0};
    snprintf(uid,
             sizeof(uid),
             "%s %zu-bit key <%s@localhost>",
             id_str_pair::lookup(pubkey_alg_map, params.alg()),
             params.key_params().bits(),
             getenv_logname());
    return uid;
}

static bool
validate_keygen_primary(const KeygenParams &params, const rnp_selfsig_cert_info_t &cert)
{
    /* Confirm that the specified pk alg can certify.
     * gpg requires this, though the RFC only says that a V4 primary
     * key SHOULD be a key capable of certification.
     */
    if (!(pgp_pk_alg_capabilities(params.alg()) & PGP_KF_CERTIFY)) {
        RNP_LOG("primary key alg (%d) must be able to sign", params.alg());
        return false;
    }

    // check key flags
    if (!cert.key_flags) {
        // these are probably not *technically* required
        RNP_LOG("key flags are required");
        return false;
    } else if (cert.key_flags & ~pgp_pk_alg_capabilities(params.alg())) {
        // check the flags against the alg capabilities
        RNP_LOG("usage not permitted for pk algorithm");
        return false;
    }
    // require a userid
    if (cert.userid.empty()) {
        RNP_LOG("userid is required for primary key");
        return false;
    }
    return true;
}

static void
keygen_primary_merge_defaults(KeygenParams &params, rnp_selfsig_cert_info_t &cert)
{
    params.check_defaults();
    cert.prefs.merge_defaults(params.version());

    if (!cert.key_flags) {
        // set some default key flags if none are provided
        cert.key_flags = pk_alg_default_flags(params.alg());
    }
    if (cert.userid.empty()) {
        cert.userid = default_uid(params);
    }
}

#if defined(ENABLE_PQC)
static bool
pgp_check_key_hash_requirements(KeygenParams &params)
{
    switch (params.alg()) {
    case PGP_PKA_SPHINCSPLUS_SHA2:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_SPHINCSPLUS_SHAKE: {
        auto &slhdsa = dynamic_cast<const pgp::SlhdsaKeyParams &>(params.key_params());
        if (!sphincsplus_hash_allowed(params.alg(), slhdsa.param(), params.hash())) {
            return false;
        }
        break;
    }
    case PGP_PKA_DILITHIUM3_ED25519:
        FALLTHROUGH_STATEMENT;
    // TODO: add case PGP_PKA_DILITHIUM5_ED448: FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM3_P256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM5_P384:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM3_BP256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM5_BP384:
        if (!dilithium_hash_allowed(params.hash())) {
            return false;
        }
        break;
    default:
        break;
    }
    return true;
}
#endif

static bool
validate_keygen_subkey(const KeygenParams &params, const rnp_selfsig_binding_info_t &binding)
{
    if (!binding.key_flags) {
        RNP_LOG("key flags are required");
        return false;
    } else if (binding.key_flags & ~pgp_pk_alg_capabilities(params.alg())) {
        // check the flags against the alg capabilities
        RNP_LOG("usage not permitted for pk algorithm");
        return false;
    }
    return true;
}

static void
keygen_subkey_merge_defaults(KeygenParams &params, rnp_selfsig_binding_info_t &binding)
{
    params.check_defaults();
    if (!binding.key_flags) {
        // set some default key flags if none are provided
        binding.key_flags = pk_alg_default_flags(params.alg());
    }
}

bool
KeygenParams::generate(rnp_selfsig_cert_info_t &cert,
                       pgp_key_t &              primary_sec,
                       pgp_key_t &              primary_pub,
                       pgp_key_store_format_t   secformat)
{
    primary_sec = {};
    primary_pub = {};

    // merge some defaults in
    keygen_primary_merge_defaults(*this, cert);
    // now validate the keygen fields
    if (!validate_keygen_primary(*this, cert)) {
        return false;
    }

#if defined(ENABLE_PQC)
    // check hash requirements
    if (!pgp_check_key_hash_requirements(*this)) {
        RNP_LOG("invalid hash algorithm for the chosen key");
        return false;
    }
#endif

    // generate the raw key and fill tag/secret fields
    pgp_key_pkt_t secpkt;
    if (!generate(secpkt, true)) {
        return false;
    }

    pgp_key_t sec(secpkt);
    pgp_key_t pub(secpkt, true);
#if defined(ENABLE_CRYPTO_REFRESH)
    // for v6 packets, a direct-key sig is mandatory.
    if (sec.version() == PGP_V6) {
        sec.add_direct_sig(cert, hash(), ctx(), &pub);
    }
#endif
    sec.add_uid_cert(cert, hash(), ctx(), &pub);

    switch (secformat) {
    case PGP_KEY_STORE_GPG:
    case PGP_KEY_STORE_KBX:
        primary_sec = std::move(sec);
        primary_pub = std::move(pub);
        break;
    case PGP_KEY_STORE_G10:
        primary_pub = std::move(pub);
        if (!load_generated_g10_key(&primary_sec, &secpkt, NULL, &primary_pub, ctx())) {
            RNP_LOG("failed to load generated key");
            return false;
        }
        break;
    default:
        RNP_LOG("invalid format");
        return false;
    }

    /* mark it as valid */
    primary_pub.mark_valid();
    primary_sec.mark_valid();
    /* refresh key's data */
    return primary_pub.refresh_data(ctx()) && primary_sec.refresh_data(ctx());
}

bool
KeygenParams::generate(rnp_selfsig_binding_info_t &   binding,
                       pgp_key_t &                    primary_sec,
                       pgp_key_t &                    primary_pub,
                       pgp_key_t &                    subkey_sec,
                       pgp_key_t &                    subkey_pub,
                       const pgp_password_provider_t &password_provider,
                       pgp_key_store_format_t         secformat)
{
    // validate args
    if (!primary_sec.is_primary() || !primary_pub.is_primary() || !primary_sec.is_secret() ||
        !primary_pub.is_public()) {
        RNP_LOG("invalid parameters");
        return false;
    }
    subkey_sec = {};
    subkey_pub = {};

    // merge some defaults in
    keygen_subkey_merge_defaults(*this, binding);

    // now validate the keygen fields
    if (!validate_keygen_subkey(*this, binding)) {
        return false;
    }

#if defined(ENABLE_PQC)
    // check hash requirements
    if (!pgp_check_key_hash_requirements(*this)) {
        RNP_LOG("invalid hash algorithm for the chosen key");
        return false;
    }
#endif

    /* decrypt the primary seckey if needed (for signatures) */
    rnp::KeyLocker primlock(primary_sec);
    if (primary_sec.encrypted() && !primary_sec.unlock(password_provider, PGP_OP_ADD_SUBKEY)) {
        RNP_LOG("Failed to unlock primary key.");
        return false;
    }
    /* generate the raw subkey */
    pgp_key_pkt_t secpkt;
    if (!generate(secpkt, false)) {
        return false;
    }
    pgp_key_pkt_t pubpkt = pgp_key_pkt_t(secpkt, true);
    pgp_key_t     sec(secpkt, primary_sec);
    pgp_key_t     pub(pubpkt, primary_pub);
    /* add binding */
    primary_sec.add_sub_binding(sec, pub, binding, hash(), ctx());
    /* copy to the result */
    subkey_pub = std::move(pub);
    switch (secformat) {
    case PGP_KEY_STORE_GPG:
    case PGP_KEY_STORE_KBX:
        subkey_sec = std::move(sec);
        break;
    case PGP_KEY_STORE_G10:
        if (!load_generated_g10_key(&subkey_sec, &secpkt, &primary_sec, &subkey_pub, ctx())) {
            RNP_LOG("failed to load generated key");
            return false;
        }
        break;
    default:
        RNP_LOG("invalid format");
        return false;
    }

    subkey_pub.mark_valid();
    subkey_sec.mark_valid();
    return subkey_pub.refresh_data(&primary_pub, ctx()) &&
           subkey_sec.refresh_data(&primary_sec, ctx());
}

} // namespace rnp
