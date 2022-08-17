/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include <rekey/rnp_key_store.h>
#include <librekey/key_store_pgp.h>
#include <librekey/key_store_g10.h>
#include <librepgp/stream-packet.h>
#include "crypto.h"
#include "pgp-key.h"
#include "defaults.h"
#include "utils.h"

static const uint8_t DEFAULT_SYMMETRIC_ALGS[] = {
  PGP_SA_AES_256, PGP_SA_AES_192, PGP_SA_AES_128};
static const uint8_t DEFAULT_HASH_ALGS[] = {
  PGP_HASH_SHA256, PGP_HASH_SHA384, PGP_HASH_SHA512, PGP_HASH_SHA224};
static const uint8_t DEFAULT_COMPRESS_ALGS[] = {
  PGP_C_ZLIB, PGP_C_BZIP2, PGP_C_ZIP, PGP_C_NONE};

static const id_str_pair pubkey_alg_map[] = {
  {PGP_PKA_RSA, "RSA (Encrypt or Sign)"},
  {PGP_PKA_RSA_ENCRYPT_ONLY, "RSA Encrypt-Only"},
  {PGP_PKA_RSA_SIGN_ONLY, "RSA Sign-Only"},
  {PGP_PKA_ELGAMAL, "Elgamal (Encrypt-Only)"},
  {PGP_PKA_DSA, "DSA"},
  {PGP_PKA_ECDH, "ECDH"},
  {PGP_PKA_ECDSA, "ECDSA"},
  {PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN, "Reserved (formerly Elgamal Encrypt or Sign"},
  {PGP_PKA_RESERVED_DH, "Reserved for Diffie-Hellman (X9.42)"},
  {PGP_PKA_EDDSA, "EdDSA"},
  {PGP_PKA_SM2, "SM2"},
  {PGP_PKA_PRIVATE00, "Private/Experimental"},
  {PGP_PKA_PRIVATE01, "Private/Experimental"},
  {PGP_PKA_PRIVATE02, "Private/Experimental"},
  {PGP_PKA_PRIVATE03, "Private/Experimental"},
  {PGP_PKA_PRIVATE04, "Private/Experimental"},
  {PGP_PKA_PRIVATE05, "Private/Experimental"},
  {PGP_PKA_PRIVATE06, "Private/Experimental"},
  {PGP_PKA_PRIVATE07, "Private/Experimental"},
  {PGP_PKA_PRIVATE08, "Private/Experimental"},
  {PGP_PKA_PRIVATE09, "Private/Experimental"},
  {PGP_PKA_PRIVATE10, "Private/Experimental"},
  {0, NULL}};

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
    std::unique_ptr<rnp_key_store_t> key_store(new (std::nothrow) rnp_key_store_t(ctx));
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

    rnp::MemorySource  memsrc(memdst.memory(), memdst.writeb(), false);
    pgp_key_provider_t prov(rnp_key_provider_key_ptr_list, &key_ptrs);
    if (!rnp_key_store_g10_from_src(key_store.get(), &memsrc.src(), &prov)) {
        return false;
    }
    if (rnp_key_store_get_key_count(key_store.get()) != 1) {
        return false;
    }
    // if a primary key is provided, it should match the sub with regards to type
    assert(!primary_key || (primary_key->is_secret() == key_store->keys.front().is_secret()));
    *dst = pgp_key_t(key_store->keys.front());
    return true;
}

static uint8_t
pk_alg_default_flags(pgp_pubkey_alg_t alg)
{
    // just use the full capabilities as the ultimate fallback
    return pgp_pk_alg_capabilities(alg);
}

// TODO: Similar as pgp_pick_hash_alg but different enough to
//       keep another version. This will be changed when refactoring crypto
static void
adjust_hash_alg(rnp_keygen_crypto_params_t &crypto)
{
    if (!crypto.hash_alg) {
        crypto.hash_alg = (pgp_hash_alg_t) DEFAULT_HASH_ALGS[0];
    }

    if ((crypto.key_alg != PGP_PKA_DSA) && (crypto.key_alg != PGP_PKA_ECDSA)) {
        return;
    }

    pgp_hash_alg_t min_hash = (crypto.key_alg == PGP_PKA_ECDSA) ?
                                ecdsa_get_min_hash(crypto.ecc.curve) :
                                dsa_get_min_hash(crypto.dsa.q_bitlen);

    if (rnp::Hash::size(crypto.hash_alg) < rnp::Hash::size(min_hash)) {
        crypto.hash_alg = min_hash;
    }
}

static void
keygen_merge_crypto_defaults(rnp_keygen_crypto_params_t &crypto)
{
    // default to RSA
    if (!crypto.key_alg) {
        crypto.key_alg = PGP_PKA_RSA;
    }

    switch (crypto.key_alg) {
    case PGP_PKA_RSA:
        if (!crypto.rsa.modulus_bit_len) {
            crypto.rsa.modulus_bit_len = DEFAULT_RSA_NUMBITS;
        }
        break;

    case PGP_PKA_SM2:
        if (!crypto.hash_alg) {
            crypto.hash_alg = PGP_HASH_SM3;
        }
        if (!crypto.ecc.curve) {
            crypto.ecc.curve = PGP_CURVE_SM2_P_256;
        }
        break;

    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA: {
        if (!crypto.hash_alg) {
            crypto.hash_alg = (pgp_hash_alg_t) DEFAULT_HASH_ALGS[0];
        }
        break;
    }

    case PGP_PKA_EDDSA:
        if (!crypto.ecc.curve) {
            crypto.ecc.curve = PGP_CURVE_ED25519;
        }
        break;

    case PGP_PKA_DSA: {
        if (!crypto.dsa.p_bitlen) {
            crypto.dsa.p_bitlen = DSA_DEFAULT_P_BITLEN;
        }
        if (!crypto.dsa.q_bitlen) {
            crypto.dsa.q_bitlen = dsa_choose_qsize_by_psize(crypto.dsa.p_bitlen);
        }
        break;
    }
    default:
        break;
    }

    adjust_hash_alg(crypto);
}

static bool
validate_keygen_primary(const rnp_keygen_primary_desc_t &desc)
{
    /* Confirm that the specified pk alg can certify.
     * gpg requires this, though the RFC only says that a V4 primary
     * key SHOULD be a key capable of certification.
     */
    if (!(pgp_pk_alg_capabilities(desc.crypto.key_alg) & PGP_KF_CERTIFY)) {
        RNP_LOG("primary key alg (%d) must be able to sign", desc.crypto.key_alg);
        return false;
    }

    // check key flags
    if (!desc.cert.key_flags) {
        // these are probably not *technically* required
        RNP_LOG("key flags are required");
        return false;
    } else if (desc.cert.key_flags & ~pgp_pk_alg_capabilities(desc.crypto.key_alg)) {
        // check the flags against the alg capabilities
        RNP_LOG("usage not permitted for pk algorithm");
        return false;
    }
    // require a userid
    if (!desc.cert.userid[0]) {
        RNP_LOG("userid is required for primary key");
        return false;
    }
    return true;
}

static uint32_t
get_numbits(const rnp_keygen_crypto_params_t *crypto)
{
    switch (crypto->key_alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return crypto->rsa.modulus_bit_len;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        if (const ec_curve_desc_t *curve = get_curve_desc(crypto->ecc.curve)) {
            return curve->bitlen;
        } else {
            return 0;
        }
    }
    case PGP_PKA_DSA:
        return crypto->dsa.p_bitlen;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        return crypto->elgamal.key_bitlen;
    default:
        return 0;
    }
}

static void
set_default_user_prefs(pgp_user_prefs_t &prefs)
{
    if (prefs.symm_algs.empty()) {
        prefs.set_symm_algs(
          std::vector<uint8_t>(DEFAULT_SYMMETRIC_ALGS,
                               DEFAULT_SYMMETRIC_ALGS + ARRAY_SIZE(DEFAULT_SYMMETRIC_ALGS)));
    }
    if (prefs.hash_algs.empty()) {
        prefs.set_hash_algs(std::vector<uint8_t>(
          DEFAULT_HASH_ALGS, DEFAULT_HASH_ALGS + ARRAY_SIZE(DEFAULT_HASH_ALGS)));
    }
    if (prefs.z_algs.empty()) {
        prefs.set_z_algs(std::vector<uint8_t>(
          DEFAULT_COMPRESS_ALGS, DEFAULT_COMPRESS_ALGS + ARRAY_SIZE(DEFAULT_COMPRESS_ALGS)));
    }
}

static void
keygen_primary_merge_defaults(rnp_keygen_primary_desc_t &desc)
{
    keygen_merge_crypto_defaults(desc.crypto);
    set_default_user_prefs(desc.cert.prefs);

    if (!desc.cert.key_flags) {
        // set some default key flags if none are provided
        desc.cert.key_flags = pk_alg_default_flags(desc.crypto.key_alg);
    }
    if (desc.cert.userid.empty()) {
        char uid[MAX_ID_LENGTH] = {0};
        snprintf(uid,
                 sizeof(uid),
                 "%s %d-bit key <%s@localhost>",
                 id_str_pair::lookup(pubkey_alg_map, desc.crypto.key_alg),
                 get_numbits(&desc.crypto),
                 getenv_logname());
        desc.cert.userid = uid;
    }
}

bool
pgp_generate_primary_key(rnp_keygen_primary_desc_t &desc,
                         bool                       merge_defaults,
                         pgp_key_t &                primary_sec,
                         pgp_key_t &                primary_pub,
                         pgp_key_store_format_t     secformat)
{
    // validate args
    if (primary_sec.type() || primary_pub.type()) {
        RNP_LOG("invalid parameters (should be zeroed)");
        return false;
    }

    try {
        // merge some defaults in, if requested
        if (merge_defaults) {
            keygen_primary_merge_defaults(desc);
        }
        // now validate the keygen fields
        if (!validate_keygen_primary(desc)) {
            return false;
        }

        // generate the raw key and fill tag/secret fields
        pgp_key_pkt_t secpkt;
        if (!pgp_generate_seckey(desc.crypto, secpkt, true)) {
            return false;
        }

        pgp_key_t sec(secpkt);
        pgp_key_t pub(secpkt, true);
        sec.add_uid_cert(desc.cert, desc.crypto.hash_alg, *desc.crypto.ctx, &pub);

        switch (secformat) {
        case PGP_KEY_STORE_GPG:
        case PGP_KEY_STORE_KBX:
            primary_sec = std::move(sec);
            primary_pub = std::move(pub);
            break;
        case PGP_KEY_STORE_G10:
            primary_pub = std::move(pub);
            if (!load_generated_g10_key(
                  &primary_sec, &secpkt, NULL, &primary_pub, *desc.crypto.ctx)) {
                RNP_LOG("failed to load generated key");
                return false;
            }
            break;
        default:
            RNP_LOG("invalid format");
            return false;
        }
    } catch (const std::exception &e) {
        RNP_LOG("Failure: %s", e.what());
        return false;
    }

    /* mark it as valid */
    primary_pub.mark_valid();
    primary_sec.mark_valid();
    /* refresh key's data */
    return primary_pub.refresh_data(*desc.crypto.ctx) &&
           primary_sec.refresh_data(*desc.crypto.ctx);
}

static bool
validate_keygen_subkey(rnp_keygen_subkey_desc_t &desc)
{
    if (!desc.binding.key_flags) {
        RNP_LOG("key flags are required");
        return false;
    } else if (desc.binding.key_flags & ~pgp_pk_alg_capabilities(desc.crypto.key_alg)) {
        // check the flags against the alg capabilities
        RNP_LOG("usage not permitted for pk algorithm");
        return false;
    }
    return true;
}

static void
keygen_subkey_merge_defaults(rnp_keygen_subkey_desc_t &desc)
{
    keygen_merge_crypto_defaults(desc.crypto);
    if (!desc.binding.key_flags) {
        // set some default key flags if none are provided
        desc.binding.key_flags = pk_alg_default_flags(desc.crypto.key_alg);
    }
}

bool
pgp_generate_subkey(rnp_keygen_subkey_desc_t &     desc,
                    bool                           merge_defaults,
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
    if (subkey_sec.type() || subkey_pub.type()) {
        RNP_LOG("invalid parameters (should be zeroed)");
        return false;
    }

    // merge some defaults in, if requested
    if (merge_defaults) {
        keygen_subkey_merge_defaults(desc);
    }

    // now validate the keygen fields
    if (!validate_keygen_subkey(desc)) {
        return false;
    }

    try {
        /* decrypt the primary seckey if needed (for signatures) */
        rnp::KeyLocker primlock(primary_sec);
        if (primary_sec.encrypted() &&
            !primary_sec.unlock(password_provider, PGP_OP_ADD_SUBKEY)) {
            RNP_LOG("Failed to unlock primary key.");
            return false;
        }
        /* generate the raw subkey */
        pgp_key_pkt_t secpkt;
        if (!pgp_generate_seckey(desc.crypto, secpkt, false)) {
            return false;
        }
        pgp_key_pkt_t pubpkt = pgp_key_pkt_t(secpkt, true);
        pgp_key_t     sec(secpkt, primary_sec);
        pgp_key_t     pub(pubpkt, primary_pub);
        /* add binding */
        primary_sec.add_sub_binding(
          sec, pub, desc.binding, desc.crypto.hash_alg, *desc.crypto.ctx);
        /* copy to the result */
        subkey_pub = std::move(pub);
        switch (secformat) {
        case PGP_KEY_STORE_GPG:
        case PGP_KEY_STORE_KBX:
            subkey_sec = std::move(sec);
            break;
        case PGP_KEY_STORE_G10:
            if (!load_generated_g10_key(
                  &subkey_sec, &secpkt, &primary_sec, &subkey_pub, *desc.crypto.ctx)) {
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
        return subkey_pub.refresh_data(&primary_pub, *desc.crypto.ctx) &&
               subkey_sec.refresh_data(&primary_sec, *desc.crypto.ctx);
    } catch (const std::exception &e) {
        RNP_LOG("Subkey generation failed: %s", e.what());
        return false;
    }
}
