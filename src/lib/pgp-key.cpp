/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
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

#include "pgp-key.h"
#include "utils.h"
#include <librekey/key_store_pgp.h>
#include <librekey/key_store_g10.h>
#include "crypto.h"
#include "crypto/s2k.h"
#include "fingerprint.h"

#include <rnp/rnp_sdk.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-armor.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <algorithm>
#include <stdexcept>
#include "defaults.h"

static bool
pgp_user_prefs_set_arr(uint8_t **arr, size_t *arrlen, const uint8_t *val, size_t len)
{
    uint8_t *newarr = (uint8_t *) malloc(len);

    if (len && !newarr) {
        return false;
    }

    free(*arr);
    memcpy(newarr, val, len);
    *arrlen = len;
    *arr = newarr;
    return true;
}

static bool
pgp_user_prefs_add_val(uint8_t **arr, size_t *arrlen, uint8_t val)
{
    /* do not add duplicate values */
    for (size_t i = 0; i < *arrlen; i++) {
        if ((*arr)[i] == val) {
            return true;
        }
    }

    uint8_t *newarr = (uint8_t *) realloc(*arr, *arrlen + 1);

    if (!newarr) {
        return false;
    }

    newarr[(*arrlen)++] = val;
    *arr = newarr;
    return true;
}

bool
pgp_user_prefs_set_symm_algs(pgp_user_prefs_t *prefs, const uint8_t *algs, size_t len)
{
    return pgp_user_prefs_set_arr(&prefs->symm_algs, &prefs->symm_alg_count, algs, len);
}

bool
pgp_user_prefs_set_hash_algs(pgp_user_prefs_t *prefs, const uint8_t *algs, size_t len)
{
    return pgp_user_prefs_set_arr(&prefs->hash_algs, &prefs->hash_alg_count, algs, len);
}

bool
pgp_user_prefs_set_z_algs(pgp_user_prefs_t *prefs, const uint8_t *algs, size_t len)
{
    return pgp_user_prefs_set_arr(&prefs->z_algs, &prefs->z_alg_count, algs, len);
}

bool
pgp_user_prefs_set_ks_prefs(pgp_user_prefs_t *prefs, const uint8_t *vals, size_t len)
{
    return pgp_user_prefs_set_arr(&prefs->ks_prefs, &prefs->ks_pref_count, vals, len);
}

bool
pgp_user_prefs_add_symm_alg(pgp_user_prefs_t *prefs, pgp_symm_alg_t alg)
{
    return pgp_user_prefs_add_val(&prefs->symm_algs, &prefs->symm_alg_count, alg);
}

bool
pgp_user_prefs_add_hash_alg(pgp_user_prefs_t *prefs, pgp_hash_alg_t alg)
{
    return pgp_user_prefs_add_val(&prefs->hash_algs, &prefs->hash_alg_count, alg);
}

bool
pgp_user_prefs_add_z_alg(pgp_user_prefs_t *prefs, pgp_compression_type_t alg)
{
    return pgp_user_prefs_add_val(&prefs->z_algs, &prefs->z_alg_count, alg);
}

bool
pgp_user_prefs_add_ks_pref(pgp_user_prefs_t *prefs, pgp_key_server_prefs_t val)
{
    return pgp_user_prefs_add_val(&prefs->ks_prefs, &prefs->ks_pref_count, val);
}

void
pgp_free_user_prefs(pgp_user_prefs_t *prefs)
{
    if (!prefs) {
        return;
    }
    free(prefs->symm_algs);
    free(prefs->hash_algs);
    free(prefs->z_algs);
    free(prefs->ks_prefs);
    free(prefs->key_server);
    memset(prefs, 0, sizeof(*prefs));
}

static bool
pgp_key_init_with_pkt(pgp_key_t *key, const pgp_key_pkt_t *pkt)
{
    assert(!key->pkt.version);
    assert(is_key_pkt(pkt->tag));
    assert(pkt->material.alg);
    if (pgp_keyid(key->keyid, pkt) || pgp_fingerprint(key->fingerprint, pkt) ||
        !rnp_key_store_get_key_grip(&pkt->material, key->grip)) {
        return false;
    }
    /* this is correct since changes ownership */
    key->pkt = std::move(*pkt);
    return true;
}

bool
pgp_key_from_pkt(pgp_key_t *key, const pgp_key_pkt_t *pkt)
{
    try {
        pgp_key_pkt_t keypkt = *pkt;
        *key = pgp_key_t();

        /* parse secret key if not encrypted */
        if (is_secret_key_pkt(keypkt.tag)) {
            bool cleartext = keypkt.sec_protection.s2k.usage == PGP_S2KU_NONE;
            if (cleartext && decrypt_secret_key(&keypkt, NULL)) {
                RNP_LOG("failed to setup key fields");
                return false;
            }
        }

        /* this call transfers ownership */
        if (!pgp_key_init_with_pkt(key, &keypkt)) {
            RNP_LOG("failed to setup key fields");
            return false;
        }

        /* add key rawpacket */
        key->rawpkt = pgp_rawpacket_t(key->pkt);
        key->format = PGP_KEY_STORE_GPG;
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

static void
pgp_key_clear_revokes(pgp_key_t *key)
{
    key->revoked = false;
    key->revokes.clear();
    key->revocation = {};
}

static rnp_result_t
pgp_userprefs_copy(pgp_user_prefs_t *dst, const pgp_user_prefs_t *src)
{
    rnp_result_t ret = RNP_ERROR_OUT_OF_MEMORY;

    memset(dst, 0, sizeof(*dst));
    if (src->symm_alg_count &&
        !pgp_user_prefs_set_symm_algs(dst, src->symm_algs, src->symm_alg_count)) {
        return ret;
    }

    if (src->hash_alg_count &&
        !pgp_user_prefs_set_hash_algs(dst, src->hash_algs, src->hash_alg_count)) {
        goto error;
    }

    if (src->z_alg_count && !pgp_user_prefs_set_z_algs(dst, src->z_algs, src->z_alg_count)) {
        goto error;
    }

    if (src->ks_pref_count &&
        !pgp_user_prefs_set_ks_prefs(dst, src->ks_prefs, src->ks_pref_count)) {
        goto error;
    }

    if (src->key_server) {
        size_t len = strlen((char *) src->key_server) + 1;
        dst->key_server = (uint8_t *) malloc(len);
        if (!dst->key_server) {
            goto error;
        }
        memcpy(dst->key_server, src->key_server, len);
    }

    return RNP_SUCCESS;
error:
    pgp_free_user_prefs(dst);
    return ret;
}

/**
 \ingroup HighLevel_KeyGeneral

 \brief Returns the public key in the given key.
 \param key

  \return Pointer to public key

  \note This is not a copy, do not free it after use.
*/

const pgp_key_pkt_t *
pgp_key_get_pkt(const pgp_key_t *key)
{
    return &key->pkt;
}

const pgp_key_material_t *
pgp_key_get_material(const pgp_key_t *key)
{
    return &key->pkt.material;
}

pgp_pubkey_alg_t
pgp_key_get_alg(const pgp_key_t *key)
{
    return key->pkt.alg;
}

size_t
pgp_key_get_dsa_qbits(const pgp_key_t *key)
{
    if (pgp_key_get_alg(key) != PGP_PKA_DSA) {
        return 0;
    }

    return dsa_qbits(&pgp_key_get_material(key)->dsa);
}

size_t
pgp_key_get_bits(const pgp_key_t *key)
{
    return key_bitlength(pgp_key_get_material(key));
}

pgp_curve_t
pgp_key_get_curve(const pgp_key_t *key)
{
    switch (pgp_key_get_alg(key)) {
    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        return pgp_key_get_material(key)->ec.curve;
    default:
        return PGP_CURVE_UNKNOWN;
    }
}

pgp_version_t
pgp_key_get_version(const pgp_key_t *key)
{
    return key->pkt.version;
}

pgp_pkt_type_t
pgp_key_get_type(const pgp_key_t *key)
{
    return key->pkt.tag;
}

bool
pgp_key_is_public(const pgp_key_t *key)
{
    return is_public_key_pkt(key->pkt.tag);
}

bool
pgp_key_is_secret(const pgp_key_t *key)
{
    return is_secret_key_pkt(key->pkt.tag);
}

bool
pgp_key_is_encrypted(const pgp_key_t *key)
{
    if (!pgp_key_is_secret(key)) {
        return false;
    }

    const pgp_key_pkt_t *pkt = pgp_key_get_pkt(key);
    return !pkt->material.secret;
}

uint8_t
pgp_key_get_flags(const pgp_key_t *key)
{
    return key->key_flags;
}

bool
pgp_key_can_sign(const pgp_key_t *key)
{
    return pgp_key_get_flags(key) & PGP_KF_SIGN;
}

bool
pgp_key_can_certify(const pgp_key_t *key)
{
    return pgp_key_get_flags(key) & PGP_KF_CERTIFY;
}

bool
pgp_key_can_encrypt(const pgp_key_t *key)
{
    return pgp_key_get_flags(key) & PGP_KF_ENCRYPT;
}

bool
pgp_key_is_primary_key(const pgp_key_t *key)
{
    return is_primary_key_pkt(key->pkt.tag);
}

bool
pgp_key_is_subkey(const pgp_key_t *key)
{
    return is_subkey_pkt(key->pkt.tag);
}

uint32_t
pgp_key_get_expiration(const pgp_key_t *key)
{
    return (key->pkt.version >= 4) ? key->expiration : key->pkt.v3_days * 86400;
}

uint32_t
pgp_key_get_creation(const pgp_key_t *key)
{
    return key->pkt.creation_time;
}

pgp_key_pkt_t *
pgp_decrypt_seckey_pgp(const uint8_t *      data,
                       size_t               data_len,
                       const pgp_key_pkt_t *pubkey,
                       const char *         password)
{
    pgp_source_t   src = {0};
    pgp_key_pkt_t *res = new pgp_key_pkt_t();

    if (init_mem_src(&src, data, data_len, false)) {
        delete res;
        return NULL;
    }

    if (stream_parse_key(&src, res)) {
        goto error;
    }

    if (decrypt_secret_key(res, password)) {
        goto error;
    }

    src_close(&src);
    return res;
error:
    src_close(&src);
    delete res;
    return NULL;
}

/* Note that this function essentially serves two purposes.
 * - In the case of a protected key, it requests a password and
 *   uses it to decrypt the key and fill in key->key.seckey.
 * - In the case of an unprotected key, it simply re-loads
 *   key->key.seckey by parsing the key data in packets[0].
 */
pgp_key_pkt_t *
pgp_decrypt_seckey(const pgp_key_t *              key,
                   const pgp_password_provider_t *provider,
                   const pgp_password_ctx_t *     ctx)
{
    typedef struct pgp_key_pkt_t *pgp_seckey_decrypt_t(
      const uint8_t *data, size_t data_len, const pgp_key_pkt_t *pubkey, const char *password);
    pgp_seckey_decrypt_t *decryptor = NULL;

    // sanity checks
    if (!key || !pgp_key_is_secret(key) || !provider) {
        RNP_LOG("invalid args");
        return NULL;
    }
    switch (key->format) {
    case PGP_KEY_STORE_GPG:
    case PGP_KEY_STORE_KBX:
        decryptor = pgp_decrypt_seckey_pgp;
        break;
    case PGP_KEY_STORE_G10:
        decryptor = g10_decrypt_seckey;
        break;
    default:
        RNP_LOG("unexpected format: %d", key->format);
        return NULL;
    }

    // ask the provider for a password
    char password[MAX_PASSWORD_LENGTH] = {0};
    if (pgp_key_is_protected(key) &&
        !pgp_request_password(provider, ctx, password, sizeof(password))) {
        return NULL;
    }
    // attempt to decrypt with the provided password
    const pgp_rawpacket_t &pkt = pgp_key_get_rawpacket(key);
    pgp_key_pkt_t *        decrypted_seckey =
      decryptor(pkt.raw.data(), pkt.raw.size(), pgp_key_get_pkt(key), password);
    pgp_forget(password, sizeof(password));
    return decrypted_seckey;
}

const pgp_key_id_t &
pgp_key_get_keyid(const pgp_key_t *key)
{
    return key->keyid;
}

const pgp_fingerprint_t &
pgp_key_get_fp(const pgp_key_t *key)
{
    return key->fingerprint;
}

const pgp_key_grip_t &
pgp_key_get_grip(const pgp_key_t *key)
{
    return key->grip;
}

const pgp_fingerprint_t &
pgp_key_get_primary_fp(const pgp_key_t *key)
{
    return key->primary_fp;
}

bool
pgp_key_has_primary_fp(const pgp_key_t *key)
{
    return key->primary_fp_set;
}

void
pgp_key_set_primary_fp(pgp_key_t *key, const pgp_fingerprint_t &fp)
{
    key->primary_fp = fp;
    key->primary_fp_set = true;
}

bool
pgp_key_link_subkey_fp(pgp_key_t *key, pgp_key_t *subkey)
{
    pgp_key_set_primary_fp(subkey, pgp_key_get_fp(key));
    if (!pgp_key_add_subkey_fp(key, pgp_key_get_fp(subkey))) {
        RNP_LOG("failed to add subkey grip");
        return false;
    }
    return true;
}

size_t
pgp_key_get_userid_count(const pgp_key_t *key)
{
    return key->uids.size();
}

const pgp_userid_t *
pgp_key_get_userid(const pgp_key_t *key, size_t idx)
{
    return (idx < key->uids.size()) ? &key->uids[idx] : NULL;
}

pgp_userid_t *
pgp_key_get_userid(pgp_key_t *key, size_t idx)
{
    return (idx < key->uids.size()) ? &key->uids[idx] : NULL;
}

const pgp_revoke_t *
pgp_key_get_userid_revoke(const pgp_key_t *key, size_t uid)
{
    for (size_t i = 0; i < pgp_key_get_revoke_count(key); i++) {
        const pgp_revoke_t *revoke = pgp_key_get_revoke(key, i);
        if (revoke->uid == uid) {
            return revoke;
        }
    }
    return NULL;
}

bool
pgp_key_has_userid(const pgp_key_t *key, const char *uid)
{
    for (auto &userid : key->uids) {
        if (userid.str == uid) {
            return true;
        }
    }
    return false;
}

pgp_userid_t *
pgp_key_add_userid(pgp_key_t *key)
{
    try {
        key->uids.push_back({});
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
    return &key->uids.back();
}

pgp_revoke_t *
pgp_key_add_revoke(pgp_key_t *key)
{
    try {
        key->revokes.push_back({});
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
    return &key->revokes.back();
}

size_t
pgp_key_get_revoke_count(const pgp_key_t *key)
{
    return key->revokes.size();
}

const pgp_revoke_t *
pgp_key_get_revoke(const pgp_key_t *key, size_t idx)
{
    return (idx < key->revokes.size()) ? &key->revokes[idx] : NULL;
}

pgp_revoke_t *
pgp_key_get_revoke(pgp_key_t *key, size_t idx)
{
    return (idx < key->revokes.size()) ? &key->revokes[idx] : NULL;
}

pgp_subsig_t *
pgp_key_add_subsig(pgp_key_t *key)
{
    try {
        key->subsigs.push_back({});
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
    return &key->subsigs.back();
}

size_t
pgp_key_get_subsig_count(const pgp_key_t *key)
{
    return key->subsigs.size();
}

const pgp_subsig_t *
pgp_key_get_subsig(const pgp_key_t *key, size_t idx)
{
    return (idx < key->subsigs.size()) ? &key->subsigs[idx] : NULL;
}

pgp_subsig_t *
pgp_key_get_subsig(pgp_key_t *key, size_t idx)
{
    return (idx < key->subsigs.size()) ? &key->subsigs[idx] : NULL;
}

bool
pgp_subsig_from_signature(pgp_subsig_t *dst, const pgp_signature_t *sig)
{
    pgp_subsig_t subsig = {};
    subsig.sig = *sig;
    if (signature_has_trust(&subsig.sig)) {
        signature_get_trust(&subsig.sig, &subsig.trustlevel, &subsig.trustamount);
    }
    uint8_t *algs = NULL;
    size_t   count = 0;
    if (signature_get_preferred_symm_algs(&subsig.sig, &algs, &count) &&
        !pgp_user_prefs_set_symm_algs(&subsig.prefs, algs, count)) {
        RNP_LOG("failed to alloc symm algs");
        return false;
    }
    if (signature_get_preferred_hash_algs(&subsig.sig, &algs, &count) &&
        !pgp_user_prefs_set_hash_algs(&subsig.prefs, algs, count)) {
        RNP_LOG("failed to alloc hash algs");
        return false;
    }
    if (signature_get_preferred_z_algs(&subsig.sig, &algs, &count) &&
        !pgp_user_prefs_set_z_algs(&subsig.prefs, algs, count)) {
        RNP_LOG("failed to alloc z algs");
        return false;
    }
    if (signature_has_key_flags(&subsig.sig)) {
        subsig.key_flags = signature_get_key_flags(&subsig.sig);
    }
    if (signature_has_key_server_prefs(&subsig.sig)) {
        uint8_t ks_pref = signature_get_key_server_prefs(&subsig.sig);
        if (!pgp_user_prefs_set_ks_prefs(&subsig.prefs, &ks_pref, 1)) {
            RNP_LOG("failed to alloc ks prefs");
            return false;
        }
    }
    if (signature_has_key_server(&subsig.sig)) {
        subsig.prefs.key_server = (uint8_t *) signature_get_key_server(&subsig.sig);
        if (!subsig.prefs.key_server) {
            RNP_LOG("failed to alloc ks");
            return false;
        }
    }
    /* add signature rawpacket */
    try {
        subsig.rawpkt = pgp_rawpacket_t(*sig);
    } catch (const std::exception &e) {
        RNP_LOG("failed to build sig rawpacket: %s", e.what());
        return false;
    }

    *dst = std::move(subsig);
    return true;
}

bool
pgp_key_has_signature(const pgp_key_t *key, const pgp_signature_t *sig)
{
    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        const pgp_subsig_t *subsig = pgp_key_get_subsig(key, i);
        if (subsig->sig == *sig) {
            return true;
        }
    }
    return false;
}

pgp_subsig_t *
pgp_key_replace_signature(pgp_key_t *key, pgp_signature_t *oldsig, pgp_signature_t *newsig)
{
    pgp_subsig_t *subsig = NULL;
    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        subsig = pgp_key_get_subsig(key, i);
        if (subsig->sig == *oldsig) {
            break;
        }
        subsig = NULL;
    }
    if (!subsig) {
        return NULL;
    }

    /* create rawpackets here since oldsig may be equal to subsig */
    pgp_rawpacket_t oldraw;
    pgp_rawpacket_t newraw;
    try {
        oldraw = *oldsig;
        newraw = *newsig;
    } catch (const std::exception &e) {
        RNP_LOG("failed to create rawpacket: %s", e.what());
        return NULL;
    }

    /* fill new subsig */
    pgp_subsig_t newsubsig = {};
    if (!pgp_subsig_from_signature(&newsubsig, newsig)) {
        RNP_LOG("failed to fill subsig");
        return NULL;
    }
    newsubsig.uid = subsig->uid;
    /* replace rawpacket */
    try {
        newsubsig.rawpkt = pgp_rawpacket_t(*newsig);
    } catch (const std::exception &e) {
        RNP_LOG("failed to replace rawpacket: %s", e.what());
        return NULL;
    }

    *subsig = std::move(newsubsig);
    return subsig;
}

static bool
pgp_sig_is_certification(const pgp_subsig_t *sig)
{
    pgp_sig_type_t type = signature_get_type(&sig->sig);
    return (type == PGP_CERT_CASUAL) || (type == PGP_CERT_GENERIC) ||
           (type == PGP_CERT_PERSONA) || (type == PGP_CERT_POSITIVE);
}

static bool
pgp_sig_self_signed(const pgp_key_t *key, const pgp_subsig_t *sig)
{
    /* if we have fingerprint let's check it */
    if (signature_has_keyfp(&sig->sig)) {
        pgp_fingerprint_t sigfp = {};
        if (signature_get_keyfp(&sig->sig, sigfp)) {
            return pgp_key_get_fp(key) == sigfp;
        }
    }
    if (!signature_has_keyid(&sig->sig)) {
        return false;
    }
    pgp_key_id_t sigid = {};
    if (!signature_get_keyid(&sig->sig, sigid)) {
        return false;
    }
    return pgp_key_get_keyid(key) == sigid;
}

static bool
pgp_sig_is_self_signature(const pgp_key_t *key, const pgp_subsig_t *sig)
{
    if (!pgp_key_is_primary_key(key) || !pgp_sig_is_certification(sig)) {
        return false;
    }

    return pgp_sig_self_signed(key, sig);
}

static bool
pgp_sig_is_direct_self_signature(const pgp_key_t *key, const pgp_subsig_t *sig)
{
    if (!pgp_key_is_primary_key(key) || (signature_get_type(&sig->sig) != PGP_SIG_DIRECT)) {
        return false;
    }

    return pgp_sig_self_signed(key, sig);
}

static bool
pgp_sig_is_key_revocation(const pgp_key_t *key, const pgp_subsig_t *sig)
{
    return pgp_key_is_primary_key(key) && (signature_get_type(&sig->sig) == PGP_SIG_REV_KEY);
}

static bool
pgp_sig_is_userid_revocation(const pgp_key_t *key, const pgp_subsig_t *sig)
{
    return pgp_key_is_primary_key(key) && (signature_get_type(&sig->sig) == PGP_SIG_REV_CERT);
}

static bool
pgp_sig_is_subkey_binding(const pgp_key_t *key, const pgp_subsig_t *sig)
{
    return pgp_key_is_subkey(key) && (signature_get_type(&sig->sig) == PGP_SIG_SUBKEY);
}

static bool
pgp_sig_is_subkey_revocation(const pgp_key_t *key, const pgp_subsig_t *sig)
{
    return pgp_key_is_subkey(key) && (signature_get_type(&sig->sig) == PGP_SIG_REV_SUBKEY);
}

pgp_subsig_t *
pgp_key_latest_selfsig(pgp_key_t *key, pgp_sig_subpacket_type_t subpkt)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        pgp_subsig_t *sig = pgp_key_get_subsig(key, i);
        if (!sig->valid) {
            continue;
        }
        if (!pgp_sig_is_self_signature(key, sig) &&
            !pgp_sig_is_direct_self_signature(key, sig)) {
            continue;
        }

        if (subpkt && !signature_get_subpkt(&sig->sig, subpkt)) {
            continue;
        }

        uint32_t creation = signature_get_creation(&sig->sig);
        if (creation >= latest) {
            latest = creation;
            res = sig;
        }
    }
    return res;
}

pgp_subsig_t *
pgp_key_latest_uid_selfcert(pgp_key_t *key, uint32_t uid)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        pgp_subsig_t *sig = pgp_key_get_subsig(key, i);
        if (!sig->valid || (sig->uid != uid)) {
            continue;
        }
        if (!pgp_sig_is_self_signature(key, sig)) {
            continue;
        }

        uint32_t creation = signature_get_creation(&sig->sig);
        if (creation >= latest) {
            latest = creation;
            res = sig;
        }
    }
    return res;
}

pgp_subsig_t *
pgp_key_latest_binding(pgp_key_t *subkey, bool validated)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    for (size_t i = 0; i < pgp_key_get_subsig_count(subkey); i++) {
        pgp_subsig_t *sig = pgp_key_get_subsig(subkey, i);
        if (validated && !sig->valid) {
            continue;
        }
        if (!pgp_sig_is_subkey_binding(subkey, sig)) {
            continue;
        }

        uint32_t creation = signature_get_creation(&sig->sig);
        if (creation >= latest) {
            latest = creation;
            res = sig;
        }
    }
    return res;
}

static void
pgp_key_validate_signature(pgp_key_t *   key,
                           pgp_key_t *   signer,
                           pgp_key_t *   primary,
                           pgp_subsig_t *sig)
{
    sig->validated = false;
    sig->valid = false;

    pgp_userid_t *uid = NULL;
    if (pgp_sig_is_certification(sig) || pgp_sig_is_userid_revocation(key, sig)) {
        uid = pgp_key_get_userid(key, sig->uid);
        if (!uid) {
            RNP_LOG("Userid not found");
            return;
        }
    }

    pgp_signature_info_t sinfo = {};
    sinfo.sig = &sig->sig;
    sinfo.signer = signer;
    sinfo.signer_valid = true;
    if (pgp_sig_is_self_signature(key, sig) || pgp_sig_is_subkey_binding(key, sig)) {
        sinfo.ignore_expiry = true;
    }

    pgp_sig_type_t stype = signature_get_type(&sig->sig);
    switch (stype) {
    case PGP_SIG_BINARY:
    case PGP_SIG_TEXT:
    case PGP_SIG_STANDALONE:
    case PGP_SIG_PRIMARY:
        RNP_LOG("Invalid key signature type: %d", (int) stype);
        return;
    case PGP_CERT_GENERIC:
    case PGP_CERT_PERSONA:
    case PGP_CERT_CASUAL:
    case PGP_CERT_POSITIVE:
    case PGP_SIG_REV_CERT:
        signature_check_certification(&sinfo, pgp_key_get_pkt(key), &uid->pkt);
        break;
    case PGP_SIG_SUBKEY:
        if (!primary) {
            RNP_LOG("No primary key specified");
            return;
        }
        signature_check_binding(&sinfo, pgp_key_get_pkt(primary), pgp_key_get_pkt(key));
        break;
    case PGP_SIG_DIRECT:
    case PGP_SIG_REV_KEY:
        signature_check_direct(&sinfo, pgp_key_get_pkt(key));
        break;
    case PGP_SIG_REV_SUBKEY:
        if (!primary) {
            RNP_LOG("No primary key specified");
            return;
        }
        signature_check_subkey_revocation(
          &sinfo, pgp_key_get_pkt(primary), pgp_key_get_pkt(key));
        break;
    default:
        RNP_LOG("Unsupported key signature type: %d", (int) stype);
        return;
    }

    sig->validated = true;
    sig->valid = sinfo.valid;
    /* revocation signature cannot expire */
    if ((stype != PGP_SIG_REV_KEY) && (stype != PGP_SIG_REV_SUBKEY) &&
        (stype != PGP_SIG_REV_CERT)) {
        sig->valid = sig->valid && !sinfo.expired;
    }
}

static void
pgp_key_validate_self_signatures(pgp_key_t *key)
{
    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        pgp_subsig_t *sig = pgp_key_get_subsig(key, i);
        if (sig->validated) {
            continue;
        }

        if (pgp_sig_is_self_signature(key, sig) || pgp_sig_is_userid_revocation(key, sig) ||
            pgp_sig_is_key_revocation(key, sig)) {
            pgp_key_validate_signature(key, key, NULL, sig);
        }
    }
}

static void
pgp_subkey_validate_self_signatures(pgp_key_t *sub, pgp_key_t *key)
{
    for (size_t i = 0; i < pgp_key_get_subsig_count(sub); i++) {
        pgp_subsig_t *sig = pgp_key_get_subsig(sub, i);
        if (sig->validated) {
            continue;
        }

        if (pgp_sig_is_subkey_binding(sub, sig) || pgp_sig_is_subkey_revocation(sub, sig)) {
            pgp_key_validate_signature(sub, key, key, sig);
        }
    }
}

static pgp_map_t ss_rr_code_map[] = {
  {PGP_REVOCATION_NO_REASON, "No reason specified"},
  {PGP_REVOCATION_SUPERSEDED, "Key is superseded"},
  {PGP_REVOCATION_COMPROMISED, "Key material has been compromised"},
  {PGP_REVOCATION_RETIRED, "Key is retired and no longer used"},
  {PGP_REVOCATION_NO_LONGER_VALID, "User ID information is no longer valid"},
  {0x00, NULL}, /* this is the end-of-array marker */
};

bool
pgp_subkey_refresh_data(pgp_key_t *sub, pgp_key_t *key)
{
    /* validate self-signatures if not done yet */
    if (key) {
        pgp_subkey_validate_self_signatures(sub, key);
    }
    pgp_subsig_t *sig = pgp_key_latest_binding(sub, key);
    /* subkey expiration */
    sub->expiration = sig ? signature_get_key_expiration(&sig->sig) : 0;
    /* subkey flags */
    if (sig && signature_has_key_flags(&sig->sig)) {
        sub->key_flags = sig->key_flags;
    } else {
        sub->key_flags = pgp_pk_alg_capabilities(pgp_key_get_alg(sub));
    }
    /* revocation */
    pgp_key_clear_revokes(sub);
    for (size_t i = 0; i < pgp_key_get_subsig_count(sub); i++) {
        sig = pgp_key_get_subsig(sub, i);
        if (!sig->valid || !pgp_sig_is_subkey_revocation(sub, sig)) {
            continue;
        }
        sub->revoked = true;
        char *reason = NULL;
        if (!signature_has_revocation_reason(&sig->sig)) {
            RNP_LOG("Warning: no revocation reason in subkey revocation");
            sub->revocation.code = PGP_REVOCATION_NO_REASON;
        } else if (!signature_get_revocation_reason(
                     &sig->sig, &sub->revocation.code, &reason)) {
            return false;
        }

        try {
            sub->revocation.reason = (reason && strlen(reason)) ?
                                       reason :
                                       pgp_str_from_map(sub->revocation.code, ss_rr_code_map);
            free(reason);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            free(reason);
            return false;
        }
        break;
    }
    return true;
}

bool
pgp_key_refresh_data(pgp_key_t *key)
{
    if (!pgp_key_is_primary_key(key)) {
        RNP_LOG("key must be primary");
        return false;
    }
    /* validate self-signatures if not done yet */
    pgp_key_validate_self_signatures(key);
    /* key expiration */
    pgp_subsig_t *sig = pgp_key_latest_selfsig(key, PGP_SIG_SUBPKT_UNKNOWN);
    key->expiration = sig ? signature_get_key_expiration(&sig->sig) : 0;
    /* key flags */
    if (sig && signature_has_key_flags(&sig->sig)) {
        key->key_flags = sig->key_flags;
    } else {
        key->key_flags = pgp_pk_alg_capabilities(pgp_key_get_alg(key));
    }
    /* primary userid */
    key->uid0_set = false;
    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        sig = pgp_key_get_subsig(key, i);
        if (!sig->valid || !pgp_sig_is_self_signature(key, sig)) {
            continue;
        }
        if (signature_get_primary_uid(&sig->sig)) {
            key->uid0 = sig->uid;
            key->uid0_set = true;
            break;
        }
    }
    /* revocation(s) */
    pgp_key_clear_revokes(key);
    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        sig = pgp_key_get_subsig(key, i);
        if (!sig->valid) {
            continue;
        }
        pgp_revoke_t *revocation = NULL;
        if (pgp_sig_is_key_revocation(key, sig)) {
            if (key->revoked) {
                continue;
            }
            key->revoked = true;
            revocation = &key->revocation;
            revocation->uid = -1;
        } else if (pgp_sig_is_userid_revocation(key, sig)) {
            if (!(revocation = pgp_key_add_revoke(key))) {
                RNP_LOG("failed to add revoke");
                return false;
            }
            revocation->uid = sig->uid;
        }

        if (!revocation) {
            continue;
        }

        char *reason = NULL;
        if (!signature_has_revocation_reason(&sig->sig)) {
            RNP_LOG("Warning: no revocation reason in key/userid revocation");
            revocation->code = PGP_REVOCATION_NO_REASON;
        } else if (!signature_get_revocation_reason(&sig->sig, &revocation->code, &reason)) {
            return false;
        }

        try {
            revocation->reason = (reason && strlen(reason)) ?
                                   reason :
                                   pgp_str_from_map(revocation->code, ss_rr_code_map);
            free(reason);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            free(reason);
            return false;
        }
    }

    return true;
}

size_t
pgp_key_get_rawpacket_count(const pgp_key_t *key)
{
    if (key->format == PGP_KEY_STORE_G10) {
        return 1;
    }
    return 1 + key->uids.size() + key->subsigs.size();
}

pgp_rawpacket_t &
pgp_key_get_rawpacket(pgp_key_t *key)
{
    return key->rawpkt;
}
const pgp_rawpacket_t &
pgp_key_get_rawpacket(const pgp_key_t *key)
{
    return key->rawpkt;
}

size_t
pgp_key_get_subkey_count(const pgp_key_t *key)
{
    return key->subkey_fps.size();
}

bool
pgp_key_add_subkey_fp(pgp_key_t *key, const pgp_fingerprint_t &fp)
{
    if (std::find(key->subkey_fps.begin(), key->subkey_fps.end(), fp) !=
        key->subkey_fps.end()) {
        return true;
    }

    try {
        key->subkey_fps.push_back(fp);
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

void
pgp_key_remove_subkey_fp(pgp_key_t *key, const pgp_fingerprint_t &fp)
{
    auto it = std::find(key->subkey_fps.begin(), key->subkey_fps.end(), fp);
    if (it != key->subkey_fps.end()) {
        key->subkey_fps.erase(it);
    }
}

const pgp_fingerprint_t &
pgp_key_get_subkey_fp(const pgp_key_t *key, size_t idx)
{
    return key->subkey_fps[idx];
}

pgp_key_t *
pgp_key_get_subkey(const pgp_key_t *key, rnp_key_store_t *store, size_t idx)
{
    try {
        const pgp_fingerprint_t &fp = pgp_key_get_subkey_fp(key, idx);
        return rnp_key_store_get_key_by_fpr(store, fp);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
}

pgp_key_flags_t
pgp_pk_alg_capabilities(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_RSA:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH | PGP_KF_ENCRYPT);

    case PGP_PKA_RSA_SIGN_ONLY:
        // deprecated, but still usable
        return PGP_KF_SIGN;

    case PGP_PKA_RSA_ENCRYPT_ONLY:
        // deprecated, but still usable
        return PGP_KF_ENCRYPT;

    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN: /* deprecated */
        // These are no longer permitted per the RFC
        return PGP_KF_NONE;

    case PGP_PKA_DSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);

    case PGP_PKA_SM2:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH | PGP_KF_ENCRYPT);

    case PGP_PKA_ECDH:
    case PGP_PKA_ELGAMAL:
        return PGP_KF_ENCRYPT;

    default:
        RNP_LOG("unknown pk alg: %d\n", alg);
        return PGP_KF_NONE;
    }
}

bool
pgp_key_is_locked(const pgp_key_t *key)
{
    if (!pgp_key_is_secret(key)) {
        RNP_LOG("key is not a secret key");
        return false;
    }
    return pgp_key_is_encrypted(key);
}

bool
pgp_key_unlock(pgp_key_t *key, const pgp_password_provider_t *provider)
{
    pgp_key_pkt_t *decrypted_seckey = NULL;

    // sanity checks
    if (!key || !provider) {
        return false;
    }
    if (!pgp_key_is_secret(key)) {
        RNP_LOG("key is not a secret key");
        return false;
    }

    // see if it's already unlocked
    if (!pgp_key_is_locked(key)) {
        return true;
    }

    pgp_password_ctx_t ctx = {.op = PGP_OP_UNLOCK, .key = key};
    decrypted_seckey = pgp_decrypt_seckey(key, provider, &ctx);

    if (decrypted_seckey) {
        // this shouldn't really be necessary, but just in case
        forget_secret_key_fields(&key->pkt.material);
        // copy the decrypted mpis into the pgp_key_t
        key->pkt.material = decrypted_seckey->material;
        key->pkt.material.secret = true;
        delete decrypted_seckey;
        return true;
    }
    return false;
}

bool
pgp_key_lock(pgp_key_t *key)
{
    // sanity checks
    if (!key || !pgp_key_is_secret(key)) {
        RNP_LOG("invalid args");
        return false;
    }

    // see if it's already locked
    if (pgp_key_is_locked(key)) {
        return true;
    }

    forget_secret_key_fields(&key->pkt.material);
    return true;
}

static bool
pgp_write_seckey(pgp_dest_t *   dst,
                 pgp_pkt_type_t tag,
                 pgp_key_pkt_t *seckey,
                 const char *   password)
{
    bool           res = false;
    pgp_pkt_type_t oldtag = seckey->tag;

    seckey->tag = tag;
    if (encrypt_secret_key(seckey, password, NULL)) {
        goto done;
    }
    res = stream_write_key(seckey, dst);
done:
    seckey->tag = oldtag;
    return res;
}

static bool
write_key_to_rawpacket(pgp_key_pkt_t *        seckey,
                       pgp_rawpacket_t &      packet,
                       pgp_pkt_type_t         type,
                       pgp_key_store_format_t format,
                       const char *           password)
{
    pgp_dest_t memdst = {};
    bool       ret = false;

    if (init_mem_dest(&memdst, NULL, 0)) {
        goto done;
    }

    // encrypt+write the key in the appropriate format
    switch (format) {
    case PGP_KEY_STORE_GPG:
    case PGP_KEY_STORE_KBX:
        if (!pgp_write_seckey(&memdst, type, seckey, password)) {
            RNP_LOG("failed to write seckey");
            goto done;
        }
        break;
    case PGP_KEY_STORE_G10:
        if (!g10_write_seckey(&memdst, seckey, password)) {
            RNP_LOG("failed to write g10 seckey");
            goto done;
        }
        break;
    default:
        RNP_LOG("invalid format");
        goto done;
    }

    try {
        uint8_t *mem = (uint8_t *) mem_dest_get_memory(&memdst);
        packet = pgp_rawpacket_t(mem, memdst.writeb, type);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        goto done;
    }
    ret = true;
done:
    dst_close(&memdst, true);
    return ret;
}

bool
rnp_key_add_protection(pgp_key_t *                    key,
                       pgp_key_store_format_t         format,
                       rnp_key_protection_params_t *  protection,
                       const pgp_password_provider_t *password_provider)
{
    char password[MAX_PASSWORD_LENGTH] = {0};

    if (!key || !password_provider) {
        return false;
    }

    pgp_password_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.op = PGP_OP_PROTECT;
    ctx.key = key;

    // ask the provider for a password
    if (!pgp_request_password(password_provider, &ctx, password, sizeof(password))) {
        return false;
    }

    bool ret = pgp_key_protect(key, &key->pkt, format, protection, password);
    pgp_forget(password, sizeof(password));
    return ret;
}

bool
pgp_key_protect(pgp_key_t *                  key,
                pgp_key_pkt_t *              decrypted_seckey,
                pgp_key_store_format_t       format,
                rnp_key_protection_params_t *protection,
                const char *                 new_password)
{
    bool                        ret = false;
    rnp_key_protection_params_t default_protection = {.symm_alg = DEFAULT_PGP_SYMM_ALG,
                                                      .cipher_mode = DEFAULT_PGP_CIPHER_MODE,
                                                      .iterations = 0,
                                                      .hash_alg = DEFAULT_PGP_HASH_ALG};
    pgp_key_pkt_t *             seckey = NULL;

    // sanity check
    if (!key || !decrypted_seckey || !new_password) {
        RNP_LOG("NULL args");
        goto done;
    }
    if (!pgp_key_is_secret(key)) {
        RNP_LOG("Warning: this is not a secret key");
        goto done;
    }
    if (!decrypted_seckey->material.secret) {
        RNP_LOG("Decrypted seckey must be provided");
        goto done;
    }

    seckey = &key->pkt;
    // force these, as it's the only method we support
    seckey->sec_protection.s2k.usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    seckey->sec_protection.s2k.specifier = PGP_S2KS_ITERATED_AND_SALTED;

    if (!protection) {
        protection = &default_protection;
    }

    if (!protection->symm_alg) {
        protection->symm_alg = default_protection.symm_alg;
    }
    if (!protection->cipher_mode) {
        protection->cipher_mode = default_protection.cipher_mode;
    }
    if (!protection->hash_alg) {
        protection->hash_alg = default_protection.hash_alg;
    }
    if (!protection->iterations) {
        protection->iterations =
          pgp_s2k_compute_iters(protection->hash_alg, DEFAULT_S2K_MSEC, DEFAULT_S2K_TUNE_MSEC);
    }

    seckey->sec_protection.symm_alg = protection->symm_alg;
    seckey->sec_protection.cipher_mode = protection->cipher_mode;
    seckey->sec_protection.s2k.iterations = pgp_s2k_round_iterations(protection->iterations);
    seckey->sec_protection.s2k.hash_alg = protection->hash_alg;

    // write the protected key to raw packet
    if (!write_key_to_rawpacket(decrypted_seckey,
                                pgp_key_get_rawpacket(key),
                                pgp_key_get_type(key),
                                format,
                                new_password)) {
        goto done;
    }
    key->format = format;
    ret = true;

done:
    return ret;
}

bool
pgp_key_unprotect(pgp_key_t *key, const pgp_password_provider_t *password_provider)
{
    bool           ret = false;
    pgp_key_pkt_t *seckey = NULL;
    pgp_key_pkt_t *decrypted_seckey = NULL;

    // sanity check
    if (!pgp_key_is_secret(key)) {
        RNP_LOG("Warning: this is not a secret key");
        goto done;
    }
    // already unprotected
    if (!pgp_key_is_protected(key)) {
        ret = true;
        goto done;
    }

    seckey = &key->pkt;

    if (pgp_key_is_encrypted(key)) {
        pgp_password_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.op = PGP_OP_UNPROTECT;
        ctx.key = key;

        decrypted_seckey = pgp_decrypt_seckey(key, password_provider, &ctx);
        if (!decrypted_seckey) {
            goto done;
        }
        seckey = decrypted_seckey;
    }
    seckey->sec_protection.s2k.usage = PGP_S2KU_NONE;
    if (!write_key_to_rawpacket(
          seckey, pgp_key_get_rawpacket(key), pgp_key_get_type(key), key->format, NULL)) {
        goto done;
    }
    if (decrypted_seckey) {
        key->pkt = std::move(*decrypted_seckey);
        /* current logic is that unprotected key should be additionally unlocked */
        forget_secret_key_fields(&key->pkt.material);
    }
    ret = true;
done:
    delete decrypted_seckey;
    return ret;
}

bool
pgp_key_is_protected(const pgp_key_t *key)
{
    // sanity check
    if (!pgp_key_is_secret(key)) {
        RNP_LOG("Warning: this is not a secret key");
    }
    return key->pkt.sec_protection.s2k.usage != PGP_S2KU_NONE;
}

bool
pgp_key_add_userid_certified(pgp_key_t *              key,
                             const pgp_key_pkt_t *    seckey,
                             pgp_hash_alg_t           hash_alg,
                             rnp_selfsig_cert_info_t *cert)
{
    // sanity checks
    if (!key || !seckey || !cert || !cert->userid[0]) {
        RNP_LOG("wrong parameters");
        return false;
    }
    // userids are only valid for primary keys, not subkeys
    if (!pgp_key_is_primary_key(key)) {
        RNP_LOG("cannot add a userid to a subkey");
        return false;
    }
    // see if the key already has this userid
    if (pgp_key_has_userid(key, (const char *) cert->userid)) {
        RNP_LOG("key already has this userid");
        return false;
    }
    // this isn't really valid for this format
    if (key->format == PGP_KEY_STORE_G10) {
        RNP_LOG("Unsupported key store type");
        return false;
    }
    // We only support modifying v4 and newer keys
    if (key->pkt.version < PGP_V4) {
        RNP_LOG("adding a userid to V2/V3 key is not supported");
        return false;
    }
    // TODO: changing the primary userid is not currently supported
    if (key->uid0_set && cert->primary) {
        RNP_LOG("changing the primary userid is not supported");
        return false;
    }

    /* Fill the transferable userid */
    pgp_transferable_userid_t uid;
    uid.uid.tag = PGP_PKT_USER_ID;
    uid.uid.uid_len = strlen((char *) cert->userid);
    if (!(uid.uid.uid = (uint8_t *) malloc(uid.uid.uid_len))) {
        RNP_LOG("allocation failed");
        return false;
    }
    /* uid.uid.uid looks really weird */
    memcpy(uid.uid.uid, (char *) cert->userid, uid.uid.uid_len);
    if (!transferable_userid_certify(*seckey, uid, *seckey, hash_alg, *cert)) {
        RNP_LOG("failed to add userid certification");
        return false;
    }

    return rnp_key_add_transferable_userid(key, &uid) && pgp_key_refresh_data(key);
}

static bool
update_sig_expiration(pgp_signature_t *dst, const pgp_signature_t *src, uint32_t expiry)
{
    try {
        *dst = *src;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
    if (!expiry) {
        pgp_sig_subpkt_t *subpkt = signature_get_subpkt(dst, PGP_SIG_SUBPKT_KEY_EXPIRY);
        signature_remove_subpkt(dst, subpkt);
    } else {
        signature_set_key_expiration(dst, expiry);
    }
    signature_set_creation(dst, time(NULL));
    return true;
}

bool
pgp_key_set_expiration(pgp_key_t *                    key,
                       pgp_key_t *                    seckey,
                       uint32_t                       expiry,
                       const pgp_password_provider_t *prov)
{
    if (!pgp_key_is_primary_key(key)) {
        RNP_LOG("Not a primary key");
        return false;
    }

    /* locate the latest valid certification */
    pgp_subsig_t *subsig = pgp_key_latest_selfsig(key, PGP_SIG_SUBPKT_UNKNOWN);
    if (!subsig) {
        RNP_LOG("No valid self-signature");
        return false;
    }

    /* update signature and re-sign it */
    if (!expiry && !signature_has_key_expiration(&subsig->sig)) {
        return true;
    }

    bool locked = pgp_key_is_locked(seckey);
    if (locked && !pgp_key_unlock(seckey, prov)) {
        RNP_LOG("Failed to unlock secret key");
        return false;
    }
    pgp_signature_t newsig;
    bool            res = false;
    if (!update_sig_expiration(&newsig, &subsig->sig, expiry)) {
        goto done;
    }
    if (pgp_sig_is_certification(subsig)) {
        pgp_userid_t *uid = pgp_key_get_userid(key, subsig->uid);
        if (!uid) {
            RNP_LOG("uid not found");
            goto done;
        }
        if (!signature_calculate_certification(
              pgp_key_get_pkt(key), &uid->pkt, &newsig, pgp_key_get_pkt(seckey))) {
            RNP_LOG("failed to calculate signature");
            goto done;
        }
    } else {
        /* direct-key signature case */
        if (!signature_calculate_direct(
              pgp_key_get_pkt(key), &newsig, pgp_key_get_pkt(seckey))) {
            RNP_LOG("failed to calculate signature");
            goto done;
        }
    }

    /* replace signature, first for secret key since it may be replaced in public */
    if (pgp_key_has_signature(seckey, &subsig->sig)) {
        res = pgp_key_replace_signature(seckey, &subsig->sig, &newsig) &&
              pgp_key_refresh_data(key);
    }
    res = res && pgp_key_replace_signature(key, &subsig->sig, &newsig) &&
          pgp_key_refresh_data(key);
done:
    if (locked) {
        pgp_key_lock(seckey);
    }
    return res;
}

bool
pgp_subkey_set_expiration(pgp_key_t *                    sub,
                          pgp_key_t *                    primsec,
                          pgp_key_t *                    secsub,
                          uint32_t                       expiry,
                          const pgp_password_provider_t *prov)
{
    if (!pgp_key_is_subkey(sub)) {
        RNP_LOG("Not a subkey");
        return false;
    }

    /* find the latest valid subkey binding */
    pgp_subsig_t *subsig = pgp_key_latest_binding(sub, true);
    if (!subsig) {
        RNP_LOG("No valid subkey binding");
        return false;
    }
    if (!expiry && !signature_has_key_expiration(&subsig->sig)) {
        return true;
    }

    bool res = false;
    bool subsign = pgp_key_get_flags(secsub) & PGP_KF_SIGN;
    bool locked = pgp_key_is_locked(primsec);
    if (locked && !pgp_key_unlock(primsec, prov)) {
        RNP_LOG("Failed to unlock primary key");
        return false;
    }
    pgp_signature_t newsig;
    bool            sublocked = false;
    if (subsign && pgp_key_is_locked(secsub)) {
        if (!pgp_key_unlock(secsub, prov)) {
            RNP_LOG("Failed to unlock subkey");
            goto done;
        }
        sublocked = true;
    }

    /* update signature and re-sign */
    if (!update_sig_expiration(&newsig, &subsig->sig, expiry)) {
        goto done;
    }
    if (!signature_calculate_binding(
          pgp_key_get_pkt(primsec), pgp_key_get_pkt(secsub), &newsig, subsign)) {
        RNP_LOG("failed to calculate signature");
        goto done;
    }

    /* replace signature, first for the secret key since it may be replaced in public */
    if (pgp_key_has_signature(secsub, &subsig->sig)) {
        res = pgp_key_replace_signature(secsub, &subsig->sig, &newsig) &&
              pgp_subkey_refresh_data(secsub, primsec);
    }
    res = res && pgp_key_replace_signature(sub, &subsig->sig, &newsig) &&
          pgp_subkey_refresh_data(sub, primsec);
done:
    if (locked) {
        pgp_key_lock(primsec);
    }
    if (sublocked) {
        pgp_key_lock(secsub);
    }
    return res;
}

static size_t
pgp_key_write_signatures(pgp_dest_t *dst, const pgp_key_t *key, uint32_t uid, size_t start)
{
    for (size_t i = start; i < pgp_key_get_subsig_count(key); i++) {
        const pgp_subsig_t *sig = pgp_key_get_subsig(key, i);
        if (sig->uid != uid) {
            return i;
        }
        dst_write(dst, sig->rawpkt.raw.data(), sig->rawpkt.raw.size());
    }
    return pgp_key_get_subsig_count(key);
}

bool
pgp_key_write_packets(const pgp_key_t *key, pgp_dest_t *dst)
{
    if (!pgp_key_get_rawpacket_count(key)) {
        return false;
    }
    /* write key rawpacket */
    const pgp_rawpacket_t &pkt = pgp_key_get_rawpacket(key);
    dst_write(dst, pkt.raw.data(), pkt.raw.size());

    if (key->format == PGP_KEY_STORE_G10) {
        return !dst->werr;
    }

    /* write signatures on key */
    size_t idx = pgp_key_write_signatures(dst, key, (uint32_t) -1, 0);

    /* write uids and their signatures */
    for (size_t i = 0; i < pgp_key_get_userid_count(key); i++) {
        const pgp_userid_t *uid = pgp_key_get_userid(key, i);
        dst_write(dst, uid->rawpkt.raw.data(), uid->rawpkt.raw.size());
        idx = pgp_key_write_signatures(dst, key, i, idx);
    }
    return !dst->werr;
}

bool
pgp_key_write_xfer(pgp_dest_t *dst, const pgp_key_t *key, const rnp_key_store_t *keyring)
{
    if (!pgp_key_write_packets(key, dst)) {
        RNP_LOG("Failed to export primary key");
        return false;
    }

    if (!keyring) {
        return !dst->werr;
    }

    // Export subkeys
    for (auto &fp : key->subkey_fps) {
        const pgp_key_t *subkey = rnp_key_store_get_key_by_fpr(keyring, fp);
        if (!subkey) {
            char fphex[PGP_FINGERPRINT_SIZE * 2 + 1] = {0};
            rnp_hex_encode(fp.fingerprint, fp.length, fphex, sizeof(fphex), RNP_HEX_LOWERCASE);
            RNP_LOG("Warning! Subkey %s not found.", fphex);
            continue;
        }
        if (!pgp_key_write_packets(subkey, dst)) {
            RNP_LOG("Error occured when exporting a subkey");
            return false;
        }
    }
    return !dst->werr;
}

bool
pgp_key_write_autocrypt(pgp_dest_t &dst, pgp_key_t &key, pgp_key_t &sub, size_t uid)
{
    pgp_subsig_t *cert = pgp_key_latest_uid_selfcert(&key, uid);
    if (!cert) {
        RNP_LOG("No valid uid certification");
        return false;
    }
    pgp_subsig_t *binding = pgp_key_latest_binding(&sub, true);
    if (!binding) {
        RNP_LOG("No valid binding for subkey");
        return false;
    }
    /* write all or nothing */
    pgp_dest_t memdst = {};
    if (init_mem_dest(&memdst, NULL, 0)) {
        RNP_LOG("Allocation failed");
        return false;
    }

    bool res = false;
    try {
        if (pgp_key_is_secret(&key)) {
            pgp_key_pkt_t pkt(key.pkt, true);
            res = stream_write_key(&pkt, &memdst);
        } else {
            res = stream_write_key(&key.pkt, &memdst);
        }

        res = res && stream_write_userid(&key.uids[uid].pkt, &memdst) &&
              stream_write_signature(&cert->sig, &memdst);

        if (res && pgp_key_is_secret(&sub)) {
            pgp_key_pkt_t pkt(sub.pkt, true);
            res = stream_write_key(&pkt, &memdst);
        } else if (res) {
            res = stream_write_key(&sub.pkt, &memdst);
        }
        res = res && stream_write_signature(&binding->sig, &memdst);
        if (res) {
            dst_write(&dst, mem_dest_get_memory(&memdst), memdst.writeb);
            res = !dst.werr;
        }
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
    }
    dst_close(&memdst, true);
    return res;
}

pgp_key_t *
find_suitable_key(pgp_op_t            op,
                  pgp_key_t *         key,
                  pgp_key_provider_t *key_provider,
                  uint8_t             desired_usage)
{
    assert(desired_usage);
    if (!key) {
        return NULL;
    }
    if (pgp_key_get_flags(key) & desired_usage) {
        return key;
    }
    pgp_key_request_ctx_t ctx{.op = op, .secret = pgp_key_is_secret(key)};
    ctx.search.type = PGP_KEY_SEARCH_FINGERPRINT;

    for (auto &fp : key->subkey_fps) {
        ctx.search.by.fingerprint = fp;
        pgp_key_t *subkey = pgp_request_key(key_provider, &ctx);
        if (subkey && (pgp_key_get_flags(subkey) & desired_usage)) {
            return subkey;
        }
    }
    return NULL;
}

pgp_hash_alg_t
pgp_hash_adjust_alg_to_key(pgp_hash_alg_t hash, const pgp_key_pkt_t *pubkey)
{
    if ((pubkey->alg != PGP_PKA_DSA) && (pubkey->alg != PGP_PKA_ECDSA)) {
        return hash;
    }

    pgp_hash_alg_t hash_min;
    if (pubkey->alg == PGP_PKA_ECDSA) {
        hash_min = ecdsa_get_min_hash(pubkey->material.ec.curve);
    } else {
        hash_min = dsa_get_min_hash(mpi_bits(&pubkey->material.dsa.q));
    }

    if (pgp_digest_length(hash) < pgp_digest_length(hash_min)) {
        return hash_min;
    }
    return hash;
}

static void
pgp_key_validate_primary(pgp_key_t *key, rnp_key_store_t *keyring)
{
    /* validate signatures if needed */
    pgp_key_validate_self_signatures(key);

    /* consider public key as valid on this level if it has at least one non-expired
     * self-signature (or it is secret), and is not revoked */
    key->valid = false;
    key->validated = true;
    bool has_cert = false;
    bool has_expired = false;
    for (size_t i = 0; i < pgp_key_get_subsig_count(key); i++) {
        pgp_subsig_t *sig = pgp_key_get_subsig(key, i);
        if (!sig->validated || !sig->valid) {
            continue;
        }

        if (pgp_sig_is_self_signature(key, sig) && !has_cert) {
            /* check whether key is expired */
            if (!signature_has_key_expiration(&sig->sig)) {
                has_cert = true;
                continue;
            }
            time_t expiry =
              pgp_key_get_creation(key) + signature_get_key_expiration(&sig->sig);
            has_expired = expiry < time(NULL);
            has_cert = !has_expired;
        } else if (pgp_sig_is_key_revocation(key, sig)) {
            return;
        }
    }
    /* we have at least one non-expiring key self-signature or secret key */
    if (has_cert || pgp_key_is_secret(key)) {
        key->valid = true;
        return;
    }
    /* we have valid self-signature which expires key */
    if (has_expired) {
        return;
    }

    /* let's check whether key has at least one valid subkey binding */
    for (size_t i = 0; i < pgp_key_get_subkey_count(key); i++) {
        pgp_key_t *sub = pgp_key_get_subkey(key, keyring, i);
        if (!sub) {
            continue;
        }
        pgp_subkey_validate_self_signatures(sub, key);
        pgp_subsig_t *sig = pgp_key_latest_binding(sub, true);
        if (!sig) {
            continue;
        }
        /* check whether subkey is expired - then do not mark key as valid */
        if (signature_has_key_expiration(&sig->sig)) {
            time_t expiry =
              pgp_key_get_creation(sub) + signature_get_key_expiration(&sig->sig);
            if (expiry < time(NULL)) {
                continue;
            }
        }
        key->valid = true;
        return;
    }
}

void
pgp_key_validate_subkey(pgp_key_t *subkey, pgp_key_t *key)
{
    /* consider subkey as valid on this level if it has valid primary key, has at least one
     * non-expired binding signature (or is secret), and is not revoked. */
    subkey->valid = false;
    subkey->validated = true;
    if (!key || !key->valid) {
        return;
    }
    /* validate signatures if needed */
    pgp_subkey_validate_self_signatures(subkey, key);

    bool has_binding = false;
    for (size_t i = 0; i < pgp_key_get_subsig_count(subkey); i++) {
        pgp_subsig_t *sig = pgp_key_get_subsig(subkey, i);
        if (!sig->validated || !sig->valid) {
            continue;
        }

        if (pgp_sig_is_subkey_binding(subkey, sig) && !has_binding) {
            /* check whether subkey is expired */
            if (signature_has_key_expiration(&sig->sig)) {
                time_t expiry =
                  pgp_key_get_creation(subkey) + signature_get_key_expiration(&sig->sig);
                if (expiry < time(NULL)) {
                    continue;
                }
            }
            has_binding = true;
        } else if (pgp_sig_is_subkey_revocation(subkey, sig)) {
            return;
        }
    }
    subkey->valid = has_binding || (pgp_key_is_secret(subkey) && pgp_key_is_secret(key));
    return;
}

void
pgp_key_validate(pgp_key_t *key, rnp_key_store_t *keyring)
{
    key->valid = false;
    key->validated = false;
    if (!pgp_key_is_subkey(key)) {
        pgp_key_validate_primary(key, keyring);
    } else {
        pgp_key_validate_subkey(
          key, rnp_key_store_get_key_by_fpr(keyring, pgp_key_get_primary_fp(key)));
    }
}

void
pgp_key_revalidate_updated(pgp_key_t *key, rnp_key_store_t *keyring)
{
    if (pgp_key_is_subkey(key)) {
        pgp_key_t *primary = rnp_key_store_get_primary_key(keyring, key);
        if (primary) {
            pgp_key_revalidate_updated(primary, keyring);
        }
        return;
    }

    pgp_key_validate(key, keyring);
    /* validate/re-validate all subkeys as well */
    for (auto &fp : key->subkey_fps) {
        pgp_key_t *subkey = rnp_key_store_get_key_by_fpr(keyring, fp);
        if (subkey) {
            pgp_key_validate_subkey(subkey, key);
            pgp_subkey_refresh_data(subkey, key);
        }
    }

    if (!pgp_key_refresh_data(key)) {
        RNP_LOG("Failed to refresh key data");
    }
}

static void
mem_dest_to_vector(pgp_dest_t *dst, std::vector<uint8_t> &vec)
{
    uint8_t *mem = (uint8_t *) mem_dest_get_memory(dst);
    try {
        vec = std::vector<uint8_t>(mem, mem + dst->writeb);
        dst_close(dst, true);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        dst_close(dst, true);
        throw;
    }
}

pgp_rawpacket_t::pgp_rawpacket_t(const pgp_signature_t &sig)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        throw std::bad_alloc();
    }

    if (!stream_write_signature(&sig, &dst)) {
        dst_close(&dst, true);
        throw std::bad_alloc();
    }

    mem_dest_to_vector(&dst, raw);
    tag = PGP_PKT_SIGNATURE;
}

pgp_rawpacket_t::pgp_rawpacket_t(pgp_key_pkt_t &key)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        throw std::bad_alloc();
    }

    if (!stream_write_key(&key, &dst)) {
        dst_close(&dst, true);
        throw std::bad_alloc();
    }

    mem_dest_to_vector(&dst, raw);
    tag = key.tag;
}

pgp_rawpacket_t::pgp_rawpacket_t(const pgp_userid_pkt_t &uid)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        throw std::bad_alloc();
    }

    if (!stream_write_userid(&uid, &dst)) {
        dst_close(&dst, true);
        throw std::bad_alloc();
    }

    mem_dest_to_vector(&dst, raw);
    tag = uid.tag;
}

pgp_subsig_t::pgp_subsig_t(const pgp_subsig_t &src)
{
    uid = src.uid;
    sig = src.sig;
    rawpkt = src.rawpkt;
    trustlevel = src.trustlevel;
    trustamount = src.trustamount;
    key_flags = src.key_flags;
    if (pgp_userprefs_copy(&prefs, &src.prefs)) {
        throw std::bad_alloc();
    }
    validated = src.validated;
    valid = src.valid;
}

pgp_subsig_t::pgp_subsig_t(pgp_subsig_t &&src)
{
    uid = src.uid;
    sig = std::move(src.sig);
    rawpkt = std::move(src.rawpkt);
    trustlevel = src.trustlevel;
    trustamount = src.trustamount;
    key_flags = src.key_flags;
    prefs = src.prefs;
    src.prefs = {};
    validated = src.validated;
    valid = src.valid;
}

pgp_subsig_t &
pgp_subsig_t::operator=(pgp_subsig_t &&src)
{
    if (&src == this) {
        return *this;
    }

    pgp_free_user_prefs(&prefs);
    uid = src.uid;
    sig = std::move(src.sig);
    rawpkt = std::move(src.rawpkt);
    trustlevel = src.trustlevel;
    trustamount = src.trustamount;
    key_flags = src.key_flags;
    prefs = src.prefs;
    src.prefs = {};
    validated = src.validated;
    valid = src.valid;
    return *this;
}

pgp_subsig_t &
pgp_subsig_t::operator=(const pgp_subsig_t &src)
{
    if (&src == this) {
        return *this;
    }

    pgp_free_user_prefs(&prefs);
    uid = src.uid;
    sig = src.sig;
    rawpkt = src.rawpkt;
    trustlevel = src.trustlevel;
    trustamount = src.trustamount;
    key_flags = src.key_flags;
    if (pgp_userprefs_copy(&prefs, &src.prefs)) {
        throw std::bad_alloc();
    }
    validated = src.validated;
    valid = src.valid;
    return *this;
}

pgp_subsig_t::~pgp_subsig_t()
{
    pgp_free_user_prefs(&prefs);
}

pgp_key_t::pgp_key_t(const pgp_key_t &src, bool pubonly)
{
    /* Do some checks for g10 keys */
    if (src.format == PGP_KEY_STORE_G10) {
        if (pubonly) {
            RNP_LOG("attempt to copy public part from g10 key");
            throw std::invalid_argument("pubonly");
        }
        if (pgp_key_get_rawpacket_count(&src) != 1) {
            RNP_LOG("wrong g10 key packets");
            throw std::invalid_argument("rawpacket_count");
        }
    }

    if (pubonly) {
        pkt = pgp_key_pkt_t(src.pkt, true);
        rawpkt = pgp_rawpacket_t(pkt);
    } else {
        pkt = src.pkt;
        rawpkt = src.rawpkt;
    }

    uids = src.uids;
    subsigs = src.subsigs;
    revokes = src.revokes;
    subkey_fps = src.subkey_fps;
    primary_fp_set = src.primary_fp_set;
    primary_fp = src.primary_fp;
    expiration = src.expiration;
    key_flags = src.key_flags;
    keyid = src.keyid;
    fingerprint = src.fingerprint;
    grip = src.grip;
    uid0 = src.uid0;
    uid0_set = src.uid0_set;
    revoked = src.revoked;
    revocation = src.revocation;
    format = src.format;
    valid = src.valid;
    validated = src.validated;
}

pgp_key_t &
pgp_key_t::operator=(pgp_key_t &&src)
{
    if (&src == this) {
        return *this;
    }
    uids = std::move(src.uids);
    subsigs = std::move(src.subsigs);
    pgp_key_clear_revokes(this);
    revokes = std::move(src.revokes);

    subkey_fps = std::move(src.subkey_fps);
    primary_fp = std::move(src.primary_fp);
    primary_fp_set = src.primary_fp_set;
    expiration = src.expiration;
    pkt = std::move(src.pkt);
    rawpkt = std::move(src.rawpkt);
    key_flags = src.key_flags;
    keyid = src.keyid;
    fingerprint = src.fingerprint;
    grip = std::move(src.grip);
    uid0 = src.uid0;
    uid0_set = src.uid0_set;
    revoked = src.revoked;
    revocation = src.revocation;
    src.revocation = {};
    format = src.format;
    valid = src.valid;
    validated = src.validated;

    return *this;
}
