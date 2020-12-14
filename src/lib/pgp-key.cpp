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
    if (key->pkt.version >= 4) {
        return key->expiration;
    }
    /* too large value for pkt.v3_days may overflow uint32_t */
    if (key->pkt.v3_days > (0xffffffffu / 86400)) {
        return 0xffffffffu;
    }
    return (uint32_t) key->pkt.v3_days * 86400;
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
    pgp_key_pkt_t *res = NULL;

    if (init_mem_src(&src, data, data_len, false)) {
        return NULL;
    }
    try {
        res = new pgp_key_pkt_t();
        if (res->parse(src)) {
            goto error;
        }
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
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

static bool
pgp_sig_is_certification(const pgp_subsig_t &sig)
{
    pgp_sig_type_t type = sig.sig.type();
    return (type == PGP_CERT_CASUAL) || (type == PGP_CERT_GENERIC) ||
           (type == PGP_CERT_PERSONA) || (type == PGP_CERT_POSITIVE);
}

static bool
pgp_sig_self_signed(const pgp_key_t &key, const pgp_subsig_t &sig)
{
    /* if we have fingerprint let's check it */
    if (sig.sig.has_keyfp()) {
        return sig.sig.keyfp() == pgp_key_get_fp(&key);
    }
    if (!sig.sig.has_keyid()) {
        return false;
    }
    return pgp_key_get_keyid(&key) == sig.sig.keyid();
}

static bool
pgp_sig_is_self_signature(const pgp_key_t &key, const pgp_subsig_t &sig)
{
    if (!pgp_key_is_primary_key(&key) || !pgp_sig_is_certification(sig)) {
        return false;
    }

    return pgp_sig_self_signed(key, sig);
}

static bool
pgp_sig_is_direct_self_signature(const pgp_key_t &key, const pgp_subsig_t &sig)
{
    if (!pgp_key_is_primary_key(&key) || (sig.sig.type() != PGP_SIG_DIRECT)) {
        return false;
    }

    return pgp_sig_self_signed(key, sig);
}

static bool
pgp_sig_is_key_revocation(const pgp_key_t &key, const pgp_subsig_t &sig)
{
    return pgp_key_is_primary_key(&key) && (sig.sig.type() == PGP_SIG_REV_KEY);
}

static bool
pgp_sig_is_userid_revocation(const pgp_key_t &key, const pgp_subsig_t &sig)
{
    return pgp_key_is_primary_key(&key) && (sig.sig.type() == PGP_SIG_REV_CERT);
}

static bool
pgp_sig_is_subkey_binding(const pgp_key_t &key, const pgp_subsig_t &sig)
{
    return pgp_key_is_subkey(&key) && (sig.sig.type() == PGP_SIG_SUBKEY);
}

static bool
pgp_sig_is_subkey_revocation(const pgp_key_t &key, const pgp_subsig_t &sig)
{
    return pgp_key_is_subkey(&key) && (sig.sig.type() == PGP_SIG_REV_SUBKEY);
}

pgp_subsig_t *
pgp_key_latest_selfsig(pgp_key_t *key, pgp_sig_subpacket_type_t subpkt)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    for (size_t i = 0; i < key->sig_count(); i++) {
        pgp_subsig_t &sig = key->get_sig(i);
        if (!sig.valid()) {
            continue;
        }
        if (!pgp_sig_is_self_signature(*key, sig) &&
            !pgp_sig_is_direct_self_signature(*key, sig)) {
            continue;
        }

        if (subpkt && !sig.sig.get_subpkt(subpkt)) {
            continue;
        }

        uint32_t creation = sig.sig.creation();
        if (creation >= latest) {
            latest = creation;
            res = &sig;
        }
    }
    return res;
}

static pgp_subsig_t *
pgp_key_latest_uid_selfcert(pgp_key_t &key, uint32_t uid)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    for (size_t i = 0; i < key.sig_count(); i++) {
        pgp_subsig_t &sig = key.get_sig(i);
        if (!sig.valid() || (sig.uid != uid)) {
            continue;
        }
        if (!pgp_sig_is_self_signature(key, sig)) {
            continue;
        }

        uint32_t creation = sig.sig.creation();
        if (creation >= latest) {
            latest = creation;
            res = &sig;
        }
    }
    return res;
}

pgp_subsig_t *
pgp_key_latest_binding(pgp_key_t *subkey, bool validated)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    for (size_t i = 0; i < subkey->sig_count(); i++) {
        pgp_subsig_t &sig = subkey->get_sig(i);
        if (validated && !sig.valid()) {
            continue;
        }
        if (!pgp_sig_is_subkey_binding(*subkey, sig)) {
            continue;
        }

        uint32_t creation = sig.sig.creation();
        if (creation >= latest) {
            latest = creation;
            res = &sig;
        }
    }
    return res;
}

pgp_key_t *
pgp_sig_get_signer(const pgp_subsig_t &sig, rnp_key_store_t *keyring, pgp_key_provider_t *prov)
{
    pgp_key_request_ctx_t ctx = {};
    /* if we have fingerprint let's check it */
    if (sig.sig.has_keyfp()) {
        ctx.search.by.fingerprint = sig.sig.keyfp();
        ctx.search.type = PGP_KEY_SEARCH_FINGERPRINT;
    }
    if ((ctx.search.type == PGP_KEY_SEARCH_UNKNOWN) && sig.sig.has_keyid()) {
        ctx.search.by.keyid = sig.sig.keyid();
        ctx.search.type = PGP_KEY_SEARCH_KEYID;
    }
    if (ctx.search.type == PGP_KEY_SEARCH_UNKNOWN) {
        RNP_LOG("No way to search for the signer.");
        return NULL;
    }

    pgp_key_t *key = rnp_key_store_search(keyring, &ctx.search, NULL);
    if (key || !prov) {
        return key;
    }

    ctx.op = PGP_OP_VERIFY;
    ctx.secret = false;
    return pgp_request_key(prov, &ctx);
}

void
pgp_key_validate_signature(pgp_key_t &   key,
                           pgp_key_t &   signer,
                           pgp_key_t *   primary,
                           pgp_subsig_t &sig)
{
    sig.validity.validated = false;
    sig.validity.sigvalid = false;
    sig.validity.expired = false;

    pgp_signature_info_t sinfo = {};
    sinfo.sig = &sig.sig;
    sinfo.signer = &signer;
    sinfo.signer_valid = true;
    if (pgp_sig_is_self_signature(key, sig) || pgp_sig_is_subkey_binding(key, sig)) {
        sinfo.ignore_expiry = true;
    }

    pgp_sig_type_t stype = sig.sig.type();
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
    case PGP_SIG_REV_CERT: {
        if (sig.uid >= key.uid_count()) {
            RNP_LOG("Userid not found");
            return;
        }
        signature_check_certification(
          &sinfo, pgp_key_get_pkt(&key), &key.get_uid(sig.uid).pkt);
        break;
    }
    case PGP_SIG_SUBKEY:
        if (!primary) {
            RNP_LOG("No primary key specified");
            return;
        }
        signature_check_binding(&sinfo, pgp_key_get_pkt(primary), &key);
        break;
    case PGP_SIG_DIRECT:
    case PGP_SIG_REV_KEY:
        signature_check_direct(&sinfo, pgp_key_get_pkt(&key));
        break;
    case PGP_SIG_REV_SUBKEY:
        if (!primary) {
            RNP_LOG("No primary key specified");
            return;
        }
        signature_check_subkey_revocation(
          &sinfo, pgp_key_get_pkt(primary), pgp_key_get_pkt(&key));
        break;
    default:
        RNP_LOG("Unsupported key signature type: %d", (int) stype);
        return;
    }

    sig.validity.validated = true;
    sig.validity.sigvalid = sinfo.valid;
    /* revocation signature cannot expire */
    if ((stype != PGP_SIG_REV_KEY) && (stype != PGP_SIG_REV_SUBKEY) &&
        (stype != PGP_SIG_REV_CERT)) {
        sig.validity.expired = sinfo.expired;
    }
}

static void
pgp_key_validate_self_signatures(pgp_key_t &key)
{
    for (size_t i = 0; i < key.sig_count(); i++) {
        pgp_subsig_t &sig = key.get_sig(i);
        if (sig.validity.validated) {
            continue;
        }

        if (pgp_sig_is_self_signature(key, sig) || pgp_sig_is_userid_revocation(key, sig) ||
            pgp_sig_is_key_revocation(key, sig)) {
            pgp_key_validate_signature(key, key, NULL, sig);
        }
    }
}

static void
pgp_subkey_validate_self_signatures(pgp_key_t &sub, pgp_key_t &key)
{
    for (size_t i = 0; i < sub.sig_count(); i++) {
        pgp_subsig_t &sig = sub.get_sig(i);
        if (sig.validity.validated) {
            continue;
        }

        if (pgp_sig_is_subkey_binding(sub, sig) || pgp_sig_is_subkey_revocation(sub, sig)) {
            pgp_key_validate_signature(sub, key, &key, sig);
        }
    }
}

static bool
is_key_expired(const pgp_key_t &key, const pgp_subsig_t &sig)
{
    /* key expiration: absense of subpkt or 0 means it never expires */
    uint32_t expiration = sig.sig.key_expiration();
    if (!expiration) {
        return false;
    }
    return pgp_key_get_creation(&key) + expiration < time(NULL);
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
        pgp_subkey_validate_self_signatures(*sub, *key);
    }
    pgp_subsig_t *sig = pgp_key_latest_binding(sub, key);
    /* subkey expiration */
    sub->expiration = sig ? sig->sig.key_expiration() : 0;
    /* subkey flags */
    if (sig && sig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        sub->key_flags = sig->key_flags;
    } else {
        sub->key_flags = pgp_pk_alg_capabilities(pgp_key_get_alg(sub));
    }
    /* revocation */
    sub->clear_revokes();
    for (size_t i = 0; i < sub->sig_count(); i++) {
        pgp_subsig_t &sig = sub->get_sig(i);
        if (!sig.valid() || !pgp_sig_is_subkey_revocation(*sub, sig)) {
            continue;
        }
        sub->revoked = true;
        try {
            sub->revocation = pgp_revoke_t(sig);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
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
    pgp_key_validate_self_signatures(*key);
    /* key expiration */
    pgp_subsig_t *sig = pgp_key_latest_selfsig(key, PGP_SIG_SUBPKT_UNKNOWN);
    key->expiration = sig ? sig->sig.key_expiration() : 0;
    /* key flags */
    if (sig && sig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        key->key_flags = sig->key_flags;
    } else {
        key->key_flags = pgp_pk_alg_capabilities(pgp_key_get_alg(key));
    }
    /* revocation(s) */
    key->clear_revokes();
    for (size_t i = 0; i < key->sig_count(); i++) {
        pgp_subsig_t &sig = key->get_sig(i);
        if (!sig.valid()) {
            continue;
        }
        try {
            if (pgp_sig_is_key_revocation(*key, sig)) {
                if (key->revoked) {
                    continue;
                }
                key->revoked = true;
                key->revocation = pgp_revoke_t(sig);
            } else if (pgp_sig_is_userid_revocation(*key, sig)) {
                if (sig.uid >= key->uid_count()) {
                    RNP_LOG("Invalid uid index");
                    continue;
                }
                pgp_userid_t &uid = key->get_uid(sig.uid);
                if (uid.revoked) {
                    continue;
                }
                uid.revoked = true;
                uid.revocation = pgp_revoke_t(sig);
            }
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
    }
    /* userid validities */
    for (size_t i = 0; i < key->uid_count(); i++) {
        key->get_uid(i).valid = false;
    }
    for (size_t i = 0; i < key->sig_count(); i++) {
        pgp_subsig_t &sig = key->get_sig(i);
        /* if certification expires key then consider userid as expired too */
        if (!sig.valid() || !pgp_sig_is_certification(sig) ||
            !pgp_sig_self_signed(*key, sig) || is_key_expired(*key, sig)) {
            continue;
        }
        if (sig.uid >= key->uid_count()) {
            continue;
        }
        key->get_uid(sig.uid).valid = true;
    }
    /* check whether uid is revoked */
    for (size_t i = 0; i < key->uid_count(); i++) {
        pgp_userid_t &uid = key->get_uid(i);
        if (uid.revoked) {
            uid.valid = false;
        }
    }
    /* primary userid: pick it only from valid ones */
    key->uid0_set = false;
    for (size_t i = 0; i < key->sig_count(); i++) {
        pgp_subsig_t &sig = key->get_sig(i);
        if (!sig.valid() || !pgp_sig_is_certification(sig) ||
            !pgp_sig_self_signed(*key, sig)) {
            continue;
        }
        if ((sig.uid >= key->uid_count()) || !key->get_uid(sig.uid).valid) {
            continue;
        }
        if (sig.sig.primary_uid()) {
            key->uid0 = sig.uid;
            key->uid0_set = true;
            break;
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
    return 1 + key->uid_count() + key->sig_count();
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
    try {
        seckey->write(*dst);
        res = !dst->werr;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
    }
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
    if (key->has_uid((const char *) cert->userid)) {
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
    try {
        key->add_uid(uid);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }

    return pgp_key_refresh_data(key);
}

static bool
update_sig_expiration(pgp_signature_t *dst, const pgp_signature_t *src, uint32_t expiry)
{
    try {
        *dst = *src;
        if (!expiry) {
            dst->remove_subpkt(dst->get_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY));
        } else {
            dst->set_key_expiration(expiry);
        }
        dst->set_creation(time(NULL));
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
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
    if (!expiry && !subsig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY)) {
        return true;
    }

    bool locked = pgp_key_is_locked(seckey);
    if (locked && !pgp_key_unlock(seckey, prov)) {
        RNP_LOG("Failed to unlock secret key");
        return false;
    }
    pgp_signature_t newsig;
    pgp_sig_id_t    oldsigid = subsig->sigid;
    bool            res = false;
    if (!update_sig_expiration(&newsig, &subsig->sig, expiry)) {
        goto done;
    }
    if (pgp_sig_is_certification(*subsig)) {
        if (subsig->uid >= key->uid_count()) {
            RNP_LOG("uid not found");
            goto done;
        }
        if (!signature_calculate_certification(pgp_key_get_pkt(key),
                                               &key->get_uid(subsig->uid).pkt,
                                               &newsig,
                                               pgp_key_get_pkt(seckey))) {
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
    if (seckey->has_sig(oldsigid)) {
        try {
            seckey->replace_sig(oldsigid, newsig);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            goto done;
        }
        if (!pgp_key_refresh_data(seckey)) {
            goto done;
        }
    }
    if (key == seckey) {
        res = true;
        goto done;
    }
    try {
        key->replace_sig(oldsigid, newsig);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        goto done;
    }
    res = pgp_key_refresh_data(key);
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
    if (!expiry && !subsig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY)) {
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
    pgp_sig_id_t    oldsigid = subsig->sigid;
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
    if (secsub->has_sig(oldsigid)) {
        try {
            secsub->replace_sig(oldsigid, newsig);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            goto done;
        }
        if (!pgp_subkey_refresh_data(secsub, primsec)) {
            goto done;
        }
    }
    if (sub == secsub) {
        res = true;
        goto done;
    }
    try {
        sub->replace_sig(oldsigid, newsig);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        goto done;
    }
    res = pgp_subkey_refresh_data(sub, primsec);
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
    for (size_t i = start; i < key->sig_count(); i++) {
        const pgp_subsig_t *sig = &key->get_sig(i);
        if (sig->uid != uid) {
            return i;
        }
        dst_write(dst, sig->rawpkt.raw.data(), sig->rawpkt.raw.size());
    }
    return key->sig_count();
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
    size_t idx = pgp_key_write_signatures(dst, key, PGP_UID_NONE, 0);

    /* write uids and their signatures */
    for (size_t i = 0; i < key->uid_count(); i++) {
        const pgp_userid_t &uid = key->get_uid(i);
        dst_write(dst, uid.rawpkt.raw.data(), uid.rawpkt.raw.size());
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
    pgp_subsig_t *cert = pgp_key_latest_uid_selfcert(key, uid);
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
            pkt.write(memdst);
        } else {
            key.pkt.write(memdst);
        }
        key.get_uid(uid).pkt.write(memdst);
        cert->sig.write(memdst);
        if (pgp_key_is_secret(&sub)) {
            pgp_key_pkt_t pkt(sub.pkt, true);
            pkt.write(memdst);
        } else {
            sub.pkt.write(memdst);
        }
        binding->sig.write(memdst);
        dst_write(&dst, mem_dest_get_memory(&memdst), memdst.writeb);
        res = !dst.werr;
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

    pgp_key_t *subkey = NULL;
    for (auto &fp : key->subkey_fps) {
        ctx.search.by.fingerprint = fp;
        pgp_key_t *cur = pgp_request_key(key_provider, &ctx);
        if (!cur || !(pgp_key_get_flags(cur) & desired_usage) || !cur->valid) {
            continue;
        }
        if (!subkey || (pgp_key_get_creation(cur) > pgp_key_get_creation(subkey))) {
            subkey = cur;
        }
    }
    return subkey;
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
pgp_key_validate_primary(pgp_key_t &key, rnp_key_store_t *keyring)
{
    /* validate signatures if needed */
    pgp_key_validate_self_signatures(key);

    /* consider public key as valid on this level if it has at least one non-expired
     * self-signature (or it is secret), and is not revoked */
    key.valid = false;
    key.validated = true;
    bool has_cert = false;
    bool has_expired = false;
    for (size_t i = 0; i < key.sig_count(); i++) {
        pgp_subsig_t &sig = key.get_sig(i);
        if (!sig.valid()) {
            continue;
        }

        if (pgp_sig_is_self_signature(key, sig) && !has_cert) {
            if (!is_key_expired(key, sig)) {
                has_cert = true;
                continue;
            }
            has_expired = true;
        } else if (pgp_sig_is_key_revocation(key, sig)) {
            return;
        }
    }
    /* we have at least one non-expiring key self-signature or secret key */
    if (has_cert || pgp_key_is_secret(&key)) {
        key.valid = true;
        return;
    }
    /* we have valid self-signature which expires key */
    if (has_expired) {
        return;
    }

    /* let's check whether key has at least one valid subkey binding */
    for (size_t i = 0; i < pgp_key_get_subkey_count(&key); i++) {
        pgp_key_t *sub = pgp_key_get_subkey(&key, keyring, i);
        if (!sub) {
            continue;
        }
        pgp_subkey_validate_self_signatures(*sub, key);
        pgp_subsig_t *sig = pgp_key_latest_binding(sub, true);
        if (!sig) {
            continue;
        }
        /* check whether subkey is expired - then do not mark key as valid */
        if (is_key_expired(*sub, *sig)) {
            continue;
        }
        key.valid = true;
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
    pgp_subkey_validate_self_signatures(*subkey, *key);

    bool has_binding = false;
    for (size_t i = 0; i < subkey->sig_count(); i++) {
        pgp_subsig_t &sig = subkey->get_sig(i);
        if (!sig.valid()) {
            continue;
        }

        if (pgp_sig_is_subkey_binding(*subkey, sig) && !has_binding) {
            /* check whether subkey is expired */
            if (is_key_expired(*subkey, sig)) {
                continue;
            }
            has_binding = true;
        } else if (pgp_sig_is_subkey_revocation(*subkey, sig)) {
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
        pgp_key_validate_primary(*key, keyring);
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
            if (!pgp_subkey_refresh_data(subkey, key)) {
                RNP_LOG("Failed to refresh subkey data");
            }
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

static void
bytevec_append_uniq(std::vector<uint8_t> &vec, uint8_t val)
{
    if (std::find(vec.begin(), vec.end(), val) == vec.end()) {
        vec.push_back(val);
    }
}

void
pgp_user_prefs_t::set_symm_algs(const std::vector<uint8_t> &algs)
{
    symm_algs = algs;
}

void
pgp_user_prefs_t::add_symm_alg(pgp_symm_alg_t alg)
{
    bytevec_append_uniq(symm_algs, alg);
}

void
pgp_user_prefs_t::set_hash_algs(const std::vector<uint8_t> &algs)
{
    hash_algs = algs;
}

void
pgp_user_prefs_t::add_hash_alg(pgp_hash_alg_t alg)
{
    bytevec_append_uniq(hash_algs, alg);
}

void
pgp_user_prefs_t::set_z_algs(const std::vector<uint8_t> &algs)
{
    z_algs = algs;
}

void
pgp_user_prefs_t::add_z_alg(pgp_compression_type_t alg)
{
    bytevec_append_uniq(z_algs, alg);
}

void
pgp_user_prefs_t::set_ks_prefs(const std::vector<uint8_t> &prefs)
{
    ks_prefs = prefs;
}

void
pgp_user_prefs_t::add_ks_pref(pgp_key_server_prefs_t pref)
{
    bytevec_append_uniq(ks_prefs, pref);
}

pgp_rawpacket_t::pgp_rawpacket_t(const pgp_signature_t &sig)
{
    pgp_dest_t dst = {};

    if (init_mem_dest(&dst, NULL, 0)) {
        throw std::bad_alloc();
    }

    try {
        sig.write(dst);
    } catch (const std::exception &e) {
        dst_close(&dst, true);
        throw;
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
    try {
        key.write(dst);
    } catch (const std::exception &e) {
        dst_close(&dst, true);
        throw;
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
    try {
        uid.write(dst);
    } catch (const std::exception &e) {
        dst_close(&dst, true);
        throw;
    }
    mem_dest_to_vector(&dst, raw);
    tag = uid.tag;
}

pgp_subsig_t::pgp_subsig_t(const pgp_signature_t &pkt)
{
    sig = pkt;
    sigid = sig.get_id();
    if (sig.has_subpkt(PGP_SIG_SUBPKT_TRUST)) {
        trustlevel = sig.trust_level();
        trustamount = sig.trust_amount();
    }
    prefs.set_symm_algs(sig.preferred_symm_algs());
    prefs.set_hash_algs(sig.preferred_hash_algs());
    prefs.set_z_algs(sig.preferred_z_algs());

    if (sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        key_flags = sig.key_flags();
    }
    if (sig.has_subpkt(PGP_SIG_SUBPKT_KEYSERV_PREFS)) {
        prefs.set_ks_prefs({sig.key_server_prefs()});
    }
    if (sig.has_subpkt(PGP_SIG_SUBPKT_PREF_KEYSERV)) {
        prefs.key_server = sig.key_server();
    }
    /* add signature rawpacket */
    rawpkt = pgp_rawpacket_t(sig);
}

bool
pgp_subsig_t::valid() const
{
    return validity.validated && validity.sigvalid && !validity.expired;
}

pgp_userid_t::pgp_userid_t(const pgp_userid_pkt_t &uidpkt)
{
    /* copy packet data */
    pkt = uidpkt;
    rawpkt = pgp_rawpacket_t(uidpkt);
    /* populate uid string */
    if (uidpkt.tag == PGP_PKT_USER_ID) {
        str = std::string(uidpkt.uid, uidpkt.uid + uidpkt.uid_len);
    } else {
        str = "(photo)";
    }
}

size_t
pgp_userid_t::sig_count() const
{
    return sigs_.size();
}

const pgp_sig_id_t &
pgp_userid_t::get_sig(size_t idx) const
{
    if (idx >= sigs_.size()) {
        throw std::out_of_range("idx");
    }
    return sigs_[idx];
}

bool
pgp_userid_t::has_sig(const pgp_sig_id_t &id) const
{
    return std::find(sigs_.begin(), sigs_.end(), id) != sigs_.end();
}

void
pgp_userid_t::add_sig(const pgp_sig_id_t &sig)
{
    sigs_.push_back(sig);
}

void
pgp_userid_t::replace_sig(const pgp_sig_id_t &id, const pgp_sig_id_t &newsig)
{
    auto it = std::find(sigs_.begin(), sigs_.end(), id);
    if (it == sigs_.end()) {
        throw std::invalid_argument("id");
    }
    *it = newsig;
}

pgp_revoke_t::pgp_revoke_t(pgp_subsig_t &sig)
{
    uid = sig.uid;
    sigid = sig.sigid;
    if (!sig.sig.has_subpkt(PGP_SIG_SUBPKT_REVOCATION_REASON)) {
        RNP_LOG("Warning: no revocation reason in the revocation");
        code = PGP_REVOCATION_NO_REASON;
    } else {
        code = sig.sig.revocation_code();
        reason = sig.sig.revocation_reason();
    }
    if (reason.empty()) {
        reason = pgp_str_from_map(code, ss_rr_code_map);
    }
}

pgp_key_t::pgp_key_t(const pgp_key_pkt_t &keypkt)
{
    if (!is_key_pkt(keypkt.tag) || !keypkt.material.alg) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    pkt = keypkt;
    if (pgp_keyid(keyid, pkt) || pgp_fingerprint(fingerprint, pkt) ||
        !rnp_key_store_get_key_grip(&pkt.material, grip)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }

    /* parse secret key if not encrypted */
    if (is_secret_key_pkt(pkt.tag)) {
        bool cleartext = keypkt.sec_protection.s2k.usage == PGP_S2KU_NONE;
        if (cleartext && decrypt_secret_key(&pkt, NULL)) {
            RNP_LOG("failed to setup key fields");
            throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
        }
    }
    /* add rawpacket */
    rawpkt = pgp_rawpacket_t(pkt);
    format = PGP_KEY_STORE_GPG;
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

    uids_ = src.uids_;
    sigs_ = src.sigs_;
    sigs_map_ = src.sigs_map_;
    keysigs_ = src.keysigs_;
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

pgp_key_t::pgp_key_t(const pgp_transferable_key_t &src) : pgp_key_t(src.key)
{
    /* add direct-key signatures */
    for (auto &sig : src.signatures) {
        add_sig(sig);
    }

    /* add userids and their signatures */
    for (auto &uid : src.userids) {
        add_uid(uid);
    }
}

pgp_key_t::pgp_key_t(const pgp_transferable_subkey_t &src, pgp_key_t *primary)
    : pgp_key_t(src.subkey)
{
    /* add subkey binding signatures */
    for (auto &sig : src.signatures) {
        add_sig(sig);
    }

    /* setup key grips if primary is available */
    if (primary && !pgp_key_link_subkey_fp(primary, this)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
}

size_t
pgp_key_t::sig_count() const
{
    return sigs_.size();
}

pgp_subsig_t &
pgp_key_t::get_sig(size_t idx)
{
    if (idx >= sigs_.size()) {
        throw std::out_of_range("idx");
    }
    return get_sig(sigs_[idx]);
}

const pgp_subsig_t &
pgp_key_t::get_sig(size_t idx) const
{
    if (idx >= sigs_.size()) {
        throw std::out_of_range("idx");
    }
    return get_sig(sigs_[idx]);
}

bool
pgp_key_t::has_sig(const pgp_sig_id_t &id) const
{
    return sigs_map_.count(id);
}

pgp_subsig_t &
pgp_key_t::get_sig(const pgp_sig_id_t &id)
{
    if (!has_sig(id)) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return sigs_map_.at(id);
}

const pgp_subsig_t &
pgp_key_t::get_sig(const pgp_sig_id_t &id) const
{
    if (!has_sig(id)) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return sigs_map_.at(id);
}

pgp_subsig_t &
pgp_key_t::replace_sig(const pgp_sig_id_t &id, const pgp_signature_t &newsig)
{
    /* save oldsig's uid */
    size_t uid = get_sig(id).uid;
    /* delete first old sig since we may have theoretically the same sigid */
    pgp_sig_id_t oldid = id;
    sigs_map_.erase(oldid);
    auto &res = sigs_map_.emplace(std::make_pair(newsig.get_id(), newsig)).first->second;
    res.uid = uid;
    auto it = std::find(sigs_.begin(), sigs_.end(), oldid);
    *it = res.sigid;
    if (uid == PGP_UID_NONE) {
        auto it = std::find(keysigs_.begin(), keysigs_.end(), oldid);
        *it = res.sigid;
    } else {
        uids_[uid].replace_sig(oldid, res.sigid);
    }
    return res;
}

pgp_subsig_t &
pgp_key_t::add_sig(const pgp_signature_t &sig, size_t uid)
{
    const pgp_sig_id_t sigid = sig.get_id();
    sigs_map_.erase(sigid);
    pgp_subsig_t &res = sigs_map_.emplace(std::make_pair(sigid, sig)).first->second;
    res.uid = uid;
    sigs_.push_back(sigid);
    if (uid == PGP_UID_NONE) {
        keysigs_.push_back(sigid);
    } else {
        uids_[uid].add_sig(sigid);
    }
    return res;
}

size_t
pgp_key_t::keysig_count() const
{
    return keysigs_.size();
}

pgp_subsig_t &
pgp_key_t::get_keysig(size_t idx)
{
    if (idx >= keysigs_.size()) {
        throw std::out_of_range("idx");
    }
    return get_sig(keysigs_[idx]);
}

size_t
pgp_key_t::uid_count() const
{
    return uids_.size();
}

pgp_userid_t &
pgp_key_t::get_uid(size_t idx)
{
    if (idx >= uids_.size()) {
        throw std::out_of_range("idx");
    }
    return uids_[idx];
}

const pgp_userid_t &
pgp_key_t::get_uid(size_t idx) const
{
    if (idx >= uids_.size()) {
        throw std::out_of_range("idx");
    }
    return uids_[idx];
}

bool
pgp_key_t::has_uid(const std::string &uidstr) const
{
    for (auto &userid : uids_) {
        if (!userid.valid) {
            continue;
        }
        if (userid.str == uidstr) {
            return true;
        }
    }
    return false;
}

pgp_userid_t &
pgp_key_t::add_uid(const pgp_transferable_userid_t &uid)
{
    /* construct userid */
    uids_.emplace_back(uid.uid);
    /* add certifications */
    for (auto &sig : uid.signatures) {
        add_sig(sig, uid_count() - 1);
    }
    return uids_.back();
}

void
pgp_key_t::clear_revokes()
{
    revoked = false;
    revocation = {};
    for (auto &uid : uids_) {
        uid.revoked = false;
        uid.revocation = {};
    }
}
