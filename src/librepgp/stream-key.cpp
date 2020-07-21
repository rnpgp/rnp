/*
 * Copyright (c) 2018-2020, [Ribose Inc](https://www.ribose.com).
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

#include "config.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include "stream-def.h"
#include "stream-key.h"
#include "stream-armor.h"
#include "stream-packet.h"
#include "stream-sig.h"
#include "types.h"
#include "fingerprint.h"
#include "pgp-key.h"
#include "list.h"
#include "crypto.h"
#include "crypto/signatures.h"
#include "../librekey/key_store_pgp.h"
#include <set>

static bool
copy_signatures(list *dst, const list *src)
{
    for (list_item *sig = list_front(*src); sig; sig = list_next(sig)) {
        pgp_signature_t *newsig = (pgp_signature_t *) list_append(dst, NULL, sizeof(*newsig));
        if (!newsig) {
            signature_list_destroy(dst);
            return false;
        }
        try {
            *newsig = *((pgp_signature_t *) sig);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
    }
    return true;
}

static bool
list_has_signature(const list *lst, const pgp_signature_t *sig)
{
    for (list_item *lsig = list_front(*lst); lsig; lsig = list_next(lsig)) {
        if (signature_pkt_equal((pgp_signature_t *) lsig, sig)) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Add signatures from src to list dst, skipping the duplicates.
 *
 * @param dst List which will contain all distinct signatures from src and dst
 * @param src List to merge signatures from
 * @return true on success or false otherwise. On failure dst may have some sigs appended.
 */
static rnp_result_t
merge_signatures(list *dst, const list *src)
{
    for (list_item *sig = list_front(*src); sig; sig = list_next(sig)) {
        if (list_has_signature(dst, (pgp_signature_t *) sig)) {
            continue;
        }
        pgp_signature_t *newsig = (pgp_signature_t *) list_append(dst, NULL, sizeof(*newsig));
        if (!newsig) {
            return RNP_ERROR_OUT_OF_MEMORY;
        }
        try {
            *newsig = *((pgp_signature_t *) sig);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            list_remove((list_item *) newsig);
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    return RNP_SUCCESS;
}

static rnp_result_t
transferable_userid_merge(pgp_transferable_userid_t *dst, const pgp_transferable_userid_t *src)
{
    if (!userid_pkt_equal(&dst->uid, &src->uid)) {
        RNP_LOG("wrong userid merge attempt");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    return merge_signatures(&dst->signatures, &src->signatures);
}

bool
transferable_subkey_copy(pgp_transferable_subkey_t *      dst,
                         const pgp_transferable_subkey_t *src,
                         bool                             pubonly)
{
    if (!copy_key_pkt(&dst->subkey, &src->subkey, pubonly)) {
        RNP_LOG("failed to copy subkey pkt");
        return false;
    }

    if (!copy_signatures(&dst->signatures, &src->signatures)) {
        RNP_LOG("failed to copy subkey signatures");
        return false;
    }
    return true;
}

rnp_result_t
transferable_subkey_from_key(pgp_transferable_subkey_t *dst, const pgp_key_t *key)
{
    pgp_source_t memsrc = {};
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (!rnp_key_to_src(key, &memsrc)) {
        return RNP_ERROR_BAD_STATE;
    }

    ret = process_pgp_subkey(memsrc, *dst, false);
    src_close(&memsrc);
    return ret;
}

rnp_result_t
transferable_subkey_merge(pgp_transferable_subkey_t *dst, const pgp_transferable_subkey_t *src)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (!key_pkt_equal(&dst->subkey, &src->subkey, true)) {
        RNP_LOG("wrong subkey merge call");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if ((ret = merge_signatures(&dst->signatures, &src->signatures))) {
        RNP_LOG("failed to merge signatures");
    }
    return ret;
}

bool
transferable_key_copy(pgp_transferable_key_t *      dst,
                      const pgp_transferable_key_t *src,
                      bool                          pubonly)
{
    if (!copy_key_pkt(&dst->key, &src->key, pubonly)) {
        RNP_LOG("failed to copy key pkt");
        return false;
    }

    try {
        dst->userids = src->userids;
        dst->subkeys = src->subkeys;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }

    if (!copy_signatures(&dst->signatures, &src->signatures)) {
        RNP_LOG("failed to copy key signatures");
        return false;
    }
    return true;
}

rnp_result_t
transferable_key_from_key(pgp_transferable_key_t *dst, const pgp_key_t *key)
{
    pgp_source_t memsrc = {};
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (!rnp_key_to_src(key, &memsrc)) {
        return RNP_ERROR_BAD_STATE;
    }

    ret = process_pgp_key(&memsrc, *dst, false);
    src_close(&memsrc);
    return ret;
}

static pgp_transferable_userid_t *
transferable_key_has_userid(pgp_transferable_key_t *src, const pgp_userid_pkt_t *userid)
{
    for (auto &uid : src->userids) {
        if (userid_pkt_equal(&uid.uid, userid)) {
            return &uid;
        }
    }
    return NULL;
}

static pgp_transferable_subkey_t *
transferable_key_has_subkey(pgp_transferable_key_t &src, const pgp_key_pkt_t &subkey)
{
    for (auto &srcsub : src.subkeys) {
        if (key_pkt_equal(&srcsub.subkey, &subkey, true)) {
            return &srcsub;
        }
    }
    return NULL;
}

rnp_result_t
transferable_key_merge(pgp_transferable_key_t *dst, const pgp_transferable_key_t *src)
{
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (!key_pkt_equal(&dst->key, &src->key, true)) {
        RNP_LOG("wrong key merge call");
        return RNP_ERROR_BAD_PARAMETERS;
    }
    /* direct-key signatures */
    if ((ret = merge_signatures(&dst->signatures, &src->signatures))) {
        RNP_LOG("failed to merge signatures");
        return ret;
    }
    /* userids */
    for (auto &srcuid : src->userids) {
        pgp_transferable_userid_t *dstuid = transferable_key_has_userid(dst, &srcuid.uid);
        if (dstuid) {
            if ((ret = transferable_userid_merge(dstuid, &srcuid))) {
                RNP_LOG("failed to merge userid");
                return ret;
            }
            continue;
        }
        /* add userid */
        try {
            dst->userids.emplace_back(srcuid);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }

    /* subkeys */
    for (auto &srcsub : src->subkeys) {
        pgp_transferable_subkey_t *dstsub = transferable_key_has_subkey(*dst, srcsub.subkey);
        if (dstsub) {
            if ((ret = transferable_subkey_merge(dstsub, &srcsub))) {
                RNP_LOG("failed to merge subkey");
                return ret;
            }
            continue;
        }
        /* add subkey */
        if (is_public_key_pkt(dst->key.tag) != is_public_key_pkt(srcsub.subkey.tag)) {
            RNP_LOG("warning: adding public/secret subkey to secret/public key");
        }
        try {
            dst->subkeys.emplace_back(srcsub);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return RNP_ERROR_OUT_OF_MEMORY;
        }
    }
    return RNP_SUCCESS;
}

pgp_transferable_userid_t *
transferable_key_add_userid(pgp_transferable_key_t *key, const char *userid)
{
    try {
        key->userids.emplace_back();
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }

    pgp_transferable_userid_t &uid = key->userids.back();
    uid.uid.tag = PGP_PKT_USER_ID;
    uid.uid.uid_len = strlen(userid);
    if (!(uid.uid.uid = (uint8_t *) malloc(uid.uid.uid_len))) {
        key->userids.pop_back();
        return NULL;
    }
    memcpy(uid.uid.uid, userid, uid.uid.uid_len);
    return &uid;
}

bool
signature_calculate_certification(const pgp_key_pkt_t *   key,
                                  const pgp_userid_pkt_t *uid,
                                  pgp_signature_t *       sig,
                                  const pgp_key_pkt_t *   signer)
{
    if (!key || !uid || !sig || !signer) {
        RNP_LOG("NULL parameter(s)");
        return false;
    }

    rng_t rng = {};
    if (!rng_init(&rng, RNG_SYSTEM)) {
        RNP_LOG("RNG init failed");
        return false;
    }

    pgp_hash_t hash = {};
    bool       res = signature_fill_hashed_data(sig) &&
               signature_hash_certification(sig, key, uid, &hash) &&
               !signature_calculate(sig, &signer->material, &hash, &rng);
    rng_destroy(&rng);
    return res;
}

bool
signature_calculate_direct(const pgp_key_pkt_t *key,
                           pgp_signature_t *    sig,
                           const pgp_key_pkt_t *signer)
{
    if (!key || !sig || !signer) {
        RNP_LOG("NULL parameter(s)");
        return false;
    }

    rng_t rng = {};
    if (!rng_init(&rng, RNG_SYSTEM)) {
        RNP_LOG("RNG init failed");
        return false;
    }

    pgp_hash_t hash = {};
    bool res = signature_fill_hashed_data(sig) && signature_hash_direct(sig, key, &hash) &&
               !signature_calculate(sig, &signer->material, &hash, &rng);
    rng_destroy(&rng);
    return res;
}

pgp_signature_t *
transferable_userid_certify(const pgp_key_pkt_t *          key,
                            pgp_transferable_userid_t *    userid,
                            const pgp_key_pkt_t *          signer,
                            pgp_hash_alg_t                 hash_alg,
                            const rnp_selfsig_cert_info_t *cert)
{
    pgp_signature_t   sig = {};
    pgp_key_id_t      keyid = {};
    pgp_fingerprint_t keyfp;

    if (!key || !userid || !signer || !cert) {
        RNP_LOG("invalid parameters");
        return NULL;
    }

    if (pgp_keyid(keyid, signer)) {
        RNP_LOG("failed to calculate keyid");
        return NULL;
    }

    if (pgp_fingerprint(keyfp, signer)) {
        RNP_LOG("failed to calculate keyfp");
        return NULL;
    }

    sig.version = PGP_V4;
    sig.halg = pgp_hash_adjust_alg_to_key(hash_alg, signer);
    sig.palg = signer->alg;
    sig.type = PGP_CERT_POSITIVE;

    if (!signature_set_keyfp(&sig, keyfp)) {
        RNP_LOG("failed to set issuer fingerprint");
        return NULL;
    }
    if (!signature_set_creation(&sig, time(NULL))) {
        RNP_LOG("failed to set creation time");
        return NULL;
    }
    if (cert->key_expiration && !signature_set_key_expiration(&sig, cert->key_expiration)) {
        RNP_LOG("failed to set key expiration time");
        return NULL;
    }
    if (cert->key_flags && !signature_set_key_flags(&sig, cert->key_flags)) {
        RNP_LOG("failed to set key flags");
        return NULL;
    }
    if (cert->primary && !signature_set_primary_uid(&sig, true)) {
        RNP_LOG("failed to set primary userid");
        return NULL;
    }
    const pgp_user_prefs_t *prefs = &cert->prefs;
    if (prefs->symm_alg_count &&
        !signature_set_preferred_symm_algs(
          &sig, (uint8_t *) prefs->symm_algs, prefs->symm_alg_count)) {
        RNP_LOG("failed to set symm alg prefs");
        return NULL;
    }
    if (prefs->hash_alg_count &&
        !signature_set_preferred_hash_algs(
          &sig, (uint8_t *) prefs->hash_algs, prefs->hash_alg_count)) {
        RNP_LOG("failed to set hash alg prefs");
        return NULL;
    }
    if (prefs->z_alg_count &&
        !signature_set_preferred_z_algs(&sig, (uint8_t *) prefs->z_algs, prefs->z_alg_count)) {
        RNP_LOG("failed to set compress alg prefs");
        return NULL;
    }
    if (prefs->ks_pref_count &&
        !signature_set_key_server_prefs(&sig, (uint8_t) prefs->ks_prefs[0])) {
        RNP_LOG("failed to set key server prefs");
        return NULL;
    }
    if (prefs->key_server &&
        !signature_set_preferred_key_server(&sig, (char *) prefs->key_server)) {
        RNP_LOG("failed to set preferred key server");
        return NULL;
    }
    if (!signature_set_keyid(&sig, keyid)) {
        RNP_LOG("failed to set issuer key id");
        return NULL;
    }

    if (!signature_calculate_certification(key, &userid->uid, &sig, signer)) {
        RNP_LOG("failed to calculate signature");
        return NULL;
    }
    pgp_signature_t *res =
      (pgp_signature_t *) list_append(&userid->signatures, NULL, sizeof(sig));
    *res = std::move(sig);
    return res;
}

static bool
signature_calculate_primary_binding(const pgp_key_pkt_t *key,
                                    const pgp_key_pkt_t *subkey,
                                    pgp_hash_alg_t       halg,
                                    pgp_signature_t *    sig,
                                    pgp_hash_t *         hash,
                                    rng_t *              rng)
{
    pgp_key_id_t keyid = {};

    sig->version = PGP_V4;
    sig->halg = pgp_hash_adjust_alg_to_key(halg, subkey);
    sig->palg = subkey->alg;
    sig->type = PGP_SIG_PRIMARY;

    if (pgp_keyid(keyid, subkey)) {
        RNP_LOG("failed to calculate keyid");
        return false;
    }
    if (!signature_set_creation(sig, time(NULL))) {
        RNP_LOG("failed to set embedded sig creation time");
        return false;
    }
    if (!signature_set_keyid(sig, keyid)) {
        RNP_LOG("failed to set issuer key id");
        return false;
    }
    if (!signature_fill_hashed_data(sig)) {
        RNP_LOG("failed to hash signature");
        return false;
    }
    if (signature_calculate(sig, &subkey->material, hash, rng)) {
        RNP_LOG("failed to calculate signature");
        return false;
    }
    return true;
}

bool
signature_calculate_binding(const pgp_key_pkt_t *key,
                            const pgp_key_pkt_t *sub,
                            pgp_signature_t *    sig,
                            bool                 subsign)
{
    pgp_hash_t   hash = {};
    pgp_hash_t   hashcp = {};
    rng_t        rng = {};
    pgp_key_id_t keyid;

    if (pgp_keyid(keyid, key)) {
        RNP_LOG("failed to calculate keyid");
        return false;
    }

    if (!rng_init(&rng, RNG_SYSTEM)) {
        RNP_LOG("RNG init failed");
        return false;
    }

    bool res = false;
    if (!signature_fill_hashed_data(sig) || !signature_hash_binding(sig, key, sub, &hash) ||
        !pgp_hash_copy(&hashcp, &hash)) {
        RNP_LOG("failed to hash signature");
        goto end;
    }

    if (signature_calculate(sig, &key->material, &hash, &rng)) {
        RNP_LOG("failed to calculate signature");
        goto end;
    }

    /* unhashed subpackets. Primary key binding signature and issuer key id */
    if (subsign) {
        pgp_signature_t embsig = {};
        if (!signature_calculate_primary_binding(
              key, sub, sig->halg, &embsig, &hashcp, &rng)) {
            RNP_LOG("failed to calculate primary key binding signature");
            goto end;
        }
        if (!signature_set_embedded_sig(sig, &embsig)) {
            RNP_LOG("failed to add primary key binding signature");
            goto end;
        }
    }

    /* add keyid since it should (probably) be after the primary key binding if any */
    if (!signature_set_keyid(sig, keyid)) {
        RNP_LOG("failed to set issuer key id");
        goto end;
    }
    res = true;
end:
    pgp_hash_finish(&hashcp, NULL);
    rng_destroy(&rng);
    return res;
}

pgp_signature_t *
transferable_subkey_bind(const pgp_key_pkt_t *             key,
                         pgp_transferable_subkey_t *       subkey,
                         pgp_hash_alg_t                    hash_alg,
                         const rnp_selfsig_binding_info_t *binding)
{
    if (!key || !subkey || !binding) {
        RNP_LOG("invalid parameters");
        return NULL;
    }

    pgp_fingerprint_t keyfp;
    if (pgp_fingerprint(keyfp, key)) {
        RNP_LOG("failed to calculate keyfp");
        return NULL;
    }

    pgp_signature_t sig = {};
    pgp_key_flags_t realkf = (pgp_key_flags_t) 0;

    sig.version = PGP_V4;
    sig.halg = pgp_hash_adjust_alg_to_key(hash_alg, key);
    sig.palg = key->alg;
    sig.type = PGP_SIG_SUBKEY;

    if (!signature_set_keyfp(&sig, keyfp)) {
        RNP_LOG("failed to set issuer fingerprint");
        return NULL;
    }
    if (!signature_set_creation(&sig, time(NULL))) {
        RNP_LOG("failed to set creation time");
        return NULL;
    }
    if (binding->key_expiration &&
        !signature_set_key_expiration(&sig, binding->key_expiration)) {
        RNP_LOG("failed to set key expiration time");
        return NULL;
    }
    if (binding->key_flags && !signature_set_key_flags(&sig, binding->key_flags)) {
        RNP_LOG("failed to set key flags");
        return NULL;
    }

    realkf = (pgp_key_flags_t) binding->key_flags;
    if (!realkf) {
        realkf = pgp_pk_alg_capabilities(subkey->subkey.alg);
    }

    if (!signature_calculate_binding(key, &subkey->subkey, &sig, realkf & PGP_KF_SIGN)) {
        return NULL;
    }

    pgp_signature_t *res =
      (pgp_signature_t *) list_append(&subkey->signatures, NULL, sizeof(sig));
    *res = std::move(sig);
    return res;
}

pgp_signature_t *
transferable_key_revoke(const pgp_key_pkt_t *key,
                        const pgp_key_pkt_t *signer,
                        pgp_hash_alg_t       hash_alg,
                        const pgp_revoke_t * revoke)
{
    pgp_signature_t   sig;
    bool              res = false;
    pgp_key_id_t      keyid;
    pgp_fingerprint_t keyfp;

    if (!key || !signer || !revoke) {
        RNP_LOG("invalid parameters");
        return NULL;
    }
    if (pgp_keyid(keyid, signer)) {
        RNP_LOG("failed to calculate keyid");
        return NULL;
    }
    if (pgp_fingerprint(keyfp, signer)) {
        RNP_LOG("failed to calculate keyfp");
        return NULL;
    }

    sig.version = PGP_V4;
    sig.halg = pgp_hash_adjust_alg_to_key(hash_alg, signer);
    sig.palg = signer->alg;
    sig.type = is_primary_key_pkt(key->tag) ? PGP_SIG_REV_KEY : PGP_SIG_REV_SUBKEY;

    if (!signature_set_keyfp(&sig, keyfp)) {
        RNP_LOG("failed to set issuer fingerprint");
        return NULL;
    }
    if (!signature_set_creation(&sig, time(NULL))) {
        RNP_LOG("failed to set creation time");
        return NULL;
    }
    if (!signature_set_revocation_reason(&sig, revoke->code, revoke->reason.c_str())) {
        RNP_LOG("failed to set revocation reason");
        return NULL;
    }
    if (!signature_set_keyid(&sig, keyid)) {
        RNP_LOG("failed to set issuer key id");
        return NULL;
    }

    if (is_primary_key_pkt(key->tag)) {
        res = signature_calculate_direct(key, &sig, signer);
    } else {
        res = signature_calculate_binding(signer, key, &sig, false);
    }
    if (!res) {
        RNP_LOG("failed to calculate signature");
        return NULL;
    }

    try {
        return new pgp_signature_t(std::move(sig));
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
}

static bool
skip_pgp_packets(pgp_source_t *src, const std::set<pgp_pkt_type_t> &pkts)
{
    do {
        int pkt = stream_pkt_type(src);
        if (pkt <= 0) {
            break;
        }
        if (pkts.find((pgp_pkt_type_t) pkt) == pkts.end()) {
            return true;
        }
        uint64_t ppos = src->readb;
        if (stream_skip_packet(src)) {
            RNP_LOG("failed to skip packet at %" PRIu64, ppos);
            return false;
        }
    } while (1);

    return true;
}

static rnp_result_t
process_pgp_key_signatures(pgp_source_t *src, list *sigs, bool skiperrors)
{
    int          ptag;
    rnp_result_t ret = RNP_ERROR_BAD_FORMAT;

    while ((ptag = stream_pkt_type(src)) == PGP_PKT_SIGNATURE) {
        pgp_signature_t *sig = (pgp_signature_t *) list_append(sigs, NULL, sizeof(*sig));
        if (!sig) {
            RNP_LOG("sig alloc failed");
            return RNP_ERROR_OUT_OF_MEMORY;
        }

        uint64_t sigpos = src->readb;
        if ((ret = stream_parse_signature(src, sig))) {
            RNP_LOG("failed to parse signature at %" PRIu64, sigpos);
            sig->~pgp_signature_t();
            list_remove((list_item *) sig);
            if (!skiperrors) {
                return ret;
            }
        }

        if (!skip_pgp_packets(src, {PGP_PKT_TRUST})) {
            return RNP_ERROR_READ;
        }
    }

    return ptag < 0 ? RNP_ERROR_BAD_FORMAT : RNP_SUCCESS;
}

static rnp_result_t
process_pgp_userid(pgp_source_t *src, pgp_transferable_userid_t *uid, bool skiperrors)
{
    rnp_result_t ret;
    uint64_t     uidpos = src->readb;
    if ((ret = stream_parse_userid(src, &uid->uid))) {
        RNP_LOG("failed to parse userid at %" PRIu64, uidpos);
        return ret;
    }
    if (!skip_pgp_packets(src, {PGP_PKT_TRUST})) {
        return RNP_ERROR_READ;
    }
    return process_pgp_key_signatures(src, &uid->signatures, skiperrors);
}

rnp_result_t
process_pgp_subkey(pgp_source_t &src, pgp_transferable_subkey_t &subkey, bool skiperrors)
{
    int          ptag;
    rnp_result_t ret = RNP_ERROR_BAD_FORMAT;

    subkey = {};
    uint64_t keypos = src.readb;
    if (!is_subkey_pkt(ptag = stream_pkt_type(&src))) {
        RNP_LOG("wrong subkey ptag: %d at %" PRIu64, ptag, keypos);
        return RNP_ERROR_BAD_FORMAT;
    }

    if ((ret = stream_parse_key(&src, &subkey.subkey))) {
        RNP_LOG("failed to parse subkey at %" PRIu64, keypos);
        goto done;
    }

    if (!skip_pgp_packets(&src, {PGP_PKT_TRUST})) {
        ret = RNP_ERROR_READ;
        goto done;
    }

    ret = process_pgp_key_signatures(&src, &subkey.signatures, skiperrors);
done:
    return ret;
}

rnp_result_t
process_pgp_keys(pgp_source_t *src, pgp_key_sequence_t &keys, bool skiperrors)
{
    bool          armored = false;
    pgp_source_t  armorsrc = {0};
    pgp_source_t *origsrc = src;
    bool          has_secret = false;
    bool          has_public = false;
    rnp_result_t  ret = RNP_ERROR_GENERIC;

    keys = {};
    /* check whether keys are armored */
armoredpass:
    if (is_armored_source(src)) {
        if ((ret = init_armored_src(&armorsrc, src))) {
            RNP_LOG("failed to parse armored data");
            goto finish;
        }
        armored = true;
        src = &armorsrc;
    }

    /* read sequence of transferable OpenPGP keys as described in RFC 4880, 11.1 - 11.2 */
    while (!src_eof(src) && !src_error(src)) {
        pgp_transferable_key_t curkey;
        int                    ptag = stream_pkt_type(src);
        if (!is_primary_key_pkt(ptag)) {
            RNP_LOG("wrong key tag: %d at pos %" PRIu64, ptag, src->readb);
            ret = RNP_ERROR_BAD_FORMAT;
            goto finish;
        }

        ret = process_pgp_key(src, curkey, skiperrors);
        if ((ret == RNP_ERROR_BAD_FORMAT) && skiperrors &&
            skip_pgp_packets(src,
                             {PGP_PKT_TRUST,
                              PGP_PKT_SIGNATURE,
                              PGP_PKT_USER_ID,
                              PGP_PKT_USER_ATTR,
                              PGP_PKT_PUBLIC_SUBKEY,
                              PGP_PKT_SECRET_SUBKEY})) {
            continue;
        }
        if (ret) {
            goto finish;
        }
        try {
            keys.keys.emplace_back(std::move(curkey));
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }

        has_secret |= (ptag == PGP_PKT_SECRET_KEY);
        has_public |= (ptag == PGP_PKT_PUBLIC_KEY);
    }

    /* file may have multiple armored keys */
    if (armored && !src_eof(origsrc) && is_armored_source(origsrc)) {
        src_close(&armorsrc);
        armored = false;
        src = origsrc;
        goto armoredpass;
    }

    if (has_secret && has_public) {
        RNP_LOG("warning! public keys are mixed together with secret ones!");
    }

    ret = RNP_SUCCESS;
finish:
    if (armored) {
        src_close(&armorsrc);
    }
    if (ret) {
        keys = {};
    }
    return ret;
}

rnp_result_t
process_pgp_key(pgp_source_t *src, pgp_transferable_key_t &key, bool skiperrors)
{
    pgp_source_t armorsrc = {0};
    bool         armored = false;
    int          ptag;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    key = {};
    /* check whether keys are armored */
    if (is_armored_source(src)) {
        if ((ret = init_armored_src(&armorsrc, src))) {
            RNP_LOG("failed to parse armored data");
            return ret;
        }
        armored = true;
        src = &armorsrc;
    }

    /* main key packet */
    uint64_t keypos = src->readb;
    ptag = stream_pkt_type(src);
    if ((ptag <= 0) || !is_primary_key_pkt(ptag)) {
        RNP_LOG("wrong key packet tag: %d at %" PRIu64, ptag, keypos);
        ret = RNP_ERROR_BAD_FORMAT;
        goto finish;
    }

    if ((ret = stream_parse_key(src, &key.key))) {
        RNP_LOG("failed to parse key pkt at %" PRIu64, keypos);
        goto finish;
    }

    if (!skip_pgp_packets(src, {PGP_PKT_TRUST})) {
        ret = RNP_ERROR_READ;
        goto finish;
    }

    /* direct-key signatures */
    if ((ret = process_pgp_key_signatures(src, &key.signatures, skiperrors))) {
        goto finish;
    }

    /* user ids/attrs with signatures */
    while ((ptag = stream_pkt_type(src)) > 0) {
        if ((ptag != PGP_PKT_USER_ID) && (ptag != PGP_PKT_USER_ATTR)) {
            break;
        }

        try {
            key.userids.emplace_back();
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            ret = RNP_ERROR_OUT_OF_MEMORY;
            goto finish;
        }
        ret = process_pgp_userid(src, &key.userids.back(), skiperrors);
        if ((ret == RNP_ERROR_BAD_FORMAT) && skiperrors &&
            skip_pgp_packets(src, {PGP_PKT_TRUST, PGP_PKT_SIGNATURE})) {
            key.userids.pop_back();
            /* skip malformed uid */
            continue;
        }
        if (ret) {
            goto finish;
        }
    }

    /* subkeys with signatures */
    while ((ptag = stream_pkt_type(src)) > 0) {
        if (!is_subkey_pkt(ptag)) {
            break;
        }

        pgp_transferable_subkey_t subkey;
        ret = process_pgp_subkey(*src, subkey, skiperrors);
        if ((ret == RNP_ERROR_BAD_FORMAT) && skiperrors &&
            skip_pgp_packets(src, {PGP_PKT_TRUST, PGP_PKT_SIGNATURE})) {
            /* skip malformed subkey */
            continue;
        }
        try {
            key.subkeys.emplace_back(std::move(subkey));
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            ret = RNP_ERROR_OUT_OF_MEMORY;
        }
        if (ret) {
            goto finish;
        }
    }
    ret = ptag >= 0 ? RNP_SUCCESS : RNP_ERROR_BAD_FORMAT;
finish:
    if (armored) {
        src_close(&armorsrc);
    }
    return ret;
}

static bool
write_pgp_signatures(list signatures, pgp_dest_t *dst)
{
    for (list_item *sig = list_front(signatures); sig; sig = list_next(sig)) {
        if (!stream_write_signature((pgp_signature_t *) sig, dst)) {
            return false;
        }
    }

    return true;
}

rnp_result_t
write_pgp_keys(pgp_key_sequence_t &keys, pgp_dest_t *dst, bool armor)
{
    pgp_dest_t   armdst = {0};
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (armor) {
        pgp_armored_msg_t msgtype = PGP_ARMORED_PUBLIC_KEY;
        if (!keys.keys.empty() && is_secret_key_pkt(keys.keys.front().key.tag)) {
            msgtype = PGP_ARMORED_SECRET_KEY;
        }

        if ((ret = init_armored_dst(&armdst, dst, msgtype))) {
            return ret;
        }
        dst = &armdst;
    }

    for (auto &key : keys.keys) {
        /* main key */
        if (!stream_write_key(&key.key, dst)) {
            ret = RNP_ERROR_WRITE;
            goto finish;
        }
        /* revocation signatures */
        if (!write_pgp_signatures(key.signatures, dst)) {
            ret = RNP_ERROR_WRITE;
            goto finish;
        }
        /* user ids/attrs and signatures */
        for (auto &uid : key.userids) {
            if (!stream_write_userid(&uid.uid, dst) ||
                !write_pgp_signatures(uid.signatures, dst)) {
                ret = RNP_ERROR_WRITE;
                goto finish;
            }
        }
        /* subkeys with signatures */
        for (auto &skey : key.subkeys) {
            if (!stream_write_key(&skey.subkey, dst) ||
                !write_pgp_signatures(skey.signatures, dst)) {
                ret = RNP_ERROR_WRITE;
                goto finish;
            }
        }
    }
    ret = RNP_SUCCESS;
finish:
    if (armor) {
        dst_close(&armdst, ret);
    }
    return ret;
}

rnp_result_t
write_pgp_key(pgp_transferable_key_t *key, pgp_dest_t *dst, bool armor)
{
    pgp_key_sequence_t keys;

    try {
        keys.keys.emplace_back();
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    /* temporary solution to not implement copy constructor */
    pgp_transferable_key_t &front = keys.keys.front();
    memcpy(&front, key, sizeof(*key));
    rnp_result_t res = write_pgp_keys(keys, dst, armor);
    memset(&front, 0, sizeof(front));
    return res;
}

static rnp_result_t
decrypt_secret_key_v3(pgp_crypt_t *crypt, uint8_t *dec, const uint8_t *enc, size_t len)
{
    size_t idx;
    size_t pos = 0;
    size_t mpilen;
    size_t blsize;

    if (!(blsize = pgp_cipher_block_size(crypt))) {
        RNP_LOG("wrong crypto");
        return RNP_ERROR_BAD_STATE;
    }

    /* 4 RSA secret mpis with cleartext header */
    for (idx = 0; idx < 4; idx++) {
        if (pos + 2 > len) {
            RNP_LOG("bad v3 secret key data");
            return RNP_ERROR_BAD_FORMAT;
        }
        mpilen = (read_uint16(enc + pos) + 7) >> 3;
        memcpy(dec + pos, enc + pos, 2);
        pos += 2;
        if (pos + mpilen > len) {
            RNP_LOG("bad v3 secret key data");
            return RNP_ERROR_BAD_FORMAT;
        }
        pgp_cipher_cfb_decrypt(crypt, dec + pos, enc + pos, mpilen);
        pos += mpilen;
        if (mpilen < blsize) {
            RNP_LOG("bad rsa v3 mpi len");
            return RNP_ERROR_BAD_FORMAT;
        }
        pgp_cipher_cfb_resync(crypt, enc + pos - blsize);
    }

    /* sum16 */
    if (pos + 2 != len) {
        return RNP_ERROR_BAD_FORMAT;
    }
    memcpy(dec + pos, enc + pos, 2);
    return RNP_SUCCESS;
}

static rnp_result_t
parse_secret_key_mpis(pgp_key_pkt_t *key, const uint8_t *mpis, size_t len)
{
    pgp_packet_body_t body;
    bool              res;

    if (!mpis) {
        return RNP_ERROR_NULL_POINTER;
    }

    /* check the cleartext data */
    switch (key->sec_protection.s2k.usage) {
    case PGP_S2KU_NONE:
    case PGP_S2KU_ENCRYPTED: {
        /* calculate and check sum16 of the cleartext */
        uint16_t sum = 0;
        size_t   idx;

        len -= 2;
        for (idx = 0; idx < len; idx++) {
            sum += mpis[idx];
        }
        if (sum != read_uint16(mpis + len)) {
            RNP_LOG("wrong key checksum");
            return RNP_ERROR_DECRYPT_FAILED;
        }
        break;
    }
    case PGP_S2KU_ENCRYPTED_AND_HASHED: {
        /* calculate and check sha1 hash of the cleartext */
        pgp_hash_t hash;
        uint8_t    hval[PGP_MAX_HASH_SIZE];

        if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
            return RNP_ERROR_BAD_STATE;
        }
        len -= PGP_SHA1_HASH_SIZE;
        pgp_hash_add(&hash, mpis, len);
        if (pgp_hash_finish(&hash, hval) != PGP_SHA1_HASH_SIZE) {
            return RNP_ERROR_BAD_STATE;
        }
        if (memcmp(hval, mpis + len, PGP_SHA1_HASH_SIZE)) {
            return RNP_ERROR_DECRYPT_FAILED;
        }
        break;
    }
    default:
        RNP_LOG("unknown s2k usage: %d", (int) key->sec_protection.s2k.usage);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* parse mpis depending on algorithm */
    packet_body_part_from_mem(&body, mpis, len);

    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        res = get_packet_body_mpi(&body, &key->material.rsa.d) &&
              get_packet_body_mpi(&body, &key->material.rsa.p) &&
              get_packet_body_mpi(&body, &key->material.rsa.q) &&
              get_packet_body_mpi(&body, &key->material.rsa.u);
        break;
    case PGP_PKA_DSA:
        res = get_packet_body_mpi(&body, &key->material.dsa.x);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        res = get_packet_body_mpi(&body, &key->material.ec.x);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        res = get_packet_body_mpi(&body, &key->material.eg.x);
        break;
    default:
        RNP_LOG("uknown pk alg : %d", (int) key->alg);
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!res) {
        RNP_LOG("failed to parse secret data");
        return RNP_ERROR_BAD_FORMAT;
    }

    if (body.pos < body.len) {
        RNP_LOG("extra data in sec key");
        return RNP_ERROR_BAD_FORMAT;
    }

    key->material.secret = true;

    return RNP_SUCCESS;
}

rnp_result_t
decrypt_secret_key(pgp_key_pkt_t *key, const char *password)
{
    size_t       keysize;
    uint8_t      keybuf[PGP_MAX_KEY_SIZE];
    uint8_t *    decdata = NULL;
    pgp_crypt_t  crypt;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    if (!key) {
        return RNP_ERROR_NULL_POINTER;
    }
    if (!is_secret_key_pkt(key->tag)) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* check whether data is not encrypted */
    if (!key->sec_protection.s2k.usage) {
        return parse_secret_key_mpis(key, key->sec_data, key->sec_len);
    }
    /* data is encrypted */
    if (!password) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (key->sec_protection.cipher_mode != PGP_CIPHER_MODE_CFB) {
        RNP_LOG("unsupported secret key encryption mode");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    keysize = pgp_key_size(key->sec_protection.symm_alg);
    if (!keysize || !pgp_s2k_derive_key(&key->sec_protection.s2k, password, keybuf, keysize)) {
        RNP_LOG("failed to derive key");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if (!(decdata = (uint8_t *) malloc(key->sec_len))) {
        RNP_LOG("allocation failed");
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto finish;
    }

    if (!pgp_cipher_cfb_start(
          &crypt, key->sec_protection.symm_alg, keybuf, key->sec_protection.iv)) {
        RNP_LOG("failed to start cfb decryption");
        ret = RNP_ERROR_DECRYPT_FAILED;
        goto finish;
    }

    switch (key->version) {
    case PGP_V3:
        if (!is_rsa_key_alg(key->alg)) {
            RNP_LOG("non-RSA v3 key");
            ret = RNP_ERROR_BAD_PARAMETERS;
            break;
        }
        ret = decrypt_secret_key_v3(&crypt, decdata, key->sec_data, key->sec_len);
        break;
    case PGP_V4:
        pgp_cipher_cfb_decrypt(&crypt, decdata, key->sec_data, key->sec_len);
        ret = RNP_SUCCESS;
        break;
    default:
        ret = RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_cipher_cfb_finish(&crypt);
    if (ret) {
        goto finish;
    }

    ret = parse_secret_key_mpis(key, decdata, key->sec_len);
finish:
    pgp_forget(keybuf, sizeof(keybuf));
    if (decdata) {
        pgp_forget(decdata, key->sec_len);
        free(decdata);
    }
    return ret;
}

static bool
write_secret_key_mpis(pgp_packet_body_t *body, pgp_key_pkt_t *key)
{
    pgp_hash_t hash;
    uint8_t    hval[PGP_MAX_HASH_SIZE];
    bool       res = false;

    /* add mpis */
    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        res = add_packet_body_mpi(body, &key->material.rsa.d) &&
              add_packet_body_mpi(body, &key->material.rsa.p) &&
              add_packet_body_mpi(body, &key->material.rsa.q) &&
              add_packet_body_mpi(body, &key->material.rsa.u);
        break;
    case PGP_PKA_DSA:
        res = add_packet_body_mpi(body, &key->material.dsa.x);
        break;
    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        res = add_packet_body_mpi(body, &key->material.ec.x);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        res = add_packet_body_mpi(body, &key->material.eg.x);
        break;
    default:
        RNP_LOG("uknown pk alg : %d", (int) key->alg);
        return false;
    }

    if (!res) {
        return false;
    }

    /* add sum16 if sha1 is not used */
    if (key->sec_protection.s2k.usage != PGP_S2KU_ENCRYPTED_AND_HASHED) {
        uint16_t sum = 0;
        for (size_t i = 0; i < body->len; i++) {
            sum += body->data[i];
        }
        return add_packet_body_uint16(body, sum);
    }

    /* add sha1 hash */
    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        RNP_LOG("failed to create sha1 hash");
        return false;
    }
    pgp_hash_add(&hash, body->data, body->len);
    if (pgp_hash_finish(&hash, hval) != PGP_SHA1_HASH_SIZE) {
        RNP_LOG("failed to finish hash");
        return false;
    }
    return add_packet_body(body, hval, PGP_SHA1_HASH_SIZE);
}

rnp_result_t
encrypt_secret_key(pgp_key_pkt_t *key, const char *password, rng_t *rng)
{
    pgp_packet_body_t body;
    uint8_t           keybuf[PGP_MAX_KEY_SIZE];
    size_t            keysize;
    size_t            blsize;
    pgp_crypt_t       crypt;
    rnp_result_t      ret = RNP_ERROR_GENERIC;

    if (!is_secret_key_pkt(key->tag) || !key->material.secret) {
        return RNP_ERROR_BAD_PARAMETERS;
    }
    if (key->sec_protection.s2k.usage &&
        (key->sec_protection.cipher_mode != PGP_CIPHER_MODE_CFB)) {
        RNP_LOG("unsupported secret key encryption mode");
        return RNP_ERROR_BAD_PARAMETERS;
    }

    /* build secret key data */
    if (!init_packet_body(&body, PGP_PKT_RESERVED)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    if (!write_secret_key_mpis(&body, key)) {
        ret = RNP_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    /* check whether data is not encrypted */
    if (key->sec_protection.s2k.usage == PGP_S2KU_NONE) {
        free(key->sec_data);
        key->sec_data = body.data;
        key->sec_len = body.len;
        return RNP_SUCCESS;
    }
    /* data is encrypted */
    keysize = pgp_key_size(key->sec_protection.symm_alg);
    blsize = pgp_block_size(key->sec_protection.symm_alg);
    if (!keysize || !blsize) {
        RNP_LOG("wrong symm alg");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto error;
    }
    /* generate iv and s2k salt */
    if (rng) {
        if (!rng_get_data(rng, key->sec_protection.iv, blsize)) {
            ret = RNP_ERROR_RNG;
            goto error;
        }
        if ((key->sec_protection.s2k.specifier != PGP_S2KS_SIMPLE) &&
            !rng_get_data(rng, key->sec_protection.s2k.salt, PGP_SALT_SIZE)) {
            ret = RNP_ERROR_RNG;
            goto error;
        }
    } else {
        /* temporary solution! */
        if (!rng_generate(key->sec_protection.iv, blsize)) {
            ret = RNP_ERROR_RNG;
            goto error;
        }
        if ((key->sec_protection.s2k.specifier != PGP_S2KS_SIMPLE) &&
            !rng_generate(key->sec_protection.s2k.salt, PGP_SALT_SIZE)) {
            ret = RNP_ERROR_RNG;
            goto error;
        }
    }
    /* derive key */
    if (!pgp_s2k_derive_key(&key->sec_protection.s2k, password, keybuf, keysize)) {
        RNP_LOG("failed to derive key");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto error;
    }
    /* encrypt sec data */
    if (key->version < PGP_V4) {
        RNP_LOG("encryption of v3 keys is not supported");
        ret = RNP_ERROR_BAD_PARAMETERS;
        goto error;
    }
    if (!pgp_cipher_cfb_start(
          &crypt, key->sec_protection.symm_alg, keybuf, key->sec_protection.iv)) {
        RNP_LOG("failed to start cfb encryption");
        ret = RNP_ERROR_DECRYPT_FAILED;
        goto error;
    }
    pgp_cipher_cfb_encrypt(&crypt, body.data, body.data, body.len);
    pgp_cipher_cfb_finish(&crypt);
    free(key->sec_data);
    key->sec_data = body.data;
    key->sec_len = body.len;
    /* cleanup cleartext fields */
    forget_secret_key_fields(&key->material);
    return RNP_SUCCESS;
error:
    pgp_forget(keybuf, sizeof(keybuf));
    pgp_forget(body.data, body.len);
    free_packet_body(&body);
    return ret;
}

void
forget_secret_key_fields(pgp_key_material_t *key)
{
    if (!key || !key->secret) {
        return;
    }

    switch (key->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        mpi_forget(&key->rsa.d);
        mpi_forget(&key->rsa.p);
        mpi_forget(&key->rsa.q);
        mpi_forget(&key->rsa.u);
        break;
    case PGP_PKA_DSA:
        mpi_forget(&key->dsa.x);
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        mpi_forget(&key->eg.x);
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        mpi_forget(&key->ec.x);
        break;
    default:
        RNP_LOG("unknown key algorithm: %d", (int) key->alg);
    }

    key->secret = false;
}

pgp_transferable_userid_t::pgp_transferable_userid_t(const pgp_transferable_userid_t &src)
{
    if (!copy_userid_pkt(&uid, &src.uid)) {
        throw std::bad_alloc();
    }
    signatures = NULL;
    if (!copy_signatures(&signatures, &src.signatures)) {
        throw std::bad_alloc();
    }
}

pgp_transferable_userid_t &
pgp_transferable_userid_t::operator=(const pgp_transferable_userid_t &src)
{
    if (this == &src) {
        return *this;
    }
    free_userid_pkt(&uid);
    if (!copy_userid_pkt(&uid, &src.uid)) {
        throw std::bad_alloc();
    }
    signature_list_destroy(&signatures);
    if (!copy_signatures(&signatures, &src.signatures)) {
        throw std::bad_alloc();
    }
    return *this;
}

pgp_transferable_userid_t::~pgp_transferable_userid_t()
{
    free_userid_pkt(&uid);
    signature_list_destroy(&signatures);
}

pgp_transferable_subkey_t::pgp_transferable_subkey_t(const pgp_transferable_subkey_t &src)
{
    copy_key_pkt(&subkey, &src.subkey, false);
    signatures = NULL;
    if (!copy_signatures(&signatures, &src.signatures)) {
        throw std::bad_alloc();
    }
}

pgp_transferable_subkey_t::pgp_transferable_subkey_t(pgp_transferable_subkey_t &&src)
{
    subkey = src.subkey;
    src.subkey = {};
    signatures = src.signatures;
    src.signatures = NULL;
}

pgp_transferable_subkey_t &
pgp_transferable_subkey_t::operator=(const pgp_transferable_subkey_t &src)
{
    if (this == &src) {
        return *this;
    }
    free_key_pkt(&subkey);
    copy_key_pkt(&subkey, &src.subkey, false);
    signature_list_destroy(&signatures);
    if (!copy_signatures(&signatures, &src.signatures)) {
        throw std::bad_alloc();
    }
    return *this;
}

pgp_transferable_subkey_t &
pgp_transferable_subkey_t::operator=(pgp_transferable_subkey_t &&src)
{
    if (this == &src) {
        return *this;
    }
    free_key_pkt(&subkey);
    subkey = src.subkey;
    src.subkey = {};
    signature_list_destroy(&signatures);
    signatures = src.signatures;
    src.signatures = NULL;
    return *this;
}

pgp_transferable_subkey_t::~pgp_transferable_subkey_t()
{
    forget_secret_key_fields(&subkey.material);
    free_key_pkt(&subkey);
    signature_list_destroy(&signatures);
}

pgp_transferable_key_t::pgp_transferable_key_t(pgp_transferable_key_t &&src)
{
    key = src.key;
    src.key = {};
    userids = std::move(src.userids);
    subkeys = std::move(src.subkeys);
    signatures = src.signatures;
    src.signatures = NULL;
}

pgp_transferable_key_t &
pgp_transferable_key_t::operator=(pgp_transferable_key_t &&src)
{
    if (this == &src) {
        return *this;
    }
    forget_secret_key_fields(&key.material);
    free_key_pkt(&key);
    key = src.key;
    src.key = {};

    userids = std::move(src.userids);
    subkeys = std::move(src.subkeys);

    signature_list_destroy(&signatures);
    signatures = src.signatures;
    src.signatures = NULL;
    return *this;
}

pgp_transferable_key_t::~pgp_transferable_key_t()
{
    forget_secret_key_fields(&key.material);
    free_key_pkt(&key);
    signature_list_destroy(&signatures);
}
