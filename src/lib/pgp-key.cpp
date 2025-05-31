/*
 * Copyright (c) 2017-2022 [Ribose Inc](https://www.ribose.com).
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
#include <librekey/key_store_g10.h>
#include "crypto/s2k.h"
#include "crypto/mem.h"
#include "crypto/signatures.h"
#include "fingerprint.h"
#include "keygen.hpp"

#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-armor.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cassert>
#include <time.h>
#include <algorithm>
#include <stdexcept>
#include "defaults.h"

pgp_key_pkt_t *
pgp_decrypt_seckey_pgp(const pgp_rawpacket_t &raw,
                       const pgp_key_pkt_t &  pubkey,
                       const char *           password)
{
    try {
        rnp::MemorySource src(raw.raw.data(), raw.raw.size(), false);
        auto              res = std::unique_ptr<pgp_key_pkt_t>(new pgp_key_pkt_t());
        if (res->parse(src.src()) || decrypt_secret_key(res.get(), password)) {
            return NULL;
        }
        return res.release();
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
}

/* Note that this function essentially serves two purposes.
 * - In the case of a protected key, it requests a password and
 *   uses it to decrypt the key and fill in key->key.seckey.
 * - In the case of an unprotected key, it simply re-loads
 *   key->key.seckey by parsing the key data in packets[0].
 */
pgp_key_pkt_t *
pgp_decrypt_seckey(const pgp_key_t &              key,
                   const pgp_password_provider_t &provider,
                   const pgp_password_ctx_t &     ctx)
{
    // sanity checks
    if (!key.is_secret()) {
        RNP_LOG("invalid args");
        return NULL;
    }
    // ask the provider for a password
    rnp::secure_array<char, MAX_PASSWORD_LENGTH> password;
    if (key.is_protected() &&
        !pgp_request_password(&provider, &ctx, password.data(), password.size())) {
        return NULL;
    }
    // attempt to decrypt with the provided password
    switch (key.format) {
    case PGP_KEY_STORE_GPG:
    case PGP_KEY_STORE_KBX:
        return pgp_decrypt_seckey_pgp(key.rawpkt(), key.pkt(), password.data());
    case PGP_KEY_STORE_G10:
        return g10_decrypt_seckey(key.rawpkt(), key.pkt(), password.data());
    default:
        RNP_LOG("unexpected format: %d", key.format);
        return NULL;
    }
}

static const id_str_pair ss_rr_code_map[] = {
  {PGP_REVOCATION_NO_REASON, "No reason specified"},
  {PGP_REVOCATION_SUPERSEDED, "Key is superseded"},
  {PGP_REVOCATION_COMPROMISED, "Key material has been compromised"},
  {PGP_REVOCATION_RETIRED, "Key is retired and no longer used"},
  {PGP_REVOCATION_NO_LONGER_VALID, "User ID information is no longer valid"},
  {0x00, NULL},
};

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

#if defined(ENABLE_CRYPTO_REFRESH)
    case PGP_PKA_ED25519:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);
    case PGP_PKA_X25519:
        return PGP_KF_ENCRYPT;
#endif

    case PGP_PKA_SM2:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH | PGP_KF_ENCRYPT);

    case PGP_PKA_ECDH:
    case PGP_PKA_ELGAMAL:
        return PGP_KF_ENCRYPT;

#if defined(ENABLE_PQC)
    case PGP_PKA_KYBER768_X25519:
        FALLTHROUGH_STATEMENT;
    // TODO add case PGP_PKA_KYBER1024_X448: FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER768_P256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER1024_P384:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER768_BP256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER1024_BP384:
        return PGP_KF_ENCRYPT;

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
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_SPHINCSPLUS_SHA2:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_SPHINCSPLUS_SHAKE:
        return pgp_key_flags_t(PGP_KF_SIGN | PGP_KF_CERTIFY | PGP_KF_AUTH);
#endif

    default:
        RNP_LOG("unknown pk alg: %d\n", alg);
        return PGP_KF_NONE;
    }
}

bool
pgp_key_t::write_sec_pgp(pgp_dest_t &       dst,
                         pgp_key_pkt_t &    seckey,
                         const std::string &password,
                         rnp::RNG &         rng)
{
    bool           res = false;
    pgp_pkt_type_t oldtag = seckey.tag;

    seckey.tag = type();
    if (encrypt_secret_key(&seckey, password.c_str(), rng)) {
        goto done;
    }
    try {
        seckey.write(dst);
        res = !dst.werr;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
    }
done:
    seckey.tag = oldtag;
    return res;
}

bool
pgp_key_t::write_sec_rawpkt(pgp_key_pkt_t &       seckey,
                            const std::string &   password,
                            rnp::SecurityContext &ctx)
{
    // encrypt+write the key in the appropriate format
    try {
        rnp::MemoryDest memdst;
        switch (format) {
        case PGP_KEY_STORE_GPG:
        case PGP_KEY_STORE_KBX:
            if (!write_sec_pgp(memdst.dst(), seckey, password, ctx.rng)) {
                RNP_LOG("failed to write secret key");
                return false;
            }
            break;
        case PGP_KEY_STORE_G10:
            if (!g10_write_seckey(&memdst.dst(), &seckey, password.c_str(), ctx)) {
                RNP_LOG("failed to write g10 secret key");
                return false;
            }
            break;
        default:
            RNP_LOG("invalid format");
            return false;
        }

        rawpkt_ = pgp_rawpacket_t((uint8_t *) memdst.memory(), memdst.writeb(), type());
        return true;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

static bool
update_sig_expiration(pgp_signature_t *      dst,
                      const pgp_signature_t *src,
                      uint64_t               create,
                      uint32_t               expiry)
{
    try {
        *dst = *src;
        if (!expiry) {
            dst->remove_subpkt(dst->find_subpkt(pgp::pkt::sigsub::Type::KeyExpirationTime));
            ;
        } else {
            dst->set_key_expiration(expiry);
        }
        dst->set_creation(create);
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
                       const pgp_password_provider_t &prov,
                       rnp::SecurityContext &         ctx)
{
    if (!key->is_primary()) {
        RNP_LOG("Not a primary key");
        return false;
    }

    std::vector<pgp_sig_id_t> sigs;
    /* update expiration for the latest direct-key signature and self-signature for each userid
     */
    pgp_subsig_t *sig = key->latest_selfsig(PGP_UID_NONE);
    if (sig) {
        sigs.push_back(sig->sigid);
    }
    for (size_t uid = 0; uid < key->uid_count(); uid++) {
        sig = key->latest_selfsig(uid);
        if (sig) {
            sigs.push_back(sig->sigid);
        }
    }
    if (sigs.empty()) {
        RNP_LOG("No valid self-signature(s)");
        return false;
    }

    rnp::KeyLocker seclock(*seckey);
    for (const auto &sigid : sigs) {
        pgp_subsig_t &sig = key->get_sig(sigid);
        /* update signature and re-sign it */
        if (!expiry && !sig.sig.has_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY)) {
            continue;
        }

        /* unlock secret key if needed */
        if (seckey->is_locked() && !seckey->unlock(prov)) {
            RNP_LOG("Failed to unlock secret key");
            return false;
        }

        pgp_signature_t newsig;
        pgp_sig_id_t    oldsigid = sigid;
        if (!update_sig_expiration(&newsig, &sig.sig, ctx.time(), expiry)) {
            return false;
        }
        try {
            if (sig.is_cert()) {
                if (sig.uid >= key->uid_count()) {
                    RNP_LOG("uid not found");
                    return false;
                }
                seckey->sign_cert(key->pkt(), key->get_uid(sig.uid).pkt, newsig, ctx);
            } else {
                /* direct-key signature case */
                seckey->sign_direct(key->pkt(), newsig, ctx);
            }
            /* replace signature, first for secret key since it may be replaced in public */
            if (seckey->has_sig(oldsigid)) {
                seckey->replace_sig(oldsigid, newsig);
            }
            if (key != seckey) {
                key->replace_sig(oldsigid, newsig);
            }
        } catch (const std::exception &e) {
            RNP_LOG("failed to calculate or add signature: %s", e.what());
            return false;
        }
    }

    if (!seckey->refresh_data(ctx)) {
        RNP_LOG("Failed to refresh seckey data.");
        return false;
    }
    if ((key != seckey) && !key->refresh_data(ctx)) {
        RNP_LOG("Failed to refresh key data.");
        return false;
    }
    return true;
}

bool
pgp_subkey_set_expiration(pgp_key_t *                    sub,
                          pgp_key_t *                    primsec,
                          pgp_key_t *                    secsub,
                          uint32_t                       expiry,
                          const pgp_password_provider_t &prov,
                          rnp::SecurityContext &         ctx)
{
    if (!sub->is_subkey()) {
        RNP_LOG("Not a subkey");
        return false;
    }

    /* find the latest valid subkey binding */
    pgp_subsig_t *subsig = sub->latest_binding();
    if (!subsig) {
        RNP_LOG("No valid subkey binding");
        return false;
    }
    if (!expiry && !subsig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_EXPIRY)) {
        return true;
    }

    rnp::KeyLocker primlock(*primsec);
    if (primsec->is_locked() && !primsec->unlock(prov)) {
        RNP_LOG("Failed to unlock primary key");
        return false;
    }
    bool           subsign = secsub->can_sign();
    rnp::KeyLocker sublock(*secsub);
    if (subsign && secsub->is_locked() && !secsub->unlock(prov)) {
        RNP_LOG("Failed to unlock subkey");
        return false;
    }

    try {
        /* update signature and re-sign */
        pgp_signature_t newsig;
        pgp_sig_id_t    oldsigid = subsig->sigid;
        if (!update_sig_expiration(&newsig, &subsig->sig, ctx.time(), expiry)) {
            return false;
        }
        primsec->sign_subkey_binding(*secsub, newsig, ctx);
        /* replace signature, first for the secret key since it may be replaced in public */
        if (secsub->has_sig(oldsigid)) {
            secsub->replace_sig(oldsigid, newsig);
            if (!secsub->refresh_data(primsec, ctx)) {
                return false;
            }
        }
        if (sub == secsub) {
            return true;
        }
        sub->replace_sig(oldsigid, newsig);
        return sub->refresh_data(primsec, ctx);
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

pgp_key_t *
find_suitable_key(pgp_op_t          op,
                  pgp_key_t *       key,
                  rnp::KeyProvider *key_provider,
                  bool              no_primary,
                  bool              pref_pqc_sub)
{
    if (!key || !key_provider) {
        return NULL;
    }
    bool secret = false;
    switch (op) {
    case PGP_OP_ENCRYPT:
        break;
    case PGP_OP_SIGN:
    case PGP_OP_CERTIFY:
        secret = true;
        break;
    default:
        RNP_LOG("Unsupported operation: %d", (int) op);
        return NULL;
    }
    /* Return if specified primary key fits our needs */
    if (!no_primary && key->usable_for(op)) {
        return key;
    }
    /* Check for the case when we need to look up for a secret key */
    if (!no_primary && secret && key->is_public() && key->usable_for(op, true)) {
        rnp::KeyFingerprintSearch search(key->fp());
        pgp_key_t *               sec = key_provider->request_key(search, op, secret);
        if (sec && sec->usable_for(op)) {
            return sec;
        }
    }
    /* Now look up for subkeys */
    pgp_key_t *subkey = NULL;
    for (auto &fp : key->subkey_fps()) {
        rnp::KeyFingerprintSearch search(fp);
        pgp_key_t *               cur = key_provider->request_key(search, op, secret);
        if (!cur || !cur->usable_for(op)) {
            continue;
        }
#if defined(ENABLE_PQC)
        if (pref_pqc_sub && op == PGP_OP_ENCRYPT) {
            /* prefer PQC encryption over non-PQC encryption. Assume non-PQC key is only there
             * for backwards compatibility. */
            if (subkey && subkey->is_pqc_alg() && !cur->is_pqc_alg()) {
                /* do not override already found PQC key with non-PQC key */
                continue;
            }
            if (subkey && cur->is_pqc_alg() && !subkey->is_pqc_alg()) {
                /* override non-PQC key with PQC key */
                subkey = cur;
                continue;
            }
        }
#endif
        if (!subkey || (cur->creation() > subkey->creation())) {
            subkey = cur;
        }
    }
    return subkey;
}

pgp_rawpacket_t::pgp_rawpacket_t(const pgp_signature_t &sig)
{
    raw = sig.write();
    tag = PGP_PKT_SIGNATURE;
}

pgp_rawpacket_t::pgp_rawpacket_t(pgp_key_pkt_t &key)
{
    rnp::MemoryDest dst;
    key.write(dst.dst());
    raw = dst.to_vector();
    tag = key.tag;
}

pgp_rawpacket_t::pgp_rawpacket_t(const pgp_userid_pkt_t &uid)
{
    rnp::MemoryDest dst;
    uid.write(dst.dst());
    raw = dst.to_vector();
    tag = uid.tag;
}

void
pgp_rawpacket_t::write(pgp_dest_t &dst) const
{
    dst_write(&dst, raw.data(), raw.size());
}

void
pgp_validity_t::mark_valid()
{
    validated = true;
    valid = true;
    expired = false;
}

void
pgp_validity_t::reset()
{
    validated = false;
    valid = false;
    expired = false;
}

pgp_subsig_t::pgp_subsig_t(const pgp_signature_t &pkt)
{
    sig = pkt;
    sigid = sig.get_id();
    /* add signature rawpacket */
    rawpkt = pgp_rawpacket_t(sig);
}

bool
pgp_subsig_t::valid() const
{
    return validity.validated && validity.valid && !validity.expired;
}

bool
pgp_subsig_t::validated() const
{
    return validity.validated;
}

bool
pgp_subsig_t::is_cert() const
{
    switch (sig.type()) {
    case PGP_CERT_CASUAL:
    case PGP_CERT_GENERIC:
    case PGP_CERT_PERSONA:
    case PGP_CERT_POSITIVE:
        return true;
    default:
        return false;
    }
}

bool
pgp_subsig_t::expired(uint64_t at) const
{
    /* sig expiration: absence of subpkt or 0 means it never expires */
    uint64_t expiration = sig.expiration();
    if (!expiration) {
        return false;
    }
    return expiration + sig.creation() < at;
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
pgp_userid_t::add_sig(const pgp_sig_id_t &sig, bool begin)
{
    size_t idx = begin ? 0 : sigs_.size();
    sigs_.insert(sigs_.begin() + idx, sig);
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

bool
pgp_userid_t::del_sig(const pgp_sig_id_t &id)
{
    auto it = std::find(sigs_.begin(), sigs_.end(), id);
    if (it == sigs_.end()) {
        return false;
    }
    sigs_.erase(it);
    return true;
}

void
pgp_userid_t::clear_sigs()
{
    sigs_.clear();
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
        reason = id_str_pair::lookup(ss_rr_code_map, code);
    }
}

pgp_key_t::pgp_key_t(const pgp_key_pkt_t &keypkt) : pkt_(keypkt)
{
    if (!is_key_pkt(pkt_.tag) || !pkt_.material->alg()) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    if (pgp_keyid(keyid_, pkt_) || pgp_fingerprint(fingerprint_, pkt_)) {
        throw rnp::rnp_exception(RNP_ERROR_GENERIC);
    }
    grip_ = pkt_.material->grip();

    /* parse secret key if not encrypted */
    if (is_secret_key_pkt(pkt_.tag)) {
        bool cleartext = pkt_.sec_protection.s2k.usage == PGP_S2KU_NONE;
        if (cleartext && decrypt_secret_key(&pkt_, NULL)) {
            RNP_LOG("failed to setup key fields");
            throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
        }
        /* decryption resets validity */
        pkt_.material->set_validity(keypkt.material->validity());
    }
    /* add rawpacket */
    rawpkt_ = pgp_rawpacket_t(pkt_);
    format = PGP_KEY_STORE_GPG;
}

pgp_key_t::pgp_key_t(const pgp_key_pkt_t &pkt, pgp_key_t &primary) : pgp_key_t(pkt)
{
    primary.link_subkey_fp(*this);
}

pgp_key_t::pgp_key_t(const pgp_key_t &src, bool pubonly)
{
    /* Do some checks for g10 keys */
    if (src.format == PGP_KEY_STORE_G10) {
        if (pubonly) {
            RNP_LOG("attempt to copy public part from g10 key");
            throw std::invalid_argument("pubonly");
        }
    }

    if (pubonly) {
        pkt_ = pgp_key_pkt_t(src.pkt_, true);
        rawpkt_ = pgp_rawpacket_t(pkt_);
    } else {
        pkt_ = src.pkt_;
        rawpkt_ = src.rawpkt_;
    }

    uids_ = src.uids_;
    sigs_ = src.sigs_;
    sigs_map_ = src.sigs_map_;
    keysigs_ = src.keysigs_;
    subkey_fps_ = src.subkey_fps_;
    primary_fp_set_ = src.primary_fp_set_;
    primary_fp_ = src.primary_fp_;
    expiration_ = src.expiration_;
    flags_ = src.flags_;
    keyid_ = src.keyid_;
    fingerprint_ = src.fingerprint_;
    grip_ = src.grip_;
    uid0_ = src.uid0_;
    uid0_set_ = src.uid0_set_;
    revoked_ = src.revoked_;
    revocation_ = src.revocation_;
    revokers_ = src.revokers_;
    format = src.format;
    validity_ = src.validity_;
    valid_till_ = src.valid_till_;
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
    if (primary) {
        primary->link_subkey_fp(*this);
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
    if (it == sigs_.end()) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }
    *it = res.sigid;
    if (uid == PGP_UID_NONE) {
        auto it = std::find(keysigs_.begin(), keysigs_.end(), oldid);
        if (it == keysigs_.end()) {
            throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
        }
        *it = res.sigid;
    } else {
        uids_[uid].replace_sig(oldid, res.sigid);
    }
    return res;
}

pgp_subsig_t &
pgp_key_t::add_sig(const pgp_signature_t &sig, size_t uid, bool begin)
{
    const pgp_sig_id_t sigid = sig.get_id();
    sigs_map_.erase(sigid);
    pgp_subsig_t &res = sigs_map_.emplace(std::make_pair(sigid, sig)).first->second;
    res.uid = uid;
    if (uid == PGP_UID_NONE) {
        size_t idx = begin ? 0 : keysigs_.size();
        sigs_.insert(sigs_.begin() + idx, sigid);
        keysigs_.insert(keysigs_.begin() + idx, sigid);
        return res;
    }

    /* Calculate correct position in sigs_ */
    size_t idx = keysigs_.size();
    for (size_t u = 0; u < uid; u++) {
        idx += uids_[u].sig_count();
    }
    if (!begin) {
        idx += uids_[uid].sig_count();
    }
    sigs_.insert(sigs_.begin() + idx, sigid);
    uids_[uid].add_sig(sigid, begin);
    return res;
}

bool
pgp_key_t::del_sig(const pgp_sig_id_t &sigid)
{
    if (!has_sig(sigid)) {
        return false;
    }
    uint32_t uid = get_sig(sigid).uid;
    if (uid == PGP_UID_NONE) {
        /* signature over the key itself */
        auto it = std::find(keysigs_.begin(), keysigs_.end(), sigid);
        if (it != keysigs_.end()) {
            keysigs_.erase(it);
        }
    } else if (uid < uids_.size()) {
        /* userid-related signature */
        uids_[uid].del_sig(sigid);
    }
    auto it = std::find(sigs_.begin(), sigs_.end(), sigid);
    if (it != sigs_.end()) {
        sigs_.erase(it);
    }
    return sigs_map_.erase(sigid);
}

size_t
pgp_key_t::del_sigs(const std::vector<pgp_sig_id_t> &sigs)
{
    /* delete actual signatures */
    size_t res = 0;
    for (auto &sig : sigs) {
        res += sigs_map_.erase(sig);
    }
    /* rebuild vectors with signatures order */
    keysigs_.clear();
    for (auto &uid : uids_) {
        uid.clear_sigs();
    }
    std::vector<pgp_sig_id_t> newsigs;
    newsigs.reserve(sigs_map_.size());
    for (auto &sigid : sigs_) {
        if (!sigs_map_.count(sigid)) {
            continue;
        }
        newsigs.push_back(sigid);
        uint32_t uid = get_sig(sigid).uid;
        if (uid == PGP_UID_NONE) {
            keysigs_.push_back(sigid);
        } else {
            uids_[uid].add_sig(sigid);
        }
    }
    sigs_ = std::move(newsigs);
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

size_t
pgp_key_t::get_uid_idx(const pgp_userid_pkt_t &uid) const
{
    for (size_t idx = 0; idx < uids_.size(); idx++) {
        if (uids_[idx].pkt == uid) {
            return idx;
        }
    }
    return PGP_UID_NONE;
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

uint32_t
pgp_key_t::uid_idx(const pgp_userid_pkt_t &uid) const
{
    for (uint32_t idx = 0; idx < uids_.size(); idx++) {
        if (uids_[idx].pkt == uid) {
            return idx;
        }
    }
    return PGP_UID_NONE;
}

void
pgp_key_t::del_uid(size_t idx)
{
    if (idx >= uids_.size()) {
        throw std::out_of_range("idx");
    }

    std::vector<pgp_sig_id_t> newsigs;
    /* copy sigs which do not belong to uid */
    newsigs.reserve(sigs_.size());
    for (auto &id : sigs_) {
        if (get_sig(id).uid == idx) {
            sigs_map_.erase(id);
            continue;
        }
        newsigs.push_back(id);
    }
    sigs_ = std::move(newsigs);
    uids_.erase(uids_.begin() + idx);
    /* update uids */
    if (idx == uids_.size()) {
        return;
    }
    for (auto &sig : sigs_map_) {
        if ((sig.second.uid == PGP_UID_NONE) || (sig.second.uid <= idx)) {
            continue;
        }
        sig.second.uid--;
    }
}

bool
pgp_key_t::has_primary_uid() const
{
    return uid0_set_;
}

uint32_t
pgp_key_t::get_primary_uid() const
{
    if (!uid0_set_) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return uid0_;
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

bool
pgp_key_t::revoked() const
{
    return revoked_;
}

const pgp_revoke_t &
pgp_key_t::revocation() const
{
    if (!revoked_) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return revocation_;
}

void
pgp_key_t::clear_revokes()
{
    revoked_ = false;
    revocation_ = {};
    for (auto &uid : uids_) {
        uid.revoked = false;
        uid.revocation = {};
    }
}

void
pgp_key_t::add_revoker(const pgp_fingerprint_t &revoker)
{
    for (auto &rev : revokers_) {
        if (rev == revoker) {
            return;
        }
    }
    revokers_.push_back(revoker);
}

bool
pgp_key_t::has_revoker(const pgp_fingerprint_t &revoker) const
{
    for (auto &rev : revokers_) {
        if (rev == revoker) {
            return true;
        }
    }
    return false;
}

size_t
pgp_key_t::revoker_count() const
{
    return revokers_.size();
}

const pgp_fingerprint_t &
pgp_key_t::get_revoker(size_t idx) const
{
    if (idx >= revokers_.size()) {
        throw std::out_of_range("idx");
    }
    return revokers_[idx];
}

const pgp_key_pkt_t &
pgp_key_t::pkt() const noexcept
{
    return pkt_;
}

pgp_key_pkt_t &
pgp_key_t::pkt() noexcept
{
    return pkt_;
}

void
pgp_key_t::set_pkt(const pgp_key_pkt_t &pkt)
{
    pkt_ = pkt;
}

const pgp::KeyMaterial *
pgp_key_t::material() const noexcept
{
    return pkt_.material.get();
}

pgp::KeyMaterial *
pgp_key_t::material() noexcept
{
    return pkt_.material.get();
}

pgp_pubkey_alg_t
pgp_key_t::alg() const noexcept
{
    return pkt_.alg;
}

pgp_curve_t
pgp_key_t::curve() const
{
    return material() ? material()->curve() : PGP_CURVE_UNKNOWN;
}

pgp_version_t
pgp_key_t::version() const noexcept
{
    return pkt().version;
}

pgp_pkt_type_t
pgp_key_t::type() const noexcept
{
    return pkt().tag;
}

bool
pgp_key_t::encrypted() const noexcept
{
    return is_secret() && material() && !material()->secret();
}

uint8_t
pgp_key_t::flags() const noexcept
{
    return flags_;
}

bool
pgp_key_t::can_sign() const noexcept
{
    return flags_ & PGP_KF_SIGN;
}

bool
pgp_key_t::can_certify() const noexcept
{
    return flags_ & PGP_KF_CERTIFY;
}

bool
pgp_key_t::can_encrypt() const noexcept
{
    return flags_ & PGP_KF_ENCRYPT;
}

bool
pgp_key_t::has_secret() const noexcept
{
    if (!is_secret()) {
        return false;
    }
    if ((format == PGP_KEY_STORE_GPG) && !pkt_.sec_len) {
        return false;
    }
    if (pkt_.sec_protection.s2k.usage == PGP_S2KU_NONE) {
        return true;
    }
    switch (pkt_.sec_protection.s2k.specifier) {
    case PGP_S2KS_SIMPLE:
    case PGP_S2KS_SALTED:
    case PGP_S2KS_ITERATED_AND_SALTED:
        return true;
    default:
        return false;
    }
}

#if defined(ENABLE_PQC)
bool
pgp_key_t::is_pqc_alg() const
{
    switch (alg()) {
    case PGP_PKA_KYBER768_X25519:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER768_P256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER1024_P384:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER768_BP256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_KYBER1024_BP384:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM3_ED25519:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM3_P256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM5_P384:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM3_BP256:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_DILITHIUM5_BP384:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_SPHINCSPLUS_SHA2:
        FALLTHROUGH_STATEMENT;
    case PGP_PKA_SPHINCSPLUS_SHAKE:
        return true;
    default:
        return false;
    }
}
#endif

bool
pgp_key_t::usable_for(pgp_op_t op, bool if_secret) const
{
    switch (op) {
    case PGP_OP_ADD_SUBKEY:
        return is_primary() && can_sign() && (if_secret || has_secret());
    case PGP_OP_SIGN:
        return can_sign() && valid() && (if_secret || has_secret());
    case PGP_OP_CERTIFY:
        return can_certify() && valid() && (if_secret || has_secret());
    case PGP_OP_DECRYPT:
        return can_encrypt() && valid() && (if_secret || has_secret());
    case PGP_OP_UNLOCK:
    case PGP_OP_PROTECT:
    case PGP_OP_UNPROTECT:
        return has_secret();
    case PGP_OP_VERIFY:
        return can_sign() && valid();
    case PGP_OP_ADD_USERID:
        return is_primary() && can_sign() && (if_secret || has_secret());
    case PGP_OP_ENCRYPT:
        return can_encrypt() && valid();
    default:
        return false;
    }
}

uint32_t
pgp_key_t::expiration() const noexcept
{
    if (pkt_.version >= 4) {
        return expiration_;
    }
    /* too large value for pkt.v3_days may overflow uint32_t */
    if (pkt_.v3_days > (0xffffffffu / 86400)) {
        return 0xffffffffu;
    }
    return (uint32_t) pkt_.v3_days * 86400;
}

bool
pgp_key_t::expired() const noexcept
{
    return validity_.expired;
}

uint32_t
pgp_key_t::creation() const noexcept
{
    return pkt_.creation_time;
}

bool
pgp_key_t::is_public() const noexcept
{
    return is_public_key_pkt(pkt_.tag);
}

bool
pgp_key_t::is_secret() const noexcept
{
    return is_secret_key_pkt(pkt_.tag);
}

bool
pgp_key_t::is_primary() const noexcept
{
    return is_primary_key_pkt(pkt_.tag);
}

bool
pgp_key_t::is_subkey() const noexcept
{
    return is_subkey_pkt(pkt_.tag);
}

bool
pgp_key_t::is_locked() const noexcept
{
    if (!is_secret()) {
        RNP_LOG("key is not a secret key");
        return false;
    }
    return encrypted();
}

bool
pgp_key_t::is_protected() const noexcept
{
    // sanity check
    if (!is_secret()) {
        RNP_LOG("Warning: this is not a secret key");
    }
    return pkt_.sec_protection.s2k.usage != PGP_S2KU_NONE;
}

bool
pgp_key_t::valid() const noexcept
{
    return validity_.validated && validity_.valid && !validity_.expired;
}

bool
pgp_key_t::validated() const noexcept
{
    return validity_.validated;
}

uint64_t
pgp_key_t::valid_till_common(bool expiry) const
{
    if (!validated()) {
        return 0;
    }
    uint64_t till = expiration() ? (uint64_t) creation() + expiration() : UINT64_MAX;
    if (valid()) {
        return till;
    }
    if (revoked()) {
        /* we should not believe to the compromised key at all */
        if (revocation_.code == PGP_REVOCATION_COMPROMISED) {
            return 0;
        }
        const pgp_subsig_t &revsig = get_sig(revocation_.sigid);
        if (revsig.sig.creation() > creation()) {
            /* pick less time from revocation time and expiration time */
            return std::min((uint64_t) revsig.sig.creation(), till);
        }
        return 0;
    }
    /* if key is not marked as expired then it wasn't valid at all */
    return expiry ? till : 0;
}

uint64_t
pgp_key_t::valid_till() const noexcept
{
    return valid_till_;
}

bool
pgp_key_t::valid_at(uint64_t timestamp) const noexcept
{
    /* TODO: consider implementing more sophisticated checks, as key validity time could
     * possibly be non-continuous */
    return (timestamp >= creation()) && timestamp && (timestamp <= valid_till());
}

const pgp_key_id_t &
pgp_key_t::keyid() const noexcept
{
    return keyid_;
}

const pgp_fingerprint_t &
pgp_key_t::fp() const noexcept
{
    return fingerprint_;
}

const pgp_key_grip_t &
pgp_key_t::grip() const noexcept
{
    return grip_;
}

const pgp_fingerprint_t &
pgp_key_t::primary_fp() const
{
    if (!primary_fp_set_) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    return primary_fp_;
}

bool
pgp_key_t::has_primary_fp() const noexcept
{
    return primary_fp_set_;
}

void
pgp_key_t::unset_primary_fp() noexcept
{
    primary_fp_set_ = false;
    primary_fp_ = {};
}

void
pgp_key_t::link_subkey_fp(pgp_key_t &subkey)
{
    if (!is_primary() || !subkey.is_subkey()) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    subkey.primary_fp_ = fp();
    subkey.primary_fp_set_ = true;
    add_subkey_fp(subkey.fp());
}

void
pgp_key_t::add_subkey_fp(const pgp_fingerprint_t &fp)
{
    if (std::find(subkey_fps_.begin(), subkey_fps_.end(), fp) == subkey_fps_.end()) {
        subkey_fps_.push_back(fp);
    }
}

size_t
pgp_key_t::subkey_count() const noexcept
{
    return subkey_fps_.size();
}

void
pgp_key_t::remove_subkey_fp(const pgp_fingerprint_t &fp)
{
    auto it = std::find(subkey_fps_.begin(), subkey_fps_.end(), fp);
    if (it != subkey_fps_.end()) {
        subkey_fps_.erase(it);
    }
}

const pgp_fingerprint_t &
pgp_key_t::get_subkey_fp(size_t idx) const
{
    return subkey_fps_[idx];
}

const std::vector<pgp_fingerprint_t> &
pgp_key_t::subkey_fps() const
{
    return subkey_fps_;
}

size_t
pgp_key_t::rawpkt_count() const
{
    if (format == PGP_KEY_STORE_G10) {
        return 1;
    }
    return 1 + uid_count() + sig_count();
}

pgp_rawpacket_t &
pgp_key_t::rawpkt()
{
    return rawpkt_;
}

const pgp_rawpacket_t &
pgp_key_t::rawpkt() const
{
    return rawpkt_;
}

void
pgp_key_t::set_rawpkt(const pgp_rawpacket_t &src)
{
    rawpkt_ = src;
}

bool
pgp_key_t::unlock(const pgp_password_provider_t &provider, pgp_op_t op)
{
    // sanity checks
    if (!usable_for(PGP_OP_UNLOCK)) {
        return false;
    }
    // see if it's already unlocked
    if (!is_locked()) {
        return true;
    }

    pgp_password_ctx_t ctx(op, this);
    pgp_key_pkt_t *    decrypted_seckey = pgp_decrypt_seckey(*this, provider, ctx);
    if (!decrypted_seckey) {
        return false;
    }

    // move the decrypted mpis into the pgp_key_t
    pkt_.material = std::move(decrypted_seckey->material);
    delete decrypted_seckey;
    return true;
}

bool
pgp_key_t::lock() noexcept
{
    // sanity checks
    if (!is_secret()) {
        RNP_LOG("invalid args");
        return false;
    }

    // see if it's already locked
    if (is_locked()) {
        return true;
    }

    assert(material());
    if (material()) {
        material()->clear_secret();
    }
    return true;
}

bool
pgp_key_t::protect(const rnp_key_protection_params_t &protection,
                   const pgp_password_provider_t &    password_provider,
                   rnp::SecurityContext &             sctx)
{
    pgp_password_ctx_t ctx(PGP_OP_PROTECT, this);

    // ask the provider for a password
    rnp::secure_array<char, MAX_PASSWORD_LENGTH> password;
    if (!pgp_request_password(&password_provider, &ctx, password.data(), password.size())) {
        return false;
    }
    return protect(pkt_, protection, password.data(), sctx);
}

bool
pgp_key_t::protect(pgp_key_pkt_t &                    decrypted,
                   const rnp_key_protection_params_t &protection,
                   const std::string &                new_password,
                   rnp::SecurityContext &             ctx)
{
    if (!is_secret()) {
        RNP_LOG("Warning: this is not a secret key");
        return false;
    }
    bool ownpkt = &decrypted == &pkt_;
    if (!decrypted.material->secret()) {
        RNP_LOG("Decrypted secret key must be provided");
        return false;
    }

    /* force encrypted-and-hashed and iterated-and-salted as it's the only method we support*/
    pkt_.sec_protection.s2k.usage = PGP_S2KU_ENCRYPTED_AND_HASHED;
    pkt_.sec_protection.s2k.specifier = PGP_S2KS_ITERATED_AND_SALTED;
    /* use default values where needed */
    pkt_.sec_protection.symm_alg =
      protection.symm_alg ? protection.symm_alg : DEFAULT_PGP_SYMM_ALG;
    pkt_.sec_protection.cipher_mode =
      protection.cipher_mode ? protection.cipher_mode : DEFAULT_PGP_CIPHER_MODE;
    pkt_.sec_protection.s2k.hash_alg =
      protection.hash_alg ? protection.hash_alg : DEFAULT_PGP_HASH_ALG;
    auto iter = protection.iterations;
    if (!iter) {
        iter = ctx.s2k_iterations(pkt_.sec_protection.s2k.hash_alg);
    }
    pkt_.sec_protection.s2k.iterations = pgp_s2k_round_iterations(iter);
    if (!ownpkt) {
        /* decrypted is assumed to be temporary variable so we may modify it */
        decrypted.sec_protection = pkt_.sec_protection;
    }

    /* write the protected key to raw packet */
    return write_sec_rawpkt(decrypted, new_password, ctx);
}

bool
pgp_key_t::unprotect(const pgp_password_provider_t &password_provider,
                     rnp::SecurityContext &         secctx)
{
    /* sanity check */
    if (!is_secret()) {
        RNP_LOG("Warning: this is not a secret key");
        return false;
    }
    /* already unprotected */
    if (!is_protected()) {
        return true;
    }
    /* simple case */
    if (!encrypted()) {
        pkt_.sec_protection.s2k.usage = PGP_S2KU_NONE;
        return write_sec_rawpkt(pkt_, "", secctx);
    }

    pgp_password_ctx_t ctx(PGP_OP_UNPROTECT, this);

    pgp_key_pkt_t *decrypted_seckey = pgp_decrypt_seckey(*this, password_provider, ctx);
    if (!decrypted_seckey) {
        return false;
    }
    decrypted_seckey->sec_protection.s2k.usage = PGP_S2KU_NONE;
    if (!write_sec_rawpkt(*decrypted_seckey, "", secctx)) {
        delete decrypted_seckey;
        return false;
    }
    pkt_ = std::move(*decrypted_seckey);
    /* current logic is that unprotected key should be additionally unlocked */
    assert(material());
    if (material()) {
        material()->clear_secret();
    }
    delete decrypted_seckey;
    return true;
}

void
pgp_key_t::write(pgp_dest_t &dst) const
{
    /* write key rawpacket */
    rawpkt_.write(dst);

    if (format == PGP_KEY_STORE_G10) {
        return;
    }

    /* write signatures on key */
    for (auto &sigid : keysigs_) {
        get_sig(sigid).rawpkt.write(dst);
    }

    /* write uids and their signatures */
    for (const auto &uid : uids_) {
        uid.rawpkt.write(dst);
        for (size_t idx = 0; idx < uid.sig_count(); idx++) {
            get_sig(uid.get_sig(idx)).rawpkt.write(dst);
        }
    }
}

void
pgp_key_t::write_xfer(pgp_dest_t &dst, const rnp::KeyStore *keyring) const
{
    write(dst);
    if (dst.werr) {
        RNP_LOG("Failed to export primary key");
        return;
    }

    if (!keyring) {
        return;
    }

    // Export subkeys
    for (auto &fp : subkey_fps_) {
        const pgp_key_t *subkey = keyring->get_key(fp);
        if (!subkey) {
            char fphex[PGP_FINGERPRINT_HEX_SIZE] = {0};
            rnp::hex_encode(
              fp.fingerprint, fp.length, fphex, sizeof(fphex), rnp::HexFormat::Lowercase);
            RNP_LOG("Warning! Subkey %s not found.", fphex);
            continue;
        }
        subkey->write(dst);
        if (dst.werr) {
            RNP_LOG("Error occurred when exporting a subkey");
            return;
        }
    }
}

bool
pgp_key_t::write_autocrypt(pgp_dest_t &dst, pgp_key_t &sub, uint32_t uid)
{
    pgp_subsig_t *cert = latest_uid_selfcert(uid);
    if (!cert) {
        RNP_LOG("No valid uid certification");
        return false;
    }
    pgp_subsig_t *binding = sub.latest_binding();
    if (!binding) {
        RNP_LOG("No valid binding for subkey");
        return false;
    }
    if (is_secret() || sub.is_secret()) {
        RNP_LOG("Public key required");
        return false;
    }

    try {
        /* write all or nothing */
        rnp::MemoryDest memdst;
        pkt().write(memdst.dst());
        get_uid(uid).pkt.write(memdst.dst());
        cert->sig.write(memdst.dst());
        sub.pkt().write(memdst.dst());
        binding->sig.write(memdst.dst());
        dst_write(&dst, memdst.memory(), memdst.writeb());
        return !dst.werr;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return false;
    }
}

std::vector<uint8_t>
pgp_key_t::write_vec() const
{
    rnp::MemoryDest dst;
    write(dst.dst());
    return dst.to_vector();
}

/* look only for primary userids */
#define PGP_UID_PRIMARY ((uint32_t) -2)
/* look for any uid, except PGP_UID_NONE) */
#define PGP_UID_ANY ((uint32_t) -3)

pgp_subsig_t *
pgp_key_t::latest_selfsig(uint32_t uid)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = nullptr;

    for (auto &sigid : sigs_) {
        auto &sig = get_sig(sigid);
        if (!sig.valid()) {
            continue;
        }
        bool skip = false;
        switch (uid) {
        case PGP_UID_NONE:
            skip = (sig.uid != PGP_UID_NONE) || !is_direct_self(sig);
            break;
        case PGP_UID_PRIMARY: {
            skip = !is_self_cert(sig) ||
                   !sig.sig.get_subpkt(pgp::pkt::sigsub::Type::PrimaryUserID) ||
                   !sig.sig.primary_uid() || (sig.uid == PGP_UID_NONE);
            break;
        }
        case PGP_UID_ANY:
            skip = !is_self_cert(sig) || (sig.uid == PGP_UID_NONE);
            break;
        default:
            skip = (sig.uid != uid) || !is_self_cert(sig);
            break;
        }
        if (skip) {
            continue;
        }

        uint32_t creation = sig.sig.creation();
        if (creation >= latest) {
            latest = creation;
            res = &sig;
        }
    }

    /* if there is later self-sig for the same uid without primary flag, then drop res */
    if ((uid == PGP_UID_PRIMARY) && res) {
        pgp_subsig_t *overres = latest_selfsig(res->uid);
        if (overres && (overres->sig.creation() > res->sig.creation())) {
            res = nullptr;
        }
    }
    return res;
}

pgp_subsig_t *
pgp_key_t::latest_binding(bool validated)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    for (auto &sigid : sigs_) {
        auto &sig = get_sig(sigid);
        if (validated && !sig.valid()) {
            continue;
        }
        if (!is_binding(sig)) {
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
pgp_key_t::latest_uid_selfcert(uint32_t uid)
{
    uint32_t      latest = 0;
    pgp_subsig_t *res = NULL;

    if (uid >= uids_.size()) {
        return NULL;
    }

    for (size_t idx = 0; idx < uids_[uid].sig_count(); idx++) {
        auto &sig = get_sig(uids_[uid].get_sig(idx));
        if (!sig.valid() || (sig.uid != uid)) {
            continue;
        }
        if (!is_self_cert(sig)) {
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

bool
pgp_key_t::is_signer(const pgp_subsig_t &sig) const
{
    /* if we have fingerprint let's check it */
    if (sig.sig.has_keyfp()) {
        return sig.sig.keyfp() == fp();
    }
    if (!sig.sig.has_keyid()) {
        return false;
    }
    return keyid() == sig.sig.keyid();
}

bool
pgp_key_t::expired_with(const pgp_subsig_t &sig, uint64_t at) const
{
    /* key expiration: absence of subpkt or 0 means it never expires */
    uint64_t expiration = sig.sig.key_expiration();
    if (!expiration) {
        return false;
    }
    return expiration + creation() < at;
}

bool
pgp_key_t::is_self_cert(const pgp_subsig_t &sig) const
{
    return is_primary() && sig.is_cert() && is_signer(sig);
}

bool
pgp_key_t::is_direct_self(const pgp_subsig_t &sig) const
{
    return is_primary() && (sig.sig.type() == PGP_SIG_DIRECT) && is_signer(sig);
}

bool
pgp_key_t::is_revocation(const pgp_subsig_t &sig) const
{
    return is_primary() ? (sig.sig.type() == PGP_SIG_REV_KEY) :
                          (sig.sig.type() == PGP_SIG_REV_SUBKEY);
}

bool
pgp_key_t::is_uid_revocation(const pgp_subsig_t &sig) const
{
    return is_primary() && (sig.sig.type() == PGP_SIG_REV_CERT);
}

bool
pgp_key_t::is_binding(const pgp_subsig_t &sig) const
{
    return is_subkey() && (sig.sig.type() == PGP_SIG_SUBKEY);
}

void
pgp_key_t::validate_sig(const pgp_key_t &           key,
                        pgp_subsig_t &              sig,
                        const rnp::SecurityContext &ctx) const noexcept
{
    sig.validity.reset();

    pgp_signature_info_t sinfo = {};
    sinfo.sig = &sig.sig;
    sinfo.signer_valid = true;
    if (key.is_self_cert(sig) || key.is_binding(sig)) {
        sinfo.ignore_expiry = true;
    }

    pgp_sig_type_t stype = sig.sig.type();
    try {
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
            validate_cert(sinfo, key.pkt(), key.get_uid(sig.uid).pkt, ctx);
            break;
        }
        case PGP_SIG_SUBKEY:
            if (!is_signer(sig)) {
                RNP_LOG("Invalid subkey binding's signer.");
                return;
            }
            validate_binding(sinfo, key, ctx);
            break;
        case PGP_SIG_DIRECT:
            if (!is_signer(sig)) {
                RNP_LOG("Invalid direct key signer.");
                return;
            }
            validate_direct(sinfo, ctx);
            break;
        case PGP_SIG_REV_KEY:
            if (!is_signer(sig)) {
                RNP_LOG("Invalid key revocation signer.");
                return;
            }
            validate_key_rev(sinfo, key.pkt(), ctx);
            break;
        case PGP_SIG_REV_SUBKEY:
            if (!is_signer(sig)) {
                RNP_LOG("Invalid subkey revocation's signer.");
                return;
            }
            validate_sub_rev(sinfo, key.pkt(), ctx);
            break;
        default:
            RNP_LOG("Unsupported key signature type: %d", (int) stype);
            return;
        }
    } catch (const std::exception &e) {
        RNP_LOG("Key signature validation failed: %s", e.what());
    }

    sig.validity.validated = true;
    sig.validity.valid = sinfo.valid;
    /* revocation signature cannot expire */
    if ((stype != PGP_SIG_REV_KEY) && (stype != PGP_SIG_REV_SUBKEY) &&
        (stype != PGP_SIG_REV_CERT)) {
        sig.validity.expired = sinfo.expired;
    }
}

void
pgp_key_t::validate_sig(pgp_signature_info_t &      sinfo,
                        rnp::Hash &                 hash,
                        const rnp::SecurityContext &ctx,
                        const pgp_literal_hdr_t *   hdr) const noexcept
{
    sinfo.no_signer = false;
    sinfo.valid = false;
    sinfo.expired = false;

    /* Validate signature itself */
    if (sinfo.signer_valid || valid_at(sinfo.sig->creation())) {
        sinfo.valid = !signature_validate(*sinfo.sig, *pkt_.material, hash, ctx, hdr);
    } else {
        sinfo.valid = false;
        RNP_LOG("invalid or untrusted key");
    }

    /* Check signature's expiration time */
    uint32_t now = ctx.time();
    uint32_t create = sinfo.sig->creation();
    uint32_t expiry = sinfo.sig->expiration();
    if (create > now) {
        /* signature created later then now */
        RNP_LOG("signature created %d seconds in future", (int) (create - now));
        sinfo.expired = true;
    }
    if (create && expiry && (create + expiry < now)) {
        /* signature expired */
        RNP_LOG("signature expired");
        sinfo.expired = true;
    }

    /* check key creation time vs signature creation */
    if (creation() > create) {
        RNP_LOG("key is newer than signature");
        sinfo.valid = false;
    }

    /* check whether key was not expired when sig created */
    if (!sinfo.ignore_expiry && expiration() && (creation() + expiration() < create)) {
        RNP_LOG("signature made after key expiration");
        sinfo.valid = false;
    }

    /* Check signer's fingerprint */
    if (sinfo.sig->has_keyfp() && (sinfo.sig->keyfp() != fp())) {
        RNP_LOG("issuer fingerprint doesn't match signer's one");
        sinfo.valid = false;
    }

    /* Check for unknown critical notations */
    for (auto &subpkt : sinfo.sig->subpkts) {
        if (!subpkt->critical() || (subpkt->type() != pgp::pkt::sigsub::Type::NotationData)) {
            continue;
        }
        auto &notation = dynamic_cast<pgp::pkt::sigsub::NotationData &>(*subpkt);
        RNP_LOG("unknown critical notation: %s", notation.name().c_str());
        sinfo.valid = false;
    }
}

void
pgp_key_t::validate_cert(pgp_signature_info_t &      sinfo,
                         const pgp_key_pkt_t &       key,
                         const pgp_userid_pkt_t &    uid,
                         const rnp::SecurityContext &ctx) const
{
    auto hash = signature_hash_certification(*sinfo.sig, key, uid);
    validate_sig(sinfo, *hash, ctx);
}

void
pgp_key_t::validate_binding(pgp_signature_info_t &      sinfo,
                            const pgp_key_t &           subkey,
                            const rnp::SecurityContext &ctx) const
{
    if (!is_primary() || !subkey.is_subkey()) {
        RNP_LOG("Invalid binding signature key type(s)");
        sinfo.valid = false;
        return;
    }
    auto hash = signature_hash_binding(*sinfo.sig, pkt(), subkey.pkt());
    validate_sig(sinfo, *hash, ctx);
    if (!sinfo.valid || !(sinfo.sig->key_flags() & PGP_KF_SIGN)) {
        return;
    }

    /* check primary key binding signature if any */
    sinfo.valid = false;
    auto sub = dynamic_cast<pgp::pkt::sigsub::EmbeddedSignature *>(
      sinfo.sig->get_subpkt(pgp::pkt::sigsub::Type::EmbeddedSignature, false));
    if (!sub) {
        RNP_LOG("error! no primary key binding signature");
        return;
    }
    if (!sub->signature()) {
        RNP_LOG("invalid embedded signature subpacket");
        return;
    }
    if (sub->signature()->type() != PGP_SIG_PRIMARY) {
        RNP_LOG("invalid primary key binding signature");
        return;
    }
    if (sub->signature()->version < PGP_V4) {
        RNP_LOG("invalid primary key binding signature version");
        return;
    }

    hash = signature_hash_binding(*sub->signature(), pkt(), subkey.pkt());
    pgp_signature_info_t bindinfo = {};
    bindinfo.sig = sub->signature();
    bindinfo.signer_valid = true;
    bindinfo.ignore_expiry = true;
    subkey.validate_sig(bindinfo, *hash, ctx);
    sinfo.valid = bindinfo.valid && !bindinfo.expired;
}

void
pgp_key_t::validate_sub_rev(pgp_signature_info_t &      sinfo,
                            const pgp_key_pkt_t &       subkey,
                            const rnp::SecurityContext &ctx) const
{
    auto hash = signature_hash_binding(*sinfo.sig, pkt(), subkey);
    validate_sig(sinfo, *hash, ctx);
}

void
pgp_key_t::validate_direct(pgp_signature_info_t &sinfo, const rnp::SecurityContext &ctx) const
{
    auto hash = signature_hash_direct(*sinfo.sig, pkt());
    validate_sig(sinfo, *hash, ctx);
}

void
pgp_key_t::validate_key_rev(pgp_signature_info_t &      sinfo,
                            const pgp_key_pkt_t &       key,
                            const rnp::SecurityContext &ctx) const
{
    auto hash = signature_hash_direct(*sinfo.sig, key);
    validate_sig(sinfo, *hash, ctx);
}

void
pgp_key_t::validate_self_signatures(const rnp::SecurityContext &ctx)
{
    for (auto &sigid : sigs_) {
        auto &sig = get_sig(sigid);
        if (sig.validity.validated) {
            continue;
        }
        if (!is_signer(sig)) {
            continue;
        }

        if (is_direct_self(sig) || is_self_cert(sig) || is_uid_revocation(sig) ||
            is_revocation(sig)) {
            validate_sig(*this, sig, ctx);
        }
    }
}

void
pgp_key_t::validate_self_signatures(pgp_key_t &primary, const rnp::SecurityContext &ctx)
{
    for (auto &sigid : sigs_) {
        pgp_subsig_t &sig = get_sig(sigid);
        if (sig.validity.validated) {
            continue;
        }

        if (is_binding(sig) || is_revocation(sig)) {
            primary.validate_sig(*this, sig, ctx);
        }
    }
}

bool
pgp_key_t::validate_desig_revokes(rnp::KeyStore &keyring)
{
    if (revokers_.empty()) {
        return false;
    }
    bool refresh = false;
    for (auto &sigid : sigs_) {
        auto &sig = get_sig(sigid);
        if (!is_revocation(sig) || is_signer(sig)) {
            continue;
        }
        /* Don't think we should deal with sigs without issuer's fingerprint */
        if (!sig.sig.has_keyfp() || !has_revoker(sig.sig.keyfp())) {
            continue;
        }
        /* If signature was validated and valid, do not re-validate it */
        if (sig.validated() && sig.validity.valid) {
            continue;
        }

        auto revoker = keyring.get_signer(sig.sig);
        if (!revoker) {
            continue;
        }

        revoker->validate_sig(*this, sig, keyring.secctx);
        if (sig.valid()) {
            /* return true only if new valid revocation was added */
            refresh = true;
        }
    }

    return refresh;
}

void
pgp_key_t::validate_primary(rnp::KeyStore &keyring)
{
    /* validate signatures if needed */
    validate_self_signatures(keyring.secctx);

    /* consider public key as valid on this level if it is not expired and has at least one
     * valid self-signature, and is not revoked */
    validity_.reset();
    validity_.validated = true;
    bool has_cert = false;
    bool has_expired = false;
    /* check whether key is revoked */
    for (auto &sigid : sigs_) {
        pgp_subsig_t &sig = get_sig(sigid);
        if (!sig.valid()) {
            continue;
        }
        if (is_revocation(sig)) {
            return;
        }
    }
    /* if we have direct-key signature, then it has higher priority for expiration check */
    uint64_t      now = keyring.secctx.time();
    pgp_subsig_t *dirsig = latest_selfsig(PGP_UID_NONE);
    if (dirsig) {
        has_expired = expired_with(*dirsig, now);
        has_cert = !has_expired;
    }
    /* if we have primary uid and it is more restrictive, then use it as well */
    pgp_subsig_t *prisig = NULL;
    if (!has_expired && (prisig = latest_selfsig(PGP_UID_PRIMARY))) {
        has_expired = expired_with(*prisig, now);
        has_cert = !has_expired;
    }
    /* if we don't have direct-key sig and primary uid, use the latest self-cert */
    pgp_subsig_t *latest = NULL;
    if (!dirsig && !prisig && (latest = latest_selfsig(PGP_UID_ANY))) {
        has_expired = expired_with(*latest, now);
        has_cert = !has_expired;
    }

    /* we have at least one non-expiring key self-signature */
    if (has_cert) {
        validity_.valid = true;
        return;
    }
    /* we have valid self-signature which expires key */
    if (has_expired) {
        validity_.expired = true;
        return;
    }

    /* let's check whether key has at least one valid subkey binding */
    for (size_t i = 0; i < subkey_count(); i++) {
        pgp_key_t *sub = keyring.get_subkey(*this, i);
        if (!sub) {
            continue;
        }
        sub->validate_self_signatures(*this, keyring.secctx);
        pgp_subsig_t *sig = sub->latest_binding();
        if (!sig) {
            continue;
        }
        /* check whether subkey is expired - then do not mark key as valid */
        if (sub->expired_with(*sig, now)) {
            continue;
        }
        validity_.valid = true;
        return;
    }
}

void
pgp_key_t::validate_subkey(pgp_key_t *primary, const rnp::SecurityContext &ctx)
{
    /* consider subkey as valid on this level if it has valid primary key, has at least one
     * non-expired binding signature, and is not revoked. */
    validity_.reset();
    validity_.validated = true;
    if (!primary || (!primary->valid() && !primary->expired())) {
        return;
    }
    /* validate signatures if needed */
    validate_self_signatures(*primary, ctx);

    bool has_binding = false;
    bool has_expired = false;
    for (auto &sigid : sigs_) {
        pgp_subsig_t &sig = get_sig(sigid);
        if (!sig.valid()) {
            continue;
        }

        if (is_binding(sig) && !has_binding) {
            /* check whether subkey is expired */
            if (expired_with(sig, ctx.time())) {
                has_expired = true;
                continue;
            }
            has_binding = true;
        } else if (is_revocation(sig)) {
            return;
        }
    }
    validity_.valid = has_binding && primary->valid();
    if (!validity_.valid) {
        validity_.expired = has_expired;
    }
}

void
pgp_key_t::validate(rnp::KeyStore &keyring)
{
    validity_.reset();
    if (!is_subkey()) {
        validate_primary(keyring);
        return;
    }
    pgp_key_t *primary = nullptr;
    if (has_primary_fp()) {
        primary = keyring.get_key(primary_fp());
    }
    validate_subkey(primary, keyring.secctx);
}

void
pgp_key_t::revalidate(rnp::KeyStore &keyring)
{
    if (is_subkey()) {
        pgp_key_t *primary = keyring.primary_key(*this);
        if (primary) {
            primary->revalidate(keyring);
        } else {
            validate_subkey(NULL, keyring.secctx);
        }
        return;
    }

    validate_desig_revokes(keyring);
    validate(keyring);
    if (!refresh_data(keyring.secctx)) {
        RNP_LOG("Failed to refresh key data");
    }
    /* validate/re-validate all subkeys as well */
    for (auto &fp : subkey_fps_) {
        pgp_key_t *subkey = keyring.get_key(fp);
        if (subkey) {
            subkey->validate_subkey(this, keyring.secctx);
            if (!subkey->refresh_data(this, keyring.secctx)) {
                RNP_LOG("Failed to refresh subkey data");
            }
        }
    }
}

void
pgp_key_t::mark_valid()
{
    validity_.mark_valid();
    for (size_t i = 0; i < sig_count(); i++) {
        get_sig(i).validity.mark_valid();
    }
}

void
pgp_key_t::sign_init(rnp::RNG &       rng,
                     pgp_signature_t &sig,
                     pgp_hash_alg_t   hash,
                     uint64_t         creation,
                     pgp_version_t    version) const
{
    sig.version = version;
    sig.halg = pkt_.material->adjust_hash(hash);
    sig.palg = alg();
    sig.set_keyfp(fp());
    sig.set_creation(creation);
    if (version == PGP_V4) {
        // for v6 issuing keys, this MUST NOT be included
        sig.set_keyid(keyid());
    }
#if defined(ENABLE_CRYPTO_REFRESH)
    if (version == PGP_V6) {
        sig.salt.resize(rnp::Hash::size(sig.halg) / 2);
        rng.get(sig.salt.data(), sig.salt.size());
    }
#endif
}

void
pgp_key_t::sign_cert(const pgp_key_pkt_t &   key,
                     const pgp_userid_pkt_t &uid,
                     pgp_signature_t &       sig,
                     rnp::SecurityContext &  ctx)
{
    sig.fill_hashed_data();
    auto hash = signature_hash_certification(sig, key, uid);
    signature_calculate(sig, *pkt_.material, *hash, ctx);
}

void
pgp_key_t::sign_direct(const pgp_key_pkt_t & key,
                       pgp_signature_t &     sig,
                       rnp::SecurityContext &ctx)
{
    sig.fill_hashed_data();
    auto hash = signature_hash_direct(sig, key);
    signature_calculate(sig, *pkt_.material, *hash, ctx);
}

void
pgp_key_t::sign_binding(const pgp_key_pkt_t & key,
                        pgp_signature_t &     sig,
                        rnp::SecurityContext &ctx)
{
    sig.fill_hashed_data();
    auto hash = is_primary() ? signature_hash_binding(sig, pkt(), key) :
                               signature_hash_binding(sig, key, pkt());
    signature_calculate(sig, *pkt_.material, *hash, ctx);
}

void
pgp_key_t::gen_revocation(const pgp_revoke_t &  revoke,
                          pgp_hash_alg_t        hash,
                          const pgp_key_pkt_t & key,
                          pgp_signature_t &     sig,
                          rnp::SecurityContext &ctx)
{
    sign_init(ctx.rng, sig, hash, ctx.time(), key.version);
    sig.set_type(is_primary_key_pkt(key.tag) ? PGP_SIG_REV_KEY : PGP_SIG_REV_SUBKEY);
    sig.set_revocation_reason(revoke.code, revoke.reason);

    if (is_primary_key_pkt(key.tag)) {
        sign_direct(key, sig, ctx);
    } else {
        sign_binding(key, sig, ctx);
    }
}

void
pgp_key_t::sign_subkey_binding(pgp_key_t &           sub,
                               pgp_signature_t &     sig,
                               rnp::SecurityContext &ctx,
                               bool                  subsign)
{
    if (!is_primary()) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    sign_binding(sub.pkt(), sig, ctx);
    /* add primary key binding subpacket if requested */
    if (subsign) {
        pgp_signature_t embsig;
        sub.sign_init(ctx.rng, embsig, sig.halg, ctx.time(), sub.version());
        embsig.set_type(PGP_SIG_PRIMARY);
        sub.sign_binding(pkt(), embsig, ctx);
        sig.set_embedded_sig(embsig);
    }
}

#if defined(ENABLE_CRYPTO_REFRESH)
void
pgp_key_t::add_direct_sig(rnp::CertParams &     cert,
                          pgp_hash_alg_t        hash,
                          rnp::SecurityContext &ctx,
                          pgp_key_t *           pubkey)
{
    // We only support modifying v4 and newer keys
    if (pkt().version < PGP_V4) {
        RNP_LOG("adding a direct-key sig to V2/V3 key is not supported");
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    pgp_signature_t sig;
    sign_init(ctx.rng, sig, hash, ctx.time(), pkt().version);
    sig.set_type(PGP_SIG_DIRECT);
    cert.populate(sig);
    sign_direct(pkt_, sig, ctx);

    add_sig(sig, PGP_UID_NONE);
    refresh_data(ctx);
    if (!pubkey) {
        return;
    }
    pubkey->add_sig(sig, PGP_UID_NONE);
    pubkey->refresh_data(ctx);
}
#endif

void
pgp_key_t::add_uid_cert(rnp::CertParams &     cert,
                        pgp_hash_alg_t        hash,
                        rnp::SecurityContext &ctx,
                        pgp_key_t *           pubkey)
{
    if (cert.userid.empty()) {
        /* todo: why not to allow empty uid? */
        RNP_LOG("wrong parameters");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    // userids are only valid for primary keys, not subkeys
    if (!is_primary()) {
        RNP_LOG("cannot add a userid to a subkey");
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }
    // see if the key already has this userid
    if (has_uid(cert.userid)) {
        RNP_LOG("key already has this userid");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    // this isn't really valid for this format
    if (format == PGP_KEY_STORE_G10) {
        RNP_LOG("Unsupported key store type");
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }
    // We only support modifying v4 and newer keys
    if (pkt().version < PGP_V4) {
        RNP_LOG("adding a userid to V2/V3 key is not supported");
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }
    /* TODO: if key has at least one uid then has_primary_uid() will be always true! */
    if (has_primary_uid() && cert.primary) {
        RNP_LOG("changing the primary userid is not supported");
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    /* Fill the transferable userid */
    pgp_userid_pkt_t uid;
    pgp_signature_t  sig;
    sign_init(ctx.rng, sig, hash, ctx.time(), pkt().version);
    cert.populate(uid, sig);
    try {
        sign_cert(pkt_, uid, sig, ctx);
    } catch (const std::exception &e) {
        RNP_LOG("Failed to certify: %s", e.what());
        throw;
    }
    /* add uid and signature to the key and pubkey, if non-NULL */
    uids_.emplace_back(uid);
    add_sig(sig, uid_count() - 1);
    refresh_data(ctx);
    if (!pubkey) {
        return;
    }
    pubkey->uids_.emplace_back(uid);
    pubkey->add_sig(sig, pubkey->uid_count() - 1);
    pubkey->refresh_data(ctx);
}

void
pgp_key_t::add_sub_binding(pgp_key_t &               subsec,
                           pgp_key_t &               subpub,
                           const rnp::BindingParams &binding,
                           pgp_hash_alg_t            hash,
                           rnp::SecurityContext &    ctx)
{
    if (!is_primary()) {
        RNP_LOG("must be called on primary key");
        throw rnp::rnp_exception(RNP_ERROR_BAD_STATE);
    }

    /* populate signature */
    pgp_signature_t sig;
    sign_init(ctx.rng, sig, hash, ctx.time(), version());
    sig.set_type(PGP_SIG_SUBKEY);
    if (binding.expiration) {
        sig.set_key_expiration(binding.expiration);
    }
    if (binding.flags) {
        sig.set_key_flags(binding.flags);
    }
    /* calculate binding */
    pgp_key_flags_t realkf = (pgp_key_flags_t) binding.flags;
    if (!realkf) {
        realkf = pgp_pk_alg_capabilities(subsec.alg());
    }
    sign_subkey_binding(subsec, sig, ctx, realkf & PGP_KF_SIGN);
    /* add to the secret and public key */
    subsec.add_sig(sig);
    subpub.add_sig(sig);
}

void
pgp_key_t::refresh_revocations()
{
    clear_revokes();
    for (size_t i = 0; i < sig_count(); i++) {
        pgp_subsig_t &sig = get_sig(i);
        if (!sig.valid()) {
            continue;
        }
        if (is_revocation(sig)) {
            if (revoked_) {
                continue;
            }
            revoked_ = true;
            revocation_ = pgp_revoke_t(sig);
            continue;
        }
        if (is_uid_revocation(sig)) {
            if (sig.uid >= uid_count()) {
                RNP_LOG("Invalid uid index");
                continue;
            }
            pgp_userid_t &uid = get_uid(sig.uid);
            if (uid.revoked) {
                continue;
            }
            uid.revoked = true;
            uid.revocation = pgp_revoke_t(sig);
        }
    }
}

bool
pgp_key_t::refresh_data(const rnp::SecurityContext &ctx)
{
    if (!is_primary()) {
        RNP_LOG("key must be primary");
        return false;
    }
    /* validate self-signatures if not done yet */
    validate_self_signatures(ctx);
    /* key expiration */
    expiration_ = 0;
    /* if we have direct-key signature, then it has higher priority */
    pgp_subsig_t *dirsig = latest_selfsig(PGP_UID_NONE);
    if (dirsig) {
        expiration_ = dirsig->sig.key_expiration();
    }
    /* if we have primary uid and it is more restrictive, then use it as well */
    pgp_subsig_t *prisig = latest_selfsig(PGP_UID_PRIMARY);
    if (prisig && prisig->sig.key_expiration() &&
        (!expiration_ || (prisig->sig.key_expiration() < expiration_))) {
        expiration_ = prisig->sig.key_expiration();
    }
    /* if we don't have direct-key sig and primary uid, use the latest self-cert */
    pgp_subsig_t *latest = latest_selfsig(PGP_UID_ANY);
    if (!dirsig && !prisig && latest) {
        expiration_ = latest->sig.key_expiration();
    }
    /* key flags: check in direct-key sig first, then primary uid, and then latest */
    if (dirsig && dirsig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        flags_ = dirsig->sig.key_flags();
    } else if (prisig && prisig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        flags_ = prisig->sig.key_flags();
    } else if (latest && latest->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        flags_ = latest->sig.key_flags();
    } else {
        flags_ = pgp_pk_alg_capabilities(alg());
    }
    /* designated revokers */
    revokers_.clear();
    for (size_t i = 0; i < sig_count(); i++) {
        pgp_subsig_t &sig = get_sig(i);
        /* pick designated revokers only from direct-key signatures */
        if (!sig.valid() || !is_direct_self(sig)) {
            continue;
        }
        if (!sig.sig.has_revoker()) {
            continue;
        }
        add_revoker(sig.sig.revoker());
    }
    /* revocation(s) */
    refresh_revocations();
    /* valid till */
    valid_till_ = valid_till_common(expired());
    /* userid validities */
    for (size_t i = 0; i < uid_count(); i++) {
        get_uid(i).valid = false;
    }
    for (size_t i = 0; i < sig_count(); i++) {
        pgp_subsig_t &sig = get_sig(i);
        /* consider userid as valid if it has at least one non-expired self-sig */
        if (!sig.valid() || !sig.is_cert() || !is_signer(sig) || sig.expired(ctx.time())) {
            continue;
        }
        if (sig.uid >= uid_count()) {
            continue;
        }
        get_uid(sig.uid).valid = true;
    }
    /* check whether uid is revoked */
    for (size_t i = 0; i < uid_count(); i++) {
        pgp_userid_t &uid = get_uid(i);
        if (uid.revoked) {
            uid.valid = false;
        }
    }
    /* primary userid: use latest one which is not overridden by later non-primary selfsig */
    uid0_set_ = false;
    if (prisig && get_uid(prisig->uid).valid) {
        uid0_ = prisig->uid;
        uid0_set_ = true;
    }
    return true;
}

bool
pgp_key_t::refresh_data(pgp_key_t *primary, const rnp::SecurityContext &ctx)
{
    /* validate self-signatures if not done yet */
    if (primary) {
        validate_self_signatures(*primary, ctx);
    }
    pgp_subsig_t *sig = latest_binding(primary);
    /* subkey expiration */
    expiration_ = sig ? sig->sig.key_expiration() : 0;
    /* subkey flags */
    if (sig && sig->sig.has_subpkt(PGP_SIG_SUBPKT_KEY_FLAGS)) {
        flags_ = sig->sig.key_flags();
    } else {
        flags_ = pgp_pk_alg_capabilities(alg());
    }
    /* revocation */
    clear_revokes();
    for (size_t i = 0; i < sig_count(); i++) {
        pgp_subsig_t &sig = get_sig(i);
        if (!sig.valid() || !is_revocation(sig)) {
            continue;
        }
        revoked_ = true;
        try {
            revocation_ = pgp_revoke_t(sig);
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
        break;
    }
    /* valid till */
    if (primary) {
        valid_till_ =
          std::min(primary->valid_till(), valid_till_common(expired() || primary->expired()));
    } else {
        valid_till_ = valid_till_common(expired());
    }
    return true;
}

void
pgp_key_t::merge_validity(const pgp_validity_t &src)
{
    validity_.valid = validity_.valid && src.valid;
    /* We may safely leave validated status only if both merged keys are valid && validated.
     * Otherwise we'll need to revalidate. For instance, one validated but invalid key may add
     * revocation signature, or valid key may add certification to the invalid one. */
    validity_.validated = validity_.valid && validity_.validated && src.validated;
    /* if expired is true at least in one case then valid and validated are false */
    validity_.expired = false;
}

bool
pgp_key_t::merge(const pgp_key_t &src)
{
    assert(!is_subkey());
    assert(!src.is_subkey());

    /* if src is secret key then merged key will become secret as well. */
    if (src.is_secret() && !is_secret()) {
        pkt_ = src.pkt();
        rawpkt_ = src.rawpkt();
        /* no subkey processing here - they are separated from the main key */
    }

    /* merge direct-key signatures */
    for (auto &sigid : src.keysigs_) {
        if (has_sig(sigid)) {
            continue;
        }
        add_sig(src.get_sig(sigid).sig);
    }

    /* merge user ids and their signatures */
    for (auto &srcuid : src.uids_) {
        /* check whether we have this uid and add if needed */
        size_t uididx = get_uid_idx(srcuid.pkt);
        if (uididx == PGP_UID_NONE) {
            uididx = uid_count();
            uids_.emplace_back(srcuid.pkt);
        }
        /* add uid signatures */
        for (size_t idx = 0; idx < srcuid.sig_count(); idx++) {
            auto &sigid = srcuid.get_sig(idx);
            if (has_sig(sigid)) {
                continue;
            }
            add_sig(src.get_sig(sigid).sig, uididx);
        }
    }

    /* Update subkey fingerprints */
    for (auto &fp : src.subkey_fps()) {
        add_subkey_fp(fp);
    }

    /* check whether key was unlocked and assign secret key data */
    if (src.is_secret() && !src.is_locked() && (!is_secret() || is_locked())) {
        pkt().material = src.pkt().material->clone();
    }
    /* copy validity status */
    merge_validity(src.validity_);
    return true;
}

bool
pgp_key_t::merge(const pgp_key_t &src, pgp_key_t *primary)
{
    assert(is_subkey());
    assert(src.is_subkey());

    /* if src is secret key then merged key will become secret as well. */
    if (src.is_secret() && !is_secret()) {
        pkt_ = src.pkt();
        rawpkt_ = src.rawpkt();
    }

    /* add subkey binding signatures */
    for (auto &sigid : src.keysigs_) {
        if (has_sig(sigid)) {
            continue;
        }
        add_sig(src.get_sig(sigid).sig);
    }

    /* check whether key was unlocked and assign secret key data */
    if (src.is_secret() && !src.is_locked() && (!is_secret() || is_locked())) {
        pkt().material = src.pkt().material->clone();
    }
    /* copy validity status */
    merge_validity(src.validity_);
    /* link subkey fps */
    if (primary) {
        primary->link_subkey_fp(*this);
    }
    return true;
}
