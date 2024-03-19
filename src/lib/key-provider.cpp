/*
 * Copyright (c) 2017-2024 [Ribose Inc](https://www.ribose.com).
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

#include <string>
#include <map>
#include "key-provider.h"
#include "pgp-key.h"
#include "fingerprint.h"
#include "types.h"
#include "utils.h"
#include "str-utils.h"
#include "crypto/mem.h"
#include <rekey/rnp_key_store.h>

namespace rnp {

KeySearch::Type
KeySearch::find_type(const std::string &name)
{
    static const std::map<const std::string, KeySearch::Type> types = {
      {"keyid", Type::KeyID},
      {"fingerprint", Type::Fingerprint},
      {"grip", Type::Grip},
      {"userid", Type::UserID}};
    if (types.find(name) == types.end()) {
        return Type::Unknown;
    }
    return types.at(name);
}

std::unique_ptr<KeySearch>
KeySearch::create(const pgp_key_id_t &keyid)
{
    return std::unique_ptr<KeySearch>(new KeyIDSearch(keyid));
}

std::unique_ptr<KeySearch>
KeySearch::create(const pgp_fingerprint_t &fp)
{
    return std::unique_ptr<KeySearch>(new KeyFingerprintSearch(fp));
}

std::unique_ptr<KeySearch>
KeySearch::create(const pgp_key_grip_t &grip)
{
    return std::unique_ptr<KeySearch>(new KeyGripSearch(grip));
}

std::unique_ptr<KeySearch>
KeySearch::create(const std::string &uid)
{
    return std::unique_ptr<KeySearch>(new KeyUIDSearch(uid));
}

std::unique_ptr<KeySearch>
KeySearch::create(const std::string &name, const std::string &value)
{
    auto type = find_type(name);
    if (type == Type::Unknown) {
        return nullptr;
    }
    if (type == Type::UserID) {
        return create(value);
    }
    /* All the rest values are hex-encoded */
    auto binval = hex_to_bin(value);
    if (binval.empty()) {
        return nullptr;
    }
    switch (type) {
    case Type::Fingerprint:
        if (!pgp_fingerprint_t::size_valid(binval.size())) {
            RNP_LOG("Invalid fingerprint: %s", value.c_str());
            return nullptr;
        }
        return create(pgp_fingerprint_t(binval));
    case Type::KeyID: {
        if (binval.size() != PGP_KEY_ID_SIZE) {
            RNP_LOG("Invalid keyid: %s", value.c_str());
            return nullptr;
        }
        pgp_key_id_t keyid{};
        memcpy(keyid.data(), binval.data(), keyid.size());
        return create(keyid);
    }
    case Type::Grip: {
        if (binval.size() != PGP_KEY_GRIP_SIZE) {
            RNP_LOG("Invalid grip: %s", value.c_str());
            return nullptr;
        }
        pgp_key_grip_t grip{};
        memcpy(grip.data(), binval.data(), grip.size());
        return create(grip);
    }
    default:
        return nullptr;
    }
}

bool
KeyIDSearch::matches(const pgp_key_t &key) const
{
    return (key.keyid() == keyid_) || (keyid_ == pgp_key_id_t({}));
}

const std::string
KeyIDSearch::name() const
{
    return "keyid";
}

std::string
KeyIDSearch::value() const
{
    return bin_to_hex(keyid_.data(), keyid_.size());
}

bool
KeyIDSearch::hidden() const
{
    return keyid_ == pgp_key_id_t({});
}

KeyIDSearch::KeyIDSearch(const pgp_key_id_t &keyid)
{
    type_ = Type::KeyID;
    keyid_ = keyid;
}

bool
KeyFingerprintSearch::matches(const pgp_key_t &key) const
{
    return key.fp() == fp_;
}

const std::string
KeyFingerprintSearch::name() const
{
    return "fingerprint";
}

std::string
KeyFingerprintSearch::value() const
{
    return bin_to_hex(fp_.fingerprint, fp_.length);
}

KeyFingerprintSearch::KeyFingerprintSearch(const pgp_fingerprint_t &fp)
{
    type_ = Type::Fingerprint;
    fp_ = fp;
}

const pgp_fingerprint_t &
KeyFingerprintSearch::get_fp() const
{
    return fp_;
}

bool
KeyGripSearch::matches(const pgp_key_t &key) const
{
    return key.grip() == grip_;
}

const std::string
KeyGripSearch::name() const
{
    return "grip";
}

std::string
KeyGripSearch::value() const
{
    return bin_to_hex(grip_.data(), grip_.size());
}

KeyGripSearch::KeyGripSearch(const pgp_key_grip_t &grip)
{
    type_ = Type::Grip;
    grip_ = grip;
}

bool
KeyUIDSearch::matches(const pgp_key_t &key) const
{
    return key.has_uid(uid_);
}

const std::string
KeyUIDSearch::name() const
{
    return "userid";
}

std::string
KeyUIDSearch::value() const
{
    return uid_;
}

KeyUIDSearch::KeyUIDSearch(const std::string &uid)
{
    type_ = Type::UserID;
    uid_ = uid;
}

pgp_key_t *
KeyProvider::request_key(const KeySearch &search, pgp_op_t op, bool secret) const
{
    pgp_key_t *key = nullptr;
    if (!callback) {
        return key;
    }
    pgp_key_request_ctx_t ctx(op, secret, search);
    if (!(key = callback(&ctx, userdata))) {
        return nullptr;
    }
    // confirm that the key actually matches the search criteria
    if (!search.matches(*key) || (key->is_secret() != secret)) {
        return nullptr;
    }
    return key;
}
} // namespace rnp

pgp_key_t *
rnp_key_provider_key_ptr_list(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    std::vector<pgp_key_t *> *key_list = (std::vector<pgp_key_t *> *) userdata;
    for (auto key : *key_list) {
        if (ctx->search.matches(*key) && (key->is_secret() == ctx->secret)) {
            return key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_provider_chained(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    for (rnp::KeyProvider **pprovider = (rnp::KeyProvider **) userdata;
         pprovider && *pprovider;
         pprovider++) {
        auto       provider = *pprovider;
        pgp_key_t *key = nullptr;
        if ((key = provider->callback(ctx, provider->userdata))) {
            return key;
        }
    }
    return NULL;
}

pgp_key_t *
rnp_key_provider_store(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    auto ks = (rnp::KeyStore *) userdata;

    for (pgp_key_t *key = ks->search(ctx->search); key; key = ks->search(ctx->search, key)) {
        if (key->is_secret() == ctx->secret) {
            return key;
        }
    }
    return NULL;
}
