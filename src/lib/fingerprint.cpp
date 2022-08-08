/*
 * Copyright (c) 2017-2022, [Ribose Inc](https://www.ribose.com).
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

#include <string.h>
#include "fingerprint.h"
#include "crypto/hash.hpp"
#include <librepgp/stream-key.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-packet.h>
#include "utils.h"

rnp_result_t
pgp_fingerprint(pgp_fingerprint_t &fp, const pgp_key_pkt_t &key)
{
    if ((key.version == PGP_V2) || (key.version == PGP_V3)) {
        if (!is_rsa_key_alg(key.alg)) {
            RNP_LOG("bad algorithm");
            return RNP_ERROR_NOT_SUPPORTED;
        }
        try {
            auto hash = rnp::Hash::create(PGP_HASH_MD5);
            hash->add(key.material.rsa.n);
            hash->add(key.material.rsa.e);
            fp.length = hash->finish(fp.fingerprint);
            return RNP_SUCCESS;
        } catch (const std::exception &e) {
            RNP_LOG("Failed to calculate v3 fingerprint: %s", e.what());
            return RNP_ERROR_BAD_STATE;
        }
    }

    if (key.version != PGP_V4) {
        RNP_LOG("unsupported key version");
        return RNP_ERROR_NOT_SUPPORTED;
    }

    try {
        auto hash = rnp::Hash::create(PGP_HASH_SHA1);
        signature_hash_key(key, *hash);
        fp.length = hash->finish(fp.fingerprint);
        return RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("Failed to calculate v4 fingerprint: %s", e.what());
        return RNP_ERROR_BAD_STATE;
    }
}

/**
 * \ingroup Core_Keys
 * \brief Calculate the Key ID from the public key.
 * \param keyid Space for the calculated ID to be stored
 * \param key The key for which the ID is calculated
 */

rnp_result_t
pgp_keyid(pgp_key_id_t &keyid, const pgp_key_pkt_t &key)
{
    pgp_fingerprint_t fp;
    rnp_result_t      ret;
    size_t            n;

    if ((key.version == PGP_V2) || (key.version == PGP_V3)) {
        if (!is_rsa_key_alg(key.alg)) {
            RNP_LOG("bad algorithm");
            return RNP_ERROR_NOT_SUPPORTED;
        }
        n = mpi_bytes(&key.material.rsa.n);
        (void) memcpy(keyid.data(), key.material.rsa.n.mpi + n - keyid.size(), keyid.size());
        return RNP_SUCCESS;
    }

    if ((ret = pgp_fingerprint(fp, key))) {
        return ret;
    }
    (void) memcpy(keyid.data(), fp.fingerprint + fp.length - keyid.size(), keyid.size());
    return RNP_SUCCESS;
}

bool
pgp_fingerprint_t::operator==(const pgp_fingerprint_t &src) const
{
    return (length == src.length) && !memcmp(fingerprint, src.fingerprint, length);
}

bool
pgp_fingerprint_t::operator!=(const pgp_fingerprint_t &src) const
{
    return !(*this == src);
}
