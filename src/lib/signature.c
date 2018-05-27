/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

/** \file
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: signature.c,v 1.34 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <rnp/rnp_sdk.h>
#include "crypto/common.h"
#include "packet-create.h"
#include "fingerprint.h"
#include "signature.h"
#include "pgp-key.h"
#include <librepgp/stream-sig.h>
#include <librepgp/stream-packet.h>
#include "utils.h"

/**
 * \ingroup Core_Signature
 *
 * \brief Verify a certification signature.
 *
 * \param key The public key that was signed.
 * \param id The user ID that was signed
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 * \return true if OK
 */
bool
pgp_check_useridcert_sig(rnp_ctx_t *            rnp_ctx,
                         const pgp_key_pkt_t *  key,
                         const uint8_t *        id,
                         const pgp_sig_info_t * sig,
                         const pgp_key_pkt_t *  signer,
                         const pgp_rawpacket_t *raw_packet)
{
    pgp_signature_t  sigpkt = {0};
    pgp_userid_pkt_t uid = {0};
    pgp_source_t     sigsrc = {0};
    pgp_hash_t       hash = {0};
    bool             res = false;

    if (init_mem_src(&sigsrc, raw_packet->raw, raw_packet->length, false)) {
        return false;
    }

    uid.tag = PGP_PTAG_CT_USER_ID;
    uid.uid = (uint8_t *) id;
    uid.uid_len = strlen((const char *) id);

    if (stream_parse_signature(&sigsrc, &sigpkt)) {
        src_close(&sigsrc);
        return false;
    }

    if (!(res = signature_hash_certification(&sigpkt, key, &uid, &hash))) {
        goto done;
    }

    res = !signature_validate(&sigpkt, &signer->material, &hash, rnp_ctx_rng_handle(rnp_ctx));
done:
    src_close(&sigsrc);
    free_signature(&sigpkt);
    return res;
}

/**
 * \ingroup Core_Signature
 *
 * Verify a certification signature.
 *
 * \param key The public key that was signed.
 * \param attribute The user attribute that was signed
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 * \return true if OK
 */
bool
pgp_check_userattrcert_sig(rnp_ctx_t *            rnp_ctx,
                           const pgp_key_pkt_t *  key,
                           const pgp_data_t *     attribute,
                           const pgp_sig_info_t * sig,
                           const pgp_key_pkt_t *  signer,
                           const pgp_rawpacket_t *raw_packet)
{
    pgp_signature_t  sigpkt = {0};
    pgp_userid_pkt_t uid = {0};
    pgp_source_t     sigsrc = {0};
    pgp_hash_t       hash = {0};
    bool             res = false;

    if (init_mem_src(&sigsrc, raw_packet->raw, raw_packet->length, false)) {
        return false;
    }

    uid.tag = PGP_PTAG_CT_USER_ATTR;
    uid.uid = attribute->contents;
    uid.uid_len = attribute->len;

    if (stream_parse_signature(&sigsrc, &sigpkt)) {
        src_close(&sigsrc);
        return false;
    }

    if (!(res = signature_hash_certification(&sigpkt, key, &uid, &hash))) {
        goto done;
    }

    res = !signature_validate(&sigpkt, &signer->material, &hash, rnp_ctx_rng_handle(rnp_ctx));
done:
    src_close(&sigsrc);
    free_signature(&sigpkt);
    return res;
}

/**
 * \ingroup Core_Signature
 *
 * Verify a subkey signature.
 *
 * \param key The public key whose subkey was signed.
 * \param subkey The subkey of the public key that was signed.
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 * \return true if OK
 */
bool
pgp_check_subkey_sig(rnp_ctx_t *            rnp_ctx,
                     const pgp_key_pkt_t *  key,
                     const pgp_key_pkt_t *  subkey,
                     const pgp_sig_info_t * sig,
                     const pgp_key_pkt_t *  signer,
                     const pgp_rawpacket_t *raw_packet)
{
    pgp_signature_t sigpkt = {0};
    pgp_source_t    sigsrc = {0};
    pgp_hash_t      hash = {0};
    bool            res = false;

    if (init_mem_src(&sigsrc, raw_packet->raw, raw_packet->length, false)) {
        return false;
    }

    if (stream_parse_signature(&sigsrc, &sigpkt)) {
        src_close(&sigsrc);
        return false;
    }

    if (!(res = signature_hash_binding(&sigpkt, key, subkey, &hash))) {
        goto done;
    }

    res = !signature_validate(&sigpkt, &signer->material, &hash, rnp_ctx_rng_handle(rnp_ctx));
done:
    src_close(&sigsrc);
    free_signature(&sigpkt);
    return res;
}

/**
 * \ingroup Core_Signature
 *
 * Verify a direct signature.
 *
 * \param key The public key which was signed.
 * \param sig The signature.
 * \param signer The public key of the signer.
 * \param raw_packet The raw signature packet.
 * \return true if OK
 */
bool
pgp_check_direct_sig(rnp_ctx_t *            rnp_ctx,
                     const pgp_key_pkt_t *  key,
                     const pgp_sig_info_t * sig,
                     const pgp_key_pkt_t *  signer,
                     const pgp_rawpacket_t *raw_packet)
{
    pgp_signature_t sigpkt = {0};
    pgp_source_t    sigsrc = {0};
    pgp_hash_t      hash = {0};
    bool            res = false;

    if (init_mem_src(&sigsrc, raw_packet->raw, raw_packet->length, false)) {
        return false;
    }

    if (stream_parse_signature(&sigsrc, &sigpkt)) {
        src_close(&sigsrc);
        return false;
    }

    if (!(res = signature_hash_direct(&sigpkt, key, &hash))) {
        goto done;
    }

    res = !signature_validate(&sigpkt, &signer->material, &hash, rnp_ctx_rng_handle(rnp_ctx));
done:
    src_close(&sigsrc);
    free_signature(&sigpkt);
    return res;
}
