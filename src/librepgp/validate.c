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
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: validate.c,v 1.44 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <repgp/repgp.h>
#include <rnp/rnp_sdk.h>
#include <repgp/repgp.h>

#include <librepgp/packet-show.h>
#include <librepgp/reader.h>
#include "signature.h"
#include "utils.h"
#include "memory.h"
#include "crypto.h"
#include "validate.h"
#include "pgp-key.h"

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

static int
key_reader(pgp_stream_t *stream,
           void *        dest,
           size_t        length,
           pgp_error_t **errors,
           pgp_reader_t *readinfo,
           pgp_cbdata_t *cbinfo)
{
    validate_reader_t *reader = pgp_reader_get_arg(readinfo);

    RNP_USED(stream);
    RNP_USED(errors);
    RNP_USED(cbinfo);
    if (reader->offset == reader->key->packets[reader->packet].length) {
        reader->packet += 1;
        reader->offset = 0;
    }
    if (reader->packet == reader->key->packetc) {
        return 0;
    }

    /*
     * we should never be asked to cross a packet boundary in a single
     * read
     */
    if (reader->key->packets[reader->packet].length < reader->offset + length) {
        (void) fprintf(stderr, "key_reader: weird length\n");
        return 0;
    }

    (void) memcpy(dest, &reader->key->packets[reader->packet].raw[reader->offset], length);
    reader->offset += (unsigned) length;

    return (int) length;
}

static void
free_sig_info(pgp_sig_info_t *sig)
{
    free(sig->v4_hashed);
    free(sig);
}

static void
copy_sig_info(pgp_sig_info_t *dst, const pgp_sig_info_t *src)
{
    (void) memcpy(dst, src, sizeof(*src));
    if ((dst->v4_hashed = calloc(1, src->v4_hashlen)) == NULL) {
        (void) fprintf(stderr, "copy_sig_info: bad alloc\n");
    } else {
        (void) memcpy(dst->v4_hashed, src->v4_hashed, src->v4_hashlen);
    }
}

static bool
add_sig_to_list(const pgp_sig_info_t *sig, pgp_sig_info_t **sigs, unsigned *count)
{
    pgp_sig_info_t *newsigs;

    if (*count == 0) {
        newsigs = calloc(*count + 1, sizeof(pgp_sig_info_t));
    } else {
        newsigs = realloc(*sigs, (*count + 1) * sizeof(pgp_sig_info_t));
    }
    if (newsigs == NULL) {
        (void) fprintf(stderr, "add_sig_to_list: alloc failure\n");
        return false;
    }
    *sigs = newsigs;
    copy_sig_info(&(*sigs)[*count], sig);
    *count += 1;
    return true;
}

static char *
fmtsecs(int64_t n, char *buf, size_t size)
{
    if (n > 365 * 24 * 60 * 60) {
        n /= (365 * 24 * 60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " year%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 30 * 24 * 60 * 60) {
        n /= (30 * 24 * 60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " month%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 24 * 60 * 60) {
        n /= (24 * 60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " day%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 60 * 60) {
        n /= (60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " hour%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 60) {
        n /= 60;
        (void) snprintf(buf, size, "%" PRId64 " minute%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    (void) snprintf(buf, size, "%" PRId64 " second%s", n, (n == 1) ? "" : "s");
    return buf;
}

pgp_cb_ret_t
pgp_validate_key_cb(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    const pgp_contents_t *content = &pkt->u;
    const pgp_key_t *     signer;
    validate_key_cb_t *   key;
    pgp_error_t **        errors;
    pgp_io_t *            io;
    unsigned              from;
    unsigned              valid = 0;
    rnp_ctx_t *           rnp_ctx;

    io = cbinfo->io;
    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(io->errs, "%s\n", pgp_show_packet_tag(pkt->tag));
    }
    key = pgp_callback_arg(cbinfo);
    rnp_ctx = key->result->rnp_ctx;
    errors = pgp_callback_errors(cbinfo);
    switch (pkt->tag) {
    case PGP_PTAG_CT_PUBLIC_KEY:
        if (key->pubkey.version != 0) {
            (void) fprintf(io->errs, "pgp_validate_key_cb: version bad\n");
            return PGP_FINISHED;
        }
        key->pubkey = content->pubkey;
        return PGP_KEEP_MEMORY;

    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        if (key->subkey.version) {
            pgp_pubkey_free(&key->subkey);
        }
        key->subkey = content->pubkey;
        return PGP_KEEP_MEMORY;

    case PGP_PTAG_CT_SECRET_KEY:
        key->seckey = content->seckey;
        key->pubkey = key->seckey.pubkey;
        return PGP_KEEP_MEMORY;

    case PGP_PTAG_CT_USER_ID:
        if (key->userid) {
            pgp_userid_free(&key->userid);
        }
        key->userid = content->userid;
        key->last_seen = ID;
        return PGP_KEEP_MEMORY;

    case PGP_PTAG_CT_USER_ATTR:
        if (content->userattr.len == 0) {
            (void) fprintf(io->errs, "pgp_validate_key_cb: user attribute length 0");
            return PGP_FINISHED;
        }
        (void) fprintf(io->outs, "user attribute, length=%d\n", (int) content->userattr.len);
        if (key->userattr.len) {
            pgp_data_free(&key->userattr);
        }
        key->userattr = content->userattr;
        key->last_seen = ATTRIBUTE;
        return PGP_KEEP_MEMORY;

    case PGP_PTAG_CT_SIGNATURE:        /* V3 sigs */
    case PGP_PTAG_CT_SIGNATURE_FOOTER: /* V4 sigs */
        from = 0;
        signer = rnp_key_store_get_key_by_id(
          io, key->keyring, content->sig.info.signer_id, &from, NULL);
        if (!signer) {
            if (!add_sig_to_list(
                  &content->sig.info, &key->result->unknown_sigs, &key->result->unknownc)) {
                (void) fprintf(io->errs, "pgp_validate_key_cb: user attribute length 0");
                return PGP_FINISHED;
            }
            break;
        }
        if (!pgp_key_can_sign(signer)) {
            (void) fprintf(io->errs, "WARNING: signature made with key that can not sign\n");
        }
        switch (content->sig.info.type) {
        case PGP_CERT_GENERIC:
        case PGP_CERT_PERSONA:
        case PGP_CERT_CASUAL:
        case PGP_CERT_POSITIVE:
        case PGP_SIG_REV_CERT:
            valid =
              (key->last_seen == ID) ?
                pgp_check_useridcert_sig(rnp_ctx,
                                         &key->pubkey,
                                         key->userid,
                                         &content->sig,
                                         pgp_get_pubkey(signer),
                                         key->reader->key->packets[key->reader->packet].raw) :
                pgp_check_userattrcert_sig(rnp_ctx,
                                           &key->pubkey,
                                           &key->userattr,
                                           &content->sig,
                                           pgp_get_pubkey(signer),
                                           key->reader->key->packets[key->reader->packet].raw);
            break;

        case PGP_SIG_SUBKEY:
            /*
             * XXX: we should also check that the signer is the
             * key we are validating, I think.
             */
            valid = pgp_check_subkey_sig(rnp_ctx,
                                         &key->pubkey,
                                         &key->subkey,
                                         &content->sig,
                                         pgp_get_pubkey(signer),
                                         key->reader->key->packets[key->reader->packet].raw);
            break;

        case PGP_SIG_DIRECT:
            valid = pgp_check_direct_sig(rnp_ctx,
                                         &key->pubkey,
                                         &content->sig,
                                         pgp_get_pubkey(signer),
                                         key->reader->key->packets[key->reader->packet].raw);
            break;

        case PGP_SIG_STANDALONE:
        case PGP_SIG_PRIMARY:
        case PGP_SIG_REV_KEY:
        case PGP_SIG_REV_SUBKEY:
        case PGP_SIG_TIMESTAMP:
        case PGP_SIG_3RD_PARTY:
            PGP_ERROR_1(errors,
                        PGP_E_UNIMPLEMENTED,
                        "Sig Verification type 0x%02x not done yet\n",
                        content->sig.info.type);
            break;

        default:
            PGP_ERROR_1(errors,
                        PGP_E_UNIMPLEMENTED,
                        "Unexpected signature type 0x%02x\n",
                        content->sig.info.type);
        }

        if (valid) {
            if (!add_sig_to_list(
                  &content->sig.info, &key->result->valid_sigs, &key->result->validc)) {
                PGP_ERROR_1(errors, PGP_E_UNIMPLEMENTED, "%s", "Can't add good sig to list\n");
            }
        } else {
            PGP_ERROR_1(errors, PGP_E_V_BAD_SIGNATURE, "%s", "Bad Sig");
            if (!add_sig_to_list(
                  &content->sig.info, &key->result->invalid_sigs, &key->result->invalidc)) {
                PGP_ERROR_1(errors, PGP_E_UNIMPLEMENTED, "%s", "Can't add good sig to list\n");
            }
        }
        break;

    /* ignore these */
    case PGP_PARSER_PTAG:
    case PGP_PTAG_CT_SIGNATURE_HEADER:
    case PGP_PARSER_PACKET_END:
        break;

    case PGP_GET_PASSWORD:
        if (key->getpassword) {
            return key->getpassword(pkt, cbinfo);
        }
        break;

    case PGP_PTAG_CT_TRUST:
        /* 1 byte for level (depth), 1 byte for trust amount */
        printf("trust dump\n");
        printf("Got trust\n");
        // hexdump(stdout, (const uint8_t *)content->trust.data, 10, " ");
        // hexdump(stdout, (const uint8_t *)&content->ss_trust, 2, " ");
        // printf("Trust level %d, amount %d\n", key->trust.level, key->trust.amount);
        break;

    default:
        (void) fprintf(stderr, "unexpected tag=0x%x\n", pkt->tag);
        return PGP_FINISHED;
    }
    return PGP_RELEASE_MEMORY;
}

static void
key_destroyer(pgp_reader_t *readinfo)
{
    free(pgp_reader_get_arg(readinfo));
}

bool
pgp_key_reader_set(pgp_stream_t *stream, const pgp_key_t *key)
{
    validate_reader_t *data;

    data = calloc(1, sizeof(*data));

    if (data == NULL) {
        (void) fprintf(stderr, "pgp_key_reader_set: bad alloc\n");
        return false;
    }

    data->key = key;
    data->packet = 0;
    data->offset = 0;
    pgp_reader_set(stream, key_reader, key_destroyer, data);

    return true;
}

/**
   \ingroup HighLevel_Verify
   \brief Frees validation result and associated memory
   \param result Struct to be freed
   \note Must be called after validation functions
*/
void
pgp_validate_result_free(pgp_validation_t *result)
{
    if (result != NULL) {
        if (result->valid_sigs) {
            free_sig_info(result->valid_sigs);
        }
        if (result->invalid_sigs) {
            free_sig_info(result->invalid_sigs);
        }
        if (result->unknown_sigs) {
            free_sig_info(result->unknown_sigs);
        }
        free(result);
        /* result = NULL; - XXX unnecessary */
    }
}

bool
validate_result_status(const char *f, pgp_validation_t *val)
{
    time_t now;
    time_t t;
    char   buf[128];

    now = time(NULL);
    if (now < val->birthtime) {
        /* signature is not valid yet! */
        if (f) {
            (void) fprintf(stderr, "\"%s\": ", f);
        } else {
            (void) fprintf(stderr, "memory ");
        }
        (void) fprintf(stderr,
                       "signature not valid until %.24s (%s)\n",
                       ctime(&val->birthtime),
                       fmtsecs((int64_t)(val->birthtime - now), buf, sizeof(buf)));
        return false;
    }
    if (val->duration != 0 && now > val->birthtime + val->duration) {
        /* signature has expired */
        t = val->duration + val->birthtime;
        if (f) {
            (void) fprintf(stderr, "\"%s\": ", f);
        } else {
            (void) fprintf(stderr, "memory ");
        }
        (void) fprintf(stderr,
                       "signature not valid after %.24s (%s ago)\n",
                       ctime(&t),
                       fmtsecs((int64_t)(now - t), buf, sizeof(buf)));
        return false;
    }
    return val->validc && !val->invalidc && !val->unknownc;
}

bool
pgp_validate_key_sigs(pgp_validation_t *     result,
                      const pgp_key_t *      key,
                      const rnp_key_store_t *keyring,
                      pgp_cb_ret_t cb_get_password(const pgp_packet_t *, pgp_cbdata_t *))
{
    pgp_stream_t *    stream;
    validate_key_cb_t keysigs;

    (void) memset(&keysigs, 0x0, sizeof(keysigs));
    keysigs.result = result;
    keysigs.getpassword = cb_get_password;

    stream = pgp_new(sizeof(*stream));
    if (stream == NULL) {
        return false;
    }
    /* pgp_parse_options(&opt,PGP_PTAG_CT_SIGNATURE,PGP_PARSE_PARSED); */

    keysigs.keyring = keyring;

    pgp_set_callback(stream, pgp_validate_key_cb, &keysigs);
    stream->readinfo.accumulate = 1;
    if (!pgp_key_reader_set(stream, key)) {
        return false;
    }

    /* Note: Coverity incorrectly reports an error that keysigs.reader */
    /* is never used. */
    keysigs.reader = stream->readinfo.arg;

    repgp_parse(stream, true);

    pgp_pubkey_free(&keysigs.pubkey);
    if (keysigs.subkey.version) {
        pgp_pubkey_free(&keysigs.subkey);
    }
    pgp_userid_free(&keysigs.userid);
    pgp_data_free(&keysigs.userattr);

    pgp_stream_delete(stream);

    return (!result->invalidc && !result->unknownc && result->validc);
}
