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
 * This file contains the base functions used by the writers.
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: writer.c,v 1.33 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <repgp/repgp.h>

#include "crypto/bn.h"
#include "packet-create.h"
#include "writer.h"
#include "signature.h"
#include "readerwriter.h"
#include "memory.h"
#include "utils.h"
#include "compress.h"

#define MAX_PARTIAL_DATA_LENGTH 1073741824
#define MAX_PARTIAL_DATA_LENGTH_POWER 30

/*
 * return true if OK, otherwise false
 */
static bool
base_write(pgp_output_t *out, const void *src, size_t len)
{
    return !!out->writer.writer(src, len, &out->errors, &out->writer);
}

/**
 * \ingroup Core_WritePackets
 *
 * \param src
 * \param len
 * \param output
 * \return 1 if OK, otherwise 0
 */

bool
pgp_write(pgp_output_t *output, const void *src, size_t len)
{
    return base_write(output, src, len);
}

/**
 * \ingroup Core_WritePackets
 * \param n
 * \param len
 * \param output
 * \return 1 if OK, otherwise 0
 */

bool
pgp_write_scalar(pgp_output_t *output, unsigned n, unsigned len)
{
    uint8_t c;

    while (len-- > 0) {
        c = n >> (len * 8);
        if (!base_write(output, &c, 1)) {
            return false;
        }
    }
    return true;
}

/**
 * \ingroup Core_WritePackets
 * \param bn
 * \param output
 * \return 1 if OK, otherwise 0
 */

bool
pgp_write_mpi(pgp_output_t *output, const BIGNUM *bn)
{
    unsigned bits;
    uint8_t  buf[RNP_BUFSIZ];

    bits = (unsigned) BN_num_bits(bn);
    if (bits > 65535) {
        (void) fprintf(stderr, "pgp_write_mpi: too large %u\n", bits);
        return false;
    }
    BN_bn2bin(bn, buf);
    return pgp_write_scalar(output, bits, 2) && pgp_write(output, buf, BITS_TO_BYTES(bits));
}

/**
 * \ingroup Core_WritePackets
 * \param tag
 * \param output
 * \return 1 if OK, otherwise 0
 */

bool
pgp_write_ptag(pgp_output_t *output, pgp_content_enum tag)
{
    uint8_t c;

    c = tag | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT;
    return base_write(output, &c, 1);
}

/**
 * \ingroup Core_WritePackets
 * \param len
 * \param output
 * \return 1 if OK, otherwise 0
 */

bool
pgp_write_length(pgp_output_t *output, unsigned len)
{
    uint8_t c[2];

    if (len < 192) {
        c[0] = len;
        return base_write(output, c, 1);
    }
    if (len < 8192 + 192) {
        c[0] = ((len - 192) >> 8) + 192;
        c[1] = (len - 192) % 256;
        return base_write(output, c, 2);
    }
    return pgp_write_scalar(output, 0xff, 1) && pgp_write_scalar(output, len, 4);
}

/*
 * Note that we finalise from the top down, so we don't use writers below
 * that have already been finalised
 */
unsigned
pgp_writer_info_finalise(pgp_error_t **errors, pgp_writer_t *writer)
{
    unsigned ret = 1;

    if (writer->finaliser) {
        ret = writer->finaliser(errors, writer);
        writer->finaliser = NULL;
    }
    if (writer->next && !pgp_writer_info_finalise(errors, writer->next)) {
        writer->finaliser = NULL;
        return 0;
    }
    return ret;
}

void
pgp_writer_info_delete(pgp_writer_t *writer)
{
    /* we should have finalised before deleting */
    if (writer->finaliser) {
        (void) fprintf(stderr, "pgp_writer_info_delete: not done\n");
        return;
    }
    if (writer->next) {
        pgp_writer_info_delete(writer->next);
        free(writer->next);
        writer->next = NULL;
    }
    if (writer->destroyer) {
        writer->destroyer(writer);
        writer->destroyer = NULL;
    }
    writer->writer = NULL;
}

/**
 * \ingroup Core_Writers
 *
 * Set a writer in output. There should not be another writer set.
 *
 * \param output The output structure
 * \param writer
 * \param finaliser
 * \param destroyer
 * \param arg The argument for the writer and destroyer
 */
bool
pgp_writer_set(pgp_output_t *          output,
               pgp_writer_func_t *     writer,
               pgp_writer_finaliser_t *finaliser,
               pgp_writer_destroyer_t *destroyer,
               void *                  arg)
{
    if (output->writer.writer) {
        (void) fprintf(stderr, "pgp_writer_set: already set\n");
        return false;
    }
    output->writer.writer = writer;
    output->writer.finaliser = finaliser;
    output->writer.destroyer = destroyer;
    output->writer.arg = arg;
    output->writer.ctx = output->ctx;
    return true;
}

/**
 * \ingroup Core_Writers
 *
 * Push a writer in output. There must already be another writer set.
 *
 * \param output The output structure
 * \param writer
 * \param finaliser
 * \param destroyer
 * \param arg The argument for the writer and destroyer
 */
bool
pgp_writer_push(pgp_output_t *          output,
                pgp_writer_func_t *     writer,
                pgp_writer_finaliser_t *finaliser,
                pgp_writer_destroyer_t *destroyer,
                void *                  arg)
{
    pgp_writer_t *copy = NULL;

    if ((copy = calloc(1, sizeof(*copy))) == NULL) {
        (void) fprintf(stderr, "pgp_writer_push: bad alloc\n");
        return false;
    }

    if (output->writer.writer == NULL) {
        if (copy != NULL) {
            free(copy);
        }
        (void) fprintf(stderr, "pgp_writer_push: no orig writer\n");
        return false;
    }

    *copy = output->writer;
    output->writer.next = copy;

    output->writer.writer = writer;
    output->writer.finaliser = finaliser;
    output->writer.destroyer = destroyer;
    output->writer.arg = arg;
    output->writer.ctx = output->ctx;
    return true;
}

void
pgp_writer_pop(pgp_output_t *output)
{
    pgp_writer_t *next;

    /* Make sure the finaliser has been called. */
    if (output->writer.finaliser) {
        (void) fprintf(stderr, "pgp_writer_pop: finaliser not called\n");
    } else if (output->writer.next == NULL) {
        (void) fprintf(stderr, "pgp_writer_pop: not a stacked writer\n");
    } else {
        if (output->writer.destroyer) {
            output->writer.destroyer(&output->writer);
        }
        next = output->writer.next;
        output->writer = *next;
        free(next);
    }
}

/**
 * \ingroup Core_Writers
 *
 * Close the writer currently set in output.
 *
 * \param output The output structure
 */
unsigned
pgp_writer_close(pgp_output_t *output)
{
    if (!output) {
        return 0;
    }

    unsigned ret = pgp_writer_info_finalise(&output->errors, &output->writer);
    pgp_writer_info_delete(&output->writer);
    return ret;
}

/**
 * \ingroup Core_Writers
 *
 * Get the arg supplied to pgp_createinfo_set_writer().
 *
 * \param writer The writer_info structure
 * \return The arg
 */
void *
pgp_writer_get_arg(pgp_writer_t *writer)
{
    return writer->arg;
}

/**
 * \ingroup Core_Writers
 *
 * Write to the next writer down in the stack.
 *
 * \param ctx Operation context
 * \param writer The writer_info structure.
 * \param src The data to write.
 * \param len The length of src.
 * \param errors A place to store errors.
 * \return Success - if 0, then errors should contain the error.
 */
static bool
stacked_write(pgp_writer_t *writer, const void *src, size_t len, pgp_error_t **errors)
{
    return !!writer->next->writer(src, len, errors, writer->next);
}

/**
 * \ingroup Core_Writers
 *
 * Free the arg. Many writers just have a calloc()ed lump of storage, this
 * function releases it.
 *
 * \param writer the info structure.
 */
static void
generic_destroyer(pgp_writer_t *writer)
{
    free(pgp_writer_get_arg(writer));
}

/**
 * \ingroup Core_Writers
 *
 * A writer that just writes to the next one down. Useful for when you
 * want to insert just a finaliser into the stack.
 */
unsigned
pgp_writer_passthrough(const uint8_t *src,
                       unsigned       len,
                       pgp_error_t ** errors,
                       pgp_writer_t * writer)
{
    return stacked_write(writer, src, len, errors);
}

/**************************************************************************/

/**
 * \struct dashesc_t
 */
typedef struct {
    unsigned          seen_nl : 1;
    unsigned          seen_cr : 1;
    pgp_create_sig_t *sig;
    pgp_memory_t *    trailing;
} dashesc_t;

#define CH_CR ('\r')
#define CH_LF ('\n')
#define CH_DASH ('-')
#define CH_SPACE (' ')
#define CH_TAB ('\t')
#define STR_CR ("\r")
#define STR_LF ("\n")
#define STR_DASHESC ("- ")

static bool
dash_esc_writer(const uint8_t *src, size_t len, pgp_error_t **errors, pgp_writer_t *writer)
{
    dashesc_t *dash = pgp_writer_get_arg(writer);
    size_t     n;
    bool       escape;

    if (rnp_get_debug(__FILE__)) {
        size_t i = 0;

        (void) fprintf(stderr, "dash_esc_writer writing %zu:\n", len);
        for (i = 0; i < len; i++) {
            fprintf(stderr, "0x%02x ", src[i]);
            if (((i + 1) % 16) == 0) {
                (void) fprintf(stderr, STR_LF);
            } else if (((i + 1) % 8) == 0) {
                (void) fprintf(stderr, "  ");
            }
        }
        (void) fprintf(stderr, STR_LF);
    }
    /* XXX: make this efficient */
    for (n = 0; n < len; ++n) {
        size_t l;

        escape = false;
        if (dash->seen_nl || dash->seen_cr) {
            if (src[n] == CH_DASH) {
                escape = true;
            }
        }
        dash->seen_nl = src[n] == CH_LF;

        if (dash->seen_nl && !dash->seen_cr) {
            if (!stacked_write(writer, STR_CR, 1, errors)) {
                return false;
            }
            pgp_sig_add_data(dash->sig, STR_CR, 1);
        }
        if (dash->seen_cr && !dash->seen_nl) {
            if (!stacked_write(writer, STR_LF, 1, errors)) {
                return false;
            }
            pgp_sig_add_data(dash->sig, STR_LF, 1);
        }
        dash->seen_cr = src[n] == CH_CR;

        if (escape && !stacked_write(writer, STR_DASHESC, 2, errors)) {
            return false;
        }

        if (!stacked_write(writer, &src[n], 1, errors)) {
            return false;
        }

        /* trailing whitespace isn't included in the signature */
        if (src[n] == CH_SPACE || src[n] == CH_TAB) {
            if (!pgp_memory_add(dash->trailing, &src[n], 1)) {
                return false;
            }
        } else {
            if ((l = pgp_mem_len(dash->trailing)) != 0) {
                if (!dash->seen_nl && !dash->seen_cr) {
                    pgp_sig_add_data(dash->sig, pgp_mem_data(dash->trailing), l);
                }
                pgp_memory_clear(dash->trailing);
            }
            pgp_sig_add_data(dash->sig, &src[n], 1);
        }
    }
    return true;
}

/**
 * \param writer
 */
static void
dash_escaped_destroyer(pgp_writer_t *writer)
{
    dashesc_t *dash;

    dash = pgp_writer_get_arg(writer);
    pgp_memory_free(dash->trailing);
    free(dash);
}

/**
 * \ingroup Core_WritersNext
 * \brief Push Clearsigned Writer onto stack
 * \param output
 * \param sig
 */
bool
pgp_writer_push_clearsigned(pgp_output_t *output, pgp_create_sig_t *sig)
{
    static const char header[] = "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: ";
    const char *      hash;
    dashesc_t *       dash;

    hash = pgp_hash_name(pgp_sig_get_hash(sig));
    if ((dash = calloc(1, sizeof(*dash))) == NULL) {
        PGP_ERROR_1(&output->errors, PGP_E_W, "%s", "Bad alloc");
        return 0;
    }
    bool ret = (pgp_write(output, header, (sizeof(header) - 1)) &&
                pgp_write(output, hash, strlen(hash)) && pgp_write(output, "\r\n\r\n", 4));

    if (!ret) {
        PGP_ERROR_1(&output->errors, PGP_E_W, "%s", "Error pushing clearsigned header");
        free(dash);
        return false;
    }
    dash->seen_nl = 1;
    dash->sig = sig;
    dash->trailing = pgp_memory_new();
    if (dash->trailing == NULL) {
        free(dash);
        PGP_ERROR_1(&output->errors, PGP_E_FAIL, "%s", "can't allocate mem");
        return 0;
    }
    if (!pgp_writer_push(output, dash_esc_writer, NULL, dash_escaped_destroyer, dash)) {
        free(dash);
        return false;
    }
    return true;
}

/**
 * \struct base64_t
 */
typedef struct {
    unsigned         pos;
    uint8_t          t;
    unsigned         checksum;
    pgp_armor_type_t type;
} base64_t;

static const char b64map[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static bool
base64_writer(const uint8_t *src, size_t len, pgp_error_t **errors, pgp_writer_t *writer)
{
    base64_t *base64;
    size_t    n;

    base64 = pgp_writer_get_arg(writer);
    for (n = 0; n < len;) {
        base64->checksum = pgp_crc24(base64->checksum, src[n]);
        if (base64->pos == 0) {
            /* XXXXXX00 00000000 00000000 */
            if (!stacked_write(writer, &b64map[(unsigned) src[n] >> 2], 1, errors)) {
                return false;
            }

            /* 000000XX xxxx0000 00000000 */
            base64->t = (src[n++] & 3) << 4;
            base64->pos = 1;
        } else if (base64->pos == 1) {
            /* 000000xx XXXX0000 00000000 */
            base64->t += (unsigned) src[n] >> 4;
            if (!stacked_write(writer, &b64map[base64->t], 1, errors)) {
                return false;
            }

            /* 00000000 0000XXXX xx000000 */
            base64->t = (src[n++] & 0xf) << 2;
            base64->pos = 2;
        } else if (base64->pos == 2) {
            /* 00000000 0000xxxx XX000000 */
            base64->t += (unsigned) src[n] >> 6;
            if (!stacked_write(writer, &b64map[base64->t], 1, errors)) {
                return false;
            }

            /* 00000000 00000000 00XXXXXX */
            if (!stacked_write(writer, &b64map[src[n++] & 0x3f], 1, errors)) {
                return false;
            }

            base64->pos = 0;
        }
    }

    return true;
}

/**
 * \struct linebreak_t
 */
typedef struct {
    unsigned pos;
} linebreak_t;

#define BREAKPOS 76

static bool
linebreak_writer(const uint8_t *src, size_t len, pgp_error_t **errors, pgp_writer_t *writer)
{
    linebreak_t *linebreak;
    size_t       n;

    linebreak = pgp_writer_get_arg(writer);
    for (n = 0; n < len; ++n, ++linebreak->pos) {
        if (src[n] == '\r' || src[n] == '\n') {
            linebreak->pos = 0;
        }
        if (linebreak->pos == BREAKPOS) {
            if (!stacked_write(writer, "\r\n", 2, errors)) {
                return false;
            }
            linebreak->pos = 0;
        }
        if (!stacked_write(writer, &src[n], 1, errors)) {
            return false;
        }
    }

    return true;
}

static bool
armoured_message_finaliser(pgp_error_t **errors, pgp_writer_t *writer)
{
    /* TODO: This is same as sig_finaliser apart from trailer. */
    static const char trl_message[] = "\r\n-----END PGP MESSAGE-----\r\n";
    static const char trl_pubkey[] = "\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n";
    static const char trl_seckey[] = "\r\n-----END PGP PRIVATE KEY BLOCK-----\r\n";
    static const char trl_signature[] = "\r\n-----END PGP SIGNATURE-----\r\n";

    base64_t *  base64;
    uint8_t     c[3];
    const char *trailer = NULL;

    base64 = pgp_writer_get_arg(writer);

    switch (base64->type) {
    case PGP_PGP_MESSAGE:
        trailer = trl_message;
        break;
    case PGP_PGP_PUBLIC_KEY_BLOCK:
        trailer = trl_pubkey;
        break;
    case PGP_PGP_PRIVATE_KEY_BLOCK:
        trailer = trl_seckey;
        break;
    case PGP_PGP_SIGNATURE:
    case PGP_PGP_CLEARTEXT_SIGNATURE:
        trailer = trl_signature;
        break;
    default:
        fprintf(stderr, "armoured_message_finaliser: unusual type\n");
        return false;
    }

    if (base64->pos) {
        if (!stacked_write(writer, &b64map[base64->t], 1, errors)) {
            return false;
        }
        if (base64->pos == 1 && !stacked_write(writer, "==", 2, errors)) {
            return false;
        }
        if (base64->pos == 2 && !stacked_write(writer, "=", 1, errors)) {
            return false;
        }
    }
    /* Ready for the checksum */
    if (!stacked_write(writer, "\r\n=", 3, errors)) {
        return false;
    }

    base64->pos = 0; /* get ready to write the checksum */

    c[0] = base64->checksum >> 16;
    c[1] = base64->checksum >> 8;
    c[2] = base64->checksum;
    /* push the checksum through our own writer */
    if (!base64_writer(c, 3, errors, writer)) {
        return false;
    }

    return stacked_write(writer, trailer, strlen(trailer), errors);
}

/**
 \ingroup Core_WritersNext
 \brief Push Armoured Writer on stack (generic)
*/
bool
pgp_writer_push_armoured(pgp_output_t *output, pgp_armor_type_t type)
{
    static char hdr_pubkey[] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n";
    static char hdr_privkey[] = "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n";
    static char hdr_message[] = "-----BEGIN PGP MESSAGE-----\r\n";
    static char hdr_signature[] = "-----BEGIN PGP SIGNATURE-----\r\n";
    static char hdr_version[] = "Version: " PACKAGE_STRING "\r\n\r\n";
    static char hdr_crlf[] = "\r\n";

    base64_t *   base64;
    linebreak_t *linebreak;

    if ((linebreak = calloc(1, sizeof(*linebreak))) == NULL) {
        (void) fprintf(stderr, "pgp_writer_push_armoured: bad alloc\n");
        return false;
    }

    switch (type) {
    case PGP_PGP_MESSAGE:
        pgp_write(output, hdr_message, sizeof(hdr_message) - 1);
        pgp_write(output, hdr_crlf, sizeof(hdr_crlf) - 1);
        break;

    case PGP_PGP_PUBLIC_KEY_BLOCK:
        pgp_write(output, hdr_pubkey, sizeof(hdr_pubkey) - 1);
        pgp_write(output, hdr_version, sizeof(hdr_version) - 1);
        break;

    case PGP_PGP_PRIVATE_KEY_BLOCK:
        pgp_write(output, hdr_privkey, sizeof(hdr_privkey) - 1);
        pgp_write(output, hdr_version, sizeof(hdr_version) - 1);
        break;

    case PGP_PGP_SIGNATURE:
        pgp_write(output, hdr_signature, sizeof(hdr_signature) - 1);
        pgp_write(output, hdr_crlf, sizeof(hdr_crlf) - 1);
        break;

    case PGP_PGP_CLEARTEXT_SIGNATURE:
        pgp_writer_pop(output);
        if (!pgp_write(output, hdr_crlf, sizeof(hdr_crlf) - 1) ||
            !pgp_write(output, hdr_signature, sizeof(hdr_signature) - 1) ||
            !pgp_write(output, hdr_version, sizeof(hdr_version) - 1)) {
            PGP_ERROR_1(
              &output->errors, PGP_E_W, "%s", "Error switching to armoured signature");
            free(linebreak);
            return false;
        }
        break;

    default:
        free(linebreak);
        (void) fprintf(stderr, "pgp_writer_push_armoured: unusual type\n");
        return false;
    }

    if (!pgp_writer_push(output, linebreak_writer, NULL, generic_destroyer, linebreak)) {
        free(linebreak);
        return false;
    }

    if ((base64 = calloc(1, sizeof(*base64))) == NULL) {
        (void) fprintf(stderr, "pgp_writer_push_armoured: bad alloc\n");
        return false;
    }
    base64->checksum = CRC24_INIT;
    base64->type = type;

    if (!pgp_writer_push(
          output, base64_writer, armoured_message_finaliser, generic_destroyer, base64)) {
        free(base64);
        return false;
    }

    return true;
}

/**************************************************************************/

typedef struct {
    pgp_crypt_t *crypt;
    int          free_crypt;
} crypt_t;

/*
 * This writer simply takes plaintext as input,
 * encrypts it with the given key
 * and outputs the resulting encrypted text
 */
static bool
encrypt_writer(const uint8_t *src, size_t len, pgp_error_t **errors, pgp_writer_t *writer)
{
#define BUFSZ 1024 /* arbitrary number */
    uint8_t  encbuf[BUFSZ];
    size_t   remaining;
    unsigned done = 0;
    crypt_t *pgp_encrypt;

    remaining = len;
    pgp_encrypt = (crypt_t *) pgp_writer_get_arg(writer);
    while (remaining > 0) {
        size_t size = (remaining < BUFSZ) ? remaining : BUFSZ;

        /* memcpy(buf,src,size); // \todo copy needed here? */
        pgp_cipher_cfb_encrypt(pgp_encrypt->crypt, encbuf, src + done, size);

        if (rnp_get_debug(__FILE__)) {
            hexdump(stderr, "unencrypted", &src[done], 16);
            hexdump(stderr, "encrypted", encbuf, 16);
        }
        if (!stacked_write(writer, encbuf, size, errors)) {
            if (rnp_get_debug(__FILE__)) {
                fprintf(stderr, "encrypted_writer: stacked write\n");
            }
            return false;
        }
        remaining -= size;
        done += size;
    }

    return true;
}

static void
encrypt_destroyer(pgp_writer_t *writer)
{
    crypt_t *pgp_encrypt;

    pgp_encrypt = (crypt_t *) pgp_writer_get_arg(writer);
    if (pgp_encrypt->free_crypt) {
        free(pgp_encrypt->crypt);
    }
    free(pgp_encrypt);
}

/**
\ingroup Core_WritersNext
\brief Push Encrypted Writer onto stack (create SE packets)
*/
bool
pgp_push_enc_crypt(pgp_output_t *output, pgp_crypt_t *pgp_crypt)
{
    /* Create encrypt to be used with this writer */
    /* Remember to free this in the destroyer */
    crypt_t *pgp_encrypt;

    if ((pgp_encrypt = calloc(1, sizeof(*pgp_encrypt))) == NULL) {
        (void) fprintf(stderr, "pgp_push_enc_crypt: bad alloc\n");
        return false;
    } else {
        /* Setup the encrypt */
        pgp_encrypt->crypt = pgp_crypt;
        pgp_encrypt->free_crypt = 0;
        /* And push writer on stack */
        if (!pgp_writer_push(output, encrypt_writer, NULL, encrypt_destroyer, pgp_encrypt)) {
            return false;
            free(pgp_encrypt);
        }
    }
    return true;
}

/**************************************************************************/

typedef struct {
    pgp_crypt_t *crypt;
} encrypt_se_ip_t;

static bool encrypt_se_ip_writer(const uint8_t *, size_t, pgp_error_t **, pgp_writer_t *);
static void encrypt_se_ip_destroyer(pgp_writer_t *);

/* */

/**
\ingroup Core_WritersNext
\brief Push Encrypted SE IP Writer onto stack
*/
bool
pgp_push_enc_se_ip(pgp_output_t *      output,
                   const pgp_pubkey_t *pubkey,
                   pgp_symm_alg_t      cipher,
                   size_t              len)
{
    pgp_pk_sesskey_t *encrypted_pk_sesskey;
    encrypt_se_ip_t * se_ip;
    pgp_crypt_t *     encrypted;

    /* one packet can't be bigger than 0xffffffff, so, switch to streaming encryption*/
    if (len >= MAX_PARTIAL_DATA_LENGTH) {
        return pgp_push_stream_enc_se_ip(output, pubkey, cipher);
    }

    if ((se_ip = calloc(1, sizeof(*se_ip))) == NULL) {
        (void) fprintf(stderr, "pgp_push_enc_se_ip: bad alloc\n");
        return false;
    }

    /* Create and write encrypted PK session key */
    if ((encrypted_pk_sesskey = pgp_create_pk_sesskey(pubkey, cipher)) == NULL) {
        (void) fprintf(stderr, "pgp_push_enc_se_ip: null pk sesskey\n");
        free(se_ip);
        return false;
    }
    if (!pgp_write_pk_sesskey(output, encrypted_pk_sesskey)) {
        free(se_ip);
        return false;
    }

    /* Setup the se_ip */
    if ((encrypted = calloc(1, sizeof(*encrypted))) == NULL) {
        free(se_ip);
        pgp_pk_sesskey_free(encrypted_pk_sesskey);
        free(encrypted_pk_sesskey);
        (void) fprintf(stderr, "pgp_push_enc_se_ip: bad alloc\n");
        return false;
    }

    if (!pgp_cipher_start(
          encrypted, encrypted_pk_sesskey->symm_alg, &encrypted_pk_sesskey->key[0], NULL)) {
        free(se_ip);
        pgp_pk_sesskey_free(encrypted_pk_sesskey);
        free(encrypted_pk_sesskey);
        free(encrypted);
        return false;
    }

    se_ip->crypt = encrypted;

    /* And push writer on stack */
    if (!pgp_writer_push(output, encrypt_se_ip_writer, NULL, encrypt_se_ip_destroyer, se_ip)) {
        free(se_ip);
        pgp_pk_sesskey_free(encrypted_pk_sesskey);
        free(encrypted_pk_sesskey);
        free(encrypted);
        return false;
    }
    /* tidy up */
    pgp_pk_sesskey_free(encrypted_pk_sesskey);
    free(encrypted_pk_sesskey);
    return true;
}

static bool
encrypt_se_ip_writer(const uint8_t *src,
                     size_t         len,
                     pgp_error_t ** errors,
                     pgp_writer_t * writer)
{
    const unsigned   bufsz = 128;
    encrypt_se_ip_t *se_ip = pgp_writer_get_arg(writer);
    pgp_output_t *   litoutput = NULL;
    pgp_output_t *   zoutput = NULL;
    pgp_output_t *   output = NULL;
    pgp_memory_t *   litmem = NULL;
    pgp_memory_t *   zmem = NULL;
    pgp_memory_t *   localmem = NULL;
    bool             ret = true;
    bool             compress = writer->ctx->zlevel > 0;

    if (!pgp_setup_memory_write(writer->ctx, &litoutput, &litmem, bufsz) ||
        (compress && !pgp_setup_memory_write(writer->ctx, &zoutput, &zmem, bufsz)) ||
        !pgp_setup_memory_write(writer->ctx, &output, &localmem, bufsz)) {
        (void) fprintf(stderr, "can't setup memory write\n");
        return false;
    }

    /* create literal data packet from source data */
    pgp_write_litdata(litoutput, src, (const int) len, PGP_LDT_BINARY);
    if (pgp_mem_len(litmem) <= len) {
        (void) fprintf(stderr, "encrypt_se_ip_writer: bad len\n");
        pgp_teardown_memory_write(litoutput, litmem);
        if (compress) {
            pgp_teardown_memory_write(zoutput, zmem);
        }
        pgp_teardown_memory_write(output, localmem);
        return false;
    }

    /* create compressed packet from literal data packet */
    if (compress &&
        !pgp_writez(zoutput,
                    pgp_mem_data(litmem),
                    pgp_mem_len(litmem),
                    (pgp_compression_type_t) writer->ctx->zalg,
                    writer->ctx->zlevel)) {
        RNP_LOG("Compression failed");
        return false;
    }

    /* create SE IP packet set from this compressed literal data */
    if (!compress) {
        zmem = litmem;
    }
    pgp_write_se_ip_pktset(
      output, pgp_mem_data(zmem), (unsigned) pgp_mem_len(zmem), se_ip->crypt);
    if (pgp_mem_len(localmem) <= pgp_mem_len(zmem)) {
        RNP_LOG("bad comp len");
        return false;
    }

    /* now write memory to next writer */
    ret = stacked_write(writer, pgp_mem_data(localmem), pgp_mem_len(localmem), errors);

    pgp_memory_free(localmem);
    if (compress) {
        pgp_memory_free(zmem);
    }
    pgp_memory_free(litmem);

    return ret;
}

static void
encrypt_se_ip_destroyer(pgp_writer_t *writer)
{
    encrypt_se_ip_t *se_ip;

    se_ip = pgp_writer_get_arg(writer);

    pgp_cipher_finish(se_ip->crypt);
    free(se_ip->crypt);
    free(se_ip);
}

unsigned
pgp_write_se_ip_pktset(pgp_output_t * output,
                       const uint8_t *data,
                       const size_t   len,
                       pgp_crypt_t *  crypted)
{
    pgp_output_t *mdcoutput;
    pgp_memory_t *mdc;
    uint8_t       hashed[PGP_SHA1_HASH_SIZE];
    uint8_t *     preamble;
    const size_t  mdcsize = 1 + 1 + PGP_SHA1_HASH_SIZE;
    size_t        preamblesize;
    size_t        bufsize;

    const size_t blocksize = pgp_cipher_block_size(crypted);

    preamblesize = blocksize + 2;
    if ((preamble = calloc(1, preamblesize)) == NULL) {
        (void) fprintf(stderr, "pgp_write_se_ip_pktset: bad alloc\n");
        return 0;
    }
    bufsize = preamblesize + len + mdcsize;

    if (bufsize > UINT_MAX) {
        RNP_LOG("Buffer should be less than 4gb\n");
        return 0;
    }

    if (!pgp_write_ptag(output, PGP_PTAG_CT_SE_IP_DATA) ||
        !pgp_write_length(output, (unsigned) (1 + bufsize)) ||
        !pgp_write_scalar(output, PGP_SE_IP_DATA_VERSION, 1)) {
        free(preamble);
        return 0;
    }
    if (pgp_random(preamble, blocksize)) {
        (void) fprintf(stderr, "pgp_random failed\n");
        return 0;
    }
    preamble[blocksize] = preamble[blocksize - 2];
    preamble[blocksize + 1] = preamble[blocksize - 1];

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "preamble", preamble, preamblesize);
    }

    /* now construct MDC packet and add to the end of the buffer */
    if (!pgp_setup_memory_write(output->ctx, &mdcoutput, &mdc, mdcsize)) {
        (void) fprintf(stderr, "can't setup memory write\n");
        return 0;
    }
    pgp_calc_mdc_hash(preamble, preamblesize, data, (unsigned) len, hashed);
    pgp_write_mdc(mdcoutput, hashed);

    if (rnp_get_debug(__FILE__)) {
        hexdump(stderr, "plaintext", data, len);
        hexdump(stderr, "mdc", pgp_mem_data(mdc), PGP_SHA1_HASH_SIZE + 1 + 1);
    }

    /* and write it out */
    pgp_push_enc_crypt(output, crypted);
    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(stderr,
                       "writing %" PRIsize "u + %lu + %" PRIsize "u\n",
                       preamblesize,
                       len,
                       pgp_mem_len(mdc));
    }
    if (!pgp_write(output, preamble, (unsigned) preamblesize) ||
        !pgp_write(output, data, len) ||
        !pgp_write(output, pgp_mem_data(mdc), (unsigned) pgp_mem_len(mdc))) {
        /* \todo fix cleanup here and in old code functions */
        return 0;
    }

    pgp_writer_pop(output);

    /* cleanup  */
    pgp_teardown_memory_write(mdcoutput, mdc);
    free(preamble);

    return 1;
}

typedef struct {
    int fd;
} writer_fd_t;

static bool
fd_writer(const uint8_t *src, size_t len, pgp_error_t **errors, pgp_writer_t *writer)
{
    writer_fd_t *writerfd;
    ssize_t      n;
    size_t       wlen;

    writerfd = pgp_writer_get_arg(writer);

    /* The manpage for write says that writev(2) might fail with EINVAL:

     [EINVAL]           The sum of the iov_len values in the iov array over-
                        flows a 32-bit integer.

     * I see EINVAL on macOS then I tried to write 4Gb as one call.
     * I'm not sure but looks like write(2) is implemented using writev(2) and that explains
     the problem.
     */
    while (len > 0) {
        wlen = len;
        if (wlen > INT_MAX) {
            wlen = INT_MAX;
        }
        n = write(writerfd->fd, src, wlen);
        if (n == -1) {
            (void) fprintf(stderr,
                           "write(%d, %p, %zu) returns -1, errno: %s\n",
                           writerfd->fd,
                           (void *) src,
                           len,
                           strerror(errno));
            return false;
        }
        len -= n;
        src += n;
    }
    return true;
}

static void
writer_fd_destroyer(pgp_writer_t *writer)
{
    free(pgp_writer_get_arg(writer));
}

/**
 * \ingroup Core_WritersFirst
 * \brief Write to a File
 *
 * Set the writer in output to be a stock writer that writes to a file
 * descriptor. If another writer has already been set, then that is
 * first destroyed.
 *
 * \param output The output structure
 * \param fd The file descriptor
 *
 */

void
pgp_writer_set_fd(pgp_output_t *output, int fd)
{
    writer_fd_t *writer;

    if ((writer = calloc(1, sizeof(*writer))) == NULL) {
        (void) fprintf(stderr, "pgp_writer_set_fd: bad alloc\n");
    } else {
        writer->fd = fd;
        if (!pgp_writer_set(output, fd_writer, NULL, writer_fd_destroyer, writer)) {
            free(writer);
        }
    }
}

static bool
memory_writer(const uint8_t *src, size_t len, pgp_error_t **errors, pgp_writer_t *writer)
{
    pgp_memory_t *mem;

    RNP_USED(errors);
    mem = pgp_writer_get_arg(writer);
    if (!pgp_memory_add(mem, src, len)) {
        return false;
    }
    return true;
}

/**
 * \ingroup Core_WritersFirst
 * \brief Write to memory
 *
 * Set a memory writer.
 *
 * \param output The output structure
 * \param mem The memory structure
 * \note It is the caller's responsiblity to call pgp_memory_free(mem)
 * \sa pgp_memory_free()
 */

void
pgp_writer_set_memory(pgp_output_t *output, pgp_memory_t *mem)
{
    pgp_writer_set(output, memory_writer, NULL, NULL, mem);
}

/**************************************************************************/

typedef struct {
    pgp_crypt_t * crypt;
    pgp_memory_t *mem_data;
    pgp_memory_t *litmem;
    pgp_output_t *litoutput;
    pgp_memory_t *se_ip_mem;
    pgp_output_t *se_ip_out;
    pgp_hash_t    hash;
} str_enc_se_ip_t;

static bool str_enc_se_ip_writer(const uint8_t *src,
                                 size_t         len,
                                 pgp_error_t ** errors,
                                 pgp_writer_t * writer);

static bool str_enc_se_ip_finaliser(pgp_error_t **errors, pgp_writer_t *writer);

static void str_enc_se_ip_destroyer(pgp_writer_t *writer);

/* */

/**
\ingroup Core_WritersNext
\param output
\param pubkey
*/
bool
pgp_push_stream_enc_se_ip(pgp_output_t *      output,
                          const pgp_pubkey_t *pubkey,
                          pgp_symm_alg_t      cipher)
{
    pgp_pk_sesskey_t *encrypted_pk_sesskey;
    str_enc_se_ip_t * se_ip;
    const unsigned    bufsz = 1024;
    pgp_crypt_t *     encrypted;

    if ((se_ip = calloc(1, sizeof(*se_ip))) == NULL) {
        (void) fprintf(stderr, "pgp_push_stream_enc_se_ip: bad alloc\n");
        return false;
    }
    encrypted_pk_sesskey = pgp_create_pk_sesskey(pubkey, cipher);
    if (!encrypted_pk_sesskey) {
        RNP_LOG("pgp_create_pk_sesskey failed");
        return false;
    }
    if (!pgp_write_pk_sesskey(output, encrypted_pk_sesskey)) {
        RNP_LOG("pgp_write_pk_sesskey failed");
        return false;
    }

    /* Setup the se_ip */
    if ((encrypted = calloc(1, sizeof(*encrypted))) == NULL) {
        free(se_ip);
        (void) fprintf(stderr, "pgp_push_stream_enc_se_ip: bad alloc\n");
        return false;
    }

    if (!pgp_cipher_start(
          encrypted, encrypted_pk_sesskey->symm_alg, &encrypted_pk_sesskey->key[0], NULL)) {
        free(se_ip);
        return false;
    }

    se_ip->crypt = encrypted;

    se_ip->mem_data = pgp_memory_new();
    if (se_ip->mem_data == NULL) {
        free(encrypted);
        free(se_ip);
        (void) fprintf(stderr, "can't allocate mem\n");
        return false;
    }
    pgp_memory_init(se_ip->mem_data, bufsz);

    se_ip->litmem = NULL;
    se_ip->litoutput = NULL;

    if (!pgp_setup_memory_write(output->ctx, &se_ip->se_ip_out, &se_ip->se_ip_mem, bufsz)) {
        free(encrypted);
        free(se_ip);
        (void) fprintf(stderr, "can't setup memory write\n");
        return false;
    }

    /* And push writer on stack */
    if (!pgp_writer_push(output,
                         str_enc_se_ip_writer,
                         str_enc_se_ip_finaliser,
                         str_enc_se_ip_destroyer,
                         se_ip)) {
        free(se_ip);
    }
    /* tidy up */
    free(encrypted_pk_sesskey);

    return true;
}

/* calculate the partial data length */
static size_t
partial_data_len(size_t len)
{
    size_t mask;
    int    i;

    if (len == 0) {
        (void) fprintf(stderr, "partial_data_len: 0 len\n");
        return 0;
    }
    if (len > MAX_PARTIAL_DATA_LENGTH) {
        return MAX_PARTIAL_DATA_LENGTH;
    }
    mask = MAX_PARTIAL_DATA_LENGTH;
    for (i = 0; i <= MAX_PARTIAL_DATA_LENGTH_POWER; i++) {
        if (mask & len) {
            break;
        }
        mask >>= 1;
    }
    return mask;
}

static unsigned
write_partial_len(pgp_output_t *output, unsigned len)
{
    /* len must be a power of 2 from 0 to 30 */
    uint8_t c;
    int     i;

    for (i = 0; i <= MAX_PARTIAL_DATA_LENGTH_POWER; i++) {
        if ((len >> i) & 1) {
            break;
        }
    }
    c = 224 + i;
    return pgp_write(output, &c, 1);
}

static void
stream_write_litdata(pgp_output_t *output, const uint8_t *data, size_t len)
{
    size_t pdlen;

    while (len > 0) {
        pdlen = partial_data_len(len);
        write_partial_len(output, pdlen);
        pgp_write(output, data, pdlen);
        data += pdlen;
        len -= pdlen;
    }
}

static bool
stream_write_litdata_first(pgp_output_t *         output,
                           const uint8_t *        data,
                           size_t                 len,
                           const pgp_litdata_enum type)
{
    /* \todo do we need to check text data for <cr><lf> line endings ? - Yes, we need.
    For non-PGP_LDT_BINARY we should convert line endings to the canonical CRLF style. */

    size_t   sz_towrite;
    size_t   sz_pd;
    char *   fname = NULL;
    int64_t  mtime = 0;
    unsigned flen = 0;

    /* checking whether filename and modification time are available */
    if (output->ctx) {
        fname = output->ctx->filename;
        mtime = output->ctx->filemtime;
        flen = fname ? strlen(fname) : 0;
        if (flen > 255) {
            (void) fprintf(
              stderr, "stream_write_litdata_first : filename %s too long\n", fname);
            return false;
        }
    }

    sz_towrite = 1 + 1 + flen + 4 + len;
    sz_pd = (size_t) partial_data_len(sz_towrite);
    if (sz_pd < 512) {
        (void) fprintf(stderr, "stream_write_litdata_first: bad sz_pd\n");
        return false;
    }
    pgp_write_ptag(output, PGP_PTAG_CT_LITDATA);
    write_partial_len(output, (unsigned) sz_pd);
    pgp_write_scalar(output, (unsigned) type, 1);
    pgp_write_scalar(output, flen, 1);
    if (flen > 0) {
        pgp_write(output, fname, flen);
    }
    pgp_write_scalar(output, mtime, 4);
    pgp_write(output, data, (unsigned) (sz_pd - 6));

    data += (sz_pd - 6);
    sz_towrite -= (unsigned) sz_pd;

    stream_write_litdata(output, data, (unsigned) sz_towrite);
    return true;
}

static unsigned
stream_write_litdata_last(pgp_output_t *output, const uint8_t *data, unsigned len)
{
    pgp_write_length(output, len);
    return pgp_write(output, data, len);
}

static void
stream_write_se_ip(pgp_output_t *   output,
                   const uint8_t *  data,
                   size_t           len,
                   str_enc_se_ip_t *se_ip)
{
    size_t pdlen;

    while (len > 0) {
        pdlen = partial_data_len(len);
        write_partial_len(output, pdlen);

        pgp_push_enc_crypt(output, se_ip->crypt);
        pgp_write(output, data, pdlen);
        pgp_writer_pop(output);

        pgp_hash_add(&se_ip->hash, data, pdlen);

        data += pdlen;
        len -= pdlen;
    }
}

static unsigned
stream_write_se_ip_first(pgp_output_t *   output,
                         const uint8_t *  data,
                         size_t           len,
                         str_enc_se_ip_t *se_ip)
{
    uint8_t *    preamble;
    size_t       preamblesize;
    size_t       sz_towrite;
    size_t       sz_pd;
    const size_t blocksize = pgp_cipher_block_size(se_ip->crypt);

    preamblesize = blocksize + 2;
    sz_towrite = preamblesize + 1 + len;
    if ((preamble = calloc(1, preamblesize)) == NULL) {
        (void) fprintf(stderr, "stream_write_se_ip_first: bad alloc\n");
        return 0;
    }
    sz_pd = (size_t) partial_data_len(sz_towrite);
    if (sz_pd < 512) {
        free(preamble);
        (void) fprintf(stderr, "stream_write_se_ip_first: bad sz_pd\n");
        return 0;
    }
    pgp_write_ptag(output, PGP_PTAG_CT_SE_IP_DATA);
    write_partial_len(output, sz_pd);
    pgp_write_scalar(output, PGP_SE_IP_DATA_VERSION, 1);
    pgp_push_enc_crypt(output, se_ip->crypt);

    if (pgp_random(preamble, blocksize)) {
        (void) fprintf(stderr, "pgp_random failed\n");
        return 0;
    }
    preamble[blocksize] = preamble[blocksize - 2];
    preamble[blocksize + 1] = preamble[blocksize - 1];
    if (!pgp_hash_create(&se_ip->hash, PGP_HASH_SHA1)) {
        free(preamble);
        (void) fprintf(stderr, "stream_write_se_ip_first: bad hash init\n");
        return 0;
    }
    pgp_write(output, preamble, preamblesize);
    pgp_hash_add(&se_ip->hash, preamble, preamblesize);
    pgp_write(output, data, (sz_pd - preamblesize - 1));
    pgp_hash_add(&se_ip->hash, data, (sz_pd - preamblesize - 1));
    data += (sz_pd - preamblesize - 1);
    sz_towrite -= sz_pd;
    pgp_writer_pop(output);
    stream_write_se_ip(output, data, sz_towrite, se_ip);
    free(preamble);
    return 1;
}

static unsigned
stream_write_se_ip_last(pgp_output_t *   output,
                        const uint8_t *  data,
                        size_t           len,
                        str_enc_se_ip_t *se_ip)
{
    pgp_output_t *mdcoutput;
    pgp_memory_t *mdcmem;
    const size_t  mdcsize = 1 + 1 + PGP_SHA1_HASH_SIZE;
    uint8_t       c;
    uint8_t       hashed[PGP_SHA1_HASH_SIZE];
    size_t        bufsize = len + mdcsize;

    if (bufsize > UINT_MAX) {
        fprintf(stderr, "Buffer should be less than 4gb\n");
        return 0;
    }

    pgp_hash_add(&se_ip->hash, data, len);

    /* MDC packet tag */
    c = MDC_PKT_TAG;
    pgp_hash_add(&se_ip->hash, &c, 1);

    /* MDC packet len */
    c = PGP_SHA1_HASH_SIZE;
    pgp_hash_add(&se_ip->hash, &c, 1);

    /* finish */
    pgp_hash_finish(&se_ip->hash, hashed);

    if (!pgp_setup_memory_write(output->ctx, &mdcoutput, &mdcmem, mdcsize)) {
        return 0;
    }
    pgp_write_mdc(mdcoutput, hashed);

    /* write length of last se_ip chunk */
    pgp_write_length(output, bufsize);

    /* encode everting */
    pgp_push_enc_crypt(output, se_ip->crypt);

    pgp_write(output, data, len);
    pgp_write(output, pgp_mem_data(mdcmem), pgp_mem_len(mdcmem));

    pgp_writer_pop(output);

    pgp_teardown_memory_write(mdcoutput, mdcmem);

    return 1;
}

static bool
str_enc_se_ip_writer(const uint8_t *src,
                     size_t         len,
                     pgp_error_t ** errors,
                     pgp_writer_t * writer)
{
    str_enc_se_ip_t *se_ip;
    bool             ret;
    size_t           datalength;

    se_ip = pgp_writer_get_arg(writer);
    if (se_ip->litoutput == NULL) {
        /* first literal data chunk is not yet written */
        datalength = pgp_mem_len(se_ip->mem_data) + len;

        /* 4.2.2.4. Partial Body Lengths */
        /* The first partial length MUST be at least 512 octets long. */
        if (datalength < 512) {
            if (!pgp_memory_add(se_ip->mem_data, src, len)) {
                return false;
            }
            return true; /* will wait for more data or
                       * end of stream             */
        }

        if (!pgp_setup_memory_write(
              writer->ctx, &se_ip->litoutput, &se_ip->litmem, datalength + 32)) {
            return false;
        }

        // merged first small chunk with next chunk
        if (pgp_mem_len(se_ip->mem_data) > 0) {
            if (!pgp_memory_add(se_ip->mem_data, src, len)) {
                return false;
            }
            stream_write_litdata_first(
              se_ip->litoutput, pgp_mem_data(se_ip->mem_data), datalength, PGP_LDT_BINARY);
        } else {
            stream_write_litdata_first(se_ip->litoutput, src, len, PGP_LDT_BINARY);
        }

        stream_write_se_ip_first(
          se_ip->se_ip_out, pgp_mem_data(se_ip->litmem), pgp_mem_len(se_ip->litmem), se_ip);
    } else {
        stream_write_litdata(se_ip->litoutput, src, len);
        stream_write_se_ip(
          se_ip->se_ip_out, pgp_mem_data(se_ip->litmem), pgp_mem_len(se_ip->litmem), se_ip);
    }

    /* now write memory to next writer */
    ret = stacked_write(
      writer, pgp_mem_data(se_ip->se_ip_mem), pgp_mem_len(se_ip->se_ip_mem), errors);

    pgp_memory_clear(se_ip->litmem);
    pgp_memory_clear(se_ip->se_ip_mem);

    return ret;
}

/* write last chunk of data */
static bool
str_enc_se_ip_finaliser(pgp_error_t **errors, pgp_writer_t *writer)
{
    str_enc_se_ip_t *se_ip;

    se_ip = pgp_writer_get_arg(writer);
    if (se_ip->litoutput == NULL) {
        /* first literal data chunk was not written */
        /* so we know the total length of data, write a simple packet */

        /* create literal data packet from buffered data */
        if (!pgp_setup_memory_write(writer->ctx,
                                    &se_ip->litoutput,
                                    &se_ip->litmem,
                                    pgp_mem_len(se_ip->mem_data) + 32)) {
            return false;
        }

        pgp_write_litdata(se_ip->litoutput,
                          pgp_mem_data(se_ip->mem_data),
                          (const int) pgp_mem_len(se_ip->mem_data),
                          PGP_LDT_BINARY);

        /* create SE IP packet set from this literal data */
        pgp_write_se_ip_pktset(se_ip->se_ip_out,
                               pgp_mem_data(se_ip->litmem),
                               pgp_mem_len(se_ip->litmem),
                               se_ip->crypt);

    } else {
        /* finish writing */
        stream_write_litdata_last(se_ip->litoutput, NULL, 0);
        stream_write_se_ip_last(
          se_ip->se_ip_out, pgp_mem_data(se_ip->litmem), pgp_mem_len(se_ip->litmem), se_ip);
    }

    /* now write memory to next writer */
    return stacked_write(
      writer, pgp_mem_data(se_ip->se_ip_mem), pgp_mem_len(se_ip->se_ip_mem), errors);
}

static void
str_enc_se_ip_destroyer(pgp_writer_t *writer)
{
    str_enc_se_ip_t *se_ip;

    se_ip = pgp_writer_get_arg(writer);
    pgp_memory_free(se_ip->mem_data);
    pgp_teardown_memory_write(se_ip->litoutput, se_ip->litmem);
    pgp_teardown_memory_write(se_ip->se_ip_out, se_ip->se_ip_mem);

    pgp_cipher_finish(se_ip->crypt);

    free(se_ip->crypt);
    free(se_ip);
}

static bool
hash_calculator(const uint8_t *src,
                const size_t   len,
                pgp_error_t ** errors,
                pgp_writer_t * writer)
{
    pgp_hash_t *hash = pgp_writer_get_arg(writer);

    pgp_hash_add(hash, src, len);
    return stacked_write(writer, src, len, errors);
}

bool
pgp_writer_push_hash(pgp_output_t *output, pgp_hash_t *hash)
{
    if (!hash) {
        return false;
    }
    return pgp_writer_push(output, hash_calculator, NULL, NULL, hash);
}

static bool
sum16_calculator(const uint8_t *src,
                 const size_t   len,
                 pgp_error_t ** errors,
                 pgp_writer_t * writer)
{
    uint16_t *sum = pgp_writer_get_arg(writer);

    for (size_t i = 0; i < len; i++) {
        *sum += src[i];
    }
    return stacked_write(writer, src, len, errors);
}

bool
pgp_writer_push_sum16(pgp_output_t *output)
{
    uint16_t *sum = calloc(1, sizeof(*sum));
    if (!sum) {
        return false;
    }
    return pgp_writer_push(output, sum16_calculator, NULL, generic_destroyer, sum);
}

uint16_t
pgp_writer_pop_sum16(pgp_output_t *output)
{
    uint16_t *sum = pgp_writer_get_arg(&output->writer);
    uint16_t  value = *sum;

    pgp_writer_pop(output);
    return value;
}

/**
 \ingroup Core_Writers
 \brief Create and initialise output and mem; Set for writing to mem
 \param ctx Operation context, may be NULL
 \param output Address where new output pointer will be set
 \param mem Address when new mem pointer will be set
 \param bufsz Initial buffer size (will automatically be increased when necessary)
 \note It is the caller's responsiblity to free output and mem.
 \sa pgp_teardown_memory_write()
*/
bool
pgp_setup_memory_write(rnp_ctx_t *ctx, pgp_output_t **output, pgp_memory_t **mem, size_t bufsz)
{
    /*
     * initialise needed structures for writing to memory
     */

    *output = pgp_output_new();
    if (*output == NULL) {
        return false;
    }
    *mem = pgp_memory_new();
    if (*mem == NULL) {
        free(*output);
        return false;
    }

    (*output)->ctx = ctx;
    pgp_memory_init(*mem, bufsz);
    pgp_writer_set_memory(*output, *mem);

    return true;
}

/**
   \ingroup Core_Writers
   \brief Closes writer and frees output and mem
   \param output
   \param mem
   \sa pgp_setup_memory_write()
*/
void
pgp_teardown_memory_write(pgp_output_t *output, pgp_memory_t *mem)
{
    if (output) {
        pgp_writer_close(output); /* new */
    }
    pgp_output_delete(output);
    pgp_memory_free(mem);
}
