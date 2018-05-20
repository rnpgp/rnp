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

#include "writer.h"
#include "memory.h"
#include "utils.h"

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

#define CH_CR ('\r')
#define CH_LF ('\n')
#define CH_DASH ('-')
#define CH_SPACE (' ')
#define CH_TAB ('\t')
#define STR_CR ("\r")
#define STR_LF ("\n")
#define STR_DASHESC ("- ")

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
armored_message_finaliser(pgp_error_t **errors, pgp_writer_t *writer)
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
        fprintf(stderr, "armored_message_finaliser: unusual type\n");
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
pgp_writer_push_armored(pgp_output_t *output, pgp_armor_type_t type)
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
        (void) fprintf(stderr, "pgp_writer_push_armored: bad alloc\n");
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
              &output->errors, PGP_E_W, "%s", "Error switching to armored signature");
            free(linebreak);
            return false;
        }
        break;

    default:
        free(linebreak);
        (void) fprintf(stderr, "pgp_writer_push_armored: unusual type\n");
        return false;
    }

    if (!pgp_writer_push(output, linebreak_writer, NULL, generic_destroyer, linebreak)) {
        free(linebreak);
        return false;
    }

    if ((base64 = calloc(1, sizeof(*base64))) == NULL) {
        (void) fprintf(stderr, "pgp_writer_push_armored: bad alloc\n");
        return false;
    }
    base64->checksum = CRC24_INIT;
    base64->type = type;

    if (!pgp_writer_push(
          output, base64_writer, armored_message_finaliser, generic_destroyer, base64)) {
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
