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
    return !!out->writer.writer((const uint8_t*)src, len, &out->errors, &out->writer);
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

static bool
memory_writer(const uint8_t *src, size_t len, pgp_error_t **errors, pgp_writer_t *writer)
{
    pgp_memory_t *mem;

    RNP_USED(errors);
    mem = (pgp_memory_t*)pgp_writer_get_arg(writer);
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
