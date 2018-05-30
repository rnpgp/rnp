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
 * \brief Parser for OpenPGP packets
 */
#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: packet-parse.c,v 1.51 2012/03/05 02:20:18 christos Exp $");
#endif

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include <repgp/repgp.h>
#include <repgp/repgp_def.h>
#include "pgp-key.h"
#include "crypto/s2k.h"
#include "packet-parse.h"
#include "packet-print.h"
#include "packet-show.h"
#include "stream-packet.h"
#include "stream-key.h"
#include "stream-sig.h"
#include "reader.h"
#include "utils.h"

#define ERRP(cbinfo, cont, err)                    \
    do {                                           \
        cont.u.error = err;                        \
        CALLBACK(PGP_PARSER_ERROR, cbinfo, &cont); \
        return 0;                                  \
        /*NOTREACHED*/                             \
    } while (/*CONSTCOND*/ 0)

/**
 * limread_data reads the specified amount of the subregion's data
 * into a data_t structure
 *
 * \param data    Empty structure which will be filled with data
 * \param len    Number of octets to read
 * \param subregion
 * \param stream    How to parse
 *
 * \return true on success, false on failure
 */
static bool
limread_data(pgp_data_t *data, unsigned len, pgp_region_t *subregion, pgp_stream_t *stream)
{
    data->len = len;

    if (subregion->length - subregion->readc < len) {
        RNP_LOG("bad length\n");
        return false;
    }

    data->contents = calloc(1, data->len);
    if (!data->contents) {
        return false;
    }

    return !!pgp_limited_read(stream,
                              data->contents,
                              data->len,
                              subregion,
                              &stream->errors,
                              &stream->readinfo,
                              &stream->cbinfo);
}

/**
 * read_data reads the remainder of the subregion's data
 * into a data_t structure
 *
 * \param data
 * \param subregion
 * \param stream
 *
 * \return true on success, false on failure
 */
static bool
read_data(pgp_data_t *data, pgp_region_t *region, pgp_stream_t *stream)
{
    const int cc = region->length - region->readc;
    return (cc >= 0) && limread_data(data, (unsigned) cc, region, stream);
}

void
pgp_init_subregion(pgp_region_t *subregion, pgp_region_t *region)
{
    (void) memset(subregion, 0x0, sizeof(*subregion));
    subregion->parent = region;
}

/*
 * XXX: replace pgp_ptag_t with something more appropriate for limiting reads
 */

/**
 * low-level function to read data from reader function
 *
 * Use this function, rather than calling the reader directly.
 *
 * If the accumulate flag is set in *stream, the function
 * adds the read data to the accumulated data, and updates
 * the accumulated length. This is useful if, for example,
 * the application wants access to the raw data as well as the
 * parsed data.
 *
 * This function will also try to read the entire amount asked for, but not
 * if it is over INT_MAX. Obviously many callers will know that they
 * never ask for that much and so can avoid the extra complexity of
 * dealing with return codes and filled-in lengths.
 *
 * \param *dest
 * \param *plength
 * \param flags
 * \param *stream
 *
 * \return PGP_R_OK
 * \return PGP_R_PARTIAL_READ
 * \return PGP_R_EOF
 * \return PGP_R_EARLY_EOF
 *
 * \sa #pgp_reader_ret_t for details of return codes
 */

static int
sub_base_read(pgp_stream_t *stream,
              void *        dest,
              size_t        length,
              pgp_error_t **errors,
              pgp_reader_t *readinfo,
              pgp_cbdata_t *cbinfo)
{
    size_t n;

    /* reading more than this would look like an error */
    if (length > INT_MAX)
        length = INT_MAX;

    for (n = 0; n < length;) {
        int r;

        r = readinfo->reader(stream, (char *) dest + n, length - n, errors, readinfo, cbinfo);
        if (r > (int) (length - n)) {
            (void) fprintf(stderr, "sub_base_read: bad read\n");
            return 0;
        }
        if (r < 0) {
            return r;
        }
        if (r == 0) {
            break;
        }
        n += (unsigned) r;
    }

    if (n == 0) {
        return 0;
    }
    if (readinfo->accumulate) {
        if (readinfo->asize < readinfo->alength) {
            (void) fprintf(stderr, "sub_base_read: bad size\n");
            return 0;
        }
        if (readinfo->alength + n > readinfo->asize) {
            uint8_t *temp;

            readinfo->asize = (readinfo->asize * 2) + (unsigned) n;
            temp = realloc(readinfo->accumulated, readinfo->asize);
            if (temp == NULL) {
                (void) fprintf(stderr, "sub_base_read: bad alloc\n");
                return 0;
            }
            readinfo->accumulated = temp;
        }
        if (readinfo->asize < readinfo->alength + n) {
            (void) fprintf(stderr, "sub_base_read: bad realloc\n");
            return 0;
        }
        (void) memcpy(readinfo->accumulated + readinfo->alength, dest, n);
    }
    /* we track length anyway, because it is used for packet offsets */
    readinfo->alength += (unsigned) n;
    /* and also the position */
    readinfo->position += (unsigned) n;

    return (int) n;
}

int
pgp_stacked_read(pgp_stream_t *stream,
                 void *        dest,
                 size_t        length,
                 pgp_error_t **errors,
                 pgp_reader_t *readinfo,
                 pgp_cbdata_t *cbinfo)
{
    return sub_base_read(stream, dest, length, errors, readinfo->next, cbinfo);
}

/* This will do a full read so long as length < MAX_INT */
static int
base_read(uint8_t *dest, size_t length, pgp_stream_t *stream)
{
    return sub_base_read(
      stream, dest, length, &stream->errors, &stream->readinfo, &stream->cbinfo);
}

/*
 * Read a full size_t's worth. If the return is < than length, then
 * *last_read tells you why - < 0 for an error, == 0 for EOF
 */

static size_t
full_read(pgp_stream_t *stream,
          uint8_t *     dest,
          size_t        length,
          int *         last_read,
          pgp_error_t **errors,
          pgp_reader_t *readinfo,
          pgp_cbdata_t *cbinfo)
{
    size_t t;
    int    r = 0; /* preset in case some loon calls with length
                   * == 0 */

    for (t = 0; t < length;) {
        r = sub_base_read(stream, dest + t, length - t, errors, readinfo, cbinfo);
        if (r <= 0) {
            *last_read = r;
            return t;
        }
        t += (size_t) r;
    }

    *last_read = r;

    return t;
}

/** Read a scalar value of selected length from reader.
 *
 * Read an unsigned scalar value from reader in Big Endian representation.
 *
 * This function does not know or care about packet boundaries. It
 * also assumes that an EOF is an error.
 *
 * \param *result    The scalar value is stored here
 * \param *reader    Our reader
 * \param length    How many bytes to read
 * \return        1 on success, 0 on failure
 */
static bool
_read_scalar(unsigned *result, unsigned length, pgp_stream_t *stream)
{
    unsigned t = 0;

    if (length > sizeof(*result)) {
        (void) fprintf(stderr, "_read_scalar: bad length\n");
        return false;
    }

    while (length--) {
        uint8_t c;
        int     r;

        r = base_read(&c, 1, stream);
        if (r != 1)
            return false;
        t = (t << 8) + c;
    }

    *result = t;
    return true;
}

/**
 * \ingroup Core_ReadPackets
 * \brief Read bytes from a region within the packet.
 *
 * Read length bytes into the buffer pointed to by *dest.
 * Make sure we do not read over the packet boundary.
 * Updates the Packet Tag's pgp_ptag_t::readc.
 *
 * If length would make us read over the packet boundary, or if
 * reading fails, we call the callback with an error.
 *
 * Note that if the region is indeterminate, this can return a short
 * read - check region->last_read for the length. EOF is indicated by
 * a success return and region->last_read == 0 in this case (for a
 * region of known length, EOF is an error).
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param dest        The destination buffer
 * \param length    How many bytes to read
 * \param region    Pointer to packet region
 * \param errors    Error stack
 * \param readinfo        Reader info
 * \param cbinfo    Callback info
 * \return        1 on success, 0 on error
 */
bool
pgp_limited_read(pgp_stream_t *stream,
                 uint8_t *     dest,
                 size_t        length,
                 pgp_region_t *region,
                 pgp_error_t **errors,
                 pgp_reader_t *readinfo,
                 pgp_cbdata_t *cbinfo)
{
    size_t r;
    int    lr;

    if (!region->indeterminate && region->readc + length > region->length) {
        PGP_ERROR_1(errors, PGP_E_P_NOT_ENOUGH_DATA, "%s", "Not enough data");
        return false;
    }
    r = full_read(stream, dest, length, &lr, errors, readinfo, cbinfo);
    if (lr < 0) {
        PGP_ERROR_1(errors, PGP_E_R_READ_FAILED, "%s", "Read failed");
        return false;
    }
    if (!region->indeterminate && r != length) {
        PGP_ERROR_1(errors, PGP_E_R_READ_FAILED, "%s", "Read failed");
        return false;
    }
    region->last_read = (unsigned) r;
    do {
        region->readc += (unsigned) r;
        if (region->parent && region->length > region->parent->length) {
            (void) fprintf(stderr, "ops_limited_read: bad length\n");
            return false;
        }
    } while ((region = region->parent) != NULL);
    return true;
}

/**
   \ingroup Core_ReadPackets
   \brief Call pgp_limited_read on next in stack
*/
bool
pgp_stacked_limited_read(pgp_stream_t *stream,
                         uint8_t *     dest,
                         unsigned      length,
                         pgp_region_t *region,
                         pgp_error_t **errors,
                         pgp_reader_t *readinfo,
                         pgp_cbdata_t *cbinfo)
{
    return pgp_limited_read(stream, dest, length, region, errors, readinfo->next, cbinfo);
}

static bool
limread(uint8_t *dest, unsigned length, pgp_region_t *region, pgp_stream_t *info)
{
    return pgp_limited_read(
      info, dest, length, region, &info->errors, &info->readinfo, &info->cbinfo);
}

/** Skip over length bytes of this packet.
 *
 * Calls limread() to skip over some data.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param length    How many bytes to skip
 * \param *region    Pointer to packet region
 * \param *stream    How to parse
 * \return        1 on success, 0 on error (calls the cb with PGP_PARSER_ERROR in
 * limread()).
 */
static bool
limskip(unsigned length, pgp_region_t *region, pgp_stream_t *stream)
{
    uint8_t buf[RNP_BUFSIZ];

    while (length > 0) {
        unsigned n = length % RNP_BUFSIZ;

        if (!limread(buf, n, region, stream)) {
            return false;
        }
        length -= n;
    }
    return true;
}

/** Read a scalar.
 *
 * Read a big-endian scalar of length bytes, respecting packet
 * boundaries (by calling limread() to read the raw data).
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest        The scalar value is stored here
 * \param length    How many bytes make up this scalar (at most 4)
 * \param *region    Pointer to current packet region
 * \param *stream    How to parse
 * \param *cb        The callback
 * \return        1 on success, 0 on error (calls the cb with PGP_PARSER_ERROR in
 * limread()).
 *
 * \see RFC4880 3.1
 */
static bool
limread_scalar(unsigned *dest, unsigned len, pgp_region_t *region, pgp_stream_t *stream)
{
    uint8_t  c[4] = "";
    unsigned t;
    unsigned n;

    if (len > 4) {
        (void) fprintf(stderr, "limread_scalar: bad length\n");
        return false;
    }
    /*LINTED*/
    if (/*CONSTCOND*/ sizeof(*dest) < 4) {
        (void) fprintf(stderr, "limread_scalar: bad dest\n");
        return false;
    }
    if (!limread(c, len, region, stream)) {
        return false;
    }
    for (t = 0, n = 0; n < len; ++n) {
        t = (t << 8) + c[n];
    }
    *dest = t;
    return true;
}

/** Read a timestamp.
 *
 * Timestamps in OpenPGP are unix time, i.e. seconds since The Epoch (1.1.1970).  They are
 * stored in an unsigned scalar
 * of 4 bytes.
 *
 * This function reads the timestamp using limread_scalar().
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *dest        The timestamp is stored here
 * \param *ptag        Pointer to current packet's Packet Tag.
 * \param *reader    Our reader
 * \param *cb        The callback
 * \return        see limread_scalar()
 *
 * \see RFC4880 3.5
 */
static bool
limited_read_time(time_t *dest, pgp_region_t *region, pgp_stream_t *stream)
{
    uint8_t c;
    time_t  mytime = 0;
    int     i;

    /*
     * Cannot assume that time_t is 4 octets long -
     * SunOS 5.10 and NetBSD both have 64-bit time_ts.
     */
    if (/* CONSTCOND */ sizeof(time_t) == 4) {
        return limread_scalar((unsigned *) (void *) dest, 4, region, stream);
    }
    for (i = 0; i < 4; i++) {
        if (!limread(&c, 1, region, stream)) {
            return false;
        }
        mytime = (mytime << 8) + c;
    }
    *dest = mytime;
    return true;
}

static bool
limread_mpi(pgp_mpi_t *mpi, pgp_region_t *region, pgp_stream_t *stream)
{
    /* an MPI has a 2 byte length part.
     * Length is given in bits, so the
     * largest we should ever need for
     * the buffer is RNP_BUFSIZ bytes. */
    unsigned length;
    unsigned nonzero;
    unsigned ret;

    ret = (unsigned) limread_scalar(&length, 2, region, stream);
    if (!ret) {
        return false;
    }

    nonzero = length & 7; /* there should be this many zero bits in the MS byte */
    if (!nonzero) {
        nonzero = 8;
    }
    length = (length + 7) / 8;

    if (length == 0) {
        /* if we try to read a length of 0, then fail */
        if (rnp_get_debug(__FILE__)) {
            (void) fprintf(stderr, "limread_mpi: 0 length\n");
        }
        return false;
    }
    if (length > PGP_MPINT_SIZE) {
        (void) fprintf(stderr, "limread_mpi: bad length\n");
        return false;
    }
    if (!limread(mpi->mpi, length, region, stream)) {
        return false;
    }
    if (((unsigned) mpi->mpi[0] >> nonzero) != 0 ||
        !((unsigned) mpi->mpi[0] & (1U << (nonzero - 1U)))) {
        PGP_ERROR_1(&stream->errors, PGP_E_P_MPI_FORMAT_ERROR, "%s", "MPI Format error");
        return false;
    }
    mpi->len = length;
    return true;
}

/** Read some data with a New-Format length from reader.
 *
 * \sa Internet-Draft RFC4880.txt Section 4.2.2
 *
 * \param *length    Where the decoded length will be put
 * \param *stream    How to parse
 * \return           true if success
 *
 */

static bool
read_new_length(unsigned *length, pgp_stream_t *stream)
{
    uint8_t c;

    stream->partial_read = 0;
    if (base_read(&c, 1, stream) != 1) {
        return false;
    }
    if (c < 192) {
        /* 1. One-octet packet */
        *length = c;
        return true;
    }
    if (c < 224) {
        /* 2. Two-octet packet */
        unsigned t = (c - 192) << 8;

        if (base_read(&c, 1, stream) != 1) {
            return false;
        }
        *length = t + c + 192;
        return true;
    }
    if (c < 255) {
        return false;
    }
    /* 4. Five-Octet packet */
    return _read_scalar(length, 4, stream);
}

/** Read the length information for a new format Packet Tag.
 *
 * New style Packet Tags encode the length in one to five octets.  This function reads the
 * right amount of bytes and
 * decodes it to the proper length information.
 *
 * This function makes sure to respect packet boundaries.
 *
 * \param *length    return the length here
 * \param *ptag        Pointer to current packet's Packet Tag.
 * \param *reader    Our reader
 * \param *cb        The callback
 * \return        true on success, 0 on error (by limread_scalar() or limread() or if the
 * MPI
 * is
 * not properly formed (XXX
 *                  see comment below)
 *
 * \see RFC4880 4.2.2
 * \see pgp_ptag_t
 */
static bool
limited_read_new_length(unsigned *length, pgp_region_t *region, pgp_stream_t *stream)
{
    uint8_t c = 0x0;

    if (!limread(&c, 1, region, stream)) {
        return false;
    }
    if (c < 192) {
        *length = c;
        return true;
    }
    if (c < 224) {
        unsigned t = (c - 192) << 8;

        if (!limread(&c, 1, region, stream)) {
            return false;
        }
        *length = t + c + 192;
        return true;
    }
    if (c < 255) {
        return false;
    }
    return limread_scalar(length, 4, region, stream);
}

/**
\ingroup Core_Create
\brief Free allocated memory
*/
void
pgp_data_free(pgp_data_t *data)
{
    free(data->contents);
    data->contents = NULL;
    data->len = 0;
}

/**
\ingroup Core_Create
\brief Free allocated memory
*/
/* ! Free packet memory, set pointer to NULL */
void
pgp_rawpacket_free(pgp_rawpacket_t *packet)
{
    if (packet->raw == NULL) {
        return;
    }
    free(packet->raw);
    packet->raw = NULL;
}

/**
\ingroup Core_Create
\brief Free allocated memory
*/
/* ! Free any memory allocated when parsing the packet content */
void
repgp_parser_content_free(pgp_packet_t *c)
{
    switch (c->tag) {
    case PGP_PARSER_PTAG:
    case PGP_PTAG_CT_COMPRESSED:
    case PGP_PTAG_SS_CREATION_TIME:
    case PGP_PTAG_SS_EXPIRATION_TIME:
    case PGP_PTAG_SS_KEY_EXPIRY:
    case PGP_PTAG_SS_TRUST:
    case PGP_PTAG_SS_ISSUER_KEY_ID:
    case PGP_PTAG_CT_1_PASS_SIG:
    case PGP_PTAG_SS_PRIMARY_USER_ID:
    case PGP_PTAG_SS_REVOCABLE:
    case PGP_PTAG_SS_REVOCATION_KEY:
    case PGP_PTAG_CT_SIGNATURE_HEADER:
    case PGP_PARSER_DONE:
        break;

    case PGP_PTAG_CT_TRUST:
        pgp_data_free(&c->u.trust);
        break;

    case PGP_PTAG_CT_SIGNATURE:
    case PGP_PTAG_CT_SIGNATURE_FOOTER:
        free_signature(&c->u.sig);
        break;

    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        free_key_pkt(&c->u.key);
        break;

    case PGP_PTAG_CT_USER_ID:
        pgp_userid_free(&c->u.userid);
        break;

    case PGP_PTAG_SS_SIGNERS_USER_ID:
        break;

    case PGP_PTAG_CT_USER_ATTR:
        pgp_data_free(&c->u.userattr);
        break;

    case PGP_PTAG_SS_PREFERRED_SKA:
    case PGP_PTAG_SS_PREFERRED_HASH:
    case PGP_PTAG_SS_PREF_COMPRESS:
    case PGP_PTAG_SS_KEY_FLAGS:
    case PGP_PTAG_SS_KEYSERV_PREFS:
    case PGP_PTAG_SS_FEATURES:
    case PGP_PTAG_SS_NOTATION_DATA:
    case PGP_PTAG_SS_POLICY_URI:
    case PGP_PTAG_SS_REGEXP:
    case PGP_PTAG_SS_PREF_KEYSERV:
    case PGP_PTAG_SS_REVOCATION_REASON:
        break;

    case PGP_PTAG_SS_EMBEDDED_SIGNATURE:
        break;

    case PGP_PTAG_SS_ISSUER_FPR:
        break;

    case PGP_PARSER_PACKET_END:
        pgp_rawpacket_free(&c->u.packet);
        break;

    case PGP_PTAG_RAW_SS:
        if (c->u.ss_raw.raw != NULL) {
            free(c->u.ss_raw.raw);
        }
        c->u.ss_raw.raw = NULL;
        break;

    case PGP_PARSER_ERROR:
    case PGP_PARSER_ERRCODE:
        break;

    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        free_key_pkt(&c->u.key);
        break;

    default:
        fprintf(stderr, "Can't free %d (0x%x)\n", c->tag, c->tag);
    }
}

/**
 * \ingroup Core_ReadPackets
 * \brief Parse a public key packet.
 *
 * This function parses an entire v3 (== v2) or v4 public key packet for RSA, ElGamal, and DSA
 * keys.
 *
 * Once the key has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag        Pointer to the current Packet Tag.  This function should consume the
 * entire packet.
 * \param *reader    Our reader
 * \param *cb        The callback
 * \return        1 on success, 0 on error
 *
 * \see RFC4880 5.5.2
 */
static bool
parse_pubkey(pgp_stream_t *stream)
{
    pgp_source_t src;
    pgp_packet_t pkt;
    memset(&pkt, 0x00, sizeof(pgp_packet_t));

    if (!stream->readinfo.accumulate) {
        return false;
    }

    if (init_mem_src(&src, stream->readinfo.accumulated, stream->readinfo.alength, false)) {
        return false;
    }

    if (stream_parse_key(&src, &pkt.u.key)) {
        src_close(&src);
        return false;
    }
    src_close(&src);

    CALLBACK(pkt.u.key.tag, &stream->cbinfo, &pkt);
    return true;
}

/**
 * \ingroup Core_ReadPackets
 * \brief Parse one user attribute packet.
 *
 * User attribute packets contain one or more attribute subpackets.
 * For now, handle the whole packet as raw data.
 */

static bool
parse_userattr(pgp_region_t *region, pgp_stream_t *stream)
{
    pgp_packet_t pkt = {0};

    /*
     * xxx- treat as raw data for now. Could break down further into
     * attribute sub-packets later - rachel
     */
    if (region->readc != 0) {
        /* We should not have read anything so far */
        (void) fprintf(stderr, "parse_userattr: bad length\n");
        return false;
    }
    if (!read_data(&pkt.u.userattr, region, stream)) {
        return false;
    }
    CALLBACK(PGP_PTAG_CT_USER_ATTR, &stream->cbinfo, &pkt);
    return true;
}

/**
\ingroup Core_Create
\brief Free allocated memory
*/
/* ! Free the memory used when parsing this packet type */
void
pgp_userid_free(uint8_t **id)
{
    if (!id) {
        return;
    }
    free(*id);
    *id = NULL;
}

/**
 * \ingroup Core_ReadPackets
 * \brief Parse a user id.
 *
 * This function parses an user id packet, which is basically just a char array the size of the
 * packet.
 *
 * The char array is to be treated as an UTF-8 string.
 *
 * The userid gets null terminated by this function.  Freeing it is the responsibility of the
 * caller.
 *
 * Once the userid has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag        Pointer to the Packet Tag.  This function should consume the entire
 * packet.
 * \param *reader    Our reader
 * \param *cb        The callback
 * \return        1 on success, 0 on error
 *
 * \see RFC4880 5.11
 */
static bool
parse_userid(pgp_region_t *region, pgp_stream_t *stream)
{
    pgp_packet_t pkt = {0};

    if (region->readc != 0) {
        /* We should not have read anything so far */
        (void) fprintf(stderr, "parse_userid: bad length\n");
        return false;
    }

    if ((pkt.u.userid = calloc(1, region->length + 1)) == NULL) {
        (void) fprintf(stderr, "parse_userid: bad alloc\n");
        return false;
    }

    if (region->length && !limread(pkt.u.userid, region->length, region, stream)) {
        pgp_userid_free(&pkt.u.userid);
        return false;
    }
    pkt.u.userid[region->length] = 0x0;
    CALLBACK(PGP_PTAG_CT_USER_ID, &stream->cbinfo, &pkt);
    return true;
}

/**
 * \ingroup Core_Parse
 * \brief Parse a version 3 signature.
 *
 * This function parses an version 3 signature packet, handling RSA and DSA signatures.
 *
 * Once the signature has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag        Pointer to the Packet Tag.  This function should consume the entire
 * packet.
 * \param *reader    Our reader
 * \param *cb        The callback
 * \return        true on success, false on error
 *
 * \see RFC4880 5.2.2
 */
static bool
parse_v3_sig(pgp_region_t *region, pgp_stream_t *stream)
{
    pgp_packet_t pkt;
    uint8_t      c = 0x0;

    /* clear signature */
    (void) memset(&pkt.u.sig, 0x0, sizeof(pkt.u.sig));

    pkt.u.sig.version = PGP_V3;

    /* hash info length */
    if (!limread(&c, 1, region, stream)) {
        return false;
    }
    if (c != 5) {
        ERRP(&stream->cbinfo, pkt, "bad hash info length");
    }

    if (!limread(&c, 1, region, stream)) {
        return false;
    }
    pkt.u.sig.type = (pgp_sig_type_t) c;
    /* XXX: check signature type */

    time_t cr = 0;

    if (!limited_read_time(&cr, region, stream)) {
        return false;
    }
    pkt.u.sig.creation_time = cr;

    if (!limread(pkt.u.sig.signer, PGP_KEY_ID_SIZE, region, stream)) {
        return false;
    }

    if (!limread(&c, 1, region, stream)) {
        return false;
    }
    pkt.u.sig.palg = (pgp_pubkey_alg_t) c;
    /* XXX: check algorithm */

    if (!limread(&c, 1, region, stream)) {
        return false;
    }
    pkt.u.sig.halg = (pgp_hash_alg_t) c;
    /* XXX: check algorithm */

    if (!limread(pkt.u.sig.lbits, 2, region, stream)) {
        return false;
    }

    switch (pkt.u.sig.palg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_SIGN_ONLY:
        if (!limread_mpi(&pkt.u.sig.material.rsa.s, region, stream)) {
            return false;
        }
        break;

    case PGP_PKA_DSA:
        if (!limread_mpi(&pkt.u.sig.material.dsa.r, region, stream) ||
            !limread_mpi(&pkt.u.sig.material.dsa.s, region, stream)) {
            return false;
        }
        break;

    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
        if (!limread_mpi(&pkt.u.sig.material.ecc.r, region, stream) ||
            !limread_mpi(&pkt.u.sig.material.ecc.s, region, stream)) {
            return false;
        }
        break;

    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!limread_mpi(&pkt.u.sig.material.eg.r, region, stream) ||
            !limread_mpi(&pkt.u.sig.material.eg.s, region, stream)) {
            return false;
        }
        break;

    default:
        PGP_ERROR_1(&stream->errors,
                    PGP_E_ALG_UNSUPPORTED_SIGNATURE_ALG,
                    "Unsupported signature key algorithm (%s)",
                    pgp_show_pka(pkt.u.sig.palg));
        return false;
    }

    if (region->readc != region->length) {
        PGP_ERROR_1(&stream->errors,
                    PGP_E_R_UNCONSUMED_DATA,
                    "Unconsumed data (%d)",
                    region->length - region->readc);
        return false;
    }
    CALLBACK(PGP_PTAG_CT_SIGNATURE, &stream->cbinfo, &pkt);
    return true;
}

static bool
read_subpkt(pgp_signature_t *        sig,
            pgp_region_t *           region,
            pgp_stream_t *           stream,
            pgp_sig_subpacket_type_t type)
{
    pgp_data_t        data = {0};
    pgp_sig_subpkt_t *subpkt = NULL;
    if (!read_data(&data, region, stream)) {
        return false;
    }
    subpkt = signature_add_subpkt(sig, type, data.len, false);

    if (!subpkt) {
        pgp_data_free(&data);
        return false;
    }

    subpkt->hashed = 1;
    memcpy(subpkt->data, data.contents, data.len);
    pgp_data_free(&data);
    if (!signature_parse_subpacket(subpkt)) {
        return false;
    }

    return true;
}

/**
 * \ingroup Core_ReadPackets
 * \brief Parse one signature sub-packet.
 *
 * Version 4 signatures can have an arbitrary amount of (hashed and
 * unhashed) subpackets.  Subpackets are used to hold optional
 * attributes of subpackets.
 *
 * This function parses one such signature subpacket.
 *
 * Once the subpacket has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag        Pointer to the Packet Tag.  This function should consume the entire
 * subpacket.
 * \param *reader    Our reader
 * \param *cb        The callback
 * \return           true on success
 *
 * \see RFC4880 5.2.3
 */
static bool
parse_one_sig_subpacket(pgp_signature_t *sig, pgp_region_t *region, pgp_stream_t *stream)
{
    pgp_region_t subregion = {0};
    pgp_packet_t pkt = {0};
    uint8_t      bools = 0x0;
    uint8_t      c = 0x0;
    unsigned     doread = 1;
    unsigned     t8;
    unsigned     t7;

    pgp_init_subregion(&subregion, region);
    if (!limited_read_new_length(&subregion.length, region, stream)) {
        return false;
    }

    if (subregion.length > region->length) {
        ERRP(&stream->cbinfo, pkt, "Subpacket too long");
    }

    if (!limread(&c, 1, &subregion, stream)) {
        return false;
    }

    t8 = (c & 0x7f) / 8;
    t7 = 1 << (c & 7);

    pkt.critical = (unsigned) c >> 7;
    pkt.tag = (pgp_content_enum)(PGP_PTAG_SIG_SUBPKT_BASE + (c & 0x7f));

    /* Application wants it delivered raw */
    if (stream->ss_raw[t8] & t7) {
        pkt.u.ss_raw.tag = pkt.tag;
        pkt.u.ss_raw.length = subregion.length - 1;
        pkt.u.ss_raw.raw = calloc(1, pkt.u.ss_raw.length);
        if (pkt.u.ss_raw.raw == NULL) {
            (void) fprintf(stderr, "parse_one_sig_subpacket: bad alloc\n");
            return false;
        }
        if (!limread(pkt.u.ss_raw.raw, (unsigned) pkt.u.ss_raw.length, &subregion, stream)) {
            free(pkt.u.ss_raw.raw);
            return false;
        }
        CALLBACK(PGP_PTAG_RAW_SS, &stream->cbinfo, &pkt);
        if (pkt.u.ss_raw.raw != NULL) {
            free(pkt.u.ss_raw.raw);
        }
        return true;
    }
    switch (pkt.tag) {
    case PGP_PTAG_SS_CREATION_TIME:
    case PGP_PTAG_SS_EXPIRATION_TIME:
    case PGP_PTAG_SS_KEY_EXPIRY: {
        time_t tm = 0;
        bool   res = false;
        if (!limited_read_time(&tm, &subregion, stream)) {
            return false;
        }
        if (pkt.tag == PGP_PTAG_SS_CREATION_TIME) {
            res = signature_set_creation(sig, tm);
        } else if (pkt.tag == PGP_PTAG_SS_EXPIRATION_TIME) {
            res = signature_set_expiration(sig, tm);
        } else if (pkt.tag == PGP_PTAG_SS_KEY_EXPIRY) {
            res = signature_set_key_expiration(sig, tm);
        }
        if (!res) {
            return false;
        }
        break;
    }
    case PGP_PTAG_SS_TRUST: {
        uint8_t level, amount;
        if (!limread(&level, 1, &subregion, stream) ||
            !limread(&amount, 1, &subregion, stream)) {
            return false;
        }
        if (!signature_set_trust(sig, level, amount)) {
            return false;
        }
        break;
    }
    case PGP_PTAG_SS_REVOCABLE:
        if (!limread(&bools, 1, &subregion, stream)) {
            return false;
        }
        if (!signature_set_revocable(sig, bools)) {
            return false;
        }
        break;
    case PGP_PTAG_SS_ISSUER_KEY_ID: {
        uint8_t issuer[PGP_KEY_ID_SIZE] = {0};
        if (!limread(issuer, PGP_KEY_ID_SIZE, &subregion, stream)) {
            return false;
        }
        if (!signature_set_keyid(sig, issuer)) {
            return false;
        }
        break;
    }
    case PGP_PTAG_SS_PREFERRED_SKA: {
        pgp_data_t pref = {0};
        bool       res = false;
        if (!read_data(&pref, &subregion, stream)) {
            return false;
        }
        res = signature_set_preferred_symm_algs(sig, pref.contents, pref.len);
        pgp_data_free(&pref);
        if (!res) {
            return false;
        }
        break;
    }
    case PGP_PTAG_SS_PREFERRED_HASH: {
        pgp_data_t pref = {0};
        bool       res = false;
        if (!read_data(&pref, &subregion, stream)) {
            return false;
        }
        res = signature_set_preferred_hash_algs(sig, pref.contents, pref.len);
        pgp_data_free(&pref);
        if (!res) {
            return false;
        }
        break;
    }
    case PGP_PTAG_SS_PREF_COMPRESS: {
        pgp_data_t pref = {0};
        bool       res = false;
        if (!read_data(&pref, &subregion, stream)) {
            return false;
        }
        res = signature_set_preferred_z_algs(sig, pref.contents, pref.len);
        pgp_data_free(&pref);
        if (!res) {
            return false;
        }
        break;
    }
    case PGP_PTAG_SS_PRIMARY_USER_ID:
        if (!limread(&bools, 1, &subregion, stream)) {
            return false;
        }
        if (!signature_set_primary_uid(sig, bools)) {
            return false;
        }
        break;
    case PGP_PTAG_SS_KEY_FLAGS: {
        pgp_data_t flags = {0};
        bool       res = false;
        if (!read_data(&flags, &subregion, stream)) {
            return false;
        }
        res = signature_set_key_flags(sig, flags.contents[0]);
        pgp_data_free(&flags);
        if (!res) {
            return false;
        }
        break;
    }
    case PGP_PTAG_SS_KEYSERV_PREFS: {
        pgp_data_t prefs = {0};
        bool       res = false;
        if (!read_data(&prefs, &subregion, stream)) {
            return false;
        }
        res = signature_set_key_server_prefs(sig, prefs.contents[0]);
        pgp_data_free(&prefs);
        if (!res) {
            return false;
        }
        break;
    }
    case PGP_PTAG_SS_FEATURES: {
        pgp_data_t data = {0};
        if (!read_data(&data, &subregion, stream)) {
            return false;
        }
        signature_set_features(sig, data.contents[0]);
        pgp_data_free(&data);
        break;
    }
    case PGP_PTAG_SS_SIGNERS_USER_ID: {
        pgp_data_t data = {0};
        if (!read_data(&data, &subregion, stream)) {
            return false;
        }
        signature_set_signer_uid(sig, data.contents, data.len);
        pgp_data_free(&data);
        break;
    }
    case PGP_PTAG_SS_EMBEDDED_SIGNATURE: {
        pgp_data_t data = {0};
        if (!read_data(&data, &subregion, stream)) {
            return false;
        }
        signature_set_embedded_sig(sig, data.contents, data.len);
        pgp_data_free(&data);
        break;
    }
    case PGP_PTAG_SS_ISSUER_FPR: {
        pgp_data_t fpdata = {0};
        if (!read_data(&fpdata, &subregion, stream) || fpdata.len != 21 ||
            fpdata.contents[0] != 0x04) {
            return false;
        }
        pgp_fingerprint_t fp = {.length = fpdata.len - 1};
        memcpy(fp.fingerprint, fpdata.contents + 1, fp.length);
        signature_set_keyfp(sig, &fp);
        pgp_data_free(&fpdata);
        break;
    }
    case PGP_PTAG_SS_NOTATION_DATA:
        if (!read_subpkt(sig, &subregion, stream, PGP_SIG_SUBPKT_NOTATION_DATA)) {
            return false;
        }
        break;
    case PGP_PTAG_SS_POLICY_URI:
        if (!read_subpkt(sig, &subregion, stream, PGP_SIG_SUBPKT_POLICY_URI)) {
            return false;
        }
        break;
    case PGP_PTAG_SS_REGEXP:
        if (!read_subpkt(sig, &subregion, stream, PGP_SIG_SUBPKT_REGEXP)) {
            return false;
        }
        break;
    case PGP_PTAG_SS_PREF_KEYSERV:
        if (!read_subpkt(sig, &subregion, stream, PGP_SIG_SUBPKT_PREF_KEYSERV)) {
            return false;
        }
        break;
    case PGP_PTAG_SS_REVOCATION_REASON:
        if (!read_subpkt(sig, &subregion, stream, PGP_SIG_SUBPKT_REVOCATION_REASON)) {
            return false;
        }
        break;
    case PGP_PTAG_SS_REVOCATION_KEY:
        if (!read_subpkt(sig, &subregion, stream, PGP_SIG_SUBPKT_REVOCATION_KEY)) {
            return false;
        }
        break;

    default:
        if (stream->ss_parsed[t8] & t7) {
            PGP_ERROR_1(&stream->errors,
                        PGP_E_PROTO_UNKNOWN_SS,
                        "Unknown signature subpacket type (%d)",
                        c & 0x7f);
        }
        doread = 0;
        break;
    }

    /* Application doesn't want it delivered parsed */
    if (!(stream->ss_parsed[t8] & t7)) {
        if (pkt.critical) {
            PGP_ERROR_1(&stream->errors,
                        PGP_E_PROTO_CRITICAL_SS_IGNORED,
                        "Critical signature subpacket ignored (%d)",
                        c & 0x7f);
        }
        if (!doread && !limskip(subregion.length - 1, &subregion, stream)) {
            return false;
        }
        if (doread) {
            repgp_parser_content_free(&pkt);
        }
        return true;
    }
    if (doread && subregion.readc != subregion.length) {
        PGP_ERROR_1(&stream->errors,
                    PGP_E_R_UNCONSUMED_DATA,
                    "Unconsumed data (%d)",
                    subregion.length - subregion.readc);
        return false;
    }
    CALLBACK(pkt.tag, &stream->cbinfo, &pkt);
    return true;
}

/**
 * \ingroup Core_ReadPackets
 * \brief Parse several signature subpackets.
 *
 * Hashed and unhashed subpacket sets are preceded by an octet count that specifies the length
 * of the complete set.
 * This function parses this length and then calls parse_one_sig_subpacket() for each subpacket
 * until the
 * entire set is consumed.
 *
 * This function does not call the callback directly, parse_one_sig_subpacket() does for each
 * subpacket.
 *
 * \param *ptag        Pointer to the Packet Tag.
 * \param *reader    Our reader
 * \param *cb        The callback
 * \return           true on success
 *
 * \see RFC4880 5.2.3
 */
static bool
parse_sig_subpkts(pgp_signature_t *sig, pgp_region_t *region, pgp_stream_t *stream)
{
    pgp_region_t subregion = {0};
    pgp_packet_t pkt = {0};

    pgp_init_subregion(&subregion, region);
    if (!limread_scalar(&subregion.length, 2, region, stream)) {
        return false;
    }

    if (subregion.length > region->length) {
        ERRP(&stream->cbinfo, pkt, "Subpacket set too long");
    }

    while (subregion.readc < subregion.length) {
        if (!parse_one_sig_subpacket(sig, &subregion, stream)) {
            return false;
        }
    }

    if (subregion.readc != subregion.length) {
        if (!limskip(subregion.length - subregion.readc, &subregion, stream)) {
            ERRP(&stream->cbinfo, pkt, "parse_sig_subpkts: subpacket length read mismatch");
        }
        ERRP(&stream->cbinfo, pkt, "Subpacket length mismatch");
    }
    return true;
}

/**
 * \ingroup Core_ReadPackets
 * \brief Parse a version 4 signature.
 *
 * This function parses a version 4 signature including all its hashed and unhashed subpackets.
 *
 * Once the signature packet has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag        Pointer to the Packet Tag.
 * \param *reader    Our reader
 * \param *cb        The callback
 * \return        true on success, false on error
 *
 * \see RFC4880 5.2.3
 */
static bool
parse_v4_sig(pgp_region_t *region, pgp_stream_t *stream)
{
    pgp_packet_t pkt;
    uint8_t      c = 0x0;

    if (rnp_get_debug(__FILE__)) {
        fprintf(stderr, "\nparse_v4_sig\n");
    }
    /* clear signature */
    (void) memset(&pkt.u.sig, 0x0, sizeof(pkt.u.sig));

    /* Set version,type,algorithms */

    pkt.u.sig.version = PGP_V4;

    if (!limread(&c, 1, region, stream)) {
        return false;
    }
    pkt.u.sig.type = (pgp_sig_type_t) c;
    if (rnp_get_debug(__FILE__)) {
        fprintf(stderr,
                "signature type=%d (%s)\n",
                pkt.u.sig.type,
                pgp_show_sig_type(pkt.u.sig.type));
    }
    /* XXX: check signature type */

    if (!limread(&c, 1, region, stream)) {
        return false;
    }
    pkt.u.sig.palg = (pgp_pubkey_alg_t) c;
    /* XXX: check key algorithm */
    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(
          stderr, "key_alg=%d (%s)\n", pkt.u.sig.palg, pgp_show_pka(pkt.u.sig.palg));
    }
    if (!limread(&c, 1, region, stream)) {
        return false;
    }
    pkt.u.sig.halg = (pgp_hash_alg_t) c;
    /* XXX: check hash algorithm */
    if (rnp_get_debug(__FILE__)) {
        fprintf(stderr, "hash_alg=%d %s\n", pkt.u.sig.halg, pgp_show_hash_alg(pkt.u.sig.halg));
    }
    CALLBACK(PGP_PTAG_CT_SIGNATURE_HEADER, &stream->cbinfo, &pkt);

    if (!parse_sig_subpkts(&pkt.u.sig, region, stream)) {
        return false;
    }

    /* copy hashed subpackets */

    if (!stream->readinfo.accumulate) {
        /* We must accumulate, else we can't check the signature */
        fprintf(stderr, "*** ERROR: must set accumulate to 1\n");
        return false;
    }

    if (!parse_sig_subpkts(&pkt.u.sig, region, stream)) {
        return false;
    }

    if (!limread(pkt.u.sig.lbits, 2, region, stream)) {
        return false;
    }

    switch (pkt.u.sig.palg) {
    case PGP_PKA_RSA:
        if (!limread_mpi(&pkt.u.sig.material.rsa.s, region, stream)) {
            return false;
        }
        if (rnp_get_debug(__FILE__)) {
            char *sig = mpi2hex(&pkt.u.sig.material.rsa.s);
            (void) fprintf(stderr, "parse_v4_sig: RSA: sig is \n%s\n", sig);
            free(sig);
        }
        break;

    case PGP_PKA_DSA:
        if (!limread_mpi(&pkt.u.sig.material.dsa.r, region, stream)) {
            /*
             * usually if this fails, it just means we've reached
             * the end of the keyring
             */
            if (rnp_get_debug(__FILE__)) {
                (void) fprintf(stderr, "Error reading DSA r field in signature\n");
            }
            return false;
        }
        if (!limread_mpi(&pkt.u.sig.material.dsa.s, region, stream)) {
            ERRP(&stream->cbinfo, pkt, "Error reading DSA s field in signature\n");
        }
        break;

    case PGP_PKA_EDDSA:
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH:
        if (!limread_mpi(&pkt.u.sig.material.ecc.r, region, stream) ||
            !limread_mpi(&pkt.u.sig.material.ecc.s, region, stream)) {
            return false;
        }
        break;

    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        if (!limread_mpi(&pkt.u.sig.material.eg.r, region, stream) ||
            !limread_mpi(&pkt.u.sig.material.eg.s, region, stream)) {
            return false;
        }
        break;

    case PGP_PKA_PRIVATE00:
    case PGP_PKA_PRIVATE01:
    case PGP_PKA_PRIVATE02:
    case PGP_PKA_PRIVATE03:
    case PGP_PKA_PRIVATE04:
    case PGP_PKA_PRIVATE05:
    case PGP_PKA_PRIVATE06:
    case PGP_PKA_PRIVATE07:
    case PGP_PKA_PRIVATE08:
    case PGP_PKA_PRIVATE09:
    case PGP_PKA_PRIVATE10: {
        pgp_data_t data = {0};
        if (!read_data(&data, region, stream)) {
            return false;
        }
        pgp_data_free(&data);
        break;
    }
    default:
        PGP_ERROR_1(&stream->errors,
                    PGP_E_ALG_UNSUPPORTED_SIGNATURE_ALG,
                    "Bad v4 signature key algorithm (%s)",
                    pgp_show_pka(pkt.u.sig.palg));
        return false;
    }
    if (region->readc != region->length) {
        PGP_ERROR_1(&stream->errors,
                    PGP_E_R_UNCONSUMED_DATA,
                    "Unconsumed data (%d)",
                    region->length - region->readc);
        return false;
    }
    CALLBACK(PGP_PTAG_CT_SIGNATURE_FOOTER, &stream->cbinfo, &pkt);
    return true;
}

/**
 * \ingroup Core_ReadPackets
 * \brief Parse a signature subpacket.
 *
 * This function calls the appropriate function to handle v3 or v4 signatures.
 *
 * Once the signature packet has been parsed successfully, it is passed to the callback.
 *
 * \param *ptag        Pointer to the Packet Tag.
 * \param *reader    Our reader
 * \param *cb        The callback
 * \return        true on success, false on error
 */
static bool
parse_sig(pgp_region_t *region, pgp_stream_t *stream)
{
    pgp_packet_t pkt;
    uint8_t      c = 0x0;

    if (region->readc != 0) {
        /* We should not have read anything so far */
        RNP_LOG("bad length\n");
        return false;
    }

    (void) memset(&pkt, 0x0, sizeof(pkt));
    if (!limread(&c, 1, region, stream)) {
        return false;
    }
    if (c == 2 || c == 3) {
        return parse_v3_sig(region, stream);
    }
    if (c == 4) {
        return parse_v4_sig(region, stream);
    }
    PGP_ERROR_1(
      &stream->errors, PGP_E_PROTO_BAD_SIGNATURE_VRSN, "Bad signature version (%d)", c);
    return false;
}

/**
 \ingroup Core_ReadPackets
 \brief Parse a Trust packet
*/
static bool
parse_trust(pgp_region_t *region, pgp_stream_t *stream)
{
    pgp_packet_t pkt = {0};

    if (!read_data(&pkt.u.trust, region, stream)) {
        return false;
    }
    CALLBACK(PGP_PTAG_CT_TRUST, &stream->cbinfo, &pkt);
    return true;
}

static int
consume_packet(pgp_region_t *region, pgp_stream_t *stream, unsigned warn)
{
    pgp_packet_t pkt = {0};
    pgp_data_t   remainder = {0};

    if (region->indeterminate) {
        ERRP(&stream->cbinfo, pkt, "Can't consume indeterminate packets");
    }

    if (read_data(&remainder, region, stream)) {
        /* now throw it away */
        pgp_data_free(&remainder);
        if (warn) {
            PGP_ERROR_1(
              &stream->errors, PGP_E_P_PACKET_CONSUMED, "%s", "Warning: packet consumer");
        }
        return 1;
    }
    PGP_ERROR_1(&stream->errors,
                PGP_E_P_PACKET_NOT_CONSUMED,
                "%s",
                (warn) ? "Warning: Packet was not consumed" : "Packet was not consumed");
    return warn;
}

/**
 * \ingroup Core_ReadPackets
 * \brief Parse a secret key
 */
static bool
parse_seckey(pgp_stream_t *stream)
{
    pgp_source_t src;
    pgp_packet_t pkt;
    memset(&pkt, 0x00, sizeof(pgp_packet_t));

    if (!stream->readinfo.accumulate) {
        return false;
    }

    if (init_mem_src(&src, stream->readinfo.accumulated, stream->readinfo.alength, false)) {
        return false;
    }

    if (stream_parse_key(&src, &pkt.u.key)) {
        src_close(&src);
        return false;
    }
    src_close(&src);

    bool cleartext = pkt.u.key.sec_protection.s2k.usage == PGP_S2KU_NONE;
    if (cleartext && decrypt_secret_key(&pkt.u.key, NULL)) {
        return false;
    }

    CALLBACK(pkt.u.key.tag, &stream->cbinfo, &pkt);
    return true;
}

/**
 * \ingroup Core_ReadPackets
 * \brief Parse one packet.
 *
 * This function parses the packet tag.  It computes the value of the
 * content tag and then calls the appropriate function to handle the
 * content.
 *
 * \param *stream    How to parse
 * \param *pktlen    On return, will contain number of bytes in packet
 * \return 1 on success, 0 on error, -1 on EOF */
static rnp_result_t
parse_packet(pgp_stream_t *stream, uint32_t *pktlen)
{
    pgp_packet_t     pkt = {0};
    pgp_region_t     region = {0};
    uint8_t          ptag;
    unsigned         indeterminate = 0;
    int              ret;
    pgp_content_enum tag;

    pkt.u.ptag.position = stream->readinfo.position;

    ret = base_read(&ptag, 1, stream);

    if (rnp_get_debug(__FILE__)) {
        RNP_LOG("base_read returned %d, ptag %d\n", ret, ptag);
    }

    /* errors in the base read are effectively EOF. */
    if (ret <= 0) {
        return RNP_ERROR_EOF;
    }

    *pktlen = 0;

    if (!(ptag & PGP_PTAG_ALWAYS_SET)) {
        pkt.u.error = "Format error (ptag bit not set)";
        CALLBACK(PGP_PARSER_ERROR, &stream->cbinfo, &pkt);
        return RNP_ERROR_GENERIC;
    }
    pkt.u.ptag.new_format = !!(ptag & PGP_PTAG_NEW_FORMAT);
    if (pkt.u.ptag.new_format) {
        pkt.u.ptag.type = (ptag & PGP_PTAG_NF_CONTENT_TAG_MASK);
        pkt.u.ptag.length_type = 0;
        if (!read_new_length(&pkt.u.ptag.length, stream)) {
            return RNP_ERROR_GENERIC;
        }
    } else {
        unsigned rb;

        rb = 0;
        pkt.u.ptag.type =
          ((unsigned) ptag & PGP_PTAG_OF_CONTENT_TAG_MASK) >> PGP_PTAG_OF_CONTENT_TAG_SHIFT;
        pkt.u.ptag.length_type = ptag & PGP_PTAG_OF_LENGTH_TYPE_MASK;
        switch (pkt.u.ptag.length_type) {
        case PGP_PTAG_OLD_LEN_1:
            rb = _read_scalar(&pkt.u.ptag.length, 1, stream);
            break;

        case PGP_PTAG_OLD_LEN_2:
            rb = _read_scalar(&pkt.u.ptag.length, 2, stream);
            break;

        case PGP_PTAG_OLD_LEN_4:
            rb = _read_scalar(&pkt.u.ptag.length, 4, stream);
            break;

        case PGP_PTAG_OLD_LEN_INDETERMINATE:
            pkt.u.ptag.length = 0;
            indeterminate = 1;
            rb = 1;
            break;
        }
        if (!rb) {
            return RNP_ERROR_GENERIC;
        }
    }
    tag = pkt.u.ptag.type;

    CALLBACK(PGP_PARSER_PTAG, &stream->cbinfo, &pkt);

    pgp_init_subregion(&region, NULL);
    region.length = pkt.u.ptag.length;
    region.indeterminate = indeterminate;
    if (rnp_get_debug(__FILE__)) {
        (void) fprintf(stderr, "parse_packet: type %u\n", pkt.u.ptag.type);
    }
    switch (pkt.u.ptag.type) {
    case PGP_PTAG_CT_SIGNATURE:
        ret = parse_sig(&region, stream);
        break;
    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        if (!consume_packet(&region, stream, 0)) {
            ret = -1;
            break;
        }
        ret = parse_pubkey(stream);
        break;
    case PGP_PTAG_CT_TRUST:
        ret = parse_trust(&region, stream);
        break;
    case PGP_PTAG_CT_USER_ID:
        ret = parse_userid(&region, stream);
        break;
    case PGP_PTAG_CT_USER_ATTR:
        ret = parse_userattr(&region, stream);
        break;
    case PGP_PTAG_CT_SECRET_KEY:
    case PGP_PTAG_CT_SECRET_SUBKEY:
        if (!consume_packet(&region, stream, 0)) {
            ret = -1;
            break;
        }
        ret = parse_seckey(stream);
        break;
    default:
        PGP_ERROR_1(
          &stream->errors, PGP_E_P_UNKNOWN_TAG, "Unknown content tag 0x%x", pkt.u.ptag.type);
        ret = -1;
    }

    /* Ensure that the entire packet has been consumed */

    if (region.length != region.readc && !region.indeterminate) {
        if (!consume_packet(&region, stream, 0)) {
            ret = -1;
        }
    }

    /* also consume it if there's been an error? */
    /* \todo decide what to do about an error on an */
    /* indeterminate packet */
    if (ret == 0) {
        if (!consume_packet(&region, stream, 0)) {
            ret = -1;
        }
    }
    /* set pktlen */

    *pktlen = stream->readinfo.alength;

    /* do callback on entire packet, if desired and there was no error */
    if (ret > 0 && stream->readinfo.accumulate) {
        pkt.u.packet.length = stream->readinfo.alength;
        pkt.u.packet.raw = stream->readinfo.accumulated;
        pkt.u.packet.tag = tag;
        stream->readinfo.accumulated = NULL;
        stream->readinfo.asize = 0;
        CALLBACK(PGP_PARSER_PACKET_END, &stream->cbinfo, &pkt);
    }
    stream->readinfo.alength = 0;

    return (ret == 1) ? RNP_SUCCESS : (ret < 0) ? RNP_ERROR_EOF : RNP_ERROR_GENERIC;
}

/**
 * \ingroup Core_ReadPackets
 *
 * \brief Parse packets from an input stream until EOF or error.
 *
 * \details Setup the necessary parsing configuration in "stream"
 * before calling repgp_parse().
 *
 * That information includes :
 *
 * - a "reader" function to be used to get the data to be parsed
 *
 * - a "callback" function to be called when this library has identified
 * a parseable object within the data
 *
 * - whether the calling function wants the signature subpackets
 * returned raw, parsed or not at all.
 *
 * After returning, stream->errors holds any errors encountered while parsing.
 *
 * \param stream    Parsing configuration
 * \return        1 on success in all packets, 0 on error in any packet
 *
 * \sa CoreAPI Overview
 *
 * \sa pgp_print_errors()
 *
 */

bool
repgp_parse(pgp_stream_t *stream, const bool show_errors)
{
    uint32_t     pktlen;
    rnp_result_t res;

    do {
        res = parse_packet(stream, &pktlen);
    } while (RNP_ERROR_EOF != res);
    pgp_packet_t pkt = {0};
    CALLBACK(PGP_PARSER_DONE, &stream->cbinfo, &pkt);
    if (show_errors) {
        pgp_print_errors(stream->errors);
    }
    return (stream->errors == NULL);
}

void
repgp_parse_options(pgp_stream_t *stream, pgp_content_enum tag, repgp_parse_type_t type)
{
    unsigned t7;
    unsigned t8;

    if (tag == PGP_PTAG_SS_ALL) {
        int n;

        for (n = 0; n < 256; ++n) {
            repgp_parse_options(stream, PGP_PTAG_SIG_SUBPKT_BASE + n, type);
        }
        return;
    }
    if (tag < PGP_PTAG_SIG_SUBPKT_BASE || tag > PGP_PTAG_SIG_SUBPKT_BASE + NTAGS - 1) {
        (void) fprintf(stderr, "repgp_parse_options: bad tag\n");
        return;
    }
    t8 = (tag - PGP_PTAG_SIG_SUBPKT_BASE) / 8;
    t7 = 1 << ((tag - PGP_PTAG_SIG_SUBPKT_BASE) & 7);
    switch (type) {
    case REPGP_PARSE_RAW:
        stream->ss_raw[t8] |= t7;
        stream->ss_parsed[t8] &= ~t7;
        break;

    case REPGP_PARSE_PARSED:
        stream->ss_raw[t8] &= ~t7;
        stream->ss_parsed[t8] |= t7;
        break;

    case REPGP_PARSE_IGNORE:
        stream->ss_raw[t8] &= ~t7;
        stream->ss_parsed[t8] &= ~t7;
        break;
    }
}

/**
\ingroup Core_ReadPackets
\brief Free pgp_stream_t struct and its contents
*/
void
pgp_stream_delete(pgp_stream_t *stream)
{
    pgp_cbdata_t *cbinfo;
    pgp_cbdata_t *next;

    for (cbinfo = stream->cbinfo.next; cbinfo; cbinfo = next) {
        next = cbinfo->next;
        free(cbinfo);
    }
    if (stream->readinfo.destroyer) {
        stream->readinfo.destroyer(&stream->readinfo);
    }
    pgp_free_errors(stream->errors);
    if (stream->readinfo.accumulated) {
        free(stream->readinfo.accumulated);
    }

    free(stream);
}

/**
\ingroup Core_ReadPackets
\brief Returns the parse_info's reader_info
\return Pointer to the reader_info inside the parse_info
*/
pgp_reader_t *
pgp_readinfo(pgp_stream_t *stream)
{
    return &stream->readinfo;
}

/**
\ingroup Core_ReadPackets
\brief Sets the parse_info's callback
This is used when adding the first callback in a stack of callbacks.
\sa pgp_callback_push()
*/

void
pgp_set_callback(pgp_stream_t *stream, pgp_cbfunc_t *cb, void *arg)
{
    stream->cbinfo.cbfunc = cb;
    stream->cbinfo.arg = arg;
    stream->cbinfo.errors = &stream->errors;
}

/**
\ingroup Core_ReadPackets
\brief Adds a further callback to a stack of callbacks
\sa pgp_set_callback()
*/
void
pgp_callback_push(pgp_stream_t *stream, pgp_cbfunc_t *cb, void *arg)
{
    pgp_cbdata_t *cbinfo;

    if ((cbinfo = calloc(1, sizeof(*cbinfo))) == NULL) {
        (void) fprintf(stderr, "pgp_callback_push: bad alloc\n");
        return;
    }
    (void) memcpy(cbinfo, &stream->cbinfo, sizeof(*cbinfo));
    cbinfo->io = stream->io;
    stream->cbinfo.next = cbinfo;
    pgp_set_callback(stream, cb, arg);
}

/**
\ingroup Core_ReadPackets
\brief Returns callback's arg
*/
void *
pgp_callback_arg(pgp_cbdata_t *cbinfo)
{
    return cbinfo->arg;
}

/**
\ingroup Core_ReadPackets
\brief Returns callback's errors
*/
void *
pgp_callback_errors(pgp_cbdata_t *cbinfo)
{
    return cbinfo->errors;
}

/**
\ingroup Core_ReadPackets
\brief Calls the parse_cb_info's callback if present
\return Return value from callback, if present; else PGP_FINISHED
*/
pgp_cb_ret_t
pgp_callback(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    return (cbinfo->cbfunc) ? cbinfo->cbfunc(pkt, cbinfo) : PGP_FINISHED;
}

/**
\ingroup Core_ReadPackets
\brief Calls the next callback  in the stack
\return Return value from callback
*/
pgp_cb_ret_t
pgp_stacked_callback(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    return pgp_callback(pkt, cbinfo->next);
}

/**
\ingroup Core_ReadPackets
\brief Returns the parse_info's errors
\return parse_info's errors
*/
pgp_error_t *
pgp_stream_get_errors(pgp_stream_t *stream)
{
    return stream->errors;
}
