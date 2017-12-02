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

/*
 * ! \file \brief Standard API print functions
 */
#include "config.h"

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: packet-print.c,v 1.42 2012/02/22 06:29:40 agc Exp $");
#endif

#ifdef RNP_DEBUG
#include <assert.h>
#endif

#include <rnp/rnp_sdk.h>

#include "crypto/ec.h"
#include "packet-show.h"
#include "signature.h"
#include "pgp-key.h"
#include "reader.h"

#define F_REVOKED 1

#define F_PRINTSIGS 2

#define PTIMESTR_LEN 10

#define PUBKEY_DOES_EXPIRE(pk) ((pk)->duration > 0)

#define PUBKEY_HAS_EXPIRED(pk, t) (((pk)->birthtime + (pk)->duration) < (t))

#define SIGNATURE_PADDING "          "

/* static functions */
static bool format_key_usage(char *buffer, size_t size, uint8_t flags);

static inline void
print_indent(int indent)
{
    printf("%*c", indent * 2, '\0');
}

static void
print_name(int indent, const char *name)
{
    if (name) {
        print_indent(indent);
        printf("%s: ", name);
    }
}

static void
print_hex_data_full(
  int indent, const char *name, const char *header, const uint8_t *data, size_t data_len)
{
    if (name) {
        print_name(indent, name);
    }
    print_indent(indent);
    hexdump(stdout, header, data, data_len);
}

static void
print_hex_data_size(
  int indent, const char *name, const char *header, const uint8_t *data, size_t data_len)
{
    print_name(indent, name);
    printf("[data size: %lu bytes]\n", data_len);
}

static inline void
print_uint(int indent, const char *name, unsigned val)
{
    print_name(indent, name);
    printf("%u\n", val);
}

static inline void
showtime(const char *name, time_t t)
{
    printf("%s=%" PRItime "d (%.24s)", name, (long long) t, ctime(&t));
}

static void
print_time(int indent, const char *name, time_t t)
{
    print_indent(indent);
    printf("%s: ", name);
    showtime("time", t);
    printf("\n");
}

static void
print_string_and_value(int indent, const char *name, const char *str, uint8_t value)
{
    print_name(indent, name);
    printf("%s (0x%x)\n", str, value);
}

static void
print_bn(int indent, const char *name, const BIGNUM *bn)
{
    print_indent(indent);
    printf("%s = ", name);
    if (bn) {
        BN_print_fp(stdout, bn);
        size_t bsz = 0;
        (void) BN_num_bits(bn, &bsz);
        printf(" (%zu bits)\n", bsz);
    } else {
        puts("(unset)");
    }
}

static void
print_escaped(const uint8_t *data, size_t length)
{
    while (length-- > 0) {
        if ((*data >= 0x20 && *data < 0x7f && *data != '%') || *data == '\n') {
            putchar(*data);
        } else {
            printf("%%%02x", *data);
        }
        ++data;
    }
}

static void
print_string(int indent, const char *name, const char *str)
{
    print_name(indent, name);
    print_escaped((const uint8_t *) str, strlen(str));
    putchar('\n');
}

static inline void
print_utf8_string(int indent, const char *name, const uint8_t *str)
{
    /* \todo Do this better for non-English character sets */
    print_string(indent, name, (const char *) str);
}

static void
print_duration(int indent, const char *name, time_t t)
{
    int mins, hours, days, years;

    print_indent(indent);
    printf("%s: ", name);
    printf("duration %" PRItime "d seconds", (long long) t);

    mins = (int) (t / 60);
    hours = mins / 60;
    days = hours / 24;
    years = days / 365;

    printf(" (approx. ");
    if (years) {
        printf("%d %s", years, years == 1 ? "year" : "years");
    } else if (days) {
        printf("%d %s", days, days == 1 ? "day" : "days");
    } else if (hours) {
        printf("%d %s", hours, hours == 1 ? "hour" : "hours");
    }
    printf(")\n");
}

static inline void
print_boolean(int indent, const char *name, uint8_t boolval)
{
    print_name(indent, name);
    printf("%s\n", (boolval) ? "Yes" : "No");
}

static void
print_text_breakdown(int indent, pgp_text_t *text)
{
    const char *prefix = ".. ";
    unsigned    i;

    /* these were recognised */
    for (i = 0; i < text->known.used; i++) {
        print_indent(indent);
        printf("%s", prefix);
        printf("%s\n", text->known.strings[i]);
    }
    /*
     * these were not recognised. the strings will contain the hex value
     * of the unrecognised value in string format - see
     * process_octet_str()
     */
    if (text->unknown.used) {
        printf("\n");
        print_indent(indent);
        printf("Not Recognised: ");
    }
    for (i = 0; i < text->unknown.used; i++) {
        print_indent(indent);
        printf("%s", prefix);
        printf("%s\n", text->unknown.strings[i]);
    }
}

static void
print_headers(const pgp_headers_t *h)
{
    unsigned i;

    for (i = 0; i < h->headerc; ++i) {
        printf("%s=%s\n", h->headers[i].key, h->headers[i].value);
    }
}

static void
print_block(int indent, const char *name, const uint8_t *str, size_t length)
{
    int o = (int) length;

    print_indent(indent);
    printf(">>>>> %s >>>>>\n", name);

    print_indent(indent);
    for (; length > 0; --length) {
        if (*str >= 0x20 && *str < 0x7f && *str != '%') {
            putchar(*str);
        } else if (*str == '\n') {
            putchar(*str);
            print_indent(indent);
        } else {
            printf("%%%02x", *str);
        }
        ++str;
    }
    if (o && str[-1] != '\n') {
        putchar('\n');
        print_indent(indent);
        fputs("[no newline]", stdout);
    } else {
        print_indent(indent);
    }
    printf("<<<<< %s <<<<<\n", name);
}

/* return the number of bits in the public key */
static size_t
numkeybits(const pgp_pubkey_t *pubkey)
{
    size_t sz = 0;
    switch (pubkey->alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        (void) BN_num_bits(pubkey->key.rsa.n, &sz);
        return sz;
    case PGP_PKA_DSA:
        (void) BN_num_bytes(pubkey->key.dsa.q, &sz);
        switch (sz) {
        case 20:
            return 1024;
        case 28:
            return 2048;
        case 32:
            return 3072;
        default:
            return 0;
        }
    case PGP_PKA_ELGAMAL:
        (void) BN_num_bits(pubkey->key.elgamal.y, &sz);
        return sz;

    case PGP_PKA_ECDH:
    case PGP_PKA_ECDSA:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2: {
        // BN_num_bytes returns value <= curve order
        const ec_curve_desc_t *curve = get_curve_desc(pubkey->key.ecc.curve);
        return curve ? curve->bitlen : 0;
    }
    default:
        (void) fprintf(stderr, "Unknown public key alg in numkeybits\n");
        return -1;
    }
}

/* Write the time as a string to buffer `dest`. The time string is guaranteed
 * to be PTIMESTR_LEN characters long.
 */
static char *
ptimestr(char *dest, size_t size, time_t t)
{
    struct tm *tm;

    tm = gmtime(&t);

    /* Remember - we guarantee that the time string will be PTIMESTR_LEN
     * characters long.
     */
    snprintf(dest, size, "%04d-%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
#ifdef RNP_DEBUG
    assert(stelen(dest) == PTIMESTR_LEN);
#endif
    return dest;
}

/* Print the sub key binding signature info. */
static int
psubkeybinding(char *buf, size_t size, const pgp_key_t *key, const char *expired)
{
    char keyid[512];
    char t[32];
    char key_usage[8];

    format_key_usage(key_usage, sizeof(key_usage), key->key_flags);
    const pgp_pubkey_t *pubkey = pgp_get_pubkey(key);
    return snprintf(buf,
                    size,
                    "encryption %zu/%s %s %s [%s] %s\n",
                    numkeybits(pubkey),
                    pgp_show_pka(pubkey->alg),
                    rnp_strhexdump(keyid, key->keyid, PGP_KEY_ID_SIZE, ""),
                    ptimestr(t, sizeof(t), pubkey->birthtime),
                    key_usage,
                    expired);
}

/* Searches a key's revocation list for the given key UID. If it is found its
 * index is returned, otherwise -1 is returned.
 */
static int
isrevoked(const pgp_key_t *key, unsigned uid)
{
    unsigned i;

    for (i = 0; i < key->revokec; i++) {
        if (key->revokes[i].uid == uid)
            return i;
    }
    return -1;
}

static bool
iscompromised(const pgp_key_t *key, unsigned uid)
{
    int r = isrevoked(key, uid);

    return r >= 0 && key->revokes[r].code == PGP_REVOCATION_COMPROMISED;
}

/* Formats a public key expiration notice. Assumes that the public key
 * expires. Return 1 on success and 0 on failure.
 */
static bool
format_pubkey_expiration_notice(char *              buffer,
                                const pgp_pubkey_t *pubkey,
                                time_t              time,
                                size_t              size)
{
    char *buffer_end = buffer + size;

    buffer[0] = '\0';

    /* Write the opening bracket. */
    buffer += snprintf(buffer, buffer_end - buffer, "%s", "[");
    if (buffer >= buffer_end)
        return false;

    /* Write the expiration state label. */
    buffer += snprintf(buffer,
                       buffer_end - buffer,
                       "%s ",
                       PUBKEY_HAS_EXPIRED(pubkey, time) ? "EXPIRED" : "EXPIRES");

    /* Ensure that there will be space for tihe time. */
    if (buffer_end - buffer < PTIMESTR_LEN + 1)
        return false;

    /* Write the expiration time. */
    ptimestr(buffer, buffer_end - buffer, pubkey->birthtime + pubkey->duration);
    buffer += PTIMESTR_LEN;
    if (buffer >= buffer_end)
        return false;

    /* Write the closing bracket. */
    buffer += snprintf(buffer, buffer_end - buffer, "%s", "]");
    if (buffer >= buffer_end)
        return false;

    return true;
}

static int
format_uid_line(char *buffer, uint8_t *uid, size_t size, int flags)
{
    return snprintf(buffer,
                    size,
                    "uid    %s%s%s\n",
                    flags & F_PRINTSIGS ? "" : SIGNATURE_PADDING,
                    uid,
                    flags & F_REVOKED ? " [REVOKED]" : "");
}

/* TODO: Consider replacing `trustkey` with an optional `uid` parameter. */
/* TODO: Consider passing only signer_id and birthtime. */
static int
format_sig_line(char *buffer, const pgp_sig_t *sig, const pgp_key_t *trustkey, size_t size)
{
    char keyid[PGP_KEY_ID_SIZE * 3];
    char time[PTIMESTR_LEN + sizeof(char)];

    ptimestr(time, sizeof(time), sig->info.birthtime);
    return snprintf(buffer,
                    size,
                    "sig        %s  %s  %s\n",
                    rnp_strhexdump(keyid, sig->info.signer_id, PGP_KEY_ID_SIZE, ""),
                    time,
                    trustkey != NULL ? (char *) trustkey->uids[trustkey->uid0] : "[unknown]");
}

static int
format_subsig_line(char *              buffer,
                   const pgp_key_t *   key,
                   const pgp_key_t *   trustkey,
                   const pgp_subsig_t *subsig,
                   size_t              size)
{
    char expired[128];
    int  n = 0;

    expired[0] = '\0';
    if (PUBKEY_DOES_EXPIRE(&key->key.pubkey)) {
        format_pubkey_expiration_notice(
          expired, &key->key.pubkey, time(NULL), sizeof(expired));
    }
    if (subsig->sig.info.version == 4 && subsig->sig.info.type == PGP_SIG_SUBKEY) {
        /* XXX: The character count of this was previously ignored.
         *      This seems to have been incorrect, but if not
         *      you should revert it.
         */
        n += psubkeybinding(buffer, size, key, expired);
    } else
        n += format_sig_line(buffer, &subsig->sig, trustkey, size);

    return n;
}

static int
format_uid_notice(char *                 buffer,
                  pgp_io_t *             io,
                  const rnp_key_store_t *keyring,
                  const pgp_key_t *      key,
                  unsigned               uid,
                  size_t                 size,
                  int                    flags)
{
    unsigned n = 0;

    if (isrevoked(key, uid) >= 0)
        flags |= F_REVOKED;

    n += format_uid_line(buffer, key->uids[uid], size, flags);

    for (unsigned i = 0; i < key->subsigc; i++) {
        pgp_subsig_t *   subsig = &key->subsigs[i];
        const pgp_key_t *trustkey;
        unsigned         from = 0;

        /* TODO: To me this looks like an unnecessary consistency
         *       check that should be performed upstream before
         *       passing the information down here. Maybe not,
         *       if anyone can shed alternate light on this
         *       that would be great.
         */
        if (flags & F_PRINTSIGS && subsig->uid != uid) {
            continue;

            /* TODO: I'm also unsure about this one. */
        } else if (!(subsig->sig.info.version == 4 &&
                     subsig->sig.info.type == PGP_SIG_SUBKEY && uid == key->uidc - 1)) {
            continue;
        }

        trustkey =
          rnp_key_store_get_key_by_id(io, keyring, subsig->sig.info.signer_id, &from, NULL);

        n += format_subsig_line(buffer + n, key, trustkey, subsig, size - n);
    }

    return n;
}

static bool
format_key_usage(char *buffer, size_t size, uint8_t flags)
{
    static const pgp_bit_map_t flags_map[] = {
      {PGP_KF_ENCRYPT, "E"}, {PGP_KF_SIGN, "S"}, {PGP_KF_CERTIFY, "C"}, {PGP_KF_AUTH, "A"},
    };

    *buffer = '\0';
    for (size_t i = 0; i < ARRAY_SIZE(flags_map); i++) {
        if (flags & flags_map[i].mask) {
            const size_t current_length = strlen(buffer);
            if (current_length == size - 1) {
                return false;
            }
            strncat(buffer, flags_map[i].string, size - current_length - 1);
        }
    }
    return true;
}

static bool
format_key_usage_json(json_object *arr, uint8_t flags)
{
    static const pgp_bit_map_t flags_map[] = {
      {PGP_KF_ENCRYPT, "encrypt"},
      {PGP_KF_SIGN, "sign"},
      {PGP_KF_CERTIFY, "certify"},
      {PGP_KF_AUTH, "authenticate"},
    };

    for (size_t i = 0; i < ARRAY_SIZE(flags_map); i++) {
        if (flags & flags_map[i].mask) {
            json_object *str = json_object_new_string(flags_map[i].string);
            if (!str) {
                return false;
            }
            if (json_object_array_add(arr, str) != 0) {
                return false;
            }
        }
    }
    return true;
}

#ifndef KB
#define KB(x) ((x) *1024)
#endif

/* XXX: Why 128KiB? */
#define NOTICE_BUFFER_SIZE KB(128)

/* print into a string (malloc'ed) the pubkeydata */
int
pgp_sprint_key(pgp_io_t *             io,
               const rnp_key_store_t *keyring,
               const pgp_key_t *      key,
               char **                buf,
               const char *           header,
               const pgp_pubkey_t *   pubkey,
               const int              psigs)
{
    unsigned i;
    time_t   now;
    char *   uid_notices;
    int      uid_notices_offset = 0;
    char *   string;
    int      total_length;
    char     keyid[PGP_KEY_ID_SIZE * 3];
    char     fingerprint[PGP_FINGERPRINT_HEX_SIZE];
    char     expiration_notice[128];
    char     birthtime[32];
    char     key_usage[8];

    if (key->revoked)
        return -1;

    now = time(NULL);

    if (PUBKEY_DOES_EXPIRE(pubkey)) {
        format_pubkey_expiration_notice(
          expiration_notice, pubkey, now, sizeof(expiration_notice));
    } else
        expiration_notice[0] = '\0';

    uid_notices = (char *) malloc(NOTICE_BUFFER_SIZE);
    if (uid_notices == NULL)
        return -1;

    /* TODO: Perhaps this should index key->uids instead of using the
     *       iterator index.
     */
    for (i = 0; i < key->uidc; i++) {
        int flags = 0;

        if (iscompromised(key, i))
            continue;

        if (psigs)
            flags |= F_PRINTSIGS;

        uid_notices_offset += format_uid_notice(uid_notices + uid_notices_offset,
                                                io,
                                                keyring,
                                                key,
                                                i,
                                                NOTICE_BUFFER_SIZE - uid_notices_offset,
                                                flags);
    }
    uid_notices[uid_notices_offset] = '\0';

    rnp_strhexdump(keyid, key->keyid, PGP_KEY_ID_SIZE, "");

    rnp_strhexdump(fingerprint, key->fingerprint.fingerprint, key->fingerprint.length, " ");

    ptimestr(birthtime, sizeof(birthtime), pubkey->birthtime);

    if (!format_key_usage(key_usage, sizeof(key_usage), key->key_flags)) {
        return -1;
    }

    /* XXX: For now we assume that the output string won't exceed 16KiB
     *      in length but this is completely arbitrary. What this
     *      really needs is some objective facts to base this
     *      size on.
     */

    total_length = -1;
    string = (char *) malloc(KB(16));
    if (string != NULL) {
        total_length = snprintf(string,
                                KB(16),
                                "%s %zu/%s %s %s [%s] %s\n                 %s\n%s",
                                header,
                                numkeybits(pubkey),
                                pgp_show_pka(pubkey->alg),
                                keyid,
                                birthtime,
                                key_usage,
                                expiration_notice,
                                fingerprint,
                                uid_notices);
        *buf = string;
    }

    free((void *) uid_notices);

    return total_length;
}

/* return the key info as a JSON encoded string */
int
repgp_sprint_json(pgp_io_t *                    io,
                  const struct rnp_key_store_t *keyring,
                  const pgp_key_t *             key,
                  json_object *                 keyjson,
                  const char *                  header,
                  const pgp_pubkey_t *          pubkey,
                  const int                     psigs)
{
    char     keyid[PGP_KEY_ID_SIZE * 3];
    char     fp[PGP_FINGERPRINT_HEX_SIZE];
    int      r;
    unsigned i;
    unsigned j;

    if (key == NULL || key->revoked) {
        return -1;
    }

    // add the top-level values
    json_object_object_add(keyjson, "header", json_object_new_string(header));
    json_object_object_add(keyjson, "key bits", json_object_new_int(numkeybits(pubkey)));
    json_object_object_add(keyjson, "pka", json_object_new_string(pgp_show_pka(pubkey->alg)));
    json_object_object_add(
      keyjson,
      "key id",
      json_object_new_string(rnp_strhexdump(keyid, key->keyid, PGP_KEY_ID_SIZE, "")));
    json_object_object_add(keyjson,
                           "fingerprint",
                           json_object_new_string(rnp_strhexdump(
                             fp, key->fingerprint.fingerprint, key->fingerprint.length, "")));
    json_object_object_add(keyjson, "creation time", json_object_new_int(pubkey->birthtime));
    json_object_object_add(keyjson, "duration", json_object_new_int(pubkey->duration));
    json_object_object_add(keyjson, "key flags", json_object_new_int(key->key_flags));
    json_object *usage_arr = json_object_new_array();
    format_key_usage_json(usage_arr, key->key_flags);
    json_object_object_add(keyjson, "usage", usage_arr);

    // iterating through the uids
    json_object *uid_arr = json_object_new_array();
    for (i = 0; i < key->uidc; i++) {
        if ((r = isrevoked(key, i)) >= 0 &&
            key->revokes[r].code == PGP_REVOCATION_COMPROMISED) {
            continue;
        }
        // add an array of the uids (and checking whether is REVOKED and
        // indicate it as well)
        json_object *uidobj = json_object_new_object();
        json_object_object_add(
          uidobj, "user id", json_object_new_string((char *) key->uids[i]));
        json_object_object_add(
          uidobj, "revoked", json_object_new_boolean((r >= 0) ? TRUE : FALSE));
        for (j = 0; j < key->subsigc; j++) {
            if (psigs) {
                if (key->subsigs[j].uid != i) {
                    continue;
                }
            } else {
                if (!(key->subsigs[j].sig.info.version == 4 &&
                      key->subsigs[j].sig.info.type == PGP_SIG_SUBKEY && i == key->uidc - 1)) {
                    continue;
                }
            }
            json_object *subsigc = json_object_new_object();
            json_object_object_add(
              subsigc,
              "signer id",
              json_object_new_string(rnp_strhexdump(
                keyid, key->subsigs[j].sig.info.signer_id, PGP_KEY_ID_SIZE, "")));
            json_object_object_add(
              subsigc,
              "creation time",
              json_object_new_int((int64_t)(key->subsigs[j].sig.info.birthtime)));

            unsigned         from = 0;
            const pgp_key_t *trustkey = rnp_key_store_get_key_by_id(
              io, keyring, key->subsigs[j].sig.info.signer_id, &from, NULL);

            json_object_object_add(
              subsigc,
              "user id",
              json_object_new_string((trustkey) ? (char *) trustkey->uids[trustkey->uid0] :
                                                  "[unknown]"));
            json_object_object_add(uidobj, "signature", subsigc);
        }
        json_object_array_add(uid_arr, uidobj);
    } // for uidc
    json_object_object_add(keyjson, "user ids", uid_arr);
    if (rnp_get_debug(__FILE__)) {
        printf("%s,%d: The json object created: %s\n",
               __FILE__,
               __LINE__,
               json_object_to_json_string_ext(keyjson, JSON_C_TO_STRING_PRETTY));
    }
    return 1;
}

int
pgp_hkp_sprint_key(pgp_io_t *                    io,
                   const struct rnp_key_store_t *keyring,
                   const pgp_key_t *             key,
                   char **                       buf,
                   const pgp_pubkey_t *          pubkey,
                   const int                     psigs)
{
    const pgp_key_t *trustkey;
    unsigned         from;
    unsigned         i;
    unsigned         j;
    char             keyid[PGP_KEY_ID_SIZE * 3];
    char             uidbuf[KB(128)];
    char             fingerprint[PGP_FINGERPRINT_HEX_SIZE];
    int              n;

    if (key->revoked) {
        return -1;
    }
    for (i = 0, n = 0; i < key->uidc; i++) {
        n += snprintf(&uidbuf[n],
                      sizeof(uidbuf) - n,
                      "uid:%lld:%lld:%s\n",
                      (long long) pubkey->birthtime,
                      (long long) pubkey->duration,
                      key->uids[i]);
        for (j = 0; j < key->subsigc; j++) {
            if (psigs) {
                if (key->subsigs[j].uid != i) {
                    continue;
                }
            } else {
                if (!(key->subsigs[j].sig.info.version == 4 &&
                      key->subsigs[j].sig.info.type == PGP_SIG_SUBKEY && i == key->uidc - 1)) {
                    continue;
                }
            }
            from = 0;
            trustkey = rnp_key_store_get_key_by_id(
              io, keyring, key->subsigs[j].sig.info.signer_id, &from, NULL);
            if (key->subsigs[j].sig.info.version == 4 &&
                key->subsigs[j].sig.info.type == PGP_SIG_SUBKEY) {
                n +=
                  snprintf(&uidbuf[n],
                           sizeof(uidbuf) - n,
                           "sub:%zu:%d:%s:%lld:%lld\n",
                           numkeybits(pubkey),
                           key->subsigs[j].sig.info.key_alg,
                           rnp_strhexdump(
                             keyid, key->subsigs[j].sig.info.signer_id, PGP_KEY_ID_SIZE, ""),
                           (long long) (key->subsigs[j].sig.info.birthtime),
                           (long long) pubkey->duration);
            } else {
                n +=
                  snprintf(&uidbuf[n],
                           sizeof(uidbuf) - n,
                           "sig:%s:%lld:%s\n",
                           rnp_strhexdump(
                             keyid, key->subsigs[j].sig.info.signer_id, PGP_KEY_ID_SIZE, ""),
                           (long long) key->subsigs[j].sig.info.birthtime,
                           (trustkey) ? (char *) trustkey->uids[trustkey->uid0] : "");
            }
        }
    }

    rnp_strhexdump(fingerprint, key->fingerprint.fingerprint, PGP_FINGERPRINT_SIZE, "");

    n = -1;
    {
        /* XXX: This number is completely arbitrary. */
        char *buffer = (char *) malloc(KB(16));

        if (buffer != NULL) {
            n = snprintf(buffer,
                         KB(16),
                         "pub:%s:%d:%zu:%lld:%lld\n%s",
                         fingerprint,
                         pubkey->alg,
                         numkeybits(pubkey),
                         (long long) pubkey->birthtime,
                         (long long) pubkey->duration,
                         uidbuf);
            *buf = buffer;
        }
    }
    return n;
}

/* print the key data for a pub or sec key */
void
repgp_print_key(pgp_io_t *             io,
                const rnp_key_store_t *keyring,
                const pgp_key_t *      key,
                const char *           header,
                const pgp_pubkey_t *   pubkey,
                const int              psigs)
{
    char *cp;

    if (pgp_sprint_key(io, keyring, key, &cp, header, pubkey, psigs) >= 0) {
        (void) fprintf(io->res, "%s", cp);
        free(cp);
    }
}

/**
\ingroup Core_Print
\param pubkey
*/
void
pgp_print_pubkey(size_t indent, const pgp_pubkey_t *pubkey)
{
    printf("------- PUBLIC KEY ------\n");
    print_uint(indent, "Version", (unsigned) pubkey->version);
    print_time(indent, "Creation Time", pubkey->birthtime);
    if (pubkey->version == PGP_V3) {
        print_uint(0, "Days Valid", pubkey->days_valid);
    }
    print_string_and_value(indent, "Algorithm", pgp_show_pka(pubkey->alg), pubkey->alg);
    switch (pubkey->alg) {
    case PGP_PKA_DSA:
        print_bn(indent, "p", pubkey->key.dsa.p);
        print_bn(indent, "q", pubkey->key.dsa.q);
        print_bn(indent, "g", pubkey->key.dsa.g);
        print_bn(indent, "y", pubkey->key.dsa.y);
        break;

    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        print_bn(indent, "n", pubkey->key.rsa.n);
        print_bn(indent, "e", pubkey->key.rsa.e);
        break;

    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        print_bn(indent, "p", pubkey->key.elgamal.p);
        print_bn(indent, "g", pubkey->key.elgamal.g);
        print_bn(indent, "y", pubkey->key.elgamal.y);
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH: {
        const ec_curve_desc_t *curve = get_curve_desc(pubkey->key.ecc.curve);
        if (curve) {
            print_string(indent, "curve", curve->botan_name);
            print_bn(indent, "public point", pubkey->key.ecc.point);
        }
        break;
    }
    default:
        (void) fprintf(stderr, "pgp_print_pubkey: Unusual algorithm\n");
    }

    printf("------- end of PUBLIC KEY ------\n");
}

int
pgp_sprint_pubkey(const pgp_key_t *key, char *out, size_t outsize)
{
    char fp[PGP_FINGERPRINT_HEX_SIZE];
    int  cc;

    cc = snprintf(out,
                  outsize,
                  "key=%s\nname=%s\ncreation=%lld\nexpiry=%lld\nversion=%d\nalg=%d\n",
                  rnp_strhexdump(fp, key->fingerprint.fingerprint, PGP_FINGERPRINT_SIZE, ""),
                  key->uids[key->uid0],
                  (long long) key->key.pubkey.birthtime,
                  (long long) key->key.pubkey.days_valid,
                  key->key.pubkey.version,
                  key->key.pubkey.alg);
    switch (key->key.pubkey.alg) {
    case PGP_PKA_DSA:
        cc += snprintf(&out[cc],
                       outsize - cc,
                       "p=%s\nq=%s\ng=%s\ny=%s\n",
                       BN_bn2hex(key->key.pubkey.key.dsa.p),
                       BN_bn2hex(key->key.pubkey.key.dsa.q),
                       BN_bn2hex(key->key.pubkey.key.dsa.g),
                       BN_bn2hex(key->key.pubkey.key.dsa.y));
        break;
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        cc += snprintf(&out[cc],
                       outsize - cc,
                       "n=%s\ne=%s\n",
                       BN_bn2hex(key->key.pubkey.key.rsa.n),
                       BN_bn2hex(key->key.pubkey.key.rsa.e));
        break;
    case PGP_PKA_EDDSA:
        cc += snprintf(
          &out[cc], outsize - cc, "point=%s\n", BN_bn2hex(key->key.pubkey.key.ecc.point));
        break;
    case PGP_PKA_ECDSA:
    case PGP_PKA_SM2:
    case PGP_PKA_ECDH: {
        const ec_curve_desc_t *curve = get_curve_desc(key->key.pubkey.key.ecc.curve);
        if (curve) {
            cc += snprintf(&out[cc],
                           outsize - cc,
                           "curve=%s\npoint=%s\n",
                           curve->botan_name,
                           BN_bn2hex(key->key.pubkey.key.ecc.point));
        }
        break;
    }
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        cc += snprintf(&out[cc],
                       outsize - cc,
                       "p=%s\ng=%s\ny=%s\n",
                       BN_bn2hex(key->key.pubkey.key.elgamal.p),
                       BN_bn2hex(key->key.pubkey.key.elgamal.g),
                       BN_bn2hex(key->key.pubkey.key.elgamal.y));
        break;
    default:
        (void) fprintf(stderr, "pgp_print_pubkey: Unusual algorithm\n");
    }
    return cc;
}

static void
print_seckey_verbose(pgp_printstate_t *     printstate,
                     const pgp_content_enum type,
                     const pgp_seckey_t *   seckey)
{
    pgp_print_pubkey(printstate->indent, &seckey->pubkey);
    print_uint(printstate->indent, "S2K Usage", seckey->protection.s2k.usage);
    if (seckey->protection.s2k.usage != PGP_S2KU_NONE) {
        print_uint(printstate->indent, "S2K Specifier", seckey->protection.s2k.specifier);
        print_string_and_value(printstate->indent,
                               "Symmetric algorithm",
                               pgp_show_symm_alg(seckey->protection.symm_alg),
                               seckey->protection.symm_alg);
        print_string_and_value(printstate->indent,
                               "Hash algorithm",
                               pgp_show_hash_alg((uint8_t) seckey->protection.s2k.hash_alg),
                               seckey->protection.s2k.hash_alg);
        if (seckey->protection.s2k.specifier != PGP_S2KS_SIMPLE) {
            printstate->content_printer(printstate->indent,
                                        "Salt",
                                        NULL,
                                        seckey->protection.s2k.salt,
                                        (unsigned) sizeof(seckey->protection.s2k.salt));
        }
        if (seckey->protection.s2k.specifier == PGP_S2KS_ITERATED_AND_SALTED) {
            print_uint(printstate->indent, "Octet count", seckey->protection.s2k.iterations);
        }
        printstate->content_printer(printstate->indent,
                                    "IV",
                                    NULL,
                                    seckey->protection.iv,
                                    pgp_block_size(seckey->protection.symm_alg));
    }
    /* no more set if encrypted */
    if (seckey->encrypted) {
        return;
    }
    switch (seckey->pubkey.alg) {
    case PGP_PKA_RSA:
        print_bn(printstate->indent, "d", seckey->key.rsa.d);
        print_bn(printstate->indent, "p", seckey->key.rsa.p);
        print_bn(printstate->indent, "q", seckey->key.rsa.q);
        print_bn(printstate->indent, "u", seckey->key.rsa.u);
        break;

    case PGP_PKA_DSA:
        print_bn(printstate->indent, "x", seckey->key.dsa.x);
        break;

    case PGP_PKA_ECDSA:
    case PGP_PKA_ECDH:
    case PGP_PKA_EDDSA:
    case PGP_PKA_SM2:
        print_bn(printstate->indent, "x", seckey->key.ecc.x);
        break;

    default:
        (void) fprintf(stderr, "print_seckey_verbose: unusual algorithm\n");
    }
    if (seckey->protection.s2k.usage == PGP_S2KU_ENCRYPTED_AND_HASHED) {
        printstate->content_printer(
          printstate->indent, "Checkhash", NULL, seckey->checkhash, PGP_CHECKHASH_SIZE);
    } else {
        print_uint(printstate->indent, "Checksum", seckey->checksum);
    }
}

static void
print_pk_sesskey(pgp_printstate_t *      printstate,
                 pgp_content_enum        tag,
                 const pgp_pk_sesskey_t *key)
{
    print_uint(printstate->indent, "Version", key->version);
    printstate->content_printer(
      printstate->indent, "Key ID", NULL, key->key_id, sizeof(key->key_id));
    print_string_and_value(printstate->indent, "Algorithm", pgp_show_pka(key->alg), key->alg);

    switch (key->alg) {
    case PGP_PKA_RSA:
        print_bn(printstate->indent, "encrypted_m", key->params.rsa.encrypted_m);
        break;

    case PGP_PKA_ELGAMAL:
        print_bn(printstate->indent, "g^k", key->params.elgamal.g_to_k);
        print_bn(printstate->indent, "encrypted_m", key->params.elgamal.encrypted_m);
        break;

    default:
        (void) fprintf(stderr, "print_pk_sesskey: unusual algorithm\n");
    }

    if (tag == PGP_PTAG_CT_PK_SESSION_KEY) {
        print_string_and_value(printstate->indent,
                               "Symmetric algorithm",
                               pgp_show_symm_alg(key->symm_alg),
                               key->symm_alg);
        printstate->content_printer(
          printstate->indent, "Key", NULL, key->key, pgp_key_size(key->symm_alg));
        print_uint(printstate->indent, "Checksum", key->checksum);
    }
}

static void
start_subpacket(int *indent, int type)
{
    print_indent(*indent);
    printf("* %s (type 0x%02x)\n",
           pgp_show_ss_type((pgp_content_enum) type),
           type - PGP_PTAG_SIG_SUBPKT_BASE);
    *indent += 4;
}

inline static void
end_subpacket(int *indent)
{
    *indent -= 4;
}

inline static void
print_packet_length_type(int indent, const pgp_ptag_t *ptag)
{
    /* Applicable only if old format */
    if (ptag->new_format == 0) {
        print_indent(indent);
        printf("Length type: %d\n", ptag->length_type);
    }
}

/**
\ingroup Core_Print
\param contents
*/
bool
pgp_print_packet(pgp_cbdata_t *cbinfo, const pgp_packet_t *pkt)
{
#define print_data(indent, name, pgp_data) \
    print->content_printer(indent, name, NULL, (pgp_data)->contents, (pgp_data)->len)
#define print_hexdump(indent, name, data, len) \
    print->content_printer(indent, name, NULL, data, len)

    if (!cbinfo || !pkt) {
        return false;
    }

    const pgp_contents_t *content = &pkt->u;
    pgp_text_t *          text;
    const char *          str;
    pgp_printstate_t *    print = &cbinfo->printstate;
    const bool            print_full_content = (cbinfo->arg) ? *((bool *) cbinfo->arg) : true;
    print->content_printer = print_full_content ? &print_hex_data_full : &print_hex_data_size;

    if (print->unarmored && pkt->tag != PGP_PTAG_CT_UNARMORED_TEXT) {
        print->unarmored = 0;
        puts("UNARMOURED TEXT ends");
    }

    if (rnp_get_debug(__FILE__)) {
        if (pkt->tag == PGP_PARSER_PTAG) {
            printf("=> PGP_PARSER_PTAG: %s\n",
                   pgp_show_packet_tag((pgp_content_enum) content->ptag.type));
        } else {
            printf("=> %s\n", pgp_show_packet_tag(pkt->tag));
        }
    }

    switch (pkt->tag) {
    case PGP_PARSER_ERROR:
        printf("parse error: %s\n", content->error);
        break;

    case PGP_PARSER_ERRCODE:
        printf("parse error: %s\n", pgp_errcode(content->errcode.errcode));
        break;

    case PGP_PARSER_PACKET_END:
        if (print_full_content) {
            print_hex_data_full(print->indent,
                                NULL,
                                "Packet contents",
                                content->packet.raw,
                                content->packet.length);
        }
        print->indent = 0;
        break;

    case PGP_PARSER_PTAG:
        if (content->ptag.type == PGP_PTAG_CT_PUBLIC_KEY) {
            print->indent = 0;
            printf("\n*** NEXT KEY ***\n");
        }
        printf("\n");
        print_indent(print->indent);
        printf("* PACKET: %s (tag %u) (%u bytes) offset=0x%x format=%s\n",
               pgp_show_packet_tag((pgp_content_enum) content->ptag.type),
               content->ptag.type,
               content->ptag.length,
               content->ptag.position,
               content->ptag.new_format ? "new" : "old");
        print->indent = 4;
        print_packet_length_type(print->indent, &content->ptag);
        break;

    case PGP_PTAG_CT_SE_DATA_HEADER:
        break;

    case PGP_PTAG_CT_SE_IP_DATA_HEADER:
        printf("Version: %d\n", content->se_ip_data_header);
        break;

    case PGP_PTAG_CT_SE_IP_DATA_BODY:
        print->content_printer(print->indent,
                               NULL,
                               "data",
                               content->se_data_body.data,
                               content->se_data_body.length);
        break;

    case PGP_PTAG_CT_PUBLIC_KEY:
    case PGP_PTAG_CT_PUBLIC_SUBKEY:
        pgp_print_pubkey(print->indent, &content->pubkey);
        break;

    case PGP_PTAG_CT_TRUST:
        print_data(print->indent, "Trust", &content->trust);
        break;

    case PGP_PTAG_CT_USER_ID:
        print_utf8_string(print->indent, "userid", content->userid);
        break;

    case PGP_PTAG_CT_SIGNATURE:
        print_uint(print->indent, "Version", (unsigned) content->sig.info.version);
        if (content->sig.info.birthtime_set) {
            print_time(print->indent, "Signature Creation Time", content->sig.info.birthtime);
        }
        if (content->sig.info.duration_set) {
            print_uint(
              print->indent, "Signature Duration", (unsigned) content->sig.info.duration);
        }

        print_string_and_value(print->indent,
                               "Signature Type",
                               pgp_show_sig_type(content->sig.info.type),
                               content->sig.info.type);

        if (content->sig.info.signer_id_set) {
            print_hexdump(print->indent,
                          "Signer ID",
                          content->sig.info.signer_id,
                          (unsigned) sizeof(content->sig.info.signer_id));
        }

        print_string_and_value(print->indent,
                               "Public Key Algorithm",
                               pgp_show_pka(content->sig.info.key_alg),
                               content->sig.info.key_alg);
        print_string_and_value(print->indent,
                               "Hash Algorithm",
                               pgp_show_hash_alg((uint8_t) content->sig.info.hash_alg),
                               (uint8_t) content->sig.info.hash_alg);
        print_uint(print->indent, "Hashed data len", (unsigned) content->sig.info.v4_hashlen);
        print_indent(print->indent);
        print_hexdump(print->indent, "hash2", &content->sig.hash2[0], 2);
        switch (content->sig.info.key_alg) {
        case PGP_PKA_RSA:
        case PGP_PKA_RSA_SIGN_ONLY:
            print_bn(print->indent, "RSA sign", content->sig.info.sig.rsa.sig);
            break;

        case PGP_PKA_DSA:
            print_bn(print->indent, "r", content->sig.info.sig.dsa.r);
            print_bn(print->indent, "s", content->sig.info.sig.dsa.s);
            break;

        case PGP_PKA_ECDSA:
        case PGP_PKA_EDDSA:
        case PGP_PKA_SM2:
            print_bn(print->indent, "r", content->sig.info.sig.ecc.r);
            print_bn(print->indent, "s", content->sig.info.sig.ecc.s);
            break;

        case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
            print_bn(print->indent, "r", content->sig.info.sig.elgamal.r);
            print_bn(print->indent, "s", content->sig.info.sig.elgamal.s);
            break;

        default:
            (void) fprintf(stderr, "pgp_print_packet: Unusual algorithm\n");
            return false;
        }

        if (content->sig.hash)
            printf("data hash is set\n");

        break;

    case PGP_PTAG_CT_COMPRESSED:
        print_uint(print->indent, "Compressed Data Type", (unsigned) content->compressed);
        break;

    case PGP_PTAG_CT_1_PASS_SIG:
        print_uint(print->indent, "Version", (unsigned) content->one_pass_sig.version);
        print_string_and_value(print->indent,
                               "Signature Type",
                               pgp_show_sig_type(content->one_pass_sig.type),
                               content->one_pass_sig.type);
        print_string_and_value(print->indent,
                               "Hash Algorithm",
                               pgp_show_hash_alg((uint8_t) content->one_pass_sig.halg),
                               (uint8_t) content->one_pass_sig.halg);
        print_string_and_value(print->indent,
                               "Public Key Algorithm",
                               pgp_show_pka(content->one_pass_sig.palg),
                               content->one_pass_sig.palg);
        print_hexdump(print->indent,
                      "Signer ID",
                      content->one_pass_sig.keyid,
                      (unsigned) sizeof(content->one_pass_sig.keyid));
        print_uint(print->indent, "Nested", content->one_pass_sig.nested);
        break;

    case PGP_PTAG_CT_USER_ATTR:
        print_hexdump(print->indent,
                      "User Attribute",
                      content->userattr.contents,
                      (unsigned) content->userattr.len);
        break;

    case PGP_PTAG_RAW_SS:
        if (pkt->critical) {
            (void) fprintf(stderr, "contents are critical\n");
            return false;
        }
        start_subpacket(&print->indent, pkt->tag);
        print_uint(print->indent,
                   "Raw Signature Subpacket: tag",
                   (unsigned) (content->ss_raw.tag - (unsigned) PGP_PTAG_SIG_SUBPKT_BASE));

        print_hexdump(
          print->indent, "Raw Data", content->ss_raw.raw, (unsigned) content->ss_raw.length);
        break;

    case PGP_PTAG_SS_CREATION_TIME:
        start_subpacket(&print->indent, pkt->tag);
        print_time(print->indent, "Signature Creation Time", content->ss_time);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_EXPIRATION_TIME:
        start_subpacket(&print->indent, pkt->tag);
        print_duration(print->indent, "Signature Expiration Time", content->ss_time);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_KEY_EXPIRY:
        start_subpacket(&print->indent, pkt->tag);
        print_duration(print->indent, "Key Expiration Time", content->ss_time);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_TRUST:
        start_subpacket(&print->indent, pkt->tag);
        print_string(print->indent, "Trust Signature", "");
        print_uint(print->indent, "Level", (unsigned) content->ss_trust.level);
        print_uint(print->indent, "Amount", (unsigned) content->ss_trust.amount);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_REVOCABLE:
        start_subpacket(&print->indent, pkt->tag);
        print_boolean(print->indent, "Revocable", content->ss_revocable);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_REVOCATION_KEY:
        start_subpacket(&print->indent, pkt->tag);
        /* not yet tested */
        printf("  revocation key: class=0x%x", content->ss_revocation_key.class);
        if (content->ss_revocation_key.class & 0x40) {
            printf(" (sensitive)");
        }
        printf(", algid=0x%x", content->ss_revocation_key.algid);
        hexdump(
          stdout, "fingerprint", content->ss_revocation_key.fingerprint, PGP_FINGERPRINT_SIZE);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_ISSUER_KEY_ID:
        start_subpacket(&print->indent, pkt->tag);
        print_hexdump(print->indent,
                      "Issuer Key Id",
                      content->ss_issuer,
                      (unsigned) sizeof(content->ss_issuer));
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_PREFERRED_SKA:
        start_subpacket(&print->indent, pkt->tag);
        print_data(print->indent, "Preferred Symmetric Algorithms", &content->ss_skapref);
        text = pgp_showall_ss_skapref(&content->ss_skapref);
        print_text_breakdown(print->indent, text);
        pgp_text_free(text);

        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_PRIMARY_USER_ID:
        start_subpacket(&print->indent, pkt->tag);
        print_boolean(print->indent, "Primary User ID", content->ss_primary_userid);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_PREFERRED_HASH:
        start_subpacket(&print->indent, pkt->tag);
        print_data(print->indent, "Preferred Hash Algorithms", &content->ss_hashpref);
        text = pgp_showall_ss_hashpref(&content->ss_hashpref);
        print_text_breakdown(print->indent, text);
        pgp_text_free(text);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_PREF_COMPRESS:
        start_subpacket(&print->indent, pkt->tag);
        print_data(print->indent, "Preferred Compression Algorithms", &content->ss_zpref);
        text = pgp_showall_ss_zpref(&content->ss_zpref);
        print_text_breakdown(print->indent, text);
        pgp_text_free(text);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_KEY_FLAGS:
        start_subpacket(&print->indent, pkt->tag);
        print_data(print->indent, "Key Flags", &content->ss_key_flags);

        text = pgp_showall_ss_key_flags(&content->ss_key_flags);
        print_text_breakdown(print->indent, text);
        pgp_text_free(text);

        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_KEYSERV_PREFS:
        start_subpacket(&print->indent, pkt->tag);
        print_data(print->indent, "Key Server Preferences", &content->ss_key_server_prefs);
        text = pgp_show_keyserv_prefs(&content->ss_key_server_prefs);
        print_text_breakdown(print->indent, text);
        pgp_text_free(text);

        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_FEATURES:
        start_subpacket(&print->indent, pkt->tag);
        print_data(print->indent, "Features", &content->ss_features);
        text = pgp_showall_ss_features(content->ss_features);
        print_text_breakdown(print->indent, text);
        pgp_text_free(text);

        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_NOTATION_DATA:
        start_subpacket(&print->indent, pkt->tag);
        print_indent(print->indent);
        printf("Notation Data:\n");

        print->indent++;
        print_data(print->indent, "Flags", &content->ss_notation.flags);
        text = pgp_showall_notation(content->ss_notation);
        print_text_breakdown(print->indent, text);
        pgp_text_free(text);

        print_data(print->indent, "Name", &content->ss_notation.name);

        print_data(print->indent, "Value", &content->ss_notation.value);

        print->indent--;
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_REGEXP:
        start_subpacket(&print->indent, pkt->tag);
        print_hexdump(print->indent,
                      "Regular Expression",
                      (uint8_t *) content->ss_regexp,
                      (unsigned) strlen(content->ss_regexp));
        print_string(print->indent, NULL, content->ss_regexp);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_POLICY_URI:
        start_subpacket(&print->indent, pkt->tag);
        print_string(print->indent, "Policy URL", content->ss_policy);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_SIGNERS_USER_ID:
        start_subpacket(&print->indent, pkt->tag);
        print_utf8_string(print->indent, "Signer's User ID", content->ss_signer);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_PREF_KEYSERV:
        start_subpacket(&print->indent, pkt->tag);
        print_string(print->indent, "Preferred Key Server", content->ss_keyserv);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_EMBEDDED_SIGNATURE:
        start_subpacket(&print->indent, pkt->tag);
        end_subpacket(&print->indent); /* \todo print out contents? */
        break;

    case PGP_PTAG_SS_ISSUER_FPR:
        start_subpacket(&print->indent, pkt->tag);
        print_hexdump(print->indent,
                      "Issuer Fingerprint",
                      content->ss_issuer_fpr.contents + 1,
                      content->ss_issuer_fpr.len - 1);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_USERDEFINED00:
    case PGP_PTAG_SS_USERDEFINED01:
    case PGP_PTAG_SS_USERDEFINED02:
    case PGP_PTAG_SS_USERDEFINED03:
    case PGP_PTAG_SS_USERDEFINED04:
    case PGP_PTAG_SS_USERDEFINED05:
    case PGP_PTAG_SS_USERDEFINED06:
    case PGP_PTAG_SS_USERDEFINED07:
    case PGP_PTAG_SS_USERDEFINED08:
    case PGP_PTAG_SS_USERDEFINED09:
    case PGP_PTAG_SS_USERDEFINED10:
        start_subpacket(&print->indent, pkt->tag);
        print_hexdump(print->indent,
                      "Internal or user-defined",
                      content->ss_userdef.contents,
                      (unsigned) content->ss_userdef.len);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_RESERVED:
        start_subpacket(&print->indent, pkt->tag);
        print_hexdump(print->indent,
                      "Reserved",
                      content->ss_userdef.contents,
                      (unsigned) content->ss_userdef.len);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_SS_REVOCATION_REASON:
        start_subpacket(&print->indent, pkt->tag);
        print_hexdump(print->indent, "Revocation Reason", &content->ss_revocation.code, 1);
        str = pgp_show_ss_rr_code(content->ss_revocation.code);
        print_string(print->indent, NULL, str);
        end_subpacket(&print->indent);
        break;

    case PGP_PTAG_CT_LITDATA_HEADER:
        printf("  literal data header format=%c filename='%s'\n",
               content->litdata_header.format,
               content->litdata_header.filename);
        showtime("    modification time", content->litdata_header.mtime);
        printf("\n");
        break;

    case PGP_PTAG_CT_LITDATA_BODY:
        printf("  literal data body length=%u\n", content->litdata_body.length);
        printf("    data=");
        print_escaped(content->litdata_body.data, content->litdata_body.length);
        printf("\n");
        break;

    case PGP_PTAG_CT_SIGNATURE_HEADER:
        print_uint(print->indent, "Version", (unsigned) content->sig.info.version);
        if (content->sig.info.birthtime_set) {
            print_time(print->indent, "Signature Creation Time", content->sig.info.birthtime);
        }
        if (content->sig.info.duration_set) {
            print_uint(
              print->indent, "Signature Duration", (unsigned) content->sig.info.duration);
        }
        print_string_and_value(print->indent,
                               "Signature Type",
                               pgp_show_sig_type(content->sig.info.type),
                               content->sig.info.type);
        if (content->sig.info.signer_id_set) {
            print_hexdump(print->indent,
                          "Signer ID",
                          content->sig.info.signer_id,
                          (unsigned) sizeof(content->sig.info.signer_id));
        }
        print_string_and_value(print->indent,
                               "Public Key Algorithm",
                               pgp_show_pka(content->sig.info.key_alg),
                               content->sig.info.key_alg);
        print_string_and_value(print->indent,
                               "Hash Algorithm",
                               pgp_show_hash_alg((uint8_t) content->sig.info.hash_alg),
                               (uint8_t) content->sig.info.hash_alg);
        print_uint(print->indent, "Hashed data len", (unsigned) content->sig.info.v4_hashlen);

        break;

    case PGP_PTAG_CT_SIGNATURE_FOOTER:
        print_indent(print->indent);
        print_hexdump(print->indent, "hash2", &content->sig.hash2[0], 2);

        switch (content->sig.info.key_alg) {
        case PGP_PKA_RSA:
            print_bn(print->indent, "RSA sign", content->sig.info.sig.rsa.sig);
            break;

        case PGP_PKA_DSA:
            print_bn(print->indent, "r", content->sig.info.sig.dsa.r);
            print_bn(print->indent, "s", content->sig.info.sig.dsa.s);
            break;

        case PGP_PKA_ECDSA:
        case PGP_PKA_EDDSA:
        case PGP_PKA_SM2:
            print_bn(print->indent, "r", content->sig.info.sig.ecc.r);
            print_bn(print->indent, "s", content->sig.info.sig.ecc.s);
            break;

        case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
            print_bn(print->indent, "r", content->sig.info.sig.elgamal.r);
            print_bn(print->indent, "s", content->sig.info.sig.elgamal.s);
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
        case PGP_PKA_PRIVATE10:
            print_data(print->indent, "Private/Experimental", &content->sig.info.sig.unknown);
            break;

        default:
            (void) fprintf(stderr, "pgp_print_packet: Unusual key algorithm\n");
            return false;
        }
        break;

    case PGP_GET_PASSWORD:
        break;

    case PGP_PTAG_CT_SECRET_KEY:
        print_seckey_verbose(print, pkt->tag, &content->seckey);
        break;

    case PGP_PTAG_CT_SECRET_SUBKEY:
        print_seckey_verbose(print, pkt->tag, &content->seckey);
        break;

    case PGP_PTAG_CT_ARMOR_HEADER:
        print_string(print->indent, "type", content->armor_header.type);
        break;

    case PGP_PTAG_CT_SIGNED_CLEARTEXT_HEADER:
        print_headers(&content->cleartext_head);
        break;

    case PGP_PTAG_CT_SIGNED_CLEARTEXT_BODY:
        print_block(print->indent,
                    "signed cleartext",
                    content->cleartext_body.data,
                    content->cleartext_body.length);
        break;

    case PGP_PTAG_CT_SIGNED_CLEARTEXT_TRAILER:
        printf("hash algorithm: %d\n", pgp_hash_alg_type(content->cleartext_trailer));
        printf("\n");
        break;

    case PGP_PTAG_CT_UNARMORED_TEXT:
        if (!print->unarmored) {
            print->unarmored = 1;
        }
        putchar('[');
        print_escaped(content->unarmored_text.data, content->unarmored_text.length);
        putchar(']');
        break;

    case PGP_PTAG_CT_ARMOR_TRAILER:
        print_string(print->indent, "type", content->armor_header.type);
        break;

    case PGP_PTAG_CT_PK_SESSION_KEY:
    case PGP_PTAG_CT_ENCRYPTED_PK_SESSION_KEY:
        print_pk_sesskey(print, pkt->tag, &content->pk_sesskey);
        break;

    case PGP_GET_SECKEY:
        print_pk_sesskey(
          print, PGP_PTAG_CT_ENCRYPTED_PK_SESSION_KEY, content->get_seckey.pk_sesskey);
        break;

    default:
        fprintf(stderr, "pgp_print_packet: unknown tag=%d (0x%x)\n", pkt->tag, pkt->tag);
        return false;
    }
    return true;
}
