/*
 * Copyright (c) 2017-2020, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
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

#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#else
#include "uniwin.h"
#endif
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <inttypes.h>

#include "key_store_pgp.h"
#include "key_store_kbx.h"
#include "pgp-key.h"
#include <librepgp/stream-sig.h>

#define BLOB_SIZE_LIMIT (5 * 1024 * 1024) // same limit with GnuPG 2.1

#define BLOB_HEADER_SIZE 0x5
#define BLOB_FIRST_SIZE 0x20

static uint8_t
ru8(uint8_t *p)
{
    return (uint8_t) p[0];
}

static uint16_t
ru16(uint8_t *p)
{
    return (uint16_t)(((uint8_t) p[0] << 8) | (uint8_t) p[1]);
}

static uint32_t
ru32(uint8_t *p)
{
    return (uint32_t)(((uint8_t) p[0] << 24) | ((uint8_t) p[1] << 16) | ((uint8_t) p[2] << 8) |
                      (uint8_t) p[3]);
}

static bool
rnp_key_store_kbx_parse_header_blob(kbx_header_blob_t *first_blob)
{
    uint8_t *image = first_blob->blob.image + BLOB_HEADER_SIZE;

    if (first_blob->blob.length != BLOB_FIRST_SIZE) {
        RNP_LOG("The first blob has wrong length: %" PRIu32 " but expected %d",
                first_blob->blob.length,
                (int) BLOB_FIRST_SIZE);
        return false;
    }

    first_blob->version = ru8(image);
    image += 1;
    if (first_blob->version != 1) {
        RNP_LOG("Wrong version, expect 1 but has %" PRIu8, first_blob->version);
        return false;
    }

    first_blob->flags = ru16(image);
    image += 2;

    // blob should contains a magic KBXf
    if (memcmp(image, "KBXf", 4)) {
        RNP_LOG("The first blob hasn't got a KBXf magic string");
        return false;
    }
    image += 4;
    // RFU
    image += 4;
    // File creation time
    first_blob->file_created_at = ru32(image);
    image += 4;
    // Duplicated?
    first_blob->file_created_at = ru32(image);
    image += 4;
    // RFU +4 bytes
    // RFU +4 bytes
    return true;
}

static bool
rnp_key_store_kbx_parse_pgp_blob(kbx_pgp_blob_t *pgp_blob)
{
    int      i;
    uint8_t *image = pgp_blob->blob.image;
    uint32_t len = pgp_blob->blob.length;

    image += BLOB_HEADER_SIZE;
    len -= BLOB_HEADER_SIZE;

    if (len < 15) {
        RNP_LOG("Too few data in the blob.");
        return false;
    }
    pgp_blob->version = ru8(image);
    image++;

    if (pgp_blob->version != 1) {
        RNP_LOG("Wrong version: %" PRIu8, pgp_blob->version);
        return false;
    }

    pgp_blob->flags = ru16(image);
    image += 2;

    pgp_blob->keyblock_offset = ru32(image);
    image += 4;

    pgp_blob->keyblock_length = ru32(image);
    image += 4;

    if ((pgp_blob->keyblock_offset > pgp_blob->blob.length) ||
        (pgp_blob->keyblock_offset > (UINT32_MAX - pgp_blob->keyblock_length)) ||
        pgp_blob->blob.length < (pgp_blob->keyblock_offset + pgp_blob->keyblock_length)) {
        RNP_LOG("Wrong keyblock offset/length, blob size: %" PRIu32
                ", keyblock offset: %" PRIu32 ", length: %" PRIu32,
                pgp_blob->blob.length,
                pgp_blob->keyblock_offset,
                pgp_blob->keyblock_length);
        return false;
    }

    pgp_blob->nkeys = ru16(image);
    image += 2;

    if (pgp_blob->nkeys < 1) {
        RNP_LOG("PGP blob should contains at least 1 key");
        return false;
    }

    /* Size of the single key record */
    pgp_blob->keys_len = ru16(image);
    image += 2;

    if (pgp_blob->keys_len < 28) {
        RNP_LOG("PGP blob needs 28 bytes, but contains: %" PRIu16 " bytes",
                pgp_blob->keys_len);
        return false;
    }
    len -= 15;

    for (i = 0; i < pgp_blob->nkeys; i++) {
        kbx_pgp_key_t nkey = {};

        if (len < pgp_blob->keys_len) {
            RNP_LOG("Too few bytes left for key blob");
            return false;
        }

        // copy fingerprint
        memcpy(nkey.fp, image, 20);
        image += 20;

        nkey.keyid_offset = ru32(image);
        image += 4;

        nkey.flags = ru16(image);
        image += 2;

        // RFU
        image += 2;

        // skip padding bytes if it existed
        image += pgp_blob->keys_len - 28;
        len -= pgp_blob->keys_len;

        if (!list_append(&pgp_blob->keys, &nkey, sizeof(nkey))) {
            RNP_LOG("alloc failed");
            return false;
        }
    }

    if (len < 2) {
        RNP_LOG("No data for sn_size");
        return false;
    }
    pgp_blob->sn_size = ru16(image);
    image += 2;
    len -= 2;

    if (pgp_blob->sn_size > len) {
        RNP_LOG("SN is %" PRIu16 ", while bytes left are %" PRIu32, pgp_blob->sn_size, len);
        return false;
    }

    if (pgp_blob->sn_size > 0) {
        pgp_blob->sn = (uint8_t *) malloc(pgp_blob->sn_size);
        if (pgp_blob->sn == NULL) {
            RNP_LOG("bad malloc");
            return false;
        }

        memcpy(pgp_blob->sn, image, pgp_blob->sn_size);
        image += pgp_blob->sn_size;
        len -= pgp_blob->sn_size;
    }

    if (len < 4) {
        RNP_LOG("Too few data for uids");
        return false;
    }
    pgp_blob->nuids = ru16(image);
    image += 2;
    pgp_blob->uids_len = ru16(image);
    image += 2;
    len -= 4;

    if (pgp_blob->uids_len < 12) {
        RNP_LOG("Too few bytes for uid struct: %" PRIu16, pgp_blob->uids_len);
        return false;
    }

    for (i = 0; i < pgp_blob->nuids; i++) {
        kbx_pgp_uid_t nuid = {};

        if (len < pgp_blob->uids_len) {
            RNP_LOG("Too few bytes to read uid struct.");
            return false;
        }
        nuid.offset = ru32(image);
        image += 4;

        nuid.length = ru32(image);
        image += 4;

        nuid.flags = ru16(image);
        image += 2;

        nuid.validity = ru8(image);
        image += 1;

        // RFU
        image += 1;

        // skip padding bytes if it existed
        image += (pgp_blob->uids_len - 12);
        len -= pgp_blob->uids_len;

        if (!list_append(&pgp_blob->uids, &nuid, sizeof(nuid))) {
            RNP_LOG("alloc failed");
            return false;
        }
    }

    if (len < 4) {
        RNP_LOG("No data left for sigs");
        return false;
    }

    pgp_blob->nsigs = ru16(image);
    image += 2;

    pgp_blob->sigs_len = ru16(image);
    image += 2;
    len -= 4;

    if (pgp_blob->sigs_len < 4) {
        RNP_LOG("Too small SIGN structure: %" PRIu16, pgp_blob->uids_len);
        return false;
    }

    for (i = 0; i < pgp_blob->nsigs; i++) {
        kbx_pgp_sig_t nsig = {};

        if (len < pgp_blob->sigs_len) {
            RNP_LOG("Too few data for sig");
            return false;
        }

        nsig.expired = ru32(image);
        image += 4;

        // skip padding bytes if it existed
        image += (pgp_blob->sigs_len - 4);
        len -= pgp_blob->sigs_len;

        if (!list_append(&pgp_blob->sigs, &nsig, sizeof(nsig))) {
            RNP_LOG("alloc failed");
            return false;
        }
    }

    if (len < 16) {
        RNP_LOG("Too few data for trust/validities");
        return false;
    }

    pgp_blob->ownertrust = ru8(image);
    image += 1;

    pgp_blob->all_Validity = ru8(image);
    image += 1;

    // RFU
    image += 2;

    pgp_blob->recheck_after = ru32(image);
    image += 4;

    pgp_blob->latest_timestamp = ru32(image);
    image += 4;

    pgp_blob->blob_created_at = ru32(image);
    image += 4;

    // here starts keyblock, UID and reserved space for future usage

    // Maybe we should add checksum verify but GnuPG never checked it
    // Checksum is last 20 bytes of blob and it is SHA-1, if it invalid MD5 and starts from 4
    // zero it is MD5.

    return true;
}

static kbx_blob_t *
rnp_key_store_kbx_parse_blob(uint8_t *image, uint32_t image_len)
{
    // a blob shouldn't be less of length + type
    if (image_len < BLOB_HEADER_SIZE) {
        RNP_LOG("Blob size is %" PRIu32 " but it shouldn't be less of header", image_len);
        return NULL;
    }

    uint32_t      length = ru32(image + 0);
    kbx_blob_type type = (kbx_blob_type) ru8(image + 4);
    size_t        bloblen = 0;

    switch (type) {
    case KBX_EMPTY_BLOB:
        bloblen = sizeof(kbx_blob_t);
        break;
    case KBX_HEADER_BLOB:
        bloblen = sizeof(kbx_header_blob_t);
        break;
    case KBX_PGP_BLOB:
        bloblen = sizeof(kbx_pgp_blob_t);
        break;
    case KBX_X509_BLOB:
        // current we doesn't parse X509 blob, so, keep it as is
        bloblen = sizeof(kbx_blob_t);
        break;
    // unsupported blob type
    default:
        RNP_LOG("Unsupported blob type: %d", (int) type);
        return NULL;
    }

    kbx_blob_t *blob = (kbx_blob_t *) calloc(1, bloblen);
    if (!blob) {
        RNP_LOG("Can't allocate memory");
        return NULL;
    }

    blob->image = image;
    blob->length = length;
    blob->type = type;

    // call real parser of blob
    switch (type) {
    case KBX_HEADER_BLOB:
        if (!rnp_key_store_kbx_parse_header_blob((kbx_header_blob_t *) blob)) {
            free(blob);
            return NULL;
        }
        break;
    case KBX_PGP_BLOB:
        if (!rnp_key_store_kbx_parse_pgp_blob((kbx_pgp_blob_t *) blob)) {
            free_kbx_pgp_blob((kbx_pgp_blob_t *) blob);
            free(blob);
            return NULL;
        }
        break;
    default:
        break;
    }

    return blob;
}

bool
rnp_key_store_kbx_from_src(rnp_key_store_t *         key_store,
                           pgp_source_t *            src,
                           const pgp_key_provider_t *key_provider)
{
    pgp_source_t    memsrc = {};
    size_t          has_bytes;
    uint8_t *       buf;
    uint32_t        blob_length;
    kbx_pgp_blob_t *pgp_blob;
    kbx_blob_t **   blob;
    bool            res = false;

    if (read_mem_src(&memsrc, src)) {
        RNP_LOG("failed to get data to memory source");
        return false;
    }

    has_bytes = memsrc.size;
    buf = (uint8_t *) mem_src_get_memory(&memsrc);
    while (has_bytes > 4) {
        blob_length = ru32(buf);
        if (blob_length > BLOB_SIZE_LIMIT) {
            RNP_LOG("Blob size is %" PRIu32 " bytes but limit is %d bytes",
                    blob_length,
                    (int) BLOB_SIZE_LIMIT);
            goto finish;
        }
        if (has_bytes < blob_length) {
            RNP_LOG("Blob have size %" PRIu32 " bytes but file contains only %zu bytes",
                    blob_length,
                    has_bytes);
            goto finish;
        }
        blob = (kbx_blob_t **) list_append(&key_store->blobs, NULL, sizeof(*blob));
        if (!blob) {
            RNP_LOG("alloc failed");
            goto finish;
        }

        *blob = rnp_key_store_kbx_parse_blob(buf, blob_length);
        if (!*blob) {
            list_remove((list_item *) blob);
            goto finish;
        }

        if ((*blob)->type == KBX_PGP_BLOB) {
            pgp_source_t blsrc = {};
            // parse keyblock if it existed
            pgp_blob = (kbx_pgp_blob_t *) *blob;

            if (!pgp_blob->keyblock_length) {
                RNP_LOG("PGP blob have zero size");
                goto finish;
            }

            if (init_mem_src(&blsrc,
                             (*blob)->image + pgp_blob->keyblock_offset,
                             pgp_blob->keyblock_length,
                             false)) {
                RNP_LOG("memory src allocation failed");
                goto finish;
            }

            if (rnp_key_store_pgp_read_from_src(key_store, &blsrc)) {
                src_close(&blsrc);
                goto finish;
            }
            src_close(&blsrc);
        }

        has_bytes -= blob_length;
        buf += blob_length;
    }

    res = true;
finish:
    src_close(&memsrc);
    return res;
}

static bool
pbuf(pgp_dest_t *dst, const void *buf, size_t len)
{
    dst_write(dst, buf, len);
    return dst->werr == RNP_SUCCESS;
}

static bool
pu8(pgp_dest_t *dst, uint8_t p)
{
    return pbuf(dst, &p, 1);
}

static bool
pu16(pgp_dest_t *dst, uint16_t f)
{
    uint8_t p[2];
    p[0] = (uint8_t)(f >> 8);
    p[1] = (uint8_t) f;
    return pbuf(dst, p, 2);
}

static bool
pu32(pgp_dest_t *dst, uint32_t f)
{
    uint8_t p[4];
    STORE32BE(p, f);
    return pbuf(dst, p, 4);
}

static bool
rnp_key_store_kbx_write_header(rnp_key_store_t *key_store, pgp_dest_t *dst)
{
    uint16_t    flags = 0;
    uint32_t    file_created_at = time(NULL);
    kbx_blob_t *blob = (kbx_blob_t *) list_front(key_store->blobs);

    if (blob && (blob->type == KBX_HEADER_BLOB)) {
        file_created_at = ((kbx_header_blob_t *) blob)->file_created_at;
    }

    return !(!pu32(dst, BLOB_FIRST_SIZE) || !pu8(dst, KBX_HEADER_BLOB) ||
             !pu8(dst, 1)                                                   // version
             || !pu16(dst, flags) || !pbuf(dst, "KBXf", 4) || !pu32(dst, 0) // RFU
             || !pu32(dst, 0)                                               // RFU
             || !pu32(dst, file_created_at) || !pu32(dst, time(NULL)) || !pu32(dst, 0)); // RFU
}

static bool
rnp_key_store_kbx_write_pgp(rnp_key_store_t *key_store, pgp_key_t *key, pgp_dest_t *dst)
{
    unsigned   i;
    pgp_dest_t memdst = {};
    size_t     key_start, uid_start;
    uint8_t *  p;
    uint8_t    checksum[20];
    uint32_t   pt;
    pgp_hash_t hash = {0};
    bool       result = false;
    list       subkey_sig_expirations = NULL; // expirations (uint32_t) of subkey signatures
    uint32_t   expiration = 0;

    if (init_mem_dest(&memdst, NULL, BLOB_SIZE_LIMIT)) {
        RNP_LOG("alloc failed");
        return false;
    }

    if (!pu32(&memdst, 0)) { // length, we don't know length of blob yet, so it's 0 right now
        goto finish;
    }

    if (!pu8(&memdst, KBX_PGP_BLOB) || !pu8(&memdst, 1)) { // type, version
        goto finish;
    }

    if (!pu16(&memdst, 0)) { // flags, not used by GnuPG
        goto finish;
    }

    if (!pu32(&memdst, 0) ||
        !pu32(&memdst, 0)) { // offset and length of keyblock, update later
        goto finish;
    }

    if (!pu16(&memdst, 1 + key->subkey_count())) { // number of keys in keyblock
        goto finish;
    }
    if (!pu16(&memdst, 28)) { // size of key info structure)
        goto finish;
    }

    if (!pbuf(&memdst, key->fp().fingerprint, PGP_FINGERPRINT_SIZE) ||
        !pu32(&memdst, memdst.writeb - 8) || // offset to keyid (part of fpr for V4)
        !pu16(&memdst, 0) ||                 // flags, not used by GnuPG
        !pu16(&memdst, 0)) {                 // RFU
        goto finish;
    }

    // same as above, for each subkey
    for (auto &sfp : key->subkey_fps()) {
        pgp_key_t *subkey = rnp_key_store_get_key_by_fpr(key_store, sfp);
        if (!pbuf(&memdst, subkey->fp().fingerprint, PGP_FINGERPRINT_SIZE) ||
            !pu32(&memdst, memdst.writeb - 8) || // offset to keyid (part of fpr for V4)
            !pu16(&memdst, 0) ||                 // flags, not used by GnuPG
            !pu16(&memdst, 0)) {                 // RFU
            goto finish;
        }
        // load signature expirations while we're at it
        for (i = 0; i < subkey->sig_count(); i++) {
            expiration = subkey->get_sig(i).sig.key_expiration();
            if (list_append(&subkey_sig_expirations, &expiration, sizeof(expiration)) ==
                NULL) {
                goto finish;
            };
        }
    }

    if (!pu16(&memdst, 0)) { // Zero size of serial number
        goto finish;
    }

    // skip serial number

    if (!pu16(&memdst, key->uid_count()) || !pu16(&memdst, 12)) {
        goto finish;
    }

    uid_start = memdst.writeb;

    for (i = 0; i < key->uid_count(); i++) {
        if (!pu32(&memdst, 0) ||
            !pu32(&memdst, 0)) { // UID offset and length, update when blob has done
            goto finish;
        }

        if (!pu16(&memdst, 0)) { // flags, (not yet used)
            goto finish;
        }

        if (!pu8(&memdst, 0) || !pu8(&memdst, 0)) { // Validity & RFU
            goto finish;
        }
    }

    if (!pu16(&memdst, key->sig_count() + list_length(subkey_sig_expirations)) ||
        !pu16(&memdst, 4)) {
        goto finish;
    }

    for (i = 0; i < key->sig_count(); i++) {
        if (!pu32(&memdst, key->get_sig(i).sig.key_expiration())) {
            goto finish;
        }
    }
    for (list_item *expiration_entry = list_front(subkey_sig_expirations); expiration_entry;
         expiration_entry = list_next(expiration_entry)) {
        expiration = *(uint32_t *) expiration_entry;
        if (!pu32(&memdst, expiration)) {
            goto finish;
        }
    }

    if (!pu8(&memdst, 0) ||
        !pu8(&memdst, 0)) { // Assigned ownertrust & All_Validity (not yet used)
        goto finish;
    }

    if (!pu16(&memdst, 0) || !pu32(&memdst, 0)) { // RFU & Recheck_after
        goto finish;
    }

    if (!pu32(&memdst, time(NULL)) ||
        !pu32(&memdst, time(NULL))) { // Latest timestamp && created
        goto finish;
    }

    if (!pu32(&memdst, 0)) { // Size of reserved space
        goto finish;
    }

    // wrtite UID, we might redesign PGP write and use this information from keyblob
    for (i = 0; i < key->uid_count(); i++) {
        const pgp_userid_t &uid = key->get_uid(i);
        p = (uint8_t *) mem_dest_get_memory(&memdst) + uid_start + (12 * i);
        /* store absolute uid offset in the output stream */
        pt = memdst.writeb + dst->writeb;
        STORE32BE(p, pt);
        /* and uid length */
        pt = uid.str.size();
        p = (uint8_t *) mem_dest_get_memory(&memdst) + uid_start + (12 * i) + 4;
        STORE32BE(p, pt);
        /* uid data itself */
        if (!pbuf(&memdst, uid.str.c_str(), pt)) {
            goto finish;
        }
    }

    /* write keyblock and fix the offset/length */
    key_start = memdst.writeb;
    pt = key_start;
    p = (uint8_t *) mem_dest_get_memory(&memdst) + 8;
    STORE32BE(p, pt);

    key->write(memdst);
    if (memdst.werr) {
        goto finish;
    }

    for (auto &sfp : key->subkey_fps()) {
        const pgp_key_t *subkey = rnp_key_store_get_key_by_fpr(key_store, sfp);
        subkey->write(memdst);
        if (memdst.werr) {
            goto finish;
        }
    }

    /* key blob length */
    pt = memdst.writeb - key_start;
    p = (uint8_t *) mem_dest_get_memory(&memdst) + 12;
    STORE32BE(p, pt);

    // fix the length of blob
    pt = memdst.writeb + 20;
    p = (uint8_t *) mem_dest_get_memory(&memdst);
    STORE32BE(p, pt);

    // checksum
    if (!pgp_hash_create(&hash, PGP_HASH_SHA1)) {
        RNP_LOG("bad sha1 alloc");
        goto finish;
    }

    if (hash._output_len != 20) {
        RNP_LOG("wrong hash size %zu, should be 20 bytes", hash._output_len);
        goto finish;
    }

    pgp_hash_add(&hash, (uint8_t *) mem_dest_get_memory(&memdst), memdst.writeb);

    if (!pgp_hash_finish(&hash, checksum)) {
        goto finish;
    }

    if (!(pbuf(&memdst, checksum, 20))) {
        goto finish;
    }

    /* finally write to the output */
    dst_write(dst, mem_dest_get_memory(&memdst), memdst.writeb);
    result = dst->werr == RNP_SUCCESS;
finish:
    dst_close(&memdst, true);
    list_destroy(&subkey_sig_expirations);
    return result;
}

static bool
rnp_key_store_kbx_write_x509(rnp_key_store_t *key_store, pgp_dest_t *dst)
{
    for (list_item *item = list_front(key_store->blobs); item; item = list_next(item)) {
        kbx_blob_t *blob = *((kbx_blob_t **) item);
        if (blob->type != KBX_X509_BLOB) {
            continue;
        }

        if (!pbuf(dst, blob->image, blob->length)) {
            return false;
        }
    }

    return true;
}

bool
rnp_key_store_kbx_to_dst(rnp_key_store_t *key_store, pgp_dest_t *dst)
{
    if (!rnp_key_store_kbx_write_header(key_store, dst)) {
        RNP_LOG("Can't write KBX header");
        return false;
    }

    for (auto &key : key_store->keys) {
        if (!key.is_primary()) {
            continue;
        }
        if (!rnp_key_store_kbx_write_pgp(key_store, &key, dst)) {
            RNP_LOG("Can't write PGP blobs for key %p", &key);
            return false;
        }
    }

    if (!rnp_key_store_kbx_write_x509(key_store, dst)) {
        RNP_LOG("Can't write X509 blobs");
        return false;
    }

    return true;
}

void
free_kbx_pgp_blob(kbx_pgp_blob_t *pgp_blob)
{
    list_destroy(&pgp_blob->keys);
    if (pgp_blob->sn_size > 0) {
        free(pgp_blob->sn);
    }
    list_destroy(&pgp_blob->uids);
    list_destroy(&pgp_blob->sigs);
}
