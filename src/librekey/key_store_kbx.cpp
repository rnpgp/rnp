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
#include <cassert>

#include "key_store_pgp.h"
#include "key_store_kbx.h"
#include "pgp-key.h"
#include <librepgp/stream-sig.h>

/* same limit with GnuPG 2.1 */
#define BLOB_SIZE_LIMIT (5 * 1024 * 1024)
/* limit the number of keys/sigs/uids in the blob */
#define BLOB_OBJ_LIMIT 0x8000

#define BLOB_HEADER_SIZE 0x5
#define BLOB_FIRST_SIZE 0x20
#define BLOB_KEY_SIZE 0x1C
#define BLOB_UID_SIZE 0x0C
#define BLOB_SIG_SIZE 0x04
#define BLOB_VALIDITY_SIZE 0x10

uint8_t
kbx_blob_t::ru8(size_t idx)
{
    return image_[idx];
}

uint16_t
kbx_blob_t::ru16(size_t idx)
{
    return read_uint16(image_.data() + idx);
}

uint32_t
kbx_blob_t::ru32(size_t idx)
{
    return read_uint32(image_.data() + idx);
}

kbx_blob_t::kbx_blob_t(std::vector<uint8_t> &data)
{
    if (data.size() < BLOB_HEADER_SIZE) {
        RNP_LOG("Too small KBX blob.");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    uint32_t len = read_uint32(data.data());
    if (len > BLOB_SIZE_LIMIT) {
        RNP_LOG("Too large KBX blob.");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    if (len != data.size()) {
        RNP_LOG("KBX blob size mismatch.");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    image_ = data;
    type_ = (kbx_blob_type_t) ru8(4);
}

bool
kbx_header_blob_t::parse()
{
    if (length() != BLOB_FIRST_SIZE) {
        RNP_LOG("The first blob has wrong length: %" PRIu32 " but expected %d",
                length(),
                (int) BLOB_FIRST_SIZE);
        return false;
    }

    size_t idx = BLOB_HEADER_SIZE;
    version_ = ru8(idx++);
    if (version_ != 1) {
        RNP_LOG("Wrong version, expect 1 but has %" PRIu8, version_);
        return false;
    }

    flags_ = ru16(idx);
    idx += 2;

    // blob should contains a magic KBXf
    if (memcmp(image_.data() + idx, "KBXf", 4)) {
        RNP_LOG("The first blob hasn't got a KBXf magic string");
        return false;
    }
    idx += 4;
    // RFU
    idx += 4;
    // File creation time
    file_created_at_ = ru32(idx);
    idx += 4;
    // Duplicated?
    file_created_at_ = ru32(idx);
    // RFU +4 bytes
    // RFU +4 bytes
    return true;
}

bool
kbx_pgp_blob_t::parse()
{
    if (image_.size() < 15 + BLOB_HEADER_SIZE) {
        RNP_LOG("Too few data in the blob.");
        return false;
    }

    size_t idx = BLOB_HEADER_SIZE;
    /* version */
    version_ = ru8(idx++);
    if (version_ != 1) {
        RNP_LOG("Wrong version: %" PRIu8, version_);
        return false;
    }
    /* flags */
    flags_ = ru16(idx);
    idx += 2;
    /* keyblock offset */
    keyblock_offset_ = ru32(idx);
    idx += 4;
    /* keyblock length */
    keyblock_length_ = ru32(idx);
    idx += 4;

    if ((keyblock_offset_ > image_.size()) ||
        (keyblock_offset_ > (UINT32_MAX - keyblock_length_)) ||
        (image_.size() < (keyblock_offset_ + keyblock_length_))) {
        RNP_LOG("Wrong keyblock offset/length, blob size: %zu"
                ", keyblock offset: %" PRIu32 ", length: %" PRIu32,
                image_.size(),
                keyblock_offset_,
                keyblock_length_);
        return false;
    }
    /* number of key blocks */
    size_t nkeys = ru16(idx);
    idx += 2;
    if (nkeys < 1) {
        RNP_LOG("PGP blob should contains at least 1 key");
        return false;
    }
    if (nkeys > BLOB_OBJ_LIMIT) {
        RNP_LOG("Too many keys in the PGP blob");
        return false;
    }

    /* Size of the single key record */
    size_t keys_len = ru16(idx);
    idx += 2;
    if (keys_len < BLOB_KEY_SIZE) {
        RNP_LOG(
          "PGP blob needs %d bytes, but contains: %zu bytes", (int) BLOB_KEY_SIZE, keys_len);
        return false;
    }

    for (size_t i = 0; i < nkeys; i++) {
        if (image_.size() - idx < keys_len) {
            RNP_LOG("Too few bytes left for key blob");
            return false;
        }

        kbx_pgp_key_t nkey = {};
        /* copy fingerprint */
        memcpy(nkey.fp, &image_[idx], 20);
        idx += 20;
        /* keyid offset */
        nkey.keyid_offset = ru32(idx);
        idx += 4;
        /* flags */
        nkey.flags = ru16(idx);
        idx += 2;
        /* RFU */
        idx += 2;
        /* skip padding bytes if it existed */
        idx += keys_len - BLOB_KEY_SIZE;
        keys_.push_back(std::move(nkey));
    }

    if (image_.size() - idx < 2) {
        RNP_LOG("No data for sn_size");
        return false;
    }
    size_t sn_size = ru16(idx);
    idx += 2;

    if (image_.size() - idx < sn_size) {
        RNP_LOG("SN is %zu, while bytes left are %zu", sn_size, image_.size() - idx);
        return false;
    }

    if (sn_size) {
        sn_ = {image_.begin() + idx, image_.begin() + idx + sn_size};
        idx += sn_size;
    }

    if (image_.size() - idx < 4) {
        RNP_LOG("Too few data for uids");
        return false;
    }
    size_t nuids = ru16(idx);
    if (nuids > BLOB_OBJ_LIMIT) {
        RNP_LOG("Too many uids in the PGP blob");
        return false;
    }

    size_t uids_len = ru16(idx + 2);
    idx += 4;

    if (uids_len < BLOB_UID_SIZE) {
        RNP_LOG("Too few bytes for uid struct: %zu", uids_len);
        return false;
    }

    for (size_t i = 0; i < nuids; i++) {
        if (image_.size() - idx < uids_len) {
            RNP_LOG("Too few bytes to read uid struct.");
            return false;
        }
        kbx_pgp_uid_t nuid = {};
        /* offset */
        nuid.offset = ru32(idx);
        idx += 4;
        /* length */
        nuid.length = ru32(idx);
        idx += 4;
        /* flags */
        nuid.flags = ru16(idx);
        idx += 2;
        /* validity */
        nuid.validity = ru8(idx);
        idx++;
        /* RFU */
        idx++;
        // skip padding bytes if it existed
        idx += uids_len - BLOB_UID_SIZE;

        uids_.push_back(std::move(nuid));
    }

    if (image_.size() - idx < 4) {
        RNP_LOG("No data left for sigs");
        return false;
    }

    size_t nsigs = ru16(idx);
    if (nsigs > BLOB_OBJ_LIMIT) {
        RNP_LOG("Too many sigs in the PGP blob");
        return false;
    }

    size_t sigs_len = ru16(idx + 2);
    idx += 4;

    if (sigs_len < BLOB_SIG_SIZE) {
        RNP_LOG("Too small SIGN structure: %zu", uids_len);
        return false;
    }

    for (size_t i = 0; i < nsigs; i++) {
        if (image_.size() - idx < sigs_len) {
            RNP_LOG("Too few data for sig");
            return false;
        }

        kbx_pgp_sig_t nsig = {};
        nsig.expired = ru32(idx);
        idx += 4;

        // skip padding bytes if it existed
        idx += (sigs_len - BLOB_SIG_SIZE);

        sigs_.push_back(nsig);
    }

    if (image_.size() - idx < BLOB_VALIDITY_SIZE) {
        RNP_LOG("Too few data for trust/validities");
        return false;
    }

    ownertrust_ = ru8(idx);
    idx++;
    all_validity_ = ru8(idx);
    idx++;
    // RFU
    idx += 2;
    recheck_after_ = ru32(idx);
    idx += 4;
    latest_timestamp_ = ru32(idx);
    idx += 4;
    blob_created_at_ = ru32(idx);
    // do not forget to idx += 4 on further expansion

    // here starts keyblock, UID and reserved space for future usage

    // Maybe we should add checksum verify but GnuPG never checked it
    // Checksum is last 20 bytes of blob and it is SHA-1, if it invalid MD5 and starts from 4
    // zero it is MD5.

    return true;
}

static std::unique_ptr<kbx_blob_t>
rnp_key_store_kbx_parse_blob(const uint8_t *image, size_t image_len)
{
    std::unique_ptr<kbx_blob_t> blob;
    // a blob shouldn't be less of length + type
    if (image_len < BLOB_HEADER_SIZE) {
        RNP_LOG("Blob size is %zu but it shouldn't be less of header", image_len);
        return blob;
    }

    try {
        std::vector<uint8_t> data(image, image + image_len);
        kbx_blob_type_t      type = (kbx_blob_type_t) image[4];

        switch (type) {
        case KBX_EMPTY_BLOB:
            blob = std::unique_ptr<kbx_blob_t>(new kbx_blob_t(data));
            break;
        case KBX_HEADER_BLOB:
            blob = std::unique_ptr<kbx_blob_t>(new kbx_header_blob_t(data));
            break;
        case KBX_PGP_BLOB:
            blob = std::unique_ptr<kbx_blob_t>(new kbx_pgp_blob_t(data));
            break;
        case KBX_X509_BLOB:
            // current we doesn't parse X509 blob, so, keep it as is
            blob = std::unique_ptr<kbx_blob_t>(new kbx_blob_t(data));
            break;
        // unsupported blob type
        default:
            RNP_LOG("Unsupported blob type: %d", (int) type);
            return blob;
        }

        if (!blob->parse()) {
            return NULL;
        }
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return NULL;
    }
    return blob;
}

bool
rnp_key_store_kbx_from_src(rnp_key_store_t *         key_store,
                           pgp_source_t *            src,
                           const pgp_key_provider_t *key_provider)
{
    pgp_source_t memsrc = {};
    if (read_mem_src(&memsrc, src)) {
        RNP_LOG("failed to get data to memory source");
        return false;
    }

    size_t has_bytes = memsrc.size;
    /* complications below are because of memsrc uses malloc instead of new */
    std::unique_ptr<uint8_t, void (*)(void *)> mem(
      (uint8_t *) mem_src_get_memory(&memsrc, true), free);
    src_close(&memsrc);
    uint8_t *buf = mem.get();

    while (has_bytes > 4) {
        size_t blob_length = read_uint32(buf);
        if (blob_length > BLOB_SIZE_LIMIT) {
            RNP_LOG("Blob size is %zu bytes but limit is %d bytes",
                    blob_length,
                    (int) BLOB_SIZE_LIMIT);
            return false;
        }
        if (blob_length < BLOB_HEADER_SIZE) {
            RNP_LOG("Too small blob header size");
            return false;
        }
        if (has_bytes < blob_length) {
            RNP_LOG("Blob have size %zu bytes but file contains only %zu bytes",
                    blob_length,
                    has_bytes);
            return false;
        }
        auto blob = rnp_key_store_kbx_parse_blob(buf, blob_length);
        if (!blob.get()) {
            RNP_LOG("Failed to parse blob");
            return false;
        }
        kbx_blob_t *pblob = blob.get();
        try {
            key_store->blobs.push_back(std::move(blob));
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }

        if (pblob->type() == KBX_PGP_BLOB) {
            // parse keyblock if it existed
            kbx_pgp_blob_t &pgp_blob = dynamic_cast<kbx_pgp_blob_t &>(*pblob);
            if (!pgp_blob.keyblock_length()) {
                RNP_LOG("PGP blob have zero size");
                return false;
            }

            pgp_source_t blsrc = {};
            if (init_mem_src(&blsrc,
                             pgp_blob.image().data() + pgp_blob.keyblock_offset(),
                             pgp_blob.keyblock_length(),
                             false)) {
                RNP_LOG("memory src allocation failed");
                return false;
            }

            if (rnp_key_store_pgp_read_from_src(key_store, &blsrc)) {
                src_close(&blsrc);
                return false;
            }
            src_close(&blsrc);
        }

        has_bytes -= blob_length;
        buf += blob_length;
    }

    return true;
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
    uint16_t flags = 0;
    uint32_t file_created_at = time(NULL);

    if (!key_store->blobs.empty() && (key_store->blobs[0]->type() == KBX_HEADER_BLOB)) {
        kbx_header_blob_t &blob = dynamic_cast<kbx_header_blob_t &>(*key_store->blobs[0]);
        file_created_at = blob.file_created_at();
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
    unsigned              i;
    pgp_dest_t            memdst = {};
    size_t                key_start, uid_start;
    uint8_t *             p;
    uint8_t               checksum[20];
    uint32_t              pt;
    bool                  result = false;
    std::vector<uint32_t> subkey_sig_expirations;
    uint32_t              expiration = 0;

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
            try {
                subkey_sig_expirations.push_back(expiration);
            } catch (const std::exception &e) {
                RNP_LOG("%s", e.what());
                goto finish;
            }
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

    if (!pu16(&memdst, key->sig_count() + subkey_sig_expirations.size()) ||
        !pu16(&memdst, 4)) {
        goto finish;
    }

    for (i = 0; i < key->sig_count(); i++) {
        if (!pu32(&memdst, key->get_sig(i).sig.key_expiration())) {
            goto finish;
        }
    }
    for (auto &expiration : subkey_sig_expirations) {
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
    try {
        rnp::Hash hash(PGP_HASH_SHA1);
        assert(hash.size() == 20);
        hash.add(mem_dest_get_memory(&memdst), memdst.writeb);
        hash.finish(checksum);
    } catch (const std::exception &e) {
        RNP_LOG("Hashing failed: %s", e.what());
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
    return result;
}

static bool
rnp_key_store_kbx_write_x509(rnp_key_store_t *key_store, pgp_dest_t *dst)
{
    for (auto &blob : key_store->blobs) {
        if (blob->type() != KBX_X509_BLOB) {
            continue;
        }
        if (!pbuf(dst, blob->image().data(), blob->length())) {
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
