/*
 * Copyright (c) 2017-2020, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#else
#include "uniwin.h"
#endif
#include <string.h>
#include <inttypes.h>
#include <rnp/rnp_def.h>
#include "types.h"
#include "crypto.h"
#include "crypto/mem.h"
#include "stream-packet.h"
#include "stream-key.h"
#include <algorithm>

uint32_t
read_uint32(const uint8_t *buf)
{
    return ((uint32_t) buf[0] << 24) | ((uint32_t) buf[1] << 16) | ((uint32_t) buf[2] << 8) |
           (uint32_t) buf[3];
}

uint16_t
read_uint16(const uint8_t *buf)
{
    return ((uint16_t) buf[0] << 8) | buf[1];
}

void
write_uint16(uint8_t *buf, uint16_t val)
{
    buf[0] = val >> 8;
    buf[1] = val & 0xff;
}

size_t
write_packet_len(uint8_t *buf, size_t len)
{
    if (len < 192) {
        buf[0] = len;
        return 1;
    } else if (len < 8192 + 192) {
        buf[0] = ((len - 192) >> 8) + 192;
        buf[1] = (len - 192) & 0xff;
        return 2;
    } else {
        buf[0] = 0xff;
        STORE32BE(&buf[1], len);
        return 5;
    }
}

int
get_packet_type(uint8_t ptag)
{
    if (!(ptag & PGP_PTAG_ALWAYS_SET)) {
        return -1;
    }

    if (ptag & PGP_PTAG_NEW_FORMAT) {
        return (int) (ptag & PGP_PTAG_NF_CONTENT_TAG_MASK);
    } else {
        return (int) ((ptag & PGP_PTAG_OF_CONTENT_TAG_MASK) >> PGP_PTAG_OF_CONTENT_TAG_SHIFT);
    }
}

int
stream_pkt_type(pgp_source_t &src)
{
    if (src_eof(&src)) {
        return 0;
    }
    size_t hdrneed = 0;
    if (!stream_pkt_hdr_len(src, hdrneed)) {
        return -1;
    }
    uint8_t hdr[PGP_MAX_HEADER_SIZE];
    if (!src_peek_eq(&src, hdr, hdrneed)) {
        return -1;
    }
    return get_packet_type(hdr[0]);
}

bool
stream_pkt_hdr_len(pgp_source_t &src, size_t &hdrlen)
{
    uint8_t buf[2];

    if (!src_peek_eq(&src, buf, 2) || !(buf[0] & PGP_PTAG_ALWAYS_SET)) {
        return false;
    }

    if (buf[0] & PGP_PTAG_NEW_FORMAT) {
        if (buf[1] < 192) {
            hdrlen = 2;
        } else if (buf[1] < 224) {
            hdrlen = 3;
        } else if (buf[1] < 255) {
            hdrlen = 2;
        } else {
            hdrlen = 6;
        }
        return true;
    }

    switch (buf[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
    case PGP_PTAG_OLD_LEN_1:
        hdrlen = 2;
        return true;
    case PGP_PTAG_OLD_LEN_2:
        hdrlen = 3;
        return true;
    case PGP_PTAG_OLD_LEN_4:
        hdrlen = 5;
        return true;
    case PGP_PTAG_OLD_LEN_INDETERMINATE:
        hdrlen = 1;
        return true;
    default:
        return false;
    }
}

static bool
get_pkt_len(uint8_t *hdr, size_t *pktlen)
{
    if (hdr[0] & PGP_PTAG_NEW_FORMAT) {
        // 1-byte length
        if (hdr[1] < 192) {
            *pktlen = hdr[1];
            return true;
        }
        // 2-byte length
        if (hdr[1] < 224) {
            *pktlen = ((size_t)(hdr[1] - 192) << 8) + (size_t) hdr[2] + 192;
            return true;
        }
        // partial length - we do not allow it here
        if (hdr[1] < 255) {
            return false;
        }
        // 4-byte length
        *pktlen = read_uint32(&hdr[2]);
        return true;
    }

    switch (hdr[0] & PGP_PTAG_OF_LENGTH_TYPE_MASK) {
    case PGP_PTAG_OLD_LEN_1:
        *pktlen = hdr[1];
        return true;
    case PGP_PTAG_OLD_LEN_2:
        *pktlen = read_uint16(&hdr[1]);
        return true;
    case PGP_PTAG_OLD_LEN_4:
        *pktlen = read_uint32(&hdr[1]);
        return true;
    default:
        return false;
    }
}

bool
stream_read_pkt_len(pgp_source_t *src, size_t *pktlen)
{
    uint8_t buf[6] = {};
    size_t  read = 0;

    if (!stream_pkt_hdr_len(*src, read)) {
        return false;
    }

    if (!src_read_eq(src, buf, read)) {
        return false;
    }

    return get_pkt_len(buf, pktlen);
}

bool
stream_read_partial_chunk_len(pgp_source_t *src, size_t *clen, bool *last)
{
    uint8_t hdr[5] = {};
    size_t  read = 0;

    if (!src_read(src, hdr, 1, &read)) {
        RNP_LOG("failed to read header");
        return false;
    }
    if (read < 1) {
        RNP_LOG("wrong eof");
        return false;
    }

    *last = true;
    // partial length
    if ((hdr[0] >= 224) && (hdr[0] < 255)) {
        *last = false;
        *clen = get_partial_pkt_len(hdr[0]);
        return true;
    }
    // 1-byte length
    if (hdr[0] < 192) {
        *clen = hdr[0];
        return true;
    }
    // 2-byte length
    if (hdr[0] < 224) {
        if (!src_read_eq(src, &hdr[1], 1)) {
            RNP_LOG("wrong 2-byte length");
            return false;
        }
        *clen = ((size_t)(hdr[0] - 192) << 8) + (size_t) hdr[1] + 192;
        return true;
    }
    // 4-byte length
    if (!src_read_eq(src, &hdr[1], 4)) {
        RNP_LOG("wrong 4-byte length");
        return false;
    }
    *clen = ((size_t) hdr[1] << 24) | ((size_t) hdr[2] << 16) | ((size_t) hdr[3] << 8) |
            (size_t) hdr[4];
    return true;
}

bool
stream_old_indeterminate_pkt_len(pgp_source_t *src)
{
    uint8_t ptag = 0;
    if (!src_peek_eq(src, &ptag, 1)) {
        return false;
    }
    return !(ptag & PGP_PTAG_NEW_FORMAT) &&
           ((ptag & PGP_PTAG_OF_LENGTH_TYPE_MASK) == PGP_PTAG_OLD_LEN_INDETERMINATE);
}

bool
stream_partial_pkt_len(pgp_source_t *src)
{
    uint8_t hdr[2] = {};
    if (!src_peek_eq(src, hdr, 2)) {
        return false;
    }
    return (hdr[0] & PGP_PTAG_NEW_FORMAT) && (hdr[1] >= 224) && (hdr[1] < 255);
}

size_t
get_partial_pkt_len(uint8_t blen)
{
    return 1 << (blen & 0x1f);
}

rnp_result_t
stream_peek_packet_hdr(pgp_source_t *src, pgp_packet_hdr_t *hdr)
{
    size_t hlen = 0;
    memset(hdr, 0, sizeof(*hdr));
    if (!stream_pkt_hdr_len(*src, hlen)) {
        uint8_t hdr2[2] = {0};
        if (!src_peek_eq(src, hdr2, 2)) {
            RNP_LOG("pkt header read failed");
            return RNP_ERROR_READ;
        }

        RNP_LOG("bad packet header: 0x%02x%02x", hdr2[0], hdr2[1]);
        return RNP_ERROR_BAD_FORMAT;
    }

    if (!src_peek_eq(src, hdr->hdr, hlen)) {
        RNP_LOG("failed to read pkt header");
        return RNP_ERROR_READ;
    }

    hdr->hdr_len = hlen;
    hdr->tag = (pgp_pkt_type_t) get_packet_type(hdr->hdr[0]);

    if (stream_partial_pkt_len(src)) {
        hdr->partial = true;
    } else if (stream_old_indeterminate_pkt_len(src)) {
        hdr->indeterminate = true;
    } else {
        (void) get_pkt_len(hdr->hdr, &hdr->pkt_len);
    }

    return RNP_SUCCESS;
}

static rnp_result_t
stream_read_packet_partial(pgp_source_t *src, pgp_dest_t *dst)
{
    uint8_t hdr = 0;
    if (!src_read_eq(src, &hdr, 1)) {
        return RNP_ERROR_READ;
    }

    bool   last = false;
    size_t partlen = 0;
    if (!stream_read_partial_chunk_len(src, &partlen, &last)) {
        return RNP_ERROR_BAD_FORMAT;
    }

    uint8_t *buf = (uint8_t *) malloc(PGP_INPUT_CACHE_SIZE);
    if (!buf) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    while (partlen > 0) {
        size_t read = std::min(partlen, (size_t) PGP_INPUT_CACHE_SIZE);
        if (!src_read_eq(src, buf, read)) {
            free(buf);
            return RNP_ERROR_READ;
        }
        if (dst) {
            dst_write(dst, buf, read);
        }
        partlen -= read;
        if (partlen > 0) {
            continue;
        }
        if (last) {
            break;
        }
        if (!stream_read_partial_chunk_len(src, &partlen, &last)) {
            free(buf);
            return RNP_ERROR_BAD_FORMAT;
        }
    }
    free(buf);
    return RNP_SUCCESS;
}

rnp_result_t
stream_read_packet(pgp_source_t *src, pgp_dest_t *dst)
{
    if (stream_old_indeterminate_pkt_len(src)) {
        return dst_write_src(src, dst, PGP_MAX_OLD_LEN_INDETERMINATE_PKT_SIZE);
    }

    if (stream_partial_pkt_len(src)) {
        return stream_read_packet_partial(src, dst);
    }

    try {
        pgp_packet_body_t body(PGP_PKT_RESERVED);
        rnp_result_t      ret = body.read(*src);
        if (dst) {
            body.write(*dst, false);
        }
        return ret;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_GENERIC;
    }
}

rnp_result_t
stream_skip_packet(pgp_source_t *src)
{
    return stream_read_packet(src, NULL);
}

rnp_result_t
stream_parse_marker(pgp_source_t &src)
{
    try {
        pgp_packet_body_t pkt(PGP_PKT_MARKER);
        rnp_result_t      res = pkt.read(src);
        if (res) {
            return res;
        }
        if ((pkt.size() != PGP_MARKER_LEN) ||
            memcmp(pkt.data(), PGP_MARKER_CONTENTS, PGP_MARKER_LEN)) {
            return RNP_ERROR_BAD_FORMAT;
        }
        return RNP_SUCCESS;
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
}

bool
is_key_pkt(int tag)
{
    switch (tag) {
    case PGP_PKT_PUBLIC_KEY:
    case PGP_PKT_PUBLIC_SUBKEY:
    case PGP_PKT_SECRET_KEY:
    case PGP_PKT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
is_subkey_pkt(int tag)
{
    return (tag == PGP_PKT_PUBLIC_SUBKEY) || (tag == PGP_PKT_SECRET_SUBKEY);
}

bool
is_primary_key_pkt(int tag)
{
    return (tag == PGP_PKT_PUBLIC_KEY) || (tag == PGP_PKT_SECRET_KEY);
}

bool
is_public_key_pkt(int tag)
{
    switch (tag) {
    case PGP_PKT_PUBLIC_KEY:
    case PGP_PKT_PUBLIC_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
is_secret_key_pkt(int tag)
{
    switch (tag) {
    case PGP_PKT_SECRET_KEY:
    case PGP_PKT_SECRET_SUBKEY:
        return true;
    default:
        return false;
    }
}

bool
is_rsa_key_alg(pgp_pubkey_alg_t alg)
{
    switch (alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
    case PGP_PKA_RSA_SIGN_ONLY:
        return true;
    default:
        return false;
    }
}

pgp_packet_body_t::pgp_packet_body_t(pgp_pkt_type_t tag)
{
    data_.reserve(16);
    tag_ = tag;
    secure_ = is_secret_key_pkt(tag);
}

pgp_packet_body_t::pgp_packet_body_t(const uint8_t *data, size_t len)
{
    data_.assign(data, data + len);
    tag_ = PGP_PKT_RESERVED;
    secure_ = false;
}

pgp_packet_body_t::~pgp_packet_body_t()
{
    if (secure_) {
        secure_clear(data_.data(), data_.size());
    }
}

uint8_t *
pgp_packet_body_t::data() noexcept
{
    return data_.data();
}

size_t
pgp_packet_body_t::size() const noexcept
{
    return data_.size();
}

size_t
pgp_packet_body_t::left() const noexcept
{
    return data_.size() - pos_;
}

bool
pgp_packet_body_t::get(uint8_t &val) noexcept
{
    if (pos_ >= data_.size()) {
        return false;
    }
    val = data_[pos_++];
    return true;
}

bool
pgp_packet_body_t::get(uint16_t &val) noexcept
{
    if (pos_ + 2 > data_.size()) {
        return false;
    }
    val = read_uint16(data_.data() + pos_);
    pos_ += 2;
    return true;
}

bool
pgp_packet_body_t::get(uint32_t &val) noexcept
{
    if (pos_ + 4 > data_.size()) {
        return false;
    }
    val = read_uint32(data_.data() + pos_);
    pos_ += 4;
    return true;
}

bool
pgp_packet_body_t::get(uint8_t *val, size_t len) noexcept
{
    if (pos_ + len > data_.size()) {
        return false;
    }
    memcpy(val, data_.data() + pos_, len);
    pos_ += len;
    return true;
}

bool
pgp_packet_body_t::get(pgp_key_id_t &val) noexcept
{
    static_assert(std::tuple_size<pgp_key_id_t>::value == PGP_KEY_ID_SIZE,
                  "pgp_key_id_t size mismatch");
    return get(val.data(), val.size());
}

bool
pgp_packet_body_t::get(pgp_mpi_t &val) noexcept
{
    uint16_t bits = 0;
    if (!get(bits)) {
        return false;
    }
    size_t len = (bits + 7) >> 3;
    if (len > PGP_MPINT_SIZE) {
        RNP_LOG("too large mpi");
        return false;
    }
    if (!len) {
        RNP_LOG("0 mpi");
        return false;
    }
    if (!get(val.mpi, len)) {
        RNP_LOG("failed to read mpi body");
        return false;
    }
    /* check the mpi bit count */
    val.len = len;
    size_t mbits = mpi_bits(&val);
    if (mbits != bits) {
        RNP_LOG(
          "Warning! Wrong mpi bit count: got %" PRIu16 ", but actual is %zu", bits, mbits);
    }
    return true;
}

bool
pgp_packet_body_t::get(pgp_curve_t &val) noexcept
{
    uint8_t oidlen = 0;
    if (!get(oidlen)) {
        return false;
    }
    uint8_t oid[MAX_CURVE_OID_HEX_LEN] = {0};
    if (!oidlen || (oidlen == 0xff) || (oidlen > sizeof(oid))) {
        RNP_LOG("unsupported curve oid len: %" PRIu8, oidlen);
        return false;
    }
    if (!get(oid, oidlen)) {
        return false;
    }
    pgp_curve_t res = find_curve_by_OID(oid, oidlen);
    if (res == PGP_CURVE_MAX) {
        RNP_LOG("unsupported curve");
        return false;
    }
    val = res;
    return true;
}

bool
pgp_packet_body_t::get(pgp_s2k_t &s2k) noexcept
{
    uint8_t spec = 0, halg = 0;
    if (!get(spec) || !get(halg)) {
        return false;
    }
    s2k.specifier = (pgp_s2k_specifier_t) spec;
    s2k.hash_alg = (pgp_hash_alg_t) halg;

    switch (s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        return true;
    case PGP_S2KS_SALTED:
        return get(s2k.salt, PGP_SALT_SIZE);
    case PGP_S2KS_ITERATED_AND_SALTED: {
        uint8_t iter = 0;
        if (!get(s2k.salt, PGP_SALT_SIZE) || !get(iter)) {
            return false;
        }
        s2k.iterations = iter;
        return true;
    }
    case PGP_S2KS_EXPERIMENTAL: {
        try {
            s2k.experimental = {data_.begin() + pos_, data_.end()};
        } catch (const std::exception &e) {
            RNP_LOG("%s", e.what());
            return false;
        }
        uint8_t gnu[3] = {0};
        if (!get(gnu, 3) || memcmp(gnu, "GNU", 3)) {
            RNP_LOG("Unknown experimental s2k. Skipping.");
            pos_ = data_.size();
            s2k.gpg_ext_num = PGP_S2K_GPG_NONE;
            return true;
        }
        uint8_t ext_num = 0;
        if (!get(ext_num)) {
            return false;
        }
        if ((ext_num != PGP_S2K_GPG_NO_SECRET) && (ext_num != PGP_S2K_GPG_SMARTCARD)) {
            RNP_LOG("Unsupported gpg extension num: %" PRIu8 ", skipping", ext_num);
            pos_ = data_.size();
            s2k.gpg_ext_num = PGP_S2K_GPG_NONE;
            return true;
        }
        s2k.gpg_ext_num = (pgp_s2k_gpg_extension_t) ext_num;
        if (s2k.gpg_ext_num == PGP_S2K_GPG_NO_SECRET) {
            return true;
        }
        if (!get(s2k.gpg_serial_len)) {
            RNP_LOG("Failed to get GPG serial len");
            return false;
        }
        size_t len = s2k.gpg_serial_len;
        if (s2k.gpg_serial_len > 16) {
            RNP_LOG("Warning: gpg_serial_len is %d", (int) len);
            len = 16;
        }
        if (!get(s2k.gpg_serial, len)) {
            RNP_LOG("Failed to get GPG serial");
            return false;
        }
        return true;
    }
    default:
        RNP_LOG("unknown s2k specifier: %d", (int) s2k.specifier);
        return false;
    }
}

void
pgp_packet_body_t::add(const void *data, size_t len)
{
    data_.insert(data_.end(), (uint8_t *) data, (uint8_t *) data + len);
}

void
pgp_packet_body_t::add_byte(uint8_t bt)
{
    data_.push_back(bt);
}

void
pgp_packet_body_t::add_uint16(uint16_t val)
{
    uint8_t bytes[2];
    write_uint16(bytes, val);
    add(bytes, 2);
}

void
pgp_packet_body_t::add_uint32(uint32_t val)
{
    uint8_t bytes[4];
    STORE32BE(bytes, val);
    add(bytes, 4);
}

void
pgp_packet_body_t::add(const pgp_key_id_t &val)
{
    add(val.data(), val.size());
}

void
pgp_packet_body_t::add(const pgp_mpi_t &val)
{
    if (!val.len) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }

    unsigned idx = 0;
    while ((idx < val.len - 1) && (!val.mpi[idx])) {
        idx++;
    }

    unsigned bits = (val.len - idx - 1) << 3;
    unsigned hibyte = val.mpi[idx];
    while (hibyte) {
        bits++;
        hibyte = hibyte >> 1;
    }

    uint8_t hdr[2] = {(uint8_t)(bits >> 8), (uint8_t)(bits & 0xff)};
    add(hdr, 2);
    add(val.mpi + idx, val.len - idx);
}

void
pgp_packet_body_t::add_subpackets(const pgp_signature_t &sig, bool hashed)
{
    pgp_packet_body_t spbody(PGP_PKT_RESERVED);

    for (auto &subpkt : sig.subpkts) {
        if (subpkt.hashed != hashed) {
            continue;
        }

        uint8_t splen[6];
        size_t  lenlen = write_packet_len(splen, subpkt.len + 1);
        spbody.add(splen, lenlen);
        spbody.add_byte(subpkt.type | (subpkt.critical << 7));
        spbody.add(subpkt.data, subpkt.len);
    }

    if (spbody.data_.size() > 0xffff) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    add_uint16(spbody.data_.size());
    add(spbody.data_.data(), spbody.data_.size());
}

void
pgp_packet_body_t::add(const pgp_curve_t curve)
{
    const ec_curve_desc_t *desc = get_curve_desc(curve);
    if (!desc) {
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    add_byte((uint8_t) desc->OIDhex_len);
    add(desc->OIDhex, (uint8_t) desc->OIDhex_len);
}

void
pgp_packet_body_t::add(const pgp_s2k_t &s2k)
{
    add_byte(s2k.specifier);
    add_byte(s2k.hash_alg);

    switch (s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        return;
    case PGP_S2KS_SALTED:
        add(s2k.salt, PGP_SALT_SIZE);
        return;
    case PGP_S2KS_ITERATED_AND_SALTED: {
        unsigned iter = s2k.iterations;
        if (iter > 255) {
            iter = pgp_s2k_encode_iterations(iter);
        }
        add(s2k.salt, PGP_SALT_SIZE);
        add_byte(iter);
        return;
    }
    case PGP_S2KS_EXPERIMENTAL: {
        if ((s2k.gpg_ext_num != PGP_S2K_GPG_NO_SECRET) &&
            (s2k.gpg_ext_num != PGP_S2K_GPG_SMARTCARD)) {
            RNP_LOG("Unknown experimental s2k.");
            add(s2k.experimental.data(), s2k.experimental.size());
            return;
        }
        add("GNU", 3);
        add_byte(s2k.gpg_ext_num);
        if (s2k.gpg_ext_num == PGP_S2K_GPG_SMARTCARD) {
            static_assert(sizeof(s2k.gpg_serial) == 16, "invalid gpg serial length");
            size_t slen = s2k.gpg_serial_len > 16 ? 16 : s2k.gpg_serial_len;
            add_byte(s2k.gpg_serial_len);
            add(s2k.gpg_serial, slen);
        }
        return;
    }
    default:
        RNP_LOG("unknown s2k specifier");
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
}

rnp_result_t
pgp_packet_body_t::read(pgp_source_t &src) noexcept
{
    /* Make sure we have enough data for packet header */
    if (!src_peek_eq(&src, hdr_, 2)) {
        return RNP_ERROR_READ;
    }

    /* Read the packet header and length */
    size_t len = 0;
    if (!stream_pkt_hdr_len(src, len)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    if (!src_peek_eq(&src, hdr_, len)) {
        return RNP_ERROR_READ;
    }
    hdr_len_ = len;

    int ptag = get_packet_type(hdr_[0]);
    if ((ptag < 0) || ((tag_ != PGP_PKT_RESERVED) && (tag_ != ptag))) {
        RNP_LOG("tag mismatch: %d vs %d", (int) tag_, ptag);
        return RNP_ERROR_BAD_FORMAT;
    }
    tag_ = (pgp_pkt_type_t) ptag;

    if (!stream_read_pkt_len(&src, &len)) {
        return RNP_ERROR_READ;
    }

    /* early exit for the empty packet */
    if (!len) {
        return RNP_SUCCESS;
    }

    if (len > PGP_MAX_PKT_SIZE) {
        RNP_LOG("too large packet");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* Read the packet contents */
    try {
        data_.resize(len);
    } catch (const std::exception &e) {
        RNP_LOG("malloc of %d bytes failed, %s", (int) len, e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    size_t read = 0;
    if (!src_read(&src, data_.data(), len, &read) || (read != len)) {
        RNP_LOG("read %d instead of %d", (int) read, (int) len);
        return RNP_ERROR_READ;
    }
    pos_ = 0;
    return RNP_SUCCESS;
}

void
pgp_packet_body_t::write(pgp_dest_t &dst, bool hdr) noexcept
{
    if (hdr) {
        uint8_t hdrbt[6] = {
          (uint8_t)(tag_ | PGP_PTAG_ALWAYS_SET | PGP_PTAG_NEW_FORMAT), 0, 0, 0, 0, 0};
        size_t hlen = 1 + write_packet_len(&hdrbt[1], data_.size());
        dst_write(&dst, hdrbt, hlen);
    }
    dst_write(&dst, data_.data(), data_.size());
}

void
pgp_packet_body_t::mark_secure(bool secure) noexcept
{
    secure_ = secure;
}

void
pgp_sk_sesskey_t::write(pgp_dest_t &dst) const
{
    pgp_packet_body_t pktbody(PGP_PKT_SK_SESSION_KEY);
    /* version and algorithm fields */
    pktbody.add_byte(version);
    pktbody.add_byte(alg);
    if (version == PGP_SKSK_V5) {
        pktbody.add_byte(aalg);
    }
    /* S2K specifier */
    pktbody.add_byte(s2k.specifier);
    pktbody.add_byte(s2k.hash_alg);

    switch (s2k.specifier) {
    case PGP_S2KS_SIMPLE:
        break;
    case PGP_S2KS_SALTED:
        pktbody.add(s2k.salt, sizeof(s2k.salt));
        break;
    case PGP_S2KS_ITERATED_AND_SALTED:
        pktbody.add(s2k.salt, sizeof(s2k.salt));
        pktbody.add_byte(s2k.iterations);
        break;
    default:
        RNP_LOG("Unexpected s2k specifier: %d", (int) s2k.specifier);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    /* v5 : iv */
    if (version == PGP_SKSK_V5) {
        pktbody.add(iv, ivlen);
    }
    /* encrypted key and auth tag for v5 */
    if (enckeylen) {
        pktbody.add(enckey, enckeylen);
    }
    /* write packet */
    pktbody.write(dst);
}

rnp_result_t
pgp_sk_sesskey_t::parse(pgp_source_t &src)
{
    pgp_packet_body_t pkt(PGP_PKT_SK_SESSION_KEY);
    rnp_result_t      res = pkt.read(src);
    if (res) {
        return res;
    }

    /* version */
    uint8_t bt;
    if (!pkt.get(bt) || ((bt != PGP_SKSK_V4) && (bt != PGP_SKSK_V5))) {
        RNP_LOG("wrong packet version");
        return RNP_ERROR_BAD_FORMAT;
    }
    version = bt;
    /* symmetric algorithm */
    if (!pkt.get(bt)) {
        RNP_LOG("failed to get symm alg");
        return RNP_ERROR_BAD_FORMAT;
    }
    alg = (pgp_symm_alg_t) bt;

    if (version == PGP_SKSK_V5) {
        /* aead algorithm */
        if (!pkt.get(bt)) {
            RNP_LOG("failed to get aead alg");
            return RNP_ERROR_BAD_FORMAT;
        }
        aalg = (pgp_aead_alg_t) bt;
        if ((aalg != PGP_AEAD_EAX) && (aalg != PGP_AEAD_OCB)) {
            RNP_LOG("unsupported AEAD algorithm : %d", (int) aalg);
            return RNP_ERROR_BAD_PARAMETERS;
        }
    }

    /* s2k */
    if (!pkt.get(s2k)) {
        RNP_LOG("failed to parse s2k");
        return RNP_ERROR_BAD_FORMAT;
    }

    /* v4 key */
    if (version == PGP_SKSK_V4) {
        /* encrypted session key if present */
        size_t keylen = pkt.left();
        if (keylen) {
            if (keylen > PGP_MAX_KEY_SIZE + 1) {
                RNP_LOG("too long esk");
                return RNP_ERROR_BAD_FORMAT;
            }
            if (!pkt.get(enckey, keylen)) {
                RNP_LOG("failed to get key");
                return RNP_ERROR_BAD_FORMAT;
            }
        }
        enckeylen = keylen;
        return RNP_SUCCESS;
    }

    /* v5: iv + esk + tag. For both EAX and OCB ivlen and taglen are 16 octets */
    size_t noncelen = pgp_cipher_aead_nonce_len(aalg);
    size_t taglen = pgp_cipher_aead_tag_len(aalg);
    size_t keylen = 0;

    if (pkt.left() > noncelen + taglen + PGP_MAX_KEY_SIZE) {
        RNP_LOG("too long esk");
        return RNP_ERROR_BAD_FORMAT;
    }
    if (pkt.left() < noncelen + taglen + 8) {
        RNP_LOG("too short esk");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* iv */
    if (!pkt.get(iv, noncelen)) {
        RNP_LOG("failed to get iv");
        return RNP_ERROR_BAD_FORMAT;
    }
    ivlen = noncelen;

    /* key */
    keylen = pkt.left();
    if (!pkt.get(enckey, keylen)) {
        RNP_LOG("failed to get key");
        return RNP_ERROR_BAD_FORMAT;
    }
    enckeylen = keylen;
    return RNP_SUCCESS;
}

void
pgp_pk_sesskey_t::write(pgp_dest_t &dst) const
{
    pgp_packet_body_t pktbody(PGP_PKT_PK_SESSION_KEY);
    pktbody.add_byte(version);
    pktbody.add(key_id);
    pktbody.add_byte(alg);
    pktbody.add(material_buf.data(), material_buf.size());
    pktbody.write(dst);
}

rnp_result_t
pgp_pk_sesskey_t::parse(pgp_source_t &src)
{
    pgp_packet_body_t pkt(PGP_PKT_PK_SESSION_KEY);
    rnp_result_t      res = pkt.read(src);
    if (res) {
        return res;
    }
    /* version */
    uint8_t bt = 0;
    if (!pkt.get(bt) || (bt != PGP_PKSK_V3)) {
        RNP_LOG("wrong packet version");
        return RNP_ERROR_BAD_FORMAT;
    }
    version = bt;
    /* key id */
    if (!pkt.get(key_id)) {
        RNP_LOG("failed to get key id");
        return RNP_ERROR_BAD_FORMAT;
    }
    /* public key algorithm */
    if (!pkt.get(bt)) {
        RNP_LOG("failed to get palg");
        return RNP_ERROR_BAD_FORMAT;
    }
    alg = (pgp_pubkey_alg_t) bt;

    /* raw signature material */
    if (!pkt.left()) {
        RNP_LOG("No encrypted material");
        return RNP_ERROR_BAD_FORMAT;
    }
    try {
        material_buf.resize(pkt.left());
    } catch (const std::exception &e) {
        RNP_LOG("%s", e.what());
        return RNP_ERROR_OUT_OF_MEMORY;
    }
    /* we cannot fail here */
    pkt.get(material_buf.data(), material_buf.size());
    /* check whether it can be parsed */
    pgp_encrypted_material_t material = {};
    if (!parse_material(material)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    return RNP_SUCCESS;
}

bool
pgp_pk_sesskey_t::parse_material(pgp_encrypted_material_t &material) const
{
    pgp_packet_body_t pkt(material_buf.data(), material_buf.size());
    switch (alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
        /* RSA m */
        if (!pkt.get(material.rsa.m)) {
            RNP_LOG("failed to get rsa m");
            return false;
        }
        break;
    case PGP_PKA_ELGAMAL:
    case PGP_PKA_ELGAMAL_ENCRYPT_OR_SIGN:
        /* ElGamal g, m */
        if (!pkt.get(material.eg.g) || !pkt.get(material.eg.m)) {
            RNP_LOG("failed to get elgamal mpis");
            return false;
        }
        break;
    case PGP_PKA_SM2:
        /* SM2 m */
        if (!pkt.get(material.sm2.m)) {
            RNP_LOG("failed to get sm2 m");
            return false;
        }
        break;
    case PGP_PKA_ECDH: {
        /* ECDH ephemeral point */
        if (!pkt.get(material.ecdh.p)) {
            RNP_LOG("failed to get ecdh p");
            return false;
        }
        /* ECDH m */
        uint8_t bt = 0;
        if (!pkt.get(bt)) {
            RNP_LOG("failed to get ecdh m len");
            return false;
        }
        if (bt > ECDH_WRAPPED_KEY_SIZE) {
            RNP_LOG("wrong ecdh m len");
            return false;
        }
        material.ecdh.mlen = bt;
        if (!pkt.get(material.ecdh.m, bt)) {
            RNP_LOG("failed to get ecdh m len");
            return false;
        }
        break;
    }
    default:
        RNP_LOG("unknown pk alg %d", (int) alg);
        return false;
    }

    if (pkt.left()) {
        RNP_LOG("extra %d bytes in pk packet", (int) pkt.left());
        return false;
    }
    return true;
}

void
pgp_pk_sesskey_t::write_material(const pgp_encrypted_material_t &material)
{
    pgp_packet_body_t pktbody(PGP_PKT_PK_SESSION_KEY);

    switch (alg) {
    case PGP_PKA_RSA:
    case PGP_PKA_RSA_ENCRYPT_ONLY:
        pktbody.add(material.rsa.m);
        break;
    case PGP_PKA_SM2:
        pktbody.add(material.sm2.m);
        break;
    case PGP_PKA_ECDH:
        pktbody.add(material.ecdh.p);
        pktbody.add_byte(material.ecdh.mlen);
        pktbody.add(material.ecdh.m, material.ecdh.mlen);
        break;
    case PGP_PKA_ELGAMAL:
        pktbody.add(material.eg.g);
        pktbody.add(material.eg.m);
        break;
    default:
        RNP_LOG("Unknown pk alg: %d", (int) alg);
        throw rnp::rnp_exception(RNP_ERROR_BAD_PARAMETERS);
    }
    material_buf = {pktbody.data(), pktbody.data() + pktbody.size()};
}

void
pgp_one_pass_sig_t::write(pgp_dest_t &dst) const
{
    pgp_packet_body_t pktbody(PGP_PKT_ONE_PASS_SIG);
    pktbody.add_byte(version);
    pktbody.add_byte(type);
    pktbody.add_byte(halg);
    pktbody.add_byte(palg);
    pktbody.add(keyid);
    pktbody.add_byte(nested);
    pktbody.write(dst);
}

rnp_result_t
pgp_one_pass_sig_t::parse(pgp_source_t &src)
{
    pgp_packet_body_t pkt(PGP_PKT_ONE_PASS_SIG);
    /* Read the packet into memory */
    rnp_result_t res = pkt.read(src);
    if (res) {
        return res;
    }

    uint8_t buf[13] = {0};
    if ((pkt.size() != 13) || !pkt.get(buf, 13)) {
        return RNP_ERROR_BAD_FORMAT;
    }
    /* version */
    if (buf[0] != 3) {
        RNP_LOG("wrong packet version");
        return RNP_ERROR_BAD_FORMAT;
    }
    version = buf[0];
    /* signature type */
    type = (pgp_sig_type_t) buf[1];
    /* hash algorithm */
    halg = (pgp_hash_alg_t) buf[2];
    /* pk algorithm */
    palg = (pgp_pubkey_alg_t) buf[3];
    /* key id */
    static_assert(std::tuple_size<decltype(keyid)>::value == PGP_KEY_ID_SIZE,
                  "pgp_one_pass_sig_t.keyid size mismatch");
    memcpy(keyid.data(), &buf[4], PGP_KEY_ID_SIZE);
    /* nested flag */
    nested = buf[12];
    return RNP_SUCCESS;
}
