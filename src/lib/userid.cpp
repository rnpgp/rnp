/*
 * Copyright (c) 2017-2025 [Ribose Inc](https://www.ribose.com).
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

#include "userid.hpp"
#include <algorithm>
#include <stdexcept>

namespace rnp {

UserID::UserID(const pgp_userid_pkt_t &uidpkt) : UserID()
{
    /* copy packet data */
    pkt = uidpkt;
    rawpkt = RawPacket(uidpkt);
    /* populate uid string */
    if (uidpkt.tag == PGP_PKT_USER_ID) {
        str.assign(uidpkt.uid.data(), uidpkt.uid.data() + uidpkt.uid.size());
    } else {
        str = "(photo)";
    }
}

size_t
UserID::sig_count() const
{
    return sigs_.size();
}

const pgp::SigID &
UserID::get_sig(size_t idx) const
{
    return sigs_.at(idx);
}

bool
UserID::has_sig(const pgp::SigID &id) const
{
    return std::find(sigs_.begin(), sigs_.end(), id) != sigs_.end();
}

void
UserID::add_sig(const pgp::SigID &sig, bool begin)
{
    size_t idx = begin ? 0 : sigs_.size();
    sigs_.insert(sigs_.begin() + idx, sig);
}

void
UserID::replace_sig(const pgp::SigID &id, const pgp::SigID &newsig)
{
    auto it = std::find(sigs_.begin(), sigs_.end(), id);
    if (it == sigs_.end()) {
        throw std::invalid_argument("id");
    }
    *it = newsig;
}

bool
UserID::del_sig(const pgp::SigID &id)
{
    auto it = std::find(sigs_.begin(), sigs_.end(), id);
    if (it == sigs_.end()) {
        return false;
    }
    sigs_.erase(it);
    return true;
}

void
UserID::clear_sigs()
{
    sigs_.clear();
}

/* Decode the variable-length subpacket length prefix used by both signature
 * and User Attribute subpackets (see RFC 4880 §5.2.3.1 / RFC 9580 §5.2.3.1).
 * On success, returns true and advances `pos` past the length field. */
static bool
skip_subpacket_length(const std::vector<uint8_t> &buf, size_t &pos, size_t &len)
{
    if (pos >= buf.size()) {
        return false;
    }
    uint8_t b0 = buf[pos++];
    if (b0 < 192) {
        len = b0;
    } else if (b0 < 224) {
        if (pos >= buf.size()) {
            return false;
        }
        len = ((size_t)(b0 - 192) << 8) + buf[pos++] + 192;
    } else if (b0 == 255) {
        if (pos + 4 > buf.size()) {
            return false;
        }
        len = ((size_t) buf[pos] << 24) | ((size_t) buf[pos + 1] << 16) |
              ((size_t) buf[pos + 2] << 8) | (size_t) buf[pos + 3];
        pos += 4;
    } else {
        /* 224-254: partial-length, not valid for UserAttr subpackets */
        return false;
    }
    return true;
}

bool
parse_photo_attribute(const std::vector<uint8_t> &uid,
                      std::vector<uint8_t> &      image,
                      PhotoFormat &               format)
{
    image.clear();
    format = PhotoFormat::Unknown;

    /* Walk attribute subpackets until we find an image (type 1). */
    size_t pos = 0;
    while (pos < uid.size()) {
        size_t sub_len = 0;
        if (!skip_subpacket_length(uid, pos, sub_len)) {
            return false;
        }
        if (sub_len == 0 || pos + sub_len > uid.size()) {
            return false;
        }
        size_t         sub_end = pos + sub_len;
        uint8_t        sub_type = uid[pos];
        const uint8_t *img = nullptr;
        size_t         img_len = 0;
        if (sub_type == 1 && sub_len >= 2) {
            /* Image Attribute. Per RFC 4880 §5.12.1 / RFC 9580 §5.13.1,
             * the image header length byte counts ITSELF, so the remaining
             * header bytes to skip are (hdr_len - 1). */
            uint8_t hdr_len = uid[pos + 1];
            if (hdr_len < 1 || (size_t) hdr_len + 1 > sub_len) {
                return false;
            }
            img = uid.data() + pos + 1 + hdr_len;
            img_len = sub_len - 1 - hdr_len;
        }
        if (img && img_len >= 3) {
            if (img[0] == 0xFF && img[1] == 0xD8 && img[2] == 0xFF) {
                format = PhotoFormat::JPEG;
            } else if (img[0] == 0x89 && img[1] == 0x50 && img[2] == 0x4E && img_len >= 4 &&
                       img[3] == 0x47) {
                format = PhotoFormat::PNG;
            } else {
                /* Unknown image format; still return the bytes and let the
                 * caller decide. */
                format = PhotoFormat::Unknown;
            }
            image.assign(img, img + img_len);
            return true;
        }
        pos = sub_end;
    }
    return false;
}

} // namespace rnp
