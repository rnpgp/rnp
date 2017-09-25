/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

#ifndef STREAM_ARMOUR_H_
#define STREAM_ARMOUR_H_

#include "stream-common.h"

typedef enum {
    PGP_ARMOURED_UNKNOWN,
    PGP_ARMOURED_MESSAGE,
    PGP_ARMOURED_PUBLIC_KEY,
    PGP_ARMOURED_SECRET_KEY,
    PGP_ARMOURED_SIGNATURE,
    PGP_ARMOURED_CLEARTEXT
} pgp_armoured_msg_t;

/* @brief Init dearmoring stream
 * @param src allocated pgp_source_t structure
 * @param readsrc source to read data from
 * @return RNP_SUCCESS on success or error code otherwise
 **/
rnp_result_t init_armoured_src(pgp_source_t *src, pgp_source_t *readsrc);

/* @brief Init armouring stream
 * @param dst allocated pgp_dest_t structure
 * @param writedst destination to write armoured data to
 * @param msgtype type of the message (see pgp_armoured_msg_t)
 * @return RNP_SUCCESS on success or error code otherwise
 **/
rnp_result_t init_armoured_dst(pgp_dest_t *       dst,
                               pgp_dest_t *       writedst,
                               pgp_armoured_msg_t msgtype);

/* @brief Dearmour the source, outputing binary data
 * @param src initialized source with armoured data
 * @param dst initialized dest to write binary data to
 * @return RNP_SUCCESS on success or error code otherwise
 **/
rnp_result_t rnp_dearmour_source(pgp_source_t *src, pgp_dest_t *dst);

/* @brief Armour the source, outputing base64-encoded data with headers
 * @param src initialized source with binary data
 * @param dst destination to write armoured data
 * @msgtype type of the message, to write correct armour headers
 * @return RNP_SUCCESS on success or error code otherwise
 **/
rnp_result_t rnp_armour_source(pgp_source_t *src, pgp_dest_t *dst, pgp_armoured_msg_t msgtype);

#endif
