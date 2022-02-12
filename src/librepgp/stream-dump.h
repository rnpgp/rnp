/*
 * Copyright (c) 2018, [Ribose Inc](https://www.ribose.com).
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

#ifndef STREAM_DUMP_H_
#define STREAM_DUMP_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include "json_object.h"
#include "json.h"
#include "rnp.h"
#include "stream-common.h"

typedef struct rnp_dump_ctx_t {
    bool   dump_mpi;
    bool   dump_packets;
    bool   dump_grips;
    size_t layers;
    size_t stream_pkts;
    size_t failures;
} rnp_dump_ctx_t;

rnp_result_t stream_dump_packets(rnp_dump_ctx_t *ctx, pgp_source_t *src, pgp_dest_t *dst);

rnp_result_t stream_dump_packets_json(rnp_dump_ctx_t *ctx,
                                      pgp_source_t *  src,
                                      json_object **  jso);

#endif
