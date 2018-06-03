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
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: validate.c,v 1.44 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <repgp/repgp.h>
#include <rnp/rnp_sdk.h>
#include <repgp/repgp.h>

#include <librepgp/packet-show.h>
#include <librepgp/reader.h>
#include <librepgp/stream-packet.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-key.h>
#include "utils.h"
#include "memory.h"
#include "crypto.h"
#include "validate.h"
#include "pgp-key.h"


static char *
fmtsecs(int64_t n, char *buf, size_t size)
{
    if (n > 365 * 24 * 60 * 60) {
        n /= (365 * 24 * 60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " year%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 30 * 24 * 60 * 60) {
        n /= (30 * 24 * 60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " month%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 24 * 60 * 60) {
        n /= (24 * 60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " day%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 60 * 60) {
        n /= (60 * 60);
        (void) snprintf(buf, size, "%" PRId64 " hour%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    if (n > 60) {
        n /= 60;
        (void) snprintf(buf, size, "%" PRId64 " minute%s", n, (n == 1) ? "" : "s");
        return buf;
    }
    (void) snprintf(buf, size, "%" PRId64 " second%s", n, (n == 1) ? "" : "s");
    return buf;
}

/**
   \ingroup HighLevel_Verify
   \brief Frees validation result and associated memory
   \param result Struct to be freed
   \note Must be called after validation functions
*/
void
pgp_validate_result_free(pgp_validation_t *result)
{
    if (result) {
        for (size_t i = 0; i < result->validc; i++) {
            free_signature(&result->valid_sigs[i]);
        }
        free(result->valid_sigs);
        for (size_t i = 0; i < result->invalidc; i++) {
            free_signature(&result->invalid_sigs[i]);
        }
        free(result->invalid_sigs);
        for (size_t i = 0; i < result->unknownc; i++) {
            free_signature(&result->unknown_sigs[i]);
        }
        free(result->unknown_sigs);
        free(result);
    }
}

bool
validate_result_status(const char *f, pgp_validation_t *val)
{
    time_t now;
    time_t t;
    char   buf[128];

    now = time(NULL);
    if (now < val->creation) {
        /* signature is not valid yet! */
        if (f) {
            (void) fprintf(stderr, "\"%s\": ", f);
        } else {
            (void) fprintf(stderr, "memory ");
        }
        (void) fprintf(stderr,
                       "signature not valid until %.24s (%s)\n",
                       ctime(&val->creation),
                       fmtsecs((int64_t)(val->creation - now), buf, sizeof(buf)));
        return false;
    }
    if (val->expiration != 0 && now > val->creation + val->expiration) {
        /* signature has expired */
        t = val->expiration + val->creation;
        if (f) {
            (void) fprintf(stderr, "\"%s\": ", f);
        } else {
            (void) fprintf(stderr, "memory ");
        }
        (void) fprintf(stderr,
                       "signature not valid after %.24s (%s ago)\n",
                       ctime(&t),
                       fmtsecs((int64_t)(now - t), buf, sizeof(buf)));
        return false;
    }
    return val->validc && !val->invalidc && !val->unknownc;
}
