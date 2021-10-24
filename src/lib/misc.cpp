/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
 * Copyright (c) 2009-2010 The NetBSD Foundation, Inc.
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
 */
#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#if defined(__NetBSD__)
__COPYRIGHT("@(#) Copyright (c) 2009 The NetBSD Foundation, Inc. All rights reserved.");
__RCSID("$NetBSD: misc.c,v 1.41 2012/03/05 02:20:18 christos Exp $");
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <sys/param.h>
#include <unistd.h>
#else
#include "uniwin.h"
#endif

#include "crypto.h"
#include "crypto/mem.h"
#include "utils.h"
#include "str-utils.h"
#include "json_utils.h"

#ifdef _WIN32
#include <windows.h>
#include <locale>
#include <codecvt>
#define vsnprintf _vsnprintf
#endif

/* Shortcut function to add field checking it for null to avoid allocation failure.
   Please note that it deallocates val on failure. */
bool
obj_add_field_json(json_object *obj, const char *name, json_object *val)
{
    if (!val) {
        return false;
    }
    // TODO: in JSON-C 0.13 json_object_object_add returns bool instead of void
    json_object_object_add(obj, name, val);
    if (!json_object_object_get_ex(obj, name, NULL)) {
        json_object_put(val);
        return false;
    }

    return true;
}

bool
obj_add_hex_json(json_object *obj, const char *name, const uint8_t *val, size_t val_len)
{
    if (val_len > 1024 * 1024) {
        RNP_LOG("too large json hex field: %zu", val_len);
        val_len = 1024 * 1024;
    }

    char   smallbuf[64] = {0};
    size_t hexlen = val_len * 2 + 1;

    char *hexbuf = hexlen < sizeof(smallbuf) ? smallbuf : (char *) malloc(hexlen);
    if (!hexbuf) {
        return false;
    }

    bool res = rnp::hex_encode(val, val_len, hexbuf, hexlen, rnp::HEX_LOWERCASE) &&
               obj_add_field_json(obj, name, json_object_new_string(hexbuf));

    if (hexbuf != smallbuf) {
        free(hexbuf);
    }
    return res;
}

bool
array_add_element_json(json_object *obj, json_object *val)
{
    if (!val) {
        return false;
    }
    if (json_object_array_add(obj, val)) {
        json_object_put(val);
        return false;
    }
    return true;
}

const char *
id_str_pair::lookup(const id_str_pair pair[], int id, const char *notfound)
{
    while (pair && pair->str) {
        if (pair->id == id) {
            return pair->str;
        }
        pair++;
    }
    return notfound;
}

int
id_str_pair::lookup(const id_str_pair pair[], const char *str, int notfound)
{
    while (pair && pair->str) {
        if (rnp::str_case_eq(str, pair->str)) {
            return pair->id;
        }
        pair++;
    }
    return notfound;
}

int
id_str_pair::lookup(const id_str_pair pair[], const std::vector<uint8_t> &bytes, int notfound)
{
    while (pair && pair->str) {
        if ((strlen(pair->str) == bytes.size()) &&
            !memcmp(pair->str, bytes.data(), bytes.size())) {
            return pair->id;
        }
        pair++;
    }
    return notfound;
}
