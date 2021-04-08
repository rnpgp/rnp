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
#include "json_utils.h"

#ifdef _WIN32
#include <windows.h>
#include <locale>
#include <codecvt>
#define vsnprintf _vsnprintf
#endif

/**
 * Searches the given map for the given type.
 * Returns a human-readable descriptive string if found,
 * returns NULL if not found
 *
 * It is the responsibility of the calling function to handle the
 * error case sensibly (i.e. don't just print out the return string.
 *
 */
static const char *
str_from_map_or_null(int type, pgp_map_t *map)
{
    pgp_map_t *row;

    for (row = map; row->string != NULL; row++) {
        if (row->type == type) {
            return row->string;
        }
    }
    return NULL;
}

/**
 * \ingroup Core_Print
 *
 * Searches the given map for the given type.
 * Returns a readable string if found, "Unknown" if not.
 */

const char *
pgp_str_from_map(int type, pgp_map_t *map)
{
    const char *str;

    str = str_from_map_or_null(type, map);
    return (str) ? str : "Unknown";
}

#define LINELEN 16

/* show hexadecimal/ascii dump */
void
hexdump(FILE *fp, const char *header, const uint8_t *src, size_t length)
{
    size_t i;
    char   line[LINELEN + 1];

    (void) fprintf(fp, "%s%s", (header) ? header : "", (header) ? "" : "");
    (void) fprintf(fp, " (%zu byte%s):\n", length, (length == 1) ? "" : "s");
    for (i = 0; i < length; i++) {
        if (i % LINELEN == 0) {
            (void) fprintf(fp, "%.5zu | ", i);
        }
        (void) fprintf(fp, "%.02x ", (uint8_t) src[i]);
        line[i % LINELEN] = (isprint(src[i])) ? src[i] : '.';
        if (i % LINELEN == LINELEN - 1) {
            line[LINELEN] = 0x0;
            (void) fprintf(fp, " | %s\n", line);
        }
    }
    if (i % LINELEN != 0) {
        for (; i % LINELEN != 0; i++) {
            (void) fprintf(fp, "   ");
            line[i % LINELEN] = ' ';
        }
        line[LINELEN] = 0x0;
        (void) fprintf(fp, " | %s\n", line);
    }
}

/* small useful functions for setting the file-level debugging levels */
/* if the debugv list contains the filename in question, we're debugging it */

enum { MAX_DEBUG_NAMES = 32 };

static int   debugc;
static char *debugv[MAX_DEBUG_NAMES];

/* set the debugging level per filename */
bool
rnp_set_debug(const char *f)
{
    const char *name;
    int         i;

    if (f == NULL) {
        f = "all";
    }
    if ((name = strrchr(f, '/')) == NULL) {
        name = f;
    } else {
        name += 1;
    }
    for (i = 0; ((i < MAX_DEBUG_NAMES) && (i < debugc)); i++) {
        if (strcmp(debugv[i], name) == 0) {
            return true;
        }
    }
    if (i == MAX_DEBUG_NAMES) {
        return false;
    }
    debugv[debugc++] = strdup(name);
    return debugv[debugc - 1] != NULL;
}

/* get the debugging level per filename */
bool
rnp_get_debug(const char *f)
{
    const char *name;
    int         i;

    if (!debugc) {
        return false;
    }

    if ((name = strrchr(f, '/')) == NULL) {
        name = f;
    } else {
        name += 1;
    }
    for (i = 0; i < debugc; i++) {
        if (strcmp(debugv[i], "all") == 0 || strcmp(debugv[i], name) == 0) {
            return true;
        }
    }
    return false;
}

void
rnp_clear_debug()
{
    for (int i = 0; i < debugc; i++) {
        free(debugv[i]);
        debugv[i] = NULL;
    }
    debugc = 0;
}

/* portable replacement for strcasecmp(3) */
int
rnp_strcasecmp(const char *s1, const char *s2)
{
    int n;

    for (; (n = tolower((uint8_t) *s1) - tolower((uint8_t) *s2)) == 0 && *s1; s1++, s2++) {
    }
    return n;
}

/* return the hexdump as a string */
char *
rnp_strhexdump_upper(char *dest, const uint8_t *src, size_t length, const char *sep)
{
    unsigned i;
    int      n;

    for (n = 0, i = 0; i < length; i += 2) {
        n += snprintf(&dest[n], 3, "%02X", *src++);
        n += snprintf(&dest[n], 10, "%02X%s", *src++, sep);
    }
    return dest;
}

char *
rnp_strlwr(char *s)
{
    char *p = s;
    while (*p) {
        *p = tolower((unsigned char) *p);
        p++;
    }
    return s;
}

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
