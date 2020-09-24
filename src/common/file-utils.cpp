/*
 * Copyright (c) 2017-2020 [Ribose Inc](https://www.ribose.com).
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
/** File utilities
 *  @file
 */

#include "file-utils.h"
#include "config.h"
#ifdef _MSC_VER
#include <stdlib.h>
#include <stdio.h>
#include "uniwin.h"
#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#else
#include <sys/stat.h>
#endif // _MSC_VER

bool
rnp_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* return the file modification time */
int64_t
rnp_filemtime(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return 0;
    } else {
        return st.st_mtime;
    }
}

#ifdef _MSC_VER
/* mkstemp extracted from libc/sysdeps/posix/tempname.c.  Copyright
   (C) 1991-1999, 2000, 2001, 2006 Free Software Foundation, Inc.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.  */

static const char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* Generate a temporary file name based on TMPL.  TMPL must match the
   rules for mk[s]temp (i.e. end in "XXXXXX").  The name constructed
   does not exist at the time of the call to mkstemp.  TMPL is
   overwritten with the result.  */
int
rnp_mkstemp(char *tmpl)
{
    size_t                    len;
    char *                    XXXXXX;
    static unsigned long long value;
    unsigned long long        random_time_bits;
    unsigned int              count;
    int                       fd = -1;
    int                       save_errno = errno;

    /* A lower bound on the number of temporary files to attempt to
       generate.  The maximum total number of temporary file names that
       can exist for a given template is 62**6.  It should never be
       necessary to try all these combinations.  Instead if a reasonable
       number of names is tried (we define reasonable as 62**3) fail to
       give the system administrator the chance to remove the problems.  */
#define ATTEMPTS_MIN (62 * 62 * 62)

    /* The number of times to attempt to generate a temporary file.  To
       conform to POSIX, this must be no smaller than TMP_MAX.  */
#if ATTEMPTS_MIN < TMP_MAX
    unsigned int attempts = TMP_MAX;
#else
    unsigned int attempts = ATTEMPTS_MIN;
#endif

    len = strlen(tmpl);
    if (len < 6 || strcmp(&tmpl[len - 6], "XXXXXX")) {
        errno = EINVAL;
        return -1;
    }

    /* This is where the Xs start.  */
    XXXXXX = &tmpl[len - 6];

    /* Get some more or less random data.  */
    {
        SYSTEMTIME stNow;
        FILETIME   ftNow;

        // get system time
        GetSystemTime(&stNow);
        stNow.wMilliseconds = 500;
        if (!SystemTimeToFileTime(&stNow, &ftNow)) {
            errno = -1;
            return -1;
        }

        random_time_bits = (((unsigned long long) ftNow.dwHighDateTime << 32) |
                            (unsigned long long) ftNow.dwLowDateTime);
    }
    value += random_time_bits ^ (unsigned long long) GetCurrentThreadId();

    for (count = 0; count < attempts; value += 7777, ++count) {
        unsigned long long v = value;

        /* Fill in the random bits.  */
        XXXXXX[0] = letters[v % 62];
        v /= 62;
        XXXXXX[1] = letters[v % 62];
        v /= 62;
        XXXXXX[2] = letters[v % 62];
        v /= 62;
        XXXXXX[3] = letters[v % 62];
        v /= 62;
        XXXXXX[4] = letters[v % 62];
        v /= 62;
        XXXXXX[5] = letters[v % 62];

        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef HAVE_O_BINARY
        flags |= O_BINARY;
#else
#ifdef HAVE__O_BINARY
        flags |= _O_BINARY;
#endif
#endif
        fd = open(tmpl, flags, _S_IREAD | _S_IWRITE);
        if (fd >= 0) {
            errno = save_errno;
            return fd;
        } else if (errno != EEXIST)
            return -1;
    }

    /* We got out of the loop because we ran out of combinations to try.  */
    errno = EEXIST;
    return -1;
}
#endif // _MSC_VER
