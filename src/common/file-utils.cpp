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
#include <locale>
#include <codecvt>
#include <random>
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
static const char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/** @private
 *  generate a temporary file name based on TMPL.
 *
 *  @param tmpl filename template in UTF-8 ending in XXXXXX
 *  @return file descriptor of newly created and opened file, or -1 on error
 **/
int
rnp_mkstemp(char *tmpl)
{
    int       save_errno = errno;
    const int mask_length = 6;
    int       len = strlen(tmpl);
    if (len < mask_length || strcmp(&tmpl[len - mask_length], "XXXXXX")) {
        errno = EINVAL;
        return -1;
    }
    std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8conv;
    std::wstring tmpl_w = utf8conv.from_bytes(tmpl, tmpl + len - mask_length);

    /* This is where the Xs start.  */
    char *XXXXXX = &tmpl[len - mask_length];

    std::random_device rd;
    std::mt19937_64    rng(rd());

    for (unsigned int countdown = TMP_MAX; --countdown;) {
        unsigned long long v = rng();

        XXXXXX[0] = letters[v % 36];
        v /= 36;
        XXXXXX[1] = letters[v % 36];
        v /= 36;
        XXXXXX[2] = letters[v % 36];
        v /= 36;
        XXXXXX[3] = letters[v % 36];
        v /= 36;
        XXXXXX[4] = letters[v % 36];
        v /= 36;
        XXXXXX[5] = letters[v % 36];

        int flags = O_WRONLY | O_CREAT | O_EXCL | O_BINARY;
        int fd =
          _wopen((tmpl_w + utf8conv.from_bytes(XXXXXX)).c_str(), flags, _S_IREAD | _S_IWRITE);
        if (fd != -1) {
            errno = save_errno;
            return fd;
        } else if (errno != EEXIST)
            return -1;
    }

    // We got out of the loop because we ran out of combinations to try.
    errno = EEXIST;
    return -1;
}
#endif // _MSC_VER
