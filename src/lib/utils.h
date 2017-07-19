/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __RNP__UTILS_H__
#define __RNP__UTILS_H__

#define RNP_MSG(msg) (void) fprintf(stdout, msg);
#define RNP_LOG_FD(fd, ...)                                                  \
    do {                                                                     \
        (void) fprintf((fd), "[%s() %s:%d] ", __func__, __FILE__, __LINE__); \
        (void) fprintf((fd), __VA_ARGS__);                                   \
        (void) fprintf((fd), "\n");                                          \
    } while (0)

#define RNP_LOG(...) RNP_LOG_FD(stderr, __VA_ARGS__)

#define CHECK(exp, val, err)                          \
    do {                                              \
        if ((exp) != (val)) {                         \
            RNP_LOG("ERROR: (" #exp ")!=(" #val ")"); \
            ret = (err);                              \
            goto end;                                 \
        }                                             \
    } while (false)

#define BITS_TO_BYTES(b) (((b) + (CHAR_BIT - 1)) / CHAR_BIT)

#endif