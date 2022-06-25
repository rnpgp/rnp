/*-
 * Copyright (c) 2017-2021 Ribose Inc.
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

#ifndef RNP_LOGGING_H_
#define RNP_LOGGING_H_

#include <stdlib.h>
#include <stdint.h>

/* environment variable name */
static const char RNP_LOG_CONSOLE[] = "RNP_LOG_CONSOLE";

bool rnp_log_switch();
void set_rnp_log_switch(int8_t);
void rnp_log_stop();
void rnp_log_continue();

namespace rnp {
class LogStop {
    bool stop_;

  public:
    LogStop(bool stop = true) : stop_(stop)
    {
        if (stop_) {
            rnp_log_stop();
        }
    }
    ~LogStop()
    {
        if (stop_) {
            rnp_log_continue();
        }
    }
};
} // namespace rnp

#define RNP_LOG_FD(fd, ...)                                                  \
    do {                                                                     \
        if (!rnp_log_switch())                                               \
            break;                                                           \
        (void) fprintf((fd), "[%s() %s:%d] ", __func__, __FILE__, __LINE__); \
        (void) fprintf((fd), __VA_ARGS__);                                   \
        (void) fprintf((fd), "\n");                                          \
    } while (0)

#define RNP_LOG(...) RNP_LOG_FD(stderr, __VA_ARGS__)

#define RNP_LOG_KEY(msg, key)                                                            \
    do {                                                                                 \
        if (!(key)) {                                                                    \
            RNP_LOG(msg, "(null)");                                                      \
            break;                                                                       \
        }                                                                                \
        char                keyid[PGP_KEY_ID_SIZE * 2 + 1] = {0};                        \
        const pgp_key_id_t &id = key->keyid();                                           \
        rnp::hex_encode(id.data(), id.size(), keyid, sizeof(keyid), rnp::HEX_LOWERCASE); \
        RNP_LOG(msg, keyid);                                                             \
    } while (0)

#define RNP_LOG_KEY_PKT(msg, key)                                                      \
    do {                                                                               \
        pgp_key_id_t keyid = {};                                                       \
        if (pgp_keyid(keyid, (key))) {                                                 \
            RNP_LOG(msg, "unknown");                                                   \
            break;                                                                     \
        };                                                                             \
        char keyidhex[PGP_KEY_ID_SIZE * 2 + 1] = {0};                                  \
        rnp::hex_encode(                                                               \
          keyid.data(), keyid.size(), keyidhex, sizeof(keyidhex), rnp::HEX_LOWERCASE); \
        RNP_LOG(msg, keyidhex);                                                        \
    } while (0)

#endif