/*
 * Copyright (c) 2018-2019 [Ribose Inc](https://www.ribose.com).
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

#include "rnp_tests.h"
#include "support.h"

static const char LOGTEST_FILENAME[] = "logtest.log";

TEST_F(rnp_tests, test_log_switch)
{
    FILE *stream = fopen(LOGTEST_FILENAME, "w");
    assert_non_null(stream);
    bool saved_rnp_log_switch = rnp_log_switch();

    // reset _rnp_log_switch manually
    set_rnp_log_switch(0);
    RNP_LOG_FD(stream, "x");
    fflush(stream);
    assert_int_equal(0, ftell(stream)); // nothing was written

    // enable _rnp_log_switch manually
    set_rnp_log_switch(1);
    RNP_LOG_FD(stream, "x");
    fflush(stream);
    assert_int_not_equal(0, ftell(stream)); // something was written

    fclose(stream);
    assert_int_equal(0, unlink(LOGTEST_FILENAME));

    stream = fopen(LOGTEST_FILENAME, "w");
    assert_non_null(stream);

    const char *saved_env = getenv(RNP_LOG_CONSOLE);

    // let _rnp_log_switch initialize to 0 from unset environment variable
    assert_int_equal(0, unsetenv(RNP_LOG_CONSOLE));
    set_rnp_log_switch(-1);
    RNP_LOG_FD(stream, "x");
    fflush(stream);
    assert_int_equal(0, ftell(stream)); // nothing was written

    // let _rnp_log_switch initialize to 0 from environment variable "0"
    setenv(RNP_LOG_CONSOLE, "0", 1);
    set_rnp_log_switch(-1);
    RNP_LOG_FD(stream, "x");
    fflush(stream);
    assert_int_equal(0, ftell(stream)); // nothing was written

    // let _rnp_log_switch initialize to 1 from environment variable "1"
    setenv(RNP_LOG_CONSOLE, "1", 1);
    set_rnp_log_switch(-1);
    RNP_LOG_FD(stream, "x");
    fflush(stream);
    assert_int_not_equal(0, ftell(stream)); // something was written

    // restore environment variable
    if (saved_env) {
        assert_int_equal(0, setenv(RNP_LOG_CONSOLE, saved_env, 1));
    } else {
        unsetenv(RNP_LOG_CONSOLE);
    }

    // restore _rnp_log_switch
    set_rnp_log_switch(saved_rnp_log_switch ? 1 : 0);

    fclose(stream);
    assert_int_equal(0, unlink(LOGTEST_FILENAME));
}
