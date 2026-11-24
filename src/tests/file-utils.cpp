/*
 * Copyright (c) 2020 [Ribose Inc](https://www.ribose.com).
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
#include "file-utils.h"

#ifndef _WIN32
#include <signal.h>
#include <sys/resource.h>
#endif

TEST_F(rnp_tests, test_rnp_mkstemp)
{
#ifdef _WIN32
    const char  tmpl[17] = "test-file.XXXXXX";
    char        buf[17];
    const int   size = 20;
    int         fds[size];
    std::string filenames[size];
    for (int i = 0; i < size; i++) {
        memcpy(buf, tmpl, sizeof(buf));
        int fd = rnp_mkstemp(buf);
        assert_int_not_equal(-1, fd);
        fds[i] = fd;
        filenames[i] = buf;
    }
    assert_false(filenames[0] == filenames[1]);
    for (int i = 0; i < size; i++) {
        if (fds[i] != -1) {
            assert_int_equal(0, close(fds[i]));
            assert_int_equal(0, unlink(filenames[i].c_str()));
        }
    }
#endif
}

TEST_F(rnp_tests, test_rnp_access)
{
#ifdef _WIN32
    /* Assume we are running as non-Administrator user */
    assert_int_equal(0, rnp_access("C:\\Windows", F_OK));
    assert_int_equal(0, rnp_access("C:\\Windows", R_OK));
    assert_int_equal(0, rnp_access("C:\\Windows", W_OK));
    assert_int_equal(0, rnp_access("C:\\Windows\\System32\\User32.dll", F_OK));
    assert_int_equal(0, rnp_access("C:\\Windows\\System32\\User32.dll", R_OK));
    /* Should fail, but unfortunately _waccess() works this way */
    assert_int_equal(0, rnp_access("C:\\Windows\\System32\\User32.dll", W_OK));
#else
    /* Assume we are running as non-root and root directory is non-writable for us */
    assert_int_equal(0, rnp_access("/", F_OK));
    assert_int_equal(0, rnp_access("/", R_OK));
    assert_int_equal(-1, rnp_access("/", W_OK));
    assert_int_equal(0, rnp_access("/tmp", R_OK | W_OK));
#endif
}

#ifndef _WIN32
TEST_F(rnp_tests, test_output_short_write)
{
    /* A short write, e.g. on a full filesystem or when a file size limit is
     * hit, must be reported as an error instead of silently dropping the
     * remaining data and reporting success while the output is truncated
     * (#2590). Writes are buffered in the output cache, so the failure
     * surfaces when the cache is flushed on rnp_output_finish(). */
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_path(&output, "shortwrite-test"));

    std::vector<uint8_t> data(2048, 'A');
    size_t               written = 0;

    /* Limit the file size to 512 bytes: the flush of the 2048 buffered
     * bytes must fail. Lower only the soft limit - the hard limit cannot
     * be raised back by a non-root process. */
    struct rlimit    oldlim = {};
    struct sigaction sa = {}, oldsa = {};
    assert_int_equal(0, getrlimit(RLIMIT_FSIZE, &oldlim));
    struct rlimit lim = {512, oldlim.rlim_max};
    sa.sa_handler = SIG_IGN;
    assert_int_equal(0, sigaction(SIGXFSZ, &sa, &oldsa));
    assert_int_equal(0, setrlimit(RLIMIT_FSIZE, &lim));

    assert_rnp_success(rnp_output_write(output, data.data(), data.size(), NULL));
    assert_rnp_failure(rnp_output_finish(output));

    struct stat st = {};
    assert_int_equal(0, stat("shortwrite-test", &st));
    assert_true(st.st_size < (off_t) data.size());

    assert_int_equal(0, setrlimit(RLIMIT_FSIZE, &oldlim));
    sigaction(SIGXFSZ, &oldsa, NULL);

    rnp_output_destroy(output);
    unlink("shortwrite-test");

    /* Without the limit the same write fully succeeds */
    assert_rnp_success(rnp_output_to_path(&output, "shortwrite-test"));
    assert_rnp_success(rnp_output_write(output, data.data(), data.size(), &written));
    assert_int_equal(written, data.size());
    assert_rnp_success(rnp_output_finish(output));
    rnp_output_destroy(output);
    assert_int_equal(0, stat("shortwrite-test", &st));
    assert_int_equal(st.st_size, (off_t) data.size());
    unlink("shortwrite-test");
}
#endif
