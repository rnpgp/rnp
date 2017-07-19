/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
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

void
cli_rnp(void **state)
{
    rnp_test_state_t *rstate = *state;
    int               res;
    char *            cwd;
    char              cmd[PATH_MAX];

    rnp_assert_non_null(rstate, cwd = getenv("ORIGCWD"));
    rnp_assert_true(rstate, snprintf(cmd, sizeof(cmd), "%s/cli_tests.py rnp", cwd) > 0);

    res = system(cmd);
    res = WEXITSTATUS(res);
    rnp_assert_int_equal(rstate, res, 0);
}

void
cli_rnpkeys(void **state)
{
    rnp_test_state_t *rstate = *state;
    int               res;
    char *            cwd;
    char              cmd[PATH_MAX];

    rnp_assert_non_null(rstate, cwd = getenv("ORIGCWD"));
    rnp_assert_true(rstate, snprintf(cmd, sizeof(cmd), "%s/cli_tests.py rnp", cwd) > 0);

    res = system(cmd);
    res = WEXITSTATUS(res);
    rnp_assert_int_equal(rstate, res, 0);
}

void
cli_performance(void **state)
{
    rnp_test_state_t *rstate = *state;
    int               res;
    char *            cwd;
    char              cmd[PATH_MAX];

    rnp_assert_non_null(rstate, cwd = getenv("ORIGCWD"));
    rnp_assert_true(rstate, snprintf(cmd, sizeof(cmd), "%s/cli_perf.py", cwd) > 0);

    res = system(cmd);
    res = WEXITSTATUS(res);
    rnp_assert_int_equal(rstate, res, 0);
}