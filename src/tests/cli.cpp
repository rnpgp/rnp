/*
 * Copyright (c) 2018 [Ribose Inc](https://www.ribose.com).
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
#include "utils.h"

int rnp_main(int argc, char **argv);

int
call_rnp(const char *cmd, ...)
{
    int     argc = 0;
    int     res;
    char ** argv = (char **) calloc(32, sizeof(char *));
    va_list args;
    va_start(args, cmd);
    while (cmd) {
        argv[argc++] = (char *) cmd;
        cmd = va_arg(args, char *);
    }
    va_end(args);
    /* reset state of getopt_long used in rnp */
    optind = 1;

    res = rnp_main(argc, argv);
    free(argv);

    return res;
}

#define KEYS "data/keyrings"
#define FILES "data/test_cli"

void
test_cli_rnp(void **state)
{
    int ret;
    assert_int_equal(0, call_rnp("rnp", "--version", NULL));

    /* sign with default key */
    ret = call_rnp("rnp",
                   "--homedir",
                   KEYS "/1",
                   "--password",
                   "password",
                   "--sign",
                   FILES "/hello.txt",
                   NULL);
    assert_int_equal(ret, 0);

    /* encrypt with default key */
    ret = call_rnp(
      "rnp", "--homedir", KEYS "/1", "--encrypt", FILES "/hello.txt", "--overwrite", NULL);
    assert_int_equal(ret, 0);
}
