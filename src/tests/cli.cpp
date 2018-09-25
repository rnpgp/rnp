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

static int
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
#define MKEYS "data/test_stream_key_merge/"
#define FILES "data/test_cli"

void
test_cli_rnp_keyfile(void **state)
{
    int ret;

    /* sign with keyfile, using default key */
    ret = call_rnp("rnp",
                   "--keyfile",
                   MKEYS "key-sec.asc",
                   "--password",
                   "password",
                   "-s",
                   FILES "/hello.txt",
                   NULL);
    assert_int_equal(ret, 0);
    assert_true(file_exists(FILES "/hello.txt.pgp"));
    /* verify signed file */
    ret =
      call_rnp("rnp", "--keyfile", MKEYS "key-pub.asc", "-v", FILES "/hello.txt.pgp", NULL);
    assert_int_equal(ret, 0);
    assert_int_equal(unlink(FILES "/hello.txt.pgp"), 0);

    /* sign with keyfile, using user id */
    ret = call_rnp("rnp",
                   "-f",
                   MKEYS "key-sec.asc",
                   "-u",
                   "key-merge-uid-2",
                   "--password",
                   "password",
                   "--armor",
                   "-s",
                   FILES "/hello.txt",
                   NULL);
    assert_int_equal(ret, 0);
    assert_true(file_exists(FILES "/hello.txt.asc"));
    /* verify signed file */
    ret = call_rnp("rnp", "-f", MKEYS "key-pub.asc", "-v", FILES "/hello.txt.asc", NULL);
    assert_int_equal(ret, 0);
    /* verify with key without self-signature - should fail */
    ret =
      call_rnp("rnp", "-f", MKEYS "key-pub-just-key.pgp", "-v", FILES "/hello.txt.asc", NULL);
    assert_int_not_equal(ret, 0);
    assert_int_equal(unlink(FILES "/hello.txt.asc"), 0);

    /* encrypt with keyfile, using default key */
    ret = call_rnp("rnp", "--keyfile", MKEYS "key-pub.asc", "-e", FILES "/hello.txt", NULL);
    assert_int_equal(ret, 0);
    assert_true(file_exists(FILES "/hello.txt.pgp"));
    /* decrypt it with raw seckey, without userids and sigs */
    ret = call_rnp("rnp",
                   "--keyfile",
                   MKEYS "key-sec-no-uid-no-sigs.pgp",
                   "--password",
                   "password",
                   "-d",
                   FILES "/hello.txt.pgp",
                   NULL);
    assert_int_equal(ret, 0);
    assert_int_equal(unlink(FILES "/hello.txt.pgp"), 0);

    /* try to encrypt with keyfile, using the signing subkey */
    ret = call_rnp("rnp",
                   "--keyfile",
                   MKEYS "key-pub.asc",
                   "-r",
                   "16CD16F267CCDD4F",
                   "--armor",
                   "-e",
                   FILES "/hello.txt",
                   NULL);
    assert_int_not_equal(ret, 0);
    assert_false(file_exists(FILES "/hello.txt.asc"));
    /* now encrypt with keyfile, using the encrypting subkey */
    ret = call_rnp("rnp",
                   "--keyfile",
                   MKEYS "key-pub.asc",
                   "-r",
                   "AF1114A47F5F5B28",
                   "--armor",
                   "-e",
                   FILES "/hello.txt",
                   NULL);
    assert_int_equal(ret, 0);
    assert_true(file_exists(FILES "/hello.txt.asc"));
    /* fail to decrypt it with pubkey */
    ret = call_rnp("rnp",
                   "--keyfile",
                   MKEYS "key-pub-subkey-1.pgp",
                   "--password",
                   "password",
                   "-d",
                   FILES "/hello.txt.asc",
                   NULL);
    assert_int_not_equal(ret, 0);
    /* decrypt correctly with seckey + subkeys */
    ret = call_rnp("rnp",
                   "--keyfile",
                   MKEYS "key-sec.pgp",
                   "--password",
                   "password",
                   "-d",
                   FILES "/hello.txt.asc",
                   NULL);
    assert_int_equal(ret, 0);
    assert_int_equal(unlink(FILES "/hello.txt.asc"), 0);
}

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

    /* sign and verify back with g10 key */
    ret = call_rnp("rnp",
                   "--homedir",
                   KEYS "/3",
                   "-u",
                   "4BE147BB22DF1E60",
                   "--password",
                   "password",
                   "--sign",
                   FILES "/hello.txt",
                   "--overwrite",
                   NULL);
    assert_int_equal(ret, 0);
    ret = call_rnp("rnp", "--homedir", KEYS "/3", "--verify", FILES "/hello.txt.pgp", NULL);
    assert_int_equal(ret, 0);

    /* encrypt and decrypt back with g10 key */
    ret = call_rnp("rnp",
                   "--homedir",
                   KEYS "/3",
                   "-r",
                   "4BE147BB22DF1E60",
                   "--encrypt",
                   FILES "/hello.txt",
                   "--overwrite",
                   NULL);
    assert_int_equal(ret, 0);
    ret = call_rnp("rnp",
                   "--homedir",
                   KEYS "/3",
                   "--password",
                   "password",
                   "--decrypt",
                   FILES "/hello.txt.pgp",
                   NULL);
    assert_int_equal(ret, 0);
}
