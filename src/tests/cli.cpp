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

#ifndef _WIN32
#include <sys/wait.h>
#endif

#include "rnp_tests.h"
#include "support.h"
#include "utils.h"

int rnp_main(int argc, char **argv);
int rnpkeys_main(int argc, char **argv);

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

    if (!strcmp(argv[0], "rnp")) {
        res = rnp_main(argc, argv);
    } else if (!strcmp(argv[0], "rnpkeys")) {
        res = rnpkeys_main(argc, argv);
    } else {
        res = -1;
    }
    free(argv);

    return res;
}

#define KEYS "data/keyrings"
#define MKEYS "data/test_stream_key_merge/"
#define FILES "data/test_cli"
#define G10KEYS "data/test_stream_key_load/g10"

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

static bool
test_cli_g10_key_sign(const char *userid)
{
    int ret;

    /* check signature */
    ret = call_rnp("rnp",
                   "--homedir",
                   G10KEYS,
                   "--password",
                   "password",
                   "-u",
                   userid,
                   "-s",
                   FILES "/hello.txt",
                   NULL);
    if (ret) {
        return false;
    }

    /* verify back */
    ret = call_rnp("rnp", "--homedir", G10KEYS, "-v", FILES "/hello.txt.pgp", NULL);
    if (ret) {
        return false;
    }
    unlink(FILES "/hello.txt.pgp");
    return true;
}

static bool
test_cli_g10_key_encrypt(const char *userid)
{
    int ret;

    /* encrypt */
    ret = call_rnp("rnp", "--homedir", G10KEYS, "-r", userid, "-e", FILES "/hello.txt", NULL);
    if (ret) {
        return false;
    }

    /* decrypt it back */
    ret = call_rnp("rnp",
                   "--homedir",
                   G10KEYS,
                   "--password",
                   "password",
                   "-d",
                   FILES "/hello.txt.pgp",
                   NULL);
    if (ret) {
        return false;
    }
    unlink(FILES "/hello.txt.pgp");
    return true;
}

void
test_cli_g10_operations(void **state)
{
    int ret;

    /* sign with default g10 key */
    ret = call_rnp(
      "rnp", "--homedir", G10KEYS, "--password", "password", "-s", FILES "/hello.txt", NULL);
    assert_int_equal(ret, 0);

    /* verify back */
    ret = call_rnp("rnp", "--homedir", G10KEYS, "-v", FILES "/hello.txt.pgp", NULL);
    assert_int_equal(ret, 0);
    assert_int_equal(unlink(FILES "/hello.txt.pgp"), 0);

    /* encrypt with default g10 key */
    ret = call_rnp("rnp", "--homedir", G10KEYS, "-e", FILES "/hello.txt", NULL);
    assert_int_equal(ret, 0);

    /* decrypt it back */
    ret = call_rnp("rnp",
                   "--homedir",
                   G10KEYS,
                   "--password",
                   "password",
                   "-d",
                   FILES "/hello.txt.pgp",
                   NULL);
    assert_int_equal(ret, 0);
    assert_int_equal(unlink(FILES "/hello.txt.pgp"), 0);

    /* check dsa/eg key */
    assert_true(test_cli_g10_key_sign("c8a10a7d78273e10"));    // signing key
    assert_true(test_cli_g10_key_encrypt("c8a10a7d78273e10")); // will find subkey
    assert_false(test_cli_g10_key_sign("02a5715c3537717e"));   // fail - encrypting subkey
    assert_true(test_cli_g10_key_encrypt("02a5715c3537717e")); // success

    /* check rsa/rsa key, both key and subkey are SCE */
    assert_true(test_cli_g10_key_sign("2fb9179118898e8b"));
    assert_true(test_cli_g10_key_encrypt("2fb9179118898e8b"));
    assert_true(test_cli_g10_key_sign("6e2f73008f8b8d6e"));
    assert_true(test_cli_g10_key_encrypt("6e2f73008f8b8d6e"));

    /* check ed25519 key */
    assert_true(test_cli_g10_key_sign("cc786278981b0728"));
    assert_false(test_cli_g10_key_encrypt("cc786278981b0728"));

    /* check ed25519/x25519 key */
    assert_true(test_cli_g10_key_sign("941822a0fc1b30a5"));
    assert_true(test_cli_g10_key_encrypt("941822a0fc1b30a5"));
    assert_false(test_cli_g10_key_sign("c711187e594376af"));
    assert_true(test_cli_g10_key_encrypt("c711187e594376af"));

    /* check p256 key */
    assert_true(test_cli_g10_key_sign("23674f21b2441527"));
    assert_true(test_cli_g10_key_encrypt("23674f21b2441527"));
    assert_false(test_cli_g10_key_sign("37e285e9e9851491"));
    assert_true(test_cli_g10_key_encrypt("37e285e9e9851491"));

    /* check p384 key */
    assert_true(test_cli_g10_key_sign("242a3aa5ea85f44a"));
    assert_true(test_cli_g10_key_encrypt("242a3aa5ea85f44a"));
    assert_false(test_cli_g10_key_sign("e210e3d554a4fad9"));
    assert_true(test_cli_g10_key_encrypt("e210e3d554a4fad9"));

    /* check p521 key */
    assert_true(test_cli_g10_key_sign("2092ca8324263b6a"));
    assert_true(test_cli_g10_key_encrypt("2092ca8324263b6a"));
    assert_false(test_cli_g10_key_sign("9853df2f6d297442"));
    assert_true(test_cli_g10_key_encrypt("9853df2f6d297442"));

    /* check bp256 key */
    assert_true(test_cli_g10_key_sign("d0c8a3daf9e0634a"));
    assert_true(test_cli_g10_key_encrypt("d0c8a3daf9e0634a"));
    assert_false(test_cli_g10_key_sign("2edabb94d3055f76"));
    assert_true(test_cli_g10_key_encrypt("2edabb94d3055f76"));

    /* check bp384 key */
    assert_true(test_cli_g10_key_sign("6cf2dce85599ada2"));
    assert_true(test_cli_g10_key_encrypt("6cf2dce85599ada2"));
    assert_false(test_cli_g10_key_sign("cff1bb6f16d28191"));
    assert_true(test_cli_g10_key_encrypt("cff1bb6f16d28191"));

    /* check bp512 key */
    assert_true(test_cli_g10_key_sign("aa5c58d14f7b8f48"));
    assert_true(test_cli_g10_key_encrypt("aa5c58d14f7b8f48"));
    assert_false(test_cli_g10_key_sign("20cdaa1482ba79ce"));
    assert_true(test_cli_g10_key_encrypt("20cdaa1482ba79ce"));

    /* check secp256k1 key */
    assert_true(test_cli_g10_key_sign("3ea5bb6f9692c1a0"));
    assert_true(test_cli_g10_key_encrypt("3ea5bb6f9692c1a0"));
    assert_false(test_cli_g10_key_sign("7635401f90d3e533"));
    assert_true(test_cli_g10_key_encrypt("7635401f90d3e533"));
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

void
test_cli_examples(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    char *examples_path = rnp_compose_path(rstate->original_dir, "../examples", NULL);
    char *example_path = NULL;
    /* key generation example */
    example_path = rnp_compose_path(examples_path, "generate", NULL);
    assert_non_null(example_path);
    assert_int_equal(system(example_path), 0);
    free(example_path);

    /* encryption sample */
    example_path = rnp_compose_path(examples_path, "encrypt", NULL);
    assert_non_null(example_path);
    assert_int_equal(system(example_path), 0);
    free(example_path);

    /* decryption sample */
    example_path = rnp_compose_path(examples_path, "decrypt", NULL);
    assert_non_null(example_path);
    assert_int_equal(system(example_path), 0);
    free(example_path);

    /* signing sample */
    example_path = rnp_compose_path(examples_path, "sign", NULL);
    assert_non_null(example_path);
    assert_int_equal(system(example_path), 0);
    free(example_path);

    /* verification sample */
    example_path = rnp_compose_path(examples_path, "verify", NULL);
    assert_non_null(example_path);
    assert_int_equal(system(example_path), 0);
    free(example_path);

    free(examples_path);
}

void
test_cli_rnpkeys(void **state)
{
    int ret;
    assert_int_equal(0, call_rnp("rnpkeys", "--version", NULL));

    /* test keys listing */
    ret = call_rnp("rnpkeys", "--homedir", KEYS "/1", "--list-keys", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", KEYS "/1", "--list-keys", "--with-sigs", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", KEYS "/2", "--list-keys", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", KEYS "/2", "--list-keys", "--with-sigs", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", KEYS "/3", "--list-keys", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", KEYS "/3", "--list-keys", "--with-sigs", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", KEYS "/5", "--list-keys", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", KEYS "/5", "--list-keys", "--with-sigs", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", G10KEYS, "--list-keys", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", G10KEYS, "--list-keys", "--with-sigs", NULL);
    assert_int_equal(ret, 0);

    /* test single key listing command */
    ret = call_rnp("rnpkeys", "--homedir", KEYS "/1", "--list-keys", "2fcadf05ffa501bb", NULL);
    assert_int_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", KEYS "/1", "--list-keys", "00000000", NULL);
    assert_int_not_equal(ret, 0);

    ret = call_rnp("rnpkeys", "--homedir", KEYS "/1", "--list-keys", "zzzzzzzz", NULL);
    assert_int_not_equal(ret, 0);
}

void
test_cli_redumper(void **state)
{
    rnp_test_state_t *rstate = (rnp_test_state_t *) *state;
    char *            redumper_path =
      rnp_compose_path(rstate->original_dir, "../apps/packet-dumper/redumper", NULL);
    char cmd[512] = {0};
    int  chnum;
    int  status;
    /* call redumper's help */
    chnum = snprintf(cmd, sizeof(cmd), "%s -h", redumper_path);
    assert_true(chnum < (int) sizeof(cmd));
    status = system(cmd);
    // there are no equivalents for WIFEXITED and WEXITSTATUS on Windows
#ifndef _WIN32
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 1);
#endif
    /* run redumper on some data */
    chnum = snprintf(cmd, sizeof(cmd), "%s \"%s\"", redumper_path, KEYS "/1/pubring.gpg");
    assert_true(chnum < (int) sizeof(cmd));
    status = system(cmd);
#ifndef _WIN32
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
#endif
    /* run redumper on some data with json output */
    chnum = snprintf(cmd, sizeof(cmd), "%s -j \"%s\"", redumper_path, KEYS "/1/pubring.gpg");
    assert_true(chnum < (int) sizeof(cmd));
    status = system(cmd);
#ifndef _WIN32
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
#endif
    free(redumper_path);
}
