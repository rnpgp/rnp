/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <rnp_tests.h>
#include <rnp_tests_support.h>

static int setup_test(void **state) {
  *state = make_temp_dir();
  assert_int_equal(0, setenv("HOME", (char *)*state, 1));
  assert_int_equal(0, chdir((char *)*state));
  return 0;
}

static int teardown_test(void **state) {
  delete_recursively((char *)*state);
  free(*state);
  *state = NULL;
  return 0;
}

int main(void) {
  int ret;
  /* Create a temporary HOME.
   * This is just an extra guard to protect against accidental
   * modifications of a user's HOME.
   */
  char *tmphome = make_temp_dir();
  assert_int_equal(0, setenv("HOME", tmphome, 1));
  assert_int_equal(0, chdir(tmphome));

  struct CMUnitTest tests[] = {
    cmocka_unit_test(hash_test_success),
    cmocka_unit_test(cipher_test_success),
    cmocka_unit_test(pkcs1_rsa_test_success),
    cmocka_unit_test(raw_elg_test_success),
    cmocka_unit_test(rnpkeys_generatekey_testSignature),
    cmocka_unit_test(rnpkeys_generatekey_testEncryption),
    cmocka_unit_test(rnpkeys_generatekey_verifySupportedHashAlg),
    cmocka_unit_test(rnpkeys_generatekey_verifyUserIdOption),
    cmocka_unit_test(rnpkeys_generatekey_verifykeyHomeDirOption),
    cmocka_unit_test(rnpkeys_generatekey_verifykeyNonexistingHomeDir),
    cmocka_unit_test(rnpkeys_generatekey_verifykeyHomeDirNoPermission),
    cmocka_unit_test(rnpkeys_exportkey_verifyUserId),
  };

  /* Each test entry will invoke setup_test before running
   * and teardown_test after running. */
  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    tests[i].setup_func = setup_test;
    tests[i].teardown_func = teardown_test;
  }
  ret = cmocka_run_group_tests(tests, NULL, NULL);

  delete_recursively(tmphome);
  free(tmphome);
  return ret;
}
