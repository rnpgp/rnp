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

#include "../librekey/key_store_pgp.h"
#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"

/* This test loads G10 keyrings and verifies certain properties
 * of the keys are correct.
 */
void
test_load_g10(void **state)
{
    pgp_io_t         io = {.errs = stderr, .res = stdout, .outs = stdout};
    uint8_t          keyid[PGP_KEY_ID_SIZE];
    const pgp_key_t *key;

    // load pubring
    rnp_key_store_t *pub_store = rnp_key_store_new("KBX", "data/keyrings/3/pubring.kbx");
    assert_non_null(pub_store);
    assert_true(rnp_key_store_load_from_file(&io, pub_store, NULL));
    // load secring
    rnp_key_store_t *sec_store = rnp_key_store_new("G10", "data/keyrings/3/private-keys-v1.d");
    assert_non_null(sec_store);
    pgp_key_provider_t key_provider = {.callback = rnp_key_provider_store,
                                       .userdata = pub_store};
    assert_true(rnp_key_store_load_from_file(&io, sec_store, &key_provider));

    // find (primary)
    key = NULL;
    assert_true(rnp_hex_decode("4BE147BB22DF1E60", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, sec_store, keyid, NULL);
    assert_non_null(key);
    // check properties
    assert_true(pgp_key_is_protected(key));

    // find (sub)
    key = NULL;
    assert_true(rnp_hex_decode("A49BAE05C16E8BC8", keyid, sizeof(keyid)));
    key = rnp_key_store_get_key_by_id(&io, sec_store, keyid, NULL);
    assert_non_null(key);
    // check properties
    assert_true(pgp_key_is_protected(key));

    // cleanup
    rnp_key_store_free(pub_store);
    rnp_key_store_free(sec_store);
}
