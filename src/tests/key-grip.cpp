/*
 * Copyright (c) 2018, [Ribose Inc](https://www.ribose.com).
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
#include "../librepgp/stream-packet.h"
#include "../librepgp/stream-sig.h"
#include "pgp-key.h"

#include "rnp_tests.h"
#include "support.h"

void
test_key_grip(void **state)
{
    uint8_t          grip[PGP_FINGERPRINT_SIZE];
    const pgp_key_t *key;
    rnp_key_store_t *pub_store = NULL;
    rnp_key_store_t *sec_store = NULL;

    pub_store = rnp_key_store_new("KBX", "data/test_stream_key_load/g10/pubring.kbx");
    assert_non_null(pub_store);
    assert_true(rnp_key_store_load_from_file(pub_store, NULL));

    sec_store = rnp_key_store_new("G10", "data/test_stream_key_load/g10/private-keys-v1.d");
    assert_non_null(sec_store);
    pgp_key_provider_t key_provider = {.callback = rnp_key_provider_store,
                                       .userdata = pub_store};
    assert_true(rnp_key_store_load_from_file(sec_store, &key_provider));

    // dsa-eg public/secret key
    assert_true(
      rnp_hex_decode("552286BEB2999F0A9E26A50385B90D9724001187", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));
    assert_true(
      rnp_hex_decode("A5E4CD2CBBE44A16E4D6EC05C2E3C3A599DC763C", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));

    // rsa/rsa public/secret key
    assert_true(
      rnp_hex_decode("D148210FAF36468055B83D0F5A6DEB83FBC8E864", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));
    assert_true(
      rnp_hex_decode("CED7034A8EB5F4CE90DF99147EC33D86FCD3296C", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));

    // ed25519 : public/secret key
    assert_true(
      rnp_hex_decode("940D97D75C306D737A59A98EAFF1272832CEDC0B", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));

    // nistp256 : public/secret key/subkey
    assert_true(
      rnp_hex_decode("FC81AECE90BCE6E54D0D637D266109783AC8DAC0", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));
    assert_true(
      rnp_hex_decode("A56DC8DB8355747A809037459B4258B8A743EAB5", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));

    // nistp384 : public/secret key/subkey
    assert_true(
      rnp_hex_decode("A1338230AED1C9C125663518470B49056C9D1733", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));
    assert_true(
      rnp_hex_decode("797A83FE041FFE06A7F4B1D32C6F4AE0F6D87ADF", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));

    // nistp521 : public/secret key/subkey
    assert_true(
      rnp_hex_decode("D91B789603EC9138AA20342A2B6DC86C81B70F5D", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));
    assert_true(
      rnp_hex_decode("FD048B2CA1919CB241DC8A2C7FA3E742EF343DCA", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));

    // brainpool256 : public/secret key/subkey
    assert_true(
      rnp_hex_decode("A01BAA22A72F09A0FF0A1D4CBCE70844DD52DDD7", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));
    assert_true(
      rnp_hex_decode("C1678B7DE5F144C93B89468D5F9764ACE182ED36", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));

    // brainpool384 : public/secret key/subkey
    assert_true(
      rnp_hex_decode("2F25DB025DEBF3EA2715350209B985829B04F50A", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));
    assert_true(
      rnp_hex_decode("B6BD8B81F75AF914163D97DF8DE8F6FC64C283F8", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));

    // brainpool512 : public/secret key/subkey
    assert_true(
      rnp_hex_decode("5A484F56AB4B8B6583B6365034999F6543FAE1AE", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));
    assert_true(
      rnp_hex_decode("9133E4A7E8FC8515518DF444C3F2F247EEBBADEC", grip, sizeof(grip)));
    assert_non_null(key = rnp_key_store_get_key_by_grip(pub_store, grip));
    assert_non_null(key = rnp_key_store_get_key_by_grip(sec_store, grip));

    // cleanup
    rnp_key_store_free(pub_store);
    rnp_key_store_free(sec_store);
}
