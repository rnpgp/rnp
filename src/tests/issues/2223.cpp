/*
 * Copyright (c) 2026 [Ribose Inc].
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

#include "../rnp_tests.h"
#include "../support.h"
#include <string>
#include <vector>

/* Issue #2223: an OpenPGP certificate with a signature containing an unknown
 * critical subpacket (here: the 1st party approved 3rd party certifications
 * subpacket 37 from the 1pa3pc draft, over the user id) must be imported - the
 * signature with the unknown critical subpacket must not be relied upon, while
 * other signatures and the key itself are loaded as usual. */
static const char dkg_1pa3pc_cert[] =
  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
  "\n"
  "xjMEZXEJyxYJKwYBBAHaRw8BAQdA5BpbW0bpl5qCng/RiqwhQINrplDMSS5JsO/Y\n"
  "O+5Zi7HCiQQfFgoAMQWCZadnIAUJBdtHCwMLCQcDFQoIApsBAh4BFiEE1HcEDHDC\n"
  "FWpcKYVJu36RAUlea/cACgkQu36RAUlea/edDQD+M2QjnoEyu/TjI+gRXBpXQ5jC\n"
  "snnp9FdYhaSSUW/vZ8kBAJByWljA9aMfVaVrmvgcYw7jzJz+gmZspBRB++5LZ20N\n"
  "zRA8ZGtnQGRlYmlhbi5vcmc+wsARBBMWCgB5AwsJB0cUAAAAAAAeACBzYWx0QG5v\n"
  "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmeJfmd4tfVMI8Nwn0zRQg40bKLnzKDzjO7z\n"
  "PB6DhHZ/7wMVCggCmwECHgEWIQTUdwQMcMIValwphUm7fpEBSV5r9wUCZadfkAUJ\n"
  "BdnwRQAKCRC7fpEBSV5r9+owAP93bFzEmTyUj+lmhrot7LSQg3q939MHqd6TlUd/\n"
  "iPPgfAEA7nf3V5/WPTDhsc2L1cgPVcANe42j/KZFWKuTYsnt0wrCwQAEFhYKAXIF\n"
  "gmXD0MIJELt+kQFJXmv3RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n"
  "cGdwLm9yZxSzeD6OCTQUteGo38Ue9DSic5eOjZ8oeSlQQ2UNjGDqFiEE1HcEDHDC\n"
  "FWpcKYVJu36RAUlea/fAQaUW7nLWeB0XnOSQDsDyATT23t6kDcfNXwjXVYoSdrZD\n"
  "HwvDA4IgZ+2YOx8h6t4UWxgdbptKy0MDoKpDj4N536WCc3kzvfuSzdirrt5eD6H0\n"
  "hCoFh7MeVLvFeWodAXaTNJQMv3tUH8F4R8fbp92a1bm50FkJowd9c3boOuGbeGlz\n"
  "UsDFLyMSw0H04PMlRHraE6voIIwPvcsv0AMADV+O+AkBsWCMYGFONn8+x13GeReN\n"
  "2PUY7rpBJmljiO3Ol9e7PKLdvqQJhs68CgKgsW9tPSj/KCsCPcdLtXU7l4LpJw7i\n"
  "zfAXUtL61Ce+LDs2qVtpxAbMIBdmM5DHJcjcFk0B4rwSAAAgmwEAuWxVaeAc1GmV\n"
  "iBn26LX1pkbcVuMdsQW1Vjy4I6kBHl0BAJ5w+OaUAX9ubO8Wznwr7kEyizXTgnIu\n"
  "e5ka9/f4TAMB\n"
  "=56Jp\n"
  "-----END PGP PUBLIC KEY BLOCK-----\n";

TEST_F(rnp_tests, test_ffi_key_load_unknown_critical_subpacket)
{
    rnp_ffi_t ffi = NULL;
    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));

    /* 1. import must succeed, loading the key, its user id and signatures */
    rnp_input_t input = NULL;
    assert_rnp_success(rnp_input_from_memory(
      &input, (const uint8_t *) dkg_1pa3pc_cert, strlen(dkg_1pa3pc_cert), true));
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    char *results = NULL;
    assert_rnp_success(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results));
    rnp_buffer_destroy(results);
    rnp_input_destroy(input);
    rnp_output_destroy(output);

    size_t count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 1);

    rnp_key_handle_t key = NULL;
    assert_rnp_success(rnp_locate_key(ffi, "userid", "<dkg@debian.org>", &key));
    assert_non_null(key);

    size_t uid_count = 0;
    assert_rnp_success(rnp_key_get_uid_count(key, &uid_count));
    assert_int_equal(uid_count, 1);

    rnp_uid_handle_t uid = NULL;
    assert_rnp_success(rnp_key_get_uid_handle_at(key, 0, &uid));
    size_t sig_count = 0;
    assert_rnp_success(rnp_uid_get_signature_count(uid, &sig_count));
    /* self-certification plus the 1pa3pc certification with the unknown critical
     * subpacket 37 */
    assert_int_equal(sig_count, 2);

    /* 2. exactly one of the certifications is valid: the self-certification.
     *    Both are made by the dkg's key (the 1pa3pc certification is first-party),
     *    but the one with the unknown critical subpacket must not be relied upon. */
    size_t valid_sigs = 0;
    for (size_t idx = 0; idx < sig_count; idx++) {
        rnp_signature_handle_t sig = NULL;
        assert_rnp_success(rnp_uid_get_signature_at(uid, idx, &sig));
        if (rnp_signature_is_valid(sig, 0) == RNP_SUCCESS) {
            valid_sigs++;
        }
        rnp_signature_handle_destroy(sig);
    }
    assert_int_equal(valid_sigs, 1);
    rnp_uid_handle_destroy(uid);

    /* 3. key must round-trip through export/import, keeping the subpacket */
    assert_rnp_success(rnp_output_to_memory(&output, 0));
    assert_rnp_success(rnp_key_export(key, output, RNP_KEY_EXPORT_PUBLIC));
    uint8_t *exported = NULL;
    size_t   exported_len = 0;
    assert_rnp_success(
      rnp_output_memory_get_buf(output, &exported, &exported_len, false));
    std::vector<uint8_t> exported_vec(exported, exported + exported_len);
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);

    assert_rnp_success(rnp_ffi_create(&ffi, "GPG", "GPG"));
    assert_rnp_success(rnp_input_from_memory(
      &input, exported_vec.data(), exported_vec.size(), false));
    assert_rnp_success(rnp_import_keys(ffi, input, RNP_LOAD_SAVE_PUBLIC_KEYS, &results));
    rnp_buffer_destroy(results);
    rnp_input_destroy(input);
    count = 0;
    assert_rnp_success(rnp_get_public_key_count(ffi, &count));
    assert_int_equal(count, 1);
    rnp_ffi_destroy(ffi);
}
