/*
 * Copyright (c) 2017-2022 [Ribose Inc](https://www.ribose.com).
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

#include <crypto/common.h>
#include "rnp.h"
#include <librepgp/stream-packet.h>
#include <librepgp/stream-key.h>

#include "rnp_tests.h"
#include "support.h"
#include "fingerprint.hpp"
#include "keygen.hpp"
#include "userid.hpp"

TEST_F(rnp_tests, hash_test_success)
{
    uint8_t hash_output[PGP_MAX_HASH_SIZE];

    const pgp_hash_alg_t hash_algs[] = {PGP_HASH_MD5,
                                        PGP_HASH_SHA1,
                                        PGP_HASH_SHA256,
                                        PGP_HASH_SHA384,
                                        PGP_HASH_SHA512,
                                        PGP_HASH_SHA224,
                                        PGP_HASH_SM3,
                                        PGP_HASH_SHA3_256,
                                        PGP_HASH_SHA3_512,
                                        PGP_HASH_UNKNOWN};

    const uint8_t test_input[3] = {'a', 'b', 'c'};
    const char *  hash_alg_expected_outputs[] = {
      "900150983CD24FB0D6963F7D28E17F72",
      "A9993E364706816ABA3E25717850C26C9CD0D89D",
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
      "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1"
      "E7CC2358BAECA"
      "134C825A7",
      "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A27"
      "4FC1A836BA3C2"
      "3A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
      "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7",
      "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0",
      "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532",
      ("B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E1"
       "0E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0")};

    for (int i = 0; hash_algs[i] != PGP_HASH_UNKNOWN; ++i) {
#if !defined(ENABLE_SM2)
        if (hash_algs[i] == PGP_HASH_SM3) {
            assert_throw({ auto hash = rnp::Hash::create(hash_algs[i]); });
            size_t hash_size = rnp::Hash::size(hash_algs[i]);
            assert_int_equal(hash_size * 2, strlen(hash_alg_expected_outputs[i]));
            continue;
        }
#endif
        auto   hash = rnp::Hash::create(hash_algs[i]);
        size_t hash_size = rnp::Hash::size(hash_algs[i]);
        assert_int_equal(hash_size * 2, strlen(hash_alg_expected_outputs[i]));

        hash->add(test_input, 1);
        hash->add(test_input + 1, sizeof(test_input) - 1);
        hash->finish(hash_output);

        assert_true(bin_eq_hex(hash_output, hash_size, hash_alg_expected_outputs[i]));
    }
}

TEST_F(rnp_tests, cipher_test_success)
{
    const uint8_t  key[16] = {0};
    uint8_t        iv[16];
    pgp_symm_alg_t alg = PGP_SA_AES_128;
    pgp_crypt_t    crypt;

    uint8_t cfb_data[20] = {0};
    memset(iv, 0x42, sizeof(iv));

    assert_int_equal(1, pgp_cipher_cfb_start(&crypt, alg, key, iv));

    assert_int_equal(0, pgp_cipher_cfb_encrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data)));

    assert_true(
      bin_eq_hex(cfb_data, sizeof(cfb_data), "BFDAA57CB812189713A950AD9947887983021617"));
    assert_int_equal(0, pgp_cipher_cfb_finish(&crypt));

    assert_int_equal(1, pgp_cipher_cfb_start(&crypt, alg, key, iv));
    assert_int_equal(0, pgp_cipher_cfb_decrypt(&crypt, cfb_data, cfb_data, sizeof(cfb_data)));
    assert_true(
      bin_eq_hex(cfb_data, sizeof(cfb_data), "0000000000000000000000000000000000000000"));
    assert_int_equal(0, pgp_cipher_cfb_finish(&crypt));
}

TEST_F(rnp_tests, pkcs1_rsa_test_success)
{
    rnp::secure_bytes ptext({'a', 'b', 'c'});
    rnp::secure_bytes dec;

    rnp::KeygenParams keygen(PGP_PKA_RSA, global_ctx);
    auto &            rsa = dynamic_cast<pgp::RSAKeyParams &>(keygen.key_params());
    rsa.set_bits(1024);

    pgp_key_pkt_t seckey;
    assert_true(keygen.generate(seckey, true));

    pgp::RSAEncMaterial enc;
    pgp::EGEncMaterial  enc2;
    assert_rnp_failure(seckey.material->encrypt(global_ctx, enc2, ptext));
    assert_rnp_success(seckey.material->encrypt(global_ctx, enc, ptext));
    assert_int_equal(enc.enc.m.size(), 1024 / 8);

    assert_rnp_failure(seckey.material->decrypt(global_ctx, dec, enc2));
    assert_true(dec.empty());
    assert_rnp_success(seckey.material->decrypt(global_ctx, dec, enc));
    assert_int_equal(dec.size(), 3);
    assert_true(bin_eq_hex(dec.data(), 3, "616263"));

    /* Try signing */
    assert_true(keygen.generate(seckey, true));

    rnp::secure_bytes hash(32);
    global_ctx.rng.get(hash.data(), hash.size());
    pgp::RSASigMaterial sig(PGP_HASH_SHA256);
    pgp::DSASigMaterial sig2(PGP_HASH_SHA256);

    assert_rnp_failure(seckey.material->sign(global_ctx, sig2, hash));
    assert_rnp_failure(seckey.material->verify(global_ctx, sig2, hash));
    assert_rnp_success(seckey.material->sign(global_ctx, sig, hash));
    assert_rnp_success(seckey.material->verify(global_ctx, sig, hash));

    // cut one byte off hash -> invalid sig
    rnp::secure_bytes hash_cut(hash.begin(), hash.end() - 1);
    assert_rnp_failure(seckey.material->verify(global_ctx, sig, hash_cut));

    // modify sig
    sig.sig.s[0] ^= 0xff;
    assert_rnp_failure(seckey.material->verify(global_ctx, sig, hash));
}

TEST_F(rnp_tests, pkcs1_rsa_test_sign_enc_only)
{
    rnp::KeygenParams keygen(PGP_PKA_RSA_SIGN_ONLY, global_ctx);
    auto &            rsa = dynamic_cast<pgp::RSAKeyParams &>(keygen.key_params());
    rsa.set_bits(1024);

    pgp_key_pkt_t seckey;
    assert_false(keygen.generate(seckey, true));

    rnp::KeygenParams keygen2(PGP_PKA_RSA_ENCRYPT_ONLY, global_ctx);
    auto &            rsa2 = dynamic_cast<pgp::RSAKeyParams &>(keygen2.key_params());
    rsa2.set_bits(1024);

    pgp_key_pkt_t seckey2;
    assert_false(keygen2.generate(seckey2, true));
}

/* OpenPGP MPIs have leading zero bytes stripped, so about 1/256 of RSA
 * ciphertexts/signatures is one byte shorter than the modulus. Botan 3.13+
 * (and some OpenSSL versions) reject such inputs, so decryption/verification
 * must left-pad them back to the modulus length (issue #2465, commit 82283888).
 * The vectors below are fixed: 1024-bit key, 127-byte ciphertext of "abc",
 * and a 127-byte SHA-256 signature. */
TEST_F(rnp_tests, pkcs1_rsa_short_mpi_test_success)
{
    pgp::rsa::Key key;
    assert_true(
      hex2mpi(&key.n,
              "C4A740F92F24DB0425803FB0A16D9BC474BBF2A7884AFA70C1281E31BC71ABAAFFCFB78D"
              "E52721A31384D89C4DDCBD2D51DF3EE3319EE2F0EDA99D41A142403CF827E9D5D25B3A"
              "0952911846C4193FA8BCF86AC3CB4E7F66173203CEBC9E366C56AC2AA0FCF33B0E229D"
              "4494FA0DC5550C6507F32B00E53A4B579A9808F43A21"));
    assert_true(hex2mpi(&key.e, "010001"));
    assert_true(
      hex2mpi(&key.d,
              "837B785BA303B753FC66D52E99A01967AECD031EB467BD2EAA56D2695A9F7DB1E53BD274"
              "12E4A8FEC9CC26AFCAF76D9CE182AC1F674BDE5C4BEAFDF3A588103E075F253A8D6DCD06"
              "3F3731EC7BBE7BC713ACC7D70219EEC5CA601DC9D5091A98BDEE3C42B4276B2065160055"
              "DC86B1658A7121F404B1BEFC2B3D37A9F718E1E1"));
    assert_true(
      hex2mpi(&key.p,
              "DA4A8AEF86EDF1E4982A47B3CCA6A4627A0CE58A5456C200E1FABDF9339CC1B81EA1A9F"
              "89698877F41587AFC8382687E45290E73D58E57B363E499EFA6C1BC15"));
    assert_true(
      hex2mpi(&key.q,
              "E69FD2EB2FCA5F029881F0A088D2B14D7C59E29C1B759A2DE5C2B1913BBAB50A72EA1C8"
              "9B0A51722DD89F9D7AC17945704CC086C788CB77CB9B50D0661EC6CDD"));
    assert_true(
      hex2mpi(&key.u,
              "DD962C16022ACCB0A5D10F6CA9A27A6CF23179EBF966824B24CE055F3CDFF2E077E3831C"
              "1093A9EF46142878B9F85133342BA8CBB4633F6D9037F7F1D45C0170"));

    /* short ciphertext: one byte shorter than the modulus */
    pgp::rsa::Encrypted enc;
    assert_true(
      hex2mpi(&enc.m,
              "301DDA159609D4AA8A8F97658CB8B73D659D73980690484E378B960F44C34FE3E575124"
              "30C15691E375F6E228F860FA97CF2497AE87EB579C1C450B6C99B510528F50362CC48465"
              "667F1DF69F499EF8DBD07E4F038FABD91C7806EFC9C0F296BCBE26BB480F41DBB37B2D29"
              "1C6111F3AE285C97EF57D32C32B0822122B47A0"));
    assert_int_equal(enc.m.size(), 127);

    rnp::secure_bytes dec;
    assert_rnp_success(key.decrypt_pkcs1(global_ctx.rng, dec, enc));
    assert_int_equal(dec.size(), 3);
    assert_true(bin_eq_hex(dec.data(), dec.size(), "616263"));

    /* short signature over fixed digest: one byte shorter than the modulus */
    pgp::rsa::Signature sig;
    assert_true(
      hex2mpi(&sig.s,
              "30FFB372A7D8BFA9B7393EE3829C1BBE0B2D6C2CDD5695A003E2D4FB1C01B0347836A2F"
              "4FBB67AC9DB9ED91DD227709C428E40B676EBBF0FD956AF7F114D75496BA3E243A49047"
              "586A92563DAB73B8ADBB7AAEB08A726E0228C45912A4CC7FEDB0E0A45EA91944B8C3DEC1"
              "D1E859CE07BC4E7FAD3AA23DAC2F92FD293913BE"));
    assert_int_equal(sig.s.size(), 127);
    rnp::secure_bytes digest({0x00, 0x00, 0x00, 0x18, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                              0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
                              0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B});
    assert_rnp_success(key.verify_pkcs1(sig, PGP_HASH_SHA256, digest));
}

TEST_F(rnp_tests, rnp_test_eddsa)
{
    rnp::KeygenParams keygen(PGP_PKA_EDDSA, global_ctx);
    pgp_key_pkt_t     seckey;
    assert_true(keygen.generate(seckey, true));

    rnp::secure_bytes hash(32);
    global_ctx.rng.get(hash.data(), hash.size());

    pgp::ECSigMaterial  sig(PGP_HASH_SHA256);
    pgp::RSASigMaterial sig2(PGP_HASH_SHA256);

    assert_rnp_failure(seckey.material->sign(global_ctx, sig2, hash));
    assert_rnp_failure(seckey.material->verify(global_ctx, sig2, hash));

    assert_rnp_success(seckey.material->sign(global_ctx, sig, hash));
    assert_rnp_success(seckey.material->verify(global_ctx, sig, hash));

    pgp::ECDHEncMaterial enc;
    assert_rnp_failure(seckey.material->encrypt(global_ctx, enc, hash));
    assert_rnp_failure(seckey.material->decrypt(global_ctx, hash, enc));

    // cut one byte off hash -> invalid sig
    rnp::secure_bytes hash_cut(31);
    assert_rnp_failure(seckey.material->verify(global_ctx, sig, hash_cut));

    // swap r/s -> invalid sig
    pgp::mpi tmp = sig.sig.r;
    sig.sig.r = sig.sig.s;
    sig.sig.s = tmp;
    assert_rnp_failure(seckey.material->verify(global_ctx, sig, hash));
}

#if defined(ENABLE_CRYPTO_REFRESH)
TEST_F(rnp_tests, rnp_test_ed448)
{
    rnp::KeygenParams keygen(PGP_PKA_ED448, global_ctx);
    pgp_key_pkt_t     seckey;
    assert_true(keygen.generate(seckey, true));

    auto &ed = dynamic_cast<pgp::Ed448KeyMaterial &>(*seckey.material);
    assert_int_equal(ed.pub().size(), 57);
    assert_int_equal(ed.priv().size(), 57);

    /* Write the secret key fields and parse them back: both use the curve's encoded key
     * size, which is 57 bytes for Ed448, not BITS_TO_BYTES(448). */
    auto cleartext = seckey.sec_data;
    assert_false(cleartext.empty());
    seckey.sec_protection.s2k.usage = PGP_S2KU_NONE;
    assert_rnp_success(encrypt_secret_key(&seckey, NULL, global_ctx.rng));
    assert_true(seckey.sec_data == cleartext);
    seckey.material->clear_secret();
    assert_false(seckey.material->secret());
    assert_rnp_success(decrypt_secret_key(&seckey, NULL));
    assert_true(seckey.material->secret());
    auto &parsed = dynamic_cast<pgp::Ed448KeyMaterial &>(*seckey.material);
    assert_int_equal(parsed.priv().size(), 57);
    assert_int_equal(parsed.pub().size(), 57);

    rnp::secure_bytes hash(64);
    global_ctx.rng.get(hash.data(), hash.size());
    pgp::Ed448SigMaterial sig(PGP_HASH_SHA512);
    assert_rnp_success(seckey.material->sign(global_ctx, sig, hash));
    assert_rnp_success(seckey.material->verify(global_ctx, sig, hash));
}
#endif

TEST_F(rnp_tests, rnp_test_x25519)
{
    rnp::KeygenParams keygen(PGP_PKA_ECDH, global_ctx);
    auto &            ecc = dynamic_cast<pgp::ECCKeyParams &>(keygen.key_params());
    ecc.set_curve(PGP_CURVE_25519);

    pgp_key_pkt_t seckey;
    assert_true(keygen.generate(seckey, true));

    /* check for length and correctly tweaked bits */
    auto &ec = dynamic_cast<pgp::ECKeyMaterial &>(*seckey.material);
    assert_int_equal(ec.x().size(), 32);
    assert_int_equal(ec.x()[31] & 7, 0);
    assert_int_equal(ec.x()[0] & 128, 0);
    assert_int_equal(ec.x()[0] & 64, 64);
    /* encrypt */
    pgp::Fingerprint     fp(seckey);
    rnp::secure_bytes    in({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    pgp::ECDHEncMaterial enc;
    pgp::SM2EncMaterial  enc2;
    enc.enc.fp = fp.vec();
    assert_rnp_failure(seckey.material->encrypt(global_ctx, enc2, in));
    assert_rnp_success(seckey.material->encrypt(global_ctx, enc, in));
    assert_true(enc.enc.m.size() > 16);
    assert_int_equal(enc.enc.p[0], 0x40);
    assert_int_equal(enc.enc.p.size(), 33);
    /* decrypt */
    rnp::secure_bytes out;
    assert_rnp_failure(seckey.material->decrypt(global_ctx, out, enc2));
    assert_true(out.empty());
    assert_rnp_success(seckey.material->decrypt(global_ctx, out, enc));
    assert_int_equal(out.size(), 16);
    assert_int_equal(memcmp(in.data(), out.data(), 16), 0);
    /* negative cases */
    enc.enc.p[16] ^= 0xff;
    assert_rnp_failure(seckey.material->decrypt(global_ctx, out, enc));

    enc.enc.p[16] ^= 0xff;
    enc.enc.p[0] = 0x04;
    assert_rnp_failure(seckey.material->decrypt(global_ctx, out, enc));

    enc.enc.p[0] = 0x40;
    uint8_t back = enc.enc.m.back();
    enc.enc.m.pop_back();
    assert_rnp_failure(seckey.material->decrypt(global_ctx, out, enc));

    enc.enc.m.push_back(back);
    enc.enc.m.push_back(0);
    assert_rnp_failure(seckey.material->decrypt(global_ctx, out, enc));

    rnp::secure_bytes hash(32);
    global_ctx.rng.get(hash.data(), hash.size());
    pgp::ECSigMaterial sig(PGP_HASH_SHA256);
    assert_rnp_failure(seckey.material->sign(global_ctx, sig, hash));
    assert_rnp_failure(seckey.material->verify(global_ctx, sig, hash));
}

static void
elgamal_roundtrip(const pgp::eg::Key &key, rnp::RNG &rng)
{
    rnp::secure_bytes  in_b({0x01, 0x02, 0x03, 0x04, 0x17});
    pgp::eg::Encrypted enc = {{}};
    rnp::secure_bytes  res;

    assert_rnp_success(key.encrypt_pkcs1(rng, enc, in_b));
    assert_rnp_success(key.decrypt_pkcs1(rng, res, enc));
    assert_int_equal(res.size(), in_b.size());
    assert_true(bin_eq_hex(res.data(), res.size(), "0102030417"));
}

TEST_F(rnp_tests, raw_elgamal_random_key_test_success)
{
    pgp::eg::Key key;

    assert_rnp_success(key.generate(global_ctx.rng, 1024));
    assert_true(key.validate(true));
    elgamal_roundtrip(key, global_ctx.rng);
}

TEST_F(rnp_tests, ecdsa_signverify_success)
{
    const pgp_hash_alg_t hash_alg = PGP_HASH_SHA512;

    struct curve {
        pgp_curve_t id;
        size_t      size;
    } curves[] = {
      {PGP_CURVE_NIST_P_256, 32}, {PGP_CURVE_NIST_P_384, 48}, {PGP_CURVE_NIST_P_521, 64}};

    for (size_t i = 0; i < ARRAY_SIZE(curves); i++) {
        // Generate test data. Mainly to make valgrind not to complain about uninitialized data
        rnp::secure_bytes hash(rnp::Hash::size(hash_alg));
        global_ctx.rng.get(hash.data(), hash.size());

        rnp::KeygenParams keygen(PGP_PKA_ECDSA, global_ctx);
        keygen.set_hash(hash_alg);
        auto &ecc = dynamic_cast<pgp::ECCKeyParams &>(keygen.key_params());
        ecc.set_curve(curves[i].id);

        pgp_key_pkt_t seckey1;
        pgp_key_pkt_t seckey2;

        assert_true(keygen.generate(seckey1, true));
        assert_true(keygen.generate(seckey2, true));

        rnp::secure_bytes    in({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
        rnp::secure_bytes    out;
        pgp::ECDHEncMaterial enc;
        assert_rnp_failure(seckey1.material->encrypt(global_ctx, enc, in));
        assert_rnp_failure(seckey1.material->decrypt(global_ctx, out, enc));

        pgp::ECSigMaterial sig(hash_alg);
        assert_rnp_success(seckey1.material->sign(global_ctx, sig, hash));
        assert_rnp_success(seckey1.material->verify(global_ctx, sig, hash));

        // Fails because of different key used
        assert_rnp_failure(seckey2.material->verify(global_ctx, sig, hash));

        // Fails because message won't verify
        hash[0] = ~hash[0];
        assert_rnp_failure(seckey1.material->verify(global_ctx, sig, hash));
    }
}

TEST_F(rnp_tests, ecdh_roundtrip)
{
    struct curve {
        pgp_curve_t id;
        size_t      size;
    } curves[] = {
      {PGP_CURVE_NIST_P_256, 32}, {PGP_CURVE_NIST_P_384, 48}, {PGP_CURVE_NIST_P_521, 66}};

    rnp::secure_bytes in({1, 2, 3});
    in.insert(in.end(), 32 - in.size(), 0);

    for (size_t i = 0; i < ARRAY_SIZE(curves); i++) {
        rnp::KeygenParams keygen(PGP_PKA_ECDH, global_ctx);
        keygen.set_hash(PGP_HASH_SHA512);
        auto &ecc = dynamic_cast<pgp::ECCKeyParams &>(keygen.key_params());
        ecc.set_curve(curves[i].id);

        pgp_key_pkt_t ecdh_key1{};
        assert_true(keygen.generate(ecdh_key1, true));

        pgp::Fingerprint   ecdh_key1_fpr(ecdh_key1);
        pgp::ECSigMaterial sig(keygen.hash());
        rnp::secure_bytes  hash(rnp::Hash::size(keygen.hash()));
        assert_rnp_failure(ecdh_key1.material->sign(global_ctx, sig, hash));
        assert_rnp_failure(ecdh_key1.material->verify(global_ctx, sig, hash));

        pgp::ECDHEncMaterial enc;
        enc.enc.fp = ecdh_key1_fpr.vec();
        assert_rnp_success(ecdh_key1.material->encrypt(global_ctx, enc, in));

        rnp::secure_bytes res;
        assert_rnp_success(ecdh_key1.material->decrypt(global_ctx, res, enc));

        assert_int_equal(in.size(), res.size());
        assert_true(in == res);
    }
}

namespace pgp {
class ECDHTestKeyMaterial : public ECDHKeyMaterial {
  public:
    ECDHTestKeyMaterial(const ECDHKeyMaterial &src) : ECDHKeyMaterial(src)
    {
    }

    void
    set_key_wrap_alg(pgp_symm_alg_t alg)
    {
        key_.key_wrap_alg = alg;
    }

    ec::Key &
    ec()
    {
        return key_;
    }
};
} // namespace pgp

TEST_F(rnp_tests, ecdh_decryptionNegativeCases)
{
    rnp::secure_bytes in({1, 2, 3, 4});
    in.insert(in.end(), 32 - in.size(), 0);
    rnp::secure_bytes res;

    rnp::KeygenParams keygen(PGP_PKA_ECDH, global_ctx);
    keygen.set_hash(PGP_HASH_SHA512);
    auto &ecc = dynamic_cast<pgp::ECCKeyParams &>(keygen.key_params());
    ecc.set_curve(PGP_CURVE_NIST_P_256);

    pgp_key_pkt_t ecdh_key1;
    assert_true(keygen.generate(ecdh_key1, true));

    pgp::Fingerprint     ecdh_key1_fpr(ecdh_key1);
    pgp::ECDHEncMaterial enc;
    enc.enc.fp = ecdh_key1_fpr.vec();
    assert_rnp_success(ecdh_key1.material->encrypt(global_ctx, enc, in));

    auto m = enc.enc.m;
    enc.enc.m.resize(0);
    assert_int_equal(ecdh_key1.material->decrypt(global_ctx, res, enc), RNP_ERROR_GENERIC);

    enc.enc.m.assign(m.begin(), m.end() - 1);
    assert_int_equal(ecdh_key1.material->decrypt(global_ctx, res, enc), RNP_ERROR_GENERIC);

    pgp::ECDHTestKeyMaterial key1_mod(
      dynamic_cast<pgp::ECDHKeyMaterial &>(*ecdh_key1.material));
    key1_mod.set_key_wrap_alg(PGP_SA_IDEA);
    assert_int_equal(key1_mod.decrypt(global_ctx, res, enc), RNP_ERROR_NOT_SUPPORTED);
}

TEST_F(rnp_tests, sm2_roundtrip)
{
    rnp::KeygenParams keygen(PGP_PKA_SM2, global_ctx);
    keygen.set_hash(PGP_HASH_SM3);

    rnp::secure_bytes key(27, 0);
    global_ctx.rng.get(key.data(), key.size());

    pgp_key_pkt_t seckey;
#if defined(ENABLE_SM2)
    assert_true(keygen.generate(seckey, true));
    auto &eckey = *seckey.material;

    pgp_hash_alg_t       hashes[] = {PGP_HASH_SM3, PGP_HASH_SHA256, PGP_HASH_SHA512};
    pgp::SM2EncMaterial  enc;
    pgp::ECDHEncMaterial enc2;

    for (size_t i = 0; i < ARRAY_SIZE(hashes); ++i) {
        rnp::secure_bytes dec(32, 0);
        assert_rnp_failure(eckey.encrypt(global_ctx, enc2, key));
        assert_rnp_failure(eckey.decrypt(global_ctx, dec, enc2));
        assert_rnp_success(eckey.encrypt(global_ctx, enc, key));
        assert_rnp_success(eckey.decrypt(global_ctx, dec, enc));
        assert_true(dec == key);
    }
#else
    assert_false(keygen.generate(seckey, true));
#endif
}

#if defined(ENABLE_SM2)
TEST_F(rnp_tests, sm2_sm3_signature_test)
{
    const char *msg = "no backdoors here";

    pgp::ec::Key       sm2_key;
    pgp::ec::Signature sig;

    pgp_hash_alg_t hash_alg = PGP_HASH_SM3;
    const size_t   hash_len = rnp::Hash::size(hash_alg);

    sm2_key.curve = PGP_CURVE_NIST_P_256;

    hex2mpi(&sm2_key.p,
            "04d9a2025f1ab59bc44e35fc53aeb8e87a79787d30cd70a1f7c49e064b8b8a2fb24d8"
            "c82f49ee0a5b11df22cb0c3c6d9d5526d9e24d02ff8c83c06a859c26565f1");
    hex2mpi(&sm2_key.x, "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC");

    assert_rnp_success(pgp::sm2::validate_key(global_ctx.rng, sm2_key, true));

    auto hash = rnp::Hash::create(hash_alg);

    assert_rnp_success(pgp::sm2::compute_za(sm2_key, *hash, "sm2_p256_test@example.com"));
    hash->add(msg, strlen(msg));
    rnp::secure_bytes digest = hash->sec_finish();
    assert_int_equal(digest.size(), hash_len);

    // First generate a signature, then verify it
    assert_rnp_success(pgp::sm2::sign(global_ctx.rng, sig, hash_alg, digest, sm2_key));
    assert_rnp_success(pgp::sm2::verify(sig, hash_alg, digest, sm2_key));

    // Check that invalid signatures are rejected
    digest[0] ^= 1;
    assert_rnp_failure(pgp::sm2::verify(sig, hash_alg, digest, sm2_key));

    digest[0] ^= 1;
    assert_rnp_success(pgp::sm2::verify(sig, hash_alg, digest, sm2_key));

    // Now verify a known good signature for this key/message (generated by GmSSL)
    hex2mpi(&sig.r, "96AA39A0C4A5C454653F394E86386F2E38BE14C57D0E555F3A27A5CEF30E51BD");
    hex2mpi(&sig.s, "62372BE4AC97DBE725AC0B279BB8FD15883858D814FD792DDB0A401DCC988E70");
    assert_rnp_success(pgp::sm2::verify(sig, hash_alg, digest, sm2_key));
}
#endif

#if defined(ENABLE_SM2)
TEST_F(rnp_tests, sm2_sha256_signature_test)
{
    const char *       msg = "hi chappy";
    pgp::ec::Key       sm2_key;
    pgp::ec::Signature sig;
    pgp_hash_alg_t     hash_alg = PGP_HASH_SHA256;
    const size_t       hash_len = rnp::Hash::size(hash_alg);

    sm2_key.curve = PGP_CURVE_SM2_P_256;
    hex2mpi(&sm2_key.p,
            "04d03d30dd01ca3422aeaccf9b88043b554659d3092b0a9e8cce3e8c4530a98cb79d7"
            "05e6213eee145b748e36e274e5f101dc10d7bbc9dab9a04022e73b76e02cd");
    hex2mpi(&sm2_key.x, "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC");

    assert_rnp_success(pgp::sm2::validate_key(global_ctx.rng, sm2_key, true));

    auto hash = rnp::Hash::create(hash_alg);
    assert_rnp_success(pgp::sm2::compute_za(sm2_key, *hash, "sm2test@example.com"));
    hash->add(msg, strlen(msg));
    rnp::secure_bytes digest = hash->sec_finish();
    assert_int_equal(digest.size(), hash_len);

    // First generate a signature, then verify it
    assert_rnp_success(pgp::sm2::sign(global_ctx.rng, sig, hash_alg, digest, sm2_key));
    assert_rnp_success(pgp::sm2::verify(sig, hash_alg, digest, sm2_key));

    // Check that invalid signatures are rejected
    digest[0] ^= 1;
    assert_rnp_failure(pgp::sm2::verify(sig, hash_alg, digest, sm2_key));

    digest[0] ^= 1;
    assert_rnp_success(pgp::sm2::verify(sig, hash_alg, digest, sm2_key));

    // Now verify a known good signature for this key/message (generated by GmSSL)
    hex2mpi(&sig.r, "94DA20EA69E4FC70692158BF3D30F87682A4B2F84DF4A4829A1EFC5D9C979D3F");
    hex2mpi(&sig.s, "EE15AF8D455B728AB80E592FCB654BF5B05620B2F4D25749D263D5C01FAD365F");
    assert_rnp_success(pgp::sm2::verify(sig, hash_alg, digest, sm2_key));
}
#endif

TEST_F(rnp_tests, test_dsa_roundtrip)
{
    struct key_params {
        size_t         p;
        size_t         q;
        pgp_hash_alg_t h;
    } keys[] = {
      // all 1024 key-hash combinations
      {1024, 160, PGP_HASH_SHA1},
      {1024, 160, PGP_HASH_SHA224},
      {1024, 160, PGP_HASH_SHA256},
      {1024, 160, PGP_HASH_SHA384},
      {1024, 160, PGP_HASH_SHA512},
      // all 2048 key-hash combinations
      {2048, 256, PGP_HASH_SHA256},
      {2048, 256, PGP_HASH_SHA384},
      {2048, 256, PGP_HASH_SHA512},
      // misc
      {1088, 224, PGP_HASH_SHA512},
      {1024, 256, PGP_HASH_SHA256},
    };

    uint8_t message[PGP_MAX_HASH_SIZE];
    global_ctx.rng.get(message, sizeof(message));

    for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
        rnp::KeygenParams keygen(PGP_PKA_DSA, global_ctx);
        keygen.set_hash(keys[i].h);
        auto &dsa = dynamic_cast<pgp::DSAKeyParams &>(keygen.key_params());
        dsa.set_bits(keys[i].p);
        dsa.set_qbits(keys[i].q);

        pgp_key_pkt_t seckey;
        assert_true(keygen.generate(seckey, true));
        // try to prevent timeouts in travis-ci
        printf(
          "p: %zu q: %zu h: %s\n", dsa.bits(), dsa.qbits(), rnp::Hash::name(keygen.hash()));
        fflush(stdout);

        rnp::secure_bytes  in({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
        rnp::secure_bytes  out;
        pgp::EGEncMaterial enc;
        assert_rnp_failure(seckey.material->encrypt(global_ctx, enc, in));
        assert_rnp_failure(seckey.material->decrypt(global_ctx, out, enc));

        auto &              key = *seckey.material;
        rnp::secure_bytes   hash(message, message + rnp::Hash::size(keygen.hash()));
        pgp::DSASigMaterial sig(keygen.hash());
        assert_rnp_success(key.sign(global_ctx, sig, hash));
        assert_rnp_success(key.verify(global_ctx, sig, hash));
    }
}

TEST_F(rnp_tests, test_dsa_verify_negative)
{
    uint8_t       message[PGP_MAX_HASH_SIZE];
    pgp_key_pkt_t sec_key1;
    pgp_key_pkt_t sec_key2;

    global_ctx.rng.get(message, sizeof(message));

    rnp::KeygenParams keygen(PGP_PKA_DSA, global_ctx);
    keygen.set_hash(PGP_HASH_SHA1);
    auto &dsa = dynamic_cast<pgp::DSAKeyParams &>(keygen.key_params());
    dsa.set_bits(1024);
    dsa.set_qbits(160);

    assert_true(keygen.generate(sec_key1, true));
    // try to prevent timeouts in travis-ci
    printf("p: %zu q: %zu h: %s\n", dsa.bits(), dsa.qbits(), rnp::Hash::name(keygen.hash()));
    assert_true(keygen.generate(sec_key2, true));

    auto &key1 = *sec_key1.material;
    auto &key2 = *sec_key2.material;

    rnp::secure_bytes   hash(message, message + rnp::Hash::size(keygen.hash()));
    pgp::DSASigMaterial sig(keygen.hash());
    assert_rnp_success(key1.sign(global_ctx, sig, hash));
    // wrong key used
    assert_int_equal(key2.verify(global_ctx, sig, hash), RNP_ERROR_SIGNATURE_INVALID);
    // different message
    hash[0] = ~hash[0];
    assert_int_equal(key1.verify(global_ctx, sig, hash), RNP_ERROR_SIGNATURE_INVALID);
}

TEST_F(rnp_tests, test_dsa_verify_rs_size_check)
{
    uint8_t       message[PGP_MAX_HASH_SIZE];
    pgp_key_pkt_t sec_key;

    global_ctx.rng.get(message, sizeof(message));

    rnp::KeygenParams keygen(PGP_PKA_DSA, global_ctx);
    keygen.set_hash(PGP_HASH_SHA256);
    auto &dsa = dynamic_cast<pgp::DSAKeyParams &>(keygen.key_params());
    dsa.set_bits(1024);
    dsa.set_qbits(160);
    assert_true(keygen.generate(sec_key, true));

    auto &              key = *sec_key.material;
    rnp::secure_bytes   hash(message, message + rnp::Hash::size(keygen.hash()));
    pgp::DSASigMaterial sig(keygen.hash());
    assert_rnp_success(key.sign(global_ctx, sig, hash));
    assert_rnp_success(key.verify(global_ctx, sig, hash));

    // r and s must not be longer than q, on every backend
    std::vector<uint8_t> big(512, 0xAB);
    pgp::DSASigMaterial  big_r(sig);
    big_r.sig.r.assign(big.data(), big.size());
    assert_int_equal(key.verify(global_ctx, big_r, hash), RNP_ERROR_BAD_PARAMETERS);
    pgp::DSASigMaterial big_s(sig);
    big_s.sig.s.assign(big.data(), big.size());
    assert_int_equal(key.verify(global_ctx, big_s, hash), RNP_ERROR_BAD_PARAMETERS);
    // r as long as q but not below it goes to the signature check
    std::vector<uint8_t> top(dsa.qbits() / 8, 0xFF);
    pgp::DSASigMaterial  top_r(sig);
    top_r.sig.r.assign(top.data(), top.size());
    assert_int_equal(key.verify(global_ctx, top_r, hash), RNP_ERROR_SIGNATURE_INVALID);
}

#if defined(ENABLE_PQC)
TEST_F(rnp_tests, kyber_ecdh_roundtrip)
{
    pgp_pubkey_alg_t algs[] = {
        PGP_PKA_KYBER768_X25519,
#if defined(ENABLE_PQC) && defined(ENABLE_CRYPTO_REFRESH)
        PGP_PKA_KYBER1024_X448,
        PGP_PKA_KYBER1024_P521,
        PGP_PKA_KYBER768_BP384,
        PGP_PKA_KYBER1024_BP512
#endif
    };

    rnp::secure_bytes in(32, 0);
    rnp::secure_bytes res(36);

    for (size_t i = 0; i < in.size(); i++) {
        in[i] = i; // assures that we do not have a special case with all-zeroes
    }

    for (size_t i = 0; i < ARRAY_SIZE(algs); i++) {
        rnp::KeygenParams keygen(algs[i], global_ctx);
        keygen.set_hash(PGP_HASH_SHA512);

        pgp_key_pkt_t key_pkt;
        assert_true(keygen.generate(key_pkt, true));

        pgp::MlkemEcdhEncMaterial enc(algs[i]);
        assert_rnp_success(key_pkt.material->encrypt(global_ctx, enc, in));
        assert_rnp_success(key_pkt.material->decrypt(global_ctx, res, enc));

        assert_int_equal(in.size(), res.size());
        assert_true(in == res);
    }
}
#endif

#if defined(ENABLE_PQC) && defined(ENABLE_CRYPTO_REFRESH)
TEST_F(rnp_tests, dilithium_exdsa_signverify_success)
{
    uint8_t              message[64];
    const pgp_hash_alg_t hash_alg = PGP_HASH_SHA512;

    pgp_pubkey_alg_t algs[] = {PGP_PKA_DILITHIUM3_ED25519,
                               PGP_PKA_DILITHIUM5_ED448,
                               PGP_PKA_DILITHIUM3_P384,
                               PGP_PKA_DILITHIUM5_P521,
                               PGP_PKA_DILITHIUM3_BP384,
                               PGP_PKA_DILITHIUM5_BP512};

    for (size_t i = 0; i < ARRAY_SIZE(algs); i++) {
        // Generate test data. Mainly to make valgrind not to complain about uninitialized data
        global_ctx.rng.get(message, sizeof(message));

        rnp::KeygenParams keygen(algs[i], global_ctx);
        keygen.set_hash(hash_alg);

        pgp_key_pkt_t seckey1;
        pgp_key_pkt_t seckey2;

        assert_true(keygen.generate(seckey1, true));
        assert_true(keygen.generate(seckey2, true));

        auto &key1 = *seckey1.material;
        auto &key2 = *seckey2.material;

        pgp::DilithiumSigMaterial sig(keygen.alg(), keygen.hash());
        sig.halg = hash_alg;
        rnp::secure_bytes hash(message, message + sizeof(message));
        assert_rnp_success(key1.sign(global_ctx, sig, hash));
        assert_rnp_success(key1.verify(global_ctx, sig, hash));

        // Fails because of different key used
        assert_rnp_failure(key2.verify(global_ctx, sig, hash));
    }
}

TEST_F(rnp_tests, sphincsplus_signverify_success)
{
    uint8_t          message[64];
    pgp_pubkey_alg_t algs[] = {PGP_PKA_SPHINCSPLUS_SHAKE_128f,
                               PGP_PKA_SPHINCSPLUS_SHAKE_128s,
                               PGP_PKA_SPHINCSPLUS_SHAKE_256s};

    for (size_t i = 0; i < ARRAY_SIZE(algs); i++) {
        // Generate test data. Mainly to make valgrind not to complain about uninitialized
        // data
        global_ctx.rng.get(message, sizeof(message));

        rnp::KeygenParams keygen(algs[i], global_ctx);

        pgp_key_pkt_t seckey1;
        pgp_key_pkt_t seckey2;

        assert_true(keygen.generate(seckey1, true));
        assert_true(keygen.generate(seckey2, true));

        auto &                 key1 = *seckey1.material;
        auto &                 key2 = *seckey2.material;
        rnp::secure_bytes      hash(message, message + sizeof(message));
        pgp::SlhdsaSigMaterial sig(algs[i], keygen.hash());
        assert_rnp_success(key1.sign(global_ctx, sig, hash));
        assert_rnp_success(key1.verify(global_ctx, sig, hash));

        // Fails because of different key used
        assert_rnp_failure(key2.verify(global_ctx, sig, hash));
    }
}
#endif

// platforms known to not have a robust response can compile with
// -DS2K_MINIMUM_TUNING_RATIO=2 (or whatever they need)
#ifndef S2K_MINIMUM_TUNING_RATIO
#define S2K_MINIMUM_TUNING_RATIO 4
#endif

TEST_F(rnp_tests, s2k_iteration_tuning)
{
    pgp_hash_alg_t hash_alg = PGP_HASH_SHA512;

    /*
    Run trials for a while (1/4 second) to ensure dynamically clocked
    cores spin up to full speed.
    */
    const size_t TRIAL_MSEC = 250;

    const size_t iters_100 = pgp_s2k_compute_iters(hash_alg, 100, TRIAL_MSEC);
    const size_t iters_10 = pgp_s2k_compute_iters(hash_alg, 10, TRIAL_MSEC);

    double ratio = static_cast<double>(iters_100) / iters_10;
    printf("s2k iteration tuning ratio: %g, (%zu:%zu)\n", ratio, iters_10, iters_100);
    // Test roughly linear cost, often skeyed by clock idle
    assert_greater_than(ratio, S2K_MINIMUM_TUNING_RATIO);

    // Should not crash for unknown hash algorithm
    assert_int_equal(pgp_s2k_compute_iters(PGP_HASH_UNKNOWN, 1000, TRIAL_MSEC), 0);
    /// TODO test that hashing iters_xx data takes roughly requested time

    size_t iter_sha1 = global_ctx.s2k_iterations(PGP_HASH_SHA1);
    assert_int_equal(iter_sha1, global_ctx.s2k_iterations(PGP_HASH_SHA1));
    size_t iter_sha512 = global_ctx.s2k_iterations(PGP_HASH_SHA512);
    assert_int_equal(iter_sha512, global_ctx.s2k_iterations(PGP_HASH_SHA512));
    assert_int_equal(global_ctx.s2k_iterations(PGP_HASH_UNKNOWN), 0);
}

TEST_F(rnp_tests, s2k_iteration_encode_decode)
{
    const size_t MAX_ITER = 0x3e00000; // 0x1F << (0xF + 6);
    // encoding tests
    assert_int_equal(pgp_s2k_encode_iterations(0), 0);
    assert_int_equal(pgp_s2k_encode_iterations(512), 0);
    assert_int_equal(pgp_s2k_encode_iterations(1024), 0);
    assert_int_equal(pgp_s2k_encode_iterations(1024), 0);
    assert_int_equal(pgp_s2k_encode_iterations(1025), 1);
    assert_int_equal(pgp_s2k_encode_iterations(1088), 1);
    assert_int_equal(pgp_s2k_encode_iterations(1089), 2);
    assert_int_equal(pgp_s2k_encode_iterations(2048), 16);
    assert_int_equal(pgp_s2k_encode_iterations(MAX_ITER - 1), 0xFF);
    assert_int_equal(pgp_s2k_encode_iterations(MAX_ITER), 0xFF);
    assert_int_equal(pgp_s2k_encode_iterations(MAX_ITER + 1), 0xFF);
    assert_int_equal(pgp_s2k_encode_iterations(SIZE_MAX), 0xFF);
    // decoding tests
    assert_int_equal(pgp_s2k_decode_iterations(0), 1024);
    assert_int_equal(pgp_s2k_decode_iterations(1), 1088);
    assert_int_equal(pgp_s2k_decode_iterations(16), 2048);
    assert_int_equal(pgp_s2k_decode_iterations(0xFF), MAX_ITER);
}

static bool
read_key_pkt(pgp_key_pkt_t *key, const char *path)
{
    pgp_source_t src = {};
    if (init_file_src(&src, path)) {
        return false;
    }
    bool res = !key->parse(src);
    src.close();
    return res;
}

namespace pgp {
class RSATestKeyMaterial : public RSAKeyMaterial {
  public:
    RSATestKeyMaterial(const RSAKeyMaterial &src) : RSAKeyMaterial(src)
    {
    }

    rsa::Key &
    rsa()
    {
        return key_;
    }
};

class DSATestKeyMaterial : public DSAKeyMaterial {
  public:
    DSATestKeyMaterial(const DSAKeyMaterial &src) : DSAKeyMaterial(src)
    {
    }

    dsa::Key &
    dsa()
    {
        return key_;
    }
};

class EGTestKeyMaterial : public EGKeyMaterial {
  public:
    EGTestKeyMaterial(const EGKeyMaterial &src) : EGKeyMaterial(src)
    {
    }

    eg::Key &
    eg()
    {
        return key_;
    }
};

class ECDSATestKeyMaterial : public ECDSAKeyMaterial {
  public:
    ECDSATestKeyMaterial(const ECDSAKeyMaterial &src) : ECDSAKeyMaterial(src)
    {
    }

    ec::Key &
    ec()
    {
        return key_;
    }
};

class EDDSATestKeyMaterial : public EDDSAKeyMaterial {
  public:
    EDDSATestKeyMaterial(const EDDSAKeyMaterial &src) : EDDSAKeyMaterial(src)
    {
    }

    ec::Key &
    ec()
    {
        return key_;
    }
};

} // namespace pgp

#define KEYS "data/test_validate_key_material/"

TEST_F(rnp_tests, test_validate_key_material)
{
    pgp_key_pkt_t key;

    /* RSA key and subkey */
    assert_true(read_key_pkt(&key, KEYS "rsa-pub.pgp"));
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    pgp::RSATestKeyMaterial rkey(dynamic_cast<pgp::RSAKeyMaterial &>(*key.material));
    rkey.rsa().n[rkey.rsa().n.size() - 1] &= ~1;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    rkey.rsa().n[rkey.rsa().n.size() - 1] |= 1;
    rkey.rsa().e[rkey.rsa().e.size() - 1] &= ~1;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    key = pgp_key_pkt_t();

    assert_true(read_key_pkt(&key, KEYS "rsa-sub.pgp"));
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    rkey = pgp::RSATestKeyMaterial(dynamic_cast<pgp::RSAKeyMaterial &>(*key.material));
    rkey.rsa().n[rkey.rsa().n.size() - 1] &= ~1;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    rkey.rsa().n[rkey.rsa().n.size() - 1] |= 1;
    rkey.rsa().e[rkey.rsa().e.size() - 1] &= ~1;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    key = pgp_key_pkt_t();

    assert_true(read_key_pkt(&key, KEYS "rsa-sec.pgp"));
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    assert_true(key.material->validity().valid);
    assert_true(key.material->validity().validated);
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    /* make sure validity is reset after decryption */
    assert_false(key.material->validity().valid);
    assert_false(key.material->validity().validated);
    assert_true(key.material->secret());
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    rkey = pgp::RSATestKeyMaterial(dynamic_cast<pgp::RSAKeyMaterial &>(*key.material));
    rkey.rsa().e[rkey.rsa().e.size() - 1] += 1;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    rkey.rsa().e[rkey.rsa().e.size() - 1] -= 1;
    rkey.rsa().p[rkey.rsa().p.size() - 1] += 2;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    rkey.rsa().p[rkey.rsa().p.size() - 1] -= 2;
    rkey.rsa().q[rkey.rsa().q.size() - 1] += 2;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    rkey.rsa().q[rkey.rsa().q.size() - 1] -= 2;
    rkey.validate(global_ctx);
    assert_true(rkey.valid());
    key = pgp_key_pkt_t();

    assert_true(read_key_pkt(&key, KEYS "rsa-ssb.pgp"));
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material->secret());
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    rkey = pgp::RSATestKeyMaterial(dynamic_cast<pgp::RSAKeyMaterial &>(*key.material));
    rkey.rsa().e[rkey.rsa().e.size() - 1] += 1;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    rkey.rsa().e[rkey.rsa().e.size() - 1] -= 1;
    rkey.rsa().p[rkey.rsa().p.size() - 1] += 2;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    rkey.rsa().p[rkey.rsa().p.size() - 1] -= 2;
    rkey.rsa().q[rkey.rsa().q.size() - 1] += 2;
    rkey.validate(global_ctx);
    assert_false(rkey.valid());
    rkey.rsa().q[rkey.rsa().q.size() - 1] -= 2;
    rkey.validate(global_ctx);
    assert_true(rkey.valid());
    key = pgp_key_pkt_t();

    /* DSA-ElGamal key */
    assert_true(read_key_pkt(&key, KEYS "dsa-sec.pgp"));
    pgp::DSATestKeyMaterial dkey(dynamic_cast<pgp::DSAKeyMaterial &>(*key.material));
    dkey.dsa().q[dkey.dsa().q.size() - 1] += 2;
    dkey.validate(global_ctx);
    assert_false(dkey.valid());
    dkey.dsa().q[dkey.dsa().q.size() - 1] -= 2;
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material->secret());
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    dkey = pgp::DSATestKeyMaterial(dynamic_cast<pgp::DSAKeyMaterial &>(*key.material));
    dkey.dsa().y[dkey.dsa().y.size() - 1] += 2;
    dkey.validate(global_ctx);
    assert_false(dkey.valid());
    dkey.dsa().y[dkey.dsa().y.size() - 1] -= 2;
    dkey.dsa().p[dkey.dsa().p.size() - 1] += 2;
    dkey.validate(global_ctx);
    assert_false(dkey.valid());
    dkey.dsa().p[dkey.dsa().p.size() - 1] -= 2;
    /* since Botan calculates y from x on key load we do not check x vs y */
    dkey.dsa().x = dkey.dsa().q;
    dkey.validate(global_ctx);
    assert_false(dkey.valid());
    key = pgp_key_pkt_t();

    assert_true(read_key_pkt(&key, KEYS "eg-sec.pgp"));
    pgp::EGTestKeyMaterial gkey(dynamic_cast<pgp::EGKeyMaterial &>(*key.material));
    gkey.eg().p[gkey.eg().p.size() - 1] += 2;
    gkey.validate(global_ctx);
    assert_false(gkey.valid());
    gkey.eg().p[gkey.eg().p.size() - 1] -= 2;
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material->secret());
    gkey = pgp::EGTestKeyMaterial(dynamic_cast<pgp::EGKeyMaterial &>(*key.material));
    gkey.validate(global_ctx);
    assert_true(gkey.valid());
    gkey.eg().p[gkey.eg().p.size() - 1] += 2;
    gkey.validate(global_ctx);
    assert_false(gkey.valid());
    gkey.eg().p[gkey.eg().p.size() - 1] -= 2;
    /* since Botan calculates y from x on key load we do not check x vs y */
    gkey.eg().x = gkey.eg().p;
    gkey.validate(global_ctx);
    assert_false(gkey.valid());
    key = pgp_key_pkt_t();

    /* ElGamal key with small subgroup */
    assert_true(read_key_pkt(&key, KEYS "eg-sec-small-group.pgp"));
    key.material->validate(global_ctx);
    assert_false(key.material->valid());
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    key = pgp_key_pkt_t();

    assert_true(read_key_pkt(&key, KEYS "eg-sec-small-group-enc.pgp"));
    key.material->validate(global_ctx);
    assert_false(key.material->valid());
    assert_rnp_success(decrypt_secret_key(&key, "password"));
    key = pgp_key_pkt_t();

    /* ECDSA key */
    assert_true(read_key_pkt(&key, KEYS "ecdsa-p256-sec.pgp"));
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    pgp::ECDSATestKeyMaterial ekey(dynamic_cast<pgp::ECDSAKeyMaterial &>(*key.material));
    ekey.validate(global_ctx);
    assert_true(ekey.valid());
    ekey.ec().p[0] += 2;
    ekey.validate(global_ctx);
    assert_false(ekey.valid());
    ekey.ec().p[0] -= 2;
    ekey.ec().p[10] += 2;
    ekey.validate(global_ctx);
    assert_false(ekey.valid());
    ekey.ec().p[10] -= 2;
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material->secret());
    key = pgp_key_pkt_t();

    /* ECDH key */
    assert_true(read_key_pkt(&key, KEYS "ecdh-p256-sec.pgp"));
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    pgp::ECDHTestKeyMaterial ehkey(dynamic_cast<pgp::ECDHKeyMaterial &>(*key.material));
    ehkey.ec().p[0] += 2;
    ehkey.validate(global_ctx);
    assert_false(ehkey.valid());
    ehkey.ec().p[0] -= 2;
    ehkey.ec().p[10] += 2;
    ehkey.validate(global_ctx);
    assert_false(ehkey.valid());
    ehkey.ec().p[10] -= 2;
    /* truncated point (single 0x04 prefix) must be rejected, not read past the buffer */
    pgp::mpi ehp = ehkey.ec().p;
    ehkey.ec().p.resize(1);
    ehkey.validate(global_ctx);
    assert_false(ehkey.valid());
    ehkey.ec().p = ehp;
    assert_rnp_success(decrypt_secret_key(&key, NULL));
    assert_true(key.material->secret());
    key = pgp_key_pkt_t();

    /* EDDSA key, just test for header since any value can be secret key */
    assert_true(read_key_pkt(&key, KEYS "ed25519-sec.pgp"));
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    pgp::EDDSATestKeyMaterial edkey(dynamic_cast<pgp::EDDSAKeyMaterial &>(*key.material));
    edkey.ec().p[0] += 2;
    edkey.validate(global_ctx);
    assert_false(edkey.valid());
    edkey.ec().p[0] -= 2;
    key = pgp_key_pkt_t();

    /* x25519 key, same as the previous - botan calculates pub key from the secret one */
    assert_true(read_key_pkt(&key, KEYS "x25519-sec.pgp"));
    key.material->validate(global_ctx);
    assert_true(key.material->valid());
    ehkey = pgp::ECDHTestKeyMaterial(dynamic_cast<pgp::ECDHKeyMaterial &>(*key.material));
    ehkey.ec().p[0] += 2;
    ehkey.validate(global_ctx);
    assert_false(ehkey.valid());
    ehkey.ec().p[0] -= 2;
    key = pgp_key_pkt_t();
}

TEST_F(rnp_tests, test_parse_photo_attribute)
{
    /* Direct unit tests for rnp::parse_photo_attribute. The FFI path
     * (test_ffi_load_userattr) only exercises one fixture; here we cover
     * each branch of the parser directly so codecov sees every code path
     * and so regressions in length decoding or magic-byte detection surface
     * independently of the cli_tests fixture set. */
    using namespace rnp;

    auto build_userattr = [](uint8_t                     subpacket_type,
                             uint8_t                     header_len,
                             const std::vector<uint8_t> &header_tail,
                             const std::vector<uint8_t> &image) -> std::vector<uint8_t> {
        /* Build a UserAttr body containing exactly one subpacket of the
         * requested shape. Subpacket body = type + hdr_len + header_tail + image. */
        size_t               sub_body = 1 + 1 + header_tail.size() + image.size();
        std::vector<uint8_t> body;
        if (sub_body < 192) {
            body.push_back((uint8_t) sub_body);
        } else {
            body.push_back((uint8_t)(((sub_body - 192) >> 8) + 192));
            body.push_back((uint8_t)((sub_body - 192) & 0xff));
        }
        body.push_back(subpacket_type);
        body.push_back(header_len);
        body.insert(body.end(), header_tail.begin(), header_tail.end());
        body.insert(body.end(), image.begin(), image.end());
        return body;
    };

    /* JPEG happy path: 16-byte header, magic FF D8 FF E0 ... */
    {
        std::vector<uint8_t> image = {
          0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01};
        std::vector<uint8_t> header_tail(15, 0x00);
        auto                 body = build_userattr(1, 16, header_tail, image);
        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::Unknown;
        assert_true(parse_photo_attribute(body, out, fmt));
        assert_int_equal((int) fmt, (int) PhotoFormat::JPEG);
        assert_int_equal(out.size(), image.size());
        assert_true(memcmp(out.data(), image.data(), image.size()) == 0);
    }

    /* PNG happy path: magic 89 50 4E 47 0D 0A 1A 0A */
    {
        std::vector<uint8_t> image = {
          0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 'P', 'N', 'G'};
        std::vector<uint8_t> header_tail(15, 0x00);
        auto                 body = build_userattr(1, 16, header_tail, image);
        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::Unknown;
        assert_true(parse_photo_attribute(body, out, fmt));
        assert_int_equal((int) fmt, (int) PhotoFormat::PNG);
        assert_int_equal(out.size(), image.size());
    }

    /* Unknown image format — bytes returned, format = Unknown */
    {
        std::vector<uint8_t> image = {0x42, 0x4D, 0x00, 0x00, 'B', 'M'}; // BMP magic
        std::vector<uint8_t> header_tail(15, 0x00);
        auto                 body = build_userattr(1, 16, header_tail, image);
        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::JPEG;
        assert_true(parse_photo_attribute(body, out, fmt));
        assert_int_equal((int) fmt, (int) PhotoFormat::Unknown);
        assert_int_equal(out.size(), image.size());
    }

    /* Empty body — must fail cleanly */
    {
        std::vector<uint8_t> empty;
        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::Unknown;
        assert_false(parse_photo_attribute(empty, out, fmt));
    }

    /* Subpacket type != 1 — must skip past it, then EOF without an image,
     * so return false. */
    {
        std::vector<uint8_t> image = {0xFF, 0xD8, 0xFF, 0xE0};
        std::vector<uint8_t> header_tail(15, 0x00);
        auto                 body = build_userattr(2 /*unknown type*/, 16, header_tail, image);
        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::Unknown;
        assert_false(parse_photo_attribute(body, out, fmt));
    }

    /* Image header length 0 — must reject (RFC says it must be >= 16) */
    {
        std::vector<uint8_t> image = {0xFF, 0xD8, 0xFF};
        auto                 body = build_userattr(1, 0, {}, image);
        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::Unknown;
        assert_false(parse_photo_attribute(body, out, fmt));
    }

    /* Image too small (< 3 bytes) — must fail since magic can't be checked */
    {
        std::vector<uint8_t> image = {0xFF, 0xD8};
        std::vector<uint8_t> header_tail(15, 0x00);
        auto                 body = build_userattr(1, 16, header_tail, image);
        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::Unknown;
        assert_false(parse_photo_attribute(body, out, fmt));
    }

    /* 5-byte subpacket length form (b0 == 255) — exercised separately from
     * the 2-byte form, which is what the existing fixture happens to use. */
    {
        std::vector<uint8_t> image(400,
                                   0xAA); // > 192 to force 5-byte form? actually need >8383
        image[0] = 0xFF;
        image[1] = 0xD8;
        image[2] = 0xFF;
        std::vector<uint8_t> header_tail(15, 0x00);
        size_t               sub_body = 1 + 1 + header_tail.size() + image.size();
        std::vector<uint8_t> body = {0xFF,
                                     (uint8_t)((sub_body >> 24) & 0xff),
                                     (uint8_t)((sub_body >> 16) & 0xff),
                                     (uint8_t)((sub_body >> 8) & 0xff),
                                     (uint8_t)(sub_body & 0xff)};
        body.push_back(1); // subpacket type
        body.push_back(16);
        body.insert(body.end(), header_tail.begin(), header_tail.end());
        body.insert(body.end(), image.begin(), image.end());
        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::Unknown;
        assert_true(parse_photo_attribute(body, out, fmt));
        assert_int_equal((int) fmt, (int) PhotoFormat::JPEG);
    }

    /* Partial-length encoding (b0 in 224-254) — not valid for UserAttr
     * subpackets, must reject. */
    {
        std::vector<uint8_t> body = {0xE0, 0x01, 0x10, 0xFF, 0xD8, 0xFF};
        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::Unknown;
        assert_false(parse_photo_attribute(body, out, fmt));
    }

    /* Multiple subpackets: first one is unknown type, second is the image.
     * The walker must skip past the first and find the image. */
    {
        std::vector<uint8_t> image = {0xFF, 0xD8, 0xFF, 0xE0, 'J', 'F', 'I', 'F'};
        std::vector<uint8_t> header_tail(15, 0x00);

        /* First subpacket: type 99, body just 4 bytes of filler */
        std::vector<uint8_t> body;
        body.push_back(5); // length = 5 (1 type + 4 filler)
        body.push_back(99);
        body.push_back(1);
        body.push_back(2);
        body.push_back(3);
        body.push_back(4);

        /* Second subpacket: real image */
        size_t sub_body = 1 + 1 + header_tail.size() + image.size();
        body.push_back((uint8_t) sub_body);
        body.push_back(1);
        body.push_back(16);
        body.insert(body.end(), header_tail.begin(), header_tail.end());
        body.insert(body.end(), image.begin(), image.end());

        std::vector<uint8_t> out;
        PhotoFormat          fmt = PhotoFormat::Unknown;
        assert_true(parse_photo_attribute(body, out, fmt));
        assert_int_equal((int) fmt, (int) PhotoFormat::JPEG);
        assert_int_equal(out.size(), image.size());
    }
}

TEST_F(rnp_tests, test_sm2_enabled)
{
    char *features = NULL;
    bool  supported = false;
    /* check whether FFI returns value which corresponds to defines */
#if defined(ENABLE_SM2)
    assert_true(sm2_enabled());
    /* SM2 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_PK_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM2") != std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "SM2", &supported));
    assert_true(supported);
    /* SM3 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_HASH_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM3") != std::string::npos);
    rnp_buffer_destroy(features);
    supported = false;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SM3", &supported));
    assert_true(supported);
    /* SM4 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM4") != std::string::npos);
    rnp_buffer_destroy(features);
    supported = false;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "SM4", &supported));
    assert_true(supported);
    /* Curve */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_CURVE, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM2 P-256") != std::string::npos);
    rnp_buffer_destroy(features);
    supported = false;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "SM2 P-256", &supported));
    assert_true(supported);
#else
    assert_false(sm2_enabled());
    /* SM2 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_PK_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM2") == std::string::npos);
    rnp_buffer_destroy(features);
    supported = true;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_PK_ALG, "SM2", &supported));
    assert_false(supported);
    /* SM3 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_HASH_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM3") == std::string::npos);
    rnp_buffer_destroy(features);
    supported = true;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_HASH_ALG, "SM3", &supported));
    assert_false(supported);
    /* SM4 */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM4") == std::string::npos);
    rnp_buffer_destroy(features);
    supported = true;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "SM4", &supported));
    assert_false(supported);
    /* Curve */
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_CURVE, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("SM2 P-256") == std::string::npos);
    rnp_buffer_destroy(features);
    supported = true;
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "SM2 P-256", &supported));
    assert_false(supported);
#endif
}

TEST_F(rnp_tests, test_aead_enabled)
{
    char *features = NULL;
    bool  supported = false;
    /* check whether FFI returns value which corresponds to defines */
#if defined(ENABLE_AEAD)
    bool has_eax = aead_eax_enabled();
    bool has_ocb = aead_ocb_enabled();
    assert_true(has_eax || has_ocb);
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_AEAD_ALG, &features));
    assert_non_null(features);
    assert_true((std::string(features).find("EAX") != std::string::npos) == has_eax);
    assert_true((std::string(features).find("OCB") != std::string::npos) == has_ocb);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "EAX", &supported));
    assert_true(supported == has_eax);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "OCB", &supported));
    assert_true(supported == has_ocb);
#else
    assert_false(aead_eax_enabled());
    assert_false(aead_ocb_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_AEAD_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("EAX") == std::string::npos);
    assert_true(std::string(features).find("OCB") == std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "EAX", &supported));
    assert_false(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_AEAD_ALG, "OCB", &supported));
    assert_false(supported);
#endif
}

TEST_F(rnp_tests, test_idea_enabled)
{
    char *features = NULL;
    bool  supported = false;
    /* check whether FFI returns value which corresponds to defines */
#if defined(ENABLE_IDEA)
    assert_true(idea_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("IDEA") != std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "IDEA", &supported));
    assert_true(supported);
#else
    assert_false(idea_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("IDEA") == std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "IDEA", &supported));
    assert_false(supported);
#endif
}

TEST_F(rnp_tests, test_twofish_enabled)
{
    char *features = NULL;
    bool  supported = false;
    /* check whether FFI returns value which corresponds to defines */
#if defined(ENABLE_TWOFISH)
    assert_true(twofish_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("TWOFISH") != std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "TWOFISH", &supported));
    assert_true(supported);
#else
    assert_false(twofish_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_SYMM_ALG, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("TWOFISH") == std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_SYMM_ALG, "TWOFISH", &supported));
    assert_false(supported);
#endif
}

TEST_F(rnp_tests, test_brainpool_enabled)
{
    char *features = NULL;
    bool  supported = false;
    /* check whether FFI returns value which corresponds to defines */
#if defined(ENABLE_BRAINPOOL)
    assert_true(brainpool_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_CURVE, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("brainpool") != std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP256r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP384r1", &supported));
    assert_true(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP512r1", &supported));
    assert_true(supported);
#else
    assert_false(brainpool_enabled());
    assert_rnp_success(rnp_supported_features(RNP_FEATURE_CURVE, &features));
    assert_non_null(features);
    assert_true(std::string(features).find("brainpool") == std::string::npos);
    rnp_buffer_destroy(features);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP256r1", &supported));
    assert_false(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP384r1", &supported));
    assert_false(supported);
    assert_rnp_success(rnp_supports_feature(RNP_FEATURE_CURVE, "brainpoolP512r1", &supported));
    assert_false(supported);
#endif
}

#if defined(CRYPTO_BACKEND_BOTAN)
TEST_F(rnp_tests, test_windows_botan_crash)
{
    /* Reproducer for https://github.com/randombit/botan/issues/3812 . Related CLI test
     * test_sym_encrypted__rnp_aead_botan_crash */

    auto data = file_to_vec("data/test_messages/message.aead-windows-issue-botan");
    /* First 32 bytes are encrypted key as it was extracted from the OpenPGP stream, so
     * skipping. */
    uint8_t *idx = data.data() + 32;
    uint8_t  bufbin[64] = {0};
    uint8_t  outbuf[32768] = {0};
    size_t   outsz = sizeof(outbuf);
    size_t   written = 0;
    size_t   read = 0;
    size_t   diff = 0;

    /* Now the data which exposes a possible crash */
    struct botan_cipher_struct *cipher = NULL;
    assert_int_equal(botan_cipher_init(&cipher, "AES-128/OCB", BOTAN_CIPHER_INIT_FLAG_DECRYPT),
                     0);

    const char *key2 = "417835a476bc5958b18d41fb00cf682d";
    assert_int_equal(rnp::hex_decode(key2, bufbin, 16), 16);
    assert_int_equal(botan_cipher_set_key(cipher, bufbin, 16), 0);

    const char *ad2 = "d40107020c0000000000000000";
    assert_int_equal(rnp::hex_decode(ad2, bufbin, 13), 13);
    assert_int_equal(botan_cipher_set_associated_data(cipher, bufbin, 13), 0);

    const char *nonce2 = "005dbbbe0088f9d17ca2d8d464920f";
    assert_int_equal(rnp::hex_decode(nonce2, bufbin, 15), 15);
    assert_int_equal(botan_cipher_start(cipher, bufbin, 15), 0);

    assert_int_equal(
      botan_cipher_update(cipher, 0, outbuf, outsz, &written, idx, 32736, &read), 0);
    diff = 32736 - read;
    idx += read;

    assert_int_equal(
      botan_cipher_update(cipher, 0, outbuf, outsz, &written, idx, diff + 32736, &read), 0);
    idx += read;
    diff = diff + 32736 - read;

    assert_int_equal(
      botan_cipher_update(cipher, 0, outbuf, outsz, &written, idx, diff + 32736, &read), 0);
    idx += read;
    diff = diff + 32736 - read;

    assert_int_equal(
      botan_cipher_update(cipher, 0, outbuf, outsz, &written, idx, diff + 32736, &read), 0);
    idx += read;
    diff = diff + 32736 - read;

    uint32_t ver_major = botan_version_major();
    uint32_t ver_minor = botan_version_minor();
    uint32_t ver_patch = botan_version_patch();
    uint32_t ver = (ver_major << 16) | (ver_minor << 8) | ver_patch;
    uint32_t ver_2_19_3 = (2 << 16) | (19 << 8) | 3;
    uint32_t ver_3_2_0 = (3 << 16) | (2 << 8);
    bool     check = true;
    /* Currently AV happens with versions up to 2.19.3 and 3.2.0 */
    if ((ver_major == 2) && (ver <= ver_2_19_3)) {
        check = false;
    }
    if ((ver_major == 3) && (ver <= ver_3_2_0)) {
        check = false;
    }

    if (check) {
        assert_int_equal(botan_cipher_update(cipher,
                                             BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                                             outbuf,
                                             outsz,
                                             &written,
                                             idx,
                                             diff + 25119,
                                             &read),
                         0);
    }

    assert_int_equal(botan_cipher_reset(cipher), 0);
    assert_int_equal(botan_cipher_destroy(cipher), 0);
}
#endif

/* Known-answer verification tests below use published vectors from the
 * Wycheproof project (https://github.com/C2SP/wycheproof, testvectors_v1,
 * Apache-2.0), complementing the self-generated roundtrip tests above with
 * signatures produced by an independent implementation. Only cases whose
 * structure survives the OpenPGP MPI encoding are embedded: the DER transport
 * formatting of the source files (tag/length mutations) does not apply at
 * this layer, since r/s/sig components are carried as MPIs, not ASN.1. */

static std::vector<uint8_t>
kat_hex_vec(const char *hex)
{
    std::vector<uint8_t> res(strlen(hex) / 2);
    if (!res.empty()) {
        rnp::hex_decode(hex, res.data(), res.size());
    }
    return res;
}

static void
kat_digest(rnp::secure_bytes &digest, pgp_hash_alg_t halg, const std::vector<uint8_t> &msg)
{
    auto hash = rnp::Hash::create(halg);
    digest.resize(rnp::Hash::size(halg));
    if (!msg.empty()) {
        hash->add(msg.data(), msg.size());
    }
    hash->finish(digest.data());
}

struct kat_rs_case {
    const char *msg;
    const char *r;
    const char *s;
    bool        valid;
};

TEST_F(rnp_tests, test_ecdsa_p256_kat)
{
    /* public point = 04 || wx || wy */
    pgp::ec::Key eckey;
    eckey.curve = PGP_CURVE_NIST_P_256;
    hex2mpi(&eckey.p,
            "042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c7328"
            "38c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e734151"
            "3e");

    auto material = pgp::KeyMaterial::create(PGP_PKA_ECDSA, eckey);
    assert_true(material);

    const kat_rs_case cases[] = {

      /* true: signature malleability */
      {"313233343030",
       "2BA3A8BE6B94D5EC80A6D9D1190A436EFFE50D85A1EEE859B8CC6AF9BD5C2E18",
       "4CD60B855D442F5B3C7B11EB6C4E0AE7525FE710FAB9AA7C77A67F79E6FADD76",
       true},

      /* true: valid */
      {"313233343030",
       "2BA3A8BE6B94D5EC80A6D9D1190A436EFFE50D85A1EEE859B8CC6AF9BD5C2E18",
       "B329F479A2BBD0A5C384EE1493B1F5186A87139CAC5DF4087C134B49156847DB",
       true},

      /* false: replacing r with zero */
      {"313233343030",
       "00",
       "B329F479A2BBD0A5C384EE1493B1F5186A87139CAC5DF4087C134B49156847DB",
       false},

      /* false: replaced r by r + n */
      {"313233343030",
       "012BA3A8BD6B94D5ED80A6D9D1190A436EBCCC0833490686DEAC8635BCB9BF53"
       "69",
       "B329F479A2BBD0A5C384EE1493B1F5186A87139CAC5DF4087C134B49156847DB",
       false},

      /* false: replaced r by -r */
      {"313233343030",
       "D45C5741946B2A137F59262EE6F5BC91001AF27A5E1117A64733950642A3D1E8",
       "B329F479A2BBD0A5C384EE1493B1F5186A87139CAC5DF4087C134B49156847DB",
       false},

      /* false: replaced s by s + n */
      {"313233343030",
       "01B329F478A2BBD0A6C384EE1493B1F518276E0E4A5375928D6FCD160C11CB6D"
       "2C",
       "B329F479A2BBD0A5C384EE1493B1F5186A87139CAC5DF4087C134B49156847DB",
       false},

      /* false: replaced s by -s */
      {"313233343030",
       "FF4CD60B865D442F5A3C7B11EB6C4E0AE79578EC6353A20BF783ECB4B6EA97B8"
       "25",
       "B329F479A2BBD0A5C384EE1493B1F5186A87139CAC5DF4087C134B49156847DB",
       false},

      /* true: Edge case for Shamir multiplication */
      {"3639383139",
       "64A1AAB5000D0E804F3E2FC02BDEE9BE8FF312334E2BA16D11547C97711C898E",
       "6AF015971CC30BE6D1A206D4E013E0997772A2F91D73286FFD683B9BB2CF4F1B",
       true},

    };

    for (const auto &c : cases) {
        auto              msg = kat_hex_vec(c.msg);
        rnp::secure_bytes digest;
        kat_digest(digest, PGP_HASH_SHA256, msg);
        pgp::ECSigMaterial sig(PGP_HASH_SHA256);
        assert_true(hex2mpi(&sig.sig.r, c.r));
        assert_true(hex2mpi(&sig.sig.s, c.s));
        if (c.valid) {
            assert_rnp_success(material->verify(global_ctx, sig, digest));
        } else {
            assert_rnp_failure(material->verify(global_ctx, sig, digest));
        }
    }
}

TEST_F(rnp_tests, test_dsa_2048_224_kat)
{
    pgp::dsa::Key dsakey;

    hex2mpi(&dsakey.p,
            "8f7935d9b9aae9bfabed887acf4951b6f32ec59e3baf3718e8eac4961f3efd36"
            "06e74351a9c4183339b809e7c2ae1c539ba7475b85d011adb8b4798775498469"
            "5cac0e8f14b3360828a22ffa27110a3d62a993453409a0fe696c4658f84bdd20"
            "819c3709a01057b195adcd00233dba5484b6291f9d648ef883448677979cec04"
            "b434a6ac2e75e9985de23db0292fc1118c9ffa9d8181e7338db792b730d7b9e3"
            "49592f68099872153915ea3d6b8b4653c633458f803b32a4c2e0f27290256e4e"
            "3f8a3b0838a1c450e4e18c1a29a37ddf5ea143de4b66ff04903ed5cf1623e158"
            "d487c608e97f211cd81dca23cb6e380765f822e342be484c05763939601cd667");

    hex2mpi(&dsakey.q, "baf696a68578f7dfdee7fa67c977c785ef32b233bae580c0bcd5695d");

    hex2mpi(&dsakey.g,
            "16a65c58204850704e7502a39757040d34da3a3478c154d4e4a5c02d242ee04f"
            "96e61e4bd0904abdac8f37eeb1e09f3182d23c9043cb642f88004160edf9ca09"
            "b32076a79c32a627f2473e91879ba2c4e744bd2081544cb55b802c368d1fa83e"
            "d489e94e0fa0688e32428a5c78c478c68d0527b71c9a3abb0b0be12c44689639"
            "e7d3ce74db101a65aa2b87f64c6826db3ec72f4b5599834bb4edb02f7c90e9a4"
            "96d3a55d535bebfc45d4f619f63f3dedbb873925c2f224e07731296da887ec1e"
            "4748f87efb5fdeb75484316b2232dee553ddaf02112b0d1f02da30973224fe27"
            "aeda8b9d4b2922d9ba8be39ed9e103a63c52810bc688b7e2ed4316e1ef17dbde");

    hex2mpi(&dsakey.y,
            "1e77f842b1ae0fcd9929d394161d41e14614ff7507a9a31f4a1f14d22e2a627a"
            "1f4e596624883f1a5b168e9425146f22d5f6ee28757414714bb994ba1129f015"
            "d6e04a717edf9b530a5d5cab94f14631e8b4cf79aeb358cc741845553841e8ac"
            "461630e804a62f43676ba6794af66899c377b869ea612a7b9fe6611aa96be52e"
            "b8b62c979117bbbcca8a7ec1e1ffab1c7dfcfc7048700d3ae3858136e897701d"
            "7c2921b5dfef1d1f897f50d96ca1b5c2edc58cada18919e35642f0807eebfa00"
            "c99a32f4d095c3188f78ed54711be0325c4b532aeccd6540a567c327225440ea"
            "15319bde06510479a1861799e25b57decc73c036d75a0702bd373ca231349931");

    auto material = pgp::KeyMaterial::create(dsakey);
    assert_true(material);

    const kat_rs_case cases[] = {

      /* true: valid */
      {"313233343030",
       "A545D62D6E336775FB6A9B8495721646A54BD8C6173FC0A2295A1B7B",
       "068259CF902E5D55EB26E7BF850A82D40FC5456B3A902679612EA4A8",
       true},

      /* false: replacing s with zero */
      {"313233343030",
       "A545D62D6E336775FB6A9B8495721646A54BD8C6173FC0A2295A1B7B",
       "00",
       false},

      /* false: replaced r by r + q */
      {"313233343030",
       "01603C6CD3F3AC5F55DA5295EC5EE9DDCC947E8AF9D2254162E62F84D8",
       "068259CF902E5D55EB26E7BF850A82D40FC5456B3A902679612EA4A8",
       false},

      /* false: replaced r by -r */
      {"313233343030",
       "FF5ABA29D291CC988A0495647B6A8DE9B95AB42739E8C03F5DD6A5E485",
       "068259CF902E5D55EB26E7BF850A82D40FC5456B3A902679612EA4A8",
       false},

      /* false: replaced s by -s */
      {"313233343030",
       "F97DA6306FD1A2AA14D918407AF57D2BF03ABA94C56FD9869ED15B58",
       "068259CF902E5D55EB26E7BF850A82D40FC5456B3A902679612EA4A8",
       false},

      /* true: pseudorandom signatures */
      {"313233343030",
       "A939DF97DDBE605A925E2456ACC196CEEA94410D54EED9D501BEFB90",
       "2F50CE7BAC70F84F265794A3ADA363F9AFACF7B88C5273E23CAC5E55",
       true},

      /* true: pseudorandom signatures */
      {"313233343030",
       "3B98FA1F5EA18AF8E2878571152F257ACCF243342582A757535F4A46",
       "1D86C74F77CDE3FDEB48EFA02CA06A5264981310FA5922339D52DFFF",
       true},

    };

    for (const auto &c : cases) {
        auto              msg = kat_hex_vec(c.msg);
        rnp::secure_bytes digest;
        kat_digest(digest, PGP_HASH_SHA224, msg);
        pgp::DSASigMaterial sig(PGP_HASH_SHA224);
        assert_true(hex2mpi(&sig.sig.r, c.r));
        assert_true(hex2mpi(&sig.sig.s, c.s));
        if (c.valid) {
            assert_rnp_success(material->verify(global_ctx, sig, digest));
        } else {
            assert_rnp_failure(material->verify(global_ctx, sig, digest));
        }
    }
}

TEST_F(rnp_tests, test_rsa_2048_kat)
{
    pgp::rsa::Key rsakey;

    hex2mpi(&rsakey.n,
            "a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e6"
            "37f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097"
            "b5ab393189db92512ed8a7711a1253facd20f79c15e8247f3d3e42e46e48c98e"
            "254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490ed81299615d981"
            "4c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b"
            "4c03145b5d3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a19"
            "69816f48698bcbba1b4d9cae79d460d8f9f85e7975005d9bc22c4e5ac0f7c1a4"
            "5d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f742b9d5");

    hex2mpi(&rsakey.e, "010001");

    auto material = pgp::KeyMaterial::create(PGP_PKA_RSA, rsakey);
    assert_true(material);

    struct kat_rsa_case {
        const char *msg;
        const char *sig;
        bool        valid;
    };
    const kat_rsa_case cases[] = {

      /* true */
      {"",
       "840F5DAC53106DD1F9C57219224CF51289290C42F20466875BA8E830AC5690E5"
       "41536FCC8AB03B731F82BF66D83F194E7E180B3963EC7A2F3F7904A7CE49AED4"
       "7DA4D4B79421EAF937D301B3E696169297B797C32C076A12BE4DE0B58E003C51"
       "23051A84A10C62F8DAC2F42A8640008EB3C7CCCD6760FF5B51B6897639225828"
       "45F048FB8150E5A7A6CA2ECCC7BDC85349AD5B26C52137A79FA3FE5C29AB5CD7"
       "615013219C1941B6708E9C3C23FEFF5FEBAF0C8EBCA5750B54E3E6E99A3E876B"
       "396F27860B7F3EC4E9191703C6332D944F6F69751167680C79C4F6B57F1CC875"
       "5D24B6EC158CCDBACDB23107A33CB6B332516C13274D1F9DCCC21DCED869E486",
       true},

      /* true */
      {"0000000000000000000000000000000000000000",
       "8A1B220CB2AB415DC760EB7F5BB10335A3CCA269D7DBBF7D0962BA79F9CF7B43"
       "A5FC09C99A1584F07403473D6C189A836897A5B6F8EA9FA22D601E6BA5F7411F"
       "E27C638B81B1A22363583A80FCE8C7DF3E40FB51BD0E60D0A6653F79F3BCB7EC"
       "3E9DC14CFB5B31AB1735BCA692D50AC03F979DDA92747C6430F8045EFA3513BA"
       "6E0CE3E9E35570E1C30C8EBE589B44192E1344CA83DFA576FC6FDC7BF1CD7CEE"
       "875B001C8C02CE8D602769E4BD9D241C4857182A0089A8B67644E73EEF105C55"
       "0EFA47A40874289395AC0C4E02FD4BA98E130A4C2D1B95521C6AF4A002AC3BDC"
       "6E52122AE4C08CC3DA1C896E059ACBDDEC574AC0432F6103DD97273D8803C102",
       true},

      /* true */
      {"54657374",
       "264491E844C119F14E425C03282139A558DCDAEB82A4628173CD407FD319F907"
       "6EAEBC0DD87A1C22E4D17839096886D58A9D5B7F7AEB63EFEC56C45AC7BEAD42"
       "03B6886E1FAA90E028EC0AE094D46BF3F97EFDD19045CFBC25A1ABDA2432639F"
       "9876405C0D68F8EDBF047C12A454F7681D5D5A2B54BD3723D193DBAD4338BAAD"
       "753264006E2D08931C4B8BB79AA1C9CAD10EB6605F87C5831F6E2B08E002F9C6"
       "F21141F5841D92727DD3E1D99C36BC560DA3C9067DF99FCAF818941F72588BE3"
       "3032BAD22CAF6704223BB114D575B6D02D9D222B580005D930E8F40CCE9F672E"
       "EBB634A20177D84351627964B83F2053D736A84AB1A005F63BD5BA943DE6205C",
       true},

      /* false: The message is hashed with SHA-1 instead of  */
      {"313233343030",
       "3EC58A94C9495ECEC016BABF77FA114D78097E484840D82C3CFE7DE98D2EE21B"
       "499992BFE3A778161E781F89D20745BFD1EA6037C2E7FD67C3F95479315DDA5B"
       "87FB53BADF0B813F28410DE6E79A11B351B1668586500917FEB44AAE0FC18BA6"
       "DE2BDFB6444D89B9B8B67490C1F2B81E3081E5C5C7C39F4F8F9BCA2AE2A92464"
       "65610A9E6A5A67162A3A40857FEA59E128F21903AFA9143BFF67DF9679918A0F"
       "5C7288AF9154F096C03A13601DB5724356131051CE39037C6B870BFCA5198CB9"
       "385137B7CF5383630B459CC6132B7AC611D13712F91B2911B9F8526E02A8C61A"
       "CB7D184A7C6D86D6246CDC6BD13174B6969E5033BB90C4ABAA907968EDEEC362",
       false},

      /* false: invalid PKCS#1 signature padding: 0001ff...e */
      {"313233343030",
       "4B140ACB262C451B0761236B926AFA2829E8A095828F7DCF196EAF7FA46FDCF7"
       "FBCAF194AA3000AE8D3DC7DACC26952502B1558A67FB692DA5FCC7DBF48CBC52"
       "60E2B2A7041FDF7BF46F531D4EF48998DFCB65E182065535AAF182AE6ABF6E81"
       "9E7D96EC86178137A3C14383F89438AB35F0DC7698E1811C415E163F8BAC5435"
       "DDDBA5DB55AA6B393D538D31B34332FCC34EF8E6EB059D4CC453297D6895BA48"
       "0593A5536A4E553A55417295B6F6798734DF67E739E54D3092DE4F476CC0F65A"
       "AC6950631081DF1116097A7F6A9D00A1AFBE0CE6B2BD32EF22ACC95219F05DF9"
       "FB7E9A8B391E6277CFFEDA298BF094730F5663172183DC5842056DE36137EE90",
       false},

      /* false: the signature is not reduced */
      {"313233343030",
       "BA0D3D34D59915BE6351725300FFF4617210FA767B6C48522900CE2E2C8F88B3"
       "F855BC9DE7609603F2F405A81D3D6C1B8AC05A79FD278BB9C6AF6DC90A6323C5"
       "D77C0562CDED072BB63E9CE533D9CA497479ECF7D75E6B6A4D4A86418909B865"
       "21C5D6C7D5D634352D2ED6B15B16873F26B918E31B81E9363AD0AB373E7AC982"
       "E6AA3ECCAA4CB6DBC1A807B73082DFAC6A5D7B2ABBB0A8D3F12F3C8AAC976FE6"
       "6B44350A2B7A8840F53BCD1FE76D9A0BDEC6C6EACFC2081B58C3E818F2E40BB8"
       "D07B360C5FCE83ECE59267D39141C87807FDBEE5B4ED5FC86E51111A57020211"
       "A593E4D91A6DD0EBDE6317EBC12F52F405415527E7DF07BA8AF42ECBEFC41D7D",
       false},

      /* false: the signature is not reduced */
      {"313233343030",
       "CBAA8C11633469333A628D32E51AF55AB1E1E55F0BA468446F532B1766924A05"
       "B9D0B5702493B949535330CAAE75D6D874B5BD24ADDC6515B1FC81A6C62F6AE3"
       "CD09FDBB1FA3C609600D668E2C1B711BC8509171A99AC6284E4F27CB638A7CFC"
       "46AB9054B296C0D3EDBE5F7B199F977FCC3BE1065BDAB6D2976453A3BE3E714D"
       "BD61C56FCF0472BCDA6A08A05511AA0E19896ADEA8B76E8C9CF397F97E470CC7"
       "22557C0C02DBC7595BF9A6BBED8EF1035C4808B673B5583CAA82BAB3F9A6CB08"
       "E8690F2D820E724E17E1799EEBCE40990663D9E1404A9DEED8731D808DCBE4CA"
       "5AD828A1386A8F4A4745D77777BAE65CDB393763D8C176151574B03F3B3B38A8",
       false},

      /* false: the signature has value n */
      {"313233343030",
       "A2B451A07D0AA5F96E455671513550514A8A5B462EBEF717094FA1FEE82224E6"
       "37F9746D3F7CAFD31878D80325B6EF5A1700F65903B469429E89D6EAC8845097"
       "B5AB393189DB92512ED8A7711A1253FACD20F79C15E8247F3D3E42E46E48C98E"
       "254A2FE9765313A03EFF8F17E1A029397A1FA26A8DCE26F490ED81299615D981"
       "4C22DA610428E09C7D9658594266F5C021D0FCECA08D945A12BE82DE4D1ECE6B"
       "4C03145B5D3495D4ED5411EB878DAF05FD7AFC3E09ADA0F1126422F590975A19"
       "69816F48698BCBBA1B4D9CAE79D460D8F9F85E7975005D9BC22C4E5AC0F7C1A4"
       "5D12569A62807D3B9A02E5A530E773066F453D1F5B4C2E9CF7820283F742B9D5",
       false},

      /* false: the signature has value -1 */
      {"313233343030",
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
       false},

    };

    for (const auto &c : cases) {
        auto              msg = kat_hex_vec(c.msg);
        rnp::secure_bytes digest;
        kat_digest(digest, PGP_HASH_SHA256, msg);
        pgp::RSASigMaterial sig(PGP_HASH_SHA256);
        assert_true(hex2mpi(&sig.sig.s, c.sig));
        if (c.valid) {
            assert_rnp_success(material->verify(global_ctx, sig, digest));
        } else {
            assert_rnp_failure(material->verify(global_ctx, sig, digest));
        }
    }
}
