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

#include "config.h"
#include <rnp/rnp_types.h>
#include "pgp-key.h"
#include "crypto.h"
#include <string.h>

/* low-level key generation example */
int
generate_lowlevel_25519()
{
    rng_t                       rng = {}; /* random number generator */
    rnp_key_store_t *           pubring = NULL;
    rnp_key_store_t *           secring = NULL;
    pgp_key_t                   key_sec = {}; /* primary secret & public keys */
    pgp_key_t                   key_pub = {};
    pgp_key_t                   sub_sec = {}; /* secret & public subkey */
    pgp_key_t                   sub_pub = {};
    pgp_key_t *                 keyptr = NULL;
    rnp_keygen_primary_desc_t   key_params = {};   /* primary key generation params */
    rnp_keygen_subkey_desc_t    sub_params = {};   /* subkey generation params */
    rnp_key_protection_params_t protection = {};   /* secret key/subkey encryption params */
    key_store_format_t key_format = GPG_KEY_STORE; /* secret key format, OpenPGP/GPG keys */
    pgp_password_provider_t prov = {};             /* password source */
    char *                  exported_key;
    int                     result = 1; /* error return */

    /* initialize rng */
    if (!rng_init(&rng, RNG_SYSTEM)) {
        fprintf(stdout, "Failed to initialize RNG\n");
        goto finish;
    }

    /* setup key and subkey generation params, let's have Ed25519/X25519 keypair */
    /* we set only basic fields, other will be set by default. You may control here key flags,
     * preferred algorithms, and so on */
    key_params.crypto = {.key_alg = PGP_PKA_EDDSA,
                         .hash_alg = PGP_HASH_SHA256,
                         .rng = &rng,
                         .ecc = {.curve = PGP_CURVE_ED25519}};
    key_params.cert = {
      .userid = "25519@key", .key_expiration = 365 * 24 * 60 * 60, .primary = 1};
    sub_params.crypto = {.key_alg = PGP_PKA_ECDH,
                         .hash_alg = PGP_HASH_SHA256,
                         .rng = &rng,
                         .ecc = {.curve = PGP_CURVE_25519}};
    sub_params.binding = {.key_expiration = 180 * 24 * 60 * 60};

    if (!pgp_generate_keypair(&rng,
                              &key_params,
                              &sub_params,
                              true,
                              &key_sec,
                              &key_pub,
                              &sub_sec,
                              &sub_pub,
                              key_format)) {
        fprintf(stdout, "failed to generate keys\n");
        goto finish;
    }

    /* setup key encryption parameters: hash for key derivation, symmetric algorithm, and key
     * derivation iterations */
    protection = {.hash_alg = PGP_HASH_SHA256,
                  .symm_alg = PGP_SA_AES_256,
                  .iterations = (unsigned) pgp_s2k_compute_iters(PGP_HASH_SHA256, 100, 10)};
    prov = {.callback = rnp_password_provider_string, .userdata = (void *) "password"};
    /* encrypt secret key and subkey with password */
    if (!rnp_key_add_protection(&key_sec, key_format, &protection, &prov)) {
        fprintf(stdout, "failed to encrypt primary key\n");
        goto finish;
    }

    if (!rnp_key_add_protection(&sub_sec, key_format, &protection, &prov)) {
        fprintf(stdout, "failed to encrypt subkey\n");
        goto finish;
    }

    /* allocate keyrings */
    pubring = rnp_key_store_new(RNP_KEYSTORE_GPG, "pubring.pgp");
    secring = rnp_key_store_new(RNP_KEYSTORE_GPG, "secring.pgp");
    if (!pubring || !secring) {
        fprintf(stdout, "allocation failed\n");
        goto finish;
    }

    /* add keys and subkeys to corresponding keyrings. This transfers ownership on key data */
    if (!rnp_key_store_add_key(secring, &key_sec) ||
        !rnp_key_store_add_key(secring, &sub_sec) ||
        !rnp_key_store_add_key(pubring, &key_pub) ||
        !rnp_key_store_add_key(pubring, &sub_pub)) {
        fprintf(stdout, "failed to add keys to key store\n");
        goto finish;
    }

    /* write keyrings to files */
    if (!rnp_key_store_write_to_file(secring, 0) || !rnp_key_store_write_to_file(pubring, 0)) {
        fprintf(stdout, "failed to write keyring\n");
        goto finish;
    }

    /* let's print armored keys to the stdout as well */
    fprintf(stdout, "%s", "Curve 25519 key:\n");
    /* public key part */
    keyptr = rnp_key_store_get_key_by_name(pubring, "25519@key", NULL);
    exported_key = pgp_export_key(pubring, keyptr);
    fprintf(stdout, "%s", exported_key);
    free(exported_key);
    /* secret key part */
    keyptr = rnp_key_store_get_key_by_name(secring, "25519@key", NULL);
    exported_key = pgp_export_key(secring, keyptr);
    fprintf(stdout, "%s", exported_key);
    free(exported_key);

    result = 0;
finish:
    rnp_key_store_free(pubring);
    rnp_key_store_free(secring);
    rng_destroy(&rng);
    return result;
}

int
generate_highlevel_rsa()
{
    rnp_t                       rnp = {};
    rnp_params_t                params = {};
    rnp_keygen_primary_desc_t   key_params = {}; /* primary key generation params */
    rnp_keygen_subkey_desc_t    sub_params = {}; /* subkey generation params */
    rnp_key_protection_params_t protection = {}; /* secret key/subkey encryption params */
    pgp_key_t *                 key = NULL;
    char *                      exported_key = NULL;
    int                         result = 2;

    /* setup rnp parameters */
    rnp_params_init(&params);
    params.pubpath = strdup("pubring.pgp");
    params.secpath = strdup("secring.pgp");
    params.ks_pub_format = RNP_KEYSTORE_GPG;
    params.ks_sec_format = RNP_KEYSTORE_GPG;
    params.password_provider = {.callback = rnp_password_provider_string,
                                .userdata = (void *) "password"};

    if (rnp_init(&rnp, &params) != RNP_SUCCESS) {
        fprintf(stdout, "failed to init rnp\n");
        goto finish;
    }

    if (!rnp_key_store_load_keys(&rnp, true)) {
        fprintf(stdout, "warning - failed to load keyrings\n");
    }

    /* setup key/subkey generation and encryption parameters */
    key_params.crypto = {
      .key_alg = PGP_PKA_RSA, .hash_alg = PGP_HASH_SHA256, .rsa = {.modulus_bit_len = 2048}};
    key_params.cert = {
      .userid = "rsa@key", .key_expiration = 365 * 24 * 60 * 60, .primary = 1};
    sub_params.crypto = {
      .key_alg = PGP_PKA_RSA, .hash_alg = PGP_HASH_SHA256, .rsa = {.modulus_bit_len = 2048}};
    sub_params.binding = {.key_expiration = 180 * 24 * 60 * 60};
    protection = {.hash_alg = PGP_HASH_SHA256,
                  .symm_alg = PGP_SA_AES_256,
                  .iterations = (unsigned) pgp_s2k_compute_iters(PGP_HASH_SHA256, 100, 10)};

    rnp.action.generate_key_ctx.primary.keygen = key_params;
    rnp.action.generate_key_ctx.primary.protection = protection;
    rnp.action.generate_key_ctx.subkey.keygen = sub_params;
    rnp.action.generate_key_ctx.subkey.protection = protection;

    if (!(key = rnp_generate_key(&rnp))) {
        fprintf(stdout, "failed to generate key\n");
        goto finish;
    }

    /* let's print armored keys to the stdout as well */
    fprintf(stdout, "%s", "RSA key:\n");
    /* public key part */
    exported_key = rnp_export_key(&rnp, "rsa@key", false);
    fprintf(stdout, "%s", exported_key);
    free(exported_key);
    /* secret key part */
    exported_key = rnp_export_key(&rnp, "rsa@key", true);
    fprintf(stdout, "%s", exported_key);
    free(exported_key);
    result = 0;
finish:
    rnp_params_free(&params);
    rnp_end(&rnp);
    return result;
}

int
main(int argc, char **argv)
{
    int res = generate_lowlevel_25519();
    if (res) {
        return res;
    }

    res = generate_highlevel_rsa();
    return res;
}