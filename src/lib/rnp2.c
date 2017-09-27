/*-
 * Copyright (c) 2017 Ribose Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <rnp/rnp2.h>
#include "list.h"
#include "crypto.h"
#include "signature.h"
#include "pgp-key.h"
#include <librepgp/validate.h>
#include "hash.h"
#include <rnp/rnp_types.h>
#include <stdlib.h>

struct rnp_passphrase_cb_data {
    rnp_passphrase_cb cb_fn;
    void *            cb_data;
};

struct rnp_keyring_st {
    rnp_t                         rnp_ctx;
    struct rnp_passphrase_cb_data cb;
};

struct rnp_key_st {
    pgp_key_t *key;
};

static pgp_key_t *
find_suitable_subkey(const pgp_key_t *primary, uint8_t desired_usage)
{
    // fixme copied fron rnp.c
    if (!primary || DYNARRAY_IS_EMPTY(primary, subkey)) {
        return NULL;
    }
    // search in reverse with the assumption that the last
    // in the list would be the newest created subkey, for now
    for (unsigned i = primary->subkeyc; i-- > 0;) {
        pgp_key_t *subkey = primary->subkeys[i];
        if (subkey->key_flags & desired_usage) {
            return subkey;
        }
    }
    return NULL;
}

static bool
rnp_passphrase_cb_bounce(const pgp_passphrase_ctx_t *ctx,
                         char *                      passphrase,
                         size_t                      passphrase_size,
                         void *                      userdata_void)
{
    printf("callback?\n");
    struct rnp_passphrase_cb_data *userdata = (struct rnp_passphrase_cb_data *) userdata_void;
    int                            rc = userdata->cb_fn(
      userdata->cb_data, "TODO create a context string", passphrase, passphrase_size);

    return (rc == 0);
}

const char *
rnp_result_to_string(rnp_result_t result)
{
    switch (result) {
    case RNP_SUCCESS:
        return "Success";

    case RNP_ERROR_GENERIC:
        return "Unknown error";
    case RNP_ERROR_BAD_FORMAT:
        return "Bad format";
    case RNP_ERROR_BAD_PARAMETERS:
        return "Bad parameters";
    case RNP_ERROR_NOT_IMPLEMENTED:
        return "Not implemented";
    case RNP_ERROR_NOT_SUPPORTED:
        return "Not supported";
    case RNP_ERROR_OUT_OF_MEMORY:
        return "Out of memory";
    case RNP_ERROR_SHORT_BUFFER:
        return "Buffer too short";
    case RNP_ERROR_NULL_POINTER:
        return "Null pointer";

    case RNP_ERROR_ACCESS:
        return "Error accessing file";
    case RNP_ERROR_READ:
        return "Error reading file";
    case RNP_ERROR_WRITE:
        return "Error writing file";

    case RNP_ERROR_BAD_STATE:
        return "Bad state";
    case RNP_ERROR_MAC_INVALID:
        return "Invalid MAC";
    case RNP_ERROR_SIGNATURE_INVALID:
        return "Invalid signature";
    case RNP_ERROR_KEY_GENERATION:
        return "Error during key generation";
    case RNP_ERROR_KEY_NOT_FOUND:
        return "Key not found";
    case RNP_ERROR_NO_SUITABLE_KEY:
        return "Not suitable key";
    case RNP_ERROR_DECRYPT_FAILED:
        return "Decryption failed";
    case RNP_ERROR_NO_SIGNATURES_FOUND:
        return "No signatures found cannot verify";

    case RNP_ERROR_NOT_ENOUGH_DATA:
        return "Not enough data";
    case RNP_ERROR_UNKNOWN_TAG:
        return "Unknown tag";
    case RNP_ERROR_PACKET_NOT_CONSUMED:
        return "Packet not consumed";
    case RNP_ERROR_NO_USERID:
        return "Not userid";
    case RNP_ERROR_EOF:
        return "EOF detected";
    }

    return "Unknown error";
}

rnp_result_t
rnp_keyring_open(rnp_keyring_t *   keyring,
                 const char *      keyring_format,
                 const char *      pub_path,
                 const char *      sec_path,
                 rnp_passphrase_cb cb,
                 void *            cb_data)
{
    *keyring = calloc(1, sizeof(struct rnp_keyring_st));
    if (!keyring)
        return RNP_ERROR_OUT_OF_MEMORY;

    (*keyring)->cb.cb_fn = cb;
    (*keyring)->cb.cb_data = cb_data;

    rnp_params_t rnp_params;
    memset(&rnp_params, 0, sizeof(rnp_params));

    rnp_params.ks_pub_format = keyring_format;
    rnp_params.ks_sec_format = keyring_format;

    rnp_params.pubpath = (char *) pub_path;
    rnp_params.secpath = (char *) sec_path;

    rnp_params.passphrase_provider = (pgp_passphrase_provider_t){
      .callback = rnp_passphrase_cb_bounce, .userdata = &((*keyring)->cb)};

    rnp_result_t res = rnp_init(&(*keyring)->rnp_ctx, &rnp_params);

    return res;
}

static pgp_key_t *
resolve_userid(rnp_t *rnp, const rnp_key_store_t *keyring, const char *userid)
{
    pgp_key_t *key = NULL;

    if (userid == NULL) {
        return NULL;
    }

    if ((strlen(userid) > 1) && userid[0] == '0' && userid[1] == 'x') {
        userid += 2;
    }

    rnp_key_store_get_key_by_name(rnp->io, keyring, userid, &key);
    return key;
}

static pgp_key_t *
resolve_public_key(rnp_t *rnp, const char *userid)
{
    return resolve_userid(rnp, rnp->pubring, userid);
}

rnp_result_t
rnp_keyring_close(rnp_keyring_t keyring)
{
    if (keyring != NULL) {
        rnp_end(&keyring->rnp_ctx);
        free(keyring);
    }
    return RNP_SUCCESS;
}

rnp_result_t
rnp_insert_public_key(rnp_keyring_t keyring,
                      const char *  key_format,
                      const uint8_t key_bits[],
                      size_t        key_len)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_insert_armored_public_key(rnp_keyring_t keyring, const char *key)
{
    rnp_result_t     rc = RNP_ERROR_GENERIC;
    rnp_key_store_t *tmp_keystore = NULL;
    list             imported_grips = NULL;
    list_item *      item = NULL;

    tmp_keystore = rnp_key_store_new(RNP_KEYSTORE_GPG, "");
    if (!tmp_keystore) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    pgp_memory_t *membuf = pgp_memory_new();
    pgp_memory_add(membuf, (const uint8_t *) key, strlen(key));

    bool ret = rnp_key_store_load_from_mem(&keyring->rnp_ctx, tmp_keystore, 1, membuf);

    pgp_memory_free(membuf);

    if (ret == false || tmp_keystore->keyc == 0) {
        return RNP_ERROR_BAD_FORMAT;
    }

    rnp_t *rnp = &keyring->rnp_ctx;
    // loop through each key
    for (unsigned i = 0; i < tmp_keystore->keyc; i++) {
        pgp_key_t *      key = &tmp_keystore->keys[i];
        pgp_key_t *      importedkey = NULL;
        rnp_key_store_t *dest = pgp_is_key_secret(key) ? rnp->secring : rnp->pubring;

        // check if it already exists
        importedkey = rnp_key_store_get_key_by_grip(rnp->io, dest, key->grip);
        if (!importedkey) {
            // add it to the dest store
            if (!rnp_key_store_add_key(rnp->io, dest, key)) {
                rc = RNP_ERROR_WRITE;
                goto done;
            }
            // keep track of what keys have been imported
            list_append(&imported_grips, key->grip, sizeof(key->grip));
            importedkey = rnp_key_store_get_key_by_grip(rnp->io, dest, key->grip);
            for (unsigned j = 0; j < key->subkeyc; j++) {
                pgp_key_t *subkey = key->subkeys[j];

                if (!rnp_key_store_add_key(rnp->io, dest, subkey)) {
                    rc = RNP_ERROR_WRITE;
                    goto done;
                }
                // fix up the subkeys dynarray pointers...
                importedkey->subkeys[j] =
                  rnp_key_store_get_key_by_grip(rnp->io, dest, subkey->grip);
                // keep track of what keys have been imported
                list_append(&imported_grips, subkey->grip, sizeof(subkey->grip));
            }
        }
    }

    // update the keyrings on disk
    if (!rnp_key_store_write_to_file(rnp, rnp->secring, 0) ||
        !rnp_key_store_write_to_file(rnp, rnp->pubring, 0)) {
        RNP_LOG("failed to write keyring");
        goto done;
    }

    rc = RNP_SUCCESS;

done:
    // remove all the imported keys from the temporary store,
    // since we're taking ownership of their internal data
    item = list_front(imported_grips);
    while (item) {
        uint8_t *grip = (uint8_t *) item;
        rnp_key_store_remove_key(
          rnp->io, tmp_keystore, rnp_key_store_get_key_by_grip(rnp->io, tmp_keystore, grip));
        item = list_next(item);
    }
    list_destroy(&imported_grips);
    rnp_key_store_free(tmp_keystore);
    return rc;
}

rnp_result_t
rnp_export_public_key(rnp_key_t key, uint32_t flags, char **buf, size_t *buf_len)
{
    pgp_output_t *output;
    pgp_memory_t *mem;

    bool armor = (flags & RNP_EXPORT_FLAG_ARMORED);

    if (key == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (!pgp_setup_memory_write(NULL, &output, &mem, 128)) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    pgp_write_xfer_pubkey(output, key->key, NULL, armor);

    *buf_len = pgp_mem_len(mem);
    if (armor)
        *buf_len += 1;

    *buf = malloc(*buf_len);

    if (*buf == NULL) {
        pgp_teardown_memory_write(output, mem);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    memcpy(*buf, pgp_mem_data(mem), pgp_mem_len(mem));

    if (armor)
        buf[*buf_len - 1] = 0;

    return RNP_SUCCESS;
}

rnp_result_t
rnp_sign(rnp_keyring_t keyring,
         const char *  userid,
         const char *  hash_fn,
         bool          clearsign,
         bool          armor,
         const uint8_t msg[],
         size_t        msg_len,
         uint8_t **    sig,
         size_t *      sig_len)
{
    if (msg == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (clearsign == true && armor == false) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    pgp_key_t *keypair = resolve_userid(&keyring->rnp_ctx, keyring->rnp_ctx.pubring, userid);
    if (keypair == NULL) {
        return RNP_ERROR_KEY_NOT_FOUND;
    }
    if (pgp_key_can_sign(keypair) == false) {
        keypair = find_suitable_subkey(keypair, PGP_KF_SIGN);
        if (!keypair)
            return RNP_ERROR_NO_SUITABLE_KEY;
    }

    // key exist and might be used to sign, trying get it from secring
    unsigned from = 0;

    keypair = rnp_key_store_get_key_by_id(
      keyring->rnp_ctx.io, keyring->rnp_ctx.secring, keypair->keyid, &from, NULL);

    if (keypair == NULL) {
        return RNP_ERROR_KEY_NOT_FOUND;
    }

    const pgp_seckey_t *seckey = NULL;
    pgp_seckey_t *      decrypted_seckey = NULL;

    if (pgp_key_is_locked(keypair)) {
        decrypted_seckey =
          pgp_decrypt_seckey(keypair,
                             &keyring->rnp_ctx.passphrase_provider,
                             &(pgp_passphrase_ctx_t){.op = PGP_OP_SIGN, .key = keypair});
        if (decrypted_seckey == NULL) {
            return RNP_ERROR_DECRYPT_FAILED;
        }
        seckey = decrypted_seckey;
    } else {
        seckey = &keypair->key.seckey;
    }

    if (!seckey) {
        return RNP_ERROR_DECRYPT_FAILED;
    }
    /* sign file */

    rnp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rnp = &keyring->rnp_ctx;
    ctx.halg = pgp_str_to_hash_alg(hash_fn);
    ctx.armour = armor;

    pgp_memory_t *signedmem =
      pgp_sign_buf(&ctx, keyring->rnp_ctx.io, msg, msg_len, seckey, clearsign);

    if (signedmem == NULL) {
        return RNP_ERROR_GENERIC;
    }

    *sig_len = pgp_mem_len(signedmem);
    if (ctx.armour)
        *sig_len += 1;

    *sig = calloc(1, *sig_len);
    if (*sig == NULL) {
        pgp_seckey_free(decrypted_seckey);
        free(decrypted_seckey);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    memcpy(*sig, pgp_mem_data(signedmem), pgp_mem_len(signedmem));
    pgp_memory_free(signedmem);

    pgp_seckey_free(decrypted_seckey);
    free(decrypted_seckey);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_verify(
  rnp_keyring_t keyring, const uint8_t sig[], size_t sig_len, uint8_t **msg, size_t *msg_len)
{
    pgp_memory_t *signedmem = NULL;
    pgp_memory_t *cat = NULL;

    *msg_len = 0;
    *msg = NULL;

    if (sig == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    signedmem = pgp_memory_new();
    if (!signedmem) {
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    cat = pgp_memory_new();
    if (cat == NULL) {
        pgp_memory_free(signedmem);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    if (!pgp_memory_add(signedmem, sig, sig_len)) {
        return RNP_ERROR_GENERIC;
    }

    pgp_validation_t result;
    (void) memset(&result, 0x0, sizeof(result));
    bool ok = pgp_validate_mem(
      keyring->rnp_ctx.io, &result, signedmem, &cat, false, keyring->rnp_ctx.pubring);

    /* signedmem is freed from pgp_validate_mem */

    if (ok) {
        *msg_len = pgp_mem_len(cat);
        *msg = malloc(*msg_len);
        memcpy(*msg, pgp_mem_data(cat), *msg_len);
        pgp_memory_free(cat);
        return RNP_SUCCESS;
    }

    pgp_memory_free(cat);

    if (result.validc + result.invalidc + result.unknownc == 0) {
        return RNP_ERROR_NO_SIGNATURES_FOUND;
    }

    return RNP_ERROR_SIGNATURE_INVALID;
}

rnp_result_t
rnp_sign_detached(rnp_keyring_t keyring,
                  const char *  ident,
                  const char *  hash_fn,
                  bool          armor,
                  const uint8_t msg[],
                  size_t        msg_len,
                  uint8_t **    sig,
                  size_t *      sig_len)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_verify_detached(rnp_keyring_t keyring,
                    const uint8_t msg[],
                    size_t        msg_len,
                    const uint8_t sig[],
                    size_t        sig_len)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_verify_detached_file(rnp_keyring_t keyring,
                         const char *  file_path,
                         const uint8_t sig[],
                         size_t        sig_len)
{
    return RNP_ERROR_NOT_IMPLEMENTED;
}

static pgp_compression_type_t
pgp_str_to_zalg(const char *z_alg)
{
    if (z_alg == NULL)
        return PGP_C_NONE;

    if (strcmp(z_alg, "none") == 0)
        return PGP_C_NONE;
    if (strcmp(z_alg, "zlib") == 0)
        return PGP_C_ZLIB;
    if (strcmp(z_alg, "zip") == 0)
        return PGP_C_ZIP;
    if (strcmp(z_alg, "bzip2") == 0)
        return PGP_C_BZIP2;

    // something we don't recognize ...
    return PGP_C_NONE;
}

rnp_result_t
rnp_encrypt(rnp_keyring_t keyring,
            const char *  userid,
            const char *  cipher,
            const char *  z_alg,
            size_t        z_level,
            bool          armored,
            const uint8_t msg[],
            size_t        msg_len,
            uint8_t **    output,
            size_t *      output_len)
{
    rnp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rnp = &keyring->rnp_ctx;
    ctx.ealg = pgp_str_to_cipher(cipher);
    ctx.zalg = pgp_str_to_zalg(z_alg);
    ctx.zlevel = z_level;
    ctx.armour = armored;

    *output = NULL;
    *output_len = 0;

    const pgp_key_t *keypair = resolve_public_key(ctx.rnp, userid);
    if (!keypair)
        return RNP_ERROR_KEY_NOT_FOUND;

    if (pgp_key_can_encrypt(keypair) == false) {
        keypair = find_suitable_subkey(keypair, PGP_KF_ENCRYPT);
        if (!keypair)
            return RNP_ERROR_NO_SUITABLE_KEY;
    }

    pgp_memory_t *enc =
      pgp_encrypt_buf(&ctx, keyring->rnp_ctx.io, msg, msg_len, pgp_get_pubkey(keypair));

    const size_t mem_len = pgp_mem_len(enc);

    if (armored)
        *output_len = mem_len + 1; // space for null
    else
        *output_len = mem_len;

    *output = calloc(1, *output_len);
    if (*output == NULL) {
        pgp_memory_free(enc);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    memcpy(*output, pgp_mem_data(enc), mem_len);
    pgp_memory_free(enc);

    return RNP_SUCCESS;
}

/**
* Decrypt a message
* @param key the private key to attempt decryption with
* @param msg the ciphertext
* @param msg_len length of msg in bytes
* @param output pointer that will be set to a newly allocated
* buffer, length *output_len, free with rnp_buffer_free
* @param output_len will be set to the length of output
*/
rnp_result_t
rnp_decrypt(rnp_keyring_t keyring,
            const uint8_t input[],
            size_t        input_len,
            uint8_t **    output,
            size_t *      output_len)
{
    *output = NULL;
    *output_len = 0;

    if (input == NULL) {
        return RNP_ERROR_NULL_POINTER;
    }

    if (input_len < 32) {
        return RNP_ERROR_SHORT_BUFFER;
    }

    const char *armor_head = "-----BEGIN PGP MESSAGE-----";
    const int   armored = (memcmp(input, armor_head, strlen(armor_head)) == 0);

    pgp_memory_t *mem = pgp_decrypt_buf(keyring->rnp_ctx.io,
                                        input,
                                        input_len,
                                        keyring->rnp_ctx.secring,
                                        keyring->rnp_ctx.pubring,
                                        armored,
                                        /*use_ssh*/ 0,
                                        1,
                                        &keyring->rnp_ctx.passphrase_provider);

    if (mem == NULL) {
        return RNP_ERROR_DECRYPT_FAILED;
    }

    *output_len = pgp_mem_len(mem);

    *output = malloc(*output_len);
    if (*output == NULL) {
        pgp_memory_free(mem);
        return RNP_ERROR_OUT_OF_MEMORY;
    }

    memcpy(*output, pgp_mem_data(mem), *output_len);
    pgp_memory_free(mem);
    return RNP_SUCCESS;
}

static pgp_pubkey_alg_t
pgp_str_to_pka(const char *str)
{
    if (strcmp(str, "RSA") == 0)
        return PGP_PKA_RSA;

    if (strcmp(str, "ECDSA") == 0)
        return PGP_PKA_ECDSA;

    if (strcmp(str, "SM2") == 0)
        return PGP_PKA_SM2;

    if (strcmp(str, "EDDSA") == 0)
        return PGP_PKA_EDDSA;

    return PGP_PKA_NOTHING;
}

rnp_result_t
rnp_generate_private_key(rnp_keyring_t keyring,
                         const char *  userid,
                         const char *  signature_hash,
                         const char *  prikey_algo,
                         const char *  prikey_params,
                         const char *  primary_passphrase,
                         uint32_t      primary_expiration,
                         const char *  subkey_algo,
                         const char *  subkey_params,
                         const char *  subkey_passphrase,
                         uint32_t      subkey_expiration)
{
    rnp_result_t rc = RNP_ERROR_GENERIC;

    const pgp_hash_alg_t   hash_alg = pgp_str_to_hash_alg(signature_hash);
    const pgp_pubkey_alg_t pri_alg = pgp_str_to_pka(prikey_algo);
    const pgp_pubkey_alg_t sub_alg = pgp_str_to_pka(subkey_algo);

    pgp_key_t *primary_sec = NULL;
    pgp_key_t *primary_pub = NULL;
    pgp_key_t *subkey_sec = NULL;
    pgp_key_t *subkey_pub = NULL;

    if (hash_alg == PGP_HASH_UNKNOWN || pri_alg == PGP_PKA_NOTHING ||
        sub_alg == PGP_PKA_NOTHING) {
        rc = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    if (strlen(userid) >= MAX_ID_LENGTH) {
        rc = RNP_ERROR_BAD_PARAMETERS;
        goto done;
    }

    rnp_keygen_primary_desc_t primary_desc;
    rnp_keygen_subkey_desc_t  subkey_desc;
    memset(&primary_desc, 0, sizeof(primary_desc));
    memset(&subkey_desc, 0, sizeof(subkey_desc));

    primary_desc.crypto.key_alg = pri_alg;
    primary_desc.crypto.hash_alg = hash_alg;

    if (pri_alg == PGP_PKA_RSA) {
        primary_desc.crypto.rsa.modulus_bit_len = strtol(prikey_params, NULL, 0);
    } else {
        // primary_desc.crypto.ecc.curve; // TODO
    }

    strcpy((char *) primary_desc.cert.userid, userid);
    primary_desc.cert.key_flags = pgp_pk_alg_capabilities(pri_alg); // fixme
    primary_desc.cert.key_expiration = primary_expiration;
    primary_desc.cert.primary = 1;

    subkey_desc.crypto.key_alg = pri_alg;
    subkey_desc.crypto.hash_alg = hash_alg;

    if (pri_alg == PGP_PKA_RSA) {
        subkey_desc.crypto.rsa.modulus_bit_len = strtol(prikey_params, NULL, 0);
    } else {
        // subkey_desc.crypto.ecc.curve; // TODO
    }

    subkey_desc.binding.key_flags = pgp_pk_alg_capabilities(sub_alg); // fixme
    subkey_desc.binding.key_expiration = subkey_expiration;

    primary_sec = calloc(1, sizeof(*primary_sec));
    primary_pub = calloc(1, sizeof(*primary_pub));
    subkey_sec = calloc(1, sizeof(*subkey_sec));
    subkey_pub = calloc(1, sizeof(*subkey_pub));
    if (!primary_sec || !primary_pub || !subkey_sec || !subkey_pub) {
        rc = RNP_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    const key_store_format_t key_format =
      ((rnp_key_store_t *) keyring->rnp_ctx.secring)->format;

    if (!pgp_generate_keypair(&primary_desc,
                              &subkey_desc,
                              true,
                              primary_sec,
                              primary_pub,
                              subkey_sec,
                              subkey_pub,
                              key_format)) {
        rc = RNP_ERROR_KEY_GENERATION;
        goto done;
    }

    if (!pgp_key_protect_passphrase(primary_sec, key_format, NULL, primary_passphrase)) {
        rc = RNP_ERROR_GENERIC;
        goto done;
    }

    if (!pgp_key_protect_passphrase(subkey_sec, key_format, NULL, subkey_passphrase)) {
        rc = RNP_ERROR_GENERIC;
        goto done;
    }

    rnp_t *rnp = &keyring->rnp_ctx;

    // add them all to the key store
    if (!rnp_key_store_add_key(rnp->io, rnp->secring, primary_sec) ||
        !rnp_key_store_add_key(rnp->io, rnp->secring, subkey_sec) ||
        !rnp_key_store_add_key(rnp->io, rnp->pubring, primary_pub) ||
        !rnp_key_store_add_key(rnp->io, rnp->pubring, subkey_pub)) {
        rc = RNP_ERROR_WRITE;
        goto done;
    }

    // update the keyring on disk
    if (!rnp_key_store_write_to_file(rnp, rnp->secring, 0) ||
        !rnp_key_store_write_to_file(rnp, rnp->pubring, 0)) {
        rc = RNP_ERROR_WRITE;
        goto done;
    }

    rc = RNP_SUCCESS;

done:
    free(primary_sec);
    free(primary_pub);
    free(subkey_sec);
    free(subkey_pub);

    if (rc != RNP_SUCCESS) {
        return rc;
    }
    return RNP_SUCCESS;
}

void
rnp_buffer_free(void *ptr)
{
    free(ptr);
}

rnp_result_t
rnp_key_get_primary_uid(rnp_key_t key, char **uid)
{
    if (key == NULL || key->key == NULL || uid == NULL)
        return RNP_ERROR_NULL_POINTER;

    if (key->key->uid0_set)
        return rnp_key_get_uid_at(key, key->key->uid0, uid);
    else
        return rnp_key_get_uid_at(key, 0, uid);
}

rnp_result_t
rnp_key_get_uid_count(rnp_key_t key, size_t *count)
{
    if (key == NULL || key->key == NULL || count == NULL)
        return RNP_ERROR_NULL_POINTER;

    *count = key->key->uidc;
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_uid_at(rnp_key_t key, size_t idx, char **uid)
{
    if (key == NULL || key->key == NULL || uid == NULL)
        return RNP_ERROR_NULL_POINTER;
    if (idx > key->key->uidc)
        return RNP_ERROR_BAD_PARAMETERS;

    size_t uid_len = strlen((const char*)key->key->uids[idx]);
    *uid = calloc(uid_len + 1, 1);

    if (*uid == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    memcpy(*uid, key->key->uids[idx], uid_len);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_fprint(rnp_key_t key, char **fprint)
{
    if (key == NULL || key->key == NULL || fprint == NULL)
        return RNP_ERROR_NULL_POINTER;

    *fprint = calloc(PGP_FINGERPRINT_HEX_SIZE + 1, 1);
    if (*fprint == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    rnp_strhexdump(
      *fprint, key->key->fingerprint.fingerprint, key->key->fingerprint.length, " ");

    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_keyid(rnp_key_t key, char **keyid)
{
    if (key == NULL || key->key == NULL || keyid == NULL)
        return RNP_ERROR_NULL_POINTER;

    *keyid = calloc(PGP_KEY_ID_SIZE * 2 + 1, 1);
    if (*keyid == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    rnp_strhexdump(*keyid, key->key->keyid, PGP_KEY_ID_SIZE, "");

    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_get_grip(rnp_key_t key, char **grip)
{
    if (key == NULL || key->key == NULL || grip == NULL)
        return RNP_ERROR_NULL_POINTER;

    *grip = calloc(PGP_FINGERPRINT_SIZE * 2 + 1, 1);
    if (*grip == NULL)
        return RNP_ERROR_OUT_OF_MEMORY;

    rnp_strhexdump(*grip, key->key->grip, PGP_FINGERPRINT_SIZE, "");

    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_locked(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;

    *result = pgp_key_is_locked(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_unlock(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx)
{
    if (key == NULL || key->key == NULL || cb == NULL)
        return RNP_ERROR_NULL_POINTER;
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_key_is_protected(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_key_is_protected(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_protect(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx)
{
    if (key == NULL || key->key == NULL || cb == NULL)
        return RNP_ERROR_NULL_POINTER;
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_key_unprotect(rnp_key_t key, rnp_passphrase_cb cb, void *app_ctx)
{
    if (key == NULL || key->key == NULL || cb == NULL)
        return RNP_ERROR_NULL_POINTER;
    return RNP_ERROR_NOT_IMPLEMENTED;
}

rnp_result_t
rnp_key_is_primary_key(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_key_is_primary_key(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_subkey(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_key_is_subkey(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_secret(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_is_key_secret(key->key);
    return RNP_SUCCESS;
}

rnp_result_t
rnp_key_is_public(rnp_key_t key, bool *result)
{
    if (key == NULL || key->key == NULL || result == NULL)
        return RNP_ERROR_NULL_POINTER;
    *result = pgp_is_key_public(key->key);
    return RNP_SUCCESS;
}
