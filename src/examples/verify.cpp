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
#include <librepgp/stream-common.h>
#include <librepgp/stream-parse.h>
#include <librepgp/stream-sig.h>
#include <librepgp/stream-key.h>
#include <librekey/key_store_pgp.h>
#include "packet-create.h"
#include "crypto.h"
#include <string.h>

bool
load_signed_file(char *buffer, size_t maxlen, size_t *read)
{
    FILE *  efile = NULL;
    ssize_t dataread = 0;

    if (!(efile = fopen("signed.asc", "r"))) {
        fprintf(stdout, "failed to read signed data from file: run ./sign example first\n");
        return false;
    }
    dataread = fread(buffer, 1, maxlen, efile);
    fclose(efile);
    if ((dataread < 0) || ((size_t) dataread == maxlen)) {
        fprintf(stdout, "failed to read signed data\n");
        return false;
    }
    *read = dataread;
    return true;
}

void
keyid_to_filename(uint8_t *keyid, char *filename)
{
    rnp_hex_encode(
      keyid, PGP_KEY_ID_SIZE, filename, PGP_KEY_ID_SIZE * 2 + 1, RNP_HEX_LOWERCASE);
    memcpy(filename + PGP_KEY_ID_SIZE * 2, ".key", 5);
}

bool
write_key_to_file(const rnp_key_store_t *keystore, const pgp_key_t *key, const char *filename)
{
    pgp_dest_t keyfile = {};
    bool       res = false;

    if (init_file_dest(&keyfile, filename, true) != RNP_SUCCESS) {
        return false;
    }

    res = pgp_write_xfer_key(&keyfile, key, keystore);
    dst_close(&keyfile, !res);

    return res;
}

pgp_transferable_key_t *
load_key_from_file(const char *filename)
{
    pgp_source_t            src = {};
    pgp_transferable_key_t *res = NULL;

    if (init_file_src(&src, filename) != RNP_SUCCESS) {
        fprintf(stdout, "failed to read file %s.\n", filename);
        return NULL;
    }

    if (!(res = (pgp_transferable_key_t *) calloc(1, sizeof(*res)))) {
        fprintf(stdout, "allocation failed\n");
        goto finish;
    }

    if (process_pgp_key(&src, res) != RNP_SUCCESS) {
        fprintf(stdout, "failed to process key file %s\n", filename);
        free(res);
        res = NULL;
        goto finish;
    }

finish:
    src_close(&src);
    return res;
}

/* this function will export each key from the keyring to separate file, named <keyid>.key */
int
export_keys()
{
    rnp_key_store_t *keyring = NULL;
    int              result = 1;

    /* allocate keyring and load it from the file */
    keyring = rnp_key_store_new(RNP_KEYSTORE_GPG, "pubring.pgp");

    if (!rnp_key_store_load_from_file(keyring, NULL)) {
        fprintf(stdout, "failed to read keyring. Did you run ./generate example?\n");
        goto finish;
    }

    /* export each of the primary keys together with subkeys */
    for (size_t idx = 0; idx < rnp_key_store_get_key_count(keyring); idx++) {
        pgp_key_t *key = rnp_key_store_get_key(keyring, idx);
        char       keyname[32] = {0};

        /* subkeys are stored together with primary keys, so skip them */
        if (!pgp_key_is_primary_key(key)) {
            continue;
        }

        keyid_to_filename(key->keyid, keyname);
        if (!write_key_to_file(keyring, key, keyname)) {
            fprintf(stdout, "failed to write key to the file\n");
            goto finish;
        }
    }

    result = 0;
finish:
    rnp_key_store_free(keyring);
    return result;
}

pgp_key_t *
key_provider_example(const pgp_key_request_ctx_t *ctx, void *userdata)
{
    rnp_t *                 rnp = (rnp_t *) userdata;
    pgp_key_t *             key = NULL;
    pgp_transferable_key_t *tkey = NULL;
    char                    keyname[32] = {0};

    if (!rnp) {
        return NULL;
    }

    /* in this example we work only with public keys */
    if (ctx->secret) {
        return NULL;
    }

    /* in this example we search only by keyid, which will be enough for verification */
    if (ctx->search.type != PGP_KEY_SEARCH_KEYID) {
        return NULL;
    }

    key = rnp_key_store_get_key_by_id(rnp->pubring, ctx->search.by.keyid, NULL);

    if (key) {
        return key;
    }

    /* load key from the file, using it's keyid as the filename */
    keyid_to_filename((uint8_t *) ctx->search.by.keyid, keyname);
    snprintf(keyname + 16, sizeof(keyname) - 16, ".key");
    tkey = load_key_from_file(keyname);
    if (!tkey) {
        return NULL;
    }

    /* transferable key is a structure with OpenPGP packets, it requires some processing to be
     * added to the keyring and be transformed to pgp_key_t */
    if (!rnp_key_store_add_transferable_key(rnp->pubring, tkey)) {
        fprintf(stdout, "failed to add loaded key to the keyring\n");
        return NULL;
    }

    return rnp_key_store_get_key_by_id(rnp->pubring, ctx->search.by.keyid, NULL);
}

void
example_on_signatures(pgp_parse_handler_t *handler, pgp_signature_info_t *sigs, int count)
{
    uint8_t keyid[PGP_KEY_ID_SIZE];
    char    id[MAX_ID_LENGTH + 1];

    for (int i = 0; i < count; i++) {
        signature_get_keyid(sigs[i].sig, keyid);
        userid_to_id(keyid, id);

        if (sigs[i].unknown) {
            fprintf(stdout, "Unknown signature from key %s\n", id);
            continue;
        }
        if (sigs[i].no_signer) {
            fprintf(stdout, "Signer's key %s not found\n", id);
            continue;
        }
        if (!sigs[i].valid) {
            fprintf(stdout, "INVALID signature from key %s\n", id);
            continue;
        }
        if (sigs[i].expired) {
            fprintf(stdout, "EXPIRED signature from key %s\n", id);
            continue;
        }
        fprintf(stdout, "VALID signature from key %s\n", id);
    }
}

int
verify_highlevel()
{
    rnp_t        rnp = {};
    rnp_params_t params = {};
    rnp_ctx_t    ctx = {};
    int          result = 1;
    char         signed_message[10000] = {0};
    size_t       signed_len = 0;
    char         verified_message[10000] = {0};
    size_t       verified_len = 0;

    /* Setup rnp parameters. Keys will be loaded dynamically, by request */
    rnp_params_init(&params);
    params.pubpath = strdup("");
    params.secpath = strdup("");
    params.ks_pub_format = RNP_KEYSTORE_GPG;
    params.ks_sec_format = RNP_KEYSTORE_GPG;

    /* initialize rnp structure */
    if (rnp_init(&rnp, &params) != RNP_SUCCESS) {
        fprintf(stdout, "failed to init rnp");
        goto finish;
    }

    /* set our custom key provider */
    rnp.key_provider = {.callback = key_provider_example, .userdata = &rnp};

    /* initalize context with data from rnp_t */
    if (rnp_ctx_init(&ctx, &rnp) != RNP_SUCCESS) {
        fprintf(stdout, "failed to initialize context\n");
        goto finish;
    }

    ctx.on_signatures = (void *) example_on_signatures;

    /* load signed file to memory */
    if (!load_signed_file(signed_message, sizeof(signed_message), &signed_len)) {
        goto finish;
    }

    /* Verify the data in memory. You may use rnp_process_file to work with files as well.
    Please note that successfull verification doesn't mean that all signatures are valid -
    those should be checked in on_signatures handler. */
    if (rnp_process_mem(&ctx,
                        signed_message,
                        signed_len,
                        verified_message,
                        sizeof(verified_message),
                        &verified_len) != RNP_SUCCESS) {
        fprintf(stdout, "verification failed\n");
        goto finish;
    }

    fprintf(stdout, "Verified message:\n%.*s\n", (int) verified_len, verified_message);
    result = 0;
finish:
    rnp_ctx_free(&ctx);
    rnp_params_free(&params);
    rnp_end(&rnp);
    return result;
}

int
main(int argc, char **argv)
{
    int res;
    res = export_keys();
    if (res) {
        return res;
    }
    res = verify_highlevel();
    return res;
}