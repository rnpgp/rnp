/*
 * Copyright (c) 2017, [Ribose Inc](https://www.ribose.com).
 * All rights reserved.
 *
 * This code is originally derived from software contributed by
 * Ribose Inc (https://www.ribose.com).
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

/** \file
 * Parser demo app
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <repgp/repgp.h>

#include <rnp/rnp.h>             // for rnp_t, rnp_ctx_t et. all
#include <rekey/rnp_key_store.h> // for keystore stuff

#define RING "/home/flowher/.rnp/"

static bool
configure_rnp(rnp_t *rnp)
{
    rnp_params_t params = {0};
    bool         res = true;

    // IO
    pgp_io_t pgpio = {.errs = stderr, .res = stdout, .outs = stdout};
    rnp->io = malloc(sizeof(pgp_io_t));
    memcpy(rnp->io, &pgpio, sizeof(pgp_io_t));

    // RNP
    params.pubpath = strdup(RING "pubring.gpg");
    params.secpath = strdup(RING "secring.gpg");
    params.ks_pub_format = RNP_KEYSTORE_GPG;
    params.ks_sec_format = RNP_KEYSTORE_GPG;
    if (rnp_init(rnp, &params) != RNP_SUCCESS) {
        res = false;
        goto end;
    }

    // Load keys
    if (!rnp_key_store_load_keys(rnp, true)) {
        res = false;
        goto end;
    }

end:
    rnp_params_free(&params);
    return res;
}

int
verification()
{
    rnp_t     rnp = {0};
    rnp_ctx_t ctx = {0};

    if (!configure_rnp(&rnp)) {
        return 1;
    }
    rnp_ctx_init(&ctx, &rnp);

    repgp_io_t io = repgp_create_io();
    repgp_set_input(io, create_filepath_handle("data/signed", 11));
    repgp_set_output(io, create_filepath_handle("/tmp/signed_out", 15));
    printf("RES = %d\n", repgp_verify(&ctx, io) == RNP_SUCCESS);

end:
    repgp_destroy_io(io);
    free(rnp.io);
    rnp.io = NULL;
    rnp_end(&rnp);

    return 0;
}

int
decryption()
{
    rnp_t     rnp = {0};
    rnp_ctx_t ctx = {0};

    if (!configure_rnp(&rnp)) {
        return 1;
    }
    rnp_ctx_init(&ctx, &rnp);

    /* ----- perform decryption ----- */
    uint8_t out_buf[4096] = {0};
    size_t  out_buf_size = sizeof(out_buf);
    uint8_t in_buf[4096] = {0};
    size_t  in_buf_size = sizeof(in_buf);

    FILE *f = fopen("data/encrypted.gpg", "rb");
    in_buf_size = fread(in_buf, 1, in_buf_size, f);
    fclose(f);

    repgp_io_t io = repgp_create_io();
    repgp_set_input(io, create_data_handle(in_buf, in_buf_size));
    repgp_handle_t out_buf_handle = create_buffer_handle(4096);
    repgp_set_output(io, out_buf_handle);
    printf("RES = %d\n", repgp_decrypt(&ctx, io) == RNP_SUCCESS);

    if (repgp_copy_buffer_from_handle(out_buf, &out_buf_size, out_buf_handle) != RNP_SUCCESS) {
        assert(false);
    }

    out_buf[sizeof(out_buf) - 1] = '\0';
    printf("%s\n", out_buf);

end:
    repgp_destroy_io(io);
    free(rnp.io);
    rnp.io = NULL;
    rnp_end(&rnp);

    return 0;
}

int
list()
{
    rnp_t     rnp = {0};
    rnp_ctx_t ctx = {0};

    if (!configure_rnp(&rnp)) {
        return 1;
    }

    rnp_ctx_init(&ctx, &rnp);
    repgp_handle_t handle = create_filepath_handle("data/encrypted.gpg", 18);
    printf("RES = %d\n", repgp_list_packets(&ctx, handle) == RNP_SUCCESS);

end:
    repgp_destroy_handle(handle);
    free(rnp.io);
    rnp.io = NULL;
    rnp_end(&rnp);

    return 0;
}

int
validate_pubkeys()
{
    rnp_t     rnp = {0};
    rnp_ctx_t ctx = {0};

    if (!configure_rnp(&rnp)) {
        return 1;
    }

    rnp_ctx_init(&ctx, &rnp);
    printf("RES = %d\n", repgp_validate_pubkeys_signatures(&ctx) == RNP_SUCCESS);

end:
    free(rnp.io);
    rnp.io = NULL;
    rnp_end(&rnp);

    return 0;
}

int
main()
{
    // verification();
    decryption();
    // list();
    // validate_pubkeys();
}
