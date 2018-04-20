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

#include <assert.h>
#include <sys/time.h>
#include <botan/ffi.h>

#include <rnp/rnp.h>
#include <repgp/repgp.h>

#include <librepgp/packet-parse.h>
#include <librepgp/reader.h>

#include <crypto.h>
#include <crypto/common.h>
#include <pgp-key.h>
#include <rnp/rnp.h>

#include "rnp_tests.h"
#include "support.h"
#include "list.h"
#include "pgp-parse-data.h"

static const char *KEYRING_1_PASSWORD = "password";

static void
set_io(pgp_io_t *io)
{
    io->outs = stdout;
    io->res = stdout;
    io->errs = stderr;
}

static pgp_cb_ret_t
tag_collector(const pgp_packet_t *pkt, pgp_cbdata_t *cbinfo)
{
    list *taglist = pgp_callback_arg(cbinfo);
    list_append(taglist, &pkt->tag, sizeof(pkt->tag));
    return PGP_RELEASE_MEMORY;
}

void
pgp_parse_keyrings_1_pubring(void **state)
{
    rnp_test_state_t *rstate = *state;
    char              path[PATH_MAX];
    pgp_stream_t *    stream;
    list              taglist;
    pgp_io_t          io = {0};

    set_io(&io);
    paths_concat(path, sizeof(path), rstate->data_dir, "keyrings/1/pubring.gpg", NULL);

    /* file read */
    {
        taglist = NULL;
        stream = NULL;
        int fd = pgp_setup_file_read(&io, &stream, path, &taglist, tag_collector, 1);
        assert_false(fd < 0);
        assert_non_null(stream);

        repgp_parse_options(stream, PGP_PTAG_SS_ALL, REPGP_PARSE_PARSED);
        assert_true(repgp_parse(stream, 1));
        pgp_teardown_file_read(stream, fd);
        stream = NULL;

        assert_int_equal(list_length(taglist), ARRAY_SIZE(tags_keyrings_1_pubring));
        list_item *item = list_front(taglist);
        size_t     i = 0;
        while (item) {
            pgp_content_enum tag = *(pgp_content_enum *) item;
            assert_int_equal(tag, tags_keyrings_1_pubring[i]);

            item = list_next(item);
            i++;
        }
        list_destroy(&taglist);
    }

    /* memory read */
    {
        taglist = NULL;
        stream = NULL;
        pgp_memory_t *mem = pgp_memory_new();
        assert_non_null(mem);

        assert_true(pgp_mem_readfile(mem, path));
        assert_true(pgp_setup_memory_read(&io, &stream, mem, &taglist, tag_collector, 1));
        assert_non_null(stream);

        repgp_parse_options(stream, PGP_PTAG_SS_ALL, REPGP_PARSE_PARSED);
        assert_true(repgp_parse(stream, 1));
        pgp_teardown_memory_read(stream, mem);
        stream = NULL;

        assert_int_equal(list_length(taglist), ARRAY_SIZE(tags_keyrings_1_pubring));
        list_item *item = list_front(taglist);
        size_t     i = 0;
        while (item) {
            pgp_content_enum tag = *(pgp_content_enum *) item;
            assert_int_equal(tag, tags_keyrings_1_pubring[i]);

            item = list_next(item);
            i++;
        }
        list_destroy(&taglist);
    }
}

static bool
setup_keystore_1(rnp_test_state_t *state, rnp_t *rnp)
{
    rnp_params_t params = {0};
    bool         res = true;
    char         path[PATH_MAX] = {0};

    assert(state->data_dir);

    paths_concat(path, sizeof(path), state->data_dir, "keyrings/1/pubring.gpg", NULL);
    params.pubpath = strdup(path);
    paths_concat(path, sizeof(path), state->data_dir, "keyrings/1/secring.gpg", NULL);
    params.secpath = strdup(path);
    if (!params.pubpath || !params.secpath) {
        res = false;
        goto end;
    }
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

    // Set password
    rnp->password_provider.callback = string_copy_password_callback;
    rnp->password_provider.userdata = /*unconst*/ (char *) KEYRING_1_PASSWORD;

end:
    rnp_params_free(&params);
    return res;
}

void
test_repgp_decrypt(void **state)
{
    rnp_t     rnp = {0};
    rnp_ctx_t ctx = {0};

    rnp_test_state_t *rstate = *state;

    uint8_t out_buf[1024] = {0};
    char    input_file[1024] = {0};
    size_t  out_buf_size = sizeof(out_buf);
    uint8_t in_buf[1024] = {0};
    size_t  in_buf_size = sizeof(in_buf);
    char    plaintext[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\n";

    /*  Setup keystore. This text was encrypted with keys stored in keyrings/1/.. */
    setup_keystore_1(rstate, &rnp);
    assert_int_equal(rnp_ctx_init(&ctx, &rnp), RNP_SUCCESS);

    /* Read encrypted file */
    paths_concat(
      (char *) input_file, sizeof(input_file), rstate->data_dir, "test_repgp/encrypted_text.gpg\0", NULL);
    FILE *f = fopen(input_file, "rb");
    assert_non_null(f);
    in_buf_size = fread(in_buf, 1, in_buf_size, f);
    assert_true(in_buf_size > 0);
    fclose(f);

    /* Decrypt buffer */
    repgp_io_t *io = repgp_create_io();
    assert_non_null(io);
    repgp_set_input(io, create_data_handle(in_buf, in_buf_size));
    repgp_handle_t *out_buf_handle = create_buffer_handle(1024);
    repgp_set_output(io, out_buf_handle);
    assert_int_equal(repgp_decrypt(&ctx, io), RNP_SUCCESS);
    assert_int_equal(repgp_copy_buffer_from_handle(out_buf, &out_buf_size, out_buf_handle),
                     RNP_SUCCESS);
    repgp_destroy_io(io);

    /* Check if same as encryption input */
    assert_int_equal(memcmp(plaintext, out_buf, out_buf_size), 0);

    /* Decrypt file to temporary file.
       - Create temporary directory with file called "o" in it
       - Try to decrypt to "o" */
    char *tmpdir = make_temp_dir();
    char *tmp_filename = malloc(strlen(tmpdir) + 3);
    memcpy(tmp_filename, tmpdir, strlen(tmpdir));
    memcpy(tmp_filename + strlen(tmpdir), "/o", 3);

    io = repgp_create_io();
    out_buf_size = sizeof(out_buf);
    assert_non_null(io);
    repgp_set_input(io, create_filepath_handle(input_file));
    repgp_set_output(io, create_filepath_handle(tmp_filename));
    assert_int_equal(repgp_decrypt(&ctx, io), RNP_SUCCESS);

    repgp_destroy_io(io);

    /* Check if same as encryption input */
    f = fopen(tmp_filename, "rb");
    assert_non_null(f);
    in_buf_size = fread(in_buf, 1, in_buf_size, f);
    assert_true(in_buf_size > 0);
    fclose(f);
    assert_int_equal(memcmp(plaintext, in_buf, in_buf_size), 0);

    /* Cleanup */
    rnp_end(&rnp);
    delete_recursively(tmpdir);
    free(tmpdir);
    free(tmp_filename);
}

void
test_repgp_verify(void **state)
{
    rnp_t     rnp = {0};
    rnp_ctx_t ctx = {0};

    rnp_test_state_t *rstate = *state;
    char              input_file[1024] = {0};
    uint8_t           input_buf[1024] = {0};

    /* Setup keystore. This text was signed with keys stored in keyrings/1/.. */
    setup_keystore_1(rstate, &rnp);
    assert_int_equal(rnp_ctx_init(&ctx, &rnp), RNP_SUCCESS);

    paths_concat(
      (char *) input_file, sizeof(input_file), rstate->data_dir, "test_repgp/signed.gpg", NULL);

    /* Test verification from file */
    repgp_io_t *io = repgp_create_io();
    assert_non_null(io);
    repgp_set_input(io, create_filepath_handle(input_file));
    repgp_set_output(io, create_filepath_handle("-"));
    rnp_assert_int_equal(rstate, repgp_verify(&ctx, io), RNP_SUCCESS);
    repgp_destroy_io(io);

    /* Test verification from memory */
    FILE *f = fopen(input_file, "rb");
    assert_non_null(f);
    size_t in_buf_size = fread(input_buf, 1, sizeof(input_buf), f);
    assert_true(in_buf_size > 0);
    fclose(f);

    io = repgp_create_io();
    assert_non_null(io);
    repgp_set_input(io, create_data_handle(input_buf, in_buf_size));
    repgp_set_output(io, create_buffer_handle(1024));
    rnp_assert_int_equal(rstate, repgp_verify(&ctx, io), RNP_SUCCESS);
    repgp_destroy_io(io);

    /* Cleanup */
    rnp_end(&rnp);
}
