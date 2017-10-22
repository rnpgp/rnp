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

#include <rnp/rnp.h>
#include <repgp/repgp.h>

#include <librepgp/packet-parse.h>
#include <librepgp/reader.h>

#include <crypto.h>
#include <crypto/bn.h>
#include <crypto/rsa.h>
#include <crypto/dsa.h>
#include <crypto/eddsa.h>
#include <crypto/elgamal.h>
#include <crypto/ecdsa.h>
#include <pgp-key.h>
#include <rnp/rnp.h>

#include "rnp_tests.h"
#include "readerwriter.h"
#include "support.h"
#include "list.h"
#include "pgp-parse-data.h"
#include "compress.h"
#include "crc24_radix64.h"

static const char *KEYRING_1_PASSWORD = "password";

uint32_t ref1(uint32_t crc, unsigned char *octets, size_t len);

static bool
read_file_to_memory(rnp_test_state_t *rstate,
                    uint8_t *         out_buffer,
                    size_t *          out_buffer_len,
                    const uint8_t *   filepath)
{
    char path[PATH_MAX];
    paths_concat(path, sizeof(path), rstate->data_dir, filepath, NULL);

    FILE *f = fopen(path, "rb");
    if (!f)
        return false;

    *out_buffer_len = fread(out_buffer, 1, *out_buffer_len, f);
    fclose(f);

    return true;
}

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

void
pgp_compress_roundtrip(void **state)
{
    rnp_test_state_t *rstate = *state;

    const pgp_compression_type_t algs[] = {PGP_C_ZLIB, PGP_C_ZIP, PGP_C_BZIP2, PGP_C_NONE};

    for (size_t i = 0; algs[i] != PGP_C_NONE; ++i) {
        for (size_t level = 1; level <= 9; ++level) {
            printf("alg %d level %zd\n", algs[i], level);

            uint8_t       file_buf[4096] = {0};
            size_t        file_buf_size = sizeof(file_buf);
            rnp_ctx_t     ctx = {0};
            rnp_t         rnp = {0};
            pgp_output_t *out = NULL;
            pgp_memory_t *mem = NULL;
            pgp_stream_t *stream = NULL;
            list          taglist = NULL;
            pgp_io_t      io = {0};

            assert_true(read_file_to_memory(
              rstate, file_buf, &file_buf_size, (const uint8_t *) "keyrings/1/pubring.gpg"));

            set_io(&io);

            /* Perform write */
            assert_int_equal(rnp_ctx_init(&ctx, &rnp), RNP_SUCCESS);
            assert_true(pgp_setup_memory_write(&ctx, &out, &mem, 4096));
            assert_true(pgp_writez(out, file_buf, file_buf_size, algs[i], level));

            assert_true(pgp_setup_memory_read(&io, &stream, mem, &taglist, tag_collector, 1));
            repgp_parse_options(stream, PGP_PTAG_SS_ALL, REPGP_PARSE_PARSED);
            assert_true(repgp_parse(stream, true));

            pgp_teardown_memory_write(out, mem);
            mem = NULL;
            pgp_teardown_memory_read(stream, mem);
            stream = NULL;

            assert_int_equal(list_length(taglist), ARRAY_SIZE(tags_keyrings_1_pubring) + 3);

            list_item *item = list_front(taglist);
            assert_int_equal(PGP_PARSER_PTAG, *((int *) item));

            item = list_next(item);
            assert_int_equal(PGP_PTAG_CT_COMPRESSED, *((int *) item));

            item = list_next(item);
            assert_int_equal(PGP_PARSER_PTAG, *((int *) item));

            item = list_next(item);
            assert_int_equal(PGP_PTAG_CT_PUBLIC_KEY, *((int *) item));

            item = list_next(item);
            assert_int_equal(PGP_PARSER_PACKET_END, *((int *) item));

            /* From now all all packets are the same as in tags_keyrings_1_pubring
            * except the last one.
            */
            item = list_next(item);
            for (size_t i = 3; i < ARRAY_SIZE(tags_keyrings_1_pubring); i++) {
                pgp_content_enum tag = *(pgp_content_enum *) item;
                assert_int_equal(tag, tags_keyrings_1_pubring[i]);
                item = list_next(item);
            }

            pgp_content_enum tag = *(pgp_content_enum *) item;
            assert_int_equal(tag, PGP_PARSER_PACKET_END);
            assert_non_null(!list_next(item));

            list_destroy(&taglist);
        }
    }
}

static bool
setup_keystore_1(rnp_test_state_t *state, rnp_t *rnp)
{
    rnp_params_t params = {0};
    bool         res = true;
    char         path[PATH_MAX] = {0};

    // IO
    pgp_io_t pgpio = {.errs = stderr, .res = stdout, .outs = stdout};
    rnp->io = malloc(sizeof(pgp_io_t));
    if (!rnp->io) {
        return false;
    }

    memcpy(rnp->io, &pgpio, sizeof(pgp_io_t));
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
    rnp->passphrase_provider.callback = string_copy_passphrase_callback;
    rnp->passphrase_provider.userdata = /*unconst*/ (char *) KEYRING_1_PASSWORD;

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
      (char *) input_file, sizeof(input_file), rstate->data_dir, "encrypted_text.gpg\0", NULL);
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
    free(rnp.io);
    rnp.io = NULL;
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
      (char *) input_file, sizeof(input_file), rstate->data_dir, "signed.gpg", NULL);

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
    free(rnp.io);
    rnp.io = NULL;
    rnp_end(&rnp);
}

void
test_repgp_list_packets(void **state)
{
    rnp_t     rnp = {0};
    rnp_ctx_t ctx = {0};

    rnp_test_state_t *rstate = *state;
    char              input_file[1024] = {0};
    uint8_t           input_buf[1024] = {0};

    /* Setup keystore. This text was signed with keys stored in keyrings/1/.. */
    assert_int_equal(rnp_ctx_init(&ctx, &rnp), RNP_SUCCESS);

    paths_concat(
      (char *) input_file, sizeof(input_file), rstate->data_dir, "signed.gpg", NULL);

    /* Test listing from file */
    repgp_io_t *io = repgp_create_io();
    assert_non_null(io);
    repgp_handle_t *input = create_filepath_handle(input_file);
    rnp_assert_int_equal(rstate, repgp_list_packets(&ctx, input, false), RNP_SUCCESS);
    repgp_destroy_handle(input);

    /* Test listing from memory */
    FILE *f = fopen(input_file, "rb");
    assert_non_null(f);
    size_t in_buf_size = fread(input_buf, 1, sizeof(input_buf), f);
    assert_true(in_buf_size > 0);
    fclose(f);

    io = repgp_create_io();
    assert_non_null(io);
    input = create_filepath_handle(input_file);
    rnp_assert_int_equal(rstate, repgp_list_packets(&ctx, input, false), RNP_SUCCESS);
    repgp_destroy_handle(input);

    /* Cleanup */
    free(rnp.io);
    rnp.io = NULL;
    rnp_end(&rnp);
}

static bool
test_CRC32_KAT()
{
    bool     ret = true;
    uint8_t  buf[15] = "ABCDEF012345678";
    uint32_t crc = 0;

    ret &= (0x382CC0 == crc24_final(crc24_update(CRC24_FAST_INIT, buf, sizeof(buf))));
    crc = crc24_update(CRC24_FAST_INIT, buf, sizeof(buf) - 3);
    crc = crc24_update(crc, &buf[sizeof(buf) - 3], 3);
    ret &= (0x382CC0 == crc24_final(crc));
    return ret;
}

#define REF_CRC24_INIT 0xB704CEL
#define REF_CRC24_POLY 0x1864CFBL

// CRC24-Radix64 reference implementation from RFC 4880
uint32_t
ref1(uint32_t crc, unsigned char *octets, size_t len)
{
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= REF_CRC24_POLY;
        }
    }
    return crc & 0xFFFFFFL;
}

static bool
test_CRC32_REF()
{
    static const uint32_t BUFLEN = 9999;
    struct timeval        t1 = {0};
    uint8_t               buf[BUFLEN];

    gettimeofday(&t1, NULL);
    srand(t1.tv_sec);
    for (int i = 0; i < BUFLEN; i++) {
        buf[i] = rand() % 0xFF;
    }

    if (ref1(REF_CRC24_INIT, buf, BUFLEN) !=
        crc24_final(crc24_update(CRC24_FAST_INIT, buf, BUFLEN))) {
        return false;
    }

    for (int i = 1; i <= BUFLEN; i++) {
        uint32_t c1 = ref1(REF_CRC24_INIT, buf, i);
        uint32_t c2 = crc24_update(CRC24_FAST_INIT, buf, i);

        if (ref1(c1, buf, BUFLEN) != crc24_final(crc24_update(c2, buf, BUFLEN))) {
            return false;
        }
    }

    return true;
}
#undef REF_CRC24_INIT
#undef REF_CRC24_POLY

void
test_crc24_4byte_slicer(void **state)
{
    rnp_test_state_t *rstate = *state;

    rnp_assert_true(rstate, test_CRC32_KAT());
    rnp_assert_true(rstate, test_CRC32_REF());
}
