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

#include <rnp/rnp.h>

#include <librepgp/packet-parse.h>
#include <librepgp/reader.h>

#include <crypto.h>
#include <crypto/bn.h>
#include <crypto/rsa.h>
#include <crypto/dsa.h>
#include <crypto/eddsa.h>
#include <crypto/elgamal.h>
#include <crypto/ecdsa.h>
#include <packet.h>
#include <pgp-key.h>
#include <rnp/rnp.h>

#include "rnp_tests.h"
#include "readerwriter.h"
#include "support.h"
#include "list.h"
#include "pgp-parse-data.h"
#include "compress.h"

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

        pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);
        assert_true(pgp_parse(stream, 1));
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

        pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);
        assert_true(pgp_parse(stream, 1));
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
    uint8_t           file_buf[4096] = {0};
    size_t            file_buf_size = sizeof(file_buf);
    rnp_ctx_t         ctx = {0};
    rnp_t             rnp = {0};
    pgp_output_t *    out = NULL;
    pgp_memory_t *    mem = NULL;
    pgp_stream_t *    stream = NULL;
    list              taglist = NULL;
    pgp_io_t          io = {0};
    rnp_test_state_t *rstate = *state;

    assert_true(read_file_to_memory(
      rstate, file_buf, &file_buf_size, (const uint8_t *) "keyrings/1/pubring.gpg"));

    set_io(&io);

    /* Perform write */
    assert_int_equal(rnp_ctx_init(&ctx, &rnp), RNP_SUCCESS);
    assert_true(pgp_setup_memory_write(&ctx, &out, &mem, 4096));
    assert_true(pgp_writez(out, file_buf, file_buf_size));

    assert_true(pgp_setup_memory_read(&io, &stream, mem, &taglist, tag_collector, 1));
    pgp_parse_options(stream, PGP_PTAG_SS_ALL, PGP_PARSE_PARSED);
    assert_true(pgp_parse(stream, true));

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
