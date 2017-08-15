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

#include <crypto/rsa.h>
#include <crypto/dsa.h>
#include <crypto/eddsa.h>
#include <crypto/elgamal.h>
#include <crypto.h>
#include <packet.h>
#include <pgp-key.h>
#include <crypto/bn.h>
#include <rnp/rnp.h>
#include <crypto/ecdsa.h>
#include <readerwriter.h>

#include "rnp_tests.h"
#include "support.h"
#include "list.h"
#include "pgp-parse-data.h"

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

    io.outs = stdout;
    io.res = stdout;
    io.errs = stderr;
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
