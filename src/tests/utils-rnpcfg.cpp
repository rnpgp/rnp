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

#include "rnp_tests.h"
#include "support.h"
#include "list.h"
#include "utils.h"
#include <rnp/rnpcfg.h>

void
test_rnpcfg(void **state)
{
    rnp_cfg_t  cfg1 = {0}, cfg2 = {0};
    rnp_cfg_t *cfgs[2] = {&cfg1, &cfg2};
    rnp_cfg_t *cfg = NULL;
    list *     lst;
    char       buf[32];

    assert_null(rnp_cfg_getstr(&cfg1, "key"));

    /* set the values */
    assert_true(rnp_cfg_setstr(&cfg1, "key_str", "val"));
    assert_true(rnp_cfg_setstr(&cfg1, "key_true", "true"));
    assert_true(rnp_cfg_setstr(&cfg1, "key_True", "True"));
    assert_true(rnp_cfg_setint(&cfg1, "key_int", 999));
    assert_true(rnp_cfg_setstr(&cfg1, "key_100", "100"));
    assert_true(rnp_cfg_setbool(&cfg1, "key_bool", true));

    for (int i = 0; i < 10; i++) {
        snprintf(buf, sizeof(buf), "val%d", i);
        assert_true(rnp_cfg_addstr(&cfg1, "key_list", buf));
    }

    /* copy empty cfg2 to cfg1 to make sure values are not deleted */
    rnp_cfg_copy(&cfg1, &cfg2);

    /* copy to the cfg2 */
    rnp_cfg_copy(&cfg2, &cfg1);

    /* copy second time to make sure there are no leaks */
    rnp_cfg_copy(&cfg2, &cfg1);

    /* get values back, including transformations */
    for (int i = 0; i < 2; i++) {
        cfg = cfgs[i];

        assert_int_equal(rnp_cfg_getint(cfg, "key_int"), 999);
        assert_int_equal(rnp_cfg_getint(cfg, "key_100"), 100);
        assert_true(rnp_cfg_getbool(cfg, "key_int"));
        assert_true(rnp_cfg_getbool(cfg, "key_bool"));
        assert_true(rnp_cfg_getbool(cfg, "key_true"));
        assert_true(rnp_cfg_getbool(cfg, "key_True"));
        assert_false(rnp_cfg_getbool(cfg, "key_notfound"));

        assert_string_equal(rnp_cfg_getstr(cfg, "key_str"), "val");
        assert_null(rnp_cfg_getstr(cfg, "key_str1"));
        assert_null(rnp_cfg_getstr(cfg, "key_st"));

        assert_non_null(lst = rnp_cfg_getlist(cfg, "key_list"));
        assert_int_equal(list_length(*lst), 10);

        list_item *li = list_front(*lst);

        for (int j = 0; j < 10; j++) {
            assert_non_null(li);
            const char *val = rnp_cfg_val_getstr((rnp_cfg_val_t *) li);
            assert_non_null(val);
            snprintf(buf, sizeof(buf), "val%d", j);
            assert_string_equal(buf, val);
            li = list_next(li);
        }
    }

    /* override value */
    assert_true(rnp_cfg_setint(&cfg1, "key_int", 222));
    assert_int_equal(rnp_cfg_getint(&cfg1, "key_int"), 222);
    assert_int_equal(rnp_cfg_getint(&cfg2, "key_int"), 999);
    assert_true(rnp_cfg_setstr(&cfg1, "key_int", "333"));
    assert_int_equal(rnp_cfg_getint(&cfg1, "key_int"), 333);

    /* unset value */
    assert_true(rnp_cfg_unset(&cfg1, "key_int"));
    assert_false(rnp_cfg_unset(&cfg1, "key_int"));

    rnp_cfg_free(&cfg1);
    rnp_cfg_free(&cfg2);
}
