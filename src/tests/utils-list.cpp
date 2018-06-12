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

static void
validate_int_list(list l, const int *expected, size_t count)
{
    list_item *item = list_front(l);

    // check front and back
    assert_int_equal(*(int *) list_front(l), expected[0]);
    assert_int_equal(*(int *) list_back(l), expected[count - 1]);

    // check length
    assert_int_equal(list_length(l), count);
    size_t length = 0;
    while (item) {
        int *value = (int *) item;
        // check each value
        assert_int_equal(*value, *expected++);
        item = list_next(item);
        length++;
    }
    assert_int_equal(list_length(l), length);
}

void
test_utils_list(void **state)
{
    list l = NULL;
    assert_int_equal(0, list_length(l));

    // initial append
    {
        int        i = 3;
        list_item *item = list_append(&l, &i, sizeof(i));
        assert_ptr_equal(item, list_back(l));
        assert_int_equal(*(int *) item, i);
        static const int expected[] = {3};
        assert_non_null(l);
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // append a few more
    {
        for (int i = 4; i < 9; i++) {
            list_item *item = list_append(&l, &i, sizeof(i));
            assert_ptr_equal(item, list_back(l));
            assert_int_equal(*(int *) item, i);
        }
        static const int expected[] = {3, 4, 5, 6, 7, 8};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // insert at front
    {
        int        i = 1;
        list_item *item = list_insert(&l, &i, sizeof(i));
        assert_ptr_equal(item, list_front(l));
        assert_int_equal(*(int *) item, i);
        static const int expected[] = {1, 3, 4, 5, 6, 7, 8};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // insert before (front)
    {
        int        i = 0;
        list_item *where = list_front(l);
        list_item *item = list_insert_before(where, &i, sizeof(i));
        assert_ptr_equal(item, list_front(l));
        assert_int_equal(*(int *) item, i);
        static const int expected[] = {0, 1, 3, 4, 5, 6, 7, 8};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // insert before
    {
        int        i = 2;
        list_item *where = list_next(list_next(list_front(l)));
        list_item *item = list_insert_before(where, &i, sizeof(i));
        assert_ptr_equal(list_prev(where), item);
        assert_ptr_equal(list_next(item), where);
        assert_int_equal(*(int *) item, i);
        static const int expected[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // append (NULL data)
    {
        list_item *item = list_append(&l, NULL, sizeof(int));
        assert_ptr_equal(item, list_back(l));
        assert_non_null(item);
        assert_int_equal(*(int *) item, 0);
        *(int *) item = 10;
        static const int expected[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 10};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // insert after
    {
        int        i = 9;
        list_item *where = list_prev(list_back(l));
        list_item *item = list_insert_after(where, &i, sizeof(i));
        assert_ptr_equal(list_next(where), item);
        static const int expected[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // insert after (end)
    {
        int        i = 11;
        list_item *where = list_back(l);
        list_item *item = list_insert_after(where, &i, sizeof(i));
        assert_ptr_equal(item, list_back(l));
        static const int expected[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // find
    {
        static const int expected_list[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
        for (size_t i = 0; i < ARRAY_SIZE(expected_list); i++) {
            const int *expected = &expected_list[i];
            assert_non_null(list_find(l, expected, sizeof(int)));
            assert_int_equal(*(int *) list_find(l, expected, sizeof(int)), *expected);
        }
    }

    // remove (back)
    {
        list_remove(list_back(l));
        static const int expected[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // remove (front)
    {
        list_remove(list_front(l));
        static const int expected[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // find (not found)
    {
        int i = 0;
        assert_null(list_find(l, &i, sizeof(i)));
    }

    // insert a duplicate
    {
        int i = 5;
        list_insert_before(list_find(l, &i, sizeof(i)), &i, sizeof(i));
        static const int expected[] = {1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // find the two 5s
    {
        int        i = 5;
        list_item *first = list_find(l, &i, sizeof(i));
        assert_non_null(first);
        assert_int_equal(*(int *) first, i);
        list_item *second = list_find_next(first, &i, sizeof(i));
        assert_non_null(second);
        assert_int_equal(*(int *) second, i);
        assert_ptr_not_equal(first, second);

        assert_null(list_find_next(second, &i, sizeof(i)));

        // remove both
        list_remove(first);
        list_remove(second);
    }

    // check the final result
    {
        static const int expected[] = {1, 2, 3, 4, 6, 7, 8, 9, 10};
        validate_int_list(l, expected, ARRAY_SIZE(expected));
    }

    // check membership
    {
        list_item *item = list_front(l);
        list list2 = NULL;
        int i = 1;
        assert_true(list_append(&list2, &i, sizeof(i)));
        while (item) {
            assert_true(list_is_member(l, item));
            assert_false(list_is_member(l, list_front(list2)));
            assert_false(list_is_member(list2, item));
            item = list_next(item);
        }
        list_destroy(&list2);
    }

    // remove all
    {
        list_item *item = list_front(l);
        while (item) {
            list_item *next = list_next(item);
            list_remove(item);
            item = next;
        }
        assert_null(list_front(l));
        assert_null(list_back(l));
        assert_int_equal(list_length(l), 0);
    }

    list_destroy(&l);
    assert_null(l);
}
