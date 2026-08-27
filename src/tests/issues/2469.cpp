
#include "../rnp_tests.h"
#include "../support.h"
#include <librepgp/stream-ctx.h>
#include "key.hpp"
#include "ffi-priv-types.h"


TEST_F(rnp_tests, test_ffi_output_memory_get_buf_empty)
{
    rnp_output_t output = NULL;
    assert_rnp_success(rnp_output_to_memory(&output, 0));

    uint8_t *buf = (uint8_t *) 0x1; // sentinel, should be overwritten
    size_t   len = 123;             // sentinel, should be overwritten
    assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &len, false));
    assert_int_equal(len, 0);
    assert_null(buf);

    rnp_output_destroy(output);
}