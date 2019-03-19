#define BOOST_TEST_MODULE rnp_tests
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include <fstream>
#include "rnp/rnp2.h"
#include "support.h"

struct RNPTests {
    public:
    RNPTests() {
        m_dir = make_temp_dir();
        assert_int_equal(0, setenv("HOME", m_dir, 1));
        assert_int_equal(0, chdir(m_dir));
        copy_recursively(getenv("RNP_TEST_DATA"), m_dir);
    }

    ~RNPTests() {
        free(m_dir);
    }
    private:
    char *m_dir;
};

BOOST_FIXTURE_TEST_SUITE(ffi, RNPTests);
BOOST_AUTO_TEST_CASE(test_case)
{
    std::string data;

    // enarmor plain message
    const std::string msg("this is a test");
    data.clear();
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) msg.data(), msg.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_enarmor(input, output, "message"));

        rnp_output_memory_get_buf(output, &buf, &buf_size, false);
        data = std::string(buf, buf + buf_size);
        assert_true(starts_with(data, "-----BEGIN PGP MESSAGE-----\r\n"));
        assert_true(ends_with(data, "-----END PGP MESSAGE-----\r\n"));

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) data.data(), data.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_dearmor(input, output));

        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_size, false));
        std::string dearmored(buf, buf + buf_size);
        assert_true(msg == dearmored);

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }

    // enarmor public key
    data.clear();
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        // enarmor
        assert_rnp_success(rnp_input_from_path(&input, "data/keyrings/1/pubring.gpg"));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_enarmor(input, output, NULL));

        rnp_output_memory_get_buf(output, &buf, &buf_size, false);
        data = std::string(buf, buf + buf_size);
        assert_true(starts_with(data, "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"));
        assert_true(ends_with(data, "-----END PGP PUBLIC KEY BLOCK-----\r\n"));

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
    // dearmor public key
    {
        uint8_t *    buf = NULL;
        size_t       buf_size = 0;
        rnp_input_t  input = NULL;
        rnp_output_t output = NULL;

        assert_rnp_success(
          rnp_input_from_memory(&input, (const uint8_t *) data.data(), data.size(), true));
        assert_rnp_success(rnp_output_to_memory(&output, 0));

        assert_rnp_success(rnp_dearmor(input, output));

        assert_rnp_success(rnp_output_memory_get_buf(output, &buf, &buf_size, false));
        std::string   dearmored(buf, buf + buf_size);
        std::ifstream inf("data/keyrings/1/pubring.gpg", std::ios::binary | std::ios::ate);
        std::string   from_disk(inf.tellg(), ' ');
        inf.seekg(0);
        inf.read(&from_disk[0], from_disk.size());
        inf.close();
        assert_true(dearmored == from_disk);

        rnp_input_destroy(input);
        rnp_output_destroy(output);
    }
}
BOOST_AUTO_TEST_SUITE_END()

