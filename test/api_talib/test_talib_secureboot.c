
#include "atca_config.h"
#include "cryptoauthlib.h"
#include "atca_test.h"

#if ATCA_TA_SUPPORT

const uint8_t ta_sboot_dummy_image[] =
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

static const uint8_t sboot_digest[] =
{ 0xFE, 0x10, 0x74, 0xAA, 0xEC, 0x4C, 0x28, 0x72, 0x7C, 0xDC, 0x58, 0x20, 0xB2, 0xED, 0xFB, 0x3B,
  0xFF, 0xBF, 0xC4, 0x1C, 0xC4, 0x7B, 0x0E, 0xE5, 0x87, 0xC3, 0x8A, 0xBA, 0x2A, 0x49, 0x54, 0xED, };

static const uint8_t sboot_signature[] =
{ 0x4E, 0xEF, 0xCE, 0x5E, 0x90, 0xDC, 0x04, 0xE8, 0xAA, 0x7A, 0x6A, 0x3D, 0xC2, 0xED, 0xA6, 0xE8,
  0x8F, 0x6B, 0xA8, 0x6A, 0x47, 0xB4, 0x64, 0x30, 0x9D, 0x53, 0x82, 0xA8, 0x79, 0xB0, 0x15, 0xD8,
  0xE9, 0x23, 0x2D, 0xE3, 0x7E, 0xF2, 0x44, 0x48, 0xA2, 0x16, 0xED, 0xC4, 0x14, 0xBA, 0x1C, 0x88,
  0xF4, 0x0E, 0x6A, 0xB3, 0x2F, 0xA6, 0xA7, 0xCD, 0x3E, 0x36, 0x89, 0x83, 0xEF, 0xC3, 0x2E, 0x68, };

/** \brief Execute Secureboot preset phase to allocate memory to store digest in vega
 * NOTE: This should run before config lock only
 */
TEST(atca_cmd_basic_test, sboot_preset)
{
    ATCA_STATUS status;
    bool is_preboot_enabled = false;

    // Skip if config zone is locked
    test_assert_config_is_unlocked();

    // Preboot
    if ((test_ta100_configdata[33] & TA_SECUREBOOT_CONFIG_PREBOOT_ENABLE_MASK)
        == TA_SECUREBOOT_CONFIG_PREBOOT_ENABLE_MASK)
    {
        is_preboot_enabled = true;
        status = talib_secureboot_preboot_preset(atcab_get_device(), NULL);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    }
    // Full store
    if ((test_ta100_configdata[32] & TA_SECUREBOOT_CONFIG_MODE_MASK)
             == TA_SECUREBOOT_CONFIG_FULL_STORE_MODE)
    {
        status = talib_secureboot_fullstore_preset(atcab_get_device(), NULL);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    }
    // Partial
    else if ((test_ta100_configdata[32] & TA_SECUREBOOT_CONFIG_MODE_MASK)
              == TA_SECUREBOOT_CONFIG_PARTIAL_MODE)
    {
        status = talib_secureboot_partial_preset(atcab_get_device());
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    }
    else
    {
        if (!is_preboot_enabled)
        {
            TEST_IGNORE_MESSAGE("Ignoring the test, Secureboot is not configured");
        }
    }
}

/** \brief Execute Preboot update and boot phase. Secureboot image signature
 *         verified and store the digest into vega secureboot handle.
 *         This test case run only when Preboot is enabled in sboot config
 */
TEST(atca_cmd_basic_test, sboot_preboot)
{
    ATCA_STATUS status;
    uint16_t public_key_id;
    bool is_validated;

    // skip if config is not locked
    test_assert_config_is_locked();

    // skip if setup is not locked
    test_assert_data_is_locked();

    // check secureboot preboot mode is enabled
    check_config_ta_sboot_preboot_enable();

    // Get secureboot public key handle
    status = atca_test_config_get_id(TEST_TYPE_ECC_ROOT_KEY, &public_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Secureboot preboot update phase
    status = talib_secureboot_preboot_update(atcab_get_device(), TA_HANDLE_INPUT_BUFFER,
                                                public_key_id, sboot_digest, sboot_signature,
                                                TA_SIGN_P256_SIG_SIZE, &is_validated);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_validated);




    is_validated = false;
    // Secureboot preboot boot phase
    status = talib_secureboot_preboot_boot(atcab_get_device(), TA_HANDLE_INPUT_BUFFER,
                                            sboot_digest, &is_validated);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_validated);
}

/** \brief Execute secureboot command in full asymmetric mode
 */
TEST(atca_cmd_basic_test, sboot_full_asymmetric)
{
    ATCA_STATUS status;
    uint16_t public_key_id;
    bool is_validated = false;

    // skip if config is not locked
    test_assert_config_is_locked();

    // skip if setup is not locked
    test_assert_data_is_locked();

    // check FULL asymmetric mode is enabled in secureboot configuration
    check_config_ta_sboot_enable(TA_SECUREBOOT_CONFIG_FULL_ASYMM_MODE);

    // Get secureboot public key handle
    status = atca_test_config_get_id(TEST_TYPE_ECC_ROOT_KEY, &public_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Secure boot full asymmetric
    status = talib_secureboot_full_asymmetric(atcab_get_device(), TA_HANDLE_INPUT_BUFFER,
                                              public_key_id, sboot_digest, sboot_signature,
                                              TA_SIGN_P256_SIG_SIZE, &is_validated);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_validated);
}

/** \brief Execute Full store update and boot phase. Secureboot image signature
 *         verified and store the digest into vega secureboot handle.
 *         This test case run only when full store mode is enabled in sboot config
 */
TEST(atca_cmd_basic_test, sboot_fullstore)
{
    ATCA_STATUS status;
    uint16_t public_key_id;
    bool is_validated;

    // skip if config is not locked
    test_assert_config_is_locked();

    // skip if setup is not locked
    test_assert_data_is_locked();

    // Check Full store is enabled in secureboot configuration
    check_config_ta_sboot_enable(TA_SECUREBOOT_CONFIG_FULL_STORE_MODE);


    // Get secureboot public key handle
    status = atca_test_config_get_id(TEST_TYPE_ECC_ROOT_KEY, &public_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Secureboot full store update phase
    status = talib_secureboot_fullstore_update(atcab_get_device(), TA_HANDLE_INPUT_BUFFER,
                                               public_key_id, sboot_digest, sboot_signature,
                                               TA_SIGN_P256_SIG_SIZE, &is_validated);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_validated);





    is_validated = false;
    // Secureboot full store boot phase
    status = talib_secureboot_fullstore_boot(atcab_get_device(), TA_HANDLE_INPUT_BUFFER,
                                             sboot_digest, &is_validated);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_validated);

}

/** \brief Execute partial code, final and complete phase to verify the secureboot image signature
 *         Once signature is verified, the digest will be stored in vega.
 *         this test can be run only when partial mode is enabled in sboot config
 *         NOTE: here secureboot code image size is 256 bytes. So portion_count should be one
 */
TEST(atca_cmd_basic_test, sboot_partial)
{
    ATCA_STATUS status;
    uint16_t public_key_id;
    uint8_t digest[TA_SHA256_DIGEST_SIZE];
    int32_t code_size = sizeof(ta_sboot_dummy_image);
    uint16_t index = 0;
    bool is_validated;
    uint32_t begin;
    uint32_t end;

    // skip if config is not locked
    test_assert_config_is_locked();

    // skip if setup is not locked
    test_assert_data_is_locked();

    // Check Full store is enabled in secureboot configuration
    check_config_ta_sboot_enable(TA_SECUREBOOT_CONFIG_PARTIAL_MODE);

    // secureboot partial setup phase
    status = talib_secureboot_partial_setup(atcab_get_device(), (uint32_t)code_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // secureboot partial code phase
    while (code_size > TA_SECUREBOOT_PARTIAL_CODE_SIZE_MAX)
    {
        status = talib_secureboot_partial_code(atcab_get_device(), &ta_sboot_dummy_image[index]);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        index += TA_SECUREBOOT_PARTIAL_CODE_SIZE_MAX;
        code_size -= TA_SECUREBOOT_PARTIAL_CODE_SIZE_MAX;
    }

    // secureboot partial final phase
    status = talib_secureboot_partial_final(atcab_get_device(), &ta_sboot_dummy_image[index],
                                            (size_t)code_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Get secureboot public key handle
    status = atca_test_config_get_id(TEST_TYPE_ECC_ROOT_KEY, &public_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // secureboot partial complete phase - verify signature
    status = talib_secureboot_partial_complete(atcab_get_device(), public_key_id, sboot_signature,
                                               TA_SIGN_P256_SIG_SIZE, &is_validated);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_validated);






    // get begin and end address
    status = talib_secureboot_partial_address(atcab_get_device(), &begin, &end);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // compute digest
    status = talib_sha(atcab_get_device(), (end - begin) + 1, &ta_sboot_dummy_image[begin], digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // secureboot partial boot phase
    is_validated = false;
    status = talib_secureboot_partial_boot(atcab_get_device(), TA_HANDLE_INPUT_BUFFER,
                                           digest, &is_validated);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_validated);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_secureboot_info[] =
{
    /* Dafault configuration enables pre boot and full store secureboot config mode only */
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_preset),                  DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_preboot),                 DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_full_asymmetric),         DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_fullstore),               DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_partial),                 DEVICE_MASK(TA100) },
    /* Array Termination element*/
    { (fp_test_case)NULL,                    (uint8_t)0 },
};
// *INDENT-ON*

t_test_case_info* talib_secureboot_tests[] = {
    talib_secureboot_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif