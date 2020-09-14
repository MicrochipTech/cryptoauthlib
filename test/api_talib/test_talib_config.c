/**
 * \file
 * \brief TA Library API (tablib) Test Configuration
 *
 * \copyright (c) 2015-2020 Microchip Technology Inc. and its subsidiaries.
 *
 * \page License
 *
 * Subject to your compliance with these terms, you may use Microchip software
 * and any derivatives exclusively with Microchip products. It is your
 * responsibility to comply with third party license terms applicable to your
 * use of third party software (including open source software) that may
 * accompany Microchip software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
 * SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
 * OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
 * MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
 * FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
 * LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
 * THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
 * THIS SOFTWARE.
 */

#include "atca_test.h"
#include "test_talib.h"
#include "test_ecc_certificate_chain.h"

#if ATCA_TA_SUPPORT

const uint8_t test_ta100_configdata[TA_CONFIG_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
    0x12, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static ta_element_attributes_t attr_rw_data = { 3, 72, 0, 0, 0, 0x54, 4 };
static ta_element_attributes_t attr_ecc_private = { 1, 0x1700, 0, 0, 0, 0x01, 0 };
static ta_element_attributes_t attr_ecc_public = { 0, 0x00, 0, 0, 0, 0x55, 4 };
static ta_element_attributes_t attr_hmac_key = { 0x42, 0x0600, 0, 0, 0, 0x55, 8 };
static ta_element_attributes_t attr_aes_key = { 0x62, 0x0600, 0, 0, 0, 0x55, 8 };
static ta_element_attributes_t attr_ecc_root_public = { 0, 0x06FF, 0, 0, 0, 0x55, 4 };

uint8_t auth_hmac_key[] = { 0xa2, 0x26, 0xe1, 0x65, 0x69, 0x01, 0x80, 0xeb, 0x1a, 0x0c, 0x9c, 0x5b, 0x64, 0x5e, 0x42, 0x02,
                            0xfa, 0x2f, 0x4f, 0xfd, 0x68, 0x75 };


static device_object_meta_t talib_config_object_data[] =
{
    { TEST_TYPE_ECC_SIGN,     0x8102,                                  &attr_ecc_private                               },
    { TEST_TYPE_ECC_VERIFY,   0x8103,                                  &attr_ecc_public                                },
    { TEST_TYPE_ECC_GENKEY,   TA_HANDLE_VOLATILE_REGISTER0,            &attr_ecc_private                               },
    { TEST_TYPE_ECDH,         TA_HANDLE_VOLATILE_REGISTER1,            &attr_ecc_private                               },
    { TEST_TYPE_AES,          0x8106,                                  &attr_aes_key                                   },
    { TEST_TYPE_HMAC,         0x8105,                                  &attr_hmac_key                                  },
    { TEST_TYPE_AUTH_HMAC,    0xAB1D,                                  &attr_hmac_key                                  },
    { TEST_TYPE_AUTH_GCM,     0xAAD1,                                  &attr_aes_key                                   },
    { TEST_TYPE_AUTH_CMAC,    0x9492,                                  &attr_aes_key                                   },
    { TEST_TYPE_DATA,         0x8101,                                  &attr_rw_data                                   },
    { TEST_TYPE_ECC_ROOT_KEY, 0x8107,                                  &attr_ecc_root_public                           },
    { 0,                      0,                                       NULL                                            }
};

ATCA_STATUS talib_config_get_handle_by_test(uint8_t test_type, uint16_t* handle)
{
    ATCA_STATUS status = ATCA_UNIMPLEMENTED;
    device_object_meta_t* ptr = talib_config_object_data;

    for (; ptr->test_type; ptr++)
    {
        if (ptr->test_type == test_type)
        {
            *handle = ptr->handle;
            status = ATCA_SUCCESS;
            break;
        }
    }
    return status;
}


int talib_config_print_handles(int argc, char* argv[])
{
    ATCA_STATUS status;
    uint16_t handles[20];
    size_t handle_count = sizeof(handles) / sizeof(uint16_t);

    status = atcab_init(gCfg);
    memset(handles, 0, sizeof(handles));

    if (ATCA_SUCCESS == status)
    {
        status = talib_info_get_handles_array(atcab_get_device(), handles, &handle_count);
    }

    if (ATCA_SMALL_BUFFER == status)
    {
        printf("\rTruncated List - actual %zu\r\n", handle_count);
        handle_count = sizeof(handles) / sizeof(uint16_t);
        status = ATCA_SUCCESS;
    }

    for (int i = 0; i < (int)handle_count && !status; i++)
    {
        uint8_t handle_info[9];
        status = talib_info_get_handle_info(atcab_get_device(), handles[i], handle_info);

        printf("\rHandle: 0x%04x, Class: %d\r\n", handles[i], handle_info[0] & TA_HANDLE_INFO_CLASS_MASK);
    }

    return 0;
}

int talib_config_clear_handles(int argc, char* argv[])
{
    ATCA_STATUS status;
    uint16_t handles[20];
    size_t handle_count = sizeof(handles) / sizeof(uint16_t);
    int i;

    status = atcab_init(gCfg);
    memset(handles, 0, sizeof(handles));

    if (ATCA_SUCCESS == status)
    {
        status = talib_info_get_handles_array(atcab_get_device(), handles, &handle_count);
    }

    if (ATCA_SMALL_BUFFER == status)
    {
        printf("\rTruncated List - actual %zu\r\n", handle_count);
        handle_count = sizeof(handles) / sizeof(uint16_t);
        status = ATCA_SUCCESS;
    }

    for (i = 0; i < (int)handle_count; i++)
    {
        status = talib_delete_handle(atcab_get_device(), handles[i]);
        if (status)
        {
            printf("\n0x%04x: Failed to Delete\n", handles[i]);
        }
        else
        {
            printf("\n0x%04x: Deleted\r\n", handles[i]);
        }
    }
    return 0;
}

int talib_configure_device(int argc, char* argv[])
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);

    if (ATCA_SUCCESS == status)
    {
        device_object_meta_t * create_ptr = talib_config_object_data;

        for (; create_ptr->test_type; create_ptr++)
        {
            ta_element_attributes_t* attr_ptr = (ta_element_attributes_t*)create_ptr->attributes;

            if (TEST_TYPE_HMAC == create_ptr->test_type)
            {
                status = talib_create_hmac_element_with_handle(atcab_get_device(), 32, create_ptr->handle, attr_ptr);

                if (ATCA_SUCCESS == status)
                {
                    status = talib_write_element(atcab_get_device(), create_ptr->handle, 32, g_slot4_key);
                }

            }
            else if (TEST_TYPE_AUTH_HMAC == create_ptr->test_type)
            {
                status = talib_create_hmac_element_with_handle(atcab_get_device(), sizeof(auth_hmac_key), create_ptr->handle, attr_ptr);

                if (ATCA_SUCCESS == status)
                {
                    status = talib_write_element(atcab_get_device(), create_ptr->handle, sizeof(auth_hmac_key), auth_hmac_key);
                }
            }

            else if (TEST_TYPE_ECC_ROOT_KEY == create_ptr->test_type)
            {
                status = talib_create_element_with_handle(_gDevice, create_ptr->handle, attr_ptr);

                if (ATCA_SUCCESS == status)
                {
                    status = talib_write_element(_gDevice, create_ptr->handle, sizeof(test_ecc_root_public_key), test_ecc_root_public_key);
                }
            }

            else
            {
                status = talib_create_element_with_handle(atcab_get_device(), create_ptr->handle, attr_ptr);
            }

            if (status && (TA_BAD_HANDLE != status))
            {
                printf("Handle 0x%04x Create Failed (%x)\n", create_ptr->handle, status);
            }

            if (!status && (create_ptr->test_type == TEST_TYPE_ECC_SIGN))
            {
                status = talib_genkey_compat(atcab_get_device(), create_ptr->handle, NULL);
            }

        }
    }

    return 0;
}

extern t_test_case_info* talib_auth_tests[];
extern t_test_case_info* talib_create_tests[];
extern t_test_case_info* talib_aes_tests[];
extern t_test_case_info* talib_counter_tests[];
extern t_test_case_info* talib_ecdh_tests[];
extern t_test_case_info* talib_export_import_tests[];
extern t_test_case_info* talib_genkey_tests[];
extern t_test_case_info* talib_info_tests[];
extern t_test_case_info* talib_kdf_tests[];
extern t_test_case_info* talib_mac_tests[];
extern t_test_case_info* talib_managecert_tests[];
extern t_test_case_info* talib_power_tests[];
extern t_test_case_info* talib_random_tests[];
extern t_test_case_info* talib_rsa_enc_tests[];
extern t_test_case_info* talib_selftest_tests[];
extern t_test_case_info* talib_sha_tests[];
extern t_test_case_info* talib_sign_tests[];
extern t_test_case_info* talib_verify_tests[];
extern t_test_case_info* talib_write_tests[];

void run_all_talib_tests(void)
{
    RunAllTests(talib_managecert_tests);
    RunAllTests(talib_aes_tests);
    RunAllTests(talib_auth_tests);
    RunAllTests(talib_counter_tests);
    RunAllTests(talib_create_tests);
    RunAllTests(talib_ecdh_tests);
    RunAllTests(talib_export_import_tests);
    RunAllTests(talib_genkey_tests);
    RunAllTests(talib_info_tests);
    RunAllTests(talib_kdf_tests);
    RunAllTests(talib_mac_tests);
    RunAllTests(talib_power_tests);
    RunAllTests(talib_random_tests);
    RunAllTests(talib_rsa_enc_tests);
    RunAllTests(talib_selftest_tests);
    RunAllTests(talib_sha_tests);
    RunAllTests(talib_sign_tests);
    RunAllTests(talib_verify_tests);
    RunAllTests(talib_write_tests);
}

int run_talib_tests(int argc, char* argv[])
{
#ifndef ATCA_NO_HEAP
    hal_test_set_memory_f(unity_malloc, unity_free);
#endif

    return run_test(argc, argv, run_all_talib_tests);
}


#endif
