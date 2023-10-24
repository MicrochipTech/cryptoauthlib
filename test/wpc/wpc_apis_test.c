/**
 * \file
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

#include "third_party/unity/unity_fixture.h"
#include "atca_test.h"
#include "app/wpc/wpc_apis.h"
#include "app/wpc/zcust_def_1_signer.h"
#include "app/wpc/zcust_def_2_device.h"
#include "atcacert/atcacert_def.h"

TEST_GROUP(wpc_apis);

TEST_SETUP(wpc_apis)
{
    atcab_init(gCfg);
    test_assert_data_is_locked();
}

TEST_TEAR_DOWN(wpc_apis)
{
    atcab_release();
}

TEST(wpc_apis, wpc_get_digests_request_response)
{
    int ret;
    uint8_t request[2];
    uint8_t response[35];
    char displaystr[128];
    uint16_t buflen;
    size_t displaylen;
    ATCADevice device = atcab_get_device();


    /* Read the chain digest manually first */

    buflen = sizeof(request);
    ret = wpc_msg_get_digests(request, &buflen, 0x01);
    TEST_ASSERT_SUCCESS(ret);

    displaylen = sizeof(displaystr);
    atcab_bin2hex(request, sizeof(request), displaystr, &displaylen);
    printf("Digests request: \r\n%s\r\n", displaystr);

    buflen = sizeof(response);
    ret = wpc_msg_digests(device, response, &buflen, request);
    TEST_ASSERT_SUCCESS(ret);

    displaylen = sizeof(displaystr);
    atcab_bin2hex(response, sizeof(response), displaystr, &displaylen);
    printf("Digests response: \r\n%s\r\n", displaystr);
}

TEST(wpc_apis, wpc_get_certificate_request_response)
{
    int ret;
    uint8_t request[2];
    uint8_t response[1024];
    uint8_t buffer[512];
    uint16_t buflen;
    ATCADevice device = atcab_get_device();

    /* Load the chain digest manually */

    /* Request the full cert chain */
    buflen = sizeof(request);
    ret = wpc_msg_get_certificate(request, &buflen, 0, 0, 0);
    TEST_ASSERT_SUCCESS(ret);

    buflen = sizeof(response);
    ret = wpc_msg_certificate(device, response, &buflen, request, buffer, (uint16_t)sizeof(buffer));
    TEST_ASSERT_SUCCESS(ret);

    /* Verify the chain digest matches */

    /* Verify the certificate chain is correct */
}

TEST(wpc_apis, wpc_challenge_request_response)
{
    int ret;
    uint8_t request[2 + 16];
    uint8_t response[3 + 32 + 32];
    uint16_t buflen;
    char displaystr[256];
    size_t displaylen;
    ATCADevice device = atcab_get_device();

    /* Read the public key from the device manually */

    /* Generate a challenge message */
    buflen = sizeof(request);
    ret = wpc_msg_challenge(device, request, &buflen, 0);
    TEST_ASSERT_SUCCESS(ret);

    displaylen = sizeof(displaystr);
    atcab_bin2hex(request, sizeof(request), displaystr, &displaylen);
    printf("Challenge request: \r\n%s\r\n", displaystr);

    buflen = sizeof(response);
    ret = wpc_msg_challenge_auth(device, response, &buflen, request);
    TEST_ASSERT_SUCCESS(ret);

    displaylen = sizeof(displaystr);
    atcab_bin2hex(response, sizeof(response), displaystr, &displaylen);
    printf("Challenge auth response: \r\n%s\r\n", displaystr);

    /* Verify the challenge response */
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info wpc_apis_unit_test_info[] =
{
    { REGISTER_TEST_CASE(wpc_apis, wpc_get_digests_request_response),     DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(wpc_apis, wpc_get_certificate_request_response), DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(wpc_apis, wpc_challenge_request_response),       DEVICE_MASK(ATECC608)},
    { (fp_test_case)NULL,                                                  (uint8_t)0 },
};
// *INDENT-ON*
