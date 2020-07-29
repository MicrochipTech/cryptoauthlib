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
#include "jwt/atca_jwt.h"

/* Configuration Options */
#define ATCA_JWT_TEST_DEVICES  ( DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) )
#define ATCA_JWT_TEST_SIGNING_KEY_ID    (0)

/* Test Vectors */
static const char atca_jwt_test_vector_header[] = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.";
static const char atca_jwt_test_vector_claim_string[] = ".{\"Test\":\"Value\"";
static const char atca_jwt_test_vector_claim_numeric[] = ".{\"Test\":12345";

static const int atca_jwt_test_vector_payload_iat = 123456789;
static const int atca_jwt_test_vector_payload_exp = 234567890;
static const char atca_jwt_test_vector_payload_aud[] = "audience";
static const char atca_jwt_test_vector_payload[] =
    "eyJpYXQiOjEyMzQ1Njc4OSwiZXhwIjoyMzQ1Njc4OTAsImF1ZCI6ImF1ZGllbmNlIn0.";

static const uint8_t atca_jwt_test_vector_pubkey[ATCA_ECCP256_PUBKEY_SIZE] = {
    0x01, 0x31, 0x95, 0xB2, 0x30, 0x4D, 0xC7, 0x7E, 0xC0, 0x94, 0x6A, 0x02, 0xE0, 0x4E, 0xDC, 0x51,
    0xED, 0xF7, 0xE8, 0x77, 0x9D, 0x44, 0xC9, 0x2B, 0x90, 0xB8, 0xF7, 0xC3, 0x4B, 0x72, 0x9B, 0xD8,
    0x11, 0x74, 0x6E, 0x88, 0x31, 0x9A, 0xE5, 0xC9, 0xEF, 0x68, 0x34, 0x51, 0x34, 0x7F, 0xAB, 0xF9,
    0xC2, 0x2C, 0x81, 0x37, 0x8A, 0xA2, 0xF3, 0x6E, 0xB9, 0x54, 0x4C, 0x5A, 0xF9, 0x62, 0xF6, 0xED
};
static const char atca_jwt_test_vector_sig[] =
    "0v-QYqmt2Zc0gqVaK0IY2bRWGgTZ4S3DVF2rsZFPXVu1UM9F_ACuin0HkpqNIsjYH6IXXnzMi_xBVdY4ILOrkQ";

static const char atca_jwt_test_vector_invalid_sig[] =
    "OgnwEMP1l7x67pYNgGxHAIyHZkAwRT3cbWHKCrH4Zi5fOrxXLwFUpnF_0FdPGz3WakETEeWYg79h36tZG_Q_uw";

TEST_GROUP(atca_jwt);

TEST_SETUP(atca_jwt)
{
}

TEST_TEAR_DOWN(atca_jwt)
{
}

TEST(atca_jwt, check_payload_start_period)
{
    atca_jwt_t jwt;
    char buf[4] = { '.', 0, 0, 0 };

    jwt.buf = buf;
    jwt.buflen = sizeof(buf);
    jwt.cur = 1;

    atca_jwt_check_payload_start(&jwt);

    TEST_ASSERT_EQUAL(2, jwt.cur);

    TEST_ASSERT_EQUAL('{', buf[1]);
}

TEST(atca_jwt, check_payload_start_brace)
{
    atca_jwt_t jwt;
    char buf[4] = { '{', 0, 0, 0 };

    jwt.buf = buf;
    jwt.buflen = sizeof(buf);
    jwt.cur = 1;

    atca_jwt_check_payload_start(&jwt);

    TEST_ASSERT_EQUAL(1, jwt.cur);

    TEST_ASSERT_EQUAL(0, buf[1]);
}

TEST(atca_jwt, check_payload_start_other)
{
    atca_jwt_t jwt;
    char buf[4] = { '\"', 0, 0, 0 };

    jwt.buf = buf;
    jwt.buflen = sizeof(buf);
    jwt.cur = 1;

    atca_jwt_check_payload_start(&jwt);

    TEST_ASSERT_EQUAL(2, jwt.cur);

    TEST_ASSERT_EQUAL(',', buf[1]);
}

TEST(atca_jwt, check_payload_start_invalid_params)
{
    atca_jwt_t jwt = { NULL, 4, 0 };
    char buf[4] = { '\"', 0, 0, 0 };

    atca_jwt_check_payload_start(NULL);
    TEST_ASSERT(true);

    atca_jwt_check_payload_start(&jwt);
    TEST_ASSERT(true);

    jwt.buf = buf;
    jwt.buflen = 1;
    jwt.cur = 1;

    atca_jwt_check_payload_start(&jwt);

    TEST_ASSERT_EQUAL(0, buf[1]);
}

TEST(atca_jwt, init)
{
    atca_jwt_t jwt;
    char buf[512];
    size_t len = strlen(atca_jwt_test_vector_header);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_init(&jwt, buf, sizeof(buf)));

    TEST_ASSERT_EQUAL(buf, jwt.buf);

    TEST_ASSERT_EQUAL(sizeof(buf), jwt.buflen);

    TEST_ASSERT_EQUAL(jwt.cur, len);

    TEST_ASSERT_EQUAL_MEMORY(atca_jwt_test_vector_header, buf, len);
}

TEST(atca_jwt, init_invalid_params)
{
    atca_jwt_t jwt;
    char buf[512];

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_init(NULL, buf, 512));
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_init(&jwt, NULL, 512));
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_init(&jwt, buf, 0));
}

TEST(atca_jwt, claim_add_string)
{
    atca_jwt_t jwt;
    char buf[512] = { '.' };

    jwt.buf = buf;
    jwt.buflen = sizeof(buf);
    jwt.cur = 1;

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_add_claim_string(&jwt, "Test", "Value"));

    TEST_ASSERT_EQUAL_MEMORY(atca_jwt_test_vector_claim_string, buf,
                             strlen(atca_jwt_test_vector_claim_string));
}

TEST(atca_jwt, claim_add_string_invalid_params)
{
    atca_jwt_t jwt;
    char buf[512] = { '.', 0 };

    jwt.buf = buf;
    jwt.buflen = sizeof(buf);
    jwt.cur = 1;

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_add_claim_string(NULL, "Test", "Value"));

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_add_claim_string(&jwt, NULL, "Value"));
    TEST_ASSERT_EQUAL_MEMORY(".", buf, 2);

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_add_claim_string(&jwt, "Test", NULL));
    TEST_ASSERT_EQUAL_MEMORY(".", buf, 2);
}

TEST(atca_jwt, claim_add_numeric)
{
    atca_jwt_t jwt;
    char buf[512] = { '.' };

    jwt.buf = buf;
    jwt.buflen = sizeof(buf);
    jwt.cur = 1;

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_add_claim_numeric(&jwt, "Test", 12345));

    TEST_ASSERT_EQUAL_MEMORY(atca_jwt_test_vector_claim_numeric, buf,
                             strlen(atca_jwt_test_vector_claim_numeric));
}

TEST(atca_jwt, claim_add_numeric_invalid_params)
{
    atca_jwt_t jwt;
    char buf[512] = { '.', 0 };

    jwt.buf = buf;
    jwt.buflen = sizeof(buf);
    jwt.cur = 1;

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_add_claim_numeric(NULL, "Test", 12345));

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_add_claim_numeric(&jwt, NULL, 12345));
    TEST_ASSERT_EQUAL_MEMORY(".", buf, 2);
}

TEST(atca_jwt, verify_invalid_params)
{
    char buf[512];
    uint8_t pubkey[ATCA_ECCP256_PUBKEY_SIZE];

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_verify(NULL, sizeof(buf), pubkey));

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_verify(buf, 0, pubkey));

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_verify(buf, sizeof(buf), NULL));
}

TEST(atca_jwt, finalize_invalid_params)
{
    atca_jwt_t jwt;
    char buf[2] = { '.', 0 };

    jwt.buf = buf;
    jwt.buflen = sizeof(buf);
    jwt.cur = 1;

    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_finalize(NULL, ATCA_JWT_TEST_SIGNING_KEY_ID));

    jwt.buf = NULL;
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_finalize(&jwt, ATCA_JWT_TEST_SIGNING_KEY_ID));
    jwt.buf = buf;

    jwt.buflen = 0;
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_finalize(&jwt, ATCA_JWT_TEST_SIGNING_KEY_ID));
    jwt.buflen = sizeof(buf);

    jwt.cur = 0;
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, atca_jwt_finalize(&jwt, ATCA_JWT_TEST_SIGNING_KEY_ID));
}

/* These tests require an attached and configured device */
TEST_GROUP(atca_jwt_crypto);

TEST_SETUP(atca_jwt_crypto)
{
    ATCA_STATUS status = atcab_init(gCfg);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    test_assert_config_is_locked();
}

TEST_TEAR_DOWN(atca_jwt_crypto)
{
    ATCA_STATUS status;

    status = atcab_wakeup();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_sleep();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_release();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_jwt_crypto, verify)
{
    char buf[512];

    snprintf(buf, sizeof(buf), "%s%s%s",
             atca_jwt_test_vector_header,
             atca_jwt_test_vector_payload,
             atca_jwt_test_vector_sig);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_verify(buf, sizeof(buf),
                                                    atca_jwt_test_vector_pubkey));
}

TEST(atca_jwt_crypto, verify_invalid)
{
    char buf[512];

    snprintf(buf, sizeof(buf), "%s%s%s",
             atca_jwt_test_vector_header,
             atca_jwt_test_vector_payload,
             atca_jwt_test_vector_invalid_sig);

    TEST_ASSERT_EQUAL(ATCA_CHECKMAC_VERIFY_FAILED, atca_jwt_verify(buf, sizeof(buf),
                                                                   atca_jwt_test_vector_pubkey));
}

TEST(atca_jwt_crypto, finalize)
{
    atca_jwt_t jwt;
    char buf[512];
    size_t len;
    char * payload;
    char * sig;
    uint8_t pubkey[ATCA_ECCP256_PUBKEY_SIZE];

    /* Build the JWT */
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_init(&jwt, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_add_claim_numeric(&jwt, "iat", atca_jwt_test_vector_payload_iat));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_add_claim_numeric(&jwt, "exp", atca_jwt_test_vector_payload_exp));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_add_claim_string(&jwt, "aud", atca_jwt_test_vector_payload_aud));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_finalize(&jwt, ATCA_JWT_TEST_SIGNING_KEY_ID));

    /* Check header */
    payload = strchr(buf, '.') + 1;
    len = strlen(atca_jwt_test_vector_header);
    TEST_ASSERT_EQUAL(len, payload - buf);
    TEST_ASSERT_EQUAL_MEMORY(atca_jwt_test_vector_header, buf, len);

    /* Check payload */
    sig = strchr(payload, '.') + 1;
    len = strlen(atca_jwt_test_vector_payload);
    TEST_ASSERT_EQUAL(len, sig - payload);
    TEST_ASSERT_EQUAL_MEMORY(atca_jwt_test_vector_payload, payload, len);

    /* Load the device public key */
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atcab_get_pubkey(ATCA_JWT_TEST_SIGNING_KEY_ID, pubkey));

    /* Verify the token with the public key */
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, atca_jwt_verify(buf, sizeof(buf), pubkey));
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info jwt_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_jwt,        check_payload_start_period),                ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt,        check_payload_start_brace),                 ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt,        check_payload_start_other),                 ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt,        check_payload_start_invalid_params),        ATCA_JWT_TEST_DEVICES},

    { REGISTER_TEST_CASE(atca_jwt,        init),                                      ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt,        init_invalid_params),                       ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt,        claim_add_string),                          ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt,        claim_add_string_invalid_params),           ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt,        claim_add_numeric),                         ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt,        claim_add_numeric_invalid_params),          ATCA_JWT_TEST_DEVICES},

    { REGISTER_TEST_CASE(atca_jwt,        verify_invalid_params),                     ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt,        finalize_invalid_params),                   ATCA_JWT_TEST_DEVICES},

    { REGISTER_TEST_CASE(atca_jwt_crypto, verify),                                    ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt_crypto, verify_invalid),                            ATCA_JWT_TEST_DEVICES},
    { REGISTER_TEST_CASE(atca_jwt_crypto, finalize),                                  ATCA_JWT_TEST_DEVICES},

    { (fp_test_case)NULL,                 (uint8_t)0 },                               /* Array Termination element*/
};
// *INDENT-ON*