/**
 * \file
 * \brief Unity tests for the cryptoauthlib Verify Command
 *
 * \copyright (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
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
#include <stdlib.h>
#include "atca_test.h"
#include "basic/atca_basic.h"
#include "host/atca_host.h"
#include "test/atca_tests.h"
#include "atca_execution.h"

TEST(atca_cmd_unit_test, counter)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint8_t increased_bin_val[4] = { 0x00 };
    uint32_t test;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build a counter command
    packet.param1 = COUNTER_MODE_INCREMENT;
    packet.param2 = 0x0000;
    status = atCounter(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(COUNTER_RSP_SIZE, packet.data[ATCA_COUNT_IDX]);
    memcpy(increased_bin_val, &packet.data[ATCA_RSP_DATA_IDX], sizeof(increased_bin_val));

    // build a counter command
    packet.param1 = COUNTER_MODE_READ;
    packet.param2 = 0x0000;
    status = atCounter(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(increased_bin_val, &packet.data[ATCA_RSP_DATA_IDX], 4);
    memcpy(&test, &packet.data[ATCA_RSP_DATA_IDX], 4);
}

TEST(atca_cmd_basic_test, counter_test)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint32_t counter_value1;
    uint32_t counter_value2;

    test_assert_config_is_locked();

    // Read current counter value
    status = atcab_counter_read(1, &counter_value1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Increment counter and make sure new value is 1 higher
    status = atcab_counter_increment(1, &counter_value2);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(counter_value1 + 1, counter_value2);

    // Increment again with NULL
    status = atcab_counter_increment(1, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Re-read counter value to double check
    status = atcab_counter_read(1, &counter_value1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(counter_value2 + 1, counter_value1);

    // Check bad counter ID
    status = atcab_counter_increment(3, NULL);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
}

/*
   The test case implements the counter match function in ECC608A. Counter[0] is
   incremented to a value less than (32-counter_limit) and counter match slot data
   is written to value that is greater than the counter[0] value by counter_limit,
   so that only once the private key in slot 0 can be used for signing and next
   time signing with the key,returns an execution error. Finally writing the match
   slot data value to a higher value so that further test executes with private
   key.
 */
TEST(atca_cmd_basic_test, counter_match)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t msg[ATCA_SHA_DIGEST_SIZE];
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    uint8_t signature[ATCA_SIG_SIZE];
    uint16_t private_key_id = 0;
    bool is_verified = false;
    uint8_t counter_match_slot_data[32];
    uint32_t counter_match;
    uint32_t counter0_value;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    // Read the current counter 0 value
    status = atcab_counter_read(0, &counter0_value);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("Starting counter 0: %u\r\n", (unsigned int)counter0_value);

    // Increase the counter 0 value so that it is aligned to multiple of 32-counter_limit
    while ((uint8_t)(counter0_value % 32) < (32 - 1))
    {
        status = atcab_counter_increment(0, &counter0_value);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    }
    printf("Incrementing counter 0 to 32-byte boundary: %u\r\n", (unsigned int)counter0_value);

    // Update the counter match value
    counter_match = counter0_value + 1; // Calculate the counter match value to be written in slot
    status = atcah_encode_counter_match(counter_match, counter_match_slot_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 10, 0, counter_match_slot_data, sizeof(counter_match_slot_data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("Setting counter match to: %u\r\n", (unsigned int)counter_match);

    // Generate random message
    status = atcab_random(msg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate key pair
    status = atcab_genkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign message with key tied to counter 0, it should succeed because the limit hasn't been reached yet
    status = atcab_sign(private_key_id, msg, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validate counter change
    status = atcab_counter_read(0, &counter0_value);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("Counter 0 after successful sign: %u\r\n", (unsigned int)counter0_value);
    TEST_ASSERT_EQUAL(counter_match, counter0_value); // Counter should now equal the counter match value

    // Verify signature
    status = atcab_verify_extern(msg, signature, public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    // Sign message with key tied to counter 0, it should fail because the limit has been reached
    status = atcab_sign(private_key_id, msg, signature);
    TEST_ASSERT_EQUAL(ATCA_EXECUTION_ERROR, status);

    // Validate counter doesn't change
    status = atcab_counter_read(0, &counter0_value);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("Counter 0 after failed sign: %u\r\n", (unsigned int)counter0_value);
    TEST_ASSERT_EQUAL(counter_match, counter0_value); // Counter should not increment after reaching counter match

    // Set counter match value to high limit so the slot can be used for other tests
    status = atcah_encode_counter_match((COUNTER_MAX_VALUE - 31), counter_match_slot_data);                           // The counter match value should be aligned for 32
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 10, 0, counter_match_slot_data, sizeof(counter_match_slot_data)); //Writing the maximum value to the slot for the remaning test cases to execute
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/*
   Test the counter 1 for the different value range.
   Write different range of values to counter 1 configuration zone and read the value to verify it.
 */
TEST(atca_cmd_basic_test, counter_write_test)
{

    ATCA_STATUS status = ATCA_SUCCESS;
    uint16_t counter_id = 1;
    uint32_t counter_value_low = 0;
    uint32_t counter_value_mid = COUNTER_MAX_VALUE / 2;
    uint32_t counter_value_max = COUNTER_MAX_VALUE;
    uint32_t counter_read_value;

    test_assert_config_is_unlocked();

    status = atcab_write_config_counter(counter_id, counter_value_low); //Write the counter_value_low to counter1 config zone
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_counter_read(counter_id, &counter_read_value);         //Read the counter_value from counter1 config zone
    TEST_ASSERT_EQUAL_MEMORY(&counter_value_low, &counter_read_value, 4); //Verify the read value with the counter_value_low


    status = atcab_write_config_counter(counter_id, counter_value_mid); //Write the counter_value_mid to counter1 config zone
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_counter_read(counter_id, &counter_read_value);         //Read the counter_value from counter1 config zone
    TEST_ASSERT_EQUAL_MEMORY(&counter_value_mid, &counter_read_value, 4); //Verify the read value with the counter_value_mid


    status = atcab_write_config_counter(counter_id, counter_value_max); //Write the counter_value_max to counter1 config zone
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_counter_read(counter_id, &counter_read_value);         //Read the counter_value from counter1 config zone
    TEST_ASSERT_EQUAL_MEMORY(&counter_value_max, &counter_read_value, 4); //Verify the read value with the counter_value_max

    //For other tests to utilize this counter,Reset the counter value to counter_value_low
    status = atcab_write_config_counter(counter_id, counter_value_low); //Write the counter_value_low to counter1 config zone
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}

// *INDENT-OFF* - Preserve formatting
t_test_case_info counter_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, counter_write_test), DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, counter_test),       DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, counter_match),                               DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },        /* Array Termination element*/
};

t_test_case_info counter_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, counter), DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A)  },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

