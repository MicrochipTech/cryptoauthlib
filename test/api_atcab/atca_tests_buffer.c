/**
 * \file
 * \brief Unit Tests for buffer handling utilities
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

#include "test_atcab.h"
#include "cal_buffer.h"

#define BUF_INIT_VAL    (0x5AU)
static uint8_t g_ref_buf[32];
static uint8_t g_out_buf[32];


void init_ref_array(uint8_t * buf, size_t len)
{
    size_t i;

    for (i = 0U; i < len; i++)
    {
        buf[i] = i;
    }
}

static unsigned int check_ref_array(uint8_t * buf, size_t len, size_t offset)
{
    unsigned int i;

    for (i = offset; i < len; i++)
    {
        if (buf[i] != i)
        {
            break;
        }
    }
    return i - offset;
}

static unsigned int check_array(uint8_t* buf, size_t len, uint8_t val)
{
    unsigned int i;

    for (i = 0; i < len; i++)
    {
        if (buf[i] != val)
        {
            break;
        }
    }
    return i;
}


TEST_GROUP(cal_buffer);

TEST_SETUP(cal_buffer)
{
    init_ref_array(g_ref_buf, sizeof(g_ref_buf));
    (void)memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
}

TEST_TEAR_DOWN(cal_buffer)
{

}

TEST(cal_buffer, read_bytes_params)
{
    ATCA_STATUS status;
    cal_buffer cab = CAL_BUF_INIT(0U, NULL);

    /* Invalid pointers */
    status = cal_buf_read_bytes(NULL, 0U, NULL, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Empty Buffer */
    status = cal_buf_read_bytes(&cab, 0U, NULL, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    TEST_ASSERT(sizeof(g_out_buf) == check_array(g_out_buf, sizeof(g_out_buf), BUF_INIT_VAL));

    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    TEST_ASSERT(sizeof(g_out_buf) == check_array(g_out_buf, sizeof(g_out_buf), BUF_INIT_VAL));

    /* Valid Buffer */
    cab.buf = g_ref_buf;
    cab.len = sizeof(g_ref_buf);

    /* No destination */
    status = cal_buf_read_bytes(&cab, 0U, NULL, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Try to read more bytes than exist */
    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, 64U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
    TEST_ASSERT(sizeof(g_out_buf) == check_array(g_out_buf, sizeof(g_out_buf), BUF_INIT_VAL));

    /* Try to read with an invalid offset */
    status = cal_buf_read_bytes(&cab, sizeof(g_ref_buf), g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
    TEST_ASSERT(sizeof(g_out_buf) == check_array(g_out_buf, sizeof(g_out_buf), BUF_INIT_VAL));

    /* Try to read past the end of the buffer with an offset */
    status = cal_buf_read_bytes(&cab, 20U, g_out_buf, 20U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
    TEST_ASSERT(sizeof(g_out_buf) == check_array(g_out_buf, sizeof(g_out_buf), BUF_INIT_VAL));

#if MULTIPART_BUF_EN
    cal_buffer cab_part1 = { sizeof(g_ref_buf) / 2U, &g_ref_buf[sizeof(g_ref_buf) / 2U], NULL };
    cab.len = sizeof(g_ref_buf) / 2U;
    cab.next = &cab_part1;

    /* Try to read more bytes than exist */
    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, 64U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to read with an invalid offset */
    status = cal_buf_read_bytes(&cab, sizeof(g_ref_buf), g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to read past the end of the buffer with an offset */
    status = cal_buf_read_bytes(&cab, 20U, g_out_buf, 20U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
#endif
}

TEST(cal_buffer, read_bytes)
{
    ATCA_STATUS status;
    cal_buffer cab = CAL_BUF_INIT(sizeof(g_ref_buf), g_ref_buf);

    /* Zero Length Read */
    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, 0U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(sizeof(g_out_buf) == check_array(g_out_buf, sizeof(g_out_buf), BUF_INIT_VAL));

    /* One Byte Read */
    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, 1U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, g_out_buf[0]);
    TEST_ASSERT(sizeof(g_out_buf) - 1U == check_array(&g_out_buf[1], sizeof(g_out_buf) - 1U, BUF_INIT_VAL));

    /* Full Read */
    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, sizeof(g_out_buf));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(g_ref_buf, g_out_buf, sizeof(g_out_buf));

    /* Offset Read */
    memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_read_bytes(&cab, 10U, g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&g_ref_buf[10], g_out_buf, 10U);
    TEST_ASSERT(sizeof(g_out_buf) - 10U == check_array(&g_out_buf[10], sizeof(g_out_buf) - 10U, BUF_INIT_VAL));
}

TEST(cal_buffer, write_bytes_params)
{
    ATCA_STATUS status;
    cal_buffer cab = CAL_BUF_INIT(0U, NULL);

    /* Invalid pointers */
    status = cal_buf_write_bytes(NULL, 0U, NULL, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

    /* Empty Buffer */
    status = cal_buf_write_bytes(&cab, 0U, NULL, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

    /* Valid Buffer */
    cab.buf = g_ref_buf;
    cab.len = sizeof(g_ref_buf);

    /* No Source */
    status = cal_buf_write_bytes(&cab, 0U, NULL, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

    /* Try to write more bytes than can be written */
    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, 64U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

    /* Try to write with an invalid offset */
    status = cal_buf_write_bytes(&cab, sizeof(g_ref_buf), g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

    /* Try to write past the end of the buffer with an offset */
    status = cal_buf_read_bytes(&cab, 20U, g_out_buf, 20U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

#if MULTIPART_BUF_EN
    cal_buffer cab_part1 = { sizeof(g_ref_buf) / 2U, &g_ref_buf[sizeof(g_ref_buf) / 2U], NULL };
    cab.len = sizeof(g_ref_buf) / 2U;
    cab.next = &cab_part1;

    /* Try to write more bytes than can be written */
    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, 64U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to write with an invalid offset */
    status = cal_buf_write_bytes(&cab, sizeof(g_ref_buf), g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to write past the end of the buffer with an offset */
    status = cal_buf_read_bytes(&cab, 20U, g_out_buf, 20U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
#endif
}

TEST(cal_buffer, write_bytes)
{
    ATCA_STATUS status;
    cal_buffer cab = CAL_BUF_INIT(sizeof(g_ref_buf), g_ref_buf);

    /* Zero Length Write */
    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, 0U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

    /* One Byte Write */
    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, 1U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(BUF_INIT_VAL, g_ref_buf[0]);
    TEST_ASSERT(sizeof(g_ref_buf) - 1U == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 1U));

    /* Full Write */
    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, sizeof(g_out_buf));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(g_ref_buf, g_out_buf, sizeof(g_out_buf));
    TEST_ASSERT(sizeof(g_ref_buf) == check_array(g_ref_buf, sizeof(g_ref_buf), BUF_INIT_VAL));

    /* Offset Write */
    init_ref_array(g_ref_buf, sizeof(g_ref_buf));
    status = cal_buf_write_bytes(&cab, 10U, g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&g_ref_buf[10], g_out_buf, 10U);
    /* Make sure nothing was writen before the offset */
    TEST_ASSERT(10U == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));
    /* Make sure nothing was writen after the offset + length */
    TEST_ASSERT(sizeof(g_ref_buf) - 20U == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 20U));
}

TEST(cal_buffer, read_number_params)
{
    ATCA_STATUS status;
    cal_buffer cab = CAL_BUF_INIT(0U, NULL);
    uint32_t n32bit = 0xFF0102AA;

    /* Invalid pointers */
    status = cal_buf_read_number(NULL, 0U, NULL, 0U, false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Empty Buffer */
    status = cal_buf_read_number(&cab, 0U, NULL, 0U, false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    status = cal_buf_read_number(&cab, 0U, &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    TEST_ASSERT_EQUAL(0xFF0102AA, n32bit);

    status = cal_buf_read_number(&cab, 0U, &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    TEST_ASSERT_EQUAL(0xFF0102AA, n32bit);

    /* Valid Buffer */
    cab.buf = g_ref_buf;
    cab.len = sizeof(g_ref_buf);

    /* No destination */
    status = cal_buf_read_number(&cab, 0U, NULL, 0U, false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Try to read with an invalid offset */
    status = cal_buf_read_number(&cab, sizeof(g_ref_buf), &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to read past the end of the buffer with an offset */
    status = cal_buf_read_number(&cab, sizeof(g_ref_buf) - 2U, &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

#if MULTIPART_BUF_EN
    cal_buffer cab_part1 = { sizeof(g_ref_buf) / 2U, &g_ref_buf[sizeof(g_ref_buf) / 2U], NULL };
    cab.len = sizeof(g_ref_buf) / 2U;
    cab.next = &cab_part1;

    /* No destination */
    status = cal_buf_read_number(&cab, 0U, NULL, 0U, false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Try to read with an invalid offset */
    status = cal_buf_read_number(&cab, sizeof(g_ref_buf), &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to read past the end of the buffer with an offset */
    status = cal_buf_read_number(&cab, sizeof(g_ref_buf) - 2U, &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
#endif
}

TEST(cal_buffer, read_number)
{
    ATCA_STATUS status;

#if MULTIPART_BUF_EN
    cal_buffer cab = { sizeof(g_ref_buf), g_ref_buf, NULL };
#else
    cal_buffer cab = { sizeof(g_ref_buf), g_ref_buf };
#endif
    uint32_t n32bit;
#ifdef ATCA_PLATFORM_BE
    bool platform_be = true;
#else
    bool platform_be = false;
#endif

    /* Match the buffer to the host endianness */
    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, 0U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x03020100, n32bit);

    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, 10U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x0D0C0B0A, n32bit);

    /* Ensure buffer and host endiannes are different */
    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, 0U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00010203, n32bit);

    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, 10U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x0A0B0C0D, n32bit);
}

TEST(cal_buffer, write_number_params)
{
    ATCA_STATUS status;
    cal_buffer cab = CAL_BUF_INIT(0U, NULL);
    uint32_t n32bit = 0xFF0102AA;

    /* Invalid pointers */
    status = cal_buf_write_number(NULL, 0U, NULL, 0U, false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Empty Buffer */
    status = cal_buf_write_number(&cab, 0U, NULL, 0U, false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    status = cal_buf_write_number(&cab, 0U, &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    status = cal_buf_write_number(&cab, 0U, &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Valid Buffer */
    cab.buf = g_ref_buf;
    cab.len = sizeof(g_ref_buf);

    /* No Source */
    status = cal_buf_write_number(&cab, 0U, NULL, 0U, false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Try to write with an invalid offset */
    status = cal_buf_write_number(&cab, sizeof(g_ref_buf), &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to write past the end of the buffer with an offset */
    status = cal_buf_write_number(&cab, sizeof(g_ref_buf) - 2U, &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

#if MULTIPART_BUF_EN
    cal_buffer cab_part1 = { sizeof(g_ref_buf) / 2U, &g_ref_buf[sizeof(g_ref_buf) / 2U], NULL };
    cab.len = sizeof(g_ref_buf) / 2U;
    cab.next = &cab_part1;

    /* No Source */
    status = cal_buf_write_number(&cab, 0U, NULL, 0U, false);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Try to write with an invalid offset */
    status = cal_buf_write_number(&cab, sizeof(g_ref_buf), &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to write past the end of the buffer with an offset */
    status = cal_buf_write_number(&cab, sizeof(g_ref_buf) - 2U, &n32bit, sizeof(n32bit), false);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
#endif
}

TEST(cal_buffer, write_number)
{
    ATCA_STATUS status;
    cal_buffer cab = CAL_BUF_INIT(sizeof(g_out_buf), g_out_buf);
    uint32_t n32bit = 0xFF0102AA;
    uint32_t n32bit_reversed = 0xAA0201FF;

#ifdef ATCA_PLATFORM_BE
    bool platform_be = true;
#else
    bool platform_be = false;
#endif

    /* Match the buffer to the host endianness */
    status = cal_buf_write_number(&cab, 0U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit, &g_out_buf[0], sizeof(uint32_t));
    TEST_ASSERT(sizeof(g_out_buf) - sizeof(uint32_t) == check_array(&g_out_buf[sizeof(uint32_t)], sizeof(g_out_buf) - sizeof(uint32_t), BUF_INIT_VAL));

    /* /w Offset */
    (void)memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_write_number(&cab, 10U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit, &g_out_buf[10], sizeof(uint32_t));
    TEST_ASSERT(10U == check_array(g_out_buf, 10, BUF_INIT_VAL));
    TEST_ASSERT(sizeof(g_out_buf) - sizeof(uint32_t) - 10U == check_array(&g_out_buf[sizeof(uint32_t) + 10U], sizeof(g_out_buf) - sizeof(uint32_t) - 10U, BUF_INIT_VAL));

    /* Ensure buffer and host endiannes are different */
    (void)memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_write_number(&cab, 0U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit_reversed, &g_out_buf[0], sizeof(uint32_t));
    TEST_ASSERT(sizeof(g_out_buf) - sizeof(uint32_t) == check_array(&g_out_buf[sizeof(uint32_t)], sizeof(g_out_buf) - sizeof(uint32_t), BUF_INIT_VAL));

    /* /w Offset */
    (void)memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_write_number(&cab, 10U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit_reversed, &g_out_buf[10], sizeof(uint32_t));
    TEST_ASSERT(10U == check_array(g_out_buf, 10, BUF_INIT_VAL));
    TEST_ASSERT(sizeof(g_out_buf) - sizeof(uint32_t) - 10U == check_array(&g_out_buf[sizeof(uint32_t) + 10U], sizeof(g_out_buf) - sizeof(uint32_t) - 10U, BUF_INIT_VAL));
}

TEST(cal_buffer, copy_params)
{
    ATCA_STATUS status;
    cal_buffer cab1 = CAL_BUF_INIT(0U, NULL);
    cal_buffer cab2 = CAL_BUF_INIT(0U, NULL);

    /* Invalid pointers */
    status = cal_buf_copy(NULL, 0U, NULL, 0U, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Empty Buffer */
    status = cal_buf_copy(&cab1, 0U, NULL, 0U, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    status = cal_buf_copy(&cab1, 0U, &cab2, 0U, 0U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    status = cal_buf_copy(&cab1, 0U, &cab2, 0U, 10U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Valid Buffer */
    cab1.buf = g_out_buf;
    cab1.len = sizeof(g_out_buf);
    cab2.buf = g_ref_buf;
    cab2.len = sizeof(g_ref_buf);

    /* No Source */
    status = cal_buf_copy(&cab1, 0U, NULL, 0U, 10U);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    /* Try to copy more bytes than there is room */
    status = cal_buf_copy(&cab1, 0U, &cab2, 0U, 64U);
    TEST_ASSERT(ATCA_INVALID_SIZE == status || (ATCA_SMALL_BUFFER == status));

    /* Try to copy with an invalid offset */
    status = cal_buf_copy(&cab1, 0U, &cab2, sizeof(g_ref_buf), 10U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to copy past the end of the buffer with an offset */
    status = cal_buf_copy(&cab1, 0U, &cab2, 20U, 20U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

#if MULTIPART_BUF_EN
    cal_buffer cab_part1 = { sizeof(g_ref_buf) / 2U, &g_ref_buf[sizeof(g_ref_buf) / 2U], NULL };
    cab2.len = sizeof(g_ref_buf) / 2U;
    cab2.next = &cab_part1;

    /* Try to copy more bytes than exist */
    status = cal_buf_copy(&cab2, 0U, &cab1, 0U, 64U);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    /* Try to copy with an invalid offset */
    status = cal_buf_copy(&cab2, sizeof(g_ref_buf), &cab1, 0U, 10U);
    TEST_ASSERT_EQUAL(ATCA_SMALL_BUFFER, status);

    /* Try to copy past the end of the buffer with an offset */
    status = cal_buf_copy(&cab2, 20U, &cab1, 0U, 20U);
    TEST_ASSERT_EQUAL(ATCA_SMALL_BUFFER, status);
#endif
}

TEST(cal_buffer, copy)
{
    ATCA_STATUS status;
    cal_buffer cab1 = CAL_BUF_INIT(sizeof(g_ref_buf), g_ref_buf);
    cal_buffer cab2 = CAL_BUF_INIT(sizeof(g_out_buf), g_out_buf);

    /* One Byte Copy */
    status = cal_buf_copy(&cab2, 0U, &cab1, 0U, 1U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, g_out_buf[0]);
    TEST_ASSERT(sizeof(g_out_buf) - 1U == check_array(&g_out_buf[1], sizeof(g_out_buf) - 1U, BUF_INIT_VAL));

    /* Full Copy */
    status = cal_buf_copy(&cab2, 0U, &cab1, 0U, sizeof(g_out_buf));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(g_ref_buf, g_out_buf, sizeof(g_out_buf));

    /* Offset Copy */
    memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_copy(&cab2, 0U, &cab1, 10U, 10U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&g_ref_buf[10], g_out_buf, 10U);
    TEST_ASSERT(sizeof(g_out_buf) - 10U == check_array(&g_out_buf[10], sizeof(g_out_buf) - 10U, BUF_INIT_VAL));

    cab1.len = 1U;
    cab2.len = 2U;

    status = cal_buf_copy(&cab2, 0U, &cab1, 0U, 1U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}


#if MULTIPART_BUF_EN
TEST(cal_buffer, read_bytes_multipart)
{
    ATCA_STATUS status;
    cal_buffer cab_part1 = CAL_BUF_INIT(sizeof(g_ref_buf) / 2U, &g_ref_buf[sizeof(g_ref_buf) / 2U]);
    cal_buffer cab = CAL_BUF_INIT_LINK(sizeof(g_ref_buf) / 2U, g_ref_buf, &cab_part1);

    /* Zero Length Read */
    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, 0U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(sizeof(g_out_buf) == check_array(g_out_buf, sizeof(g_out_buf), BUF_INIT_VAL));

    /* One Byte Read */
    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, 1U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, g_out_buf[0]);
    TEST_ASSERT(sizeof(g_out_buf) - 1U == check_array(&g_out_buf[1], sizeof(g_out_buf) - 1U, BUF_INIT_VAL));

    /* Full Read */
    status = cal_buf_read_bytes(&cab, 0U, g_out_buf, sizeof(g_out_buf));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(g_ref_buf, g_out_buf, sizeof(g_out_buf));

    /* Offset Read */
    memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_read_bytes(&cab, 10U, g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&g_ref_buf[10], g_out_buf, 10U);
    TEST_ASSERT(sizeof(g_out_buf) - 10U == check_array(&g_out_buf[10], sizeof(g_out_buf) - 10U, BUF_INIT_VAL));
}

TEST(cal_buffer, write_bytes_multipart)
{
    ATCA_STATUS status;
    cal_buffer cab_part1 = CAL_BUF_INIT(sizeof(g_ref_buf) / 2U, &g_ref_buf[sizeof(g_ref_buf) / 2U]);
    cal_buffer cab = CAL_BUF_INIT_LINK(sizeof(g_ref_buf) / 2U, g_ref_buf, &cab_part1);

    /* Zero Length Write */
    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, 0U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(sizeof(g_ref_buf) == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));

    /* One Byte Write */
    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, 1U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(BUF_INIT_VAL, g_ref_buf[0]);
    TEST_ASSERT(sizeof(g_ref_buf) - 1U == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 1U));

    /* Full Write */
    status = cal_buf_write_bytes(&cab, 0U, g_out_buf, sizeof(g_out_buf));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(g_ref_buf, g_out_buf, sizeof(g_out_buf));
    TEST_ASSERT(sizeof(g_ref_buf) == check_array(g_ref_buf, sizeof(g_ref_buf), BUF_INIT_VAL));

    /* Offset Write */
    init_ref_array(g_ref_buf, sizeof(g_ref_buf));
    status = cal_buf_write_bytes(&cab, 10U, g_out_buf, 10U);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&g_ref_buf[10], g_out_buf, 10U);
    /* Make sure nothing was writen before the offset */
    TEST_ASSERT(10U == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 0U));
    /* Make sure nothing was writen after the offset + length */
    TEST_ASSERT(sizeof(g_ref_buf) - 20U == check_ref_array(g_ref_buf, sizeof(g_ref_buf), 20U));
}

TEST(cal_buffer, read_number_multipart)
{
    ATCA_STATUS status;
    cal_buffer cab_part1 = CAL_BUF_INIT(sizeof(g_ref_buf) / 2U, &g_ref_buf[sizeof(g_ref_buf) / 2U]);
    cal_buffer cab = CAL_BUF_INIT_LINK(sizeof(g_ref_buf) / 2U, g_ref_buf, &cab_part1);
    uint32_t n32bit;

#ifdef ATCA_PLATFORM_BE
    bool platform_be = true;
#else
    bool platform_be = false;
#endif

    /* Match the buffer to the host endianness */
    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, 0U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x03020100, n32bit);

    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, 10U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x0D0C0B0A, n32bit);

    /* Read across the buffer boundary */
    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, sizeof(g_ref_buf) / 2U - 2U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x11100f0e, n32bit);

    /* Ensure buffer and host endiannes are different */
    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, 0U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00010203, n32bit);

    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, 10U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x0A0B0C0D, n32bit);

    /* Read across the buffer boundary */
    n32bit = 0xFF0102AA;
    status = cal_buf_read_number(&cab, sizeof(g_ref_buf) / 2U - 2U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x0e0f1011, n32bit);
}

TEST(cal_buffer, write_number_multipart)
{
    ATCA_STATUS status;
    cal_buffer cab_part1 = CAL_BUF_INIT(sizeof(g_out_buf) / 2U, &g_out_buf[sizeof(g_out_buf) / 2U]);
    cal_buffer cab = CAL_BUF_INIT_LINK(sizeof(g_out_buf) / 2U, g_out_buf, &cab_part1);
    uint32_t n32bit = 0xFF0102AA;
    uint32_t n32bit_reversed = 0xAA0201FF;

#ifdef ATCA_PLATFORM_BE
    bool platform_be = true;
#else
    bool platform_be = false;
#endif

    /* Match the buffer to the host endianness */
    status = cal_buf_write_number(&cab, 0U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit, &g_out_buf[0], sizeof(uint32_t));
    TEST_ASSERT(sizeof(g_out_buf) - sizeof(uint32_t) == check_array(&g_out_buf[sizeof(uint32_t)], sizeof(g_out_buf) - sizeof(uint32_t), BUF_INIT_VAL));

    /* /w Offset */
    (void)memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_write_number(&cab, 10U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit, &g_out_buf[10], sizeof(uint32_t));
    TEST_ASSERT(10U == check_array(g_out_buf, 10, BUF_INIT_VAL));
    TEST_ASSERT(sizeof(g_out_buf) - sizeof(uint32_t) - 10U == check_array(&g_out_buf[sizeof(uint32_t) + 10U], sizeof(g_out_buf) - sizeof(uint32_t) - 10U, BUF_INIT_VAL));

    /* Cross the buffer boundary */
    (void)memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_write_number(&cab, sizeof(g_out_buf) / 2U - 2U, &n32bit, sizeof(n32bit), platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit, &g_out_buf[sizeof(g_out_buf) / 2U - 2U], sizeof(uint32_t));

    /* Ensure buffer and host endiannes are different */
    (void)memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_write_number(&cab, 0U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit_reversed, &g_out_buf[0], sizeof(uint32_t));
    TEST_ASSERT(sizeof(g_out_buf) - sizeof(uint32_t) == check_array(&g_out_buf[sizeof(uint32_t)], sizeof(g_out_buf) - sizeof(uint32_t), BUF_INIT_VAL));

    /* /w Offset */
    (void)memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_write_number(&cab, 10U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit_reversed, &g_out_buf[10], sizeof(uint32_t));
    TEST_ASSERT(10U == check_array(g_out_buf, 10, BUF_INIT_VAL));
    TEST_ASSERT(sizeof(g_out_buf) - sizeof(uint32_t) - 10U == check_array(&g_out_buf[sizeof(uint32_t) + 10U], sizeof(g_out_buf) - sizeof(uint32_t) - 10U, BUF_INIT_VAL));

    /* Cross the buffer boundary */
    (void)memset(g_out_buf, BUF_INIT_VAL, sizeof(g_out_buf));
    status = cal_buf_write_number(&cab, sizeof(g_out_buf) / 2U - 2U, &n32bit, sizeof(n32bit), !platform_be);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&n32bit_reversed, &g_out_buf[sizeof(g_out_buf) / 2U - 2U], sizeof(uint32_t));
}

TEST(cal_buffer, copy_multipart)
{

}

#endif

t_test_case_info buffer_test_info[] =
{
    { REGISTER_TEST_CASE(cal_buffer, read_bytes_params),                NULL },
    { REGISTER_TEST_CASE(cal_buffer, read_bytes),                       NULL },
    { REGISTER_TEST_CASE(cal_buffer, write_bytes_params),               NULL },
    { REGISTER_TEST_CASE(cal_buffer, write_bytes),                      NULL },
    { REGISTER_TEST_CASE(cal_buffer, read_number_params),               NULL },
    { REGISTER_TEST_CASE(cal_buffer, read_number),                      NULL },
    { REGISTER_TEST_CASE(cal_buffer, write_number_params),              NULL },
    { REGISTER_TEST_CASE(cal_buffer, write_number),                     NULL },
    { REGISTER_TEST_CASE(cal_buffer, copy_params),                      NULL },
    { REGISTER_TEST_CASE(cal_buffer, copy),                             NULL },

#if MULTIPART_BUF_EN
    { REGISTER_TEST_CASE(cal_buffer, read_bytes_multipart),             NULL },
    { REGISTER_TEST_CASE(cal_buffer, write_bytes_multipart),            NULL },
    { REGISTER_TEST_CASE(cal_buffer, read_number_multipart),            NULL },
    { REGISTER_TEST_CASE(cal_buffer, write_number_multipart),           NULL },
    { REGISTER_TEST_CASE(cal_buffer, copy_multipart),                   NULL },
#endif

    /* Array Termination element*/
    { (fp_test_case)NULL,            NULL },
};
