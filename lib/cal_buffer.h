/**
 * \file
 * \brief Cryptoauthlib buffer management system
 *
 * \copyright (c) 2023 Microchip Technology Inc. and its subsidiaries.
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

#ifndef CAL_BUFFER_H
#define CAL_BUFFER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "atca_config_check.h"
#include "atca_status.h"

/** \ingroup cal_buf_
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cal_buffer_s
{
    /** Length of the provided buffer */
    size_t len;
    /** Pointer to the actual buffer */
    uint8_t* buf;
#if MULTIPART_BUF_EN
    /** Pointer to the next in the list */
    struct cal_buffer_s * next;
#endif
} cal_buffer;



#ifdef __COVERITY__
    #if MULTIPART_BUF_EN
    #define CAL_BUF_INIT(s, b)           { \
        _Pragma("coverity compliance deviate 'CERT EXP40-C'") \
        _Pragma("coverity compliance deviate 'CERT STR30-C'") \
        _Pragma("coverity compliance deviate 'MISRA C-2012 Rule 10.8'") \
        _Pragma("coverity compliance deviate 'MISRA C-2012 Rule 11.8'") \
        (size_t)s, (uint8_t*)b, NULL }
    #define CAL_BUF_INIT_LINK(s, b, n)    { \
        _Pragma("coverity compliance deviate 'CERT EXP40-C'") \
        _Pragma("coverity compliance deviate 'CERT STR30-C'") \
        _Pragma("coverity compliance deviate 'MISRA C-2012 Rule 10.8'") \
        _Pragma("coverity compliance deviate 'MISRA C-2012 Rule 11.8'") \
        (size_t)s, (uint8_t*)b, n }
    #else
    #define CAL_BUF_INIT(s, b)           { \
        _Pragma("coverity compliance deviate 'CERT EXP40-C'") \
        _Pragma("coverity compliance deviate 'CERT STR30-C'") \
        _Pragma("coverity compliance deviate 'MISRA C-2012 Rule 10.8'") \
        _Pragma("coverity compliance deviate 'MISRA C-2012 Rule 11.8'") \
        (size_t)s, (uint8_t*)b }
    #endif 
#else
    #if MULTIPART_BUF_EN
    #define CAL_BUF_INIT(s, b)           { (size_t)(s), (uint8_t*)(b), NULL }
    #define CAL_BUF_INIT_LINK(s, b, n)    { (size_t)(s), (uint8_t*)(b), n }
    #else
    #define CAL_BUF_INIT(s, b)           { (size_t)(s), (uint8_t*)(b) }
    #endif
#endif

ATCA_STATUS cal_buf_read_byte(cal_buffer * cab, size_t offset, uint8_t * value);
ATCA_STATUS cal_buf_write_byte(cal_buffer * cab, size_t offset, uint8_t value);

ATCA_STATUS cal_buf_read_bytes(cal_buffer * cab, size_t offset, void * dest, size_t length);
ATCA_STATUS cal_buf_write_bytes(cal_buffer * cab, size_t offset, const void * source, size_t length);
ATCA_STATUS cal_buf_read_number(cal_buffer * cab, size_t offset, void * dest, size_t num_size, bool buf_big_endian);
ATCA_STATUS cal_buf_write_number(cal_buffer * cab, size_t offset, const void * source, size_t num_size, bool buf_big_endian);

ATCA_STATUS cal_buf_copy(cal_buffer * dst, size_t dst_offset, cal_buffer * src, size_t src_offset, size_t length);
ATCA_STATUS cal_buf_set(cal_buffer * dst, size_t dst_offset, uint8_t value, size_t length);

ATCA_STATUS cal_buf_set_used(cal_buffer * buf, size_t used);
size_t      cal_buf_get_used(cal_buffer * buf);
cal_buffer cal_buf_init_const_ptr(size_t len,const uint8_t* message);

#ifdef ATCA_PRINTF
void cal_buf_print(cal_buffer * buf);
#endif

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* CAL_BUFFER_H */
