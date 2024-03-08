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

#include <string.h>
#include "cal_buffer.h"

#ifdef ATCA_PRINTF
#include <stdio.h>
#endif

/** \ingroup cal_buf_
 * @{
 */

/** \brief Read bytes from a single cal_buffer all at once - Internal implementation */
static ATCA_STATUS cal_buf_read_bytes_single(
    /** [in] Buffer structure to read from */
    cal_buffer * cab,
    /** [in] Offset to start the read from */
    size_t       offset,
    /** [in] Pointer to a destination buffer */
    void *       dest,
    /** [in] Length of the read - assumes dest has sufficent
     * memory to accept the bytes being read */
    size_t       length,
    /** [in] Reverse the order of the bytes during the read - swap endianness */
    bool         reverse
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cab->buf)
    {
        if (0U < length)
        {
            if ((cab->len > offset) && (cab->len - offset) >= length)
            {
                if (reverse)
                {
                    uint8_t * src_p = &cab->buf[offset];
                    uint8_t * dst_p = (uint8_t*)dest;
                    size_t i;
                    for (i = 0U; i < length; i++)
                    {
                        *dst_p-- = *src_p++;
                    }
                }
                else
                {
                    (void)memcpy((uint8_t*)dest, &cab->buf[offset], length);
                }
                status = ATCA_SUCCESS;
            }
            else
            {
                /* Buffer is too small to supply the requested bytes */
                status = ATCA_INVALID_SIZE;
            }
        }
        else
        {
            status = ATCA_SUCCESS;
        }
    }
    return status;
}

#if MULTIPART_BUF_EN
/** \brief Read bytes from a cal_buffer linked list - Internal implementation */
static ATCA_STATUS cal_buf_read_bytes_multipart(
    /** [in] Buffer Linked List to read from */
    cal_buffer * cab,
    /** [in] Offset to start the read from */
    size_t       offset,
    /** [in] Pointer to a destination buffer */
    void *       dest,
    /** [in] Length of the read - assumes dest has sufficent
     * memory to accept the bytes being read */
    size_t       length,
    /** [in] Reverse the order of the bytes during the read - swap endianness */
    bool         reverse
    )
{
    ATCA_STATUS status = ATCA_SUCCESS;
    cal_buffer * cab_p = cab;
    uint8_t * dest_p = (uint8_t*)dest;

    do
    {
        if (cab_p->len > offset)
        {
            size_t len = cab_p->len - offset;
            if (len >= length)
            {
                len = length;
            }
            if (ATCA_SUCCESS == (status = cal_buf_read_bytes_single(cab_p, offset, dest_p, len, reverse)))
            {
                if (reverse)
                {
                    dest_p -= len;
                }
                else
                {
                    dest_p += len;
                }
                length -= len;
                offset = 0;
            }
        }
        else
        {
            offset -= cab_p->len;
        }
        cab_p = cab_p->next;
    } while ((ATCA_SUCCESS == status) && (0U < length) && (NULL != cab_p));

    if (0U < length)
    {
        /* Buffer is too small to supply the requested bytes */
        status = ATCA_INVALID_SIZE;
    }

    return status;
}
#endif

/** \brief Read bytes from a cal_buffer or cal_buffer linked list - Internal implementation */
static ATCA_STATUS cal_buf_read_bytes_internal(
    /** [in] Pointer to a buffer structure or the head of a buffer structure linked list */
    cal_buffer * cab,
    /** [in] Offset to start the read from */
    size_t       offset,
    /** [in] Pointer to a destination buffer */
    void *       dest,
    /** [in] Length of the read - assumes dest has sufficent
     * memory to accept the bytes being read */
    size_t       length,
    /** [in] Reverse the order of the bytes during the read - swap endianness */
    bool         reverse
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != dest) && (NULL != cab))
    {
#if MULTIPART_BUF_EN
        if (NULL != cab->next)
        {
            status = cal_buf_read_bytes_multipart(cab, offset, dest, length, reverse);
        }
        else
#endif
        {
            status = cal_buf_read_bytes_single(cab, offset, dest, length, reverse);
        }
    }
    return status;
}

/** \brief Read bytes from a cal_buffer or cal_buffer linked list */
ATCA_STATUS cal_buf_read_bytes(
    /** [in] Pointer to a buffer structure or the head of a buffer structure linked list */
    cal_buffer * cab,
    /** [in] Offset to start the read from */
    size_t       offset,
    /** [in] Pointer to a destination buffer */
    void *       dest,
    /** [in] Length of the read - assumes dest has sufficent
     * memory to accept the bytes being read */
    size_t       length
    )
{
    return cal_buf_read_bytes_internal(cab, offset, dest, length, false);
}

/** \brief Write bytes into a single cal_buffer all at once - Internal implementation */
static ATCA_STATUS cal_buf_write_bytes_single(
    /** [in] Buffer structure to write to */
    cal_buffer * cab,
    /** [in] Target offset to start the write at */
    size_t       offset,
    /** [in] Pointer to a source buffer */
    const void * source,
    /** [in] Length of the write - assumes source is sufficently large to support this operation */
    size_t       length,
    /** [in] Reverse the order of the bytes during the write - swap endianness */
    bool         reverse
    )
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if (0U < length)
    {
        if ((cab->len > offset) && (cab->len - offset) >= length)
        {
            const uint8_t * src_p = (const uint8_t*)source;
            if (reverse)
            {
                uint8_t * dst_p = &cab->buf[offset];
                size_t i;
                for (i = 0U; i < length; i++)
                {
                    *dst_p++ = *src_p--;
                }
            }
            else
            {
                (void)memcpy(&cab->buf[offset], src_p, length);
            }
        }
        else
        {
            /* Buffer is too small to accept the bytes to be written */
            status = ATCA_INVALID_SIZE;
        }
    }

    return status;
}

#if MULTIPART_BUF_EN
/** \brief Write bytes into a cal_buffer linked list - Internal implementation */
static ATCA_STATUS cal_buf_write_bytes_multipart(
    /** [in] Buffer linked list to write to */
    cal_buffer * cab,
    /** [in] Target offset to start the write at */
    size_t       offset,
    /** [in] Pointer to a source buffer */
    const void * source,
    /** [in] Length of the write - assumes source is sufficently large to support this operation */
    size_t       length,
    /** [in] Reverse the order of the bytes during the write - swap endianness */
    bool         reverse
    )
{
    ATCA_STATUS status = ATCA_SUCCESS;
    cal_buffer * cab_p = cab;
    const uint8_t * src_p = (const uint8_t*)source;

    do
    {
        if (cab_p->len > offset)
        {
            size_t len = cab_p->len - offset;
            if (len >= length)
            {
                len = length;
            }
            if (ATCA_SUCCESS == (status = cal_buf_write_bytes_single(cab_p, offset, src_p, len, reverse)))
            {
                if (reverse)
                {
                    src_p -= len;
                }
                else
                {
                    src_p += len;
                }
                length -= len;
                offset = 0;
            }
        }
        else
        {
            offset -= cab_p->len;
        }
        cab_p = cab_p->next;
    } while ((ATCA_SUCCESS == status) && (0U < length) && (NULL != cab_p));

    if (0U < length)
    {
        /* Buffer is too small to supply the requested bytes */
        status = ATCA_INVALID_SIZE;
    }

    return status;
}
#endif

/** \brief Write bytes into a single cal_buffer structure or cal_buffer linked list - Internal implementation */
static ATCA_STATUS cal_buf_write_bytes_internal(
    /** [in] Pointer to a buffer structure or the head of a buffer structure linked list */
    cal_buffer * cab,
    /** [in] Target offset to start the write at */
    size_t       offset,
    /** [in] Pointer to a source buffer */
    const void * source,
    /** [in] Length of the write - assumes source is sufficently large to support this operation */
    size_t       length,
    /** [in] Reverse the order of the bytes during the write - swap endianness */
    bool         reverse
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != source) && (NULL != cab) && (NULL != cab->buf))
    {
#if MULTIPART_BUF_EN
        if (NULL != cab->next)
        {
            status = cal_buf_write_bytes_multipart(cab, offset, source, length, reverse);
        }
        else
#endif
        {
            status = cal_buf_write_bytes_single(cab, offset, source, length, reverse);
        }
    }
    return status;
}

ATCA_STATUS cal_buf_read_byte(cal_buffer * cab, size_t offset, uint8_t * value)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if MULTIPART_BUF_EN
    while ((NULL != cab) && (cab->len < offset))
    {
        offset -= cab->len;
        cab = cab->next;
    }
#endif

    if ((NULL != value) && (NULL != cab) && (cab->len > offset) && (NULL != cab->buf))
    {
        *value = cab->buf[offset];
        status = ATCA_SUCCESS;
    }

    return status;
}

ATCA_STATUS cal_buf_write_byte(cal_buffer * cab, size_t offset, uint8_t value)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if MULTIPART_BUF_EN
    while ((NULL != cab) && (cab->len < offset))
    {
        offset -= cab->len;
        cab = cab->next;
    }
#endif

    if ((NULL != cab) && (cab->len > offset) && (NULL != cab->buf))
    {
        cab->buf[offset] = value;
        status = ATCA_SUCCESS;
    }

    return status;
}


/** \brief Write bytes into a single cal_buffer structure or cal_buffer linked list*/
ATCA_STATUS cal_buf_write_bytes(
    /** [in] Pointer to a buffer structure or the head of a buffer structure linked list */
    cal_buffer * cab,
    /** [in] Target offset to start the write at */
    size_t       offset,
    /** [in] Pointer to a source buffer */
    const void * source,
    /** [in] Length of the write - assumes source is sufficently large to support this operation */
    size_t       length
    )
{
    return cal_buf_write_bytes_internal(cab, offset, source, length, false);
}

/** \brief Read a number from a cal_buffer or cal_buffer linked list
 * This function does not reinterpet the number and signedness is only preserved
 * if the destination is the same size as the representation in the buffer
 */
ATCA_STATUS cal_buf_read_number(
    /** [in] Pointer to a buffer structure or the head of a buffer structure linked list */
    cal_buffer * cab,
    /** [in] Offset to start the read from */
    size_t       offset,
    /** [in] Pointer to a destination number */
    void *       dest,
    /** [in] Size of the number in bytes */
    size_t       num_size,
    /** [in] Specifies the expected endianness representation within the buffer */
    bool         buf_big_endian
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != dest)
    {
        uint8_t * dst_p = (uint8_t*)dest;
        bool reverse = false;
    #ifdef ATCA_PLATFORM_BE
        if (!buf_big_endian)
    #else
        if (buf_big_endian)
    #endif
        {
            reverse = true;
            dst_p += num_size;
            dst_p -= 1U;
        }

        status = cal_buf_read_bytes_internal(cab, offset, dst_p, num_size, reverse);
    }

    return status;
}

/** \brief Write a number into a cal_buffer or cal_buffer linked list
 * This function does not reinterpet the number and signedness is only preserved
 * if the destination is the same size as the source
 */
ATCA_STATUS cal_buf_write_number(
    /** [in] Pointer to a buffer structure or the head of a buffer structure linked list */
    cal_buffer * cab,
    /** [in] Offset to start the write at */
    size_t       offset,
    /** [in] Pointer to a number to be written */
    const void * source,
    /** [in] Size of the number in bytes */
    size_t       num_size,
    /** [in] Specifies the expected endianness representation within the buffer */
    bool         buf_big_endian
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != source)
    {
        const uint8_t * src_p = (const uint8_t*)source;
        bool reverse = false;
    #ifdef ATCA_PLATFORM_BE
        if (!buf_big_endian)
    #else
        if (buf_big_endian)
    #endif
        {
            reverse = true;
            src_p += num_size;
            src_p -= 1U;
        }

        status = cal_buf_write_bytes_internal(cab, offset, src_p, num_size, reverse);
    }

    return status;
}

ATCA_STATUS cal_buf_set_used(cal_buffer * buf, size_t used)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != buf)
    {
        if (NULL == buf->buf)
        {
            buf->len = used;
        }
        else
        {
            status = ATCA_INVALID_SIZE;

#if MULTIPART_BUF_EN
            while ((NULL != buf) && (NULL != buf->buf) && (0U < buf->len) && (0U < used))
            {
                if (buf->len >= used)
                {
                    buf->len = used;
                    used = 0;
                    status = ATCA_SUCCESS;
                }
                else
                {
                    used -= buf->len;
                }
                buf = buf->next;
            }
#else
            if (buf->len >= used)
            {
                buf->len = used;
                status = ATCA_SUCCESS;
            }
#endif
        }
    }
    return status;
}

size_t cal_buf_get_used(cal_buffer * buf)
{
    size_t used = 0U;

    if (NULL != buf)
    {
    #if MULTIPART_BUF_EN
        do
        {
            /* coverity[cert_int30_c_violation] Wrapping is infeasible in practice because the total length is limited to UINT16_MAX elsewhere */
            used += buf->len;
            buf = buf->next;
        } while ((NULL != buf) && (NULL != buf->buf) && (0U < buf->len));
    #else
        used = buf->len;
    #endif
    }

    return used;
}


ATCA_STATUS cal_buf_copy(cal_buffer * dst, size_t dst_offset, cal_buffer * src, size_t src_offset, size_t length)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (0U < length)
    {
#if MULTIPART_BUF_EN
        while ((NULL != dst) && (dst->len < dst_offset))
        {
            dst_offset -= dst->len;
            dst = dst->next;
        }
#else
        if ((NULL == dst) || (dst_offset > dst->len))
        {
            return status;
        }
#endif

#if MULTIPART_BUF_EN
        while ((NULL != src) && (src->len < src_offset))
        {
            src_offset -= src->len;
            src = src->next;
        }
#else
        if ((NULL == src) || (src_offset > src->len))
        {
            return status;
        }
#endif

#if MULTIPART_BUF_EN
        while ((NULL != dst) && (NULL != dst->buf) && (NULL != src) && (NULL != src->buf))
#else
        if ((NULL != dst->buf) && (NULL != src->buf))
#endif
        {
            size_t bytes_to_copy;

            if (dst->len - dst_offset > length)
            {
                bytes_to_copy = length;
            }
            else
            {
                bytes_to_copy = dst->len - dst_offset;
            }

            if (src->len - src_offset < bytes_to_copy)
            {
                bytes_to_copy = src->len - src_offset;
            }

            (void)memcpy(&dst->buf[dst_offset], &src->buf[src_offset], bytes_to_copy);

            length -= bytes_to_copy;
            dst_offset += bytes_to_copy;
            src_offset += bytes_to_copy;

            if (0U == length)
            {
                status = ATCA_SUCCESS;
    #if MULTIPART_BUF_EN
                break;
    #endif
            }
            else
            {
                if (dst->len == dst_offset)
                {
    #if MULTIPART_BUF_EN
                    dst_offset = 0;
                    if (NULL == (dst = dst->next))
                    {
                        status = ATCA_SMALL_BUFFER;
                    }
    #else
                    status = ATCA_SMALL_BUFFER;
    #endif
                }
                if (src->len == src_offset)
                {
    #if MULTIPART_BUF_EN
                    src_offset = 0;
                    if (NULL == (src = src->next))
                    {
                        status = ATCA_INVALID_SIZE;
                    }
    #else
                    status = ATCA_INVALID_SIZE;
    #endif
                }
            }
        }
    }
    return status;
}

ATCA_STATUS cal_buf_set(cal_buffer * dst, size_t dst_offset, uint8_t value, size_t length)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (0U < length)
    {
#if MULTIPART_BUF_EN
        while ((NULL != dst) && (dst->len < dst_offset))
        {
            dst_offset -= dst->len;
            dst = dst->next;
        }
#else
        if ((NULL == dst) || (dst_offset > dst->len))
        {
            return status;
        }
#endif
#if MULTIPART_BUF_EN
        while ((NULL != dst) && (NULL != dst->buf))
#else
        if (NULL != dst->buf)
#endif
        {
            size_t bytes_to_set = (dst->len - dst_offset > length) ? length : dst->len - dst_offset;

            (void)memset(&dst->buf[dst_offset], (int)value, bytes_to_set);

            length -= bytes_to_set;
            dst_offset += bytes_to_set;

            if (0U == length)
            {
                status = ATCA_SUCCESS;
    #if MULTIPART_BUF_EN
                break;
    #endif
            }
            else
            {
                if (dst->len == dst_offset)
                {
    #if MULTIPART_BUF_EN
                    dst_offset = 0;
                    if (NULL == (dst = dst->next))
                    {
                        status = ATCA_SMALL_BUFFER;
                    }
    #else
                    status = ATCA_SMALL_BUFFER;
    #endif
                }
            }
        }
    }

    return status;
}

/** \brief Initialize a cal buffer with constant pointer
 * Returns the initialized cal buffer
 */
cal_buffer cal_buf_init_const_ptr(size_t len,const uint8_t* message)
{
    void **ptr = NULL;
    /* coverity[cert_str30_c_violation] Implementation treats input attributes as constants */
    void *lptr = &(message); 
    (ptr) = lptr; 

    cal_buffer init_buf = CAL_BUF_INIT(len,*ptr);
    return init_buf;
}

#ifdef ATCA_PRINTF
void cal_buf_print(cal_buffer * buf)
{
    size_t i;

    if (NULL == buf)
    {
        printf("Buffer is NULL\n");
    }
    else if (NULL == buf->buf)
    {
        printf("Buffer is inconsistent\n");
    }
    else
    {
        while ((NULL != buf) && (NULL != buf->buf))
        {
            for (i = 0; i < buf->len; i++)
            {
                printf("%02x ", buf->buf[i]);
            }
#if MULTIPART_BUF_EN
            buf = buf->next;
#else
            buf = NULL;
#endif
        }
    }
}
#endif

/** @} */
