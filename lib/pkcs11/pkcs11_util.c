/**
 * \file
 * \brief PKCS11 Library Utility Functions
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

#include "pkcs11_util.h"

/**
 * \defgroup pkcs11 Utilities (pkcs11_util_)
   @{ */



/*
 * \brief Helper function to make sure buffers meet the special padding
 * requirements of PKCS11
 * \param[IN/OUT] buf   Target buffer, will be padded with spaces
 * \param[IN]  buf_len  Length of the buffer
 */
void pkcs11_util_escape_string(CK_UTF8CHAR_PTR buf, CK_ULONG buf_len)
{
    if (NULL != buf && 0u != buf_len)
    {
        CK_ULONG i;
        for (i = 0; i < buf_len; i++)
        {
            if (0x20u > buf[i] || 0x7Eu < buf[i])
            {
                buf[i] = (CK_CHAR)' ';
            }
        }
    }
}

/*
 * \brief Helper function to convert cryptoauthlib return codes to
 * PKCS11 return codes
 */
CK_RV pkcs11_util_convert_rv(ATCA_STATUS status)
{
    CK_RV rv;

    switch (status)
    {
    case ATCA_SUCCESS:
        rv = CKR_OK;
        break;
    case ATCA_FUNC_FAIL:
    /* fallthrough */
    case ATCA_GEN_FAIL:
    /* fallthrough */
    case ATCA_BAD_PARAM:
    /* fallthrough */
    case ATCA_NOT_INITIALIZED:
        rv = CKR_FUNCTION_FAILED;
        break;
    default:
        rv = CKR_DEVICE_ERROR;
        break;
    }

    return rv;
}

int pkcs11_util_memset(void *dest, size_t destsz, int ch, size_t count)
{
#ifndef memset_s
    if (dest == NULL)
    {
        return -1;
    }
    /* coverity[misra_c_2012_rule_14_3_violation] This matches the definition used by most systems */
    if (destsz > SIZE_MAX)
    {
        return -1;
    }

    if (count > destsz)
    {
        return -1;
    }

    volatile unsigned char *p = dest;
    while (destsz != 0u && count != 0u)
    {
        if (ch >= 0 && ch <= 255)
        {
            *p++ = (unsigned char)(ch);
        }
        destsz--;
        count--;
    }

    return 0;
#else
    return memset_s(dest, destsz, ch, count);
#endif
}

/** @} */
