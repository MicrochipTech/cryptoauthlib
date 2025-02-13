/**
 * \file
 * \brief functions required to work with DER encoded data related to X.509 certificates.
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

#include "cryptoauthlib.h"
#include "atcacert_der.h"
#include <string.h>

#if ATCACERT_EN && ATCACERT_COMPCERT_EN

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "CERT INT30-C" "The module has been extensively tested to ensure behavior is correct") \
    (deviate "CERT INT31-C" "The module has been extensively tested to ensure behavior is correct") \
    (deviate "MISRA C-2012 Rule 10.4" "The module has been extensively tested to ensure behavior is correct") \
    (deviate:1 "MISRA C-2012 Rule 10.8" "The module has been extensively tested to ensure behavior is correct")
#endif

ATCA_STATUS atcacert_der_enc_length(size_t length, uint8_t* der_length, size_t* der_length_size)
{
    size_t der_length_size_calc = 0;
    uint8_t* len_bytes = (uint8_t*)&length;
    size_t l_exp = (int8_t)sizeof(length) - 1;

    if (der_length_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (length < 0x80u)
    {
        // The length can take the short form with only one byte
        der_length_size_calc = 1;
    }
    else
    {
        // Length is long-form, encoded as a multi-byte big-endian unsigned integer
#ifdef ATCA_PLATFORM_BE
        int i = 0;
        while ((i <= l_exp) && (len_bytes[i] == 0u))
        {
            ++i;
        }
        l_exp = l_exp - i;
#else
        while (l_exp > 0 && len_bytes[l_exp] == 0u)
        {
            --l_exp;
        }
#endif
        der_length_size_calc = (size_t)(2 + l_exp);
    }

    if (der_length != NULL && *der_length_size < der_length_size_calc)
    {
        *der_length_size = der_length_size_calc;
        return ATCACERT_E_BUFFER_TOO_SMALL;
    }

    *der_length_size = der_length_size_calc;

    if (der_length == NULL)
    {
        return ATCACERT_E_SUCCESS;  // Caller is only requesting the size

    }

    if (der_length_size_calc > 1u)
    {
        der_length[0] = 0x80u | (uint8_t)(der_length_size_calc - 1u);  // Set number of bytes octet with long-form flag

        // Encode length in big-endian format
        for (l_exp = 1; l_exp <= der_length_size_calc; l_exp++)
        {
#ifdef ATCA_PLATFORM_BE
            der_length[l_exp] = len_bytes[sizeof(length) - *der_length_size + l_exp];
#else
            der_length[l_exp] = len_bytes[der_length_size_calc - 1 - l_exp];
#endif
        }
    }
    else
    {
        der_length[0] = (uint8_t)length;
    }

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_der_dec_length(const uint8_t* der_length, size_t* der_length_size, size_t* length)
{
    if (der_length == NULL || der_length_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (*der_length_size < 1u)
    {
        return ATCACERT_E_DECODING_ERROR;
    }

    if ((der_length[0] & 0x80u) == 0x80u)
    {
        // Long form
        size_t num_bytes = (size_t)der_length[0] & 0x7Fu;
        size_t i;
        if (*der_length_size < num_bytes + 1u)
        {
            return ATCACERT_E_DECODING_ERROR;   //  Invalid DER length format, not enough data.
        }
        if (num_bytes == 0u)
        {
            return ATCACERT_E_DECODING_ERROR;   //  Invalid DER length format, indefinite length not supported.
        }
        if (num_bytes > sizeof(*length))
        {
            return ATCACERT_E_DECODING_ERROR;   //  Can't parse DER length format, larger than length.

        }
        if (length != NULL)
        {
            // Decode integer in big-endian format
            *length = 0u;
            for (i = 1; i <= num_bytes; i++)
            {
                *length += (size_t)der_length[i] * ((size_t)1 << (8u * (num_bytes - i)));
            }
        }
        *der_length_size = num_bytes + 1u; // Return the actual number of bytes the DER length encoding used.
    }
    else
    {
        if (length != NULL)
        {
            *length = der_length[0];
        }
        *der_length_size = 1u; // Return the actual number of bytes the DER length encoding used.
    }

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_der_adjust_length(uint8_t* der_length, size_t* der_length_size, int delta_length, size_t* new_length)
{
    ATCA_STATUS ret = 0;
    size_t new_der_len_size = 0u;
    size_t old_len = 0u;
    size_t new_len = 0u;
    uint8_t new_der_length[5];

    ret = atcacert_der_dec_length(der_length, der_length_size, &old_len);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    if (delta_length < 0 && (size_t)(-delta_length) > old_len)
    {
        return ATCACERT_E_ERROR;
    }
    /* coverity[misra_c_2012_rule_10_8_violation] Result of this operation has been analyzed as being correct */
    new_len = (size_t)((int)old_len + delta_length);

    if (new_length != NULL)
    {
        *new_length = new_len;
    }

    new_der_len_size = sizeof(new_der_length);
    ret = atcacert_der_enc_length(new_len, new_der_length, &new_der_len_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    if (*der_length_size != new_der_len_size)
    {
        return ATCACERT_E_BAD_CERT;
    }

    (void)memcpy(der_length, new_der_length, new_der_len_size);

    return 0;
}

ATCA_STATUS atcacert_der_enc_integer(const uint8_t* int_data,
                                     size_t         int_data_size,
                                     uint8_t        is_unsigned,
                                     uint8_t*       der_int,
                                     size_t*        der_int_size)
{
    uint8_t der_length[5];
    size_t der_length_size = sizeof(der_length);
    size_t der_int_size_calc = 0u;
    size_t trim = 0u;
    size_t pad = 0u;
    ATCA_STATUS ret;

    ATCA_CHECK_INVALID((int_data == NULL || der_int_size == NULL || int_data_size == 0u), ATCACERT_E_BAD_PARAMS);

    if (!((0u != is_unsigned) && ((int_data[0] & 0x80u) == 0x80u)))
    {
        // This is not an unsigned value that needs a padding byte, trim any unnecessary bytes.
        // Trim a byte when the upper 9 bits are all 0s or all 1s.
        while (
            (int_data_size - trim >= 2u) && (
                ((int_data[trim] == 0x00u) && ((int_data[trim + 1u] & 0x80u) == 0u)) ||
                ((int_data[trim] == 0xFFu) && ((int_data[trim + 1u] & 0x80u) != 0u))))
        {
            trim++;
        }
    }
    else
    {
        // Will be adding extra byte for unsigned padding so it's not interpreted as negative
        pad = 1u;
    }

    ret = atcacert_der_enc_length((uint32_t)(int_data_size + pad - trim), der_length, &der_length_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    der_int_size_calc = 1u + der_length_size + int_data_size + pad - trim;

    if (der_int != NULL && der_int_size_calc > *der_int_size)
    {
        *der_int_size = der_int_size_calc;
        return ATCACERT_E_BUFFER_TOO_SMALL;
    }

    *der_int_size = der_int_size_calc;

    if (der_int == NULL)
    {
        return ATCACERT_E_SUCCESS;                                                      // Caller just wanted the size of the encoded integer

    }
    der_int[0] = 0x02u;                                                                  // Integer tag
    (void)memcpy(&der_int[1], der_length, der_length_size);                              // Integer length
    if (0u != pad)
    {
        der_int[der_length_size + 1u] = 0u;                                                    // Unsigned integer value requires padding byte so it's not interpreted as negative
    }
    (void)memcpy(&der_int[der_length_size + 1u + pad], &int_data[trim], int_data_size - trim); // Integer value

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_der_dec_integer(const uint8_t* der_int,
                                     size_t*        der_int_size,
                                     uint8_t*       int_data,
                                     size_t*        int_data_size)
{
    ATCA_STATUS ret = 0;
    size_t der_length_size = 0u;
    size_t int_data_size_calc = 0u;

    if (der_int == NULL || der_int_size == NULL || (int_data != NULL && int_data_size == NULL))
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (*der_int_size < 1u)
    {
        return ATCACERT_E_DECODING_ERROR;  // No data to decode

    }
    if (der_int[0] != 0x02u)
    {
        return ATCACERT_E_DECODING_ERROR;  // Not an integer tag

    }
    der_length_size = *der_int_size - 1u;
    ret = atcacert_der_dec_length(&der_int[1], &der_length_size, &int_data_size_calc);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    if (*der_int_size < (1u + der_length_size + int_data_size_calc))
    {
        return ATCACERT_E_DECODING_ERROR;  // Invalid DER integer, not enough data.

    }
    *der_int_size = (1u + der_length_size + int_data_size_calc);

    if (int_data == NULL && int_data_size == NULL)
    {
        return ATCACERT_E_SUCCESS;  // Caller doesn't want the actual data, just the der_int_size

    }
    if (int_data != NULL && *int_data_size < int_data_size_calc)
    {
        *int_data_size = int_data_size_calc;
        return ATCACERT_E_BUFFER_TOO_SMALL;
    }

    *int_data_size = int_data_size_calc;

    if (int_data == NULL)
    {
        return ATCACERT_E_SUCCESS;  // Caller doesn't want the actual data, just the int_data_size

    }
    (void)memcpy(int_data, &der_int[1u + der_length_size], int_data_size_calc);

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_der_enc_ecdsa_sig_value(const cal_buffer* raw_sig,
                                             uint8_t*      der_sig,
                                             size_t*       der_sig_size)
{
    ATCA_STATUS ret = 0;
    size_t r_size = 0u;
    size_t s_size = 0u;
    size_t der_sig_size_calc = 0u;
    size_t raw_sig_size = 0u;
    uint8_t seq_length[3];
    size_t seq_length_size = sizeof(seq_length);
    size_t seq_total_size = 0u;
    uint8_t bit_string_length[3]; 
    size_t bit_string_length_size = sizeof(bit_string_length);
    size_t offset = 0u;

    ATCA_CHECK_INVALID((NULL == raw_sig) || (NULL == raw_sig->buf) || (NULL == der_sig_size), ATCACERT_E_BAD_PARAMS);

    // Calculate the size of the raw signature (R and S components)
    raw_sig_size = raw_sig->len / 2u;

    // Find size of the DER encoded R integer
    ret = atcacert_der_enc_integer(&(raw_sig->buf[0]), raw_sig_size, (uint8_t)TRUE, NULL, &r_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    // Find size of the DER encoded S integer
    ret = atcacert_der_enc_integer(&(raw_sig->buf[raw_sig_size]), raw_sig_size, (uint8_t)TRUE, NULL, &s_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    // Calculate the size of the DER encoded sequence
    ret = atcacert_der_enc_length(r_size + s_size, seq_length, &seq_length_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    seq_total_size = 1u + seq_length_size + r_size + s_size;          // include sequence tag (0x30)

    // Calculate the size of the DER encoded bit string
    ret = atcacert_der_enc_length(seq_total_size, bit_string_length, &bit_string_length_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    bit_string_length[bit_string_length_size - 1u] += 1u;
    der_sig_size_calc = 2u + bit_string_length_size + seq_total_size; // include bit string tag (0x03) and bit string spare bits (0x00)

    if (der_sig != NULL && *der_sig_size < der_sig_size_calc)
    {
        *der_sig_size = der_sig_size_calc;
        return ATCACERT_E_BUFFER_TOO_SMALL;
    }

    *der_sig_size = der_sig_size_calc;

    if (der_sig == NULL)
    {
        return ATCACERT_E_SUCCESS;                  // Caller just wanted the encoded size
    }

    der_sig[offset++] = 0x03;                                                   // signatureValue bit string tag
    (void)memcpy(&der_sig[offset], bit_string_length, bit_string_length_size);  // signatureValue bit string length
    offset += bit_string_length_size;
    der_sig[offset++] = 0x00;                                                   // signatureValue bit string spare bits
    // signatureValue bit string value is the DER encoding of ECDSA-Sig-Value
    der_sig[offset++] = 0x30;                                                   // sequence tag
    (void)memcpy(&der_sig[offset], seq_length, seq_length_size);                // sequence length
    offset += seq_length_size;

    // Add R integer
    ret = atcacert_der_enc_integer(&(raw_sig->buf[0]), raw_sig_size, (uint8_t)TRUE, &der_sig[offset], &r_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }
    offset += r_size;

    // Add S integer
    ret = atcacert_der_enc_integer(&(raw_sig->buf[raw_sig_size]), raw_sig_size, (uint8_t)TRUE, &der_sig[offset], &s_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_der_dec_ecdsa_sig_value(const uint8_t* der_sig,
                                             size_t*        der_sig_size,
                                             cal_buffer*    raw_sig)
{
    ATCA_STATUS ret = 0;
    size_t curr_idx = 0u;
    size_t dec_size = 0u;
    size_t bs_length = 0u;
    size_t bs_overhead_len = 0u;
    size_t seq_length = 0u;
    size_t r_size = 0u;
    size_t s_size = 0u;
    uint8_t int_data[R_S_LEN + 1u];
    size_t int_data_size = 0u;
    size_t rs_len = 0u;

    if (der_sig == NULL || der_sig_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (*der_sig_size < 1u)
    {
        return ATCACERT_E_DECODING_ERROR;  // No data to decode

    }
    // signatureValue bit string tag
    curr_idx = 0;
    if (der_sig[curr_idx] != 0x03u)
    {
        return ATCACERT_E_DECODING_ERROR;  // Unexpected tag value
    }
    curr_idx++;

    // signatureValue bit string length
    dec_size = *der_sig_size - curr_idx;
    ret = atcacert_der_dec_length(&der_sig[curr_idx], &dec_size, &bs_length);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;  // Failed to decode length
    }
    curr_idx += dec_size;
    if (curr_idx + bs_length > *der_sig_size)
    {
        return ATCACERT_E_DECODING_ERROR;  // Not enough data in buffer to decode the rest

    }
    // signatureValue bit string spare bits
    if (curr_idx >= *der_sig_size)
    {
        return ATCACERT_E_DECODING_ERROR;   // No data left
    }
    if (der_sig[curr_idx] != 0x00u)
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected spare bits value
    }
    curr_idx++;

    // signatureValue bit string value is the DER encoding of ECDSA-Sig-Value

    // sequence tag
    if (curr_idx >= *der_sig_size)
    {
        return ATCACERT_E_DECODING_ERROR;   // No data left
    }
    if (der_sig[curr_idx] != 0x30u)
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected tag value
    }
    curr_idx++;

    // sequence length
    if (curr_idx >= *der_sig_size)
    {
        return ATCACERT_E_DECODING_ERROR;  // No data left
    }
    dec_size = *der_sig_size - curr_idx;
    ret = atcacert_der_dec_length(&der_sig[curr_idx], &dec_size, &seq_length);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;  // Failed to decode length
    }
    curr_idx += dec_size;
    if (curr_idx + seq_length > *der_sig_size)
    {
        return ATCACERT_E_DECODING_ERROR;  // Not enough data in buffer to decode the rest

    }
    // R integer
    if (curr_idx >= *der_sig_size)
    {
        return ATCACERT_E_DECODING_ERROR;  // No data left
    }
    r_size = *der_sig_size - curr_idx;
    int_data_size = sizeof(int_data);
    ret = atcacert_der_dec_integer(&der_sig[curr_idx], &r_size, int_data, &int_data_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;  // Failed to decode length
    }
    curr_idx += r_size;

    if (raw_sig != NULL && raw_sig->buf != NULL)
    {
        (void)memset(raw_sig->buf, 0, raw_sig->len);  // Zero out the raw sig as the decoded integers may not touch all bytes

    }

    rs_len = (NULL == raw_sig) ? (ATCA_ECCP256_SIG_SIZE / 2u) : (raw_sig->len) / 2u;
    if (int_data_size <= rs_len)
    {
        if (raw_sig != NULL && raw_sig->buf != NULL)
        {
            (void)memcpy(&raw_sig->buf[rs_len - int_data_size], &int_data[0], int_data_size);
        }
    }
    else if (int_data_size == (rs_len + 1u))
    {
        if (int_data[0] != 0x00u)
        {
            return ATCACERT_E_DECODING_ERROR;  // R integer is too large
        }
        // DER integer was 0-padded to keep it positive
        if (raw_sig != NULL && raw_sig->buf != NULL)
        {
            (void)memcpy(&raw_sig->buf[0], &int_data[1], rs_len);
        }
    }
    else
    {
        return ATCACERT_E_DECODING_ERROR; // R integer is too large

    }
    // S integer
    if (curr_idx >= *der_sig_size)
    {
        return ATCACERT_E_DECODING_ERROR;  // No data left
    }
    s_size = *der_sig_size - curr_idx;
    int_data_size = sizeof(int_data);
    ret = atcacert_der_dec_integer(&der_sig[curr_idx], &s_size, int_data, &int_data_size);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;  // Failed to decode length
    }
    curr_idx += s_size;

    if (int_data_size <= rs_len)
    {
        if (raw_sig != NULL && raw_sig->buf != NULL)
        {
            (void)memcpy(&raw_sig->buf[raw_sig->len - int_data_size], &int_data[0], int_data_size);
        }
    }
    else if (int_data_size == (rs_len + 1u))
    {
        if (int_data[0] != 0x00u)
        {
            return ATCACERT_E_DECODING_ERROR;  // S integer is too large
        }
        // DER integer was 0-padded to keep it positive
        if (raw_sig != NULL && raw_sig->buf != NULL)
        {
            (void)memcpy(&raw_sig->buf[rs_len], &int_data[1], rs_len);
        }
    }
    else
    {
        return ATCACERT_E_DECODING_ERROR; // S integer is too large

    }
    if (seq_length != r_size + s_size)
    {
        return ATCACERT_E_DECODING_ERROR;  // Unexpected extra data in sequence

    }

    bs_overhead_len = ((r_size + s_size) > 128u) ? 4u : 3u; // Determines short form or long form

    if (true == (IS_ADD_SAFE_SIZE_T(r_size, s_size)))
    {
        if (true == (IS_ADD_SAFE_SIZE_T(r_size + s_size, bs_overhead_len)))
        {
            if (bs_length != r_size + s_size + bs_overhead_len)
            {
                return ATCACERT_E_DECODING_ERROR;  // Unexpected extra data in bit string
            }
        }
    }
    *der_sig_size = curr_idx;

    return ATCACERT_E_SUCCESS;
}

#ifdef __COVERITY__
#pragma coverity compliance end_block "CERT INT30-C" "CERT INT31-C" "MISRA C-2012 Rule 10.4" "MISRA C-2012 Rule 10.8"
#endif

#endif
