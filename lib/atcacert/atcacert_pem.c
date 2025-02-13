/**
 * \file
 * \brief Functions required to work with PEM encoded data related to X.509
 * certificates.
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

#include <string.h>

#include "atcacert.h"
#include "atcacert_pem.h"
#include "atca_helpers.h"

#if ATCACERT_EN && ATCACERT_COMPCERT_EN

ATCA_STATUS atcacert_encode_pem(const uint8_t* der,
                                size_t         der_size,
                                char*          pem,
                                size_t*        pem_size,
                                const char*    header,
                                const char*    footer)
{
    ATCA_STATUS rv = ATCACERT_E_SUCCESS;
    size_t max_pem_size;
    size_t header_size;
    size_t footer_size;
    size_t b64_size;
    size_t pem_index = 0;

    do
    {
#if ATCA_CHECK_PARAMS_EN
        if (der == NULL || pem == NULL || pem_size == NULL || header == NULL || footer == NULL)
        {
            rv = ATCACERT_E_BAD_PARAMS;
            break;
        }
#endif
        max_pem_size = *pem_size;
        *pem_size = 0; // Default to 0

        // Add header
        header_size = strlen(header);
        /* coverity[cert_int30_c_violation] since header would have to be a valid object in memory it could not be length of SIZE_MAX */
        if (pem_index + header_size + 2u > max_pem_size)
        {
            rv = ATCACERT_E_BUFFER_TOO_SMALL;
            break;
        }
        (void)memcpy(&pem[pem_index], header, header_size);
        pem_index += header_size;
        pem[pem_index++] = (char)'\r';
        pem[pem_index++] = (char)'\n';

        // Add base64 encoded DER data with \r\n every 64 characters
        b64_size = max_pem_size - pem_index;

        if (ATCACERT_E_SUCCESS != (rv = atcab_base64encode(der, der_size, &pem[pem_index], &b64_size)))
        {
            break;
        }
        pem_index += b64_size;

        // Add \r\n after data
        footer_size = strlen(footer);
        if (pem_index + 2u + footer_size + 2u + 1u > max_pem_size)
        {
            rv = ATCACERT_E_BUFFER_TOO_SMALL;
            break;
        }
        pem[pem_index++] = (char)'\r';
        pem[pem_index++] = (char)'\n';

        // Add footer
        (void)memcpy(&pem[pem_index], footer, footer_size);
        pem_index += footer_size;
        pem[pem_index++] = (char)'\r';
        pem[pem_index++] = (char)'\n';

        pem[pem_index] = (char)'\0'; // Terminating null, not included in size

        // Set output size
        *pem_size = pem_index;

    }
    while (false);

    return rv;
}

ATCA_STATUS atcacert_decode_pem(const char* pem,
                                size_t      pem_size,
                                uint8_t*    der,
                                size_t*     der_size,
                                const char* header,
                                const char* footer)
{
    ATCA_STATUS rv = ATCACERT_E_SUCCESS;
    const char* header_pos = NULL;
    const char* data_pos = NULL;
    const char* footer_pos = NULL;

    do
    {
#if ATCA_CHECK_PARAMS_EN
        if (pem == NULL || der == NULL || der_size == NULL || header == NULL || footer == NULL)
        {
            rv = ATCACERT_E_BAD_PARAMS;
            break;
        }
#endif
        // Find the position of the header
        header_pos = strstr(pem, header);
        if (header_pos == NULL)
        {
            // Couldn't find header
            rv = ATCACERT_E_DECODING_ERROR;
            break;
        }

        // Data should be right after the header. Not accounting for new lines as
        // the base64 decode should skip over those.
        data_pos = header_pos + strlen(header);

        if (atcab_pointer_delta(pem, data_pos) > pem_size)
        {
            rv = ATCACERT_E_DECODING_ERROR;
            break;
        }

        // Find footer
        footer_pos = strstr(data_pos, footer);
        if (footer_pos == NULL || footer_pos < data_pos)
        {
            // Couldn't find footer or found it before the data
            rv = ATCACERT_E_DECODING_ERROR;
            break;
        }

        // Decode data
        rv = atcab_base64decode(data_pos, atcab_pointer_delta(data_pos, footer_pos), der, der_size);

    }
    while (false);

    return rv;
}

ATCA_STATUS atcacert_encode_pem_cert(const uint8_t* der_cert, size_t der_cert_size, char* pem_cert, size_t* pem_cert_size)
{
    return atcacert_encode_pem(
        der_cert,
        der_cert_size,
        pem_cert,
        pem_cert_size,
        PEM_CERT_BEGIN,
        PEM_CERT_END);
}

ATCA_STATUS atcacert_encode_pem_csr(const uint8_t* der_csr, size_t der_csr_size, char* pem_csr, size_t* pem_csr_size)
{
    return atcacert_encode_pem(
        der_csr,
        der_csr_size,
        pem_csr,
        pem_csr_size,
        PEM_CSR_BEGIN,
        PEM_CSR_END);
}

ATCA_STATUS atcacert_decode_pem_cert(const char* pem_cert, size_t pem_cert_size, uint8_t* der_cert, size_t* der_cert_size)
{
    return atcacert_decode_pem(
        pem_cert,
        pem_cert_size,
        der_cert,
        der_cert_size,
        PEM_CERT_BEGIN,
        PEM_CERT_END);
}

ATCA_STATUS atcacert_decode_pem_csr(const char* pem_csr, size_t pem_csr_size, uint8_t* der_csr, size_t* der_csr_size)
{
    return atcacert_decode_pem(
        pem_csr,
        pem_csr_size,
        der_csr,
        der_csr_size,
        PEM_CSR_BEGIN,
        PEM_CSR_END);
}

#endif
