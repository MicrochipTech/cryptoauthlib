/**
 * \file
 * \brief Client side cert i/o methods. These declarations deal with the client-side, the node being authenticated,
 *        of the authentication process. It is assumed the client has an ECC CryptoAuthentication device
 *        (e.g. ATECC508A) and the certificates are stored on that device.
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */


#include <stdlib.h>
#include "atcacert_client.h"
#include "cryptoauthlib.h"
#include "basic/atca_basic.h"


int atcacert_get_response(uint8_t       device_private_key_slot,
                          const uint8_t challenge[32],
                          uint8_t       response[64])
{
    if (device_private_key_slot > 15 || challenge == NULL || response == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    return atcab_sign(device_private_key_slot, challenge, response);
}

int atcacert_read_cert(const atcacert_def_t* cert_def,
                       const uint8_t         ca_public_key[64],
                       uint8_t*              cert,
                       size_t*               cert_size)
{
    int ret = 0;
    atcacert_device_loc_t device_locs[16];
    size_t device_locs_count = 0;
    size_t i = 0;
    atcacert_build_state_t build_state;

    if (cert_def == NULL || cert == NULL || cert_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    ret = atcacert_get_device_locs(
        cert_def,
        device_locs,
        &device_locs_count,
        sizeof(device_locs) / sizeof(device_locs[0]),
        32);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    ret = atcacert_cert_build_start(&build_state, cert_def, cert, cert_size, ca_public_key);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    for (i = 0; i < device_locs_count; i++)
    {
        uint8_t data[416];
        if (device_locs[i].zone == DEVZONE_DATA && device_locs[i].is_genkey)
        {
            ret = atcab_get_pubkey(device_locs[i].slot, data);
            if (ret != ATCA_SUCCESS)
            {
                return ret;
            }
        }
        else
        {
            size_t start_block = device_locs[i].offset / 32;
            uint8_t block;
            size_t end_block = (device_locs[i].offset + device_locs[i].count) / 32;
            for (block = (uint8_t)start_block; block < end_block; block++)
            {
                ret = atcab_read_zone(device_locs[i].zone, device_locs[i].slot, block, 0, &data[block * 32 - device_locs[i].offset], 32);
                if (ret != ATCA_SUCCESS)
                {
                    return ret;
                }
            }
        }

        ret = atcacert_cert_build_process(&build_state, &device_locs[i], data);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }
    }

    ret = atcacert_cert_build_finish(&build_state);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    return ATCACERT_E_SUCCESS;
}

int atcacert_write_cert(const atcacert_def_t* cert_def,
                        const uint8_t*        cert,
                        size_t                cert_size)
{
    int ret = 0;
    atcacert_device_loc_t device_locs[16];
    size_t device_locs_count = 0;
    size_t i = 0;

    if (cert_def == NULL || cert == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    ret = atcacert_get_device_locs(cert_def, device_locs, &device_locs_count, sizeof(device_locs) / sizeof(device_locs[0]), 32);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    for (i = 0; i < device_locs_count; i++)
    {
        size_t end_block;
        size_t start_block;
        uint8_t data[416];
        uint8_t block;

        if (device_locs[i].zone == DEVZONE_CONFIG)
        {
            continue;  // Cert data isn't written to the config zone, only read
        }
        if (device_locs[i].zone == DEVZONE_DATA && device_locs[i].is_genkey)
        {
            continue;  // Public key is generated not written

        }
        ret = atcacert_get_device_data(cert_def, cert, cert_size, &device_locs[i], data);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }

        start_block = device_locs[i].offset / 32;
        end_block = (device_locs[i].offset + device_locs[i].count) / 32;
        for (block = (uint8_t)start_block; block < end_block; block++)
        {
            ret = atcab_write_zone(device_locs[i].zone, device_locs[i].slot, block, 0, &data[(block - start_block) * 32], 32);
            if (ret != ATCA_SUCCESS)
            {
                return ret;
            }
        }
    }

    return ATCACERT_E_SUCCESS;
}

int atcacert_decode_pem_cert(const char* pem_cert, size_t pem_cert_size, uint8_t* cert_bytes, size_t* cert_bytes_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    const char cert_header[] = PEM_CERT_BEGIN;
    const char cert_footer[] = PEM_CERT_END;
    size_t cert_header_size = sizeof(cert_header);
    size_t max_size = (pem_cert_size * 3 / 4) - sizeof(cert_header) - sizeof(cert_footer);
    char* cert_ptr = NULL;
    size_t cert_begin = 0;
    size_t cert_end = 0;
    size_t cert_size = 0;

    do
    {
        // Check the pointers
        if (pem_cert == NULL || cert_bytes == NULL || cert_bytes_size == NULL)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "Null input parameter");
        }
        // Check the buffer size
        if (*cert_bytes_size < max_size)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "buffer size too small");
        }
        // Strip the certificate begin & end tags
        // Find the start byte location
        cert_ptr = strstr(pem_cert, cert_header);
        cert_begin = cert_ptr == NULL ? 0 : (cert_ptr - pem_cert) + cert_header_size;

        // Find the end byte location
        cert_ptr = strstr(pem_cert, cert_footer);
        cert_end = cert_ptr == NULL ? pem_cert_size : (size_t)(cert_ptr - pem_cert);

        // Decode the base 64 bytes
        cert_size = cert_end - cert_begin;
        atcab_base64decode(&pem_cert[cert_begin], cert_size, cert_bytes, cert_bytes_size);

    }
    while (false);

    return status;
}

int atcacert_encode_pem_cert(const uint8_t* cert_bytes, size_t cert_bytes_size, char* pem_cert, size_t* pem_cert_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    const char cert_header[] = PEM_CERT_BEGIN_EOL;
    const char cert_footer[] = PEM_CERT_END_EOL;
    size_t cert_header_size = sizeof(cert_header);
    size_t cert_footer_size = sizeof(cert_footer);
    size_t pem_max_size = (cert_bytes_size * 4 / 3) + cert_header_size + cert_footer_size;
    size_t cpy_loc = 0;
    size_t encoded_len = 0;

    do
    {
        // Check the pointers
        if (pem_cert == NULL || cert_bytes == NULL || pem_cert_size == NULL)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "Null input parameter");
        }
        // Check the buffer size
        if (*pem_cert_size < pem_max_size)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "buffer size too small");
        }
        //// Allocate the buffer to hold the PEM encoded cert
        //csr_encoded = (char*)malloc(encoded_len);
        //memset(csr_encoded, 0, encoded_len);

        // Clear the pem buffer
        memset(pem_cert, 0x00, *pem_cert_size);

        // Add the certificate begin tag
        memcpy(pem_cert, cert_header, cert_header_size);
        cpy_loc += cert_header_size - 1; // Subtract the null terminator

        // Base 64 encode the bytes
        encoded_len = pem_max_size - cpy_loc;
        status = atcab_base64encode(cert_bytes, cert_bytes_size, &pem_cert[cpy_loc], &encoded_len);
        if (status != ATCA_SUCCESS)
        {
            BREAK(status, "Base 64 encoding failed");
        }
        cpy_loc += encoded_len;

        // Copy the certificate end tag
        if ((cpy_loc + cert_footer_size) > *pem_cert_size)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "buffer too small");
        }
        memcpy(&pem_cert[cpy_loc], cert_footer, cert_footer_size);
        cpy_loc += cert_footer_size - 1; // Subtract the null terminator
        *pem_cert_size = cpy_loc;

    }
    while (false);

    return status;
}

int atcacert_create_csr_pem(const atcacert_def_t* csr_def, char* csr, size_t* csr_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    size_t csr_len = 0;
    uint8_t* csr_bytes = (uint8_t*)csr;
    char* csr_encoded = NULL;
    size_t encoded_len = 0;
    const char csr_header[] = PEM_CSR_BEGIN_EOL;
    const char csr_footer[] = PEM_CSR_END_EOL;
    size_t cpy_loc = 0;

    do
    {
        // Check the pointers
        if (csr_def == NULL || csr == NULL || csr == NULL || csr_size == NULL)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "Null input parameter");
        }

        // Call the create csr function to get the csr bytes
        csr_len = *csr_size;
        status = atcacert_create_csr(csr_def, csr_bytes, &csr_len);
        if (status != ATCA_SUCCESS)
        {
            BREAK(status, "Failed to create CSR");
        }

        // Allocate the buffer to hold the fully wrapped CSR
        encoded_len = *csr_size;
        csr_encoded = malloc(encoded_len);
        memset(csr_encoded, 0, encoded_len);

        // Wrap the CSR in the header/footer
        if ((cpy_loc + sizeof(csr_header)) > *csr_size)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "CSR buffer too small");
        }
        // Copy the header into the PEM CSR
        memcpy(&csr_encoded[cpy_loc], csr_header, sizeof(csr_header));
        cpy_loc += sizeof(csr_header) - 1; // Subtract the null terminator

        // Base 64 encode the bytes
        encoded_len -= cpy_loc;
        status = atcab_base64encode(csr_bytes, csr_len, &csr_encoded[cpy_loc], &encoded_len);
        if (status != ATCA_SUCCESS)
        {
            BREAK(status, "Base 64 encoding failed");
        }
        cpy_loc += encoded_len;

        // Copy the footer into the PEM CSR
        if ((cpy_loc + sizeof(csr_footer)) > *csr_size)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "CSR buffer too small");
        }
        memcpy(&csr_encoded[cpy_loc], csr_footer, sizeof(csr_footer));
        cpy_loc += sizeof(csr_footer) - 1; // Subtract the null terminator

        // Copy the wrapped CSR
        memcpy(csr, csr_encoded, cpy_loc);
        *csr_size = cpy_loc;

    }
    while (false);

    // Deallocate the buffer if needed
    if (csr_encoded != NULL)
    {
        free(csr_encoded);
    }

    return status;
}


int atcacert_create_csr(const atcacert_def_t* csr_def, uint8_t* csr, size_t* csr_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t pub_key[ATCA_PUB_KEY_SIZE] = { 0 };
    uint8_t sig[ATCA_SIG_SIZE] = { 0 };
    const atcacert_device_loc_t* pub_dev_loc = NULL;
    const atcacert_cert_loc_t* pub_loc = NULL;
    uint16_t key_slot = 0;
    uint16_t priv_key_slot = 0;
    uint8_t tbs_digest[ATCA_BLOCK_SIZE] = { 0 };
    size_t csr_max_size = 0;

    do
    {
        // Check the pointers
        if (csr_def == NULL || csr == NULL || csr == NULL || csr_size == NULL)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "Null input parameter");
        }
        // Check the csr buffer size
        if (*csr_size < csr_def->cert_template_size)
        {
            status = ATCACERT_E_BAD_PARAMS;
            BREAK(status, "CSR buffer size too small");
        }
        // Copy the CSR template into the CSR that will be returned
        memcpy(csr, csr_def->cert_template, csr_def->cert_template_size);
        csr_max_size = *csr_size;
        *csr_size = csr_def->cert_template_size;

        // Get a few elements from the csr_def structure
        pub_loc = &(csr_def->std_cert_elements[STDCERT_PUBLIC_KEY]);
        pub_dev_loc = &(csr_def->public_key_dev_loc);
        key_slot = pub_dev_loc->slot;
        priv_key_slot = csr_def->private_key_slot;

        // Get the public key from the device
        if (pub_dev_loc->is_genkey)
        {
            // Calculate the public key from the private key
            status = atcab_get_pubkey(key_slot, pub_key);
            if (status != ATCA_SUCCESS)
            {
                BREAK(status, "Could not generate public key");
            }
        }
        else
        {
            // Read the public key from a slot
            status = atcab_read_pubkey(key_slot, pub_key);
            if (status != ATCA_SUCCESS)
            {
                BREAK(status, "Could not read public key");
            }
        }
        // Insert the public key into the CSR template
        status = atcacert_set_cert_element(csr_def, pub_loc, csr, *csr_size, pub_key, ATCA_PUB_KEY_SIZE);
        if (status != ATCA_SUCCESS)
        {
            BREAK(status, "Setting CSR public key failed");
        }

        // Get the CSR TBS digest
        status = atcacert_get_tbs_digest(csr_def, csr, *csr_size, tbs_digest);
        if (status != ATCA_SUCCESS)
        {
            BREAK(status, "Get TBS digest failed");
        }

        // Sign the TBS digest
        status = atcab_sign(priv_key_slot, tbs_digest, sig);
        if (status != ATCA_SUCCESS)
        {
            BREAK(status, "Signing CSR failed");
        }

        // Insert the signature into the CSR template
        status = atcacert_set_signature(csr_def, csr, csr_size, csr_max_size, sig);
        if (status != ATCA_SUCCESS)
        {
            BREAK(status, "Setting CSR signature failed");
        }

        // The exact size of the csr cannot be determined until after adding the signature
        // it is returned in the csr_size parameter.  (*csr_size = *csr_size;)

    }
    while (false);

    return status;
}


