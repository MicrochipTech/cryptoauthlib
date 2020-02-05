/**
 * \file
 * \brief TNG Helper Functions
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
#include "tng_atca.h"
#include "tnglora_cert_def_2_device.h"
#include "tnglora_cert_def_4_device.h"
#include "tngtls_cert_def_2_device.h"
#include "tngtls_cert_def_3_device.h"


ATCA_STATUS tng_get_type(tng_type_t* type)
{
    ATCA_STATUS ret;
    uint8_t sn[ATCA_SERIAL_NUM_SIZE];

    if (type == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    ret = atcab_read_serial_number(sn);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    if (sn[8] == 0x10 || sn[8] == 0x27)
    {
        *type = TNGTYPE_LORA;
    }
    else
    {
        *type = TNGTYPE_TLS;
    }

    return ATCA_SUCCESS;
}

ATCA_STATUS tng_get_device_cert_def(const atcacert_def_t **cert_def)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t sn[ATCA_SERIAL_NUM_SIZE];
    char otpcode[32];

    if (cert_def == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    //Set default certificate definition
    *cert_def = &g_tngtls_cert_def_2_device;

    status = atcab_read_serial_number(sn);
    if (status != ATCA_SUCCESS)
    {
        return status;
    }

    if (sn[8] == 0x01 || sn[8] == 0x10 || sn[8] == 0x27)
    {
        status = atcab_read_zone(ATCA_ZONE_OTP, 0, 0, 0, (uint8_t*)otpcode, 32);
        if (status != ATCA_SUCCESS)
        {
            return status;
        }

        if ((strncmp("wdNxAjae", otpcode, 8) == 0) || (strncmp("Rsuy5YJh", otpcode, 8) == 0))
        {
            *cert_def = &g_tngtls_cert_def_2_device;
        }
        else if ((strncmp("KQp2ZkD8", otpcode, 8) == 0) || (strncmp("x6tjuZMy", otpcode, 8) == 0))
        {
            *cert_def = &g_tngtls_cert_def_3_device;
        }
        else if (strncmp("BxZvm6q2", otpcode, 8) == 0)
        {
            *cert_def = &g_tnglora_cert_def_2_device;
        }
        else if ((strncmp("jsMu7iYO", otpcode, 8) == 0) || (strncmp("09qJNxI3", otpcode, 8) == 0))
        {
            *cert_def = &g_tnglora_cert_def_4_device;
        }
        else
        {
            //Nothing to do...Already initialized to default
        }
    }
    return status;
}

ATCA_STATUS tng_get_device_pubkey(uint8_t *public_key)
{
    ATCA_STATUS ret;
    tng_type_t type;

    ret = tng_get_type(&type);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    if (type == TNGTYPE_LORA)
    {
        return atcab_get_pubkey(TNGLORA_PRIMARY_KEY_SLOT, public_key);
    }
    else
    {
        return atcab_get_pubkey(TNGTLS_PRIMARY_KEY_SLOT, public_key);
    }
}