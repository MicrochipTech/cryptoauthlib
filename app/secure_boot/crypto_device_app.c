/**
 * \file
 *
 * \brief Provides required interface between boot loader and secure boot.
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
#include <stdio.h>
#include "cryptoauthlib.h"
#include "secure_boot.h"
#include "io_protection_key.h"
#include "crypto_device_app.h"

/** \brief Takes care interface with secure boot and provides status about user
 *         application. This also takes care of device configuration if enabled.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS crypto_device_verify_app(void)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    /*Creating interface instance for 608A*/
    ATCAIfaceCfg cfg_atecc608a_i2c_default = {
        .iface_type             = ATCA_I2C_IFACE,
        .devtype                = ATECC608A,
        .atcai2c.slave_address  = 0xC0,
        .atcai2c.bus            = 2,
        .atcai2c.baud           = 400000,
        //.atcai2c.baud = 100000,
        .wake_delay             = 1500,
        .rx_retries             = 20
    };

    do
    {
        #if CRYPTO_DEVICE_ENABLE_SECURE_BOOT
        bool is_locked;

        /*Initialize interface on enabling any crypto operation */
        if ((status = atcab_init(&cfg_atecc608a_i2c_default)) != ATCA_SUCCESS)
        {
            break;
        }

        /*Check current status of Public Key Slot lock status */
        if ((status = atcab_is_slot_locked(SECURE_BOOT_PUBLIC_KEY_SLOT, &is_locked)) != ATCA_SUCCESS)
        {
            break;
        }

        /*Before doing secure boot it is expected configuration zone is locked */
        if (!is_locked)
        {
            /*Trigger crypto device configuration */
            #if CRYPTO_DEVICE_LOAD_CONFIG_ENABLED
            if ((status = crypto_device_load_configuration()) != ATCA_SUCCESS)
            {
                break;
            }
            #else
            status = ATCA_GEN_FAIL;
            break;
            #endif
        }

        /*Initiate secure boot operation */
        if ((status = secure_boot_process()) != ATCA_SUCCESS)
        {
            break;
        }
        #endif  //CRYPTO_DEVICE_ENABLE_SECURE_BOOT

    }
    while (0);


    return status;
}

#if CRYPTO_DEVICE_LOAD_CONFIG_ENABLED
/** \brief Checks whether configuration is locked or not. if not, it writes
 *         default configuration to device and locks it.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS crypto_device_load_configuration(void)
{
    ATCA_STATUS status;
    bool is_locked = false;

    uint8_t test_ecc608_configdata[ATCA_ECC_CONFIG_SIZE] = {
        0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x04, 0x05, 0x06, 0x07, 0xEE, 0x01, 0x01, 0x00, //15
        0xC0, 0x00, 0xA1, 0x00, 0xAF, 0x2F, 0xC4, 0x44, 0x87, 0x20, 0xC4, 0xF4, 0x8F, 0x0F, 0x0F, 0x0F, //31, 5
        0x9F, 0x8F, 0x83, 0x64, 0xC4, 0x44, 0xC4, 0x64, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, //47
        0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, //63
        0x00, 0x00, 0x00, 0x00, 0xFF, 0x84, 0x03, 0xBC, 0x09, 0x69, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, //79
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x06, 0x40, 0x00, 0x00, 0x00, 0x00, //95
        0x33, 0x00, 0x1C, 0x00, 0x13, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x3E, 0x00, 0x1C, 0x00, 0x33, 0x00, //111
        0x1C, 0x00, 0x1C, 0x00, 0x38, 0x10, 0x30, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x32, 0x00, 0x30, 0x00  //127
    };

    uint8_t public_key_slot_data[72];
    uint8_t public_key_read[ATCA_PUB_KEY_SIZE];
    uint8_t public_key[] = {
        0x21, 0x67, 0x64, 0x1c, 0x9f, 0xc4, 0x13, 0x6c, 0xb4, 0xa9, 0x1a, 0x4f, 0x56, 0xd4, 0x8b, 0x83,
        0x76, 0x9e, 0x3a, 0xd8, 0x1e, 0x0e, 0x01, 0xb7, 0x59, 0xc7, 0xc7, 0x94, 0x74, 0x3f, 0x1a, 0xa6,
        0x30, 0xcc, 0xb7, 0xec, 0xfc, 0xa8, 0x2e, 0xf0, 0x5b, 0xa1, 0x3d, 0x5b, 0x34, 0x53, 0x11, 0x18,
        0xa0, 0x67, 0x73, 0x7b, 0xdb, 0x1e, 0x3d, 0x1b, 0xbc, 0xdd, 0x10, 0x5a, 0x39, 0x23, 0x25, 0x3e
    };

    do
    {
        /*Check current status of configuration lock status */
        if ((status = atcab_is_locked(LOCK_ZONE_CONFIG, &is_locked)) != ATCA_SUCCESS)
        {
            break;
        }

        /*Write configuration if it is not already locked */
        if (!is_locked)
        {
            /*Trigger Configuration write... ignore first 16 bytes*/
            if ((status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, &test_ecc608_configdata[16], (sizeof(test_ecc608_configdata) - 16))) != ATCA_SUCCESS)
            {
                break;
            }

            /*Lock Configuration Zone on completing configuration*/
            if ((status = atcab_lock(LOCK_ZONE_NO_CRC | LOCK_ZONE_CONFIG, 0)) != ATCA_SUCCESS)
            {
                break;
            }
        }

        /*Check current status of Public Key Slot lock status */
        if ((status = atcab_is_slot_locked(SECURE_BOOT_PUBLIC_KEY_SLOT, &is_locked)) != ATCA_SUCCESS)
        {
            break;
        }

        /*Write Slot Data, if it is not already locked */
        if (!is_locked)
        {
            /*Check current status of Data zone lock status */
            if ((status = atcab_is_locked(LOCK_ZONE_DATA, &is_locked)) != ATCA_SUCCESS)
            {
                break;
            }

            if (!is_locked)
            {
                /*Lock Data Zone if it is not */
                if ((status = atcab_lock(LOCK_ZONE_NO_CRC | LOCK_ZONE_DATA, 0)) != ATCA_SUCCESS)
                {
                    break;
                }
            }

            /*Write Pub Key to Slot... Reformat public key into padded format */
            memmove(&public_key_slot_data[40], &public_key[32], 32);    // Move Y to padded position
            memset(&public_key_slot_data[36], 0, 4);                    // Add Y padding bytes
            memmove(&public_key_slot_data[4], &public_key[0], 32);      // Move X to padded position
            memset(&public_key_slot_data[0], 0, 4);                     // Add X padding bytes

            /*Write Public Key to SecureBootPubKey slot*/
            if ((status = atcab_write_bytes_zone(ATCA_ZONE_DATA, SECURE_BOOT_PUBLIC_KEY_SLOT, 0, public_key_slot_data, 72)) != ATCA_SUCCESS)
            {
                break;
            }

            /*Read Public Key*/
            if ((status = atcab_read_pubkey(SECURE_BOOT_PUBLIC_KEY_SLOT, public_key_read)) != ATCA_SUCCESS)
            {
                break;
            }

            if ((status = memcmp(public_key, public_key_read, sizeof(public_key_read))) != ATCA_SUCCESS)
            {
                break;
            }

            /*Lock IO protection key slot */
            if ((status = atcab_lock_data_slot(SECURE_BOOT_PUBLIC_KEY_SLOT)) != ATCA_SUCCESS)
            {
                break;
            }
        }
    }
    while (0);

    return status;
}
#endif  //#if CRYPTO_DEVICE_CONFIG_ENABLED

