/**
 * \file
 *
 * \brief Provides required APIs to manage secure boot under various scenarios.
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

#ifndef SECURE_BOOT_H
#define SECURE_BOOT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "atca_status.h"
#include "secure_boot_memory.h"
#include "atca_command.h"
#include "crypto\atca_crypto_sw_sha2.h"
#include "host/atca_host.h"


#define SECURE_BOOT_CONFIG_DISABLE              0
#define SECURE_BOOT_CONFIG_FULL_BOTH            1
#define SECURE_BOOT_CONFIG_FULL_SIGN            2
#define SECURE_BOOT_CONFIG_FULL_DIG             3

#define SECURE_BOOT_CONFIGURATION               SECURE_BOOT_CONFIG_FULL_DIG
#define SECURE_BOOT_DIGEST_ENCRYPT_ENABLED      true
#define SECURE_BOOT_UPGRADE_SUPPORT             true


typedef struct
{
    uint16_t secure_boot_mode : 2;
    uint16_t secure_boot_reserved1 : 1;
    uint16_t secure_boot_persistent_enable : 1;
    uint16_t secure_boot_rand_nonce : 1;
    uint16_t secure_boot_reserved2 : 3;
    uint16_t secure_boot_sig_dig : 4;
    uint16_t secure_boot_pub_key : 4;
}secure_boot_config_bits;


typedef struct
{
    memory_parameters  memory_params;
    atcac_sha2_256_ctx s_sha_context;
    uint8_t            app_digest[ATCA_SHA_DIGEST_SIZE];
    #if SECURE_BOOT_DIGEST_ENCRYPT_ENABLED
    uint8_t randomnum[RANDOM_RSP_SIZE];
    uint8_t io_protection_key[ATCA_KEY_SIZE];
    #endif
}secure_boot_parameters;

typedef ATCA_STATUS (*secure_boot_handler)(secure_boot_parameters* secure_boot_params);


ATCA_STATUS secure_boot_process(void);
ATCA_STATUS check_device_io_protection_key_generate(void);
extern ATCA_STATUS host_generate_random_number(uint8_t *rand);

#ifdef __cplusplus
}
#endif

#endif



