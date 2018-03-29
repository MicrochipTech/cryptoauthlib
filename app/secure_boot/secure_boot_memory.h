/**
 * \file
 *
 * \brief Provides interface to memory component for the secure boot.
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

#ifndef SECURE_BOOT_MEMORY_H
#define SECURE_BOOT_MEMORY_H

#ifdef __cplusplus
extern "C" {
#endif

#include "atca_status.h"
#include "atca_command.h"


/*Blocking last USER_APPLICATION_HEADER_SIZE bytes for Signature and memory/application specific information*/
typedef struct
{
    uint32_t start_address;
    uint32_t memory_size;
    uint32_t version_info;
    uint8_t  reserved[52];                      //Reserving bytes for Application information and aligning to page
    uint8_t  signature[ATCA_SIG_SIZE];
}memory_parameters;

extern ATCA_STATUS secure_boot_init_memory(memory_parameters* memory_params);
extern ATCA_STATUS secure_boot_read_memory(uint8_t* pu8_data, uint32_t* pu32_target_length);
extern ATCA_STATUS secure_boot_write_memory(uint8_t* pu8_data, uint32_t* pu32_target_length);
extern void secure_boot_deinit_memory(memory_parameters* memory_params);
extern ATCA_STATUS secure_boot_mark_full_copy_completion(void);
extern bool secure_boot_check_full_copy_completion(void);

#ifdef __cplusplus
}
#endif

#endif



