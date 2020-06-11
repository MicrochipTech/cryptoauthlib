/**
 * \file
 * \brief  AES CTR, CBC & CMAC structure definitions
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

#ifndef ATCA_CRYPTO_HW_AES_H
#define ATCA_CRYPTO_HW_AES_H

#include "cryptoauthlib.h"

typedef struct atca_aes_cbc_ctx
{
    ATCADevice device;                             //!< Device Context Pointer
    uint16_t   key_id;                             //!< Key location. Can either be a slot number or ATCA_TEMPKEY_KEYID for TempKey.
    uint8_t    key_block;                          //!< Index of the 16-byte block to use within the key location for the actual key.
    uint8_t    ciphertext[ATCA_AES128_BLOCK_SIZE]; //!< Ciphertext from last operation.
} atca_aes_cbc_ctx_t;


typedef struct atca_aes_cmac_ctx
{
    atca_aes_cbc_ctx_t cbc_ctx;                       //!< CBC context
    uint32_t           block_size;                    //!< Number of bytes in current block.
    uint8_t            block[ATCA_AES128_BLOCK_SIZE]; //!< Unprocessed message storage.
} atca_aes_cmac_ctx_t;


typedef struct atca_aes_ctr_ctx
{
    ATCADevice device;                     //!< Device Context Pointer
    uint16_t   key_id;                     //!< Key location. Can either be a slot number or ATCA_TEMPKEY_KEYID for TempKey.
    uint8_t    key_block;                  //!< Index of the 16-byte block to use within the key location for the actual key.
    uint8_t    cb[ATCA_AES128_BLOCK_SIZE]; //!< Counter block, comprises of nonce + count value (16 bytes).
    uint8_t    counter_size;               //!< Size of counter in the initialization vector.
}atca_aes_ctr_ctx_t;



#endif
