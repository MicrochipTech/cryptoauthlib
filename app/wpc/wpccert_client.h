/**
 * \file
 * \brief Provides api interfaces for accessing WPC certificates from device.
 *
 * \copyright (c) 2015-2021 Microchip Technology Inc. and its subsidiaries.
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

#ifndef WPCCERT_CLIENT_H
#define WPCCERT_CLIENT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cryptoauthlib.h"
#include "atcacert/atcacert_def.h"

uint8_t wpccert_get_slots_populated(void);
uint8_t wpccert_get_slot_count(void);

ATCA_STATUS wpccert_get_slot_info(uint16_t * dig_handle, const atcacert_def_t** def, uint8_t** mfg, \
                                  uint8_t* root_dgst, uint16_t * root_dgst_handle, uint8_t slot);
ATCA_STATUS wpccert_read_cert_size(ATCADevice device, const atcacert_def_t* cert_def, size_t* cert_size);
ATCA_STATUS wpccert_read_cert(ATCADevice device, const atcacert_def_t *cert_def, uint8_t *cert, size_t *cert_size);

ATCA_STATUS wpccert_write_cert(ATCADevice device, const atcacert_def_t* cert_def, const uint8_t* cert, size_t cert_size);

ATCA_STATUS wpccert_read_pdu_cert(ATCADevice device, uint8_t* cert, size_t* cert_size, uint8_t slot);

ATCA_STATUS wpccert_read_mfg_cert(ATCADevice device, uint8_t* cert, size_t* cert_size, uint8_t slot);

ATCA_STATUS wpccert_public_key(const atcacert_def_t* cert_def, uint8_t* public_key, uint8_t* cert);

#ifdef __cplusplus
}
#endif

#endif
