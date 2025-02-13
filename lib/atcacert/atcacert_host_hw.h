/**
 * \file
 * \brief host side methods using CryptoAuth hardware
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
#ifndef ATCACERT_HOST_HA_H
#define ATCACERT_HOST_HA_H

#include <stddef.h>
#include <stdint.h>
#include "atcacert_def.h"

// Inform function naming when compiling in C++
#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup atcacert_ Certificate manipulation methods (atcacert_)
 *
 * \brief
 * These methods provide convenient ways to perform certification I/O with
 * CryptoAuth chips and perform certificate manipulation in memory
 *
   @{ */

#if ATCACERT_HW_VERIFY_EN && ATCACERT_COMPCERT_EN
/**
 * \brief Verify a certificate against its certificate authority's public key using the host's ATECC/TA
 *        device for crypto functions.
 *
 * \param[in] device         Device context pointer
 * \param[in] cert_def       Certificate definition describing how to extract the TBS and signature
 *                           components from the certificate specified.
 * \param[in] cert           Certificate to verify.
 * \param[in] cert_size      Size of the certificate (cert) in bytes.
 * \param[in] ca_public_key  The ECC P256/P384/P521 public key of the certificate authority that signed this
 *                           certificate. Formatted as the X and Y integers concatenated together.
 *
 * \return ATCACERT_E_SUCCESS if the verify succeeds, ATCACERT_VERIFY_FAILED or ATCA_EXECUTION_ERROR if it fails to
 *         verify. ATCA_EXECUTION_ERROR may occur when the public key is invalid and doesn't fall
 *         on the P256 curve.
 */
ATCA_STATUS atcacert_verify_cert_hw(ATCADevice            device,
                                    const atcacert_def_t* cert_def,
                                    const uint8_t*        cert,
                                    size_t                cert_size,
                                    cal_buffer*           ca_public_key);
#endif

#if ATCACERT_HW_CHALLENGE_EN
/**
 * \brief Generate a random challenge to be sent to the client using the RNG on the host's ATECC/TA
 *        device.
 *
 * \param[in]  device     Device context pointer
 * \param[out] challenge  Random challenge is return here.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_gen_challenge_hw(ATCADevice device, cal_buffer* challenge);
#endif


#if ATCACERT_HW_VERIFY_EN && ATCACERT_COMPCERT_EN
/**
 * \brief Verify a client's response to a challenge using the host's ATECC/TA device for crypto
 *        functions.
 *
 * The challenge-response protocol is an ECDSA Sign and Verify. This performs an ECDSA verify on the
 * response returned by the client, verifying the client has the private key counter-part to the
 * public key returned in its certificate.
 *
 * \param[in] device             Device context pointer
 * \param[in] device_public_key  Device public key as read from its certificate. Formatted as the X
 *                               and Y integers concatenated together.
 * \param[in] challenge          Challenge that was sent to the client.
 * \param[in] response           Response returned from the client to be verified.
 *
 * \return ATCACERT_E_SUCCESS if the verify succeeds, ATCACERT_VERIFY_FAILED or ATCA_EXECUTION_ERROR if it fails to
 *         verify. ATCA_EXECUTION_ERROR may occur when the public key is invalid and doesn't fall
 *         on the P256/P384/P521 curve.
 */
ATCA_STATUS atcacert_verify_response_hw(ATCADevice        device,
                                        cal_buffer* device_public_key,
                                        cal_buffer* challenge,
                                        cal_buffer* response);
#endif

/** @} */
#ifdef __cplusplus
}
#endif

#endif
