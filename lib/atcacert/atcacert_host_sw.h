/**
 * \file
 * \brief Host side methods using software implementations.  host-side, the one authenticating
 *        a client, of the authentication process. Crypto functions are performed using a software library.
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

#ifndef ATCACERT_HOST_SOFT_H
#define ATCACERT_HOST_SOFT_H

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

#if ATCAC_VERIFY_EN && ATCACERT_COMPCERT_EN
/**
 * \brief Verify a certificate against its certificate authority's public key using software crypto
 *        functions.The function is currently not implemented.
 *
 * \param[in] cert_def       Certificate definition describing how to extract the TBS and signature
 *                           components from the certificate specified.
 * \param[in] cert           Certificate to verify.
 * \param[in] cert_size      Size of the certificate (cert) in bytes.
 * \param[in] ca_public_key  Buffer pointing to the ECC P256/P384/P521 public key of the certificate 
 *                           authority that signed this certificate. Formatted as the X and Y integers 
 *                           concatenated together.                      
 *
 * \return ATCA_UNIMPLEMENTED , as the function is currently not implemented.
 */
ATCA_STATUS atcacert_verify_cert_sw(const atcacert_def_t* cert_def,
                                    const uint8_t*        cert,
                                    size_t                cert_size,
                                    const cal_buffer*     ca_public_key);
#endif


/**
 * \brief Generate a random challenge to be sent to the client using a software PRNG.The function is currently not implemented.
 *
 * \param[out] challenge  Random challenge is return in the buffer.
 *
 * \return ATCA_UNIMPLEMENTED , as the function is currently not implemented.
 */
ATCA_STATUS atcacert_gen_challenge_sw(cal_buffer* challenge);




/**
 * \brief Verify a client's response to a challenge using software crypto functions.The function is currently not implemented.
 *
 * The challenge-response protocol is an ECDSA Sign and Verify. This performs an ECDSA verify on the
 * response returned by the client, verifying the client has the private key counter-part to the
 * public key returned in its certificate.
 *
 * \param[in] device_public_key  Buffer pointing to the device public key as read from its certificate. 
 *                               Formatted as the X and Y integers concatenated together.
 * \param[in] challenge          Buffer pointing to the Challenge that was sent to the client.
 * \param[in] response           Response returned from the client to be verified is returned in the buffer.
 *
 * \return ATCA_UNIMPLEMENTED , as the function is currently not implemented.
 */
ATCA_STATUS atcacert_verify_response_sw(const cal_buffer* device_public_key,
                                        const cal_buffer* challenge,
                                        const cal_buffer* response);

/** @} */
#ifdef __cplusplus
}
#endif

#endif
