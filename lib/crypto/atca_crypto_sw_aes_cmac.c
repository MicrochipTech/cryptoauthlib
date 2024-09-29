/**
 * \file
 * \brief Common Wrapper for host side AES-CMAC implementations that feature
 * update APIs rather than an all at once implementation
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

#include "atca_crypto_sw.h"

#if ATCA_CRYPTO_AES_CMAC_EN

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-CMAC operations
 *  \brief Initialize context for performing CMAC in software.
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_cmac_init(
    struct atcac_aes_cmac_ctx*  ctx,    /**< [in] pointer to a aes-cmac context */
    const uint8_t*              key,    /**< [in] key value to use */
    const uint8_t               key_len /**< [in] length of the key */
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(key);
    UNUSED_VAR(key_len);
    return ATCA_UNIMPLEMENTED;
}

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-CMAC operations
 *  \brief Update CMAC context with input data
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_cmac_update(
    struct atcac_aes_cmac_ctx*  ctx,        /**< [in] pointer to a aes-cmac context */
    const uint8_t*              data,       /**< [in] input data */
    const size_t                data_size   /**< [in] length of input data */
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(data);
    UNUSED_VAR(data_size);
    return ATCA_UNIMPLEMENTED;
}

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-CMAC operations
 *  \brief Finish CMAC calculation and clear the CMAC context
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_cmac_finish(
    struct atcac_aes_cmac_ctx*  ctx,        /**< [in] pointer to a aes-cmac context */
    uint8_t*                    cmac,       /**< [out] cmac value */
    size_t*                     cmac_size   /**< [inout] length of cmac */
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(cmac);
    UNUSED_VAR(cmac_size);
    return ATCA_UNIMPLEMENTED;
}

#endif