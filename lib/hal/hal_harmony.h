/**
 * \file
 * \brief Harmony PLIB Definitions for Cryptoauthlib Drivers.
 *
 * \copyright (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
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

#ifndef HAL_HARMONY_H
#define HAL_HARMONY_H

typedef bool (* atca_i2c_plib_read)(uint16_t, uint8_t *, PLIB_SIZE_VAR_TYPE);
typedef bool (* atca_i2c_plib_write)(uint16_t, uint8_t *, PLIB_SIZE_VAR_TYPE);
typedef bool (* atca_i2c_plib_is_busy)(void);
typedef PLIB_I2C_ERROR (* atca_i2c_error_get)(void);
typedef bool (* atca_i2c_plib_transfer_setup)(PLIB_I2C_TRANSFER_SETUP* setup, uint32_t srcClkFreq);

typedef struct atca_plib_i2c_api
{
    atca_i2c_plib_read           read;
    atca_i2c_plib_write          write;
    atca_i2c_plib_is_busy        is_busy;
    atca_i2c_error_get           error_get;
    atca_i2c_plib_transfer_setup transfer_setup;
} atca_plib_api_t;

typedef struct atca_plib_uart_api
{
    atca_uart_plib_read           read;
    atca_uart_plib_write          write;
    atca_uart_plib_is_busy        is_busy;
    atca_uart_error_get           error_get;
    atca_uart_plib_transfer_setup transfer_setup;
} atca_plib_api_t;



#endif /* HAL_HARMONY_H */