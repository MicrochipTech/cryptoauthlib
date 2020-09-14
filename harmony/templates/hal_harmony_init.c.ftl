/**
 * \file
 * \brief ATCA Hardware abstraction layer for Microchip devices over Harmony PLIB.
 *
 * This code is structured in two parts.  Part 1 is the connection of the ATCA HAL API to the physical I2C
 * implementation. Part 2 is the Harmony I2C primitives to set up the interface.
 *
 * Prerequisite: add SERCOM I2C Master Polled support to application in Atmel Studio
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

#include "cryptoauthlib.h"

<#assign pliblist = CAL_PLIB_LIST?word_list>
<#assign PLIB_NAME  = core.PORT_API_PREFIX?string>
<#if pliblist?size != 0>
<#list pliblist as plib_id>
<#assign plib_info = plib_id?split("_")>
<#if plib_info?size == 1 || plib_info[1] == "i2c">
atca_plib_i2c_api_t ${plib_info[0]}_plib_i2c_api = {
    .read = ${.vars["${plib_info[0]}"].I2C_PLIB_API_PREFIX}_Read,
    .write = ${.vars["${plib_info[0]}"].I2C_PLIB_API_PREFIX}_Write,
    .is_busy = ${.vars["${plib_info[0]}"].I2C_PLIB_API_PREFIX}_IsBusy,
    .error_get = ${.vars["${plib_info[0]}"].I2C_PLIB_API_PREFIX}_ErrorGet,
    .transfer_setup = ${.vars["${plib_info[0]}"].I2C_PLIB_API_PREFIX}_TransferSetup
<#elseif plib_info[1] == "spi">
static void ${plib_info[0]}_select_pin(uint32_t pin, bool value)
{
    ${PLIB_NAME}_PinWrite(pin, value);
}

atca_plib_spi_api_t ${plib_info[0]}_plib_spi_api = {
    .read = ${.vars["${plib_info[0]}"].SPI_PLIB_API_PREFIX}_Read,
    .write = ${.vars["${plib_info[0]}"].SPI_PLIB_API_PREFIX}_Write,
    .is_busy = ${.vars["${plib_info[0]}"].SPI_PLIB_API_PREFIX}_IsBusy,
    .select = &${plib_info[0]}_select_pin
<#elseif plib_info[1] == "uart">
atca_plib_swi_api_t ${plib_info[0]}_plib_swi_api = {
    .read = ${.vars["${plib_info[0]}"].USART_PLIB_API_PREFIX}_Read,
    .write = ${.vars["${plib_info[0]}"].USART_PLIB_API_PREFIX}_Write,
    .error_get = ${.vars["${plib_info[0]}"].USART_PLIB_API_PREFIX}_ErrorGet,
    .transfer_setup = ${.vars["${plib_info[0]}"].USART_PLIB_API_PREFIX}_SerialSetup
</#if>
};

</#list>
</#if>


