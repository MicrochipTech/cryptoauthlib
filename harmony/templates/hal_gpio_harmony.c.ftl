/**
 *
 * \file
 * \brief ATCA Hardware abstraction layer for GPIO
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

#include "atca_hal.h"

<#assign PLIB_NAME  = core.PORT_API_PREFIX?string>

/**
 * \brief Initialize a gpio interface using given config.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_gpio_init(ATCAIface iface, ATCAIfaceCfg *cfg)
{
    return ATCA_SUCCESS;
}

/**
 * \brief Post Init for gpio hal
 *
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_gpio_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/**
 * \brief Set the state of the pin
 *
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_gpio_send(
    ATCAIface iface,            /**< Interface context */
    uint8_t word_address,       /**< Unused parameter */
    uint8_t* pin_state,         /**< Pin state to output */
    int unused_param            /**< Unused parameter  */
)
{
    (void)word_address;
    (void)unused_param;
    uint32_t pin_id = *(uint32_t*)atgetifacecfg(iface)->cfg_data;

    ${PLIB_NAME}_PinWrite(pin_id, *pin_state);

    return ATCA_SUCCESS;
}

/**
 * \brief Read the state of the pin
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_gpio_receive(
    ATCAIface iface,            /**< Interface context */
    uint8_t word_address,       /**< Unused parameter */
    uint8_t* pin_state,         /**< Pin state to output */
    uint16_t* unused_param      /**< Unused parameter  */
)
{
    (void)word_address;
    (void)unused_param;
    uint32_t pin_id = *(uint32_t*)atgetifacecfg(iface)->cfg_data;

    *pin_state = ${PLIB_NAME}_PinRead(pin_id);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_gpio_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)paramlen;

    if (iface && iface->mIfaceCFG)
    {
        switch (option)
        {
        case ATCA_HAL_CONTROL_DIRECTION:
            {
                uint8_t pin_dir = *(uint8_t*)param;
                uint32_t pin_id = *(uint32_t*)atgetifacecfg(iface)->cfg_data;

                if (pin_dir == 0) {
                    ${PLIB_NAME}_PinInputEnable(pin_id);
                }
                else
                {
                    ${PLIB_NAME}_PinOutputEnable(pin_id);
                }
            }
            return ATCA_SUCCESS;
        default:
            return ATCA_UNIMPLEMENTED;
        }
    }
    return ATCA_BAD_PARAM;
}

/**
 * \brief Release and clean up the HAL
 *
 * \param[in] hal_data  opaque pointer to hal data structure - known only
 *                      to the HAL implementation
 *
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_gpio_release(void *hal_data)
{
    return ATCA_SUCCESS;
}