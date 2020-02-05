/**
 * \file
 * \brief ATCA Hardware abstraction layer for Microchip devices over Harmony PLIB
 *
 * Prerequisite: add SERCOM I2C Master Polled support to application in MHC
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

#ifndef HAL_I2C_HARMONY_H_
#define HAL_I2C_HARMONY_H_

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses);

ATCA_STATUS hal_i2c_discover_devices(int bus_num, ATCAIfaceCfg cfg[], int *found);

ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)

ATCA_STATUS hal_i2c_post_init(ATCAIface iface);

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength);

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength);

ATCA_STATUS hal_i2c_wake(ATCAIface iface);

ATCA_STATUS hal_i2c_idle(ATCAIface iface);

ATCA_STATUS hal_i2c_sleep(ATCAIface iface);

ATCA_STATUS hal_i2c_release(void *hal_data);

/** @} */

#endif /* HAL_I2C_HARMONY_H_ */
