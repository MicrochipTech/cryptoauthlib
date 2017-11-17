/**
 * \file
 * \brief  Hardware Interface Functions - SWI bit-banged
 *
 * \copyright Copyright (c) 2017 Microchip Technology Inc. and its subsidiaries (Microchip). All rights reserved.
 *
 * \page License
 *
 * You are permitted to use this software and its derivatives with Microchip
 * products. Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Microchip may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with a
 *    Microchip integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL MICROCHIP BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <asf.h>
#include <stdint.h>
#include "swi_bitbang_samd21.h"





SWIBuses swi_buses_default = {
    { EXT3_PIN_3, EXT3_PIN_9, EXT3_PIN_I2C_SDA, EXT3_PIN_13, EXT2_PIN_3, EXT2_PIN_5, EXT2_PIN_7, EXT2_PIN_9, EXT2_PIN_13, EXT2_PIN_15, EXT2_PIN_17, EXT1_PIN_3, EXT1_PIN_5, EXT1_PIN_7, EXT1_PIN_9, EXT1_PIN_13, EXT1_PIN_15, EXT1_PIN_17, EXT3_PIN_7, EXT3_PIN_10, EXT3_PIN_I2C_SCL, EXT3_PIN_14, EXT2_PIN_4, EXT2_PIN_6, EXT2_PIN_8, EXT2_PIN_10, EXT2_PIN_14, EXT2_PIN_16, EXT2_PIN_18, EXT1_PIN_4, EXT1_PIN_6, EXT1_PIN_8, EXT1_PIN_10, EXT1_PIN_14, EXT1_PIN_16, EXT1_PIN_18 }

};


//! declaration of the variable indicating which pin the selected device is connected to
static uint8_t device_pin;


void swi_set_pin(uint8_t id)
{
    device_pin = id;
}



void swi_enable(void)
{
    struct port_config pin_conf;

    port_get_config_defaults(&pin_conf);
    pin_conf.direction  = PORT_PIN_DIR_OUTPUT;
    port_pin_set_config(device_pin, &pin_conf);
}

void swi_disable(void)
{
    struct port_config pin_conf;

    port_get_config_defaults(&pin_conf);
    port_pin_set_config(device_pin, &pin_conf);
}


void swi_set_signal_pin(uint8_t is_high)
{
    if (is_high)
        port_pin_set_output_level(device_pin, true);
    else
        port_pin_set_output_level(device_pin, false);
}

void swi_send_wake_token(void)
{
    swi_set_signal_pin(0);
    delay_us(60);
    swi_set_signal_pin(1);
}

void swi_send_bytes(uint8_t count, uint8_t *buffer)
{
    uint8_t i, bit_mask;
    struct port_config pin_conf;

    port_get_config_defaults(&pin_conf);
    pin_conf.direction  = PORT_PIN_DIR_OUTPUT;
    port_pin_set_config(device_pin, &pin_conf);

    //! Wait turn around time.
    RX_TX_DELAY;
    cpu_irq_disable();


    for (i = 0; i < count; i++)
    {
        for (bit_mask = 1; bit_mask > 0; bit_mask <<= 1)
        {
            if (bit_mask & buffer[i])   //!< Send Logic 1 (7F)
            {
                port_pin_set_output_level(device_pin, false);
                BIT_DELAY_1L;
                port_pin_set_output_level(device_pin, true);
                BIT_DELAY_7;
            }
            else     //!< Send Logic 0 (7D)
            {
                port_pin_set_output_level(device_pin, false);
                BIT_DELAY_1L;
                port_pin_set_output_level(device_pin, true);
                BIT_DELAY_1H;
                port_pin_set_output_level(device_pin, false);
                BIT_DELAY_1L;
                port_pin_set_output_level(device_pin, true);
                BIT_DELAY_5;
            }
        }
    }
    cpu_irq_enable();



}


void swi_send_byte(uint8_t byte)
{
    swi_send_bytes(1, &byte);

}




ATCA_STATUS swi_receive_bytes(uint8_t count, uint8_t *buffer)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    uint8_t i;
    uint8_t bit_mask;
    uint8_t pulse_count;
    uint16_t timeout_count;
    struct port_config pin_conf;


    port_get_config_defaults(&pin_conf);
    port_pin_set_config(device_pin, &pin_conf);


    cpu_irq_disable();
    //! Receive bits and store in buffer.
    for (i = 0; i < count; i++)
    {
        buffer[i] = 0;
        for (bit_mask = 1; bit_mask > 0; bit_mask <<= 1)
        {
            pulse_count = 0;


            timeout_count = START_PULSE_TIME_OUT;
            //! Detect start bit.

            while (--timeout_count > 0)
            {
                //! Wait for falling edge.
                if (port_pin_get_input_level(device_pin) == 0)

                    break;
            }
            if (timeout_count == 0)
            {
                status = ATCA_RX_TIMEOUT;
                break;
            }

            timeout_count = START_PULSE_TIME_OUT;

            do
            {
                //! Wait for rising edge.
                if (port_pin_get_input_level(device_pin) != 0)
                {
                    pulse_count = 1;

                    break;
                }
            }
            while (--timeout_count > 0);

            if (pulse_count == 0)
            {
                status = ATCA_RX_TIMEOUT;
                break;
            }

            //!  let's just wait the maximum time for the falling edge of a zero bit
            //! to arrive after we have detected the rising edge of the start bit.
            timeout_count = ZERO_PULSE_TIME_OUT;

            //! Detect possible edge indicating zero bit.
            do
            {
                if (port_pin_get_input_level(device_pin) == 0)
                {
                    pulse_count = 2;
                    break;
                }
            }
            while (--timeout_count > 0);


            //! Wait for rising edge of zero pulse before returning. Otherwise we might interpret
            //! its rising edge as the next start pulse.
            if (pulse_count == 2)
            {
                timeout_count = ZERO_PULSE_TIME_OUT;

                do
                    if (port_pin_get_input_level(device_pin) != 0)
                        break;

                while (timeout_count-- > 0);

            }
            //! Update byte at current buffer index.
            else
            //! received "one" bit
            {
                buffer[i] |= bit_mask;
            }
        }


        if (status != ATCA_SUCCESS)
            break;
    }

    if (status == ATCA_RX_TIMEOUT)
    {
        if (i > 0)
            //! Indicate that we timed out after having received at least one byte.
            status = ATCA_RX_FAIL;
    }

    cpu_irq_enable();


    return status;
}