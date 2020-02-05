/**
 * \file
 *
 * \brief Core related functionality implementation.
 *
 * Copyright (c) 2014-2018 Microchip Technology Inc. and its subsidiaries.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Subject to your compliance with these terms, you may use Microchip
 * software and any derivatives exclusively with Microchip products.
 * It is your responsibility to comply with third party license terms applicable
 * to your use of third party software (including open source software) that
 * may accompany Microchip software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES,
 * WHETHER EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE,
 * INCLUDING ANY IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY,
 * AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE
 * LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL
 * LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND WHATSOEVER RELATED TO THE
 * SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS BEEN ADVISED OF THE
 * POSSIBILITY OR THE DAMAGES ARE FORESEEABLE.  TO THE FULLEST EXTENT
 * ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN ANY WAY
 * RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * \asf_license_stop
 *
 */

#include <stdint.h>

#ifndef CONF_CPU_FREQUENCY
#define CONF_CPU_FREQUENCY ${core.CPU_CLOCK_FREQUENCY}
#endif

#if CONF_CPU_FREQUENCY < 1000
#define CPU_FREQ_POWER 3
#elif CONF_CPU_FREQUENCY < 10000
#define CPU_FREQ_POWER 4
#elif CONF_CPU_FREQUENCY < 100000
#define CPU_FREQ_POWER 5
#elif CONF_CPU_FREQUENCY < 1000000
#define CPU_FREQ_POWER 6
#elif CONF_CPU_FREQUENCY < 10000000
#define CPU_FREQ_POWER 7
#elif CONF_CPU_FREQUENCY < 100000000
#define CPU_FREQ_POWER 8
#elif CONF_CPU_FREQUENCY < 1000000000
#define CPU_FREQ_POWER 9
#endif


/**
 * \brief Retrieve the amount of cycles to delay for the given amount of us
 */
static inline uint32_t _get_cycles_for_us_internal(const uint32_t us, const uint32_t freq, const uint8_t power)
{
    switch (power) {
    case 9:
        return (us * (freq / 1000000) - 1) + 1;
    case 8:
        return (us * (freq / 100000) - 1) / 10 + 1;
    case 7:
        return (us * (freq / 10000) - 1) / 100 + 1;
    case 6:
        return (us * (freq / 1000) - 1) / 1000 + 1;
    case 5:
        return (us * (freq / 100) - 1) / 10000 + 1;
    case 4:
        return (us * (freq / 10) - 1) / 100000 + 1;
    default:
        return (us * freq - 1) / 1000000 + 1;
    }
}

/**
 * \brief Retrieve the amount of cycles to delay for the given amount of us
 */
uint32_t _get_cycles_for_us(const uint32_t us)
{
    return _get_cycles_for_us_internal(us, CONF_CPU_FREQUENCY, CPU_FREQ_POWER);
}

/**
 * \brief Retrieve the amount of cycles to delay for the given amount of ms
 */
static inline uint32_t _get_cycles_for_ms_internal(const uint32_t ms, const uint32_t freq, const uint8_t power)
{
    switch (power) {
    case 9:
        return (ms * (freq / 1000000)) * 1000;
    case 8:
        return (ms * (freq / 100000)) * 100;
    case 7:
        return (ms * (freq / 10000)) * 10;
    case 6:
        return (ms * (freq / 1000));
    case 5:
        return (ms * (freq / 100) - 1) / 10 + 1;
    case 4:
        return (ms * (freq / 10) - 1) / 100 + 1;
    default:
        return (ms * freq - 1) / 1000 + 1;
    }
}

/**
 * \brief Retrieve the amount of cycles to delay for the given amount of ms
 */
uint32_t _get_cycles_for_ms(const uint32_t ms)
{
    return _get_cycles_for_ms_internal(ms, CONF_CPU_FREQUENCY, CPU_FREQ_POWER);
}

/**
 * \brief Delay loop to delay n number of cycles
 */
void _delay_cycles(void *const hw, uint32_t cycles)
{
    /*lint -esym(718, __asm) */
#ifndef _UNIT_TEST_
    (void)hw;
    (void)cycles;
#if defined __GNUC__
    /*lint -e{718} */
    __asm(".syntax unified\n"
          "__delay:\n"
          "subs r1, r1, #1\n"
          "bhi __delay\n"
          ".syntax divided");
#elif defined __CC_ARM
    /*lint -e{718} */
    __asm("__delay:\n"
          "subs cycles, cycles, #1\n"
          "bhi __delay\n");
#elif defined __ICCARM__
    /*lint -e{718} */
    __asm("__delay:\n"
          "subs r1, r1, #1\n"
          "bhi __delay\n");
#endif
#endif
}

/**
 * \brief Perform delay in us
 */
void hal_delay_us(const uint32_t us)
{
    _delay_cycles((void*)0, _get_cycles_for_us(us));
}

/**
 * \brief Perform delay in ms
 */
void hal_delay_ms(const uint32_t ms)
{
    _delay_cycles((void*)0,_get_cycles_for_ms(ms));
}
