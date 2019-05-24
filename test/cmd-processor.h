/**
 * \file
 *
 * \brief  simple command processor for test console
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


#ifndef CMD_PROCESSOR_H_
#define CMD_PROCESSOR_H_

#include "cryptoauthlib.h"

#define cmdQ_SIZE    512

int processCmd(void);

volatile struct
{
    uint8_t m_getIdx;
    uint8_t m_putIdx;
    uint8_t m_entry[ cmdQ_SIZE ];
} cmdQ;

typedef void (*fp_menu_handler)(void);

typedef struct
{
    const char*     menu_cmd;
    const char*     menu_cmd_description;
    fp_menu_handler fp_handler;
}t_menu_info;


int run_tests(int test);

#if defined(ATCA_HAL_CUSTOM)
extern ATCAIfaceCfg g_cfg_atsha204a_custom;
extern ATCAIfaceCfg g_cfg_atecc108a_custom;
extern ATCAIfaceCfg g_cfg_atecc508a_custom;
extern ATCAIfaceCfg g_cfg_atecc608a_custom;
#endif

#endif /* CMD-PROCESSOR_H_ */