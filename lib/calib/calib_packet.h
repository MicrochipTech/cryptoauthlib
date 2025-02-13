/**
 * \file
 * \brief Defines packet allocation functions
 *
 * The APIs are used for allocating packets in heap or bss according to 
 * atcab heap availability. Corresponding memory free is done
 *
 * This supports the ATECC device family.
 *
 * \copyright (c) 2024 Microchip Technology Inc. and its subsidiaries.
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


#ifndef CALIB_PACKET_H
#define CALIB_PACKET_H

#include "calib_command.h"
#include "atca_device.h"
#include "atca_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct calib_packet_cache_s
{
    ATCAPacket packet_pool;
    bool used;
}calib_packet_cache_t;

ATCAPacket* calib_packet_alloc(void);

void calib_packet_free(ATCAPacket* packet);

#ifdef __cplusplus
}
#endif

#endif /* CALIB_PACKET_H */