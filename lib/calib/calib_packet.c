/**
 * \file
 * \brief CryptoAuthLib API for packet allocation.
 *
 * The APIs are used for allocating packets in heap or bss according to
 * atcab heap availability. Corresponding memory free is done
 *
 * \note List of devices that support this command - ATSHA204A, ATECC108A,
 *       ATECC508A, ATECC608A/B
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

#include "cryptoauthlib.h"
#include "calib_packet.h"

#ifdef ATCA_NO_HEAP

#ifndef CA_MAX_PACKET_CACHE
    #ifdef __XC8
        #define CA_MAX_PACKET_CACHE (1)
    #else
        #define CA_MAX_PACKET_CACHE (2)
    #endif
#else
    #if CA_MAX_PACKET_CACHE < 2
        #error "CA_MAX_PACKET_CACHE must be greater than or equal to 2 if ATCA_NO_HEAP is set"
    #endif
#endif

static calib_packet_cache_t calib_packet_cache[CA_MAX_PACKET_CACHE];

ATCAPacket* calib_packet_alloc(void)
{
    ATCAPacket* packet = NULL;

    for (uint8_t i = 0; i < CA_MAX_PACKET_CACHE; i++)
    {
        if (false == calib_packet_cache[i].used) 
        {
            calib_packet_cache[i].used = true; 
            packet =  &calib_packet_cache[i].packet_pool; 
            break;
        }
    }

    return packet; 
}
#else
ATCAPacket* calib_packet_alloc(void)
{
    ATCAPacket* packet = (ATCAPacket*)hal_malloc(sizeof(ATCAPacket));   // Allocate memory on the heap

    return packet;
}
#endif

#ifdef ATCA_NO_HEAP
void calib_packet_free(ATCAPacket* packet)
{
    if (packet == NULL)
    {
        return; 
    }

    for (uint8_t i = 0; i < CA_MAX_PACKET_CACHE; i++)
    {
        if (&calib_packet_cache[i].packet_pool == packet) 
        {
            memset(&calib_packet_cache[i].packet_pool, 0x00, sizeof(ATCAPacket)); 
            calib_packet_cache[i].used = false; 
            break;
        }
    }
}
#else
void calib_packet_free(ATCAPacket* packet)
{
    if (NULL != packet)
    {
        hal_free(packet);
    }
}
#endif
