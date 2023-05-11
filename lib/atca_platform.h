/**
 * \file
 * \brief  Configure the platform interfaces for cryptoauthlib
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
#ifndef ATCA_PLATFORM_H
#define ATCA_PLATFORM_H

#include <stddef.h>
#include <string.h>

#if defined(ATCA_TESTS_ENABLED) || !defined(ATCA_PLATFORM_MALLOC)
void*   hal_malloc(size_t size);
void    hal_free(void* ptr);
#else
#define hal_malloc      ATCA_PLATFORM_MALLOC
#define hal_free        ATCA_PLATFORM_FREE
#endif

#ifdef ATCA_PLATFORM_MEMSET_S
#define hal_memset_s    ATCA_PLATFORM_MEMSET_S
#else
#ifndef memset_s
#define hal_memset_s    atcab_memset_s
#else
#define hal_memset_s    memset_s
#endif
#endif

#ifdef ATCA_PLATFORM_STRCASESTR
#define lib_strcasestr  ATCA_PLATFORM_STRCASESTR
#else
#ifndef strcasestr
const char *lib_strcasestr(const char *haystack, const char *needle);
#else
#define lib_strcasestr  strcasestr
#endif
#endif /* ATCA_PLATFORM_STRCASESTR */

#endif /* ATCA_PLATFORM_H */
