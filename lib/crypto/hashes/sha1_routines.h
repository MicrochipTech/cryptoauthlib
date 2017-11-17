/**
 * \file
 * \brief Software implementation of the SHA1 algorithm.
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

#ifndef __SHA1_ROUTINES_DOT_H__
#define __SHA1_ROUTINES_DOT_H__

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#ifdef WIN32
#include <windows.h>
#include <assert.h>
#endif

#include <stdint.h>


#ifndef U8
#define U8 uint8_t
#endif

#ifndef U16
#define U16 uint16_t
#endif

#ifndef U32
#define U32 uint32_t
#endif


#ifndef memcpy_P
#define memcpy_P memmove
#endif

#ifndef strcpy_P
#define strcpy_P strcpy
#endif

#ifndef _WDRESET
#define _WDRESET()
#define _NOP()
#endif

typedef struct
{
    U32 h[20 / 4];      // Ensure it's word aligned
    U32 buf[64 / 4];    // Ensure it's word aligned
    U32 byteCount;
    U32 byteCountHi;
} CL_HashContext;

#define leftRotate(x, n) (x) = (((x) << (n)) | ((x) >> (32 - (n))))

void shaEngine(U32 *buf, U32 *h);
void CL_hashInit(CL_HashContext *ctx);
void CL_hashUpdate(CL_HashContext *ctx, const U8 *src, int nbytes);
void CL_hashFinal(CL_HashContext *ctx, U8 *dest);
void CL_hash(U8 *msg, int msgBytes, U8 *dest);

#endif // __SHA1_ROUTINES_DOT_H__

