/**
 * \file
 * \brief CryptoAuthLiub is meant to be portable across architectures, even
 *        non-Microchip architectures and compiler environments. This file is
 *        for isolating compiler specific macros.
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


#ifndef ATCA_COMPILER_H_
#define ATCA_COMPILER_H_

#if defined(__XC8) || defined(__XC16)
/* Microchip XC8 and XC16 Compilers ------------------------- */
#ifndef SIZE_MAX
/* coverity[misra_c_2012_rule_21_1_violation:SUPPRESS] */
#define SIZE_MAX 65535
#endif

#define ATCA_UINT16_HOST_TO_LE(x)  (x)
#define ATCA_UINT16_LE_TO_HOST(x)  (x)
#define ATCA_UINT32_HOST_TO_LE(x)  (x)
#define ATCA_UINT16_HOST_TO_BE(x)  ((((uint16_t)(x) & 0x00FF) << 8) | (((uint16_t)(x) & 0xFF00) >> 8))
#define ATCA_UINT16_BE_TO_HOST(x)  ((((uint16_t)(x) & 0x00FF) << 8) | (((uint16_t)(x) & 0xFF00) >> 8))
#define ATCA_UINT32_HOST_TO_BE(x)  ((((uint32_t)(x) & 0x000000FFUL) << 24U) | (((uint32_t)(x) & 0x0000FF00UL) << 8U) | (((uint32_t)(x) & 0x00FF0000UL) >> 8U) | (((uint32_t)(x) & 0xFF000000UL) >> 24U))
#define ATCA_UINT32_BE_TO_HOST(x)  ((((uint32_t)(x) & 0x000000FFUL) << 24U) | (((uint32_t)(x) & 0x0000FF00UL) << 8U) | (((uint32_t)(x) & 0x00FF0000UL) >> 8U) | (((uint32_t)(x) & 0xFF000000UL) >> 24U))
#define ATCA_UINT64_HOST_TO_BE(x)  (((uint64_t)ATCA_UINT32_HOST_TO_BE((uint32_t)(x)) << 32) + (uint64_t)ATCA_UINT32_HOST_TO_BE((uint32_t)((x) >> 32)))
#define ATCA_UINT64_BE_TO_HOST(x)  (((uint64_t)ATCA_UINT32_BE_TO_HOST((uint32_t)(x)) << 32) + (uint64_t)ATCA_UINT32_BE_TO_HOST((uint32_t)((x) >> 32)))
#define ATCA_UINT64_HOST_TO_LE(x)  (x)
#define SHARED_LIB_EXPORT
#define SHARED_LIB_IMPORT       extern

#elif defined(__clang__)
/* Clang/LLVM. ---------------------------------------------- */
#pragma clang diagnostic ignored "-Wunknown-pragmas"

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ATCA_UINT16_HOST_TO_LE(x)  __builtin_bswap16(x)
#define ATCA_UINT16_LE_TO_HOST(x)  __builtin_bswap16(x)
#define ATCA_UINT32_HOST_TO_LE(x)  __builtin_bswap32(x)
#define ATCA_UINT16_HOST_TO_BE(x)  (x)
#define ATCA_UINT16_BE_TO_HOST(x)  (x)
#define ATCA_UINT32_HOST_TO_BE(x)  (x)
#define ATCA_UINT32_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_BE(x)  (x)
#define ATCA_UINT64_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_LE(x)  __builtin_bswap64(x)
#define ATCA_PLATFORM_BE
#else
#define ATCA_UINT16_HOST_TO_LE(x)  (x)
#define ATCA_UINT16_LE_TO_HOST(x)  (x)
#define ATCA_UINT32_HOST_TO_LE(x)  (x)
#define ATCA_UINT16_HOST_TO_BE(x)  __builtin_bswap16(x)
#define ATCA_UINT16_BE_TO_HOST(x)  __builtin_bswap16(x)
#define ATCA_UINT32_HOST_TO_BE(x)  __builtin_bswap32(x)
#define ATCA_UINT32_BE_TO_HOST(x)  __builtin_bswap32(x)
#define ATCA_UINT64_HOST_TO_BE(x)  __builtin_bswap64(x)
#define ATCA_UINT64_BE_TO_HOST(x)  __builtin_bswap64(x)
#define ATCA_UINT64_HOST_TO_LE(x)  (x)
#endif

#ifdef WIN32
#define SHARED_LIB_EXPORT       __declspec(dllexport)
#define SHARED_LIB_IMPORT       __declspec(dllimport)
#else
#define SHARED_LIB_EXPORT
#define SHARED_LIB_IMPORT       extern
#endif

//#elif defined(__ICC) || defined(__INTEL_COMPILER)
/* Intel ICC/ICPC. ------------------------------------------ */

#elif defined(__GNUC__) || defined(__GNUG__)
/* GNU GCC/G++. --------------------------------------------- */
#if defined(__AVR32__)
#define ATCA_UINT16_HOST_TO_LE(x)  __builtin_bswap_16(x)
#define ATCA_UINT16_LE_TO_HOST(x)  __builtin_bswap_16(x)
#define ATCA_UINT32_HOST_TO_LE(x)  __builtin_bswap_32(x)
#define ATCA_UINT16_HOST_TO_BE(x)  (x)
#define ATCA_UINT16_BE_TO_HOST(x)  (x)
#define ATCA_UINT32_HOST_TO_BE(x)  (x)
#define ATCA_UINT32_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_BE(x)  (x)
#define ATCA_UINT64_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_LE(x)  __builtin_bswap64(x)
#define ATCA_NO_PRAGMA_PACK
#define ATCA_PLATFORM_BE
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ATCA_UINT16_HOST_TO_LE(x)  __builtin_bswap16(x)
#define ATCA_UINT16_LE_TO_HOST(x)  __builtin_bswap16(x)
#define ATCA_UINT16_HOST_TO_BE(x)  (x)
#define ATCA_UINT16_BE_TO_HOST(x)  (x)
#define ATCA_UINT32_HOST_TO_LE(x)  __builtin_bswap32(x)
#define ATCA_UINT32_HOST_TO_BE(x)  (x)
#define ATCA_UINT32_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_BE(x)  (x)
#define ATCA_UINT64_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_LE(x)  __builtin_bswap64(x)
#define ATCA_PLATFORM_BE
#else
#define ATCA_UINT16_HOST_TO_BE(x)  __builtin_bswap16(x)
#define ATCA_UINT16_BE_TO_HOST(x)  __builtin_bswap16(x)
#define ATCA_UINT16_HOST_TO_LE(x)  (x)
#define ATCA_UINT16_LE_TO_HOST(x)  (x)
#define ATCA_UINT32_HOST_TO_LE(x)  (x)
#define ATCA_UINT32_HOST_TO_BE(x)  __builtin_bswap32(x)
#define ATCA_UINT32_BE_TO_HOST(x)  __builtin_bswap32(x)
#define ATCA_UINT64_HOST_TO_BE(x)  __builtin_bswap64(x)
#define ATCA_UINT64_BE_TO_HOST(x)  __builtin_bswap64(x)
#define ATCA_UINT64_HOST_TO_LE(x)  (x)
#endif

#ifdef WIN32
#define SHARED_LIB_EXPORT       __declspec(dllexport)
#define SHARED_LIB_IMPORT       __declspec(dllimport)
#else
#define SHARED_LIB_EXPORT
#define SHARED_LIB_IMPORT       extern
#endif


//#elif defined(__HP_cc) || defined(__HP_aCC)
/* Hewlett-Packard C/aC++. ---------------------------------- */

//#elif defined(__IBMC__) || defined(__IBMCPP__)
/* IBM XL C/C++. -------------------------------------------- */

#elif defined(_MSC_VER)
/* Microsoft Visual Studio. --------------------------------- */
#if _MSC_VER >= 1914
// This warning was added in MSCV 2017 Update 7 (15.7.1)
#pragma warning(disable:5045)   //Spectre mitigation informative
#endif
#pragma warning(disable:4820)   //Stucture packing
#pragma warning(disable:4061)   //Missing enumerations from switch statements

// MSVC is usually always little-endian architecture
#include <stdlib.h>
#define ATCA_UINT16_HOST_TO_BE(x)  _byteswap_ushort(x)
#define ATCA_UINT16_BE_TO_HOST(x)  _byteswap_ushort(x)
#define ATCA_UINT16_HOST_TO_LE(x)  (x)
#define ATCA_UINT16_LE_TO_HOST(x)  (x)
#define ATCA_UINT32_HOST_TO_LE(x)  (x)
#define ATCA_UINT32_HOST_TO_BE(x)  _byteswap_ulong(x)
#define ATCA_UINT32_BE_TO_HOST(x)  _byteswap_ulong(x)
#define ATCA_UINT64_HOST_TO_BE(x)  _byteswap_uint64(x)
#define ATCA_UINT64_BE_TO_HOST(x)  _byteswap_uint64(x)
#define ATCA_UINT64_HOST_TO_LE(x)  (x)
/* coverity[cert_dcl37_c_violation:SUPPRESS]*/
/* coverity[misra_c_2012_rule_21_1_violation:SUPPRESS]*/
/* coverity[misra_c_2012_rule_21_2_violation:SUPPRESS]*/
#define strtok_r                   strtok_s

#define SHARED_LIB_EXPORT       __declspec(dllexport)
#define SHARED_LIB_IMPORT       __declspec(dllimport)

//#elif defined(__PGI)
/* Portland Group PGCC/PGCPP. ------------------------------- */

//#elif defined(__SUNPRO_C) || defined(__SUNPRO_CC)
/* Oracle Solaris Studio. ----------------------------------- */

#elif defined __CC_ARM
/* ARMCC/RealView ------------------------------------------- */
#ifdef __BIG_ENDIAN
#define ATCA_UINT16_HOST_TO_LE(x)  ((x >> 8) | ((x & 0xFF) << 8))
#define ATCA_UINT16_LE_TO_HOST(x)  ((x >> 8) | ((x & 0xFF) << 8))
#define ATCA_UINT32_HOST_TO_LE(x)  __rev(x)
#define ATCA_UINT32_HOST_TO_BE(x)  (x)
#define ATCA_UINT32_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_BE(x)  (x)
#define ATCA_UINT64_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_LE(x)  (((uint64_t)__rev((uint32_t)x) << 32) | (uint64_t)__rev((uint32_t)(x >> 32)))
#define ATCA_PLATFORM_BE
#else
#define ATCA_UINT16_HOST_TO_LE(x)  (x)
#define ATCA_UINT16_LE_TO_HOST(x)  (x)
#define ATCA_UINT32_HOST_TO_LE(x)  (x)
#define ATCA_UINT32_HOST_TO_BE(x)  __rev(x)
#define ATCA_UINT32_BE_TO_HOST(x)  __rev(x)
#define ATCA_UINT64_HOST_TO_BE(x)  (((uint64_t)__rev((uint32_t)x) << 32) | (uint64_t)__rev((uint32_t)(x >> 32)))
#define ATCA_UINT64_BE_TO_HOST(x)  (((uint64_t)__rev((uint32_t)x) << 32) | (uint64_t)__rev((uint32_t)(x >> 32)))
#define ATCA_UINT64_HOST_TO_LE(x)  (x)
#endif

#define SHARED_LIB_EXPORT
#define SHARED_LIB_IMPORT       extern

#elif defined __ICCARM__
/* IAR ARM ------------------------------------------- */
#pragma diag_suppress=Pe161 //Unknown pragma warning

#include <intrinsics.h>
#if __LITTLE_ENDIAN__ == 0
#define ATCA_UINT16_HOST_TO_LE(x)  __REV16(x)
#define ATCA_UINT16_LE_TO_HOST(x)  __REV16(x)
#define ATCA_UINT32_HOST_TO_LE(x)  __REV(x)
#define ATCA_UINT32_HOST_TO_BE(x)  (x)
#define ATCA_UINT32_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_BE(x)  (x)
#define ATCA_UINT64_BE_TO_HOST(x)  (x)
#define ATCA_UINT64_HOST_TO_LE(x)  (((uint64_t)__REV((uint32_t)x) << 32) | (uint64_t)__REV((uint32_t)(x >> 32)))
#define ATCA_PLATFORM_BE
#else
#define ATCA_UINT16_HOST_TO_LE(x)  (x)
#define ATCA_UINT16_LE_TO_HOST(x)  (x)
#define ATCA_UINT32_HOST_TO_LE(x)  (x)
#define ATCA_UINT32_HOST_TO_BE(x)  __REV(x)
#define ATCA_UINT32_BE_TO_HOST(x)  __REV(x)
#define ATCA_UINT64_HOST_TO_BE(x)  (((uint64_t)__REV((uint32_t)x) << 32) | (uint64_t)__REV((uint32_t)(x >> 32)))
#define ATCA_UINT64_BE_TO_HOST(x)  (((uint64_t)__REV((uint32_t)x) << 32) | (uint64_t)__REV((uint32_t)(x >> 32)))
#define ATCA_UINT64_HOST_TO_LE(x)  (x)
#endif

#define SHARED_LIB_EXPORT
#define SHARED_LIB_IMPORT       extern

#endif

#if defined(_MSC_VER) && (_MSC_VER <= 1700)
// VS2012 and earlier don't support stdbool.h
#ifndef __cplusplus
/* coverity[misra_c_2012_rule_21_1_violation:SUPPRESS] */
#define bool    unsigned char
/* coverity[misra_c_2012_rule_21_1_violation:SUPPRESS] */
#define false   0
/* coverity[misra_c_2012_rule_21_1_violation:SUPPRESS] */
#define true    1
#endif
#else
#include <stdbool.h>
#endif

#ifdef ATCA_BUILD_SHARED_LIBS
#if defined(cryptoauth_EXPORTS) && defined(_WIN32)
#define ATCA_DLL    extern SHARED_LIB_EXPORT
#else
#define ATCA_DLL    SHARED_LIB_IMPORT
#endif
#else
#undef SHARED_LIB_EXPORT
#define SHARED_LIB_EXPORT
#define ATCA_DLL    extern
#endif

#ifndef ATCA_NO_PRAGMA_PACK
#define ATCA_PACKED
#else
#define ATCA_PACKED     __attribute__ ((packed))
#endif

/** \def UNUSED_VAR
 * Enables removal of compiler warning due to unused variables
 */
#ifdef ATCA_UNUSED_VAR_CHECK
#define UNUSED_VAR(x)  ((void)(x))
#else
#define UNUSED_VAR(x)
#endif

#endif /* ATCA_COMPILER_H_ */
