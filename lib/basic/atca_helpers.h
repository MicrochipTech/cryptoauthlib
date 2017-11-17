/**
 * \file
 * \brief Helpers to support the CryptoAuthLib Basic API methods
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */

#ifndef ATCA_HELPERS_H_
#define ATCA_HELPERS_H_

#include "cryptoauthlib.h"

/** \defgroup atcab_ Basic Crypto API methods (atcab_)
 *
 * \brief
 * These methods provide the most convenient, simple API to CryptoAuth chips
 *
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

ATCA_STATUS atcab_printbin(uint8_t* binary, int bin_len, bool add_space);
ATCA_STATUS atcab_bin2hex(const uint8_t* binary, int bin_len, char* ascii_hex, int* ascii_hex_len);
ATCA_STATUS atcab_bin2hex_(const uint8_t* binary, int bin_len, char* ascii_hex, int* ascii_hex_len, bool add_space);
ATCA_STATUS atcab_hex2bin(const char* ascii_hex, int ascii_hex_len, uint8_t* binary, int* bin_len);
ATCA_STATUS atcab_printbin_sp(uint8_t* binary, int bin_len);
ATCA_STATUS atcab_printbin_label(const char* label, uint8_t* binary, int bin_len);


ATCA_STATUS packHex(const char* ascii_hex, int ascii_hex_len, char* packed_hex, int* packed_len);
bool isDigit(char c);
bool isWhiteSpace(char c);
bool isAlpha(char c);
bool isHexAlpha(char c);
bool isHex(char c);
bool isHexDigit(char c);

ATCA_STATUS packBase64(const char* ascii_base64, int ascii_base64_len, char* packed_base64, int* packed_len, const uint8_t * rules);
bool isBase64(char c, const uint8_t * rules);
bool isBase64Digit(char c, const uint8_t * rules);
char base64Index(char c, const uint8_t * rules);
char base64Char(char id, const uint8_t * rules);

extern uint8_t atcab_b64rules_default[4];
extern uint8_t atcab_b64rules_mime[4];
extern uint8_t atcab_b64rules_urlsafe[4];

ATCA_STATUS atcab_base64decode_(const char* encoded, size_t encoded_len, uint8_t* byte_array, size_t* array_len, const uint8_t * rules);
ATCA_STATUS atcab_base64decode(const char* encoded, size_t encoded_len, uint8_t* byte_array, size_t* array_len);

ATCA_STATUS atcab_base64encode_(const uint8_t* byte_array, size_t array_len, char* encoded, size_t* encoded_len, const uint8_t * rules);
ATCA_STATUS atcab_base64encode(const uint8_t* byte_array, size_t array_len, char* encoded, size_t* encoded_len);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* ATCA_HELPERS_H_ */
