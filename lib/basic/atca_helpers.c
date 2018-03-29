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

#include "cryptoauthlib.h"
#include "atca_helpers.h"
#include <stdlib.h>
#include <stdio.h>

#ifdef ATCAPRINTF

/* Ruleset:
    Index   -   Meaning
    0       -   62 Character
    1       -   63 Character
    2       -   Pad Character (none if 0)
    3       -   Maximum line length (no limit if 0) */
uint8_t atcab_b64rules_default[4]   = { '+', '/', '=', 64 };
uint8_t atcab_b64rules_mime[4]      = { '+', '/', '=', 76 };
uint8_t atcab_b64rules_urlsafe[4]   = { '-', '_', 0, 0 };


/** \brief Function that convert a binary buffer to a hex string suitable for human reading
 *  \param[in]  binary input buffer to convert
 *  \param[in]  bin_len length of buffer to convert
 *  \param[out] ascii_hex buffer that receives hex string
 *  \param[out] ascii_hex_len the length of the ascii_hex buffer
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_bin2hex(const uint8_t* binary, int bin_len, char* ascii_hex, int* ascii_hex_len)
{
    return atcab_bin2hex_(binary, bin_len, ascii_hex, ascii_hex_len, true);
}

/** \brief Function that converts a binary buffer to a hex string suitable for human reading
 *  \param[in]      inbuff input buffer to convert
 *  \param[in]      inbuffLen length of buffer to convert
 *  \param[out]     ascii_hex buffer that receives hex string
 *  \param[inout]     ascii_hex_len the length of the ascii_hex buffer
 *  \param[inout]     add_space indicates whether spaces and returns should be added for pretty printing
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_bin2hex_(const uint8_t* binary, int bin_len, char* ascii_hex, int* ascii_hex_len, bool add_space)
{
    int i;
    int hex_len = 0;

    // Verify the inputs
    if ((binary == NULL) || (ascii_hex == NULL) || (ascii_hex_len == NULL))
    {
        return ATCA_BAD_PARAM;
    }

    // Initialize the return bytes to all 0s
    memset(ascii_hex, 0, *ascii_hex_len);

    // Convert one byte at a time
    for (i = 0; i < bin_len; i++)
    {
        if (hex_len > *ascii_hex_len)
        {
            break;
        }
        if ((i % 16 == 0 && i != 0) && add_space)
        {
            sprintf(&ascii_hex[hex_len], "\r\n");
            hex_len += 2;
        }
        if (add_space)
        {
            sprintf(&ascii_hex[hex_len], "%02X ", *binary++);
            hex_len += 3;
        }
        else
        {
            sprintf(&ascii_hex[hex_len], "%02X", *binary++);
            hex_len += 2;
        }
    }
    *ascii_hex_len = (int)strlen(ascii_hex);

    return ATCA_SUCCESS;
}

/** \brief Function that converts a hex string to binary buffer
 *  \param[in]  ascii_hex    input buffer to convert
 *  \param[in]  ascii_hex_len length of buffer to convert
 *  \param[out] binary      buffer that receives binary
 *  \param[in]  bin_len      Hex length of binary buffer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_hex2bin(const char* ascii_hex, int ascii_hex_len, uint8_t* binary, int* bin_len)
{
    int i = 0;
    int j = 0;
    uint32_t byt;
    char* packed_hex = NULL;
    int packed_len = ascii_hex_len;
    char hex_byte[3];

    // Verify the inputs
    if ((binary == NULL) || (ascii_hex == NULL) || (bin_len == NULL))
    {
        return ATCA_BAD_PARAM;
    }

    // Pack the bytes (remove white space & make even number of characters)
    packed_hex = (char*)malloc(packed_len);
    memset(packed_hex, 0, packed_len);
    packHex(ascii_hex, ascii_hex_len, packed_hex, &packed_len);

    // Initialize the binary buffer to all 0s
    memset(binary, 0, *bin_len);
    memset(hex_byte, 0, 3);

    // Convert the ascii bytes to binary
    for (i = 0, j = 0; i < packed_len; i += 2, j++)
    {
        if (i > packed_len || j > *bin_len)
        {
            break;
        }
        // Copy two characters to be scanned
        memcpy(hex_byte, &packed_hex[i], 2);
        sscanf(hex_byte, "%x", (unsigned int*)&byt);
        // take the msb of the uint32_t
        binary[j] = byt;
    }
    *bin_len = j;
    free(packed_hex);
    return ATCA_SUCCESS;
}

//#else


#endif

/**
 * \brief Checks to see if a character is an ASCII representation of a digit ((c ge '0') and (c le '9'))
 * \param[in] c  character to check
 * \return True if the character is a digit
 */
bool isDigit(char c)
{
    return (c >= '0') && (c <= '9');
}

/**
 * \brief Checks to see if a character is whitespace
 * \param[in] c  character to check
 * \return True if the character is whitespace
 */
bool isWhiteSpace(char c)
{
    return (c == '\n') || (c == '\r') || (c == '\t') || (c == ' ');
}

/**
 * \brief Checks to see if a character is an ASCII representation of hex ((c >= 'A') and (c <= 'F')) || ((c >= 'a') and (c <= 'f'))
 * \param[in] c  character to check
 * \return True if the character is a hex
 */
bool isAlpha(char c)
{
    return ((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z'));
}

/**
 * \brief Checks to see if a character is an ASCII representation of hex ((c >= 'A') and (c <= 'F')) || ((c >= 'a') and (c <= 'f'))
 * \param[in] c  character to check
 * \return True if the character is a hex
 */
bool isHexAlpha(char c)
{
    return ((c >= 'A') && (c <= 'F')) || ((c >= 'a') && (c <= 'f'));
}

/**
 * \brief Returns true if this character is a valid hex character or if this is whitespace (The character can be
 *        included in a valid hexstring).
 * \param[in] c  character to check
 * \return True if the character can be included in a valid hexstring
 */
bool isHex(char c)
{
    return isHexDigit(c) || isWhiteSpace(c);
}

/**
 * \brief Returns true if this character is a valid hex character.
 * \param[in] c  character to check
 * \return True if the character can be included in a valid hexstring
 */
bool isHexDigit(char c)
{
    return isDigit(c) || isHexAlpha(c);
}

/**
 * \brief Remove white space from a ASCII hex string.
 * \param[in] ascii_hex		Initial hex string to remove white space from
 * \param[in] ascii_hex_len	Length of the initial hex string
 * \param[in] packed_hex		Resulting hex string without white space
 * \param[inout] packed_len	In: Size to packed_hex buffer
 *							Out: Number of bytes in the packed hex string
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS packHex(const char* ascii_hex, int ascii_hex_len, char* packed_hex, int* packed_len)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    int i = 0;
    int j = 0;

    do
    {
        // Verify the inputs
        if ((ascii_hex == NULL) || (packed_hex == NULL) || (packed_len == NULL))
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Null input parameter");
        }
        // Loop through each character and only add the hex characters
        for (i = 0; i < ascii_hex_len; i++)
        {
            if (isHexDigit(ascii_hex[i]))
            {
                if (j > *packed_len)
                {
                    break;
                }
                packed_hex[j++] = ascii_hex[i];
            }
        }
        *packed_len = j;
    }
    while (false);
    // TODO: If there are not an even number of characters, then pad with a '0'

    return ATCA_SUCCESS;
}

/** \brief Print each hex character in the binary buffer with spaces between bytes
 *  \param[in] label label to print
 *  \param[in] binary input buffer to print
 *  \param[in] bin_len length of buffer to print
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_printbin_label(const char* label, uint8_t* binary, int bin_len)
{
    printf("%s", label);
    return atcab_printbin(binary, bin_len, true);
}

/** \brief Print each hex character in the binary buffer with spaces between bytes
 *  \param[in] binary input buffer to print
 *  \param[in] bin_len length of buffer to print
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_printbin_sp(uint8_t* binary, int bin_len)
{
    return atcab_printbin(binary, bin_len, true);
}

/** \brief Print each hex character in the binary buffer
 *  \param[in] binary input buffer to print
 *  \param[in] bin_len length of buffer to print
 *  \param[in] add_space indicates whether spaces and returns should be added for pretty printing
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_printbin(uint8_t* binary, int bin_len, bool add_space)
{
    int i = 0;
    int line_len = 16;

    // Verify the inputs
    if ((binary == NULL))
    {
        return ATCA_BAD_PARAM;
    }

    // Set the line length
    line_len = add_space ? 16 : 32;

    // Print the bytes
    for (i = 0; i < bin_len; i++)
    {
        // Print the byte
        if (add_space)
        {
            printf("%02X ", binary[i]);
        }
        else
        {
            printf("%02X", binary[i]);
        }

        // Break at the line_len
        if ((i + 1) % line_len == 0)
        {
            printf("\r\n");
        }
    }
    // Print the last carriage return
    printf("\r\n");

    return ATCA_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Base 64 Encode/Decode

#define IS_EQUAL    (char)64
#define IS_INVALID  (char)0xFF

/**
 * \brief Returns true if this character is a valid base 64 character or if this is whitespace (A character can be
 *        included in a valid base 64 string).
 * \param[in] c      character to check
 * \param[in] rules  base64 ruleset to use
 * \return True if the character can be included in a valid base 64 string
 */
bool isBase64(char c, const uint8_t * rules)
{
    return isBase64Digit(c, rules) || isWhiteSpace(c);
}

/**
 * \brief Returns true if this character is a valid base 64 character.
 * \param[in] c      character to check
 * \param[in] rules  base64 ruleset to use
 * \return True if the character can be included in a valid base 64 string
 */
bool isBase64Digit(char c, const uint8_t * rules)
{
    return isDigit(c) || isAlpha(c) || c == rules[0] || c == rules[1] || c == rules[2];
}

/**
 * \brief Remove white space from a base 64 string.
 * \param[in] ascii_base64	Initial base 64 string to remove white space from
 * \param[in] ascii_base64_len	Length of the initial base 64 string
 * \param[in] packed_base64	Resulting base 64 string without white space
 * \param[inout] packed_len	In: Size to packedHex buffer
 *							Out: Number of bytes in the packed base 64 string
 * \param[in] rules  base64 ruleset to use
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS packBase64(const char* ascii_base64, int ascii_base64_len, char* packed_base64, int* packed_len, const uint8_t * rules)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    int i = 0;
    int j = 0;

    do
    {
        // Verify the inputs
        if ((ascii_base64 == NULL) || (packed_base64 == NULL) || (packed_len == NULL))
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Null input parameter");
        }
        // Loop through each character and only add the base 64 characters
        for (i = 0; i < ascii_base64_len; i++)
        {
            if (isBase64Digit(ascii_base64[i], rules))
            {
                if (j > *packed_len)
                {
                    break;
                }
                packed_base64[j++] = ascii_base64[i];
            }
        }
        for (; !rules[2] && j % 4; j++)
        {
            packed_base64[j] = 0;
        }

        *packed_len = j;
    }
    while (false);

    return status;
}

/**
 * \brief Returns the base 64 index of the given character.
 * \param[in] c      character to check
 * \param[in] rules  base64 ruleset to use
 * \return the base 64 index of the given character
 */
char base64Index(char c, const uint8_t * rules)
{
    if ((c >= 'A') && (c <= 'Z'))
    {
        return (char)(c - 'A');
    }
    if ((c >= 'a') && (c <= 'z'))
    {
        return (char)(26 + c - 'a');
    }
    if ((c >= '0') && (c <= '9'))
    {
        return (char)(52 + c - '0');
    }
    if (c == rules[0])
    {
        return (char)62;
    }
    if (c == rules[1])
    {
        return (char)63;
    }

    if (c == rules[2])
    {
        return IS_EQUAL;
    }
    return IS_INVALID;
}

#define B64_IS_EQUAL   (char)64
#define B64_IS_INVALID (char)0xFF

/**
 * \brief Returns the base 64 character of the given index.
 * \param[in] id     index to check
 * \param[in] rules  base64 ruleset to use
 * \return the base 64 character of the given index
 */
char base64Char(char id, const uint8_t * rules)
{
    if (id >= 0 && (id < 26))
    {
        return (char)('A' + id);
    }
    if ((id >= 26) && (id < 52))
    {
        return (char)('a' + id - 26);
    }
    if ((id >= 52) && (id < 62))
    {
        return (char)('0' + id - 52);
    }
    if (id == 62)
    {
        return rules[0];
    }
    if (id == 63)
    {
        return rules[1];
    }

    if (id == B64_IS_EQUAL)
    {
        return rules[2];
    }
    return B64_IS_INVALID;
}

/**
 * \brief Decode base64 string to data with ruleset option.
 *
 * \param[in]    encoded      Base64 string to be decoded.
 * \param[in]    encoded_len  Size of the base64 string in bytes.
 * \param[out]   byte_array   Decoded data will be returned here.
 * \param[inout] array_len    As input, the size of the byte_array buffer.
 *                            As output, the length of the decoded data.
 * \param[in]    rules        base64 ruleset to use
 */
ATCA_STATUS atcab_base64decode_(const char* encoded, size_t encoded_len, uint8_t* byte_array, size_t* array_len, const uint8_t * rules)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    int id[4];
    int i = 0;
    int j = 0;
    char* packed_base64 = NULL;
    /* Calculate the packet length round up to the next four byte boundary */
    int packed_len = encoded_len + (encoded_len % 4);

    // Set the output length.
    size_t out_len = (encoded_len * 3) / 4;

    // Allocate the memory for the packed base 64 buffer
    packed_base64 = (char*)malloc(packed_len);
    memset(packed_base64, 0, packed_len);

    do
    {
        // Check the input parameters
        if (encoded == NULL || byte_array == NULL || array_len == NULL || !rules)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Null input parameter");
        }
        // Pack the encoded characters (remove the white space from the encoded characters)
        packBase64(encoded, encoded_len, packed_base64, &packed_len, rules);

        // Packed length must be divisible by 4
        if (packed_len % 4 != 0)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Invalid base64 input");
        }
        if (*array_len < out_len)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Length of decoded buffer too small");
        }
        // Initialize the return length to 0
        *array_len = 0;

        // Take the encoded bytes in groups of 4 and decode them into 3 bytes
        for (i = 0; i < packed_len; i += 4)
        {
            id[0] = base64Index(packed_base64[i], rules);
            id[1] = base64Index(packed_base64[i + 1], rules);
            id[2] = base64Index(packed_base64[i + 2], rules);
            id[3] = base64Index(packed_base64[i + 3], rules);
            byte_array[j++] = (uint8_t)((id[0] << 2) | (id[1] >> 4));
            if (id[2] < 64)
            {
                byte_array[j++] = (uint8_t)((id[1] << 4) | (id[2] >> 2));
                if (id[3] < 64)
                {
                    byte_array[j++] = (uint8_t)((id[2] << 6) | id[3]);
                }
            }
        }
        *array_len = j;
    }
    while (false);

    // Deallocate the packed buffer
    free(packed_base64);
    return status;
}

/** \brief Encode data as base64 string with ruleset option. */
ATCA_STATUS atcab_base64encode_(
    const uint8_t*  byte_array,  /**< [in] The input byte array that will be converted to base 64 encoded characters */
    size_t          array_len,   /**< [in] The length of the byte array */
    char*           encoded,     /**< [in] The output converted to base 64 encoded characters. */
    size_t*         encoded_len, /**< [inout] Input: The size of the encoded buffer, Output: The length of the encoded base 64 character string */
    const uint8_t * rules        /**< [in] ruleset to use during encoding */
    )
{
    ATCA_STATUS status = ATCA_SUCCESS;
    size_t i = 0;
    size_t j = 0;
    size_t offset = 0;
    int id = 0;
    size_t out_len;

    size_t r3 = (array_len % 3);
    size_t b64_len = ((array_len * 4) / 3) + r3;

    do
    {
        // Check the input parameters
        if (encoded == NULL || byte_array == NULL || encoded_len == NULL || !rules)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Null input parameter");
        }

        // Set the output length.  Add the \r\n every n characters
        out_len = b64_len;
        if (rules[3])
        {
            out_len += (b64_len / rules[3]) * 2;
        }

        if (*encoded_len < out_len)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Length of encoded buffer too small");
        }
        // Initialize the return length to 0
        *encoded_len = 0;

        // Loop through the byte array by 3 then map to 4 base 64 encoded characters
        for (i = 0; i < array_len; i += 3)
        {
            id = (byte_array[i] & 0xFC) >> 2;
            encoded[j++] = base64Char(id, rules);
            id = (byte_array[i] & 0x03) << 4;
            if (i + 1 < array_len)
            {
                id |= (byte_array[i + 1] & 0xF0) >> 4;
                encoded[j++] = base64Char(id, rules);
                id = (byte_array[i + 1] & 0x0F) << 2;
                if (i + 2 < array_len)
                {
                    id |= (byte_array[i + 2] & 0xC0) >> 6;
                    encoded[j++] = base64Char(id, rules);
                    id = byte_array[i + 2] & 0x3F;
                    encoded[j++] = base64Char(id, rules);
                }
                else
                {
                    encoded[j++] = base64Char(id, rules);
                    encoded[j++] = base64Char(IS_EQUAL, rules);
                }
            }
            else
            {
                encoded[j++] = base64Char(id, rules);
                encoded[j++] = base64Char(IS_EQUAL, rules);
                encoded[j++] = base64Char(IS_EQUAL, rules);
            }
            // Add \r\n every n bytes if specified
            if (rules[3] && ((j - offset) % rules[3] == 0) && encoded[j - 1])
            {
                // as soon as we do this, we introduce an offset
                encoded[j++] = '\r';
                encoded[j++] = '\n';
                offset += 2;
            }
        }

        /* Check if there is padding to be stripped from the end*/
        for (j -= 1; j; j--)
        {
            if (encoded[j])
            {
                if ('\r' != encoded[j] && '\n' != encoded[j])
                {
                    break;
                }
            }
        }
        /* Make sure the result is terminated */
        encoded[++j] = 0;

        // Set the final encoded length
        *encoded_len = j;
    }
    while (false);
    return status;
}


/**
 * \brief Encode data as base64 string
 *
 * \param[in]    byte_array   Data to be encode in base64.
 * \param[in]    array_len    Size of byte_array in bytes.
 * \param[in]    encoded      Base64 output is returned here.
 * \param[inout] encoded_len  As input, the size of the encoded buffer.
 *                            As output, the length of the encoded base64
 *                            character string.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_base64encode(const uint8_t* byte_array, size_t array_len, char* encoded, size_t* encoded_len)
{
    return atcab_base64encode_(byte_array, array_len, encoded, encoded_len, atcab_b64rules_default);
}

/**
 * \brief Decode base64 string to data
 *
 * \param[in]    encoded     Base64 string to be decoded.
 * \param[in]    encoded_len  Size of the base64 string in bytes.
 * \param[out]   byte_array   Decoded data will be returned here.
 * \param[inout] array_len    As input, the size of the byte_array buffer.
 *                            As output, the length of the decoded data.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_base64decode(const char* encoded, size_t encoded_len, uint8_t* byte_array, size_t* array_len)
{
    return atcab_base64decode_(encoded, encoded_len, byte_array, array_len, atcab_b64rules_default);
}


