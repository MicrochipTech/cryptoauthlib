/**
 * \file
 * \brief Microchip CryptoAuthentication device command builder - this is the main object that builds the command
 * byte strings for the given device.  It does not execute the command.  The basic flow is to call
 * a command method to build the command you want given the parameters and then send that byte string
 * through the device interface.
 *
 * The primary goal of the command builder is to wrap the given parameters with the correct packet size and CRC.
 * The caller should first fill in the parameters required in the ATCAPacket parameter given to the command.
 * The command builder will deal with the mechanics of creating a valid packet using the parameter information.
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

#include "cryptoauthlib.h"

#if CALIB_CHECKMAC_EN
/** \brief ATCACommand CheckMAC method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atCheckMAC(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_CHECKMAC;
    packet->txsize = CHECKMAC_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_COUNTER_EN
/** \brief ATCACommand Counter method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atCounter(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_COUNTER;
    packet->txsize = COUNTER_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_DELETE_EN
/** \brief ATCACommand Delete method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atDelete(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_DELETE;
    packet->txsize = DELETE_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_DERIVEKEY_EN
/** \brief ATCACommand DeriveKey method
 * \param[in] ca_cmd   instance
 * \param[in] packet   pointer to the packet containing the command being built
 * \param[in] has_mac  hasMAC determines if MAC data is present in the packet input
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atDeriveKey(ATCADeviceType device_type, ATCAPacket *packet, bool has_mac)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_DERIVE_KEY;

    // hasMAC must be given since the packet does not have any implicit information to
    // know if it has a mac or not unless the size is preset
    if (has_mac)
    {
        packet->txsize = DERIVE_KEY_COUNT_LARGE;
    }
    else
    {
        packet->txsize = DERIVE_KEY_COUNT_SMALL;
    }
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_ECDH_EN
/** \brief ATCACommand ECDH method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atECDH(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_ECDH;
    packet->txsize = ECDH_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_GENDIG_EN
/** \brief ATCACommand Generate Digest method
 * \param[in] ca_cmd         instance
 * \param[in] packet         pointer to the packet containing the command being built
 * \param[in] is_no_mac_key  Should be true if GenDig is being run on a slot that has its SlotConfig.NoMac bit set
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atGenDig(ATCADeviceType device_type, ATCAPacket *packet, bool is_no_mac_key)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_GENDIG;

    if (packet->param1 == GENDIG_ZONE_SHARED_NONCE) // shared nonce mode
    {
        packet->txsize = GENDIG_COUNT + 32u;
    }
    else if (is_no_mac_key)
    {
        packet->txsize = GENDIG_COUNT + 4u;  // noMac keys use 4 bytes of OtherData in calculation
    }
    else
    {
        packet->txsize = GENDIG_COUNT;
    }
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_GENKEY_EN
/** \brief ATCACommand Generate Key method
 * \param[in] ca_cmd     instance
 * \param[in] packet    pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atGenKey(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_GENKEY;

    if ((packet->param1 & GENKEY_MODE_PUBKEY_DIGEST) == GENKEY_MODE_PUBKEY_DIGEST)
    {
        packet->txsize = GENKEY_COUNT_DATA;
    }
    else
    {
        packet->txsize = GENKEY_COUNT;
    }
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_HMAC_EN
/** \brief ATCACommand HMAC method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atHMAC(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_HMAC;
    packet->txsize = HMAC_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

/** \brief ATCACommand Info method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atInfo(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_INFO;
    packet->txsize = INFO_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}

#if CALIB_LOCK_EN || CALIB_LOCK_CA2_EN
/** \brief ATCACommand Lock method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atLock(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_LOCK;
    packet->txsize = LOCK_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_MAC_EN
/** \brief ATCACommand MAC method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atMAC(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    // variable packet size
    packet->opcode = ATCA_MAC;
    if ((packet->param1 & MAC_MODE_BLOCK2_TEMPKEY) == 0u)
    {
        packet->txsize = MAC_COUNT_LONG;
    }
    else
    {
        packet->txsize = MAC_COUNT_SHORT;
    }
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_NONCE_EN
/** \brief ATCACommand Nonce method
 * \param[in] ca_cmd   instance
 * \param[in] packet   pointer to the packet containing the command being built
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atNonce(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    // variable packet size
    uint8_t calc_mode = packet->param1 & NONCE_MODE_MASK;

    packet->opcode = ATCA_NONCE;

    if ((calc_mode == NONCE_MODE_SEED_UPDATE || calc_mode == NONCE_MODE_NO_SEED_UPDATE || calc_mode == NONCE_MODE_GEN_SESSION_KEY))
    {
        // Calculated nonce mode, 20 byte NumInm
        packet->txsize = NONCE_COUNT_SHORT;
    }
    else if (calc_mode == NONCE_MODE_PASSTHROUGH)
    {
        // PAss-through nonce mode
        if ((packet->param1 & NONCE_MODE_INPUT_LEN_MASK) == NONCE_MODE_INPUT_LEN_64)
        {
            // 64 byte NumIn
            packet->txsize = NONCE_COUNT_LONG_64;
        }
        else
        {
            // 32 byte NumIn
            packet->txsize = NONCE_COUNT_LONG;
        }
    }
    else
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "atNonce - failed; Invalid mode received");
    }
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

/** \brief ATCACommand Pause method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atPause(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_PAUSE;
    packet->txsize = PAUSE_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}

#if CALIB_PRIVWRITE_EN
/** \brief ATCACommand PrivWrite method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atPrivWrite(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_PRIVWRITE;
    packet->txsize = PRIVWRITE_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_RANDOM_EN
/** \brief ATCACommand Random method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atRandom(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_RANDOM;
    packet->txsize = RANDOM_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_READ_EN || CALIB_READ_CA2_EN
/** \brief ATCACommand Read method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atRead(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_READ;
    packet->txsize = READ_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_SECUREBOOT_EN
/** \brief ATCACommand SecureBoot method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atSecureBoot(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    ATCA_STATUS status = ATCA_SUCCESS;
    packet->opcode = ATCA_SECUREBOOT;
    packet->txsize = ATCA_CMD_SIZE_MIN;

    //variable transmit size based on mode encoding
    switch (packet->param1 & SECUREBOOT_MODE_MASK)
    {
    case SECUREBOOT_MODE_FULL:
    case SECUREBOOT_MODE_FULL_COPY:
        packet->txsize += (SECUREBOOT_DIGEST_SIZE + SECUREBOOT_SIGNATURE_SIZE);
        break;

    case SECUREBOOT_MODE_FULL_STORE:
        packet->txsize += SECUREBOOT_DIGEST_SIZE;
        break;

    default:
        status = ATCA_BAD_PARAM;
        break;
    }

    if (ATCA_SUCCESS == status)
    {
        atCalcCrc(packet);
    }

    return status;
}
#endif

#if CALIB_SHA_EN
/** \brief ATCACommand SHA method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \param[in] write_context_size  the length of the sha write_context data
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atSHA(ATCADeviceType device_type, ATCAPacket *packet, uint16_t write_context_size)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_SHA;

    switch (packet->param1 & SHA_MODE_MASK)
    {
    case SHA_MODE_SHA256_START:     // START
    case SHA_MODE_HMAC_START:
    case 0x03:                      // SHA_MODE_SHA256_PUBLIC || SHA_MODE_ECC204_HMAC_START
        packet->txsize = ATCA_CMD_SIZE_MIN;
        break;

    case SHA_MODE_SHA256_UPDATE:                                           // UPDATE
        packet->txsize = (uint8_t)((ATCA_CMD_SIZE_MIN + packet->param2) & UINT8_MAX);
        break;

    case SHA_MODE_SHA256_END:     // END
    case SHA_MODE_HMAC_END:
        // check the given packet for a size variable in param2.  If it is > 0, it should
        // be 0-63, incorporate that size into the packet
        packet->txsize = (uint8_t)((ATCA_CMD_SIZE_MIN + packet->param2) & UINT8_MAX);
        break;

    case SHA_MODE_WRITE_CONTEXT:
        packet->txsize = (uint8_t)((ATCA_CMD_SIZE_MIN + write_context_size) & UINT8_MAX);
        break;

    default:
        packet->txsize = ATCA_CMD_SIZE_MIN;
        break;
    }

    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_SIGN_EN || CALIB_SIGN_CA2_EN
/** \brief ATCACommand Sign method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atSign(ATCADeviceType device_type, ATCAPacket *packet)
{
    // Set the opcode & parameters
    packet->opcode = ATCA_SIGN;
    packet->txsize = SIGN_COUNT;
    if ((ECC204 == device_type) || (TA010 == device_type))
    {
        packet->txsize += ATCA_SHA_DIGEST_SIZE;
    }
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_UPDATEEXTRA_EN
/** \brief ATCACommand UpdateExtra method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atUpdateExtra(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_UPDATE_EXTRA;
    packet->txsize = UPDATE_COUNT;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_VERIFY_EN
/** \brief ATCACommand ECDSA Verify method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atVerify(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    ATCA_STATUS status = ATCA_SUCCESS;

    // Set the opcode & parameters
    packet->opcode = ATCA_VERIFY;

    // variable packet size based on mode
    switch (packet->param1 & VERIFY_MODE_MASK)
    {
    case VERIFY_MODE_STORED:
        packet->txsize = VERIFY_256_STORED_COUNT;
        break;

    case VERIFY_MODE_VALIDATE_EXTERNAL:
        packet->txsize = VERIFY_256_EXTERNAL_COUNT;
        break;

    case VERIFY_MODE_EXTERNAL:
        packet->txsize = VERIFY_256_EXTERNAL_COUNT;
        break;

    case VERIFY_MODE_VALIDATE:
    case VERIFY_MODE_INVALIDATE:
        packet->txsize = VERIFY_256_VALIDATE_COUNT;
        break;

    default:
        status = ATCA_BAD_PARAM;
        break;
    }

    if (ATCA_SUCCESS == status)
    {
        atCalcCrc(packet);
    }

    return status;
}
#endif

#if CALIB_WRITE_EN || CALIB_WRITE_CA2_EN
/** \brief ATCACommand Write method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \param[in] has_mac  Flag to indicate whether a mac is present or not
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atWrite(ATCADeviceType device_type, ATCAPacket *packet, bool has_mac)
{
    // Set the opcode & parameters
    packet->opcode = ATCA_WRITE;

    packet->txsize = 7;
    if (atcab_is_ca2_device(device_type))
    {
#if ATCA_CA2_SUPPORT
        if (ATCA_ZONE_CA2_CONFIG == packet->param1)
        {
            packet->txsize += 16u;
        }
        else if (ATCA_ZONE_CA2_DATA == packet->param1)
        {
            packet->txsize += ATCA_BLOCK_SIZE;
        }
        else
        {
            return ATCA_BAD_PARAM;
        }
#else
        return ATCA_UNIMPLEMENTED;
#endif
    }
    else
    {
        if ((packet->param1 & ATCA_ZONE_READWRITE_32) == ATCA_ZONE_READWRITE_32)
        {
            packet->txsize += ATCA_BLOCK_SIZE;
        }
        else
        {
            packet->txsize += ATCA_WORD_SIZE;
        }
    }

    if (has_mac)
    {
        packet->txsize += WRITE_MAC_SIZE;
    }
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_AES_EN
/** \brief ATCACommand AES method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atAES(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_AES;
    packet->txsize = ATCA_CMD_SIZE_MIN;

    if ((packet->param1 & AES_MODE_OP_MASK) == AES_MODE_GFM)
    {
        packet->txsize += ATCA_AES_GFM_SIZE;
    }
    else
    {
        packet->txsize += AES_DATA_SIZE;
    }
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_SELFTEST_EN
/** \brief ATCACommand AES method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atSelfTest(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_SELFTEST;
    packet->txsize = ATCA_CMD_SIZE_MIN;
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

#if CALIB_KDF_EN
/** \brief ATCACommand KDF method
 * \param[in]  ca_cmd  Instance
 * \param[in]  packet  Pointer to the packet containing the command being
 *                     built.
 * \return ATCA_SUCCESS
 */
ATCA_STATUS atKDF(ATCADeviceType device_type, ATCAPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = ATCA_KDF;

    // Set TX size
    if ((packet->param1 & KDF_MODE_ALG_MASK) == KDF_MODE_ALG_AES)
    {
        // AES algorithm has a fixed message size
        packet->txsize = ATCA_CMD_SIZE_MIN + KDF_DETAILS_SIZE + AES_DATA_SIZE;
    }
    else
    {
        // All other algorithms encode message size in the last byte of details
        packet->txsize = (ATCA_CMD_SIZE_MIN + KDF_DETAILS_SIZE + packet->data[3]) & UINT8_MAX;
    }
    atCalcCrc(packet);
    return ATCA_SUCCESS;
}
#endif

/** \brief Calculates CRC over the given raw data and returns the CRC in
 *         little-endian byte order.
 *
 * \param[in]  length  Size of data not including the CRC byte positions
 * \param[in]  data    Pointer to the data over which to compute the CRC
 * \param[out] crc_le  Pointer to the place where the two-bytes of CRC will be
 *                     returned in little-endian byte order.
 */
void atCRC(size_t length, const uint8_t *data, uint8_t *crc_le)
{
    size_t counter;
    uint16_t crc_register = 0;
    uint16_t polynom = 0x8005;
    uint8_t shift_register;
    uint8_t data_bit, crc_bit;

    for (counter = 0; counter < length; counter++)
    {
        for (shift_register = 0x01; shift_register > 0x00u; shift_register <<= 1)
        {
            data_bit = ((data[counter] & shift_register) != 0u) ? 1u : 0u;
            crc_bit = (uint8_t)(crc_register >> 15);
            crc_register <<= 1;
            if (data_bit != crc_bit)
            {
                crc_register ^= polynom;
            }
        }
    }
    crc_le[0] = (uint8_t)(crc_register & 0x00FFu);
    crc_le[1] = (uint8_t)(crc_register >> 8u);
}


/** \brief This function calculates CRC and adds it to the correct offset in the packet data
 * \param[in] packet Packet to calculate CRC data for
 */

void atCalcCrc(ATCAPacket *packet)
{
    uint8_t length;
    uint8_t *crc;

    packet->param2 = ATCA_UINT16_HOST_TO_LE(packet->param2);

    /* coverity[cert_int31_c_violation] txsize is properly set so length will not underflow */
    length = (packet->txsize - (uint8_t)ATCA_CRC_SIZE) & UINT8_MAX;

    // calculate crc location
    crc = &packet->data[length - ((uint8_t)ATCA_CMD_SIZE_MIN - (uint8_t)ATCA_CRC_SIZE)];

    // stuff CRC into packet
    atCRC(length, &(packet->txsize), crc);
}


/** \brief This function checks the consistency of a response.
 * \param[in] response pointer to response
 * \return ATCA_SUCCESS on success, otherwise ATCA_RX_CRC_ERROR
 */

ATCA_STATUS atCheckCrc(const uint8_t *response)
{
    uint8_t crc[ATCA_CRC_SIZE];
    uint8_t count = response[ATCA_COUNT_IDX];

    count -= (uint8_t)ATCA_CRC_SIZE;
    atCRC(count, response, crc);

    return (crc[0] == response[count] && crc[1] == response[count + 1u]) ? ATCA_SUCCESS : ATCA_RX_CRC_ERROR;
}


/** \brief determines if a given device type is a SHA device or a superset of a SHA device
 * \param[in] device_type  Type of device to check for family type
 * \return boolean indicating whether the given device is a SHA family device.
 */

bool atIsSHAFamily(ATCADeviceType device_type)
{
    bool is_sha_family;

    switch (device_type)
    {
    case SHA104:
    /* fallthrough */
    case SHA105:
    /* fallthrough */
    case ATSHA204A:
    /* fallthrough */
    case ATSHA206A:
        is_sha_family = true;
        break;

    default:
        is_sha_family = false;
        break;
    }

    return is_sha_family;
}

/** \brief determines if a given device type is an ECC device or a superset of a ECC device
 * \param[in] device_type  Type of device to check for family type
 * \return boolean indicating whether the given device is an ECC family device.
 */
bool atIsECCFamily(ATCADeviceType device_type)
{
    bool is_ecc_family;

    switch (device_type)
    {
    case ATECC108A:
    /* fallthrough */
    case ATECC508A:
    /* fallthrough */
    case ATECC608:
    /* fallthrough */
    case ECC204:
    /* fallthrough */
    case TA010:
        is_ecc_family = true;
        break;
    default:
        is_ecc_family = false;
        break;
    }

    return is_ecc_family;
}

/** \brief checks for basic error frame in data
 * \param[in] data pointer to received data - expected to be in the form of a CA device response frame
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS isATCAError(uint8_t *data)
{
    ATCA_STATUS status;

    if (data[0] == 0x04u)        // error packets are always 4 bytes long
    {
        switch (data[1])
        {
        case 0x00: //No Error
            status = ATCA_SUCCESS;
            break;
        case 0x01: // checkmac or verify failed
            status = ATCA_CHECKMAC_VERIFY_FAILED;
            break;
        case 0x03: // command received byte length, opcode or parameter was illegal
            status = ATCA_PARSE_ERROR;
            break;
        case 0x05: // computation error during ECC processing causing invalid results
            status = ATCA_STATUS_ECC;
            break;
        case 0x07: // chip is in self test failure mode
            status = ATCA_STATUS_SELFTEST_ERROR;
            break;
        case 0x08: //random number generator health test error
            status = ATCA_HEALTH_TEST_ERROR;
            break;
        case 0x0f: // chip can't execute the command
            status = ATCA_EXECUTION_ERROR;
            break;
        case 0x11: // chip was successfully woken up
            status = ATCA_WAKE_SUCCESS;
            break;
        case 0xff: // bad crc found (command not properly received by device) or other comm error
            status = ATCA_STATUS_CRC;
            break;
        default:
            status = ATCA_GEN_FAIL;
            break;
        }
    }
    else
    {
        status = ATCA_SUCCESS;
    }

    return status;
}
