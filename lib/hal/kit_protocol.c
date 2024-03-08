/**
 * \file
 *
 * \brief  Microchip Crypto Auth hardware interface object
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

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "atca_compiler.h"
#include "kit_protocol.h"
#include "atca_helpers.h"

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "MISRA C-2012 Rule 10.3" "Casting character constants to char type reduces readability") \
    (deviate "MISRA C-2012 Rule 10.4" "Casting character constants to char type reduces readability") \
    (deviate "MISRA C-2012 Rule 21.6" "Use is appropriate for this linux/windows only file")
#endif

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

/* Constants */
#define KIT_MAX_SCAN_COUNT      8
#define KIT_MAX_TX_BUF          32

#ifndef strnchr
// Local implementation of strnchr if it doesn't exist in the system
/* coverity[cert_dcl37_c_violation:SUPPRESS] */
static char * strnchr(const char * s, size_t count, int c)
{
    size_t i;

    for (i = 0; i < count; i++)
    {
        //coverity[cert_str34_c_violation:SUPPRESS] This is the standard c lib implementation used by systems that support it
        if (s[i] == c)
        {
            //coverity[cert_exp40_c_violation:SUPPRESS] Casting away const intentionally per API definition
            //coverity[misra_c_2012_rule_11_8_violation:SUPPRESS] Casting away const intentionally per API definition
            return (char*)&s[i];
        }
    }
    return NULL;
}
#endif

/** Kit Protocol is key */
const char * kit_id_from_devtype(ATCADeviceType devtype)
{
    const char* device_type;

    switch (devtype)
    {
    case ATSHA204A:
        device_type = "SHA204A";
        break;
    case ATECC108A:
        device_type = "ECC108A";
        break;
    case ATECC508A:
        device_type = "ECC508A";
        break;
    case ATECC608:
        device_type = "ECC608";
        break;
    case ATSHA206A:
        device_type = "SHA206A";
        break;
    case TA100:
        device_type = "TA100";
        break;
    case TA101:
        device_type = "TA101";
        break;
    case ECC204:
        device_type = "ECC204";
        break;
    case ECC206:
        device_type = "ECC206";
        break;
    case TA010:
        device_type = "TA010";
        break;
    case SHA104:
        device_type = "SHA104";
        break;
    case SHA105:
        device_type = "SHA105";
        break;
    case SHA106:
        device_type = "SHA106";
        break;
    case RNG90:
        device_type = "RNG90";
        break;
    default:
        device_type = "unknown";
        break;
    }

    return device_type;
}


/** Kit interface from device */
const char * kit_interface_from_kittype(ATCAKitType kittype)
{
    const char* interface_type;

    switch (kittype)
    {
    case ATCA_KIT_I2C_IFACE:
        interface_type = "TWI";
        break;
    case ATCA_KIT_SWI_IFACE:
        interface_type = "SWI";
        break;
    case ATCA_KIT_SPI_IFACE:
        interface_type = "SPI";
        break;
    default:
        interface_type = "unknown";
        break;
    }

    return interface_type;
}

/** Kit parser physical interface string */
const char* kit_interface(ATCAKitType kittype)
{
    const char* interface_type;

    switch (kittype)
    {
    case ATCA_KIT_I2C_IFACE:
        interface_type = "i2c";
        break;
    case ATCA_KIT_SWI_IFACE:
        interface_type = "swi";
        break;
    case ATCA_KIT_SPI_IFACE:
        interface_type = "spi";
        break;
    default:
        interface_type = "unknown";
        break;
    }

    return interface_type;
}

#if defined(ATCA_HAL_KIT_HID) || defined(ATCA_HAL_KIT_UART)

/** \brief HAL implementation of send over USB HID
 *  \param[in] iface     instance
 *  \param[in] txdata    pointer to bytes to send
 *  \param[in] txlength  number of bytes to send
 *  \return ATCA_STATUS
 */
ATCA_STATUS kit_phy_send(ATCAIface iface, uint8_t* txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bytes_left = 0;
    int bytes_to_send = 0;
    int packetsize = 0;
    uint8_t buffer[512]; //! Maximum number of bytes for a HID send/receive packet (typically 64)
    ATCA_STATUS status = ATCA_SUCCESS;

    if ((NULL == cfg) || (NULL == iface) || (NULL == iface->phy) ||
        (NULL == iface->phy->halsend) || (NULL == txdata))
    {
        return ATCA_BAD_PARAM;
    }

    if (ATCA_HID_IFACE == iface->mIfaceCFG->iface_type)
    {
#ifdef ATCA_HAL_KIT_HID
        /* coverity[cert_int31_c_violation] packetsize set in the config structure is assumed to be a sane value */
        packetsize = (int)ATCA_IFACECFG_VALUE(cfg, atcahid.packetsize);
#endif
    }
    else if (ATCA_UART_IFACE == iface->mIfaceCFG->iface_type)
    {
#ifdef ATCA_HAL_KIT_UART
        packetsize = 1;
#endif
    }
    else
    {
        return ATCA_BAD_PARAM;
    }

#ifdef KIT_DEBUG
    printf("Kit Send (%d): %s", txlength, txdata);
#endif

    bytes_left = txlength;
    while (bytes_left > 0)
    {
        (void)memset(buffer, 0, sizeof(buffer));

        if (bytes_left >= packetsize)
        {
            bytes_to_send = packetsize;
        }
        else
        {
            bytes_to_send = bytes_left;
        }

        if (ATCA_HID_IFACE == iface->mIfaceCFG->iface_type)
        {
#ifdef ATCA_HAL_KIT_HID
            /* coverity[cert_int32_c_violation:FALSE] */
            (void)memcpy(&buffer[1], &txdata[(txlength - bytes_left)], (size_t)bytes_to_send);
#endif
        }
        else if (ATCA_UART_IFACE == iface->mIfaceCFG->iface_type)
        {
#ifdef ATCA_HAL_KIT_UART
            /* coverity[cert_int32_c_violation:FALSE] */
            (void)memcpy(&buffer[0], &txdata[(txlength - bytes_left)], bytes_to_send);
#endif
        }
        else
        {
            return ATCA_BAD_PARAM;
        }


        if (ATCA_SUCCESS != (status = iface->phy->halsend(iface, 0xFF, buffer, packetsize)))
        {
            break;
        }

#ifdef ATCA_HAL_KIT_UART
        if (buffer[0] == '\n')   // sizeof will include \0 and count will increase
        {
            break;
        }
#endif

        bytes_left -= bytes_to_send;
    }

    return status;
}

/** \brief HAL implementation of kit protocol send over USB HID
 * \param[in]    iface   instance
 * \param[out]   rxdata  pointer to space to receive the data
 * \param[in,out] rxsize  ptr to expected number of receive bytes to request
 * \return ATCA_STATUS
 */
ATCA_STATUS kit_phy_receive(ATCAIface iface, uint8_t* rxdata, int* rxsize)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    size_t total_bytes_read = 0;
    size_t bytes_to_read = 0;
    char* location = NULL;
    uint16_t rxlen;

    if ((NULL == iface) || (NULL == iface->phy) || (NULL == iface->phy->halreceive) ||
        (NULL == rxdata) || (NULL == rxsize))
    {
        return status;
    }

    status = ATCA_SUCCESS;

#ifdef ATCA_HAL_KIT_UART
    if (ATCA_UART_IFACE == iface->mIfaceCFG->iface_type)
    {
        rxlen = 1;
        do
        {
            /* Clear out nulls if they are in the buffer */
            status = iface->phy->halreceive(iface, 0x00, rxdata, &rxlen);
        }
        while (ATCA_SUCCESS == status && *rxdata == '\0');
        total_bytes_read = 1;
    }
#endif

    bytes_to_read = *rxsize > 0 ? (size_t)*rxsize : 0U;
    rxlen = (bytes_to_read > 0U) ? (uint16_t)bytes_to_read-- : 0U;

    while (ATCA_SUCCESS == status && (NULL == location) && (0u < bytes_to_read))
    {
        status = iface->phy->halreceive(iface, 0x00, &rxdata[total_bytes_read], &rxlen);

        location = memchr(&rxdata[total_bytes_read], (int)'\n', (size_t)rxlen);

        total_bytes_read += rxlen;

        if (rxlen <= bytes_to_read)
        {
            bytes_to_read -= rxlen;
        }
    }

    // Save the total bytes read
    if (location != NULL)
    {
        *rxsize = (int)(location - (char*)rxdata);
    }
    else
    {
        *rxsize = (int)total_bytes_read;
    }

    if (ATCA_SUCCESS != status)
    {
        return status;
    }

#ifdef KIT_DEBUG
    printf("Kit Recv (%d): %s", *rxsize, rxdata);
#endif

    return ATCA_SUCCESS;
}

/** \brief HAL implementation of kit protocol init.  This function calls back to the physical protocol to send the bytes
 *  \param[in] iface  instance
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS kit_init(ATCAIface iface, ATCAIfaceCfg* cfg)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    const char kit_device[] = "board:device(%02X)\n";
    const char kit_interface_select[] = "%c:physical:interface:%s\n";
    const char kit_device_select[] = "%c:physical:select(%02X)\n";
    char txbuf[KIT_MAX_TX_BUF];
    int txlen;
    char rxbuf[KIT_RX_WRAP_SIZE + 4];
    int rxlen;
    const char* device_match, *interface_match, *interfaceKit;
    char *dev_type, *dev_interface;
    char delim[] = " ";
    char *pToken; /* string token */
    int i;
    unsigned int address;
    ATCAKitType iface_type;
    uint8_t dev_identity;

    ((void)cfg);

    device_match = kit_id_from_devtype(iface->mIfaceCFG->devtype);

    switch (iface->mIfaceCFG->iface_type)
    {
#ifdef ATCA_HAL_KIT_HID
    case ATCA_HID_IFACE:
        iface_type = ATCA_IFACECFG_VALUE(iface->mIfaceCFG, atcahid.dev_interface);
        dev_identity = ATCA_IFACECFG_VALUE(iface->mIfaceCFG, atcahid.dev_identity);
        break;
#endif
#ifdef ATCA_HAL_KIT_UART
    case ATCA_UART_IFACE:
        iface_type = ATCA_IFACECFG_VALUE(iface->mIfaceCFG, atcauart.dev_interface);
        dev_identity = ATCA_IFACECFG_VALUE(iface->mIfaceCFG, atcauart.dev_identity);
        break;
#endif
    default:
        iface_type = ATCA_KIT_AUTO_IFACE;
        dev_identity = 0;
        break;
    }

    interface_match = kit_interface_from_kittype(iface_type);

    /* Iterate to find the target device */
    for (i = 0; i < KIT_MAX_SCAN_COUNT; i++)
    {
        txlen = snprintf(txbuf, sizeof(txbuf) - 2u, kit_device, i);
        txbuf[sizeof(txbuf) - 1u] = (char)'\0';
        if (txlen < 0)
        {
            status = ATCA_INVALID_SIZE;
            break;
        }

        if (ATCA_SUCCESS != (status = kit_phy_send(iface, (uint8_t*)txbuf, txlen)))
        {
            break;
        }

        rxlen = (int)sizeof(rxbuf);
        (void)memset(rxbuf, 0, (size_t)rxlen);
        if (ATCA_SUCCESS != (status = kit_phy_receive(iface, (uint8_t*)rxbuf, &rxlen)))
        {
            break;
        }

        pToken = rxbuf;
        dev_type = strtok_r(NULL, delim, &pToken);
        if (NULL == dev_type)
        {
            status = ATCA_GEN_FAIL;
            break;
        }

        dev_interface = strtok_r(NULL, delim, &pToken);
        if (NULL == dev_interface)
        {
            status = ATCA_GEN_FAIL;
            break;
        }

        char * addr = strnchr(rxbuf, rxlen > 0 ? (size_t)rxlen : 0u, (int)'('); /* Gets the identity from the kit used for selecting the device*/
        address = 0;

        if (NULL == addr)
        {
            status = ATCA_GEN_FAIL;
            break;
        }

        if (1 != sscanf(addr, "(%02X)", &address))
        {
            status = ATCA_GEN_FAIL;
            break;
        }

        /*Selects the first device type if both device interface and device identity is not defined*/
        if (iface_type == ATCA_KIT_AUTO_IFACE && (dev_identity == 0u || dev_identity == address) && (strncmp(device_match, dev_type, 4) == 0))
        {
            /* coverity[cert_str34_c_violation] Does not invoke any undefined behavior in this case */
            txlen = snprintf(txbuf, sizeof(txbuf) - 1u, kit_device_select, device_match[0], address);
            txbuf[sizeof(txbuf) - 1u] = (char)'\0';
            if (txlen < 0)
            {
                status = ATCA_INVALID_SIZE;
                break;
            }

            if (ATCA_SUCCESS != (status = kit_phy_send(iface, (uint8_t*)txbuf, txlen)))
            {
                break;
            }

            rxlen = (int)sizeof(rxbuf);
            status = kit_phy_receive(iface, (uint8_t*)rxbuf, &rxlen);
            break;
        }
        else
        {

            if ((strncmp(device_match, dev_type, 4) == 0) && (dev_identity == 0u || dev_identity == address) && (strcmp(interface_match, dev_interface) == 0))
            {
                interfaceKit = kit_interface(iface_type);
                txlen = snprintf(txbuf, sizeof(txbuf) - 1u, kit_interface_select, device_match[0], interfaceKit);
                txbuf[sizeof(txbuf) - 1u] = (char)'\0';

                if (txlen < 0)
                {
                    status = ATCA_INVALID_SIZE;
                    break;
                }

                if (ATCA_SUCCESS != (status = kit_phy_send(iface, (uint8_t*)txbuf, txlen)))
                {
                    break;
                }

                rxlen = (int)sizeof(rxbuf);
                // Ignoring the response to support earlier versions
                (void)kit_phy_receive(iface, (uint8_t*)rxbuf, &rxlen);

                txlen = snprintf(txbuf, sizeof(txbuf) - 1u, kit_device_select, device_match[0], address);
                txbuf[sizeof(txbuf) - 1u] = (char)'\0';
                if (txlen < 0)
                {
                    status = ATCA_INVALID_SIZE;
                    break;
                }

                if (ATCA_SUCCESS != (status = kit_phy_send(iface, (uint8_t*)txbuf, txlen)))
                {
                    break;
                }

                rxlen = (int)sizeof(rxbuf);
                status = kit_phy_receive(iface, (uint8_t*)rxbuf, &rxlen);
                break;
            }
        }
    }

    if (KIT_MAX_SCAN_COUNT == i)
    {
        status = ATCA_NO_DEVICES;
    }

    return status;
}

/** \brief HAL implementation of Kit HID post init
 *  \param[in] iface  instance
 *  \return ATCA_STATUS
 */
ATCA_STATUS kit_post_init(ATCAIface iface)
{
    ((void)iface);
    return ATCA_SUCCESS;
}

/** \brief The function send word address byte of atreceive to kit protocol to receive
 *         response from device. This function call takes place only when target device is TA10x.
 * \param[in]     iface         instance
 * \param[in]     word_address  device transaction type
 * \param[in,out] rxsize        ptr to expected number of receive bytes to request
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS kit_ta_send_to_receive(ATCAIface iface, uint8_t word_address, uint16_t* rxsize)
{
    ATCA_STATUS status;
    char send_instrcode[] = "T:receive(%02X%02X%02X)\n";
    char txbuf[KIT_MAX_TX_BUF];
    int txbuf_size = (int)sizeof(txbuf);

    // Get instruction code and response length
    (void)snprintf(txbuf, sizeof(txbuf), send_instrcode, word_address, (uint8_t)((*rxsize >> 8) & 0xFFU), (uint8_t)(*rxsize & 0xFFU));
    txbuf[sizeof(txbuf) - 1u] = (char)'\0';

    // Send the word address bytes
    status = kit_phy_send(iface, (uint8_t*)txbuf, txbuf_size);

    return status;
}

/** \brief The function receive a response for send command from kit protocol whether success or not.
 *         This function call takes place only when target device is TA10x.
 * \param[in]    iface   instance
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS kit_ta_receive_send_rsp(ATCAIface iface)
{
    ATCA_STATUS status;
    uint8_t kitstatus[1] = { 0 };
    char reply[KIT_RX_WRAP_SIZE];
    int replysize = (int)sizeof(reply);
    uint8_t rxdata[(KIT_RX_WRAP_SIZE + 1) / 2];
    int rxsize = (int)sizeof(rxdata);

    // Receive the reply to send "00()\n"
    (void)memset(reply, 0, (size_t)replysize);
    if (ATCA_SUCCESS != (status = kit_phy_receive(iface, (uint8_t*)reply, &replysize)))
    {
        return ATCA_GEN_FAIL;
    }

#ifdef KIT_DEBUG
    // Print the bytes
    printf("Kit Read: %s\r", reply);
#endif

    // Unwrap from kit protocol
    (void)memset(rxdata, 0, (size_t)rxsize);
    if (ATCA_SUCCESS != (status = kit_parse_rsp(reply, replysize, kitstatus, rxdata, &rxsize)))
    {
        status = ATCA_GEN_FAIL;
    }
    if ((uint8_t)ATCA_SUCCESS != kitstatus[0])
    {
        status = ATCA_TX_FAIL;
    }

    return status;
}

/** \brief HAL implementation of kit protocol send.  This function calls back to the physical protocol to send the bytes
 *  \param[in] iface         instance
 *  \param[in] word_address  device transaction type
 *  \param[in] txdata        pointer to bytes to send
 *  \param[in] txlength      number of bytes to send
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS kit_send(ATCAIface iface, uint8_t word_address, uint8_t* txdata, int txlength)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    int nkitbuf;
    char* pkitbuf = NULL;

    do
    {
        // Wrap in kit protocol
        if(true == atcab_is_ta_device(iface->mIfaceCFG->devtype))
        {
            /* coverity[cert_int32_c_violation:FALSE] txlength maximum value is controled by maximum supported packet size of the device */
            nkitbuf = (txlength + sizeof(word_address)) * 2 + KIT_TX_WRAP_SIZE;
        }
        else
        {
            /* coverity[cert_int32_c_violation:FALSE] txlength maximum value is controled by maximum supported packet size of the device */
            nkitbuf = txlength * 2 + KIT_TX_WRAP_SIZE;
        }

        pkitbuf = hal_malloc(nkitbuf > 0 ? (size_t)nkitbuf : 0u);

        if (NULL != pkitbuf)
        {
            (void)memset(pkitbuf, 0, (size_t)nkitbuf);
        }

        if (ATCA_SUCCESS != (status = kit_wrap_cmd(iface, word_address, txdata, txlength, pkitbuf, &nkitbuf)))
        {
            status = ATCA_GEN_FAIL;
            break;
        }

    #ifdef KIT_DEBUG
        // Print the bytes
        printf("\nKit Write: %s", pkitbuf);
    #endif

        // Send the bytes
        if (ATCA_SUCCESS != (status = kit_phy_send(iface, (uint8_t*)pkitbuf, nkitbuf)))
        {
            break;
        }

        // Receive the reply to send "00()\n"
        if (true == atcab_is_ta_device(iface->mIfaceCFG->devtype))
        {
            status = kit_ta_receive_send_rsp(iface);
        }

    }
    while (false);

    // Free the bytes
    hal_free(pkitbuf);

    return status;
}

/** \brief HAL implementation to receive bytes and unwrap from kit protocol.
 *         This function calls back to the physical protocol to receive the bytes
 * \param[in]     iface         instance
 * \param[in]     word_address  device transaction type
 * \param[in]     rxdata        pointer to space to receive the data
 * \param[in,out] rxsize        ptr to expected number of receive bytes to request
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS kit_receive(ATCAIface iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxsize)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t kitstatus[1] = { 0 };
    int nkitbuf = 0;
    int dataSize;
    char *pkitbuf = NULL;

    do
    {
        // Check the pointers
        if ((rxdata == NULL) || (rxsize == NULL))
        {
            status = ATCA_BAD_PARAM;
            break;
        }

        if (true == atcab_is_ta_device(iface->mIfaceCFG->devtype))
        {
            // Send word address byte to kit protocol to receive a response from device
            if (ATCA_SUCCESS != (status = kit_ta_send_to_receive(iface, word_address, rxsize)))
            {
                break;
            }
        }

        // Receive the response bytes
        //! For large data(greater than 1020 bytes)
        //! nkitbuf in Kit_phy_receive alligns to 64 byte due to USB HID
        //! so alligned with 64 multiples for buffer size
        //coverity[misra_c_2012_rule_10_8_violation] this has been tested and confirmed to be correct for USB HID communication
        nkitbuf = (int)((((((*rxsize * 2u) + KIT_RX_WRAP_SIZE)) / 64u) + 1u) * 64u);
        pkitbuf = hal_malloc((size_t)nkitbuf);

        if (NULL != pkitbuf)
        {
            (void)memset(pkitbuf, 0, (size_t)nkitbuf);
        }

        if (ATCA_SUCCESS != (status = kit_phy_receive(iface, (uint8_t*)pkitbuf, &nkitbuf)))
        {
            status = ATCA_GEN_FAIL;
            break;
        }

    #ifdef KIT_DEBUG
        // Print the bytes
        printf("Kit Read: %s\r", pkitbuf);
    #endif

        // Unwrap from kit protocol        
        dataSize = (int)*rxsize;
        *rxsize = 0;
        if (ATCA_SUCCESS != (status = kit_parse_rsp(pkitbuf, nkitbuf, kitstatus, rxdata, &dataSize)))
        {
            break;
        }

        *rxsize = (uint16_t)(dataSize & UINT16_MAX);

    }
    while (false);

    // Free the bytes
    hal_free(pkitbuf);

    return status;
}

/** \brief Call the wake for kit protocol
 * \param[in] iface  the interface object to send the bytes over
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS kit_wake(ATCAIface iface)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t kitstatus[1] = { 0 };
    char wake[] = "d:w()\n";
    int wakesize = (int)sizeof(wake);
    char reply[KIT_RX_WRAP_SIZE + 4];
    int replysize = (int)sizeof(reply);
    uint8_t rxdata[10];
    int rxsize = (int)sizeof(rxdata);
    const char *target;

    target = kit_id_from_devtype(iface->mIfaceCFG->devtype);
    wake[0] = target[0];

    // Send the bytes
    status = kit_phy_send(iface, (uint8_t*)wake, wakesize);

#ifdef KIT_DEBUG
    // Print the bytes
    printf("\nKit Write: %s", wake);
#endif

    // Receive the reply to wake "00(04...)\n"
    (void)memset(reply, 0, (size_t)replysize);
    if (ATCA_SUCCESS != (status = kit_phy_receive(iface, (uint8_t*)reply, &replysize)))
    {
        return ATCA_GEN_FAIL;
    }

#ifdef KIT_DEBUG
    // Print the bytes
    printf("Kit Read: %s\n", reply);
#endif

    // Unwrap from kit protocol
    (void)memset(rxdata, 0, (size_t)rxsize);
    status = kit_parse_rsp(reply, replysize, kitstatus, rxdata, &rxsize);

    return hal_check_wake(rxdata, rxsize);
}

/** \brief Call the idle for kit protocol
 * \param[in] iface  the interface object to send the bytes over
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS kit_idle(ATCAIface iface)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t kitstatus[1] = { 0 };
    char idle[] = "d:i()\n";
    int idlesize = (int)sizeof(idle);
    char reply[KIT_RX_WRAP_SIZE];
    int replysize = (int)sizeof(reply);
    uint8_t rxdata[10];
    int rxsize = (int)sizeof(rxdata);
    const char *target;

    target = kit_id_from_devtype(iface->mIfaceCFG->devtype);
    idle[0] = target[0];

    // Send the bytes
    status = kit_phy_send(iface, (uint8_t*)idle, idlesize);

#ifdef KIT_DEBUG
    // Print the bytes
    printf("\nKit Write: %s", idle);
#endif

    // Receive the reply to sleep "00()\n"
    (void)memset(reply, 0, (size_t)replysize);
    if (ATCA_SUCCESS != (status = kit_phy_receive(iface, (uint8_t*)reply, &replysize)))
    {
        return ATCA_GEN_FAIL;
    }

#ifdef KIT_DEBUG
    // Print the bytes
    printf("Kit Read: %s\r", reply);
#endif

    // Unwrap from kit protocol
    (void)memset(rxdata, 0, (size_t)rxsize);
    status = kit_parse_rsp(reply, replysize, kitstatus, rxdata, &rxsize);

    return status;
}

/** \brief Call the sleep for kit protocol
 * \param[in] iface  the interface object to send the bytes over
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS kit_sleep(ATCAIface iface)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t kitstatus[1] = { 0 };

    char sleep[] = "d:s()\n";
    int sleepsize = (int)sizeof(sleep);
    char reply[KIT_RX_WRAP_SIZE];
    int replysize = (int)sizeof(reply);
    uint8_t rxdata[10];
    int rxsize = (int)sizeof(rxdata);
    const char* target;

    target = kit_id_from_devtype(iface->mIfaceCFG->devtype);
    sleep[0] = target[0];

    // Send the bytes
    status = kit_phy_send(iface, (uint8_t*)sleep, sleepsize);

#ifdef KIT_DEBUG
    // Print the bytes
    printf("\nKit Write: %s", sleep);
#endif

    // Receive the reply to sleep "00()\n"
    (void)memset(reply, 0, (size_t)replysize);
    if (ATCA_SUCCESS != (status = kit_phy_receive(iface, (uint8_t*)reply, &replysize)))
    {
        return ATCA_GEN_FAIL;
    }

#ifdef KIT_DEBUG
    // Print the bytes
    printf("Kit Read: %s\r", reply);
#endif

    // Unwrap from kit protocol
    (void)memset(rxdata, 0, (size_t)rxsize);
    status = kit_parse_rsp(reply, replysize, kitstatus, rxdata, &rxsize);

    return status;
}

/** \brief Wrap binary bytes in ascii kit protocol
 * \param[in]    iface        instance
 * \param[in]    word_address Binary word address to wrap.
 * \param[in]    txdata   Binary data to wrap.
 * \param[in]    txlen    Length of binary data in bytes.
 * \param[out]   pkitcmd  ASCII kit protocol wrapped data is returned here.
 * \param[in,out] nkitcmd  As input, the size of the pkitcmd buffer.
 *                        As output, the number of bytes returned in the
 *                        pkitcmd buffer.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS kit_wrap_cmd(ATCAIface iface, uint8_t word_address, const uint8_t* txdata, int txlen, char* pkitcmd, int* nkitcmd)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    const char* ta_cmdpre = "t:send(";
    const char* ca_cmdpre = "d:t(";
    const char* target = kit_id_from_devtype(iface->mIfaceCFG->devtype);
    bool is_ta_device = (atcab_is_ta_device(iface->mIfaceCFG->devtype)) ? true : false;
    const char* cmdpre = (atcab_is_ta_device(iface->mIfaceCFG->devtype)) ? ta_cmdpre : ca_cmdpre;
    char cmdpost[] = ")\n";
    size_t cpylen = 0U;
    size_t cpyindex = 0U;
    size_t cmdlen = 0U;

    // Check the variables
    if (pkitcmd == NULL || nkitcmd == NULL || (0 > txlen))
    {
        return ATCA_BAD_PARAM;
    }

    size_t wordaddr_cmdAsciiLen = (sizeof(word_address) * 2U);
    size_t txdata_cmdAsciiLen = (size_t)txlen * 2U;

    if(is_ta_device == true)
    {
        /* coverity[cert_int30_c_violation:FALSE] None of these inputs can exceed SIZE_MAX */
        cmdlen = wordaddr_cmdAsciiLen + txdata_cmdAsciiLen + strlen(cmdpre) + sizeof(cmdpost) - 1U;
    }
    else
    {
        /* coverity[cert_int30_c_violation:FALSE] None of these inputs can exceed SIZE_MAX */
        cmdlen = txdata_cmdAsciiLen + strlen(cmdpre) + sizeof(cmdpost) - 1U;
    }

    /* coverity[cert_int31_c_violation:FALSE] cmdlen will never exceed INT_MAX */
    if (*nkitcmd < (int)cmdlen)
    {
        return ATCA_SMALL_BUFFER;
    }

    // Wrap in kit protocol
    (void)memset(pkitcmd, 0, (size_t)*nkitcmd);

    // Copy the prefix
    cpylen = strlen(cmdpre);
    (void)memcpy(&pkitcmd[cpyindex], cmdpre, cpylen);
    cpyindex += cpylen;

    pkitcmd[0] = target[0];

    if(is_ta_device == true)
    {
        // Copy the ascii binary bytes
        if (ATCA_SUCCESS != (status = atcab_bin2hex_(&word_address, sizeof(word_address), &pkitcmd[cpyindex], &wordaddr_cmdAsciiLen, false, false, true)))
        {
            return status;
        }
        cpyindex += wordaddr_cmdAsciiLen;
    }

    if(NULL != txdata && 0 < txlen)
    {
        // Copy the ascii binary bytes
        if (ATCA_SUCCESS != (status = atcab_bin2hex_(txdata, (size_t)(txlen), &pkitcmd[cpyindex], &txdata_cmdAsciiLen, false, false, true)))
        {
            return status;
        }
        cpyindex += txdata_cmdAsciiLen;
    }

    // Copy the postfix
    cpylen = strlen(cmdpost);
    (void)memcpy(&pkitcmd[cpyindex], cmdpost, cpylen);
    /* coverity[cert_int30_c_violation:FALSE] cpyindex can never wrap because the input strings sizes are controlled to a narrow range by the caller */
    cpyindex += cpylen;

    if (cpyindex <= INT_MAX)
    {
        *nkitcmd = (int)cpyindex;
    }

    return status;
}

/** \brief Parse the response ascii from the kit
 * \param[out] pkitbuf pointer to ascii kit protocol data to parse
 * \param[in] nkitbuf length of the ascii kit protocol data
 * \param[in] kitstatus status of the ascii device
 * \param[in] rxdata pointer to the binary data buffer
 * \param[in] datasize size of the pointer to the binary data buffer
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS kit_parse_rsp(const char* pkitbuf, int nkitbuf, uint8_t* kitstatus, uint8_t* rxdata, int* datasize)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    int statusId = 0;
    int dataId = 3;
    size_t binSize = 1;
    size_t asciiDataSize = 0;
    size_t datasizeTemp = (*datasize > 0) ? (size_t)*datasize : 0u;
    char* endDataPtr = NULL;

    // First get the kit status
    if (ATCA_SUCCESS != (status = atcab_hex2bin(&pkitbuf[statusId], 2, kitstatus, &binSize)))
    {
        return status;
    }

    // Next get the binary data bytes
    endDataPtr = strnchr(pkitbuf, (nkitbuf > 0 ? (size_t)nkitbuf : 0u), (int)')');
    if (endDataPtr < (&pkitbuf[dataId]))
    {
        return ATCA_GEN_FAIL;
    }

    asciiDataSize = atcab_pointer_delta(endDataPtr, &pkitbuf[dataId]);
    status = atcab_hex2bin(&pkitbuf[dataId], asciiDataSize, rxdata, &datasizeTemp);
    *datasize = (datasizeTemp > 0u) ? (int)datasizeTemp : 0;

    return status;
}


/** \brief Perform control operations for the kit protocol
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS kit_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    (void)param;
    (void)paramlen;

    if (NULL != iface && NULL != iface->mIfaceCFG)
    {
        switch (option)
        {
        case ATCA_HAL_CONTROL_WAKE:
            status = kit_wake(iface);
            break;
        case ATCA_HAL_CONTROL_IDLE:
            status = kit_idle(iface);
            break;
        case ATCA_HAL_CONTROL_SLEEP:
            status = kit_sleep(iface);
            break;
        case ATCA_HAL_CONTROL_SELECT:
        /* fallthrough */
        case ATCA_HAL_CONTROL_DESELECT:
            status = ATCA_SUCCESS;
            break;
        default:
            status = ATCA_BAD_PARAM;
            break;
        }
    }
    return status;
}

ATCA_STATUS kit_release(void* hal_data)
{
    ((void)hal_data);
    return ATCA_SUCCESS;
}

#endif

/** @} */
#ifdef __COVERITY__
#pragma coverity compliance end_block "MISRA C-2012 Rule 10.3" "MISRA C-2012 Rule 10.4" "MISRA C-2012 Rule 21.6"
#endif
