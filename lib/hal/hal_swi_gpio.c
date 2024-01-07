/**
 * \file
 * \brief ATCA Hardware abstraction layer for 1WIRE or SWI over GPIO.
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
#include "hal_swi_gpio.h"

#if !defined(ATCA_HAL_SWI) && (defined(ATCA_HAL_SWI_GPIO) || defined(ATCA_HAL_SWI_BB))
#define ATCA_HAL_SWI
#endif

#if (defined(ATCA_ECC204_SUPPORT) || defined(ATCA_TA010_SUPPORT) || defined(ATCA_SHA104_SUPPORT)) && (defined(ATCA_HAL_SWI_GPIO) || defined(ATCA_HAL_SWI_BB))
#define ATCA_HAL_1WIRE
#endif

static ATCA_STATUS hal_swi_gpio_set_bit(
    ATCAIface iface,            /**< [in]   Device context */
    uint8_t   pin_state         /**< [in]   value to write */
    )
{
    return iface->phy->halsend(iface, 0, &pin_state, 0);
}

static ATCA_STATUS hal_swi_gpio_read_bit(
    ATCAIface iface,            /**< [in]   Device context */
    uint8_t*  pin_state         /**< [in]   location to store the read state */
    )
{
    return iface->phy->halreceive(iface, 0, pin_state, NULL);
}

static ATCA_STATUS hal_swi_gpio_set_dir(
    ATCAIface iface,           /**< [in]   Device context */
    uint8_t   pin_dir          /**< [in]   Pin type input/output */
    )
{
    return iface->phy->halcontrol(iface, ATCA_HAL_CONTROL_DIRECTION, &pin_dir, sizeof(pin_dir));
}

/** \brief Function to send logic bit 1 or 0 over GPIO using 1WIRE
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS send_logic_bit(
    ATCAIface iface,        /**< [in]   Device context */
    bool      bit_value     /**< [in]   Bit value to write */
    )
{
    ATCA_STATUS status = ATCA_SUCCESS;
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    const uint8_t* timings;
    const uint8_t logic1_swi_timings[] = { 4, 26 };
    const uint8_t logic1_1wire_timings[] = { 1, 7 };
    const uint8_t logic0_swi_timings[] = { 4, 34, 4, 4 };
    const uint8_t logic0_1wire_timings[] = { 6, 2 };

    if (bit_value == ATCA_GPIO_LOGIC_BIT1)
    {
        timings = (atcab_is_ca2_device(cfg->devtype)) ? logic1_1wire_timings : logic1_swi_timings;

        (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_CLEAR);
        atca_delay_us(*timings++);
        (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_SET);
        atca_delay_us(*timings++);
    }
    else
    {
        timings = (atcab_is_ca2_device(cfg->devtype)) ? logic0_1wire_timings : logic0_swi_timings;

        (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_CLEAR);
        atca_delay_us(*timings++);
        (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_SET);
        atca_delay_us(*timings++);

        #ifdef ATCA_HAL_SWI
        if (!atcab_is_ca2_device(cfg->devtype))
        {
            (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_CLEAR);
            atca_delay_us(*timings++);
            (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_SET);
            atca_delay_us(*timings++);
        }
        #endif
    }

    return status;
}

#ifdef ATCA_HAL_1WIRE
/** \brief Function to generate start or stop condition
 * \return  ATCA_SUCCESS
 */
static ATCA_STATUS start_stop_cond_1wire(
    ATCAIface iface        /**< [in]   Device context */
    )
{
    (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_SET);
    tHTSS_DLY;
    return ATCA_SUCCESS;
}

/** \brief Function to read the logic bit 1 or 0
 * \return  ATCA_SUCCESS
 */
static ATCA_STATUS read_logic_bit_1wire(
    ATCAIface iface,        /**< [in]   Device context */
    uint8_t * bit_value     /**< [out]  Location to store the read bit value */
    )
{
    /* Changing the PIN direction as Input */
    (void)hal_swi_gpio_set_dir(iface, ATCA_GPIO_INPUT_DIR);

    /* Read the line state */
    (void)hal_swi_gpio_read_bit(iface, bit_value);

    /* Changing the PIN direction as Output */
    (void)hal_swi_gpio_set_dir(iface, ATCA_GPIO_OUTPUT_DIR);

    return ATCA_SUCCESS;
}

/** \brief Function to read the data ACK for the transmitted byte
 * \param[in] cfg          Driver interface configurations
 * \param[in] bit_value     Contains logical bit value(ACK or NACK) to be received
 * \return  ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS read_data_ACK_1wire(ATCAIface iface, bool *bit_value)
{
    /* this checks for an ACK or NACK from device */
    (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_CLEAR);
    tRD_DLY;
    (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_SET);
    tLOW1_DLY;

    return read_logic_bit_1wire(iface, (uint8_t*)bit_value);
}
#endif /* ATCA_HAL_1WIRE */

/** \brief Function to send the specified number of bytes through GPIO bit banging
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS gpio_send_bytes(
    ATCAIface iface,        /**< [in]   Device context */
    uint8_t * txdata,       /**< [in]   Data to send */
    uint16_t  txlength      /**< [in]   Number of bytes to send */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t bit_mask;
    uint8_t count;

    protocol_type proto_type = (atcab_is_ca2_device(cfg->devtype)) ? ATCA_PROTOCOL_1WIRE : ATCA_PROTOCOL_SWI;

    if (txdata == NULL)
    {
        return status;
    }

    /* Disabling interrupts */
    __disable_irq();
    for (count = 0; count < txlength; count++)
    {
        bit_mask = (atcab_is_ca2_device(cfg->devtype)) ? ATCA_1WIRE_BIT_MASK : ATCA_SWI_BIT_MASK;
        while (bit_mask > 0)
        {
            /* if the next bit transmitted is a logic '1' */
            if (bit_mask & txdata[count])
            {
                status = send_logic_bit(iface, ATCA_GPIO_LOGIC_BIT1);
            }
            /* if the next bit transmitted is a logic '0' */
            else
            {
                status = send_logic_bit(iface, ATCA_GPIO_LOGIC_BIT0);
            }

            bit_mask = (proto_type == ATCA_PROTOCOL_1WIRE) ? bit_mask >> 1 : bit_mask << 1;
        }
        #ifdef ATCA_HAL_1WIRE
        if ((status == ATCA_SUCCESS) && (proto_type == ATCA_PROTOCOL_1WIRE))
        {
            bool bit_value;

            (void)read_data_ACK_1wire(iface, &bit_value);

            /* check for ACK/NACK */
            if (bit_value) /* if a NAK is detected */
            {
                /* device failed to send ACK */
                status = ATCA_COMM_FAIL;
                break;
            }
            tRCV0_DLY; /* slave recovery time delay (same for logic'0' and logic '1') */
        }
        #endif
    }
    /* Enabling interrupts */
    __enable_irq();

    return status;
}

#ifdef ATCA_HAL_SWI
/** \brief Function to read the logic bit 1 or 0
 * \param[in] cfg          Driver interface configurations
 * \param[in] bit_value     Contains logical bit value to be received
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS read_logic_bit_swi(
    ATCAIface iface,        /**< [in]   Device context */
    bool *    bit_value
    )
{
    int8_t timeout_count;
    uint8_t current_state = true, prev_state = true;
    uint8_t bit_count = 0;
    ATCA_STATUS status = ATCA_BAD_PARAM;

    do
    {
        //wait for start bit
        timeout_count = 90 / 2;
        while (timeout_count-- >= 0)
        {
            (void)hal_swi_gpio_read_bit(iface, &current_state);
            if (current_state != prev_state)
            {
                prev_state = current_state;
                if (!current_state)
                {
                    break;
                }

            }
            atca_delay_us(2);
        }

        if (timeout_count <= 0)
        {
            status = ATCA_TRACE(ATCA_RX_NO_RESPONSE, "No response is received");
            break;
        }

        //Read bit
        timeout_count = 40 / 2;
        while (timeout_count-- >= 0)
        {
            (void)hal_swi_gpio_read_bit(iface, &current_state);
            if (current_state != prev_state)
            {
                prev_state = current_state;
                if (current_state)
                {
                    bit_count++;
                }

            }
            atca_delay_us(2);
        }

        if (bit_count == 2)
        {
            *bit_value = 0;
        }
        else if (bit_count == 1)
        {
            *bit_value = 1;
        }
        else
        {
            status = ATCA_TRACE(ATCA_RX_FAIL, "Rx Receive - failed");
        }
    }
    while (0);

    return status;
}
#endif /* ATCA_HAL_SWI */

/** \brief Function to receive the response bytes through GPIO bit banging
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS gpio_receive_bytes(
    ATCAIface iface,        /**< [in]   Device context */
    uint8_t * rxdata,       /**< [out]  Recieved data buffer */
    uint16_t  rxlength      /**< [in]   Size of data buffer */
    )
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t bit_mask;
    uint8_t count;
    protocol_type proto_type;
    bool bit_value = 1;

    if (rxdata == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    proto_type = (atcab_is_ca2_device(cfg->devtype)) ? ATCA_PROTOCOL_1WIRE : ATCA_PROTOCOL_SWI;

    __disable_irq();
    for (count = 0; count < rxlength; count++)
    {
        bit_mask = (atcab_is_ca2_device(cfg->devtype)) ? ATCA_1WIRE_BIT_MASK : ATCA_SWI_BIT_MASK;
        while (bit_mask >= 1)
        {
            #ifdef ATCA_HAL_1WIRE
            if (proto_type == ATCA_PROTOCOL_1WIRE)
            {

                (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_CLEAR);
                /* device is set for high-speed communication */
                tHIGH_SPEED_DLY;
                (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_SET);
                tSWIN_DLY; /* delay to put master read inside the master sampling window */
                (void)read_logic_bit_1wire(iface, (uint8_t*)&bit_value);
                rxdata[count] <<= 1;
            }
            #endif

            #ifdef ATCA_HAL_SWI
            if (proto_type == ATCA_PROTOCOL_SWI)
            {
                (void)read_logic_bit_swi(iface, &bit_value);
            }
            #endif

            if (bit_value) /* if a logic '1' is detected; received "one" bit */
            {
                rxdata[count] |= bit_value;
            }
            if (proto_type == ATCA_PROTOCOL_1WIRE)
            {
                tBIT_DLY;//bit frame duration (tBIT) before reading the next bit
                bit_mask >>= 1;
            }
            else
            {
                bit_mask <<= 1;
            }
        }
        #ifdef ATCA_HAL_1WIRE
        /* send ACK except for last byte of read --> GO TO send_ACK() */
        if (((count < (rxlength - 1)) || (ATCA_1WIRE_RESPONSE_LENGTH_SIZE == rxlength)) && (proto_type == ATCA_PROTOCOL_1WIRE))
        {
            (void)send_ACK_1wire(iface);
        }
        #endif
    }
    __enable_irq();

    return ATCA_SUCCESS;
}

/** \brief Function to generate wake condition
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS generate_wake_condition(
    ATCAIface iface        /**< [in]   Device context */
    )
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_CLEAR);
    atca_delay_us(60);
    (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_SET);
    atca_delay_us(cfg->wake_delay);
    return ATCA_SUCCESS;
}

#ifdef ATCA_HAL_1WIRE
/** \brief Function to discover the available devices in the bus
 * \param[in] cfg          Driver interface configurations
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS device_discovery_1wire(ATCAIface iface)
{
    bool bit_value;
    ATCA_STATUS status = ATCA_BAD_PARAM;

    (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_CLEAR);
    tRESET_DLY;
    (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_SET);
    tRRT_DLY;
    (void)hal_swi_gpio_set_bit(iface, ATCA_GPIO_CLEAR);
    tDRR_DLY;

    (void)read_logic_bit_1wire(iface, (uint8_t*)&bit_value);

    status = (bit_value == ((bool)ATCA_GPIO_ACK)) ? ATCA_SUCCESS : ATCA_NO_DEVICES;

    return status;
}

/** \brief Function to read the data ACK for the transmitted byte
 * \param[in] dev_addr      8 bit device address
 * \param[in] oper          indicates read or write operation
 * \return  8 bit device address for write or read operation
 */
static uint8_t get_slave_addr_1wire(uint8_t dev_addr, uint8_t oper)
{
    return dev_addr | oper;
}

/** \brief Function to check wake condition for 1WIRE
 * \param[in] cfg          Driver interface configurations
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS check_wake_1wire(ATCAIface iface)
{
    ATCA_STATUS status;
    uint8_t dev_addr;

    status = device_discovery_1wire(iface);
    if (status == ATCA_NO_DEVICES)
    {
        (void)generate_wake_condition(iface);
        status = start_stop_cond_1wire(iface);
        dev_addr = get_slave_addr_1wire(iface->mIfaceCFG->atcaswi.address, ATCA_GPIO_WRITE);
        status = gpio_send_bytes(iface, &dev_addr, sizeof(dev_addr));
        (void)start_stop_cond_1wire(iface);
    }

    return status;
}
#endif /* ATCA_HAL_1WIRE */

/** \brief initialize an GPIO interface using given config
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_swi_gpio_init(ATCAIface iface, ATCAIfaceCfg* cfg)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (iface && iface->phy)
    {
        /* GPIO direction as output */
        (void)hal_swi_gpio_set_dir(iface, ATCA_GPIO_OUTPUT_DIR);

        /* by default, driving high */
        uint8_t param = ATCA_GPIO_SET;
        iface->phy->halsend(iface, 0xFF, &param, sizeof(param));
        status = ATCA_SUCCESS;
    }
    return status;
}

/**
 * \brief HAL implementation of GPIO post init.
 *
 * \param[in] iface  ATCAIface instance
 *
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_swi_gpio_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of bit banging send over Harmony
 * \param[in] iface         instance
 * \param[in] word_address  device transaction type
 * \param[in] txdata        pointer to space to bytes to send
 * \param[in] txlength      number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_swi_gpio_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCA_STATUS status = ATCA_BAD_PARAM;
    uint8_t dev_write_addr;

    if (!cfg)
    {
        return status;
    }

    if (atcab_is_ca2_device(cfg->devtype))
    {
        #ifdef ATCA_HAL_1WIRE
        if (ATCA_SUCCESS == (status = start_stop_cond_1wire(iface)))
        {
            dev_write_addr = get_slave_addr_1wire(cfg->atcaswi.address, ATCA_GPIO_WRITE);
            if (ATCA_SUCCESS == (status = gpio_send_bytes(iface, &dev_write_addr, sizeof(dev_write_addr))))
            {
                //! Send word address
                status = gpio_send_bytes(iface, &word_address, sizeof(word_address));

                //! Send data
                if((ATCA_SUCCESS == status) && (NULL != txdata) && (0u < txlength))
                {
                    status = gpio_send_bytes(iface, txdata, txlength);
                }
            }
            status = start_stop_cond_1wire(iface);
        }
        #endif
    }
    else
    {
        #ifdef ATCA_HAL_SWI
        if (ATCA_SUCCESS == (status = gpio_send_bytes(iface, &word_address, sizeof(word_address))))
        {
            if(NULL != txdata && 0U < txlength)
            {
                status = gpio_send_bytes(iface, txdata, txlength);
            }
        }
        #endif
    }

    return status;
}

/** \brief HAL implementation of bit banging receive from HARMONY
 * \param[in]    iface          Device to interact with.
 * \param[in]    word_address   device transaction type
 * \param[out]   rxdata         Data received will be returned here.
 * \param[in,out] rxlength      As input, the size of the rxdata buffer.
 *                              As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_swi_gpio_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCA_STATUS status;
    int retries;

    if ((NULL == cfg) || (NULL == rxlength) || (NULL == rxdata))
    {
        return ATCA_BAD_PARAM;
    }

    if (atcab_is_ca2_device(cfg->devtype))
    {
        #ifdef ATCA_HAL_1WIRE
        word_address = get_slave_addr_1wire(cfg->atcaswi.address, ATCA_GPIO_READ);
        if (ATCA_SUCCESS != (status = start_stop_cond_1wire(iface)))
        {
            return status;
        }
        #endif
    }
    else
    {
        word_address = ATCA_SWI_TX_WORD_ADDR;
    }

    retries = cfg->rx_retries;
    do
    {
        if (ATCA_SUCCESS == (status = gpio_send_bytes(iface, &word_address, sizeof(word_address))))
        {
            /* Reading response */
            status = gpio_receive_bytes(iface, rxdata, *rxlength);
        }
    }
    while ((retries-- > 0) && (status == ATCA_COMM_FAIL));

    #ifdef ATCA_HAL_1WIRE
    if ((atcab_is_ca2_device(cfg->devtype)) && (*rxlength != ATCA_1WIRE_RESPONSE_LENGTH_SIZE))
    {
        (void)send_NACK_1wire(iface);
    }
    status = start_stop_cond_1wire(iface);
    #endif

    return status;
}

/** \brief Put the device in idle mode
 * \param[in] iface  interface to logical device to idle
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS hal_swi_gpio_idle(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    if (cfg)
    {
        if (atcab_is_ca2_device(cfg->devtype))
        {
            return ATCA_SUCCESS;
        }
        else
        {
            return hal_swi_gpio_send(iface, ATCA_SWI_IDLE_WORD_ADDR, NULL, 0);
        }
    }

    return ATCA_BAD_PARAM;
}

/** \brief send sleep command
 * \param[in] iface  interface to logical device to sleep
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS hal_swi_gpio_sleep(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t word_address;

    if (cfg)
    {
        word_address = (atcab_is_ca2_device(cfg->devtype)) ? ATCA_1WIRE_SLEEP_WORD_ADDR : \
                       ATCA_SWI_SLEEP_WORD_ADDR;

        return hal_swi_gpio_send(iface, word_address, NULL, 0);
    }

    return ATCA_BAD_PARAM;
}

/** \brief Function to check wake condition for SWI
 * \param[in] cfg          Driver interface configurations
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS check_wake_swi(ATCAIface iface)
{
    uint8_t data[4] = { 0x00, 0x00, 0x00, 0x00 };
    uint16_t rxlength  = sizeof(data);
    const uint8_t expected_response[4] = { 0x04, 0x11, 0x33, 0x43 };
    const uint8_t selftest_fail_resp[4] = { 0x04, 0x07, 0xC4, 0x40 };

    if (gpio_receive_bytes(iface, data, rxlength) == ATCA_SUCCESS)
    {
        if (memcmp(data, expected_response, 4) == 0)
        {
            return ATCA_SUCCESS;
        }
        if (memcmp(data, selftest_fail_resp, 4) == 0)
        {
            return ATCA_STATUS_SELFTEST_ERROR;
        }
    }
    return ATCA_WAKE_FAILED;
}

/** \brief send wake token
 * \param[in] iface  interface to logical device to wakeup
 * \return ATCA_WAKE_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS hal_swi_gpio_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCA_STATUS status = ATCA_WAKE_FAILED;

    if (NULL == cfg)
    {
        return ATCA_BAD_PARAM;
    }

    if (atcab_is_ca2_device(cfg->devtype))
    {
        #ifdef ATCA_HAL_1WIRE
        status = check_wake_1wire(iface);
        #endif
    }
    else
    {
        #ifdef ATCA_HAL_SWI
        (void)generate_wake_condition(iface);
        status = check_wake_swi(iface);
        #endif
    }

    return status;
}


/** \brief Perform control operations
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_swi_gpio_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    if (iface && iface->mIfaceCFG)
    {
        switch (option)
        {
        case ATCA_HAL_CONTROL_WAKE:
            return hal_swi_gpio_wake(iface);
        case ATCA_HAL_CONTROL_IDLE:
            return hal_swi_gpio_idle(iface);
        case ATCA_HAL_CONTROL_SLEEP:
            return hal_swi_gpio_sleep(iface);
        case ATCA_HAL_CONTROL_SELECT:
        /* fallthrough */
        case ATCA_HAL_CONTROL_DESELECT:
            return ATCA_SUCCESS;
        default:
            break;
        }
    }
    return ATCA_BAD_PARAM;
}

/** \brief releases resource if no more communication
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_swi_gpio_release(void *hal_data)
{
    return ATCA_SUCCESS;
}
