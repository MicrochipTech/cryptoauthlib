/**
 * \file
 *
 * \brief  KIT protocol intepreter
 *
 * \copyright (c) 2018 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2018 Microchip Technology Inc. and its subsidiaries. You may use this
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

#include <ctype.h>

#include "ascii_kit_host.h"
#include "hal/kit_protocol.h"

/** \brief Send bytes through a cryptoauthlib hal */
static ATCA_STATUS kit_host_send_data(void* ctx, uint8_t* txdata, uint16_t txlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    atca_hal_kit_phy_t * phy = (atca_hal_kit_phy_t*)ctx;

    if (phy)
    {
        ATCAIface iface = (ATCAIface)phy->hal_data;
        if (iface)
        {
            if (iface->phy)
            {
                status = iface->phy->halsend(iface, 0, txdata, txlen);
            }
            else if (iface->hal)
            {
                status = iface->hal->halsend(iface, 0, txdata, txlen);
            }
        }
    }
    return status;
}

/** \brief Receive bytes from a cryptoauthlib hal */
static ATCA_STATUS kit_host_recv_data(void* ctx, uint8_t* rxdata, uint16_t* rxlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    atca_hal_kit_phy_t* phy = (atca_hal_kit_phy_t*)ctx;

    if (phy)
    {
        ATCAIface iface = (ATCAIface)phy->hal_data;
        if (iface)
        {
            if (iface->phy)
            {
                status = iface->phy->halreceive(iface, 0, rxdata, rxlen);
            }
            else if (iface->hal)
            {
                status = iface->hal->halreceive(iface, 0, rxdata, rxlen);
            }
        }
    }
    return status;
}


/** \brief Initializes a phy structure with a cryptoauthlib hal adapter
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS kit_host_init_phy(
    atca_hal_kit_phy_t* phy,
    ATCAIface           iface
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (phy && iface)
    {
        if (ATCA_SUCCESS == (status = hal_iface_init(iface->mIfaceCFG, &iface->hal, &iface->phy)))
        {
            phy->hal_data = iface;
            phy->send = kit_host_send_data;
            phy->recv = kit_host_recv_data;
        }
    }
    return status;
}

/** \brief Initializes the kit protocol parser context
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS kit_host_init(
    ascii_kit_host_context_t * ctx,         /**< Kit protocol parser context */
    ATCAIfaceCfg *             iface[],     /**< List of device configurations which will be used */
    const size_t               iface_count, /**< Number of configurations provided */
    const atca_hal_kit_phy_t*  phy,         /**< Kit protocol physical adapter */
    const uint32_t             flags        /**< Option Flags */
    )
{
    ATCA_STATUS ret = ATCA_BAD_PARAM;

    if (ctx && iface && iface_count && phy)
    {
        ctx->iface = iface;
        ctx->iface_count = iface_count;
        ctx->phy = phy;
        ctx->flags = (uint32_t)flags;
        ret = ATCA_SUCCESS;
    }
    return ret;
}

static const char* kit_host_get_iface_type(ATCAIfaceType iface_type)
{
    char* ret = "unknown";

    switch (iface_type)
    {
    case ATCA_I2C_IFACE:
        ret = "TWI";
        break;
    case ATCA_SWI_IFACE:
        ret = "SWI";
        break;
    case ATCA_SPI_IFACE:
        ret = "SPI";
        break;
    default:
        break;
    }

    return ret;
}

static uint8_t kit_host_get_device_id(ATCAIfaceCfg * cfg)
{
    uint8_t id = 0;

    if (cfg)
    {
        switch (cfg->iface_type)
        {
        case ATCA_I2C_IFACE:
            id = cfg->atcai2c.address;
            break;
        case ATCA_SWI_IFACE:
            id = cfg->atcaswi.address;
            break;
        case ATCA_SPI_IFACE:
            id = cfg->atcaspi.select_pin;
            break;
        default:
            break;
        }
    }
    return id;
}

/** \brief Format the status and data into the kit protocol response format */
size_t kit_host_format_response(uint8_t* response, size_t rlen, ATCA_STATUS status, uint8_t* data, size_t dlen)
{
    char* ptr = (char*)response;
    size_t ret = rlen;

    if (ATCA_SUCCESS == atcab_bin2hex_(&status, sizeof(uint8_t), (char*)ptr, &ret, false, false, true))
    {
        ptr += ret;
        *ptr++ = '(';
        if (data && dlen)
        {
            ret = rlen - (ptr - (char*)response);
            atcab_bin2hex_(data, dlen, ptr, &ret, false, false, true);
            ptr += ret;
        }
        *ptr++ = ')';
        *ptr++ = '\n';
        ret = ptr - (char*)response;
    }
    return ret;
}

/** \brief Iterate through a command list to match the given command and then will execute it */
ATCA_STATUS kit_host_process_cmd(
    ascii_kit_host_context_t* ctx,
    const kit_host_map_entry_t * cmd_list,
    int argc, char* argv[],
    uint8_t* response,
    size_t* rlen
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    const kit_host_map_entry_t* cmd;

    for (cmd = cmd_list; cmd->id && cmd->fp_command; cmd++)
    {
        if (!strncmp(cmd->id, argv[0], strlen(argv[0])))
        {
            status = cmd->fp_command(ctx, argc - 1, &argv[1], response, rlen);
            break;
        }
    }
    return status;
}

#if ATCA_CA_SUPPORT

static ATCA_STATUS kit_host_ca_wake(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    const uint8_t expected_response[4] = { 0x04, 0x11, 0x33, 0x43 };
    const uint8_t selftest_fail_resp[4] = { 0x04, 0x07, 0xC4, 0x40 };

    if (ctx && response && rlen)
    {
        status = calib_wakeup(ctx->device);
        if (ATCA_SUCCESS == status)
        {
            *rlen = kit_host_format_response(response, *rlen, status, (uint8_t*)expected_response, sizeof(expected_response));
        }
        else if (ATCA_STATUS_SELFTEST_ERROR == status)
        {
            *rlen = kit_host_format_response(response, *rlen, status, (uint8_t*)selftest_fail_resp, sizeof(selftest_fail_resp));
        }
        else
        {
            *rlen = kit_host_format_response(response, *rlen, status, NULL, 0);
        }
    }
    return status;
}

static ATCA_STATUS kit_host_ca_idle(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && response && rlen)
    {
        status = calib_idle(ctx->device);
        *rlen = 0;
    }

    return status;
}

static ATCA_STATUS kit_host_ca_sleep(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && response && rlen)
    {
        status = calib_sleep(ctx->device);
        *rlen = 0;
    }

    return status;
}

static ATCA_STATUS kit_host_ca_talk(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && argc && response && rlen)
    {
#ifdef __XC8        
        static ATCAPacket packet;
#else
        ATCAPacket packet;
#endif                
        size_t plen = sizeof(packet) - 2;

        atcab_hex2bin(argv[0], strlen(argv[0]), (uint8_t*)&packet.txsize, &plen);
        if (ATCA_SUCCESS == (status = calib_execute_command(&packet, ctx->device)))
        {
            *rlen = kit_host_format_response(response, *rlen, status, (uint8_t*)&packet.data, packet.data[0]);
        }
        else
        {
            *rlen = kit_host_format_response(response, *rlen, status, NULL, 0);
        }
#ifdef __XC8          
        (void)memset(&packet, 0, sizeof(ATCAPacket));
#endif        
    }
    return status;
}
#endif

static ATCA_STATUS kit_host_ca_select(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    ATCA_STATUS status = ATCA_FUNC_FAIL;

    if (argc > 0)
    {
        uint8_t id = (uint8_t)strtol(argv[0], NULL, 16);
        int i;

        for (i = 0; i < ctx->iface_count && status; i++)
        {
            ATCAIfaceCfg * cfg = ctx->iface[i];
            switch (cfg->iface_type)
            {
            case ATCA_I2C_IFACE:
                if (id == cfg->atcai2c.address)
                {
                    status = atcab_init_ext(&ctx->device, cfg);
                }
                break;
            case ATCA_SWI_IFACE:
                if (id == cfg->atcaswi.address)
                {
                    status = atcab_init_ext(&ctx->device, cfg);
                }
                break;
            case ATCA_SPI_IFACE:
                if (id == cfg->atcaspi.select_pin)
                {
                    status = atcab_init_ext(&ctx->device, cfg);
                }
                break;
            default:
                break;
            }
        }
    }

    *rlen = 0;
    return ATCA_SUCCESS;
}

#if ATCA_CA_SUPPORT
static kit_host_map_entry_t kit_host_ca_physical_map[] = {
    { "select", kit_host_ca_select },
    { NULL,     NULL               }
};

static ATCA_STATUS kit_host_ca_physical(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    return kit_host_process_cmd(ctx, kit_host_ca_physical_map, argc, argv, response, rlen);
}

/* Cryptoauth Device commands */
static kit_host_map_entry_t kit_host_ca_map[] = {
    { "wake",     kit_host_ca_wake     },
    { "idle",     kit_host_ca_idle     },
    { "sleep",    kit_host_ca_sleep    },
    { "talk",     kit_host_ca_talk     },
    { "physical", kit_host_ca_physical },
    { NULL,       NULL                 }
};

static ATCA_STATUS kit_host_process_ca(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    return kit_host_process_cmd(ctx, kit_host_ca_map, argc, argv, response, rlen);
}
#endif

#if ATCA_TA_SUPPORT
static ATCA_STATUS kit_host_ta_wake(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    *rlen = 0;
    return ATCA_SUCCESS;
}

static ATCA_STATUS kit_host_ta_idle(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    *rlen = 0;
    return ATCA_SUCCESS;
}

static ATCA_STATUS kit_host_ta_sleep(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    *rlen = 0;
    return ATCA_UNIMPLEMENTED;
}

static ATCA_STATUS kit_host_ta_talk(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && argc && response && rlen)
    {
        cal_buffer* packet = talib_packet_alloc();

        if (NULL != packet)
        {
            size_t plen = sizeof(ctx->buffer) - 2;
            packet->buf = ctx->buffer;

            atcab_hex2bin(argv[0], strlen(argv[0]), packet->buf, &plen);
            if (ATCA_SUCCESS == (status = talib_execute_command_raw(packet, ctx->device)))
            {

                *rlen = kit_host_format_response(response, *rlen, status, &packet->buf[PKT_CAL_BUF_DATA_IDX], packet->buf[2]);
            }
            else
            {
                *rlen = kit_host_format_response(response, *rlen, status, NULL, 0);
            }
        }
    }
    return status;
}

#include "talib/talib_fce.h"

static ATCA_STATUS kit_host_ta_send(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && argc && response && rlen)
    {
        size_t plen = sizeof(ctx->buffer) - 2;
        atcab_hex2bin(argv[0], strlen(argv[0]), ctx->buffer, &plen);

        uint8_t address = atgetifacecfg(&ctx->device->mIface)->atcai2c.address;

        (void)atcontrol(&ctx->device->mIface, ATCA_HAL_CONTROL_SELECT, NULL, 0);

        status = atsend(&ctx->device->mIface, address, ctx->buffer, plen);

        (void)atcontrol(&ctx->device->mIface, ATCA_HAL_CONTROL_DESELECT, NULL, 0);
        *rlen = 0;
    }
    return status;
}

static ATCA_STATUS kit_host_ta_receive(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    uint16_t rxdata_max_size = ATCA_RSP_DATA_MAX_LENGTH;
    uint16_t length_size = 2;
    uint16_t read_length = 0;

    if (ctx && argc && response && rlen)
    {
        do
        {
            size_t plen = sizeof(ctx->buffer) - 2;
            atcab_hex2bin(argv[0], strlen(argv[0]), ctx->buffer, &plen);

            uint8_t address = atgetifacecfg(&ctx->device->mIface)->atcai2c.address;
            uint8_t word_address = ctx->buffer[0];

            rxdata_max_size = ((uint16_t)ctx->buffer[1] * 256) + ctx->buffer[2];

            (void)atcontrol(&ctx->device->mIface, ATCA_HAL_CONTROL_SELECT, NULL, 0);

            if (ATCA_SUCCESS != (status = atsend(&ctx->device->mIface, address, &word_address, sizeof(word_address))))
            {
                return status;
            }

            /*Set read length.. Check for register reads or 1 byte reads*/
            if ((word_address == ATCA_MAIN_PROCESSOR_RD_CMD) || (word_address == 0xFF))
            {
                /* Read length bytes to know number of bytes to read */
                if (ATCA_SUCCESS != (status = atreceive(&ctx->device->mIface, address, &ctx->buffer[sizeof(ctx->buffer) / 2], &length_size)))
                {
                    break;
                }
                read_length = ((uint16_t)ctx->buffer[sizeof(ctx->buffer) / 2] * 256) + ctx->buffer[sizeof(ctx->buffer) / 2 + 1];

                if (read_length > rxdata_max_size)
                {
                    status = ATCA_SMALL_BUFFER;
                    break;
                }
                if (read_length < (3 + length_size))    //status(1) and CRC(2) size are same for CA and TA, length is variable.
                {
                    status = ATCA_RX_FAIL;
                    break;
                }

                /* Read given length bytes from device */
                read_length -= length_size;
                if (ATCA_SUCCESS != (status = atreceive(&ctx->device->mIface, address, &ctx->buffer[sizeof(ctx->buffer) / 2 + length_size],
                                                        &read_length)))
                {
                    break;
                }
                read_length += length_size;
            }
            else if ((word_address == ATCA_MAIN_PROCESSOR_RD_CSR) || (word_address == ATCA_FAST_CRYPTO_RD_FSR) ||
                     (rxdata_max_size == 1))
            {
                read_length = 1;
                length_size = 0;
                if (ATCA_SUCCESS != (status = atreceive(&ctx->device->mIface, address, &ctx->buffer[sizeof(ctx->buffer) / 2], &read_length)))
                {
                    break;
                }
            }
            else
            {
                read_length = rxdata_max_size;
                length_size = 0;
                if (ATCA_SUCCESS != (status = atreceive(&ctx->device->mIface, address, &ctx->buffer[sizeof(ctx->buffer) / 2], &read_length)))
                {
                    break;
                }
            }

            (void)atcontrol(&ctx->device->mIface, ATCA_HAL_CONTROL_DESELECT, NULL, 0);
        } while (0);
        if (ATCA_SUCCESS == status)
        {
            *rlen = kit_host_format_response(ctx->buffer, sizeof(ctx->buffer), status, &ctx->buffer[sizeof(ctx->buffer) / 2], read_length + length_size);
        }
        else
        {
            *rlen = 0;
        }
    }
    return status;
}

static kit_host_map_entry_t kit_host_ta_physical_map[] = {
    { "select", kit_host_ca_select },   /* Selection logic is the same */
    { NULL,     NULL               }
};

static ATCA_STATUS kit_host_ta_physical(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    return kit_host_process_cmd(ctx, kit_host_ta_physical_map, argc, argv, response, rlen);
}

static kit_host_map_entry_t kit_host_ta_map[] = {
    { "wake",     kit_host_ta_wake     },
    { "idle",     kit_host_ta_idle     },
    { "sleep",    kit_host_ta_sleep    },
    { "talk",     kit_host_ta_talk     },
    { "send",     kit_host_ta_send     },
    { "receive",  kit_host_ta_receive  },
    { "physical", kit_host_ta_physical },
    { NULL,       NULL                 }
};

ATCA_STATUS kit_host_process_ta(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    return kit_host_process_cmd(ctx, kit_host_ta_map, argc, argv, response, rlen);
}

#endif

static ATCA_STATUS kit_host_board_get_version(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    return ATCA_SUCCESS;
}

static ATCA_STATUS kit_host_board_get_firmware(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    return ATCA_SUCCESS;
}

static ATCA_STATUS kit_host_board_get_device(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    ATCA_STATUS status = ATCA_FUNC_FAIL;

    if (argc > 0)
    {
        uint8_t idx = (uint8_t)strtol(argv[0], NULL, 16);
        if (idx < ctx->iface_count)
        {
            ATCAIfaceCfg * cfg = ctx->iface[idx];

            *rlen = snprintf((char*)response, *rlen, "%s %s 00(%02X)\n", kit_id_from_devtype(cfg->devtype),
                             kit_host_get_iface_type(cfg->iface_type), kit_host_get_device_id(cfg));
            status = ATCA_SUCCESS;
        }
    }
    return status;
}


static kit_host_map_entry_t kit_host_board_map[] = {
    { "version",  kit_host_board_get_version  },
    { "firmware", kit_host_board_get_firmware },
    { "device",   kit_host_board_get_device   },
    { NULL,       NULL                        }
};

static ATCA_STATUS kit_host_process_board(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    return kit_host_process_cmd(ctx, kit_host_board_map, argc, argv, response, rlen);
}


static const kit_host_map_entry_t kit_host_target_map[] = {
    { "board", kit_host_process_board },
#if ATCA_CA_SUPPORT
    { "ecc",   kit_host_process_ca    },
    { "sha",   kit_host_process_ca    },
#endif
#if ATCA_TA_SUPPORT
    { "ta",    kit_host_process_ta    },
#endif
    { NULL,    NULL                   }
};

static ATCA_STATUS kit_host_process_target(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen)
{
    return kit_host_process_cmd(ctx, kit_host_target_map, argc, argv, response, rlen);
}

/** \brief Parse a line as a kit protocol command. The kit protocol is printable
 *  ascii and each line ends with a newline character */
ATCA_STATUS kit_host_process_line(
    ascii_kit_host_context_t* ctx,        /**< */
    uint8_t *                 input_line, /**< */
    size_t                    ilen,       /**< */
    uint8_t*                  response,   /**< */
    size_t*                   rlen        /**< */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    size_t i;
    char* ptr;
    int argc = 0;
    char* argv[4];

    if (ctx && input_line && ilen && response && rlen)
    {
        argc = 1;
        argv[0] = (char*)input_line;
        for (i = 0, ptr = (char*)input_line; i < ilen; i++, ptr++)
        {
            switch (*ptr)
            {
            case KIT_LAYER_DELIMITER:
            /* fallthrough */
            case KIT_DATA_BEGIN_DELIMITER:
                argv[argc++] = ptr + 1;
            /* fallthrough */
            case KIT_DATA_END_DELIMITER:
                *ptr = '\0';
                break;
            case KIT_MESSAGE_DELIMITER:
                status = kit_host_process_target(ctx, argc, argv, response, rlen);
                break;
            default:
                if (isalpha(*ptr))
                {
                    *ptr = tolower(*ptr);
                }
                break;
            }
        }
    }
    return status;
}

/** \brief Non returning kit protocol runner using the configured physical interface
   that was provided when the context was initialized */
void kit_host_task(ascii_kit_host_context_t* ctx)
{
    uint8_t* ptr = ctx->buffer;
    uint16_t rxlen = 1;
    size_t txlen;
    ATCA_STATUS status;

    for (;; )
    {
        if (ATCA_SUCCESS == ctx->phy->recv((void*)ctx->phy, ptr, &rxlen))
        {
            if (KIT_MESSAGE_DELIMITER == *ptr++)
            {
                txlen = sizeof(ctx->buffer);
                status = kit_host_process_line(ctx, ctx->buffer, ptr - ctx->buffer, ctx->buffer, &txlen);

                if ((ATCA_SUCCESS != status) || !txlen)
                {
                    txlen = snprintf((char*)ctx->buffer, sizeof(ctx->buffer), "%02X()\n", status);
                }
                ctx->phy->send((void*)ctx->phy, ctx->buffer, txlen);

                memset(ctx->buffer, '\0', sizeof(ctx->buffer));

                ptr = ctx->buffer;
            }
        }
    }
}
