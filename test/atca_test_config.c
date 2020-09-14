/**
 * \file
 * \brief  Cryptoauthlib Testing: Suite Runtime Configuration
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

#include "atca_test.h"
#include "cryptoauthlib.h"
#include "cmd-processor.h"

#ifdef ATCA_HAL_CUSTOM
extern int select_204_custom(int argc, char* argv[]);
extern int select_108_custom(int argc, char* argv[]);
extern int select_508_custom(int argc, char* argv[]);
extern int select_608_custom(int argc, char* argv[]);
extern int select_ta100_custom(int argc, char* argv[]);
#endif

/** gCfg must point to one of the cfg_ structures for any unit test to work.  this allows
   the command console to switch device types at runtime. */
ATCAIfaceCfg g_iface_config = {
#ifdef ATCA_HAL_KIT_HID
    .iface_type            = ATCA_HID_IFACE,
#else
    .iface_type            = ATCA_UNKNOWN_IFACE,
#endif
    .devtype               = ATCA_DEV_UNKNOWN,
    {
#ifdef ATCA_HAL_KIT_HID
        .atcahid           = {
            .dev_identity  = 0,
            .idx           = 0,
            .vid           = 0x03EB,
            .pid           = 0x2312,
            .packetsize    = 64,
        },
#else
        .atcai2c           = {
            .slave_address = 0xC0,
            .bus           = 2,
            .baud          = 400000,
        },
#endif
    },
    .wake_delay            = 1500,
    .rx_retries            = 20
};

ATCAIfaceCfg* gCfg = &g_iface_config;

/** \brief Sets the device the command or test suite will use
 *
 * \param[in]  ifacecfg    Platform iface config to use
 */
void atca_test_config_set_ifacecfg(ATCAIfaceCfg * ifacecfg)
{
    (void)memmove(gCfg, ifacecfg, sizeof(ATCAIfaceCfg));
}

static int select_device(ATCADeviceType device_type, bool interative)
{
    gCfg->devtype = device_type;
    if (interative)
    {
        printf("Device Selected.\r\n");
    }
    return 0;
}

int select_204(int argc, char* argv[])
{
#if defined(ATCA_HAL_CUSTOM) && defined(ATCA_ATSHA204A_SUPPORT)
    return select_204_custom(argc, argv);
#else
    return select_device(ATSHA204A, NULL != argv);
#endif
}

int select_206(int argc, char* argv[])
{
#if defined(ATCA_HAL_CUSTOM) && defined(ATCA_ATSHA206A_SUPPORT)
    return select_206_custom(argc, argv);
#else
    return select_device(ATSHA206A, NULL != argv);
#endif
}

int select_108(int argc, char* argv[])
{
#if defined(ATCA_HAL_CUSTOM) && defined(ATCA_ATECC108A_SUPPORT)
    return select_108_custom(argc, argv);
#else
    return select_device(ATECC108A, NULL != argv);
#endif
}

int select_508(int argc, char* argv[])
{
#if defined(ATCA_HAL_CUSTOM) && defined(ATCA_ATECC508A_SUPPORT)
    return select_508_custom(argc, argv);
#else
    return select_device(ATECC508A, NULL != argv);
#endif
}

int select_608(int argc, char* argv[])
{
#if defined(ATCA_HAL_CUSTOM) && defined(ATCA_ATECC608_SUPPORT)
    return select_608_custom(argc, argv);
#else
    return select_device(ATECC608, NULL != argv);
#endif
}

int select_ta100(int argc, char* argv[])
{
#if defined(ATCA_HAL_CUSTOM) && defined(ATCA_TA100_SUPPORT)
    return select_ta100_custom(argc, argv);
#else
    return select_device(TA100, NULL != argv);
#endif
}

/** \brief Sets the device the command or test suite will use
 *
 * \param[in]  argc     Number of arguments in the arg list
 * \param[out] argv     Argument list
 * \return Number of arguments parsed
 */
static int opt_device_type(int argc, char* argv[])
{
    int ret = 0;

    if (argc >= 2)
    {
        if (0 == strcmp("sha204", argv[1]))
        {
            select_204(0, NULL);
        }
        else if (0 == strcmp("sha206", argv[1]))
        {
            select_206(0, NULL);
        }
        else if (0 == strcmp("ecc108", argv[1]))
        {
            select_108(0, NULL);
        }
        else if (0 == strcmp("ecc508", argv[1]))
        {
            select_508(0, NULL);
        }
        else if (0 == strcmp("ecc608", argv[1]))
        {
            select_608(0, NULL);
        }
        else if (0 == strcmp("ta100", argv[1]))
        {
            select_ta100(0, NULL);
        }
        ret = 2;
    }
    return ret;
}

/** \brief Sets the interface the command or test suite will use
 *
 * \param[in]  argc     Number of arguments in the arg list
 * \param[out] argv     Argument list
 * \return Number of arguments parsed
 */
static int opt_iface_type(int argc, char* argv[])
{
    int ret = 0;

    if (argc >= 2)
    {
        ret = 2;

        if (0 == strcmp("hid", argv[1]))
        {
            gCfg->iface_type = ATCA_HID_IFACE;
            gCfg->atcahid.dev_identity = 0;
            gCfg->atcahid.idx = 0;
            gCfg->atcahid.vid = 0x03EB;
            gCfg->atcahid.pid = 0x2312;
            gCfg->atcahid.packetsize = 64;

            if (argc >= 3 && argv[2][0] != '-')
            {
                ret = 3;
                if (0 == strcmp("i2c", argv[2]))
                {
                    gCfg->atcahid.dev_interface = ATCA_KIT_I2C_IFACE;
                }
                else if (0 == strcmp("swi", argv[2]))
                {
                    gCfg->atcahid.dev_interface = ATCA_KIT_SWI_IFACE;
                }
                //else if (0 == strcmp("spi", argv[2]))
                //{
                //    gCfg->atcahid.dev_interface = ATCA_KIT_SPI_IFACE;
                //}
            }
            else
            {
                gCfg->atcahid.dev_interface = ATCA_KIT_AUTO_IFACE;
            }
        }
        else if (0 == strcmp("i2c", argv[1]))
        {
#ifdef ATCA_HAL_I2C
            gCfg->iface_type = ATCA_I2C_IFACE;

            if (argc >= 3 && argv[2][0] != '-')
            {
                uint32_t val = strtol(argv[2], NULL, 16);
                gCfg->atcai2c.bus = (uint8_t)val;
                ret = 3;
            }
#ifdef __linux__
            gCfg->atcai2c.baud = 100000;
#endif
#endif      /* ATCA_HAL_KIT_HID */
        }
        else if (0 == strcmp("swi", argv[1]))
        {
            gCfg->iface_type = ATCA_SWI_IFACE;

            if (argc >= 3 && argv[2][0] != '-')
            {
                uint32_t val = strtol(argv[2], NULL, 16);
                gCfg->atcaswi.bus = (uint8_t)val;
                ret = 3;
            }
        }
        else if (0 == strcmp("spi", argv[1]))
        {
            gCfg->iface_type = ATCA_SPI_IFACE;

            if (argc >= 3 && argv[2][0] != '-')
            {
                gCfg->atcaspi.bus = (uint8_t)strtol(argv[2], NULL, 16);
                ret = 3;
            }
            else
            {
                gCfg->atcaspi.bus = 0;
            }

            if (argc >= 4 && argv[3][0] != '-')
            {
                gCfg->atcaspi.select_pin = (uint8_t)strtol(argv[3], NULL, 16);
            }
            else
            {
                gCfg->atcaspi.select_pin = 0;
            }

            if (argc >= 5 && argv[4][0] != '-')
            {
                gCfg->atcaspi.baud = (uint32_t)strtol(argv[4], NULL, 10);
            }
            else
            {
                gCfg->atcaspi.baud = 200000;
            }
        }
    }
    return ret;
}

/** \brief Sets the device address based on interface type (this option must be provided after
 * specifying the interface type otherwise it might produce unexpected results).
 *
 * \param[in]  argc     Number of arguments in the arg list
 * \param[out] argv     Argument list
 * \return Number of arguments parsed
 */
static int opt_address(int argc, char* argv[])
{
    int ret = 0;

    if (argc >= 2)
    {
        uint32_t val = strtol(argv[1], NULL, 16);
        if (ATCA_HID_IFACE == gCfg->iface_type)
        {
            gCfg->atcahid.dev_identity = (uint8_t)val;
        }
        else if (ATCA_I2C_IFACE == gCfg->iface_type)
        {
            gCfg->atcai2c.slave_address = (uint8_t)val;
        }

        ret = 2;
    }
    return ret;
}

static int opt_quiet(int argc, char* argv[])
{
    g_atca_test_quiet_mode = true;
    return 1;
}

// *INDENT-OFF*  - Preserve formatting
static t_menu_info cmd_options[] =
{
    { "-d",       "device type",       opt_device_type                      },
    { "-i",       "interface",         opt_iface_type                       },
    { "-a",       "address",           opt_address                          },
    { "-y",       "silence prompts (implicit agreement)",   opt_quiet       },
    { NULL,       NULL,                NULL                                 },
};
// *INDENT-ON*

/** \brief Process an individual command option
 *
 * \param[in]  argc     Number of arguments in the arg list
 * \param[out] argv     Argument list
 * \return Number of arguments parsed from the list
 */
static int process_option(int argc, char* argv[])
{
    t_menu_info* menu_item = cmd_options;
    int ret = -1;

    if (argc)
    {
        do
        {
            if (0 == strcmp(menu_item->menu_cmd, argv[0]))
            {
                if (menu_item->fp_handler)
                {
                    ret = menu_item->fp_handler(argc, argv);
                }
                break;
            }
        }
        while ((++menu_item)->menu_cmd);
    }
    return ret;
}

/** \brief Iterate through and argument list and process all options
 *
 * \param[in]  argc     Number of arguments in the arg list
 * \param[out] argv     Argument list
 * \return Number of arguments parsed from the list
 */
int process_options(int argc, char* argv[])
{
    int ret;
    int cur_arg = 0;

    do
    {
        ret = process_option(argc - cur_arg, &argv[cur_arg]);
        cur_arg += ret;
    }
    while (argc > cur_arg && ret >= 0);

    return ret;
}
