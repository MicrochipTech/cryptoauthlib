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

#ifdef ATCA_TEST_MULTIPLE_INSTANCES
#include "atca_devcfg_list.h"
#endif

#ifdef ATCA_HAL_CUSTOM
extern int select_204_custom(int argc, char* argv[]);
extern int select_206_custom(int argc, char* argv[]);
extern int select_108_custom(int argc, char* argv[]);
extern int select_508_custom(int argc, char* argv[]);
extern int select_608_custom(int argc, char* argv[]);
extern int select_ta100_custom(int argc, char* argv[]);
extern int select_ecc204_custom(int argc, char* argv[]);
extern int select_ta010_custom(int argc, char* argv[]);
extern int select_sha104_custom(int argc, char* argv[]);
extern int select_sha105_custom(int argc, char* argv[]);
#endif

#ifdef ATCA_HAL_KIT_BRIDGE
/** The bridging protocol doesn't control the "physical" interface so to start
    the connection inside the test application it needs to be linked to
    something that exposes the following function */
extern ATCA_STATUS hal_kit_bridge_connect(ATCAIfaceCfg *, int, char **);
#endif

//#if defined(__linux__) && (defined(ATCA_HAL_SWI_UART) || defined(ATCA_HAL_KIT_UART))
#ifdef __linux__
/** In order to access the uart on linux the full device path needs to be known */
static char opt_device_name[20];
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
#ifdef ATCA_ENABLE_DEPRECATED
            .slave_address = 0xC0,
#else
            .address       = 0xC0,
#endif
            .bus           = 2,
            .baud          = 400000,
        },
#endif
    },
    .wake_delay            = 1500,
    .rx_retries            = 20
};

ATCAIfaceCfg* gCfg = &g_iface_config;

static void print_args(const char * f, int argc, char* argv[])
{
    int i;

    printf("Called from %s with %d args: ", f, argc);
    for (i = 0; i < argc; i++, argv++)
    {
        printf("%s ", *argv);
    }
    printf("\n");
}

/** \brief Retrieves the currently configured device
 *
 */
ATCADeviceType atca_test_get_device_type(void)
{
    return (NULL != gCfg) ? gCfg->devtype : ATCA_DEV_UNKNOWN;
}

/** \brief Configured device is ECC608 */
bool atca_test_cond_ecc608(void)
{
    return ATECC608 == atca_test_get_device_type();
}

/** \brief Configured device is TA100 */
bool atca_test_cond_ta100(void)
{
    return atcab_is_ta_device(atca_test_get_device_type());
}

/** \brief Configured device supports all EC p256 operations
 *
 */
bool atca_test_cond_p256_all(void)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ATECC108A == dev_type)
           || (ATECC508A == dev_type)
           || (ATECC608 == dev_type)
           || atcab_is_ta_device(dev_type);
}

/** \brief Configured device supports EC p256 sign operations
 *
 */
bool atca_test_cond_p256_sign(void)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ATECC108A == dev_type)
           || (ATECC508A == dev_type)
           || (ATECC608 == dev_type)
           || (ECC204 == dev_type)
           || (TA010 == dev_type)
           || atcab_is_ta_device(dev_type);
}

/** \brief Configured device supports EC p256 sign & verify operations */
bool atca_test_cond_p256_sign_verify(void)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ATECC108A == dev_type)
           || (ATECC508A == dev_type)
           || (ATECC608 == dev_type)
           || atcab_is_ta_device(dev_type);
}

/** \brief Configured device supports AES128 ECB operations */
bool atca_test_cond_aes128_ecb(void)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ATECC608 == dev_type) || atcab_is_ta_device(dev_type);
}

/** \brief Configured device is a second generation cryptoauth part */
bool atca_test_cond_ca2(void)
{
    return atcab_is_ca2_device(atca_test_get_device_type());
}

/** \brief Sets the device the command or test suite will use
 *
 * \param[in]  ifacecfg    Platform iface config to use
 */
void atca_test_config_set_ifacecfg(ATCAIfaceCfg * ifacecfg)
{
    (void)memmove(gCfg, ifacecfg, sizeof(ATCAIfaceCfg));
}

#ifdef ATCA_HAL_CUSTOM
static int select_custom(int argc, char* argv[])
{
    int ret;

    switch (gCfg->devtype)
    {
#ifdef ATCA_ATSHA204A_SUPPORT
    case ATSHA204A:
        ret = select_204_custom(argc, argv);
        break;
#endif
#ifdef ATCA_ATECC108A_SUPPORT
    case ATECC108A:
        ret = select_108_custom(argc, argv);
        break;
#endif
#ifdef ATCA_ATECC508A_SUPPORT
    case ATECC508A:
        ret = select_508_custom(argc, argv);
        break;
#endif
#ifdef ATCA_ATECC608_SUPPORT
    case ATECC608:
        ret = select_608_custom(argc, argv);
        break;
#endif
#ifdef ATCA_ATSHA206A_SUPPORT
    case ATSHA206A:
        ret = select_204_custom(argc, argv);
        break;
#endif
#ifdef ATCA_ECC204_SUPPORT
    case ECC204:
        ret = select_ecc204_custom(argc, argv);
        break;
#endif
#ifdef ATCA_TA010_SUPPORT
    case TA010:
        ret = select_ta010_custom(argc, argv);
        break;
#endif
#ifdef ATCA_SHA104_SUPPORT
    case SHA104:
        ret = select_sha104_custom(argc, argv);
        break;
#endif
#ifdef ATCA_SHA105_SUPPORT
    case SHA105:
        ret = select_sha105_custom(argc, argv);
        break;
#endif
#ifdef ATCA_TA100_SUPPORT
    case TA100:
        ret = select_ta100_custom(argc, argv);
        break;
#endif
    default:
        ret = -1;
        break;
    }
    return ret;
}
#endif

static int select_device_internal(int argc, char* argv[], bool interactive)
{
    int ret = -1;

    if (argc)
    {
        if (ATCA_DEV_UNKNOWN != (gCfg->devtype = iface_get_device_type_by_name(argv[0])))
        {
            ret = 0;
        }
    }

#ifdef ATCA_HAL_CUSTOM
    if (!ret)
    {
        ret = select_custom(argc, argv);
    }
#endif

    if (!ret && interactive)
    {
        printf("Device Selected.\n");
    }

    return ret;
}

/** \brief Select a device by it's name - expects one argument */
int select_device(int argc, char* argv[])
{
    return select_device_internal(argc, argv, true);
}

/** \brief Process an individual command option
 * \return Number of arguments parsed from the list or an error
 */
static int process_option(
    const t_menu_info_simple * list,    /**< [in] List of options */
    int                        argc,    /**< [in] Number of arguments in the arg list */
    char*                      argv[]   /**< [in] Argument list */
    )
{
    int ret = -1;
    const t_menu_info_simple * pList = list;

    if (pList)
    {
        if (argc)
        {
            for (; pList->menu_cmd; pList++)
            {
                if (!strcmp(pList->menu_cmd, argv[0]))
                {
                    if (pList->fp_handler)
                    {
                        if (0 < (ret = pList->fp_handler(argc - 1, &argv[1])))
                        {
                            ret = argc;
                        }
                    }
                    break;
                }
            }
        }
        else
        {
            ret = 0;
        }
        if (!ret)
        {
#ifdef ATCA_PRINTF
            /* */
            pList = list;
            for (; pList->menu_cmd; pList++)
            {

            }
#endif
        }
    }
    return ret;
}

/** \brief Sets the device the command or test suite will use
 *
 * \param[in]  argc     Number of arguments in the arg list
 * \param[out] argv     Argument list
 * \return Number of arguments parsed
 */
static int opt_device_type(int argc, char* argv[])
{
    return select_device_internal(argc, argv, false);
}

/** \brief Map the name of an iterface to the enum */
static ATCAKitType opt_get_kit_iface_type(const char * kit_iface_type_name)
{
    ATCAKitType ret = ATCA_KIT_AUTO_IFACE;

    if (kit_iface_type_name)
    {
        if (lib_strcasestr(kit_iface_type_name, "i2c"))
        {
            ret = ATCA_KIT_I2C_IFACE;
        }
        else if (lib_strcasestr(kit_iface_type_name, "spi"))
        {
            ret = ATCA_KIT_SPI_IFACE;
        }
        else if (lib_strcasestr(kit_iface_type_name, "swi"))
        {
            ret = ATCA_KIT_SWI_IFACE;
        }
    }
    return ret;
}

#ifdef ATCA_HAL_KIT_HID
/** \brief Configure the hid hal */
static int opt_iface_hid(int argc, char* argv[])
{
    ((void)argc);

    gCfg->iface_type = ATCA_HID_IFACE;

    ATCA_IFACECFG_VALUE(gCfg, atcahid.idx) = 0;
    ATCA_IFACECFG_VALUE(gCfg, atcahid.vid) = 0x03EB;
    ATCA_IFACECFG_VALUE(gCfg, atcahid.pid) = 0x2312;
    ATCA_IFACECFG_VALUE(gCfg, atcahid.packetsize) = 64;

    ATCA_IFACECFG_VALUE(gCfg, atcahid.dev_interface) = opt_get_kit_iface_type(argv[0]);
    ATCA_IFACECFG_VALUE(gCfg, atcahid.dev_identity) = 0;

    return 0;
}
#endif

#ifdef ATCA_HAL_I2C
/** \brief Configure the i2c hal */
static int opt_iface_i2c(int argc, char* argv[])
{
    int ret = -1;

    gCfg->iface_type = ATCA_I2C_IFACE;

    if (argc)
    {
        ATCA_IFACECFG_VALUE(gCfg, atcai2c.bus) = (uint8_t)strtol(argv[0], NULL, 10);
        ret = 0;
    }

    if (1 < argc)
    {
#ifdef __linux__
        ATCA_IFACECFG_VALUE(gCfg, atcai2c.baud) = 100000;
#else
        ATCA_IFACECFG_VALUE(gCfg, atcai2c.baud) = (uint32_t)strtol(argv[1], NULL, 10);
#endif
    }

    return ret;
}
#endif

#if defined(ATCA_HAL_SWI_UART) || defined(ATCA_HAL_SWI_GPIO) || defined(ATCA_HAL_SWI_BB)
/** \brief Configure the swi hal */
static int opt_iface_swi(int argc, char* argv[])
{
    int ret = -1;

    gCfg->iface_type = ATCA_SWI_IFACE;

    if (argc)
    {
#ifdef __linux__
        size_t len = strlen(argv[0]);
        if (len < sizeof(opt_device_name) - 1)
        {
            memcpy(opt_device_name, argv[0], len);
            opt_device_name[len] = '\0';
            gCfg->cfg_data = opt_device_name;
        }
#else
        ATCA_IFACECFG_VALUE(gCfg, atcaswi.bus) = (uint8_t)strtol(argv[0], NULL, 10);
#endif
        ret = 0;
    }

    return ret;
}
#endif

#ifdef ATCA_HAL_SPI
/** \brief Configure the spi hal */
static int opt_iface_spi(int argc, char* argv[])
{
    int ret = 0;

    gCfg->iface_type = ATCA_SPI_IFACE;

    if (argc)
    {
        ATCA_IFACECFG_VALUE(gCfg, atcaspi.bus) = (uint8_t)strtol(argv[0], NULL, 16);
    }
    else
    {
        ATCA_IFACECFG_VALUE(gCfg, atcaspi.bus) = 0;
    }

    if (1 < argc)
    {
        ATCA_IFACECFG_VALUE(gCfg, atcaspi.select_pin) = (uint8_t)strtol(argv[1], NULL, 16);
    }
    else
    {
        ATCA_IFACECFG_VALUE(gCfg, atcaspi.select_pin) = 0;
    }

    if (2 < argc)
    {
        ATCA_IFACECFG_VALUE(gCfg, atcaspi.baud) = (uint32_t)strtol(argv[2], NULL, 10);
    }
    else
    {
        ATCA_IFACECFG_VALUE(gCfg, atcaspi.baud) = 200000;
    }

    return ret;
}
#endif

#ifdef ATCA_HAL_KIT_UART
/** \brief Configure the kit uart hal */
static int opt_iface_uart(int argc, char* argv[])
{
    int ret = -1;

    gCfg->iface_type = ATCA_UART_IFACE;
    ATCA_IFACECFG_VALUE(gCfg, atcauart.dev_interface) = ATCA_KIT_AUTO_IFACE;
    ATCA_IFACECFG_VALUE(gCfg, atcauart.dev_identity) = 0;

    if (argc)
    {
        /* Port/Device */
#ifdef __linux__
        size_t len = strlen(argv[0]);
        if (len < sizeof(opt_device_name))
        {
            memcpy(opt_device_name, argv[0], len);
            gCfg->cfg_data = opt_device_name;
        }
#else
        ATCA_IFACECFG_VALUE(gCfg, atcauart.port) = (uint8_t)strtol(argv[0], NULL, 10);
#endif
        ret = 0;
    }

    if (1 < argc)
    {
        /* Baud rate */
        ATCA_IFACECFG_VALUE(gCfg, atcauart.baud) = (uint8_t)strtol(argv[1], NULL, 10);
    }
    else
    {
        ATCA_IFACECFG_VALUE(gCfg, atcauart.baud) = 115200UL;
    }

    if (2 < argc)
    {
        /* Word size */
        ATCA_IFACECFG_VALUE(gCfg, atcauart.wordsize) = (uint8_t)strtol(argv[2], NULL, 10);
    }
    else
    {
        ATCA_IFACECFG_VALUE(gCfg, atcauart.wordsize) = 8;
    }

    if (3 < argc)
    {
        /* Stop Bits */
        ATCA_IFACECFG_VALUE(gCfg, atcauart.stopbits) = (uint8_t)strtol(argv[3], NULL, 10);
    }
    else
    {
        ATCA_IFACECFG_VALUE(gCfg, atcauart.stopbits) = 1;
    }

    if (4 < argc)
    {
        /* Parity Bits */
        //gCfg->atcauart.parity = (uint8_t)strtol(argv[4], NULL, 16);
    }
    else
    {
        ATCA_IFACECFG_VALUE(gCfg, atcauart.parity) = 2;
    }

    return ret;
}
#endif

#ifdef ATCA_HAL_KIT_BRIDGE
/** \brief Configure the bridge hal - requires hal_kit_bridge_connect to be
 * linked into the application */
static int opt_iface_bridge(int argc, char* argv[])
{
    int ret = -1;

    gCfg->iface_type = ATCA_KIT_IFACE,
    ATCA_IFACECFG_VALUE(gCfg, atcakit.dev_interface) = ATCA_KIT_AUTO_IFACE;
    ATCA_IFACECFG_VALUE(gCfg, atcakit.dev_identity) = 0;

    if (ATCA_SUCCESS == hal_kit_bridge_connect(gCfg, argc, argv))
    {
        ret = 0;
    }

    return ret;
}
#endif

/** List of support interface types */
static t_menu_info_simple opt_iface_type_list[] = {
#ifdef ATCA_HAL_KIT_HID
    MENU_ITEM_SIMPLE("hid",    opt_iface_hid),
#endif
#ifdef ATCA_HAL_I2C
    MENU_ITEM_SIMPLE("i2c",    opt_iface_i2c),
#endif
#if defined(ATCA_HAL_SWI_UART) || defined(ATCA_HAL_SWI_GPIO) || defined(ATCA_HAL_SWI_BB)
    MENU_ITEM_SIMPLE("swi",    opt_iface_swi),
#endif
#ifdef ATCA_HAL_SPI
    MENU_ITEM_SIMPLE("spi",    opt_iface_spi),
#endif
#ifdef ATCA_HAL_KIT_UART
    MENU_ITEM_SIMPLE("uart",   opt_iface_uart),
#endif
#ifdef ATCA_HAL_KIT_BRIDGE
    MENU_ITEM_SIMPLE("bridge", opt_iface_bridge),
#endif
    MENU_ITEM_SIMPLE(NULL,     NULL)
};

#ifdef ATCA_TEST_MULTIPLE_INSTANCES
static void select_dev_cfg_data()
{
    size_t num_of_elements;
    int i;

    num_of_elements = sizeof(devcfg_list) / sizeof(devcfg_list[0]);
    for (i = 0; i < num_of_elements; i++)
    {
        if ((gCfg->iface_type == ATCA_I2C_IFACE) && (devcfg_list[i]->iface_type == ATCA_I2C_IFACE))
        {
#ifdef ATCA_ENABLE_DEPRECATED
            if (gCfg->atcai2c.slave_address == devcfg_list[i]->atcai2c.slave_address)
#else
            if (gCfg->atcai2c.address == devcfg_list[i]->atcai2c.address)
#endif
            {
                gCfg->cfg_data = devcfg_list[i]->cfg_data;
            }
        }
        else if ((gCfg->iface_type == ATCA_SPI_IFACE) && (devcfg_list[i]->iface_type == ATCA_SPI_IFACE))
        {
            if (gCfg->atcaspi.select_pin == devcfg_list[i]->atcaspi.select_pin)
            {
                gCfg->cfg_data = devcfg_list[i]->cfg_data;
            }
        }
        else if ((gCfg->iface_type == ATCA_SWI_IFACE) && (devcfg_list[i]->iface_type == ATCA_SWI_IFACE))
        {
            if (gCfg->atcaswi.bus == devcfg_list[i]->atcaswi.bus)
            {
                gCfg->cfg_data = devcfg_list[i]->cfg_data;
            }
        }
    }
}
#endif

/** \brief Sets the interface the command or test suite will use
 *
 * \param[in]  argc     Number of arguments in the arg list
 * \param[out] argv     Argument list
 * \return Number of arguments parsed
 */
static int opt_iface_type(int argc, char* argv[])
{
    int ret = process_option(opt_iface_type_list, argc, argv);

#ifdef ATCA_TEST_MULTIPLE_INSTANCES
    select_dev_cfg_data();
#endif
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
    uint8_t address = 0;
    ATCAKitType kit_type = ATCA_KIT_UNKNOWN_IFACE;

    if (argc)
    {
        address = (uint8_t)strtol(argv[0], NULL, 16);
    }
    else
    {
        ret = -1;
    }

    if (1 < argc)
    {
        if (ifacetype_is_kit(gCfg->iface_type))
        {
            kit_type = opt_get_kit_iface_type(argv[1]);
        }
    }

    (void)ifacecfg_set_address(gCfg, address, kit_type);

#ifdef ATCA_TEST_MULTIPLE_INSTANCES
    select_dev_cfg_data();
#endif

    return ret;
}

static int opt_quiet(int argc, char* argv[])
{
    print_args(__func__, argc, argv);
    ((void)argc);
    ((void)argv);
    g_atca_test_quiet_mode = true;
    return 1;
}

/** \brief Options support for the command line - '-p' is reserved to
 * stop any argument parsing and to pass the remaining arguments through
 * to the command itself */
static const t_menu_info_simple cmd_options[] =
{
    MENU_ITEM_SIMPLE("-d", opt_device_type),
    MENU_ITEM_SIMPLE("-i", opt_iface_type),
    MENU_ITEM_SIMPLE("-a", opt_address),
    MENU_ITEM_SIMPLE("-y", opt_quiet),
    MENU_ITEM_SIMPLE(NULL, NULL)
};

/** \brief Helper function to count parameters before another
    argument is encountered */
static inline int process_options_count_params(int argc, char* argv[])
{
    int i = 1;

    if (argv)
    {
        for (; i < argc && argv[i] && argv[i][0] != '-'; i++)
        {
            ;
        }
    }
    return i;
}

/** \brief Iterate through and argument list and process all options
 *
 * \param[in]  argc     Number of arguments in the arg list
 * \param[out] argv     Argument list
 * \return              Error (<0) or remaining arguments
 */
int process_options(int argc, char* argv[])
{
    int ret = -1;

    if (argc && argv)
    {
        char** pargv = argv;
        do
        {
            int opt_argc = process_options_count_params(argc, pargv);
            if (!strcmp("-p", *pargv))
            {
                /* Special command at the end the parsing and passthrough
                    arguments to the test framework */
                int i;
                pargv++;
                --argc;
                for (i = 0; i < argc; i++)
                {
                    argv[i] = pargv[i];
                }
                ret = 0;
                break;
            }
            else if (0 <= (ret = process_option(cmd_options, opt_argc, pargv)))
            {
                argc -= opt_argc;
                pargv += opt_argc;
            }
        }
        while (argc > 0 && ret >= 0 && *pargv);
    }
    else if (!argc)
    {
        ret = 0;
    }

    return (0 > ret) ? ret : argc;
}
