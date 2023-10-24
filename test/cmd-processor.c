/** \file
 * \brief simple command processor for test console
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
// Undefine the Unity FAIL macro so it doesn't conflict with the ASF definition
#undef FAIL

#include <string.h>
#ifndef _WIN32
#include "cbuf.h"
#endif
#include "cryptoauthlib.h"
#include "atca_test.h"
#include "cmd-processor.h"
#include "atca_cfgs.h"

#if ATCA_CA_SUPPORT
#include "api_calib/test_calib.h"
#endif

#if ATCA_CA_SUPPORT && !defined(DO_NOT_TEST_CERT)
#include "atcacert/test_atcacert.h"
#endif

#if ATCA_TA_SUPPORT
#include "api_talib/test_talib.h"
#endif

/* Common API Testing - atcab_ is the classic Cryptoauthlib API */
#include "api_atcab/test_atcab.h"

/* Host side Cryptographic API Testing */
#include "api_crypto/test_crypto.h"

/* Library Integration Tests - Tests to ensure the library accesses device properly*/
#include "integration/test_integration.h"

/* JWT Support */
#include "jwt/test_jwt.h"

static int help(int argc, char* argv[]);

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
static int call_exit(int argc, char* argv[]);
#endif


// *INDENT-OFF*  - Preserve formatting
static t_menu_info mas_menu_info[] =
{
    { "help",     "Display Menu",                                   help                                 },
#ifdef ATCA_ATSHA204A_SUPPORT
    { "sha204",      "Set Target Device to ATSHA204A",              select_device                        },
#endif
#ifdef ATCA_ATSHA206A_SUPPORT
    { "sha206",      "Set Target Device to ATSHA206A",              select_device                        },
#endif
#ifdef ATCA_ATECC108A_SUPPORT
    { "ecc108",      "Set Target Device to ATECC108A",              select_device                        },
#endif
#ifdef ATCA_ECC204_SUPPORT
    { "ecc204",    "Set Target Device to ECC204",                   select_device                        },
#endif
#ifdef ATCA_TA010_SUPPORT
    { "ta010",     "Set Target Device to TA010",                    select_device                        },
#endif
#ifdef ATCA_SHA104_SUPPORT
    { "sha104",    "Set Target Device to SHA104",                   select_device                        },
#endif
#ifdef ATCA_SHA105_SUPPORT
    { "sha105",    "Set Target Device to SHA105",                   select_device                        },
#endif
#ifdef ATCA_ATECC508A_SUPPORT
    { "ecc508",      "Set Target Device to ATECC508A",              select_device                        },
#endif
#ifdef ATCA_ATECC608_SUPPORT
    { "ecc608",      "Set Target Device to ATECC608",               select_device                        },
#endif
#ifdef ATCA_TA100_SUPPORT
    { "ta100",    "Set Target Device to TA100",                     select_device                        },
#endif
    { "info",     "Get the Chip Revision",                          info                                 },
    { "sernum",   "Get the Chip Serial Number",                     read_sernum                          },
    { "rand",     "Generate Some Random Numbers",                   do_randoms                           },
    { "readcfg",  "Read the Config Zone",                           read_config                          },
    { "lockstat", "Zone Lock Status",                               lock_status                          },
#ifdef ATCA_TEST_LOCK_ENABLE
    { "lockcfg",  "Lock the Config Zone",                           lock_config                          },
    { "lockdata", "Lock Data and OTP Zones",                        lock_data                            },
    { "all",      "Run all unit tests, locking as needed.",         run_all_tests                        },
#endif
    { "tng",      "Run unit tests on TNG type part.",               run_tng_tests                        },
    { "wpc",      "Run unit tests on WPC type part.",               run_wpc_tests                        },
#ifndef DO_NOT_TEST_BASIC_UNIT
    { "basic",    "Run Basic Test on Selected Device",              run_basic_tests                      },
#ifdef ATCA_TEST_LOCK_ENABLE
    { "otpzero",  "Zero Out OTP Zone",                              run_otpzero_tests                    },
#endif
    { "util",     "Run Helper Function Tests",                      run_helper_tests                     },
#ifdef ATCA_ATECC608_SUPPORT
    { "clkdivm0", "Set ATECC608 to ClockDivider M0(0x00)",          set_clock_divider_m0                 },
    { "clkdivm1", "Set ATECC608 to ClockDivider M1(0x05)",          set_clock_divider_m1                 },
    { "clkdivm2", "Set ATECC608 to ClockDivider M2(0x0D)",          set_clock_divider_m2                 },
#endif
#endif /* DO_NOT_TEST_BASIC_UNIT */
#ifndef DO_NOT_TEST_CERT
    { "cd",       "Run Unit Tests on Cert Data",                    certdata_unit_tests                  },
    { "cio",      "Run Unit Test on Cert I/O",                      certio_unit_tests                    },
#endif
#ifndef DO_NOT_TEST_SW_CRYPTO
    { "crypto",   "Run Unit Tests for Software Crypto Functions",   atca_crypto_sw_tests                 },
#endif
#if defined(ATCA_MBEDTLS)
    { "crypto_int", "Run crypto library integration tests",         run_integration_tests               },
#endif
#if defined(ATCA_JWT_EN)
    { "jwt",        "Run JWT support tests",                        run_jwt_tests                       },
#endif
#if ATCA_CA_SUPPORT
    { "calib",      "Run calib api tests",                          run_calib_tests                      },
#endif
#if ATCA_TA_SUPPORT
    { "config",    "Create testing handles in TA100 device",        talib_configure_device               },
    { "handles",   "Print info for stored handles in TA100 device", talib_config_print_handles           },
    { "clear",     "Delete Handles",                                talib_config_clear_handles           },
    { "talib",     "Run talib tests",                               run_talib_tests                      },
#ifdef TALIB_FCE_SUPPORT
    { "fce",       "Run FCE test",                                  talib_fce_cmd                        },
#endif
    { "power",     "Change device power state",                     talib_power_cmd                      },
#endif
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
    { "exit",     "Exit the test application",                      call_exit                            },
#endif
    { NULL,       NULL,                                             NULL                                 },
};
// *INDENT-ON*


/** \brief Parses an input string into an arglist. Will be modified
 *
 * \param[in]  buffer   buffer holding string to parsed
 * \param[in]  buf_len  maximum size of the input buffer
 * \param[in]  argc     Number of arguments in the arg list
 * \param[out] argv     Resulting argument list
 * \return Number of arguments parsed
 */
int parse_cmd_string(char* buffer, const size_t buf_len, const int argc, char* argv[])
{
    int nargs = 0;
    size_t i;
    char * c_ptr = buffer;
    bool in_arg = false;

    if (buffer && buf_len && argc && argv)
    {
        for (i = 0; i < buf_len; i++, c_ptr++)
        {
            if (!*c_ptr)
            {
                break;
            }
            else if (isBlankSpace(*c_ptr))
            {
                *c_ptr = '\0';
                if (in_arg)
                {
                    in_arg = false;
                }
            }
            else if (!in_arg)
            {
                argv[nargs++] = c_ptr;
                in_arg = true;
                if (nargs >= argc)
                {
                    break;
                }
            }
        }
    }

    return nargs;
}

/** \brief Execute a command if it found in the command list
 *
 * \param[in] argc     Number of arguments in the arg list
 * \param[in] argv     Argument list
 * \return Execution return code
 */
static int run_cmd(t_menu_info* menu_item, int argc, char* argv[])
{
    int ret = -1;

    printf("\n");
    if (argc && argv)
    {
        if (0 <= (ret = process_options(argc - 1, &argv[1])))
        {
            for (; menu_item->menu_cmd; menu_item++)
            {
                if (0 == strcmp(menu_item->menu_cmd, argv[0]))
                {
                    if (menu_item->fp_handler)
                    {
                        ret = menu_item->fp_handler(ret + 1, argv);
                    }
                    break;
                }
            }
        }
    }

    if (!menu_item->menu_cmd)
    {
        printf("syntax error in command: %s", argv[0]);
    }

    /* Reset quiet mode for the next command */
    g_atca_test_quiet_mode = false;

    printf("\n");
    return ret;
}

/** \brief Convert a string into command and its arguments and then execute it
 *
 * \param[in] command     buffer with a command string
 * \param[in] max_len     maximum buffer length
 * \return Execution return code
 */
static int parse_cmd(char *command, size_t max_len)
{
    int argc = CMD_PROCESSOR_MAX_ARGS;
    char* argv[CMD_PROCESSOR_MAX_ARGS] = { 0 };

    if (command[0] == '\0' || command[0] == '\n')
    {
        return ATCA_SUCCESS;
    }

    argc = parse_cmd_string(command, max_len, argc, argv);

    return run_cmd(mas_menu_info, argc, argv);
}

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
#include <stdio.h>
#include <stdlib.h>

static int exit_code;

int call_exit(int argc, char* argv[])
{
    ((void)argc);
    ((void)argv);

    exit_code = 1;
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc > 1)
    {
        exit_code = run_cmd(mas_menu_info, argc - 1, &argv[1]);
    }
    else
    {
        char buffer[1024];

        while (!exit_code)
        {
            printf("$ ");
            fflush(stdout);
            if (fgets(buffer, sizeof(buffer), stdin))
            {
                parse_cmd(buffer, sizeof(buffer));
            }
        }
    }

    return exit_code;
}
#else
int processCmd(void)
{
    static char cmd[cmdQ_SIZE + 1];
    uint16_t i = 0;

    while (!CBUF_IsEmpty(cmdQ) && i < sizeof(cmd))
    {
        cmd[i++] = CBUF_Pop(cmdQ);
    }
    cmd[i] = '\0';
    //printf("\r\n%s\r\n", command );
    parse_cmd(cmd, sizeof(cmd));
    printf("$ ");

    return ATCA_SUCCESS;
}

void atca_test_task(void)
{
    uint8_t ch;

    while (true)
    {
        ch = 0;
        scanf("%c", &ch);

        if (ch)
        {
            printf("%c", ch); // echo to output
            if (ch == 0x0d || ch == 0x0a)
            {
                processCmd();
            }
            else
            {
                CBUF_Push(cmdQ, ch);    // queue character into circular buffer
            }
        }
    }
}

#endif

static int help(int argc, char* argv[])
{
    ((void)argc);
    ((void)argv);

    uint8_t index = 0;

    printf("Usage:\r\n");
    while (mas_menu_info[index].menu_cmd != NULL)
    {
        printf("%s - %s\r\n", mas_menu_info[index].menu_cmd, mas_menu_info[index].menu_cmd_description);
        index++;
    }

    return 0;
}
