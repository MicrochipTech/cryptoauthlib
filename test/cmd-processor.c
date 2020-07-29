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

#if !defined(_WIN32) && !defined(__linux__) && !defined(__XC32__) && !defined(__APPLE__) && !defined(ESP32)
#ifdef ATMEL_START
#include "atmel_start.h"
#else
#include <asf.h>
#endif
#endif

#include <string.h>
#ifndef _WIN32
#include "cbuf.h"
#endif
#include "cryptoauthlib.h"
#include "atca_test.h"
#include "atca_crypto_sw_tests.h"
#include "cmd-processor.h"
#include "atca_cfgs.h"

#if ATCA_TA_SUPPORT
#include "api_talib/test_talib.h"
#endif

static void help(int argc, char* argv[]);

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
static void call_exit(int argc, char* argv[]);
#endif


// *INDENT-OFF*  - Preserve formatting
static t_menu_info mas_menu_info[] =
{
    { "help",     "Display Menu",                                   (fp_menu_handler)help                },
#if ATCA_CA_SUPPORT
    { "discover", "Discover Buses and Devices",                     discover                             },
#endif
#ifdef ATCA_ATSHA204A_SUPPORT
    { "204",      "Set Target Device to ATSHA204A",                 select_204                           },
#endif
#ifdef ATCA_ATSHA206A_SUPPORT
    { "206",      "Set Target Device to ATSHA206A",                 select_206                           },
#endif
#ifdef ATCA_ATECC108A_SUPPORT
    { "108",      "Set Target Device to ATECC108A",                 select_108                           },
#endif
#ifdef ATCA_ATECC508A_SUPPORT
    { "508",      "Set Target Device to ATECC508A",                 select_508                           },
#endif
#ifdef ATCA_ATECC608_SUPPORT
    { "608",      "Set Target Device to ATECC608",                  select_608                           },
#endif
#ifdef ATCA_TA100_SUPPORT
    { "ta100",    "Set Target Device to TA100",                     select_ta100                         },
#endif
    { "info",     "Get the Chip Revision",                          (fp_menu_handler)info                },
    { "sernum",   "Get the Chip Serial Number",                     read_sernum                          },
    { "rand",     "Generate Some Random Numbers",                   do_randoms                           },
    { "readcfg",  "Read the Config Zone",                           (fp_menu_handler)read_config         },
    { "lockstat", "Zone Lock Status",                               lock_status                          },
#ifdef ATCA_TEST_LOCK_ENABLE
    { "lockcfg",  "Lock the Config Zone",                           (fp_menu_handler)lock_config         },
    { "lockdata", "Lock Data and OTP Zones",                        (fp_menu_handler)lock_data           },
    { "all",      "Run all unit tests, locking as needed.",         (fp_menu_handler)run_all_tests       },
#endif
    { "tng",      "Run unit tests on TNG type part.",               (fp_menu_handler)run_tng_tests       },
#ifndef DO_NOT_TEST_BASIC_UNIT
    { "basic",    "Run Basic Test on Selected Device",              (fp_menu_handler)run_basic_tests     },
    { "unit",     "Run Unit Test on Selected Device",               (fp_menu_handler)run_unit_tests      },
#ifdef ATCA_TEST_LOCK_ENABLE
    { "otpzero",  "Zero Out OTP Zone",                              (fp_menu_handler)run_otpzero_tests   },
#endif
    { "util",     "Run Helper Function Tests",                      (fp_menu_handler)run_helper_tests    },
#ifdef ATCA_ATECC608_SUPPORT
    { "clkdivm0", "Set ATECC608 to ClockDivider M0(0x00)",          (fp_menu_handler)set_clock_divider_m0},
    { "clkdivm1", "Set ATECC608 to ClockDivider M1(0x05)",          (fp_menu_handler)set_clock_divider_m1},
    { "clkdivm2", "Set ATECC608 to ClockDivider M2(0x0D)",          (fp_menu_handler)set_clock_divider_m2},
#endif
#endif /* DO_NOT_TEST_BASIC_UNIT */
#ifndef DO_NOT_TEST_CERT
    { "cd",       "Run Unit Tests on Cert Data",                    certdata_unit_tests                  },
    { "cio",      "Run Unit Test on Cert I/O",                      certio_unit_tests                    },
#endif
#ifndef DO_NOT_TEST_SW_CRYPTO
    { "crypto",   "Run Unit Tests for Software Crypto Functions",   (fp_menu_handler)atca_crypto_sw_tests},
#endif
#if ATCA_TA_SUPPORT
    { "config",    "Create testing handles in TA100 device",        talib_configure_device               },
    { "handles",   "Print info for stored handles in TA100 device", talib_config_print_handles           },
    { "clear",     "Delete Handles",                                talib_config_clear_handles           },
    { "talib",     "Run talib tests",                               run_talib_tests                      },
#endif
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
    { "exit",     "Exit the test application",                      (fp_menu_handler)call_exit           },
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
            else if (isWhiteSpace(*c_ptr))
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
static int run_cmd(int argc, char* argv[])
{
    t_menu_info* menu_item = mas_menu_info;
    int ret = -1;

    printf("\r\n");
    if (argc)
    {
        (void)process_options(argc - 1, &argv[1]);

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

    if (!menu_item->menu_cmd)
    {
        printf("syntax error in command: %s", argv[0]);
    }

    printf("\r\n");
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

    return run_cmd(argc, argv);
}

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
#include <stdio.h>
#include <stdlib.h>

static int exit_code;

void call_exit(int argc, char* argv[])
{
    exit_code = 1;
}

int main(int argc, char* argv[])
{
    if (argc > 1)
    {
        exit_code = run_cmd(argc - 1, &argv[1]);
    }
    else
    {
        char buffer[1024];

        while (!exit_code)
        {
            printf("$ ");
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

static void help(int argc, char* argv[])
{
    uint8_t index = 0;

    printf("Usage:\r\n");
    while (mas_menu_info[index].menu_cmd != NULL)
    {
        printf("%s - %s\r\n", mas_menu_info[index].menu_cmd, mas_menu_info[index].menu_cmd_description);
        index++;
    }
}
