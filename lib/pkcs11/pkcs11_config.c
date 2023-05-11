/**
 * \file
 * \brief PKCS11 Library Configuration
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
#include "pkcs11_config.h"
#include "pkcs11_debug.h"
#include "pkcs11_slot.h"
#include "pkcs11_object.h"
#include "pkcs11_key.h"
#include "pkcs11_cert.h"
#include "pkcs11_os.h"
#include "pkcs11_util.h"

#ifndef _WIN32
#include <dirent.h>
#endif

#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
/* coverity[misra_c_2012_rule_8_6_violation:FALSE] */
extern CK_RV pkcs11_trust_load_objects(pkcs11_slot_ctx_ptr pSlot);
#endif

#pragma coverity compliance block \
(deviate "MISRA C-2012 Rule 10.3" "Casting character constants to char type reduces readability") \
(deviate "MISRA C-2012 Rule 10.4" "Casting character constants to char type reduces readability") \
(deviate "MISRA C-2012 Rule 21.6" "Standard library functions are required for file system access in linux & windows")


/**
 * \defgroup pkcs11 Configuration (pkcs11_config_)
   @{ */

void pkcs11_config_init_private(pkcs11_object_ptr pObject, const char * label, size_t len)
{
    if (len >= (size_t)PKCS11_MAX_LABEL_SIZE)
    {
        len = (size_t)PKCS11_MAX_LABEL_SIZE - 1u;
    }
    (void)memcpy((char*)pObject->name, label, len);
    pObject->name[len] = (CK_UTF8CHAR)'\0';
    pObject->class_id = CKO_PRIVATE_KEY;
    pObject->class_type = CKK_EC;
    pObject->attributes = pkcs11_key_private_attributes;
    pObject->count = pkcs11_key_private_attributes_count;
#if ATCA_CA_SUPPORT
    pObject->data = NULL;
#endif
    pObject->size = 16;
}

void pkcs11_config_init_public(pkcs11_object_ptr pObject, const char * label, size_t len)
{
    if (len >= (size_t)PKCS11_MAX_LABEL_SIZE)
    {
        len = (size_t)PKCS11_MAX_LABEL_SIZE - 1u;
    }
    (void)memcpy((char*)pObject->name, label, len);
    pObject->name[len] = (CK_UTF8CHAR)'\0';
    pObject->class_id = CKO_PUBLIC_KEY;
    pObject->class_type = CKK_EC;
    pObject->attributes = pkcs11_key_public_attributes;
    pObject->count = pkcs11_key_public_attributes_count;
#if ATCA_CA_SUPPORT
    pObject->data = NULL;
#endif
    pObject->size = 64;
}

void pkcs11_config_init_secret(pkcs11_object_ptr pObject, const char * label, size_t len, size_t keylen)
{
    if (len >= (size_t)PKCS11_MAX_LABEL_SIZE)
    {
        len = (size_t)PKCS11_MAX_LABEL_SIZE - 1u;
    }
    (void)memcpy((char*)pObject->name, label, len);
    pObject->name[len] = (CK_UTF8CHAR)'\0';
    pObject->class_id = CKO_SECRET_KEY;
    pObject->class_type = CKK_GENERIC_SECRET;
    pObject->attributes = pkcs11_key_secret_attributes;
    pObject->count = pkcs11_key_secret_attributes_count;
#if ATCA_CA_SUPPORT
    pObject->data = NULL;
#endif
    if (keylen == 32U || keylen == 16U)
    {
        pObject->size = (CK_ULONG)keylen;
    }
}

void pkcs11_config_init_cert(pkcs11_object_ptr pObject, const char * label, size_t len)
{
    if (len >= (size_t)PKCS11_MAX_LABEL_SIZE)
    {
        len = (size_t)PKCS11_MAX_LABEL_SIZE - 1u;
    }
    (void)memcpy((char*)pObject->name, label, len);
    pObject->name[len] = (CK_UTF8CHAR)'\0';
    pObject->class_id = CKO_CERTIFICATE;
    pObject->class_type = 0;
    pObject->attributes = pkcs11_cert_x509public_attributes;
    pObject->count = pkcs11_cert_x509public_attributes_count;
#if ATCA_CA_SUPPORT
    pObject->data = NULL;
#endif
    pObject->size = 0;
}

#if !PKCS11_USE_STATIC_CONFIG

#ifdef ATCA_NO_HEAP
#error Invalid configuration: ATCA_NO_HEAP && PKCS11_USE_STATIC_CONFIG==0 - Loading pkcs11 configuration from disk requires dynamic memory allocation
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

static size_t pkcs11_config_load_file(FILE* fp, char ** buffer)
{
    size_t size = 0u;

    if (NULL != buffer)
    {
        /* Get file size */
        (void)fseek(fp, 0L, SEEK_END);

        errno = 0;
        long fsize = ftell(fp);
        if ((0 > fsize) || (0 != errno))
        {
            fsize = 0;
        }

        (void)fseek(fp, 0L, SEEK_SET);

        if (0 < fsize)
        {
            size = (size_t)fsize;
            *buffer = (char*)pkcs11_os_malloc(size);
            if (NULL != *buffer)
            {
                (void)memset(*buffer, 0, size);
                if (size != fread(*buffer, 1, size, fp))
                {
                    pkcs11_os_free(*buffer);
                    *buffer = NULL;
                    size = 0;
                }
            }
            else
            {
                size = 0;
            }
        }
    }
    return size;
}

/* Parse a buffer into key value pairs. Return value should be an even value */
static int pkcs11_config_parse_buffer(char* buffer, size_t len, int argc, char* argv[])
{
    char* s;
    uint8_t args = 0;
    bool comment = FALSE;
    bool arg = FALSE;
    bool v = FALSE;

    if ((NULL == buffer) || (0u == len) || (0 >= argc) || (NULL == argv))
    {
        return 0;
    }

    s = buffer;
    while ( s < (buffer + len) && (int)args < argc)
    {
        /* coverity[cert_str34_c_violation:FALSE] */
        /* coverity[misra_c_2012_rule_16_1_violation] The parsing algorithm here is well tested */
        switch (*s)
        {
        case '\n':
            /* fallthrough */
        case '\r':
            /* End the line*/
            if (arg && !v && !comment)
            {
                /* Everything must be a key value pair */
                return 0;
            }
            else
            {
                comment = FALSE;
                v = FALSE;
                arg = FALSE;
                *s = '\0';
            }
            break;
        /* coverity[misra_c_2012_rule_16_3_violation] The parsing algorithm here is well tested */
        case '=':
            v = TRUE;
            /* fallthrough */
        case ' ':
            /* fallthrough */
        case '\t':
            *s = '\0';
            arg = FALSE;
            break;
        default:
            if (!comment)
            {
                if (*s == (char)'#')
                {
                    comment = 1;
                }
                else
                {
                    if (!arg)
                    {
                        argv[args++] = s;
                        arg = TRUE;
                    }
                }
            }
            break;
        }
        s++;
    }

    if (0u != (args & 0x1u))
    {
        /* Parsing error occured */
        args = 0;
    }

    return (int)args;
}

void pkcs11_config_split_string(char* s, char splitter, int * argc, char* argv[])
{
    char * e;
    int args = 1;

    if ((NULL == s) || (NULL == argc) || (NULL == argv))
    {
        return;
    }

    e = s + strlen(s);
    argv[0] = s;

    while(s < e && args < *argc)
    {
        if (*s == splitter)
        {
            *s = '\0';
            argv[args++] = ++s;
        }
        s++;
    }
    *argc = args;
}

static CK_RV pkcs11_config_parse_device(pkcs11_slot_ctx_ptr slot_ctx, char* cfgstr)
{
    int argc = 4;
    char* argv[4] = {"", "", "", ""};
    CK_RV rv = CKR_GENERAL_ERROR;

    pkcs11_config_split_string(cfgstr, '-', &argc, argv);

    if (0 == strcmp(argv[0], "ATECC508A"))
    {
        slot_ctx->interface_config.devtype = ATECC508A;
        rv = CKR_OK;
    }
    else if (0 == strncmp(argv[0], "ATECC608", 8))
    {
        slot_ctx->interface_config.devtype = ATECC608;
        rv = CKR_OK;

        if (1 < argc)
        {
#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
            if (0 == strcmp(argv[1], "TNGTLS") || 0 == strcmp(argv[1], "TFLXTLS") || 0 == strcmp(argv[1], "TNGLORA"))
            {
                rv = pkcs11_trust_load_objects(slot_ctx);
            }
#endif
        }
    }
    else if (0 == strcmp(argv[0], "TA100"))
    {
        slot_ctx->interface_config.devtype = TA100;
        rv = CKR_OK;
    }
    else
    {
        PKCS11_DEBUG("Unrecognized device: %s", argv[0]);
    }

    return rv;
}

static CK_RV pkcs11_config_parse_interface(pkcs11_slot_ctx_ptr slot_ctx, char* cfgstr)
{
    int argc = 4;
    char* argv[4] = {"", "", "", ""};
    CK_RV rv = CKR_GENERAL_ERROR;
    ATCAIfaceCfg * cfg = &slot_ctx->interface_config;
    long l_tmp;

    pkcs11_config_split_string(cfgstr, ',', &argc, argv);

    /* Device part number was a late addition so this defaults it to a 608 */
    slot_ctx->interface_config.devtype = ATECC608;
    slot_ctx->interface_config.wake_delay = 1500;
    slot_ctx->interface_config.rx_retries = 20;

    if (0 == strcmp(argv[0], "i2c"))
    {
        #ifdef ATCA_HAL_I2C
        cfg->iface_type = ATCA_I2C_IFACE;
        if (argc > 1)
        {
#ifdef ATCA_ENABLE_DEPRECATED
            ATCA_IFACECFG_VALUE(cfg, atcai2c.slave_address) = (uint8_t)strtol(argv[1], NULL, 16);
#else
            ATCA_IFACECFG_VALUE(cfg, atcai2c.address) = (uint8_t)strtol(argv[1], NULL, 16);
#endif
        }
        if (argc > 2)
        {
            ATCA_IFACECFG_VALUE(cfg, atcai2c.bus) = (uint8_t)strtol(argv[2], NULL, 16);
        }
        if (argc > 3)
        {
            ATCA_IFACECFG_VALUE(cfg, atcai2c.baud) = (uint32_t)strtol(argv[3], NULL, 10);
        }
        rv = CKR_OK;
        #endif
    }
    else if (0 == strcmp(argv[0], "hid"))
    {
        #ifdef ATCA_HAL_KIT_HID
        cfg->iface_type = ATCA_HID_IFACE;
        ATCA_IFACECFG_VALUE(cfg, atcahid.dev_interface) = ATCA_KIT_AUTO_IFACE;
        ATCA_IFACECFG_VALUE(cfg, atcahid.vid) = 0x03EB;
        ATCA_IFACECFG_VALUE(cfg, atcahid.pid) = 0x2312;
        ATCA_IFACECFG_VALUE(cfg, atcahid.packetsize) = 64;
        if (argc > 1)
        {
            if (0 == strcmp(argv[1], "i2c"))
            {
                ATCA_IFACECFG_VALUE(cfg, atcahid.dev_interface) = ATCA_KIT_I2C_IFACE;
            }
            else if (0 == strcmp(argv[1], "swi"))
            {
                ATCA_IFACECFG_VALUE(cfg, atcahid.dev_interface) = ATCA_KIT_SWI_IFACE;
            }
            else if (0 == strcmp(argv[1], "spi"))
            {
                ATCA_IFACECFG_VALUE(cfg, atcahid.dev_interface) = ATCA_KIT_SPI_IFACE;
            }
            else
            {
                /* Unrecognized */
            }
        }
        
        if (argc > 2)
        {
            errno = 0;
            l_tmp = strtol(argv[2], NULL, 16);
            if ((0 == errno) && (l_tmp > 0) && (l_tmp < (long)UINT8_MAX))
            {
                ATCA_IFACECFG_VALUE(cfg, atcahid.dev_identity) = (uint8_t)l_tmp;
                rv = CKR_OK;
            }
        }
        else
        {
            rv = CKR_OK;
        }
        #endif
    }
    else if (0 == strcmp(argv[0], "spi"))
    {
#ifdef ATCA_HAL_SPI
        cfg->iface_type = ATCA_SPI_IFACE;
        if (argc > 1)
        {
            ATCA_IFACECFG_VALUE(cfg, atcaspi.bus) = (uint8_t)strtol(argv[1], NULL, 16);
        }
        if (argc > 2)
        {
            ATCA_IFACECFG_VALUE(cfg, atcaspi.select_pin) = (uint8_t)strtol(argv[2], NULL, 16);
        }
        if (argc > 3)
        {
            ATCA_IFACECFG_VALUE(cfg, atcaspi.baud) = (uint32_t)strtol(argv[3], NULL, 10);
        }
        rv = CKR_OK;
#endif
    }
#if defined(ATCA_HAL_KIT_BRIDGE) && defined(PKCS11_TESTING_ENABLE)
    else if (0 == strcmp(argv[0], "bridge"))
    {
        cfg->iface_type = ATCA_KIT_IFACE;
        ATCA_IFACECFG_VALUE(cfg, atcakit.dev_interface) = ATCA_KIT_AUTO_IFACE;
        ATCA_IFACECFG_VALUE(cfg, atcakit.dev_identity) = 0;

        if(argc > 1)
        {
            strncpy((char*)slot_ctx->devpath, argv[1], sizeof(slot_ctx->devpath)-1);
        }
        if(argc > 2)
        {
            ATCA_IFACECFG_VALUE(cfg, atcakit.dev_identity) = (uint8_t)strtol(argv[2], NULL, 10);
        }
    }
#endif
    else
    {
        PKCS11_DEBUG("Unrecognized interface: %s", argv[0]);
    }
    return rv;
}

#ifndef PKCS11_LABEL_IS_SERNUM
static CK_RV pkcs11_config_parse_label(pkcs11_slot_ctx_ptr slot_ctx, char* cfgstr)
{
    CK_RV rv = CKR_OK;
    size_t len = strlen(cfgstr);

    if ((0u < len) && (len < (size_t)PKCS11_MAX_LABEL_SIZE))
    {
        (void)memcpy(slot_ctx->label, (CK_UTF8CHAR_PTR)cfgstr, len);
        slot_ctx->label[PKCS11_MAX_LABEL_SIZE] = 0;
    }
    else
    {
        rv = CKR_ARGUMENTS_BAD;
    }

    return rv;
}
#endif

static CK_RV pkcs11_config_parse_freeslots(pkcs11_slot_ctx_ptr slot_ctx, char* cfgstr)
{
    int argc = 16;
    char* argv[16] = { 0 };
    int i;

    pkcs11_config_split_string(cfgstr, ',', &argc, argv);

    for (i = 0; i < argc; i++)
    {
        errno = 0;
        long slot = strtol(argv[i], NULL, 10);
        if (0 != errno)
        {
            return CKR_GENERAL_ERROR;
        }

        if (slot > 0 && slot < 16)
        {
            slot_ctx->flags |= ((CK_FLAGS)1U << (uint16_t)slot);
        }
        else
        {
            return CKR_GENERAL_ERROR;
        }
    }

    return CKR_OK;
}

static CK_RV pkcs11_config_parse_object(pkcs11_slot_ctx_ptr slot_ctx, char* cfgstr)
{
    char* argv[5] = {"", "", "", "", ""};
    int argc = (int)sizeof(argv);
    CK_RV rv = CKR_GENERAL_ERROR;
    pkcs11_object_ptr pObject;
    long l_tmp;

#if !ATCA_CA_SUPPORT
    ((void)slot_ctx);
#endif

    pkcs11_config_split_string(cfgstr, ',', &argc, argv);

    if (0 == strcmp(argv[0], "private") && argc == 3)
    {
        pkcs11_object_ptr pPubkey = NULL;
        uint16_t slot;

        errno = 0;
        l_tmp = strtol(argv[2], NULL, 16);

        if ((0 != errno) || (l_tmp < 0) || (l_tmp > (long)UINT16_MAX))
        {
            rv = CKR_GENERAL_ERROR;
        }
        else
        {
            slot = (uint16_t)l_tmp;
            rv = pkcs11_object_alloc(slot_ctx->slot_id, &pObject);
        }

        if ((CKR_OK == rv) && (NULL != pObject))
        {
            pkcs11_config_init_private(pObject, argv[1], strlen(argv[1]));
            pObject->slot = slot;
            pObject->flags = 0;
#if ATCA_CA_SUPPORT
            pObject->config = &slot_ctx->cfg_zone;
#endif
        }

        /* Every private key object needs a cooresponding public key object */
        if (CKR_OK == rv)
        {
            rv = pkcs11_object_alloc(slot_ctx->slot_id, &pPubkey);
        }
        if (CKR_OK == rv)
        {
            pkcs11_config_init_public(pPubkey, argv[1], strlen(argv[1]));
            pPubkey->slot = slot;
            pPubkey->flags = 0;
#if ATCA_CA_SUPPORT
            pPubkey->config = &slot_ctx->cfg_zone;
#endif
        }
        else
        {
            (void)pkcs11_object_free(pObject);
        }
    }
    else if (0 == strcmp(argv[0], "public") && argc == 3)
    {
        rv = pkcs11_object_alloc(slot_ctx->slot_id, &pObject);
        if ((CKR_OK == rv) && (NULL != pObject))
        {
            pkcs11_config_init_public(pObject, argv[1], strlen(argv[1]));

            errno = 0;
            l_tmp = strtol(argv[2], NULL, 16);
            if ((0 != errno) || (l_tmp < 0) || (l_tmp > (long)UINT16_MAX))
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                pObject->slot = (uint16_t)l_tmp;
            }

            pObject->flags = 0;
#if ATCA_CA_SUPPORT
            pObject->config = &slot_ctx->cfg_zone;
#endif
        }
    }
    else if (0 == strcmp(argv[0], "secret") && argc >= 3)
    {
        rv = pkcs11_object_alloc(slot_ctx->slot_id, &pObject);
        if ((CKR_OK == rv) && (NULL != pObject))
        {
            uint8_t keylen = 32;
            
            if (4 == argc)
            {
                errno = 0;
                l_tmp = strtol(argv[3], NULL, 10);

                if ((0 != errno) || (l_tmp != 32 && l_tmp != 16))
                {
                    rv = CKR_GENERAL_ERROR;
                }
                else
                {
                    keylen = (uint8_t)l_tmp;
                }
            }
            pkcs11_config_init_secret(pObject, argv[1], strlen(argv[1]), keylen);

            errno = 0;
            l_tmp = strtol(argv[2], NULL, 16);

            if ((0 != errno) || (l_tmp < 0) || (l_tmp > (long)UINT16_MAX))
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                pObject->slot = (uint16_t)l_tmp;
            }

            pObject->flags = 0;
#if ATCA_CA_SUPPORT
            pObject->config = &slot_ctx->cfg_zone;
#endif
        }
    }
    else if (0 == strcmp(argv[0], "certificate") && argc >= 3)
    {
        rv = pkcs11_object_alloc(slot_ctx->slot_id, &pObject);
        if ((CKR_OK == rv) && (NULL != pObject))
        {
            (void)memmove(pObject->name, (CK_UTF8CHAR_PTR)argv[1], strlen(argv[1]));
            errno = 0;
            l_tmp = strtol(argv[2], NULL, 16);

            if ((0 != errno) || (l_tmp < 0) || (l_tmp > (long)UINT16_MAX))
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                pObject->slot = (uint16_t)l_tmp;
            }

            pObject->class_id = CKO_CERTIFICATE;
            pObject->class_type = CK_CERTIFICATE_CATEGORY_TOKEN_USER;
            pObject->attributes = pkcs11_cert_x509public_attributes;
            pObject->count = pkcs11_cert_x509public_attributes_count;

            /* Load certificate data from the file system */
//            pObject->size = g_cert_def_2_device.cert_template_size;
//            pObject->data = &g_cert_def_2_device;
            pObject->flags = 0;
#if ATCA_CA_SUPPORT
            pObject->config = &slot_ctx->cfg_zone;
#endif
        }
    }
    else
    {
        PKCS11_DEBUG("Unrecognized object type: %s", argv[0]);
    }

    return rv;
}

#if ATCA_TA_SUPPORT
static CK_RV pkcs11_config_parse_handle(uint16_t * handle, char* cfgstr)
{
    int argc = 4;
    char * argv[4];
    CK_RV rv = CKR_GENERAL_ERROR;

    pkcs11_config_split_string(cfgstr, ',', &argc, argv);

    if (argc == 1)
    {
        errno = 0;
        long l_tmp = strtol(argv[0], NULL, 16);
        if ((0 == errno) && (l_tmp >= 0) && (l_tmp <= (long)UINT16_MAX))
        {
            *handle = (uint16_t)l_tmp;
            rv = CKR_OK;
        }
    }

    return rv;
}
#endif

static CK_RV pkcs11_config_parse_slot_file(pkcs11_slot_ctx_ptr slot_ctx, int argc, char * argv[])
{
    CK_RV rv = CKR_GENERAL_ERROR;
    int i;

    for (i = 0; i < argc; i += 2)
    {
        if (0 == strcmp(argv[i], "device"))
        {
            rv = pkcs11_config_parse_device(slot_ctx, argv[i + 1]);
        }
        else if (0 == strcmp(argv[i], "interface"))
        {
            rv = pkcs11_config_parse_interface(slot_ctx, argv[i + 1]);
        }
#ifndef PKCS11_LABEL_IS_SERNUM
        else if (0 == strcmp(argv[i], "label"))
        {
            rv = pkcs11_config_parse_label(slot_ctx, argv[i + 1]);
        }
#endif
        else if (0 == strcmp(argv[i], "freeslots"))
        {
            rv = pkcs11_config_parse_freeslots(slot_ctx, argv[i + 1]);
        }
#if ATCA_TA_SUPPORT
        else if (0 == strcmp(argv[i], "user_pin_handle"))
        {
            rv = pkcs11_config_parse_handle(&slot_ctx->user_pin_handle, argv[i + 1]);
        }
        else if (0 == strcmp(argv[i], "so_pin_handle"))
        {
            rv = pkcs11_config_parse_handle(&slot_ctx->so_pin_handle, argv[i + 1]);
        }
#endif
        else if (0 == strcmp(argv[i], "object"))
        {
            rv = pkcs11_config_parse_object(slot_ctx, argv[i + 1]);
        }
        else
        {
            /* Unrecognized key encountered */
        }
    }
    return rv;
}

static CK_RV pkcs11_config_parse_object_file(pkcs11_slot_ctx_ptr slot_ctx, CK_BYTE slot, int argc, char * argv[])
{
    CK_RV rv;
    int i;
    pkcs11_object_ptr pObject = NULL;
    bool privkey = FALSE;

#if !ATCA_CA_SUPPORT
    ((void)slot_ctx);
#endif

    rv = pkcs11_object_alloc(slot_ctx->slot_id, &pObject);
    if ((CKR_OK == rv) && (NULL != pObject))
    {
        pObject->slot = slot;
        pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;
#if ATCA_CA_SUPPORT
        pObject->config = &slot_ctx->cfg_zone;
#endif
        (void)memset(pObject->name, 0, sizeof(pObject->name));

        for (i = 0; i < argc; i += 2)
        {
            if (0 == strcmp(argv[i], "type"))
            {
                if (0 == strcmp(argv[i + 1], "private"))
                {
                    privkey = TRUE;
                    pkcs11_config_init_private(pObject, "", 0);
                }
                else if (0 == strcmp(argv[i + 1], "public"))
                {
                    pkcs11_config_init_public(pObject, "", 0);
                }
                else if (0 == strcmp(argv[i + 1], "secret"))
                {
                    pkcs11_config_init_secret(pObject, "", 0, 32);
                }
                //else if (0 == strcmp(argv[i + 1], "certificate"))
                //{
                //}
                else
                {
                    /* Unrecognized object type */
                }
            }
            else if (0 == strcmp(argv[i], "label"))
            {
                (void)strncpy((char*)pObject->name, argv[i + 1], sizeof(pObject->name)-1U);
            }
            else
            {
                /* Unrecognized key */
            }
        }
    }

    if ((CKR_OK == rv) && privkey)
    {
        /* Have to create a public copy of private keys */
        pkcs11_object_ptr pPubkey = NULL;
        rv = pkcs11_object_alloc(slot_ctx->slot_id, &pPubkey);
        if ((CKR_OK == rv) && (NULL != pPubkey))
        {
            pPubkey->slot = slot;
            pPubkey->flags = pObject->flags;
#if ATCA_CA_SUPPORT
            pPubkey->config = &slot_ctx->cfg_zone;
#endif
            pkcs11_config_init_public(pPubkey, (char*)pObject->name, strlen((char*)pObject->name));
        }
        else
        {
            (void)pkcs11_object_free(pObject);
        }
    }


    return rv;
}

CK_RV pkcs11_config_cert(pkcs11_lib_ctx_ptr pLibCtx, pkcs11_slot_ctx_ptr pSlot, pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pLabel)
{
    ((void)pLibCtx);
    ((void)pSlot);
    ((void)pObject);
    ((void)pLabel);

    return CKR_OK;
}

CK_RV pkcs11_config_key(pkcs11_lib_ctx_ptr pLibCtx, pkcs11_slot_ctx_ptr pSlot, pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pLabel)
{
    FILE* fp;
    const char *objtype = "";
    char filename[200];
    CK_RV rv = CKR_FUNCTION_FAILED;
    uint16_t handle = UINT16_MAX;

    if(atcab_is_ca_device(pSlot->interface_config.devtype))
    {
#if ATCA_CA_SUPPORT
        uint8_t i = 0;

        /* Find a free slot that matches the object type */
        for (i = 0; i < 16u; i++)
        {
            if (0u < (pSlot->flags & ((uint32_t)1 << i)))
            {
                uint8_t keytype = ((ATCA_KEY_CONFIG_KEY_TYPE_MASK & pSlot->cfg_zone.KeyConfig[i]) & 0xFFU) >> ATCA_KEY_CONFIG_KEY_TYPE_SHIFT;
                bool privkey = (ATCA_KEY_CONFIG_PRIVATE_MASK == (ATCA_KEY_CONFIG_PRIVATE_MASK & pSlot->cfg_zone.KeyConfig[i])) ? TRUE : FALSE;

                if (CKO_PRIVATE_KEY == pObject->class_id)
                {
                    if ((4U == keytype) && privkey)
                    {
                        handle = i;
                        break;
                    }
                }
                else if (CKO_PUBLIC_KEY == pObject->class_id)
                {
                    if ((4U == keytype) && !privkey)
                    {
                        handle = i;
                        break;
                    }
                }
                else if (CKO_SECRET_KEY == pObject->class_id)
                {
                    if ((6U == keytype) || (7U == keytype))
                    {
                        handle = i;
                        break;
                    }
                }
                else
                {
                    /* Do Nothing */
                }

            }
        }
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        ATCA_STATUS status = talib_create_element(atcab_get_device(), &pObject->handle_info, &handle);
        rv = pkcs11_util_convert_rv(status);
#endif
    }

    if (UINT16_MAX != handle)
    {
        pObject->slot = handle;
        pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;

#if ATCA_CA_SUPPORT
        if(atcab_is_ca_device(pSlot->interface_config.devtype))
        {
            pObject->config = &pSlot->cfg_zone;
        }
#endif

        if (CKO_PRIVATE_KEY == pObject->class_id)
        {
            pkcs11_config_init_private(pObject, (char*)pLabel->pValue, pLabel->ulValueLen);
            objtype = "private";
        }
        else if (CKO_PUBLIC_KEY == pObject->class_id)
        {
            pkcs11_config_init_public(pObject, (char*)pLabel->pValue, pLabel->ulValueLen);
            objtype = "public";
        }
        else if (CKO_SECRET_KEY == pObject->class_id)
        {
            pkcs11_config_init_secret(pObject, (char*)pLabel->pValue, pLabel->ulValueLen, 32);
            objtype = "secret";
        }
        else
        {
            /* Unsupported class_id */
        }

        int ret = snprintf(filename, sizeof(filename), "%s%lu.%u.conf", pLibCtx->config_path,
                           pSlot->slot_id, pObject->slot);

        if (ret > 0 && ret < (int)sizeof(filename))
        {
            fp = fopen(filename, "wb");
            if (NULL != fp)
            {
                (void)fprintf(fp, "type = %s\n", objtype);
                (void)fprintf(fp, "label = %s\n", pObject->name);
                (void)fclose(fp);
                rv = CKR_OK;
            }
        }
    }

    return rv;
}

CK_RV pkcs11_config_remove_object(pkcs11_lib_ctx_ptr pLibCtx, pkcs11_slot_ctx_ptr pSlot, pkcs11_object_ptr pObject)
{
    char filename[200];

    int ret = snprintf(filename, sizeof(filename), "%s%lu.%u.conf", pLibCtx->config_path,
                       pSlot->slot_id, pObject->slot);

    if (ret > 0 && ret < (int)sizeof(filename))
    {
        (void)remove(filename);
        pSlot->flags |= ((CK_FLAGS)1 << pObject->slot);
    }

    return CKR_OK;
}

/* Load configuration from the filesystem */
CK_RV pkcs11_config_load_objects(pkcs11_slot_ctx_ptr slot_ctx)
{
#ifndef _WIN32
    DIR * d;
    struct dirent *de;
    FILE* fp;
    char* buffer;
    size_t buflen;
    char* argv[2 * (PKCS11_MAX_OBJECTS_ALLOWED + PKCS11_MAX_CONFIG_ALLOWED)];
    int argc = 0;

    pkcs11_lib_ctx_ptr pLibCtx = pkcs11_get_context();
    CK_RV rv = CKR_OK;

    /* Open the general library configuration */
    fp = fopen(ATCA_LIBRARY_CONF, "rb");
    if (fp)
    {
        buflen = pkcs11_config_load_file(fp, &buffer);
        fclose(fp);
        fp = NULL;

        if (0 < buflen)
        {
            if (0 < (argc = pkcs11_config_parse_buffer(buffer, buflen, sizeof(argv) / sizeof(argv[0]), argv)))
            {
                if (strcmp("filestore", argv[0]) == 0)
                {
                    buflen = strlen(argv[1]);
                    (void)memcpy(pLibCtx->config_path, argv[1], buflen);

                    if (pLibCtx->config_path[buflen - 1] != '/')
                    {
                        pLibCtx->config_path[buflen++] = '/';
                    }
                    pLibCtx->config_path[buflen] = '\0';
                }
            }
            else
            {
                PKCS11_DEBUG("Failed to parse the configuration file: %s\n", ATCA_LIBRARY_CONF);
            }
            pkcs11_os_free(buffer);
        }
    }

    if (NULL != (d = opendir((char*)pLibCtx->config_path)))
    {
        while((CKR_OK == rv) && (NULL != (de = readdir(d))))
        {
            if(DT_REG == de->d_type)
            {
                argc = sizeof(argv)/sizeof(argv[0]);
                size_t fnlen = strlen((char*)pLibCtx->config_path) + strlen(de->d_name) + 1;
                char* filename = pkcs11_os_malloc(fnlen);
               
                if (!filename)
                {
                    rv = CKR_HOST_MEMORY;
                    PKCS11_DEBUG("Failed to allocated a filename buffer\n");
                    break;
                }
                snprintf(filename, fnlen, "%s%s", pLibCtx->config_path, de->d_name);
                pkcs11_config_split_string(de->d_name, '.', &argc, argv);

                if (0 == strcmp(argv[argc-1], "conf"))
                {
                    CK_SLOT_ID slot_id = (CK_SLOT_ID)strtol(argv[0], NULL, 10 );

                    PKCS11_DEBUG("Opening Configuration: %s\n", filename);
                    fp = fopen(filename, "rb");
                    pkcs11_os_free(filename);
                    if (fp)
                    {
                        buflen = pkcs11_config_load_file(fp, &buffer);

                        if (0 < buflen)
                        {
                            if (2 == argc)
                            {
                                if (!slot_ctx->label[0])
                                {
                                    slot_ctx->slot_id = slot_id;
                                }
                                else if (slot_ctx->slot_id == slot_id)
                                {
                                    PKCS11_DEBUG("Tried to reload the same configuration file for the same slot\n");
                                    rv = CKR_GENERAL_ERROR;
                                }
                                else
                                {
                                    /* Move to the next context */
                                    slot_ctx = pkcs11_slot_get_new_context(pLibCtx);
                                    if(slot_ctx)
                                    {
                                        slot_ctx->slot_id = slot_id;
                                    }
                                    else
                                    {
                                        rv = CKR_GENERAL_ERROR;
                                    }
                                }

                                if (CKR_OK == rv)
                                {
                                    if (0 < (argc = pkcs11_config_parse_buffer(buffer, buflen, sizeof(argv) / sizeof(argv[0]), argv)))
                                    {
                                        rv = pkcs11_config_parse_slot_file(slot_ctx, argc, argv);
                                    }
                                    else
                                    {
                                        rv = CKR_GENERAL_ERROR;
                                        PKCS11_DEBUG("Failed to parse the slot configuration file\n");
                                    }
                                }
                            #ifndef PKCS11_LABEL_IS_SERNUM
                                if (CKR_OK == rv)
                                {
                                    /* If a label wasn't set - configure a default */
                                    if (!slot_ctx->label[0])
                                    {
                                        snprintf((char*)slot_ctx->label, sizeof(slot_ctx->label) - 1, "%02XABC", (uint8_t)slot_ctx->slot_id);
                                    }
                                }
                            #endif
                            }
                            else if (3 == argc)
                            {
                                uint16_t handle = (uint16_t)strtol(argv[1], NULL, 10);

                                if (!slot_ctx->label[0] || (slot_ctx->slot_id != slot_id))
                                {
                                    rv = CKR_GENERAL_ERROR;
                                    PKCS11_DEBUG("Trying to load an object configuration without a slot configuration file\n");
                                }

                                if (CKR_OK == rv)
                                {
                                    if (0 < (argc = pkcs11_config_parse_buffer(buffer, buflen, sizeof(argv) / sizeof(argv[0]), argv)))
                                    {
                                        rv = pkcs11_config_parse_object_file(slot_ctx, handle, argc, argv);
                                    }
                                    else
                                    {
                                        rv = CKR_GENERAL_ERROR;
                                        PKCS11_DEBUG("Failed to parse the slot configuration file\n");
                                    }
                                }

                                if (CKR_OK == rv)
                                {
                                #if ATCA_CA_SUPPORT
                                    if(atcab_is_ca_device(slot_ctx->interface_config.devtype))
                                    {
                                        /* Remove the slot from the free list*/
                                        slot_ctx->flags &= ~(1 << handle);
                                    }
                                #endif
                                }
                            }
                            pkcs11_os_free(buffer);
                        }
                        fclose(fp);
                    }
                    else
                    {
                        rv = CKR_GENERAL_ERROR;
                        PKCS11_DEBUG("Unable to open the configuration file\n");
                    }
                }
            }
        }
    }

    return rv;
#else
    return CKR_OK;
#endif
}

#endif

/* Function to load/specify device configurations depending on platform */
CK_RV pkcs11_config_load(pkcs11_slot_ctx_ptr slot_ctx)
{
    CK_RV rv = CKR_OK;

#if PKCS11_MONOTONIC_ENABLE
    pkcs11_object_ptr pObject;
    rv = pkcs11_object_alloc(slot_ctx->slot_id, &pObject);
    if (NULL != pObject)
    {
        /* Hardware Feature */
        pObject->slot = 0;
        (void)strncpy((char*)pObject->name, "counter", 8);
        pObject->class_id = CKO_HW_FEATURE;
        pObject->class_type = CKH_MONOTONIC_COUNTER;
        pObject->attributes = pkcs11_object_monotonic_attributes;
        pObject->count = pkcs11_object_monotonic_attributes_count;
        pObject->size = 4;
        pObject->config = &slot_ctx->cfg_zone;
    }

    if (CKR_OK == rv)
#endif
    {
        rv = pkcs11_config_load_objects(slot_ctx);
    }

    return rv;
}

#pragma coverity compliance end_block "MISRA C-2012 Rule 10.3" "MISRA C-2012 Rule 21.6" "CERT POS54-C"

/** @} */
