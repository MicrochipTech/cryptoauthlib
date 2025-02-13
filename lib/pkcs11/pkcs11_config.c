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
#include <stdbool.h>

#include "cryptoauthlib.h"
#include "pkcs11_config.h"
#include "pkcs11_debug.h"
#include "pkcs11_slot.h"
#include "pkcs11_object.h"
#include "pkcs11_key.h"
#include "pkcs11_cert.h"
#include "pkcs11_os.h"
#include "pkcs11_util.h"
#include <limits.h>

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "MISRA C-2012 Rule 10.3" "Casting character constants to char type reduces readability") \
    (deviate "MISRA C-2012 Rule 10.4" "Casting character constants to char type reduces readability") \
    (deviate "MISRA C-2012 Rule 21.6" "Standard library functions are required for file system access in linux & windows")
#endif

/**
 * \defgroup pkcs11 Configuration (pkcs11_config_)
   @{ */

typedef struct pkcs11_conf_filedata_s
{
    bool initialized;
    char filename[MAX_CONF_FILE_NAME_SIZE];
} pkcs11_conf_filedata;

typedef struct pkcs11_conf_filedata_s *pkcs11_conf_filedata_ptr;

#if ATCA_TA_SUPPORT
void pkcs11_config_set_key_size(pkcs11_object_ptr pObject)
{
    CK_BYTE key_type = ((pObject->handle_info.element_CKA & TA_HANDLE_INFO_KEY_TYPE_MASK) >> TA_HANDLE_INFO_KEY_TYPE_SHIFT);
    CK_ULONG private_key_size = 0u;
    CK_ULONG public_key_size = 0u;

    switch (key_type)
    {
        case TA_KEY_TYPE_ECCP224:
            pObject->class_type = CKK_EC;
            private_key_size = TA_ECC224_PVT_KEY_SIZE;
            public_key_size = TA_ECC224_PUB_KEY_SIZE;
            break;
        case TA_KEY_TYPE_ECCP384:
            pObject->class_type = CKK_EC;
            private_key_size = TA_ECC384_PVT_KEY_SIZE;
            public_key_size = TA_ECC384_PUB_KEY_SIZE;
            break;
        case TA_KEY_TYPE_ECCP521:
            pObject->class_type = CKK_EC;
            private_key_size = TA_ECC521_PVT_KEY_SIZE;
            public_key_size = TA_ECC521_PUB_KEY_SIZE;
            break;
#if PKCS11_RSA_SUPPORT_ENABLE
        case TA_KEY_TYPE_RSA1024:
            pObject->class_type = CKK_RSA;
            private_key_size = TA_RSAENC_PVT_KEY_SIZE1024;
            public_key_size = TA_RSAENC_PUB_KEY_SIZE1024;
            break;
        case TA_KEY_TYPE_RSA2048:
            pObject->class_type = CKK_RSA;
            private_key_size = TA_RSAENC_PVT_KEY_SIZE2048;
            public_key_size = TA_RSAENC_PUB_KEY_SIZE2048;
            break;
        case TA_KEY_TYPE_RSA3072:
            pObject->class_type = CKK_RSA;
            private_key_size = TA_RSAENC_PVT_KEY_SIZE3072;
            public_key_size = TA_RSAENC_PUB_KEY_SIZE3072;
            break;
        case TA_KEY_TYPE_RSA4096:
            pObject->class_type = CKK_RSA;
            private_key_size = TA_RSAENC_PVT_KEY_SIZE4096;
            public_key_size = TA_RSAENC_PUB_KEY_SIZE4096;
            break;
#endif
        default:
            pObject->class_type = CKK_EC;
            private_key_size = TA_ECC256_PVT_KEY_SIZE;
            public_key_size = TA_ECC256_PUB_KEY_SIZE;
            break;
    }

    pObject->size = (CKO_PRIVATE_KEY == pObject->class_id) ? (private_key_size) : (public_key_size);
}
#endif

void pkcs11_config_init_private(pkcs11_object_ptr pObject, const char * label, size_t len)
{
    if (len >= (size_t)PKCS11_MAX_LABEL_SIZE)
    {
        len = (size_t)PKCS11_MAX_LABEL_SIZE - 1u;
    }
    (void)memcpy((char*)pObject->name, label, len);
    pObject->name[len] = (CK_UTF8CHAR)'\0';
    pObject->class_id = CKO_PRIVATE_KEY;
    pObject->attributes = pkcs11_key_private_attributes;
    pObject->count = pkcs11_key_private_attributes_count;
    pObject->flags |= PKCS11_OBJECT_FLAG_KEY_CACHE;
#if ATCA_CA_SUPPORT
    pObject->data = NULL;
#endif
    pObject->class_type = CKK_EC;
    pObject->size = ATCA_ECCP256_PVTKEY_SIZE;

#if ATCA_TA_SUPPORT
    // Update the class type and size based on the keytype
    if (0u != pObject->handle_info.element_CKA)
    {
        (void)pkcs11_config_set_key_size(pObject);
    }
#endif
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
    pObject->attributes = pkcs11_key_public_attributes;
    pObject->count = pkcs11_key_public_attributes_count;
    pObject->flags |= PKCS11_OBJECT_FLAG_KEY_CACHE;
#if ATCA_CA_SUPPORT
    pObject->data = NULL;
#endif
    pObject->class_type = CKK_EC;
    pObject->size = ATCA_ECCP256_PVTKEY_SIZE;

#if ATCA_TA_SUPPORT
    // Update the class type and size based on the keytype
    if (0u != pObject->handle_info.element_CKA)
    {
        (void)pkcs11_config_set_key_size(pObject);
    }
#endif
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
#include <fcntl.h>

#ifndef _WIN32
#include <dirent.h>
#endif

#define PKCS11_CONFIG_U8_MAX        0xFFL
#define PKCS11_CONFIG_U16_MAX       0xFFFFL

#if UINT32_MAX > LONG_MAX
#define PKCS11_CONFIG_U32_MAX       LONG_MAX
#else
#define PKCS11_CONFIG_U32_MAX       0xFFFFFFFFL
#endif

static size_t pkcs11_config_load_file(FILE* fp, char ** buf)
{
    size_t size = 0u;

    if (NULL != buf)
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
            *buf = (char*)pkcs11_os_malloc(size);
            if (NULL != *buf)
            {
                (void)memset(*buf, 0, size);
                if (size != fread(*buf, 1, size, fp))
                {
                    pkcs11_os_free(*buf);
                    *buf = NULL;
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
    while (s < (buffer + len) && (int)args < argc)
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
                /* coverity[cert_str34_c_violation:FALSE] */
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

    while (s < e && args < *argc)
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
    char* argv[4] = { "", "", "", "" };
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
    else if (0 == strcmp(argv[0], "TA101"))
    {
        slot_ctx->interface_config.devtype = TA101;
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
    char* argv[4] = { "", "", "", "" };
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
            errno = 0;
#ifdef ATCA_ENABLE_DEPRECATED
            l_tmp = strtol(argv[1], NULL, 16);
            if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U8_MAX))
            {
                ATCA_IFACECFG_VALUE(cfg, atcai2c.slave_address) = (uint8_t)l_tmp;
            }
#else
            l_tmp = strtol(argv[1], NULL, 16);
            if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U8_MAX))
            {
                ATCA_IFACECFG_VALUE(cfg, atcai2c.address) = (uint8_t)l_tmp;
            }
#endif
            if (0 != errno)
            {
                return CKR_GENERAL_ERROR;
            }
        }
        if (argc > 2)
        {
            errno = 0;
            l_tmp = strtol(argv[2], NULL, 16);

            if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U8_MAX))
            {
                ATCA_IFACECFG_VALUE(cfg, atcai2c.bus) = (uint8_t)l_tmp;
            }

            if (0 != errno)
            {
                return CKR_GENERAL_ERROR;
            }
        }
        if (argc > 3)
        {
            errno = 0;
            l_tmp = strtol(argv[3], NULL, 10);

            if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U32_MAX))
            {
                ATCA_IFACECFG_VALUE(cfg, atcai2c.baud) = (uint32_t)l_tmp;
            }

            if (0 != errno)
            {
                return CKR_GENERAL_ERROR;
            }
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
            if ((0 == errno) && (l_tmp > 0) && (l_tmp < PKCS11_CONFIG_U8_MAX))
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
            errno = 0;
            l_tmp = strtol(argv[1], NULL, 16);
            if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U8_MAX))
            {
                ATCA_IFACECFG_VALUE(cfg, atcaspi.bus) = (uint8_t)l_tmp;
            }

            if (0 != errno)
            {
                return CKR_GENERAL_ERROR;
            }
        }
        if (argc > 2)
        {
            errno = 0;
            l_tmp = strtol(argv[2], NULL, 16);
            if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U8_MAX))
            {
                ATCA_IFACECFG_VALUE(cfg, atcaspi.select_pin) = (uint8_t)l_tmp;
            }

            if (0 != errno)
            {
                return CKR_GENERAL_ERROR;
            }
        }
        if (argc > 3)
        {
            errno = 0;
            l_tmp = strtol(argv[3], NULL, 10);

            if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U32_MAX))
            {
                ATCA_IFACECFG_VALUE(cfg, atcaspi.baud) = (uint32_t)l_tmp;
            }

            if (0 != errno)
            {
                return CKR_GENERAL_ERROR;
            }
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

        if (argc > 1)
        {
            (void)strncpy((char*)slot_ctx->devpath, argv[1], sizeof(slot_ctx->devpath) - 1u);
            slot_ctx->devpath[sizeof(slot_ctx->devpath) - 1u] = (uint8_t)'\0';
        }
        if (argc > 2)
        {
            errno = 0;
            l_tmp = strtol(argv[2], NULL, 10);

            if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U8_MAX))
            {
                ATCA_IFACECFG_VALUE(cfg, atcakit.dev_identity) = (uint8_t)l_tmp;
            }

            if (0 != errno)
            {
                return CKR_GENERAL_ERROR;
            }
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

        if (slot >= 0 && slot < 16)
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

static CK_RV pkcs11_config_parse_object(pkcs11_slot_ctx_ptr slot_ctx, char* cfgstr, pkcs11_object_ptr *ptrObject)
{
    char* argv[5] = { "", "", "", "", "" };
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

        if ((0 != errno) || (l_tmp < 0) || (l_tmp > PKCS11_CONFIG_U16_MAX))
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
            if ((0 != errno) || (l_tmp < 0) || (l_tmp > PKCS11_CONFIG_U16_MAX))
            {
                rv = CKR_GENERAL_ERROR;
            }
            else
            {
                pObject->slot = (uint16_t)l_tmp;
            }

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

            if ((0 != errno) || (l_tmp < 0) || (l_tmp > PKCS11_CONFIG_U16_MAX))
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

            if ((0 != errno) || (l_tmp < 0) || (l_tmp > PKCS11_CONFIG_U16_MAX))
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

    if (NULL != ptrObject && (CKR_OK == rv))
    {
        *ptrObject = pObject;
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
        if ((0 == errno) && (l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U16_MAX))
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
            rv = pkcs11_config_parse_object(slot_ctx, argv[i + 1], NULL);
        }
        else
        {
            /* Unrecognized key encountered */
        }
    }
    return rv;
}

static CK_RV pkcs11_config_parse_object_file(pkcs11_slot_ctx_ptr slot_ctx, uint16_t slot, int argc, char * argv[])
{
    CK_RV rv = CKR_GENERAL_ERROR;
    int i = 0;
    pkcs11_object_ptr pObject = NULL;

    ((void)argc);

    if (0 == strcmp(argv[i], "type"))
    {
        rv = pkcs11_config_parse_object(slot_ctx, argv[i + 1], &pObject);

        if (CKR_OK == rv && NULL != pObject)
        {
            pObject->slot = slot;
        }

    }
    else if (0 == strcmp(argv[i], "label"))
    {
        rv = pkcs11_object_alloc(slot_ctx->slot_id, &pObject);
        if ((CKR_OK == rv) && (NULL != pObject))
        {
            pObject->slot = slot;
            pObject->flags = 0;
#if ATCA_CA_SUPPORT
            pObject->config = &slot_ctx->cfg_zone;
#endif
            (void)memcpy((char*)pObject->name, argv[i + 1], sizeof(pObject->name) - 1u);
        }
    }
    else
    {
        /* Unrecognized handle type */
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
    const char *objtype = "";
    char filename[200];
    char child_config_data[200];
    FILE* configfile = NULL;
    CK_RV rv = CKR_FUNCTION_FAILED;
    uint16_t handle = UINT16_MAX;

    if (atcab_is_ca_device(pSlot->interface_config.devtype))
    {
#if ATCA_CA_SUPPORT
        uint8_t i = 0;
        /* Find a free slot that matches the object type */
        for (i = 0; i < 16u; i++)
        {
            if (0u < (pSlot->flags & ((CK_FLAGS)1 << i)))
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
#if ATCA_TA_SUPPORT && TALIB_CREATE_SHARED_DATA_EN
        ATCA_STATUS status = talib_create_element(pSlot->device_ctx, &pObject->handle_info, &handle);
        rv = pkcs11_util_convert_rv(status);
#endif
    }

    if (UINT16_MAX != handle)
    {
        pObject->slot = handle;
        pObject->flags = PKCS11_OBJECT_FLAG_DESTROYABLE;

#if ATCA_CA_SUPPORT
        if (atcab_is_ca_device(pSlot->interface_config.devtype))
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

        int ret = 0x00;
        if (atcab_is_ca_device(pSlot->interface_config.devtype))
        {
#if ATCA_CA_SUPPORT
            ret = snprintf(filename, sizeof(filename), "%s%lu.%u.conf", pLibCtx->config_path,
                           pSlot->slot_id, pObject->slot);
#endif
        }
        else
        {
            ret = snprintf(filename, sizeof(filename), "%s%lu.%04x.conf", pLibCtx->config_path,
                           pSlot->slot_id, pObject->slot);
        }

        if (ret > 0 && ret < (int)sizeof(filename))
        {
            /* coverity[cert_fio32_c_violation] files are created in pLibCtx->config_path which has already been validated as a proper device*/
            /* coverity[misra_c_2012_rule_10_1_violation] Macro usage is valid per POSIX specification*/
            configfile = fopen(filename, "w");
            if (NULL != configfile)
            {
                (void)snprintf(child_config_data, sizeof(child_config_data), "%s,%s,0x%04x", objtype, pObject->name, pObject->slot);

                (void)fprintf(configfile, "type = %s\n", child_config_data);
                (void)fclose(configfile);
                rv = CKR_OK;
            }
        }
    }

    return rv;
}

CK_RV pkcs11_config_remove_object(pkcs11_lib_ctx_ptr pLibCtx, pkcs11_slot_ctx_ptr pSlot, pkcs11_object_ptr pObject)
{
    char filename[200];
    int ret = 0x00;
    if (atcab_is_ca_device(pSlot->interface_config.devtype))
    {
        ret = snprintf(filename, sizeof(filename), "%s%lu.%u.conf", pLibCtx->config_path,
                       pSlot->slot_id, pObject->slot);
    }
    else
    {
        ret = snprintf(filename, sizeof(filename), "%s%lu.%04x.conf", pLibCtx->config_path,
                       pSlot->slot_id, pObject->slot);
    }

    if (ret > 0 && ret < (int)sizeof(filename))
    {
        (void)remove(filename);
        if (atcab_is_ca_device(pSlot->interface_config.devtype))
        {
#if ATCA_CA_SUPPORT
            /* coverity[cert_int34_c_violation] shift will not affect precision since slot max can be only till 15 */
            pSlot->flags |= ((CK_FLAGS)1 << pObject->slot);
#endif
        }
    }

    return CKR_OK;
}

/* Load configuration from the filesystem */
CK_RV pkcs11_config_load_objects(pkcs11_slot_ctx_ptr slot_ctx)
{
#ifndef _WIN32
    DIR* directory;
    struct dirent* de;
    FILE* fp;
    char* buf;
    size_t buflen;
    int argc = 0;
    CK_BYTE i = 0;
    char* argv[2 * (PKCS11_MAX_OBJECTS_ALLOWED + PKCS11_MAX_CONFIG_ALLOWED)];
    pkcs11_conf_filedata_ptr updateConfFileData[MAX_CONF_FILES];
    char fileName_tmp[MAX_CONF_FILE_NAME_SIZE];
    CK_BYTE totalConfFileCount = 0;
    long l_tmp = 0;

    if (NULL == slot_ctx)
    {
        return CKR_ARGUMENTS_BAD;
    }

    (void)memset(updateConfFileData, 0, sizeof(updateConfFileData));

    pkcs11_lib_ctx_ptr pLibCtx = pkcs11_get_context();
    CK_RV rv = CKR_OK;

    /* Open the general library configuration */
    /* coverity[cert_fio32_c_violation] files are created in pLibCtx->config_path which has already been validated as a proper device*/
    fp = fopen(ATCA_LIBRARY_CONF, "rb");
    if (NULL != fp)
    {
        buflen = pkcs11_config_load_file(fp, &buf);
        (void)fclose(fp);
        fp = NULL;

        if (0u < buflen)
        {
            if (0 < (argc = pkcs11_config_parse_buffer(buf, buflen, (int)(sizeof(argv) / sizeof(argv[0])), argv)))
            {
                if (strcmp("filestore", argv[0]) == 0)
                {
                    buflen = strlen(argv[1]);
                    (void)memcpy((char*)pLibCtx->config_path, argv[1], buflen);

                    if (pLibCtx->config_path[buflen - 1u] != (unsigned char)'/')
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
            pkcs11_os_free(buf);
        }
    }
    else
    {
        rv = CKR_GENERAL_ERROR;
    }

    if (NULL != (directory = opendir((char*)pLibCtx->config_path)))
    {
        /*Update all the conf file names*/
        /* coverity[misra_c_2012_rule_13_5_violation] readdir is needed for the loop */
        while ((CKR_OK == rv) && (NULL != (de = readdir(directory))))
        {
            if ((uint8_t)DT_REG == de->d_type)
            {
                size_t fn_len = strlen(de->d_name);
                if (5u < fn_len && ((size_t)MAX_CONF_FILE_NAME_SIZE > fn_len))
                {
                    /* Configuration files must end with ".conf" */
                    if (0 == strcmp(&de->d_name[fn_len - 5u], ".conf"))
                    {
                        /* coverity[misra_c_2012_directive_4_12_violation] Standard library functions are required */
                        /* coverity[misra_c_2012_rule_21_3_violation] Standard library functions are required */
                        updateConfFileData[i] = (pkcs11_conf_filedata*)malloc(sizeof(pkcs11_conf_filedata));

                        if (NULL != updateConfFileData[i])
                        {
                            (void)strcpy(updateConfFileData[i]->filename, de->d_name);
                            updateConfFileData[i]->initialized = false;

                            if (UINT8_MAX > totalConfFileCount)
                            {
                                totalConfFileCount++;
                            }
                        }
                        i++;
                    }
                }
            }
        }
        /* Reset Index after updating the list*/
        i = 0;

        /* close directory */
        (void)closedir(directory);
    }
    else
    {
        rv = CKR_GENERAL_ERROR;
        PKCS11_DEBUG("Failed to open directory");
    }

    argc = sizeof(argv) / sizeof(argv[0]);
    /* First parse base file and then parse handle files if present*/
    while (NULL != updateConfFileData[i])
    {
        size_t fileName_len = strlen(updateConfFileData[i]->filename);
        (void)memcpy((void*)fileName_tmp, (const void*)updateConfFileData[i]->filename, sizeof(updateConfFileData[i]->filename));
        fileName_tmp[fileName_len] = '\0';
        pkcs11_config_split_string(fileName_tmp, '.', &argc, argv);

        /* Load Base file first and then load child files*/
        if ((2 == argc) && (false == updateConfFileData[i]->initialized))
        {

            size_t fnlen = strlen((char*)pLibCtx->config_path) + strlen(updateConfFileData[i]->filename) + 1u;
            char* filename = pkcs11_os_malloc(fnlen);

            if (NULL == filename)
            {
                rv = CKR_HOST_MEMORY;
                PKCS11_DEBUG("Failed to allocated a filename buffer\n");
                break;
            }
            (void)snprintf(filename, fnlen, "%s%s", pLibCtx->config_path, updateConfFileData[i]->filename);

            if (0 == strcmp(argv[argc - 1], "conf"))
            {
                errno = 0;
                CK_SLOT_ID slot_id = 0;
                l_tmp = strtol(argv[0], NULL, 10);

                if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U32_MAX))
                {
                    slot_id = (CK_SLOT_ID)l_tmp;
                }

                if (0 != errno)
                {
                    pkcs11_os_free(filename);
                    break;
                }

                CK_SLOT_ID baseSlotid_tmp = slot_id;

                PKCS11_DEBUG("Opening Configuration: %s\n", filename);
                /* coverity[cert_fio32_c_violation] files are created in pLibCtx->config_path which has already been validated as a proper device*/
                fp = fopen(filename, "rb");
                pkcs11_os_free(filename);
                if (NULL != fp)
                {
                    buflen = pkcs11_config_load_file(fp, &buf);

                    if (0U < buflen)
                    {
                        if (0u == slot_ctx->label[0])
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
                            if (NULL != slot_ctx)
                            {
                                slot_ctx->slot_id = slot_id;

                                /* Set Defaults */
                                slot_ctx->user_pin_handle = 0xFFFF;
                                slot_ctx->so_pin_handle = 0xFFFF;
                            }
                            else
                            {
                                /* Load configuration untill max PKCS11 slots allowed*/
                                pkcs11_os_free(buf);
                                (void)fclose(fp);
                                break;
                            }
                        }

                        if (CKR_OK == rv)
                        {
                            if (0 < (argc = pkcs11_config_parse_buffer(buf, buflen, (int)(sizeof(argv) / sizeof(argv[0])), argv)))
                            {
                                rv = pkcs11_config_parse_slot_file(slot_ctx, argc, argv);
                                PKCS11_DEBUG("Load conf file status [%d] slot_id [%d]\n", slot_ctx->slot_id);
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
                            if (0u == slot_ctx->label[0])
                            {
                                (void)snprintf((char*)slot_ctx->label, sizeof(slot_ctx->label) - 1u, "%02XABC", (uint8_t)slot_ctx->slot_id);
                            }
                            /* Load configuration is successful*/
                            slot_ctx->slot_state = SLOT_STATE_CONFIGURED;
                            updateConfFileData[i]->initialized = true;
                        }
#endif
                        pkcs11_os_free(buf);
                    }
                    (void)fclose(fp);

                    /* Base conf file load success, check for all child files and load them*/
                    if (CKR_OK == rv)
                    {
                        CK_ULONG idx;
                        /* Check all conf files for THE correponding child conf files */
                        for (idx = 0; idx < totalConfFileCount; idx++)
                        {
                            argc = sizeof(argv) / sizeof(argv[0]);

                            (void)memset(fileName_tmp, 0, sizeof(fileName_tmp));
                            size_t fileNametmp_len = strlen(updateConfFileData[idx]->filename);
                            (void)memcpy((void*)fileName_tmp, (const void*)updateConfFileData[idx]->filename, sizeof(updateConfFileData[idx]->filename));
                            fileName_tmp[fileNametmp_len] = '\0';
                            pkcs11_config_split_string(fileName_tmp, '.', &argc, argv);

                            errno = 0;
                            CK_SLOT_ID c_tmp = 0;
                            l_tmp = strtol(argv[0], NULL, 10);
                            if (l_tmp >= 0 && l_tmp <= (long)PKCS11_MAX_SLOTS_ALLOWED)
                            {
                                c_tmp = (CK_SLOT_ID)l_tmp;
                            }

                            if (0 != errno)
                            {
                                break;
                            }
                            /* If the child file slot id matches with parent file slot id
                               and if not initialized load the configuration*/
                            if ((argc > 0) && (0 == strcmp(argv[argc - 1], "conf")) && (3 == argc) \
                                && (baseSlotid_tmp == c_tmp) && !updateConfFileData[idx]->initialized)
                            {
                                fnlen = strlen((char*)pLibCtx->config_path) + strlen((char*)updateConfFileData[idx]->filename) + 1u;

                                char* handlefilename = pkcs11_os_malloc(fnlen);

                                if (NULL == handlefilename)
                                {
                                    rv = CKR_HOST_MEMORY;
                                    PKCS11_DEBUG("Failed to allocated a filename buffer\n");
                                    break;
                                }
                                (void)snprintf(handlefilename, fnlen, "%s%s", pLibCtx->config_path, updateConfFileData[idx]->filename);

                                errno = 0;
                                CK_SLOT_ID cslot_id = 0;
                                l_tmp = strtol(argv[0], NULL, 10);
                                if ((l_tmp >= 0) && (l_tmp <= (long)PKCS11_MAX_SLOTS_ALLOWED))
                                {
                                    cslot_id = (CK_SLOT_ID)l_tmp;
                                }

                                if (0 != errno)
                                {
                                    pkcs11_os_free(handlefilename);
                                    break;
                                }
                                PKCS11_DEBUG("Opening Child Configuration: %s\n", handlefilename);
                                /* coverity[cert_fio32_c_violation] files are created in pLibCtx->config_path which has already been validated as a proper device*/
                                fp = fopen(handlefilename, "rb");
                                pkcs11_os_free(handlefilename);
                                if (NULL != fp)
                                {
                                    buflen = pkcs11_config_load_file(fp, &buf);

                                    if (0u < buflen)
                                    {
                                        errno = 0;
                                        uint16_t handle = 0;
                                        l_tmp = strtol(argv[1], NULL, 16);

                                        if ((l_tmp >= 0) && (l_tmp <= PKCS11_CONFIG_U16_MAX))
                                        {
                                            handle = (uint16_t)l_tmp;
                                        }

                                        if (0 != errno)
                                        {
                                            pkcs11_os_free(buf);
                                            (void)fclose(fp);
                                            break;
                                        }

                                        if (0u == slot_ctx->label[0] || (slot_ctx->slot_id != cslot_id))
                                        {
                                            rv = CKR_GENERAL_ERROR;
                                            PKCS11_DEBUG("Trying to load an object configuration without a slot configuration file\n");
                                        }

                                        if (CKR_OK == rv)
                                        {
                                            (void)memset(argv, 0, sizeof(argv));
                                            if (0 < (argc = pkcs11_config_parse_buffer(buf, buflen, (int)(sizeof(argv) / sizeof(argv[0])), argv)))
                                            {
                                                rv = pkcs11_config_parse_object_file(slot_ctx, handle, argc, argv);
                                                PKCS11_DEBUG("Load Handle file status [%d] slot_id [%d]\n", slot_ctx->slot_id);
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
                                            if (atcab_is_ca_device(slot_ctx->interface_config.devtype))
                                            {
                                                /* Remove the slot from the free list*/
                                                slot_ctx->flags &= ~((CK_ULONG)1 << handle);
                                            }
#endif
                                            /* Child conf loaded successfully*/
                                            updateConfFileData[idx]->initialized = true;
                                        }
                                        pkcs11_os_free(buf);

                                    }
                                    (void)fclose(fp);
                                }
                            }
                        }
                    }
                }
                else
                {
                    rv = CKR_GENERAL_ERROR;
                    PKCS11_DEBUG("Unable to open the configuration file\n");
                }
            }
            else
            {
                pkcs11_os_free(filename);
            }
        }

        i++;
    }

    for (i = 0; NULL != updateConfFileData[i]; i++)
    {
        pkcs11_os_free(updateConfFileData[i]);
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
        if (CKR_OK == (rv = pkcs11_config_load_objects(slot_ctx)))
        {
            slot_ctx->slot_state = SLOT_STATE_CONFIGURED;
        }
    }

    return rv;
}

#ifdef __COVERITY__
#pragma coverity compliance end_block "MISRA C-2012 Rule 10.3" "MISRA C-2012 Rule 21.6" "CERT POS54-C"
#endif

/** @} */
