/**
 * \file
 * \brief PKCS11 Library Slot Handling
 *
 * The nomenclature here can lead to some confusion - the pkcs11 slot is
 * not the same as a device slot. So for example each slot defined here is a
 * specific device (most systems would have only one). The "slots" as defined
 * by the device specification would be enumerated seperately as related to
 * specific supported mechanisms as cryptographic "objects".
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
#include "pkcs11_init.h"
#include "pkcs11_slot.h"
#include "pkcs11_info.h"
#include "pkcs11_util.h"
#include "pkcs11_object.h"
#include "pkcs11_os.h"

#include <stdio.h>

/**
 * \defgroup pkcs11 Slot Management (pkcs11_)
   @{ */

#ifdef ATCA_NO_HEAP
static pkcs11_slot_ctx pkcs11_slot_cache[PKCS11_MAX_SLOTS_ALLOWED];
#endif

/**
 * \brief Retrieve the current slot context
 */
pkcs11_slot_ctx_ptr pkcs11_slot_get_context(pkcs11_lib_ctx_ptr lib_ctx, CK_SLOT_ID slotID)
{
    if (NULL == lib_ctx)
    {
        lib_ctx = pkcs11_get_context();
    }

    if (NULL != lib_ctx && NULL != lib_ctx->slots)
    {
        pkcs11_slot_ctx_ptr rv = (pkcs11_slot_ctx_ptr)lib_ctx->slots;
        CK_ULONG idx = 0;
        for (idx = 0; idx < lib_ctx->slot_cnt; idx++)
        {
            if (rv->slot_id == slotID)
            {
                return rv;
            }
            rv++;
        }
    }
    return NULL;
}

pkcs11_slot_ctx_ptr pkcs11_slot_get_new_context(pkcs11_lib_ctx_ptr lib_ctx)
{
    if (NULL == lib_ctx)
    {
        lib_ctx = pkcs11_get_context();
    }

    if (NULL != lib_ctx && NULL != lib_ctx->slots)
    {
        pkcs11_slot_ctx_ptr rv = (pkcs11_slot_ctx_ptr)lib_ctx->slots;
        CK_ULONG idx = 0;
        for (idx = 0; idx < lib_ctx->slot_cnt; idx++)
        {
            if (SLOT_STATE_UNINITIALIZED == rv->slot_state)
            {
                return rv;
            }
            rv++;
        }
    }
    return NULL;
}

CK_VOID_PTR pkcs11_slot_initslots(CK_ULONG pulCount)
{
#ifdef ATCA_NO_HEAP
    int i;
    for (i = 0; i < PKCS11_MAX_SLOTS_ALLOWED; i++)
    {
        (void)memset(&pkcs11_slot_cache[i], 0, sizeof(pkcs11_slot_ctx));
    }

    return &pkcs11_slot_cache;
#else
    pkcs11_slot_ctx_ptr slot_ctx_array = NULL;

    if (pulCount <= (CK_ULONG)((SIZE_MAX / sizeof(pkcs11_slot_ctx)) & UINT32_MAX))
    {
        slot_ctx_array = pkcs11_os_malloc(sizeof(pkcs11_slot_ctx) * pulCount);
    }

    if (NULL != slot_ctx_array)
    {
        (void)memset(slot_ctx_array, 0, sizeof(pkcs11_slot_ctx) * pulCount);
    }
    return slot_ctx_array;
#endif
}

CK_RV pkcs11_slot_deinitslots(pkcs11_lib_ctx_ptr lib_ctx)
{
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL == lib_ctx)
    {
        lib_ctx = pkcs11_get_context();
    }

    if (NULL != lib_ctx->slots)
    {
#ifdef ATCA_NO_HEAP
        int i;
        for (i = 0; i < PKCS11_MAX_SLOTS_ALLOWED; i++)
        {
            (void)memset(&pkcs11_slot_cache[i], 0, sizeof(pkcs11_slot_ctx));
        }
#else
        /* free device context*/
        pkcs11_slot_ctx_ptr pslot_ctx = (pkcs11_slot_ctx_ptr)lib_ctx->slots;
        CK_ULONG i = 0;
        for (i = 0; i < lib_ctx->slot_cnt; i++)
        {
            if ((NULL != pslot_ctx) && (NULL != pslot_ctx->device_ctx))
            {
                pkcs11_os_free(pslot_ctx->device_ctx);
            }
            pslot_ctx++;
        }

        (void)memset(lib_ctx->slots, 0, sizeof(pkcs11_slot_ctx) * PKCS11_MAX_SLOTS_ALLOWED);
        pkcs11_os_free(lib_ctx->slots);
#endif
        rv = CKR_OK;
    }
    return rv;
}

CK_RV pkcs11_slot_config(CK_SLOT_ID slotID)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    pkcs11_slot_ctx_ptr slot_ctx;
    CK_RV rv;

    if (NULL == lib_ctx)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    slot_ctx = pkcs11_slot_get_context(lib_ctx, slotID);

    if (NULL == slot_ctx)
    {
        return CKR_SLOT_ID_INVALID;
    }

    /* Set Defaults */
    slot_ctx->user_pin_handle = 0xFFFF;
    slot_ctx->so_pin_handle = 0xFFFF;

    /* Load the configuration */
    rv = pkcs11_config_load(slot_ctx);

    return rv;
}

#if defined(ATCA_HAL_KIT_BRIDGE) && defined(PKCS11_TESTING_ENABLE)
/* coverity[misra_c_2012_rule_8_6_violation] never defined */
extern ATCA_STATUS hal_kit_bridge_connect(ATCAIfaceCfg *, int, char **);
#endif

#if defined(PKCS11_508_SUPPORT) && defined(PKCS11_608_SUPPORT)
static ATCA_STATUS pkcs11_slot_check_device_type(ATCAIfaceCfg *ifacecfg, ATCADevice device)
{
    uint8_t info[4] = { 0 };
    ATCA_STATUS status = atcab_info_ext(device, info);

    if (ATCA_SUCCESS == status)
    {
        ATCADeviceType devType = ATCA_DEV_UNKNOWN;

        if (0x50 == info[2])
        {
            devType = ATECC508A;
        }
        else if (0x60 == info[2])
        {
            devType = ATECC608;
        }

        if (ifacecfg->devtype != devType)
        {
            ifacecfg->devtype = devType;
            (void)atcab_release_ext(&device);
            atca_delay_ms(1);
            status = atcab_init_ext(&device, ifacecfg);
        }
    }

    return status;
}
#endif

/** \brief This is an internal function that initializes a pkcs11 slot - it must already have the locks in place before being called. */
CK_RV pkcs11_slot_init(CK_SLOT_ID slotID)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    pkcs11_slot_ctx_ptr slot_ctx;
    ATCA_STATUS status = (ATCA_STATUS)CKR_OK;
    int retries;

    if (NULL == lib_ctx)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    slot_ctx = pkcs11_slot_get_context(lib_ctx, slotID);

    if (NULL == slot_ctx)
    {
        return CKR_SLOT_ID_INVALID;
    }

#if PKCS11_USE_STATIC_CONFIG
    if (CKR_OK != pkcs11_config_interface(slot_ctx))
    {
        return CKR_DEVICE_ERROR;
    }
#endif

    if (SLOT_STATE_CONFIGURED == slot_ctx->slot_state)
    {
        ATCAIfaceCfg *ifacecfg = &slot_ctx->interface_config;

        retries = 2;
        do
        {
#if defined(ATCA_HAL_KIT_BRIDGE) && defined(PKCS11_TESTING_ENABLE)
            if (ATCA_KIT_IFACE == ifacecfg->iface_type)
            {
                int argc = 3;
                char *argv[3];
                pkcs11_config_split_string((char*)slot_ctx->devpath, ':', &argc, argv);
                status = hal_kit_bridge_connect(ifacecfg, argc, argv);
            }
            if (ATCA_SUCCESS == status)
#endif
            {
                /* If a PKCS11 was killed an left the device in the idle state then
                   starting up again will require the device to go back to a known state
                   that is accomplished here by retrying the initalization */
                slot_ctx->device_ctx = NULL;
                status = atcab_init_ext(&slot_ctx->device_ctx, ifacecfg);
            }
        } while (retries-- != 0 && status != ATCA_SUCCESS);

#ifdef ATCA_HAL_I2C
        if (ATCA_SUCCESS != status)
        {
            if (0xC0u != ATCA_IFACECFG_VALUE(ifacecfg, atcai2c.address))
            {
                /* Try the default address */
                ATCA_IFACECFG_VALUE(ifacecfg, atcai2c.address) = 0xC0;
                (void)atcab_release_ext(&slot_ctx->device_ctx);
                atca_delay_ms(1);
                retries = 2;
                do
                {
                    /* Same as the above */
                    slot_ctx->device_ctx = NULL;
                    status = atcab_init_ext(&slot_ctx->device_ctx, ifacecfg);
                    retries--;
                } while ((retries != 0) && (ATCA_SUCCESS != status));
            }
        }
#endif

#if defined(PKCS11_508_SUPPORT) && defined(PKCS11_608_SUPPORT)
        /* If both are supported check the device to verify */
        if ((ATCA_SUCCESS == status) && atcab_is_ca_device(ifacecfg->devtype))
        {
            status = pkcs11_slot_check_device_type(ifacecfg, slot_ctx->device_ctx);
        }
#endif

        if (ATCA_SUCCESS == status)
        {
            if (atcab_is_ca_device(ifacecfg->devtype))
            {
#if ATCA_CA_SUPPORT
                /* Only the classic cryptoauth devices require the configuration
                   to be loaded into memory */
                status = atcab_read_config_zone_ext(slot_ctx->device_ctx, (uint8_t*)&slot_ctx->cfg_zone);
#else
                status = ATCA_GEN_FAIL;
#endif
            }
            else
            {
#if ATCA_TA_SUPPORT
                /* Iterate through all objects and attach handle info */
                status = pkcs11_object_load_handle_info(slot_ctx->device_ctx, lib_ctx);
#else
                status = ATCA_GEN_FAIL;
#endif
            }
        }

        if (ATCA_SUCCESS == status)
        {
            slot_ctx->slot_id = slotID;
            slot_ctx->slot_state = SLOT_STATE_READY;
        }
    }

    return (ATCA_SUCCESS == status) ? CKR_OK : CKR_DEVICE_ERROR;
}

static CK_ULONG pkcs11_slot_get_active_count(pkcs11_lib_ctx_ptr lib_ctx)
{
    CK_ULONG active_cnt = 0;
    CK_ULONG i;

    pkcs11_slot_ctx_ptr pslot = (pkcs11_slot_ctx_ptr)lib_ctx->slots;

    if (NULL != pslot)
    {
        for (i = 0; i < lib_ctx->slot_cnt; i++)
        {
            /* coverity[misra_c_2012_rule_14_3_violation] after increment pslot can be null */
            if (NULL != pslot && (SLOT_STATE_UNINITIALIZED != pslot->slot_state))
            {
                if (active_cnt < UINT32_MAX)
                {
                    active_cnt++;
                }
            }

            pslot++;
        }
    }
    return active_cnt;
}

static void pkcs11_slot_fill_list(pkcs11_lib_ctx_ptr lib_ctx, CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList)
{
    CK_ULONG i;
    CK_ULONG j = 0;

    pkcs11_slot_ctx_ptr pslot = (pkcs11_slot_ctx_ptr)lib_ctx->slots;

    if (NULL != pslot)
    {
        for (i = 0; i < lib_ctx->slot_cnt; i++)
        {
            if (tokenPresent)
            {
                /* coverity[misra_c_2012_rule_14_3_violation] pslot can be NUll after increment */
                if (NULL != pslot && (SLOT_STATE_UNINITIALIZED != pslot->slot_state))
                {
                    if (j < UINT32_MAX)
                    {
                        pSlotList[j++] = pslot->slot_id;
                        PKCS11_DEBUG("Slot Id: %d \n", pslot->slot_id);
                    }
                }
            }
            else
            {
                /* coverity[misra_c_2012_rule_14_3_violation] pslot can be NUll after increment */
                if (NULL != pslot)
                {
                    pSlotList[j++] = pslot->slot_id;
                }
            }
            pslot++;
        }
    }
}

CK_RV pkcs11_slot_get_list(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    CK_ULONG slot_cnt = 0;

    if (NULL == lib_ctx || FALSE == lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    /* Ref PKCS11 Sec 5.5 - C_GetSlotList */
    if (NULL == pulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (tokenPresent)
    {
        /* Get the list of installed devices */
        slot_cnt = pkcs11_slot_get_active_count(lib_ctx);
    }
    else
    {
        slot_cnt = lib_ctx->slot_cnt;
    }

    /* Ref PKCS11 Sec 5.5 - C_GetSlotList Requirement #2 */
    if (NULL != pSlotList)
    {
        if (slot_cnt > *pulCount)
        {
            *pulCount = slot_cnt;
            return CKR_BUFFER_TOO_SMALL;
        }
        else
        {
            pkcs11_slot_fill_list(lib_ctx, tokenPresent, pSlotList);
        }
    }

    *pulCount = slot_cnt;

    return CKR_OK;
}

/**
 * \brief Obtains information about a particular slot
 */
CK_RV pkcs11_slot_get_info(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    pkcs11_slot_ctx_ptr slot_ctx;
    ATCAIfaceCfg *if_cfg_ptr;
    CK_UTF8CHAR buf[8] = { 0 };
    CK_RV rv = CKR_OK;

    if (NULL == lib_ctx || FALSE == lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (NULL == pInfo)
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* Initialize the input structure */
    (void)memset(pInfo, 0, sizeof(CK_SLOT_INFO));

    /* Retreive the slot context - i.e. the attached device (ECC508A, SHA256, etc) */
    slot_ctx = pkcs11_slot_get_context(lib_ctx, slotID);

    if (NULL == slot_ctx)
    {
        return CKR_SLOT_ID_INVALID;
    }

    /* Default version information */
    pInfo->hardwareVersion.major = (CK_BYTE)(CK_UNAVAILABLE_INFORMATION & 0xFFu);
    pInfo->hardwareVersion.minor = (CK_BYTE)(CK_UNAVAILABLE_INFORMATION & 0xFFu);
    pInfo->firmwareVersion.major = (CK_BYTE)(CK_UNAVAILABLE_INFORMATION & 0xFFu);
    pInfo->firmwareVersion.minor = (CK_BYTE)(CK_UNAVAILABLE_INFORMATION & 0xFFu);

    /* Get the reference to the slot configuration structure that was used */
    if_cfg_ptr = &slot_ctx->interface_config;

    /* Set up the flags - Always a hardware slot, only removable devices can
       be listed as not present */
    pInfo->flags = CKF_HW_SLOT | CKF_TOKEN_PRESENT;

    /* So there a number of rules about what a slot can and can not be - this
       means there needs to be a fixed configuration somewhere or a scan
       operation when we intialize */

    /* if the interface is USB then it's removable otherwise assume it's not - This might require a
        configuration API for cases where the device is used for consumable authentication */
    if (ATCA_UART_IFACE == if_cfg_ptr->iface_type || ATCA_HID_IFACE == if_cfg_ptr->iface_type)
    {
        pInfo->flags |= CKF_REMOVABLE_DEVICE;
        if (SLOT_STATE_READY != slot_ctx->slot_state)
        {
            pInfo->flags &= ~CKF_TOKEN_PRESENT;
        }
    }

    /* Basic description of the expected interface based on the configuration */
    if (slotID <= (CK_ULONG)INT32_MAX)
    {
        /* coverity[misra_c_2012_rule_21_6_violation: FALSE] Standard library functions are required */
        (void)snprintf((char*)pInfo->slotDescription, sizeof(pInfo->slotDescription), "%d_%d_%d", (int)slotID,
                       (int)if_cfg_ptr->devtype, (int)if_cfg_ptr->iface_type);
    }

    if (SLOT_STATE_READY == slot_ctx->slot_state)
    {
        if (CKR_OK == (rv = pkcs11_lock_both(lib_ctx)))
        {
            if (CKR_OK == (rv = pkcs11_util_convert_rv(atcab_info_ext(slot_ctx->device_ctx, buf))))
            {
                /* SHA204 = 00 02 00 09, ECC508 = 00 00 50 00, AES132 = 0A 07*/
                pInfo->hardwareVersion.major = 0;
                pInfo->hardwareVersion.minor = buf[3];
            }
            (void)pkcs11_unlock_both(lib_ctx);
        }
    }

    /* Use the same manufacturer ID we use throughout */
    /* coverity[misra_c_2012_rule_21_6_violation] snprintf is approved for formatted string writes to buffers */
    (void)snprintf((char*)pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "%s", pkcs11_lib_manufacturer_id);

    /* Make sure strings are escaped properly */
    pkcs11_util_escape_string(pInfo->manufacturerID, (CK_ULONG)sizeof(pInfo->manufacturerID));
    pkcs11_util_escape_string(pInfo->slotDescription, (CK_ULONG)sizeof(pInfo->slotDescription));

    return rv;
}

/** @} */
