/**
 * \file
 * \brief PKCS11 Library Session Handling
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

#if ATCA_CA_SUPPORT
#include "host/atca_host.h"
#endif

#include "pkcs11_config.h"
#include "pkcs11_debug.h"
#include "pkcs11_session.h"
#include "pkcs11_token.h"
#include "pkcs11_init.h"
#include "pkcs11_slot.h"
#include "pkcs11_object.h"
#include "pkcs11_os.h"
#include "pkcs11_util.h"
#include "pkcs11_key.h"
#include "pkcs11_cert.h"

/**
 * \defgroup pkcs11 Session Management (pkcs11_)
   @{ */

#ifdef ATCA_NO_HEAP
static pkcs11_session_ctx pkcs11_session_cache[PKCS11_MAX_SESSIONS_ALLOWED];
#else
static pkcs11_session_ctx_ptr pkcs11_session_cache[PKCS11_MAX_SESSIONS_ALLOWED];
#endif

static pkcs11_session_ctx_ptr pkcs11_allocate_session_context(void)
{
    pkcs11_session_ctx_ptr rv = NULL;

#ifdef ATCA_NO_HEAP
    CK_ULONG i;
    for (i = 0; i < (CK_ULONG)PKCS11_MAX_SESSIONS_ALLOWED; i++)
    {

        if (!pkcs11_session_cache[i].initialized)
        {
            rv = &pkcs11_session_cache[i];
            break;
        }
    }
#else
    CK_ULONG i;
    for (i = 0; i < (CK_ULONG)PKCS11_MAX_SESSIONS_ALLOWED; i++)
    {
        if (NULL == pkcs11_session_cache[i])
        {
            /* Use dynamic memory assignement from OS abstraction layer */
            rv = pkcs11_os_malloc(sizeof(pkcs11_session_ctx));
            pkcs11_session_cache[i] = rv;
            break;
        }
    }
#endif

    return rv;
}

pkcs11_session_ctx_ptr pkcs11_get_session_context(CK_SESSION_HANDLE hSession)
{
    pkcs11_session_ctx_ptr rv = NULL;

#ifdef ATCA_NO_HEAP
    CK_ULONG i;
    for (i = 0; i < (CK_ULONG)PKCS11_MAX_SESSIONS_ALLOWED; i++)
    {
        if (hSession == pkcs11_session_cache[i].handle)
        {
            rv = &pkcs11_session_cache[i];
            break;
        }
    }
#else
    CK_ULONG i;
    for (i = 0; i < (CK_ULONG)PKCS11_MAX_SESSIONS_ALLOWED; i++)
    {
        if (NULL != pkcs11_session_cache[i])
        {
            if (hSession == pkcs11_session_cache[i]->handle)
            {
                rv = pkcs11_session_cache[i];
                break;
            }
        }
    }
#endif

    return rv;
}

static CK_RV pkcs11_session_free_session_context(pkcs11_session_ctx_ptr session_ctx)
{
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != session_ctx)
    {
        (void)pkcs11_util_memset(session_ctx, sizeof(pkcs11_session_ctx), 0, sizeof(pkcs11_session_ctx));
#ifdef ATCA_HEAP
        CK_ULONG i;
        for (i = 0; i < (CK_ULONG)PKCS11_MAX_SESSIONS_ALLOWED; i++)
        {
            if (session_ctx == pkcs11_session_cache[i])
            {
                pkcs11_session_cache[i] = NULL;
                pkcs11_os_free(session_ctx);
                break;
            }
        }
#endif
        rv = CKR_OK;
    }
    return rv;
}

/**
 * \brief Check if the session is initialized properly
 */
CK_RV pkcs11_session_check(pkcs11_session_ctx_ptr *pSession, CK_SESSION_HANDLE hSession)
{
    pkcs11_session_ctx_ptr ctx = pkcs11_get_session_context(hSession);
    CK_RV rv = CKR_SESSION_HANDLE_INVALID;

    if (NULL != ctx)
    {
        if (ctx->initialized)
        {
            rv = CKR_OK;
        }
        else
        {
            rv = CKR_SESSION_CLOSED;
        }
    }

    if (NULL != pSession)
    {
        if (CKR_OK != rv)
        {
            *pSession = NULL;
        }
        else
        {
            *pSession = ctx;
        }
    }
    return rv;
}


CK_RV pkcs11_reserve_resource(pkcs11_lib_ctx_ptr pContext, pkcs11_session_ctx_ptr pSession, uint8_t resource)
{
    CK_RV rv = CKR_OPERATION_ACTIVE;

    if ((NULL != pContext) && (NULL != pContext->dev_state))
    {
        if ((PKCS11_MAX_SLOTS_ALLOWED > pSession->slot->slot_id) && (PKCS11_MAX_DEV_CTX > resource))
        {
            if (CKR_OK == pkcs11_lock_both(pContext))
            {
                pkcs11_dev_ctx * ctx = &pContext->dev_state->resources[pSession->slot->slot_id].contexts[resource];

                #if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
                hal_pid_t ours = hal_get_pid();
                if (0 == ctx->owner || 0 != hal_check_pid(ctx->owner))
                {
                    ctx->session = pSession->handle;
                    ctx->owner = ours;
                    rv = ATCA_SUCCESS;
                }
                #endif

                if ((0u == ctx->session) || (ctx->session == pSession->handle))
                {
                    #if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
                    if (ctx->owner == ours)
                    {
                        ctx->session = pSession->handle;
                        ctx->owner = ours;
                    }
                    #else
                    ctx->session = pSession->handle;
                    rv = ATCA_SUCCESS;
                    #endif
                }
                (void)pkcs11_unlock_both(pContext);
            }
        }
    }

    return rv;
}

CK_RV pkcs11_release_resource(pkcs11_lib_ctx_ptr pContext, pkcs11_session_ctx_ptr pSession, uint8_t resource)
{
    CK_RV rv = CKR_GENERAL_ERROR;

    if ((NULL != pContext) && (NULL != pContext->dev_state))
    {
        if ((PKCS11_MAX_SLOTS_ALLOWED > pSession->slot->slot_id) && (PKCS11_MAX_DEV_CTX > resource))
        {
            if (CKR_OK == pkcs11_lock_both(pContext))
            {
                pkcs11_dev_ctx * ctx = &pContext->dev_state->resources[pSession->slot->slot_id].contexts[resource];
                if ((0U == ctx->session) || (ctx->session == pSession->handle))
                {
                    #if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
                    hal_pid_t ours = hal_get_pid();
                    if ((0 == ctx->owner) || (ctx->owner == ours))
                    {
                        ctx->session = 0;
                        ctx->owner = 0;
                        rv = ATCA_SUCCESS;
                    }
                    #else
                    ctx->session = 0;
                    rv = ATCA_SUCCESS;
                    #endif
                }
                (void)pkcs11_unlock_both(pContext);
            }
        }
    }

    return rv;
}

CK_RV pkcs11_session_open(
    CK_SLOT_ID              slotID,
    CK_FLAGS                flags,
    CK_VOID_PTR             pApplication,
    CK_NOTIFY               notify,
    CK_SESSION_HANDLE_PTR   phSession)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    pkcs11_slot_ctx_ptr slot_ctx;
    pkcs11_session_ctx_ptr session_ctx;

    ((void)pApplication);
    /* coverity[misra_c_2012_rule_11_1_violation:SUPPRESS] */
    ((void)notify);

    if (NULL == lib_ctx || FALSE == lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (NULL == phSession)
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* See PKCS11 Sec 5.6 - Legacy reaons */
    if (CKF_SERIAL_SESSION != (flags & CKF_SERIAL_SESSION))
    {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    /* Retrieve the slot context - i.e. the attached device (ECC508A, SHA256, etc) */
    slot_ctx = pkcs11_slot_get_context(lib_ctx, slotID);

    if (NULL == slot_ctx)
    {
        return CKR_SLOT_ID_INVALID;
    }

    if (SLOT_STATE_READY != slot_ctx->slot_state)
    {
        return CKR_TOKEN_NOT_RECOGNIZED;
    }

    /* See PKCS11 Sec 5.6 - if token_info returned write protected r/w is disallowed */
    // if (flags & CKF_RW_SESSION)
    //{
    //     return CKR_TOKEN_WRITE_PROTECTED;
    // }

    if (CKR_OK == pkcs11_lock_context(lib_ctx))
    {
        /* Get a new session context */
        session_ctx = pkcs11_allocate_session_context();

        /* Check that a session was created */
        if (NULL == session_ctx)
        {
            return CKR_HOST_MEMORY;
        }

        /* Initialize the session */
        session_ctx->slot = slot_ctx;
        session_ctx->initialized = TRUE;
        session_ctx->active_mech = CKM_VENDOR_DEFINED;
        session_ctx->state = CKS_RO_PUBLIC_SESSION;

        /* Assign the session handle */
        /* coverity[cert_int36_c_violation] A truncated pointer on 64 bit platforms should still be unique in a memory space */
        session_ctx->handle = (CK_SESSION_HANDLE)session_ctx;

        *phSession = session_ctx->handle;
        (void)pkcs11_unlock_context(lib_ctx);
    }

    return CKR_OK;
}

CK_RV pkcs11_session_close(CK_SESSION_HANDLE hSession)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    pkcs11_session_ctx_ptr session_ctx = pkcs11_get_session_context(hSession);
    pkcs11_slot_ctx_ptr slot_ctx;

    if (NULL == lib_ctx || FALSE == lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (NULL == session_ctx)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx->initialized)
    {
        return CKR_SESSION_CLOSED;
    }

    /* Get the slot */
    slot_ctx = (pkcs11_slot_ctx_ptr)session_ctx->slot;

    if (NULL != slot_ctx)
    {
        /* Do whatever we need to shutdown the session with the device */
    }
    else
    {
        /* We should go looking for the right slot since something got messed up
           that would be a pkcs11_slot_* function to find a slot given a session */
    }
    if (CKR_OK == pkcs11_lock_context(lib_ctx))
    {
        /* Free the session */
        (void)pkcs11_session_free_session_context(session_ctx);
        (void)pkcs11_unlock_context(lib_ctx);
    }

    return CKR_OK;
}

/**
 * \brief Close all sessions for a given slot - not actually all open sessions
 */
CK_RV pkcs11_session_closeall(CK_SLOT_ID slotID)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    pkcs11_slot_ctx_ptr slot_ctx;

    if (NULL == lib_ctx || FALSE == lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    slot_ctx = pkcs11_slot_get_context(lib_ctx, slotID);

    if (NULL == slot_ctx)
    {
        return CKR_SLOT_ID_INVALID;
    }

    /* If there were the ability to have multiple sessions open for a slot then
       we'd loop over the sessions and close them in order*/

#ifdef ATCA_NO_HEAP
    {
        CK_ULONG i;
        for (i = 0; i < (CK_ULONG)PKCS11_MAX_SESSIONS_ALLOWED; i++)
        {
            //! for specified slotid close all sessions related with it.
            if ((NULL != pkcs11_session_cache[i].slot) && (pkcs11_session_cache[i].slot->slot_id == slotID))
            {
                pkcs11_session_close(pkcs11_session_cache[i].handle);
            }
        }
    }
#else
    {
        CK_ULONG i;
        for (i = 0; i < (CK_ULONG)PKCS11_MAX_SESSIONS_ALLOWED; i++)
        {
            //! for specified slotid close all sessions related with it.
            if (NULL != pkcs11_session_cache[i])
            {
                if ((NULL != pkcs11_session_cache[i]->slot) && (pkcs11_session_cache[i]->slot->slot_id == slotID))
                {
                    (void)pkcs11_session_close(pkcs11_session_cache[i]->handle);
                }
            }
        }
    }
#endif

    return CKR_OK;
}

/**
 * \brief Obtains information about a particular session
 */
CK_RV pkcs11_session_get_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    pkcs11_session_ctx_ptr session_ctx = pkcs11_get_session_context(hSession);
    pkcs11_slot_ctx_ptr slot_ctx;

    if (NULL == lib_ctx || FALSE == lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (NULL == pInfo)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (NULL == session_ctx)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx->initialized)
    {
        return CKR_SESSION_CLOSED;
    }

    pInfo->state = session_ctx->state;
    pInfo->ulDeviceError = session_ctx->error;

    slot_ctx = session_ctx->slot;
    if (NULL != slot_ctx)
    {
        pInfo->slotID = slot_ctx->slot_id;
    }

    pInfo->flags = CKF_RW_SESSION | CKF_SERIAL_SESSION;

    return CKR_OK;
}

CK_RV pkcs11_session_login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = pkcs11_get_context();
    pkcs11_session_ctx_ptr session_ctx = pkcs11_get_session_context(hSession);
    bool is_ca_device = false;
    uint16_t key_len = 0;
    uint8_t auth_idx = 0;
    CK_RV rv;

    ((void)userType);

    if (NULL == pLibCtx || FALSE == pLibCtx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (NULL == pPin || 0u == ulPinLen)
    {
        PKCS11_DEBUG("pin: %p, pin-len: %d\n", pPin, ulPinLen);
        return CKR_ARGUMENTS_BAD;
    }

    if (NULL == session_ctx)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx->initialized)
    {
        return CKR_SESSION_CLOSED;
    }

    if (session_ctx->slot->logged_in)
    {
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    do
    {
        //! Reserve the PKCS11_AUTH_OP_0 / PKCS11_AUTH_OP_1 based on availability
        rv = pkcs11_reserve_resource(pLibCtx, session_ctx, (uint8_t)((PKCS11_AUTH_OP_0 + auth_idx) & UINT8_MAX));

        if(CKR_OK != rv)
        {
            auth_idx++;
        }
    }while((CKR_OK != rv) && (MAX_AUTH_SESSIONS > auth_idx));

    if(CKR_OK != rv)
    {
        //! Auth operation unavailable return error
        PKCS11_DEBUG(" Login failed: Resource unavailable\r\n");
        return rv;
    }

    is_ca_device = atcab_is_ca_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx));
    key_len = (uint16_t)(is_ca_device ? 32 : 16);

    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
#ifndef PKCS11_PIN_KDF_ALWAYS
        if ((uint16_t)(2u * key_len) == ulPinLen)
        {
            rv = pkcs11_token_convert_pin_to_key(pPin, ulPinLen, NULL, 0, session_ctx->slot->read_key, key_len, session_ctx->slot);
        }
        else
#endif
        {
            uint8_t sn[ATCA_SERIAL_NUM_SIZE];
            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {
                if (CKR_OK == (rv = pkcs11_util_convert_rv(atcab_read_serial_number_ext(session_ctx->slot->device_ctx, sn))))
                {
                    rv = pkcs11_token_convert_pin_to_key(pPin, ulPinLen, sn, (CK_LONG)sizeof(sn), session_ctx->slot->read_key, key_len, session_ctx->slot);
                }
                (void)pkcs11_unlock_device(pLibCtx);
            }
        }

#if (ATCA_TA_SUPPORT && ATCA_HOSTLIB_EN && TALIB_AUTH_EN)
        ATCA_STATUS status;
        if (CKR_OK == rv && atcab_is_ta_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)))
        {
            uint8_t auth_i_nonce[16] = { 0 };
            uint8_t auth_r_nonce[16] = { 0 };

#if PKCS11_AUTH_TERMINATE_BEFORE_LOGIN
            ATCADevice device = session_ctx->slot->device_ctx;
            (void)talib_auth_terminate(device);
#endif
            (void)atcac_sw_random(auth_r_nonce, sizeof(auth_r_nonce));

            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {
                    status = talib_auth_generate_nonce(session_ctx->slot->device_ctx, (TA_HANDLE_AUTH_SESSION0 + auth_idx),
                                                   TA_AUTH_GENERATE_OPT_NONCE_SRC_MASK | TA_AUTH_GENERATE_OPT_RANDOM_MASK, auth_i_nonce);

                if (CKR_OK == (rv = pkcs11_util_convert_rv(status)))
                {
                    cal_buffer key = CAL_BUF_INIT(16U, session_ctx->slot->read_key);
                    status = talib_auth_startup(session_ctx->slot->device_ctx, session_ctx->slot->user_pin_handle,
                                                TA_AUTH_ALG_ID_GCM128, 0x1FFF, &key, auth_i_nonce, auth_r_nonce);
                    rv = pkcs11_util_convert_rv(status);
                }

                if (CKR_OK != rv)
                {
                    PKCS11_DEBUG(" Login failed: Terminating auth session\r\n");
                    (void)talib_auth_terminate(session_ctx->slot->device_ctx);
                }
                (void)pkcs11_unlock_device(pLibCtx);
            }
        }
#endif
        (void)pkcs11_unlock_context(pLibCtx);
    }

    if (CKR_OK != rv)
    {
        (void)pkcs11_release_resource(pLibCtx, session_ctx, (uint8_t)((PKCS11_AUTH_OP_0 + auth_idx) & UINT8_MAX));
    }

    if (CKR_OK == rv)
    {
        session_ctx->slot->logged_in = TRUE;
        session_ctx->state = CKS_RO_USER_FUNCTIONS;
    }

    return rv;
}

CK_RV pkcs11_session_logout(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_OK;
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    pkcs11_session_ctx_ptr session_ctx = pkcs11_get_session_context(hSession);
    uint8_t auth_idx = 0;

    if (NULL == lib_ctx || FALSE == lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if (NULL == session_ctx)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!session_ctx->initialized)
    {
        return CKR_SESSION_CLOSED;
    }

#if (ATCA_TA_SUPPORT && TALIB_AUTH_EN)
    if (session_ctx->slot->logged_in && atcab_is_ta_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)))
    {
        if (CKR_OK == (rv = pkcs11_lock_both(lib_ctx)))
        {
            (void)talib_auth_terminate(session_ctx->slot->device_ctx);
            (void)pkcs11_unlock_both(lib_ctx);
        }
    }
#endif

    (void)pkcs11_cert_clear_session_cache(session_ctx);
    (void)pkcs11_key_clear_session_cache(session_ctx);

    do
    {
        (void)pkcs11_release_resource(lib_ctx, session_ctx, (uint8_t)((PKCS11_AUTH_OP_0 + auth_idx) & UINT8_MAX));
        auth_idx++;
     }while(MAX_AUTH_SESSIONS > auth_idx);

    /* Wipe the io protection secret regardless if the above operatios succeeded */
    (void)pkcs11_util_memset(session_ctx->slot->read_key, sizeof(session_ctx->slot->read_key), 0, sizeof(session_ctx->slot->read_key));

    session_ctx->slot->logged_in = FALSE;
    session_ctx->state = CKS_RO_PUBLIC_SESSION;

    return rv;
}

#if 0
/* Authorize an object for use - Legacy function @todo rework with new access model */
CK_RV pkcs11_session_authorize(pkcs11_session_ctx_ptr pSession, CK_VOID_PTR pObject)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    atecc508a_config_t * pConfig;

    ATCA_STATUS status;
    uint8_t response[MAC_SIZE];
    uint8_t sn[ATCA_SERIAL_NUM_SIZE];
    uint16_t key_id = PKCS11_PIN_SLOT;
    atca_check_mac_in_out_t checkmac_params;
    atca_temp_key_t temp_key;
    atca_nonce_in_out_t nonce_params;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];

    if (!pSession || !obj_ptr)
    {
        return CKR_ARGUMENTS_BAD;
    }

#if 0
    pConfig = (atecc508a_config_t*)obj_ptr->config;

    if (!pConfig)
    {
        return CKR_GENERAL_ERROR;
    }

    if (ATCA_KEY_CONFIG_REQ_AUTH_MASK & pConfig->KeyConfig[obj_ptr->slot])
    {
        key_id = (pConfig->KeyConfig[obj_ptr->slot] &
                  ATCA_KEY_CONFIG_AUTH_KEY_MASK) >> ATCA_KEY_CONFIG_AUTH_KEY_SHIFT;
    }
    else
    {
        /* No Authorization is required */
        return CKR_OK;
    }
#endif

    /* Initialize the intermediate buffers */
    (void)memset(&temp_key, 0, sizeof(temp_key));
    (void)memset(&nonce_params, 0, sizeof(nonce_params));
    (void)memset(num_in, 0, sizeof(num_in));
    (void)memset(other_data, 0, sizeof(other_data));

    /* Read Device Serial Number */
    status = atcab_read_serial_number(sn);

    if (ATCA_SUCCESS == status)
    {
        /* Perform random nonce and store it in tempkey */
        nonce_params.mode = NONCE_MODE_SEED_UPDATE;
        nonce_params.zero = 0;
        nonce_params.num_in = num_in;
        nonce_params.rand_out = rand_out;
        nonce_params.temp_key = &temp_key;
        status = atcab_nonce_rand(nonce_params.num_in, rand_out);
    }

    if (ATCA_SUCCESS == status)
    {
        /* Calculate nonce value of tempkey locally */
        status = atcah_nonce(&nonce_params);
    }

    if (ATCA_SUCCESS == status)
    {
        /* Calculate the expected checkmac answer the host will provide */
        other_data[0] = ATCA_MAC;
        other_data[2] = (uint8_t)key_id;

        checkmac_params.mode = CHECKMAC_MODE_BLOCK2_TEMPKEY;
        checkmac_params.key_id = key_id;
        checkmac_params.client_chal = NULL;
        checkmac_params.client_resp = response;
        checkmac_params.other_data = other_data;
        checkmac_params.sn = sn;
        checkmac_params.otp = NULL;
        checkmac_params.slot_key = pSession->read_key;
        checkmac_params.target_key = NULL;
        checkmac_params.temp_key = &temp_key;
        status = atcah_check_mac(&checkmac_params);
    }

    if (ATCA_SUCCESS == status)
    {
        /* Perform CheckMac which will compare the host provided
         * mac against the internally computed one */
        status = atcab_checkmac(
            checkmac_params.mode,
            checkmac_params.key_id,
            checkmac_params.client_chal,
            checkmac_params.client_resp,
            checkmac_params.other_data);
    }

    if (ATCA_SUCCESS == status)
    {
        return CKR_OK;
    }
    else
    {
        return CKR_PIN_INCORRECT;
    }
}
#endif

/** @} */
