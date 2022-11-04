/**
 * \file
 * \brief PKCS11 Library Init/Deinit
 *
 * Copyright (c) 2017 Microchip Technology Inc. All rights reserved.
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

#include "pkcs11_config.h"
#include "pkcs11_debug.h"
#include "pkcs11_init.h"
#include "pkcs11_os.h"
#include "pkcs11_slot.h"
#include "pkcs11_object.h"
#include "pkcs11_session.h"
#include "cryptoauthlib.h"

#ifdef CreateMutex
#undef CreateMutex /* CreateMutex is defined to CreateMutexW in synchapi.h in Windows. */
#endif

/**
 * \defgroup pkcs11 Initialization (pkcs11_)
   @{ */

/** Library intialization defaults if none were provided */
static const CK_C_INITIALIZE_ARGS pkcs11_init_defaults = {
    NULL_PTR,           /**< Callback to create a mutex */
    NULL_PTR,           /**< Callback to destroy a mutex */
    NULL_PTR,           /**< Callback to lock a mutex */
    NULL_PTR,           /**< Callback to unlock a mutex */
    CKF_OS_LOCKING_OK,  /**< Initialization Flags  */
    NULL_PTR,           /**< Reserved - Must be NULL */
};

/**
 * \brief Library Context - currently static but could be allocated
 */
static pkcs11_lib_ctx pkcs11_context;

/**
 * \brief Retrieve the current library context
 */
pkcs11_lib_ctx_ptr pkcs11_get_context(void)
{
    return &pkcs11_context;
}

CK_RV pkcs11_lock_context(pkcs11_lib_ctx_ptr pContext)
{
    CK_RV rv = CKR_OK;

    if (pContext)
    {
        if (pContext->lock_mutex)
        {
            rv = pContext->lock_mutex(pContext->lib_lock);
        }
        else
        {
            rv = pkcs11_os_lock_mutex(pContext->lib_lock);
        }

        if (CKR_OK == rv)
        {
            pContext->lib_locked = TRUE;
        }
    }
    return rv;
}

CK_RV pkcs11_unlock_context(pkcs11_lib_ctx_ptr pContext)
{
    CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

    if (!pContext)
    {
        pContext = pkcs11_get_context();
    }

    if (pContext)
    {
        /* Assume that even if unlock fails it will still have unlocked the mutex */
        pContext->lib_locked = FALSE;

        if (pContext->unlock_mutex)
        {
            rv = pContext->unlock_mutex(pContext->lib_lock);
        }
        else
        {
            rv = pkcs11_os_unlock_mutex(pContext->lib_lock);
        }
    }

    return rv;
}

CK_RV pkcs11_lock_device(pkcs11_lib_ctx_ptr pContext)
{
    CK_RV rv = CKR_OK;

    if (pContext)
    {
        if (pContext->lib_locked)
        {
            if (pContext->dev_lock)
            {
                rv = pkcs11_os_lock_mutex(pContext->dev_lock);
            }
        }
        else
        {
            PKCS11_DEBUG("Library tried to lock out of order\n");
            rv = CKR_GENERAL_ERROR;
        }
    }
    return rv;
}

CK_RV pkcs11_unlock_device(pkcs11_lib_ctx_ptr pContext)
{
    if (!pContext)
    {
        pContext = pkcs11_get_context();
    }

    if (pContext && pContext->dev_lock)
    {
        return pkcs11_os_unlock_mutex(pContext->dev_lock);
    }
    else
    {
        return CKR_OK;
    }
}

CK_RV pkcs11_lock_both(pkcs11_lib_ctx_ptr pContext)
{
    CK_RV rv = CKR_OK;

    if (CKR_OK == (rv = pkcs11_lock_context(pContext)))
    {
        if(CKR_OK != (rv = pkcs11_lock_device(pContext)))
        {
            (void)pkcs11_unlock_context(pContext);
        }
    }
    return rv;
}

CK_RV pkcs11_unlock_both(pkcs11_lib_ctx_ptr pContext)
{
    CK_RV rv1 = CKR_OK;
    CK_RV rv2 = CKR_OK;

    if (!pContext)
    {
        pContext = pkcs11_get_context();
    }

    rv1 = pkcs11_unlock_device(pContext);
    rv2 = pkcs11_unlock_context(pContext);

    return rv1 ? rv1 : rv2;
}


/**
 * \brief Check if the library is initialized properly
 */
CK_RV pkcs11_init_check(pkcs11_lib_ctx_ptr * ppContext, CK_BBOOL lock)
{
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    CK_RV rv = CKR_CRYPTOKI_NOT_INITIALIZED;

    if (ppContext)
    {
        *ppContext = NULL_PTR;
    }

    if (lib_ctx)
    {
        if (lib_ctx->initialized)
        {
            if (ppContext)
            {
                *ppContext = lib_ctx;
            }

            if (lock)
            {
                rv = pkcs11_lock_context(lib_ctx);
            }
            else
            {
                rv = CKR_OK;
            }
        }
    }
    return rv;
}

/**
 * \brief Initializes the PKCS11 API Library for Cryptoauthlib
 */
CK_RV pkcs11_init(CK_C_INITIALIZE_ARGS_PTR pInitArgs)
{
    CK_BBOOL allset = FALSE;
    CK_BBOOL allunset = FALSE;
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();
    CK_RV rv = CKR_OK;

    if (!pInitArgs)
    {
        pInitArgs = (CK_C_INITIALIZE_ARGS_PTR)&pkcs11_init_defaults;
    }

    if (!lib_ctx)
    {
        /** \todo This is where we should allocate a new context if we're using dynamic memory */
        /** \todo If we're using dyamic memory we need to make sure to deallocate it if any of the errors after the allocations are encountered */
        return CKR_GENERAL_ERROR;
    }

    if (lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    allset = (pInitArgs->CreateMutex && pInitArgs->DestroyMutex && pInitArgs->LockMutex && pInitArgs->UnlockMutex);
    allunset = (!pInitArgs->CreateMutex && !pInitArgs->DestroyMutex && !pInitArgs->LockMutex && !pInitArgs->UnlockMutex);

    /* PKCS11 Sec 5.4 - All must be set or unset - No mixing  */
    if ((!allset && !allunset) || pInitArgs->pReserved)
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* Only need to check if our library needs to create threads */
    if (CKF_LIBRARY_CANT_CREATE_OS_THREADS & pInitArgs->flags)
    {
        /* If we can't operate successfully without creating threads we'd respond: */
        // return CKR_NEED_TO_CREATE_THREADS;
    }
    
    if (CKF_OS_LOCKING_OK & pInitArgs->flags)
    {
        /* 2. If the flag is set, and the function pointer fields aren’t supplied
              (i.e., they all have the value NULL_PTR), that means that the application
              will be performing multi-threaded Cryptoki access, and the library needs
              to use the native operating system primitives to ensure safe multi-threaded
              access.  If the library is unable to do this, C_Initialize should return
              with the value CKR_CANT_LOCK. */
        /* 4. If the flag is set, and the function pointer fields are supplied (i.e., they
              all have non-NULL_PTR values), that means that the application will be performing
              multi-threaded Cryptoki access, and the library needs to use either the native
              operating system primitives or the supplied function pointers for mutex-handling
              to ensure safe multi-threaded access.  If the library is unable to do this, 
              C_Initialize should return with the value CKR_CANT_LOCK. */
        
        /* Per the above PKCS11 rules we will use our own mutex. One mutex is always a better
        choice to avoid deadlocks. */
        if (pkcs11_os_create_mutex(&lib_ctx->lib_lock))
        {
            PKCS11_DEBUG("Mutex Create Failed - Rule 2 or 4\n");
            return CKR_CANT_LOCK;
        }
    }
    else
    {
        if (allset)
        {
        /* 3. If the flag isn’t set, and the function pointer fields are supplied (i.e.,
              they all have non-NULL_PTR values), that means that the application will
              be performing multi-threaded Cryptoki access, and the library needs to use
              the supplied function pointers for mutex-handling to ensure safe multi-threaded
              access.  If the library is unable to do this, C_Initialize should return with
              the value CKR_CANT_LOCK. */
            lib_ctx->create_mutex = pInitArgs->CreateMutex;
            lib_ctx->destroy_mutex = pInitArgs->DestroyMutex;
            lib_ctx->lock_mutex = pInitArgs->LockMutex;
            lib_ctx->unlock_mutex = pInitArgs->UnlockMutex;

            /* Perform library initialization steps */
            if (lib_ctx->create_mutex(&lib_ctx->lib_lock))
            {
                PKCS11_DEBUG("Mutex Create Failed - Rule 3\n");
                return CKR_CANT_LOCK;
            }

            /* Regardless of the User's mutex arrangements the library has to protect the device */
            if (pkcs11_os_create_mutex(&lib_ctx->dev_lock))
            {
                /* Clean up the best we can */
                if (lib_ctx->lib_lock && lib_ctx->destroy_mutex)
                {
                    (void)lib_ctx->destroy_mutex(lib_ctx->lib_lock);
                    lib_ctx->lib_lock = NULL;
                }
                PKCS11_DEBUG("Device Mutex Create Failed - Rule 3\n");
                return CKR_GENERAL_ERROR;
            }
        }
        else
        {
        /* 1. If the flag isn’t set, and the function pointer fields aren’t supplied (i.e., they all
              have the value NULL_PTR), that means that the application won’t be accessing the
              Cryptoki library from multiple threads simultaneously. */

            /* Regardless of the user's mutex arrangements the library has to protect the device so
            we always lock the context at the safest location. */
            if (pkcs11_os_create_mutex(&lib_ctx->lib_lock))
            {
                PKCS11_DEBUG("Mutex Create Failed - Rule 1\n");
                return CKR_CANT_LOCK;
            }
        }
    }

    /* Lock the library context */
    if (CKR_OK == (rv = pkcs11_lock_both(lib_ctx)))
    {
        /* Initialize the Crypto device */
        lib_ctx->slots = pkcs11_slot_initslots(PKCS11_MAX_SLOTS_ALLOWED);
        if (lib_ctx->slots)
        {
            lib_ctx->slot_cnt = PKCS11_MAX_SLOTS_ALLOWED;
        }

        /* Set up a slot with a configuration */
        if (CKR_OK == (rv = pkcs11_slot_config(0)))
        {
            /* Attempt to Initialize the slot */
            rv = pkcs11_slot_init(0);
        }

        if (CKR_OK == rv)
        {
            lib_ctx->initialized = TRUE;
        }

        rv = pkcs11_unlock_both(lib_ctx);
    }

    return rv;
}

/* Close the library */
CK_RV pkcs11_deinit(CK_VOID_PTR pReserved)
{
    CK_RV rv = CKR_OK;
    uint32_t ulSlot = 0;
    pkcs11_lib_ctx_ptr lib_ctx = pkcs11_get_context();

    if (pReserved)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (!lib_ctx || !lib_ctx->initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    /* Lock the library */
    if (CKR_OK == (rv == pkcs11_lock_context(lib_ctx)))
    {
        if (CKR_OK == pkcs11_lock_device(lib_ctx))
        {
        #if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(atcab_get_device_type()))
            {
                (void)talib_auth_terminate(atcab_get_device());
            }
        #endif

            /* Release the crypto device */
            atcab_release();

            /* No more device communciation will be occuring */
            (void)pkcs11_unlock_device(lib_ctx);
        }

        /* Clean up the device specific mutex if it exists*/
        if (lib_ctx->dev_lock)
        {
            (void)pkcs11_os_destroy_mutex(lib_ctx->dev_lock);
            lib_ctx->dev_lock = NULL;
        }

        /* Close all the sessions that might be open */
        for (; ulSlot < pkcs11_context.slot_cnt; ulSlot++)
        {
            pkcs11_slot_ctx_ptr slot_ctx_ptr = &((pkcs11_slot_ctx_ptr)(pkcs11_context.slots))[ulSlot];
            if (slot_ctx_ptr)
            {
                (void)pkcs11_session_closeall(slot_ctx_ptr->slot_id);
            }
        }

        /* Clear the object cache */
        (void)pkcs11_object_deinit(&pkcs11_context);

        /** \todo If other threads are waiting for something to happen this call should
        cause those calls to unblock and return CKR_CRYPTOKI_NOT_INITIALIZED - How
        that is done by this simplified mutex API is yet to be determined */

        /* the library is now closing */
        (void)pkcs11_unlock_context(lib_ctx);
        
        /* Clean up the library lock */
        if (lib_ctx->destroy_mutex(lib_ctx->lib_lock)) 
        {
            (void)lib_ctx->destroy_mutex(lib_ctx->lib_lock);
        }
        else
        {
            (void)pkcs11_os_destroy_mutex(lib_ctx->lib_lock);
        }
        lib_ctx->lib_lock = NULL;

        pkcs11_context.initialized = FALSE;
    }

    return rv;
}

/** @} */
