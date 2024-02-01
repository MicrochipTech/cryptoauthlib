/**
 * \file
 * \brief PKCS11 Library Operating System Abstraction Functions
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

#include "pkcs11_os.h"
#include "pkcs11_util.h"
#include "pkcs11_init.h"

/**
 * \defgroup pkcs11 OS Abstraction (pkcs11_so_)
   @{ */


/**
 * \brief Application callback for creating a mutex object
 * \param[in,out] ppMutex location to receive ptr to mutex
 */
CK_RV pkcs11_os_create_mutex(CK_VOID_PTR_PTR ppMutex)
{
    return pkcs11_util_convert_rv(hal_create_mutex(ppMutex, "atpkcs11_3_6"));
}

/*
 * \brief Application callback for destroying a mutex object
 * \param[IN] pMutex pointer to mutex
 */
CK_RV pkcs11_os_destroy_mutex(CK_VOID_PTR pMutex)
{
    return pkcs11_util_convert_rv(hal_destroy_mutex(pMutex));
}

/*
 * \brief Application callback for locking a mutex
 * \param[IN] pMutex pointer to mutex
 */
CK_RV pkcs11_os_lock_mutex(CK_VOID_PTR pMutex)
{
    return pkcs11_util_convert_rv(hal_lock_mutex(pMutex));
}

/*
 * \brief Application callback for unlocking a mutex
 * \param[IN] pMutex pointer to mutex
 */
CK_RV pkcs11_os_unlock_mutex(CK_VOID_PTR pMutex)
{
    return pkcs11_util_convert_rv(hal_unlock_mutex(pMutex));
}

CK_RV pkcs11_os_alloc_shared_ctx(void ** ppShared, size_t size)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

#if ((defined(__linux__) || defined(__APPLE__)) && defined(ATCA_USE_SHARED_MUTEX))
    bool initialized = false;
    if (ATCA_SUCCESS == (status = hal_alloc_shared(ppShared, size, "atpkcs11_3_6", &initialized)))
    {
        if (initialized)
        {
            status = hal_init_mutex(*ppShared, true);
        }
    }
#else
    if (ppShared)
    {
    #if defined(ATCA_NO_HEAP)
        static pkcs11_dev_state tracker;
        *ppShared = &tracker;
        status = ATCA_SUCCESS;
    #else
        if (NULL != (*ppShared = hal_malloc(size)))
        {
            status = ATCA_SUCCESS;
        }
    #endif
    }
#endif

    return pkcs11_util_convert_rv(status);
}

CK_RV pkcs11_os_free_shared_ctx(void * pShared, size_t size)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

#if ((defined(__linux__) || defined(__APPLE__)) && defined(ATCA_USE_SHARED_MUTEX))
    status = hal_free_shared(pShared, size);
#elif defined(ATCA_NO_HEAP)
    ((void)pShared);
    ((void)size);
    status = ATCA_SUCCESS;
#else
    ((void)size);
    hal_free(pShared);
    status = ATCA_SUCCESS;
#endif

    return pkcs11_util_convert_rv(status);
}

/** @} */
