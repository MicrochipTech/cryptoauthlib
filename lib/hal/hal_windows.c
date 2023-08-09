/**
 * \file
 * \brief ATCA Hardware abstraction layer for windows timer functions.
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

#include "atca_hal.h"
#include <windows.h>
#include <math.h>


/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */


/** \brief This function delays for a number of microseconds.
 *
 * \param[in] delay number of microseconds to delay
 */
void hal_delay_us(uint32_t delay)
{
    // divide by 1000 to convert us to ms
    // todo: use a timer with us accuracy
    /* coverity[cert_flp34_c_violation] Loss of precision is inconsequential for this calculation */
    /* coverity[cert_flp36_c_violation] Loss of precision is inconsequential for this calculation */
    uint32_t ms = (uint32_t)round(((float)delay / 1.0e3) + 0.5);     // Miliseconds

    // use Windows supplied delay
    Sleep(ms);
}

/** \brief This function delays for a number of milliseconds.
 *
 *         You can override this function if you like to do
 *         something else in your system while delaying.
 * \param[in] delay number of milliseconds to delay
 */

void hal_delay_ms(uint32_t delay)
{
    // use Windows supplied delay
    Sleep(delay);
}

#ifndef ATCA_USE_RTOS_TIMER
/**
 * \brief Application callback for creating a mutex object
 * \param[IN/OUT] ppMutex location to receive ptr to mutex
 * \param[IN] pName Name of the mutex for systems using named objects
 */
ATCA_STATUS hal_create_mutex(void** ppMutex, const char *pName)
{
    if (NULL == ppMutex)
    {
        return ATCA_BAD_PARAM;
    }

    /* To share a lock in a dll across processing the mutexes must be named */
    *ppMutex = CreateMutex(NULL, FALSE, pName);

    if (NULL == *ppMutex)
    {
        return ATCA_GEN_FAIL;
    }

    return ATCA_SUCCESS;
}

/*
 * \brief Application callback for destroying a mutex object
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_destroy_mutex(void* pMutex)
{
    if (NULL == pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    (void)CloseHandle(pMutex);

    return ATCA_SUCCESS;
}


/*
 * \brief Application callback for locking a mutex
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_lock_mutex(void* pMutex)
{
    DWORD rv;

    if (NULL == pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    rv = WaitForSingleObject((HANDLE)pMutex, INFINITE);

    /* coverity[misra_c_2012_rule_10_4_violation:SUPPRESS] Win32 API */
    if (WAIT_OBJECT_0 == rv)
    {
        return ATCA_SUCCESS;
    }
    /* coverity[misra_c_2012_rule_10_4_violation:SUPPRESS] Win32 API */
    else if (WAIT_ABANDONED_0 == rv)
    {
        /* Lock was obtained but its because another process terminated so the
           state is indeterminate and will probably need to be fixed */
        return ATCA_FUNC_FAIL;
    }
    else
    {
        return ATCA_GEN_FAIL;
    }
}

/*
 * \brief Application callback for unlocking a mutex
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_unlock_mutex(void* pMutex)
{
    ATCA_STATUS rv = ATCA_SUCCESS;

    if (NULL == pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    if (!ReleaseMutex((HANDLE)pMutex))
    {
        rv = ATCA_GEN_FAIL;
    }

    return rv;
}

/** \brief Check if the pid exists in the system
 */
ATCA_STATUS hal_check_pid(hal_pid_t pid)
{
    return ATCA_UNIMPLEMENTED;
}

#endif
/** @} */
