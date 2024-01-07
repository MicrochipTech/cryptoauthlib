/*
 * Copyright (c) 2020 Microchip Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hal/atca_hal.h"

#include <zephyr.h>
#include <kernel.h>


#ifndef ATCA_MUTEX_TIMEOUT
#define ATCA_MUTEX_TIMEOUT  K_FOREVER
#endif

/**
 * \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

#if !defined(ATCA_PLATFORM_MALLOC)
void*   hal_malloc(size_t size)
{
    return k_malloc(size);
}
#endif

#if !defined(ATCA_PLATFORM_FREE)
void    hal_free(void* ptr)
{
    k_free(ptr);
}
#endif

/** \brief This function delays for a number of microseconds.
 *
 * \param[in] delay number of microseconds to delay
 */
void hal_delay_us(uint32_t delay)
{
    k_busy_wait(delay);
}

/** \brief This function delays for a number of tens of microseconds.
 *
 * \param[in] delay number of 0.01 milliseconds to delay
 */
void hal_delay_10us(uint32_t delay)
{
    k_usleep(delay * 10);
}


/** \brief This function delays for a number of milliseconds.
 *
 *         You can override this function if you like to do
 *         something else in your system while delaying.
 * \param[in] delay number of milliseconds to delay
 */

/* ASF already has delay_ms - see delay.h */
void hal_delay_ms(uint32_t delay)
{
    hal_delay_us(delay * 1000);
}


ATCA_STATUS hal_create_mutex(void ** ppMutex, char* pName)
{
    (void)pName;

    if (!ppMutex)
    {
        return ATCA_BAD_PARAM;
    }

    (*ppMutex) = (struct k_mutex*)k_malloc(sizeof(struct k_mutex));

    if (!*ppMutex)
    {
        return ATCA_FUNC_FAIL;
    }

    k_mutex_init((struct k_mutex*)(*ppMutex));

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_destroy_mutex(void * pMutex)
{
    if (!pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    k_free(pMutex);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_lock_mutex(void * pMutex)
{
    if (!pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    if (k_mutex_lock((struct k_mutex*)pMutex, ATCA_MUTEX_TIMEOUT))
    {
        return ATCA_GEN_FAIL;
    }
    else
    {
        return ATCA_SUCCESS;
    }
}

ATCA_STATUS hal_unlock_mutex(void * pMutex)
{
    if (!pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    k_mutex_unlock((struct k_mutex*)pMutex);

    return ATCA_SUCCESS;
}

/** @} */
