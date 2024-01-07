/** \file
 *  \brief Timer Utility Functions for Linux
 *
 * \copyright (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "atca_hal.h"


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
    (void)usleep(delay);
}

/** \brief This function delays for a number of milliseconds.
 *
 * \param[in] delay number of milliseconds to delay
 */
void hal_delay_ms(uint32_t delay)
{
    /* Cap delay at 5 minutes */
    if (300000U > delay)
    {
        hal_delay_us(delay * 1000U);
    }
    else
    {
        hal_delay_us(300000U * 1000U);
    }
}

#ifndef ATCA_USE_RTOS_TIMER

#ifdef ATCA_USE_SHARED_MUTEX

#include <pthread.h>
#include <sys/mman.h>

ATCA_STATUS hal_alloc_shared(
    void **     pShared,    /**< [in/out] Location to store the pointer to the allocated shared memory */
    size_t      size,       /**< [in] Requested size of the block */
    const char* pName,      /**< [in] Name of the shared memory block */
    bool *      initialized /**< [out] Returns initialized status (true if new and initialized to zero, false if existing) */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    int fd;
    bool created = false;

    if ((NULL != pShared) && (NULL != pName) && (100000U > size))
    {
        /* Treat initialized as an optional parameter */
        if (NULL == initialized)
        {
            /* coverity[misra_c_2012_rule_18_6_violation] Input parameter is an optional field */
            initialized = &created;
        }

#ifdef __COVERITY__
#pragma coverity compliance block \
        (fp:2 "MISRA C-2012 Rule 7.1" "Retaining octal representation is better for readability for POSIX (UNIX) permissions") \
        (fp:6 "MISRA C-2012 Rule 10.1" "Macro usage is correct per POSIX specification" )
#endif

        /* Set up a shared memory region */
        errno = 0;
        if (0 > (fd = shm_open(pName, O_RDWR | O_CREAT | O_EXCL, 0666)))
        {
            /* coverity[cert_err30_c_violation:FALSE] shm_open sets errno per it's specification */
            /* coverity[misra_c_2012_rule_22_10_violation:FALSE] shm_open sets errno per it's specification */
            if (EEXIST == errno)
            {
                fd = shm_open(pName, O_RDWR, 0666);
            }
        }
        else
        {
            if (0 > ftruncate(fd, (off_t)size))
            {
                (void)close(fd);
                fd = -1;
            }
            else
            {
                *initialized = true;
            }
        }

        if (0 <= fd)
        {
            /* coverity[misra_c_2012_directive_4_12_violation] Required for the linux environment */
            if (NULL != (*pShared = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)))
            {
                status = ATCA_SUCCESS;
                if (true == *initialized)
                {
                    /* Initialize the shared memory if it is newly created */
                    (void)memset(*pShared, 0, size);
                }
            }
            else
            {
                status = ATCA_ALLOC_FAILURE;
            }
            (void)close(fd);
        }

#ifdef __COVERITY__
#pragma coverity compliance end_block "MISRA C-2012 Rule 7.1" "MISRA C-2012 Rule 10.1"
#endif

    }

    return status;
}

ATCA_STATUS hal_free_shared(void * pShared, size_t size)
{
    return (0 != munmap(pShared, size)) ? ATCA_GEN_FAIL : ATCA_SUCCESS;
}

/**
 * \brief Initialize a mutex
 * \param[IN] pMutex location of the mutex
 */
ATCA_STATUS hal_init_mutex(void * pMutex, bool shared)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

    if (NULL != pMutex)
    {
        pthread_mutexattr_t muattr;
        (void)pthread_mutexattr_init(&muattr);
        (void)pthread_mutexattr_settype(&muattr, PTHREAD_MUTEX_ERRORCHECK);
    #ifdef PTHREAD_PRIO_INHERIT
        (void)pthread_mutexattr_setprotocol(&muattr, PTHREAD_PRIO_INHERIT);
    #endif
        (void)pthread_mutexattr_setrobust(&muattr, PTHREAD_MUTEX_ROBUST);
        if (shared)
        {
            (void)pthread_mutexattr_setpshared(&muattr, PTHREAD_PROCESS_SHARED);
            ((hal_mutex_t*)pMutex)->shared = 1;
        }

        if (0 != pthread_mutex_init((pthread_mutex_t*)pMutex, &muattr))
        {
            return ATCA_GEN_FAIL;
        }
        status = ATCA_SUCCESS;
    }
    return status;
}

/**
 * \brief Application callback for creating a mutex object
 * \param[IN/OUT] ppMutex location to receive ptr to mutex
 * \param[IN/OUT] name String used to identify the mutex
 */
ATCA_STATUS hal_create_mutex(void ** ppMutex, const char* pName)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    bool created = false;

    if ((NULL != ppMutex) && (NULL != pName))
    {
        if (ATCA_SUCCESS == (status = hal_alloc_shared(ppMutex, sizeof(hal_mutex_t), pName, &created)))
        {
            if (created)
            {
                status = hal_init_mutex(*ppMutex, true);
            }
        }
    }

    return status;
}

/*
 * \brief Application callback for destroying a mutex object
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_destroy_mutex(void *pMutex)
{
    if (NULL == pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    if (!((hal_mutex_t*)pMutex)->shared)
    {
        (void)pthread_mutex_destroy((pthread_mutex_t*)pMutex);
        /* coverity[misra_c_2012_rule_21_3_violation] Required for the linux environment */
        free(pMutex);
    }
    return ATCA_SUCCESS;
}

/*
 * \brief Application callback for locking a mutex
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_lock_mutex(void *pMutex)
{
    int rv;

    if (NULL == pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    rv = pthread_mutex_lock((pthread_mutex_t*)pMutex);

    if ((0 == rv) || (EDEADLK == rv))
    {
        return ATCA_SUCCESS;
    }
    else if (EOWNERDEAD == rv)
    {
        /* Lock was obtained but its because another process terminated so the
           state is indeterminate and will probably need to be fixed */
        (void)pthread_mutex_consistent((pthread_mutex_t*)pMutex);
        return ATCA_SUCCESS;
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
ATCA_STATUS hal_unlock_mutex(void *pMutex)
{
    if (NULL == pMutex)
    {
        return ATCA_BAD_PARAM;
    }

    return (0 != pthread_mutex_unlock((pthread_mutex_t*)pMutex)) ? ATCA_GEN_FAIL : ATCA_SUCCESS;
}

#else

/**
 * \brief Application callback for creating a mutex object
 * \param[in,out] ppMutex location to receive ptr to mutex
 * \param[in,out] pName String used to identify the mutex
 */
ATCA_STATUS hal_create_mutex(void ** ppMutex, const char* pName)
{
    sem_t * sem;

    if (ppMutex)
    {
        return ATCA_BAD_PARAM;
    }

    if (!pName)
    {
        pName = "atca_mutex";
    }

    sem = sem_open(pName, (O_CREAT | O_RDWR), (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP), 0);
    if (SEM_FAILED == sem)
    {
        return ATCA_GEN_FAIL;
    }

    *ppMutex = sem;

    return ATCA_SUCCESS;
}

/*
 * \brief Application callback for destroying a mutex object
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_destroy_mutex(void * pMutex)
{
    sem_t * sem = (sem_t*)pMutex;

    if (!sem)
    {
        return ATCA_BAD_PARAM;
    }

    if (-1 == sem_close(sem))
    {
        return ATCA_GEN_FAIL;
    }
    else
    {
        return ATCA_SUCCESS;
    }
}

/*
 * \brief Application callback for locking a mutex
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_lock_mutex(void *pMutex)
{
    sem_t *sem = (sem_t*)pMutex;

    if (!sem)
    {
        return ATCA_BAD_PARAM;
    }

    if (-1 == sem_wait(sem))
    {
        return ATCA_GEN_FAIL;
    }
    else
    {
        return ATCA_SUCCESS;
    }
}

/*
 * \brief Application callback for unlocking a mutex
 * \param[IN] pMutex pointer to mutex
 */
ATCA_STATUS hal_unlock_mutex(void *pMutex)
{
    sem_t *sem = (sem_t*)pMutex;

    if (!sem)
    {
        return ATCA_BAD_PARAM;
    }

    if (-1 == sem_post(sem))
    {
        return ATCA_GEN_FAIL;
    }
    else
    {
        return ATCA_SUCCESS;
    }
}
#endif

/** \brief Check if the pid exists in the system
 */
ATCA_STATUS hal_check_pid(hal_pid_t pid)
{
    char buf[64];
    struct stat sb;

    /* coverity[misra_c_2012_rule_21_6_violation] snprintf is approved for formatted string writes to buffers */
    (void)snprintf(buf, sizeof(buf) - 1U, "/proc/%d", pid);

    return (0 == stat(buf, &sb)) ? 0 : -1;
}

#endif
/** @} */
