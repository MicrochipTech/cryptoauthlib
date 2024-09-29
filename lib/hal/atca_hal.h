/**
 * \file
 * \brief low-level HAL - methods used to setup indirection to physical layer interface
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


#ifndef ATCA_HAL_H_
#define ATCA_HAL_H_

#include <stdlib.h>

#ifndef LIBRARY_BUILD_EN
#include "atca_config.h"
#endif

#include "atca_status.h"
#include "atca_iface.h"


/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

typedef struct
{
    ATCA_STATUS (*send)(void* ctx, uint8_t* txdata, uint16_t txlen);        /**< Must be a blocking send */
    ATCA_STATUS (*recv)(void* ctx, uint8_t* rxdata, uint16_t* rxlen);       /**< Must be a blocking receive */
    void* (*packet_alloc)(size_t bytes);                                    /**< Allocate a phy packet */
    void (*packet_free)(void* packet);                                      /**< Free a phy packet */
    void* hal_data;                                                         /**< Physical layer context */
} atca_hal_kit_phy_t;

typedef struct
{
    int     recordedPID;
    uint8_t sessionID;
    uint8_t index;
} atca_hal_shm_t;

#ifdef __cplusplus
extern "C" {
#endif

ATCA_STATUS hal_iface_init(ATCAIfaceCfg *cfg, ATCAHAL_t** hal, ATCAHAL_t** phy);
ATCA_STATUS hal_iface_release(ATCAIfaceType iface_type, void* hal_data);

ATCA_STATUS hal_check_wake(const uint8_t* response, int response_size);

#ifdef __COVERITY__
#pragma coverity compliance block \
    (fp "MISRA C-2012 Rule 8.6" "Not all HALs are in the analysis scope")
#endif

#ifdef ATCA_HAL_I2C
ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_i2c_post_init(ATCAIface iface);
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
#ifdef ATCA_LEGACY_HAL
ATCA_STATUS hal_i2c_wake(ATCAIface iface);
ATCA_STATUS hal_i2c_idle(ATCAIface iface);
ATCA_STATUS hal_i2c_sleep(ATCAIface iface);
#endif
ATCA_STATUS hal_i2c_release(void *hal_data);
#endif

#ifdef ATCA_HAL_SWI_UART
ATCA_STATUS hal_swi_init(ATCAIface iface, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_swi_post_init(ATCAIface iface);
ATCA_STATUS hal_swi_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_swi_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_swi_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
#ifdef ATCA_LEGACY_HAL
ATCA_STATUS hal_swi_wake(ATCAIface iface);
ATCA_STATUS hal_swi_idle(ATCAIface iface);
ATCA_STATUS hal_swi_sleep(ATCAIface iface);
#endif
ATCA_STATUS hal_swi_release(void *hal_data);
#endif

#if defined(ATCA_HAL_SWI_GPIO) || defined(ATCA_HAL_SWI_BB)
ATCA_STATUS hal_swi_gpio_init(ATCAIface iface, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_swi_gpio_post_init(ATCAIface iface);
ATCA_STATUS hal_swi_gpio_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_swi_gpio_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_swi_gpio_release(void *hal_data);
ATCA_STATUS hal_swi_gpio_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
#endif

#if defined(ATCA_HAL_SWI_GPIO) || defined(ATCA_HAL_SWI_BB)
ATCA_STATUS hal_gpio_init(ATCAIface iface, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_gpio_post_init(ATCAIface iface);
ATCA_STATUS hal_gpio_send(ATCAIface iface, uint8_t word_address, uint8_t* pin_state, int unused_param);
ATCA_STATUS hal_gpio_receive(ATCAIface iface, uint8_t word_address, uint8_t* pin_state, uint16_t* unused_param);
ATCA_STATUS hal_gpio_release(void *hal_data);
ATCA_STATUS hal_gpio_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
#endif

#if defined(ATCA_HAL_SWI_UART) || defined(ATCA_HAL_KIT_UART) || defined(ATCA_HAL_UART)
ATCA_STATUS hal_uart_init(ATCAIface iface, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_uart_post_init(ATCAIface iface);
ATCA_STATUS hal_uart_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_uart_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_uart_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
#ifdef ATCA_LEGACY_HAL
ATCA_STATUS hal_uart_wake(ATCAIface iface);
ATCA_STATUS hal_uart_idle(ATCAIface iface);
ATCA_STATUS hal_uart_sleep(ATCAIface iface);
#endif
ATCA_STATUS hal_uart_release(void *hal_data);
#endif

#ifdef ATCA_HAL_SPI
ATCA_STATUS hal_spi_init(ATCAIface iface, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_spi_post_init(ATCAIface iface);
ATCA_STATUS hal_spi_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_spi_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_spi_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
#ifdef ATCA_LEGACY_HAL
ATCA_STATUS hal_spi_wake(ATCAIface iface);
ATCA_STATUS hal_spi_idle(ATCAIface iface);
ATCA_STATUS hal_spi_sleep(ATCAIface iface);
#endif
ATCA_STATUS hal_spi_release(void *hal_data);
#endif

#ifdef ATCA_HAL_KIT_HID
ATCA_STATUS hal_kit_hid_init(ATCAIface iface, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_kit_hid_post_init(ATCAIface iface);
ATCA_STATUS hal_kit_hid_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_kit_hid_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_kit_hid_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
ATCA_STATUS hal_kit_hid_release(void *hal_data);
#endif

#ifdef ATCA_HAL_KIT_BRIDGE
ATCA_STATUS hal_kit_init(ATCAIface iface, ATCAIfaceCfg* cfg);
ATCA_STATUS hal_kit_post_init(ATCAIface iface);
ATCA_STATUS hal_kit_send(ATCAIface iface, uint8_t word_address, uint8_t* txdata, int txlength);
ATCA_STATUS hal_kit_receive(ATCAIface iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxlength);
ATCA_STATUS hal_kit_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
ATCA_STATUS hal_kit_release(void* hal_data);
#endif

#ifdef ATCA_HAL_CUSTOM
ATCA_STATUS hal_custom_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
#endif

#ifdef __COVERITY__
#pragma coverity compliance end_block "MISRA C-2012 Rule 8.6"
#endif

/* Polling defaults if not overwritten by the configuration */
#ifndef ATCA_POLLING_INIT_TIME_MSEC
#define ATCA_POLLING_INIT_TIME_MSEC       1
#endif

#ifndef ATCA_POLLING_FREQUENCY_TIME_MSEC
#define ATCA_POLLING_FREQUENCY_TIME_MSEC  2
#endif

#ifndef ATCA_POLLING_MAX_TIME_MSEC
#define ATCA_POLLING_MAX_TIME_MSEC        2500
#endif

/* Control Function Options */
/** \brief Execute the hardware specific wake - generally only for kits */
#define ATCA_HAL_CONTROL_WAKE       (0U)
/** \brief Execute the hardware specific idle - generally only for kits */
#define ATCA_HAL_CONTROL_IDLE       (1U)
/** \brief Execute the hardware specific sleep - generally only for kits */
#define ATCA_HAL_CONTROL_SLEEP      (2U)
/** \brief Execute the hardware specific reset - generally only for kits */
#define ATCA_HAL_CONTROL_RESET      (3U)
/** \brief Select the device - assert CS, open device, etc */
#define ATCA_HAL_CONTROL_SELECT     (4U)
/** \brief Select the device - de-assert CS, release device, etc */
#define ATCA_HAL_CONTROL_DESELECT   (5U)
/** \brief Change the datarate of the phy */
#define ATCA_HAL_CHANGE_BAUD        (6U)
/** \brief If the phy has a buffer make sure all bytes are transmitted */
#define ATCA_HAL_FLUSH_BUFFER       (7U)
/** \brief Set the PIN mode (in vs out) */
#define ATCA_HAL_CONTROL_DIRECTION  (8U)

/** \brief Timer API for legacy implementations */
#ifndef atca_delay_ms
void atca_delay_ms(uint32_t ms);
#endif

#ifndef atca_delay_us
void atca_delay_us(uint32_t us);
#endif

/** \brief Timer API implemented at the HAL level */
void hal_delay_ms(uint32_t delay);
void hal_delay_us(uint32_t delay);

#ifdef ATCA_USE_RTOS_TIMER
void hal_rtos_delay_ms(uint32_t ms);
#endif

#if defined(__linux__) || defined(__APPLE__)
    #ifdef ATCA_USE_SHARED_MUTEX
        #include <pthread.h>
/** \brief Structure for holding a mutex in shared memory on linux */
typedef struct
{
    pthread_mutex_t mutex;
    bool            shared;
} hal_mutex_t;
    #else
        #include <semaphore.h>
typedef sem_t hal_mutex_t;
    #endif
#else
/** \brief Generic mutex type definition for most systems */
typedef void * hal_mutex_t;
#endif

/** \brief Optional hal interfaces */
ATCA_STATUS hal_create_mutex(void ** ppMutex, const char* pName);
ATCA_STATUS hal_init_mutex(void * pMutex, bool shared);
ATCA_STATUS hal_destroy_mutex(void * pMutex);
ATCA_STATUS hal_lock_mutex(void * pMutex);
ATCA_STATUS hal_unlock_mutex(void * pMutex);
ATCA_STATUS hal_alloc_shared(void ** pShared, size_t size, const char* pName, bool* initialized);
ATCA_STATUS hal_free_shared(void * pShared, size_t size);

#if  defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/syscall.h>
typedef pid_t hal_pid_t;
#define hal_get_pid             getpid
#define hal_get_thread_id()     ((hal_pid_t)syscall(SYS_gettid))
#elif defined(_WIN32)
#include <windows.h>
typedef DWORD hal_pid_t;
#define hal_get_pid         GetCurrentProcessId
#define hal_get_thread_id   GetCurrentThreadId
#endif

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
ATCA_STATUS hal_check_pid(hal_pid_t pid);
#endif

#if defined(ATCA_HEAP) && defined(ATCA_TESTS_ENABLED)
void hal_test_set_memory_f(void* (*malloc_func)(size_t size), void (*free_func)(void* ptr));
#endif

ATCA_STATUS hal_iface_register_hal(ATCAIfaceType iface_type, ATCAHAL_t *hal, ATCAHAL_t **old_hal, ATCAHAL_t* phy, ATCAHAL_t** old_phy);
uint8_t hal_is_command_word(uint8_t word_address);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* ATCA_HAL_H_ */
