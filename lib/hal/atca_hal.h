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

#include "atca_config.h"

#include "atca_status.h"
#include "atca_iface.h"
#include "atca_start_config.h"
#include "atca_start_iface.h"

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

/** \brief an intermediary data structure to allow the HAL layer to point the standard API functions
   used by the upper layers to the HAL implementation for the interface.  This isolates the upper layers
   and loosely couples the ATCAIface object from the physical implementation.
 */

typedef struct
{
    // interface is a group of function pointers to a specific HAL implementation for this interface type
    // so these function pointers are initialized in the HAL layer in order to help keep the ATCAIface object
    // from needing to know the low-level details, including global naming of HAL methods and physical implementation.
    ATCA_STATUS (*halinit)(void *hal, ATCAIfaceCfg *cfg);
    ATCA_STATUS (*halpostinit)(ATCAIface iface);
    ATCA_STATUS (*halsend)(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
    ATCA_STATUS (*halreceive)(ATCAIface iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxlength);
    ATCA_STATUS (*halwake)(ATCAIface iface);
    ATCA_STATUS (*halidle)(ATCAIface iface);
    ATCA_STATUS (*halsleep)(ATCAIface iface);
    ATCA_STATUS (*halrelease)(void* hal_data);

    void *hal_data;       // points to whatever the HAL implementation for this interface wants it to, HAL manages.
} ATCAHAL_t;

typedef struct
{
    ATCA_STATUS (*send)(void* ctx, uint8_t* txdata, uint16_t txlen);        /**< Must be a blocking send */
    ATCA_STATUS (*recv)(void* ctx, uint8_t* rxdata, uint16_t* rxlen);       /**< Must be a blocking receive */
    void* (*packet_alloc)(size_t bytes);                                    /**< Allocate a phy packet */
    void (*packet_free)(void* packet);                                      /**< Free a phy packet */
    void* hal_data;                                                         /**< Physical layer context */
} atca_hal_kit_phy_t;

#ifdef __cplusplus
extern "C" {
#endif

extern ATCA_STATUS hal_iface_init(ATCAIfaceCfg *, ATCAHAL_t** hal);
extern ATCA_STATUS hal_iface_release(ATCAIfaceType, void* hal_data);

ATCA_STATUS hal_check_wake(const uint8_t* response, int response_size);

#ifdef ATCA_HAL_I2C
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_i2c_post_init(ATCAIface iface);
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_i2c_wake(ATCAIface iface);
ATCA_STATUS hal_i2c_idle(ATCAIface iface);
ATCA_STATUS hal_i2c_sleep(ATCAIface iface);
ATCA_STATUS hal_i2c_release(void *hal_data);
ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses);
ATCA_STATUS hal_i2c_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found);
#endif

#ifdef ATCA_HAL_SWI
ATCA_STATUS hal_swi_init(void *hal, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_swi_post_init(ATCAIface iface);
ATCA_STATUS hal_swi_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_swi_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_swi_wake(ATCAIface iface);
ATCA_STATUS hal_swi_idle(ATCAIface iface);
ATCA_STATUS hal_swi_sleep(ATCAIface iface);
ATCA_STATUS hal_swi_release(void *hal_data);
ATCA_STATUS hal_swi_discover_buses(int swi_buses[], int max_buses);
ATCA_STATUS hal_swi_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found);
#endif

#ifdef ATCA_HAL_UART
ATCA_STATUS hal_uart_init(void *hal, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_uart_post_init(ATCAIface iface);
ATCA_STATUS hal_uart_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_uart_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_uart_wake(ATCAIface iface);
ATCA_STATUS hal_uart_idle(ATCAIface iface);
ATCA_STATUS hal_uart_sleep(ATCAIface iface);
ATCA_STATUS hal_uart_release(ATCAIface iface);
ATCA_STATUS hal_uart_discover_buses(int uart_buses[], int max_buses);
ATCA_STATUS hal_uart_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found);
#endif

#ifdef ATCA_HAL_SPI
ATCA_STATUS hal_spi_init(void *hal, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_spi_post_init(ATCAIface iface);
ATCA_STATUS hal_spi_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_spi_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_spi_wake(ATCAIface iface);
ATCA_STATUS hal_spi_idle(ATCAIface iface);
ATCA_STATUS hal_spi_sleep(ATCAIface iface);
ATCA_STATUS hal_spi_release(void *hal_data);
ATCA_STATUS hal_spi_discover_buses(int spi_buses[], int max_buses);
ATCA_STATUS hal_spi_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found);
#endif

#ifdef ATCA_HAL_KIT_CDC
ATCA_STATUS hal_kit_cdc_init(void *hal, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_kit_cdc_post_init(ATCAIface iface);
ATCA_STATUS hal_kit_cdc_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_kit_cdc_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_kit_cdc_wake(ATCAIface iface);
ATCA_STATUS hal_kit_cdc_idle(ATCAIface iface);
ATCA_STATUS hal_kit_cdc_sleep(ATCAIface iface);
ATCA_STATUS hal_kit_cdc_release(void *hal_data);
ATCA_STATUS hal_kit_cdc_discover_buses(int cdc_buses[], int max_buses);
ATCA_STATUS hal_kit_cdc_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found);
#endif

#ifdef ATCA_HAL_KIT_HID
ATCA_STATUS hal_kit_hid_init(void *hal, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_kit_hid_post_init(ATCAIface iface);
ATCA_STATUS hal_kit_hid_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_kit_hid_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_kit_hid_wake(ATCAIface iface);
ATCA_STATUS hal_kit_hid_idle(ATCAIface iface);
ATCA_STATUS hal_kit_hid_sleep(ATCAIface iface);
ATCA_STATUS hal_kit_hid_release(void *hal_data);
ATCA_STATUS hal_kit_hid_discover_buses(int hid_buses[], int max_buses);
ATCA_STATUS hal_kit_hid_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found);
#endif

#ifdef ATCA_HAL_KIT_BRIDGE
ATCA_STATUS hal_kit_init(void* hal, ATCAIfaceCfg* cfg);
ATCA_STATUS hal_kit_post_init(ATCAIface iface);
ATCA_STATUS hal_kit_send(ATCAIface iface, uint8_t word_address, uint8_t* txdata, int txlength);
ATCA_STATUS hal_kit_receive(ATCAIface iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxlength);
ATCA_STATUS hal_kit_wake(ATCAIface iface);
ATCA_STATUS hal_kit_idle(ATCAIface iface);
ATCA_STATUS hal_kit_sleep(ATCAIface iface);
ATCA_STATUS hal_kit_release(void* hal_data);
ATCA_STATUS hal_kit_discover_buses(int hid_buses[], int max_buses);
ATCA_STATUS hal_kit_discover_devices(int bus_num, ATCAIfaceCfg* cfg, int* found);
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

/** \brief Timer API for legacy implementations */
#ifndef atca_delay_ms
void atca_delay_ms(uint32_t ms);
#endif

#ifndef atca_delay_us
void atca_delay_us(uint32_t us);
#endif

/** \brief Timer API implemented at the HAL level */
void hal_rtos_delay_ms(uint32_t ms);
void hal_delay_ms(uint32_t ms);
void hal_delay_us(uint32_t us);

/** \brief Optional hal interfaces */
ATCA_STATUS hal_create_mutex(void ** ppMutex, char* pName);
ATCA_STATUS hal_destroy_mutex(void * pMutex);
ATCA_STATUS hal_lock_mutex(void * pMutex);
ATCA_STATUS hal_unlock_mutex(void * pMutex);

#ifndef ATCA_NO_HEAP
#ifdef ATCA_TESTS_ENABLED
void hal_test_set_memory_f(void* (*malloc_func)(size_t), void (*free_func)(void*));
#endif

#if defined(ATCA_TESTS_ENABLED) || !defined(ATCA_PLATFORM_MALLOC)
void*   hal_malloc(size_t size);
void    hal_free(void* ptr);
#else
#define hal_malloc      ATCA_PLATFORM_MALLOC
#define hal_free        ATCA_PLATFORM_FREE
#endif
#endif

#ifdef memset_s
#define hal_memset_s    memset_s
#else
#define hal_memset_s    atcab_memset_s
#endif


ATCA_STATUS hal_iface_register_hal(ATCAIfaceType iface_type, ATCAHAL_t *hal, ATCAHAL_t **old);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* ATCA_HAL_H_ */
