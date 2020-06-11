/**
 * \file
 * \brief low-level HAL - methods used to setup indirection to physical layer interface.
 * this level does the dirty work of abstracting the higher level ATCAIFace methods from the
 * low-level physical interfaces.  Its main goal is to keep low-level details from bleeding into
 * the logical interface implemetation.
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


/* when incorporating ATCA HAL into your application, you need to adjust the #defines in atca_hal.h to include
 * and exclude appropriate interfaces - this optimizes memory use when not using a specific iface implementation in your application */

#include "cryptoauthlib.h"
#include "atca_hal.h"

#ifdef ATCA_HAL_I2C
static ATCAHAL_t hal_i2c = {
    hal_i2c_init,
    hal_i2c_post_init,
    hal_i2c_send,
    hal_i2c_receive,
    hal_i2c_wake,
    hal_i2c_idle,
    hal_i2c_sleep,
    hal_i2c_release
};
#endif

#ifdef ATCA_HAL_SWI
static ATCAHAL_t hal_swi = {
    hal_swi_init,
    hal_swi_post_init,
    hal_swi_send,
    hal_swi_receive,
    hal_swi_wake,
    hal_swi_idle,
    hal_swi_sleep,
    hal_swi_release
};
#endif

#if defined(ATCA_HAL_UART) && !defined(ATCA_HAL_KIT_CDC)
static ATCAHAL_t hal_uart = {
    hal_uart_init,
    hal_uart_post_init,
    hal_uart_send,
    hal_uart_receive,
    hal_uart_wake,
    hal_uart_idle,
    hal_uart_sleep,
    hal_uart_release
};
#endif

#if !defined(ATCA_HAL_UART) && defined(ATCA_HAL_KIT_CDC)
static ATCAHAL_t hal_uart = {
    hal_kit_cdc_init,
    hal_kit_cdc_post_init,
    hal_kit_cdc_send,
    hal_kit_cdc_receive,
    hal_kit_cdc_wake,
    hal_kit_cdc_idle,
    hal_kit_cdc_sleep,
    hal_kit_cdc_release
};
#endif

#ifdef ATCA_HAL_SPI
static ATCAHAL_t hal_spi = {
    hal_spi_init,
    hal_spi_post_init,
    hal_spi_send,
    hal_spi_receive,
    hal_spi_wake,
    hal_spi_idle,
    hal_spi_sleep,
    hal_spi_release
};
#endif

#ifdef ATCA_HAL_KIT_HID
static ATCAHAL_t hal_hid = {
    hal_kit_hid_init,
    hal_kit_hid_post_init,
    hal_kit_hid_send,
    hal_kit_hid_receive,
    hal_kit_hid_wake,
    hal_kit_hid_idle,
    hal_kit_hid_sleep,
    hal_kit_hid_release
};
#endif

#ifdef ATCA_HAL_CUSTOM
static ATCAHAL_t hal_custom;
#endif

static ATCAHAL_t * atca_registered_hal_list[ATCA_UNKNOWN_IFACE] = {
#ifdef ATCA_HAL_I2C
    &hal_i2c,
#else
    NULL,
#endif
#ifdef ATCA_HAL_SWI
    &hal_swi,
#else
    NULL,
#endif
#if defined(ATCA_HAL_UART) || defined(ATCA_HAL_KIT_CDC)
    &hal_uart,
#else
    NULL,
#endif
#ifdef ATCA_HAL_SPI
    &hal_spi,
#else
    NULL,
#endif
#ifdef ATCA_HAL_KIT_HID
    &hal_hid,
#else
    NULL,
#endif
#ifdef ATCA_HAL_CUSTOM
    &hal_custom,
#else
    NULL
#endif
};

/** \brief Internal function to get a value from the hal cache
 * \param[in] iface_type - the type of physical interface to register
 * \param[out] hal pointer to the existing ATCAHAL_t structure
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS hal_iface_get_registered(ATCAIfaceType iface_type, ATCAHAL_t** hal)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((ATCA_UNKNOWN_IFACE > iface_type) && hal)
    {
        *hal = atca_registered_hal_list[iface_type];
        status = ATCA_SUCCESS;
    }

    return status;
}

/** \brief Internal function to set a value in the hal cache
 * \param[in] iface_type - the type of physical interface to register
 * \param[in] hal pointer to the existing ATCAHAL_t structure
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS hal_iface_set_registered(ATCAIfaceType iface_type, ATCAHAL_t* hal)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((ATCA_UNKNOWN_IFACE > iface_type) && hal)
    {
        atca_registered_hal_list[iface_type] = hal;
        status = ATCA_SUCCESS;
    }

    return status;
}

/** \brief Register/Replace a HAL with a
 * \param[in] iface_type - the type of physical interface to register
 * \param[in] hal pointer to the new ATCAHAL_t structure to register
 * \param[out] old pointer to the existing ATCAHAL_t structure
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_iface_register_hal(ATCAIfaceType iface_type, ATCAHAL_t *hal, ATCAHAL_t **old)
{
    ATCA_STATUS status;

    status = old ? hal_iface_get_registered(iface_type, old) : ATCA_SUCCESS;

    if (ATCA_SUCCESS == status)
    {
        status = hal_iface_set_registered(iface_type, hal);
    }

    return ATCA_SUCCESS;
}

/** \brief Standard HAL API for ATCA to initialize a physical interface
 * \param[in] cfg pointer to ATCAIfaceCfg object
 * \param[in] hal pointer to ATCAHAL_t intermediate data structure
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_iface_init(ATCAIfaceCfg *cfg, ATCAHAL_t **hal)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (cfg && hal)
    {
        status = hal_iface_get_registered(cfg->iface_type, hal);

#ifdef ATCA_HAL_CUSTOM
        if (ATCA_CUSTOM_IFACE == cfg->iface_type)
        {
            (*hal)->halinit = cfg->atcacustom.halinit;
            (*hal)->halpostinit = cfg->atcacustom.halpostinit;
            (*hal)->halreceive = cfg->atcacustom.halreceive;
            (*hal)->halsend = cfg->atcacustom.halsend;
            (*hal)->halsleep = cfg->atcacustom.halsleep;
            (*hal)->halwake = cfg->atcacustom.halwake;
            (*hal)->halidle = cfg->atcacustom.halidle;
            (*hal)->halrelease = cfg->atcacustom.halrelease;
            (*hal)->hal_data = NULL;
        }
#endif
    }

    return status;
}

/** \brief releases a physical interface, HAL knows how to interpret hal_data
 * \param[in] iface_type - the type of physical interface to release
 * \param[in] hal_data - pointer to opaque hal data maintained by HAL implementation for this interface type
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_iface_release(ATCAIfaceType iface_type, void *hal_data)
{
    ATCA_STATUS status;
    ATCAHAL_t * hal;

    status = hal_iface_get_registered(iface_type, &hal);

    if (ATCA_SUCCESS == status)
    {
        status = hal->halrelease ? hal->halrelease(hal_data) : ATCA_BAD_PARAM;
    }

    return status;
}

/** \brief Utility function for hal_wake to check the reply.
 * \param[in] response       Wake response to be checked.
 * \param[in] response_size  Size of the response to check.
 * \return ATCA_SUCCESS for expected wake, ATCA_STATUS_SELFTEST_ERROR if the
 *         power on self test failed, ATCA_WAKE_FAILED for other failures.
 */
ATCA_STATUS hal_check_wake(const uint8_t* response, int response_size)
{
    const uint8_t expected_response[4] = { 0x04, 0x11, 0x33, 0x43 };
    const uint8_t selftest_fail_resp[4] = { 0x04, 0x07, 0xC4, 0x40 };

    if (response_size != 4)
    {
        return ATCA_WAKE_FAILED;
    }
    if (memcmp(response, expected_response, 4) == 0)
    {
        return ATCA_SUCCESS;
    }
    if (memcmp(response, selftest_fail_resp, 4) == 0)
    {
        return ATCA_STATUS_SELFTEST_ERROR;
    }
    return ATCA_WAKE_FAILED;
}

#if !defined(ATCA_NO_HEAP) && defined(ATCA_TESTS_ENABLED) && defined(ATCA_PLATFORM_MALLOC)

void* (*g_hal_malloc_f)(size_t) = ATCA_PLATFORM_MALLOC;
void (*g_hal_free_f)(void*) = ATCA_PLATFORM_FREE;

void* hal_malloc(size_t size)
{
    return g_hal_malloc_f(size);
}

void hal_free(void* ptr)
{
    g_hal_free_f(ptr);
}

void hal_test_set_memory_f(void* (*malloc_func)(size_t), void (*free_func)(void*))
{
    g_hal_malloc_f = malloc_func;
    g_hal_free_f = free_func;
}

#endif
