/* Auto-generated config file atca_config.h */
#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

/* MPLAB Harmony Common Include */
#include "definitions.h"

<#assign pliblist = CAL_PLIB_LIST?word_list>
<#if pliblist?size != 0>
<#list pliblist as plib_id>
<#assign plib_info = plib_id?split("_")>
<#if plib_info?size == 1 || plib_info[1] == "i2c">
<#assign atca_hal_i2c = true>
<#elseif plib_info[1] == "spi">
<#assign atca_hal_spi = true>
</#if>
</#list>
</#if>

<#if atca_hal_i2c??>
#ifndef ATCA_HAL_I2C
#define ATCA_HAL_I2C
#endif
</#if>
<#if atca_hal_spi??>
#ifndef ATCA_HAL_SPI
#define ATCA_HAL_SPI
#endif
</#if>

<#assign devices = CAL_DEVICE_LIST?word_list>
<#if devices?size != 0>
/** Include Device Support Options */
<#list devices as device_type>
#define ATCA_${device_type}_SUPPORT
</#list>
</#if>

<#if !CAL_ENABLE_POLLING>
/** Define if cryptoauthlib is to use the maximum execution time method */
#ifndef ATCA_NO_POLL
#define ATCA_NO_POLL
#endif
</#if>

/* Polling Configuration Options  */
#ifndef ATCA_POLLING_INIT_TIME_MSEC
#define ATCA_POLLING_INIT_TIME_MSEC       ${CAL_POLL_INIT_TIME}
#endif
#ifndef ATCA_POLLING_FREQUENCY_TIME_MSEC
#define ATCA_POLLING_FREQUENCY_TIME_MSEC  ${CAL_POLL_PERIOD}
#endif
#ifndef ATCA_POLLING_MAX_TIME_MSEC
#define ATCA_POLLING_MAX_TIME_MSEC        ${CAL_POLL_TIMEOUT}
#endif

<#if !CAL_ENABLE_HEAP>
/** Define if the library is not to use malloc/free */
#ifndef ATCA_NO_HEAP
#define ATCA_NO_HEAP
#endif
</#if>

<#if CAL_ENABLE_RTOS>
/** Use RTOS timers (i.e. delays that yield when the scheduler is running) */
#ifndef ATCA_USE_RTOS_TIMER
#define ATCA_USE_RTOS_TIMER     (1)
#endif
#define atca_delay_ms   hal_rtos_delay_ms
#define atca_delay_us   hal_delay_us
<#else>
#define atca_delay_ms   hal_delay_ms
#define atca_delay_us   hal_delay_us
</#if>

/* \brief How long to wait after an initial wake failure for the POST to
 *         complete.
 * If Power-on self test (POST) is enabled, the self test will run on waking
 * from sleep or during power-on, which delays the wake reply.
 */
#ifndef ATCA_POST_DELAY_MSEC
#define ATCA_POST_DELAY_MSEC 25
#endif

<#if CAL_ENABLE_DEBUG_PRINT>
#ifndef ATCA_PRINTF
#define ATCA_PRINTF
#endif
</#if>

/* Define generic interfaces to the processor libraries */
<#assign pliblist = CAL_PLIB_LIST?word_list>
<#if pliblist?size != 0>
<#assign size_var = "size_t">

<#if atca_hal_i2c??>
<#if pliblist[0]?contains("sercom")>
#define PLIB_I2C_ERROR          SERCOM_I2C_ERROR
#define PLIB_I2C_ERROR_NONE     SERCOM_I2C_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP SERCOM_I2C_TRANSFER_SETUP
<#assign size_var = "uint32_t">
<#elseif pliblist[0]?contains("flexcom")>
#define PLIB_I2C_ERROR          FLEXCOM_TWI_ERROR
#define PLIB_I2C_ERROR_NONE     FLEXCOM_TWI_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP FLEXCOM_TWI_TRANSFER_SETUP
<#elseif pliblist[0]?contains("twihs")>
#define PLIB_I2C_ERROR          TWIHS_ERROR
#define PLIB_I2C_ERROR_NONE     TWIHS_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP TWIHS_TRANSFER_SETUP
<#elseif pliblist[0]?contains("i2c")>
#define PLIB_I2C_ERROR          I2C_ERROR
#define PLIB_I2C_ERROR_NONE     I2C_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP I2C_TRANSFER_SETUP
</#if>

typedef bool (* atca_i2c_plib_read)( uint16_t, uint8_t *, ${size_var} );
typedef bool (* atca_i2c_plib_write)( uint16_t, uint8_t *, ${size_var} );
typedef bool (* atca_i2c_plib_is_busy)( void );
typedef PLIB_I2C_ERROR (* atca_i2c_error_get)( void );
typedef bool (* atca_i2c_plib_transfer_setup)(PLIB_I2C_TRANSFER_SETUP* setup, uint32_t srcClkFreq);

typedef struct atca_plib_api
{
    atca_i2c_plib_read              read;
    atca_i2c_plib_write             write;
    atca_i2c_plib_is_busy           is_busy;
    atca_i2c_error_get              error_get;
    atca_i2c_plib_transfer_setup    transfer_setup;
} atca_plib_i2c_api_t;
</#if>
<#if atca_hal_spi??>
typedef bool (* atca_spi_plib_read)( void * , size_t );
typedef bool (* atca_spi_plib_write)( void *, size_t );
typedef bool (* atca_spi_plib_is_busy)( void );
typedef void (* atca_spi_plib_select)(uint32_t pin, bool value);

typedef struct atca_plib_spi_api
{
    atca_spi_plib_read              read;
    atca_spi_plib_write             write;
    atca_spi_plib_is_busy           is_busy;
    atca_spi_plib_select            select;
} atca_plib_spi_api_t;
</#if>

<#list pliblist as plib_id>
<#assign plib_info = plib_id?split("_")>
extern atca_plib_${plib_info[1]!"i2c"}_api_t ${plib_info[0]}_plib_${plib_info[1]!"i2c"}_api;
</#list>
</#if>

<#if cryptoauthlib_tng??>
/** Define certificate templates to be supported. */
<#if cryptoauthlib_tng.CAL_TNGTLS_SUPPORT>
#define ATCA_TNGTLS_SUPPORT
</#if>
<#if cryptoauthlib_tng.CAL_TNGLORA_SUPPORT>
#define ATCA_TNGLORA_SUPPORT
</#if>
<#if cryptoauthlib_tng.CAL_TFLEX_SUPPORT>
#define ATCA_TFLEX_SUPPORT
</#if>
<#if cryptoauthlib_tng.CAL_TNG_LEGACY_SUPPORT>
#define ATCA_TNG_LEGACY_SUPPORT
</#if>
</#if>

<#if CAL_ENABLE_WOLFCRYPTO>
/** Define Software Crypto Library to Use - if none are defined use the
    cryptoauthlib version where applicable */
#define ATCA_WOLFSSL
</#if>


#endif // ATCA_CONFIG_H
