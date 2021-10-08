/* Auto-generated config file atca_config.h */
#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

/* MPLAB Harmony Common Include */
#include "definitions.h"

<#assign pliblist = CAL_HAL_LIST?word_list>
<#if pliblist?size != 0>
<#list pliblist as plib_id>
#ifndef ATCA_HAL_${plib_id}
#define ATCA_HAL_${plib_id}
#endif

</#list>
</#if>


<#assign devices = CAL_DEVICE_LIST?word_list>
<#if devices?size != 0>
/** Include Device Support Options */
<#list devices as device_type>
#define ATCA_${device_type}_SUPPORT
</#list>
</#if>

<#if CAL_ENABLE_TA100_AES_AUTH>
/** TA100 Specific - Enable auth sessions that require AES (CMAC/GCM) from
   an external library */
#define ATCA_TA100_AES_AUTH_SUPPORT
</#if>

<#if CAL_ENABLE_TA100_FCE>
/** TA100 Specific - Enable support for the FCE APIs for the TA100 */
#define ATCA_TA100_FCE_SUPPORT
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
/** Define platform malloc/free */
#define ATCA_PLATFORM_MALLOC    OSAL_Malloc
#define ATCA_PLATFORM_FREE      OSAL_Free

/** Use RTOS timers (i.e. delays that yield when the scheduler is running) */
#ifndef ATCA_USE_RTOS_TIMER
#define ATCA_USE_RTOS_TIMER     (1)
#endif

#define atca_delay_ms   hal_rtos_delay_ms
#define atca_delay_us   hal_delay_us
<#else>
/** Define platform malloc/free */
#define ATCA_PLATFORM_MALLOC    malloc
#define ATCA_PLATFORM_FREE      free

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
<#assign is_atca_plib_i2c_exists = "False">
<#assign is_atca_plib_spi_exists = "False">
<#assign is_atca_plib_uart_exists = "False">
<#assign is_atca_plib_bb_exists = "False">
<#assign pliblist = CAL_PLIB_LIST?word_list>
<#if pliblist?size != 0>
<#list pliblist as plib_id>
<#assign plib_info = plib_id?split("_")>

<#if plib_info[plib_info?size-1] == "i2c">
<#if is_atca_plib_i2c_exists == "False">
<#assign size_var = "size_t">
<#if plib_id?contains("sercom")>
#define PLIB_I2C_ERROR          SERCOM_I2C_ERROR
#define PLIB_I2C_ERROR_NONE     SERCOM_I2C_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP SERCOM_I2C_TRANSFER_SETUP
<#assign size_var = "uint32_t">
<#elseif plib_id?contains("flexcom")>
#define PLIB_I2C_ERROR          FLEXCOM_TWI_ERROR
#define PLIB_I2C_ERROR_NONE     FLEXCOM_TWI_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP FLEXCOM_TWI_TRANSFER_SETUP
<#elseif plib_id?contains("twihs")>
#define PLIB_I2C_ERROR          TWIHS_ERROR
#define PLIB_I2C_ERROR_NONE     TWIHS_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP TWIHS_TRANSFER_SETUP
<#elseif plib_id?contains("i2c")>
#define PLIB_I2C_ERROR          I2C_ERROR
#define PLIB_I2C_ERROR_NONE     I2C_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP I2C_TRANSFER_SETUP
</#if>

typedef bool (* atca_i2c_plib_read)( uint16_t, uint8_t *, ${size_var} );
typedef bool (* atca_i2c_plib_write)( uint16_t, uint8_t *, ${size_var} );
typedef bool (* atca_i2c_plib_is_busy)( void );
typedef PLIB_I2C_ERROR (* atca_i2c_error_get)( void );
typedef bool (* atca_i2c_plib_transfer_setup)(PLIB_I2C_TRANSFER_SETUP* setup, uint32_t srcClkFreq);

typedef struct atca_plib_i2c_api
{
    atca_i2c_plib_read              read;
    atca_i2c_plib_write             write;
    atca_i2c_plib_is_busy           is_busy;
    atca_i2c_error_get              error_get;
    atca_i2c_plib_transfer_setup    transfer_setup;
} atca_plib_i2c_api_t;
<#assign is_atca_plib_i2c_exists = "True">
</#if>
</#if>

<#if plib_info[plib_info?size-1] == "spi">
<#if is_atca_plib_spi_exists == "False">
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
<#assign is_atca_plib_spi_exists = "True">
</#if>
</#if>

<#if plib_info[plib_info?size-1] == "uart">
<#if is_atca_plib_uart_exists == "False">
<#if plib_id?contains("flexcom")>
#define PLIB_SWI_ERROR             FLEXCOM_USART_ERROR
#define PLIB_SWI_SERIAL_SETUP      FLEXCOM_USART_SERIAL_SETUP
#define PLIB_SWI_READ_ERROR        FLEXCOM_USART_EVENT_READ_ERROR
#define PLIB_SWI_READ_CALLBACK     FLEXCOM_USART_RING_BUFFER_CALLBACK
#define PLIB_SWI_PARITY_NONE       FLEXCOM_USART_PARITY_NONE
#define PLIB_SWI_DATA_WIDTH        FLEXCOM_USART_DATA_7_BIT
#define PLIB_SWI_STOP_BIT          FLEXCOM_USART_STOP_1_BIT
#define PLIB_SWI_EVENT             FLEXCOM_USART_EVENT
<#elseif plib_id?contains("sercom")>
#define PLIB_SWI_ERROR             USART_ERROR
#define PLIB_SWI_SERIAL_SETUP      USART_SERIAL_SETUP
#define PLIB_SWI_READ_ERROR        SERCOM_USART_EVENT_READ_ERROR
#define PLIB_SWI_READ_CALLBACK     SERCOM_USART_RING_BUFFER_CALLBACK
#define PLIB_SWI_PARITY_NONE       USART_PARITY_NONE
#define PLIB_SWI_DATA_WIDTH        USART_DATA_7_BIT
#define PLIB_SWI_STOP_BIT          USART_STOP_1_BIT
#define PLIB_SWI_EVENT             SERCOM_USART_EVENT
<#elseif plib_id?contains("usart")>
#define PLIB_SWI_ERROR             USART_ERROR
#define PLIB_SWI_SERIAL_SETUP      USART_SERIAL_SETUP
#define PLIB_SWI_READ_ERROR        USART_EVENT_READ_ERROR
#define PLIB_SWI_READ_CALLBACK     USART_RING_BUFFER_CALLBACK
#define PLIB_SWI_PARITY_NONE       USART_PARITY_NONE
#define PLIB_SWI_DATA_WIDTH        USART_DATA_7_BIT
#define PLIB_SWI_STOP_BIT          USART_STOP_1_BIT
#define PLIB_SWI_EVENT             USART_EVENT
</#if>

typedef size_t (* atca_uart_plib_read)( uint8_t *, const size_t );
typedef size_t (* atca_uart_plib_write)( uint8_t *, const size_t );
typedef PLIB_SWI_ERROR (* atca_uart_error_get)( void );
typedef bool (* atca_uart_plib_serial_setup)(PLIB_SWI_SERIAL_SETUP* , uint32_t );
typedef size_t (* atca_uart_plib_readcount_get)( void );
typedef void (* atca_uart_plib_readcallbackreg)(PLIB_SWI_READ_CALLBACK, uintptr_t );

typedef struct atca_plib_uart_api
{
    atca_uart_plib_read              read;
    atca_uart_plib_write             write;
    atca_uart_error_get              error_get;
    atca_uart_plib_serial_setup      serial_setup;
    atca_uart_plib_readcount_get     readcount_get;
    atca_uart_plib_readcallbackreg   readcallback_reg;
} atca_plib_uart_api_t;

<#assign is_atca_plib_uart_exists = "True">

/** SWI Transmit delay */
#define SWI_TX_DELAY     ((uint32_t)90)
</#if>
<#elseif plib_info[plib_info?size-1] == "bb">
<#if is_atca_plib_bb_exists == "False">
typedef bool (* atca_swi_plib_read)( uint8_t );
typedef void (* atca_swi_plib_write)( uint8_t, bool );
typedef void (* atca_swi_set_pin_output)( uint8_t );
typedef void (* atca_swi_set_pin_input)( uint8_t );

typedef struct atca_plib_swi_api
{
    atca_swi_plib_read            read;
    atca_swi_plib_write           write;
    atca_swi_set_pin_output       set_pin_output_dir;
    atca_swi_set_pin_input        set_pin_input_dir;
}atca_plib_bb_api_t;
<#assign is_atca_plib_bb_exists = "True">

/**
 * \name Macros for Bit-Banged SWI Timing
 *
 * Times to drive bits at 230.4 kbps.
   @{ */

//! delay macro for width of one pulse (start pulse or zero pulse)
//! should be 4.34 us, is 4.05 us

#define BIT_DELAY_1L        atca_delay_us(4)
//! should be 4.34 us, is 4.05us
#define BIT_DELAY_1H        atca_delay_us(4)

//! time to keep pin high for five pulses plus stop bit (used to bit-bang CryptoAuth 'zero' bit)
//! should be 26.04 us, is 26.92 us
#define BIT_DELAY_5        atca_delay_us(26)    // considering pin set delay

//! time to keep pin high for seven bits plus stop bit (used to bit-bang CryptoAuth 'one' bit)
//! should be 34.72 us, is 35.13 us
#define BIT_DELAY_7        atca_delay_us(34)    // considering pin set delay

//! turn around time when switching from receive to transmit
//! should be 93 us (Setting little less value as there would be other process before these steps)
#define RX_TX_DELAY        atca_delay_us(65)

</#if>
</#if>
</#list>
</#if>

<#if atca_hal_swi??>
/** SWI Flags */
#define SWI_WAKE_TOKEN   ((uint8_t)0x00)
#define SWI_FLAG_CMD     ((uint8_t)0x77)
#define SWI_FLAG_TX      ((uint8_t)0x88)
#define SWI_FLAG_IDLE    ((uint8_t)0xBB)
#define SWI_FLAG_SLEEP   ((uint8_t)0xCC)
</#if>

<#list pliblist as plib_id>
<#assign plib_info = plib_id?split("_")>
<#assign plib_drv = plib_info[plib_info?size-1]>
extern atca_plib_${plib_drv!"i2c"}_api_t ${plib_info[0]}_plib_${plib_drv!"i2c"}_api;
</#list>

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

<#assign devcfglist = CAL_DEV_CFG_LIST?word_list>
<#if devcfglist?size != 0>
#define ATCA_TEST_MULTIPLE_INSTANCES
</#if>


#endif // ATCA_CONFIG_H
