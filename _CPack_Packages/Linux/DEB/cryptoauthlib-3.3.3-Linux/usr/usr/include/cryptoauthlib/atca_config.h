/* Auto-generated config file atca_config.h */
#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

/* Included HALS */
/* #undef ATCA_HAL_KIT_UART */
/* #undef ATCA_HAL_KIT_HID */
#define ATCA_HAL_I2C
/* #undef ATCA_HAL_SPI */
/* #undef ATCA_HAL_KIT_BRIDGE */
/* #undef ATCA_HAL_CUSTOM */
/* #undef ATCA_HAL_SWI_UART */
/* #undef ATCA_HAL_1WIRE */


/** Define to enable compatibility with legacy HALs
   (HALs with embedded device logic)*/
/* #undef ATCA_HAL_LEGACY_API */


/* Included device support */
#define ATCA_ATSHA204A_SUPPORT
#define ATCA_ATSHA206A_SUPPORT
#define ATCA_ATECC108A_SUPPORT
#define ATCA_ATECC508A_SUPPORT
#define ATCA_ATECC608_SUPPORT
/* #undef ATCA_TA100_SUPPORT */
#define ATCA_ECC204_SUPPORT

/** Device Override - Library Assumes ATECC608B support in checks */
/* #undef ATCA_ATECC608A_SUPPORT */



/** Define if cryptoauthlib is to use the maximum execution time method */
/* #undef ATCA_NO_POLL */


/* \brief How long to wait after an initial wake failure for the POST to
 *         complete.
 * If Power-on self test (POST) is enabled, the self test will run on waking
 * from sleep or during power-on, which delays the wake reply.
 */
#ifndef ATCA_POST_DELAY_MSEC
#define ATCA_POST_DELAY_MSEC 25
#endif

/***************** Diagnostic & Test Configuration Section *****************/

/** Enable debug messages */
/* #undef ATCA_PRINTF */

/** Enable to build in test hooks */
/* #undef ATCA_TESTS_ENABLED */

/******************** Features Configuration Section ***********************/

/** Define certificate templates to be supported. */
/* #undef ATCA_TNGTLS_SUPPORT */
/* #undef ATCA_TNGLORA_SUPPORT */
/* #undef ATCA_TFLEX_SUPPORT */
/* #undef ATCA_TNG_LEGACY_SUPPORT */

/** Define Software Crypto Library to Use - if none are defined use the
    cryptoauthlib version where applicable */
/* #undef ATCA_MBEDTLS */
/* #undef ATCA_OPENSSL */
/* #undef ATCA_WOLFSSL */

#ifdef ATCA_WOLFSSL
/* #undef WOLFSSL_USER_SETTINGS */
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#endif
#endif

/** Additional Runtime Configuration */
#define ATCA_LIBRARY_CONF  "/etc/cryptoauthlib/cryptoauthlib.conf"

/** Define to build atcab_ functions rather that defining them as macros */
/* #undef ATCA_USE_ATCAB_FUNCTIONS */

/** Define to enable older API forms that have been replaced */
/* #undef ATCA_ENABLE_DEPRECATED */

/** TA100 Specific - Enable auth sessions that require AES (CMAC/GCM) from
   an external library */
/* #undef ATCA_TA100_AES_AUTH_SUPPORT */

/** TA100 Specific - Enable support for the FCE APIs for the TA100 */
/* #undef ATCA_TA100_FCE_SUPPORT */

/******************** Platform Configuration Section ***********************/

/** Define if the library is not to use malloc/free */
/* #undef ATCA_NO_HEAP */

/** Define platform malloc/free */
#define ATCA_PLATFORM_MALLOC    malloc
#define ATCA_PLATFORM_FREE      free

#define atca_delay_ms   hal_delay_ms
#define atca_delay_us   hal_delay_us

#endif // ATCA_CONFIG_H
