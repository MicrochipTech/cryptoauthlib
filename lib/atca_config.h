#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

/*
* Consumers (ie target repos) of this repository must define this file.
* It should include any of the support atca configuration settings that are
   specific to that target, any common settings will be defined here.
*/
#include "platform_atca_config.h"

#include <stdint.h>
#include <string.h>

#ifndef ATCA_WORD_SIZE_BYTES
#define ATCA_WORD_SIZE_BYTES 1
#endif

/* Included device support */
#define ATCA_ATECC608_SUPPORT

/* Linked device support library */
#define ATCA_TA_SUPPORT 0


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

/** Enable preprocessor warning messages */
#define ATCA_PREPROCESSOR_WARNING 0

/******************** Features Configuration Section ***********************/
/** Define Software Crypto Library to Use - if none are defined use the
    cryptoauthlib version where applicable */
/* #undef ATCA_MBEDTLS */
/* #undef ATCA_OPENSSL */
/* #undef ATCA_WOLFSSL */

/** Additional Runtime Configuration */
/* #undef ATCA_LIBRARY_CONF */

/** Define to build atcab_ functions rather that defining them as macros */
#define ATCA_USE_ATCAB_FUNCTIONS

/** Define to enable older API forms that have been replaced */
/* #undef ATCA_ENABLE_DEPRECATED */

/** Enable Strict ISO/C99 compliance */
/* #undef ATCA_STRICT_C99 */

/** Enable ATCACERT Module */
#define ATCACERT_EN 0

/******************** Device Configuration Section *************************/
/** Enable the delete command */
#define CALIB_DELETE_EN 0

/******************** Packet Size Configuration Section *************************/
/** Provide Maximum packet size for the command to be sent and received */
/* #undef MAX_PACKET_SIZE */

/** Enables multipart buffer handling (generally for small memory model platforms) */
#define MULTIPART_BUF_EN 0

#endif // ATCA_CONFIG_H
