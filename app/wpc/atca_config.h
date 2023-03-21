/* Auto-generated config file atca_config.h */
#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

/* MPLAB Harmony Common Include */
#include "definitions.h"

#ifndef ATCA_HAL_I2C
#define ATCA_HAL_I2C
#endif



/** Include Device Support Options */
#define ATCA_ATECC608_SUPPORT




/* Polling Configuration Options  */
#ifndef ATCA_POLLING_INIT_TIME_MSEC
#define ATCA_POLLING_INIT_TIME_MSEC       1
#endif
#ifndef ATCA_POLLING_FREQUENCY_TIME_MSEC
#define ATCA_POLLING_FREQUENCY_TIME_MSEC  2
#endif
#ifndef ATCA_POLLING_MAX_TIME_MSEC
#define ATCA_POLLING_MAX_TIME_MSEC        2500
#endif

/** Define if the library is not to use malloc/free */
#define ATCA_NO_HEAP

#define atca_delay_ms   hal_delay_ms
#define atca_delay_us   hal_delay_us

/* \brief How long to wait after an initial wake failure for the POST to
 *         complete.
 * If Power-on self test (POST) is enabled, the self test will run on waking
 * from sleep or during power-on, which delays the wake reply.
 */
#ifndef ATCA_POST_DELAY_MSEC
#define ATCA_POST_DELAY_MSEC 25
#endif


/* Define generic interfaces to the processor libraries */

#define PLIB_I2C_ERROR          SERCOM_I2C_ERROR
#define PLIB_I2C_ERROR_NONE     SERCOM_I2C_ERROR_NONE
#define PLIB_I2C_TRANSFER_SETUP SERCOM_I2C_TRANSFER_SETUP

typedef bool (* atca_i2c_plib_read)(uint16_t, uint8_t *, uint32_t);
typedef bool (* atca_i2c_plib_write)(uint16_t, uint8_t *, uint32_t);
typedef bool (* atca_i2c_plib_is_busy)(void);
typedef PLIB_I2C_ERROR (* atca_i2c_error_get)(void);
typedef bool (* atca_i2c_plib_transfer_setup)(PLIB_I2C_TRANSFER_SETUP* setup, uint32_t srcClkFreq);

typedef struct atca_plib_i2c_api
{
    atca_i2c_plib_read           read;
    atca_i2c_plib_write          write;
    atca_i2c_plib_is_busy        is_busy;
    atca_i2c_error_get           error_get;
    atca_i2c_plib_transfer_setup transfer_setup;
} atca_plib_i2c_api_t;




extern atca_plib_i2c_api_t sercom2_plib_i2c_api;

/* WPC Configuration */
#define WPC_CHAIN_DIGEST_HANDLE_0   0x03
#define WPC_CHAIN_CERT_DEF_0        g_cert_def_2_device

/* Define for a simple mapping of slot to certificate */
#define WPC_STRICT_SLOT_INDEX

/* One of the certificate format options is to generate the certificate serial
   number from a hash of several data elements - this saves storage in the device
   at the expense of code space and time */
#define WPC_CERT_SN_FROM_HASH_EN    FEATURE_DISABLED

/* Enable the Power Transmitter API */
#define WPC_MSG_PT_EN               FEATURE_ENABLED

/* Disable the Power Receiver API since this project is demonstrating the transmitter */
#define WPC_MSG_PR_EN               FEATURE_DISABLED


/* Turn off parameter checking in the library - enable for easier debugging in development */
//#define ATCA_CHECK_PARAMS_EN        FEATURE_DISABLED

/* API Configuration Options */
#define ATCAB_AES_EN                FEATURE_DISABLED
#define ATCAB_AES_GCM_EN            FEATURE_DISABLED
#define ATCAB_COUNTER_EN            FEATURE_DISABLED
#define ATCAB_DELETE_EN             FEATURE_DISABLED
#define ATCAB_DERIVEKEY_EN          FEATURE_DISABLED
#define ATCAB_ECDH_EN               FEATURE_DISABLED
#define ATCAB_ECDH_ENC_EN           FEATURE_DISABLED
#define ATCAB_GENDIG_EN             FEATURE_DISABLED
#define ATCAB_GENKEY_MAC_EN         FEATURE_DISABLED
#define ATCAB_HMAC_EN               FEATURE_DISABLED
#define ATCAB_INFO_LATCH_EN         FEATURE_DISABLED
#define ATCAB_KDF_EN                FEATURE_DISABLED
#define ATCAB_LOCK_EN               FEATURE_DISABLED
#define ATCAB_MAC_EN                FEATURE_DISABLED
#define ATCAB_PRIVWRITE_EN          FEATURE_DISABLED
/* By default the random command is only required for the power receiver to generate
   challenges - because a health check on the rng before a sign can return failures
   the power transmitter has a choice - enable the random command which will use more
   code or retry the sign operation if a health check failure occurs. */
#define ATCAB_RANDOM_EN             WPC_MSG_PR_EN
#define ATCAB_READ_ENC_EN           FEATURE_DISABLED
#define ATCAB_SECUREBOOT_EN         FEATURE_DISABLED
#define ATCAB_SECUREBOOT_MAC_EN     FEATURE_DISABLED
#define ATCAB_SELFTEST_EN           FEATURE_DISABLED
#define ATCAB_SHA_HMAC_EN           FEATURE_DISABLED
#define ATCAB_SIGN_INTERNAL_EN      FEATURE_DISABLED
#define ATCAB_UPDATEEXTRA_EN        FEATURE_DISABLED
/* Enable the verify command when the power receiver api is enabled - this helps
   with testing - it is unnecessary for the power transmitter */
#define ATCAB_VERIFY_EN             WPC_MSG_PR_EN
#define ATCAB_WRITE_EN              FEATURE_DISABLED

/* Disable software cryptography */
#define ATCAC_SHA1_EN               FEATURE_DISABLED
#define ATCAC_SHA256_EN             FEATURE_DISABLED

/* Certificate Processing Configuration */
#define ATCACERT_DATEFMT_UTC_EN     FEATURE_ENABLED
#define ATCACERT_DATEFMT_GEN_EN     FEATURE_ENABLED

#define ATCACERT_DATEFMT_ISO_EN     FEATURE_DISABLED
#define ATCACERT_DATEFMT_POSIX_EN   FEATURE_DISABLED


#endif // ATCA_CONFIG_H
