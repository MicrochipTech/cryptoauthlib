#ifndef WPC_CONFIG_H
#define WPC_CONFIG_H

#if ATCA_ECC_SUPPORT
/* WPC Configuration */
   #define WPC_CHAIN_DIGEST_HANDLE_0   0x03
   #define WPC_CHAIN_CERT_DEF_0        g_cert_def_2_device
   #define WPC_CHAIN_ROOT_DIGEST_0     g_root_ca_digest
#elif ATCA_CA2_SUPPORT
/* WPC Configuration */
   #define WPC_CHAIN_DIGEST_HANDLE_0   0x02
   #define WPC_CHAIN_CERT_DEF_0        g_cert_def_3_device
   #define WPC_CHAIN_ROOT_DIGEST_0     g_cert_def_3_root_digest
   #define WPC_CHAIN_MFG_CERT_0        g_cert_def_3_signer
#elif ATCA_TA_SUPPORT
/* WPC Configuration */
   #define WPC_CHAIN_DIGEST_HANDLE_0         0x8602
   #define WPC_CHAIN_CERT_DEF_0              g_cert_def_5_device
   #define WPC_CHAIN_ROOT_DIGEST_HANDLE_0    0x8050
#endif

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

#ifndef ATCA_PUB_KEY_SIZE
#define ATCA_PUB_KEY_SIZE                   (64u)
#endif
#ifndef ATCA_SHA_DIGEST_SIZE
#define ATCA_SHA_DIGEST_SIZE                (32u)
#endif

#endif
