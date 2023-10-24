#ifndef WPC_CHECK_CONFIG_H
#define WPC_CHECK_CONFIG_H

/* Pick up the global configuration and library checks */
#include "cryptoauthlib.h"

/* WPC "Slot" Configuration follows the WPC nomenclature where a slot is
   defined as a certificate chain which also has a uniquely defined format

   Configuring a chain for cryptoauth parts:
     WPC_CHAIN_DIGEST_HANDLE_<slot_id>
     WPC_CHAIN_CERT_DEF_<slot_id>
     WPC_CHAIN_ROOT_DIGEST_<slot_id>

   Configuring a chain for trust anchor parts:
     WPC_CHAIN_DIGEST_HANDLE_<slot_id>
     WPC_CHAIN_HANDLE_<slot_id>
     WPC_CHAIN_ROOT_DIGEST_<slot_id>

 */

/* Enable the Power Transmitter APIs */
#ifndef WPC_MSG_PT_EN
#define WPC_MSG_PT_EN               DEFAULT_ENABLED
#endif

/* Enable the Power Reciever APIs */
#ifndef WPC_MSG_PR_EN
#define WPC_MSG_PR_EN               DEFAULT_ENABLED
#endif

/** Use the option WPC_STRICT_SLOT_INDEX to configure simple mapping of slot to certificate */
#ifndef WPC_STRICT_SLOT_INDEX_EN
#define WPC_STRICT_SLOT_INDEX_EN    DEFAULT_DISABLED
#endif

/* One of the certificate format options is to generate the certificate serial
   number from a hash of several data elements - this saves storage in the device
   at the expense of code space and time */
#ifndef WPC_CERT_SN_FROM_HASH_EN
#define WPC_CERT_SN_FROM_HASH_EN    DEFAULT_DISABLED
#endif

/* These are defaults set up for the testing environment */
#ifdef ATCA_TESTS_ENABLED
#if !(defined(WPC_CHAIN_DIGEST_HANDLE_0) || defined(WPC_CHAIN_CERT_DEF_0) || defined(WPC_CHAIN_ROOT_DIGEST_0))
#define WPC_CHAIN_DIGEST_HANDLE_0       0x03
#define WPC_CHAIN_CERT_DEF_0            g_cert_def_2_device
#define WPC_CHAIN_ROOT_DIGEST_0         g_root_ca_digest
#endif
#endif /* ATCA_TESTS_ENABLED */

#if ATCA_CA_SUPPORT && ATCA_TA_SUPPORT
#error "The WPC application reference is not designed to work with both cryptoauth and trust anchor support enabled"
#endif

/* Check for extraneous configuration options set for cryptoauth parts */
#if ATCA_CA_SUPPORT
#if (defined(WPC_CHAIN_HANDLE_0) || defined(WPC_CHAIN_HANDLE_1) || defined(WPC_CHAIN_HANDLE_2) || defined(WPC_CHAIN_HANDLE_3))
#warning "The WPC_CHAIN_HANDLE_n configurations will be ignored for cryptoauth devices - use WPC_CHAIN_CERT_DEF_n instead"
#endif
#endif

/* Check for extraneous configuration options set for trust anchor parts */
#if ATCA_TA_SUPPORT
#if (defined(WPC_CHAIN_CERT_DEF_0) || defined(WPC_CHAIN_CERT_DEF_1) || defined(WPC_CHAIN_CERT_DEF_2) || defined(WPC_CHAIN_CERT_DEF_3))
#warning "The WPC_CHAIN_CERT_DEF_n configurations will be ignored for trust anchor devices - use WPC_CHAIN_HANDLE_n instead"
#endif
#endif

/* Chain 0 must always be defined per the WPC */
#if !(defined(WPC_CHAIN_HANDLE_0) || defined(WPC_CHAIN_CERT_DEF_0))
#error "WPC Requires that slot 0 always contains a valid chain"
#endif

/* Check that the definitions are complete for a given chain */
#if (defined(WPC_CHAIN_HANDLE_0) || defined(WPC_CHAIN_CERT_DEF_0)) != (defined(WPC_CHAIN_DIGEST_HANDLE_0) && defined(WPC_CHAIN_ROOT_DIGEST_0))
#error "WPC Slot 0 definition is incomplete"
#endif
#if (defined(WPC_CHAIN_HANDLE_1) || defined(WPC_CHAIN_CERT_DEF_1)) != (defined(WPC_CHAIN_DIGEST_HANDLE_1) && defined(WPC_CHAIN_ROOT_DIGEST_1))
#error "WPC Slot 1 definition is incomplete"
#endif
#if (defined(WPC_CHAIN_HANDLE_2) || defined(WPC_CHAIN_CERT_DEF_2)) != (defined(WPC_CHAIN_DIGEST_HANDLE_2) && defined(WPC_CHAIN_ROOT_DIGEST_2))
#error "WPC Slot 2 definition is incomplete"
#endif
#if (defined(WPC_CHAIN_HANDLE_3) || defined(WPC_CHAIN_CERT_DEF_3)) != (defined(WPC_CHAIN_DIGEST_HANDLE_3) && defined(WPC_CHAIN_ROOT_DIGEST_3))
#error "WPC Slot 3 definition is incomplete"
#endif

#endif /* WPC_CHECK_CONFIG_H */
