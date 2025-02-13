#include "atcacert/atcacert_def.h"
#include "zcust_def_4_signer.h"

#if ATCACERT_INTEGRATION_EN
static struct atcac_x509_ctx* parsed;
#endif

const atcacert_def_t g_cert_def_5_device = {
    .type = CERTTYPE_X509_FULL_STORED,
    .private_key_slot = 0x8051,
#if ATCACERT_COMPCERT_EN
    .public_key_dev_loc = {
        .zone = DEVZONE_DATA,
        .slot = 0x8051,
        .is_genkey = 1,
        .offset = 0,
        .count = 64
    },
#endif
    .comp_cert_dev_loc = {
        .zone = DEVZONE_DATA,
        .slot = 0x8601,
        .is_genkey = 0,
        .offset = 0,
        .count = 314
    },
    .ca_cert_def = &g_cert_def_4_signer,
#if ATCACERT_INTEGRATION_EN
    .parsed = &parsed
#endif
};
