#include "atcacert/atcacert_def.h"

#if ATCACERT_INTEGRATION_EN
static struct atcac_x509_ctx* parsed;
#endif

const atcacert_def_t g_cert_def_4_signer = {
    .type = CERTTYPE_X509_FULL_STORED,
    .comp_cert_dev_loc = {
        .zone = DEVZONE_DATA,
        .slot = 0x8600,
        .is_genkey = 0,
        .offset = 0,
        .count = 327
    },
    .ca_cert_def = NULL,
#if ATCACERT_INTEGRATION_EN
    .parsed = &parsed
#endif
};
