# Certificate Options
option(ATCACERT_COMPCERT_EN       "Include Compressed Certificate support" ON)
option(ATCACERT_FULLSTOREDCERT_EN "Include Full Certificate support" ON)

# Full certificate integration option
if (ATCA_MBEDTLS OR ATCA_WOLFSSL OR ATCA_OPENSSL)
option(ATCACERT_INTEGRATION_EN "Enable ATCACERT full certificate integration" ON)
endif()

if(ATCACERT_COMPCERT_EN OR ATCACERT_FULLSTOREDCERT_EN)
set(ATCACERT_SUPPORT ON)
endif()