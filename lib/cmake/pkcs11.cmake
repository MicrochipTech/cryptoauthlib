# Helper CMake file for PKCS11 extension to the library

# PKCS11 Configuration Options - See pkcs11_config.h.in
option(PKCS11_DEBUG_ENABLE              "Enable debug of PKCS11 implementation - NOT SECURE" OFF)
option(PKCS11_USE_STATIC_MEMORY         "Use statically allocated library context" ${ATCA_NO_HEAP})
option(PKCS11_USE_STATIC_CONFIG         "Use a compiled configuration rather than loading from a filestore - only intended for embedded devices" OFF)
option(PKCS11_EXTERNAL_FUNCTION_LIST    "Use an alternative function list - only for embedded devices" OFF)
option(PKCS11_TESTING_ENABLE            "Enable testing functions that shouldn't be part of production builds" OFF)
option(PKCS11_PIN_KDF_ALWAYS            "Always a kdf function to convert a provide pin to a stored key" OFF)
option(PKCS11_PIN_PBKDF2_EN             "Use the PBKDF2 algorithm to convert pin to stored key value" OFF)
option(PKCS11_LOCK_PIN_SLOT             "Define to lock the PIN slot after writing" OFF)
option(PKCS11_TOKEN_INIT_SUPPORT        "Enable device initialization using pkcs11 token initialization - UNSAFE" OFF)
option(PKCS11_MONOTONIC_ENABLE          "Map device counters to the pkcs11 montotonic counter class" OFF)
option(PKCS11_AUTO_ID_ENABLE            "Generate CKA_ID values based on standards" ON)
option(PKCS11_AUTH_TERMINATE_BEFORE_LOGIN    "Enable auth terminate before c_login" OFF)
option(PKCS11_RSA_SUPPORT_ENABLE        "Enable RSA support" OFF)

set(PKCS11_MAX_SLOTS_ALLOWED    1   CACHE STRING "Maximum number of slots allowed in the system")
set(PKCS11_MAX_SESSIONS_ALLOWED 10  CACHE STRING "Maximum number of total sessions allowed in the system")
set(PKCS11_MAX_CERTS_CACHED     5   CACHE STRING "Maximum number of x509 certificates allowed to be cached")
set(PKCS11_MAX_KEYS_CACHED      5   CACHE STRING "Maximum number of key IDs allowed to be cached")
set(PKCS11_MAX_OBJECTS_ALLOWED  16  CACHE STRING "Maximum number of cryptographic objects allowed to be cached")
set(PKCS11_MAX_LABEL_SIZE       30  CACHE STRING "Maximum label size in characters")
set(PKCS11_MAX_CONFIG_ALLOWED 7 CACHE STRING "Maximum depth to configuration options")
set(PKCS11_PIN_PBKDF2_ITERATIONS  2 CACHE STRING "Define how many iterations PBKDF2 will use for PIN KDF")
set(PKCS11_SEARCH_CACHE_SIZE    250 CACHE STRING "Static Search Attribute Cache in bytes")

file(GLOB PKCS11_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "pkcs11/*.c")
file(GLOB PKCS11_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "pkcs11/*.h")

configure_file(pkcs11/pkcs11_config.h.in ${CMAKE_CURRENT_BINARY_DIR}/pkcs11_config.h @ONLY)
set(PKCS11_INC ${PKCS11_INC} ${CMAKE_CURRENT_BINARY_DIR}/pkcs11_config.h)
