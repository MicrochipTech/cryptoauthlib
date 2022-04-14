# Helper CMake file for PKCS11 extension to the library

# PKCS11 Configuration Options - See pkcs11_config.h.in
set(PKCS11_DEBUG_ENABLE         OFF CACHE BOOL   "Enable PKCS#11 Debugging Messages")
set(PKCS11_USE_STATIC_MEMORY    ${ATCA_NO_HEAP}  CACHE BOOL   "Use Static Memory Allocation")
set(PKCS11_USE_STATIC_CONFIG    OFF CACHE BOOL   "Use a compiled configuration rather than loading from a filestore")
set(PKCS11_MAX_SLOTS_ALLOWED    1   CACHE STRING "Maximum number of slots allowed in the system")
set(PKCS11_MAX_SESSIONS_ALLOWED 10  CACHE STRING "Maximum number of total sessions allowed in the system")
set(PKCS11_MAX_OBJECTS_ALLOWED  16  CACHE STRING "Maximum number of cryptographic objects allowed to be cached")
set(PKCS11_MAX_LABEL_SIZE       30  CACHE STRING "Maximum label size in characters")
set(PKCS11_LOCK_PIN_SLOT        OFF CACHE BOOL   "Define to lock the PIN slot after writing")
set(PKCS11_PIN_KDF_ALWAYS       OFF CACHE BOOL   "Define to always convert PIN using KDF")
set(PKCS11_PIN_PBKDF2_EN        OFF CACHE BOOL   "Define to use PBKDF2 for PIN KDF")
set(PKCS11_PIN_PBKDF2_ITERATIONS  2 CACHE STRING "Define how many iterations PBKDF2 will use for PIN KDF")
set(PKCS11_SEARCH_CACHE_SIZE    250 CACHE STRING "Static Search Attribute Cache in bytes")
set(PKCS11_TOKEN_INIT_SUPPORT   OFF CACHE BOOL   "Support for configuring a blank or new device")
set(PKCS11_MONOTONIC_ENABLE     OFF CACHE BOOL   "Include the monotonic hardware feature as an object")

file(GLOB PKCS11_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "pkcs11/*.c")
file(GLOB PKCS11_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "pkcs11/*.h")

configure_file(pkcs11/pkcs11_config.h.in ${CMAKE_CURRENT_BINARY_DIR}/pkcs11_config.h @ONLY)
set(PKCS11_INC ${PKCS11_INC} ${CMAKE_CURRENT_BINARY_DIR}/pkcs11_config.h)

if(ATCA_TNGTLS_SUPPORT OR ATCA_TNGLORA_SUPPORT OR ATCA_TFLEX_SUPPORT)
SET(TNG_SRC ${TNG_SRC} ../app/pkcs11/trust_pkcs11_config.c)
endif()

if(${CMAKE_VERSION} VERSION_GREATER "3.8.0")
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${PKCS11_SRC})
endif()
