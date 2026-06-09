cmake_minimum_required(VERSION 3.20.0)
project(pkcs11support C)

if(ATCA_PKCS11_SUPPORT)
    file(GLOB PKCS11_SRC "*.c")
    file(GLOB PKCS11_INC "*.h")

    # Compile directly with the rest of the sources
    target_sources(cryptoauth PRIVATE ${PKCS11_SRC})
    get_target_property(CAL_BIN_DIR cryptoauth BINARY_DIR)
    set(PKCS11_CONFIG ${CAL_BIN_DIR}/pkcs11_config.h)

    configure_file(pkcs11_config.h.in ${PKCS11_CONFIG} @ONLY)
    set(PKCS11_INC ${PKCS11_INC} ${PKCS11_CONFIG})
endif()
