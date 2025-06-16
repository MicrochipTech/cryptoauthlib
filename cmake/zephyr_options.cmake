# zephyr_options.cmake
# Map Zephyr Kconfig symbols (CONFIG_* variables) to our ATCA_* CMake options

# Only run under Zephyr support
if (ATCA_ZEPHYR_SUPPORT)
    message(STATUS "Mapping Kconfig symbols to CryptoAuthLib CMake options...")

    # List of all CryptoAuthLib options to map
    set(_opts
        HAL_I2C HAL_SPI HAL_CUSTOM HAL_KIT_HID HAL_KIT_BRIDGE HAL_KIT_UART HAL_SWI_UART
        PRINTF NO_HEAP CHECK_PARAMS_EN ENABLE_DEPRECATED STRICT_C99 MULTIPART_BUF_EN
        MBEDTLS WOLFSSL OPENSSL JWT_EN
        ATCACERT_COMPCERT_EN ATCACERT_FULLSTOREDCERT_EN
        TNGTLS_SUPPORT TNGLORA_SUPPORT TFLEX_SUPPORT TNG_LEGACY_SUPPORT
        WPC_SUPPORT
        ATCAC_SHA384_EN ATCAC_SHA512_EN
        PKCS11
        ATSHA204A_SUPPORT ATSHA206A_SUPPORT ATECC108A_SUPPORT ATECC508A_SUPPORT
        ATECC608_SUPPORT ECC204_SUPPORT TA010_SUPPORT SHA104_SUPPORT SHA105_SUPPORT
    )

    foreach(opt IN LISTS _opts)
        # Construct Kconfig var name, e.g. CONFIG_ATCA_HAL_I2C
        set(_kconfig_var CONFIG_ATCA_${opt})
        if(DEFINED ${_kconfig_var})
            # Read its boolean value (y/n) into a CMake boolean
            if(${_kconfig_var})
                set(ATCA_${opt} ON CACHE BOOL "Auto-set from Kconfig (${_kconfig_var})" FORCE)
            else()
                set(ATCA_${opt} OFF CACHE BOOL "Auto-clear from Kconfig (${_kconfig_var})" FORCE)
            endif()
        endif()
    endforeach()
endif()
