cmake_minimum_required(VERSION 3.10.0)
project(cryptoauth C)

include(CheckSymbolExists)

# HAL Selection
option(ATCA_HAL_KIT_HID "Include the HID HAL Driver")
option(ATCA_HAL_KIT_BRIDGE "General purpose kit protocol (Packet and Stream)")
option(ATCA_HAL_I2C "Include the I2C Hal Driver - Linux & MCU only")
option(ATCA_HAL_SPI "Include the SPI HAL Driver - Linux & MCU only")
option(ATCA_HAL_CUSTOM "Include support for Custom/Plug-in Hal Driver")
option(ATCA_HAL_KIT_UART "Include the UART HAL Driver")
option(ATCA_HAL_SWI_UART "Include the SWI using UART Driver")

# Library Options
option(ATCA_PRINTF "Enable Debug print statements in library")
option(ATCA_JWT_EN "Enable jwt functionality")
option(ATCA_PKCS11 "Build PKCS11 Library")
option(ATCA_BUILD_SHARED_LIBS "Build CryptoAuthLib as shared library" ON)
option(ATCA_NO_HEAP "Do not use dynamic (heap) allocation functions" OFF)
option(ATCA_USE_ATCAB_FUNCTIONS "Build the atcab_ api functions rather than using macros" OFF)
option(ATCA_ENABLE_DEPRECATED "Enable the use of older APIs that that been replaced" OFF)
option(ATCA_STRICT_C99 "Enable strict C99 compliance for the libray" OFF)
option(MULTIPART_BUF_EN "Enable MultiPart Buffer" OFF)

# Software Cryptographic backend for host crypto abstractions
option(ATCA_MBEDTLS "Integrate with mbedtls" OFF)
option(ATCA_WOLFSSL "Integrate with WolfSSL" OFF)
option(ATCA_OPENSSL "Integration with OpenSSL" OFF)

# Trust Platform Options
option(ATCA_TNGTLS_SUPPORT "Include Trust & Go TLS Certificates")
option(ATCA_TNGLORA_SUPPORT "Include Trust & Go LORA Certificates")
option(ATCA_TFLEX_SUPPORT "Include Trust Flex Certificates")
option(ATCA_TNG_LEGACY_SUPPORT "Include previous version of Trust & Go Certificates")

# WPC Options
option(ATCA_WPC_SUPPORT "Include WPC Certificates")

# SHA Options
option(ATCAC_SHA384_EN "Include SHA384 support" OFF)
option(ATCAC_SHA512_EN "Include SHA512 support" OFF)

# Certificate Options
option(ATCACERT_COMPCERT_EN       "Include Compressed Certificate support" ON)
option(ATCACERT_FULLSTOREDCERT_EN "Include Full Certificate support" ON)

# Device enablement
option(ATCA_ATSHA204A_SUPPORT "Include support for ATSHA204A device" ON)
option(ATCA_ATSHA206A_SUPPORT "Include support for ATSHA206A device" ON)
option(ATCA_ATECC108A_SUPPORT "Include support for ATECC108A device" ON)
option(ATCA_ATECC508A_SUPPORT "Include support for ATECC508A device" ON)
option(ATCA_ATECC608_SUPPORT "Include support for ATECC608 device" ON)
option(ATCA_ECC204_SUPPORT "Include support for ECC204 device" ON)
option(ATCA_TA010_SUPPORT "Include support for TA010 device" ON)
option(ATCA_SHA104_SUPPORT "Include support for SHA104 device" ON)
option(ATCA_SHA105_SUPPORT "Include support for SHA105 device" ON)

# This does various device checks
include(cmake/devices.cmake)

# Preprocessor Warning option
if (NOT MSVC)
option(ATCA_PREPROCESSOR_WARNING "Enable preprocessor warning statements in library" OFF)
else()
SET(ATCA_PREPROCESSOR_WARNING OFF CACHE BOOL "Force the option to OFF since visual studio compiler does not support corresponding preprocessor directive" FORCE)
endif()

# RTOS Selection
if (TARGET zephyr_interface)
SET(ATCA_ZEPHYR_SUPPORT ON CACHE INTERNAL "Include zephyr hal drivers")
endif()

# Check Integration Options
if (ATCA_MBEDTLS AND (ATCA_WOLFSSL OR ATCA_OPENSSL))
message(FATAL_ERROR "Only one external SSL/TLS library can be supported")
elseif (ATCA_WOLFSSL AND (ATCA_MBEDTLS OR ATCA_OPENSSL))
message(FATAL_ERROR "Only one external SSL/TLS library can be supported")
endif()

# Full certificate integration option
if (ATCA_MBEDTLS OR ATCA_WOLFSSL OR ATCA_OPENSSL)
option(ATCACERT_INTEGRATION_EN "Enable ATCACERT full certificate integration" ON)
endif()

# Check Platform Information
check_symbol_exists(malloc "stdlib.h" HAS_MALLOC)
check_symbol_exists(free "stdlib.h" HAS_FREE)
check_symbol_exists(strcasestr "string.h" HAS_STRCASESTR)
check_symbol_exists(memset_s "string.h" HAS_MEMSET_S)

set(BUILD_SHARED_LIBS ${ATCA_BUILD_SHARED_LIBS})

# Collect Library Sources
file(GLOB LIB_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.c")
file(GLOB LIB_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.h")
file(GLOB ATCACERT_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "atcacert/*.c")
file(GLOB ATCACERT_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "atcacert/*.h")
file(GLOB CALIB_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "calib/*.c")
file(GLOB CALIB_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "calib/*.h")
file(GLOB_RECURSE CRYPTO_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "crypto/*.c")
file(GLOB CRYPTO_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "crypto/*.h")
file(GLOB CRYPTO_HASHES_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "crypto/hashes/*.h")
file(GLOB HOST_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "host/*.c")
file(GLOB HOST_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "host/*.h")
file(GLOB JWT_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "jwt/*.c")
file(GLOB JWT_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "jwt/*.h")
file(GLOB TNG_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "../app/tng/*.c")
file(GLOB TNG_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "../app/tng/*.h")
file(GLOB WPC_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "../app/wpc/*.c")
file(GLOB WPC_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "../app/wpc/*.h")
file(GLOB SHA206_API_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "../app/api_206a/*.c")
file(GLOB SHA206_API_INC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "../app/api_206a/*.h")

if(ATCA_PKCS11 AND (ATCA_TNGTLS_SUPPORT OR ATCA_TNGLORA_SUPPORT OR ATCA_TFLEX_SUPPORT))
SET(TNG_SRC ${TNG_SRC} ../app/pkcs11/trust_pkcs11_config.c)
endif()

if(${CMAKE_VERSION} VERSION_GREATER "3.8.0")
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${ATCACERT_SRC})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${CALIB_SRC})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${CRYPTO_SRC})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${HOST_SRC})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${JWT_SRC})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${PKCS11_SRC})
if(ATCA_TNGTLS_SUPPORT OR ATCA_TNGLORA_SUPPORT OR ATCA_TFLEX_SUPPORT)
source_group("App/Tng" FILES ${TNG_SRC})
endif()
source_group("App/Wpc" FILES ${WPC_SRC})
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/talib" AND IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/talib")
    # Include supporting option checks first
    include(talib/cmake/checks.cmake)
endif()

if (ATCA_MBEDTLS)
    include(cmake/mbedtls.cmake)
endif(ATCA_MBEDTLS)

if (ATCA_WOLFSSL)
    include(cmake/wolfssl.cmake)
endif(ATCA_WOLFSSL)

if (ATCA_OPENSSL)
    find_package(OpenSSL REQUIRED)
    file(GLOB OPENSSL_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "openssl/*.c")
    if(${CMAKE_VERSION} VERSION_GREATER "3.8.0")
        source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${OPENSSL_SRC})
    endif()
endif(ATCA_OPENSSL)

if (ATCA_ATSHA204A_SUPPORT OR ATCA_ATSHA206A_SUPPORT OR
    ATCA_ATECC108A_SUPPORT OR ATCA_ATECC508A_SUPPORT OR
    ATCA_ATECC608_SUPPORT OR ATCA_ECC204_SUPPORT OR ATCA_TA010_SUPPORT OR ATCA_SHA104_SUPPORT OR ATCA_SHA105_SUPPORT)
set(LIB_SRC ${LIB_SRC} ${CALIB_SRC} ${HOST_SRC})
endif()

if (ATCA_ATSHA206A_SUPPORT)
set(LIB_SRC ${LIB_SRC} ${SHA206_API_SRC})
endif()

if (ATCA_TNGTLS_SUPPORT OR ATCA_TNGLORA_SUPPORT OR ATCA_TFLEX_SUPPORT)
set(LIB_SRC ${LIB_SRC} ${TNG_SRC})
endif()

# Add the basic sources to the library
set(CRYPTOAUTH_SRC ${LIB_SRC}
                   ${ATCACERT_SRC}
                   ${CRYPTO_SRC}
                   ${JWT_SRC}
                   ${MBEDTLS_SRC}
                   ${WOLFSSL_SRC}
                   ${OPENSSL_SRC}
                   hal/atca_hal.c )

set(HAL_INC hal/atca_hal.h)

if(ATCA_HAL_KIT_HID)
set(NEED_USB true)
endif()

if(WIN32)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} hal/hal_windows.c)
set(HID_SRC ../third_party/hidapi/windows/hid.c)
elseif(APPLE)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} hal/hal_linux.c)
set(HID_SRC ../third_party/hidapi/mac/hid.c)
elseif(UNIX)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} hal/hal_linux.c)
set(TWI_SRC hal/hal_linux_i2c_userspace.c)
set(SPI_SRC hal/hal_linux_spi_userspace.c)
set(LINUX TRUE)
endif()

if(ATCA_ZEPHYR_SUPPORT)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} ../third_party/hal/zephyr/hal_zephyr.c)
SET(TWI_SRC ../third_party/hal/zephyr/hal_zephyr_i2c.c)
SET(SPI_SRC ../third_party/hal/zephyr/hal_zephyr_spi.c)
endif()

if(LINUX AND NEED_USB)
find_path(LIBUSB_INCLUDE_DIR NAMES libusb.h PATH_SUFFIXES "include" "libusb" "libusb-1.0")
find_path(LIBUDEV_INCLUDE_DIR NAMES libudev.h PATH_SUFFIXES "include")
find_library(HAS_LIBUSB usb-1.0)
find_library(HAS_LIBUDEV udev)

if(HAS_LIBUSB AND LIBUSB_INCLUDE_DIR)
set(LIBUSB_GOOD TRUE)
endif()

if(HAS_LIBUDEV AND LIBUDEV_INCLUDE_DIR)
set(LIBUDEV_GOOD TRUE)
endif()

if(LIBUDEV_GOOD)
set(USE_UDEV TRUE)
elseif(LIBUSB_GOOD)
set(USE_LIBUSB TRUE)
else()
message(FATAL_ERROR, "Missing Build Dependencies for USB - install libusb-1.0-0-dev or libudev-dev")
endif()

endif(LINUX AND NEED_USB)

if(USE_UDEV)
set(USB_INCLUDE_DIR ${LIBUDEV_INCLUDE_DIR})
set(HID_SRC ../third_party/hidapi/linux/hid.c)
endif(USE_UDEV)

if(USE_LIBUSB)
set(USB_INCLUDE_DIR ${LIBUSB_INCLUDE_DIR})
set(HID_SRC ../third_party/hidapi/libusb/hid.c)
endif(USE_LIBUSB)

if(NEED_USB OR ATCA_HAL_KIT_UART)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} hal/kit_protocol.c)
endif()

if(ATCA_HAL_KIT_HID)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} ${HID_SRC} hal/hal_all_platforms_kit_hidapi.c)
endif(ATCA_HAL_KIT_HID)

if(ATCA_HAL_KIT_UART OR ATCA_HAL_SWI_UART)
if(WIN32)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} hal/hal_windows_kit_uart.c)
elseif(LINUX OR APPLE)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} hal/hal_linux_uart_userspace.c)
endif()
endif()

if(ATCA_HAL_I2C)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} ${TWI_SRC})
endif(ATCA_HAL_I2C)

if(ATCA_HAL_SPI)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} ${SPI_SRC})
endif(ATCA_HAL_SPI)

if(ATCA_HAL_SWI_UART)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} hal/hal_swi_uart.c)
endif(ATCA_HAL_SWI_UART)

if(ATCA_HAL_KIT_BRIDGE)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} hal/hal_kit_bridge.c)
endif(ATCA_HAL_KIT_BRIDGE)

if(ATCA_WPC_SUPPORT)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} ${WPC_SRC})
endif(ATCA_WPC_SUPPORT)

# Add Remaining Sources depending on target library type
if(ATCA_MBEDTLS)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} ${MBEDTLS_SRC})
endif()

if(ATCA_PKCS11)
    if(LINUX OR ATCA_ZEPHYR_SUPPORT)
        include(cmake/pkcs11.cmake)
        set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} ${PKCS11_SRC})
        set(ATCA_LIBRARY_CONF ${DEFAULT_CONF_PATH}/${DEFAULT_CONF_FILE_NAME} CACHE STRING "" FORCE)
    else()
        message(FATAL_ERROR "PKCS11 Interface is only available for linux systems - if the target is linux check cross-compilation configuration")
    endif()
endif()

if(ATCA_BUILD_SHARED_LIBS)
add_definitions(-DATCA_BUILD_SHARED_LIBS)
set(CRYPTOAUTH_SRC ${CRYPTOAUTH_SRC} atca_utils_sizes.c)
endif(ATCA_BUILD_SHARED_LIBS)

add_library(cryptoauth ${CRYPTOAUTH_SRC} ${ATCACERT_DEF_SRC})
if (ATCA_TA_SUPPORT)
add_subdirectory(talib)
endif()

set_target_properties(cryptoauth PROPERTIES C_STANDARD 99 VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})

if(HAS_MALLOC)
set(ATCA_PLATFORM_MALLOC malloc CACHE STRING "" FORCE)
endif(HAS_MALLOC)

if(HAS_FREE)
set(ATCA_PLATFORM_FREE free CACHE STRING "" FORCE)
endif(HAS_FREE)

if(HAS_STRCASESTR)
set(ATCA_PLATFORM_STRCASESTR strcasestr CACHE STRING "" FORCE)
endif(HAS_STRCASESTR)

if(HAS_MEMSET_S)
set(ATCA_PLATFORM_MEMSET_S memset_s CACHE STRING "" FORCE)
endif(HAS_MEMSET_S)

if(BUILD_TESTS)
set(ATCA_TESTS_ENABLED ON CACHE INTERNAL "")
endif(BUILD_TESTS)

configure_file(atca_config.h.in atca_config.h @ONLY)
set(LIB_INC ${LIB_INC} ${CMAKE_CURRENT_BINARY_DIR}/atca_config.h)

include_directories(cryptoauth PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
                                      ${CMAKE_CURRENT_SOURCE_DIR}
                                      ${CMAKE_BINARY_DIR}/downloaded
                                      ../app/tng
                                      ../third_party
                                      ../third_party/hidapi/hidapi
                                      ${USB_INCLUDE_DIR})

if(ATCA_MBEDTLS)
target_link_libraries(cryptoauth mbedtls)
endif()

if(ATCA_WOLFSSL)
target_link_libraries(cryptoauth wolfssl)
endif()

if(ATCA_OPENSSL)
include_directories(cryptoauth PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(cryptoauth ${OPENSSL_CRYPTO_LIBRARY})
endif()

if(WIN32)
set_target_properties(cryptoauth PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS true)
target_link_libraries(cryptoauth setupapi.lib)
endif(WIN32)

if(APPLE)
find_library(IO_KIT_LIB IOKit)
find_library(CORE_LIB CoreFoundation)
target_link_libraries(cryptoauth ${IO_KIT_LIB} ${CORE_LIB})
endif()

if(LINUX)
add_definitions(-DATCA_USE_SHARED_MUTEX)
if(USE_LIBUSB)
target_link_libraries(cryptoauth usb-1.0)
elseif(USE_UDEV)
target_link_libraries(cryptoauth udev)
endif()
target_link_libraries(cryptoauth rt)
endif(LINUX)

if(NOT MSVC)
target_compile_options(cryptoauth PRIVATE -ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=.
                                                   -fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=.)
#target_compile_options(cryptoauth PRIVATE -Wall -Wextra -Werror)
target_compile_options(cryptoauth PRIVATE -Wall -Wextra)
endif()

if(ATCA_STRICT_C99)
set_property(TARGET cryptoauth PROPERTY C_STANDARD 99)
if(NOT MSVC)
target_compile_options(cryptoauth PRIVATE -Wpedantic)
endif()
endif()

if(NOT MSVC AND ATCA_HAL_KIT_HID)
set_source_files_properties(${HID_SRC} PROPERTIES COMPILE_FLAGS "-w")
endif()

if(DEFAULT_LIB_PATH)
if(${CMAKE_VERSION} VERSION_GREATER "3.12.0")
install(TARGETS ${PROJECT_NAME}
        LIBRARY
          DESTINATION ${DEFAULT_LIB_PATH}
          COMPONENT Libraries
          NAMELINK_COMPONENT Development)
else()
install(TARGETS ${PROJECT_NAME}
        LIBRARY
          DESTINATION ${DEFAULT_LIB_PATH}
          COMPONENT Libraries)
endif()
endif(DEFAULT_LIB_PATH)

if(DEFAULT_INC_PATH)
install(FILES ${LIB_INC} DESTINATION ${DEFAULT_INC_PATH} COMPONENT Development)
install(FILES ${HAL_INC} DESTINATION ${DEFAULT_INC_PATH}/hal COMPONENT Development)
install(FILES ${ATCACERT_INC} DESTINATION ${DEFAULT_INC_PATH}/atcacert COMPONENT Development)
install(FILES ${CALIB_INC} DESTINATION ${DEFAULT_INC_PATH}/calib COMPONENT Development)
install(FILES ${CRYPTO_INC} DESTINATION ${DEFAULT_INC_PATH}/crypto COMPONENT Development)
install(FILES ${CRYPTO_HASHES_INC} DESTINATION ${DEFAULT_INC_PATH}/crypto/hashes COMPONENT Development)
install(FILES ${HOST_INC} DESTINATION ${DEFAULT_INC_PATH}/host COMPONENT Development)
install(FILES ${JWT_INC} DESTINATION ${DEFAULT_INC_PATH}/jwt COMPONENT Development)
install(FILES ${TNG_INC} DESTINATION ${DEFAULT_INC_PATH}/app/tng COMPONENT Development)
install(FILES ${WPC_INC} DESTINATION ${DEFAULT_INC_PATH}/app/wpc COMPONENT Development)
install(FILES ${SHA206_API_INC} DESTINATION ${DEFAULT_INC_PATH}/app/api_206a COMPONENT Development)
if(ATCA_MBEDTLS)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/atca_mbedtls_interface.h DESTINATION ${DEFAULT_INC_PATH}/mbedtls COMPONENT Development)
endif(ATCA_MBEDTLS)
if(ATCA_OPENSSL)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/openssl/atca_openssl_interface.h DESTINATION ${DEFAULT_INC_PATH}/openssl COMPONENT Development)
endif(ATCA_OPENSSL)
if(ATCA_WOLFSSL)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/atca_wolfssl_interface.h DESTINATION ${DEFAULT_INC_PATH}/wolfssl COMPONENT Development)
endif(ATCA_WOLFSSL)
endif(DEFAULT_INC_PATH)
