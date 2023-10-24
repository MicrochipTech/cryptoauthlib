cmake_minimum_required(VERSION 3.10)
project (cryptoauth_test C)

option (ATCA_TEST_LOCK_ENABLE "Enable device locking functions and tests" OFF)
option (ATCA_TEST_DELETE_ENABLE "Enable device wiping functions and tests" OFF)

file(GLOB TEST_ATCACERT_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "atcacert/*.c")
file(GLOB TEST_JWT_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "jwt/*.c")
file(GLOB TEST_TNG_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "tng/*.c")
file(GLOB TEST_WPC_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "wpc/*.c")
file(GLOB TEST_API_ATCAB RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "api_atcab/*.c")
file(GLOB TEST_API_CALIB RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "api_calib/*.c")
file(GLOB TEST_API_CRYPTO RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "api_crypto/*.c")
file(GLOB TEST_API_TALIB RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "api_talib/*.c")
file(GLOB TEST_VECTORS_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "vectors/*.c")
file(GLOB TEST_INTEGRATION_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "integration/*.c")
file(GLOB TEST_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.c")
file(GLOB UNITY_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "../third_party/unity/*.c")

set(CRYPTOAUTH_TEST_SRC ${TEST_SRC} 
                        ${TEST_TNG_SRC}
                        ${TEST_JWT_SRC}
                        ${TEST_ATCACERT_SRC}
                        ${TEST_API_ATCAB}
                        ${TEST_API_CALIB}
                        ${TEST_API_CRYPTO}
                        ${TEST_VECTORS_SRC})

if(ATCA_TA100_SUPPORT)
set(CRYPTOAUTH_TEST_SRC ${CRYPTOAUTH_TEST_SRC} ${TEST_API_TALIB})
endif(ATCA_TA100_SUPPORT)

if(ATCA_WPC_SUPPORT)
set(CRYPTOAUTH_TEST_SRC ${CRYPTOAUTH_TEST_SRC} ${TEST_WPC_SRC})
endif(ATCA_WPC_SUPPORT)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${CRYPTOAUTH_TEST_SRC})
source_group("Unity" FILES ${UNITY_SRC})

if(TEST_CUSTOM_CMD_SRC)
list(REMOVE_ITEM CRYPTOAUTH_TEST_SRC cmd-processor.c)
set(CRYPTOAUTH_TEST_SRC ${CRYPTOAUTH_TEST_SRC} ${TEST_CUSTOM_CMD_SRC})
source_group("External Files" FILES ${TEST_CUSTOM_CMD_SRC})
endif()

if(ATCA_MBEDTLS)
set(CRYPTOAUTH_TEST_SRC ${CRYPTOAUTH_TEST_SRC} ${TEST_INTEGRATION_SRC})
endif()

add_executable(cryptoauth_test ${CRYPTOAUTH_TEST_SRC} ${UNITY_SRC})

include_directories(cryptoauth_test ${CMAKE_CURRENT_SOURCE_DIR}
                                    ${CMAKE_BINARY_DIR}/downloaded
                                    ${CMAKE_BINARY_DIR}/downloaded/wolfssl
                                    ${CMAKE_BINARY_DIR}/downloaded/mbedtls/include
                                    ${CMAKE_CURRENT_SOURCE_DIR}/../
                                    ${CMAKE_CURRENT_SOURCE_DIR}/api_atcab
                                    ${CMAKE_CURRENT_SOURCE_DIR}/api_calib
                                    ${CMAKE_CURRENT_SOURCE_DIR}/api_crypto
                                    ${CMAKE_CURRENT_SOURCE_DIR}/api_talib
                                    ${CMAKE_CURRENT_SOURCE_DIR}/integration
                                    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
                                    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party
                                    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/mbedtls/include
                                    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/wolfssl
                                    ${CMAKE_CURRENT_BINARY_DIR}/../lib)

target_link_libraries(cryptoauth_test cryptoauth)

if(UNIX)
target_link_libraries(cryptoauth_test pthread)
endif()

if(NOT MSVC)
target_compile_options(cryptoauth_test PRIVATE -ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=./test
                                                   -fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=./test)
target_compile_options(cryptoauth_test PRIVATE -Wall -Wextra)
endif()

if(ATCA_STRICT_C99)
set_property(TARGET cryptoauth_test PROPERTY C_STANDARD 99)
if(NOT MSVC)
target_compile_options(cryptoauth_test PRIVATE -Wpedantic)
endif()
endif()

if(ATCA_BUILD_SHARED_LIBS)
target_compile_definitions(cryptoauth_test PUBLIC -DATCA_BUILD_SHARED_LIBS)
endif(ATCA_BUILD_SHARED_LIBS)

if(ATCA_TEST_LOCK_ENABLE)
target_compile_definitions(cryptoauth_test PUBLIC -DATCA_TEST_LOCK_ENABLE)
endif(ATCA_TEST_LOCK_ENABLE)

if(ATCA_TEST_DELETE_ENABLE)
target_compile_definitions(cryptoauth_test PUBLIC -DATCA_TEST_DELETE_ENABLE)
endif(ATCA_TEST_DELETE_ENABLE)

set_property(TARGET cryptoauth_test PROPERTY VS_DEBUGGER_WORKING_DIRECTORY "$(OutputPath)")

add_custom_command(TARGET cryptoauth_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_SOURCE_DIR}/vectors/sha-byte-test-vectors
                $<TARGET_FILE_DIR:${PROJECT_NAME}>/sha-byte-test-vectors )

add_custom_command(TARGET cryptoauth_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_SOURCE_DIR}/vectors/aes_cmac_vectors
                $<TARGET_FILE_DIR:${PROJECT_NAME}>/aes_cmac_vectors )

add_custom_command(TARGET cryptoauth_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_SOURCE_DIR}/vectors/aes_gcm_cavp_vectors
                $<TARGET_FILE_DIR:${PROJECT_NAME}>/aes_gcm_cavp_vectors )

add_custom_command(TARGET cryptoauth_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_SOURCE_DIR}/vectors/hmac_test_vectors
                $<TARGET_FILE_DIR:${PROJECT_NAME}>/hmac_test_vectors )
