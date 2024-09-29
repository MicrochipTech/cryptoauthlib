# Helper Cmake file to properly set up wolfssl integration

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../third_party/CMakeLists-wolfssl.txt.in ${CMAKE_BINARY_DIR}/wolfssl_downloader/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/wolfssl_downloader/)
execute_process(COMMAND ${CMAKE_COMMAND} --build .
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/wolfssl_downloader/)

#file(GLOB WOLFSSL_LIB_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "../third_party/wolfssl/wolfcrypt/src/*.c" "../third_party/wolfssl/src/*.c")

set(WOLFSSL_LIB_SRC ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/aes.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/arc4.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/asn.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/cmac.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/coding.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/des3.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/dsa.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/ecc.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/hash.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/hmac.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/integer.c
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/kdf.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/memory.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/pwdbased.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/random.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/rsa.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/sha.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/sha256.c
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/sha512.c
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/sp_int.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/tfm.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/wc_encrypt.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/wc_port.c
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/wolfmath.c
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/pkcs12.c 
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/logging.c  
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/wolfcrypt/src/md4.c  
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/src/tls.c 
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/src/internal.c 
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/src/wolfio.c 
				${CMAKE_BINARY_DIR}/downloaded/wolfssl/src/keys.c 
                ${CMAKE_BINARY_DIR}/downloaded/wolfssl/src/ssl.c 
                    )


add_library(wolfssl STATIC ${WOLFSSL_LIB_SRC})
target_compile_definitions(wolfssl PRIVATE -DWOLFSSL_USER_SETTINGS)
configure_file(../third_party/wolfssl_settings.h.in user_settings.h @ONLY)
set(WOLFSSL_USER_SETTINGS TRUE)

if(NOT MSVC)
target_compile_options(wolfssl PRIVATE -fPIC)
endif()

include_directories(wolfssl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                    ${CMAKE_BINARY_DIR}/downloaded/wolfssl
                                    ${CMAKE_CURRENT_BINARY_DIR})


file(GLOB WOLFSSL_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "wolfssl/*.c")
if(${CMAKE_VERSION} VERSION_GREATER "3.8.0")
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${WOLFSSL_SRC})
endif()
