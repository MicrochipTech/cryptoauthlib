# Helper Cmake file to properly set up mbedtls integration

if (NOT TARGET mbedtls)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../third_party/CMakeLists-mbedtls.txt.in ${CMAKE_BINARY_DIR}/mbedtls_downloader/CMakeLists.txt)
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/mbedtls_downloader/)
execute_process(COMMAND ${CMAKE_COMMAND} --build .
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/mbedtls_downloader/)

file(GLOB MBEDTLS_LIB_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "${CMAKE_BINARY_DIR}/downloaded/mbedtls/library/*.c")

add_library(mbedtls STATIC ${MBEDTLS_LIB_SRC})

target_compile_definitions(mbedtls PUBLIC -DMBEDTLS_CMAC_C -DMBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
if(NOT MSVC)
target_compile_options(mbedtls PRIVATE -fPIC)
endif()
include_directories(mbedtls PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                    ${CMAKE_BINARY_DIR}/downloaded/mbedtls/include)
endif()

file(GLOB MBEDTLS_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "mbedtls/*.c")

if(NOT MSVC)
set_source_files_properties(mbedtls/atca_mbedtls_wrap.c PROPERTIES COMPILE_FLAGS -Wno-pedantic)
endif()

if(${CMAKE_VERSION} VERSION_GREATER "3.8.0")
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${MBEDTLS_SRC})
endif()

set(MBEDTLS_SRC ${MBEDTLS_SRC} "../third_party/atca_mbedtls_patch.c")
