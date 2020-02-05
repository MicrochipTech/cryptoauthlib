cmake_minimum_required(VERSION 2.6.4)
project (cryptoauth_test)

file(GLOB TEST_ATCACERT_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "atcacert/*.c")
file(GLOB TEST_JWT_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "jwt/*.c")
file(GLOB TEST_TNG_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "tng/*.c")
file(GLOB TEST_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.c")


add_executable(cryptoauth_test ${TEST_SRC} ${TEST_TNG_SRC} ${TEST_JWT_SRC} ${TEST_ATCACERT_SRC})

include_directories(cryptoauth_test ${CMAKE_CURRENT_SOURCE_DIR}/../ ${CMAKE_CURRENT_SOURCE_DIR}/../lib ${CMAKE_CURRENT_BINARY_DIR}/../lib)

target_link_libraries(cryptoauth_test cryptoauth)

if(UNIX)
target_link_libraries(cryptoauth_test pthread)
endif()
