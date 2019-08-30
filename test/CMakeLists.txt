cmake_minimum_required(VERSION 2.6.4)
project (cryptoauth_test)

file(GLOB TEST_ATCACERT_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "atcacert/*.c")
file(GLOB TEST_JWT_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "jwt/*.c")
file(GLOB TEST_TNG_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "tng/*.c")
file(GLOB TEST_SRC RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.c")

if(ATCA_HAL_KIT_HID)
add_definitions(-DATCA_HAL_KIT_HID)
endif(ATCA_HAL_KIT_HID)

if(ATCA_HAL_KIT_CDC)
add_definitions(-DATCA_HAL_KIT_CDC)
endif(ATCA_HAL_KIT_CDC)

if(ATCA_HAL_I2C)
add_definitions(-DATCA_HAL_I2C)
endif(ATCA_HAL_I2C)

if(ATCA_HAL_CUSTOM)
add_definitions(-DATCA_HAL_CUSTOM)
endif()

add_executable(cryptoauth_test ${TEST_SRC} ${TEST_TNG_SRC} ${TEST_JWT_SRC} ${TEST_ATCACERT_SRC})

include_directories(cryptoauth_test ${CMAKE_CURRENT_SOURCE_DIR}/../ ${CMAKE_CURRENT_SOURCE_DIR}/../lib)

target_link_libraries(cryptoauth_test cryptoauth)

if(UNIX)
target_link_libraries(cryptoauth_test pthread)
endif()
