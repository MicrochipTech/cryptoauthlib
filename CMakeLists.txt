cmake_minimum_required(VERSION 2.6.4)
project (cryptoauthlib)

# Set the current release version
set(VERSION "2018.10.26")
set(VERSION_MAJOR 2028)
set(VERSION_MINOR 10)
set(VERSION_PATCH 26)

# Build Options
option(BUILD_TESTS "Create Test Application with library" OFF)
#set(ATCA_PKCS11 ON CACHE INTERNAL "")

message(STATUS "Building Configuration: ${CMAKE_BUILD_TYPE}")


if(BUILD_TESTS)
set(ATCA_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
endif(BUILD_TESTS)

add_subdirectory(lib)

# Tests
if(BUILD_TESTS)
add_subdirectory(test)
endif(BUILD_TESTS)

