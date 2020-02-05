cmake_minimum_required(VERSION 2.6.4)
project (cryptoauthlib)

# Set the current release version
set(VERSION "3.1.0")
set(VERSION_MAJOR 3)
set(VERSION_MINOR 1)
set(VERSION_PATCH 0)

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

