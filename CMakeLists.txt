cmake_minimum_required(VERSION 3.1.0)
project (cryptoauthlib C)

# Set the current release version
set(VERSION "3.7.0")
set(VERSION_MAJOR 3)
set(VERSION_MINOR 7)
set(VERSION_PATCH 0)

# Build Options
option(BUILD_TESTS "Create Test Application with library" OFF)

if(UNIX)
option(SETUP_INSTALLER "Setup installation and packaging as well" ON)
else()
set(SETUP_INSTALLER OFF CACHE INTERNAL "Disabling installation on this platform")
endif()

# Default install root which is normally /usr/local/
set(CMAKE_INSTALL_PREFIX "/" CACHE INTERNAL "")

# If including certificate definitions into the library then include them as ATCACERT_DEF_SRC
#file(GLOB ATCACERT_DEF_SRC ABSOLUTE "app/*.c")

include(cmake/check_environment.cmake)

# Make sure when testing that everything goes where it should
if(BUILD_TESTS)
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

add_subdirectory(lib)

# Tests
if(BUILD_TESTS)
add_subdirectory(test)
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT cryptoauth_test)
endif(BUILD_TESTS)

# If we're installing the library then we'll add the global configuration files
if(SETUP_INSTALLER)
include(cmake/config_install.cmake)
endif()
