cmake_minimum_required(VERSION 3.20.0)

# Option to enable Zephyr support
option(ATCA_ZEPHYR_SUPPORT "Enable Zephyr HAL support and build as a Zephyr library" OFF)

project (cryptoauthlib C)

# Set the current release version
set(VERSION "3.7.8")
set(VERSION_MAJOR 3)
set(VERSION_MINOR 7)
set(VERSION_PATCH 8)

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

if (NOT Zephyr_FOUND AND ATCA_ZEPHYR_SUPPORT)
    find_package(Zephyr QUIET HINTS $ENV{ZEPHYR_BASE})
endif()    
    
if (Zephyr_FOUND)
    set(ATCA_ZEPHYR_SUPPORT ON CACHE BOOL "Auto-enable Zephyr support when Zephyr toolchain detected" FORCE)
    include_directories(${ZEPHYR_INCLUDE_DIRS})
    include(cmake/zephyr_options.cmake)
else()
    # If Zephyr support is requested but not found, we can still proceed with the build
    message(STATUS "Zephyr support requested but not found, proceeding without Zephyr")
    set(ATCA_ZEPHYR_SUPPORT OFF CACHE BOOL "Zephyr support not found" FORCE)    
endif()

add_subdirectory(lib)

# Make sure when testing that everything goes where it should
if(BUILD_TESTS)
    set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

# Tests
if(BUILD_TESTS)
    add_subdirectory(test)
    set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT cryptoauth_test)
endif(BUILD_TESTS)

# If we're installing the library then we'll add the global configuration files
if(SETUP_INSTALLER)
    include(cmake/config_install.cmake)
endif()
