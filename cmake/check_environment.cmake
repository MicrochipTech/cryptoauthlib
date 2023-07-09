

# RTOS Selection
if (TARGET zephyr_interface)
SET(ATCA_ZEPHYR_SUPPORT ON CACHE INTERNAL "Build is part of a zephyr project")
endif()

if(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Default build type" FORCE)
endif()

if ((UNIX AND NOT ATCA_ZEPHYR_SUPPORT) OR MINGW)
    include(GNUInstallDirs)
    include(CheckSymbolExists)

    # Check for gnu extensions
    if (NOT DEFINED _GNU_SOURCE)
        check_symbol_exists(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)
    endif()

    if(_GNU_SOURCE)
        set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
        add_definitions(-D_GNU_SOURCE)
    endif()

    # Check and configure packaging options
    set(DEFAULT_LIB_PATH "${CMAKE_INSTALL_FULL_LIBDIR}" CACHE
        STRING "The default absolute library path" FORCE)
    set(DEFAULT_INC_PATH "${CMAKE_INSTALL_FULL_INCLUDEDIR}/${PROJECT_NAME}" CACHE
        STRING "The default include install path" FORCE)
    set(DEFAULT_CONF_PATH "${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME}" CACHE
        STRING "The default location of ${PROJECT_NAME}.conf" FORCE)
    set(DEFAULT_STORE_PATH "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/${PROJECT_NAME}" CACHE
        STRING "The default location of the filestore directory" FORCE)
    set(DEFAULT_CONF_FILE_NAME "${PROJECT_NAME}.conf" CACHE 
        STRING "The default file for library configuration" FORCE)

    message(NOTICE "CMAKE_INSTALL_PREFIX is ${CMAKE_INSTALL_PREFIX}")
    message(NOTICE "DEFAULT_LIB_PATH is ${DEFAULT_LIB_PATH}")
    message(NOTICE "DEFAULT_INC_PATH is ${DEFAULT_INC_PATH}")
    message(NOTICE "DEFAULT_CONF_PATH is ${DEFAULT_CONF_PATH}")
    message(NOTICE "DEFAULT_STORE_PATH is ${DEFAULT_STORE_PATH}")
    message(NOTICE "DEFAULT_CONF_FILE_NAME is ${DEFAULT_CONF_FILE_NAME}")

    # Packaging
    set(CPACK_PACKAGE_VENDOR "Microchip Technology Inc")
    set(CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
    set(CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR})
    set(CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH})
    set(CPACK_GENERATOR "TGZ")
    set(CPACK_SOURCE_GENERATOR "TGZ")
    set(CPACK_SOURCE_IGNORE_FILES "build/*;\\.git/*")

    include(CPack)

endif()


