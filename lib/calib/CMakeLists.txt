cmake_minimum_required(VERSION 3.10.0)
project(casupport C)

if(ATCA_CA_SUPPORT)
    file(GLOB CALIB_SRC "*.c")
    file(GLOB CALIB_INC "*.h")
    file(GLOB HOST_SRC "../host/*.c")
    file(GLOB HOST_INC "../host/*.h")

    # Compile directly with the rest of the sources
    target_sources(cryptoauth PRIVATE ${CALIB_SRC})
    target_sources(cryptoauth PRIVATE ${HOST_SRC})

    if(DEFAULT_INC_PATH)
        install(FILES ${CALIB_INC} DESTINATION ${DEFAULT_INC_PATH}/calib COMPONENT Development)
        install(FILES ${HOST_INC} DESTINATION ${DEFAULT_INC_PATH}/host COMPONENT Development)
    endif()

endif()
