cmake_minimum_required(VERSION 3.10.0)
project(atcacertsupport C)

if(ATCACERT_SUPPORT)
    file(GLOB ATCACERT_SRC "*.c")
    file(GLOB ATCACERT_INC "*.h")

    # Compile directly with the rest of the sources
    target_sources(cryptoauth PRIVATE ${ATCACERT_SRC})

    if(DEFAULT_INC_PATH)
        install(FILES ${ATCACERT_INC} DESTINATION ${DEFAULT_INC_PATH}/atacert COMPONENT Development)
    endif()

endif()
