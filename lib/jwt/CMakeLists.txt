cmake_minimum_required(VERSION 3.10.0)
project(jwtsupport C)

if(ATCA_JWT_EN)
    file(GLOB JWT_SRC "*.c")
    file(GLOB JWT_INC "*.h")

    # Compile directly with the rest of the sources
    target_sources(cryptoauth PRIVATE ${JWT_SRC})

    if(DEFAULT_INC_PATH)
        install(FILES ${JWT_INC} DESTINATION ${DEFAULT_INC_PATH}/jwt COMPONENT Development)
    endif()

endif()
