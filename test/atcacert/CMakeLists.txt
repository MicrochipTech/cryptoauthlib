cmake_minimum_required(VERSION 3.10.0)
project(testatcacertsupport C)

if(ATCA_TEST_ATCACERT_SUPPORT)
    file(GLOB TEST_ATCACERT_SRC "*.c")
    target_sources(cryptoauth_test PRIVATE ${TEST_ATCACERT_SRC})
    target_include_directories(cryptoauth_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()
