cmake_minimum_required(VERSION 3.10.0)
project(testcasupport C)

if(ATCA_TEST_CA_SUPPORT)
    file(GLOB TEST_API_CALIB "*.c")
    target_sources(cryptoauth_test PRIVATE ${TEST_API_CALIB})
    target_include_directories(cryptoauth_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()
