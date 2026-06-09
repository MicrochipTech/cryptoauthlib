set(TEST_CALIB_DEVICES_CMAKE ${CMAKE_CURRENT_SOURCE_DIR}/api_calib/cmake)

# Device support checks
if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/sha204_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/sha204_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/sha206_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/sha206_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/ecc108_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/ecc108_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/ecc508_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/ecc508_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/ecc608_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/ecc608_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/ecc204_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/ecc204_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/ecc206_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/ecc206_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/ta010_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/ta010_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/sha104_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/sha104_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/sha106_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/sha106_checks.cmake)
endif()

if(EXISTS "${TEST_CALIB_DEVICES_CMAKE}/sha105_checks.cmake")
include(${TEST_CALIB_DEVICES_CMAKE}/sha105_checks.cmake)
endif()
