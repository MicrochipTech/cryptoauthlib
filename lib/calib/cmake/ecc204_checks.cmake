# Device enablement
option(ATCA_ECC204_SUPPORT "Include support for ECC204 device" ON)

# Device support checks
if(ATCA_ECC204_SUPPORT)
message(STATUS "Adding ECC204 Device Support")
set(ECC204_ENABLED ON PARENT_SCOPE)
set(ATCA_CA2_SUPPORT ON)
endif()