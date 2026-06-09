# Device enablement
option(ATCA_ECC206_SUPPORT "Include support for ECC206 device" ON)

# Device support checks
if(ATCA_ECC206_SUPPORT)
message(STATUS "Adding ECC206 Device Support")
set(ECC206_ENABLED ON PARENT_SCOPE)
set(ATCA_CA2_SUPPORT ON)
endif()
