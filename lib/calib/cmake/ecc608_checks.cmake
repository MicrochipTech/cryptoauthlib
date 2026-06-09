# Device enablement
option(ATCA_ATECC608_SUPPORT "Include support for ATECC608 device" ON)

# Device support checks
if(ATCA_ATECC608_SUPPORT)
message(STATUS "Adding ATECC608 Device Support")
set(ECC608_ENABLED ON PARENT_SCOPE)
set(ATCA_CA_SUPPORT ON)
endif()