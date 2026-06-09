# Device enablement
option(ATCA_TA010_SUPPORT "Include support for TA010 device" ON)

# Device support checks
if(ATCA_TA010_SUPPORT)
message(STATUS "Adding TA010 Device Support")
set(TA010_ENABLED ON PARENT_SCOPE)
set(ATCA_CA_SUPPORT ON)
endif()