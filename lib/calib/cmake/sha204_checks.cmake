# Device enablement
option(ATCA_ATSHA204A_SUPPORT "Include support for ATSHA204A device" ON)

# Device support checks
if(ATCA_ATSHA204A_SUPPORT)
message(STATUS "Adding ATSHA204A Device Support")
set(SHA204_ENABLED ON PARENT_SCOPE)
set(ATCA_CA_SUPPORT ON)
endif()