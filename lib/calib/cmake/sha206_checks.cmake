# Device enablement
option(ATCA_ATSHA206A_SUPPORT "Include support for ATSHA206A device" ON)

# Device support checks
if(ATCA_ATSHA206A_SUPPORT)
message(STATUS "Adding ATSHA206A Device Support")
set(SHA206_ENABLED ON PARENT_SCOPE)
set(ATCA_CA_SUPPORT ON)
endif()