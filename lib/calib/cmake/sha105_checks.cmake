# Device enablement
option(ATCA_SHA105_SUPPORT "Include support for SHA105 device" ON)

# Device support checks
if(ATCA_SHA105_SUPPORT)
message(STATUS "Adding SHA105 Device Support")
set(SHA105_ENABLED ON PARENT_SCOPE)
set(ATCA_CA_SUPPORT ON)
endif()