# Device enablement
option(ATCA_SHA104_SUPPORT "Include support for SHA104 device" ON)

# Device support checks
if(ATCA_SHA104_SUPPORT)
message(STATUS "Adding SHA104 Device Support")
set(SHA104_ENABLED ON PARENT_SCOPE)
set(ATCA_CA_SUPPORT ON)
endif()