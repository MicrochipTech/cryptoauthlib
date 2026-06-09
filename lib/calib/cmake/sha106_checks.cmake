# Device support checks
if(ATCA_SHA106_SUPPORT)
message(STATUS "Adding SHA106 Device Support")
set(SHA106_ENABLED ON PARENT_SCOPE)
set(ATCA_CA_SUPPORT ON)
endif()