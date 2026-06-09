# Device enablement
option(ATCA_ATECC508A_SUPPORT "Include support for ATECC508A device" ON)

# Device support checks
if(ATCA_ATECC508A_SUPPORT)
message(STATUS "Adding ATECC508A Device Support")
set(ECC508_ENABLED ON PARENT_SCOPE)
set(ATCA_CA_SUPPORT ON)
endif()