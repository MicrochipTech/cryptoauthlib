# Device enablement
option(ATCA_ATECC108A_SUPPORT "Include support for ATECC108A device" ON)

# Device support checks
if(ATCA_ATECC108A_SUPPORT)
message(STATUS "Adding ATECC108A Device Support")
set(ECC108_ENABLED ON PARENT_SCOPE)
set(ATCA_CA_SUPPORT ON)
endif()