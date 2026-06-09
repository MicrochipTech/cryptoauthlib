# Library Options
option(ATCA_JWT_EN "Enable jwt functionality")

# Device support checks
if(ATCA_JWT_EN)
set(ATCA_JWT_SUPPORT ON)
endif()