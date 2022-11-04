
# Installation
if(ATCA_PKCS11)

# Set up a default configuration file to install
configure_file(${PROJECT_SOURCE_DIR}/app/pkcs11/cryptoauthlib.conf.in ${PROJECT_BINARY_DIR}/${DEFAULT_CONF_FILE_NAME})

install(DIRECTORY DESTINATION ${DEFAULT_CONF_PATH})
install(CODE "
        if(NOT EXISTS ${DEFAULT_CONF_PATH}/${DEFAULT_CONF_FILE_NAME})
            file(INSTALL ${PROJECT_BINARY_DIR}/${DEFAULT_CONF_FILE_NAME}
                 DESTINATION ${DEFAULT_CONF_PATH})
        endif()
        ")
install(DIRECTORY DESTINATION ${DEFAULT_STORE_PATH}
        DIRECTORY_PERMISSIONS
          OWNER_EXECUTE OWNER_WRITE OWNER_READ
          GROUP_EXECUTE GROUP_WRITE GROUP_READ
          WORLD_EXECUTE WORLD_WRITE WORLD_READ
        )
install(CODE "
        if(NOT EXISTS ${DEFAULT_STORE_PATH}/slot.conf.tmpl)
            file(INSTALL ${PROJECT_SOURCE_DIR}/app/pkcs11/slot.conf.tmpl
                 DESTINATION ${DEFAULT_STORE_PATH})
        endif()
        ")
endif()
