# Install script for directory: /home/georgi/CRYPTO/microchip/cryptoauthlib/lib

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "RelWithDebInfo")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Libraries" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/lib/libcryptoauth.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/lib/libcryptoauth.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/lib/libcryptoauth.so"
         RPATH "")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/lib/libcryptoauth.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/lib" TYPE SHARED_LIBRARY FILES "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/libcryptoauth.so")
  if(EXISTS "$ENV{DESTDIR}/usr/lib/libcryptoauth.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/lib/libcryptoauth.so")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/lib/libcryptoauth.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib" TYPE FILE FILES
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_basic.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_bool.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_cfgs.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_compiler.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_config.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_debug.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_device.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_devtypes.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_helpers.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_iface.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_status.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_version.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/cryptoauthlib.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11_config.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atca_config.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/hal" TYPE FILE FILES "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/hal/atca_hal.h")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/atcacert" TYPE FILE FILES
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atcacert/atcacert.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atcacert/atcacert_client.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atcacert/atcacert_date.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atcacert/atcacert_def.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atcacert/atcacert_der.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atcacert/atcacert_host_hw.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atcacert/atcacert_host_sw.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/atcacert/atcacert_pem.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/calib" TYPE FILE FILES
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/calib/calib_aes_gcm.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/calib/calib_basic.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/calib/calib_command.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/calib/calib_execution.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/crypto" TYPE FILE FILES
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/crypto/atca_crypto_hw_aes.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/crypto/atca_crypto_sw.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/crypto/atca_crypto_sw_ecdsa.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/crypto/atca_crypto_sw_rand.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/crypto/atca_crypto_sw_sha1.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/crypto/atca_crypto_sw_sha2.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/crypto/hashes" TYPE FILE FILES
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/crypto/hashes/sha1_routines.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/crypto/hashes/sha2_routines.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/host" TYPE FILE FILES "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/host/atca_host.h")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/jwt" TYPE FILE FILES "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/jwt/atca_jwt.h")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/pkcs11" TYPE FILE FILES
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/cryptoki.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_attrib.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_cert.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_debug.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_digest.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_encrypt.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_find.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_info.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_init.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_key.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_mech.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_object.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_os.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_session.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_signature.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_slot.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_token.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11_util.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11f.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11/pkcs11t.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/pkcs11_config.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/app/tng" TYPE FILE FILES
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tflxtls_cert_def_4_device.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tng_atca.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tng_atcacert_client.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tng_root_cert.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tnglora_cert_def_1_signer.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tnglora_cert_def_2_device.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tnglora_cert_def_4_device.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tngtls_cert_def_1_signer.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tngtls_cert_def_2_device.h"
    "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/tng/tngtls_cert_def_3_device.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/usr/include/cryptoauthlib/app/api_206a" TYPE FILE FILES "/home/georgi/CRYPTO/microchip/cryptoauthlib/lib/../app/api_206a/api_206a.h")
endif()

