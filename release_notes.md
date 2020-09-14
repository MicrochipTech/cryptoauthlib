
# Microchip Cryptoauthlib Release Notes

## Release v3.2.3 (09/12/2020)

### New features
  - Additional TA100 command support (requires NDA, consult with your FAE or 
    submit a request through your myMicrochip account)

### Fixes
  - Security patch for USB HALs. Removed deprecated HALs and removed enumeration
    from the hidapi HAL.
  - Fix device matching logic to support older kits when using "auto detect"
    settings in the interface configuration
  - Fix SPI HAL generation errors for SAMG55 & SAM71 (flexcom) devices
  - Added a timeout for Harmony I2C calls to prevent infinite loops on peripheral
    failures. If a loop exists inside the peripheral library then it may still
    cause processor spins until a watchdog reset.

## Release v3.2.2 (07/28/2020)

### New Features
  - ATECC608B support added

### Fixes
  - Consistent null pointer checks between calib & talib apis. Tracing enabled
    for most all status changes
  - Fix for pkcs11 ecdh with the legacy slot write mode and encrypted read to
    pull the read key id from the correct slot (private key slot | 0x01)
  - call the proper api from atcab_init_ext so it works with device structures
    that are not the global instance


## Release v3.2.1 (06/29/2020)

### Fixes
  - PKCS11 configuration option to set token label to the device serial number
  - Fix OSX CLANG macro error
  - Add missing c++ wrapper macros to calib_basic.h
  - Ensure atcab_init_ext calls atcab_release_ext rather than atcab_release


## Release v3.2.0 (06/10/2020)

### New features
  - TA100 device support (requires NDA, consult with your FAE or submit a
    request through your myMicrochip account)
  - Extension of the existing API to support device context retention to allow
    multiple independent contexts to be maintained. The application still needs
    to ensure concurrency protections are used in the application to guard bus
    communication.
  - PKCS11 support has been moved into the main library and will be maintained
    together.
  - TNG/TFLEX support has been added to PKCS11 so enabling a TNG part in pkcs11
    can be done by specifying the part number: `device = ATECC608A-TNGTLS`
  - Several cryptographic library integrations have been added to enable
    additional host/mcu side functionality. This includes replacing cryptoauthlib
    software implementations of sha1 & sha256 with your preferred library. For
    example using WolfSSL in Harmony 3 will also enable hardware acceleration of
    those cryptographic functions. Cryptographic libraries enabled: WolfSSL,
    mbedTLS, & OpenSSL
  - Changes to atcacert ("compressed" certificate processing) to enable exact
    certificate size retrival which will help with some use cases that had issues
    with the max possible size answers.
  - Consolidation of HALs into device families rather than exact processor model
    This should reduce the amount of effort required to port the library to a
    specific platform if the framework is one that is already known.

### Known issues
  - Power modes/states for the TA100 are not automatically controlled by the
    library so the application has to manually change the power state when
    lower power modes are required. A command such as the info command will
    wake the TA100 from sleep but will produce an error. Try another command
    after the specified time to ensure communication is restored. This behavior
    is detailed in the datasheet.
  - Several TA100 commands and features are planned for the next released
    of the library such as import/export, transfer, and devupdate.

## Release v3.1.1 (03/06/2020)
  - Update Trust Flex certificates. Add compile time options to reduce code 
    space by selectively including the trust certificates that are required
  - Python updates: add sha206 apis. Fix atcab_kdf parameters
  - Fix compiler warnings in test application files and sha206 api

## Release v3.1.0 (02/05/2020)
  - The library is now semantic versioned along with the legacy date versioning.
    Python will continue to be released with the date version. Version APIs have
    been updated.
  - Configuration is done via a configuration file atca_config.h rather than
    global compiler options. You have to add this file to your project to support
    this version of the library. 
  - Harmony 3 support has been added. Update harmony configurator (and content
    loader) or manually clone crytoauthlib into your harmony directory.
  - Additional Compiler support has been added for IAR-ARM and ARMCC

## Release 11/22/2019
  - Patches for CVE-2019-16128 & CVE-2019-16129: Ensure reported packet length
    is valid for the packet being processed.
  - Improvement to encrypted read operations to allow supply of a host nonce
    (prevent replay of a read sequence to the host). Default API is changed
    but can be reverted by setting the option ATCA_USE_CONSTANT_HOST_NONCE
  - Added Azure compatible TNGTLS and TNGLORA certificates. Use the TNG client
    API to retrieve the proper certificate based on the device.
  - Misc Python updates (updated APIs for encrypted reads to match the C-API change)
    atcacert_cert_element_t now initializes properly 

## Release 08/30/2019
  - Added big-endian architecture support
  - Fixes to atcah_gen_dig() and atcah_nonce()

## Release 05/17/2019
  - Added support for TNG devices (cert transforms, new API)
  - atcab_write_pub_key() now works when the data zone is unlocked

## Release 03/04/2019
  - mbed TLS wrapper added
  - Minor bug fixes

## Release 01/25/2019
  - Python JWT support
  - Python configuration structures added
  - Restructure of secure boot app

## Release 01/04/2019
  - Added GCM functions
  - Split AES modes into separate files
  - Bug fix in SWI START driver

## Release 10/25/2018
  - Added basic certificate functions to the python wrapper.
  - Added Espressif ESP32 I2C driver.
  - Made generic Atmel START drivers to support most MCUs in START.
  - Added AES-CTR mode functions.
  - Python wrapper functions now return single values with AtcaReference.
  - Added mutex support to HAL and better support for freeRTOS.
  
## Release 08/17/2018
  - Better support for multiple kit protocol devices

## Release 07/25/2018
  - Clean up python wrapper

## Release 07/18/2018
  - Added ATCA_NO_HEAP define to remove use of malloc/free.
  - Moved PEM functions to their own file in atcacert.
  - Added wake retry to accomodate power on self test delay.
  - Added ca_cert_def member to atcacert_def_s so cert chains can be traversed
    as a linked list.

## Release 03/29/2018
  - Added support for response polling by default, which will make commands
    return faster (define ATCA_NO_POLL to use old delay method).
  - Removed atcatls related files as they were of limited value.
  - Test framework generates a prompt before locking test configuration.
  - Test framework puts device to sleep between tests.
  - Fixed mode parameter issue in atcah_gen_key_msg().
  - ATECC608A health test error code added.

## Release 01/15/2018
  - Added AES-128 CBC implementation using AES command
  - Added AES-128 CMAC implementation using AES command
  
## Release 11/22/2017
  - Added support for FLEXCOM6 on SAMG55 driver
  
## Release 11/17/2017
  - Added library support for the ATECC608A device
  - Added support for Counter command
  - atca_basic functions and tests now split into multiple files based on
    command
  - Added support for multiple base64 encoding rules
  - Added support for JSON Web Tokens (jwt)
  - Fixed atcab_write_enc() function to encrypt the data even when the device
    is unlocked
  - Fixed atcab_base64encode_() for the extra newline
  - Updated atcab_ecdh_enc() to work more consistently

## Release 07/01/2017
  - Removed assumption of SN[0:1]=0123, SN[8]=EE. SN now needs to be passed in
    for functions in atca_host and atca_basic functions will now read the
    config zone for the SN if needed.
  - Renamed atcab_gendig_host() to atcab_gendig() since it's not a host
    function. Removed original atcab_gendig(), which had limited scope.
  - Fixed atcah_hmac() for host side HMAC calculations. Added atcab_hmac().
  - Removed unnecessary ATCADeviceType parameters from some atca_basic
    functions.
  - Added atcacert_create_csr() to create a signed CSR.
  - New HAL implementation for Kit protocol over HID on Linux. Please see the
    Incorporating CryptoAuthLib in a Linux project using USB HID devices
    section in this file for more information.
  - Added atcacert_write_cert() for writing certificates to the device.
  - Added support for dynamic length certificate serial numbers in atcacert.
  - Added atcab_write() for lower level write commands.
  - Fixed atcah_write_auth_mac(), which had wrong OpCode.
  - Added atcab_verify() command for lower level verify commands.
  - Added atcab_verify_stored() for verifying data with a stored public key.
  - Removed atcab_write_bytes_slot(). Use atcab_write_bytes_zone() instead.
  - Modified atcab_write_bytes_zone() and atcab_read_bytes_zone() to specify a
    slot
  - Added atcab_verify_validate() and atcab_verify_invalidate()
  - Improvements to host functions to handle more cases.
  - Added atcab_updateextra(), atcab_derive_key()
  - Added support for more certificate formats.
  - Added general purpose hardware SHA256 functions. See atcab_hw_sha2_256().
  - Removed device specific config read/write. Generic now handles both.
  - Removed unnecessary response parameter from lock commands.
  - Enhanced and added unit tests.
  - Encrypted read and write functions now handle keys with SlotConfig.NoMac
    set
  - atcab_cmp_config_zone() handles all devices now.
  - Fixed some edge cases in atcab_read_bytes_zone().
  - Updated atSHA() to work with all devices.
  - Fixed atcacert_get_device_locs() when using stored sn.
  
## Release 01/08/2016
  - New HAL implementations for
    - Single Wire interface for SAMD21 / SAMR21
    - SAMV71 I2C HAL implementation
    - XMega A3Bu HAL implementation
  - Added atcab_version() method to return current version string of libary to
    application
  - New Bus and Discovery API 
    - returns a list of ATCA device configurations for each CryptoAuth device
      found
    - currently implemented on SAMD21/R21 I2C, SAMV71
    - additional discovery implementations to come
  - TLS APIs solidified and documented
  - Added missing doxygen documentation for some CryptoAuthLib methods 
  - Stubs for HAL SPI removed as they are unused for SHA204A and ECC508A
    support
  - bug fixes
  - updated atcab_sha() to accept a variable length message that is > 64 bytes
    and not a multiple of 64 bytes (the SHA block size).
  - refactored Cert I/O and Cert Data tests to be smaller
  - 'uncrustify' source formatting
  - published on GitHub

## Release 9/19/2015
  - Kit protocol over HID on Windows
  - Kit protocol over CDC on Linux
  - TLS integration with ATECC508A
  - Certificate I/O and reconstruction 
  - New SHA2 implementation
  - Major update to API docs, Doxygen files found in cryptoauthlib/docs
  - load cryptoauthlib/docs/index.html with your browser