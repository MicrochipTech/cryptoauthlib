
# Microchip Cryptoauthlib Release Notes

## Release v3.7.0 (09/08/2023)

### New Features
  - Added unified buffer implementation to enable multipart buffer use with APIs that
    support them.
  - See [talib/CHANGES.md] for details on talib module changes

### Fixes
  - Made `atcac` structures referencing third party libraries opaque to the user so
    installed header files are usable by applications without also including the third
    party headers.

### API Changes
  - The software crypto structures are generally no longer typedef'd so they must be 
    declared with the `struct` keyword. New typedefs were added by appending the 
    suffix `_t` which allows for the same mechanism for declaring these structure in code
    if building a standalone application (such as in embedded projects). If dynamically 
    linking with the library and using a third party crypto library one will need to use 
    the `_new` & `_free` APIs to allocate these structures for use with the `atcac` 
    interfaces.

## Release v3.6.1 (07/14/2023)

### New Features
  - Added support for PIC18 memory model with a MAX_PACKET_SIZE setting. 
  - PKCS11 Improvement to support context reservation automatically for operations that
    span multiple pkcs11 calls such as login/logout, encrypt/decrypt, etc. This prevents
    concurrent processes from interupting init-update-finish operations in PKCS11
  - Added support for data element transfers between trust anchor devices

### Fixes
  - PKCS11: resolved issues with configuration directory parsing to ensure configurations
    parse in the correct order and any extraneous files get properly rejected.
  - PKCS11: improved public key loading logic for trust anchor handles to use the most
    appropriate mechanism based on handle configuration.
  - Fixed minimal kit host implementation in support bridging to SPI by using select and
    deselect control commands

## Release v3.6.0 (04/04/2023)

### New Features
  - Compliance certified to CERT-C Level 2 & MISRA 2012. Compliance reports can be
    requested from your FAE or account manager
  - Added talib_handle helper functions to determine if a handle access type is allowed
    in the given auth session

### Fixes
  - pkcs11 public key for private keys requiring the token to be logged in will make a 
    best effort to return a value by detecting various storage methods.
  - pkcs11 encrypt/decrypt update calls return the maximum possible bytes per the selected
    algorithm.
  - pkcs7 would return the wrong padding for `length % 16 == 0`
  - hmac counter kdf method will default to digest length specified in bits

### API Changes
  - ATCA_STATUS enum is now an integer and all APIs return type ATCA_STATUS
  - atcacert API return type is now `ATCA_STATUS` rather than `int`
  - atcac_sw_sha... API return type is now `ATCA_STATUS` rather than `int`
  - _atcab_exit has been removed (includes _calib_exit and _talib_exit)
  - _gDevice has been renamed to g_atcab_device_ptr (one should be using `atcab_get_device()`)

## Release v3.5.1 (03/26/2023)

### New Features
  - Add support for SHA104, SHA105, & SHA106

## Release v3.5.0 (03/14/2023)

### New Features
  - Add support for ECC204, TA010 and framework for future devices

## Release v3.4.3 (12/23/2022)

### New Features
  - Add key load mode flags for FCE config command

### Fixes
  - WPC certificate reconstruction buffer length was too short
  - ECC204 block Read/Write did not write remaining bytes if the provided buffer was
    not padded to a 32 byte bounary
  - TA100 lock CRC was being passed with the native endianness.
  - ECC204 nonce command was missing the mode bit to emit a random number when called
    with the intention of producing random bytes


## Release v3.4.2 (12/04/2022)

### Fixes
  - PKCS11: Correct init/deinit failures from initialization mutex options. These
    would manifest as a segmentation fault on deinit, unterminated authorization
    sessions, or library already initialized return codes based on the configuration
    and inititialization data.
  - PKCS11: Added configuration option to always terminate authorization sessions on
    library initialization to work around applications that may fail to call C_CloseSession
    or C_Finalize before exiting.
  - PKCS11: Fix failures in C_DigestInit resulting from failing to check the session
    state before checking the requested digest mechanism type.
  - PKCS11: Modify how the library returns public key information based on access levels
    of the private key (generate from the private key if allowed, read from a linked public
    key, and finally return data unavailable). For the vast majority of situtations this
    prevents openssl & libp11 from crashing with segmentation faults if the user fails to
    provide a pkcs11 URI with pin value specified. These segmentation faults were confirmed
    to also exist with other PKCS11 libraries - the fundamental problem should be taken up 
    with the maintainers of openssl, libp11, and pkcs11-provider (experimental OpenSSL 
    3.0 PKCS11 support). 
  - Modified CBC update/finish APIs (added as an experimental API in v3.4.0) to match
    standard expectations of how the APIs would function. Updated algorithm tests
    to reflect this usage.
  - PKCS11: Updated encrypt/decrypt in cbc/cbcpad modes to use the updated algorithm
    implementations
  - talib full element read & write functions now account for the maximum packet size 
    based on session state.


## Release v3.4.1 (11/11/2022)

### Fixes
  - test_atcacert_build_start_signer modified to verify the structure fields since the
    structure is no longer packed
  - Python ctypes_to_bytes routine to work for all python versions
  - Pkcs11 signature rules to match section 5.2 of the specification
  - Compilation error when PKCS11 monotonic counter is enabled
  - Compiletion error when no HALs are specified during configuration
  - Align ECC204 and cryptoauth counter APIs

## Release v3.4.0 (10/27/2022)

### New Features
  - Added framework for fine grain library configuration including configuration check
    header files `<api>_config_check.h` see lib/atca_config_check.h for the top level
    header
  - Added WPC application files with reference message generation/parsing and library
    configuration file to optimize to the smallest footprint
  - TA100 read/write apis updated to segment incoming buffer into partial read/write
    operations if it exceeds the maximum supported packet size
  - Added PKCS7 padding algorithm for use with AES-CBC
  - Expose PKCS11 configuration options to CMake configuration


### Fixes
  - Improve ECC204 apis to match cryptoauthlib apis and abstract the device differences
  - Support for strict C99 compliance and clean up warnings from -Wall and pedantic levels
  - Add rsa2048 key size support to talib_rsaenc command
  - Fix for ta100 devupdate to set the proper auth session exit flags so the library will
    properly reconnect when the ta100 reboots
  - Fix ECC608 verify failure when ReqRandom bit is set for a stored public key by using
    tempkey in this situation rather than the message digest buffer. See the ECC608
    datasheet for more details of this special condition
  - Improve ta100 auth session handling of long messages by reporting the message size
    exceeds the wrapped message limit earlier in the packet creation process
  - Fixes and Improvements for PKCS11 interface based on compliance testing


## Release v3.3.3 (10/06/2021)

### New features
  - Added Zephyr support and zephyr driver api HALs for I2C & SPI. Adding cryptoauthlib
    to a zephyr project CMakeLists.txt is now possible - use subdirectory(cryptoauthlib/lib).
    One can also include the repo in the west manifest
  - Added SWI device support for linux platforms using hardware uarts
  - Added contributing guidelines and PR process documentation
  - SWI bitbang driver for harmony - supports Atmel SWI and ECC204 protocols


### Fixes
  - Wolfssl build errors when generating MHC projects containing wolfssl
  - Removed zero length aad limitation in CCM implementation
  - Changed ECC204 zone identifiers and slot types to align with cryptoauthlib
    standard forms
  - XC8/XC16 build warnings
  - Several pkcs11 fixes - token_init deadlock, null num_in for private key writes,
    fsecret key length parsing, object_create failing, etc
  - Null pointer access violation in atcab_release when using a native hal and double
    free in openssl implementation of atcac_pk_verify 


## Release v3.3.2 (06/20/2021)

### New features
  - All memory allocations now go through the hal_ platform definitions.
    In harmony these are the OSAL_ fuctions which work with any of the supported
    RTOS'.
  - Enable multiple intefaces in the Harmony 3 test project through the
    user interface.
  - Kit protocol over UART has been added. This can be paired with the
    included hosting application
  - Simple kit protocol hosting application has been added. It is available
    in app/kit_host and through Harmony 3. This is a preview release of the
    application.

### Fixes
  - Enable ATSHA206A api in the python extension
  - Made the linux i2c configuration default to 100khz so they should work
    again without having to make modifications to the baud rate field.
  - Fix pkcs11 static configuration option when used with the trust platform
    configuration file
  - Fix PKCS11 ec_point return value when pValue is null (libp11 checks the
    size in this manner before requesting it for real).
  - Fix warnings generated by missing end of file newlines.
  - Removed legacy (empty) START header references.

## Release v3.3.1 (04/23/2021)

### New features
  - Core support for kit protocol over serial ports (i.e. tty/COM ports)
  - PKCS11 support for TA100 auth sessions

### Fixes
  - Fix mbedtls integration combinations that would produce unexpected
    behavior. All variations of sign/verify _ALT now work as expected
    given a configured key (for example if a key is configured as a stored public
    and VERIFY_ALT is enabled then library will perform a stored key verify rather
    than an external public key load and verify)
  - Added mbedtls integration tests to confirm that integrations are working
    on a target platform as expected. These generally bootstrap using NIST example
    vectors before using the validated functions/algorithms to test the remaining
    integration.
  - Clean up warnings when run with very strict settings (-Wall -Wextra -pedantic -Werror)
  - Fix false wake errors when baud rate switching for I2C
  - Fix for I2C errors that could be created on the bus when there are devices
    on the bus that support general calls - this fix should also correct
    linux zero length kernel messages when enabled.
  - Fix ESP32 HAL to work with the updated HAL structure. 

## Release v3.3.0 (01/22/2021)

### API Updates
  - HAL API has been signifiantly revised to improve portability. This update
    simplies the requirements of each HAL to only the physical transport
    mechanisms. Please see the hal porting and library upgrading notes:
    https://github.com/MicrochipTech/cryptoauthlib/wiki/Upgrading-to-v3.3
  - Internal structures have been updated by removing obsolete elements and
    combining mandatory fields. This saves significant memory in both program
    and data regions.
  - Inclusive language update: all remaining legacy language elements have
    been updated. Where this impacts the external API there is the option
    ATCA_ENABLE_DEPRECATED to use the previous names.

### New features
  - ECC204 support has been added with one wire HAL support.
  - ECC204, SHA206, one wire and single wire (uart and gpio) hals have been
    added to the Harmony 3 configurator.
  - PKCS11 support for symmetric (AES & HMAC) keys has been added and enabled
    for additional mechanisms such as HMAC signing and AES encrypt/decrypt

### Fixes
  - pkcs11_token_init had several conditions that were corrected
  - fix to detect differences in i2c clock rate specifications between flexcom
    and sercom configurators in Harmony 3 and the emit the correct value for
    the cryptoauthlib interface config structure.

## Release v3.2.5 (11/30/2020)

### New features
  - TA100 ShareKey API to drive the sharekey process (requires NDA, consult 
    with your FAE or submit a request through your myMicrochip account)
  - Additional software crypto library interface functions for asymmetric
    cryptography (sign, verify, ecdh, etc)
  - XC8 & XC16 compiler support
  - AES CCM & CBC-MAC upper layer API using AES-ECB primatives

### Fixes
  - TA100 AES-GCM auth session tx packet length when command data is included
  - PKCS11 Pin length check rejecting valid pin lengths
  - aes-gcm nist vector test failed with mbedtls crypto backend due to aad
    update not being executed when aad length was zero

## Release v3.2.4 (10/17/2020)

### New features
  - Additional TA100 command support (requires NDA, consult with your FAE or 
    submit a request through your myMicrochip account)
  - Library build and install on linux now also installs the headers that
    were used to build the library including all configuration files like
    atca_config.h - customer applications building against the library will
    need to add the include/cryptoauthlib to their include search paths

### Fixes
  - Fixed errors produced when -fno-common was used during build of the library
    by resolving the variable declaration and exporting macros (tested with
    static/dynamic linkage on linux & windows platforms)
  - Added a timeout during i2c plib commands in the Harmony3 hals to prevent
    system lockups from failed peripheral transfers that don't return errors.

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
