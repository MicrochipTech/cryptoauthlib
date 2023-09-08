Cryptoauthlib Test Application
===============================================================================

The test application for cryptoauthlib provides tests and utilities for the
library and connected devices. It can be built and used both as an interactive
application or by individual command lines.

Platforms supported by CMake
-------------------------------------------------------------------------------
The test application can be configured for the following platforms by invoking
CMake:

* Windows
* Linux
* MacOs
* Zephyr

Enable the BUILD_TESTS option either in your CMakeLists.txt file that includes
cryptoauthlib or otherwise on the command line when you invoke CMake

Embedded Platforms
-------------------------------------------------------------------------------
The test application can also be added and configured if you use the following
software platforms:

### Harmony 3

Add the cryptoauthlib test application component to the component graph. The
test application depends on stdio being available so you also need to include
the stdio component which you will connect to an available uart.


Invoking the test application
-------------------------------------------------------------------------------

The test application can be run both as a command line application as well as
interactively. The default mode is interactive. 

### Embedded

#### Interactive
The function `atca_test_task` is a non returning function that waits for
characters from a stdin implementation. If the system supports scanf this can
be used to create a test application rtos task - if there are no parallel tasks
to be executed in the system then one can forgo an RTOS and simply call this
function from the main function after board initialization is complete

#### Either interactive or "command line" using a custom runner
Alternatively the function `processCmd` will accept a buffer for parsing and
execution. The buffer has to be a complete command however so ensure that the
calling code properly accumulates all need characters into the buffer first

### Platforms with a shell

#### Interactive

Launch the `cryptoauth_test` application from the build directory

#### Command line

Launch the `cryptoauth_test` application with command line arguments

```
build> ./cryptoauth_test <command> -d <device> -i <interface> [<interface options>] 
```

For example to retrieve the device serial number from a [Cryptoauth Trust Platform Development Kit](https://www.microchip.com/en-us/development-tool/DM320118)

```
./cryptoauth_test sernum -d ecc608 -i hid i2c -a 0x6C
```

Commands
-------------------------------------------------------------------------------

### Device Selection
* sha204 - Select ATSHA204/A
* sha206 - Select ATSHA206A
* ecc108 - Select ATECC108A
* ecc204 - Select ECC204
* ta010  - Select TA010
* sha104 - Select SHA104
* sha105 - Select SHA105
* ecc508 - Select ATECC508A
* ecc608 - Select ATECC608A/B
* ta100  - Select TA100

### Utilities
* info - Read the device revision data
* sernum - Read the device serial number
* readcfg - Read the configuration memory
* lockstat - Read the lock status for each memory region
* rand - Generate 32 bytes of random data from the device's RNG by executing
    atcab_random (many devices return a constant value if the configuration is 
    not 'locked')
* lockcfg - Sets the device configuration lock by executing atcab_lock_config_zone
* lockdata - Sets the device data/setup lock by executing atcab_lock_data_zone

### Software API Testing
* cd - Run the compressed certificate library (atcacert_) unit tests
* util - Run utility unit tests

### Device API Testing
* basic - Run (atcab_) API validation tests
* cio - Run compressed certificate library (atcacert_) device integration tests

### Cryptographic Library
* crypto - Run software library API tests (validate host cryptographic functions) 
* crypto_int - Run device integration tests for supported libraries
* pbkdf2 - Run pbkdf2 algorithm tests (host and device)

### ECC608 Specific Commands
* clkdivm0 - Sets the ECC608 clock divider to 0x00
* clkdivm1 - Sets the ECC608 clock divider to 0x05
* clkdivm2 - Sets the ECC608 clock divider to 0x0D

### TA100 Specific Commands
* handles - Prints the ta100 handle information for all created handles
* talib - Run (talib_) API validation tests


Options
-------------------------------------------------------------------------------

### -d (Device)

Usage: `-d <device_type>`

Selects the device type - per the device list that you would otherwise see when
invoking `help` from the menu. Possible options if the corresponding `ATCA_<device>_SUPPORT`
macro is enabled:

* sha204
* sha206
* ecc108
* ecc204
* ta010
* sha104
* sha105
* ecc508
* ecc608
* ta100


### -i (Interface)

Usage: `-i <interface_type> <interface parameters>`

Selects the interface type that will be used to communicate with the device.
Additional parameters can be used to alter the defaults for the interface

* hid <i2c/swi/spi> <i2c_bus_id>
* i2c <i2c_bus_id>
* spi <spi_bus_id> <select_pin> <baud_rate>
* uart <uart_port> <uart_baud> <uart_wordsize> <uart_stopbits> <uart_parity>

Notes:
* Uart port is an integer on windows platforms (specify 11 for COM11) and a
  string on linux/macos platforms (e.g. "/dev/ttyACM0")

### -a (Address)

Usage: `-a <device_address>`

### -y (Quiet)

Usage: `-y`

Silence prompts with an implicit agreement
