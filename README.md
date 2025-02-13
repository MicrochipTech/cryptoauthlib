CryptoAuthLib - Microchip CryptoAuthentication Library {#mainpage}
====================================================

Introduction
------------------------
This library implements the APIs required to communicate with Microchip Security
device. The family of devices supported currently are:

|CryptoAuth                                      |CryptoAuth2                               |
|-----------------------------------------------:|:-----------------------------------------|
|[ATECC608C](https://www.microchip.com/ATECC608C)|[ECC204](https://www.microchip.com/ECC204)|
|[ATECC608B](https://www.microchip.com/ATECC608B)|[ECC206](https://www.microchip.com/ECC206)|
|[ATECC608A](http://www.microchip.com/ATECC608A) |[SHA104](https://www.microchip.com/SHA104)|
|[ATECC508A](http://www.microchip.com/ATECC508A) |[SHA105](https://www.microchip.com/SHA105)|
|[ATECC108A](http://www.microchip.com/ATECC108A) |[SHA106](https://www.microchip.com/SHA106)|
|[ATSHA204A](http://www.microchip.com/ATSHA204A) |[RNG90](https://www.microchip.com/RNG90)  |
|[ATSHA206A](https://www.microchip.com/ATSHA206A)|                                          |

The best place to start is with the [Microchip Trust Platform](https://www.microchip.com/design-centers/security-ics/trust-platform)

Online API documentation is at https://microchiptech.github.io/cryptoauthlib/

Latest software and examples can be found at:
  - https://www.microchip.com/design-centers/security-ics/trust-platform
  - http://www.microchip.com/SWLibraryWeb/product.aspx?product=CryptoAuthLib


Prerequisite hardware to run CryptoAuthLib examples:
  - [CryptoAuth Trust Platform Development Kit](https://www.microchip.com/developmenttools/ProductDetails/DM320118)

Alternatively a Microchip MCU and Adapter Board:
  - [ATSAMR21 Xplained Pro]( http://www.microchip.com/atsamr21-xpro )
    or [ATSAMD21 Xplained Pro]( http://www.microchip.com/ATSAMD21-XPRO )
  - [CryptoAuthentication SOIC Socket Board](http://www.microchip.com/developmenttools/productdetails.aspx?partno=at88ckscktsoic-xpro )
    to accept SOIC parts
  - [ATECC608B mikroBUS evaluation board](https://www.microchip.com/en-us/development-tool/DT100104)
  - [ECC204 mikroBUS evaluation board](https://www.microchip.com/en-us/development-tool/ev92r58a)
  - [SHA104/SHA105 mikroBUS evaluation board](https://www.microchip.com/en-us/development-tool/ev97m19a)
  - [TA010 mikroBUS evaluation board](https://www.microchip.com/en-us/development-tool/EV74C12A)

For most development, using socketed top-boards is preferable until your
configuration is well tested, then you can commit it to a CryptoAuth Xplained
Pro Extension, for example. Keep in mind that once you lock a device, it will
not be changeable.


Examples
-----------

  - Install the [Trust Platform Design Suite](https://www.microchip.com/en-us/products/security/trust-platform ) to access Use Case examples 
    for the different Security Solutions (ATECC608, SHA104/105, ECC204, TA010, TA100…)

Configuration
-----------
In order to properly configured the library there must be a header file in your
project named `atca_config.h` at minimum this needs to contain defines for the
hal and device types being used. Most integrations have an configuration mechanism
for generating this file. See the [atca_config.h.in](lib/atca_config.h.in) template
which is configured by CMake for Linux, MacOS, & Windows projects.

An example of the configuration:

```
/* Cryptoauthlib Configuration File */
#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

/* Include HALS */
#define ATCA_HAL_I2C

/* Included device support */
#define ATCA_ATECC608_SUPPORT

/* \brief How long to wait after an initial wake failure for the POST to
 *         complete.
 * If Power-on self test (POST) is enabled, the self test will run on waking
 * from sleep or during power-on, which delays the wake reply.
 */
#ifndef ATCA_POST_DELAY_MSEC
#define ATCA_POST_DELAY_MSEC 25
#endif

#endif // ATCA_CONFIG_H
```

There are two major compiler defines that affect the operation of the library.
  - ATCA_NO_POLL can be used to revert to a non-polling mechanism for device
    responses. Normally responses are polled for after sending a command,
    giving quicker response times. However, if ATCA_NO_POLL is defined, then
    the library will simply delay the max execution time of a command before
    reading the response.
  - ATCA_NO_HEAP can be used to remove the use of malloc/free from the main
    library. This can be helpful for smaller MCUs that don't have a heap
    implemented. If just using the basic API, then there shouldn't be any code
    changes required. The lower-level API will no longer use the new/delete
    functions and the init/release functions should be used directly.

Some specific options are available in the fully documented configuration files `lib/calib/calib_config.h`,
`atca_configuration.h`, `lib/crypto/crypto_config.h`, `lib/host/atca_host_config.h` which is also the place where features can be selected.
 We provide some configurations focused on specific use cases and the checks are enabled by default. 

Release notes
-----------
See [Release Notes](release_notes.md)


Host Device Support
---------------

CryptoAuthLib will run on a variety of platforms from small micro-controllers
to desktop host systems. See [hal readme](lib/hal/README.md)

Porting requires a time delay function of millisecond resolution (hal_delay_ms) which
can be implemented via loop, timer, or rtos sleep/wait and a communication interface.

CryptoAuthLib Architecture
----------------------------
Cryptoauthlib API documentation is at https://microchiptech.github.io/cryptoauthlib/

The library is structured to support portability to:
  - multiple hardware/microcontroller platforms
  - multiple environments including bare-metal, RTOS and Windows/Linux/MacOS
  - multiple chip communication protocols (I2C, SPI, and SWI)

All platform dependencies are contained within the HAL (hardware abstraction
layer).


Directory Structure
-----------------------
```
lib - primary library source code
lib/atcacert - certificate data and i/o methods
lib/calib - the Basic Cryptoauth API
lib/crypto - Software crypto implementations external crypto libraries support (primarily SHA1 and SHA2)
lib/hal - hardware abstraction layer code for supporting specific platforms
lib/host - support functions for common host-side calculations
lib/jwt - json web token functions
test - Integration test and examples. See test/cmd-processor.c for main() implementation.

For production code, test directories should be excluded by not compiling it
into a project, so it is up to the developer to include or not as needed.  Test
code adds significant bulk to an application - it's not intended to be included
in production code.
```

Tests
------------

There is a set of integration tests found in the test directory which will at least
partially demonstrate the use of the objects.  Some tests may depend upon a
certain device being configured in a certain way and may not work for all
devices or specific configurations of the device. See [test readme](test/README.md)

Using CryptoAuthLib (Microchip CryptoAuth Library)
===========================================

The best place to start is with the [Microchip Trust Platform](https://www.microchip.com/design-centers/security-ics/trust-platform)

Also application examples are included as part of the Harmony 3 framework and can be copied from the Harmony Content Manager
or found with the Harmony 3 Framework [Cryptoauthlib_apps](https://github.com/Microchip-MPLAB-Harmony/cryptoauthlib_apps)


Incorporating CryptoAuthLib in a Linux project using USB HID devices
-----------------------------------------
The Linux HID HAL files use the Linux udev development software package.

To install the udev development package under Ubuntu Linux, please type the
following command at the terminal window:

```bash
sudo apt-get install libudev-dev
```

This adds the udev development development software package to the Ubuntu Linux
installation.

The Linux HID HAL files also require a udev rule to be added to change the
permissions of the USB HID Devices.  Please add a new udev rule for the
Microchip CryptoAuth USB devices.

```bash
cd /etc/udev/rules.d
sudo touch mchp-cryptoauth.rules
```

Edit the mchp-cryptoauth.rules file and add the following line to the file:
```text
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2312", MODE="0666"
```
