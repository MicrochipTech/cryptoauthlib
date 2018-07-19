# Python CryptoAuthLib module

## Introduction
This module provides a thin python ctypes layer to evaluate the cryptoauthlib
interface to Microchip CryptoAuthentication devices.

### Code Examples
Code examples for python are available on github as part of [CryptoAuthTools](https://github.com/MicrochipTech/cryptoauthtools/python/examples) under the python/examples directory


## Installation
### CryptoAuthLib python module can be installed through Python’s pip tool:
    pip install cryptoauthlib
### To upgrade your installation when new releases are made:
    pip install –U cryptoauthlib
### If you ever need to remove your installation:
    pip uninstall cryptoauthlib


## What does python CryptoAuthLib package do?
CryptoAuthLib module gives access to most functions available as part of standard cryptoauthlib (which is written in ‘C’). These python functions for the most part are very similar to ‘C’ functions. The module in short acts as a wrapper over the ‘C’ cryptoauth library functions.

Microchip cryptoauthlib product page: [Link]( http://www.microchip.com/SWLibraryWeb/product.aspx?product=CryptoAuthLib)

## Supported hardware
- [AT88CK101](http://www.microchip.com/DevelopmentTools/ProductDetails/AT88CK101SK-MAH-XPRO)
- [CryptoAuth-XSTK]()

## Supported devices
The family of devices supported currently are:

- [ATSHA204A](http://www.microchip.com/ATSHA204A)
- [ATECC108A](http://www.microchip.com/ATECC108A)
- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)


## Using cryptoauthlib python module
The following is a 'C' code made using cryptoauthlib 'C' library.

    #include "cryptoauthlib.h"

    void main()
    {
        ATCA_STATUS status;
        uint8_t revision[4];
        uint8_t randomnum[32];

        status = atcab_init(cfg_ateccx08a_kitcdc_default)
        if (status != ATCA_SUCCESS)
        {
            printf("Error");
        }

        status = atcab_info(revision);
        if (status != ATCA_SUCCESS)
        {
            printf("Error");
        }

        status = atcab_random(randomnum);
        if (status != ATCA_SUCCESS)
        {
            printf("Error");
        }

    }

The same code in python 3.x would be:


    from cryptoauthlib import *
    from cryptoauthlib.iface import *

    ATCA_SUCCESS = 0x00
    revision = bytearray(4)
    randomnum = bytearray(32)

    # dll/so gets loaded into ctypes here
    load_cryptoauthlib()

    status = atcab_init(cfg_ateccx08a_kitcdc_default())
    if not status == ATCA_SUCCESS:
        print("Error")

    status = atcab_info(revision)
    if not status == ATCA_SUCCESS:
        print("Error")

    status = atcab_random(randomnum)
    if not status == ATCA_SUCCESS:
        print("Error")


In the above python code, "import cryptoauthlib" imports the python module. load_cryptoauthlib() function loads the dll/so using ctypes. The load_cryptoauthlib() is a function that you will not see in the 'C' library, this is a pyhon specific function and will be used in all the python scripts that use cryptoauthlib python module.


The whole process can be summerized in three simple steps:

### Step I: Import the module
from cryptoauthlib import *
The above line can be used to import all the functions available in the python module. If you don't want to use wildcard imports you can just import the required functions.

### Step II: Initilize the module
load_cryptoauthlib() function initilizes the python crptoauthlib module.

### Step III: Using Cryptoauthlib APIs
Once Step I and Step II are done all available cryptoauthlib APIs can be accessed.


## Code portability

Microchip's CryptoAuthentication products can be evaluated very easily with the power and flexibility of python, once the evaluation stage is done the python code can be ported to 'C' code. As seen in the abouve example, other than some language related differences there will be very little functional changes between the 'C' library and python module, this helps very much with code portability.


## Cryptoauthlib module API documentation

### help() command

All of the python function's documentation can be viewed through python's built in help() function.

For example, to get the documentation of atcab_info() function:

    >>> help(cryptoauthlib.atcab_info)
    Help on function atcab_info in module cryptoauthlib.atcab:

    atcab_info(revision)
    Used to get the device revision number. (DevRev)

    Args:
        revision            4-byte bytearray receiving the revision number
                            from the device. (Expects bytearray)

    Returns:
        Status code

### dir() command

The dir command without arguments, return the list of names in the current local scope. With an argument, attempt to return a list of valid attributes for that object. For example dir(cryptoauthlib) will return all the methods available in the cryptoauthlib module.

## Code Examples
Code examples for python are available on github as part of [CryptoAuthTools](https://github.com/MicrochipTech/cryptoauthtools/python/examples) under the python/examples directory

Link for latest cryptoauthlib library:- [Cryptoauthlib](http://www.microchip.com/DevelopmentTools/ProductDetails.aspx?PartNO=CryptoAuthLib)


