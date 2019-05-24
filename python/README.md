# Python CryptoAuthLib module

## Introduction
This module provides a thin python ctypes layer to evaluate the cryptoauthlib
interface to Microchip CryptoAuthentication devices.

### Code Examples
Code examples for python are available on github as part of
[CryptoAuthTools](https://github.com/MicrochipTech/cryptoauthtools)
under the [python/examples](https://github.com/MicrochipTech/cryptoauthtools/tree/master/python/examples)
directory


## Installation
### CryptoAuthLib python module can be installed through Python's pip tool:
```
    pip install cryptoauthlib
```

### To upgrade your installation when new releases are made:
```
    pip install -U cryptoauthlib
```
 
### If you ever need to remove your installation:
```
    pip uninstall cryptoauthlib
```

## What does python CryptoAuthLib package do?
CryptoAuthLib module gives access to most functions available as part of standard cryptoauthlib
(which is written in 'C'). These python functions for the most part are very similar to 'C'
functions. The module in short acts as a wrapper over the 'C' cryptoauth library functions.

Microchip cryptoauthlib product page: 
[Link]( http://www.microchip.com/SWLibraryWeb/product.aspx?product=CryptoAuthLib)

## Supported hardware
- [AT88CK101](http://www.microchip.com/DevelopmentTools/ProductDetails/AT88CK101SK-MAH-XPRO)
- [CryptoAuthentication SOIC XPRO Starter Kit (DM320109)](https://www.microchip.com/developmenttools/ProductDetails/DM320109)

## Supported devices
The family of devices supported currently are:

- [ATSHA204A](http://www.microchip.com/ATSHA204A)
- [ATECC108A](http://www.microchip.com/ATECC108A)
- [ATECC508A](http://www.microchip.com/ATECC508A)
- [ATECC608A](http://www.microchip.com/ATECC608A)


## Using cryptoauthlib python module
The following is a 'C' code made using cryptoauthlib 'C' library.

```C
#include "cryptoauthlib.h"

void main()
{
    ATCA_STATUS status;
    uint8_t revision[4];
    uint8_t randomnum[32];

    status = atcab_init(cfg_ateccx08a_kitcdc_default);
    if (status != ATCA_SUCCESS)
    {
        printf("Error");
        exit();
    }

    status = atcab_info(revision);
    if (status != ATCA_SUCCESS)
    {
        printf("Error");
        exit();
    }

    status = atcab_random(randomnum);
    if (status != ATCA_SUCCESS)
    {
        printf("Error");
        exit();
    }
}
```
    
The same code in python would be:

```python
from cryptoauthlib import *

ATCA_SUCCESS = 0x00
revision = bytearray(4)
randomnum = bytearray(32)

# Locate and load the compiled library
load_cryptoauthlib()

assert ATCA_SUCCESS == atcab_init(cfg_ateccx08a_kithid_default())

assert ATCA_SUCCESS == atcab_info(revision)
print(''.join(['%02X ' % x for x in revision]))

assert ATCA_SUCCESS == atcab_random(randomnum)
print(''.join(['%02X ' % x for x in randomnum]))
```

In the above python code, "import cryptoauthlib" imports the python module. load_cryptoauthlib()
function loads the ompiled library. The load_cryptoauthlib() is a function that you will not
see in the 'C' library, this is a python specific utility function and is required for python
scripts to locate and load the compiled library.


## In Summary

### Step I: Import the module
```
from cryptoauthlib import *
```

### Step II: Initilize the module
```
load_cryptoauthlib()

assert ATCA_SUCCESS == atcab_init(cfg_ateccx08a_kithid_default())
```

### Step III: Use Cryptoauthlib APIs
Call library APIs of your choice


## Code portability

Microchip's CryptoAuthentication products can now be evaluated with the power and flexibility of
python. Once the evaluation stage is done the python code can be ported to 'C' code.

As seen above the python API maintains a 1 to 1 equivalence to the 'C' API in order to easy the
transition between the two.


## Cryptoauthlib module API documentation

### help() command

All of the python function's documentation can be viewed through python's built in help() function.

For example, to get the documentation of atcab_info() function:

```
    >>> help(cryptoauthlib.atcab_info)
    Help on function atcab_info in module cryptoauthlib.atcab:

    atcab_info(revision)
    Used to get the device revision number. (DevRev)

    Args:
        revision            4-byte bytearray receiving the revision number
                            from the device. (Expects bytearray)

    Returns:
        Status code
```

### dir() command

The dir command without arguments, return the list of names in the current local scope. With an
argument, attempt to return a list of valid attributes for that object. For example
dir(cryptoauthlib) will return all the methods available in the cryptoauthlib module.

## Code Examples
Code examples for python are available on github as part of 
[CryptoAuthTools](https://github.com/MicrochipTech/cryptoauthtools/tree/master/python/examples) under the
python/examples directory

## Tests
Module tests can be located in the [python/tests](https://github.com/MicrochipTech/cryptoauthlib/tree/master/python/tests)
of the main cryptoauthlib repository. The [README.md](https://github.com/MicrochipTech/cryptoauthlib/tree/master/python/tests/README.md)
has details for how to run the tests. The module tests are not comprehensive for the entire functionality
of cryptoauthlib but rather are meant to test the python module code only against the library to ensure
the interfaces are correct and ctypes structures match the platform.

