"""
Cryptoauthlib Library Management
"""
# (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
#
# Subject to your compliance with these terms, you may use Microchip software
# and any derivatives exclusively with Microchip products. It is your
# responsibility to comply with third party license terms applicable to your
# use of third party software (including open source software) that may
# accompany Microchip software.
#
# THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
# EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
# WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
# PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
# SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
# OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
# MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
# FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
# LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
# THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
# THIS SOFTWARE.

import os.path
import ctypes
from .exceptions import LibraryLoadError

# Maps common name to the specific name used internally
ATCA_NAMES = {'i2c': 'i2c', 'hid': 'kithid', 'sha': 'sha204', 'ecc': 'eccx08'}

# Global cdll instance of the loaded compiled library
_CRYPTO_LIB = None

# List of basic ctypes by size
_CTYPES_BY_SIZE = {1: ctypes.c_uint8, 2: ctypes.c_uint16, 4:ctypes.c_uint32}

class AtcaReference:
    """
    A simple wrapper to pass an immutable type to a function for return
    """
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return self.value == other

    def __ne__(self, other):
        return self.value != other

    def __lt__(self, other):
        return self.value < other

    def __le__(self, other):
        return self.value <= other

    def __gt__(self, other):
        return self.value > other

    def __ge__(self, other):
        return self.value >= other

    def __int__(self):
        return int(self.value)

    def __str__(self):
        return str(self.value)


def load_cryptoauthlib(lib=None):
    """
    Load CryptoAauthLib into Python environment
    raise LibraryLoadError if cryptoauthlib library can't be loaded
    """
    global _CRYPTO_LIB      # pylint: disable=global-statement
    if lib is not None:
        _CRYPTO_LIB = lib
    else:
        curr_path = os.path.abspath(os.path.dirname(__file__))
        if os.path.exists(os.path.join(curr_path, "cryptoauth.dll")):
            _CRYPTO_LIB = ctypes.cdll.LoadLibrary(os.path.join(curr_path, "cryptoauth.dll"))
        elif os.path.exists(os.path.join(curr_path, "libcryptoauth.so")):
            _CRYPTO_LIB = ctypes.cdll.LoadLibrary(os.path.join(curr_path, "libcryptoauth.so"))
        elif os.path.exists(os.path.join(curr_path, "libcryptoauth.dylib")):
            _CRYPTO_LIB = ctypes.cdll.LoadLibrary(os.path.join(curr_path, "libcryptoauth.dylib"))
        else:
            _CRYPTO_LIB = None
            raise LibraryLoadError('Unable to find library in {}'.format(curr_path))


def get_cryptoauthlib():
    """
    This is a helper function for the other python files in this module to use the loaded library
    """
    global _CRYPTO_LIB      # pylint: disable=global-statement
    return _CRYPTO_LIB


def get_size_by_name(name):
    """
    Get the size of an object in the library using the name_size api from atca_utils_sizes.c
    """
    global _CRYPTO_LIB      # pylint: disable=global-statement
    return getattr(_CRYPTO_LIB, '{}_size'.format(name), lambda: 4)()


def get_ctype_by_name(name):
    """
    For known (atca_utils_sizes.c) types that are custom to the library retrieve the size
    """
    return _CTYPES_BY_SIZE.get(get_size_by_name(name))


__all__ = ['ATCA_NAMES', 'AtcaReference', 'load_cryptoauthlib']
