"""
Package Definition
"""

import sys

# All modules are setup to be import * safe so the following is an exception to
# the python coding standard. Also the library has to be loaded before loading
# the rest of the module to correctly set up the ctypes structures
# pylint: disable-msg=wildcard-import, wrong-import-position

from .library import *
from .exceptions import *

try:
    load_cryptoauthlib()
except LibraryLoadError as error:
    if not hasattr(sys, '_called_from_test'):
        raise error

from .status import *
from .atcab import *
from .atcacert import *
from .atjwt import *
from .iface import *
from .tng import *
