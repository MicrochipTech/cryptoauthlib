"""
Package Definition
"""
import os
import sys
import json
import ctypes

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
from .sha206_api import *

try:
    from .talib import *
except ImportError:
    pass


def __update_signature(func, attributes):
    for k, v in attributes.items():
        if isinstance(v, list):
            setattr(func, k, [eval(x) for x in v])
        else:
            setattr(func, k, eval(v))


def __update_signatures(lib, filename):
    sig_info = json.load(open(filename, 'r'))

    for k, v in sig_info.items():
        try:
            __update_signature(getattr(lib, k), v)
        except AttributeError:
            pass

if os.path.exists('cryptoauth.json'):
    __update_signatures(get_cryptoauthlib(), os.path.join(os.path.dirname(__file__), 'cryptoauth.json'))
