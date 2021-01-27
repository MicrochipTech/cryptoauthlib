"""
Package Definition
"""
import os
import sys
import json
import ctypes
import inspect
import textwrap

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


def __create_wrapper(name, attrs, ctypes_func, *args, **kwargs):
    def f(*args):
        return ctypes_func(*args)

    try:
        f.__name__ = name
    except TypeError:
        f.__name__ = name.encode()

    f.__doc__ = attrs.get('docstring', '')

    paramlist = attrs.get('parameters', [])

    f.__doc__ = os.linesep.join(textwrap.wrap(f.__doc__, width=70)) + os.linesep

    for n, d in paramlist:
        f.__doc__ += os.linesep + n + ':' + os.linesep + textwrap.indent(d, '    ') + os.linesep

    try:
        if len(paramlist) > 0:
            p = [inspect.Parameter(k, inspect.Parameter.POSITIONAL_ONLY) for k, v in attrs['parameters']]
            f.__signature__ = inspect.Signature(parameters=p)
        else:
            f.__signature__ = inspect.Signature()
    except:
        # Python 2 & < 3.4 skip the function signature updates
        pass

    return f


def __add_function(this_package, name, attrs, func):
    if not hasattr(this_package, name):
        setattr(this_package, name, __create_wrapper(name, attrs, func))


def __update_signature(func, name, attr):
    if isinstance(attr, list):
        setattr(func, name, [eval(x) for x in attr])
    elif attr is not None:
        setattr(func, name, eval(attr))


def __update_signatures(lib, filename):
    this_package = sys.modules[__package__]
    sig_info = json.load(open(filename, 'r'))

    for k, v in sig_info.items():
        try:
            func = getattr(lib, k)
            __update_signature(func, 'restype', v['restype'])
            __update_signature(func, 'argtypes', v['argtypes'])
            __add_function(this_package, k, v, func)
        except AttributeError:
            pass

_lib_definition_file = os.path.join(os.path.dirname(__file__), 'cryptoauth.json')

if os.path.exists(_lib_definition_file):
    __update_signatures(get_cryptoauthlib(), _lib_definition_file)
