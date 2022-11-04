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

from fnmatch import fnmatch
import os
from pickle import OBJ
import sys
from ctypes import *
from ctypes.util import find_library
from typing import Callable, Sequence, Any
from unittest.util import unorderable_list_difference
from .exceptions import LibraryLoadError
from .atcaenum import AtcaEnum

try:
    from textwrap import indent
except ImportError:
    # python2 compatability - we control the newlines in this module so no need
    # to worry about platform differences here - rendering will change them
    def indent(lines, insert):
        return insert + '\n{}'.format(insert).join(lines.split('\n'))


# Maps common name to the specific name used internally
ATCA_NAMES = {'i2c': 'i2c', 'hid': 'kithid', 'sha': 'sha204', 'ecc': 'eccx08'}

# Global cdll instance of the loaded compiled library
_CRYPTO_LIB = None

# List of basic ctypes by size
_CTYPES_BY_SIZE = {1: c_uint8, 2: c_uint16, 4:c_uint32}

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


def _force_local_library():
    """
    In some environments loading seems to fail under all circumstances unless
    brute forcing it.
    """
    paths = [os.path.dirname(__file__)]

    if sys.platform.startswith('win'):
        libname = 'cryptoauth.dll'
    elif sys.platform.startswith('darwin'):
        libname = 'libcryptoauth.dylib'
    else:
        if 'LD_LIBRARY_PATH' in os.environ:
            paths += os.environ['LD_LIBRARY_PATH'].split(os.pathsep)
        libname = 'libcryptoauth.so'

    for p in paths:
        libpath = os.path.join(p, libname)
        if os.path.exists(libpath):
            return libpath
    return libname


def load_cryptoauthlib(lib=None):
    """
    Load CryptoAauthLib into Python environment
    raise LibraryLoadError if cryptoauthlib library can't be loaded
    """

    global _CRYPTO_LIB      # pylint: disable=global-statement
    if lib is not None:
        _CRYPTO_LIB = lib
    else:
        try:
            library_file = find_library('cryptoauth')
            if library_file is None:
                library_file = _force_local_library()
            _CRYPTO_LIB = cdll.LoadLibrary(library_file)
        except:
            try:
                _CRYPTO_LIB = cdll.LoadLibrary(_force_local_library())
            except:
                raise LibraryLoadError('Unable to find cryptoauthlib. You may need to reinstall')



def get_cryptoauthlib():
    """
    This is a helper function for the other python files in this module to use the loaded library
    """
    global _CRYPTO_LIB      # pylint: disable=global-statement
    return _CRYPTO_LIB


def get_device_name(revision):
    """
    Returns the device name based on the info byte array values returned by atcab_info
    """
    devices = {0x10: 'ATECC108A',
               0x50: 'ATECC508A',
               0x60: 'ATECC608',
               0x20: 'ECC204',
               0x00: 'ATSHA204A',
               0x02: 'ATSHA204A',
               0x40: 'ATSHA206A'}
    device_name = devices.get(revision[2], 'UNKNOWN')
    return device_name


def get_device_type_id(name):
    """
    Returns the ATCADeviceType value based on the device name
    """
    devices = {'ATSHA204A': 0,
               'ATECC108A': 1,
               'ATECC508A': 2,
               'ATECC608A': 3,
               'ATECC608B': 3,
               'ATECC608': 3,
               'ATSAH206A': 4,
               'ECC204': 5,
               'UNKNOWN': 0x20}
    return devices.get(name.upper())


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


def get_ctype_structure_instance(structure, value):
    """
    Internal Helper Function:  Convert a value into the correct ctypes structure for a given field
    :param value: Value to convert
    :param structure: Conversion Class (resulting type)
    :return:
    """
    # pylint: disable-msg=invalid-name
    if isinstance(value, dict):
        r = structure(**value)
    elif isinstance(value, int):
        r = structure.from_buffer_copy(c_uint(value))
    elif isinstance(value, AtcaEnum):
        r = structure.from_buffer_copy(c_uint(int(value)))
    elif not isinstance(value, structure):
        r = structure(value)
    else:
        r = value
    return r


def get_ctype_array_instance(array, value):
    """
    Internal Helper Function: Convert python list into ctype array
    :param value: Value to convert
    :param array: Conversion Class (resulting type)
    :return:
    """
    # pylint: disable-msg=invalid-name, protected-access
    t = array._type_
    if t is c_char:
        # Strings are special
        if isinstance(value, str):
            a = value.encode('ascii')
        else:
            a = bytes(value)
    else:
        a = array(*[get_ctype_structure_instance(t, e) for e in value])
    return a

class _CtypeIterator:
    """
    Used to iterate through a ctypes structure or union. This iterator
    returns a tuple of three elements:
            <field_name>, <field_contents>, <field_info>
    Of course field_info is a tuple of varying size depending on how the
    field was defined (arrays, bitfields, etc)
    """
    def __init__(self, obj) -> None:
        self._obj = obj
        self._index = 0
        self._end = len(self._obj._fields_)
    def __iter__(self):
        return self
    def __next__(self):
        if self._index < self._end:
            f = self._obj._fields_[self._index]
            if d := getattr(self._obj, '_def_', {}).get(f[0], None):
                f_info = tuple(d)
            else:
                f_info = tuple(list(f)[1:])
            self._index += 1
            return f[0], getattr(self._obj, f[0]), f_info
        raise StopIteration

def _get_field_definition(obj, name):
    """
    Get meta information about the ctypes structure/union by accessing
    the field description attributes of the class that were provided
    as part of the ctype structure/union definition
    """
    # Check for the _def_ attribute first which yields superior field
    # information for our uses
    if d := getattr(obj, '_def_', {}).get(name, None):
        f = list(d)
        if len(f) > 1 and  isinstance(f[1], str):
            f[1] = getattr(obj, f[1])
        return tuple(f)
    # Fallback to the _fields_ list which is less verbose but contains
    # type information which is suitable for a lot of operations
    for f in obj._fields_:
        if f[0] == name:
            return tuple(list(f)[1:])
    # The field is not found so it's probably an anonymous union - we'll
    # recurse once if we find the field rather than going overboard
    # with recursion here. It would be a bit rediculous to have multple
    # cascaded anonymous unions - in the context of cryptoauthlib its
    # not possible
    if anon := getattr(obj, '_anonymous_', None):
        for anon_name in anon:
            anon_obj = getattr(obj, anon_name)
            for f in anon_obj._fields_:
                if f[0] == name:
                    return _get_field_definition(anon_obj, name)

def _def_to_field(f_type, f_size = None):
    """
    Helper function to convert an entry in the _def_ dictionary to the 
    tuple required for a _field_ entry
    """
    if type(f_type) == type(AtcaEnum):
        f_type = get_ctype_by_name(f_type.__name__)
    if type(f_size) == type(AtcaEnum):
        f_size = len(f_size)
    if isinstance(f_size, int):
        return f_type*f_size
    return f_type

def _convert_pointer_to_list(p, length):
    """
    Pointer types can be frustrating to interact with generally when processing data in python
    so this converts them into types that are iterable and bounded
    """
    if p._type_ in (c_ubyte, c_byte):
        return string_at(p, length)
    elif p._type_ == c_char:
        return string_at(p, length).decode('ascii')
    else:
        return [p[i] for i in range(length)]

def _get_attribute_from_ctypes(obj, obj_type, length = None, *args):
    """
    Helper function that is used by AtcaStructure and AtcaUnion to intercept attribute access
    to those objects and convert the resulting values into easier to use python objects based
    on the configuration of the structure/union
    """
    def _convert_value(e_type, value):
        try:
            return e_type(value)
        except ValueError:
            return value

    def _get_conversion_from_field(f_type):
        if type(f_type) == type(AtcaEnum):
            return lambda x: _convert_value(f_type, x)
        return lambda x: x

    if obj_type == c_char:
        # Convert character arrays to strings
        return obj.decode('ascii')
    elif getattr(obj_type, 'contents', None):
        # Check pointers and convert if possible
        if obj:
            if length:
                return _convert_pointer_to_list(obj, length)
            else:
                return obj.contents
        else:
            return None
    elif l := getattr(obj, '_length_', None):
        # Convert ctype arrays to bounded lists
        e = _get_conversion_from_field(obj_type)
        return [e(obj[i]) for i in range(l)]
    elif isinstance(obj, int):
        return _get_conversion_from_field(obj_type)(obj)
    return obj

def _check_type_rationality(cls):
    """
    This checks the structure or union size against the constants that are stored in the library
    during compilation. This is not an absolute guarentee that alignment is completely correct
    but it will catch most cases of incompability between the compiled library that is installed
    and the python module
    """
    lib_size = getattr(cls, '_size_', get_size_by_name(cls.__name__))
    py_size = sizeof(cls)
    if py_size != lib_size:
        message = ('STRUCTURE RATIONALITY CHECK FAILED!' +
                  f'\nThe size of {cls.__name__} ({py_size}) in {cls.__module__} ' + 
                  f'does not match the installed library\'s size ({lib_size}).' +
                  '\n\nThis can cause serious faults - you will need to reinstall')
        raise LibraryLoadError(message)

def _array_to_code(obj, name=None, parent = None, **kwargs):
    """
    Convert an array like item from a ctypes structure into a C language formatted
    string
    """
    name_map = lambda x: None
    array_type = None
    if parent:
        if name:
            if d := parent.get_field_definition(name):
                array_type = d[0]
                if len(d) > 1 and type(d[1]) == type(AtcaEnum):
                    # Checks to see if the parent object has a name map for the array
                    # elements
                    name_map = d[1]

    append = _object_definition_code(obj, name, parent, **kwargs)
    prepend = ''

    if isinstance(obj, str):
        # Directly render 
        append += f'"{obj}"'
    elif isinstance(obj, bytes) or getattr(array_type, '_type_', None) in (c_byte, c_ubyte):
        append += '{'
        for i, v in enumerate(obj):
            if i % 16 == 0:
                append += '\n    '
            append += f'0x{v:02x}, '
        append = append[:-1] + '\n}'
    else:
        items = ''
        for i, v in enumerate(obj):
            i_append, i_prepend = _obj_to_code(v, name_map(i), parent=obj, anon=True, **kwargs)
            items += '\n' + i_append
            prepend = i_prepend + prepend
        append += '{' + indent(items[:-1], '    ') + '\n}'

    append += ',' if parent else ';'

    return append, prepend

def _object_definition_code(obj, name = None, parent = None, parent_name=None, anon=None, type_info = None, check_names={}):
    """
    Emits the first half of the assignment of this object
    """
    if name:
        if parent is not None:
            if anon:
                return '\n'
            return f'\n.{parent_name}.{name} = ' if parent_name else f'\n.{name} = '
        else:
            if type_info:
                type_name = type_info._type_.__name__
            else:
                type_name = obj.__class__.__name__

            if 'byte' in type_name:
                type_name = 'uint8_t'

            is_array = f'[{len(obj)}]' if isinstance(obj, Sequence) else ''

            return f'\nconst {type_name} {name}{is_array} = '
    return ''

def _union_to_code(obj, name = None, parent = None, anon = None, entry = None, parent_name=None, type_info=None, **kwargs):
    if parent:
        anon = name in getattr(parent, '_anonymous_', [])
    else:
        anon = False

    if entry is None and (info := getattr(parent, '_map_', {}).get(name, None)):
        if len(info) == 1:
            entry = info[0]
        else:
            entry = info[1].get(getattr(parent, info[0]), None)

    if isinstance(entry, int):
        entry = obj._fields_[entry][0]
    if entry:
        parent = obj
        obj = getattr(obj, entry)
        name = entry

    append = '' if anon else _object_definition_code(obj, name, parent, **kwargs)
    prepend = ''

    if entry:
        if parent_name is None:
            parent_name = name
        f_append, f_prepend = _to_code(obj, name, parent=parent, anon=anon, parent_name=parent_name, **kwargs)
        append += f_append
        prepend = f_prepend + prepend
    else:
        fields = ''
        for f_name, f_item, f_info in obj:
            f_append, f_prepend = _to_code(f_item, f_name, parent=obj, type_info=f_info[0], **kwargs)
            fields += f_append
            prepend = f_prepend + prepend
        append += '{' + indent(fields[:-1], '    ')  + '\n}'

    append += ',' if parent else ';'

    return append, prepend

def _structure_to_code(obj, name = None, parent = None, type_info=None, parent_name=None, **kwargs):
    """
    Emits a string with a C language representation of the structure(s) following pointers the
    best that is can
    """
    append = _object_definition_code(obj, name, parent, **kwargs)
    prepend = ''

    fields = f' //{name}' if name and isinstance(parent, Sequence) else ''
    for f_name, f_item, f_info in obj:
        f_append, f_prepend = _to_code(f_item, f_name, parent=obj, parent_name=name, type_info=f_info[0], **kwargs)
        fields += f_append
        prepend = f_prepend + prepend
    append += '{' + indent(fields[:-1], '    ')  + '\n}'
    append += ',' if parent else ';'

    return append, prepend

def _obj_to_code(obj, name, parent=None, anon=None, parent_name=None, **kwargs):
    """
    Convert python/ctypes object into a C language representation
    """
    if isinstance(obj, Union):
        return _union_to_code(obj, name, parent=parent, anon=anon, parent_name=parent_name, **kwargs)
    elif isinstance(obj, Structure):
        return _structure_to_code(obj, name, parent=parent, anon=anon, **kwargs)
    elif isinstance(obj, Sequence):
        return _array_to_code(obj, name, parent=parent, **kwargs)
    else:
        append = _object_definition_code(obj, name, parent=parent, **kwargs)
        append += str(obj)
        append += ',' if parent else ';'
        return append, ''

def _pointer_to_code(obj, name = None, parent=None, parent_name=None, check_names={}, **kwargs):
    """
    Convert the pointer into a representative object by creating a definition in the prepend
    area
    """
    append = _object_definition_code(obj, name, parent, **kwargs)
    prepend = ''
    if obj:
        name = f'{parent_name}_{name}'
        name = check_names.get(name, name)
        prepend, more = _obj_to_code(obj, name, parent=None, check_names=check_names, **kwargs)
        prepend = more + prepend + '\n'
        append += f'&{name},'
    else:
        append += 'NULL,'
    return append, prepend

def _is_pointer(obj, type_info = None, **kwargs):
    """
    Checks to see if object looks like a pointer
    """
    return type_info and getattr(type_info, 'contents', None)

def _to_code(obj, name = None, **kwargs):
    """
    Map object types to the proper renderer function by catching pointer like objects first

    Returns: (append, prepend)
    """
    if _is_pointer(obj, **kwargs):
        return _pointer_to_code(obj, name, **kwargs)
    return _obj_to_code(obj, name, **kwargs)

def _structure_to_string(item, level: int = 0):
    """
    Emits a readable string of the structure elements coverting types and following pointers and arrays
    the best that is can
    """
    if level == 0:
        result = f'\n{item.__class__.__name__} = '
        level += 1
    else:
        result = ''
    if isinstance(item, (Structure, Union)):
        for f in item._fields_:
            result += indent(f'\n{f[0]} = ', '  '*level)
            result += _structure_to_string(getattr(item, f[0]), level + 1)
    elif isinstance(item, Sequence) and not (isinstance(item, (bytes, str)) or isinstance(item[0], int)):
        items = ''
        for i in item:
            items += '\n' + _structure_to_string(i, level+1)
        result += indent(items, '  '*level)
    else:
        result += f'{item}'
    return result

def _ctype_from_definition(cls):
    """
    Extends the ctypes structure and union types to add a new attribute _def_ which is a dictionary
    of field attributes. This extends functionality by quite a bit by supporting additional types
    and field linkages
    """
    if not getattr(cls, '_fields_', None):
        if getattr(cls, '_def_', None):
            cls._fields_ = [(k, _def_to_field(*d)) for k, d in cls._def_.items()]
        else:
            raise AttributeError(f'Trying to finalize the {cls} type without providing _fields_ or _def_ attributes')


class AtcaUnion(Union):
    """ An extended ctypes structure to accept complex inputs """
    # pylint: disable-msg=invalid-name, too-few-public-methods
    def __init__(self, *args, **kwargs):
        self._selected = ''
        if kwargs is not None:
            for f in self._fields_:
                if f[0] in kwargs:
                    if isinstance(f[1](), Union):
                        kwargs[f[0]] = get_ctype_structure_instance(f[1], kwargs[f[0]])
                    elif isinstance(f[1](), Structure):
                        kwargs[f[0]] = get_ctype_structure_instance(f[1], kwargs[f[0]])
                    elif isinstance(f[1](), Array):
                        kwargs[f[0]] = get_ctype_array_instance(f[1], kwargs[f[0]])

        super(AtcaUnion, self).__init__(*args, **kwargs)

    @classmethod
    def from_definition(cls):
        """
        Trigger _field_ creation from the values provided in _def_ - must be run before the class
        is instantiated
        """
        _ctype_from_definition(cls)

    @classmethod
    def check_rationality(cls):
        """
        Perform a rationality check on the structure definition against the expected definition by
        checking structure sizes between the compiled library and the python library
        """
        _check_type_rationality(cls)

    @classmethod
    def get_field_definition(cls, name: str):
        return _get_field_definition(cls, name)

    def __getattribute__(self, name: str) -> Any:
        obj = super().__getattribute__(name)
        if isinstance(obj, Callable) or name.startswith('_'):
            return obj
        return _get_attribute_from_ctypes(obj, *_get_field_definition(self, name))

    def __iter__(self):
        return _CtypeIterator(self)

    def __str__(self):
        return _structure_to_string(self)

    def to_c_code(self, name = None, **kwargs):
        append, prepend = _union_to_code(self, name, **kwargs)
        return prepend + append

    def update_from_buffer(self, buffer):
        if len(buffer) < sizeof(self):
            raise ValueError
        memmove(addressof(self), buffer, sizeof(self))


class AtcaStructure(Structure):
    """ An extended ctypes structure to accept complex inputs """
    # pylint: disable-msg=invalid-name, too-few-public-methods
    def __init__(self, *args, **kwargs) -> None:
        if kwargs is not None:
            for f in self._fields_:
                if f[0] in kwargs:
                    if isinstance(f[1](), Union):
                        kwargs[f[0]] = get_ctype_structure_instance(f[1], kwargs[f[0]])
                    elif isinstance(f[1](), Structure):
                        kwargs[f[0]] = get_ctype_structure_instance(f[1], kwargs[f[0]])
                    elif isinstance(f[1](), Array):
                        kwargs[f[0]] = get_ctype_array_instance(f[1], kwargs[f[0]])
                    elif isinstance(kwargs[f[0]], AtcaEnum):
                        kwargs[f[0]] = int(kwargs[f[0]])

        super(AtcaStructure, self).__init__(*args, **kwargs)

    @classmethod
    def from_definition(cls):
        """
        Trigger _field_ creation from the values provided in _def_ - must be run before the class
        is instantiated
        """
        _ctype_from_definition(cls)

    @classmethod
    def check_rationality(cls):
        """
        Perform a rationality check on the structure definition against the expected definition by
        checking structure sizes between the compiled library and the python library
        """
        _check_type_rationality(cls)

    @classmethod
    def get_field_definition(cls, name: str):
        return _get_field_definition(cls, name)

    def __getattribute__(self, name: str) -> Any:
        obj = super().__getattribute__(name)
        if isinstance(obj, Callable) or name.startswith('_'):
            return obj
        return _get_attribute_from_ctypes(obj, *_get_field_definition(self, name))

    def __iter__(self):
        return _CtypeIterator(self)

    def __str__(self):
        return _structure_to_string(self)

    def to_c_code(self, name = None, **kwargs):
        append, prepend = _structure_to_code(self, name, **kwargs)
        return prepend + append

    def update_from_buffer(self, buffer):
        if len(buffer) < sizeof(self):
            raise ValueError
        memmove(addressof(self), buffer, sizeof(self))


def ctypes_to_bytes(obj):
    """
    Convert a ctypes structure/array into bytes. This is for python2 compatibility
    """
    buf = create_string_buffer(sizeof(obj))
    memmove(buf, addressof(obj), sizeof(obj))
    return buf.raw


def create_byte_buffer(init_or_size):
    if isinstance(init_or_size, int):
        buf = (c_uint8*init_or_size)()
    else:
        buf = (c_uint8*len(init_or_size))(*list(init_or_size))
    return buf


__all__ = ['ATCA_NAMES', 'AtcaReference', 'load_cryptoauthlib', 'get_device_name', 'get_device_type_id',
           'create_byte_buffer']
