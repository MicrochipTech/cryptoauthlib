"""
Interface Configuration
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

from ctypes import Structure, Union, c_uint16, c_int, c_uint8, c_uint32, c_void_p
from .library import get_cryptoauthlib, get_ctype_by_name
from .atcaenum import AtcaEnum

# Because this module directly mirrors the C api the following is an exception to the python coding standard
# pylint: disable-msg=too-few-public-methods


class ATCAIfaceType(AtcaEnum):
    """
    Interface Type Enumerations from atca_iface.h
    """
    ATCA_I2C_IFACE = 0
    ATCA_SWI_IFACE = 1
    ATCA_UART_IFACE = 2
    ATCA_SPI_IFACE = 3
    ATCA_HID_IFACE = 4


class ATCAKitType(AtcaEnum):
    """
    Interface Type Enumerations for Kit devices
    """
    ATCA_KIT_AUTO_IFACE = 0
    ATCA_KIT_I2C_IFACE = 1
    ATCA_KIT_SWI_IFACE = 2
    ATCA_KIT_UNKNOWN_IFACE = 3


class ATCADeviceType(AtcaEnum):
    """
    Device Type Enumeration from atca_devtypes.h
    """
    ATSHA204A = 0
    ATECC108A = 1
    ATECC508A = 2
    ATECC608A = 3
    ATECC608B = 3
    ATECC608  = 3
    ATSHA206A = 4
    ATCA_DEV_UNKNOWN = 0x20


# The following must match atca_iface.h exactly


class _ATCAI2C(Structure):
    """I2C/TWI HAL configuration"""
    _fields_ = [('slave_address', c_uint8),
                ('bus', c_uint8),
                ('baud', c_uint32)]


class _ATCASWI(Structure):
    """SWI (Atmel Single Wire Interface) HAL configuration"""
    _fields_ = [('bus', c_uint8)]


class _ATCAUART(Structure):
    """Generic UART HAL configuration"""
    _fields_ = [('port', c_int),
                ('baud', c_uint32),
                ('wordsize', c_uint8),
                ('parity', c_uint8),
                ('stopbits', c_uint8)]


class _ATCAHID(Structure):
    """USB (HID) HAL configuration"""
    _fields_ = [('idx', c_int),
                ('dev_interface', get_ctype_by_name('ATCAKitType')),
                ('dev_identity', c_uint8),
                ('vid', c_uint32),
                ('pid', c_uint32),
                ('packetsize', c_uint32)]


class _ATCACUSTOM(Structure):
    """Custom HAL configuration"""
    _fields_ = [('halinit', c_void_p),
                ('halpostinit', c_void_p),
                ('halsend', c_void_p),
                ('halreceive', c_void_p),
                ('halwake', c_void_p),
                ('halidle', c_void_p),
                ('halsleep', c_void_p),
                ('halrelease', c_void_p)]


class _ATCAIfaceParams(Union):
    """HAL Configurations supported by the library (this is a union)"""
    _fields_ = [('atcai2c', _ATCAI2C),
                ('atcaswi', _ATCASWI),
                ('atcauart', _ATCAUART),
                ('atcahid', _ATCAHID),
                ('atcacustom', _ATCACUSTOM)]


class ATCAIfaceCfg(Structure):
    """Interface configuration structure used by atcab_init()"""
    _fields_ = [('iface_type', get_ctype_by_name('ATCAIfaceType')),
                ('devtype', get_ctype_by_name('ATCADeviceType')),
                ('cfg', _ATCAIfaceParams),
                ('wake_delay', c_uint16),
                ('rx_retries', c_int),
                ('cfg_data', c_void_p)]


def cfg_ateccx08a_i2c_default():
    """Default configuration for an ECCx08A device on the first logical I2C bus"""
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_ateccx08a_i2c_default')


def cfg_ateccx08a_swi_default():
    """Default configuration for an ECCx08A device on the logical SWI bus over UART"""
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_ateccx08a_swi_default')


def cfg_ateccx08a_kithid_default():
    """Default configuration for Kit protocol over a HID interface"""
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_ateccx08a_kithid_default')


def cfg_atsha20xa_i2c_default():
    """Default configuration for a SHA204A device on the first logical I2C bus"""
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_atsha20xa_i2c_default')


def cfg_atsha20xa_swi_default():
    """Default configuration for an SHA204A device on the logical SWI bus over UART"""
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_atsha20xa_swi_default')


def cfg_atsha20xa_kithid_default():
    """Default configuration for Kit protocol over a HID interface for SHA204"""
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_atsha20xa_kithid_default')


# Make module import * safe - keep at the end of the file
__all__ = (['ATCAIfaceCfg', 'ATCAIfaceType', 'ATCADeviceType', 'ATCAKitType']
           + [x for x in dir() if x.startswith('cfg_')])
