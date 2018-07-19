from ctypes import Structure, Union, c_uint16, c_int, c_uint8, c_uint32, c_void_p
from .atcab import get_cryptoauthlib

# The following must match atca_iface.h exactly

class _ATCAI2C(Structure):
    _fields_ = [('slave_address', c_uint8),
                ('bus', c_uint8),
                ('baud', c_uint32)]


class _ATCASWI(Structure):
    _fields_ = [('bus', c_uint8)]


class _ATCAUART(Structure):
    _fields_ = [('port', c_int),
                ('baud', c_uint32),
                ('wordsize', c_uint8),
                ('parity', c_uint8),
                ('stopbits', c_uint8)]


class _ATCAHID(Structure):
    _fields_ = [('idx', c_int),
                ('vid', c_uint32),
                ('pid', c_uint32),
                ('packetsize', c_uint32),
                ('guid', c_uint8*16)]


class _ATCACUSTOM(Structure):
    _fields_ = [('halinit', c_void_p),
                ('halpostinit', c_void_p),
                ('halsend', c_void_p),
                ('halreceive', c_void_p),
                ('halwake', c_void_p),
                ('halidle', c_void_p),
                ('halsleep', c_void_p),
                ('halrelease', c_void_p)]


class _ATCAIfaceParams(Union):
    _fields_ = [('atcai2c', _ATCAI2C),
                ('atcaswi', _ATCASWI),
                ('atcauart', _ATCAUART),
                ('atcahid', _ATCAHID),
                ('atcacustom', _ATCACUSTOM)]

                
class ATCAIfaceCfg(Structure):
    _fields_ = [('iface_type', c_int),
                ('devtype', c_int),
                ('cfg', _ATCAIfaceParams),
                ('wake_delay', c_uint16),
                ('rx_retries', c_int),
                ('cfg_data', c_void_p)]
    

# Default configuration for an ECCx08A device on the first logical I2C bus
def cfg_ateccx08a_i2c_default():
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_ateccx08a_i2c_default')


# Default configuration for an ECCx08A device on the logical SWI bus over UART
def cfg_ateccx08a_swi_default():
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_ateccx08a_swi_default')


# Default configuration for Kit protocol over a HID interface
def cfg_ateccx08a_kithid_default():
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_ateccx08a_kithid_default')


# Default configuration for a SHA204A device on the first logical I2C bus
def cfg_atsha204a_i2c_default():
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_atsha204a_i2c_default')


# Default configuration for an SHA204A device on the logical SWI bus over UART*/
def cfg_atsha204a_swi_default():
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_atsha204a_swi_default')


# Default configuration for Kit protocol over a HID interface for SHA204
def cfg_atsha204a_kithid_default():
    return ATCAIfaceCfg.in_dll(get_cryptoauthlib(), 'cfg_atsha204a_kithid_default')  
