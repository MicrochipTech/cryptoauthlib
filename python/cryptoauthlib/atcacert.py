from ctypes import Structure, c_int, c_uint8, c_uint16, c_char, POINTER, Array
from .atcab import get_cryptoauthlib
from .atcaenum import AtcaEnum

import binascii


class atcacert_cert_type_t(AtcaEnum):
    """Types of certificates"""
    CERTTYPE_X509 = 0       # Standard X509 certificate
    CERTTYPE_CUSTOM = 1     # Custom format


class atcacert_cert_sn_src_t(AtcaEnum):
    """Sources for the certificate serial number"""
    SNSRC_STORED = 0x0  # Cert serial is stored on the device.
    SNSRC_STORED_DYNAMIC = 0x7  # Cert serial is stored on the device with the first byte being the DER size (X509 certs only).
    SNSRC_DEVICE_SN = 0x8  # Cert serial number is 0x40(MSB) + 9-byte device serial number. Only applies to device certificates.
    SNSRC_SIGNER_ID = 0x9  # Cert serial number is 0x40(MSB) + 2-byte signer ID. Only applies to signer certificates.
    SNSRC_PUB_KEY_HASH = 0xA  # Cert serial number is the SHA256(Subject public key + Encoded dates), with uppermost 2 bits set to 01.
    SNSRC_DEVICE_SN_HASH = 0xB  # Cert serial number is the SHA256(Device SN + Encoded dates), with uppermost 2 bits set to 01. Only applies to device certificates.
    SNSRC_PUB_KEY_HASH_POS = 0xC  # Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates), with MSBit set to 0 to ensure it's positive.
    SNSRC_DEVICE_SN_HASH_POS = 0xD  # Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates), with MSBit set to 0 to ensure it's positive. Only applies to device certificates.
    SNSRC_PUB_KEY_HASH_RAW = 0xE  # Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates).
    SNSRC_DEVICE_SN_HASH_RAW = 0xF  # Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates). Only applies to device certificates.


class atcacert_device_zone_t(AtcaEnum):
    """ATECC device zones. The values match the Zone Encodings as specified in the datasheet"""
    DEVZONE_CONFIG = 0x00   # Configuration zone.
    DEVZONE_OTP = 0x01      # One Time Programmable zone.
    DEVZONE_DATA = 0x02     # Data zone (slots).
    DEVZONE_NONE = 0x07     # Special value used to indicate there is no device location.


class atcacert_date_format_t(AtcaEnum):
    DATEFMT_ISO8601_SEP = 0  # ISO8601 full date YYYY-MM-DDThh:mm:ssZ
    DATEFMT_RFC5280_UTC = 1  # RFC 5280 (X.509) 4.1.2.5.1 UTCTime format YYMMDDhhmmssZ
    DATEFMT_POSIX_UINT32_BE = 2  # POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, big endian.
    DATEFMT_POSIX_UINT32_LE = 3  # POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, little endian.
    DATEFMT_RFC5280_GEN = 4  # RFC 5280 (X.509) 4.1.2.5.2 GeneralizedTime format YYYYMMDDhhmmssZ


class atcacert_std_cert_element_t(AtcaEnum):
    """Standard dynamic certificate elements"""
    STDCERT_PUBLIC_KEY = 0
    STDCERT_SIGNATURE = 1
    STDCERT_ISSUE_DATE = 2
    STDCERT_EXPIRE_DATE = 3
    STDCERT_SIGNER_ID = 4
    STDCERT_CERT_SN = 5
    STDCERT_AUTH_KEY_ID = 6
    STDCERT_SUBJ_KEY_ID = 7


def _atcacert_convert_bytes(kwargs, name, pointer):
    k = kwargs.get(name)
    if k is not None:
        k = k.replace(' ', '').strip()
        byte_string = binascii.unhexlify(k)
        kwargs[name] = pointer((c_uint8*len(byte_string))(*list(byte_string)))


def _atcacert_convert_enum(kwargs, name, enum):
    k = kwargs.get(name)
    if k is not None and k is not int:
        kwargs[name] = int(getattr(enum, k))


def _atcacert_convert_structure(kwargs, name, structure):
    k = kwargs.get(name)
    if k is not None and type(k) is dict:
        kwargs[name] = structure(**k)


def _atcacert_convert_array(kwargs, name, array):
    k = kwargs.get(name)
    if k is not None:
        a = [array._type_(**e) for e in k]
        kwargs[name] = array(*a)


class atcacert_device_loc_t(Structure):
    _fields_ = [
        ('zone', c_int),  # Zone in the device.
        ('slot', c_uint8),  # Slot within the data zone. Only applies if zone is DEVZONE_DATA.
        ('is_genkey', c_uint8),  # If true, use GenKey command to get the contents instead of Read.
        ('offset', c_uint16),  # Byte offset in the zone.
        ('count', c_uint16)  # Byte count.
    ]

    def __init__(self, *args, **kwargs):
        if kwargs is not None:
            _atcacert_convert_enum(kwargs, 'zone', atcacert_device_zone_t)

        super(atcacert_device_loc_t, self).__init__(*args, **kwargs)


class atcacert_cert_loc_t(Structure):
    _fields_ = [('offset', c_uint16), ('count', c_uint16)]


class atcacert_cert_element_t(Structure):
    _fields_ = [
        ('id', c_char * 16),  # ID identifying this element.
        ('device_loc', atcacert_device_loc_t),  # Location in the device for the element.
        ('cert_loc', atcacert_cert_loc_t)  # Location in the certificate template for the element.
    ]


class atcacert_def_t(Structure):
    _fields_ = [
        ('type', c_int),  # Certificate type.
        ('template_id', c_uint8),       # ID for the this certificate definition (4-bit value).
        ('chain_id', c_uint8),          # ID for the certificate chain this definition is a part of (4-bit value).
        ('private_key_slot', c_uint8),   #If this is a device certificate template, this is the device slot for the device private key.
        ('sn_source', c_int),  # Where the certificate serial number comes from (4-bit value).
        ('cert_sn_dev_loc', atcacert_device_loc_t), # Only applies when sn_source is SNSRC_STORED or SNSRC_STORED_DYNAMIC. Describes where to get the certificate serial number on the device.
        ('issue_date_format', c_int),  # Format of the issue date in the certificate.
        ('expire_date_format', c_int),  # format of the expire date in the certificate.
        ('tbs_cert_loc', atcacert_cert_loc_t),  # Location in the certificate for the TBS (to be signed) portion.
        ('expire_years', c_uint8),  # Number of years the certificate is valid for (5-bit value). 0 means no expiration.
        ('public_key_dev_loc', atcacert_device_loc_t),  # Where on the device the public key can be found.
        ('comp_cert_dev_loc', atcacert_device_loc_t),  #Where on the device the compressed cert can be found.
        ('std_cert_elements', atcacert_cert_loc_t * 8),  # Where in the certificate template the standard cert elements are inserted.
        ('cert_elements', POINTER(atcacert_cert_element_t)),  # Additional certificate elements outside of the standard certificate contents.
        ('cert_elements_count', c_uint8),  # Number of additional certificate elements in cert_elements.
        ('cert_template', POINTER(c_uint8)),  #Pointer to the actual certificate template data.
        ('cert_template_size', c_uint16)  # Size of the certificate template in cert_template in bytes.
    ]

    def __init__(self, *args, **kwargs):
        if kwargs is not None:
            _atcacert_convert_enum(kwargs, 'type', atcacert_cert_type_t)
            _atcacert_convert_enum(kwargs, 'sn_source', atcacert_cert_sn_src_t)
            _atcacert_convert_enum(kwargs, 'issue_date_format', atcacert_date_format_t)
            _atcacert_convert_enum(kwargs, 'expire_date_format', atcacert_date_format_t)

            _atcacert_convert_bytes(kwargs, 'cert_template', POINTER(c_uint8))

            for f in self._fields_:
                if type(f[1]) == type(Structure):
                    _atcacert_convert_structure(kwargs, f[0], f[1])
                if type(f[1]) == type(Array):
                    _atcacert_convert_array(kwargs, f[0], f[1])

        super(atcacert_def_t, self).__init__(*args, **kwargs)

