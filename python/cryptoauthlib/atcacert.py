"""
ATCACERT: classes and functions for interacting with compressed certificates
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

import binascii
from datetime import datetime
from ctypes import Structure, c_int, c_uint8, c_uint16, c_char, POINTER, create_string_buffer, c_uint32, byref, c_size_t
from .library import get_cryptoauthlib, get_ctype_by_name, AtcaReference, AtcaStructure
from .atcaenum import AtcaEnum
from .status import Status

# Because this module directly mirrors the C api the following is an exception to the python coding standard
# pylint: disable-msg=invalid-name, too-few-public-methods


class atcacert_cert_type_t(AtcaEnum):
    """
    Types of certificates
    """
    CERTTYPE_X509 = 0       # Standard X509 certificate
    CERTTYPE_CUSTOM = 1     # Custom format


class atcacert_cert_sn_src_t(AtcaEnum):
    """
    Sources for the certificate serial number
    """
    # Cert serial is stored on the device.
    SNSRC_STORED = 0x0
    # Cert serial is stored on the device with the first byte being the DER size (X509 certs only).
    SNSRC_STORED_DYNAMIC = 0x7
    # Cert serial number is 0x40(MSB) + 9-byte device serial number. Only applies to device certificates.
    SNSRC_DEVICE_SN = 0x8
    # Cert serial number is 0x40(MSB) + 2-byte signer ID. Only applies to signer certificates.
    SNSRC_SIGNER_ID = 0x9
    # Cert serial number is the SHA256(Subject public key + Encoded dates), with uppermost 2 bits set to 01.
    SNSRC_PUB_KEY_HASH = 0xA
    # Cert serial number is the SHA256(Device SN + Encoded dates), with uppermost 2 bits set to 01.
    # Only applies to device certificates.
    SNSRC_DEVICE_SN_HASH = 0xB
    # Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates),
    # with MSBit set to 0 to ensure it's positive.
    SNSRC_PUB_KEY_HASH_POS = 0xC
    # Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates),
    # with MSBit set to 0 to ensure it's positive. Only applies to device certificates.
    SNSRC_DEVICE_SN_HASH_POS = 0xD
    # Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates).
    SNSRC_PUB_KEY_HASH_RAW = 0xE
    # Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates).
    # Only applies to device certificates.
    SNSRC_DEVICE_SN_HASH_RAW = 0xF


class atcacert_device_zone_t(AtcaEnum):
    """
    ATECC device zones. The values match the Zone Encodings as specified in the datasheet
    """
    DEVZONE_CONFIG = 0x00   # Configuration zone.
    DEVZONE_OTP = 0x01      # One Time Programmable zone.
    DEVZONE_DATA = 0x02     # Data zone (slots).
    DEVZONE_NONE = 0x07     # Special value used to indicate there is no device location.


class atcacert_transform_t(AtcaEnum):
    """
    Transforms for converting the device data.
    """
    TF_NONE = 0x00              # No transform, data is used byte for byte
    TF_REVERSE = 0x01           # Reverse the bytes (e.g. change endianess)
    TF_BIN2HEX_UC = 0x02        # Convert raw binary into ASCII hex, uppercase
    TF_BIN2HEX_LC = 0x03        # Convert raw binary into ASCII hex, lowercase
    TF_HEX2BIN_UC = 0x04        # Convert ASCII hex, uppercase to binary
    TF_HEX2BIN_LC = 0x05        # Convert ASCII hex, lowercase to binary
    TF_BIN2HEX_SPACE_UC = 0x06  # Convert raw binary into ASCII hex, uppercase space between bytes
    TF_BIN2HEX_SPACE_LC = 0x07  # Convert raw binary into ASCII hex, lowercase space between bytes
    TF_HEX2BIN_SPACE_UC = 0x08  # Convert ASCII hex, uppercase with spaces between bytes to binary
    TF_HEX2BIN_SPACE_LC = 0x09  # Convert ASCII hex, lowercase with spaces between bytes to binary

class atcacert_date_format_t(AtcaEnum):
    """
    Support Date formats by the atcacert
    """
    # ISO8601 full date YYYY-MM-DDThh:mm:ssZ
    DATEFMT_ISO8601_SEP = 0
    # RFC 5280 (X.509) 4.1.2.5.1 UTCTime format YYMMDDhhmmssZ
    DATEFMT_RFC5280_UTC = 1
    # POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, big endian.
    DATEFMT_POSIX_UINT32_BE = 2
    # POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, little endian.
    DATEFMT_POSIX_UINT32_LE = 3
    # RFC 5280 (X.509) 4.1.2.5.2 GeneralizedTime format YYYYMMDDhhmmssZ
    DATEFMT_RFC5280_GEN = 4


class atcacert_std_cert_element_t(AtcaEnum):
    """
    Standard dynamic certificate elements
    """
    STDCERT_PUBLIC_KEY = 0
    STDCERT_SIGNATURE = 1
    STDCERT_ISSUE_DATE = 2
    STDCERT_EXPIRE_DATE = 3
    STDCERT_SIGNER_ID = 4
    STDCERT_CERT_SN = 5
    STDCERT_AUTH_KEY_ID = 6
    STDCERT_SUBJ_KEY_ID = 7


class CertStatus(AtcaEnum):
    """
    Status codes returned from atcacert commands and their meanings. From atcacert.h
    """
    ATCACERT_E_SUCCESS = 0               # Operation completed successfully.
    ATCACERT_E_ERROR = 1                 # General error.
    ATCACERT_E_BAD_PARAMS = 2            # Invalid/bad parameter passed to function.
    ATCACERT_E_BUFFER_TOO_SMALL = 3      # Supplied buffer for output is too small to hold the result.
    ATCACERT_E_DECODING_ERROR = 4        # Data being decoded/parsed has an invalid format.
    ATCACERT_E_INVALID_DATE = 5          # Date is invalid.
    ATCACERT_E_UNIMPLEMENTED = 6         # Function is unimplemented for the current configuration.
    ATCACERT_E_UNEXPECTED_ELEM_SIZE = 7  # A certificate element size was not what was expected.
    ATCACERT_E_ELEM_MISSING = 8          # The certificate element isn't defined for the certificate definition.
    ATCACERT_E_ELEM_OUT_OF_BOUNDS = 9    # Certificate element is out of bounds for the given certificate.
    ATCACERT_E_BAD_CERT = 10             # Certificate structure is bad in some way.
    ATCACERT_E_WRONG_CERT_DEF = 11
    ATCACERT_E_VERIFY_FAILED = 12        # Certificate or challenge/response verification failed.


def _atcacert_convert_bytes(kwargs, name, pointer):
    """
    Internal Helper Function: Convert python 'bytes' into memory pointer for ctypes structure
    :param kwargs: kwargs dictionary
    :param name: _field_ name that will be converted
    :param pointer: Conversion Class (resulting type - pointer of type x)
    :return:
    """
    k = kwargs.get(name)
    if k is not None:
        k = k.replace(' ', '').strip()
        byte_string = binascii.unhexlify(k)
        kwargs[name] = pointer((c_uint8*len(byte_string))(*list(byte_string)))


def _atcacert_convert_enum(kwargs, name, enum):
    """
    Internal Helper Function: Convert python enum into ctypes integer
    :param kwargs: kwargs dictionary
    :param name: _field_ name that will be converted
    :param enum: Conversion Class (resulting type)
    :return:
    """
    k = kwargs.get(name)
    if k is not None and k is not int:
        if isinstance(k, enum):
            kwargs[name] = int(k)
        else:
            kwargs[name] = int(getattr(enum, k))


class atcacert_device_loc_t(AtcaStructure):
    """
    CTypes mirror of atcacert_device_loc_t from atcacert_def.h
    """
    _fields_ = [
        ('zone', get_ctype_by_name('atcacert_device_zone_t')),  # Zone in the device.
        ('slot', c_uint8),  # Slot within the data zone. Only applies if zone is DEVZONE_DATA.
        ('is_genkey', c_uint8),  # If true, use GenKey command to get the contents instead of Read.
        ('offset', c_uint16),  # Byte offset in the zone.
        ('count', c_uint16)  # Byte count.
    ]
    _pack_ = 1

    def __init__(self, *args, **kwargs):
        if kwargs is not None:
            _atcacert_convert_enum(kwargs, 'zone', atcacert_device_zone_t)

        super(atcacert_device_loc_t, self).__init__(*args, **kwargs)


class atcacert_cert_loc_t(AtcaStructure):
    """
    CTypes mirror of atcacert_cert_loc_t from atcacert_def.h
    """
    _fields_ = [('offset', c_uint16), ('count', c_uint16)]
    _pack_ = 1


class atcacert_cert_element_t(AtcaStructure):
    """
    CTypes mirror of atcacert_cert_element_t from atcacert_def.h
    """
    _fields_ = [
        ('id', c_char * 25),  # ID identifying this element.
        ('device_loc', atcacert_device_loc_t),  # Location in the device for the element.
        ('cert_loc', atcacert_cert_loc_t),  # Location in the certificate template for the element.
        ('transforms', get_ctype_by_name('atcacert_transform_t') * 2)  # Transforms for converting the device data.

    ]
    _pack_ = 1


class atcacert_def_t(AtcaStructure):
    """
    CTypes mirror of atcacert_def_t from atcacert_def.h
    """
    _pack_ = 1

    def __init__(self, *args, **kwargs):
        if kwargs is not None:
            _atcacert_convert_enum(kwargs, 'type', atcacert_cert_type_t)
            _atcacert_convert_enum(kwargs, 'sn_source', atcacert_cert_sn_src_t)
            _atcacert_convert_enum(kwargs, 'issue_date_format', atcacert_date_format_t)
            _atcacert_convert_enum(kwargs, 'expire_date_format', atcacert_date_format_t)

            _atcacert_convert_bytes(kwargs, 'cert_template', POINTER(c_uint8))

        super(atcacert_def_t, self).__init__(*args, **kwargs)

# Need to define fields outside the class due to ca_cert_def, which is a pointer
# to the same class.
atcacert_def_t._fields_ = [  # pylint: disable=protected-access
    # Certificate type.
    ('type', get_ctype_by_name('atcacert_cert_type_t')),
    # ID for the this certificate definition (4-bit value).
    ('template_id', c_uint8),
    # ID for the certificate chain this definition is a part of (4-bit value).
    ('chain_id', c_uint8),
    # If this is a device certificate template, this is the device slot for the device private key.
    ('private_key_slot', c_uint8),
    # Where the certificate serial number comes from (4-bit value).
    ('sn_source', get_ctype_by_name('atcacert_cert_sn_src_t')),
    # Only applies when sn_source is SNSRC_STORED or SNSRC_STORED_DYNAMIC. Describes where to get the
    # certificate serial number on the device.
    ('cert_sn_dev_loc', atcacert_device_loc_t),
    # Format of the issue date in the certificate.
    ('issue_date_format', get_ctype_by_name('atcacert_date_format_t')),
    # format of the expire date in the certificate.
    ('expire_date_format', get_ctype_by_name('atcacert_date_format_t')),
    # Location in the certificate for the TBS (to be signed) portion.
    ('tbs_cert_loc', atcacert_cert_loc_t),
    # Number of years the certificate is valid for (5-bit value). 0 means no expiration.
    ('expire_years', c_uint8),
    # Where on the device the public key can be found.
    ('public_key_dev_loc', atcacert_device_loc_t),
    # Where on the device the compressed cert can be found.
    ('comp_cert_dev_loc', atcacert_device_loc_t),
    # Where in the certificate template the standard cert elements are inserted.
    ('std_cert_elements', atcacert_cert_loc_t * 8),
    # Additional certificate elements outside of the standard certificate contents.
    ('cert_elements', POINTER(atcacert_cert_element_t)),
    # Number of additional certificate elements in cert_elements.
    ('cert_elements_count', c_uint8),
    # Pointer to the actual certificate template data.
    ('cert_template', POINTER(c_uint8)),
    # Size of the certificate template in cert_template in bytes.
    ('cert_template_size', c_uint16),
    # Certificate definition of the CA certificate
    ('ca_cert_def', POINTER(atcacert_def_t))
]

class atcacert_tm_utc_t(Structure):
    """
    CTypes mirror of atcacert_tm_utc_t from atcacert_date.h which mimics the posix time structure
    """
    _fields_ = [
        ('tm_sec', c_int),   # 0 to 59
        ('tm_min', c_int),   # 0 to 59
        ('tm_hour', c_int),  # 0 to 23
        ('tm_mday', c_int),  # 1 to 31
        ('tm_mon', c_int),   # 0 to 11
        ('tm_year', c_int),  # years since 1900
    ]

    def __init__(self, *args, **kwargs):
        if not args and not kwargs:
            t = datetime.utcnow()
            args = (t.second, t.minute, t.hour, t.day, t.month - 1, t.year)

        super(atcacert_tm_utc_t, self).__init__(*args, **kwargs)

        if self.tm_sec not in range(60):
            raise ValueError('tm_sec out of range: {}'.format(self.tm_sec))
        if self.tm_min not in range(60):
            raise ValueError('tm_min out of range: {}'.format(self.tm_min))
        if self.tm_hour not in range(24):
            raise ValueError('tm_hour out of range: {}'.format(self.tm_hour))
        if self.tm_mday not in range(1, 31):
            raise ValueError('tm_mday out of range: {}'.format(self.tm_mday))
        if self.tm_mon not in range(12):
            raise ValueError('tm_mon out of range: {}'.format(self.tm_mon))
        # pylint: disable=no-member
        # pylint thinks tm_year isn't a member for some reason
        if self.tm_year not in range(200):
            if self.tm_year >= 1900:
                self.tm_year -= 1900
            else:
                raise ValueError('tm_year out of range: {}'.format(self.tm_year))


#===============================================================================
# Client side cert i/o methods. These declarations deal with the client-side, the node being authenticated,
# of the authentication process. It is assumed the client has an ECC CryptoAuthentication device
# (e.g. ATECC508A) and the certificates are stored on that device.


def atcacert_max_cert_size(cert_def, max_cert_size):
    """
    Return the maximum possible certificate size in bytes for a given
    cert def. Certificate can be variable size, so this gives an
    appropriate buffer size when reading the certificates.

    Args:
        cert_def       Certificate definition to find a max size for.
                       Expects atcacert_def_t.
        max_cert_size  Maximum certificate size will be returned here in bytes.
                       Expects AtcaReference.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(max_cert_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_max_cert_size = c_size_t(0)
        status = get_cryptoauthlib().atcacert_max_cert_size(byref(cert_def), byref(c_max_cert_size))
        max_cert_size.value = c_max_cert_size.value
    return status


def atcacert_get_response(device_private_key_slot, challenge, response):
    """
    Calculates the response to a challenge sent from the host.
    The challenge-response protocol is an ECDSA Sign and Verify. This performs the ECDSA Sign on the
    challenge and returns the signature as the response.

    Args:
        device_private_key_slot         Slot number for the device's private key. This must be the
                                        same slot used to generate the public key included in the
                                        device's certificate.
        challenge                       Challenge to generate the response for. Must be 32 bytes.
        response                        Response will be returned in this buffer. 64 bytes.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(response, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_response = create_string_buffer(64)
        status = get_cryptoauthlib().atcacert_get_response(device_private_key_slot, bytes(challenge), byref(c_response))
        response[0:] = bytes(c_response.raw)
    return status


def atcacert_read_cert(cert_def, ca_public_key, cert, cert_size):
    """
    Reads the certificate specified by the certificate definition from the
    ATECC508A device.
    This process involves reading the dynamic cert data from the device and combining it
    with the template found in the certificate definition.

    Args:
        cert_def                Certificate definition describing where to find the dynamic
                                certificate information on the device and how to incorporate it
                                into the template. Expects atcacert_def_t.
        ca_public_key           The ECC P256 public key of the certificate authority that signed
                                this certificate. Formatted as the 32 byte X and Y integers
                                concatenated together (64 bytes total). Set to NULL if the
                                authority key id is not needed, set properly in the cert_def
                                template, or stored on the device as specifed in the
                                cert_def cert_elements.
        cert                    Buffer to received the certificate. Expects bytearray.
        cert_size               As input, the size of the cert buffer in bytes.
                                As output, the size of the certificate returned in cert in bytes.
                                Expects AtcaReference.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(cert, bytearray) or not isinstance(cert_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_cert_size = c_uint32(cert_size.value)
        c_cert = create_string_buffer(cert_size.value)
        status = get_cryptoauthlib().atcacert_read_cert(byref(cert_def), bytes(ca_public_key), byref(c_cert),
                                                        byref(c_cert_size))
        cert[:] = bytes(c_cert.raw)[0:c_cert_size.value]
        cert_size.value = c_cert_size.value
    return status


def atcacert_write_cert(cert_def, cert, cert_size):
    """
    Take a full certificate and write it to the ATECC508A device according to the
    certificate definition.

    Args:
        cert_def                Certificate definition describing where the dynamic certificate
                                information is and how to store it on the device.
                                Expects atcacert_def_t.
        cert                    Full certificate to be stored.
        cert_size               Size of the full certificate in bytes.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    status = get_cryptoauthlib().atcacert_write_cert(byref(cert_def), bytes(cert), cert_size)
    return status


def atcacert_create_csr(csr_def, csr, csr_size):
    """
    Creates a CSR specified by the CSR definition from the ATECC508A device.
    This process involves reading the dynamic CSR data from the device and combining it
    with the template found in the CSR definition, then signing it. Return the CSR int der format

    Args:
        csr_def                 CSR definition describing where to find the dynamic CSR information
                                on the device and how to incorporate it into the template.
                                Expects atcacert_def_t.
        csr                     Buffer to receive the CSR. Expects bytearray.
        csr_size                As input, the size of the CSR buffer in bytes.
                                As output, the size of the CSR as PEM returned in cert in bytes.
                                Expects AtcaReference.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(csr, bytearray) or not isinstance(csr_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_csr_size = c_uint32(csr_size.value)
        c_csr = create_string_buffer(csr_size.value)
        status = get_cryptoauthlib().atcacert_create_csr(byref(csr_def), byref(c_csr), byref(c_csr_size))
        csr[:] = bytes(c_csr.raw)[0:c_csr_size.value]
        csr_size.value = c_csr_size.value
    return status


def atcacert_create_csr_pem(csr_def, csr, csr_size):
    """
    Creates a CSR specified by the CSR definition from the ATECC508A device.
    This process involves reading the dynamic CSR data from the device and combining it
    with the template found in the CSR definition, then signing it. Return the CSR int der format

    Args:
        csr_def                 CSR definition describing where to find the dynamic CSR information
                                on the device and how to incorporate it into the template.
                                Expects atcacert_def_t.
        csr                     Buffer to receive the CSR. Expects bytearray.
        csr_size                As input, the size of the CSR buffer in bytes.
                                As output, the size of the CSR as PEM returned in cert in bytes.
                                Expects AtcaReference.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(csr, bytearray) or not isinstance(csr_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_csr_size = c_uint32(csr_size.value)
        c_csr = create_string_buffer(csr_size.value)
        status = get_cryptoauthlib().atcacert_create_csr(byref(csr_def), byref(c_csr), byref(c_csr_size))
        csr[:] = bytes(c_csr.raw)[0:c_csr_size.value]
        csr_size.value = c_csr_size.value
    return status


# atcacert_date
# Date handling with regard to certificates.


def atcacert_date_enc(date_format, timestamp, formatted_date, formatted_date_size):
    """
    Format a timestamp according to the format type.

    Args:
        date_format             Format to use.
        timestamp               Timestamp to format. Expects atcacert_tm_utc_t.
        formatted_date          Formatted date will be returned in this buffer.
                                Expects bytearray.
        formatted_date_size     As input, the size of the formatted_date buffer.
                                As output, the size of the returned formatted_date.
                                Expects AtcaReference.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(formatted_date, bytearray) or not isinstance(formatted_date_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_formatted_date = create_string_buffer(formatted_date_size.value)
        c_formatted_date_size = c_uint32(formatted_date_size.value)
        status = get_cryptoauthlib().atcacert_date_enc(int(date_format), byref(timestamp), byref(c_formatted_date),
                                                       byref(c_formatted_date_size))
        formatted_date[:] = bytes(c_formatted_date.raw)[0:c_formatted_date_size.value]
        formatted_date_size.value = c_formatted_date_size.value
    return status


def atcacert_date_dec(date_format, formatted_date, formatted_date_size, timestamp):
    """
    Parse a formatted timestamp according to the specified format.

    Args:
        date_format             Format to parse the formatted date as.
        formatted_date          Formatted date to be parsed.
        formatted_date_size     Size of the formatted date in bytes.
        timestamp               Parsed timestamp is returned here. Expects atcacert_tm_utc_t.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    status = get_cryptoauthlib().atcacert_date_dec(int(date_format), bytes(formatted_date), formatted_date_size,
                                                   byref(timestamp))
    return status


def atcacert_date_enc_compcert(issue_date, expire_years, enc_dates):
    """
    Encode the issue and expire dates in the format used by the compressed certificate.

    Args:
        issue_date              Issue date to encode. Note that minutes and seconds will be ignored.
                                Expects atcacert_tm_utc_t.
        expire_years            Expire date is expressed as a number of years past the issue date.
                                0 should be used if there is no expire date.
        enc_dates               Encoded dates for use in the compressed certificate is returned here.
                                3 bytes. Expects bytearray.

    Returns:
        ATCACERT_E_SUCCESS on success
    """
    if not isinstance(enc_dates, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_enc_dates = create_string_buffer(3)
        status = get_cryptoauthlib().atcacert_date_enc_compcert(byref(issue_date), expire_years, byref(c_enc_dates))
        enc_dates[0:] = bytes(c_enc_dates.raw)
    return status


def atcacert_date_dec_compcert(enc_dates, expire_date_format, issue_date, expire_date):
    """
    Decode the issue and expire dates from the format used by the compressed certificate.

    Args:
        enc_dates               Encoded date from the compressed certificate. 3 bytes.
        expire_date_format      Expire date format. Only used to determine max date when no
                                expiration date is specified by the encoded date.
        issue_date              Decoded issue date is returned here. Expects atcacert_tm_utc_t.
        expire_date             Decoded expire date is returned here. If there is no
                                expiration date, the expire date will be set to a maximum
                                value for the given expire_date_format. Expects atcacert_tm_utc_t.
    Returns:
        ATCACERT_E_SUCCESS on success
    """
    status = get_cryptoauthlib().atcacert_date_dec_compcert(bytes(enc_dates), int(expire_date_format),
                                                            byref(issue_date), byref(expire_date))
    return status


def atcacert_date_get_max_date(date_format, timestamp):
    """
    Return the maximum date available for the given format.

    Args:
        format                  Format to get the max date for.
        timestamp               Max date is returned here. Expects atcacert_tm_utc_t.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    status = get_cryptoauthlib().atcacert_date_get_max_date(int(date_format), byref(timestamp))
    return status


# Make module import * safe - keep at the end of the file
__all__ = [x for x in dir() if x.startswith(__name__.split('.')[-1])] + ['CertStatus']
