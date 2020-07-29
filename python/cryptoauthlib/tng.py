"""
TNG: classes and functions for interacting with TNG devices
"""
# (c) 2015-2019 Microchip Technology Inc. and its subsidiaries.
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

from ctypes import c_int, c_size_t, byref, create_string_buffer
from .library import get_cryptoauthlib, AtcaReference
from .atcaenum import AtcaEnum
from .status import Status

# Because this module directly mirrors the C api the following is an exception to the python coding standard
# pylint: disable-msg=invalid-name


def tng_get_device_pubkey(public_key):
    """
    Uses GenKey command to calculate the public key from the primary
    device public key.

    Args:
        public_key  Public key will be returned here. Format will be
                    the X and Y integers in big-endian format.
                    64 bytes for P256 curve. Expects bytearray.

    Returns:
        ATCA_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(public_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_public_key = create_string_buffer(64)
        status = get_cryptoauthlib().tng_get_device_pubkey(byref(c_public_key))
        public_key[0:] = bytes(c_public_key.raw)
    return status


def tng_atcacert_max_device_cert_size(max_cert_size):
    """
    Return the maximum possible certificate size in bytes for a TNG
    device certificate. Certificate can be variable size, so this
    gives an appropriate buffer size when reading the certificate.

    Args:
        max_cert_size  Maximum certificate size will be returned here
                       in bytes. Expects AtcaReference.
    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(max_cert_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_max_cert_size = c_size_t(0)
        status = get_cryptoauthlib().tng_atcacert_max_device_cert_size(byref(c_max_cert_size))
        max_cert_size.value = c_max_cert_size.value
    return status


def tng_atcacert_read_device_cert(cert, cert_size, signer_cert=None):
    """
    Reads the device certificate for a TNG device.

    Args:
        cert         Buffer to received the certificate (DER format).
                     Expects bytearray.
        cert_size    As input, the size of the cert buffer in bytes.
                     As output, the size of the certificate returned
                     in cert in bytes. Expects AtcaReference.
        signer_cert  If supplied, the signer public key is used from
                     this certificate. If set to None, the signer
                     public key is read from the device.
                     Expects bytes or None.
    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(cert, bytearray) or not isinstance(cert_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_cert = create_string_buffer(cert_size.value)
        c_cert_size = c_size_t(cert_size.value)
        if signer_cert is not None:
            signer_cert = bytes(signer_cert)
        status = get_cryptoauthlib().tng_atcacert_read_device_cert(byref(c_cert), byref(c_cert_size), signer_cert)
        cert[:] = bytes(c_cert.raw)[0:c_cert_size.value]
        cert_size.value = c_cert_size.value
    return status


def tng_atcacert_device_public_key(public_key, cert=None):
    """
    Reads the device public key.

    Args:
        public_key   Public key will be returned here. Format will be
                     the X and Y integers in big-endian format.
                     64 bytes for P256 curve. Expects bytearray.
        cert         If supplied, the device public key is used from
                     this certificate. If set to None, the device
                     public key is read from the device. Expects bytes or None.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(public_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_public_key = create_string_buffer(64)
        if cert is not None:
            cert = bytes(cert)
        status = get_cryptoauthlib().tng_atcacert_device_public_key(byref(c_public_key), cert)
        public_key[:] = bytes(c_public_key.raw)
    return status


def tng_atcacert_max_signer_cert_size(max_cert_size):
    """
    Return the maximum possible certificate size in bytes for a TNG
    signer certificate. Certificate can be variable size, so this
    gives an appropriate buffer size when reading the certificate.

    Args:
        max_cert_size  Maximum certificate size will be returned here
                       in bytes. Expects AtcaReference.
    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(max_cert_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_max_cert_size = c_size_t(0)
        status = get_cryptoauthlib().tng_atcacert_max_signer_cert_size(byref(c_max_cert_size))
        max_cert_size.value = c_max_cert_size.value
    return status


def tng_atcacert_read_signer_cert(cert, cert_size):
    """
    Reads the signer certificate for a TNG device.

    Args:
        cert         Buffer to received the certificate (DER format).
                     Expects bytearray.
        cert_size    As input, the size of the cert buffer in bytes.
                     As output, the size of the certificate returned
                     in cert in bytes. Expects AtcaReference.
    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(cert, bytearray) or not isinstance(cert_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_cert = create_string_buffer(cert_size.value)
        c_cert_size = c_size_t(cert_size.value)
        status = get_cryptoauthlib().tng_atcacert_read_signer_cert(byref(c_cert), byref(c_cert_size))
        cert[:] = bytes(c_cert.raw)[0:c_cert_size.value]
        cert_size.value = c_cert_size.value
    return status


def tng_atcacert_signer_public_key(public_key, cert=None):
    """
    Reads the signer public key.

    Args:
        public_key   Public key will be returned here. Format will be
                     the X and Y integers in big-endian format.
                     64 bytes for P256 curve. Expects bytearray.
        cert         If supplied, the signer public key is used from
                     this certificate. If set to None, the signer
                     public key is read from the device. Expects bytes or None.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(public_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_public_key = create_string_buffer(64)
        if cert is not None:
            cert = bytes(cert)
        status = get_cryptoauthlib().tng_atcacert_signer_public_key(byref(c_public_key), cert)
        public_key[:] = bytes(c_public_key.raw)
    return status


def tng_atcacert_root_cert_size(cert_size):
    """
    Get the size of the TNG root cert.

    Args:
        cert_size  Certificate size will be returned here in bytes.
                   Expects AtcaReference.

    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(cert_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_cert_size = c_size_t(0)
        status = get_cryptoauthlib().tng_atcacert_root_cert_size(byref(c_cert_size))
        cert_size.value = c_cert_size.value
    return status


def tng_atcacert_root_cert(cert, cert_size):
    """
    Get the TNG root cert.

    Args:
        cert       Buffer to received the certificate (DER format).
                   Expects bytearray.
        cert_size  As input, the size of the cert buffer in bytes.
                   As output, the size of the certificate returned
                   in cert in bytes. Expects AtcaReference.
    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(cert, bytearray) or not isinstance(cert_size, AtcaReference):
        status = Status.ATCA_BAD_PARAM
    else:
        c_cert = create_string_buffer(cert_size.value)
        c_cert_size = c_size_t(cert_size.value)
        status = get_cryptoauthlib().tng_atcacert_root_cert(byref(c_cert), byref(c_cert_size))
        cert[:] = bytes(c_cert.raw)[0:c_cert_size.value]
        cert_size.value = c_cert_size.value
    return status


def tng_atcacert_root_public_key(public_key):
    """
    Gets the root public key.

    Args:
        public_key  Public key will be returned here. Format will be
                    the X and Y integers in big-endian format.
                    64 bytes for P256 curve. Expects bytearray.
    Returns:
        ATCACERT_E_SUCCESS on success, otherwise an error code.
    """
    if not isinstance(public_key, bytearray):
        status = Status.ATCA_BAD_PARAM
    else:
        c_public_key = create_string_buffer(64)
        status = get_cryptoauthlib().tng_atcacert_root_public_key(byref(c_public_key))
        public_key[:] = bytes(c_public_key.raw)
    return status
